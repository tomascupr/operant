#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const valueOptions = new Set([
  "--output",
  "--template",
  "--project-name",
  "--http-bind",
  "--http-port",
  "--postgres-bind",
  "--postgres-port",
  "--gateway-bind",
  "--gateway-port",
]);
const flagOptions = new Set(["--", "--help", "-h", "--force", "--self-test-permissions", "--self-test-arg-validation"]);

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function printUsage() {
  process.stdout.write(`Usage: operant-init-env [options]

Generate a private Docker Compose env file from .env.example.

Options:
  --output <path>          Output env file; default .env
  --template <path>        Template env file; default .env.example
  --project-name <name>    Compose project name; default operant
  --http-bind <host>       Dashboard host bind; default 127.0.0.1
  --http-port <port>       Dashboard host port; default 8080
  --postgres-bind <host>   Postgres host bind; default 127.0.0.1
  --postgres-port <port>   Postgres host port; default 5432
  --gateway-bind <host>    OpenClaw gateway host bind; default 127.0.0.1
  --gateway-port <port>    OpenClaw gateway host port; default 18789
  --force                  Overwrite an existing output file
  --help, -h               Show this help
`);
}

function validateArgs(args) {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--") continue;
    if (valueOptions.has(arg)) {
      const value = args[index + 1];
      if (!value || value === "--" || flagOptions.has(value) || valueOptions.has(value)) throw new Error(`${arg} requires a value`);
      index += 1;
      continue;
    }
    if (flagOptions.has(arg)) continue;
    throw new Error(`Unknown option: ${arg}`);
  }
}

function assertValidationFails(args, expectedMessage) {
  try {
    validateArgs(args);
  } catch (error) {
    if (String(error.message).includes(expectedMessage)) return;
    throw new Error(`Expected validation error containing "${expectedMessage}", got "${error.message}"`);
  }
  throw new Error(`Expected validation failure for args: ${args.join(" ")}`);
}

function runArgValidationSelfTest() {
  validateArgs([
    "--",
    "--output",
    ".operant/test.env",
    "--template",
    ".env.example",
    "--project-name",
    "operant-test",
    "--http-bind",
    "127.0.0.1",
    "--http-port",
    "18080",
    "--postgres-bind",
    "127.0.0.1",
    "--postgres-port",
    "15432",
    "--gateway-bind",
    "127.0.0.1",
    "--gateway-port",
    "28789",
    "--force",
  ]);
  assertValidationFails(["--unknown"], "Unknown option");
  assertValidationFails(["--output"], "requires a value");
  assertValidationFails(["--http-port", "--force"], "requires a value");
  process.stdout.write("init env argument validation self-test passed.\n");
}

try {
  validateArgs(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error.message}\n\n`);
  printUsage();
  process.exit(1);
}

if (hasFlag("--help") || hasFlag("-h")) {
  printUsage();
  process.exit(0);
}

if (hasFlag("--self-test-arg-validation")) {
  runArgValidationSelfTest();
  process.exit(0);
}

const outputPath = path.resolve(repoRoot, argValue("--output", ".env"));
const templatePath = path.resolve(repoRoot, argValue("--template", ".env.example"));
const projectName = argValue("--project-name", process.env.OPERANT_COMPOSE_PROJECT_NAME || "operant");
const httpBind = argValue("--http-bind", process.env.OPERANT_HTTP_BIND || "127.0.0.1");
const httpPort = argValue("--http-port", process.env.OPERANT_HTTP_PORT || "8080");
const postgresBind = argValue("--postgres-bind", process.env.POSTGRES_HOST_BIND || "127.0.0.1");
const postgresPort = argValue("--postgres-port", process.env.POSTGRES_HOST_PORT || "5432");
const gatewayBind = argValue("--gateway-bind", process.env.OPENCLAW_GATEWAY_HOST_BIND || "127.0.0.1");
const gatewayPort = argValue("--gateway-port", process.env.OPENCLAW_GATEWAY_HOST_PORT || "18789");
const force = hasFlag("--force");
const selfTestPermissions = hasFlag("--self-test-permissions");

function randomBase64(bytes = 32) {
  return randomBytes(bytes).toString("base64");
}

function randomToken(prefix) {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

function replaceEnvValue(source, key, value) {
  const expression = new RegExp(`^${key}=.*$`, "m");
  if (!expression.test(source)) return `${source.trimEnd()}\n${key}=${value}\n`;
  return source.replace(expression, `${key}=${value}`);
}

function validateComposeProjectName(value) {
  if (!/^[a-z0-9][a-z0-9_-]*$/.test(value)) {
    process.stderr.write("OPERANT_COMPOSE_PROJECT_NAME must start with a lowercase letter or digit and contain only lowercase letters, digits, dashes, or underscores.\n");
    process.exit(1);
  }
}

function validatePort(name, value) {
  if (!/^[0-9]+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
    process.stderr.write(`${name} must be an integer TCP port from 1 to 65535.\n`);
    process.exit(1);
  }
}

function validateBindAddress(name, value) {
  if (!/^[A-Za-z0-9_.-]+$/.test(value)) {
    process.stderr.write(`${name} must be an IPv4 address or hostname without a port.\n`);
    process.exit(1);
  }
}

function validateDistinctPorts(entries) {
  const seen = new Map();
  for (const [name, value] of entries) {
    const previous = seen.get(value);
    if (previous) {
      process.stderr.write(`${name} and ${previous} cannot both use host port ${value}.\n`);
      process.exit(1);
    }
    seen.set(value, name);
  }
}

async function writePrivateEnvFile(file, body) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, body, { mode: 0o600 });
  await chmod(file, 0o600);
}

async function runPermissionSelfTest() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "operant-init-env-"));
  const tempFile = path.join(tempDir, ".env");
  try {
    await writeFile(tempFile, "OPERANT_SECRET_KEY=old\n", { mode: 0o644 });
    await chmod(tempFile, 0o644);
    await writePrivateEnvFile(tempFile, "OPERANT_SECRET_KEY=new\n");
    const mode = (await stat(tempFile)).mode & 0o777;
    if (mode !== 0o600) throw new Error(`expected 600 permissions, got ${mode.toString(8)}`);
    process.stdout.write("init env permission self-test passed.\n");
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

if (selfTestPermissions) {
  await runPermissionSelfTest();
  process.exit(0);
}

let template;
try {
  template = await readFile(templatePath, "utf8");
} catch (error) {
  process.stderr.write(`Unable to read ${templatePath}: ${error.message}\n`);
  process.exit(1);
}

if (!force) {
  try {
    await readFile(outputPath, "utf8");
    process.stderr.write(`${outputPath} already exists. Re-run with --force to overwrite it.\n`);
    process.exit(1);
  } catch (error) {
    if (error.code !== "ENOENT") {
      process.stderr.write(`Unable to inspect ${outputPath}: ${error.message}\n`);
      process.exit(1);
    }
  }
}

let output = template;
const postgresPassword = randomToken("operant_pg");
validateComposeProjectName(projectName);
validateBindAddress("OPERANT_HTTP_BIND", httpBind);
validatePort("OPERANT_HTTP_PORT", httpPort);
validateBindAddress("POSTGRES_HOST_BIND", postgresBind);
validatePort("POSTGRES_HOST_PORT", postgresPort);
validateBindAddress("OPENCLAW_GATEWAY_HOST_BIND", gatewayBind);
validatePort("OPENCLAW_GATEWAY_HOST_PORT", gatewayPort);
validateDistinctPorts([
  ["OPERANT_HTTP_PORT", httpPort],
  ["POSTGRES_HOST_PORT", postgresPort],
  ["OPENCLAW_GATEWAY_HOST_PORT", gatewayPort],
]);
output = replaceEnvValue(output, "OPERANT_COMPOSE_PROJECT_NAME", projectName);
output = replaceEnvValue(output, "OPERANT_HTTP_BIND", httpBind);
output = replaceEnvValue(output, "OPERANT_HTTP_PORT", httpPort);
output = replaceEnvValue(output, "POSTGRES_HOST_BIND", postgresBind);
output = replaceEnvValue(output, "POSTGRES_HOST_PORT", postgresPort);
output = replaceEnvValue(output, "OPENCLAW_GATEWAY_HOST_BIND", gatewayBind);
output = replaceEnvValue(output, "OPENCLAW_GATEWAY_HOST_PORT", gatewayPort);
output = replaceEnvValue(output, "POSTGRES_PASSWORD", postgresPassword);
output = replaceEnvValue(output, "DATABASE_URL", `postgres://operant:${postgresPassword}@postgres:5432/operant`);
output = replaceEnvValue(output, "OPERANT_SECRET_KEY", randomBase64(32));
output = replaceEnvValue(output, "OPERANT_INTERNAL_TOKEN", randomToken("operant_internal"));
output = replaceEnvValue(output, "OPERANT_ADMIN_LOGIN_TOKEN", randomToken("operant_admin"));
output = replaceEnvValue(output, "OPENCLAW_GATEWAY_TOKEN", randomToken("openclaw_gateway"));

await writePrivateEnvFile(outputPath, output);
process.stdout.write(`Wrote ${outputPath}\n`);
process.stdout.write("Review Slack/model credentials in the dashboard after starting Operant.\n");
