#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoSecretMaterial, redactString, sensitiveEnvValues } from "./operant-report-redaction.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function takeArg(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  process.argv.splice(index, value ? 2 : 1);
  return value;
}

function takeFlag(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return false;
  process.argv.splice(index, 1);
  return true;
}

function takeRepeatedArg(name) {
  const values = [];
  for (;;) {
    const index = process.argv.indexOf(name);
    if (index === -1) return values;
    const value = process.argv[index + 1];
    if (!value || value.startsWith("--")) {
      process.argv.splice(index, 1);
      continue;
    }
    values.push(value);
    process.argv.splice(index, 2);
  }
}

function takeRepeatedArgs(names) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    if (!names.includes(process.argv[index])) continue;
    const value = process.argv[index + 1];
    process.argv.splice(index, value && !value.startsWith("--") ? 2 : 1);
    if (value && !value.startsWith("--")) values.push(value);
    index -= 1;
  }
  return values;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function isBaseComposeFile(file) {
  return path.resolve(repoRoot, file) === path.join(repoRoot, "docker-compose.yml");
}

function composeFileArgs(overlays) {
  if (overlays.length === 0) return [];
  const overlayFiles = overlays.filter((file) => !isBaseComposeFile(file));
  return ["docker-compose.yml", ...overlayFiles].flatMap((file) => ["--file", file]);
}

const dryRun = takeFlag("--dry-run");
const selfTestRedaction = takeFlag("--self-test-redaction");
const envPath = path.resolve(repoRoot, takeArg("--env") || process.env.OPERANT_ENV_FILE || ".env");
const profiles = takeRepeatedArg("--profile");
const composeFiles = takeRepeatedArgs(["--file", "-f", "--compose-file"]);
const composeArgs = process.argv.slice(2).filter((arg) => arg !== "--");

function parseEnv(source) {
  const parsed = {};
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) continue;
    let value = match[2].trim();
    if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    parsed[match[1]] = value;
  }
  return parsed;
}

async function envFileForRedaction(file) {
  try {
    return parseEnv(await readFile(file, "utf8"));
  } catch {
    return {};
  }
}

let consoleSensitiveValues = [];

function redactConsole(value) {
  return redactString(String(value ?? ""), consoleSensitiveValues);
}

function writeStdout(value) {
  if (value) process.stdout.write(redactConsole(value));
}

function writeStderr(value) {
  if (value) process.stderr.write(redactConsole(value));
}

async function runRedactionSelfTest() {
  const synthetic = {
    OPERANT_ADMIN_LOGIN_TOKEN: "operant_admin_compose_wrapper_redaction_token",
    OPERANT_INTERNAL_TOKEN: "operant_internal_compose_wrapper_redaction_token",
    POSTGRES_PASSWORD: "operant_pg_compose_wrapper_redaction_token",
    OPENCLAW_GATEWAY_TOKEN: "openclaw_gateway_compose_wrapper_redaction_token",
    DATABASE_URL: "postgres://operant:operant_pg_compose_wrapper_redaction_token@postgres:5432/operant",
  };
  consoleSensitiveValues = sensitiveEnvValues([process.env, synthetic]);
  const redacted = redactConsole(Object.values(synthetic).join(" "));
  assertNoSecretMaterial(redacted, Object.values(synthetic));
  if (!redacted.includes("[redacted]")) throw new Error("compose wrapper redaction self-test did not redact token values");
  process.stdout.write("compose wrapper redaction self-test passed.\n");
}

if (selfTestRedaction) {
  await runRedactionSelfTest();
  process.exit(0);
}

if (composeArgs.length === 0) {
  process.stderr.write("Usage: operant-compose [--env .env] [--file overlay.yml ...] <docker-compose-command> [...args]\n");
  process.exit(1);
}

consoleSensitiveValues = sensitiveEnvValues([process.env, await envFileForRedaction(envPath)]);
process.stdout.write(`docker compose env file: ${envPath}\n`);
const overlayFiles = composeFiles.filter((file) => !isBaseComposeFile(file));
if (overlayFiles.length > 0) process.stdout.write(`docker compose files: docker-compose.yml, ${overlayFiles.join(", ")}\n`);

const fileArgs = composeFileArgs(composeFiles);
const profileArgs = profiles.flatMap((profile) => ["--profile", profile]);

if (dryRun) {
  process.stdout.write(["docker", "compose", ...fileArgs, "--env-file", envPath, ...profileArgs, ...composeArgs].map(shellQuote).join(" "));
  process.stdout.write("\n");
  process.exit(0);
}

const child = spawn("docker", ["compose", ...fileArgs, "--env-file", envPath, ...profileArgs, ...composeArgs], {
  cwd: repoRoot,
  env: process.env,
  stdio: ["inherit", "pipe", "pipe"],
});

if (child.stdout) child.stdout.on("data", (chunk) => writeStdout(chunk.toString()));
if (child.stderr) child.stderr.on("data", (chunk) => writeStderr(chunk.toString()));

child.on("error", (error) => {
  process.stderr.write(`docker compose failed to start: ${error.message}\n`);
  process.exit(1);
});

child.on("close", (code) => process.exit(code ?? 1));
