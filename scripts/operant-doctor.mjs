#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyComposeFile } from "./operant-verify-compose.mjs";
import { missingScopes, requiredLiveBotScopes } from "./slack-scope-contract.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const valueOptions = new Set(["--env", "--live-env", "--manual-user-id"]);
const flagOptions = new Set([
  "--",
  "--help",
  "-h",
  "--denied-use-allowed-user",
  "--live-preflight",
  "--manual-slack-posts",
  "--preflight-only",
  "--self-test-arg-validation",
  "--self-test-env-validation",
  "--self-test-live-preflight",
  "--skip-model-auth-test",
  "--skip-slack-auth-test",
]);

if (hasFlag("--help") || hasFlag("-h")) {
  printUsage();
  process.exit(0);
}

if (hasFlag("--self-test-arg-validation")) {
  runArgValidationSelfTest();
  process.exit(0);
}

try {
  validateArgs(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error.message}\n\n`);
  printUsage();
  process.exit(1);
}

const compose = process.env.COMPOSE || "docker compose";
const service = process.env.OPENCLAW_SERVICE || "openclaw-gateway";
const preflightOnly = hasFlag("--preflight-only");
const livePreflight = hasFlag("--live-preflight");
const manualSlackPostsFlag = hasFlag("--manual-slack-posts");
const deniedUseAllowedUserFlag = hasFlag("--denied-use-allowed-user");
const skipSlackAuthTest = hasFlag("--skip-slack-auth-test");
const skipModelAuthTest = hasFlag("--skip-model-auth-test");
const selfTestEnvValidation = hasFlag("--self-test-env-validation");
const selfTestLivePreflight = hasFlag("--self-test-live-preflight");
const envPath = path.resolve(repoRoot, argValue("--env", ".env"));
const liveEnvArg = argValue("--live-env", "");
const liveEnvPath = liveEnvArg ? path.resolve(repoRoot, liveEnvArg) : "";

const requiredEnv = [
  "OPERANT_SECRET_KEY",
  "OPERANT_INTERNAL_TOKEN",
  "OPERANT_ADMIN_LOGIN_TOKEN",
  "POSTGRES_PASSWORD",
  "DATABASE_URL",
  "OPENCLAW_GATEWAY_TOKEN",
];

const placeholderValues = new Set([
  "",
  "change-me-in-prod",
  "change-me-admin-login-token",
  "change-me-postgres-password",
  "change-me-openclaw-gateway-token",
  "operant_admin_...",
  "T...",
  "xapp-...",
  "xoxb-...",
  "xoxp-test-user-token",
  "xoxp-denied-test-user-token",
  "sk-...",
  "sk-local-acceptance-redaction-token",
  "sk-operant-compose-smoke-model",
]);

const baseLiveEnvGroups = [
  { label: "admin Slack user ID", names: ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"] },
  { label: "Slack channel ID", names: ["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"] },
  { label: "Slack bot token", names: ["SLACK_BOT_TOKEN", "OPERANT_LIVE_SLACK_BOT_TOKEN"] },
  { label: "Slack DM channel ID", names: ["OPERANT_LIVE_DM_CHANNEL_ID"] },
];

const tokenLiveEnvGroups = [
  { label: "Slack test-user token", names: ["SLACK_USER_TOKEN", "OPERANT_LIVE_SLACK_USER_TOKEN"] },
  { label: "denied Slack user token", names: ["OPERANT_LIVE_DENIED_USER_TOKEN"] },
];

const manualLiveEnvGroups = [
  { label: "denied Slack user ID", names: ["OPERANT_LIVE_DENIED_USER_ID"] },
];

const liveSeedEnvGroups = [
  { label: "Slack app token", names: ["SLACK_APP_TOKEN", "OPERANT_LIVE_SLACK_APP_TOKEN"] },
  { label: "model API key", names: ["OPERANT_LIVE_MODEL_API_KEY", "MODEL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] },
];

function openClawGatewayScopedCommand(args) {
  return `${compose} exec ${service} sh -lc 'exec openclaw "$@" --url ws://127.0.0.1:18789 --token "$OPENCLAW_GATEWAY_TOKEN"' openclaw ${args}`;
}

function isOpenClawPairingRequired(output) {
  return /pairing required|device is not approved/i.test(String(output || ""));
}

function openClawPairingGuidance(checkName) {
  return [
    `OpenClaw operator device pairing is required before ${checkName} can pass.`,
    "Review the pending device and requested operator scopes, then approve the exact request ID on the gateway host:",
    `  ${compose} exec ${service} openclaw devices list`,
    `  ${compose} exec ${service} openclaw devices approve <requestId>`,
    "Do not use --latest as the approval step; OpenClaw treats it as a preview. Rerun live acceptance after approval.",
    "Expected operator scopes include operator.read, operator.approvals, and operator.talk.secrets; operator.admin satisfies them.",
  ].join("\n");
}

const livePreflightShapeChecks = [
  {
    label: "admin Slack user ID",
    names: ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"],
    pattern: /^[UW][A-Z0-9]{2,}$/,
    hint: "expected a Slack user ID starting with U or W",
  },
  {
    label: "Slack channel ID",
    names: ["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"],
    pattern: /^[CG][A-Z0-9]{2,}$/,
    hint: "expected a public or private Slack channel ID starting with C or G",
  },
  {
    label: "Slack bot token",
    names: ["SLACK_BOT_TOKEN", "OPERANT_LIVE_SLACK_BOT_TOKEN"],
    pattern: /^xoxb-[A-Za-z0-9._-]{8,}$/,
    hint: "expected a bot token starting with xoxb-",
  },
  {
    label: "Slack test-user token",
    names: ["SLACK_USER_TOKEN", "OPERANT_LIVE_SLACK_USER_TOKEN"],
    pattern: /^(?!xoxb-)xox[a-z.-]*-[A-Za-z0-9._-]{8,}$/,
    hint: "expected a Slack user token starting with xox and not a bot token",
  },
  {
    label: "Slack DM channel ID",
    names: ["OPERANT_LIVE_DM_CHANNEL_ID"],
    pattern: /^D[A-Z0-9]{2,}$/,
    hint: "expected a Slack DM channel ID starting with D",
  },
  {
    label: "denied Slack user token",
    names: ["OPERANT_LIVE_DENIED_USER_TOKEN"],
    pattern: /^(?!xoxb-)xox[a-z.-]*-[A-Za-z0-9._-]{8,}$/,
    hint: "expected a Slack user token starting with xox and not a bot token",
  },
  {
    label: "allowed Slack user ID",
    names: ["OPERANT_LIVE_ALLOWED_USER_ID"],
    pattern: /^[UW][A-Z0-9]{2,}$/,
    hint: "expected a Slack user ID starting with U or W",
  },
  {
    label: "denied Slack user ID",
    names: ["OPERANT_LIVE_DENIED_USER_ID"],
    pattern: /^[UW][A-Z0-9]{2,}$/,
    hint: "expected a Slack user ID starting with U or W",
  },
  {
    label: "Slack team ID",
    names: ["OPERANT_LIVE_SLACK_TEAM_ID", "SLACK_TEAM_ID"],
    pattern: /^T[A-Z0-9]{2,}$/,
    hint: "expected a Slack workspace/team ID starting with T",
  },
  {
    label: "Slack app token",
    names: ["SLACK_APP_TOKEN", "OPERANT_LIVE_SLACK_APP_TOKEN"],
    pattern: /^xapp-[A-Za-z0-9._-]{8,}$/,
    hint: "expected an app-level token starting with xapp-",
  },
];

const livePreflightDistinctChecks = [
  {
    label: "Slack test-user token and denied-user token",
    left: ["SLACK_USER_TOKEN", "OPERANT_LIVE_SLACK_USER_TOKEN"],
    right: ["OPERANT_LIVE_DENIED_USER_TOKEN"],
    hint: "use a second Slack user token so the denied-user probe exercises policy denial",
  },
];

const checks = [
  { name: "compose config", command: `${compose} config` },
  { name: "openclaw health", command: `${compose} exec ${service} openclaw health` },
  { name: "openclaw status", command: `${compose} exec ${service} openclaw status --all --json` },
  { name: "openclaw secrets reload", command: openClawGatewayScopedCommand("secrets reload --json"), skipWhenPairingRequired: true },
  { name: "openclaw exec approvals", command: openClawGatewayScopedCommand("approvals get --json --gateway"), skipWhenPairingRequired: true },
  { name: "openclaw doctor", command: `${compose} exec ${service} openclaw doctor --deep --non-interactive` },
  { name: "openclaw security audit", command: `${compose} exec ${service} openclaw security audit --deep --json` },
  { name: "openclaw slack probe", command: `${compose} exec ${service} openclaw channels status --probe --json` },
];

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function printUsage() {
  process.stdout.write(`Usage: operant-doctor [options]

Validates Operant environment files and, unless --preflight-only is set, probes
the running Compose/OpenClaw stack.

Options:
  --env <path>                    Compose env file to validate
  --live-env <path>               Private live Slack/model env overlay
  --preflight-only                Validate env, Compose topology, and Docker only
  --live-preflight                Validate live Slack/model acceptance inputs
  --manual-slack-posts            Validate manual human Slack-post mode without user tokens
  --manual-user-id <id>           Allowed human Slack user ID for manual probes
  --denied-use-allowed-user       Temporarily deny the allowed test user for denied-user probes.
                                  This is the default when no distinct denied user is configured.
  --skip-slack-auth-test          Skip live Slack API reachability checks
  --skip-model-auth-test          Skip live model API auth checks
  --self-test-arg-validation      Run CLI argument validation self-test
  --self-test-env-validation      Run base env validation self-test
  --self-test-live-preflight      Run live preflight validation self-test
  --help, -h                      Show this help
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
    "--env",
    ".env.acme",
    "--live-env",
    ".env.acme.live",
    "--preflight-only",
    "--live-preflight",
    "--manual-slack-posts",
    "--manual-user-id",
    "UALLOWED",
    "--denied-use-allowed-user",
    "--skip-slack-auth-test",
    "--skip-model-auth-test",
    "--self-test-env-validation",
    "--self-test-live-preflight",
  ]);
  assertValidationFails(["--helpful"], "Unknown option");
  assertValidationFails(["--env"], "requires a value");
  assertValidationFails(["--live-env", "--preflight-only"], "requires a value");
  process.stdout.write("Doctor argument validation self-test passed.\n");
}

function parseEnv(source) {
  const parsed = {};
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) continue;
    let value = match[2].trim();
    if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    parsed[match[1]] = value;
  }
  return parsed;
}

function decodesTo32Bytes(value) {
  const trimmed = value.trim();
  const candidates = [
    Buffer.from(trimmed, "base64"),
    /^[a-f0-9]{64}$/i.test(trimmed) ? Buffer.from(trimmed, "hex") : Buffer.alloc(0),
    Buffer.from(trimmed, "utf8"),
  ];
  return candidates.some((candidate) => candidate.length === 32);
}

function validPostgresUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "postgres:" || parsed.protocol === "postgresql:";
  } catch {
    return false;
  }
}

function isPlaceholderValue(value) {
  const trimmed = String(value ?? "").trim();
  return (
    placeholderValues.has(trimmed) ||
    trimmed.includes("...") ||
    /^<[^>]+>$/.test(trimmed) ||
    /^change-me/i.test(trimmed) ||
    /^your-/i.test(trimmed)
  );
}

function missingEnvGroups(env, groups) {
  return groups.filter((group) => !group.names.some((name) => env[name] && !isPlaceholderValue(env[name])));
}

function firstNonPlaceholderEnv(env, names) {
  for (const name of names) {
    if (env[name] && !isPlaceholderValue(env[name])) return { name, value: String(env[name]).trim() };
  }
  return null;
}

function firstEnv(env, names, fallback = "") {
  for (const name of names) {
    if (env[name]) return env[name];
  }
  return fallback;
}

function booleanEnv(env, name) {
  return /^(1|true|yes)$/i.test(String(env[name] || "").trim());
}

function manualSlackPostsEnabled(env) {
  return manualSlackPostsFlag || booleanEnv(env, "OPERANT_LIVE_MANUAL_SLACK_POSTS");
}

function deniedUseAllowedUserEnabled(env) {
  if (deniedUseAllowedUserFlag || booleanEnv(env, "OPERANT_LIVE_DENIED_USE_ALLOWED_USER")) return true;
  const hasDistinctDeniedUser =
    Boolean(firstNonPlaceholderEnv(env, ["OPERANT_LIVE_DENIED_USER_TOKEN"])) ||
    Boolean(firstNonPlaceholderEnv(env, ["OPERANT_LIVE_DENIED_USER_ID"]));
  return !hasDistinctDeniedUser;
}

function liveEnvGroupsForEnv(env) {
  return [
    ...baseLiveEnvGroups,
    ...(manualSlackPostsEnabled(env)
      ? (deniedUseAllowedUserEnabled(env) ? [] : manualLiveEnvGroups)
      : tokenLiveEnvGroups.filter((group) => group.names[0] !== "OPERANT_LIVE_DENIED_USER_TOKEN" || !deniedUseAllowedUserEnabled(env))),
  ];
}

const genericModelApiKeyEnvNames = ["OPERANT_LIVE_MODEL_API_KEY", "MODEL_API_KEY"];

function modelProviderForEnv(env) {
  return String(firstEnv(env, ["OPERANT_LIVE_MODEL_PROVIDER", "MODEL_PROVIDER"], env.ANTHROPIC_API_KEY && !env.OPENAI_API_KEY ? "anthropic" : "openai")).trim().toLowerCase();
}

function modelApiKeyEnvNamesForProvider(provider) {
  if (provider === "anthropic") return [...genericModelApiKeyEnvNames, "ANTHROPIC_API_KEY"];
  if (provider === "openai") return [...genericModelApiKeyEnvNames, "OPENAI_API_KEY"];
  return genericModelApiKeyEnvNames;
}

function modelApiKeyForProvider(env, provider) {
  return firstNonPlaceholderEnv(env, modelApiKeyEnvNamesForProvider(provider));
}

function modelCredentialErrorForProvider(env, provider = modelProviderForEnv(env)) {
  if (modelApiKeyForProvider(env, provider)) return "";
  const otherProviderKey = firstNonPlaceholderEnv(env, ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]);
  if (!otherProviderKey) return "";
  const accepted = modelApiKeyEnvNamesForProvider(provider).join("|");
  const providerHint = provider === "openai" || provider === "anthropic"
    ? `${otherProviderKey.name} is only accepted when MODEL_PROVIDER matches that provider`
    : "provider-specific keys are ignored for non-built-in providers";
  return `model API key for provider ${provider} is missing or still a placeholder (${accepted}); ${providerHint}`;
}

function run(command, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, {
      cwd: repoRoot,
      env: options.env || process.env,
      shell: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    if (child.stdout) {
      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
        if (!options.quiet) process.stdout.write(chunk);
      });
    }
    if (child.stderr) {
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
        if (!options.quiet) process.stderr.write(chunk);
      });
    }
    child.on("error", (error) => resolve({ code: 1, stdout, stderr: error.message }));
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function loadEnv() {
  try {
    return parseEnv(await readFile(envPath, "utf8"));
  } catch (error) {
    process.stderr.write(`Missing ${envPath}. Run "pnpm init:env" before "pnpm doctor".\n`);
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}

async function loadLiveEnv() {
  if (!liveEnvPath) return {};
  try {
    return parseEnv(await readFile(liveEnvPath, "utf8"));
  } catch (error) {
    process.stderr.write(`Missing ${liveEnvPath}. Check --live-env or create it from deploy/slack/live.env.example.\n`);
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}

function isLiveOverrideEnvKey(key) {
  return key.startsWith("OPERANT_LIVE_") ||
    key.startsWith("SLACK_") ||
    ["MODEL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"].includes(key);
}

function mergeRuntimeEnv(envFile, liveEnvFile) {
  const env = { ...process.env, ...envFile, ...liveEnvFile };
  for (const [key, value] of Object.entries(process.env)) {
    if (isLiveOverrideEnvKey(key)) env[key] = value;
  }
  return env;
}

function validateEnv(envFile) {
  const errors = [];
  for (const key of requiredEnv) {
    if (isPlaceholderValue(envFile[key])) errors.push(`${key} is missing or still a placeholder`);
  }
  if (envFile.OPERANT_SECRET_KEY && !decodesTo32Bytes(envFile.OPERANT_SECRET_KEY)) {
    errors.push("OPERANT_SECRET_KEY must decode to exactly 32 bytes");
  }
  for (const key of ["OPERANT_INTERNAL_TOKEN", "OPERANT_ADMIN_LOGIN_TOKEN", "OPENCLAW_GATEWAY_TOKEN"]) {
    if (envFile[key] && envFile[key].length < 24) errors.push(`${key} should be at least 24 characters`);
  }
  if (envFile.POSTGRES_PASSWORD && envFile.POSTGRES_PASSWORD.length < 24) {
    errors.push("POSTGRES_PASSWORD should be at least 24 characters");
  }
  if (envFile.DATABASE_URL && !validPostgresUrl(envFile.DATABASE_URL)) {
    errors.push("DATABASE_URL must be a valid postgres:// or postgresql:// URL");
  }
  if (envFile.DATABASE_URL && envFile.POSTGRES_PASSWORD && !envFile.DATABASE_URL.includes(envFile.POSTGRES_PASSWORD)) {
    errors.push("DATABASE_URL should use the generated POSTGRES_PASSWORD");
  }
  return errors;
}

function validEnvFixture(overrides = {}) {
  const password = "postgres-password-1234567890";
  return {
    OPERANT_SECRET_KEY: "0123456789abcdef0123456789abcdef",
    OPERANT_INTERNAL_TOKEN: "internal-token-1234567890",
    OPERANT_ADMIN_LOGIN_TOKEN: "operant-admin-token-1234567890",
    POSTGRES_PASSWORD: password,
    DATABASE_URL: `postgres://operant:${password}@postgres:5432/operant`,
    OPENCLAW_GATEWAY_TOKEN: "openclaw-gateway-token-1234567890",
    ...overrides,
  };
}

async function runEnvValidationSelfTest() {
  const validErrors = validateEnv(validEnvFixture());
  if (validErrors.length > 0) {
    throw new Error(`env validation self-test rejected a valid fixture: ${validErrors.join(", ")}`);
  }

  for (const key of requiredEnv) {
    const placeholderErrors = validateEnv(validEnvFixture({ [key]: "<placeholder>" }));
    if (!placeholderErrors.some((error) => error.includes(`${key} is missing or still a placeholder`))) {
      throw new Error(`env validation self-test did not reject generic placeholder for ${key}`);
    }
  }

  for (const [key, value] of [
    ["OPERANT_INTERNAL_TOKEN", "your-internal-token"],
    ["OPERANT_ADMIN_LOGIN_TOKEN", "operant_admin_..."],
    ["POSTGRES_PASSWORD", "change-me-postgres-password"],
    ["OPENCLAW_GATEWAY_TOKEN", "openclaw..."],
  ]) {
    const placeholderErrors = validateEnv(validEnvFixture({ [key]: value }));
    if (!placeholderErrors.some((error) => error.includes(`${key} is missing or still a placeholder`))) {
      throw new Error(`env validation self-test did not reject placeholder value for ${key}`);
    }
  }

  process.stdout.write("Doctor env validation self-test passed.\n");
}

function validateLivePreflight(env) {
  const errors = [...missingEnvGroups(env, liveEnvGroupsForEnv(env)), ...missingEnvGroups(env, liveSeedEnvGroups)].map(
    (group) => `${group.label} is missing or still a placeholder (${group.names.join("|")})`,
  );
  for (const check of livePreflightShapeChecks) {
    const selected = firstNonPlaceholderEnv(env, check.names);
    if (selected && !check.pattern.test(selected.value)) {
      errors.push(`${check.label} has an unexpected format in ${selected.name}; ${check.hint}`);
    }
  }
  for (const check of livePreflightDistinctChecks) {
    if (manualSlackPostsEnabled(env) || deniedUseAllowedUserEnabled(env)) continue;
    const left = firstNonPlaceholderEnv(env, check.left);
    const right = firstNonPlaceholderEnv(env, check.right);
    if (left && right && left.value === right.value) {
      errors.push(`${check.label} must be different; ${check.hint}`);
    }
  }
  const modelCredentialError = modelCredentialErrorForProvider(env);
  if (modelCredentialError) errors.push(modelCredentialError);
  return errors;
}

async function runLivePreflightSelfTest() {
  const placeholderErrors = validateLivePreflight({
    OPERANT_LIVE_ADMIN_SLACK_USER_ID: "U...",
    SLACK_CHANNEL_ID: "C...",
    SLACK_BOT_TOKEN: "xoxb-...",
    SLACK_USER_TOKEN: "xoxp-test-user-token",
    OPERANT_LIVE_DM_CHANNEL_ID: "D...",
    OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-denied-test-user-token",
    SLACK_APP_TOKEN: "xapp-...",
    OPENAI_API_KEY: "sk-...",
  });
  if (placeholderErrors.length !== liveEnvGroupsForEnv({}).length + liveSeedEnvGroups.length) {
    throw new Error("live preflight self-test did not reject placeholder values");
  }

  const malformedErrors = validateLivePreflight({
    OPERANT_LIVE_ADMIN_SLACK_USER_ID: "not-a-user",
    SLACK_CHANNEL_ID: "DVALIDLIVE",
    SLACK_BOT_TOKEN: "xoxp-not-a-bot-token",
    SLACK_USER_TOKEN: "xoxb-not-a-user-token",
    OPERANT_LIVE_DM_CHANNEL_ID: "CVALIDLIVE",
    OPERANT_LIVE_DENIED_USER_TOKEN: "xoxb-not-a-denied-user-token",
    SLACK_TEAM_ID: "CVALIDLIVE",
    SLACK_APP_TOKEN: "xoxb-not-an-app-token",
    OPENAI_API_KEY: "sk-live-preflight-valid",
  });
  if (malformedErrors.length !== 8) {
    throw new Error("live preflight self-test did not reject malformed Slack values");
  }

  const duplicateUserErrors = validateLivePreflight({
    OPERANT_LIVE_ADMIN_SLACK_USER_ID: "UVALIDLIVE",
    OPERANT_LIVE_SLACK_CHANNEL_ID: "CVALIDLIVE",
    OPERANT_LIVE_SLACK_BOT_TOKEN: "xoxb-live-preflight-valid",
    OPERANT_LIVE_SLACK_USER_TOKEN: "xoxp-same-live-preflight-token",
    OPERANT_LIVE_DM_CHANNEL_ID: "DVALIDLIVE",
    OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-same-live-preflight-token",
    OPERANT_LIVE_SLACK_APP_TOKEN: "xapp-live-preflight-valid",
    OPENAI_API_KEY: "sk-live-preflight-valid",
  });
  if (duplicateUserErrors.length !== livePreflightDistinctChecks.length) {
    throw new Error("live preflight self-test did not reject duplicate Slack user tokens");
  }

  const mismatchedModelErrors = validateLivePreflight({
    OPERANT_LIVE_ADMIN_SLACK_USER_ID: "UVALIDLIVE",
    OPERANT_LIVE_SLACK_CHANNEL_ID: "CVALIDLIVE",
    OPERANT_LIVE_SLACK_BOT_TOKEN: "xoxb-live-preflight-valid",
    OPERANT_LIVE_SLACK_USER_TOKEN: "xoxp-live-preflight-valid",
    OPERANT_LIVE_DM_CHANNEL_ID: "DVALIDLIVE",
    OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-denied-live-preflight-valid",
    OPERANT_LIVE_SLACK_APP_TOKEN: "xapp-live-preflight-valid",
    MODEL_PROVIDER: "anthropic",
    OPENAI_API_KEY: "sk-live-preflight-valid",
  });
  if (!mismatchedModelErrors.some((error) => error.includes("model API key for provider anthropic"))) {
    throw new Error("live preflight self-test did not reject a provider-specific model key mismatch");
  }

  const validErrors = validateLivePreflight({
    OPERANT_LIVE_ADMIN_SLACK_USER_ID: "UVALIDLIVE",
    OPERANT_LIVE_SLACK_CHANNEL_ID: "CVALIDLIVE",
    OPERANT_LIVE_SLACK_BOT_TOKEN: "xoxb-live-preflight-valid",
    OPERANT_LIVE_SLACK_USER_TOKEN: "xoxp-live-preflight-valid",
    OPERANT_LIVE_DM_CHANNEL_ID: "DVALIDLIVE",
    OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-denied-live-preflight-valid",
    OPERANT_LIVE_SLACK_TEAM_ID: "TVALIDLIVE",
    OPERANT_LIVE_SLACK_APP_TOKEN: "xapp-live-preflight-valid",
    OPENAI_API_KEY: "sk-live-preflight-valid",
  });
  if (validErrors.length > 0) {
    throw new Error(`live preflight self-test rejected valid aliases: ${validErrors.join(", ")}`);
  }

  const validLiveEnv = {
    OPERANT_LIVE_ADMIN_SLACK_USER_ID: "UVALIDLIVE",
    OPERANT_LIVE_SLACK_CHANNEL_ID: "CVALIDLIVE",
    OPERANT_LIVE_SLACK_BOT_TOKEN: "xoxb-live-preflight-valid",
    OPERANT_LIVE_SLACK_USER_TOKEN: "xoxp-live-preflight-valid",
    OPERANT_LIVE_DM_CHANNEL_ID: "DVALIDLIVE",
    OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-denied-live-preflight-valid",
    OPERANT_LIVE_SLACK_TEAM_ID: "TVALIDLIVE",
    OPERANT_LIVE_SLACK_APP_TOKEN: "xapp-live-preflight-valid",
    OPENAI_API_KEY: "sk-live-preflight-valid",
    SLACK_API_BASE_URL: "https://slack.test/api",
    OPENAI_API_BASE_URL: "https://openai.test/v1",
  };
  const manualValidLiveEnv = {
    ...validLiveEnv,
    OPERANT_LIVE_MANUAL_SLACK_POSTS: "1",
    OPERANT_LIVE_ALLOWED_USER_ID: "UALLOWEDLIVE",
    OPERANT_LIVE_DENIED_USER_ID: "UDENIEDLIVE",
    OPERANT_LIVE_SLACK_USER_TOKEN: "",
    SLACK_USER_TOKEN: "",
    OPERANT_LIVE_DENIED_USER_TOKEN: "",
  };
  const manualValidErrors = validateLivePreflight(manualValidLiveEnv);
  if (manualValidErrors.length > 0) {
    throw new Error(`live preflight self-test rejected valid manual Slack-post mode: ${manualValidErrors.join(", ")}`);
  }
  const oneHumanDeniedValidLiveEnv = {
    ...validLiveEnv,
    OPERANT_LIVE_DENIED_USE_ALLOWED_USER: "1",
    OPERANT_LIVE_DENIED_USER_TOKEN: "",
  };
  const oneHumanDeniedValidErrors = validateLivePreflight(oneHumanDeniedValidLiveEnv);
  if (oneHumanDeniedValidErrors.length > 0) {
    throw new Error(`live preflight self-test rejected valid one-human denied-user mode: ${oneHumanDeniedValidErrors.join(", ")}`);
  }
  const manualOneHumanDeniedValidLiveEnv = {
    ...manualValidLiveEnv,
    OPERANT_LIVE_DENIED_USE_ALLOWED_USER: "1",
    OPERANT_LIVE_DENIED_USER_ID: "",
  };
  const manualOneHumanDeniedValidErrors = validateLivePreflight(manualOneHumanDeniedValidLiveEnv);
  if (manualOneHumanDeniedValidErrors.length > 0) {
    throw new Error(`live preflight self-test rejected valid manual one-human denied-user mode: ${manualOneHumanDeniedValidErrors.join(", ")}`);
  }
  const anthropicLiveEnv = {
    ...validLiveEnv,
    MODEL_PROVIDER: "anthropic",
    ANTHROPIC_API_KEY: "sk-ant-live-preflight-valid",
    ANTHROPIC_API_BASE_URL: "https://anthropic.test/v1",
  };
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(String(url));
    const token = String(options.headers?.authorization || options.headers?.["x-api-key"] || "").replace(/^Bearer\s+/i, "");
    const method = parsed.pathname.endsWith("/models") ? "models" : parsed.pathname.replace(/^\/api\//, "").replace(/^\//, "");
    let body = {};
    try {
      body = options.body ? JSON.parse(String(options.body)) : {};
    } catch {
      body = {};
    }
    requests.push({ method, token, channel: parsed.searchParams.get("channel"), cursor: parsed.searchParams.get("cursor"), users: body.users });
    if (parsed.pathname.endsWith("/auth.test")) {
      if (token === "xoxb-live-preflight-valid") {
        return slackJsonResponse(
          { ok: true, user_id: "UBOTLIVE", bot_id: "BBOTLIVE", team_id: "TVALIDLIVE" },
          200,
          { "x-oauth-scopes": requiredLiveBotScopes.join(",") },
        );
      }
      if (token === "xoxb-live-preflight-missing-assistant-scope") {
        return slackJsonResponse(
          { ok: true, user_id: "UBOTLIVE", bot_id: "BBOTLIVE", team_id: "TVALIDLIVE" },
          200,
          { "x-oauth-scopes": requiredLiveBotScopes.filter((scope) => scope !== "assistant:write").join(",") },
        );
      }
      if (token === "xoxb-live-preflight-user-token") {
        return slackJsonResponse({ ok: true, user_id: "UUSERINTHEBOTSLOT", team_id: "TVALIDLIVE" });
      }
      if (token === "xoxp-live-preflight-valid") {
        return slackJsonResponse({ ok: true, user_id: "UALLOWEDLIVE", team_id: "TVALIDLIVE" });
      }
      if (token === "xoxp-denied-live-preflight-valid") {
        return slackJsonResponse({ ok: true, user_id: "UDENIEDLIVE", team_id: "TVALIDLIVE" });
      }
      if (token === "xoxp-denied-other-team-live-preflight-valid") {
        return slackJsonResponse({ ok: true, user_id: "UDENIEDLIVE", team_id: "TOTHERLIVE" });
      }
      return slackJsonResponse({ ok: false, error: "invalid_auth" });
    }
    if (parsed.pathname.endsWith("/conversations.info")) {
      if (token !== "xoxb-live-preflight-valid") return slackJsonResponse({ ok: false, error: "invalid_auth" });
      const channel = parsed.searchParams.get("channel");
      if (channel === "CVALIDLIVE") {
        return slackJsonResponse({ ok: true, channel: { id: channel, is_im: false, is_member: true } });
      }
      if (channel === "CBOTNOTMEMBER") {
        return slackJsonResponse({ ok: true, channel: { id: channel, is_im: false, is_member: false } });
      }
      if (channel === "CMISSINGDENIED") {
        return slackJsonResponse({ ok: true, channel: { id: channel, is_im: false, is_member: true } });
      }
      if (channel === "DVALIDLIVE") {
        return slackJsonResponse({ ok: true, channel: { id: channel, is_im: true, is_member: true } });
      }
      if (channel === "DNOIMREAD") {
        return slackJsonResponse({ ok: false, error: "missing_scope" });
      }
      return slackJsonResponse({ ok: false, error: "channel_not_found" });
    }
    if (parsed.pathname.endsWith("/conversations.members")) {
      if (token !== "xoxb-live-preflight-valid") return slackJsonResponse({ ok: false, error: "invalid_auth" });
      const channel = parsed.searchParams.get("channel");
      if (channel === "CVALIDLIVE") {
        return slackJsonResponse({ ok: true, members: ["UBOTLIVE", "UVALIDLIVE", "UALLOWEDLIVE", "UDENIEDLIVE"], response_metadata: { next_cursor: "" } });
      }
      if (channel === "CBOTNOTMEMBER") {
        return slackJsonResponse({ ok: true, members: ["UALLOWEDLIVE", "UDENIEDLIVE"], response_metadata: { next_cursor: "" } });
      }
      if (channel === "CMISSINGDENIED") {
        return slackJsonResponse({ ok: true, members: ["UBOTLIVE", "UALLOWEDLIVE"], response_metadata: { next_cursor: "" } });
      }
      return slackJsonResponse({ ok: false, error: "channel_not_found" });
    }
    if (parsed.pathname.endsWith("/conversations.open")) {
      if (token !== "xoxb-live-preflight-valid") return slackJsonResponse({ ok: false, error: "invalid_auth" });
      const users = String(body.users || "");
      if (users === "UALLOWEDLIVE" || users === "UVALIDLIVE") {
        return slackJsonResponse({ ok: true, channel: { id: "DVALIDLIVE", is_im: true } });
      }
      if (users === "UWRONGDMLIVE") {
        return slackJsonResponse({ ok: true, channel: { id: "DOTHERLIVE", is_im: true } });
      }
      return slackJsonResponse({ ok: false, error: "user_not_found" });
    }
    if (parsed.pathname.endsWith("/apps.connections.open")) {
      if (token === "xapp-live-preflight-valid") {
        return slackJsonResponse({ ok: true, url: "wss://wss.slack.test/link/?ticket=valid-live-preflight" });
      }
      if (token === "xapp-live-preflight-socket-off") {
        return slackJsonResponse({
          ok: true,
          url: "wss://wss.slack.test/link/?ticket=socket-off",
          response_metadata: { messages: ["[WARN] Socket Mode is not turned on."] },
        });
      }
      return slackJsonResponse({ ok: false, error: "invalid_auth" });
    }
    if (parsed.pathname.endsWith("/models")) {
      if (token === "sk-live-preflight-valid") return slackJsonResponse({ object: "list", data: [{ id: "gpt-5" }] });
      if (token === "sk-ant-live-preflight-valid" && options.headers?.["anthropic-version"]) {
        return slackJsonResponse({ data: [{ id: "claude-sonnet-4.5" }] });
      }
      return slackJsonResponse({ error: { message: "invalid api key" } }, 401);
    }
    return slackJsonResponse({ ok: false, error: "unknown_method" }, 404);
  };
  try {
    await runSlackAuthPreflight(validLiveEnv);
    await runModelAuthPreflight(validLiveEnv);
    await runModelAuthPreflight(anthropicLiveEnv);
    const authRequests = requests.filter((request) => request.method === "auth.test");
    const conversationRequests = requests.filter((request) => request.method === "conversations.info");
    const membershipRequests = requests.filter((request) => request.method === "conversations.members");
    const dmOpenRequests = requests.filter((request) => request.method === "conversations.open");
    const socketModeRequests = requests.filter((request) => request.method === "apps.connections.open");
    const modelRequests = requests.filter((request) => request.method === "models");
    if (authRequests.length !== 3 || conversationRequests.length !== 2 || membershipRequests.length !== 1 || dmOpenRequests.length !== 1 || socketModeRequests.length !== 1 || modelRequests.length !== 2) {
      throw new Error("live preflight self-test did not call expected Slack auth, Socket Mode, conversation, and model probes");
    }
    requests.length = 0;
    await runSlackAuthPreflight(manualValidLiveEnv);
    if (requests.filter((request) => request.method === "auth.test").length !== 1 ||
      requests.filter((request) => request.method === "conversations.info").length !== 2 ||
      requests.filter((request) => request.method === "conversations.members").length !== 1 ||
      requests.filter((request) => request.method === "conversations.open").length !== 1 ||
      requests.filter((request) => request.method === "apps.connections.open").length !== 1) {
      throw new Error("live preflight self-test manual Slack-post mode did not call expected bot-only Slack methods");
    }
    requests.length = 0;
    await runSlackAuthPreflight(oneHumanDeniedValidLiveEnv);
    if (requests.filter((request) => request.method === "auth.test").length !== 2 ||
      requests.filter((request) => request.method === "conversations.info").length !== 2 ||
      requests.filter((request) => request.method === "conversations.members").length !== 1 ||
      requests.filter((request) => request.method === "conversations.open").length !== 1 ||
      requests.filter((request) => request.method === "apps.connections.open").length !== 1) {
      throw new Error("live preflight self-test one-human denied-user mode did not call expected Slack methods");
    }
    requests.length = 0;
    await runSlackAuthPreflight(manualOneHumanDeniedValidLiveEnv);
    if (requests.filter((request) => request.method === "auth.test").length !== 1 ||
      requests.filter((request) => request.method === "conversations.info").length !== 2 ||
      requests.filter((request) => request.method === "conversations.members").length !== 1 ||
      requests.filter((request) => request.method === "conversations.open").length !== 1 ||
      requests.filter((request) => request.method === "apps.connections.open").length !== 1) {
      throw new Error("live preflight self-test manual one-human denied-user mode did not call expected Slack methods");
    }
    requests.length = 0;
    const partialLines = [];
    const partialResult = await runPartialSlackSetupPreflight(
      {
        ...validLiveEnv,
        OPERANT_LIVE_SLACK_USER_TOKEN: "",
        OPERANT_LIVE_DENIED_USER_TOKEN: "",
      },
      (line) => partialLines.push(line),
    );
    if (!partialResult.ok) {
      throw new Error(`live preflight self-test partial Slack setup probe failed: ${partialResult.failures.join(", ")}`);
    }
    const partialOutput = partialLines.join("");
    if (
      !partialOutput.includes("Partial live Slack setup check:") ||
      !partialOutput.includes("Socket Mode app token opens a WebSocket URL") ||
      !partialOutput.includes("bot is a member of CVALIDLIVE") ||
      !partialOutput.includes("bot can read DM DVALIDLIVE") ||
      !partialOutput.includes("DM DVALIDLIVE is the bot DM for UVALIDLIVE") ||
      !partialOutput.includes("admin UVALIDLIVE is a member of CVALIDLIVE")
    ) {
      throw new Error("live preflight self-test did not print useful partial Slack setup evidence");
    }
    if (requests.filter((request) => request.method === "auth.test").length !== 1 ||
      requests.filter((request) => request.method === "conversations.info").length !== 2 ||
      requests.filter((request) => request.method === "conversations.members").length !== 1 ||
      requests.filter((request) => request.method === "conversations.open").length !== 1 ||
      requests.filter((request) => request.method === "apps.connections.open").length !== 1) {
      throw new Error("live preflight self-test partial Slack setup probe did not call expected Slack methods");
    }
    try {
      await slackAppsConnectionsOpen("Slack app token", "xapp-live-preflight-socket-off", "https://slack.test/api");
      throw new Error("Socket Mode disabled warning was not rejected");
    } catch (error) {
      if (!/Socket Mode is not turned on/.test(error.message)) throw error;
    }
    const partialMissingDmScopeLines = [];
    const partialMissingDmScope = await runPartialSlackSetupPreflight(
      {
        ...validLiveEnv,
        OPERANT_LIVE_SLACK_USER_TOKEN: "",
        OPERANT_LIVE_DM_CHANNEL_ID: "DNOIMREAD",
        OPERANT_LIVE_DENIED_USER_TOKEN: "",
      },
      (line) => partialMissingDmScopeLines.push(line),
    );
    if (partialMissingDmScope.ok || !partialMissingDmScopeLines.join("").includes("im:read")) {
      throw new Error("live preflight self-test partial Slack setup probe did not flag missing DM read scope");
    }
    const partialMissingBotLines = [];
    const partialMissingBot = await runPartialSlackSetupPreflight(
      { ...validLiveEnv, OPERANT_LIVE_SLACK_CHANNEL_ID: "CBOTNOTMEMBER" },
      (line) => partialMissingBotLines.push(line),
    );
    if (partialMissingBot.ok || !partialMissingBotLines.join("").includes("invite the bot")) {
      throw new Error("live preflight self-test partial Slack setup probe did not flag missing bot membership");
    }
    await assertRejects(
      () => runSlackAuthPreflight({ ...validLiveEnv, OPERANT_LIVE_BOT_USER_ID: "UWRONGBOT" }),
      "configured bot user ID",
      "live preflight self-test did not reject a mismatched configured bot user ID",
    );
    await assertRejects(
      () => runSlackAuthPreflight({ ...validLiveEnv, SLACK_BOT_TOKEN: "xoxb-live-preflight-user-token" }),
      "must be a Slack bot token",
      "live preflight self-test did not reject a user token in the bot-token slot",
    );
    await assertRejects(
      () => runSlackAuthPreflight({ ...validLiveEnv, SLACK_BOT_TOKEN: "xoxb-live-preflight-missing-assistant-scope" }),
      "assistant:write",
      "live preflight self-test did not reject missing OpenClaw bot scopes",
    );
    await assertRejects(
      () => runSlackAuthPreflight({ ...validLiveEnv, OPERANT_LIVE_DENIED_USER_ID: "UWRONGDENIED" }),
      "configured denied-user ID",
      "live preflight self-test did not reject a mismatched configured denied-user ID",
    );
    await assertRejects(
      () => runSlackAuthPreflight({ ...validLiveEnv, OPERANT_LIVE_SLACK_TEAM_ID: "TWRONGLIVE" }),
      "Slack team",
      "live preflight self-test did not reject a mismatched configured Slack team ID",
    );
    await assertRejects(
      () => runSlackAuthPreflight({ ...validLiveEnv, OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-denied-other-team-live-preflight-valid" }),
      "Slack team",
      "live preflight self-test did not reject Slack tokens from different workspaces",
    );
    await assertRejects(
      () => runSlackAuthPreflight({ ...validLiveEnv, OPERANT_LIVE_SLACK_CHANNEL_ID: "CMISSINGDENIED" }),
      "Operant policy",
      "live preflight self-test did not reject missing denied-user channel membership",
    );
    await assertRejects(
      () => runSlackAuthPreflight({ ...manualValidLiveEnv, OPERANT_LIVE_ALLOWED_USER_ID: "UWRONGDMLIVE" }),
      "does not match the configured DM channel",
      "live preflight self-test did not reject mismatched allowed-user DM channel",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
  process.stdout.write("Doctor live preflight self-test passed.\n");
}

async function assertRejects(operation, expectedMessage, failureMessage) {
  try {
    await operation();
  } catch (error) {
    if (!String(error.message || "").includes(expectedMessage)) {
      throw new Error(`${failureMessage}: unexpected error ${error.message}`);
    }
    return;
  }
  throw new Error(failureMessage);
}

function slackJsonResponse(payload, status = 200, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status >= 200 && status < 300 ? "OK" : "Slack API error",
    headers: {
      get(name) {
        const found = Object.entries(headers).find(([key]) => key.toLowerCase() === String(name).toLowerCase());
        return found ? found[1] : null;
      },
    },
    json: async () => payload,
  };
}

async function slackApiCall(method, token, apiBaseUrl, params = undefined, httpMethod = "POST") {
  const url = new URL(`${apiBaseUrl.replace(/\/$/, "")}/${method}`);
  const options = {
    method: httpMethod,
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
  };
  if (httpMethod === "GET") {
    for (const [key, value] of Object.entries(params || {})) {
      if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
    }
  } else if (params !== undefined) {
    options.headers["content-type"] = "application/json; charset=utf-8";
    options.body = JSON.stringify(params);
  }
  const response = await fetch(url, options);
  let payload = {};
  try {
    payload = await response.json();
  } catch {
    payload = {};
  }
  if (payload && typeof payload === "object") {
    Object.defineProperty(payload, "__responseHeaders", {
      value: {
        oauthScopes: response.headers?.get?.("x-oauth-scopes") || "",
      },
      enumerable: false,
    });
  }
  if (!response.ok || payload.ok !== true) {
    throw new Error(`Slack ${method} failed: ${payload.error || response.statusText || response.status}`);
  }
  return payload;
}

async function slackAuthTest(label, token, apiBaseUrl) {
  try {
    return await slackApiCall("auth.test", token, apiBaseUrl);
  } catch (error) {
    throw new Error(`${label} auth.test failed: ${error.message.replace(/^Slack auth\.test failed:\s*/, "")}`);
  }
}

async function slackAppsConnectionsOpen(label, token, apiBaseUrl) {
  let payload;
  try {
    payload = await slackApiCall("apps.connections.open", token, apiBaseUrl);
  } catch (error) {
    throw new Error(`${label} apps.connections.open failed: ${error.message.replace(/^Slack apps\.connections\.open failed:\s*/, "")}`);
  }
  if (typeof payload.url !== "string" || !payload.url.startsWith("wss://")) {
    throw new Error(`${label} apps.connections.open did not return a Socket Mode WebSocket URL`);
  }
  const warnings = Array.isArray(payload.response_metadata?.messages)
    ? payload.response_metadata.messages.map((message) => String(message || "").trim()).filter(Boolean)
    : [];
  const socketModeOff = warnings.find((message) => /socket mode is not turned on/i.test(message));
  if (socketModeOff) {
    throw new Error(`${label} apps.connections.open returned a WebSocket URL, but Slack says Socket Mode is not turned on. Enable Socket Mode for this Slack app, save the app, reinstall or re-authorize it, and rerun live preflight.`);
  }
  return payload.url;
}

async function slackConversationInfo(label, token, channelId, apiBaseUrl, expectedKind, enforceMembership = true) {
  let payload;
  try {
    payload = await slackApiCall("conversations.info", token, apiBaseUrl, { channel: channelId, include_num_members: true }, "GET");
  } catch (error) {
    throw new Error(`${label} conversations.info failed: ${error.message.replace(/^Slack conversations\.info failed:\s*/, "")}`);
  }
  const conversation = payload.channel;
  if (!conversation || conversation.id !== channelId) {
    throw new Error(`${label} conversations.info did not return the configured conversation`);
  }
  if (expectedKind === "dm" && conversation.is_im !== true) {
    throw new Error(`${label} is not a Slack DM conversation`);
  }
  if (expectedKind === "channel" && conversation.is_im === true) {
    throw new Error(`${label} is a Slack DM, expected a public or private channel`);
  }
  if (enforceMembership && conversation.is_member === false) {
    throw new Error(`${label} token is not a member of the configured conversation`);
  }
  return conversation;
}

async function slackConversationOpen(label, token, userId, apiBaseUrl) {
  let payload;
  try {
    payload = await slackApiCall("conversations.open", token, apiBaseUrl, { users: userId });
  } catch (error) {
    throw new Error(`${label} conversations.open failed: ${error.message.replace(/^Slack conversations\.open failed:\s*/, "")}`);
  }
  const conversation = payload.channel;
  if (!conversation?.id || !String(conversation.id).startsWith("D")) {
    throw new Error(`${label} conversations.open did not return a Slack DM channel ID`);
  }
  return conversation;
}

async function assertSlackDmChannelForUser(label, token, configuredDmChannelId, userId, apiBaseUrl) {
  if (!userId) return null;
  const opened = await slackConversationOpen(label, token, userId, apiBaseUrl);
  if (opened.id !== configuredDmChannelId) {
    throw new Error(`${label} opened ${opened.id}, which does not match the configured DM channel ${configuredDmChannelId}; update OPERANT_LIVE_DM_CHANNEL_ID for the allowed test user`);
  }
  return opened;
}

async function slackConversationMembers(label, token, channelId, apiBaseUrl, requiredUserIds) {
  const { members, pages } = await slackConversationMemberSet(label, token, channelId, apiBaseUrl);
  const missing = new Set(requiredUserIds.filter(Boolean));
  for (const member of members) missing.delete(member);
  if (missing.size > 0) {
    throw new Error(`${label} conversations.members did not include ${Array.from(missing).join(", ")}; keep both allowed and denied test users in the test channel so Operant policy, not Slack membership, suppresses the denied-user bot reply`);
  }
  return { pages };
}

async function slackConversationMemberSet(label, token, channelId, apiBaseUrl) {
  const members = new Set();
  let cursor = "";
  let pages = 0;
  do {
    let payload;
    try {
      payload = await slackApiCall("conversations.members", token, apiBaseUrl, { channel: channelId, limit: 1000, cursor }, "GET");
    } catch (error) {
      throw new Error(`${label} conversations.members failed: ${error.message.replace(/^Slack conversations\.members failed:\s*/, "")}`);
    }
    if (!Array.isArray(payload.members)) {
      throw new Error(`${label} conversations.members did not return a members array`);
    }
    for (const member of payload.members) members.add(String(member));
    cursor = String(payload.response_metadata?.next_cursor || "").trim();
    pages += 1;
    if (pages > 100) throw new Error(`${label} conversations.members pagination exceeded 100 pages`);
  } while (cursor);
  return { members, pages };
}

function slackTeamIdFromAuth(identity) {
  return String(identity?.team_id || "").trim();
}

function assertSlackBotTokenAuth(label, identity) {
  if (!identity?.user_id) throw new Error(`${label} auth.test did not return a user_id`);
  if (!identity?.bot_id) throw new Error(`${label} must be a Slack bot token; auth.test did not return bot_id`);
}

function assertSlackBotScopes(label, authPayload) {
  const rawScopes = String(authPayload?.__responseHeaders?.oauthScopes || "");
  if (!rawScopes.trim()) {
    throw new Error(`${label} auth.test did not return x-oauth-scopes; cannot verify required Slack bot scopes: ${requiredLiveBotScopes.join(", ")}`);
  }
  const scopes = new Set(rawScopes.split(",").map((scope) => scope.trim()).filter(Boolean));
  const missing = missingScopes(scopes, requiredLiveBotScopes);
  if (missing.length > 0) {
    throw new Error(`${label} is missing required OpenClaw Slack bot scopes: ${missing.join(", ")}. Update the Slack app OAuth scopes from deploy/slack/manifest.yaml, reinstall or re-authorize the app, and replace the bot token before rerunning live acceptance.`);
  }
}

function assertSlackTeamMatch(label, expectedTeamId, actualLabel, actualTeamId) {
  const expected = String(expectedTeamId || "").trim();
  const actual = String(actualTeamId || "").trim();
  if (!expected) return;
  if (!actual) throw new Error(`${actualLabel} auth.test did not return team_id for Slack team consistency with ${label}`);
  if (expected !== actual) throw new Error(`Slack team ${label} ${expected} does not match ${actualLabel} ${actual}`);
}

async function runPartialSlackSetupPreflight(env, write = (line) => process.stderr.write(line)) {
  const apiBaseUrl = firstEnv(env, ["SLACK_API_BASE_URL"], "https://slack.com/api");
  const botToken = firstNonPlaceholderEnv(env, ["SLACK_BOT_TOKEN", "OPERANT_LIVE_SLACK_BOT_TOKEN"]);
  const appToken = firstNonPlaceholderEnv(env, ["SLACK_APP_TOKEN", "OPERANT_LIVE_SLACK_APP_TOKEN"]);
  const channel = firstNonPlaceholderEnv(env, ["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"]);
  const dmChannel = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_DM_CHANNEL_ID"]);
  const adminSlackUserId = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"]);
  const allowedSlackUserId = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_ALLOWED_USER_ID"]) || adminSlackUserId;
  const configuredBotUserId = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_BOT_USER_ID"]);
  const configuredSlackTeamId = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_SLACK_TEAM_ID", "SLACK_TEAM_ID"]);
  const failures = [];
  const notes = [];
  let botAuth = null;

  write("Partial live Slack setup check:\n");

  if (!appToken) {
    notes.push("Slack app token missing; Socket Mode app-token probe skipped");
  } else {
    try {
      await slackAppsConnectionsOpen("Slack app token", appToken.value, apiBaseUrl);
      notes.push("Socket Mode app token opens a WebSocket URL");
    } catch (error) {
      failures.push(error.message);
    }
  }

  if (!botToken) {
    notes.push("Slack bot token missing; bot identity and channel membership probes skipped");
  } else {
    try {
      botAuth = await slackAuthTest("Slack bot token", botToken.value, apiBaseUrl);
      assertSlackBotTokenAuth("Slack bot token", botAuth);
      assertSlackBotScopes("Slack bot token", botAuth);
      const botTeamId = slackTeamIdFromAuth(botAuth);
      assertSlackTeamMatch(configuredSlackTeamId?.name || "configured Slack team ID", configuredSlackTeamId?.value || "", "Slack bot token auth.test team_id", botTeamId);
      if (configuredBotUserId && botAuth.user_id && configuredBotUserId.value !== botAuth.user_id) {
        throw new Error(`configured bot user ID ${configuredBotUserId.name} does not match Slack bot token auth.test user_id`);
      }
      notes.push(`bot token authenticates as ${botAuth.user_id || "unknown bot user"} in team ${botTeamId || "unknown"}`);
    } catch (error) {
      failures.push(error.message);
    }
  }

  if (!botToken || !channel) {
    notes.push("Slack channel or bot token missing; channel membership probe skipped");
  } else {
    try {
      const conversation = await slackConversationInfo("Slack bot target channel", botToken.value, channel.value, apiBaseUrl, "channel", false);
      if (conversation.is_archived) {
        failures.push(`Slack target channel ${channel.value} is archived`);
      }
      if (conversation.is_member === false) {
        failures.push(`Slack bot token is not a member of ${channel.value}; invite the bot to the channel before live OpenClaw E2E`);
      } else {
        notes.push(`bot is a member of ${channel.value}`);
      }
      const { members } = await slackConversationMemberSet("Slack target channel", botToken.value, channel.value, apiBaseUrl);
      if (botAuth?.user_id) {
        if (members.has(botAuth.user_id)) {
          notes.push(`bot user ${botAuth.user_id} is listed in ${channel.value}`);
        } else {
          failures.push(`Slack target channel ${channel.value} members do not include bot user ${botAuth.user_id}; invite the bot before live OpenClaw E2E`);
        }
      }
      if (adminSlackUserId?.value) {
        if (members.has(adminSlackUserId.value)) {
          notes.push(`admin ${adminSlackUserId.value} is a member of ${channel.value}`);
        } else {
          failures.push(`Slack target channel ${channel.value} members do not include admin ${adminSlackUserId.value}`);
        }
      }
    } catch (error) {
      failures.push(error.message);
    }
  }

  if (!botToken || !dmChannel) {
    notes.push("Slack DM channel or bot token missing; DM reachability probe skipped");
  } else {
    try {
      await slackConversationInfo("Slack bot DM channel", botToken.value, dmChannel.value, apiBaseUrl, "dm");
      notes.push(`bot can read DM ${dmChannel.value}`);
      if (allowedSlackUserId?.value) {
        await assertSlackDmChannelForUser("Slack bot DM channel", botToken.value, dmChannel.value, allowedSlackUserId.value, apiBaseUrl);
        notes.push(`DM ${dmChannel.value} is the bot DM for ${allowedSlackUserId.value}`);
      }
    } catch (error) {
      const scopeHint = /\bmissing_scope\b/.test(error.message)
        ? "; add bot scopes im:read and im:write, then reinstall/re-authorize the Slack app"
        : "";
      failures.push(`${error.message}${scopeHint}`);
    }
  }

  for (const note of notes) write(`- ${note}\n`);
  for (const failure of failures) write(`- ${failure}\n`);
  return { ok: failures.length === 0, failures, notes };
}

async function runSlackAuthPreflight(env) {
  const apiBaseUrl = firstEnv(env, ["SLACK_API_BASE_URL"], "https://slack.com/api");
  const botToken = firstNonPlaceholderEnv(env, ["SLACK_BOT_TOKEN", "OPERANT_LIVE_SLACK_BOT_TOKEN"]);
  const appToken = firstNonPlaceholderEnv(env, ["SLACK_APP_TOKEN", "OPERANT_LIVE_SLACK_APP_TOKEN"]);
  const testUserToken = firstNonPlaceholderEnv(env, ["SLACK_USER_TOKEN", "OPERANT_LIVE_SLACK_USER_TOKEN"]);
  const deniedUserToken = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_DENIED_USER_TOKEN"]);
  const channel = firstNonPlaceholderEnv(env, ["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"]);
  const dmChannel = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_DM_CHANNEL_ID"]);
  const manualSlackPosts = manualSlackPostsEnabled(env);
  const deniedUseAllowedUser = deniedUseAllowedUserEnabled(env);
  const manualAllowedUserId = argValue("--manual-user-id", "") || firstNonPlaceholderEnv(env, ["OPERANT_LIVE_ALLOWED_USER_ID"])?.value || "";
  const configuredBotUserId = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_BOT_USER_ID"]);
  const configuredDeniedUserId = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_DENIED_USER_ID"]);
  const configuredSlackTeamId = firstNonPlaceholderEnv(env, ["OPERANT_LIVE_SLACK_TEAM_ID", "SLACK_TEAM_ID"]);
  await slackAppsConnectionsOpen("Slack app token", appToken.value, apiBaseUrl);
  const botAuth = await slackAuthTest("Slack bot token", botToken.value, apiBaseUrl);
  const testUserAuth = manualSlackPosts ? null : await slackAuthTest("Slack test-user token", testUserToken.value, apiBaseUrl);
  const deniedUserAuth = manualSlackPosts ? null : (deniedUseAllowedUser ? testUserAuth : await slackAuthTest("denied Slack user token", deniedUserToken.value, apiBaseUrl));
  const botTeamId = slackTeamIdFromAuth(botAuth);
  const testUserTeamId = slackTeamIdFromAuth(testUserAuth);
  const deniedUserTeamId = slackTeamIdFromAuth(deniedUserAuth);
  assertSlackBotTokenAuth("Slack bot token", botAuth);
  assertSlackBotScopes("Slack bot token", botAuth);
  if (!manualSlackPosts && !testUserAuth.user_id) throw new Error("Slack test-user token auth.test did not return a user_id");
  if (!manualSlackPosts && !deniedUseAllowedUser && !deniedUserAuth.user_id) throw new Error("denied Slack user token auth.test did not return a user_id");
  if (configuredBotUserId && botAuth.user_id && configuredBotUserId.value !== botAuth.user_id) {
    throw new Error(`configured bot user ID ${configuredBotUserId.name} does not match Slack bot token auth.test user_id`);
  }
  if (!manualSlackPosts && !deniedUseAllowedUser && configuredDeniedUserId && deniedUserAuth.user_id && configuredDeniedUserId.value !== deniedUserAuth.user_id) {
    throw new Error(`configured denied-user ID ${configuredDeniedUserId.name} does not match denied Slack user token auth.test user_id`);
  }
  if (!manualSlackPosts && !deniedUseAllowedUser && testUserAuth.user_id === deniedUserAuth.user_id) {
    throw new Error("Slack test-user token and denied-user token resolve to the same Slack user");
  }
  assertSlackTeamMatch(configuredSlackTeamId?.name || "configured Slack team ID", configuredSlackTeamId?.value || "", "Slack bot token auth.test team_id", botTeamId);
  if (!manualSlackPosts) {
    assertSlackTeamMatch(configuredSlackTeamId?.name || "configured Slack team ID", configuredSlackTeamId?.value || "", "Slack test-user token auth.test team_id", testUserTeamId);
    assertSlackTeamMatch("Slack bot token auth.test team_id", botTeamId, "Slack test-user token auth.test team_id", testUserTeamId);
    if (!deniedUseAllowedUser) {
      assertSlackTeamMatch(configuredSlackTeamId?.name || "configured Slack team ID", configuredSlackTeamId?.value || "", "denied Slack user token auth.test team_id", deniedUserTeamId);
      assertSlackTeamMatch("Slack bot token auth.test team_id", botTeamId, "denied Slack user token auth.test team_id", deniedUserTeamId);
    }
  } else {
    const allowedUserId = manualAllowedUserId || firstNonPlaceholderEnv(env, ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"])?.value || "";
    const deniedUserId = configuredDeniedUserId?.value || "";
    if (!deniedUseAllowedUser && allowedUserId && deniedUserId && allowedUserId === deniedUserId) {
      throw new Error("manual allowed Slack user ID and denied Slack user ID must be different");
    }
  }
  const allowedUserId = manualSlackPosts ? (manualAllowedUserId || firstNonPlaceholderEnv(env, ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"])?.value || "") : testUserAuth.user_id;
  const deniedUserId = deniedUseAllowedUser ? allowedUserId : (manualSlackPosts ? configuredDeniedUserId?.value : deniedUserAuth.user_id);
  await slackConversationInfo("Slack bot target channel", botToken.value, channel.value, apiBaseUrl, "channel");
  await slackConversationInfo("Slack bot DM channel", botToken.value, dmChannel.value, apiBaseUrl, "dm");
  await assertSlackDmChannelForUser(
    "Slack bot DM channel",
    botToken.value,
    dmChannel.value,
    allowedUserId,
    apiBaseUrl,
  );
  await slackConversationMembers("Slack target channel", botToken.value, channel.value, apiBaseUrl, [
    allowedUserId,
    deniedUserId,
  ]);
}

async function runModelAuthPreflight(env) {
  const provider = modelProviderForEnv(env);
  const modelApiKey = modelApiKeyForProvider(env, provider);
  if (!modelApiKey) {
    throw new Error(modelCredentialErrorForProvider(env, provider) || `model API key for provider ${provider} is missing or still a placeholder (${modelApiKeyEnvNamesForProvider(provider).join("|")})`);
  }
  if (provider !== "openai") {
    if (provider !== "anthropic") return { checked: false, provider, reason: "no read-only auth probe is implemented for this provider" };
    const apiBaseUrl = firstEnv(env, ["ANTHROPIC_API_BASE_URL", "OPERANT_LIVE_ANTHROPIC_API_BASE_URL"], "https://api.anthropic.com/v1").replace(/\/$/, "");
    const response = await fetch(`${apiBaseUrl}/models`, {
      method: "GET",
      headers: {
        accept: "application/json",
        "x-api-key": modelApiKey.value,
        "anthropic-version": firstEnv(env, ["ANTHROPIC_VERSION", "OPERANT_LIVE_ANTHROPIC_VERSION"], "2023-06-01"),
      },
    });
    let payload = {};
    try {
      payload = await response.json();
    } catch {
      payload = {};
    }
    if (!response.ok) {
      throw new Error(`Anthropic models list failed: ${payload.error?.message || payload.error || response.statusText || response.status}`);
    }
    if (!Array.isArray(payload.data)) {
      throw new Error("Anthropic models list did not return a data array");
    }
    return { checked: true, provider };
  }
  const apiBaseUrl = firstEnv(env, ["OPENAI_API_BASE_URL", "OPERANT_LIVE_OPENAI_API_BASE_URL"], "https://api.openai.com/v1").replace(/\/$/, "");
  const response = await fetch(`${apiBaseUrl}/models`, {
    method: "GET",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${modelApiKey.value}`,
    },
  });
  let payload = {};
  try {
    payload = await response.json();
  } catch {
    payload = {};
  }
  if (!response.ok) {
    throw new Error(`OpenAI models list failed: ${payload.error?.message || payload.error || response.statusText || response.status}`);
  }
  if (!Array.isArray(payload.data)) {
    throw new Error("OpenAI models list did not return a data array");
  }
  return { checked: true, provider };
}

async function checkDocker(env) {
  const docker = await run("docker --version", { quiet: true, env });
  if (docker.code !== 0) return { ok: false, message: "docker command is not available" };
  const composeVersion = await run(`${compose} version`, { quiet: true, env });
  if (composeVersion.code !== 0) return { ok: false, message: `${compose} version failed` };
  return { ok: true, message: `${docker.stdout.trim()} / ${composeVersion.stdout.trim()}` };
}

if (selfTestEnvValidation) {
  await runEnvValidationSelfTest();
  process.exit(0);
}

if (selfTestLivePreflight) {
  await runLivePreflightSelfTest();
  process.exit(0);
}

const envFile = await loadEnv();
const liveEnvFile = await loadLiveEnv();
const mergedEnv = mergeRuntimeEnv(envFile, liveEnvFile);

process.stdout.write(`== operant preflight ==\n`);
process.stdout.write(`env: ${envPath}\n`);
if (liveEnvPath) process.stdout.write(`live env: ${liveEnvPath}\n`);

const envErrors = validateEnv(envFile);
if (envErrors.length > 0) {
  for (const error of envErrors) process.stderr.write(`- ${error}\n`);
  process.exit(1);
}
process.stdout.write("env: ok\n");

if (livePreflight) {
  const liveEnvErrors = validateLivePreflight(mergedEnv);
  if (liveEnvErrors.length > 0) {
    if (!skipSlackAuthTest) {
      try {
        await runPartialSlackSetupPreflight(mergedEnv);
      } catch (error) {
        process.stderr.write(`Partial live Slack setup check could not run: ${error.message}\n`);
      }
    }
    process.stderr.write("Live acceptance env check failed:\n");
    for (const error of liveEnvErrors) process.stderr.write(`- ${error}\n`);
    process.stderr.write("Set these in your private env file or shell before running pnpm compose:e2e.\n");
    process.exit(1);
  }
  process.stdout.write("live acceptance env: ok\n");
  if (skipSlackAuthTest) {
    process.stdout.write("live Slack auth: skipped (--skip-slack-auth-test)\n");
  } else {
    try {
      await runSlackAuthPreflight(mergedEnv);
      process.stdout.write("live Slack auth/reachability: ok\n");
    } catch (error) {
      process.stderr.write(`Live Slack auth/reachability check failed: ${error.message}\n`);
      process.stderr.write("Fix the Slack tokens, channel/DM IDs, or bot channel membership; rerun with --skip-slack-auth-test for an offline structural check only.\n");
      process.exit(1);
    }
  }
  if (skipModelAuthTest) {
    process.stdout.write("live model auth: skipped (--skip-model-auth-test)\n");
  } else {
    try {
      const result = await runModelAuthPreflight(mergedEnv);
      if (result.checked) {
        process.stdout.write(`live model auth: ok (${result.provider})\n`);
      } else {
        process.stdout.write(`live model auth: skipped (${result.provider}; ${result.reason})\n`);
      }
    } catch (error) {
      process.stderr.write(`Live model auth check failed: ${error.message}\n`);
      process.stderr.write("Fix the model API key/provider or rerun with --skip-model-auth-test for an offline structural check only.\n");
      process.exit(1);
    }
  }
}

const composeFailures = await verifyComposeFile(path.join(repoRoot, "docker-compose.yml"));
if (composeFailures.length > 0) {
  process.stderr.write("Compose topology check failed:\n");
  for (const failure of composeFailures) process.stderr.write(`- ${failure}\n`);
  process.exit(1);
}
process.stdout.write("compose topology: ok\n");

const dockerStatus = await checkDocker(mergedEnv);
if (dockerStatus.ok) {
  process.stdout.write(`docker: ${dockerStatus.message}\n`);
} else {
  process.stdout.write(`docker: unavailable (${dockerStatus.message})\n`);
  if (!preflightOnly) {
    process.stderr.write("Install/start Docker, then rerun pnpm doctor.\n");
    process.exit(1);
  }
}

if (preflightOnly) {
  process.stdout.write("Preflight completed.\n");
  process.exit(0);
}

for (const check of checks) {
  process.stdout.write(`\n== ${check.name} ==\n${check.command}\n`);
  const result = await run(check.command, { env: mergedEnv });
  if (result.code !== 0) {
    if (isOpenClawPairingRequired(`${result.stdout || ""}\n${result.stderr || ""}`)) {
      if (check.skipWhenPairingRequired) {
        process.stdout.write(`SKIP ${check.name}: OpenClaw operator device pairing required.\n`);
        continue;
      }
      process.stderr.write(`\n${openClawPairingGuidance(check.name)}\n`);
    }
    process.stderr.write(`\n${check.name} failed with exit code ${result.code}\n`);
    process.exit(result.code);
  }
}

process.stdout.write("\nOperant doctor completed.\n");
