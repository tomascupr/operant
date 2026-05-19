#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoSecretMaterial, redactSecretMaterial, redactString, sensitiveEnvValues, writeRedactedJsonReport } from "./operant-report-redaction.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const valueOptions = new Set([
  "--admin-slack-user-id",
  "--approval-completion-regex",
  "--approval-completion-timeout-ms",
  "--approval-prompt",
  "--base-url",
  "--bot-user-id",
  "--channel-id",
  "--denied-timeout-ms",
  "--denied-user-id",
  "--denied-user-token",
  "--dm-channel-id",
  "--env",
  "--expect-reply-regex",
  "--file",
  "-f",
  "--compose-file",
  "--health-timeout-ms",
  "--live-env",
  "--manual-user-id",
  "--openclaw-checks",
  "--poll-interval-ms",
  "--profile",
  "--prompt",
  "--records-timeout-ms",
  "--report",
  "--restart-services",
  "--slack-team-id",
  "--timeout-ms",
]);
const flagOptions = new Set([
  "--",
  "--allow-blocked",
  "--down",
  "--down-volumes",
  "--help",
  "-h",
  "--self-test-arg-validation",
  "--self-test-report-redaction",
  "--denied-use-allowed-user",
  "--skip-approval-probe",
  "--skip-completion-audit",
  "--skip-credential-seed",
  "--skip-denied-user-probe",
  "--skip-dm-probe",
  "--skip-live",
  "--skip-live-preflight",
  "--skip-model-auth-test",
  "--skip-post-restart-live",
  "--skip-restart",
  "--skip-slack-approval-completion",
  "--skip-slack-approval-probe",
  "--skip-slack-auth-test",
  "--synthetic-credential-seed",
  "--manual-slack-posts",
  "--manual-slack-nudge",
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

const allowBlocked = hasFlag("--allow-blocked");
const skipLive = hasFlag("--skip-live");
const skipCredentialSeed = hasFlag("--skip-credential-seed");
const syntheticCredentialSeed = hasFlag("--synthetic-credential-seed");
const skipRestart = hasFlag("--skip-restart");
const skipPostRestartLive = hasFlag("--skip-post-restart-live");
const skipCompletionAudit = hasFlag("--skip-completion-audit");
const skipDmProbe = hasFlag("--skip-dm-probe");
const skipDeniedUserProbe = hasFlag("--skip-denied-user-probe");
const skipSlackApprovalProbe = hasFlag("--skip-slack-approval-probe");
const skipSlackApprovalCompletion = hasFlag("--skip-slack-approval-completion");
const skipApprovalProbe = hasFlag("--skip-approval-probe");
const skipLivePreflight = hasFlag("--skip-live-preflight");
const skipSlackAuthTest = hasFlag("--skip-slack-auth-test");
const skipModelAuthTest = hasFlag("--skip-model-auth-test");
const manualSlackPostsFlag = hasFlag("--manual-slack-posts");
const manualSlackNudgeFlag = hasFlag("--manual-slack-nudge");
const selfTestReportRedaction = hasFlag("--self-test-report-redaction");
const downAfter = hasFlag("--down");
const downVolumes = hasFlag("--down-volumes");
const envPath = path.resolve(repoRoot, argValue("--env", ".env"));
const liveEnvArg = argValue("--live-env", "");
const liveEnvPath = liveEnvArg ? path.resolve(repoRoot, liveEnvArg) : "";
const baseUrlOverride = argValue("--base-url", process.env.OPERANT_LIVE_BASE_URL || "");
let baseUrl = baseUrlOverride || "http://127.0.0.1:8080";
const preRestartLiveReportPath = ".operant/live-e2e-report.json";
const postRestartLiveReportPath = ".operant/live-e2e-post-restart-report.json";
const healthTimeoutMs = numericArg("--health-timeout-ms", 180_000, "OPERANT_COMPOSE_HEALTH_TIMEOUT_MS");
const pollIntervalMs = numericArg("--poll-interval-ms", 3_000, "OPERANT_COMPOSE_POLL_INTERVAL_MS");
const nonLiveSmoke = skipLive && (skipCredentialSeed || syntheticCredentialSeed);
const reportPath = path.resolve(
  repoRoot,
  argValue(
    "--report",
    process.env.OPERANT_COMPOSE_E2E_REPORT || (nonLiveSmoke ? ".operant/compose-smoke-report.json" : ".operant/compose-e2e-report.json"),
  ),
);
let reportSensitiveEnv = process.env;
let consoleSensitiveValues = sensitiveEnvValues([process.env]);
let reportArchiveAttempted = false;
const restartServices = argValue("--restart-services", process.env.OPERANT_COMPOSE_RESTART_SERVICES || "policy-audit,openclaw-gateway")
  .split(",")
  .map((service) => service.trim())
  .filter(Boolean);
const composeProfiles = repeatedArg("--profile");
const composeProfileArgs = composeProfiles.flatMap((profile) => ["--profile", profile]);
const requestedComposeFiles = repeatedArgs(["--file", "-f", "--compose-file"]);
const composeOverlayFiles = requestedComposeFiles.filter((file) => !isBaseComposeFile(file));
const composeFiles = ["docker-compose.yml", ...composeOverlayFiles];
const composeFileArgs = composeOverlayFiles.length > 0 ? composeFiles.flatMap((file) => ["--file", file]) : [];

const requiredLiveEnv = [
  { label: "admin Slack user ID", names: ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"] },
  { label: "Slack channel ID", names: ["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"] },
  { label: "Slack bot token", names: ["OPERANT_LIVE_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN"] },
];

const tokenLiveEnv = [
  { label: "Slack user token", names: ["OPERANT_LIVE_SLACK_USER_TOKEN", "SLACK_USER_TOKEN"] },
];

const manualDeniedLiveEnv = [
  { label: "denied Slack user ID", names: ["OPERANT_LIVE_DENIED_USER_ID"] },
];

const requiredSeedEnv = [
  { label: "Slack app token", names: ["OPERANT_LIVE_SLACK_APP_TOKEN", "SLACK_APP_TOKEN"] },
  { label: "model API key", names: ["OPERANT_LIVE_MODEL_API_KEY", "MODEL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] },
];

const syntheticCredentialEnv = {
  OPERANT_LIVE_ADMIN_SLACK_USER_ID: "UOPERANTSMOKEADMIN",
  SLACK_CHANNEL_ID: "COPERANTSMOKE",
  SLACK_BOT_TOKEN: "xoxb-operant-compose-smoke-bot",
  SLACK_APP_TOKEN: "xapp-operant-compose-smoke-app",
  SLACK_USER_TOKEN: "xoxp-operant-compose-smoke-user",
  OPERANT_LIVE_MODEL_PROVIDER: "openai",
  MODEL_PROVIDER: "openai",
  OPENAI_API_KEY: "sk-operant-compose-smoke-model",
  OPERANT_SYNTHETIC_SLACK_USER_ID: "UOPERANTSMOKEUSER",
  OPERANT_SYNTHETIC_GITHUB_TOKEN: "ghp-operant-compose-smoke-integration",
  OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON: JSON.stringify([
    {
      kind: "github",
      key: "api-token",
      label: "Synthetic GitHub API token",
      secretValueEnv: "OPERANT_SYNTHETIC_GITHUB_TOKEN",
    },
  ]),
};

const placeholderEnvValues = new Set([
  "U...",
  "C...",
  "D...",
  "xapp-...",
  "xoxb-...",
  "xoxe-...",
  "xoxp-test-user-token",
  "xoxp-allowed-test-user-token",
  "xoxp-denied-test-user-token",
  "sk-...",
  "operant_admin_...",
]);

const composeEvidenceInputs = [
  "package.json",
  "pnpm-lock.yaml",
  "README.md",
  "docs/setup.md",
  "docs/acceptance.md",
  "docs/openclaw/reuse-map.md",
  ".env.example",
  ".gitignore",
  ".dockerignore",
  "docker-compose.yml",
  "docker-compose.sandbox.yml",
  "apps/control-plane/package.json",
  "apps/control-plane/tsconfig.json",
  "apps/control-plane/Dockerfile",
  "apps/control-plane/migrations/001_initial.sql",
  "apps/control-plane/migrations/002_retention_processing.sql",
  "apps/control-plane/migrations/003_admin_sessions.sql",
  "apps/control-plane/migrations/004_approval_decisions.sql",
  "apps/control-plane/migrations/005_job_run_id_idempotency.sql",
  "apps/control-plane/public/favicon.svg",
  "apps/control-plane/public/index.html",
  "apps/control-plane/public/app.js",
  "apps/control-plane/public/styles.css",
  "apps/control-plane/src/auth.ts",
  "apps/control-plane/src/db.ts",
  "apps/control-plane/src/openclaw-ops.ts",
  "apps/control-plane/src/server.ts",
  "apps/control-plane/src/openclaw-config.ts",
  "apps/control-plane/src/policy.ts",
  "apps/control-plane/src/rbac.ts",
  "apps/control-plane/src/redaction.ts",
  "apps/control-plane/src/retention.ts",
  "apps/control-plane/src/schema.ts",
  "apps/control-plane/src/secrets.ts",
  "apps/control-plane/src/seed.ts",
  "deploy/openclaw/Dockerfile.sandbox",
  "deploy/openclaw/Dockerfile.sandbox-runtime",
  "deploy/openclaw/Dockerfile.gateway",
  "deploy/openclaw/ensure-slack-plugin.sh",
  "deploy/openclaw/operant-secret-resolver.mjs",
  "deploy/slack/README.md",
  "deploy/slack/manifest.yaml",
  "deploy/slack/live.env.example",
  "scripts/operant-init-env.mjs",
  "scripts/operant-verify-compose.mjs",
  "scripts/operant-verify-deploy.mjs",
  "scripts/operant-compose.mjs",
  "scripts/operant-dashboard-e2e.mjs",
  "scripts/operant-compose-e2e.mjs",
  "scripts/operant-live-e2e.mjs",
  "scripts/slack-manifest-probe.mjs",
  "scripts/slack-user-token-exchange.mjs",
  "scripts/slack-scope-contract.mjs",
  "scripts/operant-report-redaction.mjs",
  "scripts/operant-verify-report-redaction.mjs",
  "scripts/operant-doctor.mjs",
  "scripts/operant-completion-audit.mjs",
  "scripts/operant-verify-completion-audit.mjs",
  "scripts/operant-final-report.mjs",
  "scripts/operant-local-acceptance.mjs",
];

const steps = [];

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function booleanEnv(env, name) {
  return /^(1|true|yes)$/i.test(String(env[name] || "").trim());
}

function manualSlackPostsEnabled(env = process.env) {
  return manualSlackPostsFlag || booleanEnv(env, "OPERANT_LIVE_MANUAL_SLACK_POSTS");
}

function manualSlackNudgeEnabled(env = process.env) {
  return manualSlackNudgeFlag || booleanEnv(env, "OPERANT_LIVE_MANUAL_SLACK_NUDGE");
}

function deniedUseAllowedUserEnabled(env = process.env) {
  if (hasFlag("--denied-use-allowed-user") || booleanEnv(env, "OPERANT_LIVE_DENIED_USE_ALLOWED_USER")) return true;
  if (skipDeniedUserProbe) return false;
  return !hasDistinctDeniedUserConfigured(env);
}

function hasDistinctDeniedUserConfigured(env = process.env) {
  return Boolean(
    argValue("--denied-user-token", firstEnv(env, ["OPERANT_LIVE_DENIED_USER_TOKEN"])) ||
      argValue("--denied-user-id", firstEnv(env, ["OPERANT_LIVE_DENIED_USER_ID"])),
  );
}

function requiredLiveEnvForEnv(env, options = {}) {
  const includeDeniedUser = options.includeDeniedUser ?? !skipDeniedUserProbe;
  const tokenGroups = tokenLiveEnv.filter((group) => group.names[0] !== "OPERANT_LIVE_DENIED_USER_TOKEN" || !includeDeniedUser || !deniedUseAllowedUserEnabled(env));
  return [
    ...requiredLiveEnv,
    ...(manualSlackPostsEnabled(env) ? (includeDeniedUser && !deniedUseAllowedUserEnabled(env) ? manualDeniedLiveEnv : []) : tokenGroups),
  ];
}

function printUsage() {
  process.stdout.write(`Usage: operant-compose-e2e [options]

Runs the strict Docker Compose acceptance gate. By default this requires live
Slack/model credentials and writes .operant/compose-e2e-report.json.

Common options:
  --env <path>                         Compose env file
  --live-env <path>                    Private live Slack/model env overlay
  --report <path>                      Evidence report output path
  --file <path>, -f <path>             Additional Compose overlay file
  --profile <name>                     Docker Compose profile, repeatable
  --allow-blocked                      Write blocked evidence instead of failing hard
  --manual-slack-posts                 Wait for human-posted Slack probes instead of verifier user tokens
  --manual-slack-nudge                 In manual mode, ask the bot to post copy/paste prompts for humans
  --manual-user-id <id>                Allowed human Slack user ID for manual probes
  --denied-use-allowed-user            Temporarily deny the allowed test user for the denied-user probe.
                                      This is the default when no distinct denied user is configured.
  --skip-live                          Skip live Slack/OpenClaw probes
  --synthetic-credential-seed          Seed synthetic non-live credentials
  --skip-completion-audit              Skip final completion audit step
  --down --down-volumes                Tear down Compose resources after run
  --self-test-arg-validation           Run CLI argument validation self-test
  --self-test-report-redaction         Run report redaction self-test
  --help, -h                           Show this help
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
    ".operant/test.env",
    "--live-env",
    ".operant/test.live.env",
    "--report",
    ".operant/test-compose-report.json",
    "--file",
    "docker-compose.sandbox.yml",
    "-f",
    "extra.yml",
    "--compose-file",
    "another.yml",
    "--profile",
    "queue",
    "--base-url",
    "http://127.0.0.1:8080",
    "--restart-services",
    "policy-audit,openclaw-gateway",
    "--health-timeout-ms",
    "1000",
    "--poll-interval-ms",
    "100",
    "--timeout-ms",
    "1000",
    "--records-timeout-ms",
    "1000",
    "--denied-timeout-ms",
    "1000",
    "--approval-completion-timeout-ms",
    "1000",
    "--admin-slack-user-id",
    "UADMIN",
    "--channel-id",
    "CCHANNEL",
    "--slack-team-id",
    "TTEAM",
    "--bot-user-id",
    "UBOT",
    "--dm-channel-id",
    "DDM",
    "--denied-user-token",
    "xoxp-denied",
    "--denied-user-id",
    "UDENIED",
    "--openclaw-checks",
    "status,doctor",
    "--expect-reply-regex",
    "done",
    "--approval-completion-regex",
    "approved",
    "--approval-prompt",
    "Use the exec tool to run exactly: echo operant-approval",
    "--prompt",
    "hello",
    "--manual-user-id",
    "UALLOWED",
    "--allow-blocked",
    "--manual-slack-posts",
    "--manual-slack-nudge",
    "--denied-use-allowed-user",
    "--skip-live",
    "--synthetic-credential-seed",
    "--skip-completion-audit",
    "--down",
    "--down-volumes",
  ]);
  assertValidationFails(["--helpful"], "Unknown option");
  assertValidationFails(["--env"], "requires a value");
  assertValidationFails(["--report", "--allow-blocked"], "requires a value");
  const missingAssistantScopeOutput = "Slack bot token is missing required OpenClaw Slack bot scopes: assistant:write. Update the Slack app OAuth scopes from deploy/slack/manifest.yaml.";
  if (!isBlockedLivePreflightOutput(missingAssistantScopeOutput)) {
    throw new Error("Compose E2E argument validation self-test did not detect missing assistant:write as a blocked live preflight");
  }
  const socketModeDisabledOutput = "Slack app token apps.connections.open returned a WebSocket URL, but Slack says Socket Mode is not turned on. Enable Socket Mode for this Slack app, save the app, reinstall or re-authorize it, and rerun live preflight.";
  if (!isBlockedLivePreflightOutput(socketModeDisabledOutput)) {
    throw new Error("Compose E2E argument validation self-test did not detect disabled Socket Mode as a blocked live preflight");
  }
  const socketModeDetail = livePreflightBlockedDetail(socketModeDisabledOutput);
  if (!socketModeDetail.includes("Socket Mode is disabled") || socketModeDetail.includes("Enable Socket Mode")) {
    throw new Error("Compose E2E argument validation self-test did not format disabled Socket Mode blockers cleanly");
  }
  const missingMultipleScopesOutput = "Slack bot token is missing required OpenClaw Slack bot scopes: assistant:write, im:read. Update the Slack app OAuth scopes.";
  const blockedDetail = livePreflightBlockedDetail(missingMultipleScopesOutput);
  if (!blockedDetail.includes("assistant:write, im:read") || blockedDetail.includes("Update the Slack app")) {
    throw new Error("Compose E2E argument validation self-test did not format missing Slack scope blockers cleanly");
  }
  if (isBlockedLivePreflightOutput("Slack bot token failed auth.test with invalid_auth")) {
    throw new Error("Compose E2E argument validation self-test classified an unrelated live preflight failure as blocked");
  }
  const appAuthoredOutput = "Live E2E failed: Slack mention verifier post was app-authored (bot_id/app_id present) even though the token auth.test resolved to UALLOWED.";
  if (!isBlockedLiveE2eOutput(appAuthoredOutput) || !liveE2eBlockedDetail(appAuthoredOutput).includes("human-authored verifier posts")) {
    throw new Error("Compose E2E argument validation self-test did not classify app-authored Slack verifier posts as blocked");
  }
  const postRestartPrompt = defaultPostRestartPrompt("abc123ef");
  if (!postRestartPrompt.includes("abc123ef") || !postRestartPrompt.includes("post-restart E2E")) {
    throw new Error("Compose E2E argument validation self-test did not include a nonce in the post-restart prompt");
  }
  assertComposeDownVolumesGuard({ OPERANT_COMPOSE_PROJECT_NAME: "operant-smoke" });
  assertDownVolumesGuardFails({ OPERANT_COMPOSE_PROJECT_NAME: "operant" }, "default OPERANT_COMPOSE_PROJECT_NAME");
  assertDownVolumesGuardFails({ OPERANT_COMPOSE_PROJECT_NAME: "Acme Prod" }, "invalid OPERANT_COMPOSE_PROJECT_NAME");
  assertDownVolumesGuardFails({}, "explicit OPERANT_COMPOSE_PROJECT_NAME");
  process.stdout.write("Compose E2E argument validation self-test passed.\n");
}

function assertDownVolumesGuardFails(env, expectedMessage) {
  try {
    assertComposeDownVolumesGuard(env);
  } catch (error) {
    if (String(error.message).includes(expectedMessage)) return;
    throw new Error(`Expected down-volume guard error containing "${expectedMessage}", got "${error.message}"`);
  }
  throw new Error(`Expected down-volume guard failure for env: ${JSON.stringify(env)}`);
}

function repeatedArg(name) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    if (process.argv[index] !== name) continue;
    const value = process.argv[index + 1];
    if (value && !value.startsWith("--")) values.push(value);
  }
  return values;
}

function repeatedArgs(names) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    if (!names.includes(process.argv[index])) continue;
    const value = process.argv[index + 1];
    if (value && !value.startsWith("--")) values.push(value);
  }
  return values;
}

function isBaseComposeFile(file) {
  return path.resolve(repoRoot, file) === path.join(repoRoot, "docker-compose.yml");
}

function numericArg(name, fallback, envName) {
  const value = Number(argValue(name, (envName ? process.env[envName] : "") || fallback));
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number`);
  return value;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function composeCommand(args) {
  return ["docker", "compose", ...composeFileArgs, "--env-file", envPath, ...composeProfileArgs, ...args].map(shellQuote).join(" ");
}

function pnpmCommand(script, args = []) {
  return ["pnpm", script, ...args.map(shellQuote)].join(" ");
}

function record(status, name, detail = "", evidence = undefined) {
  const safeDetail = redactConsole(detail);
  const step = { status, name, detail: safeDetail, recordedAt: new Date().toISOString() };
  if (evidence !== undefined) step.evidence = redactSecretMaterial(evidence, consoleSensitiveValues);
  steps.push(step);
  const suffix = safeDetail ? `: ${safeDetail}` : "";
  process.stdout.write(`${status.toUpperCase()} ${name}${suffix}\n`);
}

function hasPassedStep(name) {
  return steps.some((step) => step.status === "pass" && step.name === name);
}

function strictFinalGateEnabled() {
  return !skipLive
    && !skipCredentialSeed
    && !skipRestart
    && !skipPostRestartLive
    && !skipDmProbe
    && !skipDeniedUserProbe
    && !skipSlackApprovalProbe
    && !skipSlackApprovalCompletion
    && !skipApprovalProbe
    && !skipLivePreflight
    && !skipSlackAuthTest
    && !skipModelAuthTest;
}

async function fileSha256(file) {
  return createHash("sha256").update(await readFile(resolveEvidenceFile(file))).digest("hex");
}

function resolveEvidenceFile(file) {
  return path.isAbsolute(file) ? file : path.join(repoRoot, file);
}

async function liveReportDescriptor(livePath, stepName, required) {
  const descriptor = { path: livePath, required, step: stepName };
  const currentStep = steps.find((step) => step.name === stepName && !["blocked", "skip"].includes(step.status));
  if (!currentStep) return descriptor;
  try {
    const absolutePath = path.resolve(repoRoot, livePath);
    const body = await readFile(absolutePath, "utf8");
    descriptor.sha256 = createHash("sha256").update(body).digest("hex");
    try {
      descriptor.generatedAt = JSON.parse(body).generatedAt || "";
    } catch {
      descriptor.generatedAt = "";
    }
  } catch {
    // Missing live reports are handled by the completion audit when the strict gate reaches them.
  }
  return descriptor;
}

async function evidenceInputFingerprints() {
  const inputs = Array.from(new Set([...composeEvidenceInputs, ...composeFiles]));
  return Promise.all(inputs.map(async (file) => ({
    file,
    sha256: await fileSha256(file),
  })));
}

async function buildReport(phase) {
  const blockedSteps = steps.filter((step) => step.status === "blocked");
  const failedSteps = steps.filter((step) => step.status === "fail");
  const requiredSteps = [
    "Compose config",
    "Compose up",
    "Operant health/ready",
    "credential/config seed",
    "credential/config verification",
    "Live preflight",
    "Operant doctor",
    "Live Slack/OpenClaw E2E",
    "Compose restart",
    "Post-restart doctor",
    "Post-restart live Slack/OpenClaw E2E",
  ];
  const missingRequiredSteps = requiredSteps.filter((name) => !hasPassedStep(name));
  const strict = strictFinalGateEnabled();
  const runtimePassed = blockedSteps.length === 0 && failedSteps.length === 0;
  const readyForCompletionAudit = strict && blockedSteps.length === 0 && failedSteps.length === 0 && missingRequiredSteps.length === 0;
  const completionAuditPassed = hasPassedStep("Completion audit");
  const liveReports = {
    preRestart: await liveReportDescriptor(preRestartLiveReportPath, "Live Slack/OpenClaw E2E", strict),
    postRestart: await liveReportDescriptor(postRestartLiveReportPath, "Post-restart live Slack/OpenClaw E2E", strict),
  };
  return {
    format: "operant.compose-e2e-report.v1",
    phase,
    generatedAt: new Date().toISOString(),
    baseUrl,
    envPath,
    liveEnvPath: liveEnvPath || undefined,
    reportPath,
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    evidenceInputs: await evidenceInputFingerprints(),
    liveReports,
    mode: nonLiveSmoke ? "non-live-smoke" : "strict-e2e",
    runtimePassed,
    smokePassed: nonLiveSmoke ? runtimePassed : undefined,
    strictFinalGate: strict,
    readyForCompletionAudit,
    passed: readyForCompletionAudit && completionAuditPassed,
    options: {
      skipLive,
      skipCredentialSeed,
      skipRestart,
      skipPostRestartLive,
      skipCompletionAudit,
      skipDmProbe,
      skipDeniedUserProbe,
      skipSlackApprovalProbe,
      skipSlackApprovalCompletion,
      manualSlackPosts: manualSlackPostsEnabled(reportSensitiveEnv),
      manualSlackNudge: manualSlackNudgeEnabled(reportSensitiveEnv),
      skipApprovalProbe,
      skipLivePreflight,
      skipSlackAuthTest,
      skipModelAuthTest,
      downAfter,
      downVolumes,
      restartServices,
      composeProfiles,
      composeFiles,
    },
    missingRequiredSteps,
    totals: {
      steps: steps.length,
      passed: steps.filter((step) => step.status === "pass").length,
      skipped: steps.filter((step) => step.status === "skip").length,
      blocked: blockedSteps.length,
      failed: failedSteps.length,
    },
    steps,
  };
}

async function writeReport(phase) {
  const report = await buildReport(phase);
  const sensitiveValues = sensitiveEnvValues([process.env, reportSensitiveEnv]);
  const archiveExisting = !selfTestReportRedaction && !reportArchiveAttempted;
  reportArchiveAttempted = true;
  const { report: redactedReport, archivedPath } = await writeRedactedJsonReport(reportPath, report, sensitiveValues, { archiveExisting });
  if (archivedPath) process.stdout.write(`Archived previous Compose E2E report: ${archivedPath}\n`);
  return redactedReport;
}

async function runReportRedactionSelfTest(env) {
  record(
    "pass",
    "Compose report redaction self-test",
    [
      firstEnv(env, ["OPERANT_ADMIN_LOGIN_TOKEN"]),
      firstEnv(env, ["SLACK_BOT_TOKEN", "OPERANT_LIVE_SLACK_BOT_TOKEN"]),
      firstEnv(env, ["OPENAI_API_KEY", "MODEL_API_KEY", "OPERANT_LIVE_MODEL_API_KEY"]),
      "xoxb-unlisted-compose-report-redaction-token",
    ].filter(Boolean).join(" "),
  );
  await writeReport("redaction-self-test");
  const body = await readFile(reportPath, "utf8");
  const sensitiveValues = sensitiveEnvValues([process.env, env]);
  assertNoSecretMaterial(JSON.parse(body), sensitiveValues);
  if (!body.includes("[redacted]")) throw new Error("Compose report redaction self-test did not write redacted markers");
  process.stdout.write("Compose report redaction self-test passed.\n");
}

function blocked(name, detail) {
  record("blocked", name, detail);
}

function firstEnv(env, names, fallback = "") {
  for (const name of names) {
    if (env[name]) return env[name];
  }
  return fallback;
}

function assertComposeDownVolumesGuard(env) {
  const projectName = String(env.OPERANT_COMPOSE_PROJECT_NAME || "").trim();
  if (!projectName) {
    throw new Error("Refusing --down-volumes without an explicit OPERANT_COMPOSE_PROJECT_NAME in the selected env file.");
  }
  if (!/^[a-z0-9][a-z0-9_-]*$/.test(projectName)) {
    throw new Error(`Refusing --down-volumes with invalid OPERANT_COMPOSE_PROJECT_NAME "${projectName}".`);
  }
  if (projectName === "operant") {
    throw new Error("Refusing --down-volumes for default OPERANT_COMPOSE_PROJECT_NAME=operant; use a unique per-run or per-workspace Compose project name.");
  }
  const composeProjectName = String(firstEnv(env, ["COMPOSE_PROJECT_NAME", "OPERANT_COMPOSE_PROJECT_NAME"], projectName)).trim();
  if (composeProjectName !== projectName) {
    throw new Error(`Refusing --down-volumes because COMPOSE_PROJECT_NAME (${composeProjectName}) does not match OPERANT_COMPOSE_PROJECT_NAME (${projectName}).`);
  }
  return projectName;
}

function firstNonPlaceholderEnv(env, names) {
  for (const name of names) {
    if (env[name] && !isPlaceholderValue(env[name])) return env[name];
  }
  return "";
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
    ? "provider-specific model keys are only accepted when MODEL_PROVIDER matches that provider"
    : "provider-specific keys are ignored for non-built-in providers";
  return `model API key for provider ${provider} is missing or still a placeholder (${accepted}); ${providerHint}`;
}

function isPlaceholderValue(value) {
  const trimmed = String(value || "").trim();
  return (
    placeholderEnvValues.has(trimmed) ||
    trimmed.includes("...") ||
    /^<[^>]+>$/.test(trimmed) ||
    /^change-me/i.test(trimmed) ||
    /^your-/i.test(trimmed)
  );
}

function adminLoginBody(env, slackUserId) {
  const adminLoginToken = firstEnv(env, ["OPERANT_ADMIN_LOGIN_TOKEN"]);
  if (!adminLoginToken || isPlaceholderValue(adminLoginToken)) throw new Error("Missing or placeholder OPERANT_ADMIN_LOGIN_TOKEN in the Compose env file");
  return { slackUserId, adminLoginToken };
}

function missingEnvGroups(env, groups) {
  return groups.filter((group) => {
    const value = firstEnv(env, group.names);
    return !value || isPlaceholderValue(value);
  });
}

function envGroupValue(env, group) {
  for (const name of group.names) {
    if (env[name]) return { name, value: String(env[name]).trim() };
  }
  return null;
}

function missingEnvGroupDetail(env, group) {
  const names = group.names.join("|");
  const found = envGroupValue(env, group);
  if (!found) return `${names} (missing)`;
  const lowerLabel = group.label.toLowerCase();
  if (lowerLabel.includes("user token")) {
    if (/^[UW][A-Z0-9]{2,}$/.test(found.value)) {
      return `${names} (${found.name} is a Slack user ID; use a temporary human user OAuth token such as xoxp-/xoxc-, not U...)`;
    }
    if (/^xoxb-/i.test(found.value)) {
      return `${names} (${found.name} is a bot token; use a temporary human user OAuth token such as xoxp-/xoxc-)`;
    }
    return `${names} (${found.name} is a placeholder; use a temporary human user OAuth token such as xoxp-/xoxc-)`;
  }
  return `${names} (${found.name} is a placeholder)`;
}

function missingEnvGroupDetails(env, groups) {
  return groups.map((group) => missingEnvGroupDetail(env, group)).join(", ");
}

function commaList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function assertNoPlaintextSecrets(payload, secrets) {
  const body = JSON.stringify(payload);
  const leaked = secrets.filter((secret) => secret && String(secret).length >= 8 && body.includes(String(secret)));
  if (leaked.length > 0) throw new Error(`Payload leaked ${leaked.length} plaintext secret value(s)`);
}

function assertIncludesAll(label, actual, expected) {
  if (!Array.isArray(actual)) throw new Error(`${label} is not an array`);
  const missing = expected.filter((value) => !actual.includes(value));
  if (missing.length > 0) throw new Error(`${label} missing expected value(s): ${missing.join(", ")}`);
}

function parseIntegrationCredentialSeeds(env) {
  const json = firstEnv(env, ["OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON"]);
  if (json) {
    let parsed;
    try {
      parsed = JSON.parse(json);
    } catch (error) {
      throw new Error(`OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON is not valid JSON: ${error.message}`);
    }
    if (!Array.isArray(parsed)) throw new Error("OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON must be a JSON array");
    return parsed.map((item, index) => {
      const secretValue = item.secretValue ?? (item.secretValueEnv ? env[item.secretValueEnv] : "");
      if (!item.kind || !item.key || !secretValue) {
        throw new Error(`Integration credential JSON item ${index} requires kind, key, and secretValue or secretValueEnv`);
      }
      return {
        kind: String(item.kind),
        key: String(item.key),
        label: item.label ? String(item.label) : undefined,
        secretValue: String(secretValue),
      };
    });
  }

  return commaList(firstEnv(env, ["OPERANT_LIVE_INTEGRATION_CREDENTIALS"])).map((spec) => {
    const separator = spec.indexOf("=");
    if (separator === -1) throw new Error(`Integration credential spec "${spec}" must use kind/key=ENV_VAR`);
    const pathPart = spec.slice(0, separator);
    const envName = spec.slice(separator + 1);
    const slash = pathPart.indexOf("/");
    if (slash === -1) throw new Error(`Integration credential spec "${spec}" must use kind/key=ENV_VAR`);
    const kind = pathPart.slice(0, slash);
    const key = pathPart.slice(slash + 1);
    const secretValue = env[envName];
    if (!kind || !key || !envName || !secretValue) throw new Error(`Integration credential spec "${spec}" references a missing value`);
    return { kind, key, label: `${kind}:${key}`, secretValue };
  });
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

function setConsoleRedactionEnv(...sources) {
  consoleSensitiveValues = sensitiveEnvValues([process.env, ...sources]);
}

function isLiveOverrideEnvKey(key) {
  return key.startsWith("OPERANT_LIVE_") ||
    key.startsWith("SLACK_") ||
    ["MODEL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCLAW_DOCKER_SOCKET", "OPENCLAW_DOCKER_GID"].includes(key);
}

function redactConsole(value) {
  return redactString(String(value ?? ""), consoleSensitiveValues);
}

function writeStdout(value) {
  if (value) process.stdout.write(redactConsole(value));
}

function writeStderr(value) {
  if (value) process.stderr.write(redactConsole(value));
}

async function fileExists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
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
    if (child.stdout) child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      if (!options.quiet) writeStdout(text);
    });
    if (child.stderr) child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr += text;
      if (!options.quiet) writeStderr(text);
    });
    child.on("error", (error) => resolve({ code: 1, stdout, stderr: error.message }));
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseJsonFromOutput(output) {
  const starts = [output.indexOf("{"), output.indexOf("[")].filter((index) => index >= 0).sort((a, b) => a - b);
  for (const start of starts) {
    try {
      return JSON.parse(output.slice(start));
    } catch {
      // Keep trying in case a diagnostic line preceded the JSON payload.
    }
  }
  return null;
}

async function requireCommand(name, command, env) {
  const result = await run(command, { quiet: true, env });
  if (result.code !== 0) {
    blocked(name, `${command} failed or is unavailable`);
    return false;
  }
  record("pass", name, (result.stdout || result.stderr).trim().split(/\r?\n/)[0]);
  return true;
}

async function waitForRoute(route) {
  const url = new URL(route, baseUrl);
  const deadline = Date.now() + healthTimeoutMs;
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(Math.min(pollIntervalMs, 10_000)) });
      if (response.ok) return;
      lastError = `${response.status} ${response.statusText}`;
    } catch (error) {
      lastError = error.message;
    }
    await sleep(pollIntervalMs);
  }
  throw new Error(`Timed out waiting for ${url}; last error: ${lastError}`);
}

async function waitForOperant() {
  process.stdout.write(`Waiting for Operant at ${baseUrl}\n`);
  await waitForRoute("/healthz");
  await waitForRoute("/readyz");
  record("pass", "Operant health/ready", baseUrl);
}

async function jsonFetch(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { raw: text };
    }
  }
  return { response, payload };
}

async function operant(route, options = {}) {
  const headers = { accept: "application/json" };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  const { response, payload } = await jsonFetch(new URL(route, baseUrl), {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (!response.ok) {
    throw new Error(`Operant ${options.method || "GET"} ${route} failed: ${payload?.error || response.statusText || response.status}`);
  }
  return payload;
}

async function optionalOperant(route, options = {}) {
  try {
    return await operant(route, options);
  } catch {
    return null;
  }
}

async function slackAuthTest(token, env) {
  const base = firstEnv(env, ["SLACK_API_BASE_URL"], "https://slack.com/api").replace(/\/$/, "");
  const { response, payload } = await jsonFetch(`${base}/auth.test`, {
    method: "POST",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
  });
  if (!response.ok || !payload?.ok) throw new Error(`Slack auth.test failed: ${payload?.error || response.statusText || response.status}`);
  return payload;
}

async function seedCredentials(env) {
  if (skipCredentialSeed) {
    record("skip", "credential/config seed", "--skip-credential-seed");
    return;
  }
  const seedEnv = syntheticCredentialSeed ? { ...env, ...syntheticCredentialEnv } : env;
  if (syntheticCredentialSeed) {
    reportSensitiveEnv = { ...reportSensitiveEnv, ...syntheticCredentialEnv };
    setConsoleRedactionEnv(reportSensitiveEnv, syntheticCredentialEnv);
  }
  const adminSlackUserId = firstEnv(seedEnv, ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"]);
  const channelId = firstEnv(seedEnv, ["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"]);
  const botToken = firstEnv(seedEnv, ["OPERANT_LIVE_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN"]);
  const appToken = firstEnv(seedEnv, ["OPERANT_LIVE_SLACK_APP_TOKEN", "SLACK_APP_TOKEN"]);
  const userToken = firstEnv(seedEnv, ["OPERANT_LIVE_SLACK_USER_TOKEN", "SLACK_USER_TOKEN"]);
  const manualSlackPosts = manualSlackPostsEnabled(seedEnv);
  const manualUserId = argValue(
    "--manual-user-id",
    firstNonPlaceholderEnv(seedEnv, ["OPERANT_LIVE_ALLOWED_USER_ID"]) || adminSlackUserId,
  );
  const modelProvider = modelProviderForEnv(seedEnv);
  const modelApiKey = modelApiKeyForProvider(seedEnv, modelProvider);
  if (!modelApiKey) {
    throw new Error(modelCredentialErrorForProvider(seedEnv, modelProvider) || `Missing model API key for provider ${modelProvider}; expected one of ${modelApiKeyEnvNamesForProvider(modelProvider).join("|")}`);
  }
  const modelName = firstEnv(seedEnv, ["OPERANT_LIVE_MODEL_NAME", "MODEL_NAME"], modelProvider === "anthropic" ? "claude-sonnet-4.5" : "gpt-5");
  const userIdentity = syntheticCredentialSeed
    ? { user_id: firstEnv(seedEnv, ["OPERANT_SYNTHETIC_SLACK_USER_ID"]) }
    : manualSlackPosts
      ? { user_id: manualUserId }
    : await slackAuthTest(userToken, seedEnv);
  if (!userIdentity.user_id) throw new Error("Could not infer an allowed Slack user ID for the live credential seed");
  const allowedDmUserIds = Array.from(new Set([
    adminSlackUserId,
    userIdentity.user_id,
    ...commaList(firstEnv(seedEnv, ["OPERANT_LIVE_ALLOWED_DM_USER_IDS"])),
  ].filter(Boolean)));
  const allowedChannelIds = Array.from(new Set([
    channelId,
    ...commaList(firstEnv(seedEnv, ["OPERANT_LIVE_ALLOWED_CHANNEL_IDS"])),
  ].filter(Boolean)));
  const approvalSlackUserIds = Array.from(new Set([
    adminSlackUserId,
    ...commaList(firstEnv(seedEnv, ["OPERANT_LIVE_APPROVER_SLACK_USER_IDS"])),
  ].filter(Boolean)));

  const login = await optionalOperant("/api/auth/login", {
    method: "POST",
    body: adminLoginBody(seedEnv, adminSlackUserId),
  });
  const slackTeamId = argValue("--slack-team-id", firstEnv(seedEnv, ["OPERANT_LIVE_SLACK_TEAM_ID", "SLACK_TEAM_ID"]));
  const seeded = await operant("/api/config/credentials", {
    method: "POST",
    token: login?.token,
    body: {
      companyName: firstEnv(seedEnv, ["OPERANT_LIVE_COMPANY_NAME"], seedEnv.OPERANT_DEFAULT_COMPANY_NAME || "Operant Live E2E"),
      workspaceName: firstEnv(seedEnv, ["OPERANT_LIVE_WORKSPACE_NAME"], seedEnv.OPERANT_DEFAULT_WORKSPACE_NAME || "Operant Live Workspace"),
      ...(slackTeamId ? { slackTeamId } : {}),
      slackBotToken: botToken,
      slackAppToken: appToken,
      modelProvider,
      modelName,
      modelApiKey,
      adminLoginToken: firstEnv(env, ["OPERANT_ADMIN_LOGIN_TOKEN"]),
      adminSlackUserId,
      allowedDmUserIds,
      allowedChannelIds,
      approvalSlackUserIds,
    },
  });
  record("pass", "credential/config seed", syntheticCredentialSeed ? `synthetic checksum ${seeded.checksum}` : `checksum ${seeded.checksum}`);
  await verifySeededConfig(seedEnv, {
    adminSlackUserId,
    channelId,
    userSlackUserId: userIdentity.user_id,
    allowedDmUserIds,
    allowedChannelIds,
    approvalSlackUserIds,
    modelProvider,
    modelName,
    secrets: [botToken, appToken, modelApiKey],
    synthetic: syntheticCredentialSeed,
  });
  await seedIntegrationCredentials(seedEnv, adminSlackUserId);
}

async function verifySeededConfig(env, expected) {
  const login = await operant("/api/auth/login", {
    method: "POST",
    body: adminLoginBody(env, expected.adminSlackUserId),
  });
  if (!login.token) throw new Error("Operant login after credential seed did not return a bearer token");
  const generated = await operant("/api/openclaw/config", {
    method: "POST",
    token: login.token,
    body: {},
  });
  assertNoPlaintextSecrets(generated.config, expected.secrets);
  const slack = generated.config?.channels?.slack;
  if (slack?.enabled !== true || slack?.mode !== "socket") throw new Error("Generated OpenClaw config did not enable Slack Socket Mode");
  if (slack.botToken?.source !== "exec" || slack.appToken?.source !== "exec") {
    throw new Error("Generated OpenClaw config did not use SecretRefs for Slack tokens");
  }
  const modelProvider = modelProviderForEnv(env);
  const modelConfig = generated.config?.models?.providers?.[modelProvider];
  if (modelConfig?.apiKey?.source !== "exec") throw new Error("Generated OpenClaw config did not use a SecretRef for the model API key");
  const expectedPrimaryModel = `${modelProvider}/${expected.modelName}`;
  const primaryModel = generated.config?.agents?.defaults?.model?.primary;
  if (primaryModel !== expectedPrimaryModel) {
    throw new Error(`Generated OpenClaw config primary model ${primaryModel || "(missing)"} did not match ${expectedPrimaryModel}`);
  }
  assertIncludesAll("Generated OpenClaw config DM allowlist", slack.allowFrom, expected.allowedDmUserIds);
  for (const channelId of expected.allowedChannelIds) {
    const channel = slack.channels?.[channelId];
    if (!channel?.enabled) throw new Error(`Generated OpenClaw config did not enable expected channel ${channelId}`);
    if (channel.requireMention !== true) {
      throw new Error(`Generated OpenClaw config channel ${channelId} did not require mentions`);
    }
    if (Array.isArray(channel.users) && channel.users.length > 0) {
      throw new Error(`Generated OpenClaw config channel ${channelId} unexpectedly scoped channel users: ${channel.users.join(", ")}`);
    }
  }
  if (!slack.execApprovals?.enabled) throw new Error("Generated OpenClaw config did not enable exec approval policy");
  assertIncludesAll("Generated OpenClaw config exec approval approvers", slack.execApprovals.approvers, expected.approvalSlackUserIds);
  await verifyCredentialSecretRefsResolve(env, [
    { label: "Slack bot token", ref: slack.botToken, value: expected.secrets[0] },
    { label: "Slack app token", ref: slack.appToken, value: expected.secrets[1] },
    { label: "model API key", ref: modelConfig.apiKey, value: expected.secrets[2] },
  ]);
  await verifyGeneratedConfigValidate(login.token, expected.secrets);
  await verifyControlPlaneOpenClawChecks(login.token, expected.secrets, env);
  record("pass", "credential/config verification", `checksum ${generated.checksum}; model ${expectedPrimaryModel}`, {
    checksum: generated.checksum,
    modelProvider,
    modelName: expected.modelName,
    primaryModel,
  });
}

async function verifyGeneratedConfigValidate(token, secrets) {
  const result = await operant("/api/openclaw/checks/config-validate", {
    method: "POST",
    token,
    body: {},
  });
  assertNoPlaintextSecrets(result, secrets);
  if (result.check !== "config-validate" || result.exitCode !== 0 || result.timedOut || result.json?.valid !== true) {
    throw new Error(`OpenClaw config-validate did not complete cleanly after credential seed: ${JSON.stringify(result)}`);
  }
  record("pass", "credential config-validate", "valid: true");
}

async function verifyControlPlaneOpenClawChecks(token, secrets, expectedEnv) {
  const checks = ["status", "tasks-list", "security-audit", "doctor"];
  const evidence = {};
  for (const check of checks) {
    const result = check === "status"
      ? await operantOpenClawStatusWithStartupRetry(token, secrets)
      : await operant(`/api/openclaw/checks/${check}`, {
        method: "POST",
        token,
        body: {},
      });
    assertNoPlaintextSecrets(result, secrets);
    if (result.check !== check || result.exitCode !== 0 || result.timedOut) {
      throw new Error(`Control-plane OpenClaw check ${check} did not complete cleanly: ${JSON.stringify(result)}`);
    }
    if (check === "status") {
      const detail = openClawStatusDetail(result.json, expectedEnv);
      if (detail.evidence.gatewayReachable !== true) throw new Error("Control-plane OpenClaw status did not report a reachable gateway");
      evidence.status = detail.evidence;
      continue;
    }
    if (check === "tasks-list" && !Array.isArray(result.json?.tasks)) {
      throw new Error("Control-plane OpenClaw tasks-list did not return task JSON");
    }
    if (check === "security-audit") {
      const critical = Number(result.json?.summary?.critical ?? result.json?.critical ?? 0);
      if (!Number.isFinite(critical) || critical > 0) throw new Error(`Control-plane OpenClaw security-audit reported ${critical} critical finding(s)`);
      evidence.securityCritical = critical;
    }
    if (check === "doctor") {
      const output = `${result.stdout || ""}\n${result.stderr || ""}`;
      const criticals = output.match(/\bCRITICAL:/g) || [];
      if (criticals.length > 0) throw new Error(`Control-plane OpenClaw doctor reported ${criticals.length} critical finding(s)`);
    }
  }
  record("pass", "control-plane OpenClaw checks", checks.join(","), evidence);
}

async function operantOpenClawStatusWithStartupRetry(token, secrets) {
  const deadline = Date.now() + healthTimeoutMs;
  let result = null;
  let lastReason = "";
  do {
    result = await operant("/api/openclaw/checks/status", {
      method: "POST",
      token,
      body: {},
    });
    assertNoPlaintextSecrets(result, secrets);
    const retryReason = openClawStartupRetryReason(result);
    if (!retryReason) return result;
    lastReason = retryReason;
    if (Date.now() >= deadline) break;
    await sleep(pollIntervalMs);
  } while (Date.now() < deadline);
  throw new Error(`Control-plane OpenClaw status did not become ready within ${healthTimeoutMs}ms; last reason: ${lastReason || "unknown"}`);
}

function openClawStartupRetryReason(result) {
  const gatewayError = typeof result?.json?.gateway?.error === "string" ? result.json.gateway.error : "";
  const output = [gatewayError, result?.stderr, result?.stdout]
    .filter(Boolean)
    .join("\n");
  if (/ECONNREFUSED|connect\s+ECONNREFUSED|gateway.*unreachable|connection refused/i.test(output)) {
    return redactConsole(output).slice(0, 500);
  }
  if (result?.json?.gateway && result.json.gateway.reachable === false) {
    return "gateway not yet reachable";
  }
  if (result?.exitCode !== 0 && /gateway|websocket|socket|connect/i.test(output)) {
    return redactConsole(output || `exit ${result.exitCode}`).slice(0, 500);
  }
  return "";
}

async function verifyCredentialSecretRefsResolve(env, refs) {
  const internalToken = env.OPERANT_INTERNAL_TOKEN;
  if (!internalToken) {
    record("skip", "credential SecretRef resolver", "missing OPERANT_INTERNAL_TOKEN");
    return;
  }
  for (const item of refs) {
    if (item.ref?.source !== "exec" || item.ref?.provider !== "operant" || !item.ref?.id) {
      throw new Error(`${item.label} SecretRef is missing or malformed`);
    }
    const resolved = await operant(`/internal/openclaw/secrets/${encodeURIComponent(item.ref.id)}`, { token: internalToken });
    if (resolved.value !== item.value) throw new Error(`Internal SecretRef resolver did not return ${item.label}`);
  }
  record("pass", "credential SecretRef resolver", `${refs.length} resolved`);
}

async function seedIntegrationCredentials(env, adminSlackUserId) {
  const seeds = parseIntegrationCredentialSeeds(env);
  if (seeds.length === 0) {
    record("skip", "integration credential seed", "no OPERANT_LIVE_INTEGRATION_CREDENTIALS");
    return;
  }
  const login = await operant("/api/auth/login", {
    method: "POST",
    body: adminLoginBody(env, adminSlackUserId),
  });
  if (!login.token) throw new Error("Operant login before integration credential seed did not return a bearer token");

  const saved = [];
  for (const seed of seeds) {
    const result = await operant("/api/integrations/credentials", {
      method: "POST",
      token: login.token,
      body: seed,
    });
    assertNoPlaintextSecrets(result, [seed.secretValue]);
    if (!result.credential?.secret_ref_id) throw new Error(`Integration credential ${seed.kind}/${seed.key} did not return metadata`);
    saved.push({ ...seed, secretRefId: result.credential.secret_ref_id });
  }

  const listed = await operant("/api/integrations/credentials", { token: login.token });
  assertNoPlaintextSecrets(listed, saved.map((seed) => seed.secretValue));
  for (const seed of saved) {
    if (!listed.credentials?.some((credential) => credential.secret_ref_id === seed.secretRefId)) {
      throw new Error(`Integration credential list did not include ${seed.kind}/${seed.key}`);
    }
  }

  const internalToken = env.OPERANT_INTERNAL_TOKEN;
  if (internalToken) {
    for (const seed of saved) {
      const resolved = await operant(`/internal/openclaw/secrets/${encodeURIComponent(seed.secretRefId)}`, { token: internalToken });
      if (resolved.value !== seed.secretValue) throw new Error(`Internal SecretRef resolver did not return ${seed.kind}/${seed.key}`);
    }
    record("pass", "integration credential seed", `${saved.length} saved and resolved`);
  } else {
    record("pass", "integration credential seed", `${saved.length} saved; resolver skipped without OPERANT_INTERNAL_TOKEN`);
  }
}

function isBlockedLivePreflightOutput(output) {
  const body = String(output || "");
  return /missing required OpenClaw Slack bot scopes:[\s\S]*assistant:write/i.test(body)
    || /apps\.connections\.open returned a WebSocket URL,[\s\S]*Socket Mode is not turned on/i.test(body);
}

function livePreflightBlockedDetail(output) {
  const body = String(output || "");
  if (/apps\.connections\.open returned a WebSocket URL,[\s\S]*Socket Mode is not turned on/i.test(body)) {
    return "Slack app setup required; Socket Mode is disabled for the installed app";
  }
  const missingMatch = /missing required OpenClaw Slack bot scopes:\s*([A-Za-z0-9:._-]+(?:\s*,\s*[A-Za-z0-9:._-]+)*)/i.exec(body);
  const missing = missingMatch?.[1]?.trim().replace(/\s+/g, " ") || "assistant:write";
  return `Slack app reinstall/reauthorization required; missing bot scope(s): ${missing}`;
}

function isBlockedLiveE2eOutput(output) {
  const body = String(output || "");
  return /Timed out waiting for [^\n]+ manual Slack message from [A-Z0-9]+ in [A-Z0-9]+/i.test(body)
    || /Slack mention verifier post was app-authored/i.test(body);
}

function liveE2eBlockedDetail(output) {
  const body = String(output || "");
  if (/Slack mention verifier post was app-authored/i.test(body)) {
    return "Slack human-authored verifier posts required; the saved user token posts as the app, so OpenClaw correctly ignores it to avoid bot loops";
  }
  const match = /Timed out waiting for ([^\n]+ manual Slack message from [A-Z0-9]+ in [A-Z0-9]+)/i.exec(body);
  return match ? `Manual Slack participation required; ${match[1]}` : "Manual Slack participation required";
}

async function runStep(name, command, env, options = {}) {
  process.stdout.write(`\n== ${name} ==\n${redactConsole(command)}\n`);
  const result = await run(command, { env });
  if (result.code !== 0) {
    const output = `${result.stdout}\n${result.stderr}`;
    if (options.blockedWhen?.(output)) {
      blocked(name, options.blockedDetail?.(output) || `${name} blocked`);
      return false;
    }
    throw new Error(`${name} failed with exit code ${result.code}`);
  }
  record("pass", name);
  return true;
}

async function runOpenClawGatewayHealth(env, label = "OpenClaw gateway health") {
  const command = composeCommand(["exec", "-T", "openclaw-gateway", "openclaw", "health"]);
  process.stdout.write(`\n== ${label} ==\n${redactConsole(command)}\n`);
  const deadline = Date.now() + healthTimeoutMs;
  let lastOutput = "";
  while (Date.now() < deadline) {
    const result = await run(command, { quiet: true, env });
    if (result.code === 0) {
      writeStdout(result.stdout);
      writeStderr(result.stderr);
      record("pass", label);
      return;
    }
    lastOutput = redactConsole(result.stdout || result.stderr || `exit ${result.code}`).trim();
    await sleep(pollIntervalMs);
  }
  throw new Error(`${label} did not pass within ${healthTimeoutMs}ms; last output: ${lastOutput}`);
}

function openClawGatewayScopedExecArgs(args) {
  return [
    "exec",
    "-T",
    "openclaw-gateway",
    "sh",
    "-lc",
    'exec openclaw "$@" --url ws://127.0.0.1:18789 --token "$OPENCLAW_GATEWAY_TOKEN"',
    "openclaw",
    ...args,
  ];
}

async function runOpenClawGatewayJsonCheck(env, label, args, validate, options = {}) {
  const command = composeCommand(options.gatewayScoped
    ? openClawGatewayScopedExecArgs(args)
    : ["exec", "-T", "openclaw-gateway", "openclaw", ...args]);
  process.stdout.write(`\n== ${label} ==\n${redactConsole(command)}\n`);
  const result = await run(command, { env });
  if (result.code !== 0) {
    const output = `${result.stdout || ""}\n${result.stderr || ""}`;
    if (options.skipWhenPairingRequired && /pairing required|device is not approved/i.test(output)) {
      record("skip", label, "requires paired/approved OpenClaw operator device");
      return;
    }
    throw new Error(`${label} failed with exit code ${result.code}`);
  }
  const parsed = parseJsonFromOutput(result.stdout);
  if (!parsed) throw new Error(`${label} did not return parseable JSON`);
  const validation = validate(parsed);
  if (validation && typeof validation === "object" && !Array.isArray(validation)) {
    record("pass", label, validation.detail || "", validation.evidence);
  } else {
    record("pass", label, validation);
  }
}

function expectedModelNameForEnv(env) {
  const provider = modelProviderForEnv(env);
  return firstEnv(env, ["OPERANT_LIVE_MODEL_NAME", "MODEL_NAME"], provider === "anthropic" ? "claude-sonnet-4.5" : "gpt-5");
}

function openClawStatusDetail(json, expectedEnv = {}) {
  const gatewayError = typeof json.gateway?.error === "string" ? json.gateway.error.trim() : "";
  const expectedModel = expectedModelNameForEnv(expectedEnv);
  const sessionDefaultModel = typeof json.sessions?.defaults?.model === "string" ? json.sessions.defaults.model.trim() : "";
  if (!sessionDefaultModel) throw new Error("OpenClaw status did not report a session default model");
  if (expectedModel && sessionDefaultModel !== expectedModel) {
    throw new Error(`OpenClaw status session default model ${sessionDefaultModel} did not match expected ${expectedModel}`);
  }
  const detail = [`${json.runtimeVersion || "unknown"}`, "gateway reachable"];
  detail.push(`session default model: ${sessionDefaultModel}`);
  if (gatewayError) {
    if (!/missing scope:\s*operator\.read/i.test(gatewayError)) {
      throw new Error(`OpenClaw status returned unexpected gateway error: ${gatewayError}`);
    }
    detail.push(`status scope-limited: ${gatewayError}`);
  }
  return {
    detail: detail.join("; "),
    evidence: {
      runtimeVersion: json.runtimeVersion || "",
      gatewayReachable: json.gateway?.reachable === true,
      sessionDefaultModel,
      expectedModel,
      ...(gatewayError ? { gatewayError } : {}),
      securityCritical: Number(json.securityAudit?.summary?.critical || 0),
    },
  };
}

async function runOpenClawGatewayOperationalChecks(env, expectedEnv = env) {
  await runOpenClawGatewayJsonCheck(env, "OpenClaw status", ["status", "--all", "--json"], (json) => {
    if (json.gateway?.reachable !== true) throw new Error("OpenClaw status did not report a reachable gateway");
    if (Number(json.securityAudit?.summary?.critical || 0) > 0) throw new Error("OpenClaw status embedded security audit reported critical findings");
    return openClawStatusDetail(json, expectedEnv);
  });
  await runOpenClawGatewayJsonCheck(env, "OpenClaw secrets reload", ["secrets", "reload", "--json"], (json) => {
    if (json.ok !== true) throw new Error("OpenClaw secrets reload did not return ok: true");
    return `warningCount: ${Number(json.warningCount || 0)}`;
  }, { gatewayScoped: true, skipWhenPairingRequired: true });
  await runOpenClawGatewayJsonCheck(env, "OpenClaw usage cost", ["gateway", "usage-cost", "--json"], (json) => {
    const totals = json.totals || {};
    const totalTokens = Number(totals.totalTokens || 0);
    const totalCost = Number(totals.totalCost || 0);
    if (!Number.isFinite(totalTokens) || !Number.isFinite(totalCost)) throw new Error("OpenClaw usage-cost did not return numeric totals");
    return `tokens: ${totalTokens}, cost: ${totalCost}`;
  }, { gatewayScoped: true, skipWhenPairingRequired: true });
  await runOpenClawGatewayJsonCheck(env, "OpenClaw security audit", ["security", "audit", "--deep", "--json"], (json) => {
    const critical = Number(json.summary?.critical || 0);
    if (critical > 0) throw new Error(`OpenClaw security audit reported ${critical} critical finding(s)`);
    return `critical: ${critical}, warn: ${Number(json.summary?.warn || 0)}`;
  });
  await runOpenClawGatewayDoctorCheck(env);
}

async function runOpenClawGatewayDoctorCheck(env) {
  const command = composeCommand(["exec", "-T", "openclaw-gateway", "openclaw", "doctor", "--deep", "--non-interactive"]);
  process.stdout.write(`\n== OpenClaw doctor ==\n${redactConsole(command)}\n`);
  const result = await run(command, { env });
  if (result.code !== 0) throw new Error(`OpenClaw doctor failed with exit code ${result.code}`);
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  const criticals = output.match(/\bCRITICAL:/g) || [];
  if (criticals.length > 0) throw new Error(`OpenClaw doctor reported ${criticals.length} critical finding(s)`);
  record("pass", "OpenClaw doctor", "no critical findings");
}

async function runRedisQueueProfileHealth(env, label = "Redis queue profile health") {
  if (!composeProfiles.includes("queue")) return;
  const command = composeCommand(["exec", "-T", "redis", "redis-cli", "ping"]);
  process.stdout.write(`\n== ${label} ==\n${redactConsole(command)}\n`);
  const deadline = Date.now() + healthTimeoutMs;
  let lastOutput = "";
  while (Date.now() < deadline) {
    const result = await run(command, { quiet: true, env });
    const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
    if (result.code === 0 && /\bPONG\b/.test(output)) {
      writeStdout(result.stdout);
      writeStderr(result.stderr);
      record("pass", label);
      return;
    }
    lastOutput = redactConsole(output || `exit ${result.code}`);
    await sleep(pollIntervalMs);
  }
  throw new Error(`${label} did not pass within ${healthTimeoutMs}ms; last output: ${lastOutput}`);
}

async function runNonLiveComposeRuntime(env) {
  if (syntheticCredentialSeed && downVolumes) {
    await runStep("Compose pre-clean", composeCommand(["down", "-v"]), env);
  }
  await runStep("Compose config", composeCommand(["config"]), env);
  await runStep("Compose up", composeCommand(["up", "--build", "-d"]), env);
  await waitForOperant();
  await runOpenClawGatewayHealth(env);
  await runRedisQueueProfileHealth(env);
  if (skipRestart) {
    record("skip", "Compose restart", "--skip-restart");
    if (syntheticCredentialSeed) {
      await seedCredentials(env);
      await runOpenClawGatewayOperationalChecks(env, { ...env, ...syntheticCredentialEnv });
    }
    return;
  }
  await runStep("Compose restart", composeCommand(["restart", ...restartServices]), env);
  await waitForOperant();
  await runOpenClawGatewayHealth(env, "Post-restart OpenClaw gateway health");
  await runRedisQueueProfileHealth(env, "Post-restart Redis queue profile health");
  if (syntheticCredentialSeed) {
    await seedCredentials(env);
    await runOpenClawGatewayOperationalChecks(env, { ...env, ...syntheticCredentialEnv });
  }
}

function liveArgs(extraPrompt = "", liveReportPath = preRestartLiveReportPath) {
  const args = ["--", "--base-url", baseUrl, "--report", liveReportPath, "--require-operant-records"];
  const forward = [
    "--admin-slack-user-id",
    "--channel-id",
    "--slack-team-id",
    "--bot-user-id",
    "--dm-channel-id",
    "--denied-user-token",
    "--denied-user-id",
    "--manual-user-id",
    "--timeout-ms",
    "--poll-interval-ms",
    "--denied-timeout-ms",
    "--records-timeout-ms",
    "--openclaw-checks",
    "--expect-reply-regex",
    "--approval-completion-timeout-ms",
    "--approval-completion-regex",
    "--approval-prompt",
  ];
  for (const name of forward) {
    const value = argValue(name, "");
    if (value) args.push(name, value);
  }
  if (skipApprovalProbe) args.push("--skip-approval-probe");
  if (manualSlackPostsEnabled(reportSensitiveEnv)) args.push("--manual-slack-posts");
  if (manualSlackNudgeEnabled(reportSensitiveEnv)) args.push("--manual-slack-nudge");
  if (deniedUseAllowedUserEnabled(reportSensitiveEnv)) args.push("--denied-use-allowed-user");
  if (!skipDmProbe) args.push("--require-dm");
  if (!skipDeniedUserProbe) args.push("--require-denied-user");
  if (skipSlackApprovalProbe) {
    args.push("--skip-slack-approval-probe");
  } else {
    args.push("--require-slack-approval");
    if (skipSlackApprovalCompletion) {
      args.push("--skip-slack-approval-completion");
    } else {
      args.push("--require-slack-approval-completion");
    }
  }
  if (extraPrompt) args.push("--prompt", extraPrompt);
  return args;
}

function livePreflightArgs() {
  const args = ["--", "--env", envPath];
  if (liveEnvPath) args.push("--live-env", liveEnvPath);
  if (manualSlackPostsEnabled(reportSensitiveEnv)) args.push("--manual-slack-posts");
  if (deniedUseAllowedUserEnabled(reportSensitiveEnv)) args.push("--denied-use-allowed-user");
  const manualUserId = argValue("--manual-user-id", "");
  if (manualUserId) args.push("--manual-user-id", manualUserId);
  if (skipSlackAuthTest) args.push("--skip-slack-auth-test");
  if (skipModelAuthTest) args.push("--skip-model-auth-test");
  return args;
}

function defaultPostRestartPrompt(nonce = randomBytes(4).toString("hex")) {
  return `Operant post-restart E2E ${nonce}: reply in this thread with a short confirmation.`;
}

function doctorArgs() {
  const args = ["--", "--env", envPath];
  if (liveEnvPath) args.push("--live-env", liveEnvPath);
  return args;
}

function validateLiveEnv(env) {
  if (skipLive) return [];
  const missing = missingEnvGroups(env, requiredLiveEnvForEnv(env));
  if (!skipDmProbe && !argValue("--dm-channel-id", firstEnv(env, ["OPERANT_LIVE_DM_CHANNEL_ID"]))) {
    missing.push({ label: "DM channel ID", names: ["OPERANT_LIVE_DM_CHANNEL_ID"] });
  }
  if (!skipDeniedUserProbe && !deniedUseAllowedUserEnabled(env) && !manualSlackPostsEnabled(env) && !argValue("--denied-user-token", firstEnv(env, ["OPERANT_LIVE_DENIED_USER_TOKEN"]))) {
    missing.push({ label: "denied Slack user token", names: ["OPERANT_LIVE_DENIED_USER_TOKEN"] });
  }
  return missing;
}

function validateSeedEnv(env) {
  if (skipCredentialSeed || syntheticCredentialSeed) return [];
  const missing = missingEnvGroups(env, skipLive ? [...requiredLiveEnvForEnv(env, { includeDeniedUser: false }), ...requiredSeedEnv] : requiredSeedEnv);
  const modelCredentialError = modelCredentialErrorForProvider(env);
  if (modelCredentialError) {
    missing.push({ label: "provider-specific model API key", names: [modelCredentialError] });
  }
  return missing;
}

async function main() {
  process.stdout.write("# Operant Compose E2E\n\n");
  process.stdout.write(`env file: ${envPath}\n`);
  if (liveEnvPath) process.stdout.write(`live env file: ${liveEnvPath}\n`);

  if (!(await fileExists(envPath))) {
    blocked("environment file", `${envPath} missing; run "pnpm init:env" first`);
    return finish();
  }
  if (liveEnvPath && !(await fileExists(liveEnvPath))) {
    blocked("live environment file", `${liveEnvPath} missing; copy deploy/slack/live.env.example to a private file first`);
    return finish();
  }
  const envFile = parseEnv(await readFile(envPath, "utf8"));
  const liveEnvFile = liveEnvPath ? parseEnv(await readFile(liveEnvPath, "utf8")) : {};
  const env = { ...process.env, ...envFile, ...liveEnvFile };
  reportSensitiveEnv = env;
  setConsoleRedactionEnv(env);
  env.OPERANT_COMPOSE_E2E_REPORT = reportPath;
  for (const [key, value] of Object.entries(process.env)) {
    if (isLiveOverrideEnvKey(key)) env[key] = value;
  }
  if (!baseUrlOverride) {
    baseUrl = firstEnv(env, ["OPERANT_LIVE_BASE_URL"]) || `http://127.0.0.1:${firstEnv(env, ["OPERANT_HTTP_PORT"], "8080")}`;
  }
  env.OPERANT_LIVE_BASE_URL = baseUrl;
  process.stdout.write(`base url: ${baseUrl}\n`);
  if (selfTestReportRedaction) {
    await runReportRedactionSelfTest(env);
    return;
  }
  record("pass", "environment file", envPath);
  if (downVolumes) {
    const guardedProjectName = assertComposeDownVolumesGuard(env);
    record("pass", "Compose down-volume project guard", guardedProjectName);
  }

  const dockerOk = await requireCommand("Docker CLI", "docker --version", env);
  const composeOk = await requireCommand("Docker Compose", "docker compose version", env);
  const daemonOk = dockerOk ? await requireCommand("Docker daemon", "docker info --format '{{.ServerVersion}}'", env) : false;
  const missingLiveEnv = validateLiveEnv(env);
  const missingSeedEnv = validateSeedEnv(env);
  if (missingLiveEnv.length > 0) {
    blocked("live Slack/OpenClaw env", `missing or placeholder ${missingEnvGroupDetails(env, missingLiveEnv)}`);
  } else if (!skipLive) {
    record("pass", "live Slack/OpenClaw env", "required variables present");
  } else {
    record("skip", "live Slack/OpenClaw env", "--skip-live");
  }
  if (missingSeedEnv.length > 0) {
    blocked("credential seed env", `missing or placeholder ${missingEnvGroupDetails(env, missingSeedEnv)}`);
  } else if (skipCredentialSeed) {
    record("skip", "credential seed env", "--skip-credential-seed");
  } else {
    record("pass", "credential seed env", "required variables present");
  }

  if (!dockerOk || !composeOk || !daemonOk) return finish();
  if (missingLiveEnv.length > 0 || missingSeedEnv.length > 0) {
    if (allowBlocked) {
      try {
        await runNonLiveComposeRuntime(env);
      } finally {
        await runStep("Compose down", composeCommand(["down", "-v"]), env);
      }
    }
    return finish();
  }

  try {
    if (nonLiveSmoke) {
      await runNonLiveComposeRuntime(env);
    } else {
      if (!skipLive) {
        if (skipLivePreflight) {
          record("skip", "Live preflight", "--skip-live-preflight");
        } else {
          const livePreflightPassed = await runStep("Live preflight", pnpmCommand("live:preflight", livePreflightArgs()), env, {
            blockedWhen: (output) => allowBlocked && isBlockedLivePreflightOutput(output),
            blockedDetail: livePreflightBlockedDetail,
          });
          if (!livePreflightPassed) return finish();
        }
      }
      await runStep("Compose config", composeCommand(["config"]), env);
      await runStep("Compose up", composeCommand(["up", "--build", "-d"]), env);
      await waitForOperant();
      await runOpenClawGatewayHealth(env);
      await runRedisQueueProfileHealth(env);
      await seedCredentials(env);
      await runStep("Operant doctor", pnpmCommand("doctor", doctorArgs()), env);
      if (!skipLive) {
        await runStep("Live Slack/OpenClaw E2E", pnpmCommand("live:e2e", liveArgs("", preRestartLiveReportPath)), env, {
          blockedWhen: (output) => allowBlocked && isBlockedLiveE2eOutput(output),
          blockedDetail: liveE2eBlockedDetail,
        });
      }

      if (skipRestart) {
        record("skip", "Compose restart", "--skip-restart");
      } else {
        await runStep("Compose restart", composeCommand(["restart", ...restartServices]), env);
        await waitForOperant();
        await runOpenClawGatewayHealth(env, "Post-restart OpenClaw gateway health");
        await runRedisQueueProfileHealth(env, "Post-restart Redis queue profile health");
        await runStep("Post-restart doctor", pnpmCommand("doctor", doctorArgs()), env);
      }
      if (!nonLiveSmoke && !skipLive && !skipPostRestartLive) {
        await runStep(
          "Post-restart live Slack/OpenClaw E2E",
          pnpmCommand("live:e2e", liveArgs(defaultPostRestartPrompt(), postRestartLiveReportPath)),
          env,
          {
            blockedWhen: (output) => allowBlocked && isBlockedLiveE2eOutput(output),
            blockedDetail: liveE2eBlockedDetail,
          },
        );
      } else if (skipPostRestartLive) {
        record("skip", "Post-restart live Slack/OpenClaw E2E", "--skip-post-restart-live");
      }
    }

    if (skipCompletionAudit) {
      record("skip", "Completion audit", "--skip-completion-audit");
    } else if (steps.some((step) => step.status === "blocked")) {
      record("skip", "Completion audit", "blocked live prerequisites remain");
    } else {
      await writeReport("pre-completion-audit");
      env.OPERANT_ALLOW_PRE_COMPLETION_AUDIT_REPORT = "true";
      await runStep("Completion audit", pnpmCommand("audit:completion"), env);
      delete env.OPERANT_ALLOW_PRE_COMPLETION_AUDIT_REPORT;
    }
  } finally {
    if (downAfter) await runStep("Compose down", composeCommand(["down", ...(downVolumes ? ["-v"] : [])]), env);
  }

  return finish();
}

async function finish() {
  try {
    await writeReport("finish");
    process.stdout.write(`Report: ${reportPath}\n`);
  } catch (error) {
    record("fail", "Compose E2E report", error.message);
  }
  const blockedSteps = steps.filter((step) => step.status === "blocked");
  const failed = steps.filter((step) => step.status === "fail");
  process.stdout.write("\n# Compose E2E Summary\n\n");
  for (const step of steps) {
    process.stdout.write(`- ${step.status.toUpperCase()} ${step.name}${step.detail ? `: ${step.detail}` : ""}\n`);
  }
  if (failed.length > 0) process.exit(1);
  if (blockedSteps.length > 0 && !allowBlocked) process.exit(2);
  if (blockedSteps.length > 0) {
    process.stdout.write("\nCompose E2E blocked; rerun without --allow-blocked in an environment with the missing prerequisites.\n");
  } else {
    process.stdout.write("\nCompose E2E passed.\n");
  }
}

try {
  await main();
} catch (error) {
  record("fail", "Compose E2E", error.message);
  await finish();
}
