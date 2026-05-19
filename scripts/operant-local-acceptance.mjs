#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoSecretMaterial, redactSecretMaterial, redactString, sensitiveEnvValues } from "./operant-report-redaction.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const valueOptions = new Set(["--report", "--env", "--final-report", "--project-name"]);
const flagOptions = new Set([
  "--help",
  "-h",
  "--keep-going",
  "--include-sandbox",
  "--self-test-report-redaction",
  "--self-test-arg-validation",
  "--self-test-final-report-artifact",
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

const reportPath = path.resolve(repoRoot, argValue("--report", process.env.OPERANT_LOCAL_ACCEPTANCE_REPORT || ".operant/local-acceptance-report.json"));
const envPath = path.resolve(repoRoot, argValue("--env", process.env.OPERANT_LOCAL_ACCEPTANCE_ENV || ".operant/local-acceptance.env"));
const finalReportPath = path.resolve(repoRoot, argValue("--final-report", process.env.OPERANT_FINAL_REPORT || ".operant/final-report.md"));
const localComposeE2eReportPath = ".operant/local-acceptance-compose-e2e-report.json";
const keepGoing = hasFlag("--keep-going");
const includeSandbox = hasFlag("--include-sandbox") || process.env.OPERANT_LOCAL_ACCEPTANCE_INCLUDE_SANDBOX === "true";
const selfTestReportRedaction = hasFlag("--self-test-report-redaction");
const selfTestFinalReportArtifact = hasFlag("--self-test-final-report-artifact");
const localComposeProjectName = argValue(
  "--project-name",
  process.env.OPERANT_LOCAL_ACCEPTANCE_PROJECT_NAME || `operant-local-${process.pid}-${Date.now().toString(36).toLowerCase()}`,
);

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function printUsage() {
  process.stdout.write(`Usage: operant-local-acceptance [options]

Runs local/static acceptance and writes a sanitized evidence report.

Options:
  --env <path>                 Compose env path to generate and use
  --report <path>              Local acceptance report output path
  --final-report <path>        Final markdown report path
  --project-name <name>        Compose project name for isolated resources
  --include-sandbox            Include the Docker sandbox overlay smoke
  --keep-going                 Continue after failed steps
  --self-test-report-redaction Run report redaction self-test
  --self-test-arg-validation   Run CLI argument validation self-test
  --self-test-final-report-artifact
                               Run final report artifact verifier self-test
  --help, -h                   Show this help
`);
}

function validateArgs(args) {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--") continue;
    if (valueOptions.has(arg)) {
      const value = args[index + 1];
      if (!value || value === "--" || value.startsWith("--")) throw new Error(`${arg} requires a value`);
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

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function runArgValidationSelfTest() {
  validateArgs([
    "--",
    "--env",
    ".operant/test.env",
    "--report",
    ".operant/test-report.json",
    "--final-report",
    ".operant/final-report.md",
    "--project-name",
    "operant-local-test",
    "--include-sandbox",
    "--keep-going",
    "--self-test-final-report-artifact",
  ]);
  assertValidationFails(["--helpful"], "Unknown option");
  assertValidationFails(["--env"], "requires a value");
  assertValidationFails(["--report", "--include-sandbox"], "requires a value");
  process.stdout.write("Local acceptance argument validation self-test passed.\n");
}

function runStep(name, command, args, options = {}) {
  const startedAt = new Date();
  const sensitiveValues = sensitiveEnvValues([process.env, options.env, envFileForRedactionSync()]);
  process.stdout.write(`\n== ${name} ==\n${redactString([command, ...args].join(" "), sensitiveValues)}\n`);
  const started = performance.now();
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, ...(options.env || {}) },
  });
  const durationMs = Math.round(performance.now() - started);
  const status = result.status === 0 ? "pass" : options.blockedOk && result.status === 2 ? "blocked" : "fail";
  process.stdout.write(`${status.toUpperCase()} ${name} (${durationMs}ms)\n`);
  const stdout = redactString(result.stdout || "", sensitiveValues);
  const stderr = redactString(result.stderr || "", sensitiveValues);
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);
  return {
    name,
    command: [command, ...args],
    status,
    exitCode: result.status,
    signal: result.signal,
    startedAt: startedAt.toISOString(),
    durationMs,
    stdoutTail: tail(stdout),
    stderrTail: tail(stderr),
  };
}

function tail(value, max = 12_000) {
  return value.length > max ? value.slice(value.length - max) : value;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("Unable to reserve a local TCP port")));
        return;
      }
      server.close(() => resolve(String(address.port)));
    });
  });
}

async function freePorts(count) {
  const ports = new Set();
  while (ports.size < count) {
    ports.add(await freePort());
  }
  return [...ports];
}

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

async function envFileForRedaction() {
  try {
    return parseEnv(await readFile(envPath, "utf8"));
  } catch {
    return {};
  }
}

function envFileForRedactionSync() {
  try {
    return parseEnv(readFileSync(envPath, "utf8"));
  } catch {
    return {};
  }
}

function readCompletionAudit() {
  const result = spawnSync("node", ["scripts/operant-completion-audit.mjs", "--json", "--allow-blocked"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    return {
      error: `completion audit failed with exit ${result.status}`,
      stdoutTail: tail(result.stdout || ""),
      stderrTail: tail(result.stderr || ""),
    };
  }
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    return {
      error: `completion audit JSON parse failed: ${error.message}`,
      stdoutTail: tail(result.stdout || ""),
      stderrTail: tail(result.stderr || ""),
    };
  }
}

async function writeReport(steps, audit = null) {
  return writeAcceptanceReport(steps, audit);
}

async function writeAcceptanceReport(steps, audit = null, finalReportArtifact = null) {
  const failed = steps.filter((step) => step.status === "fail");
  const blocked = steps.filter((step) => step.status === "blocked");
  const localComplete = failed.length === 0 && blocked.length === 0;
  const auditBlocked = Array.isArray(audit?.checks) ? audit.checks.filter((check) => check.status === "blocked") : [];
  const auditFailed = Array.isArray(audit?.checks) ? audit.checks.filter((check) => !check.ok && check.status !== "blocked") : [];
  const report = {
    format: "operant.local-acceptance-report.v1",
    generatedAt: new Date().toISOString(),
    envPath,
    complete: Boolean(audit?.complete),
    localComplete,
    objectiveComplete: Boolean(audit?.complete),
    totals: {
      steps: steps.length,
      passed: steps.filter((step) => step.status === "pass").length,
      blocked: blocked.length,
      failed: failed.length,
    },
    completionAudit: audit ? {
      objective: audit.objective,
      complete: Boolean(audit.complete),
      totals: audit.totals,
      blocked: auditBlocked.map((check) => ({
        group: check.group,
        requirement: check.requirement,
        evidence: check.evidence,
      })),
      failed: auditFailed.map((check) => ({
        group: check.group,
        requirement: check.requirement,
        evidence: check.evidence,
      })),
      error: audit.error,
    } : null,
    finalReportArtifact,
    steps,
  };
  await mkdir(path.dirname(reportPath), { recursive: true });
  const sensitiveValues = sensitiveEnvValues([process.env, await envFileForRedaction()]);
  const redactedReport = redactSecretMaterial(report, sensitiveValues);
  assertNoSecretMaterial(redactedReport, sensitiveValues);
  await writeFile(reportPath, `${JSON.stringify(redactedReport, null, 2)}\n`);
  return redactedReport;
}

async function runReportRedactionSelfTest() {
  const syntheticEnv = {
    OPERANT_SECRET_KEY: "operant-secret-redaction-self-test",
    OPERANT_INTERNAL_TOKEN: "internal-redaction-self-test-token",
    OPERANT_ADMIN_LOGIN_TOKEN: "admin-redaction-self-test-token",
    POSTGRES_PASSWORD: "postgres-redaction-self-test-password",
    DATABASE_URL: "postgres://operant:postgres-redaction-self-test-password@postgres:5432/operant",
    OPENCLAW_GATEWAY_TOKEN: "gateway-redaction-self-test-token",
    SLACK_BOT_TOKEN: "xoxb-local-acceptance-redaction-token",
    OPENAI_API_KEY: "sk-local-acceptance-redaction-token",
  };
  await mkdir(path.dirname(envPath), { recursive: true });
  await writeFile(envPath, `${Object.entries(syntheticEnv).map(([key, value]) => `${key}=${value}`).join("\n")}\n`);
  await writeAcceptanceReport(
    [{
      name: "Local acceptance report redaction self-test",
      command: ["node", "synthetic"],
      status: "pass",
      exitCode: 0,
      signal: null,
      startedAt: new Date().toISOString(),
      durationMs: 1,
      stdoutTail: `stdout ${syntheticEnv.SLACK_BOT_TOKEN} ${syntheticEnv.DATABASE_URL}`,
      stderrTail: `stderr ${syntheticEnv.OPENAI_API_KEY} xapp-unlisted-local-acceptance-redaction-token`,
    }],
    {
      objective: "redaction self-test",
      complete: false,
      totals: { checks: 1, passed: 1, blocked: 0, failed: 0 },
      checks: [{
        group: "tests",
        requirement: "redaction self-test",
        status: "pass",
        ok: true,
        evidence: syntheticEnv.OPERANT_ADMIN_LOGIN_TOKEN,
      }],
    },
  );
  const body = await readFile(reportPath, "utf8");
  const sensitiveValues = sensitiveEnvValues([process.env, syntheticEnv]);
  assertNoSecretMaterial(JSON.parse(body), sensitiveValues);
  if (!body.includes("[redacted]")) throw new Error("Local acceptance report redaction self-test did not write redacted markers");
  process.stdout.write("Local acceptance report redaction self-test passed.\n");
}

function missingFinalReportPatterns(body, requiredPatterns) {
  return requiredPatterns.filter(([, pattern]) => !pattern.test(body)).map(([label]) => label);
}

async function finalReportRequiredPatterns(audit = null, options = {}) {
  const requiredPatterns = [
    ["decision section", /^## Decision$/m],
    ["local acceptance evidence", /^## Local Acceptance Evidence$/m],
    ["Compose evidence", /^## Compose E2E Evidence$/m],
    ["Slack DM probe evidence", /^## Slack DM Probe Evidence$/m],
    ["automated Slack user-token probe evidence", /^## Automated Slack User-Token Probe Evidence$/m],
    ["non-live Compose smoke evidence section", /^## Non-Live Compose Smoke Evidence$/m],
    ["live completion handoff", /^## Live Completion Handoff$/m],
    ["commands section", /^## Commands$/m],
    ["objective success criteria matrix", /^## Objective Success Criteria Matrix$/m],
    ["strict acceptance command", /pnpm compose:e2e/],
    ["env-file Compose config command", /pnpm compose:config -- --env \.env\.acme/],
    ["env-file Compose up command", /pnpm compose:up -- --env \.env\.acme -d/],
    ["env-driven live bot command", /pnpm compose:live -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["sandbox overlay Compose command", /--file docker-compose\.sandbox\.yml/],
    ["sandbox smoke evidence section", /^## Sandbox Compose Smoke Evidence$/m],
    ["live E2E report artifacts", /live-e2e-post-restart-report\.json/],
    ["Slack DM probe report artifact", /slack-dm-probe-report\.json/],
    ["automated Slack user-token probe report artifact", /compose-e2e-auto-report\.json/],
    ["current local handoff bundle", /Current local handoff bundle:/],
    ["completion audit command", /pnpm audit:completion/],
    ["live preflight command", /pnpm live:preflight -- --env \.env\.acme/],
    ["Slack DM probe command", /pnpm slack:dm-probe -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["automated Slack user-token probe command", /OPERANT_LIVE_MANUAL_SLACK_POSTS=0 OPERANT_LIVE_MANUAL_SLACK_NUDGE=0 pnpm compose:e2e -- --env \.env\.acme --live-env \.env\.acme\.live --report \.operant\/compose-e2e-auto-report\.json --allow-blocked --down --down-volumes/],
    ["live preflight env overlay command", /pnpm live:preflight -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["standalone live E2E env overlay command", /pnpm live:e2e -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["strict Compose env overlay command", /pnpm compose:e2e -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["live env overlay command", /--live-env \.env\.acme\.live/],
    ["generated Compose env supplies admin token", /# Normally supplied by the generated Compose env passed with --env\.[\s\S]*# OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_\.\.\./],
    ["shell export keeps admin token commented", /# Shell-export alternative when not using --live-env:[\s\S]*# Normally supplied by the generated Compose env passed with --env\.[\s\S]*# export OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_\.\.\./],
    ["handoff helper reports placeholder state only by name", /process-env live\/model override names and placeholder state only, never values/],
    ["handoff package aliases", /pnpm handoff:readiness[\s\S]*pnpm handoff:verify[\s\S]*pnpm live:acceptance:preflight[\s\S]*pnpm live:acceptance/],
    ["structured integration credential live handoff", /Live Completion Handoff[\s\S]*OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON[\s\S]*secretValueEnv/],
    ["structured integration credential seed", /OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON[\s\S]*secretValueEnv[\s\S]*inline JSON secret values/],
    ["Slack app-level token Socket Mode handoff", /Live Completion Handoff[\s\S]*apps\.connections\.open[\s\S]*connections:write[\s\S]*Socket Mode WebSocket URL[\s\S]*bot token[\s\S]*cannot replace the app-level token/],
    ["live token role handoff", /Temporary user tokens must be human user tokens, not the bot token\.[\s\S]*auth\.test[\s\S]*chat\.postMessage[\s\S]*denied-policy proof is one-human by default[\s\S]*conversations\.info[\s\S]*conversations\.members[\s\S]*conversations\.replies/],
    ["colleague denied-user manual handoff", /denied-policy proof is a Slack admission-policy check[\s\S]*optional colleague-backed proof[\s\S]*OPERANT_LIVE_DENIED_USER_ID=U_COLLEAGUE_ID[\s\S]*normal top-level Slack-client message[\s\S]*no Operant thread reply/],
    ["live report result-level Slack identity handoff", /live-e2e-report\.json[\s\S]*live-e2e-post-restart-report\.json[\s\S]*result-level Slack identity evidence[\s\S]*result\.channelId[\s\S]*result\.slackTeamId[\s\S]*result\.botUserId[\s\S]*top-level bot identity/],
    ["live report membership evidence handoff", /live-e2e-report\.json[\s\S]*live-e2e-post-restart-report\.json[\s\S]*channelMembership\.method[\s\S]*conversations\.members[\s\S]*channelMembership\.channelId[\s\S]*channelMembership\.requiredUserIds[\s\S]*allowed test-user Slack ID[\s\S]*same-user-temporary-deny/],
    ["OpenClaw operator pairing handoff", /Live Completion Handoff[\s\S]*pairing required[\s\S]*openclaw devices list[\s\S]*openclaw devices approve <requestId>[\s\S]*operator\.read[\s\S]*operator\.approvals[\s\S]*operator\.talk\.secrets[\s\S]*operator\.admin/],
  ];
  if (audit?.totals) {
    requiredPatterns.push(
      ["current audit summary count", new RegExp(`Checks: ${audit.totals.passed}/${audit.totals.checks} passed`)],
      [
        "current local-acceptance audit count",
        new RegExp(`Completion audit: ${audit.totals.passed}/${audit.totals.checks} passed, ${audit.totals.blocked} blocked, ${audit.totals.failed} failed`),
      ],
    );
  }
  if (options.requireVerifiedArtifact) {
    requiredPatterns.push(["verified final report artifact status", /Final report artifact: pass/]);
  }
  if (options.requireCurrentLocalAcceptanceReport) {
    try {
      const localAcceptance = options.currentLocalAcceptanceReport || JSON.parse(await readFile(reportPath, "utf8"));
      if (localAcceptance.generatedAt) {
        requiredPatterns.push(["current local acceptance generated timestamp", new RegExp(`Generated: ${escapeRegex(localAcceptance.generatedAt)}`)]);
      }
      if (localAcceptance.totals) {
        requiredPatterns.push([
          "current local acceptance totals",
          new RegExp(`Step totals: ${localAcceptance.totals.passed || 0} passed, ${localAcceptance.totals.blocked || 0} blocked, ${localAcceptance.totals.failed || 0} failed`),
        ]);
      }
    } catch (error) {
      requiredPatterns.push(["readable current local acceptance report", new RegExp(`__missing_current_local_acceptance_report_${escapeRegex(error.message)}__`)]);
    }
  }
  return requiredPatterns;
}

async function verifyFinalReportArtifact(audit = null, options = {}) {
  const startedAt = new Date();
  const started = performance.now();
  const requiredPatterns = await finalReportRequiredPatterns(audit, options);
  try {
    const body = await readFile(finalReportPath, "utf8");
    const missing = missingFinalReportPatterns(body, requiredPatterns);
    return {
      path: finalReportPath,
      status: missing.length === 0 ? "pass" : "fail",
      missing,
      generatedAt: startedAt.toISOString(),
      durationMs: Math.round(performance.now() - started),
    };
  } catch (error) {
    return {
      path: finalReportPath,
      status: "fail",
      missing: ["readable final report"],
      error: error.message,
      generatedAt: startedAt.toISOString(),
      durationMs: Math.round(performance.now() - started),
    };
  }
}

async function runFinalReportArtifactSelfTest() {
  const audit = {
    totals: {
      checks: 93,
      passed: 90,
      blocked: 3,
      failed: 0,
    },
  };
  const localAcceptance = {
    generatedAt: "2026-01-02T03:04:05.678Z",
    totals: {
      passed: 9,
      blocked: 0,
      failed: 0,
    },
  };
  const body = `# Operant Final Verification Report

Generated: 2026-01-02T03:04:06.000Z

## Decision

Not complete.

## Audit Summary

- Checks: 90/93 passed

## Live Completion Handoff

Required private inputs:
# Normally supplied by the generated Compose env passed with --env.
# OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_...
OPERANT_LIVE_INTEGRATION_CREDENTIALS=github/api-token=GITHUB_TOKEN
OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON='[{"kind":"linear","key":"api-token","label":"Linear API token","secretValueEnv":"LINEAR_API_KEY"}]'
JSON integration credential seeds redact inline JSON secret values.
The Slack app-level token is separate from the bot token because Slack apps.connections.open requires an app-level token with connections:write and returns the temporary Socket Mode WebSocket URL. OpenClaw uses that Socket Mode connection for Slack events and interactive payloads; the bot token can read/post as the bot but cannot replace the app-level token for ingress.
Temporary user tokens must be human user tokens, not the bot token. The verifier uses the allowed token for auth.test and chat.postMessage; the allowed user token must also post into the existing DM. If Slack stores those posts with bot_id/app_id, use manual mode with real Slack-client human messages because OpenClaw ignores app-authored messages to avoid bot loops. The denied-policy proof is one-human by default: the verifier temporarily denies the allowed test user, proves no Slack reply, then restores policy before the approval probe. The bot token performs the conversations.info, conversations.members, and conversations.replies checks.
The denied-policy proof is a Slack admission-policy check: a channel member denied by Operant policy should receive no Operant thread reply. It is separate from control-plane RBAC and from tool policies, which can allow, deny, or require approval for specific tool/action pairs after a Slack request is admitted. For an optional colleague-backed proof, ask the colleague to join the test channel, copy their Slack member ID, and type only the denied-user prompt when the verifier prints it. Set OPERANT_LIVE_DENIED_USER_ID=U_COLLEAGUE_ID or pass --denied-user-id U_COLLEAGUE_ID. The colleague's message must be a normal top-level Slack-client message; the correct outcome is no Operant thread reply, proving policy suppression rather than channel membership failure.
The strict audit only accepts live-e2e-report.json and live-e2e-post-restart-report.json when each report includes result-level Slack identity evidence: result.channelId and result.slackTeamId match the top-level report channel/team, result.botUserId matches the top-level bot identity, channelMembership.method="conversations.members", channelMembership.channelId, and channelMembership.requiredUserIds containing the allowed test-user Slack ID plus either a distinct denied user or same-user-temporary-deny evidence.
If strict OpenClaw operator checks report pairing required, review openclaw devices list, approve the exact request ID with openclaw devices approve <requestId>, and rerun live acceptance. Expected scopes include operator.read, operator.approvals, and operator.talk.secrets; operator.admin satisfies them.

pnpm live:preflight -- --env .env.acme
pnpm live:preflight -- --env .env.acme --live-env .env.acme.live
pnpm live:e2e -- --env .env.acme --live-env .env.acme.live
pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live
pnpm audit:completion
live-e2e-post-restart-report.json

# Shell-export alternative when not using --live-env:
# Normally supplied by the generated Compose env passed with --env.
# export OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_...

Current local handoff bundle:
process-env live/model override names and placeholder state only, never values
pnpm handoff:readiness
pnpm handoff:verify
pnpm live:acceptance:preflight
pnpm live:acceptance

## Objective Success Criteria Matrix

## Local Acceptance Evidence

- Generated: 2026-01-02T03:04:05.678Z
- Step totals: 9 passed, 0 blocked, 0 failed
- Completion audit: 90/93 passed, 3 blocked, 0 failed
- Final report artifact: pass

## Compose E2E Evidence

## Slack DM Probe Evidence

slack-dm-probe-report.json
pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live

## Automated Slack User-Token Probe Evidence

compose-e2e-auto-report.json
OPERANT_LIVE_MANUAL_SLACK_POSTS=0 OPERANT_LIVE_MANUAL_SLACK_NUDGE=0 pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live --report .operant/compose-e2e-auto-report.json --allow-blocked --down --down-volumes

## Non-Live Compose Smoke Evidence

## Sandbox Compose Smoke Evidence

--file docker-compose.sandbox.yml

## Commands

pnpm compose:e2e
pnpm compose:config -- --env .env.acme
pnpm compose:up -- --env .env.acme -d
pnpm compose:live -- --env .env.acme --live-env .env.acme.live
--live-env .env.acme.live
`;
  const requiredPatterns = await finalReportRequiredPatterns(audit, {
    requireVerifiedArtifact: true,
    requireCurrentLocalAcceptanceReport: true,
    currentLocalAcceptanceReport: localAcceptance,
  });
  const missing = missingFinalReportPatterns(body, requiredPatterns);
  if (missing.length > 0) throw new Error(`Final report artifact self-test unexpectedly missing: ${missing.join(", ")}`);
  const staleBody = body.replace(localAcceptance.generatedAt, "2026-01-02T03:04:04.000Z");
  const staleMissing = missingFinalReportPatterns(staleBody, requiredPatterns);
  if (!staleMissing.includes("current local acceptance generated timestamp")) {
    throw new Error(`Final report artifact self-test did not reject stale local acceptance timestamp: ${staleMissing.join(", ")}`);
  }
  const staleTotalsBody = body.replace("Step totals: 9 passed, 0 blocked, 0 failed", "Step totals: 8 passed, 1 blocked, 0 failed");
  const staleTotalsMissing = missingFinalReportPatterns(staleTotalsBody, requiredPatterns);
  if (!staleTotalsMissing.includes("current local acceptance totals")) {
    throw new Error(`Final report artifact self-test did not reject stale local acceptance totals: ${staleTotalsMissing.join(", ")}`);
  }
  process.stdout.write("Final report artifact verifier self-test passed.\n");
}

if (selfTestReportRedaction) {
  await runReportRedactionSelfTest();
  process.exit(0);
}

if (selfTestFinalReportArtifact) {
  await runFinalReportArtifactSelfTest();
  process.exit(0);
}

const [localHttpPort, localPostgresPort, localGatewayPort] = await freePorts(3);

const plannedSteps = [
  ["Generate local env", "pnpm", [
    "init:env",
    "--",
    "--output",
    envPath,
    "--force",
    "--project-name",
    localComposeProjectName,
    "--http-port",
    localHttpPort,
    "--postgres-port",
    localPostgresPort,
    "--gateway-port",
    localGatewayPort,
  ]],
  ["Doctor preflight", "pnpm", ["doctor", "--", "--env", envPath, "--preflight-only"]],
  ["Static verification", "pnpm", ["verify"]],
  ["Managed local smoke", "pnpm", ["smoke:local"]],
  ["Strict Compose E2E blocked-mode evidence", "pnpm", [
    "compose:e2e",
    "--",
    "--env",
    envPath,
    "--report",
    localComposeE2eReportPath,
    "--allow-blocked",
  ]],
  ["Non-live Compose smoke blocked-mode evidence", "pnpm", ["compose:smoke", "--", "--env", envPath, "--profile", "queue", "--allow-blocked", "--down", "--down-volumes"]],
  ...(includeSandbox ? [["Docker sandbox overlay smoke evidence", "pnpm", ["compose:smoke:sandbox", "--", "--env", envPath]]] : []),
  ["Completion audit blocked-mode", "pnpm", ["audit:completion", "--", "--allow-blocked"]],
  ["Final report", "pnpm", ["report:final"]],
];

async function runPlannedSteps() {
  const steps = [];
  for (const [name, command, args] of plannedSteps) {
    const step = runStep(name, command, args);
    steps.push(step);
    await writeReport(steps);
    if (step.status === "fail" && !keepGoing) break;
  }
  return steps;
}

const steps = await runPlannedSteps();
const finalAudit = readCompletionAudit();
let report = await writeAcceptanceReport(steps, finalAudit);
const finalReportStep = steps.find((step) => step.name === "Final report" && step.status === "pass");
let finalReportArtifact = null;
if (finalReportStep) {
  runStep("Refresh final report with local acceptance evidence", "pnpm", ["report:final"]);
  finalReportArtifact = await verifyFinalReportArtifact(finalAudit);
  process.stdout.write(`${finalReportArtifact.status.toUpperCase()} Final report artifact (${finalReportArtifact.durationMs}ms)\n`);
  if (finalReportArtifact.missing?.length) {
    process.stdout.write(`Missing final report content: ${finalReportArtifact.missing.join(", ")}\n`);
  }
  report = await writeAcceptanceReport(steps, finalAudit, finalReportArtifact);
  const finalReportRefresh = runStep("Refresh final report with verified artifact evidence", "pnpm", ["report:final"]);
  if (finalReportRefresh.status === "pass") {
    const finalReportWithVerifiedArtifact = await verifyFinalReportArtifact(finalAudit, { requireVerifiedArtifact: true });
    process.stdout.write(`${finalReportWithVerifiedArtifact.status.toUpperCase()} Final report with verified artifact evidence (${finalReportWithVerifiedArtifact.durationMs}ms)\n`);
    if (finalReportWithVerifiedArtifact.missing?.length) {
      process.stdout.write(`Missing final verified report content: ${finalReportWithVerifiedArtifact.missing.join(", ")}\n`);
    }
    if (finalReportWithVerifiedArtifact.status === "fail") finalReportArtifact = finalReportWithVerifiedArtifact;
    report = await writeAcceptanceReport(steps, finalAudit, finalReportArtifact);
    if (finalReportWithVerifiedArtifact.status === "pass") {
      const finalReportSync = runStep("Refresh final report after final local acceptance report", "pnpm", ["report:final"]);
      if (finalReportSync.status === "pass") {
        const finalReportWithCurrentLocalReport = await verifyFinalReportArtifact(finalAudit, {
          requireVerifiedArtifact: true,
          requireCurrentLocalAcceptanceReport: true,
        });
        process.stdout.write(`${finalReportWithCurrentLocalReport.status.toUpperCase()} Final report with current local acceptance evidence (${finalReportWithCurrentLocalReport.durationMs}ms)\n`);
        if (finalReportWithCurrentLocalReport.missing?.length) {
          process.stdout.write(`Missing current local acceptance report content: ${finalReportWithCurrentLocalReport.missing.join(", ")}\n`);
        }
        if (finalReportWithCurrentLocalReport.status === "fail") {
          finalReportArtifact = finalReportWithCurrentLocalReport;
          report = await writeAcceptanceReport(steps, finalAudit, finalReportArtifact);
        }
      } else {
        finalReportArtifact = {
          path: finalReportPath,
          status: "fail",
          missing: ["refresh final report after final local acceptance report"],
          generatedAt: new Date().toISOString(),
          durationMs: finalReportSync.durationMs,
        };
        report = await writeAcceptanceReport(steps, finalAudit, finalReportArtifact);
      }
    }
  } else {
    finalReportArtifact = {
      path: finalReportPath,
      status: "fail",
      missing: ["refresh final report with verified artifact evidence"],
      generatedAt: new Date().toISOString(),
      durationMs: finalReportRefresh.durationMs,
    };
    report = await writeAcceptanceReport(steps, finalAudit, finalReportArtifact);
  }
} else {
  report = await writeAcceptanceReport(steps, finalAudit, finalReportArtifact);
}
process.stdout.write(`\nLocal acceptance report written to ${reportPath}\n`);
if (report.totals.failed > 0) process.exit(1);
if (finalReportArtifact?.status === "fail") process.exit(1);
