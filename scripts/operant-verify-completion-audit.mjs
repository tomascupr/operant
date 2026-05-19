#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let syntheticSmokeReportPath = "";
let syntheticSandboxSmokeReportPath = "";

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

const envKeysToScrub = [
  "OPERANT_ADMIN_LOGIN_TOKEN",
  "OPERANT_LIVE_ADMIN_SLACK_USER_ID",
  "OPERANT_LIVE_SLACK_TEAM_ID",
  "SLACK_TEAM_ID",
  "SLACK_CHANNEL_ID",
  "OPERANT_LIVE_SLACK_CHANNEL_ID",
  "SLACK_BOT_TOKEN",
  "OPERANT_LIVE_SLACK_BOT_TOKEN",
  "SLACK_CONFIG_TOKEN",
  "SLACK_CONFIGURATION_TOKEN",
  "OPERANT_LIVE_SLACK_CONFIG_TOKEN",
  "SLACK_USER_TOKEN",
  "OPERANT_LIVE_SLACK_USER_TOKEN",
  "OPERANT_LIVE_DM_CHANNEL_ID",
  "OPERANT_LIVE_DENIED_USER_TOKEN",
  "OPERANT_LIVE_MANUAL_SLACK_POSTS",
  "OPERANT_LIVE_ALLOWED_USER_ID",
  "OPERANT_LIVE_DENIED_USER_ID",
  "OPERANT_LIVE_SLACK_APP_TOKEN",
  "SLACK_APP_TOKEN",
  "OPERANT_LIVE_MODEL_API_KEY",
  "MODEL_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
];

const requiredOpenClawChecks = ["config-validate", "status", "secrets-reload", "approvals-get", "cron-status", "tasks-list", "usage-cost", "doctor", "security-audit", "channels-status"];
const requiredOpenClawCheckAssertions = {
  "config-validate": ["config-valid:true"],
  status: ["status-gateway-reachable"],
  "secrets-reload": ["secrets-reload-ok:true"],
  "tasks-list": ["tasks-json"],
  "usage-cost": ["usage-cost-numeric-totals"],
  "security-audit": ["security-critical:0"],
  "channels-status": ["channels-status-slack-connected", "channels-status-probe:true"],
};

async function fileSha256(file) {
  return createHash("sha256").update(await readFile(path.join(repoRoot, file))).digest("hex");
}

async function evidenceInputFingerprints() {
  return Promise.all(composeEvidenceInputs.map(async (file) => ({
    file,
    sha256: await fileSha256(file),
  })));
}

async function extractComposeEvidenceInputs(scriptFile) {
  const body = await readFile(path.join(repoRoot, scriptFile), "utf8");
  const match = body.match(/const composeEvidenceInputs = \[([\s\S]*?)\];/);
  assert(match, `${scriptFile} does not declare composeEvidenceInputs`);
  return [...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]);
}

async function assertEvidenceInputListsStayInSync() {
  for (const scriptFile of ["scripts/operant-compose-e2e.mjs", "scripts/operant-completion-audit.mjs"]) {
    const actual = await extractComposeEvidenceInputs(scriptFile);
    assert(
      JSON.stringify(actual) === JSON.stringify(composeEvidenceInputs),
      `${scriptFile} composeEvidenceInputs drifted from scripts/operant-verify-completion-audit.mjs`,
    );
  }
}

async function assertSlackBoundaryAuditCoversDashboardAssets() {
  const body = await readFile(path.join(repoRoot, "scripts/operant-completion-audit.mjs"), "utf8");
  assert(
    body.includes('"apps/control-plane/public"') && body.includes("dashboard public asset files scanned"),
    "completion audit must scan dashboard public assets for forbidden Slack runtime code",
  );
}

function strictLiveReport(overrides = {}) {
  return {
    format: "operant.live-e2e-report.v1",
    generatedAt: "2026-05-14T00:00:00.000Z",
    status: "pass",
    passed: true,
    baseUrl: "http://127.0.0.1:8080",
    channelId: "CSYNTHETICVERIFY",
    dmChannelId: "DSYNTHETICVERIFY",
    slackTeamId: "TSYNTHETICVERIFY",
    adminSlackUserId: "USYNTHETICVERIFY",
    botUserId: "UBOT",
    testUserId: "UTEST",
    options: {
      requireOperantRecords: true,
      requireDm: true,
      requireDeniedUser: true,
      requireSlackApproval: true,
      requireSlackApprovalCompletion: true,
      skipOpenClawChecks: false,
      skipObservationSync: false,
      skipApprovalProbe: false,
      skipSlackApprovalProbe: false,
      skipSlackApprovalCompletion: false,
      openClawChecks: requiredOpenClawChecks,
    },
    result: {
      channelId: "CSYNTHETICVERIFY",
      slackTeamId: "TSYNTHETICVERIFY",
      botUserId: "UBOT",
      parentTs: "111.111",
      replyTs: "111.222",
      dmReplyTs: "333.444",
      dmProbe: { channelId: "DSYNTHETICVERIFY", parentTs: "333.333", replyTs: "333.444" },
      deniedProbe: { userId: "UDENIEDSYNTHETIC", teamId: "TSYNTHETICVERIFY", parentTs: "555.666", noReplyObservedMs: 45000 },
      channelMembership: {
        channelId: "CSYNTHETICVERIFY",
        method: "conversations.members",
        requiredUserIds: ["UTEST", "UDENIEDSYNTHETIC"],
        pages: 1,
      },
      slackApprovalProbe: { parentTs: "777.777", approvalUiTs: "777.888", approvalCompletionTs: "888.999" },
      approvalProbe: { id: "approval-1", before: 0, after: 1, policyNames: ["risky-actions"] },
      openClawChecks: requiredOpenClawChecks.map((check) => ({
        check,
        exitCode: 0,
        timedOut: false,
        assertions: requiredOpenClawCheckAssertions[check] || [],
      })),
      operantRecordDeltas: { sessions: 1, jobs: 1, usage: 1 },
    },
    ...overrides,
  };
}

async function writeJson(file, payload) {
  await writeFile(file, `${JSON.stringify(payload, null, 2)}\n`);
}

async function liveReportDescriptor(file, step) {
  const body = await readFile(file, "utf8");
  return {
    path: path.relative(repoRoot, file),
    required: true,
    step,
    sha256: createHash("sha256").update(body).digest("hex"),
    generatedAt: JSON.parse(body).generatedAt,
  };
}

async function writeSyntheticEnv(file) {
  await writeFile(file, [
    "OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_synthetic_verify_token",
    "OPERANT_LIVE_ADMIN_SLACK_USER_ID=USYNTHETICVERIFY",
    "OPERANT_LIVE_SLACK_TEAM_ID=TSYNTHETICVERIFY",
    "SLACK_CHANNEL_ID=CSYNTHETICVERIFY",
    "SLACK_BOT_TOKEN=xoxb-synthetic-verify-token",
    "SLACK_USER_TOKEN=xoxp-synthetic-verify-token",
    "OPERANT_LIVE_DM_CHANNEL_ID=DSYNTHETICVERIFY",
    "OPERANT_LIVE_DENIED_USER_TOKEN=xoxp-synthetic-denied-verify-token",
    "SLACK_APP_TOKEN=xapp-synthetic-verify-token",
    "OPENAI_API_KEY=sk-synthetic-verify-token",
    "",
  ].join("\n"));
}

async function writeSyntheticBaseEnv(file) {
  await writeFile(file, [
    "OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_synthetic_verify_token",
    "",
  ].join("\n"));
}

async function writeSyntheticLiveEnv(file) {
  await writeFile(file, [
    "OPERANT_LIVE_ADMIN_SLACK_USER_ID=USYNTHETICVERIFY",
    "OPERANT_LIVE_SLACK_TEAM_ID=TSYNTHETICVERIFY",
    "SLACK_CHANNEL_ID=CSYNTHETICVERIFY",
    "SLACK_BOT_TOKEN=xoxb-synthetic-verify-token",
    "SLACK_USER_TOKEN=xoxp-synthetic-verify-token",
    "OPERANT_LIVE_DM_CHANNEL_ID=DSYNTHETICVERIFY",
    "OPERANT_LIVE_DENIED_USER_TOKEN=xoxp-synthetic-denied-verify-token",
    "SLACK_APP_TOKEN=xapp-synthetic-verify-token",
    "OPENAI_API_KEY=sk-synthetic-verify-token",
    "",
  ].join("\n"));
}

async function writeSyntheticManualLiveEnv(file) {
  await writeFile(file, [
    "OPERANT_LIVE_ADMIN_SLACK_USER_ID=USYNTHETICVERIFY",
    "OPERANT_LIVE_SLACK_TEAM_ID=TSYNTHETICVERIFY",
    "SLACK_CHANNEL_ID=CSYNTHETICVERIFY",
    "SLACK_BOT_TOKEN=xoxb-synthetic-verify-token",
    "OPERANT_LIVE_DM_CHANNEL_ID=DSYNTHETICVERIFY",
    "OPERANT_LIVE_MANUAL_SLACK_POSTS=1",
    "OPERANT_LIVE_ALLOWED_USER_ID=UTEST",
    "OPERANT_LIVE_DENIED_USER_ID=UDENIEDSYNTHETIC",
    "SLACK_APP_TOKEN=xapp-synthetic-verify-token",
    "OPENAI_API_KEY=sk-synthetic-verify-token",
    "",
  ].join("\n"));
}

async function writePlaceholderEnv(file) {
  await writeFile(file, [
    "OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_...",
    "OPERANT_LIVE_ADMIN_SLACK_USER_ID=U...",
    "SLACK_CHANNEL_ID=C...",
    "SLACK_BOT_TOKEN=<slack-bot-token>",
    "SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>",
    "OPERANT_LIVE_DM_CHANNEL_ID=D...",
    "OPERANT_LIVE_DENIED_USER_TOKEN=<xoxp-or-xoxc-denied-human-user-oauth-token>",
    "SLACK_APP_TOKEN=<slack-app-token>",
    "OPENAI_API_KEY=<model-api-key>",
    "",
  ].join("\n"));
}

async function writeMismatchedProviderEnv(file) {
  await writeFile(file, [
    "OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_synthetic_verify_token",
    "OPERANT_LIVE_ADMIN_SLACK_USER_ID=USYNTHETICVERIFY",
    "OPERANT_LIVE_SLACK_TEAM_ID=TSYNTHETICVERIFY",
    "SLACK_CHANNEL_ID=CSYNTHETICVERIFY",
    "SLACK_BOT_TOKEN=xoxb-synthetic-verify-token",
    "SLACK_USER_TOKEN=xoxp-synthetic-verify-token",
    "OPERANT_LIVE_DM_CHANNEL_ID=DSYNTHETICVERIFY",
    "OPERANT_LIVE_DENIED_USER_TOKEN=xoxp-synthetic-denied-verify-token",
    "SLACK_APP_TOKEN=xapp-synthetic-verify-token",
    "MODEL_PROVIDER=anthropic",
    "OPENAI_API_KEY=sk-synthetic-verify-token",
    "",
  ].join("\n"));
}

async function writeComposeReport(file, evidenceInputs, prePath, postPath, options = {}) {
  const steps = [
    ["pass", "Compose config", "2026-05-13T23:58:00.000Z"],
    ["pass", "Compose up", "2026-05-13T23:59:00.000Z"],
    ["pass", "Operant health/ready", "2026-05-13T23:59:30.000Z"],
    ["pass", "credential/config seed", "2026-05-13T23:59:40.000Z"],
    ["pass", "credential/config verification", "2026-05-13T23:59:50.000Z"],
    ["pass", "Live preflight", "2026-05-13T23:59:55.000Z"],
    ["pass", "Operant doctor", "2026-05-13T23:59:58.000Z"],
    ["pass", "Live Slack/OpenClaw E2E", "2026-05-14T00:01:00.000Z"],
    ["pass", "Compose restart", "2026-05-14T00:02:00.000Z"],
    ["pass", "Post-restart doctor", "2026-05-14T00:03:00.000Z"],
    ["pass", "Post-restart live Slack/OpenClaw E2E", "2026-05-14T00:06:00.000Z"],
    ["pass", "Completion audit", "2026-05-14T00:07:00.000Z"],
  ].map(([status, name, recordedAt]) => ({ status, name, detail: "", recordedAt }));
  await writeJson(file, {
    format: "operant.compose-e2e-report.v1",
    phase: "finish",
    generatedAt: new Date().toISOString(),
    baseUrl: "http://127.0.0.1:8080",
    envPath: options.envPath || path.join(path.dirname(file), "strict.env"),
    liveEnvPath: options.liveEnvPath,
    reportPath: file,
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    evidenceInputs,
    liveReports: {
      preRestart: await liveReportDescriptor(prePath, "Live Slack/OpenClaw E2E"),
      postRestart: await liveReportDescriptor(postPath, "Post-restart live Slack/OpenClaw E2E"),
    },
    strictFinalGate: true,
    readyForCompletionAudit: true,
    passed: true,
    options: {},
    missingRequiredSteps: [],
    totals: { steps: steps.length, passed: steps.length, skipped: 0, blocked: 0, failed: 0 },
    steps,
  });
}

async function writeSmokeReport(file, evidenceInputs, sandbox = false, overrides = {}) {
  const steps = [
    { status: "pass", name: "environment file", detail: "synthetic.env", recordedAt: "2026-05-14T00:00:00.000Z" },
    { status: "pass", name: "Docker CLI", detail: "Docker version synthetic", recordedAt: "2026-05-14T00:00:01.000Z" },
    { status: "pass", name: "Docker Compose", detail: "Docker Compose version synthetic", recordedAt: "2026-05-14T00:00:02.000Z" },
    { status: "pass", name: "Docker daemon", detail: "synthetic", recordedAt: "2026-05-14T00:00:03.000Z" },
    { status: "skip", name: "live Slack/OpenClaw env", detail: "--skip-live", recordedAt: "2026-05-14T00:00:04.000Z" },
    { status: "pass", name: "credential seed env", detail: "required variables present", recordedAt: "2026-05-14T00:00:05.000Z" },
    { status: "pass", name: "Compose config", detail: "", recordedAt: "2026-05-14T00:00:06.000Z" },
    { status: "pass", name: "Compose up", detail: "", recordedAt: "2026-05-14T00:00:07.000Z" },
    { status: "pass", name: "Operant health/ready", detail: "http://127.0.0.1:8080", recordedAt: "2026-05-14T00:00:08.000Z" },
    { status: "pass", name: "OpenClaw gateway health", detail: "", recordedAt: "2026-05-14T00:00:09.000Z" },
    { status: "pass", name: "Redis queue profile health", detail: "", recordedAt: "2026-05-14T00:00:10.000Z" },
    { status: "pass", name: "Compose restart", detail: "", recordedAt: "2026-05-14T00:00:11.000Z" },
    { status: "pass", name: "Operant health/ready", detail: "http://127.0.0.1:8080", recordedAt: "2026-05-14T00:00:12.000Z" },
    { status: "pass", name: "Post-restart OpenClaw gateway health", detail: "", recordedAt: "2026-05-14T00:00:13.000Z" },
    { status: "pass", name: "Post-restart Redis queue profile health", detail: "", recordedAt: "2026-05-14T00:00:14.000Z" },
    { status: "pass", name: "credential/config seed", detail: "synthetic checksum synthetic-checksum", recordedAt: "2026-05-14T00:00:15.000Z" },
    { status: "pass", name: "credential SecretRef resolver", detail: "3 resolved", recordedAt: "2026-05-14T00:00:16.000Z" },
    { status: "pass", name: "credential config-validate", detail: "valid: true", recordedAt: "2026-05-14T00:00:17.000Z" },
    {
      status: "pass",
      name: "credential/config verification",
      detail: "checksum synthetic-checksum; model openai/gpt-5",
      evidence: { checksum: "synthetic-checksum", modelProvider: "openai", modelName: "gpt-5", primaryModel: "openai/gpt-5" },
      recordedAt: "2026-05-14T00:00:18.000Z",
    },
    { status: "pass", name: "integration credential seed", detail: "1 saved and resolved", recordedAt: "2026-05-14T00:00:19.000Z" },
    {
      status: "pass",
      name: "OpenClaw status",
      detail: "2026.5.18; gateway reachable; session default model: gpt-5; status scope-limited: missing scope: operator.read",
      evidence: {
        runtimeVersion: "2026.5.18",
        gatewayReachable: true,
        sessionDefaultModel: "gpt-5",
        expectedModel: "gpt-5",
        gatewayError: "missing scope: operator.read",
        securityCritical: 0,
      },
      recordedAt: "2026-05-14T00:00:20.000Z",
    },
    { status: "pass", name: "OpenClaw secrets reload", detail: "warningCount: 0", recordedAt: "2026-05-14T00:00:21.000Z" },
    { status: "pass", name: "OpenClaw usage cost", detail: "tokens: 0, cost: 0", recordedAt: "2026-05-14T00:00:22.000Z" },
    { status: "pass", name: "OpenClaw security audit", detail: "critical: 0, warn: 1", recordedAt: "2026-05-14T00:00:23.000Z" },
    { status: "pass", name: "OpenClaw doctor", detail: "no critical findings", recordedAt: "2026-05-14T00:00:24.000Z" },
    { status: "skip", name: "Completion audit", detail: "--skip-completion-audit", recordedAt: "2026-05-14T00:00:25.000Z" },
    { status: "pass", name: "Compose down", detail: "", recordedAt: "2026-05-14T00:00:26.000Z" },
  ];
  await writeJson(file, {
    format: "operant.compose-e2e-report.v1",
    phase: "finish",
    generatedAt: new Date().toISOString(),
    baseUrl: "http://127.0.0.1:8080",
    envPath: path.join(path.dirname(file), "smoke.env"),
    reportPath: file,
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    evidenceInputs,
    liveReports: {},
    mode: "non-live-smoke",
    runtimePassed: true,
    smokePassed: true,
    strictFinalGate: false,
    readyForCompletionAudit: false,
    passed: false,
    options: {
      skipLive: true,
      skipCredentialSeed: false,
      skipRestart: false,
      skipPostRestartLive: false,
      skipCompletionAudit: true,
      downAfter: true,
      downVolumes: true,
      composeProfiles: ["queue"],
      composeFiles: sandbox ? ["docker-compose.yml", "docker-compose.sandbox.yml"] : ["docker-compose.yml"],
    },
    missingRequiredSteps: ["Live preflight", "Live Slack/OpenClaw E2E", "Post-restart live Slack/OpenClaw E2E"],
    totals: {
      steps: steps.length,
      passed: steps.filter((step) => step.status === "pass").length,
      skipped: steps.filter((step) => step.status === "skip").length,
      blocked: 0,
      failed: 0,
    },
    steps,
    ...overrides,
  });
}

async function writeStrictLiveReportPair(prePath, postPath) {
  await writeJson(prePath, strictLiveReport({
    generatedAt: "2026-05-14T00:00:00.000Z",
    result: {
      ...strictLiveReport().result,
      parentTs: "111.111",
      replyTs: "111.222",
    },
  }));
  await writeJson(postPath, strictLiveReport({
    generatedAt: "2026-05-14T00:05:00.000Z",
    result: {
      ...strictLiveReport().result,
      parentTs: "222.222",
      replyTs: "222.333",
    },
  }));
}

function runAudit(reportPath, envOverrides = {}, { strictLive = true } = {}) {
  const env = {
    ...process.env,
    OPERANT_COMPOSE_E2E_REPORT: reportPath,
    ...(strictLive ? { OPERANT_REQUIRE_STRICT_LIVE: "1" } : {}),
    ...(syntheticSmokeReportPath ? { OPERANT_COMPOSE_SMOKE_REPORT: syntheticSmokeReportPath } : {}),
    ...(syntheticSandboxSmokeReportPath ? { OPERANT_COMPOSE_SANDBOX_SMOKE_REPORT: syntheticSandboxSmokeReportPath } : {}),
  };
  for (const key of envKeysToScrub) delete env[key];
  Object.assign(env, envOverrides);
  const result = spawnSync(process.execPath, ["scripts/operant-completion-audit.mjs", "--json", "--allow-blocked"], {
    cwd: repoRoot,
    env,
    encoding: "utf8",
  });
  let json = null;
  try {
    json = JSON.parse(result.stdout);
  } catch {
    // Keep null and let the assertion include stdout/stderr.
  }
  return { result, json };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertAuditAccepted(audit, label) {
  assert(audit.result.status === 0, `${label} audit exited ${audit.result.status}\n${audit.result.stdout}\n${audit.result.stderr}`);
  const strictCheck = audit.json?.checks?.find((check) => check.requirement === "Strict Compose E2E evidence report");
  assert(strictCheck?.ok === true, `${label} did not accept strict evidence\n${audit.result.stdout}\n${audit.result.stderr}`);
}

function assertAuditUsedComposeEnvFile(audit, label) {
  const liveCheck = audit.json?.checks?.find((check) => check.requirement === "Live Slack verifier credentials present");
  const seedCheck = audit.json?.checks?.find((check) => check.requirement === "Live credential-seed secrets present");
  assert(liveCheck?.ok === true, `${label} did not satisfy live verifier credentials from Compose env file\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(liveCheck?.evidence?.includes("includes Compose env file"), `${label} did not report Compose env file usage for live env\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(!liveCheck.evidence.includes("OPERANT_ADMIN_LOGIN_TOKEN"), `${label} still treated generated admin login token as missing\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(seedCheck?.ok === true, `${label} did not satisfy credential-seed secrets from Compose env file\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(seedCheck.evidence.includes("includes Compose env file"), `${label} did not report Compose env file usage for seed env\n${audit.result.stdout}\n${audit.result.stderr}`);
}

function assertAuditUsedLiveEnvFile(audit, label) {
  const liveCheck = audit.json?.checks?.find((check) => check.requirement === "Live Slack verifier credentials present");
  const seedCheck = audit.json?.checks?.find((check) => check.requirement === "Live credential-seed secrets present");
  assert(liveCheck?.ok === true, `${label} did not satisfy live verifier credentials from live env file\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(seedCheck?.ok === true, `${label} did not satisfy credential-seed secrets from live env file\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(liveCheck.evidence.includes("live env file"), `${label} did not report live env file usage for live env\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(seedCheck.evidence.includes("live env file"), `${label} did not report live env file usage for seed env\n${audit.result.stdout}\n${audit.result.stderr}`);
}

function assertAuditUsedProcessEnv(audit, label) {
  const liveCheck = audit.json?.checks?.find((check) => check.requirement === "Live Slack verifier credentials present");
  const seedCheck = audit.json?.checks?.find((check) => check.requirement === "Live credential-seed secrets present");
  assert(liveCheck?.ok === true, `${label} did not satisfy live verifier credentials from process env\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(seedCheck?.ok === true, `${label} did not satisfy credential-seed secrets from process env\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(liveCheck.evidence.includes("process env live/model keys"), `${label} did not report process env usage for live env\n${audit.result.stdout}\n${audit.result.stderr}`);
  assert(seedCheck.evidence.includes("process env live/model keys"), `${label} did not report process env usage for seed env\n${audit.result.stdout}\n${audit.result.stderr}`);
}

function assertAuditRejected(audit, expected, label) {
  assert(audit.result.status === 1, `${label} should fail the audit\n${audit.result.stdout}\n${audit.result.stderr}`);
  const body = `${audit.result.stdout}\n${audit.result.stderr}`;
  assert(body.includes(expected), `${label} did not mention "${expected}"\n${body}`);
}

function assertAuditBlocked(audit, expected, label) {
  assert(audit.result.status === 0, `${label} audit exited ${audit.result.status}\n${audit.result.stdout}\n${audit.result.stderr}`);
  const body = `${audit.result.stdout}\n${audit.result.stderr}`;
  assert(body.includes(expected), `${label} did not mention "${expected}"\n${body}`);
}

await mkdir(path.join(repoRoot, ".operant"), { recursive: true });
const tempDir = await mkdtemp(path.join(os.tmpdir(), "operant-audit-"));
const repoEvidenceDir = await mkdtemp(path.join(repoRoot, ".operant/audit-verify-"));
try {
  const livePath = (name) => path.join(repoEvidenceDir, name);
  await assertEvidenceInputListsStayInSync();
  await assertSlackBoundaryAuditCoversDashboardAssets();
  const evidenceInputs = await evidenceInputFingerprints();
  syntheticSmokeReportPath = path.join(tempDir, "compose-smoke.json");
  syntheticSandboxSmokeReportPath = path.join(tempDir, "compose-sandbox-smoke.json");
  await writeSmokeReport(syntheticSmokeReportPath, evidenceInputs);
  await writeSmokeReport(syntheticSandboxSmokeReportPath, evidenceInputs, true);
  const prePath = livePath("live-pre.json");
  const postPath = livePath("live-post.json");
  const strictComposePath = path.join(tempDir, "compose-strict.json");
  await writeSyntheticEnv(path.join(tempDir, "strict.env"));
  await writeStrictLiveReportPair(prePath, postPath);
  await writeComposeReport(strictComposePath, evidenceInputs, prePath, postPath);
  const strictAudit = runAudit(strictComposePath);
  assertAuditAccepted(strictAudit, "strict synthetic report");
  assertAuditUsedComposeEnvFile(strictAudit, "strict synthetic report");

  const optionalMissingStrictAudit = runAudit(path.join(tempDir, "missing-strict-compose.json"), {}, { strictLive: false });
  assert(
    optionalMissingStrictAudit.result.status === 0,
    `default audit should not block on missing optional strict live report\n${optionalMissingStrictAudit.result.stdout}\n${optionalMissingStrictAudit.result.stderr}`,
  );
  const optionalStrictCheck = optionalMissingStrictAudit.json?.checks?.find((check) => check.requirement === "Strict Compose E2E evidence report");
  assert(optionalStrictCheck?.ok === true, `default audit did not document optional strict live evidence\n${optionalMissingStrictAudit.result.stdout}`);

  const weakSmokePath = path.join(tempDir, "compose-weak-smoke.json");
  await writeSmokeReport(weakSmokePath, evidenceInputs, false, {
    steps: JSON.parse(await readFile(syntheticSmokeReportPath, "utf8")).steps.map((step) => (
      step.name === "credential/config verification" ? { ...step, evidence: { modelProvider: "openai", modelName: "gpt-5" } } : step
    )),
  });
  assertAuditRejected(
    runAudit(strictComposePath, { OPERANT_COMPOSE_SMOKE_REPORT: weakSmokePath }),
    "missing generated primary model evidence",
    "weak non-live smoke primary-model evidence",
  );

  const splitBaseEnvPath = path.join(tempDir, "strict-base.env");
  const splitLiveEnvPath = path.join(tempDir, "strict-live.env");
  const splitLiveEnvComposePath = path.join(tempDir, "compose-strict-live-env.json");
  await writeSyntheticBaseEnv(splitBaseEnvPath);
  await writeSyntheticLiveEnv(splitLiveEnvPath);
  await writeComposeReport(splitLiveEnvComposePath, evidenceInputs, prePath, postPath, {
    envPath: splitBaseEnvPath,
    liveEnvPath: splitLiveEnvPath,
  });
  const splitLiveEnvAudit = runAudit(splitLiveEnvComposePath);
  assertAuditAccepted(splitLiveEnvAudit, "split live env synthetic report");
  assertAuditUsedLiveEnvFile(splitLiveEnvAudit, "split live env synthetic report");

  const manualBaseEnvPath = path.join(tempDir, "strict-manual-base.env");
  const manualLiveEnvPath = path.join(tempDir, "strict-manual-live.env");
  const manualLiveEnvComposePath = path.join(tempDir, "compose-strict-manual-live-env.json");
  await writeSyntheticBaseEnv(manualBaseEnvPath);
  await writeSyntheticManualLiveEnv(manualLiveEnvPath);
  await writeComposeReport(manualLiveEnvComposePath, evidenceInputs, prePath, postPath, {
    envPath: manualBaseEnvPath,
    liveEnvPath: manualLiveEnvPath,
  });
  const manualLiveEnvAudit = runAudit(manualLiveEnvComposePath);
  assertAuditAccepted(manualLiveEnvAudit, "manual live env synthetic report");
  assertAuditUsedLiveEnvFile(manualLiveEnvAudit, "manual live env synthetic report");

  const processEnvBasePath = path.join(tempDir, "strict-process-base.env");
  const processEnvComposePath = path.join(tempDir, "compose-strict-process-env.json");
  await writeSyntheticBaseEnv(processEnvBasePath);
  await writeComposeReport(processEnvComposePath, evidenceInputs, prePath, postPath, { envPath: processEnvBasePath });
  const processEnvAudit = runAudit(processEnvComposePath, {
    OPERANT_LIVE_ADMIN_SLACK_USER_ID: "USYNTHETICVERIFY",
    OPERANT_LIVE_SLACK_TEAM_ID: "TSYNTHETICVERIFY",
    SLACK_CHANNEL_ID: "CSYNTHETICVERIFY",
    SLACK_BOT_TOKEN: "xoxb-synthetic-verify-token",
    SLACK_USER_TOKEN: "xoxp-synthetic-verify-token",
    OPERANT_LIVE_DM_CHANNEL_ID: "DSYNTHETICVERIFY",
    OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-synthetic-denied-verify-token",
    SLACK_APP_TOKEN: "xapp-synthetic-verify-token",
    OPENAI_API_KEY: "sk-synthetic-verify-token",
  });
  assertAuditAccepted(processEnvAudit, "process env synthetic report");
  assertAuditUsedProcessEnv(processEnvAudit, "process env synthetic report");

  const reusedLiveReportComposePath = path.join(tempDir, "compose-reused-live-report.json");
  await writeComposeReport(reusedLiveReportComposePath, evidenceInputs, prePath, prePath);
  assertAuditRejected(
    runAudit(reusedLiveReportComposePath),
    "pre-restart and post-restart live report paths must be distinct",
    "reused live report",
  );

  const externalLiveReportComposePath = path.join(tempDir, "compose-external-live-report.json");
  await writeComposeReport(externalLiveReportComposePath, evidenceInputs, prePath, postPath);
  const externalLiveReport = JSON.parse(await readFile(externalLiveReportComposePath, "utf8"));
  externalLiveReport.liveReports.preRestart.path = path.join(tempDir, "external-live-report.json");
  await writeJson(externalLiveReportComposePath, externalLiveReport);
  assertAuditRejected(
    runAudit(externalLiveReportComposePath),
    "live report descriptor path must be repo-relative",
    "external live report descriptor",
  );

  const stalePostLivePath = livePath("live-stale-post.json");
  const stalePostComposePath = path.join(tempDir, "compose-stale-post-live-report.json");
  await writeJson(stalePostLivePath, strictLiveReport({
    generatedAt: "2026-05-13T23:59:00.000Z",
    result: {
      ...strictLiveReport().result,
      replyTs: "222.333",
    },
  }));
  await writeComposeReport(stalePostComposePath, evidenceInputs, prePath, stalePostLivePath);
  assertAuditRejected(
    runAudit(stalePostComposePath),
    "post-restart live report must be generated after pre-restart live report",
    "stale post-restart live report",
  );

  const missingRestartTimestampPath = path.join(tempDir, "compose-missing-restart-timestamp.json");
  await writeComposeReport(missingRestartTimestampPath, evidenceInputs, prePath, postPath);
  const missingRestartTimestamp = JSON.parse(await readFile(missingRestartTimestampPath, "utf8"));
  missingRestartTimestamp.steps = missingRestartTimestamp.steps.map((step) => (
    step.name === "Compose restart" ? { ...step, recordedAt: "" } : step
  ));
  await writeJson(missingRestartTimestampPath, missingRestartTimestamp);
  assertAuditRejected(
    runAudit(missingRestartTimestampPath),
    "Compose restart step missing valid recordedAt timestamp",
    "missing restart timestamp report",
  );

  const weakRestartBoundaryPath = path.join(tempDir, "compose-weak-restart-boundary.json");
  await writeComposeReport(weakRestartBoundaryPath, evidenceInputs, prePath, postPath);
  const weakRestartBoundary = JSON.parse(await readFile(weakRestartBoundaryPath, "utf8"));
  weakRestartBoundary.steps = weakRestartBoundary.steps.map((step) => (
    step.name === "Compose restart" ? { ...step, recordedAt: "2026-05-14T00:06:30.000Z" } : step
  ));
  await writeJson(weakRestartBoundaryPath, weakRestartBoundary);
  assertAuditRejected(
    runAudit(weakRestartBoundaryPath),
    "post-restart live report must be generated after Compose restart",
    "weak restart boundary report",
  );

  const preCompletionComposePath = path.join(tempDir, "compose-pre-completion.json");
  await writeComposeReport(preCompletionComposePath, evidenceInputs, prePath, postPath);
  const preCompletion = JSON.parse(await readFile(preCompletionComposePath, "utf8"));
  preCompletion.passed = false;
  await writeJson(preCompletionComposePath, preCompletion);
  assertAuditRejected(
    runAudit(preCompletionComposePath),
    "final completion audit pass is not recorded",
    "pre-completion-audit report",
  );

  const weakPinnedLivePath = livePath("live-weak-pinned.json");
  const weakPinnedComposePath = path.join(tempDir, "compose-weak-pinned.json");
  await writeJson(weakPinnedLivePath, strictLiveReport());
  await writeComposeReport(weakPinnedComposePath, evidenceInputs, weakPinnedLivePath, postPath);
  await writeJson(weakPinnedLivePath, strictLiveReport({ result: { ...strictLiveReport().result, replyTs: "999.000" } }));
  assertAuditRejected(runAudit(weakPinnedComposePath), "live report sha256 did not match Compose descriptor", "weak pinned-live-report report");

  const weakReplyOrderPath = livePath("live-weak-reply-order.json");
  const weakReplyOrderComposePath = path.join(tempDir, "compose-weak-reply-order.json");
  await writeJson(weakReplyOrderPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      parentTs: "111.222",
      replyTs: "111.111",
    },
  }));
  await writeComposeReport(weakReplyOrderComposePath, evidenceInputs, weakReplyOrderPath, postPath);
  assertAuditRejected(
    runAudit(weakReplyOrderComposePath),
    "Slack thread reply timestamp did not follow parent timestamp",
    "weak Slack reply ordering report",
  );

  const weakRecordsPath = livePath("live-weak-records.json");
  const weakRecordsComposePath = path.join(tempDir, "compose-weak-records.json");
  await writeJson(weakRecordsPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      operantRecordDeltas: { sessions: 1, jobs: 0, usage: 1 },
    },
  }));
  await writeComposeReport(weakRecordsComposePath, evidenceInputs, weakRecordsPath, postPath);
  assertAuditRejected(runAudit(weakRecordsComposePath), "missing positive jobs record delta", "weak record-delta report");

  const weakChecksPath = livePath("live-weak-checks.json");
  const weakChecksComposePath = path.join(tempDir, "compose-weak-checks.json");
  await writeJson(weakChecksPath, strictLiveReport({
    options: {
      ...strictLiveReport().options,
      skipOpenClawChecks: true,
    },
  }));
  await writeComposeReport(weakChecksComposePath, evidenceInputs, weakChecksPath, postPath);
  assertAuditRejected(runAudit(weakChecksComposePath), "skipped OpenClaw checks", "weak OpenClaw-check report");

  const weakMissingRequiredCheckPath = livePath("live-weak-missing-required-check.json");
  const weakMissingRequiredCheckComposePath = path.join(tempDir, "compose-weak-missing-required-check.json");
  await writeJson(weakMissingRequiredCheckPath, strictLiveReport({
    options: {
      ...strictLiveReport().options,
      openClawChecks: requiredOpenClawChecks.filter((check) => check !== "usage-cost"),
    },
  }));
  await writeComposeReport(weakMissingRequiredCheckComposePath, evidenceInputs, weakMissingRequiredCheckPath, postPath);
  assertAuditRejected(
    runAudit(weakMissingRequiredCheckComposePath),
    "missing OpenClaw checks: usage-cost",
    "weak missing required OpenClaw-check report",
  );

  const weakCheckAssertionPath = livePath("live-weak-check-assertion.json");
  const weakCheckAssertionComposePath = path.join(tempDir, "compose-weak-check-assertion.json");
  await writeJson(weakCheckAssertionPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      openClawChecks: requiredOpenClawChecks.map((check) => ({
        check,
        exitCode: 0,
        timedOut: false,
        assertions: check === "usage-cost" ? [] : requiredOpenClawCheckAssertions[check] || [],
      })),
    },
  }));
  await writeComposeReport(weakCheckAssertionComposePath, evidenceInputs, weakCheckAssertionPath, postPath);
  assertAuditRejected(
    runAudit(weakCheckAssertionComposePath),
    "missing OpenClaw check assertion(s): usage-cost:usage-cost-numeric-totals",
    "weak OpenClaw-check assertion report",
  );

  const weakStatusAssertionPath = livePath("live-weak-status-assertion.json");
  const weakStatusAssertionComposePath = path.join(tempDir, "compose-weak-status-assertion.json");
  await writeJson(weakStatusAssertionPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      openClawChecks: requiredOpenClawChecks.map((check) => ({
        check,
        exitCode: 0,
        timedOut: false,
        assertions: check === "status" ? [] : requiredOpenClawCheckAssertions[check] || [],
      })),
    },
  }));
  await writeComposeReport(weakStatusAssertionComposePath, evidenceInputs, weakStatusAssertionPath, postPath);
  assertAuditRejected(
    runAudit(weakStatusAssertionComposePath),
    "missing OpenClaw check assertion(s): status:status-gateway-reachable",
    "weak status assertion report",
  );

  const weakSecretsReloadAssertionPath = livePath("live-weak-secrets-reload-assertion.json");
  const weakSecretsReloadAssertionComposePath = path.join(tempDir, "compose-weak-secrets-reload-assertion.json");
  await writeJson(weakSecretsReloadAssertionPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      openClawChecks: requiredOpenClawChecks.map((check) => ({
        check,
        exitCode: 0,
        timedOut: false,
        assertions: check === "secrets-reload" ? [] : requiredOpenClawCheckAssertions[check] || [],
      })),
    },
  }));
  await writeComposeReport(weakSecretsReloadAssertionComposePath, evidenceInputs, weakSecretsReloadAssertionPath, postPath);
  assertAuditRejected(
    runAudit(weakSecretsReloadAssertionComposePath),
    "missing OpenClaw check assertion(s): secrets-reload:secrets-reload-ok:true",
    "weak secrets-reload assertion report",
  );

  const weakChannelsStatusAssertionPath = livePath("live-weak-channels-status-assertion.json");
  const weakChannelsStatusAssertionComposePath = path.join(tempDir, "compose-weak-channels-status-assertion.json");
  await writeJson(weakChannelsStatusAssertionPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      openClawChecks: requiredOpenClawChecks.map((check) => ({
        check,
        exitCode: 0,
        timedOut: false,
        assertions: check === "channels-status" ? [] : requiredOpenClawCheckAssertions[check] || [],
      })),
    },
  }));
  await writeComposeReport(weakChannelsStatusAssertionComposePath, evidenceInputs, weakChannelsStatusAssertionPath, postPath);
  assertAuditRejected(
    runAudit(weakChannelsStatusAssertionComposePath),
    "missing OpenClaw check assertion(s): channels-status:channels-status-slack-connected,channels-status-probe:true",
    "weak channels-status assertion report",
  );

  const weakCheckResultPath = livePath("live-weak-check-result.json");
  const weakCheckResultComposePath = path.join(tempDir, "compose-weak-check-result.json");
  await writeJson(weakCheckResultPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      openClawChecks: requiredOpenClawChecks
        .filter((check) => check !== "security-audit")
        .map((check) => ({ check, exitCode: 0, timedOut: false })),
    },
  }));
  await writeComposeReport(weakCheckResultComposePath, evidenceInputs, weakCheckResultPath, postPath);
  assertAuditRejected(runAudit(weakCheckResultComposePath), "missing completed OpenClaw check result", "weak OpenClaw-check result report");

  const weakApprovalCompletionPath = livePath("live-weak-approval-completion.json");
  const weakApprovalCompletionComposePath = path.join(tempDir, "compose-weak-approval-completion.json");
  await writeJson(weakApprovalCompletionPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      slackApprovalProbe: { approvalUiTs: "777.888" },
    },
  }));
  await writeComposeReport(weakApprovalCompletionComposePath, evidenceInputs, weakApprovalCompletionPath, postPath);
  assertAuditRejected(
    runAudit(weakApprovalCompletionComposePath),
    "missing Slack approval completion timestamp",
    "weak Slack approval-completion report",
  );

  const weakApprovalParentOrderPath = livePath("live-weak-approval-parent-order.json");
  const weakApprovalParentOrderComposePath = path.join(tempDir, "compose-weak-approval-parent-order.json");
  await writeJson(weakApprovalParentOrderPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      slackApprovalProbe: {
        ...strictLiveReport().result.slackApprovalProbe,
        parentTs: "777.999",
        approvalUiTs: "777.888",
      },
    },
  }));
  await writeComposeReport(weakApprovalParentOrderComposePath, evidenceInputs, weakApprovalParentOrderPath, postPath);
  assertAuditRejected(
    runAudit(weakApprovalParentOrderComposePath),
    "Slack approval UI timestamp did not follow approval parent timestamp",
    "weak Slack approval parent ordering report",
  );

  const weakApprovalCompletionOrderPath = livePath("live-weak-approval-completion-order.json");
  const weakApprovalCompletionOrderComposePath = path.join(tempDir, "compose-weak-approval-completion-order.json");
  await writeJson(weakApprovalCompletionOrderPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      slackApprovalProbe: {
        ...strictLiveReport().result.slackApprovalProbe,
        approvalCompletionTs: "777.800",
      },
    },
  }));
  await writeComposeReport(weakApprovalCompletionOrderComposePath, evidenceInputs, weakApprovalCompletionOrderPath, postPath);
  assertAuditRejected(
    runAudit(weakApprovalCompletionOrderComposePath),
    "Slack approval completion timestamp did not follow approval UI timestamp",
    "weak Slack approval completion ordering report",
  );

  const weakBaseUrlPath = livePath("live-weak-base-url.json");
  const weakBaseUrlComposePath = path.join(tempDir, "compose-weak-base-url.json");
  await writeJson(weakBaseUrlPath, strictLiveReport({
    baseUrl: "http://127.0.0.1:9999",
  }));
  await writeComposeReport(weakBaseUrlComposePath, evidenceInputs, weakBaseUrlPath, postPath);
  assertAuditRejected(runAudit(weakBaseUrlComposePath), "did not match Compose baseUrl", "weak live base URL report");

  const weakTeamPath = livePath("live-weak-team.json");
  const weakTeamComposePath = path.join(tempDir, "compose-weak-team.json");
  await writeJson(weakTeamPath, strictLiveReport({
    slackTeamId: "TWRONGVERIFY",
    result: {
      ...strictLiveReport().result,
      slackTeamId: "TWRONGVERIFY",
      deniedProbe: { ...strictLiveReport().result.deniedProbe, teamId: "TWRONGVERIFY" },
    },
  }));
  await writeComposeReport(weakTeamComposePath, evidenceInputs, weakTeamPath, postPath);
  assertAuditRejected(runAudit(weakTeamComposePath), "did not match Compose env Slack team", "weak live Slack team report");

  const weakChannelPath = livePath("live-weak-channel.json");
  const weakChannelComposePath = path.join(tempDir, "compose-weak-channel.json");
  await writeJson(weakChannelPath, strictLiveReport({
    channelId: "CWRONGVERIFY",
    result: {
      ...strictLiveReport().result,
      channelId: "CWRONGVERIFY",
    },
  }));
  await writeComposeReport(weakChannelComposePath, evidenceInputs, weakChannelPath, postPath);
  assertAuditRejected(runAudit(weakChannelComposePath), "did not match Compose env Slack channel", "weak live channel report");

  const weakResultChannelPath = livePath("live-weak-result-channel.json");
  const weakResultChannelComposePath = path.join(tempDir, "compose-weak-result-channel.json");
  await writeJson(weakResultChannelPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      channelId: "CRESULTWRONGVERIFY",
    },
  }));
  await writeComposeReport(weakResultChannelComposePath, evidenceInputs, weakResultChannelPath, postPath);
  assertAuditRejected(
    runAudit(weakResultChannelComposePath),
    "result channelId CRESULTWRONGVERIFY did not match top-level channelId",
    "weak live result channel report",
  );

  const weakMissingResultChannelPath = livePath("live-weak-missing-result-channel.json");
  const weakMissingResultChannelComposePath = path.join(tempDir, "compose-weak-missing-result-channel.json");
  const { channelId: _omittedResultChannelId, ...resultWithoutChannel } = strictLiveReport().result;
  await writeJson(weakMissingResultChannelPath, strictLiveReport({
    result: resultWithoutChannel,
  }));
  await writeComposeReport(weakMissingResultChannelComposePath, evidenceInputs, weakMissingResultChannelPath, postPath);
  assertAuditRejected(
    runAudit(weakMissingResultChannelComposePath),
    "missing result Slack channel id",
    "weak missing live result channel report",
  );

  const weakMissingResultTeamPath = livePath("live-weak-missing-result-team.json");
  const weakMissingResultTeamComposePath = path.join(tempDir, "compose-weak-missing-result-team.json");
  const { slackTeamId: _omittedResultSlackTeamId, ...resultWithoutTeam } = strictLiveReport().result;
  await writeJson(weakMissingResultTeamPath, strictLiveReport({
    result: resultWithoutTeam,
  }));
  await writeComposeReport(weakMissingResultTeamComposePath, evidenceInputs, weakMissingResultTeamPath, postPath);
  assertAuditRejected(
    runAudit(weakMissingResultTeamComposePath),
    "missing result Slack team id",
    "weak missing live result team report",
  );

  const weakMissingResultBotPath = livePath("live-weak-missing-result-bot.json");
  const weakMissingResultBotComposePath = path.join(tempDir, "compose-weak-missing-result-bot.json");
  const { botUserId: _omittedResultBotUserId, ...resultWithoutBot } = strictLiveReport().result;
  await writeJson(weakMissingResultBotPath, strictLiveReport({
    result: resultWithoutBot,
  }));
  await writeComposeReport(weakMissingResultBotComposePath, evidenceInputs, weakMissingResultBotPath, postPath);
  assertAuditRejected(
    runAudit(weakMissingResultBotComposePath),
    "missing result Slack bot user id",
    "weak missing live result bot report",
  );

  const weakResultBotPath = livePath("live-weak-result-bot.json");
  const weakResultBotComposePath = path.join(tempDir, "compose-weak-result-bot.json");
  await writeJson(weakResultBotPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      botUserId: "UWRONGBOTVERIFY",
    },
  }));
  await writeComposeReport(weakResultBotComposePath, evidenceInputs, weakResultBotPath, postPath);
  assertAuditRejected(
    runAudit(weakResultBotComposePath),
    "result botUserId UWRONGBOTVERIFY did not match top-level botUserId",
    "weak live result bot report",
  );

  const weakDmTargetPath = livePath("live-weak-dm-target.json");
  const weakDmTargetComposePath = path.join(tempDir, "compose-weak-dm-target.json");
  await writeJson(weakDmTargetPath, strictLiveReport({
    dmChannelId: "DWRONGVERIFY",
  }));
  await writeComposeReport(weakDmTargetComposePath, evidenceInputs, weakDmTargetPath, postPath);
  assertAuditRejected(runAudit(weakDmTargetComposePath), "did not match Compose env DM channel", "weak live DM target report");

  const weakAdminTargetPath = livePath("live-weak-admin-target.json");
  const weakAdminTargetComposePath = path.join(tempDir, "compose-weak-admin-target.json");
  await writeJson(weakAdminTargetPath, strictLiveReport({
    adminSlackUserId: "UWRONGVERIFY",
  }));
  await writeComposeReport(weakAdminTargetComposePath, evidenceInputs, weakAdminTargetPath, postPath);
  assertAuditRejected(runAudit(weakAdminTargetComposePath), "did not match Compose env admin Slack user", "weak live admin target report");

  const weakObservationSyncPath = livePath("live-weak-observation-sync.json");
  const weakObservationSyncComposePath = path.join(tempDir, "compose-weak-observation-sync.json");
  await writeJson(weakObservationSyncPath, strictLiveReport({
    options: {
      ...strictLiveReport().options,
      skipObservationSync: true,
    },
  }));
  await writeComposeReport(weakObservationSyncComposePath, evidenceInputs, weakObservationSyncPath, postPath);
  assertAuditRejected(runAudit(weakObservationSyncComposePath), "skipped OpenClaw observation sync", "weak observation-sync report");

  const weakDmPath = livePath("live-weak-dm.json");
  const weakDmComposePath = path.join(tempDir, "compose-weak-dm.json");
  await writeJson(weakDmPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      dmReplyTs: null,
    },
  }));
  await writeComposeReport(weakDmComposePath, evidenceInputs, weakDmPath, postPath);
  assertAuditRejected(runAudit(weakDmComposePath), "missing DM reply timestamp", "weak DM report");

  const weakDmChannelPath = livePath("live-weak-dm-channel.json");
  const weakDmChannelComposePath = path.join(tempDir, "compose-weak-dm-channel.json");
  await writeJson(weakDmChannelPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      dmProbe: {
        ...strictLiveReport().result.dmProbe,
        channelId: "DWRONGVERIFY",
      },
    },
  }));
  await writeComposeReport(weakDmChannelComposePath, evidenceInputs, weakDmChannelPath, postPath);
  assertAuditRejected(
    runAudit(weakDmChannelComposePath),
    "DM probe channel DWRONGVERIFY did not match top-level dmChannelId",
    "weak DM probe channel report",
  );

  const weakDmOrderPath = livePath("live-weak-dm-order.json");
  const weakDmOrderComposePath = path.join(tempDir, "compose-weak-dm-order.json");
  await writeJson(weakDmOrderPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      dmReplyTs: "333.333",
      dmProbe: {
        ...strictLiveReport().result.dmProbe,
        parentTs: "333.444",
        replyTs: "333.333",
      },
    },
  }));
  await writeComposeReport(weakDmOrderComposePath, evidenceInputs, weakDmOrderPath, postPath);
  assertAuditRejected(
    runAudit(weakDmOrderComposePath),
    "DM reply timestamp did not follow DM parent timestamp",
    "weak DM ordering report",
  );

  const weakDeniedPath = livePath("live-weak-denied.json");
  const weakDeniedComposePath = path.join(tempDir, "compose-weak-denied.json");
  await writeJson(weakDeniedPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      deniedProbe: null,
    },
  }));
  await writeComposeReport(weakDeniedComposePath, evidenceInputs, weakDeniedPath, postPath);
  assertAuditRejected(runAudit(weakDeniedComposePath), "missing denied-user probe timestamp", "weak denied-user report");

  const weakDeniedDurationPath = livePath("live-weak-denied-duration.json");
  const weakDeniedDurationComposePath = path.join(tempDir, "compose-weak-denied-duration.json");
  await writeJson(weakDeniedDurationPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      deniedProbe: {
        ...strictLiveReport().result.deniedProbe,
        noReplyObservedMs: 0,
      },
    },
  }));
  await writeComposeReport(weakDeniedDurationComposePath, evidenceInputs, weakDeniedDurationPath, postPath);
  assertAuditRejected(
    runAudit(weakDeniedDurationComposePath),
    "missing denied-user no-reply observation duration",
    "weak denied-user duration report",
  );

  const weakMembershipPath = livePath("live-weak-membership.json");
  const weakMembershipComposePath = path.join(tempDir, "compose-weak-membership.json");
  await writeJson(weakMembershipPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      channelMembership: null,
    },
  }));
  await writeComposeReport(weakMembershipComposePath, evidenceInputs, weakMembershipPath, postPath);
  assertAuditRejected(
    runAudit(weakMembershipComposePath),
    "missing target-channel membership evidence",
    "weak target-channel membership report",
  );

  const weakMembershipChannelPath = livePath("live-weak-membership-channel.json");
  const weakMembershipChannelComposePath = path.join(tempDir, "compose-weak-membership-channel.json");
  await writeJson(weakMembershipChannelPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      channelMembership: {
        ...strictLiveReport().result.channelMembership,
        channelId: "CWRONGSYNTHETIC",
      },
    },
  }));
  await writeComposeReport(weakMembershipChannelComposePath, evidenceInputs, weakMembershipChannelPath, postPath);
  assertAuditRejected(
    runAudit(weakMembershipChannelComposePath),
    "did not match top-level channelId",
    "weak target-channel membership channel report",
  );

  const weakMembershipMethodPath = livePath("live-weak-membership-method.json");
  const weakMembershipMethodComposePath = path.join(tempDir, "compose-weak-membership-method.json");
  await writeJson(weakMembershipMethodPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      channelMembership: {
        ...strictLiveReport().result.channelMembership,
        method: "conversations.info",
      },
    },
  }));
  await writeComposeReport(weakMembershipMethodComposePath, evidenceInputs, weakMembershipMethodPath, postPath);
  assertAuditRejected(
    runAudit(weakMembershipMethodComposePath),
    "was not checked with conversations.members",
    "weak target-channel membership method report",
  );

  const weakAllowedMembershipPath = livePath("live-weak-allowed-membership.json");
  const weakAllowedMembershipComposePath = path.join(tempDir, "compose-weak-allowed-membership.json");
  await writeJson(weakAllowedMembershipPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      channelMembership: {
        ...strictLiveReport().result.channelMembership,
        requiredUserIds: ["UDENIEDSYNTHETIC"],
      },
    },
  }));
  await writeComposeReport(weakAllowedMembershipComposePath, evidenceInputs, weakAllowedMembershipPath, postPath);
  assertAuditRejected(
    runAudit(weakAllowedMembershipComposePath),
    "target-channel membership missing allowed test user",
    "weak allowed-user membership report",
  );

  const weakDeniedMembershipPath = livePath("live-weak-denied-membership.json");
  const weakDeniedMembershipComposePath = path.join(tempDir, "compose-weak-denied-membership.json");
  await writeJson(weakDeniedMembershipPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      channelMembership: {
        ...strictLiveReport().result.channelMembership,
        requiredUserIds: ["UTEST"],
      },
    },
  }));
  await writeComposeReport(weakDeniedMembershipComposePath, evidenceInputs, weakDeniedMembershipPath, postPath);
  assertAuditRejected(
    runAudit(weakDeniedMembershipComposePath),
    "target-channel membership missing denied test user",
    "weak denied-user membership report",
  );

  const sameUserDeniedPath = livePath("live-same-user-denied.json");
  const sameUserDeniedComposePath = path.join(tempDir, "compose-same-user-denied.json");
  await writeJson(sameUserDeniedPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      deniedProbe: {
        userId: "UTEST",
        teamId: "TSYNTHETICVERIFY",
        parentTs: "555.666",
        noReplyObservedMs: 45000,
        mode: "same-user-temporary-deny",
      },
      channelMembership: {
        channelId: "CSYNTHETICVERIFY",
        method: "conversations.members",
        requiredUserIds: ["UTEST"],
        pages: 1,
      },
    },
  }));
  await writeComposeReport(sameUserDeniedComposePath, evidenceInputs, sameUserDeniedPath, postPath);
  assertAuditAccepted(runAudit(sameUserDeniedComposePath), "same-user denied-policy report");

  const weakDeniedModePath = livePath("live-weak-denied-mode.json");
  const weakDeniedModeComposePath = path.join(tempDir, "compose-weak-denied-mode.json");
  await writeJson(weakDeniedModePath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      deniedProbe: { ...strictLiveReport().result.deniedProbe, mode: "unknown-mode" },
    },
  }));
  await writeComposeReport(weakDeniedModeComposePath, evidenceInputs, weakDeniedModePath, postPath);
  assertAuditRejected(
    runAudit(weakDeniedModeComposePath),
    "denied-user probe mode unknown-mode was not recognized",
    "weak denied-user mode report",
  );

  const weakSameUserDeniedPath = livePath("live-weak-same-user-denied.json");
  const weakSameUserDeniedComposePath = path.join(tempDir, "compose-weak-same-user-denied.json");
  await writeJson(weakSameUserDeniedPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      deniedProbe: {
        ...strictLiveReport().result.deniedProbe,
        mode: "same-user-temporary-deny",
        userId: "UDENIEDSYNTHETIC",
      },
    },
  }));
  await writeComposeReport(weakSameUserDeniedComposePath, evidenceInputs, weakSameUserDeniedPath, postPath);
  assertAuditRejected(
    runAudit(weakSameUserDeniedComposePath),
    "same-user denied probe did not use the allowed test user",
    "weak same-user denied-policy report",
  );

  const weakApprovalUiPath = livePath("live-weak-approval-ui.json");
  const weakApprovalUiComposePath = path.join(tempDir, "compose-weak-approval-ui.json");
  await writeJson(weakApprovalUiPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      slackApprovalProbe: { approvalCompletionTs: "888.999" },
    },
  }));
  await writeComposeReport(weakApprovalUiComposePath, evidenceInputs, weakApprovalUiPath, postPath);
  assertAuditRejected(runAudit(weakApprovalUiComposePath), "missing Slack approval UI timestamp", "weak Slack approval UI report");

  const weakApprovalProbePath = livePath("live-weak-approval-probe.json");
  const weakApprovalProbeComposePath = path.join(tempDir, "compose-weak-approval-probe.json");
  await writeJson(weakApprovalProbePath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      approvalProbe: {},
    },
  }));
  await writeComposeReport(weakApprovalProbeComposePath, evidenceInputs, weakApprovalProbePath, postPath);
  assertAuditRejected(runAudit(weakApprovalProbeComposePath), "missing Operant approval probe id", "weak Operant approval probe report");

  const weakApprovalPolicyPath = livePath("live-weak-approval-policy.json");
  const weakApprovalPolicyComposePath = path.join(tempDir, "compose-weak-approval-policy.json");
  await writeJson(weakApprovalPolicyPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      approvalProbe: { id: "approval-1", before: 0, after: 1, policyNames: [] },
    },
  }));
  await writeComposeReport(weakApprovalPolicyComposePath, evidenceInputs, weakApprovalPolicyPath, postPath);
  assertAuditRejected(
    runAudit(weakApprovalPolicyComposePath),
    "missing Operant approval policy evidence",
    "weak Operant approval policy report",
  );

  const weakApprovalCountPath = livePath("live-weak-approval-count.json");
  const weakApprovalCountComposePath = path.join(tempDir, "compose-weak-approval-count.json");
  await writeJson(weakApprovalCountPath, strictLiveReport({
    result: {
      ...strictLiveReport().result,
      approvalProbe: { id: "approval-1", before: 1, after: 1, policyNames: ["risky-actions"] },
    },
  }));
  await writeComposeReport(weakApprovalCountComposePath, evidenceInputs, weakApprovalCountPath, postPath);
  assertAuditRejected(
    runAudit(weakApprovalCountComposePath),
    "approval count did not increase",
    "weak Operant approval count report",
  );

  const placeholderEnvDir = path.join(tempDir, "placeholder-env");
  const placeholderComposePath = path.join(placeholderEnvDir, "compose-placeholder-env.json");
  await mkdir(placeholderEnvDir);
  const placeholderPrePath = livePath("placeholder-live-pre.json");
  const placeholderPostPath = livePath("placeholder-live-post.json");
  await writeStrictLiveReportPair(placeholderPrePath, placeholderPostPath);
  await writePlaceholderEnv(path.join(placeholderEnvDir, "strict.env"));
  await writeComposeReport(
    placeholderComposePath,
    evidenceInputs,
    placeholderPrePath,
    placeholderPostPath,
  );
  assertAuditBlocked(runAudit(placeholderComposePath), "missing or placeholder env", "placeholder env report");

  const mismatchEnvDir = path.join(tempDir, "mismatched-provider-env");
  const mismatchComposePath = path.join(mismatchEnvDir, "compose-mismatched-provider-env.json");
  await mkdir(mismatchEnvDir);
  const mismatchPrePath = livePath("mismatch-live-pre.json");
  const mismatchPostPath = livePath("mismatch-live-post.json");
  await writeStrictLiveReportPair(mismatchPrePath, mismatchPostPath);
  await writeMismatchedProviderEnv(path.join(mismatchEnvDir, "strict.env"));
  await writeComposeReport(
    mismatchComposePath,
    evidenceInputs,
    mismatchPrePath,
    mismatchPostPath,
  );
  assertAuditBlocked(runAudit(mismatchComposePath), "model API key for provider anthropic", "mismatched provider env report");

  process.stdout.write("Completion audit verifier passed.\n");
} finally {
  await rm(tempDir, { recursive: true, force: true });
  await rm(repoEvidenceDir, { recursive: true, force: true });
}
