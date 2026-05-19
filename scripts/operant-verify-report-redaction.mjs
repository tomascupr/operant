#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoSecretMaterial, redactSecretMaterial, sensitiveEnvValues, writeRedactedJsonReport } from "./operant-report-redaction.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const syntheticEnv = {
  OPERANT_COMPOSE_PROJECT_NAME: "operant-redaction",
  OPERANT_SECRET_KEY: "operant-secret-redaction-verify",
  OPERANT_INTERNAL_TOKEN: "internal-redaction-verify-token",
  OPERANT_ADMIN_LOGIN_TOKEN: "admin-redaction-verify-token",
  POSTGRES_PASSWORD: "postgres-redaction-verify-password",
  DATABASE_URL: "postgres://operant:postgres-redaction-verify-password@postgres:5432/operant",
  REDIS_URL: "redis://redis:6379/0",
  OPERANT_HTTP_PORT: "8080",
  OPENCLAW_GATEWAY_TOKEN: "gateway-redaction-verify-token",
  OPERANT_LIVE_ADMIN_SLACK_USER_ID: "UREDACTIONVERIFY",
  SLACK_CHANNEL_ID: "CREDACTIONVERIFY",
  SLACK_APP_TOKEN: "xapp-report-redaction-verify-token",
  SLACK_BOT_TOKEN: "xoxb-report-redaction-verify-token",
  SLACK_USER_TOKEN: "xoxp-report-redaction-verify-token",
  OPERANT_LIVE_DM_CHANNEL_ID: "DREDACTIONVERIFY",
  OPERANT_LIVE_DENIED_USER_TOKEN: "xoxp-denied-report-redaction-verify-token",
  OPENAI_API_KEY: "sk-report-redaction-verify-token",
  OPERANT_LIVE_INTEGRATION_CREDENTIALS: "github/api-token=GITHUB_TOKEN,custom/webhook=CUSTOMER_WEBHOOK_SECRET",
  OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON: JSON.stringify([
    { kind: "linear", key: "api-token", secretValueEnv: "LINEAR_API_KEY" },
    { kind: "internal", key: "inline-token", secretValue: "inline-dynamic-integration-redaction-secret" },
  ]),
  GITHUB_TOKEN: "ghp-dynamic-report-redaction-token",
  CUSTOMER_WEBHOOK_SECRET: "customer-webhook-report-redaction-secret",
  LINEAR_API_KEY: "lin-dynamic-report-redaction-token",
};

const syntheticSecretValues = [
  syntheticEnv.OPERANT_SECRET_KEY,
  syntheticEnv.OPERANT_INTERNAL_TOKEN,
  syntheticEnv.OPERANT_ADMIN_LOGIN_TOKEN,
  syntheticEnv.POSTGRES_PASSWORD,
  syntheticEnv.DATABASE_URL,
  syntheticEnv.OPENCLAW_GATEWAY_TOKEN,
  syntheticEnv.SLACK_APP_TOKEN,
  syntheticEnv.SLACK_BOT_TOKEN,
  syntheticEnv.SLACK_USER_TOKEN,
  syntheticEnv.OPERANT_LIVE_DENIED_USER_TOKEN,
  syntheticEnv.OPENAI_API_KEY,
  syntheticEnv.GITHUB_TOKEN,
  syntheticEnv.CUSTOMER_WEBHOOK_SECRET,
  syntheticEnv.LINEAR_API_KEY,
  "inline-dynamic-integration-redaction-secret",
];

function cleanChildEnv() {
  return {
    HOME: process.env.HOME || "",
    PATH: process.env.PATH || "/usr/bin:/bin",
    TMPDIR: process.env.TMPDIR || os.tmpdir(),
    NO_COLOR: "1",
  };
}

function runNode(args, label, env = cleanChildEnv()) {
  const result = spawnSync(process.execPath, args, {
    cwd: repoRoot,
    env,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`${label} failed with exit ${result.status}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

async function writeEnv(file) {
  await writeFile(file, `${Object.entries(syntheticEnv).map(([key, value]) => `${key}=${value}`).join("\n")}\n`);
}

async function assertReportRedacted(file, label) {
  const body = await readFile(file, "utf8");
  const report = JSON.parse(body);
  assertNoSecretMaterial(report, syntheticSecretValues);
  if (!body.includes("[redacted]")) throw new Error(`${label} did not contain redacted markers`);
}

async function assertReportArchiveRedacted(tempDir) {
  const reportPath = path.join(tempDir, "archived-report.json");
  const archiveDirectory = path.join(tempDir, "report-archive");
  const sensitiveValues = sensitiveEnvValues([syntheticEnv]);
  await writeFile(reportPath, `${JSON.stringify({
    format: "operant.synthetic-report.v1",
    generatedAt: "2026-05-16T00:00:00.000Z",
    leakedToken: syntheticEnv.SLACK_BOT_TOKEN,
  }, null, 2)}\n`);

  const { archivedPath } = await writeRedactedJsonReport(
    reportPath,
    { format: "operant.synthetic-report.v1", generatedAt: "2026-05-16T00:00:01.000Z", status: "pass" },
    sensitiveValues,
    { archiveExisting: true, archiveDirectory },
  );
  if (!archivedPath) throw new Error("report archive was not written for an existing report");
  await assertReportRedacted(archivedPath, "archived report");
  const current = JSON.parse(await readFile(reportPath, "utf8"));
  assertNoSecretMaterial(current, syntheticSecretValues);
}

function assertDynamicIntegrationCredentialRedaction() {
  const sensitiveValues = sensitiveEnvValues([syntheticEnv]);
  for (const secret of [
    syntheticEnv.GITHUB_TOKEN,
    syntheticEnv.CUSTOMER_WEBHOOK_SECRET,
    syntheticEnv.LINEAR_API_KEY,
    "inline-dynamic-integration-redaction-secret",
  ]) {
    if (!sensitiveValues.includes(secret)) {
      throw new Error(`dynamic integration credential value was not treated as sensitive: ${secret}`);
    }
  }
  const redacted = redactSecretMaterial({
    envSpec: syntheticEnv.OPERANT_LIVE_INTEGRATION_CREDENTIALS,
    envJson: syntheticEnv.OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON,
    leakedValues: [
      syntheticEnv.GITHUB_TOKEN,
      syntheticEnv.CUSTOMER_WEBHOOK_SECRET,
      syntheticEnv.LINEAR_API_KEY,
      "inline-dynamic-integration-redaction-secret",
    ],
  }, sensitiveValues);
  const body = JSON.stringify(redacted);
  assertNoSecretMaterial(redacted, syntheticSecretValues);
  if ((body.match(/\[redacted\]/g) || []).length < 4) {
    throw new Error("dynamic integration credential redaction did not redact every synthetic value");
  }
}

const tempDir = await mkdtemp(path.join(os.tmpdir(), "operant-report-redaction-"));
try {
  const composeEnvPath = path.join(tempDir, "compose.env");
  const composeReportPath = path.join(tempDir, "compose-report.json");
  const localEnvPath = path.join(tempDir, "local.env");
  const localReportPath = path.join(tempDir, "local-acceptance-report.json");
  const liveReportPath = path.join(tempDir, "live-report.json");
  await writeEnv(composeEnvPath);
  assertDynamicIntegrationCredentialRedaction();
  await assertReportArchiveRedacted(tempDir);

  runNode([
    "scripts/operant-live-e2e.mjs",
    "--self-test-report-redaction",
    "--report",
    liveReportPath,
  ], "live report redaction self-test");
  await assertReportRedacted(liveReportPath, "live report");

  runNode([
    "scripts/operant-compose-e2e.mjs",
    "--self-test-report-redaction",
    "--env",
    composeEnvPath,
    "--report",
    composeReportPath,
  ], "Compose report redaction self-test");
  await assertReportRedacted(composeReportPath, "Compose report");

  runNode([
    "scripts/operant-local-acceptance.mjs",
    "--self-test-report-redaction",
    "--env",
    localEnvPath,
    "--report",
    localReportPath,
  ], "local acceptance report redaction self-test");
  await assertReportRedacted(localReportPath, "local acceptance report");

  process.stdout.write("Report redaction verifier passed.\n");
} finally {
  await rm(tempDir, { recursive: true, force: true });
}
