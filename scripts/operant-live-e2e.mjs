#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoSecretMaterial, writeRedactedJsonReport } from "./operant-report-redaction.mjs";
import { missingScopes, requiredLiveBotScopes } from "./slack-scope-contract.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const minimumManualNudgeTimeoutMs = 30_000;
const defaultAutomatedTimeoutMs = 180_000;
const defaultManualSlackTimeoutMs = 900_000;
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
  "--dm-prompt",
  "--env",
  "--expect-reply-regex",
  "--live-env",
  "--manual-user-id",
  "--openclaw-checks",
  "--poll-interval-ms",
  "--prompt",
  "--records-timeout-ms",
  "--report",
  "--slack-team-id",
  "--timeout-ms",
]);
const flagOptions = new Set([
  "--",
  "--help",
  "-h",
  "--require-denied-user",
  "--require-dm",
  "--require-operant-records",
  "--require-slack-approval",
  "--require-slack-approval-completion",
  "--denied-use-allowed-user",
  "--self-test-arg-validation",
  "--self-test-env-loading",
  "--self-test-identity-consistency",
  "--self-test-openclaw-assertions",
  "--self-test-report-redaction",
  "--self-test-transient-retry",
  "--skip-approval-probe",
  "--skip-observation-sync",
  "--skip-openclaw-checks",
  "--skip-slack-approval-completion",
  "--skip-slack-approval-probe",
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

const envArg = argValue("--env", "");
const envPath = envArg ? path.resolve(repoRoot, envArg) : "";
const liveEnvArg = argValue("--live-env", "");
const liveEnvPath = liveEnvArg ? path.resolve(repoRoot, liveEnvArg) : "";
await applyRuntimeEnvFromFiles();
const slackApiBaseUrl = process.env.SLACK_API_BASE_URL || "https://slack.com/api";
const reportPath = path.resolve(repoRoot, argValue("--report", process.env.OPERANT_LIVE_E2E_REPORT || ".operant/live-e2e-report.json"));
const selfTestReportRedaction = hasFlag("--self-test-report-redaction");
const steps = [];
let liveReportContext = {};
let reportArchiveAttempted = false;

const placeholderEnvValues = new Set([
  "",
  "U...",
  "C...",
  "D...",
  "T...",
  "operant_admin_...",
  "xapp-...",
  "xoxb-...",
  "xoxp-test-user-token",
  "xoxp-allowed-test-user-token",
  "xoxp-denied-test-user-token",
  "sk-...",
]);

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function printUsage() {
  process.stdout.write(`Usage: operant-live-e2e [options]

Runs live Slack/OpenClaw acceptance probes and writes a sanitized evidence report.

Common options:
  --env <path>                         Base env file
  --live-env <path>                    Private live Slack/model env overlay
  --report <path>                      Evidence report output path
  --base-url <url>                     Operant control-plane URL
  --admin-slack-user-id <id>           Admin Slack user for policy setup
  --channel-id <id>                    Slack channel for mention probes
  --require-operant-records            Require persisted Operant record deltas
  --require-dm                         Require the DM probe
  --require-denied-user                Require denied-user no-reply probe
  --denied-use-allowed-user            Temporarily deny the allowed test user for the denied-user probe.
                                      This is the default when no distinct denied user is configured.
  --require-slack-approval             Require Slack approval UI probe
  --require-slack-approval-completion  Require human approval completion
  --manual-slack-posts                 Wait for human-posted Slack probes instead of posting with user tokens
  --manual-slack-nudge                 In manual mode, ask the bot to post copy/paste prompts for humans
  --manual-user-id <id>                Allowed human Slack user ID for manual probes
  --skip-openclaw-checks               Skip OpenClaw health/assertion checks
  --skip-observation-sync              Skip observation sync before record checks
  --skip-approval-probe                Skip Operant API approval probe
  --skip-slack-approval-probe          Skip Slack approval UI probe
  --skip-slack-approval-completion     Skip waiting for human Slack approval
  --self-test-arg-validation           Run CLI argument validation self-test
  --self-test-report-redaction         Run report redaction self-test
  --self-test-env-loading              Run env overlay self-test
  --self-test-identity-consistency     Run Slack identity consistency self-test
  --self-test-openclaw-assertions      Run OpenClaw assertion self-test
  --self-test-transient-retry          Run transient fetch retry self-test
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
    ".operant/test-live-report.json",
    "--base-url",
    "http://127.0.0.1:8080",
    "--admin-slack-user-id",
    "UADMIN",
    "--channel-id",
    "CCHANNEL",
    "--timeout-ms",
    "1000",
    "--poll-interval-ms",
    "100",
    "--denied-timeout-ms",
    "1000",
    "--records-timeout-ms",
    "1000",
    "--approval-completion-timeout-ms",
    "1000",
    "--dm-channel-id",
    "DDM",
    "--denied-user-token",
    "xoxp-denied",
    "--denied-user-id",
    "UDENIED",
    "--bot-user-id",
    "UBOT",
    "--slack-team-id",
    "TTEAM",
    "--openclaw-checks",
    "status,doctor",
    "--prompt",
    "hello",
    "--expect-reply-regex",
    "done",
    "--manual-user-id",
    "UALLOWED",
    "--approval-completion-regex",
    "approved",
    "--approval-prompt",
    "Use the exec tool to run exactly: echo operant-approval",
    "--dm-prompt",
    "hello in dm",
    "--require-operant-records",
    "--skip-openclaw-checks",
    "--skip-observation-sync",
    "--skip-approval-probe",
    "--skip-slack-approval-probe",
    "--skip-slack-approval-completion",
    "--manual-slack-posts",
    "--manual-slack-nudge",
    "--denied-use-allowed-user",
    "--require-dm",
    "--require-denied-user",
    "--require-slack-approval",
    "--require-slack-approval-completion",
  ]);
  assertValidationFails(["--helpful"], "Unknown option");
  assertValidationFails(["--env"], "requires a value");
  assertValidationFails(["--report", "--require-dm"], "requires a value");
  const channelNudge = manualSlackNudgeText({ userId: "UALLOWED", text: "<@UBOT> hello", label: "mention" });
  if (channelNudge.includes("<@UBOT>")) throw new Error("Manual Slack channel nudge should not include bot mention IDs");
  if (!channelNudge.includes("@Operant") || !channelNudge.includes("hello")) throw new Error("Manual Slack channel nudge lost copy instructions");
  if (!channelNudge.includes("Slack client") || !channelNudge.includes("bot_id/app_id")) {
    throw new Error("Manual Slack channel nudge should explain Slack-client-only authorship");
  }
  if (!channelNudge.includes("do not include the backticks") || !channelNudge.includes("real Slack mention")) {
    throw new Error("Manual Slack channel nudge should prevent code-block prompt pastes");
  }
  if (!manualSlackNudgeText({ userId: "UALLOWED", text: "hello", label: "mention", timeoutMs: 180_000, nowMs: 0 }).includes("expires in about 180 seconds")) {
    throw new Error("Manual Slack nudge should include the verifier expiry");
  }
  const timeoutDiagnostic = manualSlackTimeoutDiagnosticText({ userId: "UALLOWED", label: "mention", detail: "best rejected candidate: thread reply" });
  if (!timeoutDiagnostic.includes("<@UALLOWED>") || !timeoutDiagnostic.includes("new top-level message") || !timeoutDiagnostic.includes("thread reply") || !timeoutDiagnostic.includes("bot_id/app_id")) {
    throw new Error("Manual Slack timeout diagnostic should explain the missed-post recovery path");
  }
  const dmNudge = manualSlackNudgeText({ userId: "UALLOWED", text: "hello in dm", label: "DM" });
  if (dmNudge.includes("@Operant")) throw new Error("Manual Slack DM nudge should not ask for an app mention");
  if (!dmNudge.includes("hello in dm")) throw new Error("Manual Slack DM nudge lost prompt text");
  if (!isHumanAuthoredSlackMessage({ user: "UALLOWED", text: "hello" }, "UALLOWED")) {
    throw new Error("Human Slack message detector rejected a human-authored message");
  }
  if (isHumanAuthoredSlackMessage({ user: "UALLOWED", bot_id: "BAPP", app_id: "AAPP", text: "hello" }, "UALLOWED")) {
    throw new Error("Human Slack message detector accepted an app-authored message");
  }
  const appAuthoredReason = manualSlackRejectionReason({ user: "UALLOWED", bot_id: "BAPP", app_id: "AAPP", text: "hello" }, "UALLOWED", "hello");
  if (!appAuthoredReason.includes("app-authored")) throw new Error("Manual Slack rejection reason did not explain app-authored messages");
  const threadedReason = manualSlackRejectionReason({ user: "UALLOWED", thread_ts: "123.000", ts: "124.000", text: "hello" }, "UALLOWED", "hello");
  if (!threadedReason.includes("thread reply")) throw new Error("Manual Slack rejection reason did not explain threaded replies");
  const textReason = manualSlackRejectionReason({ user: "UALLOWED", text: "wrong nonce" }, "UALLOWED", "hello");
  if (!textReason.includes("expected prompt")) throw new Error("Manual Slack rejection reason did not explain text mismatches");
  if (manualSlackTextMatches("@Operant hello", "<@UBOT> hello", { requireExpectedMention: true })) {
    throw new Error("Manual Slack mention matcher accepted display-name text without Slack's real mention token");
  }
  if (!manualSlackTextMatches("<@UBOT> hello", "<@UBOT> hello", { requireExpectedMention: true })) {
    throw new Error("Manual Slack mention matcher rejected Slack's real mention token");
  }
  const missingMentionReason = manualSlackRejectionReason(
    { user: "UALLOWED", text: "```@Operant hello```", ts: "126.000" },
    "UALLOWED",
    "<@UBOT> hello",
    { requireExpectedMention: true },
  );
  if (!missingMentionReason.includes("real bot mention")) {
    throw new Error("Manual Slack rejection reason did not explain missing real bot mention");
  }
  const bestCandidate = bestManualSlackCandidate([
    { user: "UBOT", text: "hello", bot_id: "BBOT", ts: "125.000" },
    { user: "UALLOWED", text: "wrong nonce", ts: "126.000" },
  ], "UALLOWED", "hello");
  if (bestCandidate?.ts !== "126.000") throw new Error("Manual Slack candidate ranking did not prefer same-user evidence");
  const temporaryDeniedPolicy = policyWithTemporaryDeniedUser({
    allowedDmUserIds: ["UALLOWED"],
    channelPolicies: [{ channelId: "C1", name: "Original", enabled: true, requireMention: true, allowedUserIds: ["UALLOWED"], deniedUserIds: [] }],
    toolPolicies: [],
    approvalPolicies: [],
  }, "C1", "UALLOWED");
  const temporaryChannel = temporaryDeniedPolicy.channelPolicies.find((policy) => policy.channelId === "C1");
  if (!temporaryChannel?.deniedUserIds.includes("UALLOWED")) throw new Error("Temporary denied-user policy did not add the denied user");
  if (!temporaryChannel.allowedUserIds.includes("UALLOWED")) throw new Error("Temporary denied-user policy lost allowed-user membership evidence");
  let rejectedAppAuthoredPost = false;
  try {
    assertVerifierPostIsHumanAuthored({ message: { user: "UALLOWED", bot_id: "BAPP", app_id: "AAPP" } }, "mention", "UALLOWED");
  } catch (error) {
    rejectedAppAuthoredPost = String(error.message || "").includes("app-authored");
  }
  if (!rejectedAppAuthoredPost) throw new Error("Verifier post authorship check did not reject app-authored chat.postMessage output");
  if (slackClientUrl("T123", "D123") !== "https://app.slack.com/client/T123/D123") {
    throw new Error("Slack client URL self-test failed");
  }
  process.stdout.write("Live E2E argument validation self-test passed.\n");
}

function recordStep(status, name, detail = "") {
  steps.push({ status, name, detail });
}

function envValue(...names) {
  for (const name of names) {
    const value = process.env[name];
    if (value && !isPlaceholderValue(value)) return value;
  }
  return "";
}

function required(name, value) {
  if (value && !isPlaceholderValue(value)) return value;
  throw new Error(`Missing or placeholder ${name}`);
}

function numericArg(name, fallback, envName) {
  const value = Number(argValue(name, (envName ? process.env[envName] : "") || fallback));
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number`);
  return value;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function valueOrEmpty(value) {
  return value && !isPlaceholderValue(value) ? value : "";
}

function booleanEnv(name) {
  return /^(1|true|yes)$/i.test(String(process.env[name] || "").trim());
}

function manualSlackPostsEnabled() {
  return hasFlag("--manual-slack-posts") || booleanEnv("OPERANT_LIVE_MANUAL_SLACK_POSTS");
}

function manualSlackNudgeEnabled() {
  return hasFlag("--manual-slack-nudge") || booleanEnv("OPERANT_LIVE_MANUAL_SLACK_NUDGE");
}

function deniedUseAllowedUserEnabled() {
  return hasFlag("--denied-use-allowed-user") || booleanEnv("OPERANT_LIVE_DENIED_USE_ALLOWED_USER");
}

function shouldUseAllowedUserForDeniedProbe({ requireDeniedUser, deniedUserToken, deniedUserIdOverride }) {
  if (deniedUseAllowedUserEnabled()) return true;
  return Boolean(requireDeniedUser && !deniedUserToken && !deniedUserIdOverride);
}

function isLiveOverrideEnvKey(key) {
  return key.startsWith("OPERANT_LIVE_") ||
    key.startsWith("SLACK_") ||
    ["MODEL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"].includes(key);
}

function mergeRuntimeEnv(baseEnv, envFile, liveEnvFile) {
  const env = { ...baseEnv, ...envFile, ...liveEnvFile };
  for (const [key, value] of Object.entries(baseEnv)) {
    if (isLiveOverrideEnvKey(key)) env[key] = value;
  }
  return env;
}

async function readEnvFile(file, label) {
  try {
    return parseEnv(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`Missing ${label} ${file}. Check --env/--live-env or create it from deploy/slack/live.env.example. ${error.message}`);
  }
}

async function applyRuntimeEnvFromFiles() {
  const envFile = envPath ? await readEnvFile(envPath, "environment file") : {};
  const liveEnvFile = liveEnvPath ? await readEnvFile(liveEnvPath, "live environment file") : {};
  const merged = mergeRuntimeEnv(process.env, envFile, liveEnvFile);
  for (const [key, value] of Object.entries(merged)) process.env[key] = value;
}

function operantBaseUrlFromEnv(env = process.env) {
  if (env.OPERANT_LIVE_BASE_URL) return env.OPERANT_LIVE_BASE_URL;
  const port = env.OPERANT_HTTP_PORT || env.OPERANT_PORT || "8080";
  const bind = env.OPERANT_HTTP_BIND && !["0.0.0.0", "::"].includes(env.OPERANT_HTTP_BIND) ? env.OPERANT_HTTP_BIND : "127.0.0.1";
  return `http://${bind}:${port}`;
}

function countItems(payload) {
  if (!payload) return null;
  if (Array.isArray(payload.items)) return payload.items.length;
  if (Array.isArray(payload.approvals)) return payload.approvals.length;
  if (Array.isArray(payload.logs)) return payload.logs.length;
  if (payload.totals && Number.isFinite(payload.totals.events)) return payload.totals.events;
  return null;
}

function isTransientFetchError(error) {
  const parts = [
    error?.name,
    error?.message,
    error?.cause?.code,
    error?.cause?.message,
  ].filter(Boolean).join(" ");
  return /fetch failed|network|ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|UND_ERR/i.test(parts);
}

function retryDelayMs(retry, attempt) {
  const base = Number(retry?.delayMs || 500);
  const max = Number(retry?.maxDelayMs || 2_500);
  return Math.max(1, Math.min(max, base * (2 ** Math.max(0, attempt - 1))));
}

async function jsonFetch(url, options = {}) {
  const { fetchImpl = fetch, retry = null, ...fetchOptions } = options;
  const attempts = Math.max(1, Number(retry?.attempts || 1));
  let lastError = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetchImpl(url, fetchOptions);
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
    } catch (error) {
      lastError = error;
      if (attempt >= attempts || !isTransientFetchError(error)) throw error;
      const pathname = (() => {
        try {
          return new URL(url).pathname;
        } catch {
          return "request";
        }
      })();
      process.stdout.write(`warn: transient fetch failure for ${pathname}; retrying ${attempt}/${attempts - 1}: ${error.message}\n`);
      await sleep(retryDelayMs(retry, attempt));
    }
  }
  throw lastError;
}

async function runTransientRetrySelfTest() {
  let calls = 0;
  const response = await jsonFetch("https://slack.com/api/conversations.history", {
    method: "GET",
    retry: { attempts: 3, delayMs: 1, maxDelayMs: 1 },
    fetchImpl: async () => {
      calls += 1;
      if (calls < 3) throw new TypeError("fetch failed");
      return new Response(JSON.stringify({ ok: true, messages: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  if (calls !== 3 || response.payload?.ok !== true) {
    throw new Error("transient retry self-test did not retry fetch failures before succeeding");
  }
  let nonTransientCalls = 0;
  let rejected = false;
  try {
    await jsonFetch("https://slack.com/api/conversations.history", {
      method: "GET",
      retry: { attempts: 3, delayMs: 1, maxDelayMs: 1 },
      fetchImpl: async () => {
        nonTransientCalls += 1;
        throw new Error("schema failure");
      },
    });
  } catch {
    rejected = true;
  }
  if (!rejected || nonTransientCalls !== 1) {
    throw new Error("transient retry self-test retried a non-transient failure");
  }
  process.stdout.write("Live E2E transient retry self-test passed.\n");
}

async function writeLiveReport(status, payload = {}) {
  const failedSteps = steps.filter((step) => step.status === "fail");
  const blockedSteps = steps.filter((step) => step.status === "blocked");
  const report = {
    format: "operant.live-e2e-report.v1",
    generatedAt: new Date().toISOString(),
    status,
    passed: status === "pass" && failedSteps.length === 0 && blockedSteps.length === 0,
    reportPath,
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    ...liveReportContext,
    totals: {
      steps: steps.length,
      passed: steps.filter((step) => step.status === "pass").length,
      skipped: steps.filter((step) => step.status === "skip").length,
      blocked: blockedSteps.length,
      failed: failedSteps.length,
    },
    steps,
    ...payload,
  };
  const archiveExisting = !selfTestReportRedaction && !reportArchiveAttempted;
  reportArchiveAttempted = true;
  const { report: redactedReport, archivedPath } = await writeRedactedJsonReport(reportPath, report, undefined, { archiveExisting });
  if (archivedPath) process.stdout.write(`Archived previous Live E2E report: ${archivedPath}\n`);
  process.stdout.write(`Live E2E report: ${reportPath}\n`);
  return redactedReport;
}

async function runReportRedactionSelfTest() {
  const syntheticEnv = {
    OPERANT_ADMIN_LOGIN_TOKEN: "admin-login-redaction-secret-12345",
    SLACK_APP_TOKEN: `${"xapp"}-redaction-self-test-token`,
    SLACK_BOT_TOKEN: `${"xoxb"}-redaction-self-test-token`,
    SLACK_USER_TOKEN: `${"xoxp"}-redaction-self-test-token`,
    MODEL_API_KEY: "model-redaction-secret-12345",
    OPENAI_API_KEY: `${"sk"}-redaction-self-test-token`,
    ANTHROPIC_API_KEY: `${"sk"}-ant-redaction-self-test-token`,
  };
  const previousEnv = Object.fromEntries(Object.keys(syntheticEnv).map((key) => [key, process.env[key]]));
  const previousContext = liveReportContext;
  const previousSteps = steps.splice(0, steps.length);
  try {
    for (const [key, value] of Object.entries(syntheticEnv)) process.env[key] = value;
    liveReportContext = {
      baseUrl: "http://127.0.0.1:8080",
      channelId: "CREDACTIONSELFTEST",
      dmChannelId: "DREDACTIONSELFTEST",
      slackTeamId: "TREDACTIONSELFTEST",
      botUserId: "UBOTREDACTIONSELFTEST",
      testUserId: "UUSERREDACTIONSELFTEST",
      redactionSelfTest: {
        exactSecret: syntheticEnv.OPERANT_ADMIN_LOGIN_TOKEN,
        tokenLikeSecret: `${"xoxb"}-unlisted-token-shaped-secret`,
      },
    };
    recordStep("pass", "Report redaction self-test", `bot=${syntheticEnv.SLACK_BOT_TOKEN}`);
    const redacted = await writeLiveReport("pass", {
      result: {
        channelId: "CREDACTIONSELFTEST",
        slackTeamId: "TREDACTIONSELFTEST",
        botUserId: "UBOTREDACTIONSELFTEST",
        exactEnvSecret: syntheticEnv.MODEL_API_KEY,
        nested: {
          slackTokens: [syntheticEnv.SLACK_APP_TOKEN, syntheticEnv.SLACK_USER_TOKEN],
          providerTokens: [syntheticEnv.OPENAI_API_KEY, syntheticEnv.ANTHROPIC_API_KEY],
          unlistedTokenLikeValue: `${"sk"}-unlisted-redaction-self-test-token`,
        },
      },
      error: `synthetic failure text with ${syntheticEnv.SLACK_BOT_TOKEN}`,
    });
    const reportBody = await readFile(reportPath, "utf8");
    const leaked = Object.values(syntheticEnv).filter((secret) => reportBody.includes(secret));
    if (leaked.length > 0) throw new Error(`Redaction self-test leaked ${leaked.length} synthetic secret(s)`);
    if (!reportBody.includes("[redacted]")) throw new Error("Redaction self-test report did not contain redacted markers");
    const parsedReport = JSON.parse(reportBody);
    if (parsedReport.channelId !== parsedReport.result?.channelId) throw new Error("Live report redaction self-test lost result-level channel identity");
    if (parsedReport.slackTeamId !== parsedReport.result?.slackTeamId) throw new Error("Live report redaction self-test lost result-level Slack team identity");
    if (parsedReport.botUserId !== parsedReport.result?.botUserId) throw new Error("Live report redaction self-test lost result-level bot identity");
    assertNoSecretMaterial(parsedReport, Object.values(syntheticEnv));
    assertNoSecretMaterial(redacted, Object.values(syntheticEnv));
    process.stdout.write("Live E2E report redaction self-test passed.\n");
  } finally {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    liveReportContext = previousContext;
    steps.splice(0, steps.length, ...previousSteps);
  }
}

async function runEnvLoadingSelfTest() {
  const dir = await mkdtemp(path.join(os.tmpdir(), "operant-live-e2e-env-"));
  try {
    const baseEnvPath = path.join(dir, "base.env");
    const liveEnvPathForTest = path.join(dir, "live.env");
    await writeFile(baseEnvPath, [
      "OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_synthetic_live",
      "SLACK_BOT_TOKEN=xoxb-base-should-be-overridden",
      "SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>",
      "",
    ].join("\n"));
    await writeFile(liveEnvPathForTest, [
      "OPERANT_LIVE_ADMIN_SLACK_USER_ID=USYNTHETICLIVE",
      "SLACK_CHANNEL_ID=CSYNTHETICLIVE",
      "SLACK_BOT_TOKEN=xoxb-live-env-token",
      "SLACK_USER_TOKEN=xoxp-live-env-token",
      "OPERANT_LIVE_DM_CHANNEL_ID=DSYNTHETICLIVE",
      "OPERANT_LIVE_DENIED_USER_TOKEN=xoxp-denied-live-env-token",
      "",
    ].join("\n"));
    const merged = mergeRuntimeEnv(
      {
        SLACK_BOT_TOKEN: "xoxb-process-wins-token",
        OPENAI_API_KEY: "sk-process-wins-token",
      },
      parseEnv(await readFile(baseEnvPath, "utf8")),
      parseEnv(await readFile(liveEnvPathForTest, "utf8")),
    );
    if (merged.OPERANT_ADMIN_LOGIN_TOKEN !== "operant_admin_synthetic_live") throw new Error("base env file did not load");
    if (merged.SLACK_USER_TOKEN !== "xoxp-live-env-token") throw new Error("live env file did not override base env");
    if (merged.SLACK_BOT_TOKEN !== "xoxb-process-wins-token") throw new Error("process live env did not retain precedence");
    if (merged.OPENAI_API_KEY !== "sk-process-wins-token") throw new Error("process model env did not retain precedence");
    if (envValueFromObject(merged, "SLACK_USER_TOKEN") !== "xoxp-live-env-token") throw new Error("loaded live env was not usable");
    if (operantBaseUrlFromEnv({ OPERANT_HTTP_BIND: "127.0.0.1", OPERANT_HTTP_PORT: "59772" }) !== "http://127.0.0.1:59772") {
      throw new Error("generated Compose HTTP port was not used for live base URL");
    }
    if (operantBaseUrlFromEnv({ OPERANT_HTTP_BIND: "0.0.0.0", OPERANT_HTTP_PORT: "18080" }) !== "http://127.0.0.1:18080") {
      throw new Error("wildcard bind was not normalized to a local live base URL");
    }
    if (valueOrEmpty("<slack-bot-token>")) throw new Error("angle-bracket placeholder was not rejected");
    process.stdout.write("Live E2E env loading self-test passed.\n");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function assertSlackIdentityMatch(label, configuredUserId, authUserId) {
  if (configuredUserId && authUserId && configuredUserId !== authUserId) {
    throw new Error(`${label} ${configuredUserId} does not match Slack auth.test user_id ${authUserId}`);
  }
}

function assertSlackBotTokenIdentity(label, identity) {
  if (!identity?.user_id) throw new Error(`${label} auth.test did not return a user_id`);
  if (!identity?.bot_id) throw new Error(`${label} must be a Slack bot token, but auth.test did not return bot_id`);
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

function assertSlackUserTokenIdentity(label, identity) {
  if (!identity?.user_id) throw new Error(`${label} auth.test did not return a user_id`);
  if (identity.bot_id) throw new Error(`${label} must be a Slack user token, but auth.test returned bot_id`);
}

function assertDistinctSlackUsers(leftLabel, leftUserId, rightLabel, rightUserId) {
  if (leftUserId && rightUserId && leftUserId === rightUserId) {
    throw new Error(`${leftLabel} and ${rightLabel} resolve to the same Slack user`);
  }
}

function slackTeamIdFromIdentity(identity) {
  return String(identity?.team_id || "").trim();
}

function assertSlackTeamMatch(label, expectedTeamId, actualLabel, actualTeamId) {
  const expected = String(expectedTeamId || "").trim();
  const actual = String(actualTeamId || "").trim();
  if (!expected) return;
  if (!actual) throw new Error(`${actualLabel} auth.test did not return team_id for Slack team consistency with ${label}`);
  if (expected !== actual) throw new Error(`Slack team ${label} ${expected} does not match ${actualLabel} ${actual}`);
}

function runIdentityConsistencySelfTest() {
  assertSlackIdentityMatch("configured bot user ID", "", "UBOT");
  assertSlackIdentityMatch("configured bot user ID", "UBOT", "UBOT");
  assertSlackIdentityMatch("configured denied-user ID", "UDENIED", "UDENIED");
  assertSlackBotTokenIdentity("Slack bot token", { user_id: "UBOT", bot_id: "BBOT" });
  assertSlackUserTokenIdentity("Slack test-user token", { user_id: "UTEST" });
  assertDistinctSlackUsers("Slack test-user token", "UTEST", "denied Slack user token", "UDENIED");
  assertSlackTeamMatch("configured Slack team ID", "TVALID", "Slack bot token auth.test team_id", "TVALID");
  assertSlackTeamMatch("Slack bot token auth.test team_id", "TVALID", "Slack test-user token auth.test team_id", "TVALID");
  for (const [label, configured, actual] of [
    ["configured bot user ID", "UWRONGBOT", "UBOT"],
    ["configured denied-user ID", "UWRONGDENIED", "UDENIED"],
  ]) {
    try {
      assertSlackIdentityMatch(label, configured, actual);
    } catch (error) {
      if (!String(error.message || "").includes("does not match Slack auth.test user_id")) {
        throw new Error(`Live E2E identity consistency self-test failed with unexpected error: ${error.message}`);
      }
      continue;
    }
    throw new Error(`Live E2E identity consistency self-test did not reject ${label}`);
  }
  for (const [operation, expectedMessage, failureMessage] of [
    [
      () => assertSlackBotTokenIdentity("Slack bot token", { user_id: "UUSER" }),
      "must be a Slack bot token",
      "Live E2E identity consistency self-test did not reject user token as bot token",
    ],
    [
      () => assertSlackUserTokenIdentity("Slack test-user token", { user_id: "UBOT", bot_id: "BBOT" }),
      "must be a Slack user token",
      "Live E2E identity consistency self-test did not reject bot token as test-user token",
    ],
    [
      () => assertDistinctSlackUsers("Slack test-user token", "USAME", "denied Slack user token", "USAME"),
      "resolve to the same Slack user",
      "Live E2E identity consistency self-test did not reject duplicate allowed/denied Slack users",
    ],
    [
      () => assertSlackTeamMatch("configured Slack team ID", "TEXPECTED", "Slack bot token auth.test team_id", "TACTUAL"),
      "Slack team",
      "Live E2E identity consistency self-test did not reject mismatched configured Slack team ID",
    ],
    [
      () => assertSlackTeamMatch("Slack bot token auth.test team_id", "TEXPECTED", "denied Slack user token auth.test team_id", "TACTUAL"),
      "Slack team",
      "Live E2E identity consistency self-test did not reject Slack tokens from different workspaces",
    ],
  ]) {
    try {
      operation();
    } catch (error) {
      if (!String(error.message || "").includes(expectedMessage)) {
        throw new Error(`${failureMessage}: unexpected error ${error.message}`);
      }
      continue;
    }
    throw new Error(failureMessage);
  }
  process.stdout.write("Live E2E identity consistency self-test passed.\n");
}

function assertIncludesAll(label, actual, expected) {
  const missing = expected.filter((value) => !actual.includes(value));
  if (missing.length > 0) throw new Error(`${label} missing assertion(s): ${missing.join(", ")}`);
}

function assertOpenClawCheckRejects(label, check, json, expectedMessage) {
  try {
    openClawCheckAssertions(check, json);
  } catch (error) {
    if (!String(error.message || "").includes(expectedMessage)) {
      throw new Error(`${label} rejected with unexpected error: ${error.message}`);
    }
    return;
  }
  throw new Error(`${label} did not reject malformed OpenClaw check output`);
}

function runOpenClawAssertionSelfTest() {
  assertIncludesAll("config-validate", openClawCheckAssertions("config-validate", { valid: true }), ["config-valid:true"]);
  assertIncludesAll(
    "status",
    openClawCheckAssertions("status", { gateway: { reachable: true }, securityAudit: { summary: { critical: 0 } } }),
    ["status-gateway-reachable", "status-security-critical:0"],
  );
  assertIncludesAll("secrets-reload", openClawCheckAssertions("secrets-reload", { ok: true }), ["secrets-reload-ok:true"]);
  assertIncludesAll("tasks-list", openClawCheckAssertions("tasks-list", { tasks: [] }), ["tasks-json"]);
  assertIncludesAll("usage-cost", openClawCheckAssertions("usage-cost", { totals: { totalTokens: 1, totalCost: 0.01 } }), ["usage-cost-numeric-totals"]);
  assertIncludesAll("security-audit", openClawCheckAssertions("security-audit", { summary: { critical: 0 } }), ["security-critical:0"]);
  assertIncludesAll(
    "channels-status",
    openClawCheckAssertions("channels-status", { ok: true, slack: { connected: true, probe: true } }),
    ["channels-status-slack-connected", "channels-status-probe:true"],
  );
  assertIncludesAll(
    "channels-status-current-shape",
    openClawCheckAssertions("channels-status", {
      channels: { slack: { configured: true, running: true, probe: { ok: true } } },
      channelAccounts: { slack: [{ enabled: true, configured: true, running: true, connected: true, probe: { ok: true } }] },
    }),
    ["channels-status-slack-connected", "channels-status-probe:true"],
  );
  assertIncludesAll(
    "channels-status-config-only",
    openClawCheckAssertions("channels-status", { configOnly: true, configuredChannels: ["slack"] }),
    ["channels-status-configured"],
  );

  assertOpenClawCheckRejects("config-validate", "config-validate", { valid: false }, "valid: true");
  assertOpenClawCheckRejects("status gateway", "status", { gateway: { reachable: false } }, "reachable gateway");
  assertOpenClawCheckRejects(
    "status embedded security audit",
    "status",
    { gateway: { reachable: true }, securityAudit: { summary: { critical: 1 } } },
    "embedded security audit",
  );
  assertOpenClawCheckRejects("secrets-reload", "secrets-reload", { ok: false }, "ok: true");
  assertOpenClawCheckRejects("tasks-list", "tasks-list", { tasks: null }, "task JSON");
  assertOpenClawCheckRejects("usage-cost", "usage-cost", { totals: {} }, "numeric totals");
  assertOpenClawCheckRejects("security-audit missing critical", "security-audit", { summary: {} }, "numeric critical count");
  assertOpenClawCheckRejects("security-audit critical finding", "security-audit", { summary: { critical: 1 } }, "critical finding");
  assertOpenClawCheckRejects("channels-status configured", "channels-status", { ok: false, slack: { connected: true, probe: true } }, "Slack configured");
  assertOpenClawCheckRejects("channels-status connected", "channels-status", { ok: true, slack: { connected: false, probe: true } }, "Slack connected");
  assertOpenClawCheckRejects("channels-status probe", "channels-status", { ok: true, slack: { connected: true, probe: false } }, "successful Slack probe");
  process.stdout.write("Live E2E OpenClaw assertion self-test passed.\n");
}

function envValueFromObject(env, name) {
  const value = env[name];
  return value && !isPlaceholderValue(value) ? value : "";
}

async function slack(method, token, params = {}, httpMethod = "POST") {
  const url = new URL(`${slackApiBaseUrl.replace(/\/$/, "")}/${method}`);
  const options = {
    method: httpMethod,
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
  };
  if (httpMethod === "GET") {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
    }
  } else {
    options.headers["content-type"] = "application/json; charset=utf-8";
    options.body = JSON.stringify(params);
  }
  const safeToRetry = httpMethod === "GET" || method === "auth.test" || method === "apps.connections.open";
  const { response, payload } = await jsonFetch(url, {
    ...options,
    retry: safeToRetry ? { attempts: 4, delayMs: 500, maxDelayMs: 2_500 } : null,
  });
  if (payload && typeof payload === "object") {
    Object.defineProperty(payload, "__responseHeaders", {
      value: {
        oauthScopes: response.headers?.get?.("x-oauth-scopes") || "",
      },
      enumerable: false,
    });
  }
  if (!response.ok || !payload?.ok) {
    throw new Error(`Slack ${method} failed: ${payload?.error || response.statusText || response.status}`);
  }
  return payload;
}

async function slackConversationMembers(label, token, channelId, requiredUserIds) {
  const missing = new Set(requiredUserIds.filter(Boolean));
  let cursor = "";
  let pages = 0;
  do {
    const payload = await slack("conversations.members", token, { channel: channelId, limit: 1000, cursor }, "GET");
    if (!Array.isArray(payload.members)) {
      throw new Error(`${label} conversations.members did not return a members array`);
    }
    for (const member of payload.members) missing.delete(String(member));
    cursor = String(payload.response_metadata?.next_cursor || "").trim();
    pages += 1;
    if (pages > 100) throw new Error(`${label} conversations.members pagination exceeded 100 pages`);
  } while (cursor && missing.size > 0);
  if (missing.size > 0) {
    throw new Error(`${label} conversations.members did not include ${Array.from(missing).join(", ")}; keep both allowed and denied test users in the test channel so Operant policy, not Slack membership, suppresses the denied-user bot reply`);
  }
  return {
    channelId,
    method: "conversations.members",
    requiredUserIds,
    pages,
  };
}

async function operant(baseUrl, route, options = {}) {
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

async function optionalOperantCount(baseUrl, token, route) {
  try {
    return countItems(await operant(baseUrl, route, { token }));
  } catch (error) {
    process.stdout.write(`warn: could not read ${route}: ${error.message}\n`);
    return null;
  }
}

async function readOperantCounts(baseUrl, token) {
  return {
    sessions: await optionalOperantCount(baseUrl, token, "/api/sessions"),
    jobs: await optionalOperantCount(baseUrl, token, "/api/jobs"),
    usage: await optionalOperantCount(baseUrl, token, "/api/usage/summary"),
  };
}

async function runApprovalProbe(baseUrl, adminToken, nonce) {
  const before = await optionalOperantCount(baseUrl, adminToken, "/api/approvals");
  const approval = await operant(baseUrl, "/api/approvals", {
    method: "POST",
    token: adminToken,
    body: {
      action: "exec:live-e2e",
      resource: "openclaw_task",
      payload: { source: "operant-live-e2e", nonce },
    },
  });
  if (!approval.id) throw new Error("Approval probe did not return an approval id");
  if (!approval.payload?.operantApproval) throw new Error("Approval probe did not record approval policy metadata");
  const decided = await operant(baseUrl, `/api/approvals/${approval.id}/decision`, {
    method: "POST",
    token: adminToken,
    body: { status: "approved" },
  });
  if (decided.status !== "approved") throw new Error(`Approval probe decision status was ${decided.status}`);
  const listed = await operant(baseUrl, "/api/approvals", { token: adminToken });
  const stored = listed.items?.find((item) => item.id === approval.id);
  if (!stored || stored.status !== "approved") throw new Error("Approval probe did not persist an approved approval record");
  return {
    id: approval.id,
    before,
    after: countItems(listed),
    policyNames: approval.payload.operantApproval.policyNames || [],
  };
}

function countDeltas(before, after) {
  return Object.fromEntries(
    Object.keys(after).map((key) => [key, before[key] === null || after[key] === null ? null : after[key] - before[key]]),
  );
}

function missingRequiredRecordDeltas(deltas) {
  return ["sessions", "jobs", "usage"].filter((key) => !(typeof deltas[key] === "number" && deltas[key] > 0));
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function numberValue(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function openClawCheckAssertions(check, json) {
  const body = objectValue(json);
  const assertions = [];
  if (check === "config-validate") {
    if (body?.valid !== true) throw new Error("OpenClaw config-validate did not return valid: true");
    assertions.push("config-valid:true");
  }
  if (check === "status") {
    const gateway = objectValue(body?.gateway);
    if (gateway?.reachable !== true) throw new Error("OpenClaw status did not report a reachable gateway");
    assertions.push("status-gateway-reachable");
    const securityAudit = objectValue(body?.securityAudit);
    const summary = objectValue(securityAudit?.summary);
    const critical = numberValue(summary?.critical);
    if (critical !== null) {
      if (critical > 0) throw new Error(`OpenClaw status embedded security audit reported ${critical} critical finding(s)`);
      assertions.push("status-security-critical:0");
    }
  }
  if (check === "secrets-reload") {
    if (body?.ok !== true) throw new Error("OpenClaw secrets reload did not return ok: true");
    assertions.push("secrets-reload-ok:true");
  }
  if (check === "tasks-list") {
    if (!Array.isArray(body?.tasks)) throw new Error("OpenClaw tasks-list did not return task JSON");
    assertions.push("tasks-json");
  }
  if (check === "usage-cost") {
    const totals = objectValue(body?.totals);
    const totalTokens = numberValue(totals?.totalTokens ?? body?.totalTokens);
    const totalCost = numberValue(totals?.totalCost ?? body?.totalCost);
    if (totalTokens === null || totalCost === null) throw new Error("OpenClaw usage-cost did not return numeric totals");
    assertions.push("usage-cost-numeric-totals");
  }
  if (check === "security-audit") {
    const summary = objectValue(body?.summary);
    const critical = numberValue(summary?.critical ?? body?.critical);
    if (critical === null) throw new Error("OpenClaw security-audit did not return a numeric critical count");
    if (critical > 0) throw new Error(`OpenClaw security-audit reported ${critical} critical finding(s)`);
    assertions.push("security-critical:0");
  }
  if (check === "channels-status") {
    const slack = slackChannelsStatus(body);
    if (slack.configured !== true) throw new Error("OpenClaw channels-status did not report Slack configured");
    if (slack.configOnly === true) {
      assertions.push("channels-status-configured");
      return assertions;
    }
    if (slack.running !== true) throw new Error("OpenClaw channels-status did not report Slack running");
    if (slack.connected !== true) throw new Error("OpenClaw channels-status did not report Slack connected");
    if (slack.probeOk !== true) throw new Error("OpenClaw channels-status did not report a successful Slack probe");
    assertions.push("channels-status-slack-connected", "channels-status-probe:true");
  }
  return assertions;
}

function slackChannelsStatus(body) {
  if (body?.configOnly === true) {
    const configuredChannels = Array.isArray(body.configuredChannels) ? body.configuredChannels.map(String) : [];
    return {
      configured: configuredChannels.includes("slack") || Boolean(objectValue(body?.config)?.channels),
      configOnly: true,
      running: false,
      connected: false,
      probeOk: false,
    };
  }
  const legacySlack = objectValue(body?.slack);
  if (legacySlack) {
    return {
      configured: body?.ok === true,
      configOnly: false,
      running: body?.ok === true,
      connected: legacySlack.connected === true,
      probeOk: legacySlack.probe === true,
    };
  }
  const channels = objectValue(body?.channels);
  const slack = objectValue(channels?.slack);
  const channelAccounts = objectValue(body?.channelAccounts);
  const slackAccounts = Array.isArray(channelAccounts?.slack) ? channelAccounts.slack : [];
  const account = slackAccounts.map(objectValue).find((item) => item?.enabled !== false) || null;
  const channelProbe = objectValue(slack?.probe);
  const accountProbe = objectValue(account?.probe);
  return {
    configured: slack?.configured === true || account?.configured === true,
    configOnly: false,
    running: slack?.running === true || account?.running === true,
    connected: account?.connected === true || slack?.healthState === "healthy",
    probeOk: channelProbe?.ok === true || accountProbe?.ok === true,
  };
}

function slackInboundStatus(body) {
  const channels = objectValue(body?.channels);
  const slack = objectValue(channels?.slack);
  const channelAccounts = objectValue(body?.channelAccounts);
  const slackAccounts = Array.isArray(channelAccounts?.slack) ? channelAccounts.slack : [];
  const account = slackAccounts.map(objectValue).find((item) => item?.enabled !== false) || null;
  return {
    configured: slack?.configured === true || account?.configured === true,
    running: slack?.running === true || account?.running === true,
    connected: account?.connected === true || slack?.healthState === "healthy",
    lastInboundAt: numberValue(account?.lastInboundAt ?? slack?.lastInboundAt),
    lastOutboundAt: numberValue(account?.lastOutboundAt ?? slack?.lastOutboundAt),
  };
}

function slackTsToEpochMs(ts) {
  const parsed = Number(ts);
  return Number.isFinite(parsed) ? Math.floor(parsed * 1000) : null;
}

async function openClawSlackIngressDiagnostic(baseUrl, token, postedTs) {
  const { response, payload: result } = await operantRaw(baseUrl, "/api/openclaw/checks/channels-status", {
    method: "POST",
    token,
    body: {},
  });
  if (!response.ok || !result || typeof result !== "object") return null;
  const status = slackInboundStatus(result.json);
  const postedAtMs = slackTsToEpochMs(postedTs);
  const inboundAfterMessage = status.lastInboundAt !== null && postedAtMs !== null && status.lastInboundAt >= postedAtMs - 1000;
  return { ...status, inboundAfterMessage };
}

async function enrichReplyTimeout(error, context) {
  if (!String(error.message || "").startsWith("Timed out waiting for bot reply")) throw error;
  let diagnostic = null;
  try {
    diagnostic = await openClawSlackIngressDiagnostic(context.baseUrl, context.adminToken, context.postedTs);
  } catch {
    diagnostic = null;
  }
  if (!diagnostic) throw error;
  const inbound = diagnostic.lastInboundAt === null ? "never" : new Date(diagnostic.lastInboundAt).toISOString();
  if (diagnostic.inboundAfterMessage) {
    throw new Error([
      error.message,
      `OpenClaw Slack channel status did receive an inbound event after that message (lastInboundAt=${inbound}, connected=${diagnostic.connected}), but no bot thread reply appeared before the verifier timeout.`,
      "This isolates Slack delivery from OpenClaw execution/reply handling; check OpenClaw gateway logs, model-provider errors, policy decisions, and whether the stack was stopped before the reply window completed.",
    ].join(" "));
  }
  throw new Error([
    error.message,
    `OpenClaw Slack channel status stayed without an inbound event after that message (lastInboundAt=${inbound}, connected=${diagnostic.connected}).`,
    "Slack scopes and apps.connections.open are not enough here: they prove token validity, not event delivery. Enable Socket Mode and Event Subscriptions on the same Slack app as the bot token, subscribe to bot events app_mention, message.channels, and message.im, save the app manifest, reinstall or re-authorize the app, then rerun live acceptance.",
  ].join(" "));
}

function isOpenClawPairingRequired(result) {
  return /pairing required|device is not approved/i.test([
    result?.stderr,
    result?.stdout,
    JSON.stringify(result?.json || {}),
  ].filter(Boolean).join("\n"));
}

function openClawPairingGuidance(check) {
  return [
    `OpenClaw check ${check} requires an approved paired operator device.`,
    "On the gateway host, review `openclaw devices list`, approve the exact request ID with `openclaw devices approve <requestId>`, then rerun live acceptance.",
    "Required operator scopes include operator.read, operator.approvals, and operator.talk.secrets; operator.admin satisfies them.",
  ].join(" ");
}

const pairingOptionalOpenClawChecks = new Set(["secrets-reload", "approvals-get", "cron-status", "usage-cost", "channels-status"]);

async function waitForOperantRecordDeltas(baseUrl, token, before, timeoutMs, pollIntervalMs, sync) {
  const deadline = Date.now() + timeoutMs;
  if (sync) await sync();
  let after = await readOperantCounts(baseUrl, token);
  let deltas = countDeltas(before, after);
  while (missingRequiredRecordDeltas(deltas).length > 0 && Date.now() < deadline) {
    await sleep(pollIntervalMs);
    if (sync) await sync();
    after = await readOperantCounts(baseUrl, token);
    deltas = countDeltas(before, after);
  }
  return { after, deltas };
}

async function runOpenClawChecks(baseUrl, token, checks) {
  await operant(baseUrl, "/api/openclaw/checks", { token });
  const results = [];
  for (const check of checks) {
    process.stdout.write(`openclaw: ${check}\n`);
    const { response, payload: result } = await operantRaw(baseUrl, `/api/openclaw/checks/${check}`, { method: "POST", token, body: {} });
    if (!result || typeof result !== "object") {
      throw new Error(`OpenClaw check ${check} returned an empty or malformed response (${response.status})`);
    }
    if (pairingOptionalOpenClawChecks.has(check) && isOpenClawPairingRequired(result)) {
      process.stdout.write(`openclaw: ${check} skipped; operator device pairing required\n`);
      results.push({
        check,
        skipped: true,
        reason: "operator device pairing required",
        exitCode: result.exitCode,
        timedOut: Boolean(result.timedOut),
        stdoutBytes: String(result.stdout || "").length,
        stderrBytes: String(result.stderr || "").length,
        jsonType: result.json === undefined ? null : Array.isArray(result.json) ? "array" : typeof result.json,
        assertions: [],
      });
      continue;
    }
    if (!response.ok || result.timedOut || result.exitCode !== 0) {
      if (isOpenClawPairingRequired(result)) {
        if (pairingOptionalOpenClawChecks.has(check)) {
          process.stdout.write(`openclaw: ${check} skipped; operator device pairing required\n`);
          results.push({
            check,
            skipped: true,
            reason: "operator device pairing required",
            exitCode: result.exitCode,
            timedOut: Boolean(result.timedOut),
            stdoutBytes: String(result.stdout || "").length,
            stderrBytes: String(result.stderr || "").length,
            jsonType: result.json === undefined ? null : Array.isArray(result.json) ? "array" : typeof result.json,
            assertions: [],
          });
          continue;
        }
        throw new Error(`${openClawPairingGuidance(check)} stderr=${String(result.stderr || "").slice(0, 500)}`);
      }
      throw new Error(`OpenClaw check ${check} failed with HTTP ${response.status} exit ${result.exitCode}; stderr=${String(result.stderr || result.error || "").slice(0, 500)}`);
    }
    const assertions = openClawCheckAssertions(check, result.json);
    results.push({
      check,
      exitCode: result.exitCode,
      timedOut: Boolean(result.timedOut),
      stdoutBytes: String(result.stdout || "").length,
      stderrBytes: String(result.stderr || "").length,
      jsonType: result.json === undefined ? null : Array.isArray(result.json) ? "array" : typeof result.json,
      assertions,
    });
  }
  return results;
}

async function operantRaw(baseUrl, route, options = {}) {
  const headers = { accept: "application/json" };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  return jsonFetch(new URL(route, baseUrl), {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
}

function slackTsAfter(ts, afterTs) {
  if (!afterTs) return true;
  const left = String(ts || "").replace(".", "");
  const right = String(afterTs || "").replace(".", "");
  if (/^\d+$/.test(left) && /^\d+$/.test(right)) return BigInt(left) > BigInt(right);
  return Number(ts) > Number(afterTs);
}

async function pollForBotReply(params) {
  const { botToken, channelId, parentTs, botUserId, botId, timeoutMs, pollIntervalMs, expectedTextPattern, afterTs } = params;
  const deadline = Date.now() + timeoutMs;
  let lastMessageCount = 0;
  while (Date.now() < deadline) {
    const replies = await slack("conversations.replies", botToken, { channel: channelId, ts: parentTs, limit: 50 }, "GET");
    const messages = Array.isArray(replies.messages) ? replies.messages : [];
    lastMessageCount = messages.length;
    const reply = messages.find((message) => {
      if (message.ts === parentTs) return false;
      if (!slackTsAfter(message.ts, afterTs)) return false;
      return isBotMessage(message, botUserId, botId);
    });
    if (reply) {
      if (expectedTextPattern && !expectedTextPattern.test(reply.text || "")) {
        throw new Error(`Bot replied, but text did not match ${expectedTextPattern}: ${reply.text || ""}`);
      }
      return reply;
    }
    await sleep(pollIntervalMs);
  }
  throw new Error(`Timed out waiting for bot reply in thread ${parentTs}${afterTs ? ` after ${afterTs}` : ""}; saw ${lastMessageCount} messages`);
}

function isBotMessage(message, botUserId, botId) {
  if (message.user === botUserId) return true;
  if (botId && message.bot_id === botId) return true;
  if (botId && message.bot_profile?.id === botId) return true;
  return false;
}

function expectedSlackMentionToken(expected) {
  const match = /^<@[A-Z0-9]+>\s*/.exec(String(expected || ""));
  return match ? match[0].trim() : "";
}

function manualSlackTextMatches(actual, expected, options = {}) {
  const actualText = String(actual || "");
  const expectedText = String(expected || "");
  const mentionToken = expectedSlackMentionToken(expectedText);
  if (options.requireExpectedMention && mentionToken && !actualText.includes(mentionToken)) return false;
  if (actualText.includes(expectedText)) return true;
  const withoutMention = expectedText.replace(/^<@[A-Z0-9]+>\s*/, "").trim();
  return Boolean(withoutMention && actualText.includes(withoutMention));
}

function isHumanAuthoredSlackMessage(message, userId) {
  return message?.user === userId && !message.bot_id && !message.app_id && message.subtype !== "bot_message";
}

function manualSlackRejectionReason(message, userId, expectedText, options = {}) {
  if (!message || typeof message !== "object") return "message was not a Slack message object";
  if (message.user !== userId) return `message user ${message.user || "unknown"} did not match expected human ${userId}`;
  if (message.bot_id || message.app_id || message.subtype === "bot_message") return "message was app-authored with bot_id/app_id/subtype, not human-authored";
  if (message.thread_ts && message.thread_ts !== message.ts) return `message was a thread reply to ${message.thread_ts}; post a new top-level message`;
  const mentionToken = expectedSlackMentionToken(expectedText);
  if (options.requireExpectedMention && mentionToken && !String(message.text || "").includes(mentionToken)) {
    return `message did not include Slack's real bot mention ${mentionToken}; type or select @Operant in Slack instead of pasting prompt text in a code block`;
  }
  if (!manualSlackTextMatches(message.text, expectedText, options)) return "message text did not include the expected prompt/nonce";
  return "";
}

function manualSlackCandidateScore(message, userId, expectedText, options = {}) {
  let score = 0;
  if (message?.user === userId) score += 8;
  if (manualSlackTextMatches(message?.text, expectedText, options)) score += 4;
  if (isHumanAuthoredSlackMessage(message, userId)) score += 2;
  const mentionToken = expectedSlackMentionToken(expectedText);
  if (mentionToken && String(message?.text || "").includes(mentionToken)) score += 2;
  if (!message?.thread_ts || message.thread_ts === message.ts) score += 1;
  return score;
}

function bestManualSlackCandidate(messages, userId, expectedText, options = {}) {
  let best = null;
  let bestScore = 0;
  for (const message of messages) {
    const score = manualSlackCandidateScore(message, userId, expectedText, options);
    if (score > bestScore) {
      best = message;
      bestScore = score;
    }
  }
  return best;
}

function compactSlackTextPreview(text) {
  const compact = String(text || "").replace(/\s+/g, " ").trim();
  if (compact.length <= 160) return compact;
  return `${compact.slice(0, 157)}...`;
}

function manualSlackCandidateDetail(message, userId, expectedText, options = {}) {
  if (!message) return "no recent candidate messages were visible to the bot token";
  const reason = manualSlackRejectionReason(message, userId, expectedText, options) || "candidate looked valid but was not accepted";
  const flags = [
    message.bot_id ? "bot_id" : "",
    message.app_id ? "app_id" : "",
    message.subtype ? `subtype=${message.subtype}` : "",
    message.thread_ts && message.thread_ts !== message.ts ? `thread_ts=${message.thread_ts}` : "",
  ].filter(Boolean);
  const flagText = flags.length ? ` flags=${flags.join(",")}` : "";
  const preview = compactSlackTextPreview(message.text);
  return `ts=${message.ts || "unknown"} user=${message.user || "unknown"}${flagText}; ${reason}${preview ? `; text=\"${preview}\"` : ""}`;
}

function assertVerifierPostIsHumanAuthored(posted, label, userId) {
  const message = posted?.message || {};
  if (isHumanAuthoredSlackMessage(message, userId)) return;
  if (message.bot_id || message.app_id || message.subtype === "bot_message") {
    throw new Error(
      `Slack ${label} verifier post was app-authored (bot_id/app_id present) even though the token auth.test resolved to ${userId}. ` +
      "The verifier already requested chat.postMessage as_user=true. OpenClaw ignores app-authored messages to avoid bot loops; use --manual-slack-posts for live acceptance or provide a Slack token/path that creates a human-authored message.",
    );
  }
}

function slackClientUrl(teamId, channelId) {
  const team = String(teamId || "").trim();
  const channel = String(channelId || "").trim();
  if (!team || !channel) return "";
  return `https://app.slack.com/client/${encodeURIComponent(team)}/${encodeURIComponent(channel)}`;
}

function manualSlackExpiryText(timeoutMs, nowMs = Date.now()) {
  const timeoutSeconds = Math.max(1, Math.round(Number(timeoutMs || 0) / 1000));
  const expiresAt = Math.floor((nowMs + timeoutSeconds * 1000) / 1000);
  return `This prompt expires in about ${timeoutSeconds} seconds, around <!date^${expiresAt}^{time_secs}|${new Date(expiresAt * 1000).toISOString()}>. Late messages are ignored.`;
}

function manualSlackHumanAuthorshipText(label) {
  const place = label === "DM" ? "that DM" : "this channel";
  return `Type it directly in the Slack client as the named human user in ${place}. Do not send it with a Slack OAuth/user token, webhook, workflow, or API client; messages with bot_id/app_id do not count even if Slack displays a human name.`;
}

function manualSlackNudgeText({ userId, text, label, timeoutMs, nowMs }) {
  const body = String(text || "").replace(/^<@[A-Z0-9]+>\s*/, "").trim();
  const copyLineOnly = "Copy only the message line inside the code block; do not include the backticks, quotes, or this instruction text.";
  if (label === "DM") {
    return [
      `Manual Operant live E2E: <@${userId}> please post this exact DM message as a new message:`,
      "```",
      body,
      "```",
      copyLineOnly,
      "This evidence must be posted in the Operant DM, not in a channel and not as a thread reply.",
      "If Slack says bot DMs are not enabled, enable App Home > Messages tab for the installed Slack app and make it writable.",
      manualSlackHumanAuthorshipText(label),
      manualSlackExpiryText(timeoutMs, nowMs),
    ].join("\n");
  }
  return [
    `Manual Operant live E2E: <@${userId}> please post this exact new ${label} message in this channel:`,
    "```",
    `@Operant ${body}`,
    "```",
    copyLineOnly,
    "The @Operant text must resolve to a real Slack mention of the bot; pasted code-block text is rejected.",
    manualSlackHumanAuthorshipText(label),
    manualSlackExpiryText(timeoutMs, nowMs),
  ].join("\n");
}

function manualSlackDmChannelReminderText({ userId, text, dmUrl, timeoutMs, nowMs }) {
  const body = String(text || "").replace(/^<@[A-Z0-9]+>\s*/, "").trim();
  return [
    `Manual Operant live E2E: <@${userId}> the verifier is waiting for a DM to Operant, not a channel message.`,
    dmUrl ? `Open the Operant DM: ${dmUrl}` : "Open the Operant DM with the bot.",
    "Post only this line as a fresh DM message:",
    "```",
    body,
    "```",
    "Do not post this DM evidence in the channel; this channel reminder is only a pointer.",
    "If Slack says bot DMs are not enabled, enable App Home > Messages tab for the installed Slack app and make it writable.",
    manualSlackExpiryText(timeoutMs, nowMs),
  ].join("\n");
}

function manualSlackTimeoutDiagnosticText({ userId, label, detail }) {
  const diagnostic = compactSlackTextPreview(detail);
  return [
    `Manual Operant live E2E timeout: no matching human-authored ${label} message from <@${userId}> arrived before the verifier window closed.`,
    "Rerun the verifier and post the newest prompt as a new top-level message before the expiry. Older messages, thread replies, and bot-authored nudges are ignored.",
    "If a message appears under a human display name but the diagnostic shows bot_id/app_id, Slack stored it as app/API-authored and OpenClaw will intentionally ignore it.",
    diagnostic ? `Diagnostic: ${diagnostic}` : "",
  ].filter(Boolean).join("\n");
}

async function sendManualSlackNudge({ botToken, channelId, userId, text, label, timeoutMs }) {
  if (timeoutMs < minimumManualNudgeTimeoutMs) {
    const detail = `${timeoutMs}ms timeout is below ${minimumManualNudgeTimeoutMs}ms minimum for bot-posted prompts`;
    recordStep("skip", `Manual Slack ${label} nudge`, detail);
    process.stdout.write(`slack manual: skipping bot nudge because ${detail}\n`);
    return null;
  }
  const nudgeText = manualSlackNudgeText({ userId, text, label, timeoutMs });
  const posted = await slack("chat.postMessage", botToken, { channel: channelId, text: nudgeText });
  if (!posted.ts) throw new Error(`Slack chat.postMessage did not return a message timestamp for manual ${label} nudge`);
  recordStep("pass", `Manual Slack ${label} nudge`, `${channelId} ${posted.ts}`);
  return posted;
}

async function sendManualSlackDmChannelReminder({ botToken, channelId, userId, text, dmUrl, timeoutMs }) {
  if (!channelId) return null;
  if (timeoutMs < minimumManualNudgeTimeoutMs) return null;
  const reminderText = manualSlackDmChannelReminderText({ userId, text, dmUrl, timeoutMs });
  const posted = await slack("chat.postMessage", botToken, { channel: channelId, text: reminderText });
  if (posted.ts) recordStep("pass", "Manual Slack DM channel reminder", `${channelId} ${posted.ts}`);
  return posted;
}

async function sendManualSlackTimeoutDiagnostic({ botToken, channelId, userId, label, detail }) {
  try {
    const text = manualSlackTimeoutDiagnosticText({ userId, label, detail });
    const posted = await slack("chat.postMessage", botToken, { channel: channelId, text });
    if (posted.ts) recordStep("pass", `Manual Slack ${label} timeout diagnostic`, `${channelId} ${posted.ts}`);
    return posted;
  } catch (error) {
    recordStep("skip", `Manual Slack ${label} timeout diagnostic`, error.message || String(error));
    return null;
  }
}

async function botReplied(params) {
  try {
    return await pollForBotReply(params);
  } catch (error) {
    if (String(error.message || "").startsWith("Timed out waiting for bot reply")) return null;
    throw error;
  }
}

async function pollForUserMessage(params) {
  const { botToken, channelId, userId, expectedText, timeoutMs, pollIntervalMs, startedAtMs, label } = params;
  const deadline = Date.now() + timeoutMs;
  const oldest = Math.max(0, Math.floor((startedAtMs - 5_000) / 1000));
  const matchOptions = { requireExpectedMention: Boolean(expectedSlackMentionToken(expectedText)) };
  let lastMessageCount = 0;
  let bestRejectedCandidate = null;
  while (Date.now() < deadline) {
    const history = await slack("conversations.history", botToken, { channel: channelId, limit: 100, oldest, inclusive: true }, "GET");
    const messages = Array.isArray(history.messages) ? history.messages : [];
    lastMessageCount = messages.length;
    const message = messages.find((candidate) => {
      if (!isHumanAuthoredSlackMessage(candidate, userId)) return false;
      if (candidate.thread_ts && candidate.thread_ts !== candidate.ts) return false;
      return manualSlackTextMatches(candidate.text, expectedText, matchOptions);
    });
    if (message?.ts) return message;
    const rejectedCandidate = bestManualSlackCandidate(messages, userId, expectedText, matchOptions);
    if (manualSlackCandidateScore(rejectedCandidate, userId, expectedText, matchOptions) > manualSlackCandidateScore(bestRejectedCandidate, userId, expectedText, matchOptions)) {
      bestRejectedCandidate = rejectedCandidate;
    }
    await sleep(pollIntervalMs);
  }
  const detail = manualSlackCandidateDetail(bestRejectedCandidate, userId, expectedText, matchOptions);
  throw new Error(`Timed out waiting for ${label} manual Slack message from ${userId} in ${channelId}; observed ${lastMessageCount} recent message(s) since ${new Date(oldest * 1000).toISOString()}; best rejected candidate: ${detail}`);
}

async function postOrWaitForSlackProbe(params) {
  const { manual, manualNudge, token, botToken, channelId, userId, text, label, timeoutMs, pollIntervalMs, slackTeamId, nudgeMirrorChannelId } = params;
  if (!manual) {
    const posted = await slack("chat.postMessage", token, { channel: channelId, text, as_user: true, unfurl_links: false, unfurl_media: false });
    if (!posted.ts) throw new Error(`Slack chat.postMessage did not return a message timestamp for ${label}`);
    assertVerifierPostIsHumanAuthored(posted, label, userId);
    return posted;
  }
  const startedAtMs = Date.now();
  const channelUrl = slackClientUrl(slackTeamId, channelId);
  if (manualNudge) {
    await sendManualSlackNudge({ botToken, channelId, userId, text, label, timeoutMs });
    if (label === "DM" && nudgeMirrorChannelId && nudgeMirrorChannelId !== channelId) {
      await sendManualSlackDmChannelReminder({ botToken, channelId: nudgeMirrorChannelId, userId, text, dmUrl: channelUrl, timeoutMs });
    }
  }
  const linkHint = channelUrl ? `\nslack manual: open ${channelUrl}` : "";
  const body = String(text || "").replace(/^<@[A-Z0-9]+>\s*/, "").trim();
  const humanText = label === "DM" ? body : `@Operant ${body}`;
  const mentionHint = expectedSlackMentionToken(text)
    ? " The @Operant text must resolve to a real Slack bot mention; do not wrap it in backticks or paste it as a code block."
    : "";
  process.stdout.write(`slack manual: post this ${label} message in ${channelId} as ${userId} while this command is running. Type it directly in the Slack client; do not use token/API automation. The verifier rejects bot_id/app_id messages and expired prompts. Keep the body/nonce exact.${mentionHint}${linkHint}\n${humanText}\n`);
  try {
    return await pollForUserMessage({ botToken, channelId, userId, expectedText: text, timeoutMs, pollIntervalMs, startedAtMs, label });
  } catch (error) {
    if (manualNudge) {
      await sendManualSlackTimeoutDiagnostic({
        botToken,
        channelId,
        userId,
        label,
        detail: error.message || String(error),
      });
    }
    throw error;
  }
}

function messageMatchesApprovalUi(message) {
  const body = JSON.stringify({
    text: message.text || "",
    blocks: message.blocks || [],
    attachments: message.attachments || [],
  });
  return /approval required|requires approval|approve|deny|authorize|permission/i.test(body);
}

async function pollForApprovalUi(params) {
  const { botToken, channelId, parentTs, botUserId, botId, timeoutMs, pollIntervalMs } = params;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const replies = await slack("conversations.replies", botToken, { channel: channelId, ts: parentTs, limit: 50 }, "GET");
    const messages = Array.isArray(replies.messages) ? replies.messages : [];
    const approvalMessage = messages.find(
      (message) => message.ts !== parentTs && isBotMessage(message, botUserId, botId) && messageMatchesApprovalUi(message),
    );
    if (approvalMessage) return approvalMessage;
    await sleep(pollIntervalMs);
  }
  throw new Error(`Timed out waiting for OpenClaw approval UI in thread ${parentTs}`);
}

function policyEvaluateBody(params) {
  return {
    slackUserId: params.slackUserId,
    slackChannelId: params.slackChannelId,
    chatType: params.chatType,
    action: "message",
    resource: "slack",
  };
}

async function requirePolicyEffect(baseUrl, adminToken, body, expectedEffect, label) {
  const decision = await operant(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body,
  });
  if (decision.effect !== expectedEffect) {
    throw new Error(`${label} policy decision was ${decision.effect}, expected ${expectedEffect}: ${JSON.stringify(decision.reasons || [])}`);
  }
  return decision;
}

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim())));
}

function policyWithTemporaryDeniedUser(policy, channelId, userId) {
  const channelPolicies = Array.isArray(policy.channelPolicies) ? policy.channelPolicies : [];
  let found = false;
  const updatedChannels = channelPolicies.map((channelPolicy) => {
    if (channelPolicy.channelId !== channelId) return {
      channelId: channelPolicy.channelId,
      name: channelPolicy.name ?? null,
      enabled: channelPolicy.enabled !== false,
      requireMention: channelPolicy.requireMention !== false,
      allowedUserIds: uniqueStrings(channelPolicy.allowedUserIds || []),
      deniedUserIds: uniqueStrings(channelPolicy.deniedUserIds || []),
    };
    found = true;
    return {
      channelId: channelPolicy.channelId,
      name: channelPolicy.name ?? "Live E2E temporary deny",
      enabled: true,
      requireMention: true,
      allowedUserIds: uniqueStrings([...(channelPolicy.allowedUserIds || []), userId]),
      deniedUserIds: uniqueStrings([...(channelPolicy.deniedUserIds || []), userId]),
    };
  });
  if (!found) {
    updatedChannels.push({
      channelId,
      name: "Live E2E temporary deny",
      enabled: true,
      requireMention: true,
      allowedUserIds: [userId],
      deniedUserIds: [userId],
    });
  }
  return {
    allowedDmUserIds: uniqueStrings(policy.allowedDmUserIds || []),
    channelPolicies: updatedChannels,
    toolPolicies: Array.isArray(policy.toolPolicies) ? policy.toolPolicies : [],
    approvalPolicies: Array.isArray(policy.approvalPolicies) ? policy.approvalPolicies : [],
  };
}

async function putPolicyAndWait(baseUrl, adminToken, policy, label) {
  const result = await operant(baseUrl, "/api/policy", { method: "PUT", token: adminToken, body: policy });
  recordStep("pass", label, result.config?.checksum || "policy updated");
  const waitMs = Number(process.env.OPERANT_LIVE_POLICY_RELOAD_WAIT_MS || 5_000);
  if (Number.isFinite(waitMs) && waitMs > 0) await sleep(waitMs);
  return result.policy;
}

async function main() {
  const baseUrl = argValue("--base-url", operantBaseUrlFromEnv());
  const adminSlackUserId = required(
    "--admin-slack-user-id or OPERANT_LIVE_ADMIN_SLACK_USER_ID",
    argValue("--admin-slack-user-id", envValue("OPERANT_LIVE_ADMIN_SLACK_USER_ID")),
  );
  const channelId = required("--channel-id or SLACK_CHANNEL_ID", argValue("--channel-id", envValue("SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID")));
  const botToken = required("SLACK_BOT_TOKEN or OPERANT_LIVE_SLACK_BOT_TOKEN", envValue("OPERANT_LIVE_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN"));
  const manualSlackPosts = manualSlackPostsEnabled();
  const manualSlackNudge = manualSlackNudgeEnabled();
  const userToken = valueOrEmpty(envValue("OPERANT_LIVE_SLACK_USER_TOKEN", "SLACK_USER_TOKEN"));
  const manualUserId = valueOrEmpty(argValue("--manual-user-id", process.env.OPERANT_LIVE_ALLOWED_USER_ID || ""));
  if (!manualSlackPosts && !userToken) {
    throw new Error("Missing or placeholder SLACK_USER_TOKEN or OPERANT_LIVE_SLACK_USER_TOKEN; alternatively use --manual-slack-posts with --manual-user-id or OPERANT_LIVE_ALLOWED_USER_ID");
  }
  const timeoutMs = numericArg("--timeout-ms", manualSlackPosts ? defaultManualSlackTimeoutMs : defaultAutomatedTimeoutMs, "OPERANT_LIVE_TIMEOUT_MS");
  const pollIntervalMs = numericArg("--poll-interval-ms", 5_000, "OPERANT_LIVE_POLL_INTERVAL_MS");
  const deniedTimeoutMs = numericArg("--denied-timeout-ms", 45_000, "OPERANT_LIVE_DENIED_TIMEOUT_MS");
  const recordsTimeoutMs = numericArg("--records-timeout-ms", 45_000, "OPERANT_LIVE_RECORDS_TIMEOUT_MS");
  const approvalCompletionTimeoutMs = numericArg("--approval-completion-timeout-ms", timeoutMs, "OPERANT_LIVE_APPROVAL_COMPLETION_TIMEOUT_MS");
  const requireOperantRecords = hasFlag("--require-operant-records");
  const skipOpenClawChecks = hasFlag("--skip-openclaw-checks");
  const skipObservationSync = hasFlag("--skip-observation-sync");
  const skipApprovalProbe = hasFlag("--skip-approval-probe");
  const skipSlackApprovalProbe = hasFlag("--skip-slack-approval-probe");
  const skipSlackApprovalCompletion = hasFlag("--skip-slack-approval-completion");
  const requireDm = hasFlag("--require-dm");
  const requireDeniedUser = hasFlag("--require-denied-user");
  const requireSlackApproval = hasFlag("--require-slack-approval");
  const requireSlackApprovalCompletion = hasFlag("--require-slack-approval-completion");
  const dmChannelId = valueOrEmpty(argValue("--dm-channel-id", envValue("OPERANT_LIVE_DM_CHANNEL_ID")));
  const deniedUserToken = valueOrEmpty(argValue("--denied-user-token", envValue("OPERANT_LIVE_DENIED_USER_TOKEN")));
  const deniedUserIdOverride = valueOrEmpty(argValue("--denied-user-id", process.env.OPERANT_LIVE_DENIED_USER_ID || ""));
  const deniedUseAllowedUser = shouldUseAllowedUserForDeniedProbe({ requireDeniedUser, deniedUserToken, deniedUserIdOverride });
  const configuredBotUserId = valueOrEmpty(argValue("--bot-user-id", process.env.OPERANT_LIVE_BOT_USER_ID || ""));
  const configuredSlackTeamId = valueOrEmpty(argValue("--slack-team-id", envValue("OPERANT_LIVE_SLACK_TEAM_ID", "SLACK_TEAM_ID")));
  const openClawChecks = argValue("--openclaw-checks", "config-validate,status,secrets-reload,approvals-get,cron-status,tasks-list,usage-cost,doctor,security-audit,channels-status")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const nonce = randomBytes(4).toString("hex");
  const prompt = argValue(
    "--prompt",
    process.env.OPERANT_LIVE_PROMPT || `Operant live E2E ${nonce}: reply in this thread with a short confirmation.`,
  );
  const expectedText = argValue("--expect-reply-regex", process.env.OPERANT_LIVE_EXPECT_REPLY_REGEX || "");
  const expectedTextPattern = expectedText ? new RegExp(expectedText, "i") : null;
  const approvalCompletionText = argValue("--approval-completion-regex", process.env.OPERANT_LIVE_APPROVAL_COMPLETION_REGEX || "");
  const approvalCompletionTextPattern = approvalCompletionText ? new RegExp(approvalCompletionText, "i") : null;
  const approvalPrompt = argValue(
    "--approval-prompt",
    process.env.OPERANT_LIVE_APPROVAL_PROMPT || `Operant approval E2E ${nonce}: use the exec tool to run exactly: echo operant-approval-${nonce}`,
  );
  if (requireDm && !dmChannelId) throw new Error("Missing --dm-channel-id or OPERANT_LIVE_DM_CHANNEL_ID for --require-dm");
  if (requireDeniedUser && !deniedUserToken && !(manualSlackPosts && deniedUserIdOverride) && !deniedUseAllowedUser) {
    throw new Error("Missing denied-user configuration for --require-denied-user; provide a distinct denied-user token/ID or use the default same-user temporary deny mode");
  }
  if (requireSlackApproval && skipSlackApprovalProbe) throw new Error("--require-slack-approval cannot be combined with --skip-slack-approval-probe");
  if (requireSlackApprovalCompletion && skipSlackApprovalCompletion) throw new Error("--require-slack-approval-completion cannot be combined with --skip-slack-approval-completion");
  if (requireSlackApprovalCompletion && skipSlackApprovalProbe) throw new Error("--require-slack-approval-completion cannot be combined with --skip-slack-approval-probe");
  liveReportContext = {
    baseUrl,
    slackApiBaseUrl,
    channelId,
    dmChannelId: dmChannelId || null,
    adminSlackUserId,
    options: {
      requireOperantRecords,
      skipOpenClawChecks,
      skipObservationSync,
      skipApprovalProbe,
      skipSlackApprovalProbe,
      skipSlackApprovalCompletion,
      requireDm,
      requireDeniedUser,
      requireSlackApproval,
      requireSlackApprovalCompletion,
      manualSlackPosts,
      manualSlackNudge,
      deniedUseAllowedUser,
      openClawChecks,
    },
  };

  process.stdout.write(`operant: ${baseUrl}\n`);
  process.stdout.write(`slack channel: ${channelId}\n`);

  await operant(baseUrl, "/healthz");
  await operant(baseUrl, "/readyz");
  recordStep("pass", "Operant health/ready");
  const adminLoginToken = required("OPERANT_ADMIN_LOGIN_TOKEN", envValue("OPERANT_ADMIN_LOGIN_TOKEN"));
  const login = await operant(baseUrl, "/api/auth/login", {
    method: "POST",
    body: { slackUserId: adminSlackUserId, adminLoginToken },
  });
  const adminToken = login.token;
  if (!adminToken) throw new Error("Operant login did not return a bearer token");
  recordStep("pass", "Operant admin login", adminSlackUserId);

  const botIdentity = await slack("auth.test", botToken);
  const userIdentity = userToken ? await slack("auth.test", userToken) : null;
  const botTeamId = slackTeamIdFromIdentity(botIdentity);
  const userTeamId = slackTeamIdFromIdentity(userIdentity);
  assertSlackBotTokenIdentity("Slack bot token", botIdentity);
  assertSlackBotScopes("Slack bot token", botIdentity);
  assertSlackIdentityMatch("configured bot user ID", configuredBotUserId, botIdentity.user_id || "");
  if (userIdentity) assertSlackUserTokenIdentity("Slack test-user token", userIdentity);
  assertSlackTeamMatch("configured Slack team ID", configuredSlackTeamId, "Slack bot token auth.test team_id", botTeamId);
  if (userIdentity) {
    assertSlackTeamMatch("configured Slack team ID", configuredSlackTeamId, "Slack test-user token auth.test team_id", userTeamId);
    assertSlackTeamMatch("Slack bot token auth.test team_id", botTeamId, "Slack test-user token auth.test team_id", userTeamId);
  }
  const botUserId = configuredBotUserId || botIdentity.user_id || "";
  const testUserId = userIdentity?.user_id || manualUserId || adminSlackUserId;
  const slackTeamId = configuredSlackTeamId || botTeamId || userTeamId || "";
  if (!botUserId) throw new Error("Could not infer Slack bot user ID; pass --bot-user-id");
  if (!testUserId) throw new Error("Could not infer allowed Slack user ID; pass --manual-user-id in manual mode");
  process.stdout.write(`slack bot: ${botUserId}${botIdentity.bot_id ? ` (${botIdentity.bot_id})` : ""}\n`);
  process.stdout.write(`slack test user: ${testUserId}${userIdentity ? "" : " (manual)" }\n`);
  if (slackTeamId) {
    process.stdout.write(`slack channel url: ${slackClientUrl(slackTeamId, channelId)}\n`);
    if (dmChannelId) process.stdout.write(`slack DM url: ${slackClientUrl(slackTeamId, dmChannelId)}\n`);
  }
  liveReportContext = {
    ...liveReportContext,
    botUserId,
    botId: botIdentity.bot_id || null,
    testUserId,
    slackTeamId: slackTeamId || null,
  };
  recordStep("pass", userIdentity ? "Slack bot/user auth.test" : "Slack bot auth.test/manual user", `bot=${botUserId} user=${testUserId}${slackTeamId ? ` team=${slackTeamId}` : ""}`);

  let openClawCheckResults = [];
  if (!skipOpenClawChecks) {
    openClawCheckResults = await runOpenClawChecks(baseUrl, adminToken, openClawChecks);
    recordStep("pass", "OpenClaw checks", openClawChecks.join(","));
  } else {
    recordStep("skip", "OpenClaw checks", "--skip-openclaw-checks");
  }
  const syncObservations = skipObservationSync ? null : async () => {
    process.stdout.write("operant: syncing OpenClaw observations\n");
    await operant(baseUrl, "/api/openclaw/observations/sync", { method: "POST", token: adminToken, body: {} });
  };

  await requirePolicyEffect(
    baseUrl,
    adminToken,
    policyEvaluateBody({ slackUserId: testUserId, slackChannelId: channelId, chatType: "channel" }),
    "allow",
    "allowlisted channel",
  );
  recordStep("pass", "Allowlisted channel policy", channelId);

  const approvalProbe = skipApprovalProbe ? null : await runApprovalProbe(baseUrl, adminToken, nonce);
  if (approvalProbe) {
    process.stdout.write(`operant: approval probe approved ${approvalProbe.id}\n`);
    recordStep("pass", "Operant approval probe", approvalProbe.id);
  } else {
    recordStep("skip", "Operant approval probe", "--skip-approval-probe");
  }

  const before = await readOperantCounts(baseUrl, adminToken);

  const message = `<@${botUserId}> ${prompt}`;
  process.stdout.write(manualSlackPosts ? "slack: waiting for manual mention\n" : "slack: posting mention\n");
  const posted = await postOrWaitForSlackProbe({
    manual: manualSlackPosts,
    manualNudge: manualSlackNudge,
    token: userToken,
    botToken,
    channelId,
    userId: testUserId,
    text: message,
    label: "mention",
    timeoutMs,
    pollIntervalMs,
    slackTeamId,
  });
  if (manualSlackPosts) recordStep("pass", "Manual Slack mention accepted", `${posted.ts}`);

  process.stdout.write(`slack: waiting for bot thread reply at ${posted.ts}\n`);
  let reply;
  try {
    reply = await pollForBotReply({
      botToken,
      channelId,
      parentTs: posted.ts,
      botUserId,
      botId: botIdentity.bot_id,
      timeoutMs,
      pollIntervalMs,
      expectedTextPattern,
    });
  } catch (error) {
    await enrichReplyTimeout(error, { baseUrl, adminToken, postedTs: posted.ts });
  }
  recordStep("pass", "Slack mention thread reply", `${posted.ts} -> ${reply.ts}`);

  const { deltas } = requireOperantRecords
    ? await waitForOperantRecordDeltas(baseUrl, adminToken, before, recordsTimeoutMs, pollIntervalMs, syncObservations)
    : { deltas: countDeltas(before, await (async () => {
      if (syncObservations) await syncObservations();
      return readOperantCounts(baseUrl, adminToken);
    })()) };
  const missingRecordDeltas = missingRequiredRecordDeltas(deltas);
  const hasRecordDelta = missingRecordDeltas.length === 0;
  if (requireOperantRecords && missingRecordDeltas.length > 0) {
    throw new Error(`Slack reply succeeded but Operant record counts did not all increase (${missingRecordDeltas.join(", ")}): ${JSON.stringify(deltas)}`);
  }
  recordStep(hasRecordDelta ? "pass" : "skip", "Operant record deltas", JSON.stringify(deltas));

  let dmReply = null;
  let dmProbe = null;
  if (dmChannelId) {
    await requirePolicyEffect(
      baseUrl,
      adminToken,
      policyEvaluateBody({ slackUserId: testUserId, chatType: "direct" }),
      "allow",
      "allowlisted DM",
    );
    process.stdout.write(manualSlackPosts ? "slack: waiting for manual DM probe\n" : "slack: posting DM probe\n");
    const dmText = argValue("--dm-prompt", process.env.OPERANT_LIVE_DM_PROMPT || `Operant live DM E2E ${nonce}: reply in this thread with a short confirmation.`);
    const dmPosted = await postOrWaitForSlackProbe({
      manual: manualSlackPosts,
      manualNudge: manualSlackNudge,
      token: userToken,
      botToken,
      channelId: dmChannelId,
      nudgeMirrorChannelId: channelId,
      userId: testUserId,
      text: dmText,
      label: "DM",
      timeoutMs,
      pollIntervalMs,
      slackTeamId,
    });
    dmReply = await pollForBotReply({
      botToken,
      channelId: dmChannelId,
      parentTs: dmPosted.ts,
      botUserId,
      botId: botIdentity.bot_id,
      timeoutMs,
      pollIntervalMs,
      expectedTextPattern,
    });
    dmProbe = { channelId: dmChannelId, parentTs: dmPosted.ts, replyTs: dmReply.ts };
    recordStep("pass", "Slack DM reply", `${dmPosted.ts} -> ${dmReply.ts}`);
  } else {
    recordStep("skip", "Slack DM reply", "no DM channel configured");
  }
  if (requireDm && !dmReply) throw new Error("DM probe was required but did not complete");

  let deniedProbe = null;
  let channelMembership = null;
  if (deniedUserToken || (manualSlackPosts && deniedUserIdOverride) || deniedUseAllowedUser) {
    const deniedIdentity = deniedUserToken ? await slack("auth.test", deniedUserToken) : null;
    const deniedTeamId = slackTeamIdFromIdentity(deniedIdentity);
    if (deniedIdentity) {
      assertSlackUserTokenIdentity("denied Slack user token", deniedIdentity);
      assertSlackIdentityMatch("configured denied-user ID", deniedUserIdOverride, deniedIdentity.user_id || "");
      assertSlackTeamMatch("configured Slack team ID", configuredSlackTeamId, "denied Slack user token auth.test team_id", deniedTeamId);
      assertSlackTeamMatch("Slack bot/user auth.test team_id", slackTeamId, "denied Slack user token auth.test team_id", deniedTeamId);
    }
    const deniedUserId = deniedUseAllowedUser ? testUserId : deniedUserIdOverride || deniedIdentity?.user_id;
    if (!deniedUseAllowedUser) {
      assertDistinctSlackUsers("Slack test-user token", testUserId, "denied Slack user token", deniedUserId);
    }
    if (!deniedUserId) throw new Error("Could not infer denied Slack user ID; pass --denied-user-id");
    channelMembership = await slackConversationMembers("Slack target channel", botToken, channelId, uniqueStrings([testUserId, deniedUserId]));
    recordStep("pass", "Slack target channel membership", `${channelId}: ${channelMembership.requiredUserIds.join(",")}`);
    let originalPolicy = null;
    if (deniedUseAllowedUser) {
      originalPolicy = await operant(baseUrl, "/api/policy", { token: adminToken });
      await putPolicyAndWait(baseUrl, adminToken, policyWithTemporaryDeniedUser(originalPolicy, channelId, deniedUserId), "Temporary denied-user policy enabled");
    }
    await requirePolicyEffect(
      baseUrl,
      adminToken,
      policyEvaluateBody({ slackUserId: deniedUserId, slackChannelId: channelId, chatType: "channel" }),
      "deny",
      "denied channel user",
    );
    try {
      process.stdout.write(manualSlackPosts ? "slack: waiting for manual denied-user channel probe\n" : "slack: posting denied-user channel probe\n");
      const deniedText = `<@${botUserId}> Operant denied-user E2E ${nonce}: policy should prevent a bot reply.`;
      const deniedPosted = await postOrWaitForSlackProbe({
        manual: manualSlackPosts,
        manualNudge: manualSlackNudge,
        token: deniedUseAllowedUser ? userToken : deniedUserToken,
        botToken,
        channelId,
        userId: deniedUserId,
        text: deniedText,
        label: deniedUseAllowedUser ? "same-user denied-policy" : "denied-user",
        timeoutMs,
        pollIntervalMs,
        slackTeamId,
      });
      const unexpectedReply = await botReplied({
        botToken,
        channelId,
        parentTs: deniedPosted.ts,
        botUserId,
        botId: botIdentity.bot_id,
        timeoutMs: deniedTimeoutMs,
        pollIntervalMs,
      });
      if (unexpectedReply) {
        throw new Error(`Denied-user probe received an unexpected bot reply at ${unexpectedReply.ts}`);
      }
      deniedProbe = {
        userId: deniedUserId,
        teamId: deniedUseAllowedUser ? slackTeamId || null : deniedTeamId || null,
        parentTs: deniedPosted.ts,
        noReplyObservedMs: deniedTimeoutMs,
        mode: deniedUseAllowedUser ? "same-user-temporary-deny" : "distinct-user",
      };
      recordStep("pass", "Denied-user no-reply policy", `${deniedUserId} ${deniedPosted.ts}${deniedUseAllowedUser ? " same-user-temporary-deny" : ""}`);
    } finally {
      if (originalPolicy) {
        await putPolicyAndWait(baseUrl, adminToken, originalPolicy, "Temporary denied-user policy restored");
      }
    }
  } else {
    recordStep("skip", "Denied-user no-reply policy", "no denied-user token configured");
  }
  if (requireDeniedUser && !deniedProbe) throw new Error("Denied-user probe was required but did not complete");

  let slackApprovalProbe = null;
  if (!skipSlackApprovalProbe || requireSlackApproval) {
    process.stdout.write(manualSlackPosts ? "slack: waiting for manual approval-required probe\n" : "slack: posting approval-required probe\n");
    const approvalText = `<@${botUserId}> ${approvalPrompt}`;
    const approvalPosted = await postOrWaitForSlackProbe({
      manual: manualSlackPosts,
      manualNudge: manualSlackNudge,
      token: userToken,
      botToken,
      channelId,
      userId: testUserId,
      text: approvalText,
      label: "approval",
      timeoutMs,
      pollIntervalMs,
      slackTeamId,
    });
    const approvalUi = await pollForApprovalUi({
      botToken,
      channelId,
      parentTs: approvalPosted.ts,
      botUserId,
      botId: botIdentity.bot_id,
      timeoutMs,
      pollIntervalMs,
    });
    slackApprovalProbe = { parentTs: approvalPosted.ts, approvalUiTs: approvalUi.ts };
    recordStep("pass", "OpenClaw Slack approval UI", `${approvalPosted.ts} -> ${approvalUi.ts}`);
    if (requireSlackApprovalCompletion) {
      process.stdout.write("slack: waiting for a human approver to approve in Slack and for OpenClaw to continue\n");
      const approvalCompletion = await pollForBotReply({
        botToken,
        channelId,
        parentTs: approvalPosted.ts,
        botUserId,
        botId: botIdentity.bot_id,
        timeoutMs: approvalCompletionTimeoutMs,
        pollIntervalMs,
        expectedTextPattern: approvalCompletionTextPattern,
        afterTs: approvalUi.ts,
      });
      slackApprovalProbe.approvalCompletionTs = approvalCompletion.ts;
      recordStep("pass", "OpenClaw Slack approval completion", `${approvalUi.ts} -> ${approvalCompletion.ts}`);
    } else if (skipSlackApprovalCompletion) {
      recordStep("skip", "OpenClaw Slack approval completion", "--skip-slack-approval-completion");
    }
  } else {
    recordStep("skip", "OpenClaw Slack approval UI", "--skip-slack-approval-probe");
  }
  if (requireSlackApproval && !slackApprovalProbe) throw new Error("Slack approval UI probe was required but did not complete");
  if (requireSlackApprovalCompletion && !slackApprovalProbe?.approvalCompletionTs) {
    throw new Error("Slack approval completion probe was required but did not complete");
  }

  process.stdout.write("Live E2E passed.\n");
  const result = {
    channelId,
    parentTs: posted.ts,
    replyTs: reply.ts,
    dmReplyTs: dmReply?.ts || null,
    dmProbe,
    deniedProbe,
    channelMembership,
    approvalProbe,
    slackApprovalProbe,
    botUserId,
    slackTeamId: slackTeamId || null,
    openClawChecks: openClawCheckResults,
    operantRecordDeltas: deltas,
  };
  await writeLiveReport("pass", { result });
  process.stdout.write(JSON.stringify(result, null, 2));
  process.stdout.write("\n");
}

try {
  if (selfTestReportRedaction) {
    await runReportRedactionSelfTest();
  } else if (hasFlag("--self-test-env-loading")) {
    await runEnvLoadingSelfTest();
  } else if (hasFlag("--self-test-identity-consistency")) {
    runIdentityConsistencySelfTest();
  } else if (hasFlag("--self-test-openclaw-assertions")) {
    runOpenClawAssertionSelfTest();
  } else if (hasFlag("--self-test-transient-retry")) {
    await runTransientRetrySelfTest();
  } else {
    await main();
  }
} catch (error) {
  process.stderr.write(`Live E2E failed: ${error.message}\n`);
  try {
    recordStep("fail", "Live E2E", error.message);
    await writeLiveReport("fail", { error: error.message });
  } catch (reportError) {
    process.stderr.write(`Live E2E report failed: ${reportError.message}\n`);
  }
  process.exit(1);
}
