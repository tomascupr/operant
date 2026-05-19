#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { assertNoSecretMaterial, redactSecretMaterial, sensitiveEnvValues } from "./operant-report-redaction.mjs";

const defaultReportPath = ".operant/slack-user-token-post-probe-report.json";

function usage() {
  return `Usage: node scripts/slack-user-token-post-probe.mjs [options]

Posts one Slack message with the configured allowed human user token, reads it
back with the bot token, and verifies whether Slack stored it as a true
human-authored message. The probe asks Slack to post as the authed user with
chat.postMessage as_user=true. Some Slack app/token combinations resolve to a
human with auth.test but still create app-authored chat.postMessage records
carrying bot_id/app_id; OpenClaw ignores those to prevent bot loops.

Options:
  --env <path>                  Load env file values
  --live-env <path>             Load private live env overlay
  --user-token <token>          Slack user token, or SLACK_USER_TOKEN
  --bot-token <xoxb>            Slack bot token, or SLACK_BOT_TOKEN
  --channel-id <C...>           Test channel, or SLACK_CHANNEL_ID
  --expected-user-id <U...>     Optional expected Slack human user ID
  --nonce <text>                Probe nonce; default random hex
  --keep-message                Do not delete the diagnostic message
  --allow-app-authored          Exit 0 even when bot_id/app_id is present
  --report <path>               Sanitized evidence report; default ${defaultReportPath}
  --json                        Print sanitized JSON result
  --self-test                   Run local self-tests without network
  --help, -h                    Show this help
`;
}

function parseArgs(argv) {
  const args = {
    envFile: "",
    liveEnvFile: "",
    userToken: "",
    botToken: "",
    channelId: "",
    expectedUserId: "",
    nonce: "",
    keepMessage: false,
    allowAppAuthored: false,
    reportPath: defaultReportPath,
    json: false,
    selfTest: false,
    help: false,
  };
  const takeValue = (name, index) => {
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${name}`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") continue;
    if (arg === "--help" || arg === "-h") args.help = true;
    else if (arg === "--env") args.envFile = takeValue(arg, index++);
    else if (arg === "--live-env") args.liveEnvFile = takeValue(arg, index++);
    else if (arg === "--user-token") args.userToken = takeValue(arg, index++);
    else if (arg === "--bot-token") args.botToken = takeValue(arg, index++);
    else if (arg === "--channel-id") args.channelId = takeValue(arg, index++);
    else if (arg === "--expected-user-id") args.expectedUserId = takeValue(arg, index++);
    else if (arg === "--nonce") args.nonce = takeValue(arg, index++);
    else if (arg === "--keep-message") args.keepMessage = true;
    else if (arg === "--allow-app-authored") args.allowAppAuthored = true;
    else if (arg === "--report") args.reportPath = takeValue(arg, index++);
    else if (arg === "--json") args.json = true;
    else if (arg === "--self-test") args.selfTest = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

function parseEnvFile(filePath) {
  const parsed = {};
  if (!filePath) return parsed;
  const content = fs.readFileSync(filePath, "utf8");
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(trimmed);
    if (!match) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    parsed[match[1]] = value;
  }
  return parsed;
}

function envValue(source, ...keys) {
  for (const key of keys) {
    const value = String(source[key] || "").trim();
    if (value && !/^<[^>]+>$/.test(value) && !["xoxb-...", "xoxp-...", "xoxc-...", "U...", "C..."].includes(value)) return value;
  }
  return "";
}

function validateSlackShape(value, pattern, label) {
  if (!pattern.test(value)) throw new Error(`${label} has an unexpected Slack ID/token shape`);
  return value;
}

async function slackApi(method, token, params = {}, httpMethod = "POST", fetchImpl = fetch) {
  const url = new URL(`https://slack.com/api/${method}`);
  const options = { method: httpMethod, headers: { authorization: `Bearer ${token}` } };
  if (httpMethod === "GET") {
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, String(value));
  } else {
    options.headers["content-type"] = "application/json; charset=utf-8";
    options.body = JSON.stringify(params);
  }
  const response = await fetchImpl(url, options);
  const text = typeof response.text === "function" ? await response.text() : JSON.stringify(await response.json());
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { ok: false, error: `invalid_json:${text.slice(0, 80)}` };
  }
  if (!payload.ok) throw new Error(`Slack ${method} failed: ${payload.error || "unknown_error"}`);
  return payload;
}

function isHumanAuthoredSlackMessage(message, userId) {
  return message?.user === userId && !message.bot_id && !message.app_id && message.subtype !== "bot_message";
}

function messageClassification(message, userId) {
  return {
    userId,
    messageUser: message?.user || null,
    hasBotId: Boolean(message?.bot_id),
    hasAppId: Boolean(message?.app_id),
    subtype: message?.subtype || null,
    humanAuthored: isHumanAuthoredSlackMessage(message, userId),
  };
}

async function writeReport(reportPath, report, sensitiveSources) {
  const sensitiveValues = sensitiveEnvValues(sensitiveSources);
  const redacted = redactSecretMaterial(report, sensitiveValues);
  assertNoSecretMaterial(redacted, sensitiveValues);
  fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(redacted, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(reportPath, 0o600);
  return redacted;
}

async function runProbe(options, fetchImpl = fetch) {
  const mergedEnv = {
    ...parseEnvFile(options.envFile),
    ...parseEnvFile(options.liveEnvFile),
    ...process.env,
  };
  const userToken = validateSlackShape(
    options.userToken || envValue(mergedEnv, "OPERANT_LIVE_SLACK_USER_TOKEN", "SLACK_USER_TOKEN"),
    /^xox[pcrs]-/,
    "Slack user token",
  );
  const botToken = validateSlackShape(
    options.botToken || envValue(mergedEnv, "OPERANT_LIVE_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN"),
    /^xoxb-/,
    "Slack bot token",
  );
  const channelId = validateSlackShape(
    options.channelId || envValue(mergedEnv, "OPERANT_LIVE_SLACK_CHANNEL_ID", "SLACK_CHANNEL_ID"),
    /^C[A-Z0-9]+$/,
    "Slack channel ID",
  );
  const expectedUserId = options.expectedUserId || envValue(mergedEnv, "OPERANT_LIVE_ALLOWED_USER_ID", "OPERANT_LIVE_ADMIN_SLACK_USER_ID");
  if (expectedUserId) validateSlackShape(expectedUserId, /^U[A-Z0-9]+$/, "Expected Slack user ID");

  const auth = await slackApi("auth.test", userToken, {}, "POST", fetchImpl);
  if (!auth.user_id) throw new Error("Slack user token auth.test did not return user_id");
  if (auth.bot_id) throw new Error("Slack user token auth.test returned bot_id; this is a bot token, not a human user token");
  if (expectedUserId && auth.user_id !== expectedUserId) {
    throw new Error(`Slack user token resolved to ${auth.user_id}, not expected user ${expectedUserId}`);
  }

  const nonce = options.nonce || Math.random().toString(16).slice(2, 10);
  const text = `Operant Slack user-token authorship probe ${nonce}`;
  const posted = await slackApi("chat.postMessage", userToken, { channel: channelId, text, as_user: true, unfurl_links: false, unfurl_media: false }, "POST", fetchImpl);
  if (!posted.ts) throw new Error("Slack chat.postMessage did not return ts");
  const history = await slackApi("conversations.history", botToken, { channel: channelId, latest: posted.ts, inclusive: true, limit: 1 }, "GET", fetchImpl);
  const message = history.messages?.[0] || posted.message || {};
  const classification = messageClassification(message, auth.user_id);

  let deletion = { attempted: false, ok: false, error: null };
  if (!options.keepMessage) {
    deletion = { attempted: true, ok: false, error: null };
    try {
      const deleted = await slackApi("chat.delete", userToken, { channel: channelId, ts: posted.ts }, "POST", fetchImpl);
      deletion.ok = Boolean(deleted.ok);
    } catch (error) {
      deletion.error = error.message || String(error);
    }
  }

  const report = {
    format: "operant.slack-user-token-post-probe-report.v1",
    generatedAt: new Date().toISOString(),
    envPath: options.envFile || "",
    liveEnvPath: options.liveEnvFile || "",
    channelId,
    auth: {
      teamId: auth.team_id || null,
      userId: auth.user_id,
      user: auth.user || null,
    },
    message: {
      ts: posted.ts,
      text,
      asUser: true,
      classification,
    },
    deletion,
    ok: classification.humanAuthored,
  };
  const redacted = await writeReport(options.reportPath, report, [mergedEnv, process.env]);
  if (!classification.humanAuthored && !options.allowAppAuthored) {
    const reason = "Slack user token posted an app-authored message even with as_user=true (bot_id/app_id present); use manual mode for strict live acceptance.";
    const error = new Error(reason);
    error.report = redacted;
    error.exitCode = 2;
    throw error;
  }
  return redacted;
}

function mockResponse(payload) {
  return { text: async () => JSON.stringify(payload) };
}

async function runSelfTest() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "operant-slack-user-post-probe-"));
  const envFile = path.join(tempDir, ".env");
  const reportPath = path.join(tempDir, "report.json");
  fs.writeFileSync(envFile, [
    "SLACK_USER_TOKEN=xoxp-user-token",
    "SLACK_BOT_TOKEN=xoxb-bot-token",
    "SLACK_CHANNEL_ID=C123",
    "OPERANT_LIVE_ADMIN_SLACK_USER_ID=U123",
    "",
  ].join("\n"), { mode: 0o600 });
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), body: String(options.body || "") });
    if (String(url).endsWith("/auth.test")) return mockResponse({ ok: true, team_id: "T123", user_id: "U123", user: "tester" });
    if (String(url).endsWith("/chat.postMessage")) return mockResponse({ ok: true, ts: "1.234" });
    if (String(url).includes("/conversations.history")) return mockResponse({ ok: true, messages: [{ ts: "1.234", user: "U123", text: "probe" }] });
    if (String(url).endsWith("/chat.delete")) return mockResponse({ ok: true });
    return mockResponse({ ok: false, error: "unexpected_method" });
  };
  const passed = await runProbe(parseArgs(["--env", envFile, "--report", reportPath, "--nonce", "abc"]), fetchImpl);
  if (!passed.ok) throw new Error("self-test did not classify human-authored message as ok");
  if (!fs.readFileSync(reportPath, "utf8").includes("\"humanAuthored\": true")) throw new Error("self-test report missing human-authored classification");
  if (!calls.some((call) => call.url.endsWith("/chat.postMessage") && call.body.includes("\"as_user\":true"))) {
    throw new Error("self-test did not request Slack as_user authorship");
  }
  if ((fs.statSync(reportPath).mode & 0o777) !== 0o600) throw new Error("self-test report permissions are not private");
  if (!calls.some((call) => call.url.endsWith("/chat.delete"))) throw new Error("self-test did not delete probe message");

  const appReportPath = path.join(tempDir, "app-report.json");
  const appFetchImpl = async (url) => {
    if (String(url).endsWith("/auth.test")) return mockResponse({ ok: true, team_id: "T123", user_id: "U123", user: "tester" });
    if (String(url).endsWith("/chat.postMessage")) return mockResponse({ ok: true, ts: "1.235" });
    if (String(url).includes("/conversations.history")) return mockResponse({ ok: true, messages: [{ ts: "1.235", user: "U123", bot_id: "B123", app_id: "A123", text: "probe" }] });
    if (String(url).endsWith("/chat.delete")) return mockResponse({ ok: true });
    return mockResponse({ ok: false, error: "unexpected_method" });
  };
  let rejectedAppAuthored = false;
  try {
    await runProbe(parseArgs(["--env", envFile, "--report", appReportPath, "--nonce", "def"]), appFetchImpl);
  } catch (error) {
    rejectedAppAuthored = error.exitCode === 2 && String(error.message || "").includes("app-authored");
  }
  if (!rejectedAppAuthored) throw new Error("self-test did not reject app-authored message");
  const allowed = await runProbe(parseArgs(["--env", envFile, "--report", appReportPath, "--nonce", "def", "--allow-app-authored"]), appFetchImpl);
  if (allowed.ok) throw new Error("self-test allow-app-authored changed the report classification");
  console.log("Slack user token post probe self-test passed.");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }
  if (args.selfTest) {
    await runSelfTest();
    return;
  }
  try {
    const report = await runProbe(args);
    if (args.json) console.log(JSON.stringify(report));
    else {
      if (report.ok) console.log(`Slack user token post probe passed: ${report.auth.userId} posted a human-authored message in ${report.channelId}.`);
      else console.log(`Slack user token post probe completed: ${report.auth.userId} posted an app-authored message in ${report.channelId}.`);
      console.log(`Report: ${args.reportPath}`);
    }
  } catch (error) {
    if (error.report && args.json) console.log(JSON.stringify(error.report));
    console.error(error.message || error);
    if (error.report) console.error(`Report: ${args.reportPath}`);
    process.exit(error.exitCode || 1);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
