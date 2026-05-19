#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { assertNoSecretMaterial, redactSecretMaterial, sensitiveEnvValues } from "./operant-report-redaction.mjs";

const defaultTimeoutMs = 180_000;
const defaultPollIntervalMs = 5_000;
const defaultReportPath = ".operant/slack-dm-probe-report.json";

function usage() {
  return `Usage: node scripts/slack-dm-manual-probe.mjs [options]

Manual Slack DM evidence probe. This verifies that the configured Operant bot DM
channel is the expected allowed user's DM, and that the bot token can observe a
human-authored exact DM message before running the full Compose E2E gate.

Options:
  --env <path>              Load env file values
  --live-env <path>         Load private live env overlay
  --bot-token <xoxb>        Slack bot token, or SLACK_BOT_TOKEN
  --channel-id <C...>       Optional channel for a reminder nudge, or SLACK_CHANNEL_ID
  --dm-channel-id <D...>    Bot DM channel, or OPERANT_LIVE_DM_CHANNEL_ID
  --manual-user-id <U...>   Human Slack user expected to post the probe
  --timeout-ms <ms>         Wait timeout; default ${defaultTimeoutMs}
  --poll-interval-ms <ms>   Poll interval; default ${defaultPollIntervalMs}
  --nonce <text>            Probe nonce; default random hex
  --nudge                   Post a bot copy/paste nudge to the DM channel
  --report <path>           Sanitized evidence report; default ${defaultReportPath}
  --json                    Print result as JSON
  --self-test               Run local parser/probe self-tests without network
`;
}

function parseArgs(argv) {
  const args = {
    envFile: "",
    liveEnvFile: "",
    botToken: "",
    channelId: "",
    dmChannelId: "",
    manualUserId: "",
    timeoutMs: defaultTimeoutMs,
    pollIntervalMs: defaultPollIntervalMs,
    reportPath: defaultReportPath,
    nonce: "",
    nudge: false,
    json: false,
    selfTest: false,
  };
  const takeValue = (name, index) => {
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${name}`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--") continue;
    if (arg === "--help" || arg === "-h") return { ...args, help: true };
    if (arg === "--env") args.envFile = takeValue(arg, index++);
    else if (arg === "--live-env") args.liveEnvFile = takeValue(arg, index++);
    else if (arg === "--bot-token") args.botToken = takeValue(arg, index++);
    else if (arg === "--channel-id") args.channelId = takeValue(arg, index++);
    else if (arg === "--dm-channel-id") args.dmChannelId = takeValue(arg, index++);
    else if (arg === "--manual-user-id") args.manualUserId = takeValue(arg, index++);
    else if (arg === "--timeout-ms") args.timeoutMs = positiveInteger(takeValue(arg, index++), arg);
    else if (arg === "--poll-interval-ms") args.pollIntervalMs = positiveInteger(takeValue(arg, index++), arg);
    else if (arg === "--report") args.reportPath = takeValue(arg, index++);
    else if (arg === "--nonce") args.nonce = takeValue(arg, index++);
    else if (arg === "--nudge") args.nudge = true;
    else if (arg === "--json") args.json = true;
    else if (arg === "--self-test") args.selfTest = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

function positiveInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
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
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    parsed[match[1]] = value;
  }
  return parsed;
}

function envValue(source, ...keys) {
  for (const key of keys) {
    const value = String(source[key] || "").trim();
    if (value && !/^<[^>]+>$/.test(value) && !["U...", "D...", "xoxb-..."].includes(value)) return value;
  }
  return "";
}

function validateSlackShape(value, pattern, label) {
  if (!pattern.test(value)) throw new Error(`${label} has an unexpected Slack ID/token shape`);
  return value;
}

async function slackApi(method, token, params = {}, httpMethod = "POST") {
  const url = new URL(`https://slack.com/api/${method}`);
  const options = {
    method: httpMethod,
    headers: { authorization: `Bearer ${token}` },
  };
  if (httpMethod === "GET") {
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, String(value));
  } else {
    options.headers["content-type"] = "application/x-www-form-urlencoded";
    options.body = new URLSearchParams(params);
  }
  const response = await fetch(url, options);
  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { ok: false, error: `invalid_json:${text.slice(0, 80)}` };
  }
  if (!payload.ok) throw new Error(`Slack ${method} failed: ${payload.error || "unknown_error"}`);
  return payload;
}

function manualTextMatches(actual, expected) {
  return String(actual || "").includes(String(expected || ""));
}

function slackClientUrl(teamId, channelId) {
  const team = String(teamId || "").trim();
  const channel = String(channelId || "").trim();
  if (!team || !channel) return "";
  return `https://app.slack.com/client/${encodeURIComponent(team)}/${encodeURIComponent(channel)}`;
}

function nudgeText(userId, expectedText) {
  return [
    `Manual Operant DM probe: <@${userId}> please post this exact DM message as a new message:`,
    "```",
    expectedText,
    "```",
    "Copy only the message line inside the code block; do not include the backticks, quotes, or this instruction text.",
    "This evidence must be posted in the Operant DM, not in a channel and not as a thread reply.",
    "If Slack says bot DMs are not enabled, enable App Home > Messages tab for the installed Slack app and make it writable.",
  ].join("\n");
}

function channelReminderText(userId, expectedText, dmUrl) {
  return [
    `Manual Operant DM probe: <@${userId}> the verifier is waiting for a DM to Operant, not a channel message.`,
    dmUrl ? `Open the Operant DM: ${dmUrl}` : "Open the Operant DM with the bot.",
    "Post only this line as a fresh DM message:",
    "```",
    expectedText,
    "```",
    "Do not post this DM evidence in the channel; the channel reminder is only a pointer.",
    "If Slack says bot DMs are not enabled, enable App Home > Messages tab for the installed Slack app and make it writable.",
  ].join("\n");
}

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function runProbe(options) {
  const mergedEnv = {
    ...parseEnvFile(options.envFile),
    ...parseEnvFile(options.liveEnvFile),
    ...process.env,
  };
  const reportSensitiveValues = sensitiveEnvValues([mergedEnv, process.env]);
  const botToken = validateSlackShape(
    options.botToken || envValue(mergedEnv, "OPERANT_LIVE_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN"),
    /^xoxb-/,
    "Slack bot token",
  );
  const dmChannelId = validateSlackShape(
    options.dmChannelId || envValue(mergedEnv, "OPERANT_LIVE_DM_CHANNEL_ID"),
    /^D[A-Z0-9]+$/,
    "Slack DM channel ID",
  );
  const manualUserId = validateSlackShape(
    options.manualUserId || envValue(mergedEnv, "OPERANT_LIVE_ALLOWED_USER_ID", "OPERANT_LIVE_ADMIN_SLACK_USER_ID"),
    /^U[A-Z0-9]+$/,
    "Manual Slack user ID",
  );
  const channelId = envValue(mergedEnv, "OPERANT_LIVE_SLACK_CHANNEL_ID", "SLACK_CHANNEL_ID");
  if (options.channelId || channelId) validateSlackShape(options.channelId || channelId, /^[CGD][A-Z0-9]+$/, "Slack reminder channel ID");

  const auth = await slackApi("auth.test", botToken);
  const botUserId = auth.user_id || "";
  const slackTeamId = auth.team_id || "";
  const dmInfo = await slackApi("conversations.info", botToken, { channel: dmChannelId }, "GET");
  if (!dmInfo.channel?.is_im) throw new Error(`${dmChannelId} is not a Slack IM/DM channel`);
  const opened = await slackApi("conversations.open", botToken, { users: manualUserId });
  if (opened.channel?.id !== dmChannelId) {
    throw new Error(`conversations.open returned ${opened.channel?.id || "<missing>"}, not ${dmChannelId}; update OPERANT_LIVE_DM_CHANNEL_ID for ${manualUserId}`);
  }
  const dmUrl = slackClientUrl(slackTeamId, dmChannelId);

  const nonce = options.nonce || Math.random().toString(16).slice(2, 10);
  const expectedText = `Operant manual DM probe ${nonce}: reply with this exact line.`;
  const startedAtMs = Date.now();
  const reportBase = {
    format: "operant.slack-dm-probe-report.v1",
    generatedAt: "",
    envPath: options.envFile || "",
    liveEnvPath: options.liveEnvFile || "",
    timeoutMs: options.timeoutMs,
    pollIntervalMs: options.pollIntervalMs,
    nudgeRequested: options.nudge,
    dmChannelId,
    reminderChannelId: options.channelId || channelId || null,
    slackTeamId: slackTeamId || null,
    dmUrl: dmUrl || null,
    manualUserId,
    botUserId,
    expectedText,
    startedAt: new Date(startedAtMs).toISOString(),
  };
  let nudge = null;
  let channelReminder = null;
  if (options.nudge) {
    const posted = await slackApi("chat.postMessage", botToken, {
      channel: dmChannelId,
      text: nudgeText(manualUserId, expectedText),
      unfurl_links: "false",
      unfurl_media: "false",
    });
    nudge = { ts: posted.ts || null };
    const reminderChannelId = options.channelId || channelId || "";
    if (reminderChannelId && reminderChannelId !== dmChannelId) {
      const reminder = await slackApi("chat.postMessage", botToken, {
        channel: reminderChannelId,
        text: channelReminderText(manualUserId, expectedText, dmUrl),
        unfurl_links: "false",
        unfurl_media: "false",
      });
      channelReminder = { channelId: reminderChannelId, ts: reminder.ts || null };
    }
  }

  if (!options.silent) {
    const promptStream = options.json ? process.stderr : process.stdout;
    promptStream.write(`slack DM probe: bot=${botUserId} dm=${dmChannelId} user=${manualUserId}\n`);
    if (dmUrl) promptStream.write(`slack DM probe: open ${dmUrl}\n`);
    promptStream.write(`slack DM probe: post this exact DM as ${manualUserId}:\n${expectedText}\n`);
  }

  const deadline = Date.now() + options.timeoutMs;
  const oldest = Math.max(0, Math.floor((startedAtMs - 5_000) / 1000));
  let observedMessages = 0;
  while (Date.now() < deadline) {
    const history = await slackApi("conversations.history", botToken, { channel: dmChannelId, limit: 100, oldest, inclusive: "true" }, "GET");
    const messages = Array.isArray(history.messages) ? history.messages : [];
    observedMessages = messages.length;
    const match = messages.find((message) => message.user === manualUserId && !message.bot_id && !message.subtype && !message.thread_ts && manualTextMatches(message.text, expectedText));
    if (match?.ts) {
      const result = { ok: true, dmChannelId, manualUserId, botUserId, expectedText, matchedTs: match.ts, nudge, channelReminder, observedMessages };
      writeReport(options.reportPath, { ...reportBase, ...result, completedAt: new Date().toISOString() }, reportSensitiveValues);
      if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      else process.stdout.write(`slack DM probe: pass ${match.ts}\n`);
      return result;
    }
    await sleep(options.pollIntervalMs);
  }
  const result = { ok: false, dmChannelId, manualUserId, botUserId, expectedText, nudge, channelReminder, observedMessages };
  writeReport(options.reportPath, { ...reportBase, ...result, completedAt: new Date().toISOString(), error: `Timed out waiting for exact human DM from ${manualUserId} in ${dmChannelId}` }, reportSensitiveValues);
  if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  throw new Error(`Timed out waiting for exact human DM from ${manualUserId} in ${dmChannelId}`);
}

function writeReport(reportPath, report, sensitiveValues) {
  if (!reportPath) return;
  const absolute = path.resolve(process.cwd(), reportPath);
  const body = { ...report, generatedAt: new Date().toISOString(), reportPath };
  const redacted = redactSecretMaterial(body, sensitiveValues);
  assertNoSecretMaterial(redacted, sensitiveValues);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, `${JSON.stringify(redacted, null, 2)}\n`);
}

async function runSelfTest() {
  const report = ".operant/slack-dm-manual-probe-self-test-report.json";
  const parsed = parseArgs(["--env", ".env", "--live-env", ".live.env", "--manual-user-id", "U123", "--channel-id", "C123", "--timeout-ms", "10", "--poll-interval-ms", "5", "--report", report, "--nudge", "--json"]);
  if (!parsed.envFile || !parsed.liveEnvFile || parsed.channelId !== "C123" || !parsed.nudge || !parsed.json || parsed.reportPath !== report || parsed.timeoutMs !== 10 || parsed.pollIntervalMs !== 5) {
    throw new Error("argument parser self-test failed");
  }
  const temp = ".operant/slack-dm-manual-probe-self-test.env";
  fs.mkdirSync(".operant", { recursive: true });
  fs.writeFileSync(temp, "SLACK_BOT_TOKEN='bot-token-placeholder'\nOPERANT_LIVE_DM_CHANNEL_ID=D123\n");
  try {
    const env = parseEnvFile(temp);
    if (env.SLACK_BOT_TOKEN !== "bot-token-placeholder" || env.OPERANT_LIVE_DM_CHANNEL_ID !== "D123") {
      throw new Error("env parser self-test failed");
    }
  } finally {
    fs.rmSync(temp, { force: true });
  }
  if (!manualTextMatches("prefix Operant manual DM probe abc: reply with this exact line.", "Operant manual DM probe abc: reply with this exact line.")) {
    throw new Error("manual text matcher self-test failed");
  }
  if (slackClientUrl("T123", "D123") !== "https://app.slack.com/client/T123/D123") {
    throw new Error("Slack client URL self-test failed");
  }
  if (!nudgeText("U123", "hello").includes("App Home > Messages tab") || !channelReminderText("U123", "hello", "https://example.invalid/dm").includes("not a channel message")) {
    throw new Error("DM nudge guidance self-test failed");
  }
  const originalFetch = globalThis.fetch;
  let expectedText = "";
  try {
    globalThis.fetch = async (url, options = {}) => {
      const parsedUrl = new URL(String(url));
      const method = parsedUrl.pathname.replace(/^\/api\//, "");
      if (method === "auth.test") return jsonResponse({ ok: true, user_id: "UBOT", team_id: "T123" });
      if (method === "conversations.info") return jsonResponse({ ok: true, channel: { id: "D123", is_im: true } });
      if (method === "conversations.open") return jsonResponse({ ok: true, channel: { id: "D123", is_im: true } });
      if (method === "chat.postMessage") {
        const body = new URLSearchParams(options.body || "");
        const channel = String(body.get("channel") || "");
        if (channel === "D123") expectedText = String(body.get("text") || "");
        return jsonResponse({ ok: true, ts: "123.456" });
      }
      if (method === "conversations.history") {
        const match = expectedText.match(/Operant manual DM probe [a-z0-9]+: reply with this exact line\./);
        return jsonResponse({ ok: true, messages: [{ ts: "124.000", user: "U123", text: match?.[0] || "" }] });
      }
      return jsonResponse({ ok: false, error: "unexpected_method" });
    };
    await runProbe({
      botToken: "xoxb-test",
      channelId: "C123",
      dmChannelId: "D123",
      manualUserId: "U123",
      timeoutMs: 10,
      pollIntervalMs: 1,
      nonce: "abc",
      nudge: true,
      json: true,
      silent: true,
      reportPath: report,
    });
    const written = JSON.parse(fs.readFileSync(report, "utf8"));
    if (written.format !== "operant.slack-dm-probe-report.v1" || written.ok !== true || written.matchedTs !== "124.000") {
      throw new Error("report writer self-test failed");
    }
    if (written.dmUrl !== "https://app.slack.com/client/T123/D123") {
      throw new Error("report Slack DM URL self-test failed");
    }
    if (written.channelReminder?.channelId !== "C123") {
      throw new Error("report Slack channel reminder self-test failed");
    }
    assertNoSecretMaterial(written, ["xoxb-test"]);
  } finally {
    globalThis.fetch = originalFetch;
    fs.rmSync(report, { force: true });
  }
  process.stdout.write("Slack DM manual probe self-test passed.\n");
}

function jsonResponse(payload) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n${usage()}`);
    process.exit(1);
  }
  if (args.help) {
    process.stdout.write(usage());
    return;
  }
  if (args.selfTest) {
    await runSelfTest();
    return;
  }
  await runProbe(args);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exit(1);
  });
}
