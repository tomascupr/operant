import fs from "node:fs";
import { pathToFileURL } from "node:url";

const DEFAULT_TIMEOUT_MS = 180_000;

function usage() {
  return `Usage: node scripts/slack-socket-mode-probe.mjs [options]

Raw Slack Socket Mode event-delivery probe. This verifies Slack app Event
Subscriptions independently of OpenClaw.

Options:
  --env <path>              Load Slack credentials from an env file
  --app-token <xapp>        Slack app-level token, or SLACK_APP_TOKEN
  --bot-token <xoxb>        Slack bot token, or SLACK_BOT_TOKEN
  --channel-id <C...>       Slack channel ID, or SLACK_CHANNEL_ID
  --manual-user-id <U...>   Human Slack user expected to post the probe
  --bot-user-id <U...>      Bot user ID; defaults to bot auth.test
  --timeout-ms <ms>         Wait timeout; default ${DEFAULT_TIMEOUT_MS}
  --nonce <text>            Probe nonce; default random hex
  --nudge                   Post a bot copy/paste nudge to the channel
  --json                    Print result as JSON
  --self-test               Run local parser self-tests without network
`;
}

function parseArgs(argv) {
  const args = {
    envFile: "",
    appToken: "",
    botToken: "",
    channelId: "",
    manualUserId: "",
    botUserId: "",
    timeoutMs: DEFAULT_TIMEOUT_MS,
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
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--") continue;
    if (arg === "--help" || arg === "-h") return { ...args, help: true };
    if (arg === "--env") args.envFile = takeValue(arg, i++);
    else if (arg === "--app-token") args.appToken = takeValue(arg, i++);
    else if (arg === "--bot-token") args.botToken = takeValue(arg, i++);
    else if (arg === "--channel-id") args.channelId = takeValue(arg, i++);
    else if (arg === "--manual-user-id") args.manualUserId = takeValue(arg, i++);
    else if (arg === "--bot-user-id") args.botUserId = takeValue(arg, i++);
    else if (arg === "--timeout-ms") args.timeoutMs = positiveInteger(takeValue(arg, i++), arg);
    else if (arg === "--nonce") args.nonce = takeValue(arg, i++);
    else if (arg === "--nudge") args.nudge = true;
    else if (arg === "--json") args.json = true;
    else if (arg === "--self-test") args.selfTest = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

function positiveInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
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
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    parsed[match[1]] = value;
  }
  return parsed;
}

function envValue(source, ...keys) {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value.trim() && !/^<[^>]+>$/.test(value.trim())) {
      return value.trim();
    }
  }
  return "";
}

function validateSlackShape(value, prefix, label) {
  if (!value.startsWith(prefix)) throw new Error(`${label} must start with ${prefix}`);
  return value;
}

async function slackApi(method, token, body = {}) {
  const response = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(body),
  });
  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { ok: false, error: `invalid_json:${text.slice(0, 80)}` };
  }
  return {
    status: response.status,
    scopes: response.headers.get("x-oauth-scopes") || "",
    payload,
  };
}

function slackResponseWarnings(payload) {
  const messages = payload?.response_metadata?.messages;
  if (!Array.isArray(messages)) return [];
  return messages.map((message) => String(message || "").trim()).filter(Boolean);
}

function assertSlackSocketModeEnabled(payload) {
  const warnings = slackResponseWarnings(payload);
  const socketModeOff = warnings.find((message) => /socket mode is not turned on/i.test(message));
  if (socketModeOff) {
    throw new Error(
      "Slack apps.connections.open returned a WebSocket URL but Slack says Socket Mode is not turned on. Enable Socket Mode for this Slack app, save the app, then reinstall or re-authorize it before rerunning the probe.",
    );
  }
}

function summarizeEnvelope(message) {
  const payload = message?.payload && typeof message.payload === "object" ? message.payload : {};
  const event = payload.event && typeof payload.event === "object" ? payload.event : payload;
  return {
    envelopeType: typeof message?.type === "string" ? message.type : "",
    eventType: typeof event.type === "string" ? event.type : "",
    subtype: typeof event.subtype === "string" ? event.subtype : "",
    channel: typeof event.channel === "string" ? event.channel : "",
    channelType: typeof event.channel_type === "string" ? event.channel_type : "",
    user: typeof event.user === "string" ? event.user : "",
    botId: typeof event.bot_id === "string" ? event.bot_id : "",
    textPrefix: typeof event.text === "string" ? event.text.slice(0, 160) : "",
  };
}

function eventMatches(summary, expected) {
  if (summary.channel !== expected.channelId) return false;
  if (expected.manualUserId && summary.user !== expected.manualUserId) return false;
  return summary.textPrefix.includes(expected.nonce);
}

async function runProbe(options) {
  const envFileValues = parseEnvFile(options.envFile);
  const mergedEnv = { ...envFileValues, ...process.env };
  const appToken = validateSlackShape(
    options.appToken || envValue(mergedEnv, "OPERANT_LIVE_SLACK_APP_TOKEN", "SLACK_APP_TOKEN"),
    "xapp-",
    "Slack app-level token",
  );
  const botToken = validateSlackShape(
    options.botToken || envValue(mergedEnv, "OPERANT_LIVE_SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN"),
    "xoxb-",
    "Slack bot token",
  );
  const channelId = options.channelId || envValue(mergedEnv, "OPERANT_LIVE_SLACK_CHANNEL_ID", "SLACK_CHANNEL_ID");
  if (!/^C[A-Z0-9]+$/.test(channelId)) throw new Error("Slack channel ID must be a public channel ID starting with C");

  const auth = await slackApi("auth.test", botToken);
  if (!auth.payload.ok) throw new Error(`Slack bot auth.test failed: ${auth.payload.error || "unknown_error"}`);
  const botUserId = options.botUserId || auth.payload.user_id || "";
  if (!/^U[A-Z0-9]+$/.test(botUserId)) throw new Error("Could not resolve Slack bot user ID");

  const nonce = options.nonce || Math.random().toString(16).slice(2, 10);
  const expectedText = `<@${botUserId}> raw socket probe ${nonce}`;
  const connection = await slackApi("apps.connections.open", appToken);
  if (!connection.payload.ok || !connection.payload.url) {
    throw new Error(`Slack apps.connections.open failed: ${connection.payload.error || "missing_url"}`);
  }
  assertSlackSocketModeEnabled(connection.payload);

  const events = [];
  let matched = false;
  let hello = false;
  let closed = false;

  const socket = new WebSocket(connection.payload.url);
  const socketDone = new Promise((resolve, reject) => {
    socket.addEventListener("open", () => {
      if (!options.json) process.stdout.write("slack socket probe: open\n");
    });
    socket.addEventListener("message", (raw) => {
      let message;
      try {
        message = JSON.parse(raw.data);
      } catch {
        message = { type: "unparsed" };
      }
      if (message?.type === "hello") {
        hello = true;
        if (!options.json) process.stdout.write("slack socket probe: hello\n");
        return;
      }
      if (message?.envelope_id) {
        socket.send(JSON.stringify({ envelope_id: message.envelope_id }));
      }
      const summary = summarizeEnvelope(message);
      events.push(summary);
      if (!options.json) process.stdout.write(`slack socket probe: event ${JSON.stringify(summary)}\n`);
      if (eventMatches(summary, { channelId, manualUserId: options.manualUserId, nonce })) {
        matched = true;
        socket.close();
        resolve();
      }
    });
    socket.addEventListener("close", () => {
      closed = true;
      resolve();
    });
    socket.addEventListener("error", (event) => {
      reject(new Error(`Slack Socket Mode WebSocket error: ${event.message || "unknown_error"}`));
    });
  });

  await new Promise((resolve) => setTimeout(resolve, 3000));
  if (!hello) throw new Error("Slack Socket Mode WebSocket opened but did not send hello");

  let nudge = null;
  if (options.nudge) {
    if (!options.manualUserId) throw new Error("--nudge requires --manual-user-id so the expected human poster is explicit");
    const message = [
      `Raw Socket Mode E2E: <@${options.manualUserId}> please post this exact text in this channel now:`,
      expectedText,
    ].join(" ");
    const posted = await slackApi("chat.postMessage", botToken, {
      channel: channelId,
      text: message,
      unfurl_links: "false",
      unfurl_media: "false",
    });
    if (!posted.payload.ok) throw new Error(`Slack nudge chat.postMessage failed: ${posted.payload.error || "unknown_error"}`);
    nudge = { ok: true, ts: posted.payload.ts };
    if (!options.json) {
      process.stdout.write(`slack socket probe: nudge posted ${posted.payload.ts}\n`);
      process.stdout.write(`slack socket probe: waiting for ${expectedText}\n`);
    }
  } else if (!options.json) {
    process.stdout.write(`slack socket probe: waiting for ${expectedText}\n`);
  }

  await Promise.race([
    socketDone,
    new Promise((resolve) => setTimeout(resolve, options.timeoutMs)),
  ]);
  if (!closed) socket.close();

  const result = {
    ok: matched,
    matched,
    expectedText,
    channelId,
    manualUserId: options.manualUserId || null,
    botUserId,
    nudge,
    observedEvents: events.length,
    events,
  };
  if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else {
    process.stdout.write(`slack socket probe: ${matched ? "pass" : "fail"} (${events.length} event envelope(s) observed)\n`);
  }
  if (!matched) {
    throw new Error(
      "Slack Socket Mode connected, but the expected event was not delivered. Recheck Slack app Event Subscriptions, save the app manifest, and reinstall or re-authorize the app.",
    );
  }
  return result;
}

function runSelfTest() {
  const parsed = parseArgs([
    "--env",
    ".env.test",
    "--channel-id",
    "C123",
    "--manual-user-id",
    "U123",
    "--timeout-ms",
    "10",
    "--nudge",
    "--json",
  ]);
  if (!parsed.envFile || !parsed.nudge || !parsed.json || parsed.timeoutMs !== 10) {
    throw new Error("argument parser self-test failed");
  }
  const temp = ".operant/slack-socket-probe-self-test.env";
  fs.mkdirSync(".operant", { recursive: true });
  fs.writeFileSync(temp, "SLACK_CHANNEL_ID=C123\nSLACK_APP_TOKEN=app-token-placeholder\n# ignored\nSLACK_BOT_TOKEN='bot-token-placeholder'\n");
  try {
    const env = parseEnvFile(temp);
    if (env.SLACK_CHANNEL_ID !== "C123" || env.SLACK_BOT_TOKEN !== "bot-token-placeholder") {
      throw new Error("env parser self-test failed");
    }
  } finally {
    fs.rmSync(temp, { force: true });
  }
  if (!eventMatches({ channel: "C123", user: "U123", textPrefix: "<@UBOT> raw socket probe abc" }, {
    channelId: "C123",
    manualUserId: "U123",
    nonce: "abc",
  })) {
    throw new Error("event matcher self-test failed");
  }
  try {
    assertSlackSocketModeEnabled({
      ok: true,
      url: "wss://wss-primary.slack.com/link/",
      response_metadata: { messages: ["[WARN] Socket Mode is not turned on."] },
    });
    throw new Error("Socket Mode warning was not rejected");
  } catch (error) {
    if (!/Socket Mode is not turned on/.test(error.message)) throw error;
  }
  process.stdout.write("Slack Socket Mode probe self-test passed.\n");
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
    runSelfTest();
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
