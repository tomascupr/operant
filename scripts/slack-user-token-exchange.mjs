#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const defaultEnvFile = ".env";
const defaultRedirectUri = "http://localhost:3999/slack/oauth/callback";
const allowedTargets = new Set(["SLACK_USER_TOKEN", "OPERANT_LIVE_SLACK_USER_TOKEN", "OPERANT_LIVE_DENIED_USER_TOKEN", "SLACK_CONFIG_TOKEN", "OPERANT_LIVE_SLACK_CONFIG_TOKEN"]);

function usage() {
  return `Usage: node scripts/slack-user-token-exchange.mjs [options]

Exchange a Slack OAuth callback code for a temporary human user token and save
the returned access_token into a gitignored env file without printing it.

Options:
  --env <path>                         Env file to read/write; default ${defaultEnvFile}
  --code <code>                        Slack OAuth callback code
  --callback-url <url>                 Full callback URL containing ?code=...
  --target <env-var>                   Token env var to write; default SLACK_USER_TOKEN
                                      Allowed: ${[...allowedTargets].join(", ")}
  --denied                             Shortcut for --target OPERANT_LIVE_DENIED_USER_TOKEN
  --client-id <id>                     Slack app Client ID; defaults to SLACK_CLIENT_ID
  --client-secret <secret>             Slack app Client Secret; defaults to SLACK_CLIENT_SECRET
  --redirect-uri <uri>                 Redirect URI; default ${defaultRedirectUri}
  --save-client-credentials            Also write supplied Client ID/Secret into the env file
  --json                               Print sanitized JSON result
  --self-test                          Run local self-tests without network
  --help, -h                           Show this help
`;
}

function parseArgs(argv) {
  const args = {
    envFile: defaultEnvFile,
    code: "",
    callbackUrl: "",
    target: "SLACK_USER_TOKEN",
    clientId: "",
    clientSecret: "",
    redirectUri: defaultRedirectUri,
    saveClientCredentials: false,
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
    else if (arg === "--code") args.code = takeValue(arg, index++);
    else if (arg === "--callback-url") args.callbackUrl = takeValue(arg, index++);
    else if (arg === "--target") args.target = takeValue(arg, index++);
    else if (arg === "--denied") args.target = "OPERANT_LIVE_DENIED_USER_TOKEN";
    else if (arg === "--client-id") args.clientId = takeValue(arg, index++);
    else if (arg === "--client-secret") args.clientSecret = takeValue(arg, index++);
    else if (arg === "--redirect-uri") args.redirectUri = takeValue(arg, index++);
    else if (arg === "--save-client-credentials") args.saveClientCredentials = true;
    else if (arg === "--json") args.json = true;
    else if (arg === "--self-test") args.selfTest = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

function parseEnvFile(filePath) {
  const parsed = {};
  if (!filePath || !fs.existsSync(filePath)) return parsed;
  const content = fs.readFileSync(filePath, "utf8");
  for (const line of content.split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
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
    if (value && !/^<[^>]+>$/.test(value)) return value;
  }
  return "";
}

function setEnvValues(filePath, updates) {
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
  const seen = new Set();
  const lines = existing.split(/\r?\n/).map((line) => {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)=/.exec(line);
    if (!match) return line;
    const key = match[1];
    if (!Object.hasOwn(updates, key)) return line;
    seen.add(key);
    return `${key}=${updates[key]}`;
  });
  for (const [key, value] of Object.entries(updates)) {
    if (!seen.has(key)) lines.push(`${key}=${value}`);
  }
  const next = lines.join("\n").replace(/\n{3,}/g, "\n\n").replace(/\s*$/, "\n");
  fs.mkdirSync(path.dirname(path.resolve(filePath)), { recursive: true });
  fs.writeFileSync(filePath, next, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function callbackCode(callbackUrl) {
  if (!callbackUrl) return "";
  const parsed = new URL(callbackUrl);
  return parsed.searchParams.get("code") || "";
}

function validateTarget(target) {
  if (!allowedTargets.has(target)) {
    throw new Error(`--target must be one of: ${[...allowedTargets].join(", ")}`);
  }
  return target;
}

function validateRedirectUri(redirectUri) {
  let parsed;
  try {
    parsed = new URL(redirectUri);
  } catch {
    throw new Error("--redirect-uri must be a valid URL");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("--redirect-uri must use http or https");
  return redirectUri;
}

async function slackOAuthAccess({ clientId, clientSecret, code, redirectUri, fetchImpl = fetch }) {
  const auth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  const response = await fetchImpl("https://slack.com/api/oauth.v2.user.access", {
    method: "POST",
    headers: {
      authorization: `Basic ${auth}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ code, redirect_uri: redirectUri }),
  });
  const payload = await safeJson(response);
  if (!payload.ok) throw new Error(`Slack oauth.v2.user.access failed: ${payload.error || "unknown_error"}`);
  if (!payload.access_token) throw new Error("Slack oauth.v2.user.access did not return access_token");
  return payload;
}

async function slackAuthTest(token, fetchImpl = fetch) {
  const response = await fetchImpl("https://slack.com/api/auth.test", {
    headers: { authorization: `Bearer ${token}` },
  });
  const payload = await safeJson(response);
  if (!payload.ok) throw new Error(`Slack auth.test failed: ${payload.error || "unknown_error"}`);
  return payload;
}

async function safeJson(response) {
  if (!response || typeof response.json !== "function") throw new Error("Slack API returned an invalid response");
  return response.json();
}

function assertHumanUserToken(label, identity) {
  if (!identity.user_id) throw new Error(`${label} auth.test did not return user_id`);
  if (identity.bot_id) throw new Error(`${label} must be a human user token, but auth.test returned bot_id`);
}

async function runExchange(args, fetchImpl = fetch) {
  const target = validateTarget(args.target);
  const redirectUri = validateRedirectUri(args.redirectUri);
  const env = { ...parseEnvFile(args.envFile), ...process.env };
  const clientId = envValue({ ...env, SLACK_CLIENT_ID: args.clientId || env.SLACK_CLIENT_ID }, "SLACK_CLIENT_ID");
  const clientSecret = envValue({ ...env, SLACK_CLIENT_SECRET: args.clientSecret || env.SLACK_CLIENT_SECRET }, "SLACK_CLIENT_SECRET");
  const code = args.code || callbackCode(args.callbackUrl);
  if (!clientId) throw new Error("Missing Slack Client ID; pass --client-id or set SLACK_CLIENT_ID in the env file");
  if (!clientSecret) throw new Error("Missing Slack Client Secret; pass --client-secret or set SLACK_CLIENT_SECRET in the env file");
  if (!code) throw new Error("Missing Slack OAuth code; pass --code or --callback-url");

  const oauth = await slackOAuthAccess({ clientId, clientSecret, code, redirectUri, fetchImpl });
  const identity = await slackAuthTest(oauth.access_token, fetchImpl);
  assertHumanUserToken(target, identity);

  const updates = { [target]: oauth.access_token };
  if (args.saveClientCredentials) {
    updates.SLACK_CLIENT_ID = clientId;
    updates.SLACK_CLIENT_SECRET = clientSecret;
  }
  setEnvValues(args.envFile, updates);

  return {
    ok: true,
    envFile: args.envFile,
    saved: Object.keys(updates),
    target,
    team_id: identity.team_id,
    user_id: identity.user_id,
    user: identity.user,
  };
}

function mockResponse(payload) {
  return { json: async () => payload };
}

async function selfTest() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "operant-slack-user-token-"));
  const envFile = path.join(tempDir, ".env");
  fs.writeFileSync(envFile, "SLACK_CLIENT_ID=C123\nSLACK_CLIENT_SECRET=S123\nSLACK_USER_TOKEN=old\n", { mode: 0o644 });
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), auth: String(options.headers?.authorization || ""), body: String(options.body || "") });
    if (String(url).endsWith("/oauth.v2.user.access")) return mockResponse({ ok: true, access_token: "xoxp-new-user-token" });
    if (String(url).endsWith("/auth.test")) return mockResponse({ ok: true, team_id: "T123", user_id: "U123", user: "tester" });
    return mockResponse({ ok: false, error: "unexpected_method" });
  };
  const result = await runExchange(
    parseArgs([
      "--env",
      envFile,
      "--callback-url",
      "http://localhost:3999/slack/oauth/callback?code=CODE123&state=",
      "--denied",
    ]),
    fetchImpl,
  );
  const updated = fs.readFileSync(envFile, "utf8");
  if (result.target !== "OPERANT_LIVE_DENIED_USER_TOKEN") throw new Error("self-test did not use denied target");
  if (!updated.includes("OPERANT_LIVE_DENIED_USER_TOKEN=xoxp-new-user-token")) throw new Error("self-test did not save denied token");
  if (updated.includes("SLACK_CLIENT_SECRET=xoxp-new-user-token")) throw new Error("self-test leaked token into wrong env var");
  if (!calls[0].body.includes("code=CODE123")) throw new Error("self-test did not exchange callback code");
  if ((fs.statSync(envFile).mode & 0o777) !== 0o600) throw new Error("self-test did not preserve private env file permissions");

  const botFetchImpl = async (url) => {
    if (String(url).endsWith("/oauth.v2.user.access")) return mockResponse({ ok: true, access_token: "xoxb-bot-token" });
    return mockResponse({ ok: true, team_id: "T123", user_id: "UBOT", user: "bot", bot_id: "B123" });
  };
  let rejectedBot = false;
  try {
    await runExchange(parseArgs(["--env", envFile, "--code", "CODE456"]), botFetchImpl);
  } catch (error) {
    rejectedBot = String(error.message || error).includes("human user token");
  }
  if (!rejectedBot) throw new Error("self-test did not reject a bot token identity");
  console.log("Slack user token exchange self-test passed.");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }
  if (args.selfTest) {
    await selfTest();
    return;
  }
  const result = await runExchange(args);
  if (args.json) console.log(JSON.stringify(result));
  else {
    console.log(`Saved ${result.target} in ${result.envFile}`);
    console.log(`Slack auth.test: team=${result.team_id || "unknown"} user=${result.user_id || "unknown"}`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message || error);
    process.exit(1);
  });
}
