#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { missingScopes, requiredLiveBotScopes, requiredSlackBotEvents } from "./slack-scope-contract.mjs";

const defaultReportPath = ".operant/slack-manifest-probe-report.json";

function usage() {
  return `Usage: node scripts/slack-manifest-probe.mjs [options]

Exports the installed Slack app manifest with a Slack configuration token and
verifies the app settings required for Operant live DM/Socket Mode acceptance.

Options:
  --env <path>                  Load env file values
  --live-env <path>             Load private live env overlay
  --config-token <token>        Slack configuration token, or SLACK_CONFIG_TOKEN
  --app-id <A...>               Slack app ID; defaults to SLACK_APP_ID or xapp token
  --report <path>               Sanitized evidence report; default ${defaultReportPath}
  --json                        Print JSON result
  --self-test                   Run local self-test without network
  --help, -h                    Show this help
`;
}

function parseArgs(argv) {
  const args = {
    envFile: "",
    liveEnvFile: "",
    configToken: "",
    appId: "",
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
    else if (arg === "--config-token") args.configToken = takeValue(arg, index++);
    else if (arg === "--app-id") args.appId = takeValue(arg, index++);
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
    if (value && !/^<[^>]+>$/.test(value) && !["A...", "xoxe-...", "xoxp-..."].includes(value)) return value;
  }
  return "";
}

function inferAppIdFromAppToken(appToken) {
  const match = /^xapp-\d+-(A[A-Z0-9]+)-/.exec(String(appToken || "").trim());
  return match?.[1] || "";
}

function validateSlackShape(value, pattern, label) {
  if (!pattern.test(value)) throw new Error(`${label} has an unexpected Slack ID/token shape`);
  return value;
}

async function slackApi(method, token, params = {}, fetchImpl = fetch) {
  const response = await fetchImpl(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params),
  });
  const text = typeof response.text === "function" ? await response.text() : JSON.stringify(await response.json());
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { ok: false, error: `invalid_json:${text.slice(0, 80)}` };
  }
  if (!payload.ok) {
    const needed = payload.needed ? `; needed=${payload.needed}` : "";
    throw new Error(`Slack ${method} failed: ${payload.error || "unknown_error"}${needed}`);
  }
  return payload;
}

function arrayValue(value) {
  return Array.isArray(value) ? value.map(String) : [];
}

function checkManifest(manifest) {
  const features = manifest?.features || {};
  const appHome = features.app_home || features.appHome || {};
  const settings = manifest?.settings || {};
  const events = arrayValue(settings.event_subscriptions?.bot_events);
  const botScopes = arrayValue(manifest?.oauth_config?.scopes?.bot);
  const missingBotScopes = missingScopes(botScopes, requiredLiveBotScopes);
  const missingBotEvents = requiredSlackBotEvents.filter((event) => !events.includes(event));
  const checks = [
    {
      key: "socket_mode_enabled",
      ok: settings.socket_mode_enabled === true,
      expected: true,
      actual: settings.socket_mode_enabled ?? null,
    },
    {
      key: "app_home.messages_tab_enabled",
      ok: appHome.messages_tab_enabled === true || appHome.messagesTabEnabled === true,
      expected: true,
      actual: appHome.messages_tab_enabled ?? appHome.messagesTabEnabled ?? null,
    },
    {
      key: "app_home.messages_tab_read_only_enabled",
      ok: appHome.messages_tab_read_only_enabled === false || appHome.messagesTabReadOnlyEnabled === false,
      expected: false,
      actual: appHome.messages_tab_read_only_enabled ?? appHome.messagesTabReadOnlyEnabled ?? null,
    },
    {
      key: "required_bot_events",
      ok: missingBotEvents.length === 0,
      expected: requiredSlackBotEvents,
      missing: missingBotEvents,
    },
    {
      key: "required_bot_scopes",
      ok: missingBotScopes.length === 0,
      expected: requiredLiveBotScopes,
      missing: missingBotScopes,
    },
  ];
  return {
    ok: checks.every((check) => check.ok),
    checks,
    summary: {
      socketModeEnabled: settings.socket_mode_enabled === true,
      messagesTabEnabled: appHome.messages_tab_enabled === true || appHome.messagesTabEnabled === true,
      messagesTabWritable: appHome.messages_tab_read_only_enabled === false || appHome.messagesTabReadOnlyEnabled === false,
      botEventCount: events.length,
      botScopeCount: botScopes.length,
    },
  };
}

function writeReport(reportPath, report) {
  fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(reportPath, 0o600);
}

async function runProbe(options, fetchImpl = fetch) {
  const mergedEnv = {
    ...parseEnvFile(options.envFile),
    ...parseEnvFile(options.liveEnvFile),
    ...process.env,
  };
  const configToken = validateSlackShape(
    options.configToken || envValue(mergedEnv, "SLACK_CONFIG_TOKEN", "SLACK_CONFIGURATION_TOKEN", "OPERANT_LIVE_SLACK_CONFIG_TOKEN"),
    /^xox[pce]-/,
    "Slack configuration token",
  );
  const appId = validateSlackShape(
    options.appId ||
      envValue(mergedEnv, "SLACK_APP_ID", "OPERANT_LIVE_SLACK_APP_ID") ||
      inferAppIdFromAppToken(envValue(mergedEnv, "OPERANT_LIVE_SLACK_APP_TOKEN", "SLACK_APP_TOKEN")),
    /^A[A-Z0-9]+$/,
    "Slack app ID",
  );

  const exported = await slackApi("apps.manifest.export", configToken, { app_id: appId }, fetchImpl);
  const result = checkManifest(exported.manifest || {});
  const report = {
    format: "operant.slack-manifest-probe-report.v1",
    generatedAt: new Date().toISOString(),
    envPath: options.envFile || "",
    liveEnvPath: options.liveEnvFile || "",
    appId,
    ok: result.ok,
    ...result,
  };
  writeReport(options.reportPath, report);
  if (!result.ok) {
    const failing = result.checks.filter((check) => !check.ok).map((check) => check.key).join(", ");
    const error = new Error(`Installed Slack app manifest is missing required Operant settings: ${failing}`);
    error.report = report;
    error.exitCode = 2;
    throw error;
  }
  return report;
}

function mockResponse(payload) {
  return { text: async () => JSON.stringify(payload) };
}

async function runSelfTest() {
  const manifest = {
    features: {
      app_home: {
        home_tab_enabled: true,
        messages_tab_enabled: true,
        messages_tab_read_only_enabled: false,
      },
    },
    oauth_config: {
      scopes: {
        bot: [...requiredLiveBotScopes],
      },
    },
    settings: {
      socket_mode_enabled: true,
      event_subscriptions: {
        bot_events: [...requiredSlackBotEvents],
      },
    },
  };
  const checks = checkManifest(manifest);
  if (!checks.ok || !checks.summary.messagesTabWritable) throw new Error("manifest checker rejected valid manifest");
  const invalid = checkManifest({
    ...manifest,
    features: { app_home: { messages_tab_enabled: true, messages_tab_read_only_enabled: true } },
  });
  if (invalid.ok || !invalid.checks.find((check) => check.key === "app_home.messages_tab_read_only_enabled" && !check.ok)) {
    throw new Error("manifest checker did not reject read-only messages tab");
  }
  let called = false;
  const fetchImpl = async (url, options = {}) => {
    called = true;
    if (!String(options.body || "").includes("app_id=A123")) throw new Error("self-test did not send app_id");
    if (!String(options.headers?.authorization || "").includes("xoxp-config")) throw new Error("self-test did not send config token");
    if (!String(url).endsWith("/apps.manifest.export")) throw new Error("self-test called unexpected Slack method");
    return mockResponse({ ok: true, manifest });
  };
  const reportPath = path.join(".operant", "slack-manifest-probe-self-test-report.json");
  const report = await runProbe(
    parseArgs(["--config-token", "xoxp-config", "--app-id", "A123", "--report", reportPath]),
    fetchImpl,
  );
  if (!called || !report.ok || report.appId !== "A123") throw new Error("manifest probe self-test failed");
  if (inferAppIdFromAppToken("xapp-1-A123-456-secret") !== "A123") throw new Error("app token app ID inference failed");
  console.log("Slack manifest probe self-test passed.");
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
    const result = await runProbe(args);
    if (args.json) console.log(JSON.stringify(result, null, 2));
    else console.log(`Slack manifest probe passed for ${result.appId}`);
  } catch (error) {
    if (args.json && error.report) console.log(JSON.stringify(error.report, null, 2));
    console.error(error.message || String(error));
    process.exitCode = error.exitCode || 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
