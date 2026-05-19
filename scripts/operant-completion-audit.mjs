#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { access, readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyComposeFile } from "./operant-verify-compose.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const allowBlocked = process.argv.includes("--allow-blocked");
const jsonOutput = process.argv.includes("--json");
const allowPreCompletionAuditReport = process.env.OPERANT_ALLOW_PRE_COMPLETION_AUDIT_REPORT === "true";
const requireStrictLive = process.env.OPERANT_REQUIRE_STRICT_LIVE === "1" || process.env.OPERANT_REQUIRE_STRICT_LIVE === "true";
const composeE2EReportPath = path.resolve(repoRoot, process.env.OPERANT_COMPOSE_E2E_REPORT || ".operant/compose-e2e-report.json");
const composeSmokeReportPath = path.resolve(repoRoot, process.env.OPERANT_COMPOSE_SMOKE_REPORT || ".operant/compose-smoke-report.json");
const composeSandboxSmokeReportPath = path.resolve(repoRoot, process.env.OPERANT_COMPOSE_SANDBOX_SMOKE_REPORT || ".operant/compose-sandbox-smoke-report.json");

const baseLiveEnvGroups = [
  ["OPERANT_ADMIN_LOGIN_TOKEN"],
  ["OPERANT_LIVE_ADMIN_SLACK_USER_ID"],
  ["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"],
  ["SLACK_BOT_TOKEN", "OPERANT_LIVE_SLACK_BOT_TOKEN"],
  ["OPERANT_LIVE_DM_CHANNEL_ID"],
];

const tokenLiveEnvGroups = [
  ["SLACK_USER_TOKEN", "OPERANT_LIVE_SLACK_USER_TOKEN"],
  ["OPERANT_LIVE_DENIED_USER_TOKEN"],
];

const manualLiveEnvGroups = [
  ["OPERANT_LIVE_DENIED_USER_ID"],
];

const liveEnvGroups = [...baseLiveEnvGroups, ...tokenLiveEnvGroups];

const composeSeedEnvGroups = [
  ["OPERANT_LIVE_SLACK_APP_TOKEN", "SLACK_APP_TOKEN"],
  ["OPERANT_LIVE_MODEL_API_KEY", "MODEL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
];

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
  "sk-local-acceptance-redaction-token",
  "sk-operant-compose-smoke-model",
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

const checks = [];
let composeReportEnv = {};
let composeReportEnvSource = "";
const processEnvSourceNames = [
  ...new Set([
    ...liveEnvGroups.flat(),
    ...manualLiveEnvGroups.flat(),
    ...composeSeedEnvGroups.flat(),
    "OPERANT_LIVE_MANUAL_SLACK_POSTS",
    "OPERANT_LIVE_ALLOWED_USER_ID",
    "OPERANT_LIVE_MODEL_PROVIDER",
    "MODEL_PROVIDER",
  ]),
].sort();
const requiredStrictOpenClawChecks = ["config-validate", "status", "secrets-reload", "approvals-get", "cron-status", "tasks-list", "usage-cost", "doctor", "security-audit", "channels-status"];
const requiredStrictOpenClawCheckAssertions = new Map([
  ["config-validate", ["config-valid:true"]],
  ["status", ["status-gateway-reachable"]],
  ["secrets-reload", ["secrets-reload-ok:true"]],
  ["tasks-list", ["tasks-json"]],
  ["usage-cost", ["usage-cost-numeric-totals"]],
  ["security-audit", ["security-critical:0"]],
  ["channels-status", ["channels-status-slack-connected", "channels-status-probe:true"]],
]);
const pairingOptionalStrictOpenClawChecks = new Set(["secrets-reload", "approvals-get", "cron-status", "usage-cost", "channels-status"]);

function addCheck(group, requirement, ok, evidence, status = ok ? "pass" : "fail") {
  checks.push({ group, requirement, ok: Boolean(ok), status, evidence });
}

function addStrictOrAdvisoryCheck(requirement, ok, blockingEvidence, advisoryEvidence) {
  if (requireStrictLive) {
    addCheck("blocked-live", requirement, ok, blockingEvidence, ok ? "pass" : "blocked");
  } else {
    addCheck("live-advisory", requirement, true, advisoryEvidence);
  }
}

async function fileExists(file) {
  try {
    await access(path.join(repoRoot, file));
    return true;
  } catch {
    return false;
  }
}

async function source(file) {
  return readFile(path.join(repoRoot, file), "utf8");
}

async function patternCheck(group, requirement, file, patterns, statusLabel) {
  let body = "";
  try {
    body = await source(file);
  } catch (error) {
    addCheck(group, requirement, false, `${file}: missing (${error.message})`);
    return;
  }
  const missing = patterns.filter(([label, pattern]) => !pattern.test(body)).map(([label]) => label);
  addCheck(group, requirement, missing.length === 0, missing.length ? `${file}: missing ${missing.join(", ")}` : `${file}: ${statusLabel || "matched"}`);
}

async function dashboardApiWiringCheck() {
  const indexPath = "apps/control-plane/public/index.html";
  const appPath = "apps/control-plane/public/app.js";
  let index = "";
  let app = "";
  try {
    [index, app] = await Promise.all([source(indexPath), source(appPath)]);
  } catch (error) {
    addCheck("control-plane", "admin dashboard API wiring", false, `dashboard source missing (${error.message})`);
    return;
  }

  const expectations = [
    ["login form", index.includes('id="login-form"') && app.includes('request("/api/auth/login"')],
    ["logout action", index.includes('id="logout"') && app.includes('request("/api/auth/logout"')],
    ["no dashboard bootstrap action", !app.includes('request("/api/bootstrap"')],
    ["summary load", app.includes('request("/api/summary"')],
    ["credential setup", index.includes('id="credentials-form"') && app.includes('request("/api/config/credentials"')],
    [
      "credential setup fields",
      ["adminSlackUserId", "adminLoginToken", "slackBotToken", "slackAppToken", "modelProvider", "modelName", "modelApiKey", "allowedDmUserIds", "allowedChannelIds", "approvalSlackUserIds"].every((name) =>
        index.includes(`name="${name}"`),
      ),
    ],
    ["integration credentials", index.includes('id="integration-credential-form"') && app.includes('request("/api/integrations/credentials"')],
    ["integration credential fields", (() => {
      const formMatch = /<form[^>]*id="integration-credential-form"[\s\S]*?<\/form>/.exec(index);
      if (!formMatch) return false;
      const formHtml = formMatch[0];
      const fieldsPresent = ["kind", "key", "label", "secretValue", "slackUserId"].every((name) => formHtml.includes(`name="${name}"`));
      const stripsEmptySlackUser = /if \(!payload\.slackUserId\)\s+delete payload\.slackUserId/.test(app);
      return fieldsPresent && stripsEmptySlackUser;
    })()],
    ["user management", index.includes('id="user-form"') && app.includes('request("/api/users"')],
    ["user access fields", ["slackUserId", "name", "email", "roles"].every((name) => index.includes(`name="${name}"`))],
    ["custom roles", index.includes('id="role-form"') && app.includes('request("/api/roles"')],
    ["custom role permission fields", index.includes('name="permissions"') && app.includes("parsePermissionPairs")],
    ["operator cockpit navigation", index.includes('data-view-target="setup-view"') && index.includes('data-view-target="openclaw-view"')],
    ["first-run readiness checklist", index.includes('id="setup-checklist"') && index.includes('id="setup-progress"') && app.includes("Ready to run Slack acceptance")],
    ["credential validation state", index.includes('id="credential-validation-state"') && app.includes("Saved as SecretRef")],
    ["confirmation modal", index.includes('id="confirm-modal"') && app.includes("confirmAction")],
    ["settings read/write", index.includes('id="settings-form"') && app.includes('request("/api/settings"') && /request\("\/api\/settings",\s*\{\s*method:\s*"PUT"/.test(app)],
    ["policy load/save/evaluate", index.includes('id="policy-editor"') && app.includes('request("/api/policy"') && /request\("\/api\/policy",\s*\{\s*method:\s*"PUT"/.test(app) && app.includes('request("/api/policy/evaluate"')],
    ["policy preview fields", ["slackUserId", "slackChannelId", "chatType", "tool", "action", "resource"].every((name) => index.includes(`name="${name}"`))],
    ["structured policy editor", ["policy-channel-form", "policy-tool-form", "policy-approval-rule-form"].every((id) => index.includes(`id="${id}"`))],
    ["approval request/decision", index.includes('id="approval-form"') && app.includes('request("/api/approvals"') && app.includes("/api/approvals/${button.dataset.approvalId}/decision")],
    ["OpenClaw config generation", index.includes('id="generate-config"') && app.includes('request("/api/openclaw/config"')],
    ["OpenClaw observation sync", index.includes('id="sync-openclaw"') && app.includes('request("/api/openclaw/observations/sync"')],
    ["OpenClaw check buttons", index.includes('class="openclaw-check"') && app.includes("/api/openclaw/checks/${button.dataset.check}")],
    ["usage summary", index.includes('id="usage-summary"') && app.includes('request("/api/usage/summary"')],
    ["usage events", index.includes('id="usage-events"') && /request\("\/api\/usage"\)/.test(app)],
    ["sessions/jobs activity", index.includes('id="activity-result"') && app.includes('request("/api/sessions"') && app.includes('request("/api/jobs"')],
    ["audit log", index.includes('id="audit-log"') && app.includes('request("/api/audit"')],
    ["retention purge", index.includes('id="retention-purge"') && app.includes('request("/api/retention/purge"')],
    ["retention export", index.includes('id="queue-export"') && app.includes('request("/api/export"')],
    ["retention wipe", index.includes('id="queue-wipe"') && index.includes('id="wipe-scope"') && app.includes('request("/api/wipe"')],
    ["synchronous export/wipe wording", index.includes("Create Export") && index.includes("Run Wipe") && app.includes('toast("Export created")') && app.includes("wipe completed") && !index.includes("Queue Export") && !index.includes("Queue Wipe") && !app.includes("wipe queued")],
  ];
  const missing = expectations.filter(([, ok]) => !ok).map(([label]) => label);
  addCheck(
    "control-plane",
    "admin dashboard API wiring",
    missing.length === 0,
    missing.length ? `${indexPath}/${appPath}: missing ${missing.join(", ")}` : `${expectations.length} dashboard controls wired to API calls`,
  );
}

async function listFiles(relativeDir, predicate) {
  const root = path.join(repoRoot, relativeDir);
  const files = [];

  async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(repoRoot, fullPath);
      if (entry.isDirectory()) {
        if (entry.name === "dist" || entry.name === "node_modules") continue;
        await walk(fullPath);
        continue;
      }
      if (entry.isFile() && predicate(relativePath)) files.push(relativePath);
    }
  }

  await walk(root);
  return files.sort();
}

async function slackRuntimeBoundaryCheck() {
  const violations = [];
  const manifestFiles = ["package.json", "apps/control-plane/package.json", "pnpm-lock.yaml"];
  const forbiddenDependencyPatterns = [
    ["Slack Bolt dependency", /(?:^|\n)\s*(?:"|')?@slack\/bolt(?:"|')?\s*[:@]/],
    ["Slack Socket Mode dependency", /(?:^|\n)\s*(?:"|')?@slack\/socket-mode(?:"|')?\s*[:@]/],
    ["Slack Events API dependency", /(?:^|\n)\s*(?:"|')?@slack\/events-api(?:"|')?\s*[:@]/],
    ["Slack interactivity dependency", /(?:^|\n)\s*(?:"|')?@slack\/interactive-messages(?:"|')?\s*[:@]/],
    ["Slack Web API runtime dependency", /(?:^|\n)\s*(?:"|')?@slack\/web-api(?:"|')?\s*[:@]/],
  ];

  for (const file of manifestFiles) {
    const body = await source(file);
    for (const [label, pattern] of forbiddenDependencyPatterns) {
      if (pattern.test(body)) violations.push(`${file}: ${label}`);
    }
  }

  const sourceFiles = await listFiles("apps/control-plane/src", (file) => file.endsWith(".ts"));
  const publicAssetFiles = await listFiles("apps/control-plane/public", (file) => /\.(?:html|js|css)$/u.test(file));
  const runtimeFiles = [...sourceFiles, ...publicAssetFiles];
  const forbiddenRuntimePatterns = [
    ["Slack SDK import", /(?:from\s+["']@slack\/|import\(["']@slack\/|require\(["']@slack\/)/],
    ["Slack Socket Mode client", /\bSocketModeClient\b|\bSocketModeReceiver\b|\bsocketMode:\s*true\b/],
    ["Slack HTTP signature verification", /x-slack-signature|x-slack-request-timestamp|SLACK_SIGNING_SECRET/],
    ["Slack event/interactivity route", /\/(?:api\/)?slack\/(?:events|event|interactivity|interactions|commands|actions)\b/],
    ["Slack direct event payload handling", /\bresponse_url\b|\burl_verification\b|\bevent_callback\b|\bblock_actions\b/],
    ["Slack Web API write runtime", /\bchat\.postMessage\b|\bfiles\.upload\b|\bviews\.open\b/],
    ["Slack Web API HTTP endpoint", /https:\/\/slack\.com\/api\/|slack\.com\/api\/(?:chat\.postMessage|files\.upload|views\.open|apps\.connections\.open)/],
  ];

  for (const file of runtimeFiles) {
    const body = await source(file);
    for (const [label, pattern] of forbiddenRuntimePatterns) {
      if (pattern.test(body)) violations.push(`${file}: ${label}`);
    }
  }

  addCheck(
    "openclaw",
    "No custom Slack runtime in Operant control plane",
    violations.length === 0,
    violations.length
      ? violations.join("; ")
      : `manifests, ${sourceFiles.length} control-plane source files, and ${publicAssetFiles.length} dashboard public asset files scanned`,
  );
}

async function migrationFilenameCheck() {
  const dir = "apps/control-plane/migrations";
  let files;
  try {
    files = (await readdir(path.join(repoRoot, dir))).filter((file) => file.endsWith(".sql")).sort();
  } catch (error) {
    addCheck("state", "ordered migration filenames", false, `${dir}: missing (${error.message})`);
    return;
  }
  const invalid = files.filter((file) => !/^\d{3}_[a-z0-9_]+\.sql$/u.test(file));
  const prefixes = files.map((file) => file.slice(0, 3));
  const duplicatePrefixes = [...new Set(prefixes.filter((prefix, index) => prefixes.indexOf(prefix) !== index))];
  const expectedPrefixes = files.map((_, index) => String(index + 1).padStart(3, "0"));
  const outOfSequence = files.filter((_, index) => prefixes[index] !== expectedPrefixes[index]);
  const problems = [
    invalid.length ? `invalid names: ${invalid.join(", ")}` : "",
    duplicatePrefixes.length ? `duplicate prefixes: ${duplicatePrefixes.join(", ")}` : "",
    outOfSequence.length ? `out of sequence: ${outOfSequence.join(", ")}` : "",
  ].filter(Boolean);
  addCheck(
    "state",
    "ordered migration filenames",
    problems.length === 0,
    problems.length ? `${dir}: ${problems.join("; ")}` : `${dir}: ${files.join(", ")}`,
  );
}

async function adminListProjectionCheck() {
  const file = "apps/control-plane/src/server.ts";
  let body = "";
  try {
    body = await source(file);
  } catch (error) {
    addCheck("security", "admin list explicit projections", false, `${file}: missing (${error.message})`);
    return;
  }
  const start = body.indexOf("const listDefinitions");
  const end = body.indexOf("async function handleApprovalDecision", start);
  const block = start >= 0 && end > start ? body.slice(start, end) : "";
  const tables = ["audit_logs", "approvals", "sessions", "jobs", "usage_events"];
  const missing = tables.filter((table) => {
    const pattern = new RegExp(`${table}:\\s*\\{[\\s\\S]*?query:\\s*\`SELECT\\s+(?!\\*)[\\s\\S]*?FROM\\s+${table}[\\s\\S]*?WHERE workspace_id = \\$1`, "u");
    return !pattern.test(block);
  });
  const dynamicWildcard = /SELECT\s+\*|FROM\s+\$\{table\}/u.test(block);
  const problems = [
    missing.length ? `missing explicit projections for ${missing.join(", ")}` : "",
    dynamicWildcard ? "list block still contains wildcard or dynamic table SQL" : "",
  ].filter(Boolean);
  addCheck("security", "admin list explicit projections", problems.length === 0, problems.length ? `${file}: ${problems.join("; ")}` : `${file}: listDefinitions use explicit columns`);
}

async function serverSqlProjectionCheck() {
  const file = "apps/control-plane/src/server.ts";
  let body = "";
  try {
    body = await source(file);
  } catch (error) {
    addCheck("security", "server SQL explicit projections", false, `${file}: missing (${error.message})`);
    return;
  }
  const wildcardMatches = [...body.matchAll(/\b(?:SELECT|RETURNING)\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)?\*/giu)].map((match) => match[0]);
  addCheck(
    "security",
    "server SQL explicit projections",
    wildcardMatches.length === 0,
    wildcardMatches.length ? `${file}: wildcard projections remain (${wildcardMatches.join(", ")})` : `${file}: no SELECT *, SELECT alias.*, or RETURNING * projections`,
  );
}

function commandAvailable(command, args = ["--version"]) {
  const result = spawnSync(command, args, { cwd: repoRoot, encoding: "utf8" });
  return {
    ok: result.status === 0,
    detail: result.status === 0 ? `${command} ${args.join(" ")} ok` : `${command} unavailable or failed`,
  };
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

function composeRuntimeEnv(baseEnv = process.env) {
  const env = { ...baseEnv, ...composeReportEnv };
  for (const [key, value] of Object.entries(baseEnv)) {
    if (key.startsWith("OPERANT_LIVE_") || key.startsWith("SLACK_") || ["MODEL_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"].includes(key)) {
      env[key] = value;
    }
  }
  return env;
}

function runtimeEnvSource(baseEnv = process.env) {
  const sources = [];
  if (composeReportEnvSource) sources.push(composeReportEnvSource);
  const presentProcessKeys = processEnvSourceNames.filter((key) => baseEnv[key] && !isPlaceholderValue(baseEnv[key]));
  if (presentProcessKeys.length > 0) sources.push(`process env live/model keys ${presentProcessKeys.join(", ")}`);
  return sources.length ? `; includes ${sources.join("; ")}` : "";
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

async function loadComposeReportEnv() {
  let report;
  try {
    report = JSON.parse(await readFile(composeE2EReportPath, "utf8"));
  } catch {
    return;
  }
  const envFragments = [];
  const sources = [];
  if (!report?.envPath) return;
  const envPath = path.resolve(repoRoot, report.envPath);
  try {
    envFragments.push(parseEnv(await readFile(envPath, "utf8")));
    sources.push(`Compose env file ${path.relative(repoRoot, envPath)}`);
  } catch {
    composeReportEnv = {};
    composeReportEnvSource = "";
    return;
  }
  if (report.liveEnvPath) {
    const liveEnvPath = path.resolve(repoRoot, report.liveEnvPath);
    try {
      envFragments.push(parseEnv(await readFile(liveEnvPath, "utf8")));
      sources.push(`live env file ${path.relative(repoRoot, liveEnvPath)}`);
    } catch {
      // Missing live env overlays are reported by the normal live credential gates.
    }
  }
  composeReportEnv = Object.assign({}, ...envFragments);
  composeReportEnvSource = sources.join("; ");
}

function missingEnvGroups(env, groups) {
  return groups
    .filter((group) => !group.some((key) => env[key] && !isPlaceholderValue(env[key])))
    .map((group) => group.join("|"));
}

function firstEnv(env, names, fallback = "") {
  for (const name of names) {
    if (env[name]) return env[name];
  }
  return fallback;
}

function firstNonPlaceholderEnv(env, names) {
  for (const name of names) {
    if (env[name] && !isPlaceholderValue(env[name])) return env[name];
  }
  return "";
}

function booleanEnv(env, name) {
  return /^(1|true|yes)$/i.test(String(env[name] || "").trim());
}

function manualSlackPostsEnabled(env) {
  return booleanEnv(env, "OPERANT_LIVE_MANUAL_SLACK_POSTS");
}

function liveVerifierEnvGroups(env) {
  return [
    ...baseLiveEnvGroups,
    ...(manualSlackPostsEnabled(env) ? manualLiveEnvGroups : tokenLiveEnvGroups),
  ];
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
  return `model API key for provider ${provider} missing (${accepted}); provider-specific keys for other providers are ignored`;
}

async function staleComposeEvidenceInputs(reportGeneratedAtMs) {
  const stale = [];
  for (const file of composeEvidenceInputs) {
    const stats = await stat(resolveEvidenceFile(file));
    if (stats.mtimeMs > reportGeneratedAtMs + 1000) stale.push(file);
  }
  return stale;
}

function resolveEvidenceFile(file) {
  return path.isAbsolute(file) ? file : path.join(repoRoot, file);
}

async function fileSha256(file) {
  return createHash("sha256").update(await readFile(resolveEvidenceFile(file))).digest("hex");
}

async function changedComposeEvidenceInputs(report, reportGeneratedAtMs) {
  if (Array.isArray(report.evidenceInputs) && report.evidenceInputs.length > 0) {
    const reported = new Map(report.evidenceInputs.map((input) => [input.file, input.sha256]));
    const changed = [];
    const filesToCheck = Array.from(new Set([...composeEvidenceInputs, ...reported.keys()]));
    for (const file of filesToCheck) {
      const current = await fileSha256(file);
      if (reported.get(file) !== current) changed.push(file);
    }
    return changed;
  }
  return staleComposeEvidenceInputs(reportGeneratedAtMs);
}

function missingRequiredOpenClawChecks(report) {
  const configured = new Set(report.options?.openClawChecks || []);
  return requiredStrictOpenClawChecks.filter((check) => !configured.has(check));
}

function missingCompletedOpenClawChecks(report) {
  const completed = new Map(
    (Array.isArray(report.result?.openClawChecks) ? report.result.openClawChecks : [])
      .map((result) => [result.check, result]),
  );
  return requiredStrictOpenClawChecks.filter((check) => {
    const result = completed.get(check);
    if (pairingOptionalStrictOpenClawChecks.has(check) && result?.skipped === true && /pairing/i.test(String(result.reason || ""))) {
      return false;
    }
    return !result || result.exitCode !== 0 || result.timedOut === true;
  });
}

function missingOpenClawCheckAssertions(report) {
  const completed = new Map(
    (Array.isArray(report.result?.openClawChecks) ? report.result.openClawChecks : [])
      .map((result) => [result.check, result]),
  );
  const missing = [];
  for (const [check, requiredAssertions] of requiredStrictOpenClawCheckAssertions.entries()) {
    const result = completed.get(check);
    if (pairingOptionalStrictOpenClawChecks.has(check) && result?.skipped === true && /pairing/i.test(String(result.reason || ""))) {
      continue;
    }
    const assertions = new Set(Array.isArray(result?.assertions) ? result.assertions : []);
    if (check === "channels-status" && assertions.has("channels-status-configured")) continue;
    const missingAssertions = requiredAssertions.filter((assertion) => !assertions.has(assertion));
    if (missingAssertions.length > 0) missing.push(`${check}:${missingAssertions.join(",")}`);
  }
  return missing;
}

function expectedLiveEnvValue(names) {
  return firstNonPlaceholderEnv(composeRuntimeEnv(), names);
}

function mismatchedLiveReportField(report, label) {
  const expectedChannelId = expectedLiveEnvValue(["SLACK_CHANNEL_ID", "OPERANT_LIVE_SLACK_CHANNEL_ID"]);
  if (expectedChannelId && report.channelId !== expectedChannelId) {
    return `${label} live report channelId ${report.channelId || "<missing>"} did not match Compose env Slack channel ${expectedChannelId}`;
  }
  if (report.result?.channelId && report.result.channelId !== report.channelId) {
    return `${label} live report result channelId ${report.result.channelId} did not match top-level channelId ${report.channelId || "<missing>"}`;
  }

  const expectedAdminSlackUserId = expectedLiveEnvValue(["OPERANT_LIVE_ADMIN_SLACK_USER_ID"]);
  if (expectedAdminSlackUserId && report.adminSlackUserId !== expectedAdminSlackUserId) {
    return `${label} live report adminSlackUserId ${report.adminSlackUserId || "<missing>"} did not match Compose env admin Slack user ${expectedAdminSlackUserId}`;
  }

  const expectedDmChannelId = expectedLiveEnvValue(["OPERANT_LIVE_DM_CHANNEL_ID"]);
  if (expectedDmChannelId && report.dmChannelId !== expectedDmChannelId) {
    return `${label} live report dmChannelId ${report.dmChannelId || "<missing>"} did not match Compose env DM channel ${expectedDmChannelId}`;
  }

  const expectedSlackTeamId = expectedLiveEnvValue(["OPERANT_LIVE_SLACK_TEAM_ID", "SLACK_TEAM_ID"]);
  if (expectedSlackTeamId && report.slackTeamId !== expectedSlackTeamId) {
    return `${label} live report slackTeamId ${report.slackTeamId || "<missing>"} did not match Compose env Slack team ${expectedSlackTeamId}`;
  }
  if (report.result?.slackTeamId && report.result.slackTeamId !== report.slackTeamId) {
    return `${label} live report result slackTeamId ${report.result.slackTeamId} did not match top-level slackTeamId ${report.slackTeamId || "<missing>"}`;
  }
  if (expectedSlackTeamId && report.result?.deniedProbe?.teamId && report.result.deniedProbe.teamId !== expectedSlackTeamId) {
    return `${label} live report denied user team ${report.result.deniedProbe.teamId} did not match Compose env Slack team ${expectedSlackTeamId}`;
  }

  const expectedBotUserId = expectedLiveEnvValue(["OPERANT_LIVE_BOT_USER_ID"]);
  if (expectedBotUserId && report.botUserId !== expectedBotUserId) {
    return `${label} live report botUserId ${report.botUserId || "<missing>"} did not match Compose env bot user ${expectedBotUserId}`;
  }

  const expectedDeniedUserId = expectedLiveEnvValue(["OPERANT_LIVE_DENIED_USER_ID"]);
  if (expectedDeniedUserId && report.result?.deniedProbe?.userId !== expectedDeniedUserId) {
    return `${label} live report denied user ${report.result?.deniedProbe?.userId || "<missing>"} did not match Compose env denied user ${expectedDeniedUserId}`;
  }

  return null;
}

function passedStep(report, name) {
  return Array.isArray(report.steps) ? report.steps.find((step) => step.status === "pass" && step.name === name) : null;
}

function passedStepIndex(report, name) {
  return Array.isArray(report.steps) ? report.steps.findIndex((step) => step.status === "pass" && step.name === name) : -1;
}

function stepRecordedAtMs(step) {
  const timestamp = Date.parse(step?.recordedAt || "");
  return Number.isFinite(timestamp) ? timestamp : NaN;
}

function slackTimestampAfter(ts, afterTs) {
  if (!ts || !afterTs) return false;
  const left = String(ts).replace(".", "");
  const right = String(afterTs).replace(".", "");
  if (/^\d+$/.test(left) && /^\d+$/.test(right)) return BigInt(left) > BigInt(right);
  return Number(ts) > Number(afterTs);
}

function liveReportDescriptorPathFailure(descriptor, label) {
  const descriptorPath = descriptor?.path;
  if (!descriptorPath || typeof descriptorPath !== "string") return `${label} live report descriptor missing path`;
  if (path.isAbsolute(descriptorPath)) return `${label} live report descriptor path must be repo-relative`;
  const normalized = path.normalize(descriptorPath);
  if (normalized.startsWith("..") || path.isAbsolute(normalized)) return `${label} live report descriptor path must stay inside the repo`;
  if (!(normalized === ".operant" || normalized.startsWith(`.operant${path.sep}`))) {
    return `${label} live report descriptor path must be under .operant`;
  }
  return null;
}

function liveReportPathFromDescriptor(descriptor) {
  return path.join(repoRoot, path.normalize(descriptor.path));
}

async function checkLiveE2EReport(descriptor, label, composeReport) {
  const pathFailure = liveReportDescriptorPathFailure(descriptor, label);
  if (pathFailure) return pathFailure;
  const liveReportPath = liveReportPathFromDescriptor(descriptor);
  let body = "";
  let report;
  try {
    body = await readFile(liveReportPath, "utf8");
    report = JSON.parse(body);
  } catch (error) {
    return `${label} live report ${descriptor?.path || "<missing path>"} missing or unreadable (${error.message})`;
  }
  if (descriptor?.required && !descriptor.sha256) return `${label} live report descriptor missing pinned sha256`;
  if (descriptor?.sha256 && createHash("sha256").update(body).digest("hex") !== descriptor.sha256) {
    return `${label} live report sha256 did not match Compose descriptor`;
  }
  if (descriptor?.required && !descriptor.generatedAt) return `${label} live report descriptor missing generatedAt`;
  if (descriptor?.generatedAt && report.generatedAt !== descriptor.generatedAt) {
    return `${label} live report generatedAt did not match Compose descriptor`;
  }
  if (report.format !== "operant.live-e2e-report.v1") return `${label} live report has invalid format`;
  if (report.status !== "pass" || report.passed !== true) return `${label} live report did not pass`;
  if (report.baseUrl !== composeReport.baseUrl) return `${label} live report baseUrl ${report.baseUrl || "<missing>"} did not match Compose baseUrl ${composeReport.baseUrl || "<missing>"}`;
  if (!report.channelId) return `${label} live report missing Slack channel id`;
  if (!report.slackTeamId) return `${label} live report missing Slack team id`;
  if (!report.botUserId || !report.testUserId) return `${label} live report missing Slack bot/test-user identity`;
  if (!report.result?.channelId) return `${label} live report missing result Slack channel id`;
  if (!report.result?.slackTeamId) return `${label} live report missing result Slack team id`;
  if (!report.result?.botUserId) return `${label} live report missing result Slack bot user id`;
  if (report.result.botUserId !== report.botUserId) {
    return `${label} live report result botUserId ${report.result.botUserId} did not match top-level botUserId ${report.botUserId || "<missing>"}`;
  }
  const targetMismatch = mismatchedLiveReportField(report, label);
  if (targetMismatch) return targetMismatch;
  if (report.options?.requireOperantRecords !== true) return `${label} live report did not require Operant records`;
  if (report.options?.requireDm !== true) return `${label} live report did not require DM probe`;
  if (report.options?.requireDeniedUser !== true) return `${label} live report did not require denied-user probe`;
  if (report.options?.requireSlackApproval !== true) return `${label} live report did not require Slack approval UI`;
  if (report.options?.requireSlackApprovalCompletion !== true) return `${label} live report did not require Slack approval completion`;
  if (report.options?.skipOpenClawChecks === true) return `${label} live report skipped OpenClaw checks`;
  if (report.options?.skipObservationSync === true) return `${label} live report skipped OpenClaw observation sync`;
  if (report.options?.skipApprovalProbe === true) return `${label} live report skipped Operant approval probe`;
  if (report.options?.skipSlackApprovalProbe === true) return `${label} live report skipped Slack approval probe`;
  if (report.options?.skipSlackApprovalCompletion === true) return `${label} live report skipped Slack approval completion probe`;
  const missingChecks = missingRequiredOpenClawChecks(report);
  if (missingChecks.length > 0) return `${label} live report missing OpenClaw checks: ${missingChecks.join(", ")}`;
  const missingCompletedChecks = missingCompletedOpenClawChecks(report);
  if (missingCompletedChecks.length > 0) return `${label} live report missing completed OpenClaw check result(s): ${missingCompletedChecks.join(", ")}`;
  const missingCheckAssertions = missingOpenClawCheckAssertions(report);
  if (missingCheckAssertions.length > 0) return `${label} live report missing OpenClaw check assertion(s): ${missingCheckAssertions.join("; ")}`;
  if (!report.result?.parentTs) return `${label} live report missing Slack thread parent timestamp`;
  if (!report.result?.replyTs) return `${label} live report missing Slack thread reply timestamp`;
  if (!slackTimestampAfter(report.result.replyTs, report.result.parentTs)) {
    return `${label} live report Slack thread reply timestamp did not follow parent timestamp`;
  }
  for (const key of ["sessions", "jobs", "usage"]) {
    if (!(typeof report.result?.operantRecordDeltas?.[key] === "number" && report.result.operantRecordDeltas[key] > 0)) {
      return `${label} live report missing positive ${key} record delta`;
    }
  }
  if (descriptor?.required && !report.result?.approvalProbe?.id) return `${label} live report missing Operant approval probe id`;
  if (descriptor?.required) {
    const approvalProbe = report.result?.approvalProbe;
    if (!Array.isArray(approvalProbe?.policyNames) || approvalProbe.policyNames.length < 1) {
      return `${label} live report missing Operant approval policy evidence`;
    }
    if (!(typeof approvalProbe.after === "number" && approvalProbe.after >= 1)) {
      return `${label} live report missing persisted Operant approval count`;
    }
    if (typeof approvalProbe.before === "number" && approvalProbe.after <= approvalProbe.before) {
      return `${label} live report approval count did not increase`;
    }
  }
  if (descriptor?.required && !report.result?.slackApprovalProbe?.approvalUiTs) return `${label} live report missing Slack approval UI timestamp`;
  if (descriptor?.required && !report.result?.slackApprovalProbe?.approvalCompletionTs) return `${label} live report missing Slack approval completion timestamp`;
  if (descriptor?.required && !report.result?.slackApprovalProbe?.parentTs) return `${label} live report missing Slack approval parent timestamp`;
  if (descriptor?.required && !slackTimestampAfter(report.result.slackApprovalProbe.approvalUiTs, report.result.slackApprovalProbe.parentTs)) {
    return `${label} live report Slack approval UI timestamp did not follow approval parent timestamp`;
  }
  if (descriptor?.required && !slackTimestampAfter(report.result.slackApprovalProbe.approvalCompletionTs, report.result.slackApprovalProbe.approvalUiTs)) {
    return `${label} live report Slack approval completion timestamp did not follow approval UI timestamp`;
  }
  if (descriptor?.required && !report.result?.dmReplyTs) return `${label} live report missing DM reply timestamp`;
  if (descriptor?.required && !report.result?.dmProbe?.channelId) return `${label} live report missing DM probe channel id`;
  if (descriptor?.required && report.result.dmProbe.channelId !== report.dmChannelId) {
    return `${label} live report DM probe channel ${report.result.dmProbe.channelId} did not match top-level dmChannelId ${report.dmChannelId || "<missing>"}`;
  }
  if (descriptor?.required && !report.result?.dmProbe?.parentTs) return `${label} live report missing DM parent timestamp`;
  if (descriptor?.required && !report.result?.dmProbe?.replyTs) return `${label} live report missing DM probe reply timestamp`;
  if (descriptor?.required && report.result.dmProbe.replyTs !== report.result.dmReplyTs) {
    return `${label} live report DM reply timestamp did not match DM probe reply timestamp`;
  }
  if (descriptor?.required && !slackTimestampAfter(report.result.dmProbe.replyTs, report.result.dmProbe.parentTs)) {
    return `${label} live report DM reply timestamp did not follow DM parent timestamp`;
  }
  if (descriptor?.required && !report.result?.deniedProbe?.parentTs) return `${label} live report missing denied-user probe timestamp`;
  if (descriptor?.required && !(typeof report.result.deniedProbe.noReplyObservedMs === "number" && report.result.deniedProbe.noReplyObservedMs > 0)) {
    return `${label} live report missing denied-user no-reply observation duration`;
  }
  if (descriptor?.required && !report.result?.channelMembership?.channelId) return `${label} live report missing target-channel membership evidence`;
  if (descriptor?.required && report.result.channelMembership.channelId !== report.channelId) {
    return `${label} live report target-channel membership ${report.result.channelMembership.channelId} did not match top-level channelId ${report.channelId || "<missing>"}`;
  }
  if (descriptor?.required && report.result.channelMembership.method !== "conversations.members") {
    return `${label} live report target-channel membership was not checked with conversations.members`;
  }
  if (descriptor?.required) {
    const memberIds = new Set(Array.isArray(report.result.channelMembership.requiredUserIds) ? report.result.channelMembership.requiredUserIds : []);
    if (!memberIds.has(report.testUserId)) return `${label} live report target-channel membership missing allowed test user`;
    const deniedMode = report.result.deniedProbe.mode || "distinct-user";
    if (!["distinct-user", "same-user-temporary-deny"].includes(deniedMode)) {
      return `${label} live report denied-user probe mode ${deniedMode} was not recognized`;
    }
    if (deniedMode === "same-user-temporary-deny") {
      if (report.result.deniedProbe.userId !== report.testUserId) {
        return `${label} live report same-user denied probe did not use the allowed test user`;
      }
    } else if (!memberIds.has(report.result.deniedProbe.userId)) {
      return `${label} live report target-channel membership missing denied test user`;
    }
  }
  return null;
}

async function checkStrictLiveReports(report, evidence) {
  const descriptors = [
    [report.liveReports?.preRestart, "pre-restart"],
    [report.liveReports?.postRestart, "post-restart"],
  ];
  const missingDescriptors = descriptors.filter(([descriptor]) => !descriptor?.path).map(([, label]) => label);
  if (missingDescriptors.length > 0) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; missing live report descriptor(s): ${missingDescriptors.join(", ")}`, "fail");
    return false;
  }
  const expectedSteps = new Map([
    ["pre-restart", "Live Slack/OpenClaw E2E"],
    ["post-restart", "Post-restart live Slack/OpenClaw E2E"],
  ]);
  const descriptorFailures = [];
  for (const [descriptor, label] of descriptors) {
    const pathFailure = liveReportDescriptorPathFailure(descriptor, label);
    if (pathFailure) descriptorFailures.push(pathFailure);
    if (descriptor.step !== expectedSteps.get(label)) {
      descriptorFailures.push(`${label} live report descriptor step ${descriptor.step || "<missing>"} did not match ${expectedSteps.get(label)}`);
    }
  }
  const preDescriptor = report.liveReports.preRestart;
  const postDescriptor = report.liveReports.postRestart;
  if (preDescriptor.path === postDescriptor.path) descriptorFailures.push("pre-restart and post-restart live report paths must be distinct");
  if (preDescriptor.sha256 && postDescriptor.sha256 && preDescriptor.sha256 === postDescriptor.sha256) {
    descriptorFailures.push("pre-restart and post-restart live report sha256 values must be distinct");
  }
  const preGeneratedAtMs = Date.parse(preDescriptor.generatedAt || "");
  const postGeneratedAtMs = Date.parse(postDescriptor.generatedAt || "");
  if (!Number.isFinite(preGeneratedAtMs) || !Number.isFinite(postGeneratedAtMs) || postGeneratedAtMs <= preGeneratedAtMs) {
    descriptorFailures.push("post-restart live report must be generated after pre-restart live report");
  }
  const preLiveIndex = passedStepIndex(report, "Live Slack/OpenClaw E2E");
  const restartIndex = passedStepIndex(report, "Compose restart");
  const postLiveIndex = passedStepIndex(report, "Post-restart live Slack/OpenClaw E2E");
  if (preLiveIndex === -1 || restartIndex === -1 || postLiveIndex === -1 || !(preLiveIndex < restartIndex && restartIndex < postLiveIndex)) {
    descriptorFailures.push("strict report steps must show live E2E before restart and post-restart live E2E after restart");
  }
  const restartStep = passedStep(report, "Compose restart");
  const restartRecordedAtMs = stepRecordedAtMs(restartStep);
  if (!Number.isFinite(restartRecordedAtMs)) {
    descriptorFailures.push("Compose restart step missing valid recordedAt timestamp");
  } else {
    if (preGeneratedAtMs >= restartRecordedAtMs) {
      descriptorFailures.push("pre-restart live report must be generated before Compose restart");
    }
    if (postGeneratedAtMs <= restartRecordedAtMs) {
      descriptorFailures.push("post-restart live report must be generated after Compose restart");
    }
  }
  if (descriptorFailures.length > 0) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; ${descriptorFailures.join("; ")}`, "fail");
    return false;
  }
  const liveFailures = [];
  for (const [descriptor, label] of descriptors) {
    const failure = await checkLiveE2EReport(descriptor, label, report);
    if (failure) liveFailures.push(failure);
  }
  if (liveFailures.length > 0) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; ${liveFailures.join("; ")}`, "fail");
    return false;
  }
  return true;
}

async function checkComposeE2EReport() {
  if (!requireStrictLive) {
    await checkOptionalComposeE2EReport();
    return;
  }

  let report;
  try {
    report = JSON.parse(await readFile(composeE2EReportPath, "utf8"));
  } catch (error) {
    addCheck(
      "blocked-live",
      "Strict Compose E2E evidence report",
      false,
      `${path.relative(repoRoot, composeE2EReportPath)} missing or unreadable (${error.message}); run pnpm compose:e2e`,
      "blocked",
    );
    return;
  }

  const evidence = `${path.relative(repoRoot, composeE2EReportPath)} generated ${report.generatedAt || "unknown time"}`;
  const reportGeneratedAtMs = Date.parse(report.generatedAt || "");
  if (!Number.isFinite(reportGeneratedAtMs)) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; invalid generatedAt`, "fail");
    return;
  }
  const changedInputs = await changedComposeEvidenceInputs(report, reportGeneratedAtMs);
  if (changedInputs.length > 0) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; stale after changes to ${changedInputs.join(", ")}`, "blocked");
    return;
  }
  if (report.format !== "operant.compose-e2e-report.v1") {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; invalid format`, "fail");
    return;
  }
  if (report.strictFinalGate !== true) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; report was not produced by the strict final gate`, "fail");
    return;
  }
  if (Number(report.totals?.failed || 0) > 0) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; ${report.totals.failed} failed step(s)`, "fail");
    return;
  }
  if (Number(report.totals?.blocked || 0) > 0) {
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; ${report.totals.blocked} blocked step(s)`, "blocked");
    return;
  }
  if (report.passed !== true && !(allowPreCompletionAuditReport && report.readyForCompletionAudit === true)) {
    const missing = Array.isArray(report.missingRequiredSteps) ? report.missingRequiredSteps.join(", ") : "unknown";
    const detail = report.readyForCompletionAudit === true
      ? "strict gate reached pre-completion-audit point but final completion audit pass is not recorded"
      : `missing required steps: ${missing}`;
    addCheck("blocked-live", "Strict Compose E2E evidence report", false, `${evidence}; ${detail}`, report.readyForCompletionAudit === true ? "fail" : "blocked");
    return;
  }
  if (!(await checkStrictLiveReports(report, evidence))) return;
  addCheck("blocked-live", "Strict Compose E2E evidence report", true, `${evidence}; strict live/restart gate reached`);
}

async function checkOptionalComposeE2EReport() {
  let report;
  try {
    report = JSON.parse(await readFile(composeE2EReportPath, "utf8"));
  } catch (error) {
    addCheck(
      "live-advisory",
      "Strict Compose E2E evidence report",
      true,
      `${path.relative(repoRoot, composeE2EReportPath)} missing or unreadable (${error.message}); optional customer-run live proof, not a default completion blocker; run OPERANT_REQUIRE_STRICT_LIVE=1 pnpm audit:completion to enforce it`,
    );
    return;
  }

  const evidence = `${path.relative(repoRoot, composeE2EReportPath)} generated ${report.generatedAt || "unknown time"}`;
  const reportGeneratedAtMs = Date.parse(report.generatedAt || "");
  const problems = [];
  if (!Number.isFinite(reportGeneratedAtMs)) {
    problems.push("invalid generatedAt");
  } else {
    const changedInputs = await changedComposeEvidenceInputs(report, reportGeneratedAtMs);
    if (changedInputs.length > 0) problems.push(`stale after changes to ${changedInputs.join(", ")}`);
  }
  if (report.format !== "operant.compose-e2e-report.v1") problems.push("invalid format");
  if (report.strictFinalGate !== true) problems.push("not produced by strict final gate");
  if (Number(report.totals?.failed || 0) > 0) problems.push(`${report.totals.failed} failed step(s)`);
  if (Number(report.totals?.blocked || 0) > 0) problems.push(`${report.totals.blocked} blocked step(s)`);

  let summary;
  if (problems.length > 0) summary = problems.join("; ");
  else if (report.passed === true) summary = "last strict report passed";
  else if (report.readyForCompletionAudit === true) summary = "last strict report reached pre-completion-audit point";
  else summary = "last strict report present";

  addCheck(
    "live-advisory",
    "Strict Compose E2E evidence report",
    true,
    `${evidence}; optional customer-run live proof, not a default completion blocker; ${summary}; set OPERANT_REQUIRE_STRICT_LIVE=1 to enforce strict live evidence`,
  );
}

async function checkNonLiveComposeSmokeReport(reportPath, requirement, expectedComposeFiles) {
  let report;
  try {
    report = JSON.parse(await readFile(reportPath, "utf8"));
  } catch (error) {
    addCheck("tests", requirement, false, `${path.relative(repoRoot, reportPath)} missing or unreadable (${error.message}); run pnpm acceptance:local -- --include-sandbox`);
    return;
  }

  const evidence = `${path.relative(repoRoot, reportPath)} generated ${report.generatedAt || "unknown time"}`;
  const reportGeneratedAtMs = Date.parse(report.generatedAt || "");
  if (!Number.isFinite(reportGeneratedAtMs)) {
    addCheck("tests", requirement, false, `${evidence}; invalid generatedAt`);
    return;
  }
  const changedInputs = await changedComposeEvidenceInputs(report, reportGeneratedAtMs);
  if (changedInputs.length > 0) {
    addCheck("tests", requirement, false, `${evidence}; stale after changes to ${changedInputs.join(", ")}`);
    return;
  }
  if (report.format !== "operant.compose-e2e-report.v1") {
    addCheck("tests", requirement, false, `${evidence}; invalid format`);
    return;
  }
  if (report.mode !== "non-live-smoke" || report.strictFinalGate !== false) {
    addCheck("tests", requirement, false, `${evidence}; report is not non-live smoke evidence`);
    return;
  }
  if (report.runtimePassed !== true || report.smokePassed !== true) {
    addCheck("tests", requirement, false, `${evidence}; smoke did not pass`);
    return;
  }
  if (Number(report.totals?.failed || 0) > 0 || Number(report.totals?.blocked || 0) > 0) {
    addCheck("tests", requirement, false, `${evidence}; ${report.totals?.failed || 0} failed and ${report.totals?.blocked || 0} blocked step(s)`);
    return;
  }
  const composeFiles = Array.isArray(report.options?.composeFiles) ? report.options.composeFiles : [];
  const missingComposeFiles = expectedComposeFiles.filter((file) => !composeFiles.includes(file));
  if (missingComposeFiles.length > 0) {
    addCheck("tests", requirement, false, `${evidence}; missing Compose file evidence: ${missingComposeFiles.join(", ")}`);
    return;
  }

  const configStep = passedStep(report, "credential/config verification");
  const statusStep = passedStep(report, "OpenClaw status");
  const primaryModel = configStep?.evidence?.primaryModel;
  const modelProvider = configStep?.evidence?.modelProvider;
  const modelName = configStep?.evidence?.modelName;
  const expectedPrimaryModel = modelProvider && modelName ? `${modelProvider}/${modelName}` : "";
  if (!primaryModel || primaryModel !== expectedPrimaryModel) {
    addCheck("tests", requirement, false, `${evidence}; missing generated primary model evidence`);
    return;
  }
  if (!statusStep?.evidence?.gatewayReachable || statusStep.evidence.securityCritical !== 0) {
    addCheck("tests", requirement, false, `${evidence}; missing reachable zero-critical OpenClaw status evidence`);
    return;
  }
  if (!statusStep.evidence.sessionDefaultModel || statusStep.evidence.sessionDefaultModel !== statusStep.evidence.expectedModel) {
    addCheck("tests", requirement, false, `${evidence}; missing matching session default model evidence`);
    return;
  }
  const integrationStep = passedStep(report, "integration credential seed");
  if (!integrationStep || !/saved and resolved/i.test(integrationStep.detail || "")) {
    addCheck("tests", requirement, false, `${evidence}; missing integration credential seed/resolver evidence`);
    return;
  }
  addCheck(
    "tests",
    requirement,
    true,
    `${evidence}; primary ${primaryModel}; session default ${statusStep.evidence.sessionDefaultModel}; integration ${integrationStep.detail}`,
  );
}

async function main() {
  await loadComposeReportEnv();
  await patternCheck("oss", "permissive open-source license", "LICENSE", [
    ["MIT license title", /^MIT License/m],
    ["permission grant", /Permission is hereby granted, free of charge/],
    ["include copyright notice condition", /The above copyright notice and this permission notice shall be included/],
    ["as-is warranty disclaimer", /THE SOFTWARE IS PROVIDED "AS IS"/],
  ]);
  await patternCheck("oss", "MIT package metadata", "package.json", [
    ["root package license", /"license":\s*"MIT"/],
  ]);
  await patternCheck("oss", "control-plane MIT package metadata", "apps/control-plane/package.json", [
    ["control-plane package license", /"license":\s*"MIT"/],
  ]);
  await patternCheck("oss", "self-hostable positioning and quick start", "README.md", [
    ["self-hostable", /self-host/i],
    ["Docker Compose quick start", /pnpm compose:up -- -d/],
  ]);
  await patternCheck("oss", "env-driven live bot and verifier documentation", "docs/setup.md", [
    ["env-driven live bot command", /pnpm compose:live -- --env \.env\.acme --live-env \.env\.acme\.live/],
  ]);
  await patternCheck("oss", "verifier vs persistent bot distinction", "docs/acceptance.md", [
    ["persistent Slack bot vs verifier prompt", /finite probes[\s\S]*exit after success[\s\S]*will not produce a bot response/],
    ["live E2E command", /pnpm live:e2e/],
  ]);
  await patternCheck("oss", "permissive OSS core feature boundary", "README.md", [
    ["MIT core", /License: MIT|MIT\.|MIT-licensed/],
    ["BYOK Slack and model config", /BYOK credentials/],
    ["integration credential storage", /AES-256-GCM[\s\S]*Postgres/],
    ["RBAC policy approvals audit usage", /RBAC,\s*policy,\s*approvals,\s*audit,\s*retention,\s*usage tracking/],
    ["Docker Compose OpenClaw wrapper", /Docker Compose/],
  ]);
  const composeFailures = await verifyComposeFile(path.join(repoRoot, "docker-compose.yml"));
  addCheck("compose", "Docker Compose topology", composeFailures.length === 0, composeFailures.length ? composeFailures.join(", ") : "docker-compose.yml and docker-compose.sandbox.yml static topology passed");
  await patternCheck("compose", "environment template", ".env.example", [
    ["OPERANT_COMPOSE_PROJECT_NAME", /OPERANT_COMPOSE_PROJECT_NAME=operant/],
    ["POSTGRES_PASSWORD", /POSTGRES_PASSWORD=change-me-postgres-password/],
    ["DATABASE_URL", /DATABASE_URL=postgres:\/\/operant:change-me-postgres-password@postgres:5432\/operant/],
    ["COMPOSE_PROFILES optional queue", /COMPOSE_PROFILES=$/m],
    ["REDIS_URL", /REDIS_URL=redis:\/\/redis:6379\/0/],
    ["OPERANT_HTTP_BIND", /OPERANT_HTTP_BIND=127\.0\.0\.1/],
    ["OPERANT_HTTP_PORT", /OPERANT_HTTP_PORT=8080/],
    ["POSTGRES_HOST_BIND", /POSTGRES_HOST_BIND=127\.0\.0\.1/],
    ["POSTGRES_HOST_PORT", /POSTGRES_HOST_PORT=5432/],
    ["OPENCLAW_GATEWAY_HOST_BIND", /OPENCLAW_GATEWAY_HOST_BIND=127\.0\.0\.1/],
    ["OPENCLAW_GATEWAY_HOST_PORT", /OPENCLAW_GATEWAY_HOST_PORT=18789/],
    ["OPERANT_SECRET_KEY", /OPERANT_SECRET_KEY=/],
    ["OPERANT_INTERNAL_TOKEN", /OPERANT_INTERNAL_TOKEN=/],
    ["OPERANT_ADMIN_LOGIN_TOKEN", /OPERANT_ADMIN_LOGIN_TOKEN=change-me-admin-login-token/],
    ["OPENCLAW_GATEWAY_TOKEN", /OPENCLAW_GATEWAY_TOKEN=/],
    ["OPENCLAW_DOCKER_SOCKET", /OPENCLAW_DOCKER_SOCKET=\/var\/run\/docker\.sock/],
    ["OPENCLAW_DOCKER_GID", /OPENCLAW_DOCKER_GID=991/],
  ]);
  await patternCheck("compose", "Docker sandbox overlay documentation", "docs/setup.md", [
    ["base Compose excludes Docker socket", /Base Compose intentionally does not mount the host Docker socket/],
    ["sandbox overlay command", /--file docker-compose\.sandbox\.yml/],
    ["dedicated host warning", /dedicated\s+single-trust-boundary Docker host/],
  ]);
  await patternCheck("compose", "environment initializer", "scripts/operant-init-env.mjs", [
    ["project-name argument", /--project-name/],
    ["project-name env fallback", /OPERANT_COMPOSE_PROJECT_NAME/],
    ["project-name validation", /validateComposeProjectName/],
    ["Postgres password generation", /postgresPassword = randomToken\("operant_pg"\)/],
    ["Postgres DATABASE_URL generation", /DATABASE_URL", `postgres:\/\/operant:\$\{postgresPassword\}@postgres:5432\/operant`/],
    ["admin login token generation", /OPERANT_ADMIN_LOGIN_TOKEN", randomToken\("operant_admin"\)/],
    ["private env write mode", /writePrivateEnvFile[\s\S]*chmod\(file,\s*0o600\)/],
    ["argument validation self-test", /--self-test-arg-validation[\s\S]*init env argument validation self-test passed/],
    ["permission self-test", /--self-test-permissions[\s\S]*expected 600 permissions/],
    ["http-bind argument", /--http-bind/],
    ["http-port argument", /--http-port/],
    ["postgres-bind argument", /--postgres-bind/],
    ["postgres-port argument", /--postgres-port/],
    ["gateway-bind argument", /--gateway-bind/],
    ["gateway-port argument", /--gateway-port/],
    ["bind validation", /validateBindAddress/],
    ["port validation", /validatePort/],
    ["distinct port validation", /validateDistinctPorts/],
  ]);
  await patternCheck("compose", "Compose wrapper profile forwarding", "scripts/operant-compose.mjs", [
    ["profile argument parser", /takeRepeatedArg\("--profile"\)/],
    ["compose file parser", /takeRepeatedArgs\(\["--file", "-f", "--compose-file"\]\)/],
    ["base file before overlays", /"docker-compose\.yml", \.\.\.overlayFiles/],
    ["profile args before compose command", /\["compose", \.\.\.fileArgs, "--env-file", envPath, \.\.\.profileArgs, \.\.\.composeArgs\]/],
    ["console output redaction", /redactConsole[\s\S]*writeStdout[\s\S]*writeStderr/],
    ["env-file redaction source", /envFileForRedaction[\s\S]*sensitiveEnvValues\(\[process\.env, await envFileForRedaction\(envPath\)\]\)/],
    ["captured docker compose output", /stdio:\s*\["inherit",\s*"pipe",\s*"pipe"\]/],
    ["redaction self-test", /--self-test-redaction[\s\S]*compose wrapper redaction self-test passed/],
  ]);
  await patternCheck("compose", "Docker build context hygiene", ".dockerignore", [
    ["root env file excluded", /^\.env$/m],
    ["generated env files excluded", /^\.env\.\*$/m],
    ["env example retained", /^!\.env\.example$/m],
    ["generated evidence excluded", /^\.operant$/m],
    ["root node_modules excluded", /^node_modules$/m],
    ["nested node_modules excluded", /^\*\*\/node_modules$/m],
    ["workspace dist directories excluded", /^apps\/(?:control-plane|\*)\/dist$/m],
  ]);
  await patternCheck("compose", "Git private artifact hygiene", ".gitignore", [
    ["root env file ignored", /^\.env$/m],
    ["private env overlays ignored", /^\.env\.\*$/m],
    ["env example retained", /^!\.env\.example$/m],
    ["generated acceptance artifacts ignored", /^\.operant\/$/m],
    ["dependency directory ignored", /^node_modules\/$/m],
  ]);
  await patternCheck("compose", "optional Docker sandbox overlay", "docker-compose.sandbox.yml", [
    ["single trust-boundary warning", /dedicated single-trust-boundary Docker host/],
    ["local sandbox image tag", /image:\s*operant-openclaw-sandbox:\$\{OPENCLAW_VERSION:-[^}]+\}/],
    ["sandbox Dockerfile build", /dockerfile:\s*deploy\/openclaw\/Dockerfile\.sandbox/],
    ["Docker CLI version build arg", /DOCKER_CLI_VERSION:\s*\$\{DOCKER_CLI_VERSION:-[^}]+\}/],
    ["socket group access", /group_add:[\s\S]*\$\{OPENCLAW_DOCKER_GID:-991\}/],
    ["gateway service override", /openclaw-gateway:/],
    ["Docker host env", /DOCKER_HOST:\s*unix:\/\/\/var\/run\/docker\.sock/],
    ["socket mount override", /\$\{OPENCLAW_DOCKER_SOCKET:-\/var\/run\/docker\.sock\}:\/var\/run\/docker\.sock/],
    ["runtime sandbox image inspect", /docker image inspect openclaw-sandbox:bookworm-slim/],
    ["runtime sandbox image build", /docker build -t openclaw-sandbox:bookworm-slim -f \/usr\/local\/share\/operant\/openclaw\/Dockerfile\.sandbox-runtime \/usr\/local\/share\/operant\/openclaw/],
    ["state dir private permissions", /chmod 700 \/home\/node\/\.openclaw/],
    ["Slack plugin bootstrap", /operant-ensure-slack-plugin/],
  ]);
  await patternCheck("compose", "OpenClaw gateway image", "deploy/openclaw/Dockerfile.gateway", [
    ["OpenClaw base image", /FROM ghcr\.io\/openclaw\/openclaw:\$\{OPENCLAW_VERSION\}/],
    ["Slack plugin package dir", /mkdir -p \/usr\/local\/share\/operant\/openclaw\/plugins/],
    ["Slack plugin bootstrap copy", /COPY deploy\/openclaw\/ensure-slack-plugin\.sh \/usr\/local\/bin\/operant-ensure-slack-plugin/],
    ["Slack plugin packed into image", /npm pack --pack-destination \/usr\/local\/share\/operant\/openclaw\/plugins @openclaw\/slack@\$\{OPENCLAW_VERSION\}/],
    ["Operant plugin build stage", /FROM node:24-alpine AS plugin-build/],
    ["Operant plugin pack step", /cd apps\/openclaw-plugin && npm pack --pack-destination \/build\/packed/],
    ["Operant plugin copied into image", /COPY --from=plugin-build[\s\S]*\/build\/packed\/\*\.tgz \/usr\/local\/share\/operant\/openclaw\/plugins\//],
    ["node user default", /^USER node$/m],
  ]);
  await patternCheck("compose", "OpenClaw Slack plugin bootstrap", "deploy/openclaw/ensure-slack-plugin.sh", [
    ["plugin detection", /has_plugin/],
    ["local package install", /openclaw plugins install \$package_pattern/],
    ["local Slack package target", /ensure_plugin "slack" "\/usr\/local\/share\/operant\/openclaw\/plugins\/openclaw-slack-\*\.tgz"/],
    ["local Operant package target", /ensure_plugin "operant" "\/usr\/local\/share\/operant\/openclaw\/plugins\/operant-openclaw-plugin-\*\.tgz"/],
    ["test harness prune", /test-harness/],
    ["failure is surfaced", /OpenClaw Slack plugin is not installed/],
    ["Operant failure is surfaced", /Operant plugin is not installed/],
  ]);
  await patternCheck("compose", "Docker sandbox gateway image", "deploy/openclaw/Dockerfile.sandbox", [
    ["OpenClaw base image", /FROM ghcr\.io\/openclaw\/openclaw:\$\{OPENCLAW_VERSION\}/],
    ["Docker CLI version pin", /ARG DOCKER_CLI_VERSION=29\.4\.3/],
    ["Docker CLI static download", /download\.docker\.com\/linux\/static\/stable\/\$\{docker_arch\}\/docker-\$\{DOCKER_CLI_VERSION\}\.tgz/],
    ["Docker CLI binary install", /install -m 0755 \/tmp\/docker\/docker \/usr\/local\/bin\/docker/],
    ["runtime sandbox Dockerfile copy", /COPY deploy\/openclaw\/Dockerfile\.sandbox-runtime \/usr\/local\/share\/operant\/openclaw\/Dockerfile\.sandbox-runtime/],
    ["Slack plugin bootstrap copy", /COPY deploy\/openclaw\/ensure-slack-plugin\.sh \/usr\/local\/bin\/operant-ensure-slack-plugin/],
    ["Slack plugin packed into image", /npm pack --pack-destination \/usr\/local\/share\/operant\/openclaw\/plugins @openclaw\/slack@\$\{OPENCLAW_VERSION\}/],
    ["apt cache cleanup", /rm -rf[\s\S]*\/var\/lib\/apt\/lists\/\*/],
    ["node user default", /^USER node$/m],
  ]);
  await patternCheck("compose", "OpenClaw runtime sandbox image", "deploy/openclaw/Dockerfile.sandbox-runtime", [
    ["Debian slim base", /FROM debian:bookworm-slim/],
    ["documented runtime tools", /apt-get install -y --no-install-recommends[\s\S]*bash[\s\S]*ca-certificates[\s\S]*curl[\s\S]*git[\s\S]*jq[\s\S]*python3[\s\S]*ripgrep/],
    ["apt cache cleanup", /rm -rf \/var\/lib\/apt\/lists\/\*/],
    ["sandbox user", /useradd --create-home --shell \/bin\/bash sandbox/],
    ["sandbox user default", /^USER sandbox$/m],
    ["sandbox workdir", /^WORKDIR \/home\/sandbox$/m],
    ["idle command", /CMD \["sleep", "infinity"\]/],
  ]);
  await patternCheck("compose", "deterministic control-plane Docker image", "apps/control-plane/Dockerfile", [
    ["pnpm lockfile copied", /^COPY package\.json pnpm-workspace\.yaml pnpm-lock\.yaml \.\/$/m],
    ["frozen dependency install", /^RUN pnpm install --filter @operant\/control-plane --frozen-lockfile$/m],
    ["production dependency stage", /^FROM node:24-alpine AS prod-deps$/m],
    ["production frozen install", /^RUN pnpm install --filter @operant\/control-plane --prod --frozen-lockfile$/m],
    ["OpenClaw native build prerequisites", /apk add --no-cache libstdc\+\+[\s\S]*\.openclaw-build-deps python3 make g\+\+[\s\S]*npm install -g openclaw@\$\{OPENCLAW_VERSION\}[\s\S]*apk del \.openclaw-build-deps/],
    ["runner package manifest for ESM", /^COPY --from=build --chown=node:node \/app\/apps\/control-plane\/package\.json \/app\/apps\/control-plane\/package\.json$/m],
    ["OpenClaw volume paths owned by node and private", /^RUN mkdir -p \/operant\/openclaw \/home\/node\/\.openclaw \/home\/node\/\.openclaw-client\/agents\/main\/sessions \/home\/node\/\.openclaw-gateway-state \\\n  && chown -R node:node \/app \/operant \/home\/node\/\.openclaw \/home\/node\/\.openclaw-client \/home\/node\/\.openclaw-gateway-state \\\n  && chmod 700 \/home\/node\/\.openclaw \/home\/node\/\.openclaw-client \/home\/node\/\.openclaw-gateway-state$/m],
    ["runtime files copied as node", /^COPY --from=build --chown=node:node \/app\/apps\/control-plane\/dist \/app\/apps\/control-plane\/dist$/m],
    ["non-root runner user", /^USER node$/m],
  ]);

  await patternCheck("control-plane", "admin dashboard surfaces", "apps/control-plane/public/index.html", [
    ["operator cockpit views", /data-view-target="setup-view"[\s\S]*data-view-target="openclaw-view"/],
    ["setup checklist", /id="setup-checklist"/],
    ["credential setup", /id="credentials-form"/],
    ["credential validation state", /id="credential-validation-state"/],
    ["custom roles", /id="role-form"/],
    ["policy editor", /id="policy-editor"/],
    ["structured policy editor", /id="policy-channel-form"[\s\S]*id="policy-tool-form"[\s\S]*id="policy-approval-rule-form"/],
    ["policy preview action/resource controls", /id="policy-form"[\s\S]*name="action"[\s\S]*name="resource"/],
    ["policy preview group chat type", /name="chatType"[\s\S]*value="group"/],
    ["confirmation modal", /id="confirm-modal"/],
    ["approval queue", /id="approvals-result"/],
    ["usage events", /id="usage-events"/],
    ["OpenClaw checks", /data-check="doctor"/],
    ["OpenClaw secrets reload", /data-check="secrets-reload"/],
    ["OpenClaw approval policy", /data-check="approvals-get"/],
    ["OpenClaw cron status", /data-check="cron-status"/],
    ["OpenClaw tasks list", /data-check="tasks-list"/],
    ["OpenClaw usage cost", /data-check="usage-cost"/],
    ["OpenClaw sync", /id="sync-openclaw"/],
    ["retention wipe scope", /id="wipe-scope"/],
  ]);
  await patternCheck("control-plane", "admin dashboard responsive layout", "apps/control-plane/public/styles.css", [
    ["cockpit shell grid", /\.app-shell[\s\S]*grid-template-columns:\s*220px minmax\(0,\s*1fr\)/],
    ["tablet nav becomes horizontal", /@media\s*\(max-width:\s*900px\)[\s\S]*\.app-shell[\s\S]*grid-template-columns:\s*1fr[\s\S]*\.sidebar[\s\S]*position:\s*static/],
    ["mobile topbar stacks", /@media\s*\(max-width:\s*640px\)[\s\S]*\.topbar[\s\S]*flex-direction:\s*column/],
    ["mobile metrics single column", /@media\s*\(max-width:\s*640px\)[\s\S]*\.metrics[\s\S]*grid-template-columns:\s*1fr/],
    ["action controls have stable width", /\.actions > button,[\s\S]*\.actions > select[\s\S]*flex:\s*1 1 160px/],
    ["panels can shrink", /\.panel[\s\S]*min-width:\s*0/],
  ]);
  await dashboardApiWiringCheck();
  await patternCheck("control-plane", "API routes", "apps/control-plane/src/server.ts", [
    ["credentials route", /\/api\/config\/credentials/],
    ["policy route", /\/api\/policy/],
    ["approval route", /\/api\/approvals/],
    ["OpenClaw checks", /\/api\/openclaw\/checks/],
    ["OpenClaw sync", /\/api\/openclaw\/observations\/sync/],
    ["internal secrets", /\/internal\/openclaw\/secrets/],
    ["internal events", /\/internal\/openclaw\/events/],
    ["member-scoped sessions", /scopedListQuery[\s\S]*table === "sessions"[\s\S]*slack_user_id = \$2/],
    ["member-scoped jobs", /scopedListQuery[\s\S]*table === "jobs"[\s\S]*JOIN sessions/],
    ["member-scoped approvals", /scopedListQuery[\s\S]*approverSlackUserIds/],
  ]);
  await adminListProjectionCheck();
  await serverSqlProjectionCheck();
  await patternCheck("security", "admin login bootstrap secret", "apps/control-plane/src/server.ts", [
    ["admin login token env", /OPERANT_ADMIN_LOGIN_TOKEN/],
    ["admin token constant-time compare", /adminLoginTokenValidation[\s\S]*timingSafeEqualString/],
    ["bootstrap requires admin token", /handleBootstrap[\s\S]*adminLoginTokenValidation/],
    ["auth login requires admin token", /handleAuthLogin[\s\S]*adminLoginTokenValidation/],
    ["header auth Slack ID validation", /function actorSlackUserId[\s\S]*slackIdSchema\.safeParse/],
    ["first credential setup requires admin token", /handleCredentials[\s\S]*credentials\.bootstrap_denied/],
    ["first credential setup requires owner", /handleCredentials[\s\S]*owner_slack_user_id[\s\S]*adminSlackUserId[\s\S]*workspace owner/],
  ]);
  await patternCheck("security", "workspace bootstrap transactional seed", "apps/control-plane/src/server.ts", [
    ["bootstrap transaction begin", /handleBootstrap[\s\S]*await client\.query\("BEGIN"\)/],
    ["bootstrap seed in transaction", /handleBootstrap[\s\S]*ensureDefaultWorkspace\(client\)/],
    ["bootstrap audit in transaction", /handleBootstrap[\s\S]*eventType: "bootstrap\.completed"[\s\S]*await client\.query\("COMMIT"\)/],
    ["bootstrap transaction rollback", /handleBootstrap[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
    ["workspace lookup explicit columns", /SELECT w\.id, w\.company_id, w\.name, w\.slack_team_id, w\.openclaw_gateway_url, w\.openclaw_config_path, w\.created_at, c\.name AS company_name/],
  ]);
  await patternCheck("security", "admin session transactional lifecycle", "apps/control-plane/src/server.ts", [
    ["login transaction begin", /handleAuthLogin[\s\S]*await client\.query\("BEGIN"\)/],
    ["login session insert in transaction", /handleAuthLogin[\s\S]*client\.query\([\s\S]*INSERT INTO admin_sessions/],
    ["login audit in transaction", /handleAuthLogin[\s\S]*eventType: "auth\.login"[\s\S]*await client\.query\("COMMIT"\)/],
    ["login transaction rollback", /handleAuthLogin[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
    ["logout transaction begin", /handleAuthLogout[\s\S]*await client\.query\("BEGIN"\)/],
    ["logout revoke in transaction", /handleAuthLogout[\s\S]*UPDATE admin_sessions SET revoked_at/],
    ["logout audit in transaction", /handleAuthLogout[\s\S]*eventType: "auth\.logout"[\s\S]*await client\.query\("COMMIT"\)/],
    ["logout transaction rollback", /handleAuthLogout[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
  ]);
  await patternCheck("security", "credential setup transactional write boundary", "apps/control-plane/src/server.ts", [
    ["credential transaction begin", /handleCredentials[\s\S]*await client\.query\("BEGIN"\)/],
    ["encrypted credentials in transaction", /upsertCredential\(client[\s\S]*slack\/botToken[\s\S]*upsertCredential\(client[\s\S]*slack\/appToken[\s\S]*upsertCredential\(\s*client[\s\S]*models\/\$\{input\.modelProvider\}\/apiKey/],
    ["model provider parsed from constrained schema", /const input = credentialInputSchema\.parse\(rawBody\)/],
    ["credential setup retains admin Slack policy user", /const allowedDmUserIds = Array\.from\(new Set\(\[[\s\S]*input\.adminSlackUserId[\s\S]*input\.allowedDmUserIds[\s\S]*channel_id[\s\S]*allowedDmUserIds/],
    ["credential setup replaces seeded channel allowlists", /DELETE FROM channel_policies WHERE workspace_id = \$1 AND name = 'Credential setup allowlist'[\s\S]*Credential setup allowlist[\s\S]*COALESCE\(channel_policies\.name, EXCLUDED\.name\)/],
    ["credential setup retains admin approval approver", /const approvalSlackUserIds = Array\.from\(new Set\(\[[\s\S]*input\.adminSlackUserId[\s\S]*input\.approvalSlackUserIds/],
    ["owner assignment in transaction", /handleCredentials[\s\S]*INSERT INTO users[\s\S]*Workspace Owner[\s\S]*INSERT INTO role_assignments[\s\S]*r\.name = 'owner'/],
    ["config generated in transaction", /generateAndPersistOpenClawConfig\(client, workspace\.id\)/],
    ["credential audit in transaction", /eventType: "credentials\.updated"[\s\S]*await client\.query\("COMMIT"\)/],
    ["credential transaction rollback", /handleCredentials[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
  ]);
  await patternCheck("security", "admin mutation transactional write boundaries", "apps/control-plane/src/server.ts", [
    ["approval create transaction begin", /handleCreateApproval[\s\S]*await client\.query\("BEGIN"\)/],
    ["approval create action/resource validation", /handleCreateApproval[\s\S]*action: policyIdentifierSchema[\s\S]*resource: policyIdentifierSchema/],
    ["approval create audit in transaction", /handleCreateApproval[\s\S]*eventType: "approval\.requested"[\s\S]*await client\.query\("COMMIT"\)/],
    ["approval create transaction rollback", /handleCreateApproval[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
    ["approval duplicate decision denial", /existingDecision[\s\S]*duplicate_decision[\s\S]*Approval decision already recorded/],
    ["integration credential transaction begin", /handleUpsertIntegrationCredential[\s\S]*await client\.query\("BEGIN"\)/],
    ["integration credential write in transaction", /handleUpsertIntegrationCredential[\s\S]*upsertCredential\(client/],
    ["integration credential audit in transaction", /handleUpsertIntegrationCredential[\s\S]*eventType: "integration_credential\.upserted"[\s\S]*await client\.query\("COMMIT"\)/],
    ["integration credential transaction rollback", /handleUpsertIntegrationCredential[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
    ["manual config generation transaction begin", /handleGenerateConfig[\s\S]*await client\.query\("BEGIN"\)/],
    ["manual config generated in transaction", /handleGenerateConfig[\s\S]*generateAndPersistOpenClawConfig\(client, workspace\.id\)/],
    ["manual config audit in transaction", /handleGenerateConfig[\s\S]*eventType: "openclaw\.config\.generated"[\s\S]*await client\.query\("COMMIT"\)/],
    ["manual config transaction rollback", /handleGenerateConfig[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
    ["retention export transaction begin", /handleExport[\s\S]*await client\.query\("BEGIN"\)/],
    ["retention export builds snapshot in transaction", /handleExport[\s\S]*buildRetentionExport\(client, workspace\)/],
    ["retention export audit in transaction", /handleExport[\s\S]*eventType: "retention\.export_completed"[\s\S]*await client\.query\("COMMIT"\)/],
    ["retention export transaction rollback", /handleExport[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
  ]);
  await patternCheck("security", "internal OpenClaw event transactional ingest", "apps/control-plane/src/server.ts", [
    ["event type constrained before audit", /const openClawEventTypeSchema = z\.string\(\)\.min\(1\)\.max\(80\)\.regex\(\/\^\[a-z\]\[a-z0-9_\.\:-\]\*\$\/\)/],
    ["event ids are bounded", /const openClawEventIdSchema = z\.string\(\)\.min\(1\)\.max\(512\)/],
    ["event Slack ids are bounded", /const openClawSlackIdSchema = z\.string\(\)\.min\(1\)\.max\(120\)/],
    ["event usage labels are bounded", /const openClawUsageLabelSchema = z\.string\(\)\.min\(1\)\.max\(160\)/],
    ["event usage token counts are bounded", /inputTokens:\s*usageTokenCountSchema\.default\(0\)[\s\S]*outputTokens:\s*usageTokenCountSchema\.default\(0\)/],
    ["event usage cost is bounded", /estimatedCostUsd:\s*usageCostUsdSchema\.optional\(\)/],
    ["schema failures return client error", /error instanceof ZodError[\s\S]*sendJson\(res, 400,[\s\S]*error: "Invalid request"/],
    ["event ingest transaction begin", /handleOpenClawEvent[\s\S]*await client\.query\("BEGIN"\)/],
    ["event session write in transaction", /handleOpenClawEvent[\s\S]*client\.query\([\s\S]*INSERT INTO sessions/],
    ["event job write in transaction", /handleOpenClawEvent[\s\S]*client\.query\([\s\S]*INSERT INTO jobs/],
    ["event job idempotent upsert", /handleOpenClawEvent[\s\S]*ON CONFLICT \(workspace_id, openclaw_run_id\) WHERE openclaw_run_id IS NOT NULL[\s\S]*metadata = jobs\.metadata \|\| EXCLUDED\.metadata/],
    ["event usage write in transaction", /handleOpenClawEvent[\s\S]*client\.query\([\s\S]*INSERT INTO usage_events/],
    ["event audit in transaction", /handleOpenClawEvent[\s\S]*eventType: `openclaw\.\$\{body\.type\}`[\s\S]*await client\.query\("COMMIT"\)/],
    ["event transaction rollback", /handleOpenClawEvent[\s\S]*await client\.query\("ROLLBACK"\)\.catch/],
  ]);
  await patternCheck("security", "HTTP security response headers", "apps/control-plane/src/server.ts", [
    ["Content Security Policy", /content-security-policy/],
    ["frame ancestors denied", /frame-ancestors 'none'/],
    ["content sniffing disabled", /x-content-type-options/],
    ["clickjacking header", /x-frame-options/],
    ["referrer policy", /referrer-policy/],
    ["permissions policy", /permissions-policy/],
  ]);
  await patternCheck("security", "JSON request body failure handling", "apps/control-plane/src/server.ts", [
    ["json body byte limit", /const maxJsonBodyBytes = 1024 \* 1024/],
    ["body limit enforced during read", /received \+= buffer\.length[\s\S]*if \(received > maxJsonBodyBytes\) throw new JsonBodyTooLargeError\(\)/],
    ["malformed json mapped to client error", /catch \{[\s\S]*throw new InvalidJsonBodyError\(\)/],
    ["oversized json returns 413", /error instanceof JsonBodyTooLargeError[\s\S]*sendJson\(res, 413/],
    ["invalid json returns 400", /error instanceof InvalidJsonBodyError[\s\S]*sendJson\(res, 400/],
  ]);
  await patternCheck("security", "static asset path boundary", "apps/control-plane/src/server.ts", [
    ["path-relative boundary helper", /function isPathInsideDirectory[\s\S]*path\.relative\(directory, target\)/],
    ["sibling prefix rejection", /!relative\.startsWith\("\.\."\)/],
    ["absolute relative-path rejection", /!path\.isAbsolute\(relative\)/],
    ["static paths resolve under public root", /path\.resolve\(publicDir,\s*`\.\$\{safePath\}`\)/],
    ["static handler uses boundary helper", /!isPathInsideDirectory\(target, publicDir\)/],
  ]);
  await patternCheck("state", "Postgres enterprise state schema", "apps/control-plane/migrations/001_initial.sql", [
    ["companies", /CREATE TABLE IF NOT EXISTS companies/],
    ["workspaces", /CREATE TABLE IF NOT EXISTS workspaces/],
    ["users", /CREATE TABLE IF NOT EXISTS users/],
    ["roles", /CREATE TABLE IF NOT EXISTS roles/],
    ["permissions", /CREATE TABLE IF NOT EXISTS permissions/],
    ["role permissions", /CREATE TABLE IF NOT EXISTS role_permissions/],
    ["role assignments", /CREATE TABLE IF NOT EXISTS role_assignments/],
    ["admin sessions", /CREATE TABLE IF NOT EXISTS admin_sessions/],
    ["workspace settings", /CREATE TABLE IF NOT EXISTS workspace_settings/],
    ["policy rules", /CREATE TABLE IF NOT EXISTS policy_rules/],
    ["channel policies", /CREATE TABLE IF NOT EXISTS channel_policies/],
    ["tool policies", /CREATE TABLE IF NOT EXISTS tool_policies[\s\S]*slack_user_ids text\[\][\s\S]*role_names text\[\]/],
    ["approval policies", /CREATE TABLE IF NOT EXISTS approval_policies/],
    ["approvals", /CREATE TABLE IF NOT EXISTS approvals/],
    ["audit logs", /CREATE TABLE IF NOT EXISTS audit_logs/],
    ["usage", /CREATE TABLE IF NOT EXISTS usage_events/],
    ["sessions", /CREATE TABLE IF NOT EXISTS sessions/],
    ["jobs", /CREATE TABLE IF NOT EXISTS jobs/],
    ["integration credentials", /CREATE TABLE IF NOT EXISTS integration_credentials/],
    ["OpenClaw configs", /CREATE TABLE IF NOT EXISTS openclaw_configs/],
    ["retention exports", /CREATE TABLE IF NOT EXISTS retention_exports/],
    ["wipe requests", /CREATE TABLE IF NOT EXISTS wipe_requests/],
  ]);
  await migrationFilenameCheck();
  await patternCheck("state", "Postgres approval decision ledger schema", "apps/control-plane/migrations/004_approval_decisions.sql", [
    ["approval decision ledger", /CREATE TABLE IF NOT EXISTS approval_decisions/],
    ["approval decision uniqueness", /UNIQUE \(approval_id, decided_by_user_id\)/],
    ["approval cascade", /approval_id uuid NOT NULL REFERENCES approvals\(id\) ON DELETE CASCADE/],
  ]);
  await patternCheck("state", "OpenClaw job run idempotency schema", "apps/control-plane/migrations/005_job_run_id_idempotency.sql", [
    ["duplicate cleanup", /WITH duplicate_jobs AS/],
    ["workspace run unique index", /CREATE UNIQUE INDEX IF NOT EXISTS jobs_workspace_openclaw_run_id_idx/],
    ["run id partial predicate", /WHERE openclaw_run_id IS NOT NULL/],
  ]);
  await patternCheck("security", "encrypted secrets and SecretRefs", "apps/control-plane/src/secrets.ts", [
    ["AES-GCM", /aes-256-gcm/],
  ]);
  await patternCheck("security", "internal SecretRef resolver request validation", "apps/control-plane/src/server.ts", [
    ["malformed SecretRef URL path handled", /function decodePathComponent[\s\S]*decodeURIComponent\(value\)[\s\S]*SecretRef id is not valid URL encoding/],
    ["SecretRef workspace scoping", /parseSecretRefId\(id\)[\s\S]*SecretRef id must start with workspaces\/<workspaceId>\//],
  ]);
  await patternCheck("security", "persisted metadata redaction", "apps/control-plane/src/redaction.ts", [
    ["token-shaped string redaction", /secretLikePattern/],
    ["sensitive key redaction", /isSensitiveKey/],
    ["SecretRef metadata allowed", /secretref/],
  ]);
  await patternCheck("security", "redaction before durable metadata writes", "apps/control-plane/src/server.ts", [
    ["bounded metadata schema import", /metadataRecordSchema/],
    ["approval payload bounded before redaction", /payload:\s*metadataRecordSchema\.default\(\{\}\)[\s\S]*redactRecordForPersistence\(body\.payload\)/],
    ["OpenClaw event metadata bounded before redaction", /metadata:\s*metadataRecordSchema\.default\(\{\}\)[\s\S]*const metadata = redactRecordForPersistence\(body\.metadata\)/],
    ["audit metadata redaction", /redactRecordForPersistence\(input\.metadata \?\? \{\}\)/],
    ["OpenClaw event metadata redaction", /const metadata = redactRecordForPersistence\(body\.metadata\)/],
    ["observation session metadata redaction", /const sessionMetadata = redactRecordForPersistence\(observed\.metadata\)/],
    ["observation usage metadata redaction", /const usageMetadata = redactRecordForPersistence\(usage\.metadata\)/],
    ["observation usage token bounds", /usageTokenCountSchema\.safeParse\(usage\.inputTokens\)[\s\S]*usageTokenCountSchema\.safeParse\(usage\.outputTokens\)[\s\S]*usageSkipped/],
    ["observation task metadata redaction", /const taskMetadata = redactRecordForPersistence\(observed\.metadata\)/],
    ["approval payload redaction", /redactRecordForPersistence\(body\.payload\)/],
  ]);
  await patternCheck("openclaw", "atomic OpenClaw config file writes", "apps/control-plane/src/server.ts", [
    ["atomic config writer", /async function writeOpenClawConfigFile/],
    ["same directory temp file", /path\.join\(dir,[\s\S]*\.tmp/],
    ["private config temp mode", /writeFile\(tempPath[\s\S]*mode:\s*0o600/],
    ["private config final chmod", /chmod\(configPath,\s*0o600\)/],
    ["user-owned resolver wrapper", /async function writeOpenClawResolverWrapper[\s\S]*mode:\s*0o700[\s\S]*operant-secret-resolver/],
    ["atomic rename to final path", /rename\(tempPath, configPath\)/],
    ["config generator uses atomic writer", /writeOpenClawConfigFile\(configPath, config, checksum\)/],
  ]);
  await patternCheck("security", "RBAC built-ins and action/resource permissions", "apps/control-plane/src/rbac.ts", [
    ["owner role", /owner:/],
    ["admin role", /admin:/],
    ["integration admin", /integration_admin:/],
    ["billing usage admin", /billing_usage_admin:/],
    ["member", /member:/],
    ["viewer", /viewer:/],
    ["permission matcher", /permissionMatches/],
  ]);
  await patternCheck("security", "RBAC built-in seed convergence", "apps/control-plane/src/seed.ts", [
    ["built-in role upsert", /ON CONFLICT \(company_id, name\) DO UPDATE SET builtin = true/],
    ["stale grant deletion", /DELETE FROM role_permissions rp[\s\S]*NOT EXISTS/],
    ["grant comparison uses jsonb recordset", /jsonb_to_recordset\(\$2::jsonb\) AS wanted\(action text, resource text\)/],
    ["current grants inserted", /INSERT INTO role_permissions[\s\S]*SELECT \$1, id FROM permissions WHERE action = \$2 AND resource = \$3/],
  ]);
  await patternCheck("tests", "RBAC built-in seed convergence unit coverage", "apps/control-plane/tests/seed.test.ts", [
    ["stale grant deletion test", /removes stale grants before inserting current grants/],
    ["delete before insert assertion", /staleGrantDeleteIndex > roleInsertIndex[\s\S]*firstGrantInsertIndex > staleGrantDeleteIndex/],
    ["grant JSON assertion", /defaultRolePermissions\.viewer/],
  ]);
  await patternCheck("tests", "RBAC built-in role unit coverage", "apps/control-plane/tests/rbac.test.ts", [
    ["owner role test", /owner can access every action and resource/],
    ["viewer role test", /viewer is read-only/],
    ["integration admin role test", /integration admin can write credentials/],
    ["billing usage admin role test", /billing usage admin can read usage and audit/],
    ["admin role test", /admin can manage users/],
    ["billing admin cannot mutate credentials", /billing_usage_admin[\s\S]*credentials:write[\s\S]*false/],
  ]);
  await patternCheck("tests", "user and custom role schema coverage", "apps/control-plane/tests/users-schema.test.ts", [
    ["member default", /defaults to member role[\s\S]*\["member"\]/],
    ["explicit role required", /requires at least one role[\s\S]*roles:\s*\[\]/],
    ["Slack ID and role name bounds", /constrains Slack IDs and role names[\s\S]*U 1[\s\S]*Admin/],
    ["user display name trim and blank rejection", /display names are trimmed and nonblank[\s\S]*Smoke Admin[\s\S]*Too small/],
    ["custom role permissions required", /custom role schema requires at least one permission/],
    ["custom role permission grant bounds", /custom role schema bounds permission grants[\s\S]*length:\s*501/],
  ]);
  await patternCheck("openclaw", "OpenClaw Slack reuse config contract", "apps/control-plane/src/openclaw-config.ts", [
    ["Slack socket mode", /mode:\s*"socket"/],
    ["exported gateway WebSocket URL normalizer", /export function gatewayWebSocketUrl/],
    ["hybrid reload", /reload:[\s\S]*mode:\s*"hybrid"/],
    ["gateway token auth", /auth:[\s\S]*mode:\s*"token"[\s\S]*OPENCLAW_GATEWAY_TOKEN/],
    ["gateway auth rate limit", /rateLimit:[\s\S]*maxAttempts:[\s\S]*windowMs:[\s\S]*lockoutMs/],
    ["control UI localhost origins", /controlUi:[\s\S]*allowedOrigins:[\s\S]*localhost:18789[\s\S]*127\.0\.0\.1:18789/],
    ["SecretRefs", /source:\s*"exec"/],
    ["Slack plugin allowlisted", /allow:\s*\[\s*"slack",\s*"operant"\s*\]/],
    ["Operant plugin entry registered", /operant:\s*\{\s*enabled:\s*true/],
    ["Slack plugin enabled", /plugins:[\s\S]*entries:[\s\S]*slack:[\s\S]*enabled:\s*true/],
    ["model SecretRefs", /apiKey:\s*secretRef\(buildSecretRefId\(input\.workspaceId,\s*`models\/\$\{input\.modelProvider\}\/apiKey`\)\)/],
    ["OpenAI PI agent runtime", /agentRuntime:[\s\S]*id:\s*"pi"/],
    ["primary model default", /model:[\s\S]*primary:\s*`\$\{input\.modelProvider\}\/\$\{input\.modelName\}`/],
    ["resolver env confinement", /passEnv:[\s\S]*OPERANT_CONTROL_PLANE_URL[\s\S]*OPERANT_INTERNAL_TOKEN/],
    ["exec approvals", /execApprovals/],
    ["direct resolver command path", /allowSymlinkCommand:\s*false/],
    ["trusted resolver dir", /trustedDirs:[\s\S]*\/operant\/openclaw/],
    ["base sandbox disabled", /input\.sandboxMode !== "docker"[\s\S]*mode:\s*"off"/],
    ["sandbox docker confinement", /sandboxMode[\s\S]*backend:\s*"docker"[\s\S]*workspaceAccess:\s*"none"[\s\S]*binds:\s*\[\]/],
    ["tool allowlist", /alsoAllow/],
    ["tool deny", /deny/],
    ["elevated tools disabled", /elevated:[\s\S]*enabled:\s*false[\s\S]*slack:\s*\[\]/],
    ["Slack DM and group policies", /dmPolicy:[\s\S]*allowlist[\s\S]*disabled[\s\S]*groupPolicy/],
    ["Slack threading", /thread:[\s\S]*historyScope:\s*"thread"/],
    ["Slack top-level mention requirement", /requireMention:\s*true/],
    ["Slack acknowledgement reaction", /ackReaction:\s*"eyes"/],
    ["Slack typing reaction", /typingReaction:\s*"pencil2"/],
    ["Slack progress streaming", /streaming:[\s\S]*mode:\s*"progress"[\s\S]*label:\s*"thinking"[\s\S]*toolProgress:\s*true/],
    ["Slack media bound", /mediaMaxMb:\s*25/],
    ["interactive replies", /interactiveReplies:\s*true/],
    ["tool redaction", /redactSensitive:\s*"tools"/],
  ]);
  await patternCheck("tests", "OpenClaw generated config security defaults unit coverage", "apps/control-plane/tests/openclaw-config.test.ts", [
    ["safe gateway defaults test", /safe gateway defaults/],
    ["gateway token and rate limit assertions", /config\.gateway\.auth[\s\S]*OPENCLAW_GATEWAY_TOKEN[\s\S]*rateLimit/],
    ["control UI origin assertions", /config\.gateway\.controlUi\.allowedOrigins/],
    ["resolver env and trusted dirs assertions", /passEnv:[\s\S]*OPERANT_INTERNAL_TOKEN[\s\S]*trustedDirs/],
    ["Slack plugin allowlist assertion", /config\.plugins\.allow[\s\S]*\["slack",\s*"operant"\]/],
    ["Operant plugin entry assertion", /config\.plugins\.entries\.operant[\s\S]*?enabled:\s*true/],
    ["Slack plugin enabled assertion", /config\.plugins\.entries\.slack[\s\S]*enabled:\s*true/],
    ["model SecretRef assertion", /models\/openai\/apiKey/],
    ["primary model assertion", /config\.agents\.defaults\.model[\s\S]*openai\/gpt-5/],
    ["base sandbox disabled assertion", /config\.agents\.defaults\.sandbox[\s\S]*mode:\s*"off"/],
    ["sandbox opt-in confinement assertion", /opts into Docker sandboxing[\s\S]*sandboxMode:\s*"docker"[\s\S]*workspaceAccess:\s*"none"[\s\S]*binds:\s*\[\]/],
    ["elevated tools disabled assertion", /config\.tools\.elevated[\s\S]*enabled:\s*false/],
    ["Slack thread streaming assertions", /config\.channels\.slack\.thread[\s\S]*historyScope:\s*"thread"[\s\S]*config\.channels\.slack\.streaming/],
    ["disabled channel assertion", /channels\.C2\.enabled[\s\S]*false/],
    ["Slack media bound assertion", /config\.channels\.slack\.mediaMaxMb[\s\S]*25/],
    ["interactive replies assertion", /interactiveReplies:\s*true/],
    ["redaction assertion", /config\.logging\.redactSensitive/],
    ["empty allowlist disables Slack policies", /disables Slack DM and group policies when no allowlists exist/],
  ]);
  await patternCheck("openclaw", "OpenClaw feature reuse research", "docs/openclaw/reuse-map.md", [
    ["local CLI evidence", /Local CLI:[\s\S]*openclaw --help[\s\S]*openclaw agent --help[\s\S]*openclaw channels capabilities --channel slack --json[\s\S]*openclaw gateway --help[\s\S]*openclaw cron --help[\s\S]*openclaw tasks --help[\s\S]*openclaw mcp --help[\s\S]*openclaw skills --help[\s\S]*openclaw plugins --help[\s\S]*openclaw security --help[\s\S]*openclaw sandbox --help/],
    ["official source list", /https:\/\/docs\.openclaw\.ai\/channels\/slack[\s\S]*https:\/\/docs\.openclaw\.ai\/gateway\/configuration[\s\S]*https:\/\/docs\.openclaw\.ai\/gateway\/secrets[\s\S]*https:\/\/docs\.openclaw\.ai\/gateway\/security[\s\S]*https:\/\/docs\.openclaw\.ai\/gateway\/sandboxing[\s\S]*https:\/\/docs\.openclaw\.ai\/install\/docker/],
    ["Slack docs/source", /Slack Socket Mode/],
    ["Socket Mode request URL guidance", /Do not enter an Event Subscriptions \*\*Request URL\*\*[\s\S]*Socket Mode[\s\S]*WebSocket[\s\S]*App Manifest/],
    ["Slack transport reuse", /Slack Socket Mode and HTTP Request URL transports/],
    ["Slack event reuse", /DMs, app mentions, channel messages, MPIMs, App Home, slash commands, interactivity, and file events/],
    ["Slack threading reuse", /Slack threading\/session routing and reply delivery/],
    ["Slack streaming reuse", /Slack live preview\/native streaming behavior/],
    ["Slack files reuse", /Slack file upload\/download handling/],
    ["Slack interactivity reuse", /Slack interactive reply buttons\/selects/],
    ["Slack approval reuse", /Slack-native exec approval prompts and approver authorization/],
    ["gateway docs/source", /gateway/],
    ["SecretRef reuse", /SecretRef resolution for env\/file\/exec providers/],
    ["gateway checks reuse", /Gateway health, doctor, security audit, status, and usage-cost commands/],
    ["hybrid reload reuse", /gateway\.reload\.mode="hybrid"/],
    ["secrets reload reuse", /openclaw secrets reload --json/],
    ["observation surfaces", /openclaw status --all --json[\s\S]*openclaw sessions --json[\s\S]*openclaw tasks list --json[\s\S]*openclaw gateway usage-cost --json/],
    ["cron scheduled work reuse", /Gateway scheduler and durable background task state[\s\S]*openclaw cron[\s\S]*openclaw tasks/],
    ["scheduler do-not-rebuild boundary", /Observe scheduled runs and durable background tasks[\s\S]*instead of building a parallel scheduler/],
    ["agent turns reuse", /Agent turns and reply delivery via `openclaw agent`[\s\S]*--deliver --reply-channel slack/],
    ["MCP bridge reuse", /MCP server configuration and channel bridge surfaces via `openclaw mcp`/],
    ["skill plugin runtime reuse", /Skill and plugin extension surfaces via `openclaw skills`[\s\S]*`openclaw plugins`/],
    ["business tool runtime do-not-rebuild boundary", /Treat business-tool execution, code\/PR work, reports, spreadsheets, decks,[\s\S]*browsing, APIs,[\s\S]*OpenClaw agent, MCP, skill,[\s\S]*instead\s+of implementing those tool runtimes/],
    ["config contract", /Slack Config Contract/],
    ["security docs/source", /Security Boundary/],
    ["sandboxing docs/source", /sandboxing|sandbox/],
    ["sandbox backends", /Docker\/SSH\/OpenShell backends/],
    ["do not rebuild", /Reuse, Do Not Rebuild/],
    ["Operant configure observe responsibility", /configure and observe these features instead of implementing parallel Slack logic/],
  ]);
  await slackRuntimeBoundaryCheck();
  await patternCheck("openclaw", "OpenClaw observation sync", "apps/control-plane/src/openclaw-ops.ts", [
    ["status observations", /extractOpenClawStatusObservations/],
    ["session list observations", /extractOpenClawSessionsObservations[\s\S]*openclaw\.sessions/],
    ["task observations", /extractOpenClawTaskObservations/],
    ["usage-cost observations", /extractOpenClawUsageCostObservations[\s\S]*openclaw\.usage-cost/],
    ["usage-cost check command", /"usage-cost":\s*\["gateway",\s*"usage-cost",\s*"--json"\]/],
    ["explicit gateway command args", /explicitGatewayArgChecks[\s\S]*secrets-reload[\s\S]*approvals-get[\s\S]*cron-status[\s\S]*usage-cost[\s\S]*openClawGatewayCommandArgs[\s\S]*--url[\s\S]*--token/],
    ["display command token redaction", /displayCommand[\s\S]*--token[\s\S]*\[REDACTED\]/],
    ["generic command runner", /runOpenClawCommand/],
  ]);
  await patternCheck("openclaw", "OpenClaw control-plane command gateway URL", "apps/control-plane/src/server.ts", [
    ["gateway command env helper", /openClawCommandExtraEnv[\s\S]*OPENCLAW_GATEWAY_URL[\s\S]*gatewayWebSocketUrl/],
    ["observation state env helper", /openClawObservationCommandExtraEnv[\s\S]*OPENCLAW_OBSERVATION_STATE_DIR[\s\S]*OPENCLAW_STATE_DIR/],
    ["checks route command env", /runOpenClawCheck\(\{[\s\S]*extraEnv:\s*openClawCommandExtraEnv\(workspace\)/],
    ["observation sync command env", /const commandParams = \{[\s\S]*extraEnv:\s*openClawObservationCommandExtraEnv\(workspace\)/],
    ["observation sessions command", /runOpenClawCommand\(\["sessions",\s*"--json"\],\s*commandParams\)/],
    ["observation usage-cost explicit gateway args", /runOpenClawCommand\(openClawGatewayCommandArgs\(\["gateway",\s*"usage-cost",\s*"--json"\],\s*commandParams\),\s*commandParams\)/],
  ]);
  await patternCheck("compose", "control-plane OpenClaw gateway command env", "docker-compose.yml", [
    ["gateway token in control plane", /policy-audit:[\s\S]*OPENCLAW_GATEWAY_TOKEN:\s*\$\{OPENCLAW_GATEWAY_TOKEN:\?set OPENCLAW_GATEWAY_TOKEN in \.env\}/],
    ["explicit private Compose ws allowance", /policy-audit:[\s\S]*OPENCLAW_ALLOW_INSECURE_PRIVATE_WS:\s*"1"/],
    ["gateway observation state mount", /OPENCLAW_OBSERVATION_STATE_DIR:\s*\/home\/node\/\.openclaw-gateway-state[\s\S]*operant-openclaw-state:\/home\/node\/\.openclaw-gateway-state/],
  ]);
  await patternCheck("docs", "setup operator pairing and integration credential docs", "docs/setup.md", [
    ["OpenClaw operator-device pairing runbook", /pairing required[\s\S]*openclaw devices list[\s\S]*openclaw devices approve <requestId>[\s\S]*operator\.read[\s\S]*operator\.approvals[\s\S]*operator\.talk\.secrets/],
    ["structured integration credential seed docs", /OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON[\s\S]*secretValueEnv[\s\S]*(?:inline JSON[\s\S]*redact|redact[\s\S]*inline JSON)/],
    ["no active admin token placeholder", /^(?![\s\S]*(^|\n)\s*(?:export\s+)?OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_\.\.\.)[\s\S]*$/],
  ]);
  await patternCheck("docs", "strict live acceptance runbook", "docs/acceptance.md", [
    ["live env template", /deploy\/slack\/live\.env\.example/],
    ["quick live E2E overlay command", /For a live Slack\/OpenClaw check[\s\S]*pnpm live:e2e -- --env \.env\.acme --live-env \.env\.acme\.live[\s\S]*--require-slack-approval-completion/],
    ["strict live preflight overlay command", /pnpm live:preflight -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["strict Compose live-env command", /pnpm compose:e2e -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["shell export alternative", /Shell-export alternative when not using `--live-env`/],
    ["shell export keeps admin token optional", /Shell-export alternative when not using `--live-env`:[\s\S]*# Normally supplied by the generated Compose env passed with --env\.[\s\S]*# export OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_\.\.\./],
    ["temporary human verifier tokens", /temporary human Slack user tokens?[\s\S]*not the bot\s+token/],
    ["user token probe methods", /SLACK_USER_TOKEN[\s\S]*auth\.test[\s\S]*chat\.postMessage/],
    ["bot token Slack read checks", /bot token[\s\S]*auth\.test[\s\S]*conversations\.info[\s\S]*conversations\.members[\s\S]*conversations\.replies/],
    ["one-human denied policy proof", /denied-policy proof does not require a second human[\s\S]*temporarily denies the\s+allowed\s+human[\s\S]*restores policy/],
    ["record delta flag", /--require-operant-records/],
    ["DM flag", /--require-dm/],
    ["denied-user flag", /--require-denied-user/],
    ["Slack approval flag", /--require-slack-approval/],
    ["Slack approval completion flag", /--require-slack-approval-completion/],
    ["optional Slack ID consistency", /OPERANT_LIVE_BOT_USER_ID[\s\S]*OPERANT_LIVE_DENIED_USER_ID[\s\S]*auth\.test/],
  ]);
  await patternCheck("docs", "Slack live acceptance runbook", "deploy/slack/README.md", [
    ["live env template", /live\.env\.example/],
    ["app-level Socket Mode token class", /App-level token[\s\S]*apps\.connections\.open[\s\S]*connections:write[\s\S]*xapp-/],
    ["Socket Mode request URL guidance", /Do not enter an Event Subscriptions \*\*Request URL\*\*[\s\S]*Socket Mode[\s\S]*WebSocket[\s\S]*App Manifest/],
    ["temporary verifier user token class", /Temporary allowed user token[\s\S]*auth\.test[\s\S]*chat\.postMessage[\s\S]*conversations\.members[\s\S]*conversations\.replies/],
    ["one-human denied policy proof", /strict denied-policy proof is one-human by default[\s\S]*temporarily updates[\s\S]*restores/],
    ["DM and bot channel membership setup", /Create the DM channel[\s\S]*Invite the bot to the channel/],
    ["OpenClaw operator-device pairing runbook", /pairing required[\s\S]*openclaw devices list[\s\S]*openclaw devices approve <requestId>[\s\S]*operator\.read[\s\S]*operator\.approvals[\s\S]*operator\.talk\.secrets/],
    ["record delta flag", /--require-operant-records/],
    ["DM flag", /--require-dm/],
    ["denied-user flag", /--require-denied-user/],
    ["Slack approval flag", /--require-slack-approval/],
    ["Slack approval completion flag", /--require-slack-approval-completion/],
    ["optional Slack ID consistency", /OPERANT_LIVE_BOT_USER_ID[\s\S]*OPERANT_LIVE_DENIED_USER_ID[\s\S]*auth\.test/],
    ["structured integration credential seed docs", /OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON[\s\S]*secretValueEnv[\s\S]*(?:inline JSON[\s\S]*redact|redact[\s\S]*inline JSON)/],
  ]);
  await patternCheck("deploy", "Slack app manifest", "deploy/slack/manifest.yaml", [
    ["socket mode", /socket_mode_enabled:\s*true/],
    ["interactivity", /interactivity:[\s\S]*is_enabled:\s*true/],
    ["App Home tabs", /home_tab_enabled:\s*true[\s\S]*messages_tab_enabled:\s*true[\s\S]*messages_tab_read_only_enabled:\s*false/],
    ["App Home event", /-\s*app_home_opened/],
    ["channel/member events", /-\s*channel_rename[\s\S]*-\s*member_joined_channel[\s\S]*-\s*member_left_channel/],
    ["verifier user write", /user:[\s\S]*-\s*chat:write[\s\S]*bot:/],
    ["app mentions scope", /-\s*app_mentions:read/],
    ["assistant scope", /-\s*assistant:write/],
    ["bot write", /-\s*chat:write/],
    ["commands scope", /-\s*commands/],
    ["app mentions", /-\s*app_mention/],
    ["IM messages", /-\s*message\.im/],
    ["channel messages", /-\s*message\.channels/],
    ["private channel messages", /-\s*message\.groups/],
    ["MPIM messages", /-\s*message\.mpim/],
    ["channel read scope for membership checks", /-\s*channels:read/],
    ["channel join scope for setup automation", /-\s*channels:join/],
    ["private channel read scope for membership checks", /-\s*groups:read/],
    ["DM read scope for reachability checks", /-\s*im:read/],
    ["MPIM read scope for reachability checks", /-\s*mpim:read/],
    ["reaction events", /-\s*reaction_added[\s\S]*-\s*reaction_removed/],
    ["pin events", /-\s*pin_added[\s\S]*-\s*pin_removed/],
    ["file scopes", /-\s*files:read[\s\S]*-\s*files:write/],
    ["reaction scopes", /-\s*reactions:read[\s\S]*-\s*reactions:write/],
    ["pin scopes", /-\s*pins:read[\s\S]*-\s*pins:write/],
    ["Slack identity scopes", /-\s*usergroups:read[\s\S]*-\s*users:read/],
  ]);
  await patternCheck("deploy", "Slack scope shared contract", "scripts/slack-scope-contract.mjs", [
    ["app-level scope contract", /requiredAppLevelScopes[\s\S]*connections:write/],
    ["verifier user scope contract", /requiredVerifierUserScopes[\s\S]*chat:write/],
    ["strict acceptance scopes", /requiredLiveBotScopes[\s\S]*app_mentions:read[\s\S]*assistant:write[\s\S]*channels:history[\s\S]*chat:write[\s\S]*im:read[\s\S]*im:write[\s\S]*reactions:write/],
    ["recommended OpenClaw scopes", /recommendedOpenClawBotScopes[\s\S]*requiredLiveBotScopes[\s\S]*commands[\s\S]*files:write[\s\S]*groups:read[\s\S]*mpim:read[\s\S]*users:read/],
    ["required bot events", /requiredSlackBotEvents[\s\S]*app_mention[\s\S]*message\.channels[\s\S]*message\.im/],
    ["recommended bot events", /recommendedSlackBotEvents[\s\S]*app_home_opened[\s\S]*channel_rename[\s\S]*member_joined_channel[\s\S]*member_left_channel[\s\S]*message\.groups[\s\S]*reaction_added[\s\S]*pin_removed/],
    ["manifest scope parser", /parseSlackBotScopesFromManifest[\s\S]*parseSlackUserScopesFromManifest/],
    ["missing scope helper", /missingScopes/],
    ["printable scope contract", /slackScopeContract[\s\S]*appLevelToken[\s\S]*verifierUserToken[\s\S]*minimumBotOAuthScopes[\s\S]*recommendedBotOAuthScopes[\s\S]*--json/],
  ]);
  await patternCheck("deploy", "Slack live env template", "deploy/slack/live.env.example", [
    ["admin login token comes from compose env", /Dashboard admin login token comes from the generated Compose env[\s\S]*# OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_\.\.\./],
    ["admin Slack user", /OPERANT_LIVE_ADMIN_SLACK_USER_ID=U\.\.\./],
    ["optional Slack team ID", /OPERANT_LIVE_SLACK_TEAM_ID=T\.\.\./],
    ["Slack channel", /SLACK_CHANNEL_ID=C\.\.\./],
    ["Slack app token", /SLACK_APP_TOKEN=<slack-app-token>/],
    ["Slack bot token", /SLACK_BOT_TOKEN=<slack-bot-token>/],
    ["allowed Slack user token", /SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>/],
    ["Slack config token", /SLACK_CONFIG_TOKEN=<xoxp-or-xoxe-slack-configuration-token>/],
    ["human user OAuth token guidance", /[Hh]uman user OAuth tokens[\s\S]*xoxp-[\s\S]*xoxc-[\s\S]*not Slack user IDs[\s\S]*not bot[\s\S]*tokens/],
    ["DM channel", /OPERANT_LIVE_DM_CHANNEL_ID=D\.\.\./],
    ["optional bot user ID", /OPERANT_LIVE_BOT_USER_ID=U\.\.\./],
    ["optional denied user ID", /OPERANT_LIVE_DENIED_USER_ID=U\.\.\./],
    ["optional policy seed DM users", /OPERANT_LIVE_ALLOWED_DM_USER_IDS=U\.\.\./],
    ["optional policy seed channels", /OPERANT_LIVE_ALLOWED_CHANNEL_IDS=C\.\.\./],
    ["optional policy seed approvers", /OPERANT_LIVE_APPROVER_SLACK_USER_IDS=U\.\.\./],
    ["optional denied Slack user token", /OPERANT_LIVE_DENIED_USER_TOKEN=<xoxp-or-xoxc-denied-human-user-oauth-token>/],
    ["one-human denied policy guidance", /[Dd]enied-policy proof is one-human by default[\s\S]*temporarily deny the allowed test user[\s\S]*restores policy/],
    ["Slack membership check guidance", /conversations\.members/],
    ["model key", /OPENAI_API_KEY=<model-api-key>/],
    ["Anthropic model key alias", /ANTHROPIC_API_KEY=<anthropic-model-api-key>/],
    ["live model provider", /OPERANT_LIVE_MODEL_PROVIDER=openai/],
    ["live model name", /OPERANT_LIVE_MODEL_NAME=gpt-5/],
    ["approval prompt", /OPERANT_LIVE_APPROVAL_PROMPT=/],
    ["integration credential seed", /OPERANT_LIVE_INTEGRATION_CREDENTIALS=github\/api-token=GITHUB_TOKEN/],
    ["integration credential format", /Format: kind\/key=ENV_VAR,kind\/key=ENV_VAR/],
    ["integration credential JSON seed", /OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON=\[\{"kind":"linear","key":"api-token","label":"Linear API token","secretValueEnv":"LINEAR_API_KEY"\}\]/],
  ]);
  await patternCheck("deploy", "Helm and Fly deployment artifacts", "deploy/helm/operant/templates/statefulset.yaml", [
    ["StatefulSet", /kind:\s*StatefulSet/],
    ["headless governing service", /serviceName:\s*\{\{ include "operant\.fullname" \. \}\}-headless/],
    ["control plane", /name:\s*control-plane/],
    ["OpenClaw gateway", /name:\s*openclaw-gateway/],
    ["state volume", /openclaw-state/],
    ["admin login token", /OPERANT_ADMIN_LOGIN_TOKEN[\s\S]*secretKeyRef:[\s\S]*key:\s*OPERANT_ADMIN_LOGIN_TOKEN/],
  ]);
  await patternCheck("deploy", "Helm secret values", "deploy/helm/operant/values.yaml", [
    ["replica count fixed to one", /replicaCount:\s*1/],
    ["admin login token value", /operantAdminLoginToken:\s*""/],
    ["OpenClaw service disabled by default", /openclaw:[\s\S]*service:[\s\S]*enabled:\s*false/],
  ]);
  await patternCheck("deploy", "Helm values schema", "deploy/helm/operant/values.schema.json", [
    ["unknown top-level keys rejected", /"additionalProperties":\s*false/],
    ["required controlPlane", /"required":[\s\S]*"controlPlane"/],
    ["required openclaw", /"required":[\s\S]*"openclaw"/],
    ["required secrets", /"required":[\s\S]*"secrets"/],
    ["replica count minimum one", /"replicaCount"[\s\S]*"minimum":\s*1/],
    ["replica count maximum one", /"replicaCount"[\s\S]*"maximum":\s*1/],
    ["port upper bound", /"maximum":\s*65535/],
    ["storage quantity pattern", /\^\[1-9\]\[0-9\]\*\(Mi\|Gi\|Ti\)\$/],
    ["service type enum", /"ClusterIP"[\s\S]*"NodePort"[\s\S]*"LoadBalancer"/],
    ["image pull policy enum", /"Always"[\s\S]*"IfNotPresent"[\s\S]*"Never"/],
    ["trust-boundary description", /company\/workspace\/trust boundary/],
  ]);
  await patternCheck("deploy", "Helm default values schema verification", "scripts/operant-verify-deploy.mjs", [
    ["Slack scope contract import", /slack-scope-contract\.mjs/],
    ["strict Slack scope manifest verification", /missing strict live-acceptance bot scopes/],
    ["recommended Slack scope manifest verification", /missing recommended OpenClaw bot scopes/],
    ["duplicate Slack scope verification", /duplicate bot scopes/],
    ["values parser", /parseSimpleYamlMap/],
    ["schema subset validator", /validateSchemaSubset/],
    ["default values validation", /verifyHelmDefaultValues/],
    ["reject unknown values keys", /additionalProperties === false[\s\S]*not allowed by schema/],
    ["required values check", /is required by schema/],
    ["port range check", /minimum[\s\S]*maximum/],
    ["quantity pattern check", /schema\.pattern/],
  ]);
  await patternCheck("deploy", "Helm services isolation", "deploy/helm/operant/templates/services.yaml", [
    ["headless service", /name:\s*\{\{ include "operant\.fullname" \. \}\}-headless[\s\S]*clusterIP:\s*None/],
    ["control-plane service", /name:\s*\{\{ include "operant\.fullname" \. \}\}-control-plane/],
    ["OpenClaw service opt-in", /\{\{- if \.Values\.openclaw\.service\.enabled \}\}[\s\S]*name:\s*\{\{ include "operant\.fullname" \. \}\}-openclaw/],
  ]);
  await patternCheck("deploy", "Helm Secret template", "deploy/helm/operant/templates/secret.yaml", [
    ["database URL required for created secret", /DATABASE_URL:\s*\{\{ required "database\.url is required when secrets\.create=true and database\.existingSecret\.name is empty" \.Values\.database\.url \| quote \}\}/],
    ["admin login token secret", /OPERANT_ADMIN_LOGIN_TOKEN:[\s\S]*secrets\.operantAdminLoginToken/],
  ]);
  addCheck("deploy", "Fly deployment notes", await fileExists("deploy/fly/README.md"), "deploy/fly/README.md");

  await patternCheck("tests", "local smoke coverage", "scripts/operant-smoke.mjs", [
    ["managed Postgres", /Initializing temporary Postgres/],
    ["credential setup", /\/api\/config\/credentials/],
    ["admin login token negative path", /Missing or invalid admin login token/],
    ["invalid admin login token negative path", /invalidAdminTokenLogin/],
    ["login success audit event", /auth\.login/],
    ["login denied audit event", /auth\.login_denied/],
    ["logout invalidates bearer session", /\/api\/auth\/logout[\s\S]*\/api\/auth\/me[\s\S]*expectStatus:\s*401/],
    ["logout audit event", /auth\.logout/],
    ["admin token is not post-bootstrap credential bypass", /body: credentialPayload,[\s\S]*expectStatus: 401/],
    ["header auth invalid Slack ID denial", /invalidHeaderAuth[\s\S]*invalid Slack user identifier/],
    ["owner credential update without bootstrap token", /credentialUpdateWithoutBootstrapToken/],
    ["security header assertion", /assertSecurityHeaders/],
    ["dashboard app asset served", /requestText\(baseUrl,\s*"\/app\.js"/],
    ["dashboard stylesheet served", /requestText\(baseUrl,\s*"\/styles\.css"/],
    ["dashboard asset API wiring smoke", /Dashboard app asset did not wire credential, OpenClaw sync, usage summary\/events, export, and wipe API calls/],
    ["dashboard mobile CSS smoke", /Dashboard stylesheet did not include the mobile topbar and metrics layout safeguards/],
    ["dashboard policy preview controls smoke", /Dashboard policy preview form did not include action\/resource controls and group chat type/],
    ["synchronous export wipe dashboard wording", /Dashboard did not describe synchronous export and wipe actions accurately/],
    ["RBAC custom role", /usage_analyst/],
    ["custom role oversized grants denial", /oversizedCustomRole[\s\S]*oversized permission grant list/],
    ["custom role unknown permission denial", /unknownCustomRolePermission[\s\S]*Unknown permission/],
    ["custom role route enforcement", /usageAnalystToken/],
    ["custom role raw usage read", /\/api\/usage",\s*\{\s*token:\s*usageAnalystToken\s*\}/],
    ["custom role credential denial", /usageAnalystToken[\s\S]*\/api\/config\/credentials[\s\S]*expectStatus:\s*403/],
    ["custom role retention denial", /usageAnalystToken[\s\S]*\/api\/wipe[\s\S]*expectStatus:\s*403/],
    ["built-in role overwrite denial", /builtinRoleOverwrite[\s\S]*Built-in roles cannot be overwritten/],
    ["unknown role assignment denial", /unknownRoleAssignment[\s\S]*Unknown role/],
    ["last owner removal denial", /lastOwnerRemoval[\s\S]*Cannot remove the last workspace owner/],
    ["RBAC integration admin route enforcement", /integrationAdminToken/],
    ["integration admin jobs read", /\/api\/jobs",\s*\{\s*token:\s*integrationAdminToken\s*\}/],
    ["integration admin policy denial", /integrationAdminToken[\s\S]*\/api\/policy[\s\S]*expectStatus:\s*403/],
    ["integration admin export denial", /integrationAdminToken[\s\S]*\/api\/export[\s\S]*expectStatus:\s*403/],
    ["RBAC viewer route enforcement", /viewerToken/],
    ["viewer jobs read", /\/api\/jobs",\s*\{\s*token:\s*viewerToken\s*\}/],
    ["viewer raw usage read", /\/api\/usage",\s*\{\s*token:\s*viewerToken\s*\}/],
    ["viewer credential denial", /viewerToken[\s\S]*\/api\/config\/credentials[\s\S]*expectStatus:\s*403/],
    ["viewer approval denial", /viewerToken[\s\S]*\/api\/approvals[\s\S]*expectStatus:\s*403/],
    ["RBAC billing usage admin route enforcement", /billingUsageAdminToken/],
    ["billing usage admin raw usage read", /\/api\/usage",\s*\{\s*token:\s*billingUsageAdminToken\s*\}/],
    ["billing usage admin credential denial", /billingUsageAdminToken[\s\S]*\/api\/integrations\/credentials[\s\S]*expectStatus:\s*403/],
    ["RBAC member route enforcement", /memberToken/],
    ["member raw usage denial", /\/api\/usage",\s*\{\s*token:\s*memberToken,\s*expectStatus:\s*403\s*\}/],
    ["member credential denial", /memberToken[\s\S]*\/api\/config\/credentials[\s\S]*expectStatus:\s*403/],
    ["member retention denial", /memberToken[\s\S]*\/api\/wipe[\s\S]*expectStatus:\s*403/],
    ["retention export all secret assertion", /slackBotToken,\s*slackAppToken,\s*modelApiKey,\s*integrationSecretValue/],
    ["retention export credential metadata count", /exportedCredentials\.length < 4[\s\S]*counts\?\.credentials/],
    ["retention export metadata-only credentials", /exportedCredentials[\s\S]*encrypted_value[\s\S]*encryptedValue/],
    ["retention export every saved credential metadata", /workspaces\/\$\{summary\.workspaceId\}\/slack\/botToken[\s\S]*workspaces\/\$\{summary\.workspaceId\}\/slack\/appToken[\s\S]*workspaces\/\$\{summary\.workspaceId\}\/models\/openai\/apiKey[\s\S]*integrationCredential\.credential\.secret_ref_id/],
    ["retention export approval decision ledger", /exportedApprovalDecisions[\s\S]*approval decision ledger[\s\S]*matchingApprovalDecisions/],
    ["audit event type assertions", /assertAuditEventTypes/],
    ["concrete audit events", /bootstrap\.completed[\s\S]*credentials\.updated[\s\S]*rbac\.denied[\s\S]*approval\.requested[\s\S]*approval\.approved[\s\S]*retention\.wipe_completed/],
    ["audit secret leak assertion", /Audit log leaked plaintext secret material/],
    ["internal SecretRef malformed path denial", /malformedSecretRefPath[\s\S]*Malformed SecretRef URL path was not rejected as a client error/],
    ["internal event malformed json denial", /malformedOpenClawEvent[\s\S]*Malformed OpenClaw event JSON was not rejected as a client error/],
    ["internal event oversized json denial", /oversizedOpenClawEvent[\s\S]*Oversized OpenClaw event JSON was not rejected with the body size limit/],
    ["internal event secret metadata probe", /apiKey:\s*modelApiKey[\s\S]*integrationToken:\s*integrationSecretValue/],
    ["internal event invalid type denial", /invalidOpenClawEventType[\s\S]*Invalid OpenClaw event type was not rejected as a client error/],
    ["internal event invalid run id denial", /invalidOpenClawRunId[\s\S]*Oversized OpenClaw run ID was not rejected as a client error/],
    ["internal event oversized metadata denial", /oversizedOpenClawMetadata[\s\S]*oversized metadata/],
    ["internal event oversized usage denial", /oversizedOpenClawUsage[\s\S]*oversized usage numbers/],
    ["internal event run id idempotency", /Repeated OpenClaw event runId created duplicate job records/],
    ["usage summary model cost aggregate", /smokeModelUsage[\s\S]*OpenAI model token and cost aggregate/],
    ["usage summary tool cost aggregate", /smokeToolUsage[\s\S]*expected tool cost aggregate/],
    ["usage summary OpenClaw usage-cost aggregate", /openClawUsageCostModel[\s\S]*OpenClaw usage-cost aggregate[\s\S]*openClawUsageCostTool[\s\S]*gateway usage-cost aggregate/],
    ["retention purge linked usage cleanup", /usageEventsLinkedToExpiredSessions[\s\S]*Retention purge left usage linked to expired sessions\/jobs/],
    ["retention purge linked job cleanup", /jobsLinkedToExpiredSessions[\s\S]*Retention purge left a job linked to an expired session/],
    ["sessions wipe linked usage cleanup", /sessionsAfterSessionWipe[\s\S]*Sessions wipe left usage events linked to wiped sessions\/jobs/],
    ["workspace wipe revokes admin sessions", /workspaceWipe[\s\S]*Workspace wipe did not revoke dashboard admin sessions[\s\S]*\/api\/auth\/me[\s\S]*expectStatus:\s*401/],
    ["member-scoped approval list", /memberVisibleApprovals[\s\S]*neither requested nor was assigned to decide/],
    ["member-scoped session list", /memberSessionsAfterIngest[\s\S]*another user's OpenClaw session/],
    ["member-scoped job list", /memberJobsAfterIngest[\s\S]*another user's OpenClaw job/],
    ["invalid approval action denial", /invalidApprovalAction[\s\S]*Invalid approval action was not rejected as a client error/],
    ["oversized approval payload denial", /oversizedApprovalPayload[\s\S]*oversized payload metadata/],
    ["invalid approval id decision denial", /invalidApprovalIdDecision[\s\S]*malformed approval id as a client error/],
    ["policy evaluation", /\/api\/policy\/evaluate/],
    ["approval decision", /\/api\/approvals\/\$\{approval.id\}\/decision/],
    ["credential setup owner guard", /missingBootstrapOwner[\s\S]*workspace owner/],
    ["credential setup invalid model provider denial", /invalidModelProvider[\s\S]*invalid model provider SecretRef path part/],
    ["credential setup invalid Slack allowlist denial", /invalidSlackAllowlistId[\s\S]*invalid Slack allowlist identifier/],
    ["credential setup blank workspace denial", /blankWorkspaceName[\s\S]*blank workspace name/],
    ["credential setup retained admin allowlist smoke", /initialDmAllowFrom[\s\S]*optional allowed DM users[\s\S]*initialChannelUsers[\s\S]*channel allowlists while adding optional users/],
    ["credential setup channel rotation smoke", /rotatedCredentialUpdate[\s\S]*stale credential-seeded channel allowlist[\s\S]*rotatedChannelUsers[\s\S]*owner\/admin\/member allowlist users/],
    ["credential setup retained admin approver smoke", /initialApprovalApprovers[\s\S]*workspace owner while adding optional approval users/],
    ["integration credential blank label denial", /blankIntegrationLabel[\s\S]*blank label/],
    ["integration credential oversized secret denial", /oversizedIntegrationSecret[\s\S]*oversized secret value/],
    ["settings invalid OpenClaw gateway URL denial", /invalidGatewayUrl[\s\S]*non-HTTP OpenClaw gateway URL/],
    ["approval minApprovals two", /minApprovals:\s*2/],
    ["approval partial pending", /partialApproval\.status !== "pending"[\s\S]*approvalsReceived !== 1/],
    ["approval duplicate decision denial", /duplicateApprovalDecision[\s\S]*revise an existing decision/],
    ["approval final threshold", /finalApproval\.status !== "approved"[\s\S]*approvalsReceived !== 2/],
    ["malformed approval decision denial", /malformedApprovalDecision[\s\S]*without a valid configured approver requirement/],
    ["OpenClaw checks index", /\/api\/openclaw\/checks",\s*\{\s*token:\s*adminToken\s*\}/],
    ["OpenClaw all check names", /status[\s\S]*doctor[\s\S]*config-validate[\s\S]*secrets-reload[\s\S]*approvals-get[\s\S]*cron-status[\s\S]*tasks-list[\s\S]*usage-cost[\s\S]*security-audit[\s\S]*channels-status/],
    ["OpenClaw unsupported check denial", /\/api\/openclaw\/checks\/not-a-check[\s\S]*expectStatus:\s*400/],
    ["OpenClaw check endpoint loop", /\/api\/openclaw\/checks\/\$\{check\}/],
    ["OpenClaw config-validate assertion", /config-validate[\s\S]*valid:\s*true/],
    ["OpenClaw tasks-list assertion", /tasks-list[\s\S]*task JSON/],
    ["OpenClaw usage-cost assertion", /usage-cost[\s\S]*token\/cost JSON/],
    ["OpenClaw security-audit assertion", /security-audit[\s\S]*critical:\s*0/],
    ["OpenClaw check audit assertions", /openclaw\.check\.status[\s\S]*openclaw\.check\.config-validate[\s\S]*openclaw\.check\.cron-status[\s\S]*openclaw\.check\.tasks-list[\s\S]*openclaw\.check\.usage-cost[\s\S]*openclaw\.check\.security-audit/],
    ["OpenClaw observation sync", /\/api\/openclaw\/observations\/sync/],
    ["OpenClaw observation oversized usage skip", /usageSkipped < 1[\s\S]*oversized usage records/],
    ["OpenClaw usage-cost sync", /usageCostSnapshotsSeen[\s\S]*usageCostInserted \+ openClawSync\.synced\.usageCostUpdated[\s\S]*usage-cost snapshots/],
    ["OpenClaw config private mode", /expected 600 for private gateway reads/],
    ["policy allowlisted DM decision", /dmDecision[\s\S]*effect !== "allow"/],
    ["policy allowlisted channel decision", /channelAllowDecision[\s\S]*effect !== "allow"/],
    ["policy unlisted channel denial", /unlistedChannelDecision[\s\S]*effect !== "deny"/],
    ["policy disabled channel denial", /disabledChannelDecision[\s\S]*disabled channel policy decision to deny/],
    ["generated disabled channel entry", /disabledChannelId[\s\S]*preserved in generated OpenClaw config/],
    ["duplicate policy identity denial", /duplicatePolicyUpdate[\s\S]*duplicate policy identities/],
    ["duplicate Slack policy list denial", /duplicateSlackListPolicyUpdate[\s\S]*duplicate Slack identifiers in policy lists/],
    ["tool deny precedence smoke", /denyPrecedenceDecision[\s\S]*specific deny to beat wildcard approval policy/],
    ["unmatched approval request denial", /unmatchedApprovalRequest[\s\S]*without a matching enabled approval policy/],
    ["policy approval-required decision", /approvalRequiredDecision[\s\S]*effect !== "approval_required"/],
    ["restart", /restartApp/],
  ]);
  await patternCheck("tests", "policy evaluation unit coverage", "apps/control-plane/tests/policy.test.ts", [
    ["DM deny test", /denies unallowlisted DM users/],
    ["channel allow test", /allows channel users when channel and user are allowlisted/],
    ["group and thread allowlist test", /applies channel allowlists to group and thread policy previews/],
    ["group and thread missing channel deny test", /denies group and thread policy previews without an allowlisted channel/],
    ["disabled channel deny test", /denies disabled channels before tool policy evaluation/],
    ["risky tool approval test", /requires approval for risky tools/],
    ["deny beats channel allow test", /tool deny beats a channel allow/],
    ["deny beats wildcard approval test", /tool deny beats wildcard approval regardless of rule order/],
    ["scoped tool entitlement test", /scopes tool entitlements to Slack users and Operant roles/],
    ["approval summary test", /approval requirements summarize matching approval policies/],
  ]);
  await patternCheck("tests", "approval policy schema safety coverage", "apps/control-plane/tests/policy-schema.test.ts", [
    ["Slack identifier and policy array bounds", /bounds Slack identifiers and policy arrays[\s\S]*U1 with space[\s\S]*length: 201/],
    ["duplicate policy identity bounds", /duplicate policy identities[\s\S]*Duplicate channel policy[\s\S]*Duplicate tool policy[\s\S]*Duplicate approval policy name[\s\S]*Duplicate approval policy approver/],
    ["duplicate Slack list bounds", /duplicate Slack lists[\s\S]*Duplicate DM allowlist Slack identifier[\s\S]*Duplicate channel allowlist Slack identifier[\s\S]*Duplicate channel denylist Slack identifier[\s\S]*Duplicate tool policy user Slack identifier[\s\S]*Duplicate tool policy role/],
    ["policy identifier shape bounds", /constrains action and resource identifiers[\s\S]*shell with spaces[\s\S]*repeat\(161\)/],
    ["model SecretRef part bounds", /constrain model SecretRef parts[\s\S]*modelProvider: "\.\.\/openai"[\s\S]*modelName: "gpt 5"/],
    ["gateway URL protocol bounds", /constrains OpenClaw gateway URLs[\s\S]*https:\/\/gateway\.example\.com[\s\S]*ftp:\/\/gateway\.example\.com/],
    ["credential secret size bounds", /credential schemas bound secret value sizes[\s\S]*repeat\(8193\)/],
    ["credential and policy display text trim and blank rejection", /display text is trimmed and nonblank[\s\S]*Operant Smoke Co[\s\S]*GitHub API token[\s\S]*Too small/],
    ["metadata record key bounds", /metadata records bound keys before persistence[\s\S]*length:\s*101[\s\S]*repeat\(121\)/],
    ["usage numeric column bounds", /usage numeric values fit persisted column ranges[\s\S]*2_147_483_648[\s\S]*1_000_000/],
    ["enabled policy requires approver", /rejects impossible enabled approval policies[\s\S]*at least one approver/],
    ["min approvals unique approver cap", /minApprovals[\s\S]*unique approvers/],
    ["disabled draft approval policy allowed", /enabled:\s*false/],
  ]);
  await patternCheck("tests", "retention export unit safety coverage", "apps/control-plane/tests/retention.test.ts", [
    ["workspace-scoped export queries", /retention export queries are workspace-scoped[\s\S]*WHERE workspace_id = \$1/],
    ["no wildcard export queries", /SELECT\\s\+\\\*/],
    ["metadata-only credential export", /retention credential export is metadata-only[\s\S]*id, kind, label, secret_ref_id, created_at, updated_at/],
    ["approval decision ledger export", /retention export includes approval decision ledger metadata[\s\S]*approval_id, decided_by_user_id, status, created_at/],
    ["workspace wipe revokes admin sessions", /workspace wipe removes operational state[\s\S]*DELETE FROM admin_sessions/],
    ["sessions wipe linked usage", /sessions wipe removes linked usage before jobs and sessions[\s\S]*session_id IN[\s\S]*job_id IN/],
    ["retention purge linked usage and jobs", /retention purge removes usage and jobs linked to expired sessions before parent records[\s\S]*jobsLinkedToExpiredSessions[\s\S]*LEFT JOIN sessions[\s\S]*j\\\.created_at < \\\$2 OR s\\\.last_event_at < \\\$2/],
  ]);
  await patternCheck("tests", "static asset path boundary unit coverage", "apps/control-plane/tests/static-path.test.ts", [
    ["sibling prefix rejection", /public2\/index\.html[\s\S]*false/],
    ["parent traversal rejection", /public\/\.\.\/secret\.txt[\s\S]*false/],
    ["in-directory allow", /index\.html[\s\S]*true/],
  ]);
  await patternCheck("tests", "live Slack E2E gate", "scripts/operant-live-e2e.mjs", [
    ["chat.postMessage", /chat\.postMessage/],
    ["conversations.replies", /conversations\.replies/],
    ["conversations.members", /conversations\.members/],
    ["target-channel membership report evidence", /channelMembership/],
    ["durable report", /operant\.live-e2e-report\.v1/],
    ["report path", /OPERANT_LIVE_E2E_REPORT/],
    ["sanitized report writer", /writeLiveReport/],
    ["report secret redaction", /writeRedactedJsonReport/],
    ["report secret assertion", /assertNoSecretMaterial/],
    ["token-shaped secret redaction", /writeRedactedJsonReport/],
    ["previous report archive", /archiveExisting/],
    ["report redaction self-test", /runReportRedactionSelfTest/],
    ["env file overlay", /envPath[\s\S]*applyRuntimeEnvFromFiles[\s\S]*readEnvFile/],
    ["live env overlay", /liveEnvPath[\s\S]*mergeRuntimeEnv/],
    ["process live env precedence", /isLiveOverrideEnvKey[\s\S]*SLACK_[\s\S]*OPENAI_API_KEY/],
    ["placeholder rejection", /isPlaceholderValue[\s\S]*\^<\[\^>\]\+>\$/],
    ["CLI help and argument validation", /--self-test-arg-validation[\s\S]*printUsage[\s\S]*validateArgs[\s\S]*Unknown option/],
    ["env loading self-test", /runEnvLoadingSelfTest[\s\S]*Live E2E env loading self-test passed/],
    ["identity consistency guard", /assertSlackIdentityMatch[\s\S]*configured bot user ID[\s\S]*configured denied-user ID/],
    ["user token kind guard", /assertSlackUserTokenIdentity[\s\S]*must be a Slack user token/],
    ["bot scope guard", /requiredLiveBotScopes[\s\S]*assertSlackBotScopes[\s\S]*x-oauth-scopes[\s\S]*missingScopes[\s\S]*missing required OpenClaw Slack bot scopes/],
    ["duplicate allowed denied user guard", /assertDistinctSlackUsers[\s\S]*resolve to the same Slack user/],
    ["Slack team consistency guard", /assertSlackTeamMatch[\s\S]*team_id[\s\S]*configuredSlackTeamId/],
    ["identity consistency self-test", /runIdentityConsistencySelfTest[\s\S]*Live E2E identity consistency self-test passed/],
    ["OpenClaw assertion guard", /runOpenClawAssertionSelfTest[\s\S]*status-gateway-reachable[\s\S]*secrets-reload-ok:true[\s\S]*usage-cost-numeric-totals[\s\S]*channels-status-probe:true/],
    ["OpenClaw checks", /openclaw-checks/],
    ["OpenClaw check result evidence", /openClawCheckResults[\s\S]*openClawChecks/],
    ["OpenClaw pairing-optional channel status", /pairingOptionalOpenClawChecks[\s\S]*channels-status[\s\S]*isOpenClawPairingRequired\(result\)[\s\S]*operator device pairing required/],
    ["manual Slack nudge helper", /--manual-slack-nudge[\s\S]*manualSlackNudgeEnabled[\s\S]*sendManualSlackNudge[\s\S]*chat\.postMessage[\s\S]*Manual Slack \$\{label\} nudge/],
    ["manual Slack client-only authoring guidance", /manualSlackHumanAuthorshipText[\s\S]*Slack client[\s\S]*OAuth\/user token[\s\S]*bot_id\/app_id[\s\S]*process\.stdout\.write[\s\S]*do not use token\/API automation/],
    ["manual Slack timeout diagnostic", /manualSlackTimeoutDiagnosticText[\s\S]*sendManualSlackTimeoutDiagnostic[\s\S]*Manual Slack \$\{label\} timeout diagnostic/],
    ["cron task and usage-cost checks", /cron-status,tasks-list,usage-cost/],
    ["observation sync", /openclaw\/observations\/sync/],
    ["DM probe", /OPERANT_LIVE_DM_CHANNEL_ID/],
    ["required DM flag", /requireDm/],
    ["denied-user probe", /OPERANT_LIVE_DENIED_USER_TOKEN/],
    ["required denied-user flag", /requireDeniedUser/],
    ["one-human denied-policy mode", /--denied-use-allowed-user[\s\S]*policyWithTemporaryDeniedUser[\s\S]*Temporary denied-user policy restored/],
    ["manual Slack default timeout", /defaultManualSlackTimeoutMs\s*=\s*900_000[\s\S]*manualSlackPosts\s*\?\s*defaultManualSlackTimeoutMs\s*:\s*defaultAutomatedTimeoutMs/],
    ["approval probe", /runApprovalProbe/],
    ["DM probe report evidence", /dmProbe = \{ channelId: dmChannelId, parentTs: dmPosted\.ts, replyTs: dmReply\.ts \}/],
    ["all record deltas", /missingRequiredRecordDeltas/],
    ["Slack approval UI probe", /pollForApprovalUi/],
    ["Slack approval UI bot source", /isBotMessage/],
    ["required Slack approval flag", /requireSlackApproval/],
    ["required Slack approval completion flag", /requireSlackApprovalCompletion/],
    ["Slack approval completion timestamp", /approvalCompletionTs/],
    ["record deltas", /require-operant-records/],
  ]);
  await patternCheck("tests", "Compose runtime E2E gate", "scripts/operant-compose-e2e.mjs", [
    ["docker compose config", /composeCommand\(\["config"\]\)/],
    ["docker compose up", /composeCommand\(\["up",\s*"--build",\s*"-d"\]\)/],
    ["Docker daemon preflight", /Docker daemon[\s\S]*docker info --format/],
    ["health ready wait", /waitForOperant/],
    ["console output redaction", /redactConsole[\s\S]*writeStdout[\s\S]*writeStderr/],
    ["captured command output", /stdio:\s*\["ignore",\s*"pipe",\s*"pipe"\]/],
    ["timestamped step evidence", /recordedAt:\s*new Date\(\)\.toISOString\(\)/],
    ["non-live smoke mode", /skipCompletionAudit/],
    ["non-live runtime helper", /runNonLiveComposeRuntime/],
    ["non-live synthetic credential seed", /syntheticCredentialSeed[\s\S]*seedCredentials/],
    ["non-live generated primary model verification", /generated\.config\?\.agents\?\.defaults\?\.model\?\.primary[\s\S]*Generated OpenClaw config primary model/],
    ["non-live gateway health", /runOpenClawGatewayHealth/],
    ["non-live gateway operational checks", /runOpenClawGatewayOperationalChecks[\s\S]*OpenClaw status[\s\S]*OpenClaw secrets reload[\s\S]*OpenClaw usage cost[\s\S]*OpenClaw security audit[\s\S]*runOpenClawGatewayDoctorCheck/],
    ["non-live authenticated gateway scoped checks", /openClawGatewayScopedExecArgs[\s\S]*--url ws:\/\/127\.0\.0\.1:18789[\s\S]*--token[\s\S]*OPENCLAW_GATEWAY_TOKEN[\s\S]*OpenClaw secrets reload[\s\S]*gatewayScoped:\s*true[\s\S]*OpenClaw usage cost[\s\S]*gatewayScoped:\s*true/],
    ["non-live paired-gateway skip evidence", /skipWhenPairingRequired[\s\S]*pairing required\|device is not approved[\s\S]*requires paired\/approved OpenClaw operator device/],
    ["non-live status session model gate", /sessionDefaultModel[\s\S]*OpenClaw status session default model[\s\S]*did not match expected/],
    ["non-live status structured evidence", /record\("pass", label, validation\.detail \|\| "", validation\.evidence\)/],
    ["non-live status scope-limited evidence", /openClawStatusDetail[\s\S]*missing scope:[\s\S]*status scope-limited: \$\{gatewayError\}/],
    ["non-live status unexpected error gate", /OpenClaw status returned unexpected gateway error/],
    ["non-live control-plane OpenClaw checks", /verifyControlPlaneOpenClawChecks[\s\S]*\/api\/openclaw\/checks\/\$\{check\}[\s\S]*status[\s\S]*tasks-list[\s\S]*security-audit[\s\S]*doctor/],
    ["non-live control-plane checks evidence", /record\("pass", "control-plane OpenClaw checks", checks\.join\(","\), evidence\)/],
    ["non-live usage-cost numeric gate", /OpenClaw usage-cost did not return numeric totals/],
    ["non-live security audit critical gate", /security audit reported \$\{critical\} critical finding/],
    ["non-live doctor critical gate", /OpenClaw doctor reported \$\{criticals\.length\} critical finding/],
    ["strict live preflight before Compose start", /"Live preflight"[\s\S]*pnpmCommand\("live:preflight", livePreflightArgs\(\)\)[\s\S]*"Compose config"/],
    ["strict live preflight Slack setup blocker classification", /isBlockedLivePreflightOutput[\s\S]*assistant:write[\s\S]*Socket Mode is not turned on[\s\S]*blockedWhen:\s*\(output\) => allowBlocked && isBlockedLivePreflightOutput\(output\)/],
    ["strict live preflight blocker self-test", /missingAssistantScopeOutput[\s\S]*socketModeDisabledOutput[\s\S]*isBlockedLivePreflightOutput[\s\S]*invalid_auth[\s\S]*classified an unrelated live preflight failure as blocked/],
    ["strict live preflight blocked stop", /livePreflightPassed[\s\S]*if \(!livePreflightPassed\) return finish\(\)/],
    ["live env overlay", /liveEnvPath[\s\S]*parseEnv\(await readFile\(liveEnvPath/],
    ["live env preflight forwarding", /livePreflightArgs[\s\S]*--live-env/],
    ["live env doctor forwarding", /doctorArgs[\s\S]*--live-env/],
    ["manual Slack nudge forwarding", /--manual-slack-nudge[\s\S]*manualSlackNudgeEnabled[\s\S]*args\.push\("--manual-slack-nudge"\)/],
    ["one-human denied-policy forwarding", /--denied-use-allowed-user[\s\S]*deniedUseAllowedUserEnabled[\s\S]*args\.push\("--denied-use-allowed-user"\)/],
    ["Slack live blocker classification", /isBlockedLiveE2eOutput[\s\S]*manual Slack message[\s\S]*Slack mention verifier post was app-authored[\s\S]*blockedWhen:\s*\(output\) => allowBlocked && isBlockedLiveE2eOutput\(output\)/],
    ["placeholder detection", /isPlaceholderValue[\s\S]*trimmed\.includes\("\.\.\."\)[\s\S]*\^<\[\^>\]\+>\$/],
    ["strict live preflight required step", /requiredSteps[\s\S]*"Live preflight"/],
    ["offline live preflight skip disables strict gate", /skipLivePreflight[\s\S]*skipSlackAuthTest[\s\S]*skipModelAuthTest[\s\S]*strictFinalGateEnabled/],
    ["Compose profile forwarding", /composeProfiles[\s\S]*composeProfileArgs[\s\S]*docker", "compose", \.\.\.composeFileArgs, "--env-file", envPath, \.\.\.composeProfileArgs/],
    ["Compose overlay forwarding", /requestedComposeFiles[\s\S]*composeOverlayFiles[\s\S]*composeFileArgs[\s\S]*docker", "compose", \.\.\.composeFileArgs, "--env-file", envPath/],
    ["Redis queue profile health", /runRedisQueueProfileHealth[\s\S]*redis-cli", "ping"[\s\S]*Redis queue profile health/],
    ["gateway health retry", /did not pass within \$\{healthTimeoutMs\}ms/],
    ["blocked-mode non-live evidence", /missingLiveEnv\.length > 0 \|\| missingSeedEnv\.length > 0[\s\S]*allowBlocked[\s\S]*runNonLiveComposeRuntime/],
    ["blocked-mode cleanup", /missingLiveEnv\.length > 0 \|\| missingSeedEnv\.length > 0[\s\S]*Compose down[\s\S]*\["down", "-v"\]/],
    ["down volumes cleanup", /downVolumes[\s\S]*"down", \.\.\.\(downVolumes \? \["-v"\] : \[\]\)/],
    ["CLI help and argument validation", /--self-test-arg-validation[\s\S]*printUsage[\s\S]*validateArgs[\s\S]*Unknown option/],
    ["credential seed", /seedCredentials/],
    ["credential seed policy env inputs", /OPERANT_LIVE_ALLOWED_DM_USER_IDS[\s\S]*OPERANT_LIVE_ALLOWED_CHANNEL_IDS[\s\S]*OPERANT_LIVE_APPROVER_SLACK_USER_IDS/],
    ["credential seed retains admin approver", /const approvalSlackUserIds = Array\.from\(new Set\(\[\s*adminSlackUserId,[\s\S]*OPERANT_LIVE_APPROVER_SLACK_USER_IDS/],
    ["credential seed Slack team CLI override", /const slackTeamId = argValue\("--slack-team-id", firstEnv\(seedEnv, \["OPERANT_LIVE_SLACK_TEAM_ID", "SLACK_TEAM_ID"\]\)\)/],
    ["config verification", /verifySeededConfig/],
    ["config verification all seeded policy values", /assertIncludesAll[\s\S]*Generated OpenClaw config DM allowlist[\s\S]*expected\.allowedDmUserIds[\s\S]*expected\.allowedChannelIds[\s\S]*Generated OpenClaw config exec approval approvers/],
    ["secret leak assertion", /assertNoPlaintextSecrets/],
    ["credential SecretRef resolver readback", /verifyCredentialSecretRefsResolve[\s\S]*credential SecretRef resolver/],
    ["credential config-validate probe", /verifyGeneratedConfigValidate[\s\S]*\/api\/openclaw\/checks\/config-validate[\s\S]*credential config-validate/],
    ["integration credential seed", /seedIntegrationCredentials/],
    ["integration credential parser", /OPERANT_LIVE_INTEGRATION_CREDENTIALS/],
    ["provider-aware model credential selection", /modelApiKeyEnvNamesForProvider[\s\S]*ANTHROPIC_API_KEY[\s\S]*OPENAI_API_KEY[\s\S]*modelCredentialErrorForProvider[\s\S]*provider-specific model keys/],
    ["Docker socket env override", /OPENCLAW_DOCKER_SOCKET[\s\S]*OPENCLAW_DOCKER_GID/],
    ["internal SecretRef resolver", /\/internal\/openclaw\/secrets/],
    ["Slack user identity", /slackAuthTest/],
    ["credentials route", /\/api\/config\/credentials/],
    ["doctor before restart", /Operant doctor/],
    ["live E2E", /live:e2e/],
    ["live E2E Slack team forwarding", /liveArgs[\s\S]*"--slack-team-id"/],
    ["strict DM requirement", /--require-dm/],
    ["strict denied-user requirement", /--require-denied-user/],
    ["strict Slack approval requirement", /--require-slack-approval/],
    ["strict Slack approval completion requirement", /--require-slack-approval-completion/],
    ["strict Operant approval probe", /skipApprovalProbe/],
    ["placeholder live env rejection", /isPlaceholderValue/],
    ["restart services", /composeCommand\(\["restart",\s*\.\.\.restartServices\]\)/],
    ["post-restart doctor", /Post-restart doctor/],
    ["pre-restart live report", /live-e2e-report\.json/],
    ["post-restart live report", /live-e2e-post-restart-report\.json/],
    ["live report descriptors", /liveReports/],
    ["live report stale artifact guard", /liveReportDescriptor[\s\S]*currentStep[\s\S]*return descriptor[\s\S]*sha256/],
    ["live report hash descriptors", /liveReportDescriptor[\s\S]*sha256[\s\S]*generatedAt/],
    ["completion audit", /audit:completion/],
    ["completion audit skipped when live blocked", /steps\.some\(\(step\) => step\.status === "blocked"\)[\s\S]*blocked live prerequisites remain/],
    ["evidence report", /writeReport/],
    ["report migration fingerprints", /apps\/control-plane\/migrations\/004_approval_decisions\.sql[\s\S]*apps\/control-plane\/migrations\/005_job_run_id_idempotency\.sql/],
    ["report env", /OPERANT_COMPOSE_E2E_REPORT/],
    ["report live env path", /liveEnvPath:\s*liveEnvPath \|\| undefined/],
    ["explicit report mode", /mode:\s*nonLiveSmoke \? "non-live-smoke" : "strict-e2e"/],
    ["explicit runtime pass field", /runtimePassed/],
    ["explicit smoke pass field", /smokePassed:\s*nonLiveSmoke \? runtimePassed : undefined/],
  ]);
  await patternCheck("tests", "Compose E2E evidence freshness gate", "scripts/operant-completion-audit.mjs", [
    ["evidence input list", /composeEvidenceInputs/],
    ["lockfile fingerprint", /pnpm-lock\.yaml/],
    ["README fingerprint", /README\.md/],
    ["env template fingerprint", /\.env\.example/],
    ["Docker ignore fingerprint", /\.dockerignore/],
    ["sandbox overlay fingerprint", /docker-compose\.sandbox\.yml/],
    ["Slack live env fingerprint", /deploy\/slack\/live\.env\.example/],
    ["control-plane package fingerprint", /apps\/control-plane\/package\.json/],
    ["control-plane migration fingerprint", /apps\/control-plane\/migrations\/004_approval_decisions\.sql[\s\S]*apps\/control-plane\/migrations\/005_job_run_id_idempotency\.sql/],
    ["control-plane dashboard fingerprint", /apps\/control-plane\/public\/app\.js/],
    ["control-plane runtime fingerprint", /apps\/control-plane\/src\/retention\.ts/],
    ["control-plane redaction fingerprint", /apps\/control-plane\/src\/redaction\.ts/],
    ["sandbox Dockerfile fingerprint", /deploy\/openclaw\/Dockerfile\.sandbox/],
    ["sandbox runtime Dockerfile fingerprint", /deploy\/openclaw\/Dockerfile\.sandbox-runtime/],
    ["Slack live README fingerprint", /deploy\/slack\/README\.md/],
    ["env initializer fingerprint", /operant-init-env\.mjs/],
    ["Compose wrapper fingerprint", /operant-compose\.mjs/],
    ["Compose verifier fingerprint", /operant-verify-compose\.mjs/],
    ["deployment verifier fingerprint", /operant-verify-deploy\.mjs/],
    ["Slack manifest probe fingerprint", /slack-manifest-probe\.mjs/],
    ["report redaction fingerprint", /operant-report-redaction\.mjs/],
    ["report redaction verifier fingerprint", /operant-verify-report-redaction\.mjs/],
    ["completion audit verifier fingerprint", /operant-verify-completion-audit\.mjs/],
    ["final report fingerprint", /operant-final-report\.mjs/],
    ["local acceptance fingerprint", /operant-local-acceptance\.mjs/],
    ["input hash check", /fileSha256/],
    ["Compose report env file loading", /loadComposeReportEnv/],
    ["Compose report live env overlay loading", /report\.liveEnvPath[\s\S]*live env file/],
    ["Compose runtime env precedence", /composeRuntimeEnv/],
    ["Compose runtime env source reporting", /runtimeEnvSource[\s\S]*process env live\/model keys/],
    ["placeholder env rejection", /isPlaceholderValue/],
    ["report fingerprints", /evidenceInputs/],
    ["strict live report validation", /checkStrictLiveReports/],
    ["pre-completion report guard", /OPERANT_ALLOW_PRE_COMPLETION_AUDIT_REPORT/],
    ["live report record delta validation", /operantRecordDeltas/],
    ["live report approval probe validation", /approvalProbe[\s\S]*policyNames[\s\S]*approval count did not increase/],
    ["live report Slack timestamp ordering", /slackTimestampAfter[\s\S]*Slack thread reply timestamp did not follow parent timestamp[\s\S]*Slack approval completion timestamp did not follow approval UI timestamp/],
    ["live report DM timestamp ordering", /dmProbe[\s\S]*DM reply timestamp did not follow DM parent timestamp/],
    ["live report denied wait validation", /noReplyObservedMs[\s\S]*missing denied-user no-reply observation duration/],
    ["live report strict flag validation", /requireOperantRecords/],
    ["live report OpenClaw check validation", /missingRequiredOpenClawChecks/],
    ["live report OpenClaw usage-cost validation", /requiredStrictOpenClawChecks[\s\S]*usage-cost/],
    ["live report completed OpenClaw check validation", /missingCompletedOpenClawChecks/],
    ["live report OpenClaw check assertion validation", /missingOpenClawCheckAssertions[\s\S]*status-gateway-reachable[\s\S]*secrets-reload-ok:true[\s\S]*usage-cost-numeric-totals[\s\S]*security-critical:0[\s\S]*channels-status-probe:true/],
    ["live report base URL validation", /baseUrl.*Compose baseUrl/],
    ["live report format validation", /operant\.live-e2e-report\.v1/],
    ["live report descriptor sha validation", /descriptor\?\.sha256[\s\S]*did not match Compose descriptor/],
    ["live report descriptor generatedAt validation", /descriptor\?\.generatedAt[\s\S]*generatedAt did not match Compose descriptor/],
    ["live report descriptor path validation", /liveReportDescriptorPathFailure[\s\S]*must be under \.operant/],
    ["post-restart live report freshness validation", /post-restart live report must be generated after pre-restart live report/],
    ["pre and post live report distinctness validation", /pre-restart and post-restart live report sha256 values must be distinct/],
    ["restart-boundary timestamp validation", /Compose restart step missing valid recordedAt timestamp[\s\S]*post-restart live report must be generated after Compose restart/],
    ["live report env target validation", /mismatchedLiveReportField[\s\S]*did not match Compose env Slack channel[\s\S]*did not match Compose env DM channel[\s\S]*did not match Compose env Slack team/],
    ["input mtime check", /staleComposeEvidenceInputs/],
    ["report generatedAt", /reportGeneratedAtMs/],
  ]);
  await patternCheck("tests", "dashboard browser E2E gate", "scripts/operant-dashboard-e2e.mjs", [
    ["managed Postgres", /Initializing temporary Postgres/],
    ["Chrome DevTools driver", /Page\.captureScreenshot[\s\S]*remote-debugging-port/],
    ["credential setup flow", /#credentials-form[\s\S]*adminLoginToken[\s\S]*slackBotToken[\s\S]*modelApiKey/],
    ["user role flow", /#role-form[\s\S]*usage_analyst[\s\S]*#user-form/],
    ["integration credential flow", /#integration-credential-form[\s\S]*SecretRef/],
    ["policy evaluation", /#policy-form[\s\S]*#policy-result[\s\S]*allow/],
    ["approval decision", /#approval-form[\s\S]*data-status="approved"/],
    ["safe OpenClaw stubs", /fakeOpenClaw[\s\S]*args\[0\] === "config"[\s\S]*args\[1\] === "validate"[\s\S]*args\[0\] === "secrets"[\s\S]*args\[1\] === "reload"/],
    ["retention export wipe", /#queue-export[\s\S]*#retention-purge[\s\S]*#queue-wipe/],
    ["masked no-plaintext assertion", /Dashboard leaked plaintext secret/],
    ["responsive screenshots", /\.operant[\s\S]*dashboard-e2e[\s\S]*desktop[\s\S]*tablet[\s\S]*mobile/],
    ["console clean assertion", /Browser console errors[\s\S]*Browser page errors/],
  ]);
  await patternCheck("tests", "Completion audit synthetic verifier coverage", "scripts/operant-verify-completion-audit.mjs", [
    ["synthetic Compose env file", /writeSyntheticEnv/],
    ["evidence input list sync guard", /assertEvidenceInputListsStayInSync[\s\S]*scripts\/operant-compose-e2e\.mjs[\s\S]*scripts\/operant-completion-audit\.mjs/],
    ["scrub process env", /envKeysToScrub/],
    ["assert Compose env usage", /assertAuditUsedComposeEnvFile/],
    ["generated admin token from env file", /OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_synthetic_verify_token/],
    ["live verifier secrets from env file", /OPERANT_LIVE_ADMIN_SLACK_USER_ID=USYNTHETICVERIFY[\s\S]*OPERANT_LIVE_SLACK_TEAM_ID=TSYNTHETICVERIFY[\s\S]*SLACK_BOT_TOKEN=xoxb-synthetic-verify-token[\s\S]*OPERANT_LIVE_DM_CHANNEL_ID=DSYNTHETICVERIFY[\s\S]*OPERANT_LIVE_DENIED_USER_TOKEN=xoxp-synthetic-denied-verify-token/],
    ["seed secrets from env file", /SLACK_APP_TOKEN=xapp-synthetic-verify-token[\s\S]*OPENAI_API_KEY=sk-synthetic-verify-token/],
    ["live env satisfied from Compose env file", /liveCheck\?\.ok === true/],
    ["live env overlay synthetic coverage", /writeSyntheticLiveEnv[\s\S]*assertAuditUsedLiveEnvFile/],
    ["process env synthetic coverage", /assertAuditUsedProcessEnv[\s\S]*process env live\/model keys/],
    ["placeholder env rejection", /writePlaceholderEnv[\s\S]*missing or placeholder env/],
    ["provider-specific model key mismatch rejection", /writeMismatchedProviderEnv[\s\S]*model API key for provider anthropic/],
    ["pinned live report rejection", /live report sha256 did not match Compose descriptor/],
    ["weak record rejection", /missing positive jobs record delta/],
    ["weak OpenClaw-check rejection", /skipped OpenClaw checks/],
    ["weak missing required OpenClaw check rejection", /missing OpenClaw checks: usage-cost/],
    ["weak OpenClaw-check result rejection", /missing completed OpenClaw check result/],
    ["weak OpenClaw-check assertion rejection", /missing OpenClaw check assertion\(s\): usage-cost:usage-cost-numeric-totals/],
    ["weak status assertion rejection", /missing OpenClaw check assertion\(s\): status:status-gateway-reachable/],
    ["weak secrets-reload assertion rejection", /missing OpenClaw check assertion\(s\): secrets-reload:secrets-reload-ok:true/],
    ["weak channels-status assertion rejection", /missing OpenClaw check assertion\(s\): channels-status:channels-status-slack-connected,channels-status-probe:true/],
    ["weak approval-completion rejection", /missing Slack approval completion timestamp/],
    ["weak Slack reply ordering rejection", /Slack thread reply timestamp did not follow parent timestamp/],
    ["weak Slack approval parent ordering rejection", /Slack approval UI timestamp did not follow approval parent timestamp/],
    ["weak approval timestamp order rejection", /Slack approval completion timestamp did not follow approval UI timestamp/],
    ["weak base URL rejection", /did not match Compose baseUrl/],
    ["weak result channel rejection", /result channelId .* did not match top-level channelId/],
    ["weak Slack team rejection", /did not match Compose env Slack team/],
    ["weak approval policy evidence rejection", /missing Operant approval policy evidence/],
    ["weak approval count rejection", /approval count did not increase/],
    ["external live report descriptor rejection", /live report descriptor path must be repo-relative/],
    ["weak observation-sync rejection", /skipped OpenClaw observation sync/],
    ["weak DM reply rejection", /missing DM reply timestamp/],
    ["weak DM probe channel rejection", /DM probe channel .* did not match top-level dmChannelId/],
    ["weak DM ordering rejection", /DM reply timestamp did not follow DM parent timestamp/],
    ["weak denied-user rejection", /missing denied-user probe timestamp/],
    ["weak denied no-reply duration rejection", /missing denied-user no-reply observation duration/],
    ["weak membership channel rejection", /did not match top-level channelId/],
    ["weak membership method rejection", /was not checked with conversations\.members/],
    ["weak allowed-user membership rejection", /target-channel membership missing allowed test user/],
    ["weak denied-user membership rejection", /target-channel membership missing denied test user/],
    ["weak approval UI rejection", /missing Slack approval UI timestamp/],
    ["weak Operant approval probe rejection", /missing Operant approval probe id/],
  ]);
  await patternCheck("tests", "Evidence report secret redaction helper", "scripts/operant-report-redaction.mjs", [
    ["exact env redaction", /sensitiveEnvValues/],
    ["dynamic integration credential redaction", /integrationCredentialEnvNames[\s\S]*OPERANT_LIVE_INTEGRATION_CREDENTIALS[\s\S]*integrationCredentialSensitiveValues[\s\S]*OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON[\s\S]*secretValueEnv/],
    ["Slack token pattern redaction", /secretLikePattern/],
    ["Operant token pattern redaction", /operant_\(\?:admin\|internal\|pg\)_/],
    ["recursive redaction", /redactSecretMaterial/],
    ["report leak assertion", /assertNoSecretMaterial/],
    ["previous report archive helper", /archiveExistingJsonReport/],
    ["shared JSON report writer", /writeRedactedJsonReport/],
  ]);
  await patternCheck("tests", "Evidence report redaction verifier coverage", "scripts/operant-verify-report-redaction.mjs", [
    ["live report writer self-test", /operant-live-e2e\.mjs[\s\S]*--self-test-report-redaction/],
    ["Compose report writer self-test", /operant-compose-e2e\.mjs[\s\S]*--self-test-report-redaction/],
    ["local acceptance report writer self-test", /operant-local-acceptance\.mjs[\s\S]*--self-test-report-redaction/],
    ["archived report redaction self-test", /assertReportArchiveRedacted/],
    ["dynamic integration credential redaction self-test", /assertDynamicIntegrationCredentialRedaction[\s\S]*GITHUB_TOKEN[\s\S]*CUSTOMER_WEBHOOK_SECRET[\s\S]*inline-dynamic-integration-redaction-secret/],
    ["persisted report leak assertion", /assertReportRedacted/],
    ["synthetic token-shaped values", /xoxb-report-redaction-verify-token[\s\S]*sk-report-redaction-verify-token/],
  ]);
  await patternCheck("tests", "Compose non-live smoke command", "package.json", [
    ["dashboard browser E2E command", /"dashboard:e2e":\s*"node scripts\/operant-dashboard-e2e\.mjs"/],
    ["compose live seed script", /"compose:live":\s*"node scripts\/operant-compose-e2e\.mjs --skip-live --skip-post-restart-live --skip-completion-audit"/],
    ["compose smoke script", /"compose:smoke":\s*"node scripts\/operant-compose-e2e\.mjs --skip-live --synthetic-credential-seed --skip-completion-audit"/],
    ["sandbox compose smoke script", /"compose:smoke:sandbox":\s*"node scripts\/operant-compose-e2e\.mjs --skip-live --synthetic-credential-seed --skip-completion-audit --file docker-compose\.sandbox\.yml --profile queue --report \.operant\/compose-sandbox-smoke-report\.json --allow-blocked --down --down-volumes"/],
    ["compose wrapper dry-run verification", /node scripts\/operant-compose\.mjs --dry-run --env \.env\.example config/],
    ["compose profile dry-run verification", /node scripts\/operant-compose\.mjs --dry-run --env \.env\.example --profile queue config/],
    ["compose overlay dry-run verification", /node scripts\/operant-compose\.mjs --dry-run --env \.env\.example --file docker-compose\.sandbox\.yml config/],
    ["compose wrapper redaction self-test", /node scripts\/operant-compose\.mjs --self-test-redaction/],
    ["Slack manifest probe self-test", /node scripts\/slack-manifest-probe\.mjs --self-test/],
    ["Compose E2E arg validation self-test", /node scripts\/operant-compose-e2e\.mjs --self-test-arg-validation/],
    ["handoff helper fresh-checkout self-test", /node scripts\/operant-handoff\.mjs --self-test/],
    ["report redaction verifier", /node scripts\/operant-verify-report-redaction\.mjs/],
    ["report redaction helper syntax", /node --check scripts\/operant-report-redaction\.mjs/],
    ["doctor arg validation self-test", /node scripts\/operant-doctor\.mjs --self-test-arg-validation/],
    ["doctor env validation self-test", /node scripts\/operant-doctor\.mjs --self-test-env-validation/],
    ["live E2E arg validation self-test command", /node scripts\/operant-live-e2e\.mjs --self-test-arg-validation/],
    ["live E2E env loading self-test command", /node scripts\/operant-live-e2e\.mjs --self-test-env-loading/],
    ["live E2E identity consistency self-test command", /node scripts\/operant-live-e2e\.mjs --self-test-identity-consistency/],
    ["live E2E OpenClaw assertion self-test command", /node scripts\/operant-live-e2e\.mjs --self-test-openclaw-assertions/],
    ["completion audit synthetic verifier", /node scripts\/operant-verify-completion-audit\.mjs/],
    ["compose config env-file script", /"compose:config":\s*"node scripts\/operant-compose\.mjs config"/],
    ["compose up env-file script", /"compose:up":\s*"node scripts\/operant-compose\.mjs up --build"/],
    ["compose down env-file script", /"compose:down":\s*"node scripts\/operant-compose\.mjs down"/],
    ["init env argument validation verifier", /node scripts\/operant-init-env\.mjs --self-test-arg-validation/],
    ["init env permission verifier", /node scripts\/operant-init-env\.mjs --self-test-permissions/],
  ]);
  await patternCheck("tests", "Live acceptance handoff helper", "scripts/operant-handoff.mjs", [
    ["one-human denied flag usage", /--denied-use-allowed-user[\s\S]*Temporarily deny the allowed user/],
    ["one-human denied parser", /deniedUseAllowedUser[\s\S]*OPERANT_LIVE_DENIED_USE_ALLOWED_USER/],
    ["one-human denied forwarding", /if \(parsed\.deniedUseAllowedUser\)[\s\S]*livePreflightArgs\.push\("--denied-use-allowed-user"\)[\s\S]*composeArgs\.push\("--denied-use-allowed-user"\)/],
    ["one-human denied self-test", /live acceptance parser did not preserve one-human manual strict options/],
    ["stale generated handoff fallback", /isStaleHandoffReportSnapshot[\s\S]*Generated handoff bundle has stale live-report snapshot fields[\s\S]*runDynamicHandoffVerify/],
  ]);
  await patternCheck("tests", "Doctor preflight rejects placeholder secrets", "scripts/operant-doctor.mjs", [
    ["Postgres password required", /"POSTGRES_PASSWORD"/],
    ["DATABASE_URL required", /"DATABASE_URL"/],
    ["Admin login token required", /"OPERANT_ADMIN_LOGIN_TOKEN"/],
    ["Postgres placeholder rejected", /change-me-postgres-password/],
    ["Admin login token placeholder rejected", /operant_admin_\.\.\./],
    ["generic base placeholder rejection", /validateEnv[\s\S]*isPlaceholderValue\(envFile\[key\]\)[\s\S]*self-test did not reject generic placeholder/],
    ["CLI help and argument validation", /--self-test-arg-validation[\s\S]*printUsage[\s\S]*validateArgs[\s\S]*Unknown option/],
    ["base env validation self-test", /--self-test-env-validation[\s\S]*runEnvValidationSelfTest/],
    ["DATABASE_URL format validation", /validPostgresUrl/],
    ["DATABASE_URL password match", /DATABASE_URL should use the generated POSTGRES_PASSWORD/],
    ["live preflight flag", /--live-preflight/],
    ["live env overlay", /liveEnvPath[\s\S]*loadLiveEnv[\s\S]*mergeRuntimeEnv/],
    ["live verifier env groups", /liveEnvGroups[\s\S]*OPERANT_LIVE_ADMIN_SLACK_USER_ID[\s\S]*OPERANT_LIVE_DM_CHANNEL_ID[\s\S]*OPERANT_LIVE_DENIED_USER_TOKEN/],
    ["live credential seed groups", /liveSeedEnvGroups[\s\S]*OPERANT_LIVE_SLACK_APP_TOKEN[\s\S]*OPENAI_API_KEY/],
    ["local acceptance model placeholder rejected", /sk-local-acceptance-redaction-token/],
    ["live preflight shape checks", /livePreflightShapeChecks[\s\S]*expected a bot token starting with xoxb-[\s\S]*expected an app-level token starting with xapp-/],
    ["live preflight Slack team shape check", /livePreflightShapeChecks[\s\S]*OPERANT_LIVE_SLACK_TEAM_ID[\s\S]*expected a Slack workspace\/team ID starting with T/],
    ["malformed live preflight self-test", /malformedErrors[\s\S]*did not reject malformed Slack values/],
    ["live preflight distinct user checks", /livePreflightDistinctChecks[\s\S]*denied-user probe exercises policy denial/],
    ["duplicate user token self-test", /duplicateUserErrors[\s\S]*did not reject duplicate Slack user tokens/],
    ["provider-specific model key mismatch self-test", /mismatchedModelErrors[\s\S]*provider-specific model key mismatch/],
    ["live preflight Slack auth test", /runSlackAuthPreflight[\s\S]*auth\.test[\s\S]*same Slack user/],
    ["live preflight bot token kind check", /(?=[\s\S]*assertSlackBotTokenAuth)(?=[\s\S]*must be a Slack bot token)(?=[\s\S]*user token in the bot-token slot)/],
    ["live preflight bot scope check", /requiredLiveBotScopes[\s\S]*assertSlackBotScopes[\s\S]*x-oauth-scopes[\s\S]*missingScopes[\s\S]*missing required OpenClaw Slack bot scopes/],
    ["live preflight missing scope self-test", /missing-assistant-scope[\s\S]*did not reject missing OpenClaw bot scopes/],
    ["configured bot user ID consistency", /mismatched configured bot user ID[\s\S]*configuredBotUserId[\s\S]*does not match Slack bot token auth\.test user_id/],
    ["configured denied user ID consistency", /mismatched configured denied-user ID[\s\S]*configuredDeniedUserId[\s\S]*does not match denied Slack user token auth\.test user_id/],
    ["Slack team consistency", /mismatched configured Slack team ID[\s\S]*Slack tokens from different workspaces[\s\S]*assertSlackTeamMatch[\s\S]*team_id/],
    ["live preflight Socket Mode app token test", /slackAppsConnectionsOpen[\s\S]*apps\.connections\.open[\s\S]*wss:\/\//],
    ["live preflight Slack reachability test", /slackConversationInfo[\s\S]*conversations\.info[\s\S]*slackConversationMembers[\s\S]*conversations\.members[\s\S]*runSlackAuthPreflight[\s\S]*Slack bot target channel[\s\S]*Slack bot DM channel[\s\S]*Slack target channel/],
    ["live preflight membership self-test", /missing denied-user channel membership/],
    ["live preflight model auth test", /runModelAuthPreflight[\s\S]*ANTHROPIC_API_BASE_URL[\s\S]*OPENAI_API_BASE_URL[\s\S]*\/models[\s\S]*data array/],
    ["doctor authenticated gateway scoped checks", /openClawGatewayScopedCommand[\s\S]*--url ws:\/\/127\.0\.0\.1:18789[\s\S]*OPENCLAW_GATEWAY_TOKEN[\s\S]*openclaw secrets reload[\s\S]*openclaw exec approvals/],
    ["doctor OpenClaw pairing guidance", /openClawPairingGuidance[\s\S]*openclaw devices list[\s\S]*openclaw devices approve <requestId>[\s\S]*operator\.talk\.secrets/],
    ["offline Slack auth skip", /--skip-slack-auth-test/],
    ["offline model auth skip", /--skip-model-auth-test/],
    ["live preflight self-test", /--self-test-live-preflight/],
  ]);
  await patternCheck("tests", "Live E2E identity consistency coverage", "scripts/operant-live-e2e.mjs", [
    ["identity helper", /function assertSlackIdentityMatch/],
    ["bot token helper", /function assertSlackBotTokenIdentity[\s\S]*must be a Slack bot token/],
    ["bot scope helper", /function assertSlackBotScopes[\s\S]*x-oauth-scopes[\s\S]*missingScopes[\s\S]*requiredLiveBotScopes/],
    ["user token helper", /function assertSlackUserTokenIdentity/],
    ["distinct user helper", /function assertDistinctSlackUsers/],
    ["team helper", /function assertSlackTeamMatch/],
    ["bot token kind check", /assertSlackBotTokenIdentity\("Slack bot token", botIdentity\)/],
    ["bot token kind self-test", /assertSlackBotTokenIdentity\("Slack bot token", \{ user_id: "UBOT", bot_id: "BBOT" \}\)[\s\S]*user token as bot token/],
    ["configured bot user check", /assertSlackIdentityMatch\("configured bot user ID", configuredBotUserId, botIdentity\.user_id/],
    ["test user token kind check", /assertSlackUserTokenIdentity\("Slack test-user token", userIdentity\)/],
    ["configured team check", /assertSlackTeamMatch\("configured Slack team ID", configuredSlackTeamId, "Slack bot token auth\.test team_id", botTeamId\)/],
    ["bot test user team check", /assertSlackTeamMatch\("Slack bot token auth\.test team_id", botTeamId, "Slack test-user token auth\.test team_id", userTeamId\)/],
    ["configured denied user check", /assertSlackIdentityMatch\("configured denied-user ID", deniedUserIdOverride, deniedIdentity\.user_id/],
    ["denied user token kind check", /assertSlackUserTokenIdentity\("denied Slack user token", deniedIdentity\)/],
    ["allowed denied distinct check", /assertDistinctSlackUsers\("Slack test-user token", testUserId, "denied Slack user token", deniedUserId\)/],
    ["denied user team check", /assertSlackTeamMatch\("Slack bot\/user auth\.test team_id", slackTeamId, "denied Slack user token auth\.test team_id", deniedTeamId\)/],
    ["target channel membership check", /slackConversationMembers[\s\S]*conversations\.members[\s\S]*Slack target channel[\s\S]*channelMembership/],
    ["identity self-test", /--self-test-identity-consistency[\s\S]*runIdentityConsistencySelfTest/],
    ["OpenClaw check pairing guidance", /isOpenClawPairingRequired[\s\S]*pairing required\|device is not approved[\s\S]*openClawPairingGuidance[\s\S]*openclaw devices approve <requestId>[\s\S]*operator\.talk\.secrets/],
  ]);
  await patternCheck("tests", "Final verification report generator", "scripts/operant-final-report.mjs", [
    ["completion audit JSON", /operant-completion-audit\.mjs",\s*"--json",\s*"--allow-blocked"/],
    ["Compose evidence", /compose-e2e-report\.json/],
    ["automated Slack user-token probe evidence", /compose-e2e-auto-report\.json/],
    ["automated Slack user-token probe section", /Automated Slack User-Token Probe Evidence/],
    ["non-live Compose smoke evidence", /compose-smoke-report\.json/],
    ["non-live Compose smoke section", /Non-Live Compose Smoke Evidence/],
    ["sandbox smoke evidence", /compose-sandbox-smoke-report\.json/],
    ["sandbox smoke section", /Sandbox Compose Smoke Evidence/],
    ["explicit smoke result", /report\.smokePassed \?\? report\.runtimePassed/],
    ["live E2E evidence", /live-e2e-post-restart-report\.json/],
    ["Slack DM probe evidence", /slack-dm-probe-report\.json/],
    ["Slack DM probe section", /Slack DM Probe Evidence/],
    ["live report descriptor fingerprints", /generatedAt=[\s\S]*sha256=/],
    ["local acceptance evidence", /local-acceptance-report\.json/],
    ["objective success criteria matrix", /Objective Success Criteria Matrix/],
    ["blocked requirements", /Blocked Requirements/],
    ["live completion handoff", /Live Completion Handoff[\s\S]*Required private inputs[\s\S]*deploy\/slack\/live\.env\.example[\s\S]*OPERANT_LIVE_SLACK_TEAM_ID[\s\S]*OPERANT_LIVE_BOT_USER_ID[\s\S]*OPERANT_LIVE_DENIED_USER_ID[\s\S]*OPERANT_LIVE_ALLOWED_DM_USER_IDS[\s\S]*OPERANT_LIVE_ALLOWED_CHANNEL_IDS[\s\S]*OPERANT_LIVE_APPROVER_SLACK_USER_IDS[\s\S]*OPERANT_LIVE_APPROVAL_PROMPT[\s\S]*OPERANT_LIVE_INTEGRATION_CREDENTIALS[\s\S]*OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON[\s\S]*secretValueEnv[\s\S]*auth\.test[\s\S]*generated OpenClaw Slack config[\s\S]*api\/integrations\/credentials[\s\S]*pnpm live:preflight -- --env \.env\.acme --live-env \.env\.acme\.live[\s\S]*pnpm live:e2e -- --env \.env\.acme --live-env \.env\.acme\.live[\s\S]*pnpm compose:e2e -- --env \.env\.acme --live-env \.env\.acme\.live[\s\S]*--allow-blocked/],
    ["final report Slack membership verifier guidance", /Live Completion Handoff[\s\S]*conversations\.members/],
    ["final report result-level Slack identity guidance", /Live Completion Handoff[\s\S]*live-e2e-report\.json[\s\S]*live-e2e-post-restart-report\.json[\s\S]*result-level Slack identity evidence[\s\S]*result\.channelId[\s\S]*result\.slackTeamId[\s\S]*result\.botUserId[\s\S]*top-level bot identity/],
    ["final report live report membership evidence guidance", /Live Completion Handoff[\s\S]*live-e2e-report\.json[\s\S]*live-e2e-post-restart-report\.json[\s\S]*channelMembership\.method[\s\S]*conversations\.members[\s\S]*channelMembership\.channelId[\s\S]*channelMembership\.requiredUserIds[\s\S]*allowed test-user Slack ID[\s\S]*same-user-temporary-deny/],
    ["final report app-level token rationale", /Live Completion Handoff[\s\S]*apps\.connections\.open[\s\S]*connections:write[\s\S]*Socket Mode WebSocket URL[\s\S]*bot token[\s\S]*cannot replace the app-level token/],
    ["final report raw Socket Mode probe handoff", /Live Completion Handoff[\s\S]*pnpm slack:socket-probe[\s\S]*Socket Mode is not turned on[\s\S]*Event Subscriptions[\s\S]*strict Compose E2E/],
    ["final report installed Slack manifest probe handoff", /Live Completion Handoff[\s\S]*pnpm slack:manifest-probe[\s\S]*app_configurations:read[\s\S]*slack-manifest-probe-report\.json/],
    ["final report DM probe handoff", /Live Completion Handoff[\s\S]*pnpm slack:dm-probe[\s\S]*slack-dm-probe-report\.json[\s\S]*conversations\.open[\s\S]*strict Compose/],
    ["final report automated token probe handoff", /Live Completion Handoff[\s\S]*compose-e2e-auto-report\.json[\s\S]*OPERANT_LIVE_MANUAL_SLACK_POSTS=0[\s\S]*OPERANT_LIVE_MANUAL_SLACK_NUDGE=0/],
    ["final report OpenClaw operator pairing handoff", /Live Completion Handoff[\s\S]*pairing required[\s\S]*openclaw devices list[\s\S]*openclaw devices approve <requestId>[\s\S]*operator\.read[\s\S]*operator\.approvals[\s\S]*operator\.talk\.secrets[\s\S]*operator\.admin/],
    ["current local handoff bundle", /Current local handoff bundle[\s\S]*live-acceptance\.env[\s\S]*live-acceptance-handoff\.md[\s\S]*verify-handoff\.sh[\s\S]*run-live-acceptance\.sh --preflight-only[\s\S]*pnpm handoff:readiness[\s\S]*pnpm handoff:verify[\s\S]*pnpm live:acceptance:preflight[\s\S]*pnpm live:acceptance/],
    ["handoff helper placeholder-state wording", /process-env live\/model override names and placeholder state only, never values/],
    ["commands section", /Strict customer acceptance/],
    ["final report one-human denied-policy guidance", /denied-policy proof is one-human by default[\s\S]*temporarily denies the allowed test user[\s\S]*restores policy/],
    ["strict live preflight overlay command", /pnpm live:preflight -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["Slack manifest probe overlay command", /pnpm slack:manifest-probe -- --env \.env\.acme\.live/],
    ["Slack DM probe overlay command", /pnpm slack:dm-probe -- --env \.env\.acme --live-env \.env\.acme\.live/],
    ["automated Slack user-token probe command", /OPERANT_LIVE_MANUAL_SLACK_POSTS=0 OPERANT_LIVE_MANUAL_SLACK_NUDGE=0 pnpm compose:e2e -- --env \.env\.acme --live-env \.env\.acme\.live --report \.operant\/compose-e2e-auto-report\.json --allow-blocked --down --down-volumes/],
    ["live env overlay command", /--live-env \.env\.acme\.live/],
    ["strict Compose live-env command before shell alternative", /pnpm compose:e2e -- --env \.env\.acme --live-env \.env\.acme\.live[\s\S]*Shell-export alternative/],
    ["final report shell export keeps admin token optional", /Shell-export alternative when not using --live-env:[\s\S]*# Normally supplied by the generated Compose env passed with --env\.[\s\S]*# export OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_\.\.\./],
  ]);
  await patternCheck("tests", "Final report command", "package.json", [
    ["report final script", /"report:final":\s*"node scripts\/operant-final-report\.mjs"/],
    ["live preflight script", /"live:preflight":\s*"node scripts\/operant-doctor\.mjs --preflight-only --live-preflight"/],
    ["manual live preflight script", /"live:preflight:manual":\s*"node scripts\/operant-doctor\.mjs --preflight-only --live-preflight --manual-slack-posts"/],
    ["manual live E2E script", /"live:e2e:manual":\s*"node scripts\/operant-live-e2e\.mjs --manual-slack-posts --manual-slack-nudge"/],
    ["manual Compose E2E script", /"compose:e2e:manual":\s*"node scripts\/operant-compose-e2e\.mjs --manual-slack-posts --manual-slack-nudge"/],
    ["handoff readiness script", /"handoff:readiness":\s*"node scripts\/operant-handoff\.mjs readiness"/],
    ["handoff verifier script", /"handoff:verify":\s*"node scripts\/operant-handoff\.mjs verify"/],
    ["live acceptance preflight helper script", /"live:acceptance:preflight":\s*"node scripts\/operant-handoff\.mjs live-acceptance --preflight-only"/],
    ["live acceptance helper script", /"live:acceptance":\s*"node scripts\/operant-handoff\.mjs live-acceptance"/],
  ]);
  await patternCheck("tests", "Local acceptance report generator", "scripts/operant-local-acceptance.mjs", [
    ["verify step", /"Static verification",\s*"pnpm",\s*\["verify"\]/],
    ["smoke step", /"Managed local smoke",\s*"pnpm",\s*\["smoke:local"\]/],
    ["Compose E2E step", /"Strict Compose E2E blocked-mode evidence"/],
    ["local Compose E2E report does not clobber strict live evidence", /localComposeE2eReportPath[\s\S]*local-acceptance-compose-e2e-report\.json[\s\S]*"--report"[\s\S]*localComposeE2eReportPath/],
    ["isolated Compose project", /OPERANT_LOCAL_ACCEPTANCE_PROJECT_NAME[\s\S]*--project-name/],
    ["free Compose ports", /freePorts[\s\S]*--http-port[\s\S]*localHttpPort[\s\S]*--postgres-port[\s\S]*localPostgresPort[\s\S]*--gateway-port[\s\S]*localGatewayPort/],
    ["queue profile Compose smoke", /"compose:smoke"[\s\S]*"--profile"[\s\S]*"queue"/],
    ["sandbox include flag", /includeSandbox/],
    ["sandbox Compose smoke", /"Docker sandbox overlay smoke evidence"[\s\S]*"compose:smoke:sandbox"/],
    ["Compose smoke cleanup", /"compose:smoke"[\s\S]*"--down"[\s\S]*"--down-volumes"/],
    ["objective complete field", /objectiveComplete/],
    ["completion audit blockers", /auditBlocked/],
    ["final report artifact verification", /verifyFinalReportArtifact/],
    ["final report current audit count verification", /current audit summary count[\s\S]*current local-acceptance audit count/],
    ["final report handoff helper placeholder-state verification", /handoff helper reports placeholder state only by name[\s\S]*process-env live\\\/model override names and placeholder state only, never values/],
    ["final report verified artifact status verification", /requireVerifiedArtifact[\s\S]*Final report artifact: pass/],
    ["final report current local acceptance evidence verification", /requireCurrentLocalAcceptanceReport[\s\S]*current local acceptance generated timestamp[\s\S]*current local acceptance totals/],
    ["final report artifact verifier self-test", /--self-test-final-report-artifact[\s\S]*runFinalReportArtifactSelfTest[\s\S]*stale local acceptance timestamp[\s\S]*stale local acceptance totals/],
    ["final report shell export admin token self-test", /shell export keeps admin token commented[\s\S]*# export OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_/],
    ["final report post-refresh acceptance report update", /finalReportWithVerifiedArtifact[\s\S]*writeAcceptanceReport\(steps, finalAudit, finalReportArtifact\)/],
    ["final report final local report resync", /Refresh final report after final local acceptance report[\s\S]*requireCurrentLocalAcceptanceReport:\s*true/],
    ["final report env-file Compose config command", /pnpm compose:config -- --env \\\.env\\\.acme/],
    ["final report env-file Compose up command", /pnpm compose:up -- --env \\\.env\\\.acme -d/],
    ["final report env-driven live bot command", /pnpm compose:live -- --env \\\.env\\\.acme --live-env \\\.env\\\.acme\\\.live/],
    ["final report live handoff artifact check", /Live Completion Handoff[\s\S]*pnpm live:preflight -- --env \\\.env\\\.acme[\s\S]*pnpm live:e2e -- --env \\\.env\\\.acme --live-env \\\.env\\\.acme\\\.live[\s\S]*structured integration credential live handoff[\s\S]*OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON[\s\S]*secretValueEnv[\s\S]*OpenClaw operator pairing handoff/],
    ["final report step", /"Final report",\s*"pnpm",\s*\["report:final"\]/],
    ["final report refresh", /Refresh final report with local acceptance evidence/],
    ["CLI help and argument validation", /--self-test-arg-validation[\s\S]*printUsage[\s\S]*validateArgs[\s\S]*Unknown option/],
    ["local report redaction", /redactSecretMaterial/],
    ["local console redaction", /redactString\(\[command, \.\.\.args\]\.join\(" "\)[\s\S]*stdoutTail: tail\(stdout\)/],
  ]);
  await patternCheck("tests", "Local acceptance command", "package.json", [
    ["acceptance local script", /"acceptance:local":\s*"node scripts\/operant-local-acceptance\.mjs"/],
    ["local acceptance arg validation self-test", /operant-local-acceptance\.mjs --self-test-arg-validation/],
    ["local acceptance final report artifact self-test", /operant-local-acceptance\.mjs --self-test-final-report-artifact/],
  ]);

  const docker = commandAvailable("docker");
  addCheck("blocked-live", "Docker command available for Compose runtime", docker.ok, docker.detail, docker.ok ? "pass" : "blocked");
  const compose = spawnSync("docker", ["compose", "version"], { cwd: repoRoot, encoding: "utf8" });
  addCheck("blocked-live", "Docker Compose available", compose.status === 0, compose.status === 0 ? "docker compose version ok" : "docker compose unavailable", compose.status === 0 ? "pass" : "blocked");
  const env = composeRuntimeEnv();
  const envSource = runtimeEnvSource();
  const missingLiveEnv = missingEnvGroups(env, liveVerifierEnvGroups(env));
  addStrictOrAdvisoryCheck(
    "Live Slack verifier credentials present",
    missingLiveEnv.length === 0,
    missingLiveEnv.length ? `missing or placeholder env: ${missingLiveEnv.join(", ")}${envSource}` : `required live env present${envSource}`,
    missingLiveEnv.length
      ? `optional strict live credentials missing or placeholder: ${missingLiveEnv.join(", ")}${envSource}; not a default completion blocker`
      : `optional strict live credentials present${envSource}`,
  );
  const missingSeedEnv = missingEnvGroups(env, composeSeedEnvGroups);
  const seedCredentialProblems = [...missingSeedEnv];
  const modelCredentialError = modelCredentialErrorForProvider(env);
  if (modelCredentialError) seedCredentialProblems.push(modelCredentialError);
  addStrictOrAdvisoryCheck(
    "Live credential-seed secrets present",
    seedCredentialProblems.length === 0,
    seedCredentialProblems.length ? `missing or placeholder env: ${seedCredentialProblems.join(", ")}${envSource}` : `required credential seed env present${envSource}`,
    seedCredentialProblems.length
      ? `optional live credential-seed secrets missing or placeholder: ${seedCredentialProblems.join(", ")}${envSource}; not a default completion blocker`
      : `optional live credential-seed secrets present${envSource}`,
  );
  await checkNonLiveComposeSmokeReport(composeSmokeReportPath, "Non-live Compose smoke evidence report", ["docker-compose.yml"]);
  await checkNonLiveComposeSmokeReport(composeSandboxSmokeReportPath, "Docker sandbox Compose smoke evidence report", ["docker-compose.yml", "docker-compose.sandbox.yml"]);
  await checkComposeE2EReport();

  const failed = checks.filter((check) => !check.ok && check.status !== "blocked");
  const blocked = checks.filter((check) => check.status === "blocked");
  const result = {
    objective: "Build Operant Docker Compose-first OpenClaw Slack control plane",
    totals: {
      checks: checks.length,
      passed: checks.filter((check) => check.ok).length,
      failed: failed.length,
      blocked: blocked.length,
    },
    complete: failed.length === 0 && blocked.length === 0,
    checks,
  };

  if (jsonOutput) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write("# Operant Completion Audit\n\n");
    process.stdout.write(`Objective: ${result.objective}\n\n`);
    process.stdout.write(`Checks: ${result.totals.passed}/${result.totals.checks} passed, ${result.totals.failed} failed, ${result.totals.blocked} blocked.\n\n`);
    for (const check of checks) {
      const marker = check.ok ? "PASS" : check.status === "blocked" ? "BLOCKED" : "FAIL";
      process.stdout.write(`- ${marker} [${check.group}] ${check.requirement}: ${check.evidence}\n`);
    }
  }

  if (failed.length > 0) process.exit(1);
  if (blocked.length > 0 && !allowBlocked) process.exit(2);
}

await main();
