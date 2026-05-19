#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdtemp, mkdir, rm, stat, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const managed = process.argv.includes("--managed");
const childProcesses = [];
let tempRoot = null;

function log(message) {
  process.stdout.write(`${message}\n`);
}

function fail(message) {
  throw new Error(message);
}

function assertSecurityHeaders(response, label) {
  const csp = response.headers.get("content-security-policy") || "";
  if (!csp.includes("default-src 'self'") || !csp.includes("frame-ancestors 'none'")) {
    fail(`${label} response did not include the expected Content-Security-Policy`);
  }
  if (response.headers.get("x-content-type-options") !== "nosniff") {
    fail(`${label} response did not include x-content-type-options: nosniff`);
  }
  if (response.headers.get("x-frame-options") !== "DENY") {
    fail(`${label} response did not include x-frame-options: DENY`);
  }
  if (response.headers.get("referrer-policy") !== "no-referrer") {
    fail(`${label} response did not include referrer-policy: no-referrer`);
  }
}

function commandPath(name, fallbacks = []) {
  return new Promise((resolve) => {
    const child = spawn("sh", ["-lc", `command -v ${name}`], { stdio: ["ignore", "pipe", "ignore"] });
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.on("close", (code) => {
      const resolved = code === 0 ? output.trim() : "";
      resolve(resolved || fallbacks.find(Boolean) || name);
    });
  });
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd || repoRoot,
      env: options.env || process.env,
      stdio: options.quiet ? ["ignore", "pipe", "pipe"] : "inherit",
    });
    let stdout = "";
    let stderr = "";
    if (child.stdout) child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    if (child.stderr) child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      const detail = stderr.trim() || stdout.trim();
      reject(new Error(`${command} ${args.join(" ")} exited ${code}${detail ? `: ${detail}` : ""}`));
    });
  });
}

function spawnManaged(command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: options.cwd || repoRoot,
    env: options.env || process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  childProcesses.push(child);
  child.stdout.on("data", (chunk) => {
    if (options.prefix) process.stdout.write(`[${options.prefix}] ${chunk}`);
  });
  child.stderr.on("data", (chunk) => {
    if (options.prefix) process.stderr.write(`[${options.prefix}] ${chunk}`);
  });
  child.on("error", (error) => {
    process.stderr.write(`${command} failed to start: ${error.message}\n`);
  });
  return child;
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const exited = await Promise.race([
    once(child, "close").then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 2_000)),
  ]);
  if (!exited && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await once(child, "close").catch(() => {});
  }
}

async function cleanup() {
  for (const child of [...childProcesses].reverse()) await stopChild(child);
  if (tempRoot) await rm(tempRoot, { recursive: true, force: true });
}

process.on("SIGINT", async () => {
  await cleanup();
  process.exit(130);
});
process.on("SIGTERM", async () => {
  await cleanup();
  process.exit(143);
});

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
    server.on("error", reject);
  });
}

async function waitFor(name, fn, timeoutMs = 20_000) {
  const start = Date.now();
  let lastError;
  while (Date.now() - start < timeoutMs) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error(`${name} did not become ready: ${lastError?.message || "timed out"}`);
}

async function request(baseUrl, route, options = {}) {
  const headers = { accept: "application/json" };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.internalToken) headers.authorization = `Bearer ${options.internalToken}`;
  Object.assign(headers, options.headers || {});
  const response = await fetch(new URL(route, baseUrl), {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (options.expectSecurityHeaders) assertSecurityHeaders(response, route);
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (options.expectStatus && response.status === options.expectStatus) return payload;
  if (!response.ok) {
    const error = payload?.error || response.statusText;
    throw new Error(`${options.method || "GET"} ${route} failed with ${response.status}: ${error}`);
  }
  if (options.expectStatus && response.status !== options.expectStatus) {
    throw new Error(`${options.method || "GET"} ${route} returned ${response.status}, expected ${options.expectStatus}`);
  }
  return payload;
}

async function requestText(baseUrl, route, options = {}) {
  const headers = {};
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  const response = await fetch(new URL(route, baseUrl), {
    method: options.method || "GET",
    headers,
  });
  if (options.expectSecurityHeaders) assertSecurityHeaders(response, route);
  const text = await response.text();
  if (!response.ok) throw new Error(`${options.method || "GET"} ${route} failed with ${response.status}: ${text || response.statusText}`);
  return text;
}

async function requestRaw(baseUrl, route, options = {}) {
  const headers = { accept: "application/json" };
  if (options.contentType) headers["content-type"] = options.contentType;
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.internalToken) headers.authorization = `Bearer ${options.internalToken}`;
  const response = await fetch(new URL(route, baseUrl), {
    method: options.method || "POST",
    headers,
    body: options.body,
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (options.expectStatus && response.status === options.expectStatus) return payload;
  if (!response.ok) {
    const error = payload?.error || response.statusText;
    throw new Error(`${options.method || "POST"} ${route} failed with ${response.status}: ${error}`);
  }
  if (options.expectStatus && response.status !== options.expectStatus) {
    throw new Error(`${options.method || "POST"} ${route} returned ${response.status}, expected ${options.expectStatus}`);
  }
  return payload;
}

async function login(baseUrl, slackUserId, adminLoginToken) {
  return request(baseUrl, "/api/auth/login", {
    method: "POST",
    body: { slackUserId, adminLoginToken },
  });
}

async function startManagedStack() {
  tempRoot = await mkdtemp(path.join(os.tmpdir(), "operant-smoke-"));
  const dataDir = path.join(tempRoot, "pgdata");
  const socketDir = path.join(tempRoot, "pgsocket");
  const configDir = path.join(tempRoot, "openclaw");
  const fakeOpenClaw = path.join(tempRoot, "fake-openclaw.mjs");
  await mkdir(socketDir);
  await mkdir(configDir);
  await writeFile(fakeOpenClaw, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "status") {
  console.log(JSON.stringify({
    sessions: {
      count: 2,
      recent: [{
        agentId: "main",
        key: "agent:main:slack:channel:smoke",
        kind: "channel",
        sessionId: "smoke-status-session",
        updatedAt: Date.now(),
        inputTokens: 21,
        outputTokens: 34,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 55,
        totalTokensFresh: true,
        model: "gpt-5",
        runtime: "OpenClaw Smoke"
      }, {
        agentId: "main",
        key: "agent:main:slack:channel:overflow",
        kind: "channel",
        sessionId: "smoke-status-overflow-session",
        updatedAt: Date.now(),
        inputTokens: 2147483648,
        outputTokens: 0,
        totalTokens: 2147483648,
        totalTokensFresh: true,
        model: "gpt-5",
        runtime: "OpenClaw Smoke"
      }]
    },
    tasks: { total: 1, active: 0, terminal: 1 }
  }));
  process.exit(0);
}
if (args[0] === "tasks" && args[1] === "list") {
  console.log(JSON.stringify({
    count: 1,
    tasks: [{
      taskId: "smoke-task",
      runId: "smoke-run-from-openclaw-status",
      childSessionKey: "agent:main:slack:channel:smoke",
      runtime: "cli",
      status: "succeeded",
      startedAt: Date.now() - 1000,
      endedAt: Date.now(),
      terminalSummary: "smoke observed"
    }]
  }));
  process.exit(0);
}
if (args[0] === "sessions") {
  console.log(JSON.stringify({
    count: 1,
    totalCount: 1,
    sessions: [{
      agentId: "main",
      key: "agent:main:slack:channel:smoke",
      kind: "channel",
      sessionId: "smoke-status-session",
      updatedAt: Date.now(),
      inputTokens: 21,
      outputTokens: 34,
      totalTokens: 55,
      totalTokensFresh: true,
      model: "gpt-5",
      modelProvider: "openai",
      agentRuntime: { id: "pi" }
    }]
  }));
  process.exit(0);
}
if (args[0] === "gateway" && args[1] === "usage-cost") {
  console.log(JSON.stringify({
    updatedAt: Date.now(),
    days: 30,
    daily: [{
      date: new Date().toISOString().slice(0, 10),
      input: 12,
      output: 34,
      cacheRead: 5,
      cacheWrite: 4,
      totalTokens: 55,
      totalCost: 0.001,
      missingCostEntries: 0
    }],
    totals: {
      input: 12,
      output: 34,
      cacheRead: 5,
      cacheWrite: 4,
      totalTokens: 55,
      totalCost: 0.001,
      missingCostEntries: 0
    }
  }));
  process.exit(0);
}
if (args[0] === "cron" && args[1] === "status") {
  console.log(JSON.stringify({ scheduler: "running", jobs: 1, enabled: 1 }));
  process.exit(0);
}
if (args[0] === "config" && args[1] === "validate") {
  console.log(JSON.stringify({ valid: true, errors: [] }));
  process.exit(0);
}
if (args[0] === "security" && args[1] === "audit") {
  console.log(JSON.stringify({ critical: 0, high: 0, medium: 0, findings: [] }));
  process.exit(0);
}
if (args[0] === "channels" && args[1] === "status") {
  console.log(JSON.stringify({ ok: true, slack: { connected: true, probe: true } }));
  process.exit(0);
}
if (args[0] === "secrets" && args[1] === "reload") {
  console.log(JSON.stringify({ ok: true, reloaded: true }));
  process.exit(0);
}
if (args[0] === "approvals" && args[1] === "get") {
  console.log(JSON.stringify({ ok: true, execApprovals: { enabled: true } }));
  process.exit(0);
}
if (args[0] === "doctor") {
  console.log(JSON.stringify({ ok: true, nonInteractive: true, checks: [] }));
  process.exit(0);
}
console.error("unsupported fake openclaw command", args.join(" "));
process.exit(2);
`);
  await chmod(fakeOpenClaw, 0o755);

  const initdb = await commandPath("initdb", ["/opt/homebrew/opt/postgresql@17/bin/initdb"]);
  const postgres = await commandPath("postgres", ["/opt/homebrew/opt/postgresql@17/bin/postgres"]);
  const psql = await commandPath("psql", ["/opt/homebrew/opt/postgresql@17/bin/psql"]);
  const pgPort = Number(process.env.OPERANT_SMOKE_POSTGRES_PORT || await getFreePort());
  const appPort = Number(process.env.OPERANT_SMOKE_PORT || await getFreePort());
  const internalToken = process.env.OPERANT_SMOKE_INTERNAL_TOKEN || `smoke-internal-${randomBytes(8).toString("hex")}`;
  const adminLoginToken = process.env.OPERANT_ADMIN_LOGIN_TOKEN || `smoke-admin-${randomBytes(16).toString("hex")}`;
  const gatewayToken = process.env.OPENCLAW_GATEWAY_TOKEN || `smoke-gateway-${randomBytes(16).toString("hex")}`;
  const secretKey = process.env.OPERANT_SECRET_KEY || randomBytes(32).toString("base64");

  log("Building control-plane app...");
  await run("pnpm", ["--filter", "@operant/control-plane", "build"], { cwd: repoRoot });

  log(`Initializing temporary Postgres in ${dataDir}...`);
  await run(initdb, ["-D", dataDir, "-A", "trust", "-U", "operant", "--no-locale", "-E", "UTF8"], { quiet: true });
  spawnManaged(postgres, ["-D", dataDir, "-h", "127.0.0.1", "-p", String(pgPort), "-k", socketDir], { prefix: "postgres" });
  await waitFor("Postgres", () => run(psql, ["-h", "127.0.0.1", "-p", String(pgPort), "-U", "operant", "-d", "postgres", "-c", "SELECT 1"], { quiet: true }));
  await run(psql, ["-h", "127.0.0.1", "-p", String(pgPort), "-U", "operant", "-d", "postgres", "-c", "CREATE DATABASE operant"], { quiet: true });

  const appEnv = {
    ...process.env,
    DATABASE_URL: `postgres://operant@127.0.0.1:${pgPort}/operant`,
    OPERANT_SECRET_KEY: secretKey,
    OPERANT_INTERNAL_TOKEN: internalToken,
    OPERANT_ADMIN_LOGIN_TOKEN: adminLoginToken,
    OPERANT_HOST: "127.0.0.1",
    OPERANT_PORT: String(appPort),
    OPENCLAW_GATEWAY_TOKEN: gatewayToken,
    OPENCLAW_GATEWAY_URL: "http://127.0.0.1:18789",
    OPENCLAW_CONFIG_PATH: path.join(configDir, "openclaw.json"),
    OPENCLAW_CLI_COMMAND: fakeOpenClaw,
    OPENCLAW_SECRET_RESOLVER_COMMAND: process.execPath,
    OPENCLAW_SECRET_RESOLVER_SCRIPT: path.join(repoRoot, "deploy/openclaw/operant-secret-resolver.mjs"),
    OPERANT_ALLOW_HEADER_AUTH: "true",
  };
  const baseUrl = `http://127.0.0.1:${appPort}`;
  let appChild = null;

  async function startApp() {
    appChild = spawnManaged(process.execPath, ["apps/control-plane/dist/src/server.js"], { env: appEnv, prefix: "operant" });
    await waitFor("Operant", () => request(baseUrl, "/readyz"));
  }

  async function restartApp() {
    log("Restarting Operant policy-audit...");
    await stopChild(appChild);
    await startApp();
  }

  async function runSql(sql) {
    await run(psql, ["-h", "127.0.0.1", "-p", String(pgPort), "-U", "operant", "-d", "operant", "-c", sql], { quiet: true });
  }

  await startApp();
  return { baseUrl, internalToken, adminLoginToken, restartApp, runSql, configPath: appEnv.OPENCLAW_CONFIG_PATH };
}

function assertNoPlaintextSecrets(config, secrets) {
  const serialized = JSON.stringify(config);
  for (const secret of secrets) {
    if (serialized.includes(secret)) fail("Generated OpenClaw config leaked plaintext secret material");
  }
}

function assertAuditEventTypes(auditLog, expectedTypes, options = {}) {
  const items = auditLog.items;
  if (!Array.isArray(items)) fail("Audit API did not return an items array");

  const eventTypes = new Set(items.map((item) => item.event_type));
  const missing = expectedTypes.filter((type) => !eventTypes.has(type));
  if (missing.length > 0) {
    fail(`Audit log is missing expected event type(s): ${missing.join(", ")}. Present: ${Array.from(eventTypes).sort().join(", ")}`);
  }

  if (options.approvalId) {
    const hasApprovalRequested = items.some((item) => item.event_type === "approval.requested" && item.resource_id === options.approvalId);
    const hasApprovalApproved = items.some((item) => item.event_type === "approval.approved" && item.resource_id === options.approvalId);
    if (!hasApprovalRequested || !hasApprovalApproved) {
      fail("Audit log did not persist request and approval decision rows for the smoke approval");
    }
  }

  const serialized = JSON.stringify(auditLog);
  for (const secret of options.secrets || []) {
    if (serialized.includes(secret)) fail("Audit log leaked plaintext secret material");
  }
}

async function runSmoke(baseUrl, internalToken, options = {}) {
  const suffix = randomBytes(4).toString("hex").toUpperCase();
  const ownerSlackUserId = process.env.OPERANT_SMOKE_OWNER_SLACK_ID || `UOWNER${suffix}`;
  const adminSlackUserId = `UADMIN${suffix}`;
  const integrationAdminSlackUserId = `UINT${suffix}`;
  const usageAnalystSlackUserId = `UUSAGE${suffix}`;
  const billingUsageAdminSlackUserId = `UBILLING${suffix}`;
  const viewerSlackUserId = `UVIEWER${suffix}`;
  const memberSlackUserId = `UMEMBER${suffix}`;
  const deniedSlackUserId = `UDENY${suffix}`;
  const channelId = `CSMOKE${suffix}`;
  const rotatedChannelId = `CROTATE${suffix}`;
  const disabledChannelId = `CDENY${suffix}`;
  const slackBotToken = `xoxb-smoke-${suffix}-bot-secret`;
  const slackAppToken = `xapp-smoke-${suffix}-app-secret`;
  const modelApiKey = `sk-smoke-${suffix}-model-secret`;
  const adminLoginToken = options.adminLoginToken || process.env.OPERANT_ADMIN_LOGIN_TOKEN || "";
  let restartVerified = false;

  log(`Smoke target: ${baseUrl}`);
  await request(baseUrl, "/healthz", { expectSecurityHeaders: true });
  await request(baseUrl, "/readyz");
  const dashboard = await requestText(baseUrl, "/", { expectSecurityHeaders: true });
  const policyForm = dashboard.match(/<form id="policy-form"[\s\S]*?<\/form>/)?.[0] || "";
  if (!dashboard.includes('id="role-form"') || !dashboard.includes('id="sync-openclaw"') || !dashboard.includes('data-check="doctor"') || !dashboard.includes('data-check="secrets-reload"') || !dashboard.includes('data-check="approvals-get"') || !dashboard.includes('data-check="usage-cost"') || !dashboard.includes('id="approvals-result"') || !dashboard.includes('id="activity-result"') || !dashboard.includes('id="usage-events"') || !dashboard.includes('id="wipe-scope"') || !dashboard.includes('name="openclawGatewayUrl"')) {
    fail("Dashboard HTML did not include custom role, approval queue, activity, retention scope, settings, and OpenClaw doctor controls");
  }
  if (!policyForm.includes('name="action"') || !policyForm.includes('name="resource"') || !policyForm.includes('<option value="group">Group</option>')) {
    fail("Dashboard policy preview form did not include action/resource controls and group chat type");
  }
  if (!dashboard.includes("Create Export") || !dashboard.includes("Run Wipe") || dashboard.includes("Queue Export") || dashboard.includes("Queue Wipe")) {
    fail("Dashboard did not describe synchronous export and wipe actions accurately");
  }
  const dashboardApp = await requestText(baseUrl, "/app.js", { expectSecurityHeaders: true });
  const dashboardStyles = await requestText(baseUrl, "/styles.css", { expectSecurityHeaders: true });
  if (!dashboardApp.includes('request("/api/config/credentials"') || !dashboardApp.includes('request("/api/openclaw/observations/sync"') || !dashboardApp.includes('request("/api/usage/summary"') || !dashboardApp.includes('request("/api/usage");') || !dashboardApp.includes('request("/api/export"') || !dashboardApp.includes('request("/api/wipe"')) {
    fail("Dashboard app asset did not wire credential, OpenClaw sync, usage summary/events, export, and wipe API calls");
  }
  if (!dashboardStyles.includes(".topbar") || !dashboardStyles.includes(".decision-item")) {
    fail("Dashboard stylesheet did not include core layout and decision-list styles");
  }
  if (!/@media\s*\(max-width:\s*640px\)[\s\S]*\.topbar[\s\S]*flex-direction:\s*column[\s\S]*\.metrics[\s\S]*grid-template-columns:\s*1fr/.test(dashboardStyles)) {
    fail("Dashboard stylesheet did not include the mobile topbar and metrics layout safeguards");
  }
  await request(baseUrl, "/api/bootstrap", {
    method: "POST",
    body: { adminLoginToken },
  });

  let ownerToken = null;
  try {
    ownerToken = (await login(baseUrl, ownerSlackUserId, adminLoginToken)).token;
  } catch {
    // Fresh databases have no role assignments yet; first credential setup creates the owner.
  }

  const missingAdminTokenLogin = await request(baseUrl, "/api/auth/login", {
    method: "POST",
    body: { slackUserId: ownerSlackUserId },
    expectStatus: 401,
  });
  if (!String(missingAdminTokenLogin?.error || "").includes("admin login token")) {
    fail("Missing or invalid admin login token was not enforced for dashboard login");
  }

  await request(baseUrl, "/api/openclaw/config", { method: "POST", body: {}, expectStatus: 401 });
  const credentialPayload = {
    companyName: "Operant Smoke Co",
    workspaceName: `Smoke Workspace ${suffix}`,
    slackTeamId: `TSMOKE${suffix}`,
    slackBotToken,
    slackAppToken,
    modelProvider: "openai",
    modelName: "gpt-5",
    modelApiKey,
    adminLoginToken,
    adminSlackUserId: ownerSlackUserId,
    allowedDmUserIds: [adminSlackUserId, memberSlackUserId],
    allowedChannelIds: [channelId],
    approvalSlackUserIds: [adminSlackUserId],
  };
  const missingBootstrapOwner = await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    body: {
      ...credentialPayload,
      adminSlackUserId: undefined,
      approvalSlackUserIds: [adminSlackUserId],
    },
    expectStatus: 400,
  });
  if (!String(missingBootstrapOwner?.error || "").includes("workspace owner")) {
    fail("First credential setup allowed credentials without creating a workspace owner");
  }
  const invalidModelProvider = await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    body: {
      ...credentialPayload,
      modelProvider: "../openai",
    },
    expectStatus: 400,
  });
  if (!String(invalidModelProvider?.error || "").includes("Invalid request")) {
    fail("Credential setup accepted an invalid model provider SecretRef path part");
  }
  const invalidSlackAllowlistId = await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    body: {
      ...credentialPayload,
      allowedDmUserIds: ["U BAD"],
    },
    expectStatus: 400,
  });
  if (!String(invalidSlackAllowlistId?.error || "").includes("Invalid request")) {
    fail("Credential setup accepted an invalid Slack allowlist identifier");
  }
  const blankWorkspaceName = await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    body: {
      ...credentialPayload,
      workspaceName: "   ",
    },
    expectStatus: 400,
  });
  if (!String(blankWorkspaceName?.error || "").includes("Invalid request")) {
    fail("Credential setup accepted a blank workspace name");
  }
  await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    token: ownerToken,
    body: credentialPayload,
  });

  ownerToken = (await login(baseUrl, ownerSlackUserId, adminLoginToken)).token;
  await request(baseUrl, "/api/auth/me", { token: ownerToken });
  await request(baseUrl, "/api/summary", { expectStatus: 401 });
  const invalidHeaderAuth = await request(baseUrl, "/api/summary", {
    expectStatus: 401,
    headers: { "x-operant-slack-user-id": "U BAD" },
  });
  if (!String(invalidHeaderAuth?.error || "").includes("admin session")) {
    fail("Header auth accepted an invalid Slack user identifier");
  }
  await request(baseUrl, "/api/audit", { expectStatus: 401 });
  await request(baseUrl, "/api/openclaw/config", { expectStatus: 401 });
  await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    body: credentialPayload,
    expectStatus: 401,
  });
  const credentialUpdateWithoutBootstrapToken = await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    token: ownerToken,
    body: {
      ...credentialPayload,
      adminLoginToken: undefined,
      workspaceName: `Smoke Workspace ${suffix} Owner Update`,
    },
  });
  if (!credentialUpdateWithoutBootstrapToken.checksum) {
    fail("Owner credential update without bootstrap token did not regenerate OpenClaw config");
  }
  const rotatedCredentialUpdate = await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    token: ownerToken,
    body: {
      ...credentialPayload,
      adminLoginToken: undefined,
      allowedChannelIds: [rotatedChannelId],
    },
  });
  if (!rotatedCredentialUpdate.checksum) {
    fail("Credential channel rotation did not regenerate OpenClaw config");
  }
  const rotatedConfig = await request(baseUrl, "/api/openclaw/config", { token: ownerToken });
  if (rotatedConfig.config.channels.slack.channels?.[channelId]) {
    fail("Credential setup left a stale credential-seeded channel allowlist after channel rotation");
  }
  const rotatedChannelUsers = rotatedConfig.config.channels.slack.channels?.[rotatedChannelId]?.users || [];
  if (!rotatedChannelUsers.includes(ownerSlackUserId) || !rotatedChannelUsers.includes(adminSlackUserId) || !rotatedChannelUsers.includes(memberSlackUserId)) {
    fail("Credential channel rotation did not retain owner/admin/member allowlist users");
  }
  await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    token: ownerToken,
    body: {
      ...credentialPayload,
      adminLoginToken: undefined,
    },
  });

  const summary = await request(baseUrl, "/api/summary", { token: ownerToken });
  const generated = await request(baseUrl, "/api/openclaw/config", {
    method: "POST",
    token: ownerToken,
    body: {},
  });
  assertNoPlaintextSecrets(generated.config, [slackBotToken, slackAppToken, modelApiKey]);
  if (generated.config.gateway.remote.url !== "ws://127.0.0.1:18789") {
    fail(`Generated OpenClaw config had unexpected remote gateway URL: ${generated.config.gateway.remote.url}`);
  }
  if (generated.config.gateway.reload?.mode !== "hybrid") {
    fail("Generated OpenClaw config did not explicitly enable hybrid config reload mode");
  }
  if (generated.config.channels.slack.actions.pins !== false) {
    fail("Initial approval-required Slack pin policy was not compiled closed in OpenClaw config");
  }
  const initialDmAllowFrom = generated.config.channels.slack.allowFrom || [];
  if (!initialDmAllowFrom.includes(ownerSlackUserId) || !initialDmAllowFrom.includes(adminSlackUserId) || !initialDmAllowFrom.includes(memberSlackUserId)) {
    fail("Credential setup did not retain the workspace owner while adding optional allowed DM users");
  }
  const initialChannelUsers = generated.config.channels.slack.channels?.[channelId]?.users || [];
  if (!initialChannelUsers.includes(ownerSlackUserId) || !initialChannelUsers.includes(adminSlackUserId) || !initialChannelUsers.includes(memberSlackUserId)) {
    fail("Credential setup did not retain the workspace owner in channel allowlists while adding optional users");
  }
  const initialApprovalApprovers = generated.config.channels.slack.execApprovals?.approvers || [];
  if (!initialApprovalApprovers.includes(ownerSlackUserId) || !initialApprovalApprovers.includes(adminSlackUserId)) {
    fail("Credential setup did not retain the workspace owner while adding optional approval users");
  }
  if (options.configPath) {
    const configMode = (await stat(options.configPath)).mode & 0o777;
    if (configMode !== 0o600) {
      fail(`Generated OpenClaw config mode was ${configMode.toString(8)}, expected 600 for private gateway reads`);
    }
  }
  await request(baseUrl, "/api/openclaw/config", { token: ownerToken });

  if (internalToken) {
    const secretRefId = `workspaces/${summary.workspaceId}/slack/botToken`;
    await request(baseUrl, `/internal/openclaw/secrets/${encodeURIComponent(secretRefId)}`, { internalToken: `${internalToken}-wrong`, expectStatus: 401 });
    await request(baseUrl, `/internal/openclaw/secrets/${encodeURIComponent("slack/botToken")}`, { internalToken, expectStatus: 400 });
    const malformedSecretRefPath = await request(baseUrl, "/internal/openclaw/secrets/%E0%A4%A", { internalToken, expectStatus: 400 });
    if (!String(malformedSecretRefPath?.error || "").includes("URL encoding")) {
      fail("Malformed SecretRef URL path was not rejected as a client error");
    }
    const secret = await request(baseUrl, `/internal/openclaw/secrets/${encodeURIComponent(secretRefId)}`, { internalToken });
    if (secret.value !== slackBotToken) fail("Internal secret resolver endpoint returned an unexpected Slack bot token");
  }

  await request(baseUrl, "/api/roles", { token: ownerToken });
  const oversizedCustomRole = await request(baseUrl, "/api/roles", {
    method: "POST",
    token: ownerToken,
    expectStatus: 400,
    body: {
      name: "too_many_permissions",
      permissions: Array.from({ length: 501 }, () => ({ action: "usage:read", resource: "usage" })),
    },
  });
  if (!String(oversizedCustomRole?.error || "").includes("Invalid request")) {
    fail("Custom role API accepted an oversized permission grant list");
  }
  const unknownCustomRolePermission = await request(baseUrl, "/api/roles", {
    method: "POST",
    token: ownerToken,
    expectStatus: 400,
    body: {
      name: "unknown_permission_role",
      permissions: [{ action: "usage:delete", resource: "usage" }],
    },
  });
  if (!String(unknownCustomRolePermission?.error || "").includes("Unknown permission")) {
    fail("Custom role API accepted an unknown action/resource permission grant");
  }
  const customRole = await request(baseUrl, "/api/roles", {
    method: "POST",
    token: ownerToken,
    body: {
      name: "usage_analyst",
      permissions: [
        { action: "settings:read", resource: "workspace" },
        { action: "usage:read", resource: "usage" },
      ],
    },
  });
  if (customRole.role.builtin || customRole.role.name !== "usage_analyst") fail("Custom role upsert returned an unexpected role");
  if (!customRole.role.permissions.some((permission) => permission.action === "usage:read" && permission.resource === "usage")) {
    fail("Custom role did not persist the usage read permission");
  }
  const builtinRoleOverwrite = await request(baseUrl, "/api/roles", {
    method: "POST",
    token: ownerToken,
    body: {
      name: "owner",
      permissions: [{ action: "usage:read", resource: "usage" }],
    },
    expectStatus: 409,
  });
  if (!String(builtinRoleOverwrite?.error || "").includes("Built-in roles cannot be overwritten")) {
    fail("Custom role API allowed overwriting the built-in owner role");
  }
  const unknownRoleAssignment = await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: `UUNKNOWNROLE${suffix}`, name: "Unknown Role User", roles: ["missing_role"] },
    expectStatus: 400,
  });
  if (!String(unknownRoleAssignment?.error || "").includes("Unknown role")) {
    fail("User API accepted an unknown role assignment");
  }
  const lastOwnerRemoval = await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: ownerSlackUserId, name: "Demoted Owner", roles: ["member"] },
    expectStatus: 409,
  });
  if (!String(lastOwnerRemoval?.error || "").includes("Cannot remove the last workspace owner")) {
    fail("User API allowed removing the last workspace owner");
  }
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: adminSlackUserId, email: `${adminSlackUserId.toLowerCase()}@example.com`, name: "Smoke Admin", roles: ["admin"] },
  });
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: integrationAdminSlackUserId, name: "Smoke Integration Admin", roles: ["integration_admin"] },
  });
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: usageAnalystSlackUserId, name: "Smoke Usage Analyst", roles: ["usage_analyst"] },
  });
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: billingUsageAdminSlackUserId, name: "Smoke Billing Usage Admin", roles: ["billing_usage_admin"] },
  });
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: viewerSlackUserId, name: "Smoke Viewer", roles: ["viewer"] },
  });
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: ownerToken,
    body: { slackUserId: memberSlackUserId, name: "Smoke Member", roles: ["member"] },
  });
  const adminToken = (await login(baseUrl, adminSlackUserId, adminLoginToken)).token;
  const integrationAdminToken = (await login(baseUrl, integrationAdminSlackUserId, adminLoginToken)).token;
  const usageAnalystToken = (await login(baseUrl, usageAnalystSlackUserId, adminLoginToken)).token;
  const billingUsageAdminToken = (await login(baseUrl, billingUsageAdminSlackUserId, adminLoginToken)).token;
  const viewerToken = (await login(baseUrl, viewerSlackUserId, adminLoginToken)).token;
  const memberToken = (await login(baseUrl, memberSlackUserId, adminLoginToken)).token;
  const users = await request(baseUrl, "/api/users", { token: adminToken });
  const admin = users.users.find((user) => user.slack_user_id === adminSlackUserId);
  if (!admin?.roles?.includes("admin")) fail("Admin user was not persisted with the admin role");
  const usageAnalyst = users.users.find((user) => user.slack_user_id === usageAnalystSlackUserId);
  if (!usageAnalyst?.roles?.includes("usage_analyst")) fail("Custom role assignment was not persisted");
  const billingUsageAdmin = users.users.find((user) => user.slack_user_id === billingUsageAdminSlackUserId);
  if (!billingUsageAdmin?.roles?.includes("billing_usage_admin")) fail("Billing usage admin role assignment was not persisted");
  const viewer = users.users.find((user) => user.slack_user_id === viewerSlackUserId);
  if (!viewer?.roles?.includes("viewer")) fail("Viewer role assignment was not persisted");
  await request(baseUrl, "/api/settings", { token: usageAnalystToken });
  await request(baseUrl, "/api/settings", {
    method: "PUT",
    token: usageAnalystToken,
    body: { retentionDays: 2 },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/openclaw/config", { token: usageAnalystToken });
  await request(baseUrl, "/api/usage", { token: usageAnalystToken });
  await request(baseUrl, "/api/usage/summary", { token: usageAnalystToken });
  await request(baseUrl, "/api/users", { token: usageAnalystToken, expectStatus: 403 });
  await request(baseUrl, "/api/audit", { token: usageAnalystToken, expectStatus: 403 });
  await request(baseUrl, "/api/sessions", { token: usageAnalystToken, expectStatus: 403 });
  await request(baseUrl, "/api/jobs", { token: usageAnalystToken, expectStatus: 403 });
  await request(baseUrl, "/api/approvals", { token: usageAnalystToken, expectStatus: 403 });
  await request(baseUrl, "/api/policy", { token: usageAnalystToken, expectStatus: 403 });
  await request(baseUrl, "/api/integrations/credentials", { token: usageAnalystToken, expectStatus: 403 });
  await request(baseUrl, "/api/openclaw/config", { method: "POST", token: usageAnalystToken, body: {}, expectStatus: 403 });
  await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    token: usageAnalystToken,
    body: credentialPayload,
    expectStatus: 403,
  });
  await request(baseUrl, "/api/integrations/credentials", {
    method: "POST",
    token: usageAnalystToken,
    body: {
      kind: "github",
      key: "usage-analyst-denied-token",
      label: "Denied usage analyst credential",
      secretValue: `usage_analyst_denied_${suffix}`,
    },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: usageAnalystToken,
    body: { allowedDmUserIds: [], channelPolicies: [], toolPolicies: [], approvalPolicies: [] },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: usageAnalystToken,
    body: { action: "exec:shell", resource: "cloud-computer", payload: { reason: "usage analyst denied smoke" } },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/export", { method: "POST", token: usageAnalystToken, body: {}, expectStatus: 403 });
  await request(baseUrl, "/api/wipe", { method: "POST", token: usageAnalystToken, body: { scope: "usage" }, expectStatus: 403 });
  await request(baseUrl, "/api/audit", { token: billingUsageAdminToken });
  await request(baseUrl, "/api/usage", { token: billingUsageAdminToken });
  await request(baseUrl, "/api/usage/summary", { token: billingUsageAdminToken });
  await request(baseUrl, "/api/settings", { token: viewerToken });
  await request(baseUrl, "/api/users", { token: viewerToken });
  await request(baseUrl, "/api/audit", { token: viewerToken });
  await request(baseUrl, "/api/openclaw/config", { token: viewerToken });
  await request(baseUrl, "/api/sessions", { token: viewerToken });
  await request(baseUrl, "/api/jobs", { token: viewerToken });
  await request(baseUrl, "/api/usage", { token: viewerToken });
  await request(baseUrl, "/api/usage/summary", { token: viewerToken });
  await request(baseUrl, "/api/settings", {
    method: "PUT",
    token: viewerToken,
    body: { retentionDays: 2 },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: viewerToken,
    body: { slackUserId: `UVIEWERDENIED${suffix}`, name: "Denied Viewer Mutation", roles: ["member"] },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    token: viewerToken,
    body: credentialPayload,
    expectStatus: 403,
  });
  await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: viewerToken,
    body: { action: "exec:shell", resource: "cloud-computer", payload: { reason: "viewer denied smoke" } },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/sessions", { token: memberToken });
  await request(baseUrl, "/api/jobs", { token: memberToken });
  await request(baseUrl, "/api/approvals", { token: memberToken });
  await request(baseUrl, "/api/settings", { token: memberToken, expectStatus: 403 });
  await request(baseUrl, "/api/users", { token: memberToken, expectStatus: 403 });
  await request(baseUrl, "/api/audit", { token: memberToken, expectStatus: 403 });
  await request(baseUrl, "/api/usage", { token: memberToken, expectStatus: 403 });
  await request(baseUrl, "/api/usage/summary", { token: memberToken, expectStatus: 403 });
  await request(baseUrl, "/api/openclaw/config", { token: memberToken, expectStatus: 403 });
  await request(baseUrl, "/api/settings", {
    method: "PUT",
    token: memberToken,
    body: { retentionDays: 2 },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/config/credentials", {
    method: "POST",
    token: memberToken,
    body: credentialPayload,
    expectStatus: 403,
  });
  await request(baseUrl, "/api/integrations/credentials", {
    method: "POST",
    token: memberToken,
    body: {
      kind: "github",
      key: "member-denied-token",
      label: "Denied member credential",
      secretValue: `member_denied_${suffix}`,
    },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: memberToken,
    body: { allowedDmUserIds: [], channelPolicies: [], toolPolicies: [], approvalPolicies: [] },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/export", { method: "POST", token: memberToken, body: {}, expectStatus: 403 });
  await request(baseUrl, "/api/wipe", { method: "POST", token: memberToken, body: { scope: "usage" }, expectStatus: 403 });
  await request(baseUrl, "/api/settings", {
    method: "PUT",
    token: billingUsageAdminToken,
    body: { retentionDays: 2 },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/integrations/credentials", {
    method: "POST",
    token: billingUsageAdminToken,
    body: {
      kind: "github",
      key: "billing-denied-token",
      label: "Denied billing credential",
      secretValue: `billing_denied_${suffix}`,
    },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/settings", { token: integrationAdminToken });
  await request(baseUrl, "/api/policy", { token: integrationAdminToken });
  await request(baseUrl, "/api/openclaw/config", { token: integrationAdminToken });
  await request(baseUrl, "/api/sessions", { token: integrationAdminToken });
  await request(baseUrl, "/api/jobs", { token: integrationAdminToken });
  await request(baseUrl, "/api/users", {
    method: "POST",
    token: integrationAdminToken,
    body: { slackUserId: `UINTDENIED${suffix}`, name: "Denied Integration Admin Mutation", roles: ["member"] },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/settings", {
    method: "PUT",
    token: integrationAdminToken,
    body: { retentionDays: 2 },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: integrationAdminToken,
    body: { allowedDmUserIds: [], channelPolicies: [], toolPolicies: [], approvalPolicies: [] },
    expectStatus: 403,
  });
  await request(baseUrl, "/api/audit", { token: integrationAdminToken, expectStatus: 403 });
  await request(baseUrl, "/api/usage/summary", { token: integrationAdminToken, expectStatus: 403 });
  await request(baseUrl, "/api/export", { method: "POST", token: integrationAdminToken, body: {}, expectStatus: 403 });
  await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: integrationAdminToken,
    body: { action: "exec:shell", resource: "cloud-computer", payload: { reason: "integration admin denied smoke" } },
    expectStatus: 403,
  });

  const integrationSecretValue = `ghp_smoke_${suffix}`;
  const blankIntegrationLabel = await request(baseUrl, "/api/integrations/credentials", {
    method: "POST",
    token: integrationAdminToken,
    expectStatus: 400,
    body: {
      kind: "github",
      key: "blank-label-token",
      label: "   ",
      secretValue: "secret",
    },
  });
  if (!String(blankIntegrationLabel?.error || "").includes("Invalid request")) {
    fail("Integration credential API accepted a blank label");
  }
  const oversizedIntegrationSecret = await request(baseUrl, "/api/integrations/credentials", {
    method: "POST",
    token: integrationAdminToken,
    expectStatus: 400,
    body: {
      kind: "github",
      key: "oversized-token",
      label: "Oversized token",
      secretValue: "s".repeat(8193),
    },
  });
  if (!String(oversizedIntegrationSecret?.error || "").includes("Invalid request")) {
    fail("Integration credential API accepted an oversized secret value");
  }
  const integrationCredential = await request(baseUrl, "/api/integrations/credentials", {
    method: "POST",
    token: integrationAdminToken,
    body: {
      kind: "github",
      key: "api-token",
      label: "Smoke GitHub API token",
      secretValue: integrationSecretValue,
    },
  });
  if (JSON.stringify(integrationCredential).includes(integrationSecretValue)) fail("Integration credential response leaked plaintext secret");
  const integrationCredentials = await request(baseUrl, "/api/integrations/credentials", { token: integrationAdminToken });
  const smokeCredential = integrationCredentials.credentials.find((credential) => credential.secret_ref_id === integrationCredential.credential.secret_ref_id);
  if (!smokeCredential) fail("Integration credential list did not include the saved credential metadata");
  if (JSON.stringify(integrationCredentials).includes(integrationSecretValue)) fail("Integration credential list leaked plaintext secret");
  if (internalToken) {
    const resolvedIntegrationSecret = await request(baseUrl, `/internal/openclaw/secrets/${encodeURIComponent(integrationCredential.credential.secret_ref_id)}`, { internalToken });
    if (resolvedIntegrationSecret.value !== integrationSecretValue) fail("Internal resolver did not return the saved integration secret");
  }

  const duplicatePolicyUpdate = await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: adminToken,
    body: {
      allowedDmUserIds: [],
      channelPolicies: [{ channelId }, { channelId }],
      toolPolicies: [
        { tool: "exec", action: "*", effect: "approval_required" },
        { tool: "exec", action: "*", effect: "approval_required" },
      ],
      approvalPolicies: [],
    },
    expectStatus: 400,
  });
  if (!String(duplicatePolicyUpdate?.error || "").includes("Invalid request")) {
    fail("Policy update accepted duplicate policy identities");
  }
  const duplicateSlackListPolicyUpdate = await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: adminToken,
    body: {
      allowedDmUserIds: [memberSlackUserId, memberSlackUserId],
      channelPolicies: [{
        channelId,
        allowedUserIds: [memberSlackUserId, memberSlackUserId],
        deniedUserIds: [deniedSlackUserId, deniedSlackUserId],
      }],
      toolPolicies: [],
      approvalPolicies: [],
    },
    expectStatus: 400,
  });
  if (!String(duplicateSlackListPolicyUpdate?.error || "").includes("Invalid request")) {
    fail("Policy update accepted duplicate Slack identifiers in policy lists");
  }

  await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: adminToken,
    body: {
      allowedDmUserIds: [memberSlackUserId],
      channelPolicies: [],
      toolPolicies: [
        { tool: "exec", action: "*", effect: "approval_required" },
        { tool: "exec", action: "shell", effect: "deny" },
      ],
      approvalPolicies: [],
    },
  });
  const denyPrecedenceDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: memberSlackUserId,
      chatType: "direct",
      tool: "exec",
      action: "shell",
      resource: "cloud-computer",
    },
  });
  if (denyPrecedenceDecision.effect !== "deny") {
    fail(`Expected specific deny to beat wildcard approval policy, got ${denyPrecedenceDecision.effect}`);
  }
  await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: adminToken,
    body: {
      allowedDmUserIds: [adminSlackUserId, memberSlackUserId],
      channelPolicies: [],
      toolPolicies: [
        { tool: "browser", action: "*", effect: "allow", roleNames: ["admin"] },
      ],
      approvalPolicies: [],
    },
  });
  const adminToolEntitlementDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: adminSlackUserId,
      chatType: "direct",
      tool: "browser",
      action: "navigate",
      resource: "cloud-computer",
    },
  });
  if (adminToolEntitlementDecision.effect !== "allow") {
    fail(`Expected admin role-scoped browser entitlement to allow, got ${adminToolEntitlementDecision.effect}`);
  }
  const memberToolEntitlementDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: memberSlackUserId,
      chatType: "direct",
      tool: "browser",
      action: "navigate",
      resource: "cloud-computer",
    },
  });
  if (memberToolEntitlementDecision.effect !== "deny") {
    fail(`Expected missing member role-scoped browser entitlement to deny, got ${memberToolEntitlementDecision.effect}`);
  }
  const unmatchedApprovalRequest = await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: memberToken,
    body: { action: "exec:shell", resource: "cloud-computer", payload: { reason: "unmatched approval smoke" } },
    expectStatus: 409,
  });
  if (!String(unmatchedApprovalRequest?.error || "").includes("No enabled approval policy matched")) {
    fail("Approval API accepted a request without a matching enabled approval policy");
  }

  const policyUpdate = await request(baseUrl, "/api/policy", {
    method: "PUT",
    token: adminToken,
    body: {
      allowedDmUserIds: [ownerSlackUserId, adminSlackUserId, memberSlackUserId],
      channelPolicies: [{
        channelId,
        name: "Smoke channel",
        enabled: true,
        requireMention: true,
        allowedUserIds: [ownerSlackUserId, adminSlackUserId, memberSlackUserId, deniedSlackUserId],
        deniedUserIds: [deniedSlackUserId],
      }, {
        channelId: disabledChannelId,
        name: "Denied smoke channel",
        enabled: false,
        requireMention: true,
        allowedUserIds: [memberSlackUserId],
        deniedUserIds: [],
      }],
      toolPolicies: [
        { tool: "slack", action: "messages", effect: "allow" },
        { tool: "exec", action: "*", effect: "approval_required" },
      ],
      approvalPolicies: [{
        name: "Smoke risky action approvals",
        actionPattern: "exec:*",
        resourcePattern: "*",
        approverSlackUserIds: [adminSlackUserId, ownerSlackUserId],
        minApprovals: 2,
        enabled: true,
      }],
    },
  });
  let expectedConfigChecksum = policyUpdate.config.checksum;
  const policyConfig = await request(baseUrl, "/api/openclaw/config", { token: adminToken });
  const channelUsers = policyConfig.config.channels.slack.channels[channelId].users;
  if (channelUsers.includes(deniedSlackUserId)) fail("Denied Slack user leaked into generated OpenClaw channel users allowlist");
  if (policyConfig.config.channels.slack.channels[disabledChannelId]?.enabled !== false) {
    fail("Disabled Slack channel denylist entry was not preserved in generated OpenClaw config");
  }
  const expectedOpenClawChecks = ["status", "doctor", "config-validate", "secrets-reload", "approvals-get", "cron-status", "tasks-list", "usage-cost", "security-audit", "channels-status"];
  const openClawChecksIndex = await request(baseUrl, "/api/openclaw/checks", { token: adminToken });
  const advertisedOpenClawChecks = new Set(openClawChecksIndex.checks || []);
  for (const check of expectedOpenClawChecks) {
    if (!advertisedOpenClawChecks.has(check)) fail(`OpenClaw checks index did not advertise ${check}`);
  }
  await request(baseUrl, "/api/openclaw/checks/not-a-check", { method: "POST", token: adminToken, body: {}, expectStatus: 400 });
  for (const check of expectedOpenClawChecks) {
    const checkResult = await request(baseUrl, `/api/openclaw/checks/${check}`, { method: "POST", token: adminToken, body: {} });
    if (checkResult.check !== check || checkResult.exitCode !== 0 || checkResult.timedOut) {
      fail(`OpenClaw check ${check} did not complete cleanly: ${JSON.stringify(checkResult)}`);
    }
    if (check === "config-validate" && checkResult.json?.valid !== true) fail("OpenClaw config-validate did not return valid: true");
    if (check === "tasks-list" && !Array.isArray(checkResult.json?.tasks)) fail("OpenClaw tasks-list did not return task JSON");
    if (check === "usage-cost" && !Number.isFinite(Number(checkResult.json?.totals?.totalCost))) fail("OpenClaw usage-cost did not return token/cost JSON");
    if (check === "security-audit" && checkResult.json?.critical !== 0) fail("OpenClaw security-audit did not return critical: 0");
  }
  const openClawSync = await request(baseUrl, "/api/openclaw/observations/sync", { method: "POST", token: adminToken, body: {} });
  if (openClawSync.synced.sessionsUpserted < 1 || openClawSync.synced.usageInserted < 1 || openClawSync.synced.jobsUpserted < 1) {
    fail(`OpenClaw observation sync did not persist session, usage, and job records: ${JSON.stringify(openClawSync.synced)}`);
  }
  if (openClawSync.synced.usageSkipped < 1) {
    fail(`OpenClaw observation sync did not skip oversized usage records: ${JSON.stringify(openClawSync.synced)}`);
  }
  if (openClawSync.synced.usageCostSnapshotsSeen < 1 || (openClawSync.synced.usageCostInserted + openClawSync.synced.usageCostUpdated) < 1) {
    fail(`OpenClaw observation sync did not persist usage-cost snapshots: ${JSON.stringify(openClawSync.synced)}`);
  }
  await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    expectStatus: 401,
    body: {
      slackUserId: deniedSlackUserId,
      slackChannelId: channelId,
      chatType: "channel",
      action: "message",
      resource: "slack",
    },
  });
  const dmDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: memberSlackUserId,
      chatType: "direct",
      action: "message",
      resource: "slack",
    },
  });
  if (dmDecision.effect !== "allow") fail(`Expected allowlisted DM policy decision, got ${dmDecision.effect}`);
  const channelAllowDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: memberSlackUserId,
      slackChannelId: channelId,
      chatType: "channel",
      tool: "slack",
      action: "messages",
      resource: "slack",
    },
  });
  if (channelAllowDecision.effect !== "allow") fail(`Expected allowlisted channel Slack action decision, got ${channelAllowDecision.effect}`);
  const unlistedChannelDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: memberSlackUserId,
      slackChannelId: `CUNLISTED${suffix}`,
      chatType: "channel",
      action: "message",
      resource: "slack",
    },
  });
  if (unlistedChannelDecision.effect !== "deny") fail(`Expected unlisted channel policy decision to deny, got ${unlistedChannelDecision.effect}`);
  const disabledChannelDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: memberSlackUserId,
      slackChannelId: disabledChannelId,
      chatType: "channel",
      tool: "slack",
      action: "messages",
      resource: "slack",
    },
  });
  if (disabledChannelDecision.effect !== "deny") fail(`Expected disabled channel policy decision to deny, got ${disabledChannelDecision.effect}`);
  const approvalRequiredDecision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: memberSlackUserId,
      slackChannelId: channelId,
      chatType: "channel",
      tool: "exec",
      action: "shell",
      resource: "cloud-computer",
    },
  });
  if (approvalRequiredDecision.effect !== "approval_required") {
    fail(`Expected risky exec policy decision to require approval, got ${approvalRequiredDecision.effect}`);
  }
  const decision = await request(baseUrl, "/api/policy/evaluate", {
    method: "POST",
    token: adminToken,
    body: {
      slackUserId: deniedSlackUserId,
      slackChannelId: channelId,
      chatType: "channel",
      action: "message",
      resource: "slack",
    },
  });
  if (decision.effect !== "deny") fail(`Expected denied user policy decision, got ${decision.effect}`);

  const invalidApprovalAction = await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: memberToken,
    expectStatus: 400,
    body: { action: "exec shell", resource: "cloud-computer", payload: { reason: "invalid action smoke" } },
  });
  if (!String(invalidApprovalAction?.error || "").includes("Invalid request")) {
    fail("Invalid approval action was not rejected as a client error");
  }
  const oversizedApprovalPayload = await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: memberToken,
    expectStatus: 400,
    body: {
      action: "exec:shell",
      resource: "cloud-computer",
      payload: Object.fromEntries(Array.from({ length: 101 }, (_, index) => [`key${index}`, index])),
    },
  });
  if (!String(oversizedApprovalPayload?.error || "").includes("Invalid request")) {
    fail("Approval API accepted oversized payload metadata");
  }
  const approval = await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: memberToken,
    body: { action: "exec:shell", resource: "cloud-computer", payload: { reason: "smoke" } },
  });
  const approvalRequirement = approval.payload.operantApproval;
  if (!approvalRequirement?.policyNames?.includes("Smoke risky action approvals")) {
    fail("Approval request did not record the matching approval policy");
  }
  if (!approvalRequirement.approverSlackUserIds?.includes(adminSlackUserId) || !approvalRequirement.approverSlackUserIds?.includes(ownerSlackUserId) || approvalRequirement.minApprovals !== 2) {
    fail("Approval request did not record required approvers and minimum approval count");
  }
  const invalidApprovalIdDecision = await request(baseUrl, "/api/approvals/not-a-uuid/decision", {
    method: "POST",
    token: adminToken,
    body: { status: "approved" },
    expectStatus: 400,
  });
  if (!String(invalidApprovalIdDecision?.error || "").includes("Invalid approval id")) {
    fail("Approval decision API did not reject a malformed approval id as a client error");
  }
  await request(baseUrl, `/api/approvals/${approval.id}/decision`, {
    method: "POST",
    token: memberToken,
    body: { status: "approved" },
    expectStatus: 403,
  });
  await request(baseUrl, `/api/approvals/${approval.id}/decision`, {
    method: "POST",
    token: billingUsageAdminToken,
    body: { status: "approved" },
    expectStatus: 403,
  });
  const partialApproval = await request(baseUrl, `/api/approvals/${approval.id}/decision`, {
    method: "POST",
    token: adminToken,
    body: { status: "approved" },
  });
  if (partialApproval.status !== "pending" || partialApproval.approvalDecision?.approvalsReceived !== 1 || partialApproval.approvalDecision?.minApprovals !== 2) {
    fail("First configured approver should record a partial approval without meeting minApprovals");
  }
  const duplicateApprovalDecision = await request(baseUrl, `/api/approvals/${approval.id}/decision`, {
    method: "POST",
    token: adminToken,
    body: { status: "denied" },
    expectStatus: 409,
  });
  if (!String(duplicateApprovalDecision?.error || "").includes("already recorded")) {
    fail("Approval decision API allowed an approver to revise an existing decision");
  }
  const finalApproval = await request(baseUrl, `/api/approvals/${approval.id}/decision`, {
    method: "POST",
    token: ownerToken,
    body: { status: "approved" },
  });
  if (finalApproval.status !== "approved" || finalApproval.approvalDecision?.approvalsReceived !== 2 || finalApproval.approvalDecision?.minApprovals !== 2) {
    fail("Second configured approver should approve once minApprovals is met");
  }
  const ownerOnlyApproval = await request(baseUrl, "/api/approvals", {
    method: "POST",
    token: ownerToken,
    body: { action: "exec:shell", resource: "cloud-computer", payload: { reason: "owner-only visibility smoke" } },
  });
  const memberVisibleApprovals = await request(baseUrl, "/api/approvals", { token: memberToken });
  if (!memberVisibleApprovals.items.some((item) => item.id === approval.id)) {
    fail("Member approval list did not include the member-requested approval");
  }
  if (memberVisibleApprovals.items.some((item) => item.id === ownerOnlyApproval.id)) {
    fail("Member approval list leaked an approval the member neither requested nor was assigned to decide");
  }
  if (options.runSql) {
    const malformedApprovalId = `00000000-0000-4000-8000-${suffix.toLowerCase()}0000`;
    await options.runSql(`INSERT INTO approvals (id, workspace_id, action, resource, payload) VALUES ('${malformedApprovalId}', '${summary.workspaceId}', 'exec:shell', 'cloud-computer', '{}'::jsonb)`);
    const malformedApprovalDecision = await request(baseUrl, `/api/approvals/${malformedApprovalId}/decision`, {
      method: "POST",
      token: adminToken,
      body: { status: "approved" },
      expectStatus: 409,
    });
    if (!String(malformedApprovalDecision?.error || "").includes("valid configured approver requirement")) {
      fail("Approval decision API accepted a pending approval without a valid configured approver requirement");
    }
  }

  if (internalToken) {
    await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      expectStatus: 404,
      body: {
        workspaceId: "00000000-0000-4000-8000-000000000000",
        type: "job.completed",
        metadata: { smoke: true, invalidWorkspace: true },
      },
    });
    const malformedOpenClawEvent = await requestRaw(baseUrl, "/internal/openclaw/events", {
      internalToken,
      contentType: "application/json",
      expectStatus: 400,
      body: "{",
    });
    if (!String(malformedOpenClawEvent?.error || "").includes("Invalid JSON")) {
      fail("Malformed OpenClaw event JSON was not rejected as a client error");
    }
    const oversizedOpenClawEvent = await requestRaw(baseUrl, "/internal/openclaw/events", {
      internalToken,
      contentType: "application/json",
      expectStatus: 413,
      body: JSON.stringify({
        workspaceId: summary.workspaceId,
        type: "job.completed",
        metadata: { smoke: true, payload: "x".repeat(1024 * 1024) },
      }),
    });
    if (!String(oversizedOpenClawEvent?.error || "").includes("1 MiB")) {
      fail("Oversized OpenClaw event JSON was not rejected with the body size limit");
    }
    const invalidOpenClawEventType = await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      expectStatus: 400,
      body: {
        workspaceId: summary.workspaceId,
        type: "job.completed\nbad",
        metadata: { smoke: true, invalidType: true },
      },
    });
    if (!String(invalidOpenClawEventType?.error || "").includes("Invalid request")) {
      fail("Invalid OpenClaw event type was not rejected as a client error");
    }
    const invalidOpenClawRunId = await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      expectStatus: 400,
      body: {
        workspaceId: summary.workspaceId,
        runId: "r".repeat(513),
        type: "job.completed",
        metadata: { smoke: true, invalidRunId: true },
      },
    });
    if (!String(invalidOpenClawRunId?.error || "").includes("Invalid request")) {
      fail("Oversized OpenClaw run ID was not rejected as a client error");
    }
    const oversizedOpenClawMetadata = await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      expectStatus: 400,
      body: {
        workspaceId: summary.workspaceId,
        type: "job.completed",
        metadata: Object.fromEntries(Array.from({ length: 101 }, (_, index) => [`key${index}`, index])),
      },
    });
    if (!String(oversizedOpenClawMetadata?.error || "").includes("Invalid request")) {
      fail("Internal OpenClaw event API accepted oversized metadata");
    }
    const oversizedOpenClawUsage = await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      expectStatus: 400,
      body: {
        workspaceId: summary.workspaceId,
        type: "usage.recorded",
        usage: {
          inputTokens: 2_147_483_648,
          outputTokens: 0,
          estimatedCostUsd: 1_000_000,
        },
        metadata: { smoke: true, invalidUsage: true },
      },
    });
    if (!String(oversizedOpenClawUsage?.error || "").includes("Invalid request")) {
      fail("Internal OpenClaw event API accepted oversized usage numbers");
    }
    await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      body: {
        workspaceId: summary.workspaceId,
        sessionKey: `smoke-session-${suffix}`,
        runId: `smoke-run-${suffix}`,
        type: "job.completed",
        slackChannelId: channelId,
        slackUserId: memberSlackUserId,
        usage: {
          provider: "openai",
          model: "gpt-5",
          inputTokens: 12,
          outputTokens: 34,
          toolName: "smoke",
          estimatedCostUsd: 0.001,
        },
        metadata: {
          smoke: true,
          apiKey: modelApiKey,
          authorization: slackBotToken,
          nested: {
            note: `app token ${slackAppToken}`,
            integrationToken: integrationSecretValue,
          },
        },
      },
    });
    await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      body: {
        workspaceId: summary.workspaceId,
        sessionKey: `smoke-session-${suffix}`,
        runId: `smoke-run-${suffix}`,
        type: "job.completed",
        slackChannelId: channelId,
        slackUserId: memberSlackUserId,
        metadata: {
          smoke: true,
          retry: true,
          apiKey: modelApiKey,
        },
      },
    });
    await request(baseUrl, "/internal/openclaw/events", {
      method: "POST",
      internalToken,
      body: {
        workspaceId: summary.workspaceId,
        sessionKey: `admin-session-${suffix}`,
        runId: `admin-run-${suffix}`,
        type: "job.completed",
        slackChannelId: channelId,
        slackUserId: adminSlackUserId,
        metadata: {
          smoke: true,
          adminVisibleOnly: true,
        },
      },
    });
  }
  const sessions = await request(baseUrl, "/api/sessions", { token: adminToken });
  const jobs = await request(baseUrl, "/api/jobs", { token: adminToken });
  if (internalToken && !sessions.items.some((item) => item.openclaw_session_key === `smoke-session-${suffix}`)) {
    fail("Session list did not include the ingested OpenClaw session");
  }
  if (internalToken && !jobs.items.some((item) => item.openclaw_run_id === `smoke-run-${suffix}`)) {
    fail("Job list did not include the ingested OpenClaw job");
  }
  if (internalToken && jobs.items.filter((item) => item.openclaw_run_id === `smoke-run-${suffix}`).length !== 1) {
    fail("Repeated OpenClaw event runId created duplicate job records");
  }
  const memberSessionsAfterIngest = await request(baseUrl, "/api/sessions", { token: memberToken });
  const memberJobsAfterIngest = await request(baseUrl, "/api/jobs", { token: memberToken });
  if (internalToken && !memberSessionsAfterIngest.items.some((item) => item.openclaw_session_key === `smoke-session-${suffix}`)) {
    fail("Member session list did not include the member's own OpenClaw session");
  }
  if (internalToken && memberSessionsAfterIngest.items.some((item) => item.openclaw_session_key === `admin-session-${suffix}`)) {
    fail("Member session list leaked another user's OpenClaw session");
  }
  if (internalToken && !memberJobsAfterIngest.items.some((item) => item.openclaw_run_id === `smoke-run-${suffix}`)) {
    fail("Member job list did not include the member's own OpenClaw job");
  }
  if (internalToken && memberJobsAfterIngest.items.some((item) => item.openclaw_run_id === `admin-run-${suffix}`)) {
    fail("Member job list leaked another user's OpenClaw job");
  }

  if (options.runSql) {
    await options.runSql(`INSERT INTO usage_events (workspace_id, provider, model, input_tokens, output_tokens, tool_name, estimated_cost_usd, created_at) VALUES ('${summary.workspaceId}', 'openai', 'gpt-5', 100, 200, 'old-smoke', 0.5, now() - interval '10 days')`);
    await options.runSql(`
      WITH expired_session AS (
        INSERT INTO sessions (workspace_id, openclaw_session_key, slack_channel_id, slack_user_id, status, last_event_at)
        VALUES ('${summary.workspaceId}', 'purge-expired-session-${suffix}', '${channelId}', '${memberSlackUserId}', 'observed', now() - interval '10 days')
        RETURNING id
      ),
      expired_job AS (
        INSERT INTO jobs (workspace_id, session_id, openclaw_run_id, status, started_at, created_at)
        SELECT '${summary.workspaceId}', id, 'purge-expired-run-${suffix}', 'observed', now(), now()
        FROM expired_session
        RETURNING id
      )
      INSERT INTO usage_events (workspace_id, session_id, job_id, provider, model, input_tokens, output_tokens, tool_name, estimated_cost_usd, created_at)
      SELECT '${summary.workspaceId}', NULL::uuid, id, 'openai', 'gpt-5', 2, 2, 'purge-linked-usage', 0.002, now()
      FROM expired_job
    `);
  }

  const settings = await request(baseUrl, "/api/settings", { token: adminToken });
  if (settings.retentionDays < 1) fail("Settings API returned an invalid retention window");
  const invalidGatewayUrl = await request(baseUrl, "/api/settings", {
    method: "PUT",
    token: adminToken,
    expectStatus: 400,
    body: { openclawGatewayUrl: "ftp://127.0.0.1:18790" },
  });
  if (!String(invalidGatewayUrl?.error || "").includes("Invalid request")) {
    fail("Settings API accepted a non-HTTP OpenClaw gateway URL");
  }
  const updatedSettings = await request(baseUrl, "/api/settings", {
    method: "PUT",
    token: adminToken,
    body: { retentionDays: 1, workspaceName: settings.workspaceName, openclawGatewayUrl: "http://127.0.0.1:18790" },
  });
  if (updatedSettings.settings.retentionDays !== 1) fail("Settings API did not persist retentionDays");
  if (!updatedSettings.config?.checksum) fail("Settings API did not regenerate config after OpenClaw gateway URL changed");
  const settingsConfig = await request(baseUrl, "/api/openclaw/config", { token: adminToken });
  if (settingsConfig.config.gateway.remote.url !== "ws://127.0.0.1:18790") {
    fail(`Settings update did not propagate OpenClaw gateway URL into generated config: ${settingsConfig.config.gateway.remote.url}`);
  }
  expectedConfigChecksum = updatedSettings.config.checksum;
  const purge = await request(baseUrl, "/api/retention/purge", { method: "POST", token: adminToken, body: {} });
  if (options.runSql && purge.deleted.usageEvents < 1) fail("Retention purge did not delete the old usage event");
  if (options.runSql && purge.deleted.usageEventsLinkedToExpiredSessions < 1) {
    fail("Retention purge did not delete usage linked to expired sessions/jobs");
  }
  if (options.runSql && purge.deleted.jobsLinkedToExpiredSessions < 1) {
    fail("Retention purge did not delete jobs linked to expired sessions");
  }
  if (options.runSql) {
    const usageAfterPurge = await request(baseUrl, "/api/usage", { token: adminToken });
    if (usageAfterPurge.items.some((item) => item.tool_name === "purge-linked-usage")) {
      fail("Retention purge left usage linked to expired sessions/jobs");
    }
    const jobsAfterPurge = await request(baseUrl, "/api/jobs", { token: adminToken });
    if (jobsAfterPurge.items.some((item) => item.openclaw_run_id === `purge-expired-run-${suffix}`)) {
      fail("Retention purge left a job linked to an expired session");
    }
  }

  const customUsageSummary = await request(baseUrl, "/api/usage/summary", { token: usageAnalystToken });
  await request(baseUrl, "/api/usage", { token: usageAnalystToken });
  if (internalToken && customUsageSummary.totals.events < 1) fail("Custom role could not read usage summary");
  const smokeModelUsage = customUsageSummary.byModel?.find((item) => item.provider === "openai" && item.model === "gpt-5");
  if (internalToken && (!smokeModelUsage || Number(smokeModelUsage.input_tokens) < 12 || Number(smokeModelUsage.output_tokens) < 34 || Number(smokeModelUsage.estimated_cost_usd) < 0.001)) {
    fail("Usage summary did not expose the expected OpenAI model token and cost aggregate");
  }
  const smokeToolUsage = customUsageSummary.byTool?.find((item) => item.tool_name === "smoke");
  if (internalToken && (!smokeToolUsage || Number(smokeToolUsage.estimated_cost_usd) < 0.001)) {
    fail("Usage summary did not expose the expected tool cost aggregate");
  }
  const openClawUsageCostModel = customUsageSummary.byModel?.find((item) => item.provider === "openclaw" && item.model === "usage-cost");
  if (!openClawUsageCostModel || Number(openClawUsageCostModel.estimated_cost_usd) < 0.001) {
    fail("Usage summary did not expose the expected OpenClaw usage-cost aggregate");
  }
  const openClawUsageCostTool = customUsageSummary.byTool?.find((item) => item.tool_name === "gateway-usage-cost");
  if (!openClawUsageCostTool || Number(openClawUsageCostTool.estimated_cost_usd) < 0.001) {
    fail("Usage summary did not expose the expected gateway usage-cost aggregate");
  }
  await request(baseUrl, "/api/usage", { token: billingUsageAdminToken });
  const billingUsageSummary = await request(baseUrl, "/api/usage/summary", { token: billingUsageAdminToken });
  if (internalToken && billingUsageSummary.totals.events < 1) fail("Billing usage admin could not read usage summary");

  if (options.restartApp) {
    await options.restartApp();
    await request(baseUrl, "/api/auth/me", { token: adminToken });
    const restartedSummary = await request(baseUrl, "/api/summary", { token: adminToken });
    if (restartedSummary.workspaceId !== summary.workspaceId) fail("Workspace changed after Operant restart");
    const restartedUsers = await request(baseUrl, "/api/users", { token: adminToken });
    if (!restartedUsers.users.some((user) => user.slack_user_id === adminSlackUserId && user.roles?.includes("admin"))) {
      fail("Admin role assignment did not survive Operant restart");
    }
    if (!restartedUsers.users.some((user) => user.slack_user_id === usageAnalystSlackUserId && user.roles?.includes("usage_analyst"))) {
      fail("Custom role assignment did not survive Operant restart");
    }
    if (!restartedUsers.users.some((user) => user.slack_user_id === billingUsageAdminSlackUserId && user.roles?.includes("billing_usage_admin"))) {
      fail("Billing usage admin role assignment did not survive Operant restart");
    }
    if (!restartedUsers.users.some((user) => user.slack_user_id === viewerSlackUserId && user.roles?.includes("viewer"))) {
      fail("Viewer role assignment did not survive Operant restart");
    }
    const restartedRoles = await request(baseUrl, "/api/roles", { token: adminToken });
    if (!restartedRoles.roles.some((role) => role.name === "usage_analyst" && role.builtin === false)) {
      fail("Custom role definition did not survive Operant restart");
    }
    const restartedConfig = await request(baseUrl, "/api/openclaw/config", { token: adminToken });
    if (restartedConfig.checksum !== expectedConfigChecksum) fail("Latest generated OpenClaw config did not survive Operant restart");
    const restartedApprovals = await request(baseUrl, "/api/approvals", { token: adminToken });
    if (!restartedApprovals.items.some((item) => item.id === approval.id && item.status === "approved")) {
      fail("Approval decision did not survive Operant restart");
    }
    const restartedUsage = await request(baseUrl, "/api/usage", { token: adminToken });
    if (internalToken && restartedUsage.items.length < 1) fail("Usage event did not survive Operant restart");
    const restartedUsageSummary = await request(baseUrl, "/api/usage/summary", { token: adminToken });
    if (internalToken && restartedUsageSummary.totals.events < 1) fail("Usage summary did not survive Operant restart");
    await request(baseUrl, "/api/usage", { token: usageAnalystToken });
    await request(baseUrl, "/api/usage/summary", { token: usageAnalystToken });
    await request(baseUrl, "/api/usage", { token: billingUsageAdminToken });
    await request(baseUrl, "/api/usage/summary", { token: billingUsageAdminToken });
    await request(baseUrl, "/api/usage", { token: viewerToken });
    await request(baseUrl, "/api/usage/summary", { token: viewerToken });
    await request(baseUrl, "/api/settings", {
      method: "PUT",
      token: usageAnalystToken,
      body: { retentionDays: 3 },
      expectStatus: 403,
    });
    restartVerified = true;
  }

  const usage = await request(baseUrl, "/api/usage", { token: adminToken });
  if (internalToken && usage.items.length < 1) fail("Expected at least one usage event after internal OpenClaw event ingest");
  const usageSummary = await request(baseUrl, "/api/usage/summary", { token: adminToken });
  if (internalToken) {
    if (usageSummary.totals.events < 1) fail("Usage summary did not count the ingested usage event");
    if (usageSummary.totals.input_tokens < 12 || usageSummary.totals.output_tokens < 34 || Number(usageSummary.totals.estimated_cost_usd) < 0.001) {
      fail("Usage summary totals did not include the ingested usage event");
    }
    if (!usageSummary.byModel.some((item) => item.provider === "openai" && item.model === "gpt-5" && item.total_tokens >= 46)) {
      fail("Usage summary did not include the OpenAI GPT-5 model breakdown");
    }
    if (!usageSummary.byTool.some((item) => item.tool_name === "smoke" && item.total_tokens === 46)) {
      fail("Usage summary did not include the smoke tool breakdown");
    }
  }
  const exported = await request(baseUrl, "/api/export", { method: "POST", token: adminToken, body: {} });
  const exportText = JSON.stringify(exported.payload);
  const seededSecrets = [slackBotToken, slackAppToken, modelApiKey, integrationSecretValue];
  if (seededSecrets.some((secret) => exportText.includes(secret))) {
    fail("Retention export leaked credential secret material");
  }
  const exportedCredentials = exported.payload?.data?.credentials;
  if (!Array.isArray(exportedCredentials) || exportedCredentials.length < 4 || (exported.payload?.counts?.credentials ?? 0) < 4) {
    fail(`Retention export did not include metadata for all saved credentials: ${JSON.stringify(exported.payload?.counts)}`);
  }
  for (const credential of exportedCredentials) {
    if ("encrypted_value" in credential || "encryptedValue" in credential) {
      fail("Retention export leaked encrypted credential fields");
    }
    for (const key of ["id", "kind", "label", "secret_ref_id", "created_at", "updated_at"]) {
      if (!(key in credential)) fail(`Retention export credential metadata missing ${key}`);
    }
  }
  const exportedSecretRefs = new Set(exportedCredentials.map((credential) => credential.secret_ref_id));
  if (![
    `workspaces/${summary.workspaceId}/slack/botToken`,
    `workspaces/${summary.workspaceId}/slack/appToken`,
    `workspaces/${summary.workspaceId}/models/openai/apiKey`,
    integrationCredential.credential.secret_ref_id,
  ].every((secretRefId) => exportedSecretRefs.has(secretRefId))) {
    fail("Retention export did not include metadata for every saved credential");
  }
  const exportedApprovalDecisions = exported.payload?.data?.approvalDecisions;
  const matchingApprovalDecisions = Array.isArray(exportedApprovalDecisions)
    ? exportedApprovalDecisions.filter((decision) => decision.approval_id === approval.id)
    : [];
  if (matchingApprovalDecisions.length !== 2 || (exported.payload?.counts?.approvalDecisions ?? 0) < 2) {
    fail(`Retention export did not include the approval decision ledger: ${JSON.stringify(exported.payload?.counts)}`);
  }
  for (const decision of matchingApprovalDecisions) {
    for (const key of ["id", "approval_id", "decided_by_user_id", "status", "created_at"]) {
      if (!(key in decision)) fail(`Retention export approval decision metadata missing ${key}`);
    }
    if (decision.status !== "approved") fail("Retention export included an unexpected approval decision status");
  }
  await request(baseUrl, "/api/wipe", { method: "POST", token: adminToken, body: { scope: "usage" } });
  const wipedUsage = await request(baseUrl, "/api/usage", { token: adminToken });
  if (wipedUsage.items.length !== 0) fail("Usage wipe did not remove usage events");
  if (options.runSql) {
    await options.runSql(`
      WITH inserted_session AS (
        INSERT INTO sessions (workspace_id, openclaw_session_key, slack_channel_id, slack_user_id, status)
        VALUES ('${summary.workspaceId}', 'session-wipe-${suffix}', '${channelId}', '${memberSlackUserId}', 'observed')
        RETURNING id
      ),
      inserted_job AS (
        INSERT INTO jobs (workspace_id, session_id, openclaw_run_id, status)
        SELECT '${summary.workspaceId}', id, 'session-wipe-run-${suffix}', 'observed'
        FROM inserted_session
        RETURNING id, session_id
      )
      INSERT INTO usage_events (workspace_id, session_id, job_id, provider, model, input_tokens, output_tokens, tool_name, estimated_cost_usd)
      SELECT '${summary.workspaceId}', session_id, id, 'openai', 'gpt-5', 1, 1, 'session-wipe', 0.001
      FROM inserted_job
    `);
    await request(baseUrl, "/api/wipe", { method: "POST", token: adminToken, body: { scope: "sessions" } });
    const sessionsAfterSessionWipe = await request(baseUrl, "/api/sessions", { token: adminToken });
    const jobsAfterSessionWipe = await request(baseUrl, "/api/jobs", { token: adminToken });
    const usageAfterSessionWipe = await request(baseUrl, "/api/usage", { token: adminToken });
    if (sessionsAfterSessionWipe.items.some((item) => item.openclaw_session_key === `session-wipe-${suffix}`)) {
      fail("Sessions wipe did not remove the targeted session");
    }
    if (jobsAfterSessionWipe.items.some((item) => item.openclaw_run_id === `session-wipe-run-${suffix}`)) {
      fail("Sessions wipe did not remove the targeted job");
    }
    if (usageAfterSessionWipe.items.some((item) => item.tool_name === "session-wipe")) {
      fail("Sessions wipe left usage events linked to wiped sessions/jobs");
    }
  }
  const logoutProbeToken = (await login(baseUrl, viewerSlackUserId, adminLoginToken)).token;
  await request(baseUrl, "/api/auth/me", { token: logoutProbeToken });
  await request(baseUrl, "/api/auth/logout", { method: "POST", token: logoutProbeToken, body: {} });
  await request(baseUrl, "/api/auth/me", { token: logoutProbeToken, expectStatus: 401 });
  const invalidAdminTokenLogin = await request(baseUrl, "/api/auth/login", {
    method: "POST",
    body: { slackUserId: viewerSlackUserId, adminLoginToken: `wrong-${adminLoginToken}` },
    expectStatus: 401,
  });
  if (!String(invalidAdminTokenLogin?.error || "").includes("admin login token")) {
    fail("Invalid admin login token was not rejected for dashboard login");
  }
  const auditLog = await request(baseUrl, "/api/audit", { token: adminToken });
  assertAuditEventTypes(auditLog, [
    "bootstrap.completed",
    "credentials.updated",
    "auth.login",
    "auth.login_denied",
    "auth.logout",
    "openclaw.config.generated",
    "roles.upserted",
    "users.upserted",
    "rbac.denied",
    "integration_credential.upserted",
    "policy.updated",
    "openclaw.check.status",
    "openclaw.check.doctor",
    "openclaw.check.config-validate",
    "openclaw.check.secrets-reload",
    "openclaw.check.approvals-get",
    "openclaw.check.cron-status",
    "openclaw.check.tasks-list",
    "openclaw.check.usage-cost",
    "openclaw.check.security-audit",
    "openclaw.check.channels-status",
    "openclaw.observations.sync",
    "policy.evaluated",
    "approval.requested",
    "approval.decision_denied",
    "approval.approved",
    "settings.updated",
    "retention.purge_completed",
    "retention.export_completed",
    "retention.wipe_completed",
    ...(internalToken ? ["openclaw.job.completed"] : []),
  ], {
    approvalId: approval.id,
    secrets: [slackBotToken, slackAppToken, modelApiKey, integrationSecretValue],
  });
  const workspaceWipe = await request(baseUrl, "/api/wipe", { method: "POST", token: adminToken, body: { scope: "workspace" } });
  if ((workspaceWipe.payload?.deleted?.adminSessions ?? 0) < 1) {
    fail("Workspace wipe did not revoke dashboard admin sessions");
  }
  await request(baseUrl, "/api/auth/me", { token: adminToken, expectStatus: 401 });

  log("Smoke passed.");
  log(JSON.stringify({
    workspaceId: summary.workspaceId,
    ownerSlackUserId,
    adminSlackUserId,
    integrationAdminSlackUserId,
    usageAnalystSlackUserId,
    billingUsageAdminSlackUserId,
    viewerSlackUserId,
    memberSlackUserId,
    channelId,
    configChecksum: generated.checksum,
    restartVerified,
  }, null, 2));
}

try {
  let baseUrl = process.env.OPERANT_SMOKE_BASE_URL || "http://127.0.0.1:8080";
  let internalToken = process.env.OPERANT_SMOKE_INTERNAL_TOKEN || process.env.OPERANT_INTERNAL_TOKEN || "";
  let smokeOptions = {};
  if (managed) {
    const managedStack = await startManagedStack();
    baseUrl = managedStack.baseUrl;
    internalToken = managedStack.internalToken;
    smokeOptions = {
      restartApp: managedStack.restartApp,
      runSql: managedStack.runSql,
      configPath: managedStack.configPath,
      adminLoginToken: managedStack.adminLoginToken,
    };
  }
  await runSmoke(baseUrl, internalToken, smokeOptions);
  await cleanup();
} catch (error) {
  await cleanup();
  process.stderr.write(`Smoke failed: ${error.message}\n`);
  process.exit(1);
}
