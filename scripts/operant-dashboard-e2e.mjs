#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const chromePath = process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const childProcesses = [];
let tempRoot = null;
let pipedreamStub = null;

function log(message) {
  process.stdout.write(`${message}\n`);
}

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
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
  if (pipedreamStub) {
    await new Promise((resolve) => pipedreamStub.close(resolve));
    pipedreamStub = null;
  }
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

async function waitFor(name, fn, timeoutMs = 25_000) {
  const start = Date.now();
  let lastError;
  while (Date.now() - start < timeoutMs) {
    try {
      const result = await fn();
      if (result !== false) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`${name} did not become ready: ${lastError?.message || "timed out"}`);
}

async function request(baseUrl, route, options = {}) {
  const headers = { accept: "application/json" };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  const response = await fetch(new URL(route, baseUrl), {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(`${options.method || "GET"} ${route} failed with ${response.status}: ${payload?.error || response.statusText}`);
  return payload;
}

async function startManagedStack() {
  tempRoot = await mkdtemp(path.join(os.tmpdir(), "operant-dashboard-e2e-"));
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
    gateway: { reachable: true },
    sessions: { count: 1, recent: [{ key: "agent:main:slack:channel:dashboard", sessionId: "dashboard-session", updatedAt: Date.now(), inputTokens: 11, outputTokens: 17, totalTokens: 28, model: "gpt-5", kind: "channel" }] },
    tasks: { total: 1, active: 0, terminal: 1 },
    securityAudit: { summary: { critical: 0 } }
  }));
  process.exit(0);
}
if (args[0] === "sessions") {
  console.log(JSON.stringify({ count: 1, sessions: [{ key: "agent:main:slack:channel:dashboard", sessionId: "dashboard-session", updatedAt: Date.now(), inputTokens: 11, outputTokens: 17, totalTokens: 28, model: "gpt-5", modelProvider: "openai", agentRuntime: { id: "pi" } }] }));
  process.exit(0);
}
if (args[0] === "tasks" && args[1] === "list") {
  console.log(JSON.stringify({ count: 1, tasks: [{ taskId: "dashboard-task", runId: "dashboard-run", childSessionKey: "agent:main:slack:channel:dashboard", status: "succeeded", startedAt: Date.now() - 1000, endedAt: Date.now() }] }));
  process.exit(0);
}
if (args[0] === "gateway" && args[1] === "usage-cost") {
  console.log(JSON.stringify({ updatedAt: Date.now(), days: 30, daily: [{ date: new Date().toISOString().slice(0, 10), input: 11, output: 17, totalTokens: 28, totalCost: 0.0007, missingCostEntries: 0 }], totals: { input: 11, output: 17, totalTokens: 28, totalCost: 0.0007, missingCostEntries: 0 } }));
  process.exit(0);
}
if (args[0] === "config" && args[1] === "validate") {
  console.log(JSON.stringify({ valid: true, errors: [] }));
  process.exit(0);
}
if (args[0] === "security" && args[1] === "audit") {
  console.log(JSON.stringify({ summary: { critical: 0, high: 0, medium: 0 }, findings: [] }));
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
if (args[0] === "cron" && args[1] === "status") {
  console.log(JSON.stringify({ scheduler: "running", jobs: 1, enabled: 1 }));
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
  const pgPort = Number(await getFreePort());
  const appPort = Number(process.env.OPERANT_DASHBOARD_E2E_PORT || await getFreePort());
  const pipedreamPort = Number(await getFreePort());
  const adminLoginToken = `dashboard-admin-${randomBytes(16).toString("hex")}`;

  pipedreamStub = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : {};
    const url = new URL(req.url || "/", `http://127.0.0.1:${pipedreamPort}`);
    const send = (status, payload, contentType = "application/json") => {
      res.writeHead(status, { "content-type": contentType });
      res.end(contentType === "application/json" ? JSON.stringify(payload) : payload);
    };
    if (url.pathname === "/v1/oauth/token") {
      send(200, { access_token: "pd-dashboard-token", expires_in: 3600 });
      return;
    }
    if (url.pathname === "/v1/apps") {
      const q = (url.searchParams.get("q") || "").toLowerCase();
      const apps = [
        { id: "app_gmail", name: "Gmail", name_slug: "gmail", description: "Read and send email" },
        { id: "app_github", name: "GitHub", name_slug: "github", description: "Issues, pull requests, and repos" },
        { id: "app_notion", name: "Notion", name_slug: "notion", description: "Docs and databases" },
      ].filter((app) => !q || app.name.toLowerCase().includes(q) || app.name_slug.includes(q));
      send(200, { data: apps, page_info: null });
      return;
    }
    if (url.pathname === "/v1/connect/proj_dashboard/tokens") {
      send(200, {
        token: `ctok_dashboard_${body.user_id || "user"}`,
        expires_at: new Date(Date.now() + 300_000).toISOString(),
      });
      return;
    }
    if (url.pathname === "/v1/connect/proj_dashboard/accounts") {
      send(200, {
        data: [
          { id: "apn_dashboard_github", app_slug: "github", app_name: "GitHub", external_user_id: url.searchParams.get("external_user_id"), name: "dashboard-github", healthy: true },
        ],
      });
      return;
    }
    if (url.pathname === "/v1/connect/proj_dashboard/accounts/apn_dashboard_github" && req.method === "DELETE") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (url.pathname === "/v3") {
      const app = req.headers["x-pd-app-slug"] || "gmail";
      send(200, `event: message\ndata: ${JSON.stringify({
        jsonrpc: "2.0",
        id: body.id,
        result: { tools: [{ name: `${app}-list`, description: `List ${app} records` }, { name: `${app}-create`, description: `Create ${app} record` }] },
      })}\n\n`, "text/event-stream");
      return;
    }
    send(404, { error: "not_found", path: url.pathname });
  });
  await new Promise((resolve) => pipedreamStub.listen(pipedreamPort, "127.0.0.1", resolve));

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
    OPERANT_SECRET_KEY: randomBytes(32).toString("base64"),
    OPERANT_INTERNAL_TOKEN: `dashboard-internal-${randomBytes(8).toString("hex")}`,
    OPERANT_ADMIN_LOGIN_TOKEN: adminLoginToken,
    OPERANT_HOST: "127.0.0.1",
    OPERANT_PORT: String(appPort),
    OPENCLAW_GATEWAY_TOKEN: `dashboard-gateway-${randomBytes(8).toString("hex")}`,
    OPENCLAW_GATEWAY_URL: "http://127.0.0.1:18789",
    OPENCLAW_CONFIG_PATH: path.join(configDir, "openclaw.json"),
    OPENCLAW_CLI_COMMAND: fakeOpenClaw,
    OPENCLAW_SECRET_RESOLVER_COMMAND: process.execPath,
    OPENCLAW_SECRET_RESOLVER_SCRIPT: path.join(repoRoot, "deploy/openclaw/operant-secret-resolver.mjs"),
    PIPEDREAM_DIAGNOSTICS_TIMEOUT_MS: "200",
    PIPEDREAM_PROJECT_CLIENT_ID: "dashboard-client-id",
    PIPEDREAM_PROJECT_CLIENT_SECRET: "dashboard-client-secret",
    PIPEDREAM_PROJECT_ID: "proj_dashboard",
    PIPEDREAM_ENVIRONMENT: "development",
    PIPEDREAM_API_BASE_URL: `http://127.0.0.1:${pipedreamPort}/v1`,
    PIPEDREAM_OAUTH_TOKEN_URL: `http://127.0.0.1:${pipedreamPort}/v1/oauth/token`,
    PIPEDREAM_CONNECT_BASE_URL: "https://pipedream.com/_static/connect.html",
    OPERANT_MCP_SOURCE_PIPEDREAM_URL: `http://127.0.0.1:${pipedreamPort}/v3`,
  };
  const baseUrl = `http://127.0.0.1:${appPort}`;
  spawnManaged(process.execPath, ["apps/control-plane/dist/src/server.js"], { env: appEnv, prefix: "operant" });
  await waitFor("Operant", () => request(baseUrl, "/readyz"));
  return { baseUrl, adminLoginToken };
}

class CdpPage {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.id = 0;
    this.pending = new Map();
    this.consoleErrors = [];
    this.pageErrors = [];
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    this.ws.addEventListener("message", (event) => this.handleMessage(event));
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve, { once: true });
      this.ws.addEventListener("error", reject, { once: true });
    });
    await this.send("Page.enable");
    await this.send("Runtime.enable");
    await this.send("Log.enable");
  }

  handleMessage(event) {
    const message = JSON.parse(event.data);
    if (message.id && this.pending.has(message.id)) {
      const { resolve, reject } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) reject(new Error(`${message.error.message}: ${message.error.data || ""}`));
      else resolve(message.result || {});
      return;
    }
    if (message.method === "Runtime.consoleAPICalled" && ["error", "assert"].includes(message.params.type)) {
      this.consoleErrors.push(message.params.args.map((arg) => arg.value || arg.description || arg.type).join(" "));
    }
    if (message.method === "Runtime.exceptionThrown") {
      this.pageErrors.push(message.params.exceptionDetails?.text || "Runtime exception");
    }
    if (message.method === "Log.entryAdded" && message.params.entry.level === "error") {
      this.consoleErrors.push(message.params.entry.text);
    }
  }

  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (!this.pending.has(id)) return;
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, 20_000);
    });
  }

  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.text || result.exceptionDetails.exception?.description || "Page evaluation failed");
    }
    return result.result?.value;
  }

  async waitForSelector(selector, timeoutMs = 20_000) {
    await waitFor(`selector ${selector}`, () => this.evaluate(`Boolean(document.querySelector(${JSON.stringify(selector)}))`), timeoutMs);
  }

  async waitForText(selector, expected, timeoutMs = 20_000) {
    await waitFor(`${selector} to include ${expected}`, async () => {
      const text = await this.evaluate(`document.querySelector(${JSON.stringify(selector)})?.textContent || ""`);
      return text.includes(expected);
    }, timeoutMs);
  }

  async setViewport(width, height) {
    await this.send("Emulation.setDeviceMetricsOverride", {
      width,
      height,
      deviceScaleFactor: 1,
      mobile: width < 640,
    });
  }

  async screenshot(filePath) {
    const result = await this.send("Page.captureScreenshot", { format: "png", fromSurface: true, captureBeyondViewport: false });
    await writeFile(filePath, Buffer.from(result.data, "base64"));
  }

  async close() {
    this.ws?.close();
  }
}

async function openBrowserPage(baseUrl) {
  await stat(chromePath).catch(() => {
    throw new Error(`Chrome executable not found at ${chromePath}. Set CHROME_PATH to run dashboard E2E.`);
  });
  const debugPort = Number(await getFreePort());
  const userDataDir = path.join(tempRoot, "chrome-profile");
  spawnManaged(chromePath, [
    "--headless=new",
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${userDataDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-breakpad",
    "--disable-crash-reporter",
    "--disable-gpu",
    "--disable-sync",
    "about:blank",
  ], { prefix: "chrome" });
  await waitFor("Chrome DevTools", async () => {
    const response = await fetch(`http://127.0.0.1:${debugPort}/json/version`);
    return response.ok;
  });
  const targetResponse = await fetch(`http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(baseUrl)}`, { method: "PUT" });
  const target = await targetResponse.json();
  const page = new CdpPage(target.webSocketDebuggerUrl);
  await page.connect();
  await page.setViewport(1440, 1000);
  await page.waitForSelector("#credentials-form");
  await page.waitForSelector("#setup-checklist .check-item");
  return page;
}

async function submitForm(page, selector, values) {
  await page.evaluate(`(() => {
    const form = document.querySelector(${JSON.stringify(selector)});
    if (!form) throw new Error("Missing form ${selector}");
    const values = ${JSON.stringify(values)};
    for (const [name, value] of Object.entries(values)) {
      const field = form.elements[name];
      if (!field) continue;
      if (field instanceof RadioNodeList) continue;
      if (field instanceof HTMLSelectElement && field.multiple && Array.isArray(value)) {
        for (const option of field.options) option.selected = value.includes(option.value);
      } else if (field instanceof HTMLInputElement && field.type === "checkbox") {
        field.checked = Boolean(value);
      } else {
        field.value = Array.isArray(value) ? value.join(", ") : String(value);
      }
      field.dispatchEvent(new Event("input", { bubbles: true }));
      field.dispatchEvent(new Event("change", { bubbles: true }));
    }
    form.requestSubmit();
  })()`);
}

async function clickAndConfirm(page, selector) {
  await page.evaluate(`document.querySelector(${JSON.stringify(selector)})?.click()`);
  await page.waitForSelector("#confirm-modal[open]");
  await page.evaluate(`document.querySelector("#confirm-accept").click()`);
}

async function layoutCheck(page) {
  return page.evaluate(`(() => {
    const overflowing = [];
    for (const node of document.querySelectorAll("button, .status-pill, h1, h2, h3, h4, p, small, label, .nav-tab")) {
      const style = getComputedStyle(node);
      if (node.closest(".data-table-wrap, .json-block, pre")) continue;
      if (node.scrollWidth > node.clientWidth + 2 && style.overflowX === "visible") {
        overflowing.push((node.textContent || node.tagName).trim().slice(0, 80));
      }
    }
    return {
      innerWidth: window.innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
      overflowing: overflowing.slice(0, 10),
    };
  })()`);
}

async function runDashboardE2E() {
  const { baseUrl, adminLoginToken } = await startManagedStack();
  const page = await openBrowserPage(baseUrl);
  const suffix = randomBytes(4).toString("hex").toUpperCase();
  const owner = `UOWNER${suffix}`;
  const member = `UMEMBER${suffix}`;
  const channel = `COPS${suffix}`;
  const secrets = {
    bot: `xoxb-dashboard-${suffix}-bot-secret`,
    app: `xapp-dashboard-${suffix}-app-secret`,
    model: `sk-dashboard-${suffix}-model-secret`,
    integration: `github-dashboard-${suffix}-secret`,
  };

  const report = {
    baseUrl,
    startedAt: new Date().toISOString(),
    screenshots: {},
    checks: [],
  };

  await submitForm(page, "#credentials-form", {
    companyName: "Operant Dashboard E2E",
    workspaceName: `Dashboard Workspace ${suffix}`,
    adminSlackUserId: owner,
    adminLoginToken,
    slackBotToken: secrets.bot,
    slackAppToken: secrets.app,
    modelProvider: "openai",
    modelName: "gpt-5",
    modelApiKey: secrets.model,
    allowedDmUserIds: member,
    allowedChannelIds: channel,
    approvalSlackUserIds: owner,
  });
  await page.waitForText("#session-state", owner);
  try {
    await page.waitForText("#readiness-state", "Ready to run Slack acceptance");
  } catch (error) {
    const readinessDebug = await page.evaluate(`(() => ({
      state: document.querySelector("#readiness-state")?.textContent || "",
      progress: document.querySelector("#setup-progress")?.textContent || "",
      checklist: Array.from(document.querySelectorAll("#setup-checklist .check-item")).map((item) => item.textContent.trim()),
      dataResult: document.querySelector("#data-result")?.textContent || "",
      loginResult: document.querySelector("#login-result")?.textContent || "",
      toast: document.querySelector("#toast")?.textContent || ""
    }))()`);
    throw new Error(`${error.message}; readiness debug: ${JSON.stringify(readinessDebug)}; console=${JSON.stringify(page.consoleErrors)}; pageErrors=${JSON.stringify(page.pageErrors)}`);
  }
  report.checks.push("first-run credentials saved and ready state reached");

  await page.evaluate(`document.querySelector('[data-view-target="people-view"]').click()`);
  await page.waitForSelector("#user-roles-select option[value='member']");
  await submitForm(page, "#role-form", {
    name: "usage_analyst",
    permissions: "settings:read workspace\nusage:read usage",
  });
  try {
    await page.waitForText("#roles-result", "usage_analyst");
  } catch (error) {
    const roleDebug = await page.evaluate(`(() => ({
      roles: document.querySelector("#roles-result")?.textContent || "",
      toast: document.querySelector("#toast")?.textContent || "",
      formName: document.querySelector("#role-form [name=name]")?.value || "",
      permissions: document.querySelector("#role-form [name=permissions]")?.value || ""
    }))()`);
    throw new Error(`${error.message}; role debug: ${JSON.stringify(roleDebug)}; console=${JSON.stringify(page.consoleErrors)}; pageErrors=${JSON.stringify(page.pageErrors)}`);
  }
  await submitForm(page, "#user-form", {
    slackUserId: member,
    name: "Dashboard Member",
    email: "dashboard-member@example.com",
    roles: ["member"],
  });
  await page.waitForText("#users-result", member);
  report.checks.push("custom role and user role assignment saved");

  await page.evaluate(`document.querySelector('[data-view-target="data-view"]').click()`);
  await submitForm(page, "#integration-credential-form", {
    kind: "github",
    key: "apiToken",
    label: "GitHub dashboard token",
    secretValue: secrets.integration,
    slackUserId: member,
  });
  await page.waitForText("#integration-credentials-result", "github");
  await page.waitForText("#integration-credentials-result", "SecretRef");
  report.checks.push("integration credential saved as metadata-only SecretRef");

  await page.evaluate(`document.querySelector('[data-view-target="policy-view"]').click()`);
  await submitForm(page, "#policy-form", {
    slackUserId: owner,
    chatType: "direct",
    action: "message",
    resource: "slack",
  });
  await page.waitForText("#policy-result", "allow");
  report.checks.push("policy preview evaluated through dashboard");

  await page.evaluate(`document.querySelector('[data-view-target="integrations-view"]').click()`);
  await page.waitForText("#pipedream-marketplace-grid", "Gmail");
  await submitForm(page, "#pipedream-search-form", { q: "github" });
  await page.waitForText("#pipedream-marketplace-grid", "GitHub");
  await page.evaluate(`document.querySelector('#pipedream-marketplace-grid [data-app="github"] .pipedream-preview').click()`);
  try {
    await page.waitForText("#pipedream-actions", "github-list");
  } catch (error) {
    const integrationDebug = await page.evaluate(`(() => ({
      grid: document.querySelector("#pipedream-marketplace-grid")?.textContent || "",
      actions: document.querySelector("#pipedream-actions")?.textContent || "",
      result: document.querySelector("#pipedream-result")?.textContent || "",
      toast: document.querySelector("#toast")?.textContent || ""
    }))()`);
    throw new Error(`${error.message}; integration debug: ${JSON.stringify(integrationDebug)}; console=${JSON.stringify(page.consoleErrors)}; pageErrors=${JSON.stringify(page.pageErrors)}`);
  }
  await page.evaluate(`document.querySelector('#pipedream-marketplace-grid [data-app="github"] .pipedream-connect').click()`);
  await page.waitForText("#pipedream-result", "connectLinkUrl");
  await page.waitForText("#pipedream-accounts", "dashboard-github");
  report.checks.push("Pipedream marketplace search, action preview, connect link, and account status rendered");

  await page.evaluate(`document.querySelector('[data-view-target="approvals-view"]').click()`);
  await submitForm(page, "#approval-form", {
    action: "exec:shell",
    resource: "cloud-computer",
    reason: "dashboard e2e approval",
  });
  await page.waitForText("#approvals-result", "exec:shell");
  await page.evaluate(`document.querySelector('#approvals-result button[data-status="approved"]').click()`);
  await page.waitForText("#approval-result", "approved");
  report.checks.push("approval created and approved through dashboard");

  await page.evaluate(`document.querySelector('[data-view-target="openclaw-view"]').click()`);
  await clickAndConfirm(page, "#sync-openclaw");
  await page.waitForText("#openclaw-result", "sessionsUpserted");
  await clickAndConfirm(page, 'button.openclaw-check[data-check="config-validate"]');
  await page.waitForText("#openclaw-result", "valid");
  await clickAndConfirm(page, 'button.openclaw-check[data-check="secrets-reload"]');
  await page.waitForText("#openclaw-result", "reloaded");
  report.checks.push("OpenClaw sync, config validate, and reload paths ran through safe stubs");

  await page.evaluate(`document.querySelector('[data-view-target="usage-view"]').click()`);
  await page.waitForText("#usage-summary", "Total tokens");
  await page.evaluate(`document.querySelector('[data-view-target="data-view"]').click()`);
  await clickAndConfirm(page, "#queue-export");
  await page.waitForText("#data-result", "Export created");
  await clickAndConfirm(page, "#retention-purge");
  await page.waitForText("#data-result", "Retention applied");
  await page.evaluate(`document.querySelector('#wipe-scope').value = 'usage'`);
  await clickAndConfirm(page, "#queue-wipe");
  await page.waitForText("#data-result", "wipe completed");
  report.checks.push("usage, export, retention, and wipe paths completed");

  const plaintextProbe = await page.evaluate(`(() => {
    const visible = document.body.innerText;
    const inputs = Array.from(document.querySelectorAll("input, textarea")).map((node) => node.value).join("\\n");
    return visible + "\\n" + inputs;
  })()`);
  for (const secret of Object.values(secrets)) {
    assert(!plaintextProbe.includes(secret), `Dashboard leaked plaintext secret ${secret}`);
  }
  report.checks.push("dashboard did not expose submitted plaintext secrets");

  const evidenceDir = path.join(repoRoot, ".operant", "dashboard-e2e");
  await mkdir(evidenceDir, { recursive: true });
  const viewports = [
    ["desktop", 1440, 1000, "health-view"],
    ["tablet", 900, 1100, "policy-view"],
    ["mobile", 390, 860, "setup-view"],
  ];
  for (const [name, width, height, viewId] of viewports) {
    await page.setViewport(width, height);
    await page.evaluate(`document.querySelector('[data-view-target="${viewId}"]').click()`);
    await page.evaluate(`document.querySelector("#toast")?.classList.remove("show")`);
    const check = await layoutCheck(page);
    assert(check.scrollWidth <= check.innerWidth + 2, `${name} viewport has horizontal overflow: ${JSON.stringify(check)}`);
    assert(check.overflowing.length === 0, `${name} viewport has text overflow: ${check.overflowing.join(", ")}`);
    const screenshotPath = path.join(evidenceDir, `${name}.png`);
    await page.screenshot(screenshotPath);
    report.screenshots[name] = screenshotPath;
    report.checks.push(`${name} viewport screenshot captured without horizontal/text overflow`);
  }

  assert(page.consoleErrors.length === 0, `Browser console errors: ${page.consoleErrors.join("; ")}`);
  assert(page.pageErrors.length === 0, `Browser page errors: ${page.pageErrors.join("; ")}`);
  report.consoleErrors = page.consoleErrors;
  report.pageErrors = page.pageErrors;
  report.finishedAt = new Date().toISOString();
  report.passed = true;
  const reportPath = path.join(repoRoot, ".operant", "dashboard-e2e-report.json");
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  await page.close();
  log(`Dashboard E2E passed: ${reportPath}`);
  return report;
}

try {
  await runDashboardE2E();
} finally {
  await cleanup();
}
