import assert from "node:assert/strict";
import test from "node:test";
import {
  createPipedreamConnectClient,
  sanitizePipedreamConnectMessage,
} from "../src/pipedream.js";

type StubCall = {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
};

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...(init.headers || {}) },
  });
}

function parseBody(init?: RequestInit): unknown {
  return typeof init?.body === "string" ? JSON.parse(init.body) : null;
}

function stubFetch(handler: (url: URL, init?: RequestInit, calls?: StubCall[]) => Response | Promise<Response>) {
  const calls: StubCall[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(input.toString());
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    calls.push({
      url: url.toString(),
      method: init?.method ?? "GET",
      headers,
      body: parseBody(init),
    });
    return handler(url, init, calls);
  };
  return { fetchImpl, calls };
}

function client(fetchImpl: typeof fetch) {
  return createPipedreamConnectClient({
    apiBaseUrl: "https://pd.test/v1",
    tokenUrl: "https://pd.test/v1/oauth/token",
    mcpUrl: "https://mcp.test/v3",
    connectBaseUrl: "https://pipedream.com/_static/connect.html",
    clientId: "client-id",
    clientSecret: "client-secret",
    projectId: "proj_test",
    environment: "development",
    fetchImpl,
  });
}

test("lists apps and normalizes Pipedream app fields", async () => {
  const { fetchImpl, calls } = stubFetch((url) => {
    if (url.pathname === "/v1/oauth/token") return jsonResponse({ access_token: "pd-token", expires_in: 3600 });
    assert.equal(url.pathname, "/v1/apps");
    assert.equal(url.searchParams.get("q"), "gmail");
    return jsonResponse({
      data: [{ id: "app_1", name: "Gmail", name_slug: "gmail", description: "Email" }],
      page_info: { end_cursor: "next" },
    });
  });

  const result = await client(fetchImpl).listApps({ q: "gmail", limit: 10 });
  assert.deepEqual(result.apps, [{ id: "app_1", name: "Gmail", slug: "gmail", description: "Email", category: null }]);
  assert.deepEqual(result.pageInfo, { end_cursor: "next" });
  assert.equal(calls[1]?.headers.authorization, "Bearer pd-token");
});

test("creates connect links without requiring the caller to build Pipedream URLs", async () => {
  const { fetchImpl, calls } = stubFetch((url) => {
    if (url.pathname === "/v1/oauth/token") return jsonResponse({ access_token: "pd-token", expires_in: 3600 });
    assert.equal(url.pathname, "/v1/connect/tokens");
    return jsonResponse({ token: "ctok_demo", expires_at: "2026-05-22T12:00:00Z" });
  });

  const result = await client(fetchImpl).createConnectToken({
    externalUserId: "U123",
    appSlug: "gmail",
    allowedOrigins: ["http://localhost:8080"],
  });
  assert.equal(result.expiresAt, "2026-05-22T12:00:00Z");
  assert.equal(result.connectLinkUrl, "https://pipedream.com/_static/connect.html?token=ctok_demo&app=gmail");
  assert.deepEqual(calls[1]?.body, {
    user_id: "U123",
    external_user_id: "U123",
    allowed_origins: ["http://localhost:8080"],
  });
});

test("lists accounts with external user scope and deletes by account id", async () => {
  const { fetchImpl, calls } = stubFetch((url, init) => {
    if (url.pathname === "/v1/oauth/token") return jsonResponse({ access_token: "pd-token", expires_in: 3600 });
    if (init?.method === "DELETE") {
      assert.equal(url.pathname, "/v1/connect/proj_test/accounts/apn_123");
      return new Response(null, { status: 204 });
    }
    assert.equal(url.pathname, "/v1/connect/proj_test/accounts");
    assert.equal(url.searchParams.get("external_user_id"), "U123");
    assert.equal(url.searchParams.get("include_credentials"), "false");
    assert.equal(url.searchParams.get("app"), "github");
    return jsonResponse({ data: [{ id: "apn_123", app_slug: "github", external_user_id: "U123", healthy: true }] });
  });

  const pd = client(fetchImpl);
  const accounts = await pd.listAccounts({ externalUserId: "U123", app: "github" });
  assert.equal(accounts[0]?.id, "apn_123");
  assert.equal(accounts[0]?.app, "github");
  await pd.deleteAccount("apn_123");
  assert.equal(calls.filter((call) => call.url.includes("/oauth/token")).length, 1);
});

test("lists MCP tools with Pipedream project and external user headers", async () => {
  const { fetchImpl, calls } = stubFetch((url) => {
    if (url.pathname === "/v1/oauth/token") return jsonResponse({ access_token: "pd-token", expires_in: 3600 });
    assert.equal(url.hostname, "mcp.test");
    return new Response(`event: message\ndata: ${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "gmail-send-email", description: "Send mail" }] },
    })}\n\n`, {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  });

  const tools = await client(fetchImpl).listTools({ externalUserId: "U123", appSlug: "gmail" });
  assert.equal(tools[0]?.name, "gmail-send-email");
  const rpcCall = calls.find((call) => call.url.startsWith("https://mcp.test/"));
  assert.equal(rpcCall?.headers["x-pd-project-id"], "proj_test");
  assert.equal(rpcCall?.headers["x-pd-environment"], "development");
  assert.equal(rpcCall?.headers["x-pd-external-user-id"], "U123");
  assert.equal(rpcCall?.headers["x-pd-app-slug"], "gmail");
});

test("redacts connect tokens and connect URLs from upstream error messages", () => {
  const message = sanitizePipedreamConnectMessage("open https://pipedream.com/_static/connect.html?token=ctok_secret&app=gmail or token ctok_other");
  assert.equal(message.includes("ctok_secret"), false);
  assert.equal(message.includes("connect.html?"), false);
});
