import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";
import test from "node:test";
import {
  createPipedreamClient,
  parseSseJsonRpc,
  PipedreamClientError,
  PipedreamRpcError,
  sanitizePipedreamMessage,
} from "../src/pipedream/client.js";
import { withJsonStub } from "./stub-server.js";

interface PipedreamStub {
  baseUrl: string;
  tokenCalls: Array<unknown>;
  rpcCalls: Array<{ headers: IncomingMessage["headers"]; body: unknown }>;
}

async function withPipedreamStub(
  handler: (req: IncomingMessage, body: unknown, stub: PipedreamStub) => { status: number; body?: unknown },
  run: (stub: PipedreamStub) => Promise<void>,
): Promise<void> {
  const stub: PipedreamStub = { baseUrl: "", tokenCalls: [], rpcCalls: [] };
  await withJsonStub((req, body) => {
    if (req.url === "/oauth/token") stub.tokenCalls.push(body);
    if (req.url === "/mcp") stub.rpcCalls.push({ headers: req.headers, body });
    return handler(req, body, stub);
  }, async (baseUrl) => {
    stub.baseUrl = baseUrl;
    await run(stub);
  });
}

test("mints an access token then forwards tools/list with the bearer + user-id + Accept headers", async () => {
  await withPipedreamStub(
    (req) => {
      if (req.url === "/oauth/token") {
        return { status: 200, body: { access_token: "pd-tok-1", expires_in: 3600, token_type: "Bearer" } };
      }
      return {
        status: 200,
        body: { jsonrpc: "2.0", id: 1, result: { tools: [{ name: "gmail-send-email", description: "Send Gmail" }] } },
      };
    },
    async (stub) => {
      const client = createPipedreamClient({
        mcpUrl: `${stub.baseUrl}/mcp`,
        tokenUrl: `${stub.baseUrl}/oauth/token`,
        clientId: "id",
        clientSecret: "secret",
        projectId: "proj_test",
        environment: "development",
      });
      const tools = await client.listTools("U_alice", "gmail");
      assert.equal(tools.length, 1);
      assert.equal(tools[0]?.name, "gmail-send-email");
      assert.equal(stub.tokenCalls.length, 1);
      assert.deepEqual(stub.tokenCalls[0], {
        grant_type: "client_credentials",
        client_id: "id",
        client_secret: "secret",
      });
      const rpc = stub.rpcCalls[0]!;
      assert.equal(rpc.headers.authorization, "Bearer pd-tok-1");
      assert.equal(rpc.headers.accept, "application/json, text/event-stream");
      assert.equal(rpc.headers["x-pd-external-user-id"], "U_alice");
      assert.equal(rpc.headers["x-pd-project-id"], "proj_test");
      assert.equal(rpc.headers["x-pd-environment"], "development");
      assert.equal(rpc.headers["x-pd-app-slug"], "gmail");
      assert.deepEqual(rpc.body, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    },
  );
});

test("parses SSE-formatted JSON-RPC responses (the format Pipedream actually returns)", async () => {
  await withPipedreamStub(
    (req) => {
      if (req.url === "/oauth/token") {
        return { status: 200, body: { access_token: "tok", expires_in: 3600 } };
      }
      const payload = JSON.stringify({
        result: { tools: [{ name: "gmail-list-labels" }, { name: "gmail-send-email" }] },
        jsonrpc: "2.0",
        id: 1,
      });
      return {
        status: 200,
        contentType: "text/event-stream",
        rawBody: `event: message\ndata: ${payload}\n\n`,
      };
    },
    async (stub) => {
      const client = createPipedreamClient({
        mcpUrl: `${stub.baseUrl}/mcp`,
        tokenUrl: `${stub.baseUrl}/oauth/token`,
        clientId: "id",
        clientSecret: "secret",
        projectId: "proj_test",
        environment: "development",
      });
      const tools = await client.listTools("U_alice", "gmail");
      assert.deepEqual(tools.map((t) => t.name), ["gmail-list-labels", "gmail-send-email"]);
    },
  );
});

test("parseSseJsonRpc tolerates CRLF, multi-line data, and ignores comments + non-data lines", () => {
  const payload = JSON.stringify({ jsonrpc: "2.0", id: 7, result: { ok: true } });
  const body = `:keep-alive\r\nevent: message\r\nid: 7\r\ndata: ${payload}\r\n\r\n`;
  assert.deepEqual(parseSseJsonRpc(body), { jsonrpc: "2.0", id: 7, result: { ok: true } });
  const multi = `event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":1,"result":{"ok":true}}\n\n`;
  assert.deepEqual(parseSseJsonRpc(multi), { jsonrpc: "2.0", id: 1, result: { ok: true } });
});

test("parseSseJsonRpc throws on a body without any data: line", () => {
  assert.throws(() => parseSseJsonRpc("event: ping\n\n"), /no data: event/);
});

test("reuses a cached access token across subsequent calls until it nears expiry", async () => {
  let issued = 0;
  let currentTime = 1_000_000;
  await withPipedreamStub(
    (req) => {
      if (req.url === "/oauth/token") {
        issued += 1;
        return { status: 200, body: { access_token: `pd-${issued}`, expires_in: 60 } };
      }
      return { status: 200, body: { jsonrpc: "2.0", id: 1, result: { tools: [] } } };
    },
    async (stub) => {
      const client = createPipedreamClient({
        mcpUrl: `${stub.baseUrl}/mcp`,
        tokenUrl: `${stub.baseUrl}/oauth/token`,
        clientId: "id",
        clientSecret: "secret",
        projectId: "proj_test",
        environment: "development",
        tokenRefreshBufferMs: 30_000,
        now: () => currentTime,
      });
      await client.listTools("U1", "gmail");
      await client.listTools("U2", "gmail");
      assert.equal(issued, 1, "second call should reuse cached token");
      currentTime += 40_000;
      await client.listTools("U3", "gmail");
      assert.equal(issued, 2, "call past refresh-buffer threshold should mint a fresh token");
    },
  );
});

test("dedupes a token mint across concurrent first calls", async () => {
  let issued = 0;
  await withPipedreamStub(
    (req) => {
      if (req.url === "/oauth/token") {
        issued += 1;
        return { status: 200, body: { access_token: `pd-${issued}`, expires_in: 3600 } };
      }
      return { status: 200, body: { jsonrpc: "2.0", id: 1, result: { tools: [] } } };
    },
    async (stub) => {
      const client = createPipedreamClient({
        mcpUrl: `${stub.baseUrl}/mcp`,
        tokenUrl: `${stub.baseUrl}/oauth/token`,
        clientId: "id",
        clientSecret: "secret",
        projectId: "proj_test",
        environment: "development",
      });
      await Promise.all([client.listTools("U1", "gmail"), client.listTools("U2", "gmail"), client.listTools("U3", "gmail")]);
      assert.equal(issued, 1, "in-flight refresh should be shared across concurrent callers");
    },
  );
});

test("callTool forwards name + arguments and returns the content blocks verbatim", async () => {
  await withPipedreamStub(
    (req) => {
      if (req.url === "/oauth/token") {
        return { status: 200, body: { access_token: "tok", expires_in: 3600 } };
      }
      return {
        status: 200,
        body: {
          jsonrpc: "2.0",
          id: 1,
          result: {
            content: [
              { type: "text", text: "Connect Gmail first: https://pipedream.com/_static/connect.html?token=ctok_x" },
            ],
            isError: true,
          },
        },
      };
    },
    async (stub) => {
      const client = createPipedreamClient({
        mcpUrl: `${stub.baseUrl}/mcp`,
        tokenUrl: `${stub.baseUrl}/oauth/token`,
        clientId: "id",
        clientSecret: "secret",
        projectId: "proj_test",
        environment: "development",
      });
      const result = await client.callTool("U_alice", "gmail-send-email", { to: "x@example.com" }, "gmail");
      assert.equal(result.isError, true);
      assert.match(result.content[0]?.text ?? "", /connect\.html\?token=/);
      const rpc = stub.rpcCalls[0]!;
      assert.equal(rpc.headers["x-pd-app-slug"], "gmail");
      assert.deepEqual(rpc.body, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "gmail-send-email", arguments: { to: "x@example.com" } },
      });
    },
  );
});

test("non-2xx token responses throw PipedreamClientError without leaking the upstream body", async () => {
  await withPipedreamStub(
    (req) => {
      if (req.url === "/oauth/token") {
        return { status: 401, body: { error: "invalid_client", client_id: "leaked-id-do-not-echo" } };
      }
      return { status: 200, body: { jsonrpc: "2.0", id: 1, result: { tools: [] } } };
    },
    async (stub) => {
      const client = createPipedreamClient({
        mcpUrl: `${stub.baseUrl}/mcp`,
        tokenUrl: `${stub.baseUrl}/oauth/token`,
        clientId: "leaked-id-do-not-echo",
        clientSecret: "secret",
        projectId: "proj_test",
        environment: "development",
      });
      await assert.rejects(
        () => client.listTools("U1", "gmail"),
        (error: unknown) => {
          if (!(error instanceof PipedreamClientError)) return false;
          assert.equal(error.status, 401);
          assert.ok(!error.message.includes("leaked-id-do-not-echo"), `token error must not echo upstream body, got: ${error.message}`);
          return true;
        },
      );
    },
  );
});

test("sanitizePipedreamMessage redacts ctok_ tokens and connect-link URLs", () => {
  const raw = "Connect Gmail at https://pipedream.com/_static/connect.html?token=ctok_abc123&app=gmail then retry. token ctok_zzz";
  const cleaned = sanitizePipedreamMessage(raw);
  assert.ok(!cleaned.includes("ctok_abc123"), `should redact ctok value, got: ${cleaned}`);
  assert.ok(!cleaned.includes("ctok_zzz"), `should redact bare ctok, got: ${cleaned}`);
  assert.ok(!cleaned.includes("connect.html?"), `should redact connect-link URL, got: ${cleaned}`);
  assert.match(cleaned, /ctok_\[redacted\]/);
  assert.match(cleaned, /<connect-link redacted>/);
});

test("JSON-RPC error responses throw PipedreamRpcError", async () => {
  await withPipedreamStub(
    (req) => {
      if (req.url === "/oauth/token") return { status: 200, body: { access_token: "t", expires_in: 3600 } };
      return {
        status: 200,
        body: { jsonrpc: "2.0", id: 1, error: { code: -32601, message: "Method not found" } },
      };
    },
    async (stub) => {
      const client = createPipedreamClient({
        mcpUrl: `${stub.baseUrl}/mcp`,
        tokenUrl: `${stub.baseUrl}/oauth/token`,
        clientId: "id",
        clientSecret: "secret",
        projectId: "proj_test",
        environment: "development",
      });
      await assert.rejects(
        () => client.listTools("U1", "gmail"),
        (error: unknown) => error instanceof PipedreamRpcError && error.code === -32601,
      );
    },
  );
});
