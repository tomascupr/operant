import assert from "node:assert/strict";
import test from "node:test";
import { createOperantClient, OperantClientError } from "../src/operant-client.js";
import { withJsonStub } from "./stub-server.js";

test("getUserContext sends the bearer token and parses the response", async () => {
  let receivedAuth: string | undefined;
  let receivedUrl: string | undefined;
  let receivedBody: unknown;
  await withJsonStub((req, body) => {
    receivedAuth = req.headers.authorization;
    receivedUrl = req.url;
    receivedBody = body;
    return {
      status: 200,
      body: {
        sessionKey: "agents/main/sessions/abc",
        workspaceId: "ws-1",
        slackUserId: "U1",
        roles: ["admin"],
      },
    };
  }, async (baseUrl) => {
    const client = createOperantClient({ baseUrl, token: "internal-token" });
    const context = await client.getUserContext("agents/main/sessions/abc");
    assert.equal(context.slackUserId, "U1");
    assert.deepEqual(context.roles, ["admin"]);
    assert.equal(receivedAuth, "Bearer internal-token");
    assert.equal(receivedUrl, "/internal/plugin/user-context");
    assert.deepEqual(receivedBody, { sessionKey: "agents/main/sessions/abc" });
  });
});

test("getUserContext returns slackUserId null when the session is unknown", async () => {
  await withJsonStub(() => ({
    status: 200,
    body: { sessionKey: "unknown", workspaceId: "ws-1", slackUserId: null, roles: [] },
  }), async (baseUrl) => {
    const client = createOperantClient({ baseUrl, token: "t" });
    const context = await client.getUserContext("unknown");
    assert.equal(context.slackUserId, null);
    assert.deepEqual(context.roles, []);
  });
});

test("checkPolicy forwards slackUserId, tool, action and returns the decision", async () => {
  let receivedBody: unknown;
  await withJsonStub((_req, body) => {
    receivedBody = body;
    return { status: 200, body: { effect: "deny", reasons: ["Tool policy denies gmail:send."] } };
  }, async (baseUrl) => {
    const client = createOperantClient({ baseUrl, token: "t" });
    const decision = await client.checkPolicy({ slackUserId: "U1", tool: "gmail", action: "send" });
    assert.equal(decision.effect, "deny");
    assert.deepEqual(receivedBody, { slackUserId: "U1", tool: "gmail", action: "send" });
  });
});

test("non-2xx responses throw OperantClientError", async () => {
  await withJsonStub(() => ({ status: 403, body: { error: "Forbidden" } }), async (baseUrl) => {
    const client = createOperantClient({ baseUrl, token: "wrong" });
    await assert.rejects(
      () => client.getUserContext("any"),
      (error: unknown) => error instanceof OperantClientError && error.status === 403,
    );
  });
});
