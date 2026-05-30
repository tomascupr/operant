import assert from "node:assert/strict";
import test from "node:test";
import type { OperantClient, PolicyDecision, PolicyEffect } from "../src/operant-client.js";
import type { PipedreamClient, PipedreamToolCallResult, PipedreamToolListing } from "../src/pipedream/client.js";
import {
  createPipedreamConnectAppTool,
  createPipedreamListActionsTool,
  createPipedreamListConnectionsTool,
  createPipedreamRunActionTool,
  createPipedreamSearchAppsTool,
  deriveAppAction,
  type PipedreamToolDependencies,
} from "../src/pipedream/tools.js";

function stubOperantClient(decide: (toolName: string) => PolicyEffect): OperantClient {
  return {
    getUserContext: async () => ({ sessionKey: "k", workspaceId: "w", slackUserId: null, roles: [] }),
    checkPolicy: async (input) => {
      const decision: PolicyDecision = {
        effect: decide(`${input.tool}/${input.action}`),
        reasons: [],
      };
      return decision;
    },
    searchPipedreamApps: async () => ({ apps: [] }),
    createPipedreamConnectToken: async (input) => ({
      app: input.appSlug ?? null,
      expiresAt: "2026-05-22T12:00:00Z",
      connectLinkUrl: `https://pipedream.com/_static/connect.html?token=ctok_demo${input.appSlug ? `&app=${input.appSlug}` : ""}`,
    }),
    listPipedreamAccounts: async () => ({ accounts: [] }),
  };
}

function stubPipedreamClient(opts: {
  list?: PipedreamToolListing[];
  callResult?: PipedreamToolCallResult;
} = {}): PipedreamClient & {
  listCalls: Array<{ slackUserId: string; appSlug: string }>;
  callCalls: Array<{ slackUserId: string; toolName: string; args?: unknown; appSlug?: string }>;
} {
  const listCalls: Array<{ slackUserId: string; appSlug: string }> = [];
  const callCalls: Array<{ slackUserId: string; toolName: string; args?: unknown; appSlug?: string }> = [];
  return {
    listCalls,
    callCalls,
    listTools: async (slackUserId, appSlug) => {
      listCalls.push({ slackUserId, appSlug });
      return opts.list ?? [];
    },
    callTool: async (slackUserId, toolName, args, appSlug) => {
      callCalls.push({ slackUserId, toolName, args, appSlug });
      return opts.callResult ?? { content: [{ type: "text", text: "ok" }] };
    },
  } as PipedreamClient & {
    listCalls: Array<{ slackUserId: string; appSlug: string }>;
    callCalls: Array<{ slackUserId: string; toolName: string; args?: unknown; appSlug?: string }>;
  };
}

function deps(overrides: Partial<PipedreamToolDependencies> = {}): PipedreamToolDependencies {
  return {
    pipedreamClient: stubPipedreamClient(),
    operantClient: stubOperantClient(() => "allow"),
    principalId: "U_alice",
    ...overrides,
  };
}

function parseFirstTextBlock(result: { content: ReadonlyArray<{ type: string; text?: string }> }): unknown {
  const block = result.content[0];
  assert.ok(block && block.type === "text" && typeof block.text === "string");
  return JSON.parse(block.text);
}

test("deriveAppAction splits a toolName on the first dash", () => {
  assert.deepEqual(deriveAppAction("gmail-send-email"), { app: "gmail", action: "send-email" });
  assert.deepEqual(deriveAppAction("ping"), { app: "ping", action: "*" });
});

test("list_actions requires an app slug and returns Pipedream tools filtered by policy", async () => {
  const pipedreamClient = stubPipedreamClient({
    list: [
      { name: "gmail-send-email", description: "Send mail" },
      { name: "gmail-list-labels", description: "List labels" },
    ],
  });
  const tool = createPipedreamListActionsTool(deps({
    pipedreamClient,
    operantClient: stubOperantClient((key) => (key === "pipedream:gmail/send-email" ? "deny" : "allow")),
  }));
  const result = await tool.execute("call-1", { app: "gmail" });
  const body = parseFirstTextBlock(result) as { app: string; tools: Array<{ toolName: string }> };
  assert.equal(body.app, "gmail");
  assert.deepEqual(body.tools.map((entry) => entry.toolName), ["gmail-list-labels"]);
  assert.deepEqual(pipedreamClient.listCalls, [{ slackUserId: "U_alice", appSlug: "gmail" }]);
});

test("list_actions returns missing_app when the agent did not pass app", async () => {
  const tool = createPipedreamListActionsTool(deps());
  const result = await tool.execute("call-1", {});
  const body = parseFirstTextBlock(result) as { error: string };
  assert.equal(body.error, "missing_app");
});

test("search_apps proxies app search through the control plane", async () => {
  let received: unknown;
  const tool = createPipedreamSearchAppsTool(deps({
    operantClient: {
      ...stubOperantClient(() => "allow"),
      searchPipedreamApps: async (input) => {
        received = input;
        return { apps: [{ id: "app_1", name: "Gmail", slug: "gmail", description: "Email", category: null }] };
      },
    },
  }));
  const result = await tool.execute("call-1", { q: "gmail", limit: 5 });
  const body = parseFirstTextBlock(result) as { apps: Array<{ slug: string }> };
  assert.deepEqual(received, { q: "gmail", limit: 5 });
  assert.equal(body.apps[0]?.slug, "gmail");
});

test("connect_app returns a short-lived connect link for the requesting Slack user", async () => {
  let received: unknown;
  const tool = createPipedreamConnectAppTool(deps({
    operantClient: {
      ...stubOperantClient(() => "allow"),
      createPipedreamConnectToken: async (input) => {
        received = input;
        return { app: "gmail", expiresAt: "2026-05-22T12:00:00Z", connectLinkUrl: "https://pipedream.com/_static/connect.html?token=ctok_demo&app=gmail" };
      },
    },
  }));
  const result = await tool.execute("call-1", { app: "gmail" });
  const body = parseFirstTextBlock(result) as { connectLinkUrl: string };
  assert.deepEqual(received, { principalId: "U_alice", appSlug: "gmail" });
  assert.match(body.connectLinkUrl, /connect\.html\?token=ctok_demo/);
});

test("list_connections returns the requesting Slack user's Pipedream accounts", async () => {
  let received: unknown;
  const tool = createPipedreamListConnectionsTool(deps({
    operantClient: {
      ...stubOperantClient(() => "allow"),
      listPipedreamAccounts: async (input) => {
        received = input;
        return { accounts: [{ id: "apn_1", app: "github", appName: "GitHub", externalUserId: "U_alice", name: "alice", healthy: true, createdAt: null, updatedAt: null }] };
      },
    },
  }));
  const result = await tool.execute("call-1", { app: "github" });
  const body = parseFirstTextBlock(result) as { accounts: Array<{ app: string }> };
  assert.deepEqual(received, { principalId: "U_alice", app: "github" });
  assert.equal(body.accounts[0]?.app, "github");
});

test("run_action forwards to Pipedream with the derived app slug", async () => {
  const pipedreamClient = stubPipedreamClient({ callResult: { content: [{ type: "text", text: "sent" }] } });
  const tool = createPipedreamRunActionTool(deps({ pipedreamClient }));
  const result = await tool.execute("call-1", { toolName: "gmail-send-email", args: { to: "x@example.com" } });
  const block = result.content[0];
  assert.ok(block && block.type === "text");
  assert.equal((block as { text: string }).text, "sent");
  assert.deepEqual(pipedreamClient.callCalls, [{
    slackUserId: "U_alice",
    toolName: "gmail-send-email",
    args: { to: "x@example.com" },
    appSlug: "gmail",
  }]);
});

test("run_action returns policy_denied without calling Pipedream when policy denies", async () => {
  const pipedreamClient = stubPipedreamClient();
  const tool = createPipedreamRunActionTool(deps({
    pipedreamClient,
    operantClient: stubOperantClient(() => "deny"),
  }));
  const result = await tool.execute("call-1", { toolName: "gmail-send-email" });
  const body = parseFirstTextBlock(result) as { error?: string };
  assert.equal(body.error, "policy_denied");
  assert.equal(pipedreamClient.callCalls.length, 0);
});

test("run_action surfaces approval_required as a workflow status, not an error", async () => {
  const tool = createPipedreamRunActionTool(deps({
    operantClient: stubOperantClient(() => "approval_required"),
  }));
  const result = await tool.execute("call-1", { toolName: "gmail-send-email" });
  const body = parseFirstTextBlock(result) as { status?: string };
  assert.equal(body.status, "approval_required");
});

test("run_action surfaces Pipedream connect-link responses verbatim", async () => {
  const pipedreamClient = stubPipedreamClient({
    callResult: {
      isError: true,
      content: [
        { type: "text", text: "Connect Gmail first: https://pipedream.com/_static/connect.html?token=ctok_demo&connectLink=true&app=gmail" },
      ],
    },
  });
  const tool = createPipedreamRunActionTool(deps({ pipedreamClient }));
  const result = await tool.execute("call-1", { toolName: "gmail-send-email" });
  const block = result.content[0];
  assert.ok(block && block.type === "text");
  assert.match((block as { text: string }).text, /connect\.html\?token=ctok_demo/);
});

test("run_action refuses to call Pipedream without a principal in session context", async () => {
  const pipedreamClient = stubPipedreamClient();
  const tool = createPipedreamRunActionTool(deps({
    pipedreamClient,
    principalId: null,
    operantClient: {
      ...stubOperantClient(() => "allow"),
      getUserContext: async () => ({ sessionKey: "k", workspaceId: "w", slackUserId: null, roles: [] }),
      checkPolicy: async () => {
        throw new Error("policy should not be checked without a Slack user");
      },
    },
  }));
  const result = await tool.execute("call-1", { toolName: "gmail-send-email" });
  const body = parseFirstTextBlock(result) as { error: string };
  assert.equal(body.error, "missing_principal_context");
  assert.equal(pipedreamClient.callCalls.length, 0);
});

test("run_action returns policy_check_failed when the control plane policy call fails", async () => {
  const pipedreamClient = stubPipedreamClient();
  const tool = createPipedreamRunActionTool(deps({
    pipedreamClient,
    operantClient: {
      ...stubOperantClient(() => "allow"),
      getUserContext: async () => ({ sessionKey: "k", workspaceId: "w", slackUserId: "U_alice", roles: [] }),
      checkPolicy: async () => {
        throw new Error("control plane unavailable");
      },
    },
  }));
  const result = await tool.execute("call-1", { toolName: "gmail-send-email" });
  const body = parseFirstTextBlock(result) as { error: string };
  assert.equal(body.error, "policy_check_failed");
  assert.equal(pipedreamClient.callCalls.length, 0);
});
