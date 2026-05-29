import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { Database } from "../src/db.js";
import { createHttpServer, type ServerState } from "../src/server.js";

const companyId = "11111111-1111-4111-8111-111111111111";
const workspaceId = "22222222-2222-4222-8222-222222222222";

type QueryResult = { rows: any[]; rowCount: number };
type QueryCall = { sql: string; params: unknown[] };

function result(rows: any[] = []): QueryResult {
  return { rows, rowCount: rows.length };
}

function createFakePool(handler: (sql: string, params: unknown[]) => QueryResult | Promise<QueryResult>) {
  const calls: QueryCall[] = [];
  const query = async (sql: string, params: unknown[] = []) => {
    calls.push({ sql, params });
    return handler(sql, params);
  };
  return {
    calls,
    pool: {
      query,
      connect: async () => ({
        query,
        release: () => {},
      }),
    } as unknown as Database,
  };
}

function createNoDbState(): ServerState {
  const { pool } = createFakePool((sql) => {
    throw new Error(`Unexpected database query: ${sql}`);
  });
  return { pool, masterKey: Buffer.alloc(32) };
}

function existingWorkspaceSeedQueries(sql: string, params: unknown[]): QueryResult | null {
  if (/SELECT w\.id AS workspace_id/.test(sql)) return result([{ workspace_id: workspaceId, company_id: companyId }]);
  if (/INSERT INTO permissions/.test(sql)) return result();
  if (/INSERT INTO roles/.test(sql)) return result([{ id: `role-${String(params[1] || "unknown")}` }]);
  if (/DELETE FROM role_permissions/.test(sql)) return result();
  if (/INSERT INTO role_permissions/.test(sql)) return result();
  return null;
}

function workspaceJoinQuery(sql: string): QueryResult | null {
  if (!/FROM workspaces w\s+JOIN companies c/.test(sql)) return null;
  return result([{
    id: workspaceId,
    company_id: companyId,
    name: "Acme Slack",
    company_name: "Acme Inc.",
    slack_team_id: null,
    openclaw_gateway_url: "http://openclaw-gateway:18789",
    openclaw_config_path: "/operant/openclaw/openclaw.json",
    created_at: new Date("2026-01-01T00:00:00.000Z"),
  }]);
}

async function withEnv<T>(env: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const previous = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(env)) {
    previous.set(key, process.env[key]);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

async function withServer<T>(state: ServerState, fn: (baseUrl: string) => Promise<T>): Promise<T> {
  const server = createHttpServer(state);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
}

async function requestJson(baseUrl: string, path: string, options: RequestInit = {}) {
  const response = await fetch(new URL(path, baseUrl), {
    ...options,
    headers: {
      accept: "application/json",
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  return {
    response,
    body: text ? JSON.parse(text) as Record<string, unknown> : {},
  };
}

test("health and unknown routes return JSON with security headers", async () => {
  await withServer(createNoDbState(), async (baseUrl) => {
    const health = await requestJson(baseUrl, "/healthz");
    assert.equal(health.response.status, 200);
    assert.equal(health.body.ok, true);
    assert.match(health.response.headers.get("content-security-policy") || "", /default-src 'self'/);
    assert.equal(health.response.headers.get("x-frame-options"), "DENY");

    const missing = await requestJson(baseUrl, "/api/does-not-exist", { method: "POST" });
    assert.equal(missing.response.status, 404);
    assert.equal(missing.body.error, "Not found");
  });
});

test("/api/bootstrap requires the admin login token before touching the database", async () => {
  await withEnv({ OPERANT_ADMIN_LOGIN_TOKEN: undefined }, async () => {
    const state = createNoDbState();
    await withServer(state, async (baseUrl) => {
      const response = await requestJson(baseUrl, "/api/bootstrap", { method: "POST", body: "{}" });
      assert.equal(response.response.status, 503);
      assert.match(String(response.body.error), /OPERANT_ADMIN_LOGIN_TOKEN/);
    });
  });

  await withEnv({ OPERANT_ADMIN_LOGIN_TOKEN: "admin-token" }, async () => {
    const state = createNoDbState();
    await withServer(state, async (baseUrl) => {
      const response = await requestJson(baseUrl, "/api/bootstrap", { method: "POST", body: "{}" });
      assert.equal(response.response.status, 401);
      assert.match(String(response.body.error), /admin login token/i);
    });
  });
});

test("/api/bootstrap accepts a valid admin token and writes the bootstrap audit row", async () => {
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return result();
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected database query: ${sql}`);
  });

  await withEnv({ OPERANT_ADMIN_LOGIN_TOKEN: "admin-token" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const response = await requestJson(baseUrl, "/api/bootstrap", {
        method: "POST",
        headers: { "x-operant-admin-login-token": "admin-token" },
        body: "{}",
      });
      assert.equal(response.response.status, 200);
      assert.equal(response.body.workspaceId, workspaceId);
      assert.equal(auditRows.length, 1);
      // audit() INSERT columns: ...actor_user_id($3), actor_slack_user_id($4), event_type($5) -> params index 4.
      assert.equal(auditRows[0][4], "bootstrap.completed");
    });
  });
});

test("credential bootstrap keeps DM allowlist separate from channel user allowlists", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "operant-http-test-"));
  const configPath = path.join(tempRoot, "openclaw.json");
  const insertedChannelPolicyParams: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") return result();
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/SELECT 1 FROM role_assignments/.test(sql)) return result();
    if (/SELECT approver_slack_user_ids/.test(sql)) return result();
    if (/UPDATE companies/.test(sql) || /UPDATE workspaces/.test(sql) || /UPDATE workspace_settings/.test(sql)) return result();
    if (/INSERT INTO integration_credentials/.test(sql)) return result();
    if (/INSERT INTO policy_rules/.test(sql) || /UPDATE policy_rules/.test(sql)) return result();
    if (/DELETE FROM channel_policies/.test(sql)) return result();
    if (/INSERT INTO channel_policies/.test(sql)) {
      insertedChannelPolicyParams.push(params);
      return result();
    }
    if (/DELETE FROM tool_policies/.test(sql) || /INSERT INTO tool_policies/.test(sql)) return result();
    if (/INSERT INTO approval_policies/.test(sql) || /UPDATE approval_policies/.test(sql)) return result();
    if (/INSERT INTO users/.test(sql)) return result([{ id: "owner-user" }]);
    if (/INSERT INTO role_assignments/.test(sql)) return result();
    if (/SELECT model_provider, model_name FROM workspace_settings/.test(sql)) return result([{ model_provider: "openai", model_name: "gpt-5" }]);
    if (/SELECT openclaw_gateway_url, openclaw_config_path FROM workspaces/.test(sql)) {
      return result([{ openclaw_gateway_url: "http://openclaw-gateway:18789", openclaw_config_path: configPath }]);
    }
    if (/SELECT conditions->'allowedDmUserIds'/.test(sql)) return result([{ ids: ["UOWNER", "UDM"] }]);
    if (/SELECT channel_id, name, enabled, require_mention, allowed_user_ids, denied_user_ids/.test(sql)) {
      return result([{ channel_id: "COPS", name: "Credential setup allowlist", enabled: true, require_mention: true, allowed_user_ids: [], denied_user_ids: [] }]);
    }
    if (/SELECT tool, action, effect, slack_user_ids, role_names/.test(sql)) {
      return result([{ tool: "slack", action: "messages", effect: "allow", slack_user_ids: [], role_names: [] }]);
    }
    if (/SELECT name, action_pattern, resource_pattern, approver_slack_user_ids/.test(sql)) {
      return result([{ name: "risky-actions", action_pattern: "exec:*", resource_pattern: "*", approver_slack_user_ids: ["UOWNER"], min_approvals: 1, enabled: true }]);
    }
    if (/INSERT INTO openclaw_configs/.test(sql) || /INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected database query: ${sql}`);
  });

  await withEnv({
    OPERANT_ADMIN_LOGIN_TOKEN: "admin-token",
    OPENCLAW_CONFIG_PATH: configPath,
    OPENCLAW_SECRET_RESOLVER_COMMAND: "/usr/local/bin/node",
  }, async () => {
    try {
      await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
        const response = await requestJson(baseUrl, "/api/config/credentials", {
          method: "POST",
          body: JSON.stringify({
            adminLoginToken: "admin-token",
            adminSlackUserId: "UOWNER",
            allowedDmUserIds: ["UDM"],
            allowedChannelIds: ["COPS"],
            approvalSlackUserIds: ["UOWNER"],
            slackBotToken: "xoxb-test-token",
            slackAppToken: "xapp-test-token",
            modelApiKey: "sk-test-token",
          }),
        });
        assert.equal(response.response.status, 200);
        assert.equal(insertedChannelPolicyParams.length, 1);
        assert.deepEqual(insertedChannelPolicyParams[0][2], []);
      });
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });
});

test("internal SecretRef routes reject missing or invalid internal tokens before database access", async () => {
  await withEnv({ OPERANT_INTERNAL_TOKEN: "internal-token" }, async () => {
    await withServer(createNoDbState(), async (baseUrl) => {
      const response = await requestJson(baseUrl, "/internal/openclaw/secrets/workspaces%2F22222222-2222-4222-8222-222222222222%2Fslack%2FbotToken");
      assert.equal(response.response.status, 401);
      assert.equal(response.body.error, "Unauthorized");
    });
  });
});

test("workspace API routes require an admin session when RBAC assignments exist", async () => {
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/SELECT 1 FROM role_assignments/.test(sql)) return result([{ exists: true }]);
    if (/FROM admin_sessions s/.test(sql)) return result();
    throw new Error(`Unexpected database query: ${sql}`);
  });

  await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
    const response = await requestJson(baseUrl, "/api/settings");
    assert.equal(response.response.status, 401);
    assert.equal(response.body.error, "Missing or invalid Operant admin session");
  });
});

test("workspace API routes return RBAC denial details for authenticated users without permission", async () => {
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/SELECT 1 FROM role_assignments/.test(sql)) return result([{ exists: true }]);
    if (/FROM users u\s+JOIN role_assignments/.test(sql)) return result([{ user_id: "user-viewer", role_name: "viewer" }]);
    if (/FROM role_assignments ra\s+JOIN role_permissions/.test(sql)) return result();
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected database query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const response = await requestJson(baseUrl, "/api/users", {
        headers: { "x-operant-slack-user-id": "UVIEWER" },
      });
      assert.equal(response.response.status, 403);
      assert.equal(response.body.error, "RBAC denied");
      assert.deepEqual(response.body.roles, ["viewer"]);
      assert.equal(auditRows.length, 1);
      // event_type is params index 4 after actor_slack_user_id was added at index 3.
      assert.equal(auditRows[0][4], "rbac.denied");
    });
  });
});

test("/api/usage/summary returns per-user cost attribution alongside model, tool, and day rollups", async () => {
  const { pool, calls } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/SELECT 1 FROM role_assignments/.test(sql)) return result([{ exists: true }]);
    if (/FROM users u\s+JOIN role_assignments/.test(sql)) return result([{ user_id: "user-owner", role_name: "owner" }]);
    if (/FROM role_assignments ra\s+JOIN role_permissions/.test(sql)) return result([{ action: "*", resource: "*" }]);
    if (/LEFT JOIN sessions/.test(sql)) return result([
      { slack_user_id: "U_ALICE", events: 2, input_tokens: 80, output_tokens: 40, total_tokens: 120, estimated_cost_usd: 0.2 },
      { slack_user_id: "unattributed", events: 1, input_tokens: 20, output_tokens: 10, total_tokens: 30, estimated_cost_usd: 0.05 },
    ]);
    if (/GROUP BY COALESCE\(provider/.test(sql)) return result([{ provider: "openai", model: "gpt", events: 3, total_tokens: 150, estimated_cost_usd: 0.25 }]);
    if (/GROUP BY COALESCE\(tool_name/.test(sql)) return result([{ tool_name: "model", events: 3, total_tokens: 150, estimated_cost_usd: 0.25 }]);
    if (/date_trunc\('day'/.test(sql)) return result([{ day: "2026-05-29", events: 3, total_tokens: 150, estimated_cost_usd: 0.25 }]);
    if (/FROM usage_events\s+WHERE workspace_id = \$1/.test(sql)) return result([{ events: 3, input_tokens: 100, output_tokens: 50, total_tokens: 150, estimated_cost_usd: 0.25 }]);
    throw new Error(`Unexpected database query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const response = await requestJson(baseUrl, "/api/usage/summary", {
        headers: { "x-operant-slack-user-id": "UOWNER" },
      });
      assert.equal(response.response.status, 200);
      assert.equal((response.body.totals as Record<string, unknown>).events, 3);
      assert.deepEqual((response.body.byUser as Array<Record<string, unknown>>).map((row) => row.slack_user_id), ["U_ALICE", "unattributed"]);
      assert.equal((response.body.byUser as Array<Record<string, unknown>>)[0].estimated_cost_usd, 0.2);
      assert.equal((response.body.byModel as unknown[]).length, 1);
      assert.equal((response.body.byTool as unknown[]).length, 1);
      assert.equal((response.body.byDay as unknown[]).length, 1);
    });
  });
  // The per-user rollup must join usage_events to sessions, not aggregate usage_events alone.
  assert.ok(calls.some((c) => /LEFT JOIN sessions/.test(c.sql)), "expected a usage query that joins sessions for per-user attribution");
});

test("plugin policy-check audits pipedream.invocation with the Slack principal as a first-class actor", async () => {
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/FROM tool_policies/.test(sql)) return result();
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected database query: ${sql}`);
  });

  await withEnv({ OPERANT_INTERNAL_TOKEN: "internal-secret" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const response = await requestJson(baseUrl, "/internal/plugin/policy-check", {
        method: "POST",
        headers: { authorization: "Bearer internal-secret" },
        body: JSON.stringify({ tool: "pipedream:github", action: "list", slackUserId: "U_PLUGIN" }),
      });
      assert.equal(response.response.status, 200);
      assert.equal(auditRows.length, 1);
      // INSERT params: actor_user_id($3 -> idx 2), actor_slack_user_id($4 -> idx 3), event_type($5 -> idx 4), ... metadata($9 -> idx 8).
      assert.equal(auditRows[0][3], "U_PLUGIN");
      assert.equal(auditRows[0][4], "pipedream.invocation");
      assert.equal((auditRows[0][8] as Record<string, unknown>).slackUserId, "U_PLUGIN");
    });
  });
});
