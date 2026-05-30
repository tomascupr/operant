import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";
import type { Database } from "../src/db.js";
import { createHttpServer, type ServerState } from "../src/server.js";

const companyId = "11111111-1111-4111-8111-111111111111";
const workspaceId = "22222222-2222-4222-8222-222222222222";
const memoryId = "33333333-3333-4333-8333-333333333333";
const skillId = "44444444-4444-4444-8444-444444444444";
const teamsAadId = "55555555-5555-4555-8555-555555555555";
const otherTeamsAadId = "66666666-6666-4666-8666-666666666666";

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
    pool: { query, connect: async () => ({ query, release: () => {} }) } as unknown as Database,
  };
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
  return result([{ id: workspaceId, company_id: companyId, name: "Acme Slack", company_name: "Acme Inc." }]);
}

// RBAC via header auth: resolves a chat principal to a single role with the given grants.
function rbacHeaderActor(sql: string, actor: { userId: string; slackUserId: string | null; teamsAadUserId: string | null; role: string; grants: Array<{ action: string; resource: string }> }): QueryResult | null {
  if (/SELECT 1 FROM role_assignments/.test(sql)) return result([{ exists: true }]);
  if (/FROM users u\s+JOIN role_assignments/.test(sql)) {
    return result([{ user_id: actor.userId, slack_user_id: actor.slackUserId, teams_aad_user_id: actor.teamsAadUserId, role_name: actor.role }]);
  }
  if (/FROM role_assignments ra\s+JOIN role_permissions/.test(sql)) return result(actor.grants);
  return null;
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
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
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
  return { response, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

const OWNER = { userId: "user-owner", slackUserId: "UOWNER", teamsAadUserId: null, role: "owner", grants: [{ action: "*", resource: "*" }] };
const MEMBER_NO_SKILLS_WRITE = {
  userId: "user-member",
  slackUserId: "UMEMBER",
  teamsAadUserId: null,
  role: "member",
  grants: [{ action: "memory:read", resource: "memory" }, { action: "memory:write", resource: "memory" }, { action: "skills:read", resource: "skill" }],
};

test("POST /api/memory redacts secret-shaped content before persisting and audits memory.written", async () => {
  const inserts: unknown[][] = [];
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO memory_entries/.test(sql)) {
      inserts.push(params);
      return result([{ id: memoryId, created_at: new Date("2026-05-31T00:00:00.000Z") }]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/memory", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ content: "deploy token is xoxb-9-abc please remember", visibility: "team", tags: ["ops"] }),
      });
      assert.equal(res.response.status, 201);
      assert.equal(res.body.id, memoryId);
      assert.equal(inserts.length, 1);
      // INSERT cols: workspace_id($1), owner_principal_id($2), owner_platform($3), visibility($4), scope_key($5), tags($6), content($7 -> idx 6).
      const content = String(inserts[0][6]);
      assert.ok(!content.includes("xoxb-"), "secret-shaped content must be redacted before persist");
      assert.match(content, /\[REDACTED\]/);
      assert.equal(inserts[0][1], "UOWNER");
      assert.equal(inserts[0][2], "slack");
      assert.equal(inserts[0][3], "team");
      // audit() cols: ...event_type($6 -> idx 5), metadata($10 -> idx 9).
      assert.equal(auditRows.length, 1);
      assert.equal(auditRows[0][5], "memory.written");
      assert.equal((auditRows[0][9] as Record<string, unknown>).visibility, "team");
    });
  });
});

test("GET /api/memory without an admin session is rejected when RBAC assignments exist", async () => {
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/SELECT 1 FROM role_assignments/.test(sql)) return result([{ exists: true }]);
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: undefined }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/memory");
      assert.equal(res.response.status, 401);
      assert.equal(res.body.error, "Missing or invalid Operant admin session");
    });
  });
});

test("POST /api/skills is denied for a member without skills:write", async () => {
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    const rbac = rbacHeaderActor(sql, MEMBER_NO_SKILLS_WRITE);
    if (rbac) return rbac;
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/skills", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UMEMBER" },
        body: JSON.stringify({ name: "draft-email", triggerHint: "when asked to email", body: "step 1" }),
      });
      assert.equal(res.response.status, 403);
      assert.equal(res.body.error, "RBAC denied");
      assert.deepEqual(res.body.roles, ["member"]);
    });
  });
});

test("POST /api/skills upserts and audits skills.upserted for an owner", async () => {
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO skill_definitions/.test(sql)) return result([{ id: skillId, name: "draft-email" }]);
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/skills", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ name: "draft-email", triggerHint: "when asked to draft an email", body: "Step 1: gather context" }),
      });
      assert.equal(res.response.status, 200);
      assert.equal(res.body.id, skillId);
      assert.equal(res.body.name, "draft-email");
      assert.ok(auditRows.some((row) => row[5] === "skills.upserted"));
    });
  });
});

test("internal memory endpoints reject a missing internal token before any DB access", async () => {
  const { pool } = createFakePool((sql) => {
    throw new Error(`Unexpected query: ${sql}`);
  });
  await withEnv({ OPERANT_INTERNAL_TOKEN: "internal-secret" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const write = await requestJson(baseUrl, "/internal/plugin/memory/write", { method: "POST", body: JSON.stringify({ principalId: "UANY", content: "x" }) });
      assert.equal(write.response.status, 401);
      const search = await requestJson(baseUrl, "/internal/plugin/memory/search", { method: "POST", body: JSON.stringify({ principalId: "UANY" }) });
      assert.equal(search.response.status, 401);
    });
  });
});

test("plugin memory search scopes to team + own-private for the active principal and audits memory.read", async () => {
  let searchSql = "";
  let searchParams: unknown[] = [];
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/SELECT[\s\S]*FROM memory_entries/.test(sql)) {
      searchSql = sql;
      searchParams = params;
      return result([{ id: memoryId, content: "team note", visibility: "team", scope_key: null, tags: [], owner_principal_id: teamsAadId, owner_platform: "msteams" }]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_INTERNAL_TOKEN: "internal-secret" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/internal/plugin/memory/search", {
        method: "POST",
        headers: { authorization: "Bearer internal-secret" },
        body: JSON.stringify({ principalId: teamsAadId, q: "note" }),
      });
      assert.equal(res.response.status, 200);
      assert.equal((res.body.entries as unknown[]).length, 1);
      // The visibility clause must be enforced server-side: team OR own-private only.
      assert.match(searchSql, /visibility = 'team'/);
      assert.match(searchSql, /visibility = 'private'/);
      assert.match(searchSql, /owner_platform = 'msteams'/);
      // The Teams principal is bound as a parameter (never another user's id), so private rows can only match this principal.
      assert.ok(searchParams.includes(teamsAadId), "active Teams principal must be a bound search parameter");
      assert.ok(!searchParams.includes(otherTeamsAadId));
      // audit cols: actor_slack_user_id($4 -> idx 3), actor_teams_aad_user_id($5 -> idx 4), event_type($6 -> idx 5).
      assert.equal(auditRows.length, 1);
      assert.equal(auditRows[0][3], null);
      assert.equal(auditRows[0][4], teamsAadId);
      assert.equal(auditRows[0][5], "memory.read");
    });
  });
});

test("plugin skills search returns workspace skills and audits skills.read", async () => {
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = existingWorkspaceSeedQueries(sql, params);
    if (seeded) return seeded;
    const workspace = workspaceJoinQuery(sql);
    if (workspace) return workspace;
    if (/SELECT[\s\S]*FROM skill_definitions/.test(sql)) {
      return result([{ id: skillId, name: "draft-email", trigger_hint: "when emailing", body: "step 1", tags: [] }]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_INTERNAL_TOKEN: "internal-secret" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/internal/plugin/skills/search", {
        method: "POST",
        headers: { authorization: "Bearer internal-secret" },
        body: JSON.stringify({ principalId: "UOWNER", q: "email" }),
      });
      assert.equal(res.response.status, 200);
      assert.equal((res.body.skills as unknown[]).length, 1);
      assert.ok(auditRows.some((row) => row[5] === "skills.read"));
    });
  });
});
