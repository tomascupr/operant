import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { Database } from "../src/db.js";
import { isValidCronExpression, isValidEveryDuration, scheduledWorkflowCreateSchema } from "../src/schema.js";
import { createHttpServer, type ServerState } from "../src/server.js";

const companyId = "11111111-1111-4111-8111-111111111111";
const workspaceId = "22222222-2222-4222-8222-222222222222";
const workflowId = "77777777-7777-4777-8777-777777777777";

type QueryResult = { rows: any[]; rowCount: number };

function result(rows: any[] = []): QueryResult {
  return { rows, rowCount: rows.length };
}

function createFakePool(handler: (sql: string, params: unknown[]) => QueryResult | Promise<QueryResult>) {
  const calls: Array<{ sql: string; params: unknown[] }> = [];
  const query = async (sql: string, params: unknown[] = []) => {
    calls.push({ sql, params });
    return handler(sql, params);
  };
  return { calls, pool: { query, connect: async () => ({ query, release: () => {} }) } as unknown as Database };
}

function seedQueries(sql: string, params: unknown[]): QueryResult | null {
  if (/^\s*(BEGIN|COMMIT|ROLLBACK)/i.test(sql)) return result();
  if (/SELECT w\.id AS workspace_id/.test(sql)) return result([{ workspace_id: workspaceId, company_id: companyId }]);
  if (/INSERT INTO permissions/.test(sql)) return result();
  if (/INSERT INTO roles/.test(sql)) return result([{ id: `role-${String(params[1] || "unknown")}` }]);
  if (/DELETE FROM role_permissions/.test(sql)) return result();
  if (/INSERT INTO role_permissions/.test(sql)) return result();
  if (/FROM workspaces w\s+JOIN companies c/.test(sql)) return result([{ id: workspaceId, company_id: companyId, name: "Acme", company_name: "Acme Inc." }]);
  return null;
}

function rbacHeaderActor(sql: string, actor: { userId: string; slackUserId: string | null; role: string; grants: Array<{ action: string; resource: string }> }): QueryResult | null {
  if (/SELECT 1 FROM role_assignments/.test(sql)) return result([{ exists: true }]);
  if (/FROM users u\s+JOIN role_assignments/.test(sql)) return result([{ user_id: actor.userId, slack_user_id: actor.slackUserId, teams_aad_user_id: null, role_name: actor.role }]);
  if (/FROM role_assignments ra\s+JOIN role_permissions/.test(sql)) return result(actor.grants);
  return null;
}

function workflowRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: workflowId,
    owner_principal_id: "UOWNER",
    owner_platform: "slack",
    name: "daily-standup",
    description: null,
    schedule_kind: "cron",
    schedule_expression: "0 9 * * 1-5",
    timezone: "Europe/Prague",
    target_channel: "C123",
    message: "Post the standup",
    tools: [],
    enabled: true,
    openclaw_cron_id: null,
    materialization_status: "pending",
    materialization_error: null,
    last_materialized_at: null,
    created_at: new Date("2026-05-31T00:00:00.000Z"),
    updated_at: new Date("2026-05-31T00:00:00.000Z"),
    ...overrides,
  };
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
    headers: { accept: "application/json", ...(options.body ? { "content-type": "application/json" } : {}), ...(options.headers || {}) },
  });
  const text = await response.text();
  return { response, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

// A fake `openclaw` CLI: emits the JSON the gateway would for cron add/list, ignores flags.
function writeStubCli(): string {
  const dir = mkdtempSync(join(tmpdir(), "operant-cron-stub-"));
  const path = join(dir, "openclaw-stub.mjs");
  writeFileSync(path, [
    "#!/usr/bin/env node",
    "const a = process.argv.slice(2);",
    "if (a[0] === 'cron' && a[1] === 'add') process.stdout.write(JSON.stringify({ id: 'cron-job-1', name: 'daily-standup' }));",
    "else if (a[0] === 'cron' && a[1] === 'list') process.stdout.write(JSON.stringify({ jobs: [{ id: 'cron-job-1', name: 'daily-standup', enabled: true }], total: 1 }));",
    "else process.stdout.write('{}');",
    "process.exit(0);",
    "",
  ].join("\n"));
  chmodSync(path, 0o755);
  return path;
}

test("schedule validators accept cron + duration shapes and reject junk", () => {
  assert.equal(isValidCronExpression("0 9 * * 1-5"), true);
  assert.equal(isValidCronExpression("*/5 * * * * *"), true); // 6-field with seconds
  assert.equal(isValidCronExpression("0 9 * *"), false); // 4 fields
  assert.equal(isValidCronExpression("every monday"), false);
  assert.equal(isValidEveryDuration("10m"), true);
  assert.equal(isValidEveryDuration("1h"), true);
  assert.equal(isValidEveryDuration("90"), false);
  // The create schema cross-checks expression against kind.
  assert.equal(scheduledWorkflowCreateSchema.safeParse({ name: "x", scheduleKind: "cron", scheduleExpression: "1h", targetChannel: "C1", message: "hi" }).success, false);
  assert.equal(scheduledWorkflowCreateSchema.safeParse({ name: "x", scheduleKind: "every", scheduleExpression: "1h", targetChannel: "C1", message: "hi" }).success, true);
  // A timezone only applies to cron; reject it on 'every' so the stored definition can't claim one the gateway ignores.
  assert.equal(scheduledWorkflowCreateSchema.safeParse({ name: "x", scheduleKind: "every", scheduleExpression: "1h", timezone: "Europe/Prague", targetChannel: "C1", message: "hi" }).success, false);
  assert.equal(scheduledWorkflowCreateSchema.safeParse({ name: "x", scheduleKind: "cron", scheduleExpression: "0 9 * * 1-5", timezone: "Europe/Prague", targetChannel: "C1", message: "hi" }).success, true);
});

// A stub `openclaw` that leaks its gateway token to stderr and fails, to prove scrubbing.
function writeLeakyStubCli() {
  const dir = mkdtempSync(join(tmpdir(), "operant-cron-leak-"));
  const path = join(dir, "openclaw-leak.mjs");
  writeFileSync(path, [
    "#!/usr/bin/env node",
    "process.stderr.write('gateway connect failed using --token ' + (process.env.OPENCLAW_GATEWAY_TOKEN || '') + ' (requestId: abc)');",
    "process.exit(1);",
    "",
  ].join("\n"));
  chmodSync(path, 0o755);
  return path;
}

const OWNER = { userId: "user-owner", slackUserId: "UOWNER", role: "owner", grants: [{ action: "*", resource: "*" }] };
const MEMBER = { userId: "user-member", slackUserId: "UMEMBER", role: "member", grants: [{ action: "workflow:read", resource: "workflow" }] };

test("POST /api/workflows scrubs the gateway token from the persisted error and the response", async () => {
  const stub = writeLeakyStubCli();
  const TOKEN = "live-gateway-token-do-not-leak";
  const updates: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO scheduled_workflows/.test(sql)) return result([workflowRow()]);
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$3/.test(sql)) {
      updates.push(params);
      return result([workflowRow({ materialization_status: params[2], materialization_error: params[3] })]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub, OPENCLAW_GATEWAY_TOKEN: TOKEN }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ name: "leaky", scheduleKind: "every", scheduleExpression: "1h", targetChannel: "last", message: "go" }),
      });
      assert.equal(res.response.status, 201);
      // Persisted materialization_error (UPDATE param $4 -> idx 3) must not contain the token.
      assert.ok(!String(updates[0][3]).includes(TOKEN), "gateway token must be scrubbed before persist");
      assert.match(String(updates[0][3]), /\[REDACTED\]/);
      // The apply.stderr returned to the client must also be scrubbed.
      assert.ok(!JSON.stringify(res.body).includes(TOKEN), "gateway token must not appear in the API response");
    });
  });
});

test("POST /api/workflows creates, materializes into OpenClaw cron, and audits workflow.created", async () => {
  const stub = writeStubCli();
  const updates: unknown[][] = [];
  const auditRows: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO scheduled_workflows/.test(sql)) return result([workflowRow()]);
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$3/.test(sql)) {
      updates.push(params);
      return result([workflowRow({ openclaw_cron_id: params[1], materialization_status: params[2] })]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ name: "daily-standup", scheduleKind: "cron", scheduleExpression: "0 9 * * 1-5", timezone: "Europe/Prague", targetChannel: "C123", message: "Post the standup", tools: ["read"] }),
      });
      assert.equal(res.response.status, 201);
      assert.equal((res.body.apply as Record<string, unknown>).status, "materialized");
      assert.equal((res.body.apply as Record<string, unknown>).ok, true);
      // materialize() persisted the gateway-assigned cron id + status.
      assert.equal(updates.length, 1);
      assert.equal(updates[0][1], "cron-job-1");
      assert.equal(updates[0][2], "materialized");
      assert.ok(auditRows.some((row) => row[5] === "workflow.created"));
    });
  });
});

test("POST /api/workflows persists the definition even when the gateway is unreachable", async () => {
  const updates: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO scheduled_workflows/.test(sql)) return result([workflowRow()]);
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$3/.test(sql)) {
      updates.push(params);
      return result([workflowRow({ materialization_status: params[2], materialization_error: params[3] })]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  // No CLI on PATH -> spawn fails -> materialization records 'error' but the row is still created.
  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: "operant-nonexistent-cli-xyz" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ name: "daily-standup", scheduleKind: "every", scheduleExpression: "1h", targetChannel: "last", message: "Run the scan" }),
      });
      assert.equal(res.response.status, 201);
      assert.equal((res.body.apply as Record<string, unknown>).status, "error");
      assert.equal((res.body.apply as Record<string, unknown>).ok, false);
      assert.equal(updates[0][2], "error");
      assert.ok(String(updates[0][3] ?? "").length > 0, "gateway error text is recorded on the row");
    });
  });
});

test("POST /api/workflows rejects an invalid cron expression with 400 before any insert", async () => {
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO scheduled_workflows/.test(sql)) throw new Error("must not insert an invalid workflow");
    throw new Error(`Unexpected query: ${sql}`);
  });
  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ name: "bad", scheduleKind: "cron", scheduleExpression: "not a cron", targetChannel: "C1", message: "hi" }),
      });
      assert.equal(res.response.status, 400);
    });
  });
});

test("POST /api/workflows is denied for a member without workflow:write", async () => {
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, MEMBER);
    if (rbac) return rbac;
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });
  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UMEMBER" },
        body: JSON.stringify({ name: "x", scheduleKind: "every", scheduleExpression: "1h", targetChannel: "last", message: "hi" }),
      });
      assert.equal(res.response.status, 403);
      assert.equal(res.body.error, "RBAC denied");
    });
  });
});

test("POST /api/workflows surfaces a duplicate name as 409", async () => {
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO scheduled_workflows/.test(sql)) {
      const err = new Error("duplicate key value violates unique constraint") as Error & { code: string };
      err.code = "23505";
      throw err;
    }
    throw new Error(`Unexpected query: ${sql}`);
  });
  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ name: "daily-standup", scheduleKind: "every", scheduleExpression: "1h", targetChannel: "last", message: "hi" }),
      });
      assert.equal(res.response.status, 409);
    });
  });
});

test("POST /api/workflows/sync flags a vanished gateway job as drift", async () => {
  const stub = writeStubCli();
  const statusUpdates: unknown[][] = [];
  const { calls, pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT[\s\S]*FROM scheduled_workflows WHERE workspace_id = \$1 AND openclaw_cron_id IS NOT NULL/.test(sql)) {
      // One row whose cron job still exists, one whose job vanished.
      return result([
        workflowRow({ id: workflowId, openclaw_cron_id: "cron-job-1", materialization_status: "materialized" }),
        workflowRow({ id: "88888888-8888-4888-8888-888888888888", name: "gone", openclaw_cron_id: "cron-job-missing", materialization_status: "materialized" }),
      ]);
    }
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$2/.test(sql)) {
      statusUpdates.push(params);
      return result();
    }
    if (/SELECT[\s\S]*FROM scheduled_workflows WHERE workspace_id = \$1 ORDER BY created_at DESC/.test(sql)) return result([]);
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows/sync", { method: "POST", headers: { "x-operant-slack-user-id": "UOWNER" } });
      assert.equal(res.response.status, 200);
      assert.equal(res.body.reconciled, 2);
      assert.equal(res.body.drift, 1);
      const statuses = statusUpdates.map((row) => row[1]);
      assert.ok(statuses.includes("materialized"));
      assert.ok(statuses.includes("drift"));
      // On drift the stale gateway id must be cleared so a later apply re-adds a fresh job.
      assert.ok(
        calls.some((c) => /UPDATE scheduled_workflows[\s\S]*openclaw_cron_id = CASE WHEN \$3/.test(c.sql)),
        "drift reconcile must clear the stale openclaw_cron_id",
      );
    });
  });
});

// A stub whose `cron add` succeeds (exit 0) but returns no parseable job id.
function writeNoIdStubCli(): string {
  const dir = mkdtempSync(join(tmpdir(), "operant-cron-noid-"));
  const path = join(dir, "openclaw-noid.mjs");
  writeFileSync(path, [
    "#!/usr/bin/env node",
    "process.stdout.write(JSON.stringify({ ok: true }));",
    "process.exit(0);",
    "",
  ].join("\n"));
  chmodSync(path, 0o755);
  return path;
}

test("POST /api/workflows records 'error' when cron add succeeds but returns no job id", async () => {
  const stub = writeNoIdStubCli();
  const updates: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/INSERT INTO scheduled_workflows/.test(sql)) return result([workflowRow()]);
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$3/.test(sql)) {
      updates.push(params);
      return result([workflowRow({ openclaw_cron_id: params[1], materialization_status: params[2] })]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows", {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ name: "daily-standup", scheduleKind: "every", scheduleExpression: "1h", targetChannel: "C1", message: "go" }),
      });
      assert.equal(res.response.status, 201);
      assert.equal((res.body.apply as Record<string, unknown>).status, "error");
      assert.equal((res.body.apply as Record<string, unknown>).ok, false);
      // Persisted with a NULL cron id (param $2) so re-apply does not blindly re-add a duplicate.
      assert.equal(updates[0][1], null);
      assert.equal(updates[0][2], "error");
      assert.match(String(updates[0][3]), /no job id/);
    });
  });
});

test("POST /api/workflows/:id/apply re-materializes a drifted workflow by re-adding the cron job", async () => {
  const stub = writeStubCli();
  const updates: unknown[][] = [];
  const auditRows: unknown[][] = [];
  const { calls, pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT[\s\S]*FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      // Drifted: enabled, but the stale id was cleared by a prior reconcile.
      return result([workflowRow({ openclaw_cron_id: null, materialization_status: "drift" })]);
    }
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$3/.test(sql)) {
      updates.push(params);
      return result([workflowRow({ openclaw_cron_id: params[1], materialization_status: params[2] })]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, `/api/workflows/${workflowId}/apply`, {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({}),
      });
      assert.equal(res.response.status, 200);
      assert.equal((res.body.apply as Record<string, unknown>).status, "materialized");
      assert.equal(updates[0][1], "cron-job-1");
      assert.ok(auditRows.some((row) => row[5] === "workflow.applied"));
      assert.ok(
        calls.some((c) => /FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2 FOR UPDATE/.test(c.sql)),
        "apply must lock the row with SELECT ... FOR UPDATE",
      );
    });
  });
});

test("POST /api/workflows/:id/apply disables a materialized workflow via cron disable", async () => {
  const stub = writeStubCli();
  const updates: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT[\s\S]*FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      return result([workflowRow({ openclaw_cron_id: "cron-job-1", materialization_status: "materialized", enabled: true })]);
    }
    if (/UPDATE scheduled_workflows SET enabled = \$2/.test(sql)) {
      return result([workflowRow({ openclaw_cron_id: "cron-job-1", enabled: params[1] as boolean })]);
    }
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$3/.test(sql)) {
      updates.push(params);
      return result([workflowRow({ openclaw_cron_id: params[1], materialization_status: params[2] })]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, `/api/workflows/${workflowId}/apply`, {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ enabled: false }),
      });
      assert.equal(res.response.status, 200);
      assert.equal((res.body.apply as Record<string, unknown>).status, "disabled");
      assert.equal(updates[0][2], "disabled");
    });
  });
});

test("POST /api/workflows/:id/apply returns 404 for an unknown workflow", async () => {
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT[\s\S]*FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) return result([]);
    throw new Error(`Unexpected query: ${sql}`);
  });
  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, `/api/workflows/${workflowId}/apply`, {
        method: "POST",
        headers: { "x-operant-slack-user-id": "UOWNER" },
        body: JSON.stringify({ enabled: true }),
      });
      assert.equal(res.response.status, 404);
    });
  });
});

// A stub whose `cron list` reports the job as disabled, to exercise intent-mismatch drift.
function writeStubCliDisabledJob(): string {
  const dir = mkdtempSync(join(tmpdir(), "operant-cron-disabled-"));
  const path = join(dir, "openclaw-disabled.mjs");
  writeFileSync(path, [
    "#!/usr/bin/env node",
    "const a = process.argv.slice(2);",
    "if (a[0] === 'cron' && a[1] === 'list') process.stdout.write(JSON.stringify({ jobs: [{ id: 'cron-job-1', name: 'daily-standup', enabled: false }], total: 1 }));",
    "else process.stdout.write('{}');",
    "process.exit(0);",
    "",
  ].join("\n"));
  chmodSync(path, 0o755);
  return path;
}

test("POST /api/workflows/sync flags an enabled-state mismatch as drift without clearing the id", async () => {
  const stub = writeStubCliDisabledJob();
  const statusUpdates: unknown[][] = [];
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT[\s\S]*FROM scheduled_workflows WHERE workspace_id = \$1 AND openclaw_cron_id IS NOT NULL/.test(sql)) {
      // Operant intends enabled=true, but the gateway job is disabled -> intent mismatch.
      return result([workflowRow({ openclaw_cron_id: "cron-job-1", enabled: true, materialization_status: "materialized" })]);
    }
    if (/UPDATE scheduled_workflows[\s\S]*materialization_status = \$2/.test(sql)) {
      statusUpdates.push(params);
      return result();
    }
    if (/SELECT[\s\S]*FROM scheduled_workflows WHERE workspace_id = \$1 ORDER BY created_at DESC/.test(sql)) return result([]);
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, "/api/workflows/sync", { method: "POST", headers: { "x-operant-slack-user-id": "UOWNER" } });
      assert.equal(res.response.status, 200);
      assert.equal(res.body.drift, 1);
      assert.equal(statusUpdates[0][1], "drift");
      assert.equal(statusUpdates[0][2], false, "present-but-mismatched job keeps its id (jobMissing=false)");
    });
  });
});

test("DELETE /api/workflows/:id removes the gateway job first, then the row, and audits workflow.deleted", async () => {
  const stub = writeStubCli();
  const auditRows: unknown[][] = [];
  let deleted = false;
  const { calls, pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT openclaw_cron_id FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      return result([{ openclaw_cron_id: "cron-job-1" }]);
    }
    if (/DELETE FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      deleted = true;
      return result([{}]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, `/api/workflows/${workflowId}`, { method: "DELETE", headers: { "x-operant-slack-user-id": "UOWNER" } });
      assert.equal(res.response.status, 200);
      assert.equal(res.body.id, workflowId);
      assert.ok(deleted);
      assert.ok(auditRows.some((row) => row[5] === "workflow.deleted"));
      assert.ok(
        calls.some((c) => /SELECT openclaw_cron_id FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2 FOR UPDATE/.test(c.sql)),
        "delete must lock the row with SELECT ... FOR UPDATE so it serializes against apply",
      );
    });
  });
});

test("DELETE /api/workflows/:id deletes a never-materialized workflow without calling the gateway", async () => {
  const auditRows: unknown[][] = [];
  let deleted = false;
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT openclaw_cron_id FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      return result([{ openclaw_cron_id: null }]);
    }
    if (/DELETE FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      deleted = true;
      return result([{}]);
    }
    if (/INSERT INTO audit_logs/.test(sql)) {
      auditRows.push(params);
      return result();
    }
    throw new Error(`Unexpected query: ${sql}`);
  });

  // A CLI that would throw if invoked, proving the gateway is never called for a null cron id.
  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: "operant-nonexistent-cli-must-not-run" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, `/api/workflows/${workflowId}`, { method: "DELETE", headers: { "x-operant-slack-user-id": "UOWNER" } });
      assert.equal(res.response.status, 200);
      assert.equal(res.body.cronRemoval, null);
      assert.ok(deleted);
      assert.ok(auditRows.some((row) => row[5] === "workflow.deleted"));
    });
  });
});

test("DELETE /api/workflows/:id retains the row (does not orphan the job) when gateway cron rm fails", async () => {
  const stub = writeLeakyStubCli(); // exits 1
  const updates: unknown[][] = [];
  let deleted = false;
  const { pool } = createFakePool((sql, params) => {
    const seeded = seedQueries(sql, params);
    if (seeded) return seeded;
    const rbac = rbacHeaderActor(sql, OWNER);
    if (rbac) return rbac;
    if (/SELECT openclaw_cron_id FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      return result([{ openclaw_cron_id: "cron-job-1" }]);
    }
    if (/DELETE FROM scheduled_workflows WHERE id = \$1 AND workspace_id = \$2/.test(sql)) {
      deleted = true;
      return result([{}]);
    }
    if (/UPDATE scheduled_workflows SET materialization_status = 'error'/.test(sql)) {
      updates.push(params);
      return result();
    }
    if (/INSERT INTO audit_logs/.test(sql)) return result();
    throw new Error(`Unexpected query: ${sql}`);
  });

  await withEnv({ OPERANT_ALLOW_HEADER_AUTH: "true", OPENCLAW_CLI_COMMAND: stub, OPENCLAW_GATEWAY_TOKEN: "tok" }, async () => {
    await withServer({ pool, masterKey: Buffer.alloc(32) }, async (baseUrl) => {
      const res = await requestJson(baseUrl, `/api/workflows/${workflowId}`, { method: "DELETE", headers: { "x-operant-slack-user-id": "UOWNER" } });
      assert.equal(res.response.status, 502);
      assert.equal(deleted, false, "row must be retained when gateway removal fails");
      assert.equal(updates.length, 1, "row is marked error for retry");
      assert.match(String(updates[0][1]), /\S/);
    });
  });
});
