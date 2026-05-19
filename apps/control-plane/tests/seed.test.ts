import assert from "node:assert/strict";
import test from "node:test";
import { defaultRolePermissions } from "../src/rbac.js";
import { seedRolesAndPermissions } from "../src/seed.js";

type QueryCall = {
  sql: string;
  params: unknown[];
};

test("built-in role seeding removes stale grants before inserting current grants", async () => {
  const calls: QueryCall[] = [];
  const pool = {
    async query(sql: string, params: unknown[] = []) {
      calls.push({ sql, params });
      if (/INSERT INTO roles/.test(sql)) {
        return { rows: [{ id: `role-${String(params[1])}` }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
  } as Parameters<typeof seedRolesAndPermissions>[0];

  await seedRolesAndPermissions(pool, "company-1");

  const roleInsertIndex = calls.findIndex((call) => /INSERT INTO roles/.test(call.sql) && call.params[1] === "viewer");
  const staleGrantDeleteIndex = calls.findIndex((call) => /DELETE FROM role_permissions rp/.test(call.sql) && call.params[0] === "role-viewer");
  const firstGrantInsertIndex = calls.findIndex((call) => /INSERT INTO role_permissions/.test(call.sql) && call.params[0] === "role-viewer");
  assert.ok(roleInsertIndex >= 0, "viewer role must be upserted");
  assert.ok(staleGrantDeleteIndex > roleInsertIndex, "stale grants must be deleted after the role exists");
  assert.ok(firstGrantInsertIndex > staleGrantDeleteIndex, "current grants must be inserted after stale grants are deleted");

  const deleteCall = calls[staleGrantDeleteIndex];
  assert.match(deleteCall.sql, /NOT EXISTS/);
  assert.match(deleteCall.sql, /jsonb_to_recordset\(\$2::jsonb\)/);
  assert.deepEqual(JSON.parse(String(deleteCall.params[1])), defaultRolePermissions.viewer);
});
