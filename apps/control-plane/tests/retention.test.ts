import assert from "node:assert/strict";
import test from "node:test";
import { buildRetentionPurgeStatements, buildWipeStatements, retentionExportQueries, retentionWipeScopes } from "../src/retention.js";

test("retention export excludes encrypted credential values", () => {
  assert.equal(retentionExportQueries.credentials.includes("encrypted_value"), false);
  assert.equal(retentionExportQueries.credentials.includes("secret_ref_id"), true);
});

test("retention export queries are workspace-scoped and avoid wildcard selection", () => {
  for (const [key, sql] of Object.entries(retentionExportQueries)) {
    assert.match(sql, /WHERE workspace_id = \$1/, `${key} must stay scoped to one workspace`);
    assert.doesNotMatch(sql, /SELECT\s+\*/i, `${key} must explicitly select export fields`);
  }
});

test("retention credential export is metadata-only", () => {
  assert.equal(
    retentionExportQueries.credentials,
    "SELECT id, kind, label, secret_ref_id, created_at, updated_at FROM integration_credentials WHERE workspace_id = $1 ORDER BY created_at",
  );
});

test("retention export includes approval decision ledger metadata", () => {
  assert.equal(
    retentionExportQueries.approvalDecisions,
    "SELECT id, approval_id, decided_by_user_id, status, created_at FROM approval_decisions WHERE workspace_id = $1 ORDER BY created_at",
  );
});

test("supports expected wipe scopes", () => {
  assert.deepEqual([...retentionWipeScopes].sort(), ["audit", "sessions", "usage", "workspace"]);
});

test("usage wipe only deletes usage events", () => {
  assert.deepEqual(buildWipeStatements("usage").map((statement) => statement.label), ["usageEvents"]);
});

test("sessions wipe removes linked usage before jobs and sessions", () => {
  const statements = buildWipeStatements("sessions");
  assert.deepEqual(statements.map((statement) => statement.label), ["usageEvents", "jobs", "sessions"]);
  assert.match(statements[0].sql, /session_id IN \(SELECT id FROM sessions WHERE workspace_id = \$1\)/);
  assert.match(statements[0].sql, /job_id IN \(SELECT id FROM jobs WHERE workspace_id = \$1\)/);
});

test("workspace wipe removes operational state but keeps workspace identity tables", () => {
  const statements = buildWipeStatements("workspace");
  const sql = statements.map((statement) => statement.sql).join("\n");
  assert.equal(sql.includes("DELETE FROM workspaces"), false);
  assert.equal(sql.includes("DELETE FROM companies"), false);
  assert.equal(sql.includes("DELETE FROM integration_credentials"), true);
  assert.equal(sql.includes("DELETE FROM openclaw_configs"), true);
  assert.equal(sql.includes("DELETE FROM admin_sessions"), true);
  assert.ok(
    statements.findIndex((statement) => statement.label === "approvalDecisions")
      < statements.findIndex((statement) => statement.label === "approvals"),
    "approval decisions must be wiped before approval requests",
  );
  assert.ok(
    statements.findIndex((statement) => statement.label === "adminSessions")
      < statements.findIndex((statement) => statement.label === "auditLogs"),
    "admin sessions must be revoked before final wipe audit evidence is written",
  );
});

test("retention purge targets operational time-series records only", () => {
  const labels = buildRetentionPurgeStatements().map((statement) => statement.label);
  assert.deepEqual(labels, ["usageEvents", "usageEventsLinkedToExpiredSessions", "jobsLinkedToExpiredSessions", "jobs", "sessions", "approvals", "auditLogs"]);
  const sql = buildRetentionPurgeStatements().map((statement) => statement.sql).join("\n");
  assert.equal(sql.includes("integration_credentials"), false);
  assert.equal(sql.includes("workspace_settings"), false);
});

test("retention purge removes usage and jobs linked to expired sessions before parent records", () => {
  const statements = buildRetentionPurgeStatements();
  const linkedUsageIndex = statements.findIndex((statement) => statement.label === "usageEventsLinkedToExpiredSessions");
  const linkedJobsIndex = statements.findIndex((statement) => statement.label === "jobsLinkedToExpiredSessions");
  const jobsIndex = statements.findIndex((statement) => statement.label === "jobs");
  const sessionsIndex = statements.findIndex((statement) => statement.label === "sessions");
  assert.ok(linkedUsageIndex > -1 && linkedUsageIndex < linkedJobsIndex && linkedUsageIndex < jobsIndex && linkedUsageIndex < sessionsIndex);
  assert.ok(linkedJobsIndex > -1 && linkedJobsIndex < sessionsIndex);
  assert.match(statements[linkedUsageIndex].sql, /session_id IN \(SELECT id FROM sessions WHERE workspace_id = \$1 AND last_event_at < \$2\)/);
  assert.match(statements[linkedUsageIndex].sql, /LEFT JOIN sessions/);
  assert.match(statements[linkedUsageIndex].sql, /j\.created_at < \$2 OR s\.last_event_at < \$2/);
  assert.match(statements[linkedJobsIndex].sql, /session_id IN \(SELECT id FROM sessions WHERE workspace_id = \$1 AND last_event_at < \$2\)/);
});
