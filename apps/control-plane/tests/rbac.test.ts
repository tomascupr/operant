import assert from "node:assert/strict";
import test from "node:test";
import { hasPermission } from "../src/rbac.js";

test("owner can access every action and resource", () => {
  assert.equal(hasPermission(["owner"], { action: "data:wipe", resource: "retention" }), true);
  assert.equal(hasPermission(["owner"], { action: "unknown", resource: "unknown" }), true);
});

test("viewer is read-only", () => {
  assert.equal(hasPermission(["viewer"], { action: "audit:read", resource: "audit_log" }), true);
  assert.equal(hasPermission(["viewer"], { action: "credentials:write", resource: "integration" }), false);
  assert.equal(hasPermission(["viewer"], { action: "users:write", resource: "user" }), false);
});

test("integration admin can write credentials but not wipe retention", () => {
  assert.equal(hasPermission(["integration_admin"], { action: "credentials:write", resource: "integration" }), true);
  assert.equal(hasPermission(["integration_admin"], { action: "observability:sync", resource: "openclaw_observation" }), true);
  assert.equal(hasPermission(["integration_admin"], { action: "data:wipe", resource: "retention" }), false);
});

test("billing usage admin can read usage and audit but cannot mutate workspace or credentials", () => {
  assert.equal(hasPermission(["billing_usage_admin"], { action: "usage:read", resource: "usage" }), true);
  assert.equal(hasPermission(["billing_usage_admin"], { action: "audit:read", resource: "audit_log" }), true);
  assert.equal(hasPermission(["billing_usage_admin"], { action: "settings:update", resource: "workspace" }), false);
  assert.equal(hasPermission(["billing_usage_admin"], { action: "credentials:write", resource: "integration" }), false);
  assert.equal(hasPermission(["billing_usage_admin"], { action: "approval:decide", resource: "approval" }), false);
});

test("admin can manage users", () => {
  assert.equal(hasPermission(["admin"], { action: "users:read", resource: "user" }), true);
  assert.equal(hasPermission(["admin"], { action: "users:write", resource: "user" }), true);
});

test("memory and skills grants follow the governance boundary", () => {
  // Members can write their own memory and read skills, but skill authoring is admin-only governance.
  assert.equal(hasPermission(["member"], { action: "memory:write", resource: "memory" }), true);
  assert.equal(hasPermission(["member"], { action: "skills:read", resource: "skill" }), true);
  assert.equal(hasPermission(["member"], { action: "skills:write", resource: "skill" }), false);
  // Admin and owner can author skills.
  assert.equal(hasPermission(["admin"], { action: "skills:write", resource: "skill" }), true);
  assert.equal(hasPermission(["owner"], { action: "skills:write", resource: "skill" }), true);
  // Viewer and integration_admin are read-only over the knowledge layer.
  assert.equal(hasPermission(["viewer"], { action: "memory:read", resource: "memory" }), true);
  assert.equal(hasPermission(["viewer"], { action: "memory:write", resource: "memory" }), false);
  assert.equal(hasPermission(["integration_admin"], { action: "skills:read", resource: "skill" }), true);
  assert.equal(hasPermission(["integration_admin"], { action: "skills:write", resource: "skill" }), false);
});

test("scheduled-workflow grants: authoring is owner/admin only, reading is broad", () => {
  // Authoring a recurring autonomous run is a governance act -> owner/admin only.
  assert.equal(hasPermission(["owner"], { action: "workflow:write", resource: "workflow" }), true);
  assert.equal(hasPermission(["admin"], { action: "workflow:write", resource: "workflow" }), true);
  assert.equal(hasPermission(["integration_admin"], { action: "workflow:write", resource: "workflow" }), false);
  assert.equal(hasPermission(["member"], { action: "workflow:write", resource: "workflow" }), false);
  assert.equal(hasPermission(["viewer"], { action: "workflow:write", resource: "workflow" }), false);
  // Everyone except the billing role can see what is scheduled.
  assert.equal(hasPermission(["admin"], { action: "workflow:read", resource: "workflow" }), true);
  assert.equal(hasPermission(["integration_admin"], { action: "workflow:read", resource: "workflow" }), true);
  assert.equal(hasPermission(["member"], { action: "workflow:read", resource: "workflow" }), true);
  assert.equal(hasPermission(["viewer"], { action: "workflow:read", resource: "workflow" }), true);
  assert.equal(hasPermission(["billing_usage_admin"], { action: "workflow:read", resource: "workflow" }), false);
});
