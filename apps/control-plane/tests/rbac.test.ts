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
