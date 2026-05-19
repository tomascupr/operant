import assert from "node:assert/strict";
import test from "node:test";
import { customRoleUpsertSchema, userUpsertSchema } from "../src/schema.js";

test("user upsert schema defaults to member role", () => {
  const parsed = userUpsertSchema.parse({ slackUserId: "U1" });
  assert.deepEqual(parsed.roles, ["member"]);
});

test("user upsert schema validates email shape", () => {
  assert.throws(() => userUpsertSchema.parse({ slackUserId: "U1", email: "not-email" }), /Invalid email/);
});

test("user upsert schema requires at least one role when roles are explicit", () => {
  assert.throws(() => userUpsertSchema.parse({ slackUserId: "U1", roles: [] }), /Too small/);
});

test("user upsert schema constrains Slack IDs and role names", () => {
  assert.throws(() => userUpsertSchema.parse({ slackUserId: "U 1" }), /Slack identifier/);
  assert.throws(() => userUpsertSchema.parse({ slackUserId: "U1", roles: ["Admin"] }), /lowercase/);
});

test("user display names are trimmed and nonblank when provided", () => {
  const parsed = userUpsertSchema.parse({ slackUserId: "U1", name: "  Smoke Admin  " });
  assert.equal(parsed.name, "Smoke Admin");
  assert.throws(() => userUpsertSchema.parse({ slackUserId: "U1", name: "   " }), /Too small/);
});

test("custom role schema accepts named permission pairs", () => {
  const parsed = customRoleUpsertSchema.parse({
    name: "usage_analyst",
    permissions: [{ action: "usage:read", resource: "usage" }],
  });
  assert.equal(parsed.name, "usage_analyst");
  assert.deepEqual(parsed.permissions, [{ action: "usage:read", resource: "usage" }]);
});

test("custom role schema rejects uppercase names", () => {
  assert.throws(() => customRoleUpsertSchema.parse({
    name: "UsageAnalyst",
    permissions: [{ action: "usage:read", resource: "usage" }],
  }));
});

test("custom role schema requires at least one permission", () => {
  assert.throws(() => customRoleUpsertSchema.parse({ name: "usage_analyst", permissions: [] }));
});

test("custom role schema bounds permission grants", () => {
  assert.throws(
    () => customRoleUpsertSchema.parse({
      name: "usage_analyst",
      permissions: Array.from({ length: 501 }, () => ({ action: "usage:read", resource: "usage" })),
    }),
    /Too big/,
  );
});
