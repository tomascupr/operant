import assert from "node:assert/strict";
import test from "node:test";
import { credentialInputSchema, integrationCredentialInputSchema, metadataRecordSchema, policyUpdateSchema, usageCostUsdSchema, usageTokenCountSchema, workspaceSettingsUpdateSchema } from "../src/schema.js";

test("policy update schema supplies defaults", () => {
  const parsed = policyUpdateSchema.parse({
    channelPolicies: [{ channelId: "C1" }],
    toolPolicies: [{ tool: "exec", action: "*", effect: "approval_required" }],
    approvalPolicies: [{ name: "risky", actionPattern: "exec:*", approverSlackUserIds: ["UADMIN"] }],
  });

  assert.deepEqual(parsed.allowedDmUserIds, []);
  assert.equal(parsed.channelPolicies[0].enabled, true);
  assert.equal(parsed.channelPolicies[0].requireMention, true);
  assert.deepEqual(parsed.channelPolicies[0].allowedUserIds, []);
  assert.deepEqual(parsed.channelPolicies[0].deniedUserIds, []);
  assert.deepEqual(parsed.toolPolicies[0].slackUserIds, []);
  assert.deepEqual(parsed.toolPolicies[0].roleNames, []);
  assert.equal(parsed.approvalPolicies[0].resourcePattern, "*");
  assert.equal(parsed.approvalPolicies[0].minApprovals, 1);
});

test("policy update schema bounds Slack identifiers and policy arrays", () => {
  assert.throws(
    () => policyUpdateSchema.parse({ allowedDmUserIds: ["U1 with space"] }),
    /Slack identifier/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({ allowedDmUserIds: Array.from({ length: 201 }, (_, index) => `U${index}`) }),
    /Too big/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({ channelPolicies: Array.from({ length: 201 }, (_, index) => ({ channelId: `C${index}` })) }),
    /Too big/,
  );
});

test("policy update schema rejects invalid tool effects", () => {
  assert.throws(
    () => policyUpdateSchema.parse({ toolPolicies: [{ tool: "exec", action: "*", effect: "maybe" }] }),
    /Invalid option/,
  );
});

test("policy update schema rejects duplicate policy identities", () => {
  assert.throws(
    () => policyUpdateSchema.parse({
      channelPolicies: [{ channelId: "C1" }, { channelId: "C1" }],
    }),
    /Duplicate channel policy/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      toolPolicies: [
        { tool: "exec", action: "*", effect: "approval_required" },
        { tool: "exec", action: "*", effect: "approval_required" },
      ],
    }),
    /Duplicate tool policy/,
  );
  assert.doesNotThrow(() => policyUpdateSchema.parse({
    toolPolicies: [
      { tool: "exec", action: "*", effect: "approval_required" },
      { tool: "exec", action: "*", effect: "deny", roleNames: ["viewer"] },
    ],
  }));
  assert.throws(
    () => policyUpdateSchema.parse({
      approvalPolicies: [
        { name: "risky", actionPattern: "exec:*", approverSlackUserIds: ["UADMIN"] },
        { name: "risky", actionPattern: "browser:*", approverSlackUserIds: ["UADMIN"] },
      ],
    }),
    /Duplicate approval policy name/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      approvalPolicies: [{ name: "risky", actionPattern: "exec:*", approverSlackUserIds: ["UADMIN", "UADMIN"] }],
    }),
    /Duplicate approval policy approver/,
  );
});

test("credential schema accepts empty body so an update can keep existing secrets", () => {
  const parsed = credentialInputSchema.parse({});
  assert.equal(parsed.slackBotToken, undefined);
  assert.equal(parsed.slackAppToken, undefined);
  assert.equal(parsed.modelApiKey, undefined);
  assert.equal(parsed.modelProvider, "openai");
  assert.equal(parsed.modelName, "gpt-5");
});

test("credential and policy schemas reject duplicate Slack lists", () => {
  assert.throws(
    () => credentialInputSchema.parse({
      slackBotToken: "xoxb-test",
      slackAppToken: "xapp-test",
      modelApiKey: "sk-testkey",
      allowedDmUserIds: ["U1", "U1"],
    }),
    /Duplicate DM allowlist Slack identifier/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({ allowedDmUserIds: ["U1", "U1"] }),
    /Duplicate DM allowlist Slack identifier/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      channelPolicies: [{ channelId: "C1", allowedUserIds: ["U1", "U1"] }],
    }),
    /Duplicate channel allowlist Slack identifier/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      channelPolicies: [{ channelId: "C1", deniedUserIds: ["U2", "U2"] }],
    }),
    /Duplicate channel denylist Slack identifier/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      toolPolicies: [{ tool: "exec", action: "*", effect: "allow", slackUserIds: ["U1", "U1"] }],
    }),
    /Duplicate tool policy user Slack identifier/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      toolPolicies: [{ tool: "exec", action: "*", effect: "allow", roleNames: ["admin", "admin"] }],
    }),
    /Duplicate tool policy role/,
  );
});

test("policy update schema constrains action and resource identifiers", () => {
  assert.throws(
    () => policyUpdateSchema.parse({ toolPolicies: [{ tool: "exec", action: "shell with spaces", effect: "allow" }] }),
    /Use only letters/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      approvalPolicies: [{ name: "bad", actionPattern: "x".repeat(161), approverSlackUserIds: ["UADMIN"] }],
    }),
    /Too big/,
  );
});

test("policy update schema rejects impossible enabled approval policies", () => {
  assert.throws(
    () => policyUpdateSchema.parse({
      approvalPolicies: [{ name: "risky", actionPattern: "exec:*", approverSlackUserIds: [] }],
    }),
    /at least one approver/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      approvalPolicies: [{
        name: "two-person",
        actionPattern: "exec:*",
        approverSlackUserIds: ["UADMIN", "UOWNER"],
        minApprovals: 3,
      }],
    }),
    /unique approvers/,
  );
  const disabled = policyUpdateSchema.parse({
    approvalPolicies: [{
      name: "draft",
      actionPattern: "exec:*",
      approverSlackUserIds: [],
      minApprovals: 3,
      enabled: false,
    }],
  });
  assert.equal(disabled.approvalPolicies[0].enabled, false);
});

test("integration credential schema constrains SecretRef path parts", () => {
  const parsed = integrationCredentialInputSchema.parse({
    kind: "github",
    key: "api-token",
    secretValue: "ghp_test",
  });
  assert.equal(parsed.label, undefined);
  assert.equal(parsed.slackUserId, undefined);
  assert.throws(
    () => integrationCredentialInputSchema.parse({ kind: "github", key: "../token", secretValue: "secret" }),
    /letters, numbers/,
  );
});

test("integration credential schema accepts a Slack user id and rejects malformed ones", () => {
  const parsed = integrationCredentialInputSchema.parse({
    kind: "gmail",
    key: "api-token",
    secretValue: "secret",
    slackUserId: "U12345",
  });
  assert.equal(parsed.slackUserId, "U12345");
  assert.throws(
    () => integrationCredentialInputSchema.parse({
      kind: "gmail",
      key: "api-token",
      secretValue: "secret",
      slackUserId: "../escape",
    }),
    /Slack identifier/,
  );
});

test("credential schemas bound secret value sizes", () => {
  assert.throws(
    () => credentialInputSchema.parse({
      slackBotToken: "xoxb-test",
      slackAppToken: "xapp-test",
      modelApiKey: "s".repeat(8193),
    }),
    /Too big/,
  );
  assert.throws(
    () => integrationCredentialInputSchema.parse({ kind: "github", key: "api-token", secretValue: "s".repeat(8193) }),
    /Too big/,
  );
});

test("credential and policy display text is trimmed and nonblank", () => {
  const credentials = credentialInputSchema.parse({
    companyName: "  Operant Smoke Co  ",
    workspaceName: "  Smoke Workspace  ",
    slackBotToken: "xoxb-test",
    slackAppToken: "xapp-test",
    modelApiKey: "sk-testkey",
  });
  assert.equal(credentials.companyName, "Operant Smoke Co");
  assert.equal(credentials.workspaceName, "Smoke Workspace");

  const integrationCredential = integrationCredentialInputSchema.parse({
    kind: "github",
    key: "api-token",
    label: "  GitHub API token  ",
    secretValue: "secret",
  });
  assert.equal(integrationCredential.label, "GitHub API token");

  assert.throws(
    () => credentialInputSchema.parse({
      workspaceName: "   ",
      slackBotToken: "xoxb-test",
      slackAppToken: "xapp-test",
      modelApiKey: "sk-testkey",
    }),
    /Too small/,
  );
  assert.throws(
    () => policyUpdateSchema.parse({
      approvalPolicies: [{ name: "   ", actionPattern: "exec:*", approverSlackUserIds: ["UADMIN"] }],
    }),
    /Too small/,
  );
});

test("metadata records bound keys before persistence", () => {
  assert.throws(
    () => metadataRecordSchema.parse(Object.fromEntries(Array.from({ length: 101 }, (_, index) => [`key${index}`, index]))),
    /at most 100 keys/,
  );
  assert.throws(
    () => metadataRecordSchema.parse({ ["k".repeat(121)]: "value" }),
    /Too big/,
  );
});

test("usage numeric values fit persisted column ranges", () => {
  assert.equal(usageTokenCountSchema.parse(2_147_483_647), 2_147_483_647);
  assert.throws(() => usageTokenCountSchema.parse(2_147_483_648), /Too big/);
  assert.throws(() => usageTokenCountSchema.parse(1.5), /Invalid input/);
  assert.equal(usageCostUsdSchema.parse(999_999.999999), 999_999.999999);
  assert.throws(() => usageCostUsdSchema.parse(1_000_000), /Too big/);
});

test("credential and settings schemas constrain model SecretRef parts", () => {
  assert.equal(credentialInputSchema.parse({
    slackBotToken: "xoxb-test",
    slackAppToken: "xapp-test",
    modelApiKey: "sk-testkey",
  }).modelProvider, "openai");
  assert.throws(
    () => credentialInputSchema.parse({
      slackBotToken: "xoxb-test",
      slackAppToken: "xapp-test",
      modelProvider: "../openai",
      modelApiKey: "sk-testkey",
    }),
    /letters, numbers/,
  );
  assert.throws(
    () => workspaceSettingsUpdateSchema.parse({ modelName: "gpt 5" }),
    /Use only letters/,
  );
});

test("workspace settings schema validates retention bounds", () => {
  const parsed = workspaceSettingsUpdateSchema.parse({ retentionDays: 30, modelProvider: "openai" });
  assert.equal(parsed.retentionDays, 30);
  assert.throws(() => workspaceSettingsUpdateSchema.parse({ retentionDays: 0 }), /Too small/);
});

test("workspace settings schema constrains OpenClaw gateway URLs", () => {
  assert.equal(workspaceSettingsUpdateSchema.parse({ openclawGatewayUrl: "https://gateway.example.com" }).openclawGatewayUrl, "https://gateway.example.com");
  assert.throws(() => workspaceSettingsUpdateSchema.parse({ openclawGatewayUrl: "ftp://gateway.example.com" }), /http or https/);
});
