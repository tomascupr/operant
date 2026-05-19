import assert from "node:assert/strict";
import test from "node:test";
import { evaluatePolicy, evaluateToolOnly, summarizeApprovalRequirement, wildcardMatches } from "../src/policy.js";

const policies = {
  allowedDmUserIds: ["U1"],
  channelPolicies: [
    {
      channelId: "C1",
      enabled: true,
      requireMention: true,
      allowedUserIds: ["U1", "U2"],
      deniedUserIds: ["U3"],
    },
  ],
  toolPolicies: [
    { tool: "exec", action: "*", effect: "approval_required" as const },
    { tool: "slack", action: "pins", effect: "deny" as const },
  ],
  approvalPolicies: [
    {
      name: "exec approvals",
      actionPattern: "exec:*",
      resourcePattern: "*",
      approverSlackUserIds: ["UADMIN"],
      minApprovals: 1,
      enabled: true,
    },
  ],
};

test("denies unallowlisted DM users", () => {
  const decision = evaluatePolicy({ slackUserId: "U9", chatType: "direct", action: "message", resource: "slack" }, policies);
  assert.equal(decision.effect, "deny");
});

test("allows channel users when channel and user are allowlisted", () => {
  const decision = evaluatePolicy({ slackUserId: "U2", slackChannelId: "C1", chatType: "channel", action: "message", resource: "slack" }, policies);
  assert.equal(decision.effect, "allow");
});

test("applies channel allowlists to group and thread policy previews", () => {
  const groupDecision = evaluatePolicy({ slackUserId: "U2", slackChannelId: "C1", chatType: "group", action: "message", resource: "slack" }, policies);
  assert.equal(groupDecision.effect, "allow");

  const threadDecision = evaluatePolicy({ slackUserId: "U2", slackChannelId: "C1", chatType: "thread", action: "message", resource: "slack" }, policies);
  assert.equal(threadDecision.effect, "allow");
});

test("denies group and thread policy previews without an allowlisted channel", () => {
  const groupDecision = evaluatePolicy({ slackUserId: "U2", slackChannelId: "C9", chatType: "group", action: "message", resource: "slack" }, policies);
  assert.equal(groupDecision.effect, "deny");

  const threadDecision = evaluatePolicy({ slackUserId: "U2", chatType: "thread", action: "message", resource: "slack" }, policies);
  assert.equal(threadDecision.effect, "deny");
});

test("denies disabled channels before tool policy evaluation", () => {
  const decision = evaluatePolicy({
    slackUserId: "U1",
    slackChannelId: "C2",
    chatType: "channel",
    tool: "slack",
    action: "messages",
    resource: "slack",
  }, {
    ...policies,
    channelPolicies: [
      ...policies.channelPolicies,
      {
        channelId: "C2",
        enabled: false,
        requireMention: true,
        allowedUserIds: ["U1"],
        deniedUserIds: [],
      },
    ],
    toolPolicies: [{ tool: "slack", action: "messages", effect: "allow" }],
  });

  assert.equal(decision.effect, "deny");
});

test("requires approval for risky tools", () => {
  const decision = evaluatePolicy({ slackUserId: "U1", chatType: "direct", tool: "exec", action: "run", resource: "tool" }, policies);
  assert.equal(decision.effect, "approval_required");
});

test("tool deny beats a channel allow", () => {
  const decision = evaluatePolicy({ slackUserId: "U1", slackChannelId: "C1", chatType: "channel", tool: "slack", action: "pins", resource: "tool" }, policies);
  assert.equal(decision.effect, "deny");
});

test("tool deny beats wildcard approval regardless of rule order", () => {
  const decision = evaluatePolicy({
    slackUserId: "U1",
    chatType: "direct",
    tool: "exec",
    action: "shell",
    resource: "tool",
  }, {
    ...policies,
    toolPolicies: [
      { tool: "exec", action: "*", effect: "approval_required" },
      { tool: "exec", action: "shell", effect: "deny" },
    ],
  });

  assert.equal(decision.effect, "deny");
});

test("scopes tool entitlements to Slack users and Operant roles", () => {
  const scopedPolicies = {
    ...policies,
    toolPolicies: [
      { tool: "browser", action: "*", effect: "allow" as const, roleNames: ["admin"] },
      { tool: "exec", action: "*", effect: "approval_required" as const, slackUserIds: ["U1"] },
      { tool: "exec", action: "shell", effect: "deny" as const, roleNames: ["viewer"] },
    ],
  };

  const adminBrowserDecision = evaluatePolicy({
    slackUserId: "U2",
    slackChannelId: "C1",
    chatType: "channel",
    tool: "browser",
    action: "navigate",
    resource: "tool",
    userRoleNames: ["admin"],
  }, scopedPolicies);
  assert.equal(adminBrowserDecision.effect, "allow");

  const memberBrowserDecision = evaluatePolicy({
    slackUserId: "U2",
    slackChannelId: "C1",
    chatType: "channel",
    tool: "browser",
    action: "navigate",
    resource: "tool",
    userRoleNames: ["member"],
  }, scopedPolicies);
  assert.equal(memberBrowserDecision.effect, "deny");

  const allowedExecDecision = evaluatePolicy({
    slackUserId: "U1",
    chatType: "direct",
    tool: "exec",
    action: "shell",
    resource: "tool",
    userRoleNames: ["member"],
  }, scopedPolicies);
  assert.equal(allowedExecDecision.effect, "approval_required");

  const viewerExecDecision = evaluatePolicy({
    slackUserId: "U1",
    chatType: "direct",
    tool: "exec",
    action: "shell",
    resource: "tool",
    userRoleNames: ["viewer"],
  }, scopedPolicies);
  assert.equal(viewerExecDecision.effect, "deny");
});

test("evaluateToolOnly returns allow when no policy matches", () => {
  const decision = evaluateToolOnly(
    { tool: "gmail", action: "send" },
    { toolPolicies: [] },
  );
  assert.equal(decision.effect, "allow");
});

test("evaluateToolOnly returns deny when a deny policy matches the action", () => {
  const decision = evaluateToolOnly(
    { tool: "exec", action: "shell" },
    { toolPolicies: [{ tool: "exec", action: "shell", effect: "deny" }] },
  );
  assert.equal(decision.effect, "deny");
});

test("evaluateToolOnly returns approval_required when a wildcard approval policy matches", () => {
  const decision = evaluateToolOnly(
    { tool: "exec", action: "shell" },
    { toolPolicies: [{ tool: "exec", action: "*", effect: "approval_required" }] },
  );
  assert.equal(decision.effect, "approval_required");
});

test("evaluateToolOnly prefers deny over approval_required when both match", () => {
  const decision = evaluateToolOnly(
    { tool: "exec", action: "shell" },
    {
      toolPolicies: [
        { tool: "exec", action: "*", effect: "approval_required" },
        { tool: "exec", action: "shell", effect: "deny" },
      ],
    },
  );
  assert.equal(decision.effect, "deny");
});

test("approval requirements summarize matching approval policies", () => {
  assert.equal(wildcardMatches("exec:*", "exec:shell"), true);
  assert.equal(wildcardMatches("exec:*", "slack:pins"), false);
  const requirement = summarizeApprovalRequirement({ action: "exec:shell", resource: "cloud-computer" }, policies);
  assert.deepEqual(requirement, {
    matchedPolicyCount: 1,
    policyNames: ["exec approvals"],
    approverSlackUserIds: ["UADMIN"],
    minApprovals: 1,
  });
});
