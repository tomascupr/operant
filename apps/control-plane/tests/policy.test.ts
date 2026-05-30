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

test("evaluateToolOnly: a user-scoped deny only blocks the targeted Slack user, not everyone", () => {
  const blocked = evaluateToolOnly(
    { tool: "pipedream:github", action: "list", platform: "slack", slackUserId: "U_BLOCKED" },
    { toolPolicies: [{ tool: "pipedream:github", action: "*", effect: "deny", slackUserIds: ["U_BLOCKED"] }] },
  );
  assert.equal(blocked.effect, "deny");
  const other = evaluateToolOnly(
    { tool: "pipedream:github", action: "list", platform: "slack", slackUserId: "U_OTHER" },
    { toolPolicies: [{ tool: "pipedream:github", action: "*", effect: "deny", slackUserIds: ["U_BLOCKED"] }] },
  );
  assert.equal(other.effect, "allow");
});

test("evaluateToolOnly: a role-scoped allow grants the role and denies users without it", () => {
  const member = evaluateToolOnly(
    { tool: "pipedream:github", action: "list", platform: "slack", slackUserId: "U1", userRoleNames: ["ops"] },
    { toolPolicies: [{ tool: "pipedream:github", action: "*", effect: "allow", roleNames: ["ops"] }] },
  );
  assert.equal(member.effect, "allow");
  const outsider = evaluateToolOnly(
    { tool: "pipedream:github", action: "list", platform: "slack", slackUserId: "U2", userRoleNames: ["member"] },
    { toolPolicies: [{ tool: "pipedream:github", action: "*", effect: "allow", roleNames: ["ops"] }] },
  );
  assert.equal(outsider.effect, "deny");
});

test("evaluateToolOnly: a Teams-scoped policy matches the active Teams AAD principal only", () => {
  const aad = "44444444-4444-4444-8444-444444444444";
  const teamsUser = evaluateToolOnly(
    { tool: "pipedream:github", action: "list", platform: "msteams", teamsAadUserId: aad },
    { toolPolicies: [{ tool: "pipedream:github", action: "*", effect: "approval_required", teamsAadUserIds: [aad] }] },
  );
  assert.equal(teamsUser.effect, "approval_required");
  const otherTeamsUser = evaluateToolOnly(
    { tool: "pipedream:github", action: "list", platform: "msteams", teamsAadUserId: "55555555-5555-4555-8555-555555555555" },
    { toolPolicies: [{ tool: "pipedream:github", action: "*", effect: "approval_required", teamsAadUserIds: [aad] }] },
  );
  assert.equal(otherTeamsUser.effect, "deny");
});

test("approval requirements summarize matching approval policies", () => {
  assert.equal(wildcardMatches("exec:*", "exec:shell"), true);
  assert.equal(wildcardMatches("exec:*", "slack:pins"), false);
  const requirement = summarizeApprovalRequirement({ action: "exec:shell", resource: "cloud-computer" }, policies);
  assert.deepEqual(requirement, {
    matchedPolicyCount: 1,
    policyNames: ["exec approvals"],
    approverSlackUserIds: ["UADMIN"],
    approverTeamsUserIds: [],
    minApprovals: 1,
  });
});

const AAD_A = "11111111-1111-4111-8111-111111111111";
const AAD_B = "22222222-2222-4222-8222-222222222222";

const teamsPolicies = {
  allowedDmUserIds: ["U1"],
  allowedTeamsDmUserIds: [AAD_A],
  channelPolicies: [
    { channelType: "msteams" as const, teamId: "teamA", channelId: "chan1", enabled: true, requireMention: true, allowedUserIds: [AAD_A], deniedUserIds: [] },
  ],
  toolPolicies: [
    { tool: "github", action: "*", effect: "allow" as const, teamsAadUserIds: [AAD_A] },
  ],
};

test("Teams DM uses the Teams allowlist, not the Slack one", () => {
  const allowed = evaluatePolicy({ channelType: "msteams", teamsAadUserId: AAD_A, chatType: "direct", action: "message", resource: "msteams" }, teamsPolicies);
  assert.equal(allowed.effect, "allow");
  const denied = evaluatePolicy({ channelType: "msteams", teamsAadUserId: AAD_B, chatType: "direct", action: "message", resource: "msteams" }, teamsPolicies);
  assert.equal(denied.effect, "deny");
});

test("Teams channel policy isolates by team: same channelId in another team does not match", () => {
  const sameTeam = evaluatePolicy({ channelType: "msteams", teamsAadUserId: AAD_A, teamsChannelId: "chan1", teamId: "teamA", chatType: "channel", action: "message", resource: "msteams" }, teamsPolicies);
  assert.equal(sameTeam.effect, "allow");
  const otherTeam = evaluatePolicy({ channelType: "msteams", teamsAadUserId: AAD_A, teamsChannelId: "chan1", teamId: "teamB", chatType: "channel", action: "message", resource: "msteams" }, teamsPolicies);
  assert.equal(otherTeam.effect, "deny");
});

test("a Slack channel policy never matches a Teams evaluation with the same channel id", () => {
  const decision = evaluatePolicy({ channelType: "msteams", teamsAadUserId: AAD_A, teamsChannelId: "C1", teamId: "teamA", chatType: "channel", action: "message", resource: "msteams" }, policies);
  assert.equal(decision.effect, "deny");
});

test("Teams tool scoping grants the entitled AAD user and denies others", () => {
  // Both users clear the DM gate so only the tool entitlement differentiates them.
  const scoped = { ...teamsPolicies, allowedTeamsDmUserIds: [AAD_A, AAD_B] };
  const entitled = evaluatePolicy({ channelType: "msteams", teamsAadUserId: AAD_A, chatType: "direct", tool: "github", action: "list", resource: "msteams" }, scoped);
  assert.equal(entitled.effect, "allow");
  const other = evaluatePolicy({ channelType: "msteams", teamsAadUserId: AAD_B, chatType: "direct", tool: "github", action: "list", resource: "msteams" }, scoped);
  assert.equal(other.effect, "deny");
});
