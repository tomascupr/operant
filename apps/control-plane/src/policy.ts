import type {
  ApprovalPolicyRecord,
  ChannelPolicyRecord,
  PolicyDecision,
  PolicyEvaluationInput,
  ToolPolicyRecord,
} from "./schema.js";

export function evaluateToolOnly(input: { tool: string; action: string }, policies: {
  toolPolicies: ToolPolicyRecord[];
}): PolicyDecision {
  const matching = policies.toolPolicies.filter((policy) => {
    return policy.tool === input.tool && (policy.action === input.action || policy.action === "*");
  });
  const denied = matching.find((policy) => policy.effect === "deny");
  if (denied) return { effect: "deny", reasons: [`Tool policy denies ${input.tool}:${input.action}.`] };
  if (matching.some((policy) => policy.effect === "approval_required")) {
    return { effect: "approval_required", reasons: [`Tool policy requires approval for ${input.tool}:${input.action}.`] };
  }
  const allowed = matching.some((policy) => policy.effect === "allow");
  return { effect: "allow", reasons: allowed ? [`Tool policy allows ${input.tool}:${input.action}.`] : [] };
}

export function evaluatePolicy(input: PolicyEvaluationInput, policies: {
  allowedDmUserIds: string[];
  channelPolicies: ChannelPolicyRecord[];
  toolPolicies: ToolPolicyRecord[];
}): PolicyDecision {
  const reasons: string[] = [];

  if (input.chatType === "direct") {
    if (!policies.allowedDmUserIds.includes(input.slackUserId)) {
      return {
        effect: "deny",
        reasons: [`Slack user ${input.slackUserId} is not in the DM allowlist.`],
      };
    }
    reasons.push("Slack user is DM-allowlisted.");
  }

  if (input.chatType !== "direct") {
    const channel = policies.channelPolicies.find((candidate) => candidate.channelId === input.slackChannelId);
    if (!channel) {
      return {
        effect: "deny",
        reasons: [`Slack channel ${input.slackChannelId ?? "<missing>"} is not allowlisted.`],
      };
    }
    if (!channel.enabled) {
      return {
        effect: "deny",
        reasons: [`Slack channel ${channel.channelId} is disabled.`],
      };
    }
    if (channel.deniedUserIds.includes(input.slackUserId)) {
      return {
        effect: "deny",
        reasons: [`Slack user ${input.slackUserId} is denied in channel ${channel.channelId}.`],
      };
    }
    if (channel.allowedUserIds.length > 0 && !channel.allowedUserIds.includes(input.slackUserId)) {
      return {
        effect: "deny",
        reasons: [`Slack user ${input.slackUserId} is not allowlisted in channel ${channel.channelId}.`],
      };
    }
    reasons.push(`Slack channel ${channel.channelId} is allowlisted.`);
  }

  if (input.tool) {
    const matchingToolPolicies = policies.toolPolicies.filter((policy) => {
      return policy.tool === input.tool && (policy.action === input.action || policy.action === "*");
    });
    const applicableToolPolicies = matchingToolPolicies.filter((policy) => toolPolicyAppliesToUser(policy, input));
    const denied = applicableToolPolicies.find((policy) => policy.effect === "deny");
    if (denied) {
      return {
        effect: "deny",
        reasons: [`Tool policy denies ${input.tool}:${input.action} for this Slack user or role.`],
      };
    }
    if (applicableToolPolicies.some((policy) => policy.effect === "approval_required")) {
      return {
        effect: "approval_required",
        reasons: [...reasons, `Tool policy requires approval for ${input.tool}:${input.action} for this Slack user or role.`],
      };
    }
    if (applicableToolPolicies.some((policy) => policy.effect === "allow")) reasons.push(`Tool policy allows ${input.tool}:${input.action} for this Slack user or role.`);
    if (applicableToolPolicies.length === 0 && matchingToolPolicies.some(isScopedGrantPolicy)) {
      return {
        effect: "deny",
        reasons: [`Slack user ${input.slackUserId} has no role or user entitlement for ${input.tool}:${input.action}.`],
      };
    }
  }

  return { effect: "allow", reasons };
}

function isScopedToolPolicy(policy: ToolPolicyRecord): boolean {
  return (policy.slackUserIds ?? []).length > 0 || (policy.roleNames ?? []).length > 0;
}

function isScopedGrantPolicy(policy: ToolPolicyRecord): boolean {
  return isScopedToolPolicy(policy) && policy.effect !== "deny";
}

function toolPolicyAppliesToUser(policy: ToolPolicyRecord, input: PolicyEvaluationInput): boolean {
  if (!isScopedToolPolicy(policy)) return true;
  if ((policy.slackUserIds ?? []).includes(input.slackUserId)) return true;
  const userRoles = new Set(input.userRoleNames ?? []);
  return (policy.roleNames ?? []).some((roleName) => userRoles.has(roleName));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function wildcardMatches(pattern: string, value: string): boolean {
  if (pattern === "*") return true;
  const expression = `^${pattern.split("*").map(escapeRegExp).join(".*")}$`;
  return new RegExp(expression).test(value);
}

export function matchingApprovalPolicies(input: { action: string; resource: string }, policies: {
  approvalPolicies: ApprovalPolicyRecord[];
}): ApprovalPolicyRecord[] {
  return policies.approvalPolicies.filter((policy) => {
    return policy.enabled
      && wildcardMatches(policy.actionPattern, input.action)
      && wildcardMatches(policy.resourcePattern, input.resource);
  });
}

export function summarizeApprovalRequirement(input: { action: string; resource: string }, policies: {
  approvalPolicies: ApprovalPolicyRecord[];
}) {
  const matchingPolicies = matchingApprovalPolicies(input, policies);
  const approverSlackUserIds = Array.from(new Set(matchingPolicies.flatMap((policy) => policy.approverSlackUserIds)));
  return {
    matchedPolicyCount: matchingPolicies.length,
    policyNames: matchingPolicies.map((policy) => policy.name),
    approverSlackUserIds,
    minApprovals: matchingPolicies.length > 0 ? Math.max(...matchingPolicies.map((policy) => policy.minApprovals)) : 1,
  };
}
