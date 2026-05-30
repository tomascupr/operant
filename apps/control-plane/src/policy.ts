import type {
  ApprovalPolicyRecord,
  ChatPlatform,
  ChannelPolicyRecord,
  PolicyDecision,
  PolicyEvaluationInput,
  ToolPolicyRecord,
} from "./schema.js";

export interface ToolPolicyPrincipal {
  platform?: ChatPlatform;
  slackUserId?: string | null;
  teamsAadUserId?: string | null;
  userRoleNames?: string[];
}

// Tool-policy gate shared by the dashboard (evaluatePolicy) and the plugin/internal
// surfaces (evaluateToolOnly). Scoped policies (per Slack/Teams user or per role) only
// apply to a matching principal, and a scoped grant with no match denies rather than
// silently falling through to a global allow.
export function evaluateToolOnly(
  input: { tool: string; action: string } & ToolPolicyPrincipal,
  policies: { toolPolicies: ToolPolicyRecord[] },
): PolicyDecision {
  const platform: ChatPlatform = input.platform ?? "slack";
  const principalId = (platform === "msteams" ? input.teamsAadUserId : input.slackUserId) ?? "";
  return evaluateToolPolicies(platform, principalId, input.userRoleNames ?? [], input.tool, input.action, policies.toolPolicies);
}

function evaluateToolPolicies(
  platform: ChatPlatform,
  principalId: string,
  userRoleNames: string[],
  tool: string,
  action: string,
  toolPolicies: ToolPolicyRecord[],
): PolicyDecision {
  const matching = toolPolicies.filter((policy) => policy.tool === tool && (policy.action === action || policy.action === "*"));
  const applicable = matching.filter((policy) => toolPolicyAppliesToUser(policy, platform, principalId, userRoleNames));
  if (applicable.some((policy) => policy.effect === "deny")) {
    return { effect: "deny", reasons: [`Tool policy denies ${tool}:${action} for this chat user or role.`] };
  }
  if (applicable.some((policy) => policy.effect === "approval_required")) {
    return { effect: "approval_required", reasons: [`Tool policy requires approval for ${tool}:${action} for this chat user or role.`] };
  }
  if (applicable.some((policy) => policy.effect === "allow")) {
    return { effect: "allow", reasons: [`Tool policy allows ${tool}:${action} for this chat user or role.`] };
  }
  if (applicable.length === 0 && matching.some(isScopedGrantPolicy)) {
    const platformLabel = platform === "msteams" ? "Teams" : "Slack";
    return { effect: "deny", reasons: [`${platformLabel} user ${principalId} has no role or user entitlement for ${tool}:${action}.`] };
  }
  return { effect: "allow", reasons: [] };
}

function inputPlatform(input: PolicyEvaluationInput): ChatPlatform {
  return input.channelType ?? "slack";
}

function inputPrincipalId(input: PolicyEvaluationInput): string {
  if (inputPlatform(input) === "msteams") return input.teamsAadUserId ?? input.principalId ?? "";
  return input.slackUserId ?? input.principalId ?? "";
}

function inputChannelId(input: PolicyEvaluationInput): string | undefined {
  if (inputPlatform(input) === "msteams") return input.teamsChannelId ?? input.slackChannelId;
  return input.slackChannelId;
}

export function evaluatePolicy(input: PolicyEvaluationInput, policies: {
  allowedDmUserIds: string[];
  allowedTeamsDmUserIds?: string[];
  channelPolicies: ChannelPolicyRecord[];
  toolPolicies: ToolPolicyRecord[];
}): PolicyDecision {
  const reasons: string[] = [];
  const platform = inputPlatform(input);
  const principalId = inputPrincipalId(input);
  const platformLabel = platform === "msteams" ? "Teams" : "Slack";
  const dmAllowlist = platform === "msteams" ? policies.allowedTeamsDmUserIds ?? [] : policies.allowedDmUserIds;

  if (input.chatType === "direct") {
    if (!dmAllowlist.includes(principalId)) {
      return {
        effect: "deny",
        reasons: [`${platformLabel} user ${principalId} is not in the DM allowlist.`],
      };
    }
    reasons.push(`${platformLabel} user is DM-allowlisted.`);
  }

  if (input.chatType !== "direct") {
    const channelId = inputChannelId(input);
    const channel = policies.channelPolicies.find((candidate) => {
      const candidatePlatform = candidate.channelType ?? "slack";
      if (candidatePlatform !== platform) return false;
      if (candidate.channelId !== channelId) return false;
      if (platform === "msteams") {
        if (!candidate.teamId || !input.teamId) return false;
        return candidate.teamId === input.teamId;
      }
      return true;
    });
    if (!channel) {
      return {
        effect: "deny",
        reasons: [`${platformLabel} channel ${channelId ?? "<missing>"} is not allowlisted.`],
      };
    }
    if (!channel.enabled) {
      return {
        effect: "deny",
        reasons: [`${platformLabel} channel ${channel.channelId} is disabled.`],
      };
    }
    if (channel.deniedUserIds.includes(principalId)) {
      return {
        effect: "deny",
        reasons: [`${platformLabel} user ${principalId} is denied in channel ${channel.channelId}.`],
      };
    }
    if (channel.allowedUserIds.length > 0 && !channel.allowedUserIds.includes(principalId)) {
      return {
        effect: "deny",
        reasons: [`${platformLabel} user ${principalId} is not allowlisted in channel ${channel.channelId}.`],
      };
    }
    reasons.push(`${platformLabel} channel ${channel.channelId} is allowlisted.`);
  }

  if (input.tool) {
    const toolDecision = evaluateToolPolicies(platform, principalId, input.userRoleNames ?? [], input.tool, input.action, policies.toolPolicies);
    if (toolDecision.effect === "deny") return toolDecision;
    if (toolDecision.effect === "approval_required") {
      return { effect: "approval_required", reasons: [...reasons, ...toolDecision.reasons] };
    }
    reasons.push(...toolDecision.reasons);
  }

  return { effect: "allow", reasons };
}

function isScopedToolPolicy(policy: ToolPolicyRecord): boolean {
  return (policy.slackUserIds ?? []).length > 0 || (policy.teamsAadUserIds ?? []).length > 0 || (policy.roleNames ?? []).length > 0;
}

function isScopedGrantPolicy(policy: ToolPolicyRecord): boolean {
  return isScopedToolPolicy(policy) && policy.effect !== "deny";
}

function toolPolicyAppliesToUser(policy: ToolPolicyRecord, platform: ChatPlatform, principalId: string, userRoleNames: string[]): boolean {
  if (!isScopedToolPolicy(policy)) return true;
  if (platform === "msteams") {
    if ((policy.teamsAadUserIds ?? []).includes(principalId)) return true;
  } else if ((policy.slackUserIds ?? []).includes(principalId)) {
    return true;
  }
  const userRoles = new Set(userRoleNames);
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
  const approverTeamsUserIds = Array.from(new Set(matchingPolicies.flatMap((policy) => policy.approverTeamsUserIds ?? [])));
  return {
    matchedPolicyCount: matchingPolicies.length,
    policyNames: matchingPolicies.map((policy) => policy.name),
    approverSlackUserIds,
    approverTeamsUserIds,
    minApprovals: matchingPolicies.length > 0 ? Math.max(...matchingPolicies.map((policy) => policy.minApprovals)) : 1,
  };
}
