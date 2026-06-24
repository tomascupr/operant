import { createHash } from "node:crypto";
import type { OpenClawConfigInput } from "./schema.js";

export type SecretRef = {
  source: "exec";
  provider: "operant";
  id: string;
};

function secretRef(id: string): SecretRef {
  return { source: "exec", provider: "operant", id };
}

export function gatewayWebSocketUrl(gatewayUrl: string): string {
  try {
    const parsed = new URL(gatewayUrl);
    if (parsed.protocol === "http:") parsed.protocol = "ws:";
    if (parsed.protocol === "https:") parsed.protocol = "wss:";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return gatewayUrl;
  }
}

export function buildSecretRefId(workspaceId: string, path: string, options: { slackUserId?: string | null } = {}): string {
  const prefix = options.slackUserId ? `workspaces/${workspaceId}/users/${options.slackUserId}` : `workspaces/${workspaceId}`;
  return `${prefix}/${path}`;
}

export function parseSecretRefId(id: string): { workspaceId: string; slackUserId: string | null } | null {
  const match = /^workspaces\/([^/]+)(?:\/users\/([^/]+))?\//.exec(id);
  if (!match) return null;
  return { workspaceId: match[1], slackUserId: match[2] ?? null };
}

const slackChannelActions = ["messages", "reactions", "pins", "memberInfo", "emojiList"] as const;
const teamsChannelActions = ["messages", "reactions", "memberInfo"] as const;

function compileSlackActions(toolPolicies: OpenClawConfigInput["toolPolicies"]) {
  const actions: Record<string, boolean> = {};
  for (const group of slackChannelActions) actions[group] = true;
  for (const policy of toolPolicies) {
    if (isScopedToolPolicy(policy)) continue;
    if (policy.tool !== "slack") continue;
    if (policy.action === "*" && policy.effect !== "allow") {
      for (const group of slackChannelActions) actions[group] = false;
    }
    if (policy.action in actions) actions[policy.action] = policy.effect === "allow";
  }
  return actions;
}

function compileTeamsActions(toolPolicies: OpenClawConfigInput["toolPolicies"]) {
  const actions: Record<string, boolean> = { memberInfo: false };
  for (const group of teamsChannelActions) {
    if (group !== "memberInfo") actions[group] = true;
  }
  for (const policy of toolPolicies) {
    if (isScopedToolPolicy(policy)) continue;
    if (policy.tool !== "msteams") continue;
    if (policy.action === "*" && policy.effect !== "allow") {
      for (const group of teamsChannelActions) actions[group] = false;
    }
    if (policy.action in actions) actions[policy.action] = policy.effect === "allow";
  }
  return actions;
}

function compileSlackChannels(channelPolicies: OpenClawConfigInput["channelPolicies"]) {
  return Object.fromEntries(
    channelPolicies.filter((policy) => (policy.channelType ?? "slack") === "slack").map((policy) => {
      const denied = new Set(policy.deniedUserIds);
      return [
        policy.channelId,
        {
          enabled: policy.enabled,
          requireMention: policy.requireMention,
          users: policy.allowedUserIds.filter((userId) => !denied.has(userId)),
        },
      ];
    }),
  );
}

function compileTeamsChannels(channelPolicies: OpenClawConfigInput["channelPolicies"]) {
  return Object.fromEntries(
    channelPolicies.filter((policy) => policy.channelType === "msteams").map((policy) => {
      const denied = new Set(policy.deniedUserIds);
      return [
        policy.channelId,
        {
          teamId: policy.teamId,
          enabled: policy.enabled,
          requireMention: policy.requireMention,
          users: policy.allowedUserIds.filter((userId) => !denied.has(userId)),
        },
      ];
    }),
  );
}

function toolPolicyName(policy: OpenClawConfigInput["toolPolicies"][number]): string {
  return policy.action === "*" ? policy.tool : `${policy.tool}:${policy.action}`;
}

function isScopedToolPolicy(policy: OpenClawConfigInput["toolPolicies"][number]): boolean {
  return (policy.slackUserIds ?? []).length > 0 || (policy.teamsAadUserIds ?? []).length > 0 || (policy.roleNames ?? []).length > 0;
}

const OPERANT_PLUGIN_TOOLS = [
  "operant_ping",
  "operant_memory_write",
  "operant_memory_search",
  "operant_skills_search",
  "pipedream_list_actions",
  "pipedream_run_action",
] as const;

function compileToolExposure(toolPolicies: OpenClawConfigInput["toolPolicies"]) {
  const alsoAllow = new Set<string>(OPERANT_PLUGIN_TOOLS);
  const deny = new Set<string>();
  const slackActions = new Set<string>(slackChannelActions);
  const teamsActions = new Set<string>(teamsChannelActions);
  for (const policy of toolPolicies) {
    if (isScopedToolPolicy(policy)) continue;
    // Channel-action policies are compiled into the per-channel actions blocks
    // (compileSlackActions / compileTeamsActions). Skip only those here.
    if (policy.tool === "slack" && (policy.action === "*" || slackActions.has(policy.action))) continue;
    if (policy.tool === "msteams" && (policy.action === "*" || teamsActions.has(policy.action))) continue;
    const name = toolPolicyName(policy);
    if (policy.effect === "allow") alsoAllow.add(name);
    if (policy.effect === "deny") deny.add(name);
  }
  // Operant's contract is "deny beats allow"; enforce it before serializing so a
  // tool never appears in both lists and the security decision can't hinge on
  // OpenClaw's (to Operant, undocumented) merge order.
  for (const name of deny) alsoAllow.delete(name);
  return {
    alsoAllow: Array.from(alsoAllow).sort(),
    deny: Array.from(deny).sort(),
  };
}

function slackConfigured(input: OpenClawConfigInput): boolean {
  return Boolean(input.slackBotTokenConfigured && input.slackAppTokenConfigured);
}

function teamsConfigured(input: OpenClawConfigInput): boolean {
  return Boolean(input.teamsAppId && input.teamsTenantId && input.teamsAppPasswordConfigured);
}

function compilePlugins(input: OpenClawConfigInput) {
  const allow: string[] = [];
  const entries: Record<string, { enabled: boolean }> = {};
  if (slackConfigured(input)) {
    allow.push("slack");
    entries.slack = { enabled: true };
  }
  if (teamsConfigured(input)) {
    allow.push("msteams");
    entries.msteams = { enabled: true };
  }
  allow.push("operant");
  entries.operant = { enabled: true };
  return {
    allow,
    bundledDiscovery: "compat",
    entries,
  };
}

const providerBaseUrls: Record<string, string> = {
  openai: "https://api.openai.com/v1",
  anthropic: "https://api.anthropic.com/v1",
};

function compileModelProvider(input: OpenClawConfigInput) {
  return {
    baseUrl: providerBaseUrls[input.modelProvider] ?? `https://api.${input.modelProvider}.com/v1`,
    models: [{ id: input.modelName, name: input.modelName }],
    // Direct OpenAI API keys should use OpenClaw's PI runtime; Codex is a
    // separate child-process harness with a different trust boundary.
    ...(input.modelProvider === "openai" ? { agentRuntime: { id: "pi" } } : {}),
    apiKey: secretRef(buildSecretRefId(input.workspaceId, `models/${input.modelProvider}/apiKey`)),
  };
}

function compileSandbox(input: OpenClawConfigInput) {
  if (input.sandboxMode !== "docker") {
    return { mode: "off" };
  }
  return {
    mode: "all",
    backend: "docker",
    scope: "agent",
    workspaceAccess: "none",
    docker: {
      binds: [],
    },
  };
}

export function generateOpenClawConfig(input: OpenClawConfigInput): Record<string, unknown> {
  const enabledApprovalPolicies = input.approvalPolicies.filter((policy) => policy.enabled);
  const uniqueSlackApprovers = Array.from(new Set(enabledApprovalPolicies.flatMap((policy) => policy.approverSlackUserIds)));
  const uniqueTeamsApprovers = Array.from(new Set(enabledApprovalPolicies.flatMap((policy) => policy.approverTeamsUserIds ?? [])));
  const channels = compileSlackChannels(input.channelPolicies);
  const teamsChannels = compileTeamsChannels(input.channelPolicies);
  const teamsDmAllowFrom = input.teamsDmAllowFrom ?? [];
  const toolExposure = compileToolExposure(input.toolPolicies);
  const plugins = compilePlugins(input);
  const generatedChannels: Record<string, unknown> = {};

  if (slackConfigured(input)) {
    generatedChannels.slack = {
      enabled: true,
      mode: "socket",
      botToken: secretRef(buildSecretRefId(input.workspaceId, "slack/botToken")),
      appToken: secretRef(buildSecretRefId(input.workspaceId, "slack/appToken")),
      dm: {
        enabled: true,
        groupEnabled: false,
      },
      dmPolicy: input.dmAllowFrom.length > 0 ? "allowlist" : "disabled",
      allowFrom: input.dmAllowFrom,
      groupPolicy: Object.keys(channels).length > 0 ? "allowlist" : "disabled",
      channels,
      requireMention: true,
      replyToMode: "all",
      ackReaction: "eyes",
      typingReaction: "pencil2",
      mediaMaxMb: 25,
      thread: {
        historyScope: "thread",
        inheritParent: false,
        initialHistoryLimit: 20,
        requireExplicitMention: false,
      },
      streaming: {
        mode: "progress",
        progress: {
          label: "thinking",
          toolProgress: true,
          commandText: "status",
        },
      },
      actions: compileSlackActions(input.toolPolicies),
      execApprovals: {
        enabled: uniqueSlackApprovers.length > 0,
        approvers: uniqueSlackApprovers,
        target: "both",
      },
      capabilities: {
        interactiveReplies: true,
      },
    };
  }

  if (teamsConfigured(input)) {
    generatedChannels.msteams = {
      enabled: true,
      appId: input.teamsAppId,
      appPassword: secretRef(buildSecretRefId(input.workspaceId, "msteams/appPassword")),
      tenantId: input.teamsTenantId,
      webhook: {
        port: input.msteamsWebhookPort ?? 3978,
        path: input.msteamsWebhookPath ?? "/api/messages",
      },
      dm: {
        enabled: true,
        groupEnabled: true,
      },
      dmPolicy: teamsDmAllowFrom.length > 0 ? "allowlist" : "disabled",
      allowFrom: teamsDmAllowFrom,
      groupPolicy: Object.keys(teamsChannels).length > 0 ? "allowlist" : "disabled",
      channels: teamsChannels,
      requireMention: true,
      historyLimit: 0,
      actions: compileTeamsActions(input.toolPolicies),
      execApprovals: {
        enabled: uniqueTeamsApprovers.length > 0,
        approvers: uniqueTeamsApprovers,
        target: "both",
      },
      capabilities: {
        interactiveReplies: false,
        files: false,
      },
    };
  }

  return {
    gateway: {
      mode: "local",
      bind: "lan",
      reload: {
        mode: "hybrid",
      },
      auth: {
        mode: "token",
        token: "${OPENCLAW_GATEWAY_TOKEN}",
        rateLimit: {
          maxAttempts: 10,
          windowMs: 60000,
          lockoutMs: 300000,
        },
      },
      controlUi: {
        allowedOrigins: ["http://localhost:18789", "http://127.0.0.1:18789"],
      },
      remote: {
        url: gatewayWebSocketUrl(input.gatewayUrl),
        transport: "direct",
        token: "${OPENCLAW_GATEWAY_TOKEN}",
      },
    },
    secrets: {
      providers: {
        operant: {
          source: "exec",
          command: input.secretResolverCommand,
          args: [input.secretResolverScript],
          passEnv: ["OPERANT_CONTROL_PLANE_URL", "OPERANT_INTERNAL_TOKEN"],
          jsonOnly: true,
          allowSymlinkCommand: false,
          trustedDirs: ["/operant/openclaw"],
        },
      },
      defaults: {
        exec: "operant",
      },
    },
    models: {
      providers: {
        [input.modelProvider]: compileModelProvider(input),
      },
    },
    agents: {
      defaults: {
        model: {
          primary: `${input.modelProvider}/${input.modelName}`,
        },
        sandbox: compileSandbox(input),
      },
    },
    tools: {
      alsoAllow: toolExposure.alsoAllow,
      deny: toolExposure.deny,
      elevated: {
        enabled: false,
        allowFrom: {
          slack: [],
        },
      },
    },
    commands: {
      ownerAllowFrom: [
        ...uniqueSlackApprovers.map((id) => `slack:${id}`),
        ...uniqueTeamsApprovers.map((id) => `msteams:${id}`),
      ],
    },
    plugins: {
      allow: plugins.allow,
      bundledDiscovery: plugins.bundledDiscovery,
      entries: plugins.entries,
    },
    channels: generatedChannels,
    logging: {
      redactSensitive: "tools",
    },
  };
}

export function checksumConfig(config: unknown): string {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex");
}
