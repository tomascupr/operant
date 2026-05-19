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

function compileSlackActions(toolPolicies: OpenClawConfigInput["toolPolicies"]) {
  const actionGroups = ["messages", "reactions", "pins", "memberInfo", "emojiList"] as const;
  const actions: Record<string, boolean> = {};
  for (const group of actionGroups) actions[group] = true;
  for (const policy of toolPolicies) {
    if (isScopedToolPolicy(policy)) continue;
    if (policy.tool !== "slack") continue;
    if (policy.action === "*" && policy.effect !== "allow") {
      for (const group of actionGroups) actions[group] = false;
    }
    if (policy.action in actions) actions[policy.action] = policy.effect === "allow";
  }
  return actions;
}

function compileSlackChannels(channelPolicies: OpenClawConfigInput["channelPolicies"]) {
  return Object.fromEntries(
    channelPolicies.map((policy) => {
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

function toolPolicyName(policy: OpenClawConfigInput["toolPolicies"][number]): string {
  return policy.action === "*" ? policy.tool : `${policy.tool}:${policy.action}`;
}

function isScopedToolPolicy(policy: OpenClawConfigInput["toolPolicies"][number]): boolean {
  return (policy.slackUserIds ?? []).length > 0 || (policy.roleNames ?? []).length > 0;
}

const OPERANT_PLUGIN_TOOLS = ["operant_ping", "pipedream_list_actions", "pipedream_run_action"] as const;

function compileToolExposure(toolPolicies: OpenClawConfigInput["toolPolicies"]) {
  const alsoAllow = new Set<string>(OPERANT_PLUGIN_TOOLS);
  const deny = new Set<string>();
  for (const policy of toolPolicies) {
    if (isScopedToolPolicy(policy)) continue;
    if (policy.tool === "slack") continue;
    const name = toolPolicyName(policy);
    if (policy.effect === "allow") alsoAllow.add(name);
    if (policy.effect === "deny") deny.add(name);
  }
  return {
    alsoAllow: Array.from(alsoAllow).sort(),
    deny: Array.from(deny).sort(),
  };
}

function compilePlugins() {
  return {
    allow: ["slack", "operant"],
    bundledDiscovery: "compat",
    entries: {
      slack: {
        enabled: true,
      },
      operant: {
        enabled: true,
      },
    },
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
  const approvers = input.approvalPolicies
    .filter((policy) => policy.enabled)
    .flatMap((policy) => policy.approverSlackUserIds);
  const uniqueApprovers = Array.from(new Set(approvers));
  const channels = compileSlackChannels(input.channelPolicies);
  const toolExposure = compileToolExposure(input.toolPolicies);
  const plugins = compilePlugins();

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
      ownerAllowFrom: uniqueApprovers.map((id) => `slack:${id}`),
    },
    plugins: {
      allow: plugins.allow,
      bundledDiscovery: plugins.bundledDiscovery,
      entries: plugins.entries,
    },
    channels: {
      slack: {
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
          enabled: uniqueApprovers.length > 0,
          approvers: uniqueApprovers,
          target: "both",
        },
        capabilities: {
          interactiveReplies: true,
        },
      },
    },
    logging: {
      redactSensitive: "tools",
    },
  };
}

export function checksumConfig(config: unknown): string {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex");
}
