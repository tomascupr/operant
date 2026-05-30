import assert from "node:assert/strict";
import test from "node:test";
import { buildSecretRefId, generateOpenClawConfig } from "../src/openclaw-config.js";
import type { OpenClawConfigInput } from "../src/schema.js";

const workspaceId = "00000000-0000-4000-8000-000000000001";

function baseInput(overrides: Partial<OpenClawConfigInput> = {}): OpenClawConfigInput {
  return {
    workspaceId,
    gatewayUrl: "http://openclaw-gateway:18789",
    modelProvider: "openai",
    modelName: "gpt-5",
    dmAllowFrom: [],
    channelPolicies: [],
    toolPolicies: [],
    approvalPolicies: [],
    slackBotTokenConfigured: true,
    slackAppTokenConfigured: true,
    secretResolverCommand: "/operant/openclaw/operant-secret-resolver",
    secretResolverScript: "/operant/openclaw/operant-secret-resolver.mjs",
    ...overrides,
  };
}

test("generates Slack Socket Mode config with SecretRefs, policy, and safe gateway defaults", () => {
  const config = generateOpenClawConfig(baseInput({
    dmAllowFrom: ["U1"],
    channelPolicies: [
      {
        channelId: "C1",
        enabled: true,
        requireMention: true,
        allowedUserIds: ["U1", "U2"],
        deniedUserIds: ["U2"],
      },
      {
        channelId: "C2",
        enabled: false,
        requireMention: true,
        allowedUserIds: ["U1"],
        deniedUserIds: [],
      },
    ],
    toolPolicies: [
      { tool: "slack", action: "pins", effect: "approval_required" },
      { tool: "browser", action: "*", effect: "allow" },
      { tool: "filesystem", action: "write", effect: "deny" },
      { tool: "exec", action: "*", effect: "approval_required" },
      { tool: "gh", action: "*", effect: "allow", roleNames: ["admin"] },
      { tool: "exec", action: "shell", effect: "deny", slackUserIds: ["U2"] },
    ],
    approvalPolicies: [
      {
        name: "risky",
        actionPattern: "exec:*",
        resourcePattern: "*",
        approverSlackUserIds: ["U1", "U3", "U1"],
        minApprovals: 1,
        enabled: true,
      },
      {
        name: "disabled",
        actionPattern: "exec:deploy",
        resourcePattern: "*",
        approverSlackUserIds: ["UDISABLED"],
        minApprovals: 1,
        enabled: false,
      },
    ],
  })) as any;

  assert.equal(config.gateway.mode, "local");
  assert.equal(config.gateway.bind, "lan");
  assert.equal(config.channels.slack.mode, "socket");
  assert.equal(config.gateway.reload.mode, "hybrid");
  assert.deepEqual(config.gateway.auth, {
    mode: "token",
    token: "${OPENCLAW_GATEWAY_TOKEN}",
    rateLimit: {
      maxAttempts: 10,
      windowMs: 60000,
      lockoutMs: 300000,
    },
  });
  assert.deepEqual(config.gateway.controlUi.allowedOrigins, [
    "http://localhost:18789",
    "http://127.0.0.1:18789",
  ]);
  assert.deepEqual(config.gateway.remote, {
    url: "ws://openclaw-gateway:18789",
    transport: "direct",
    token: "${OPENCLAW_GATEWAY_TOKEN}",
  });
  assert.deepEqual(config.secrets.providers.operant, {
    source: "exec",
    command: "/operant/openclaw/operant-secret-resolver",
    args: ["/operant/openclaw/operant-secret-resolver.mjs"],
    passEnv: ["OPERANT_CONTROL_PLANE_URL", "OPERANT_INTERNAL_TOKEN"],
    jsonOnly: true,
    allowSymlinkCommand: false,
    trustedDirs: ["/operant/openclaw"],
  });
  assert.equal(config.secrets.defaults.exec, "operant");
  assert.deepEqual(config.models.providers.openai, {
    baseUrl: "https://api.openai.com/v1",
    models: [{ id: "gpt-5", name: "gpt-5" }],
    agentRuntime: {
      id: "pi",
    },
    apiKey: {
      source: "exec",
      provider: "operant",
      id: `workspaces/${workspaceId}/models/openai/apiKey`,
    },
  });
  assert.deepEqual(config.agents.defaults.model, {
    primary: "openai/gpt-5",
  });
  assert.deepEqual(config.agents.defaults.sandbox, {
    mode: "off",
  });
  assert.deepEqual(config.tools.elevated, {
    enabled: false,
    allowFrom: {
      slack: [],
    },
  });
  assert.deepEqual(config.commands.ownerAllowFrom, ["slack:U1", "slack:U3"]);
  assert.deepEqual(config.plugins.allow, ["slack", "operant"]);
  assert.equal(config.plugins.bundledDiscovery, "compat");
  assert.deepEqual(config.plugins.entries.slack, {
    enabled: true,
  });
  assert.deepEqual(config.plugins.entries.operant, {
    enabled: true,
  });
  assert.deepEqual(config.channels.slack.botToken, {
    source: "exec",
    provider: "operant",
    id: `workspaces/${workspaceId}/slack/botToken`,
  });
  assert.deepEqual(config.channels.slack.appToken, {
    source: "exec",
    provider: "operant",
    id: `workspaces/${workspaceId}/slack/appToken`,
  });
  assert.deepEqual(config.channels.slack.dm, {
    enabled: true,
    groupEnabled: false,
  });
  assert.equal(config.channels.slack.dmPolicy, "allowlist");
  assert.deepEqual(config.channels.slack.allowFrom, ["U1"]);
  assert.equal(config.channels.slack.groupPolicy, "allowlist");
  assert.equal(config.channels.slack.requireMention, true);
  assert.equal(config.channels.slack.replyToMode, "all");
  assert.equal(config.channels.slack.ackReaction, "eyes");
  assert.equal(config.channels.slack.typingReaction, "pencil2");
  assert.deepEqual(config.channels.slack.thread, {
    historyScope: "thread",
    inheritParent: false,
    initialHistoryLimit: 20,
    requireExplicitMention: false,
  });
  assert.deepEqual(config.channels.slack.streaming, {
    mode: "progress",
    progress: {
      label: "thinking",
      toolProgress: true,
      commandText: "status",
    },
  });
  assert.deepEqual(config.channels.slack.capabilities, {
    interactiveReplies: true,
  });
  assert.equal(config.channels.slack.channels.C1.requireMention, true);
  assert.deepEqual(config.channels.slack.channels.C1.users, ["U1"]);
  assert.equal(config.channels.slack.channels.C2.enabled, false);
  assert.deepEqual(config.channels.slack.channels.C2.users, ["U1"]);
  assert.equal(config.channels.slack.mediaMaxMb, 25);
  assert.equal(config.channels.slack.actions.pins, false);
  assert.equal(config.channels.slack.execApprovals.enabled, true);
  assert.deepEqual(config.channels.slack.execApprovals.approvers, ["U1", "U3"]);
  assert.equal(config.channels.slack.execApprovals.target, "both");
  assert.deepEqual(config.tools.alsoAllow, ["browser", "operant_ping", "pipedream_list_actions", "pipedream_run_action"]);
  assert.deepEqual(config.tools.deny, ["filesystem:write"]);
  assert.equal(JSON.stringify(config.tools).includes("gh"), false);
  assert.equal(JSON.stringify(config.tools).includes("exec:shell"), false);
  assert.equal(config.logging.redactSensitive, "tools");
  assert.equal(JSON.stringify(config).includes("xoxb-"), false);
  assert.equal(JSON.stringify(config).includes("xapp-"), false);
});

test("opts into Docker sandboxing only for the dedicated sandbox overlay", () => {
  const config = generateOpenClawConfig(baseInput({ sandboxMode: "docker" })) as any;

  assert.deepEqual(config.agents.defaults.sandbox, {
    mode: "all",
    backend: "docker",
    scope: "agent",
    workspaceAccess: "none",
    docker: {
      binds: [],
    },
  });
});

test("compiles wildcard Slack action restrictions closed", () => {
  const config = generateOpenClawConfig(baseInput({
    gatewayUrl: "https://openclaw.example.com",
    dmAllowFrom: ["U1"],
    toolPolicies: [{ tool: "slack", action: "*", effect: "approval_required" }],
  })) as any;

  assert.deepEqual(config.channels.slack.actions, {
    messages: false,
    reactions: false,
    pins: false,
    memberInfo: false,
    emojiList: false,
  });
  assert.equal(config.gateway.remote.url, "wss://openclaw.example.com");
  assert.equal(config.channels.slack.execApprovals.enabled, false);
});

test("disables Slack DM and group policies when no allowlists exist", () => {
  const config = generateOpenClawConfig(baseInput()) as any;

  assert.equal(config.channels.slack.dmPolicy, "disabled");
  assert.deepEqual(config.channels.slack.allowFrom, []);
  assert.equal(config.channels.slack.groupPolicy, "disabled");
  assert.deepEqual(config.channels.slack.channels, {});
  assert.equal(config.channels.slack.dm.enabled, true);
  assert.equal(config.channels.slack.dm.groupEnabled, false);
});

test("anthropic provider config sets an explicit baseUrl", () => {
  const config = generateOpenClawConfig(baseInput({ modelProvider: "anthropic", modelName: "claude-opus-4-7" })) as any;
  assert.equal(config.models.providers.anthropic.baseUrl, "https://api.anthropic.com/v1");
  assert.equal(config.models.providers.anthropic.agentRuntime, undefined);
});

test("buildSecretRefId scopes to workspace when no slack user is provided", () => {
  assert.equal(
    buildSecretRefId(workspaceId, "integrations/gmail/api-token"),
    `workspaces/${workspaceId}/integrations/gmail/api-token`,
  );
  assert.equal(
    buildSecretRefId(workspaceId, "integrations/gmail/api-token", { slackUserId: null }),
    `workspaces/${workspaceId}/integrations/gmail/api-token`,
  );
});

test("buildSecretRefId encodes the slack user into the path when provided", () => {
  const ref = buildSecretRefId(workspaceId, "integrations/gmail/api-token", { slackUserId: "U12345" });
  assert.equal(ref, `workspaces/${workspaceId}/users/U12345/integrations/gmail/api-token`);
  assert.match(ref, /^workspaces\/[^/]+\//);
});

test("generates mixed Slack and Teams channel config with Teams SecretRefs", () => {
  const config = generateOpenClawConfig(baseInput({
    teamsAppId: "11111111-1111-4111-8111-111111111111",
    teamsAppPasswordConfigured: true,
    teamsTenantId: "22222222-2222-4222-8222-222222222222",
    msteamsWebhookPort: 3978,
    msteamsWebhookPath: "/api/messages",
    dmAllowFrom: ["U1"],
    teamsDmAllowFrom: ["33333333-3333-4333-8333-333333333333"],
    channelPolicies: [
      {
        channelType: "slack",
        channelId: "C1",
        enabled: true,
        requireMention: true,
        allowedUserIds: ["U1"],
        deniedUserIds: [],
      },
      {
        channelType: "msteams",
        teamId: "19:team@example",
        channelId: "19:channel@example",
        enabled: true,
        requireMention: true,
        allowedUserIds: ["33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"],
        deniedUserIds: ["44444444-4444-4444-8444-444444444444"],
      },
    ],
    approvalPolicies: [
      {
        name: "teams-risky",
        actionPattern: "exec:*",
        resourcePattern: "*",
        approverSlackUserIds: ["U1"],
        approverTeamsUserIds: ["33333333-3333-4333-8333-333333333333"],
        minApprovals: 1,
        enabled: true,
      },
    ],
  })) as any;

  // operant plugin is always present and bundledDiscovery is preserved
  assert.deepEqual(config.plugins.allow, ["slack", "msteams", "operant"]);
  assert.equal(config.plugins.bundledDiscovery, "compat");
  assert.deepEqual(config.plugins.entries.msteams, { enabled: true });
  assert.deepEqual(config.plugins.entries.operant, { enabled: true });
  // Slack channel config unchanged when Slack is configured
  assert.equal(config.channels.slack.channels.C1.enabled, true);
  assert.equal(config.channels.msteams.appId, "11111111-1111-4111-8111-111111111111");
  assert.deepEqual(config.channels.msteams.appPassword, {
    source: "exec",
    provider: "operant",
    id: `workspaces/${workspaceId}/msteams/appPassword`,
  });
  assert.equal(config.channels.msteams.tenantId, "22222222-2222-4222-8222-222222222222");
  assert.deepEqual(config.channels.msteams.webhook, { port: 3978, path: "/api/messages" });
  assert.equal(config.channels.msteams.requireMention, true);
  assert.equal(config.channels.msteams.historyLimit, 0);
  assert.deepEqual(config.channels.msteams.actions, { memberInfo: false, messages: true, reactions: true });
  assert.equal(config.channels.msteams.dmPolicy, "allowlist");
  assert.deepEqual(config.channels.msteams.allowFrom, ["33333333-3333-4333-8333-333333333333"]);
  assert.equal(config.channels.msteams.groupPolicy, "allowlist");
  assert.deepEqual(config.channels.msteams.channels["19:channel@example"], {
    teamId: "19:team@example",
    enabled: true,
    requireMention: true,
    users: ["33333333-3333-4333-8333-333333333333"],
  });
  assert.deepEqual(config.channels.msteams.execApprovals.approvers, ["33333333-3333-4333-8333-333333333333"]);
  assert.deepEqual(config.commands.ownerAllowFrom, ["slack:U1", "msteams:33333333-3333-4333-8333-333333333333"]);
  assert.equal(JSON.stringify(config).includes("teams-app-password"), false);
});

test("does not emit Teams channel config until the app password SecretRef exists", () => {
  const config = generateOpenClawConfig(baseInput({
    teamsAppId: "11111111-1111-4111-8111-111111111111",
    teamsTenantId: "22222222-2222-4222-8222-222222222222",
    teamsAppPasswordConfigured: false,
  })) as any;

  assert.deepEqual(config.plugins.allow, ["slack", "operant"]);
  assert.equal(config.plugins.entries.msteams, undefined);
  assert.equal(config.channels.msteams, undefined);
});

test("keeps the operant plugin when only Teams is configured", () => {
  const config = generateOpenClawConfig(baseInput({
    slackBotTokenConfigured: false,
    slackAppTokenConfigured: false,
    teamsAppId: "11111111-1111-4111-8111-111111111111",
    teamsTenantId: "22222222-2222-4222-8222-222222222222",
    teamsAppPasswordConfigured: true,
  })) as any;

  assert.deepEqual(config.plugins.allow, ["msteams", "operant"]);
  assert.equal(config.plugins.bundledDiscovery, "compat");
  assert.deepEqual(config.plugins.entries.operant, { enabled: true });
  assert.equal(config.channels.slack, undefined);
  assert.equal(config.channels.msteams.enabled, true);
});
