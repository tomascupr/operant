import { z } from "zod";

export const roleNames = [
  "owner",
  "admin",
  "integration_admin",
  "billing_usage_admin",
  "member",
  "viewer",
] as const;

export type RoleName = (typeof roleNames)[number];

export type Permission = {
  action: string;
  resource: string;
  description?: string;
};

export const chatPlatforms = ["slack", "msteams"] as const;
export type ChatPlatform = (typeof chatPlatforms)[number];

export const policyIdentifierSchema = z.string()
  .min(1)
  .max(160)
  .regex(/^[A-Za-z0-9_*.:/-]+$/, "Use only letters, numbers, '*', dots, underscores, colons, slashes, or hyphens");

export const secretRefPartSchema = z.string()
  .min(1)
  .max(80)
  .regex(/^[A-Za-z0-9_.-]+$/, "Use only letters, numbers, dots, underscores, or hyphens");

const displayNameSchema = z.string().trim().min(1).max(160);
const credentialLabelSchema = z.string().trim().min(1).max(120);

export const slackIdSchema = z.string()
  .min(1)
  .max(80)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, "Use only Slack identifier characters");

const slackIdListSchema = z.array(slackIdSchema).max(200);

export const teamsAppIdSchema = z.uuid("Use a Microsoft Teams app/client UUID");
export const teamsTenantIdSchema = z.uuid("Use a Microsoft Entra tenant UUID");
export const teamsAadUserIdSchema = z.uuid("Use a Microsoft Entra user object UUID");
export const teamsConversationIdSchema = z.string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9_.:@=-]+$/, "Use only Teams identifier characters");

export const teamsAadUserIdListSchema = z.array(teamsAadUserIdSchema).max(200);

export const chatPrincipalIdSchema = z.string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9_.:@=-]+$/, "Use only chat principal identifier characters");

function addDuplicateSlackIdIssues(ctx: z.RefinementCtx, values: string[], path: Array<string | number>, label: string): void {
  const seen = new Set<string>();
  values.forEach((value, index) => {
    if (seen.has(value)) {
      ctx.addIssue({
        code: "custom",
        path: [...path, index],
        message: `Duplicate ${label} Slack identifier ${value}`,
      });
    }
    seen.add(value);
  });
}

function addDuplicateStringIssues(ctx: z.RefinementCtx, values: string[], path: Array<string | number>, label: string): void {
  const seen = new Set<string>();
  values.forEach((value, index) => {
    if (seen.has(value)) {
      ctx.addIssue({
        code: "custom",
        path: [...path, index],
        message: `Duplicate ${label} ${value}`,
      });
    }
    seen.add(value);
  });
}

const modelNameSchema = z.string()
  .min(1)
  .max(160)
  .regex(/^[A-Za-z0-9_.:/-]+$/, "Use only letters, numbers, dots, underscores, colons, slashes, or hyphens");

const roleNameInputSchema = z.string()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_:-]*$/, "Use lowercase letters, numbers, underscores, colons, or hyphens");
const roleNameListSchema = z.array(roleNameInputSchema).max(100);

const httpUrlSchema = z.url().refine((value) => {
  const protocol = new URL(value).protocol;
  return protocol === "http:" || protocol === "https:";
}, "Use an http or https URL");

const secretValueSchema = z.string().min(1).max(8192);
const credentialSecretValueSchema = z.string().min(8).max(8192);
const maxMetadataRecordKeys = 100;

export const metadataRecordSchema = z.record(z.string().min(1).max(120), z.unknown()).superRefine((record, ctx) => {
  if (Object.keys(record).length > maxMetadataRecordKeys) {
    ctx.addIssue({
      code: "custom",
      message: `Metadata records can include at most ${maxMetadataRecordKeys} keys`,
    });
  }
});
export const usageTokenCountSchema = z.number().int().nonnegative().max(2_147_483_647);
export const usageCostUsdSchema = z.number().nonnegative().max(999_999.999999);

export const credentialInputSchema = z.object({
  companyName: displayNameSchema.optional(),
  workspaceName: displayNameSchema.optional(),
  slackTeamId: slackIdSchema.optional(),
  slackBotToken: credentialSecretValueSchema.optional(),
  slackAppToken: credentialSecretValueSchema.optional(),
  teamsAppId: teamsAppIdSchema.optional(),
  teamsAppPassword: credentialSecretValueSchema.optional(),
  teamsTenantId: teamsTenantIdSchema.optional(),
  msteamsWebhookPort: z.number().int().min(1).max(65535).optional(),
  msteamsWebhookPath: z.string().min(1).max(120).regex(/^\/[A-Za-z0-9/_:.-]*$/, "Use an absolute webhook path").optional(),
  modelProvider: secretRefPartSchema.default("openai"),
  modelName: modelNameSchema.default("gpt-5"),
  modelApiKey: credentialSecretValueSchema.optional(),
  adminSlackUserId: slackIdSchema.optional(),
  adminTeamsAadUserId: teamsAadUserIdSchema.optional(),
  allowedDmUserIds: slackIdListSchema.default([]),
  allowedChannelIds: slackIdListSchema.default([]),
  allowedTeamsDmUserIds: teamsAadUserIdListSchema.default([]),
  teamsChannelPolicies: z.array(z.object({
    teamId: teamsConversationIdSchema,
    channelId: teamsConversationIdSchema,
    name: displayNameSchema.nullable().optional(),
    allowedUserIds: teamsAadUserIdListSchema.default([]),
  })).max(200).default([]),
  approvalSlackUserIds: slackIdListSchema.default([]),
  approvalTeamsUserIds: teamsAadUserIdListSchema.default([]),
}).superRefine((input, ctx) => {
  if (Boolean(input.slackBotToken) !== Boolean(input.slackAppToken)) {
    ctx.addIssue({
      code: "custom",
      path: input.slackBotToken ? ["slackAppToken"] : ["slackBotToken"],
      message: "Slack setup requires both bot and app tokens",
    });
  }
  const teamsValues = [input.teamsAppId, input.teamsAppPassword, input.teamsTenantId].filter(Boolean);
  if (teamsValues.length > 0 && teamsValues.length < 3) {
    ctx.addIssue({
      code: "custom",
      path: ["teamsAppPassword"],
      message: "Teams setup requires app ID, app password, and tenant ID",
    });
  }
  if (!input.slackBotToken && !input.teamsAppPassword) {
    ctx.addIssue({
      code: "custom",
      path: ["slackBotToken"],
      message: "Configure Slack tokens, Teams credentials, or both",
    });
  }
  addDuplicateSlackIdIssues(ctx, input.allowedDmUserIds, ["allowedDmUserIds"], "DM allowlist");
  addDuplicateSlackIdIssues(ctx, input.allowedChannelIds, ["allowedChannelIds"], "channel allowlist");
  addDuplicateSlackIdIssues(ctx, input.approvalSlackUserIds, ["approvalSlackUserIds"], "approval");
  addDuplicateStringIssues(ctx, input.allowedTeamsDmUserIds, ["allowedTeamsDmUserIds"], "Teams DM allowlist");
  addDuplicateStringIssues(ctx, input.approvalTeamsUserIds, ["approvalTeamsUserIds"], "Teams approval");
  const teamsChannels = new Set<string>();
  input.teamsChannelPolicies.forEach((policy, index) => {
    const key = `${policy.teamId}\0${policy.channelId}`;
    if (teamsChannels.has(key)) {
      ctx.addIssue({
        code: "custom",
        path: ["teamsChannelPolicies", index, "channelId"],
        message: `Duplicate Teams channel policy for ${policy.teamId}/${policy.channelId}`,
      });
    }
    teamsChannels.add(key);
    addDuplicateStringIssues(ctx, policy.allowedUserIds, ["teamsChannelPolicies", index, "allowedUserIds"], "Teams channel allowlist");
  });
});

export type CredentialInput = z.infer<typeof credentialInputSchema>;

export const integrationCredentialInputSchema = z.object({
  kind: secretRefPartSchema,
  key: secretRefPartSchema,
  label: credentialLabelSchema.optional(),
  secretValue: secretValueSchema,
  slackUserId: slackIdSchema.optional(),
});

export type IntegrationCredentialInput = z.infer<typeof integrationCredentialInputSchema>;

export const workspaceSettingsUpdateSchema = z.object({
  companyName: displayNameSchema.optional(),
  workspaceName: displayNameSchema.optional(),
  slackTeamId: slackIdSchema.nullable().optional(),
  teamsAppId: teamsAppIdSchema.nullable().optional(),
  teamsTenantId: teamsTenantIdSchema.nullable().optional(),
  msteamsWebhookPort: z.number().int().min(1).max(65535).optional(),
  msteamsWebhookPath: z.string().min(1).max(120).regex(/^\/[A-Za-z0-9/_:.-]*$/, "Use an absolute webhook path").optional(),
  openclawGatewayUrl: httpUrlSchema.optional(),
  modelProvider: secretRefPartSchema.optional(),
  modelName: modelNameSchema.optional(),
  retentionDays: z.number().int().min(1).max(3650).optional(),
});

export type WorkspaceSettingsUpdateInput = z.infer<typeof workspaceSettingsUpdateSchema>;

export const pluginUserContextRequestSchema = z.object({
  sessionKey: z.string().min(1).max(512),
});

export type PluginUserContextRequest = z.infer<typeof pluginUserContextRequestSchema>;

export const pluginPolicyCheckRequestSchema = z.object({
  principalId: chatPrincipalIdSchema.nullable(),
  tool: policyIdentifierSchema,
  action: policyIdentifierSchema,
});

export type PluginPolicyCheckRequest = z.infer<typeof pluginPolicyCheckRequestSchema>;

// --- Governed memory + skills (migration 013) ---

export const memoryVisibilitySchema = z.enum(["private", "team"]);
export type MemoryVisibility = z.infer<typeof memoryVisibilitySchema>;

const memoryScopeKeySchema = z.string().trim().min(1).max(120)
  .regex(/^[A-Za-z0-9 _.:/-]+$/, "Use only letters, numbers, spaces, or _ . : / -");
const memoryTagSchema = z.string().trim().min(1).max(60)
  .regex(/^[A-Za-z0-9_.:/-]+$/, "Use only letters, numbers, or _ . : / -");
const memoryTagsSchema = z.array(memoryTagSchema).max(20).default([]);
const memoryContentSchema = z.string().trim().min(1).max(32_768);
const memorySearchQuerySchema = z.string().trim().min(1).max(200);
const memorySearchLimitSchema = z.number().int().min(1).max(50).default(20);

export const skillNameSchema = z.string().trim().min(1).max(120)
  .regex(/^[A-Za-z0-9 _.:/-]+$/, "Use only letters, numbers, spaces, or _ . : / -");
const skillTriggerSchema = z.string().trim().min(1).max(1024);
const skillBodySchema = z.string().trim().min(1).max(65_536);

export const memoryEntryWriteSchema = z.object({
  visibility: memoryVisibilitySchema.default("private"),
  scopeKey: memoryScopeKeySchema.optional(),
  tags: memoryTagsSchema,
  content: memoryContentSchema,
});
export type MemoryEntryWriteInput = z.infer<typeof memoryEntryWriteSchema>;

export const memorySearchSchema = z.object({
  q: memorySearchQuerySchema.optional(),
  visibility: memoryVisibilitySchema.optional(),
  scopeKey: memoryScopeKeySchema.optional(),
  tags: z.array(memoryTagSchema).max(10).default([]),
  limit: memorySearchLimitSchema,
});
export type MemorySearchInput = z.infer<typeof memorySearchSchema>;

export const skillWriteSchema = z.object({
  name: skillNameSchema,
  triggerHint: skillTriggerSchema,
  body: skillBodySchema,
  tags: memoryTagsSchema,
});
export type SkillWriteInput = z.infer<typeof skillWriteSchema>;

export const skillSearchSchema = z.object({
  q: memorySearchQuerySchema.optional(),
  tags: z.array(memoryTagSchema).max(10).default([]),
  limit: memorySearchLimitSchema,
});
export type SkillSearchInput = z.infer<typeof skillSearchSchema>;

export const pluginMemoryWriteSchema = z.object({
  principalId: chatPrincipalIdSchema,
  visibility: memoryVisibilitySchema.default("private"),
  scopeKey: memoryScopeKeySchema.optional(),
  tags: memoryTagsSchema,
  content: memoryContentSchema,
});
export type PluginMemoryWriteInput = z.infer<typeof pluginMemoryWriteSchema>;

export const pluginMemorySearchSchema = z.object({
  principalId: chatPrincipalIdSchema,
  q: memorySearchQuerySchema.optional(),
  tags: z.array(memoryTagSchema).max(10).default([]),
  limit: memorySearchLimitSchema,
});
export type PluginMemorySearchInput = z.infer<typeof pluginMemorySearchSchema>;

export const pluginSkillSearchSchema = z.object({
  principalId: chatPrincipalIdSchema,
  q: memorySearchQuerySchema.optional(),
  tags: z.array(memoryTagSchema).max(10).default([]),
  limit: memorySearchLimitSchema,
});
export type PluginSkillSearchInput = z.infer<typeof pluginSkillSearchSchema>;

export type MemoryEntryRecord = {
  id: string;
  ownerPrincipalId: string;
  ownerPlatform: ChatPlatform;
  visibility: MemoryVisibility;
  scopeKey: string | null;
  tags: string[];
  content: string;
  createdAt: string;
  updatedAt: string;
};

export type SkillRecord = {
  id: string;
  name: string;
  triggerHint: string;
  body: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
};

export const policyEvaluationSchema = z.object({
  channelType: z.enum(chatPlatforms).default("slack"),
  slackUserId: slackIdSchema.optional(),
  teamsAadUserId: teamsAadUserIdSchema.optional(),
  principalId: chatPrincipalIdSchema.optional(),
  slackChannelId: slackIdSchema.optional(),
  teamsChannelId: teamsConversationIdSchema.optional(),
  teamId: teamsConversationIdSchema.optional(),
  chatType: z.enum(["direct", "channel", "group", "thread"]).default("direct"),
  tool: policyIdentifierSchema.optional(),
  action: policyIdentifierSchema.default("message"),
  resource: policyIdentifierSchema.default("slack"),
  userRoleNames: roleNameListSchema.default([]),
}).superRefine((input, ctx) => {
  const principalId = input.channelType === "slack"
    ? input.slackUserId ?? input.principalId
    : input.teamsAadUserId ?? input.principalId;
  if (!principalId) {
    ctx.addIssue({
      code: "custom",
      path: input.channelType === "slack" ? ["slackUserId"] : ["teamsAadUserId"],
      message: `${input.channelType} policy evaluation requires a principal ID`,
    });
  }
  if (input.channelType === "msteams" && input.chatType !== "direct" && !input.teamId) {
    ctx.addIssue({
      code: "custom",
      path: ["teamId"],
      message: "Teams channel and group policy evaluation requires a team ID",
    });
  }
});

export type PolicyEvaluationInput = Omit<z.infer<typeof policyEvaluationSchema>, "userRoleNames" | "channelType"> & {
  channelType?: ChatPlatform;
  userRoleNames?: string[];
};

export type PolicyDecision = {
  effect: "allow" | "deny" | "approval_required";
  reasons: string[];
};

export const channelPolicyInputSchema = z.object({
  channelType: z.enum(chatPlatforms).default("slack"),
  teamId: teamsConversationIdSchema.nullable().optional(),
  channelId: chatPrincipalIdSchema,
  name: displayNameSchema.nullable().optional(),
  enabled: z.boolean().default(true),
  requireMention: z.boolean().default(true),
  allowedUserIds: z.array(chatPrincipalIdSchema).max(200).default([]),
  deniedUserIds: z.array(chatPrincipalIdSchema).max(200).default([]),
}).superRefine((policy, ctx) => {
  if (policy.channelType === "slack") {
    if (!slackIdSchema.safeParse(policy.channelId).success) {
      ctx.addIssue({ code: "custom", path: ["channelId"], message: "Slack channel policies require a Slack channel ID" });
    }
    for (const [field, values, label] of [
      ["allowedUserIds", policy.allowedUserIds, "channel allowlist"] as const,
      ["deniedUserIds", policy.deniedUserIds, "channel denylist"] as const,
    ]) {
      values.forEach((value, index) => {
        if (!slackIdSchema.safeParse(value).success) {
          ctx.addIssue({ code: "custom", path: [field, index], message: "Use only Slack identifier characters" });
        }
      });
      addDuplicateSlackIdIssues(ctx, values, [field], label);
    }
    return;
  }
  if (!policy.teamId) {
    ctx.addIssue({ code: "custom", path: ["teamId"], message: "Teams channel policies require a teamId" });
  }
  if (!teamsConversationIdSchema.safeParse(policy.channelId).success) {
    ctx.addIssue({ code: "custom", path: ["channelId"], message: "Teams channel policies require a Teams conversation or channel ID" });
  }
  for (const [field, values, label] of [
    ["allowedUserIds", policy.allowedUserIds, "Teams channel allowlist"] as const,
    ["deniedUserIds", policy.deniedUserIds, "Teams channel denylist"] as const,
  ]) {
    values.forEach((value, index) => {
      if (!teamsAadUserIdSchema.safeParse(value).success) {
        ctx.addIssue({ code: "custom", path: [field, index], message: "Use Microsoft Entra user object IDs for Teams allowlists" });
      }
    });
    addDuplicateStringIssues(ctx, values, [field], label);
  }
});

const teamsChannelPolicyAliasSchema = z.object({
  channelType: z.literal("msteams").default("msteams"),
  teamId: teamsConversationIdSchema,
  channelId: teamsConversationIdSchema,
  name: displayNameSchema.nullable().optional(),
  enabled: z.boolean().default(true),
  requireMention: z.boolean().default(true),
  allowedUserIds: teamsAadUserIdListSchema.default([]),
  deniedUserIds: teamsAadUserIdListSchema.default([]),
}).superRefine((policy, ctx) => {
  addDuplicateStringIssues(ctx, policy.allowedUserIds, ["allowedUserIds"], "Teams channel allowlist");
  addDuplicateStringIssues(ctx, policy.deniedUserIds, ["deniedUserIds"], "Teams channel denylist");
});

export const toolPolicyInputSchema = z.object({
  tool: policyIdentifierSchema,
  action: policyIdentifierSchema,
  effect: z.enum(["allow", "deny", "approval_required"]),
  slackUserIds: slackIdListSchema.default([]),
  teamsAadUserIds: teamsAadUserIdListSchema.default([]),
  roleNames: roleNameListSchema.default([]),
}).superRefine((policy, ctx) => {
  addDuplicateSlackIdIssues(ctx, policy.slackUserIds, ["slackUserIds"], "tool policy user");
  addDuplicateStringIssues(ctx, policy.teamsAadUserIds, ["teamsAadUserIds"], "tool policy Teams user");
  addDuplicateStringIssues(ctx, policy.roleNames, ["roleNames"], "tool policy role");
});

export const approvalPolicyInputSchema = z.object({
  name: displayNameSchema,
  actionPattern: policyIdentifierSchema,
  resourcePattern: policyIdentifierSchema.default("*"),
  approverSlackUserIds: slackIdListSchema.default([]),
  approverTeamsUserIds: teamsAadUserIdListSchema.default([]),
  minApprovals: z.number().int().positive().default(1),
  enabled: z.boolean().default(true),
}).superRefine((policy, ctx) => {
  addDuplicateSlackIdIssues(ctx, policy.approverSlackUserIds, ["approverSlackUserIds"], "approval policy approver");
  addDuplicateStringIssues(ctx, policy.approverTeamsUserIds, ["approverTeamsUserIds"], "approval policy Teams approver");
  if (!policy.enabled) return;
  const uniqueApprovers = new Set([
    ...policy.approverSlackUserIds.map((id) => `slack:${id}`),
    ...policy.approverTeamsUserIds.map((id) => `msteams:${id}`),
  ]);
  if (uniqueApprovers.size === 0) {
    ctx.addIssue({
      code: "custom",
      path: ["approverSlackUserIds"],
      message: "Enabled approval policies require at least one approver",
    });
    return;
  }
  if (policy.minApprovals > uniqueApprovers.size) {
    ctx.addIssue({
      code: "custom",
      path: ["minApprovals"],
      message: "minApprovals cannot exceed the number of unique approvers",
    });
  }
});

export const policyUpdateSchema = z.object({
  allowedDmUserIds: slackIdListSchema.default([]),
  allowedTeamsDmUserIds: teamsAadUserIdListSchema.default([]),
  channelPolicies: z.array(channelPolicyInputSchema).max(200).default([]),
  teamsChannelPolicies: z.array(teamsChannelPolicyAliasSchema).max(200).default([]),
  toolPolicies: z.array(toolPolicyInputSchema).max(500).default([]),
  approvalPolicies: z.array(approvalPolicyInputSchema).max(100).default([]),
}).superRefine((policy, ctx) => {
  addDuplicateSlackIdIssues(ctx, policy.allowedDmUserIds, ["allowedDmUserIds"], "DM allowlist");
  addDuplicateStringIssues(ctx, policy.allowedTeamsDmUserIds, ["allowedTeamsDmUserIds"], "Teams DM allowlist");

  const channelIds = new Set<string>();
  const allChannelPolicies = [...policy.channelPolicies, ...policy.teamsChannelPolicies];
  allChannelPolicies.forEach((channelPolicy, index) => {
    const key = `${channelPolicy.channelType}:${channelPolicy.teamId ?? ""}:${channelPolicy.channelId}`;
    if (channelIds.has(key)) {
      const fromAlias = index >= policy.channelPolicies.length;
      ctx.addIssue({
        code: "custom",
        path: [fromAlias ? "teamsChannelPolicies" : "channelPolicies", fromAlias ? index - policy.channelPolicies.length : index, "channelId"],
        message: `Duplicate channel policy for ${channelPolicy.channelId}`,
      });
    }
    channelIds.add(key);
  });

  const toolActions = new Set<string>();
  policy.toolPolicies.forEach((toolPolicy, index) => {
    const key = [
      toolPolicy.tool,
      toolPolicy.action,
      toolPolicy.effect,
      [...toolPolicy.slackUserIds].sort().join(","),
      [...toolPolicy.teamsAadUserIds].sort().join(","),
      [...toolPolicy.roleNames].sort().join(","),
    ].join("\0");
    if (toolActions.has(key)) {
      ctx.addIssue({
        code: "custom",
        path: ["toolPolicies", index, "action"],
        message: `Duplicate tool policy for ${toolPolicy.tool}:${toolPolicy.action} with the same effect and principal scope`,
      });
    }
    toolActions.add(key);
  });

  const approvalNames = new Set<string>();
  policy.approvalPolicies.forEach((approvalPolicy, index) => {
    if (approvalNames.has(approvalPolicy.name)) {
      ctx.addIssue({
        code: "custom",
        path: ["approvalPolicies", index, "name"],
        message: `Duplicate approval policy name ${approvalPolicy.name}`,
      });
    }
    approvalNames.add(approvalPolicy.name);

    addDuplicateSlackIdIssues(ctx, approvalPolicy.approverSlackUserIds, ["approvalPolicies", index, "approverSlackUserIds"], "approval policy approver");
    addDuplicateStringIssues(ctx, approvalPolicy.approverTeamsUserIds, ["approvalPolicies", index, "approverTeamsUserIds"], "approval policy Teams approver");
  });
}).transform((policy) => ({
  allowedDmUserIds: policy.allowedDmUserIds,
  allowedTeamsDmUserIds: policy.allowedTeamsDmUserIds,
  channelPolicies: [...policy.channelPolicies, ...policy.teamsChannelPolicies],
  toolPolicies: policy.toolPolicies,
  approvalPolicies: policy.approvalPolicies,
}));

export type PolicyUpdateInput = z.infer<typeof policyUpdateSchema>;

export const userUpsertSchema = z.object({
  slackUserId: slackIdSchema.optional(),
  teamsAadUserId: teamsAadUserIdSchema.optional(),
  teamsBotUserId: teamsConversationIdSchema.optional(),
  teamsTenantId: teamsTenantIdSchema.optional(),
  email: z.email().nullable().optional(),
  name: displayNameSchema.nullable().optional(),
  roles: z.array(roleNameInputSchema).min(1).max(25).default(["member"]),
}).superRefine((input, ctx) => {
  if (!input.slackUserId && !input.teamsAadUserId) {
    ctx.addIssue({
      code: "custom",
      path: ["slackUserId"],
      message: "Provide a Slack user ID, Teams AAD user ID, or both",
    });
  }
});

export type UserUpsertInput = z.infer<typeof userUpsertSchema>;

export const customRoleUpsertSchema = z.object({
  name: z.string().min(2).max(64).regex(/^[a-z][a-z0-9_:-]*$/, "Use lowercase letters, numbers, underscores, colons, or hyphens"),
  permissions: z.array(z.object({
    action: policyIdentifierSchema,
    resource: policyIdentifierSchema,
  })).min(1).max(500),
});

export type CustomRoleUpsertInput = z.infer<typeof customRoleUpsertSchema>;

export type WorkspaceRecord = {
  companyId: string;
  workspaceId: string;
};

export type ChannelPolicyRecord = {
  channelType?: ChatPlatform;
  teamId?: string | null;
  channelId: string;
  name?: string | null;
  enabled: boolean;
  requireMention: boolean;
  allowedUserIds: string[];
  deniedUserIds: string[];
};

export type ToolPolicyRecord = {
  tool: string;
  action: string;
  effect: "allow" | "deny" | "approval_required";
  slackUserIds?: string[];
  teamsAadUserIds?: string[];
  roleNames?: string[];
};

export type ApprovalPolicyRecord = {
  name: string;
  actionPattern: string;
  resourcePattern: string;
  approverSlackUserIds: string[];
  approverTeamsUserIds?: string[];
  minApprovals: number;
  enabled: boolean;
};

export type OpenClawConfigInput = {
  workspaceId: string;
  gatewayUrl: string;
  gatewayTokenEnv?: string;
  modelProvider: string;
  modelName: string;
  sandboxMode?: "off" | "docker";
  dmAllowFrom: string[];
  teamsDmAllowFrom?: string[];
  channelPolicies: ChannelPolicyRecord[];
  toolPolicies: ToolPolicyRecord[];
  approvalPolicies: ApprovalPolicyRecord[];
  slackBotTokenConfigured?: boolean;
  slackAppTokenConfigured?: boolean;
  teamsAppId?: string | null;
  teamsAppPasswordConfigured?: boolean;
  teamsTenantId?: string | null;
  msteamsWebhookPort?: number | null;
  msteamsWebhookPath?: string | null;
  secretResolverCommand: string;
  secretResolverScript: string;
};
