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

const httpUrlSchema = z.string().url().refine((value) => {
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
  modelProvider: secretRefPartSchema.default("openai"),
  modelName: modelNameSchema.default("gpt-5"),
  modelApiKey: credentialSecretValueSchema.optional(),
  adminSlackUserId: slackIdSchema.optional(),
  allowedDmUserIds: slackIdListSchema.default([]),
  allowedChannelIds: slackIdListSchema.default([]),
  approvalSlackUserIds: slackIdListSchema.default([]),
}).superRefine((input, ctx) => {
  addDuplicateSlackIdIssues(ctx, input.allowedDmUserIds, ["allowedDmUserIds"], "DM allowlist");
  addDuplicateSlackIdIssues(ctx, input.allowedChannelIds, ["allowedChannelIds"], "channel allowlist");
  addDuplicateSlackIdIssues(ctx, input.approvalSlackUserIds, ["approvalSlackUserIds"], "approval");
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
  slackUserId: slackIdSchema.nullable(),
  tool: policyIdentifierSchema,
  action: policyIdentifierSchema,
});

export type PluginPolicyCheckRequest = z.infer<typeof pluginPolicyCheckRequestSchema>;

export const policyEvaluationSchema = z.object({
  slackUserId: slackIdSchema,
  slackChannelId: slackIdSchema.optional(),
  chatType: z.enum(["direct", "channel", "group", "thread"]).default("direct"),
  tool: policyIdentifierSchema.optional(),
  action: policyIdentifierSchema.default("message"),
  resource: policyIdentifierSchema.default("slack"),
  userRoleNames: roleNameListSchema.default([]),
});

export type PolicyEvaluationInput = Omit<z.infer<typeof policyEvaluationSchema>, "userRoleNames"> & {
  userRoleNames?: string[];
};

export type PolicyDecision = {
  effect: "allow" | "deny" | "approval_required";
  reasons: string[];
};

export const channelPolicyInputSchema = z.object({
  channelId: slackIdSchema,
  name: displayNameSchema.nullable().optional(),
  enabled: z.boolean().default(true),
  requireMention: z.boolean().default(true),
  allowedUserIds: slackIdListSchema.default([]),
  deniedUserIds: slackIdListSchema.default([]),
}).superRefine((policy, ctx) => {
  addDuplicateSlackIdIssues(ctx, policy.allowedUserIds, ["allowedUserIds"], "channel allowlist");
  addDuplicateSlackIdIssues(ctx, policy.deniedUserIds, ["deniedUserIds"], "channel denylist");
});

export const toolPolicyInputSchema = z.object({
  tool: policyIdentifierSchema,
  action: policyIdentifierSchema,
  effect: z.enum(["allow", "deny", "approval_required"]),
  slackUserIds: slackIdListSchema.default([]),
  roleNames: roleNameListSchema.default([]),
}).superRefine((policy, ctx) => {
  addDuplicateSlackIdIssues(ctx, policy.slackUserIds, ["slackUserIds"], "tool policy user");
  addDuplicateStringIssues(ctx, policy.roleNames, ["roleNames"], "tool policy role");
});

export const approvalPolicyInputSchema = z.object({
  name: displayNameSchema,
  actionPattern: policyIdentifierSchema,
  resourcePattern: policyIdentifierSchema.default("*"),
  approverSlackUserIds: slackIdListSchema.default([]),
  minApprovals: z.number().int().positive().default(1),
  enabled: z.boolean().default(true),
}).superRefine((policy, ctx) => {
  addDuplicateSlackIdIssues(ctx, policy.approverSlackUserIds, ["approverSlackUserIds"], "approval policy approver");
  if (!policy.enabled) return;
  const uniqueApprovers = new Set(policy.approverSlackUserIds);
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
  channelPolicies: z.array(channelPolicyInputSchema).max(200).default([]),
  toolPolicies: z.array(toolPolicyInputSchema).max(500).default([]),
  approvalPolicies: z.array(approvalPolicyInputSchema).max(100).default([]),
}).superRefine((policy, ctx) => {
  addDuplicateSlackIdIssues(ctx, policy.allowedDmUserIds, ["allowedDmUserIds"], "DM allowlist");

  const channelIds = new Set<string>();
  policy.channelPolicies.forEach((channelPolicy, index) => {
    if (channelIds.has(channelPolicy.channelId)) {
      ctx.addIssue({
        code: "custom",
        path: ["channelPolicies", index, "channelId"],
        message: `Duplicate channel policy for ${channelPolicy.channelId}`,
      });
    }
    channelIds.add(channelPolicy.channelId);
  });

  const toolActions = new Set<string>();
  policy.toolPolicies.forEach((toolPolicy, index) => {
    const key = [
      toolPolicy.tool,
      toolPolicy.action,
      toolPolicy.effect,
      [...toolPolicy.slackUserIds].sort().join(","),
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
  });
});

export type PolicyUpdateInput = z.infer<typeof policyUpdateSchema>;

export const userUpsertSchema = z.object({
  slackUserId: slackIdSchema,
  email: z.string().email().nullable().optional(),
  name: displayNameSchema.nullable().optional(),
  roles: z.array(roleNameInputSchema).min(1).max(25).default(["member"]),
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
  roleNames?: string[];
};

export type ApprovalPolicyRecord = {
  name: string;
  actionPattern: string;
  resourcePattern: string;
  approverSlackUserIds: string[];
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
  channelPolicies: ChannelPolicyRecord[];
  toolPolicies: ToolPolicyRecord[];
  approvalPolicies: ApprovalPolicyRecord[];
  secretResolverCommand: string;
  secretResolverScript: string;
};
