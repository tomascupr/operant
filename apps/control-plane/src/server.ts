import { createHash, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z, ZodError } from "zod";
import { createSessionToken, hashSessionToken, readBearerToken } from "./auth.js";
import { createPool, runMigrations, type Database } from "./db.js";
import { checksumConfig, generateOpenClawConfig, buildSecretRefId, gatewayWebSocketUrl, parseSecretRefId } from "./openclaw-config.js";
import {
  extractOpenClawSessionsObservations,
  extractOpenClawStatusObservations,
  extractOpenClawTaskObservations,
  extractOpenClawUsageCostObservations,
  isOpenClawCheckName,
  openClawCheckNames,
  openClawGatewayCommandArgs,
  runOpenClawCheck,
  runOpenClawCommand,
} from "./openclaw-ops.js";
import { evaluatePolicy, evaluateToolOnly, summarizeApprovalRequirement } from "./policy.js";
import { defaultRolePermissions, permissionMatches } from "./rbac.js";
import { redactRecordForPersistence } from "./redaction.js";
import { applyRetentionPurge, applyRetentionWipe, buildRetentionExport, retentionWipeScopes } from "./retention.js";
import { decryptSecret, encryptSecret, parseMasterKey } from "./secrets.js";
import {
  credentialInputSchema,
  customRoleUpsertSchema,
  integrationCredentialInputSchema,
  metadataRecordSchema,
  pluginPolicyCheckRequestSchema,
  pluginUserContextRequestSchema,
  policyIdentifierSchema,
  policyUpdateSchema,
  policyEvaluationSchema,
  roleNames,
  slackIdSchema,
  usageCostUsdSchema,
  usageTokenCountSchema,
  workspaceSettingsUpdateSchema,
  userUpsertSchema,
  type ApprovalPolicyRecord,
  type ChannelPolicyRecord,
  type ToolPolicyRecord,
} from "./schema.js";
import { ensureDefaultWorkspace } from "./seed.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, "../../public");
const builtinRoleNames = new Set<string>(roleNames);
const openClawEventTypeSchema = z.string().min(1).max(80).regex(/^[a-z][a-z0-9_.:-]*$/);
const openClawEventIdSchema = z.string().min(1).max(512);
const openClawSlackIdSchema = z.string().min(1).max(120);
const openClawUsageLabelSchema = z.string().min(1).max(160);
const maxJsonBodyBytes = 1024 * 1024;
const pipedreamOAuthTokenUrl = "https://api.pipedream.com/v1/oauth/token";
const pipedreamDiagnosticsTimeoutMs = Number(process.env.PIPEDREAM_DIAGNOSTICS_TIMEOUT_MS || 8_000);

export const pipedreamDiagnosticEnvKeys = [
  "OPERANT_MCP_SOURCE_PIPEDREAM_URL",
  "PIPEDREAM_PROJECT_CLIENT_ID",
  "PIPEDREAM_PROJECT_CLIENT_SECRET",
  "PIPEDREAM_PROJECT_ID",
  "PIPEDREAM_ENVIRONMENT",
] as const;

type PipedreamOAuthDiagnosticStatus = "ok" | "unauthorized" | "unreachable" | "not_configured";

type PipedreamOAuthDiagnostic = {
  ok: boolean;
  status: PipedreamOAuthDiagnosticStatus;
  httpStatus?: number;
};

type OperantPluginDiagnostic = {
  ok: boolean;
  status: "enabled" | "disabled" | "missing" | "unknown";
  id: "operant";
};

class InvalidJsonBodyError extends Error {
  constructor() {
    super("Invalid JSON request body");
  }
}

class JsonBodyTooLargeError extends Error {
  constructor() {
    super("JSON request body exceeds 1 MiB");
  }
}

export type ServerState = {
  pool: Database;
  masterKey: Buffer;
};

type Queryable = Pick<Database, "query">;

type RouteContext = {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  state: ServerState;
};

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "object-src 'none'",
].join("; ");

function responseHeaders(contentType: string): Record<string, string> {
  return {
    "content-type": contentType,
    "cache-control": "no-store",
    "content-security-policy": contentSecurityPolicy,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  };
}

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  res.writeHead(statusCode, responseHeaders("application/json; charset=utf-8"));
  res.end(JSON.stringify(payload, null, 2));
}

function sendText(res: ServerResponse, statusCode: number, payload: string, contentType = "text/plain; charset=utf-8"): void {
  res.writeHead(statusCode, responseHeaders(contentType));
  res.end(payload);
}

function presentEnvValue(value: string | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

export function buildPipedreamEnvDiagnostics(env: NodeJS.ProcessEnv = process.env): Array<{ name: string; present: boolean }> {
  return pipedreamDiagnosticEnvKeys.map((name) => ({ name, present: presentEnvValue(env[name]) }));
}

function hasPipedreamHandshakeEnv(env: NodeJS.ProcessEnv): boolean {
  return presentEnvValue(env.PIPEDREAM_PROJECT_CLIENT_ID) &&
    presentEnvValue(env.PIPEDREAM_PROJECT_CLIENT_SECRET) &&
    presentEnvValue(env.PIPEDREAM_PROJECT_ID) &&
    presentEnvValue(env.PIPEDREAM_ENVIRONMENT) &&
    presentEnvValue(env.OPERANT_MCP_SOURCE_PIPEDREAM_URL);
}

function plainRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function plainString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

export function summarizeOperantPluginDiagnostic(json: unknown): OperantPluginDiagnostic {
  const root = plainRecord(json);
  const plugins = Array.isArray(root?.plugins)
    ? root.plugins
    : Array.isArray(root?.items)
      ? root.items
      : Array.isArray(json)
        ? json
        : [];
  for (const item of plugins) {
    const plugin = plainRecord(item);
    if (!plugin || plainString(plugin.id) !== "operant") continue;
    const status = plainString(plugin.status);
    const enabled = status === "enabled" || plugin.enabled === true;
    if (enabled) return { ok: true, status: "enabled", id: "operant" };
    if (status === "disabled" || plugin.enabled === false) return { ok: false, status: "disabled", id: "operant" };
    return { ok: false, status: "unknown", id: "operant" };
  }
  return { ok: false, status: "missing", id: "operant" };
}

export async function checkPipedreamOAuthHandshake(
  env: NodeJS.ProcessEnv = process.env,
  fetchImpl: typeof fetch = fetch,
): Promise<PipedreamOAuthDiagnostic> {
  if (!hasPipedreamHandshakeEnv(env)) return { ok: false, status: "not_configured" };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), pipedreamDiagnosticsTimeoutMs);
  try {
    const response = await fetchImpl(pipedreamOAuthTokenUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: env.PIPEDREAM_PROJECT_CLIENT_ID,
        client_secret: env.PIPEDREAM_PROJECT_CLIENT_SECRET,
      }),
    });
    if (!response.ok) {
      return {
        ok: false,
        status: [400, 401, 403].includes(response.status) ? "unauthorized" : "unreachable",
        httpStatus: response.status,
      };
    }
    const body = await response.json().catch(() => ({})) as { access_token?: unknown };
    return typeof body.access_token === "string" && body.access_token.length > 0
      ? { ok: true, status: "ok", httpStatus: response.status }
      : { ok: false, status: "unreachable", httpStatus: response.status };
  } catch {
    return { ok: false, status: "unreachable" };
  } finally {
    clearTimeout(timeout);
  }
}

function openClawCommandExtraEnv(workspace: { openclaw_gateway_url?: string | null }): NodeJS.ProcessEnv {
  const controlPlaneUrl = process.env.OPERANT_CONTROL_PLANE_URL ||
    `http://127.0.0.1:${process.env.OPERANT_PORT || "8080"}`;
  return {
    OPERANT_CONTROL_PLANE_URL: controlPlaneUrl,
    ...(process.env.OPERANT_INTERNAL_TOKEN ? { OPERANT_INTERNAL_TOKEN: process.env.OPERANT_INTERNAL_TOKEN } : {}),
    OPENCLAW_GATEWAY_URL: gatewayWebSocketUrl(
      workspace.openclaw_gateway_url ?? process.env.OPENCLAW_GATEWAY_URL ?? "http://openclaw-gateway:18789",
    ),
  };
}

function openClawObservationCommandExtraEnv(workspace: { openclaw_gateway_url?: string | null }): NodeJS.ProcessEnv {
  return {
    ...openClawCommandExtraEnv(workspace),
    ...(process.env.OPENCLAW_OBSERVATION_STATE_DIR
      ? { OPENCLAW_STATE_DIR: process.env.OPENCLAW_OBSERVATION_STATE_DIR }
      : {}),
  };
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let received = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    received += buffer.length;
    if (received > maxJsonBodyBytes) throw new JsonBodyTooLargeError();
    chunks.push(buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new InvalidJsonBodyError();
  }
}

async function getWorkspace(pool: Database) {
  const seeded = await ensureDefaultWorkspace(pool);
  const workspace = await pool.query(
    `SELECT w.id, w.company_id, w.name, w.slack_team_id, w.openclaw_gateway_url, w.openclaw_config_path, w.created_at, c.name AS company_name
     FROM workspaces w
     JOIN companies c ON c.id = w.company_id
     WHERE w.id = $1`,
    [seeded.workspaceId],
  );
  return workspace.rows[0];
}

async function audit(pool: Queryable, input: {
  companyId?: string;
  workspaceId?: string;
  actorUserId?: string | null;
  eventType: string;
  resourceType: string;
  resourceId?: string;
  outcome?: string;
  metadata?: Record<string, unknown>;
}) {
  await pool.query(
    `INSERT INTO audit_logs (company_id, workspace_id, actor_user_id, event_type, resource_type, resource_id, outcome, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      input.companyId ?? null,
      input.workspaceId ?? null,
      input.actorUserId ?? null,
      input.eventType,
      input.resourceType,
      input.resourceId ?? null,
      input.outcome ?? "success",
      redactRecordForPersistence(input.metadata ?? {}),
    ],
  );
}

function actorSlackUserId(req: IncomingMessage): string | null {
  if (process.env.OPERANT_ALLOW_HEADER_AUTH !== "true") return null;
  const header = req.headers["x-operant-slack-user-id"] ?? req.headers["x-operant-user-id"];
  const value = Array.isArray(header) ? header[0] : header;
  const parsed = slackIdSchema.safeParse(value?.trim() || "");
  return parsed.success ? parsed.data : null;
}

function sessionTokenFromRequest(req: IncomingMessage): string | null {
  const authorization = Array.isArray(req.headers.authorization) ? req.headers.authorization[0] : req.headers.authorization;
  const bearer = readBearerToken(authorization);
  if (bearer) return bearer;
  const header = req.headers["x-operant-session-token"];
  const value = Array.isArray(header) ? header[0] : header;
  return value?.trim() || null;
}

function internalTokenFromRequest(req: IncomingMessage): string {
  const authorization = Array.isArray(req.headers.authorization) ? req.headers.authorization[0] : req.headers.authorization;
  const bearer = readBearerToken(authorization);
  if (bearer) return bearer;
  const header = req.headers["x-operant-internal-token"];
  const value = Array.isArray(header) ? header[0] : header;
  return value?.trim() || "";
}

function timingSafeEqualString(expected: string, actual: string): boolean {
  if (!expected) return false;
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest();
  const actualDigest = createHash("sha256").update(actual || "", "utf8").digest();
  return timingSafeEqual(expectedDigest, actualDigest);
}

function isAuthorizedInternalRequest(req: IncomingMessage): boolean {
  return timingSafeEqualString(process.env.OPERANT_INTERNAL_TOKEN || "", internalTokenFromRequest(req));
}

function adminLoginTokenFromRequest(req: IncomingMessage, payload: unknown): string {
  if (payload && typeof payload === "object") {
    const value = (payload as Record<string, unknown>).adminLoginToken;
    if (typeof value === "string") return value.trim();
  }
  const header = req.headers["x-operant-admin-login-token"];
  const value = Array.isArray(header) ? header[0] : header;
  return value?.trim() || "";
}

function adminLoginTokenValidation(req: IncomingMessage, payload: unknown): { ok: true } | { ok: false; statusCode: number; error: string } {
  const expected = process.env.OPERANT_ADMIN_LOGIN_TOKEN?.trim() || "";
  if (!expected) {
    return { ok: false, statusCode: 503, error: "OPERANT_ADMIN_LOGIN_TOKEN is not configured" };
  }
  if (!timingSafeEqualString(expected, adminLoginTokenFromRequest(req, payload))) {
    return { ok: false, statusCode: 401, error: "Missing or invalid admin login token" };
  }
  return { ok: true };
}

function decodePathComponent(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

async function resolveSessionActor(pool: Queryable, req: IncomingMessage, workspaceId: string): Promise<{
  userId: string;
  slackUserId: string | null;
  roles: string[];
} | null> {
  const token = sessionTokenFromRequest(req);
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  const result = await pool.query(
    `SELECT u.id AS user_id, u.slack_user_id, array_agg(DISTINCT r.name) AS roles
     FROM admin_sessions s
     JOIN users u ON u.id = s.user_id
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE s.token_hash = $1
       AND s.workspace_id = $2
       AND s.revoked_at IS NULL
       AND s.expires_at > now()
       AND (ra.workspace_id = $2 OR ra.workspace_id IS NULL)
     GROUP BY u.id, u.slack_user_id`,
    [tokenHash, workspaceId],
  );
  if (!result.rowCount) return null;
  await pool.query("UPDATE admin_sessions SET last_seen_at = now() WHERE token_hash = $1", [tokenHash]);
  return {
    userId: result.rows[0].user_id,
    slackUserId: result.rows[0].slack_user_id,
    roles: result.rows[0].roles ?? [],
  };
}

async function hasRoleAssignments(pool: Database, workspaceId: string): Promise<boolean> {
  const result = await pool.query("SELECT 1 FROM role_assignments WHERE workspace_id = $1 LIMIT 1", [workspaceId]);
  return Boolean(result.rowCount);
}

async function userHasPermission(pool: Database, userId: string, workspaceId: string, requested: { action: string; resource: string }): Promise<boolean> {
  const result = await pool.query(
    `SELECT p.action, p.resource
     FROM role_assignments ra
     JOIN role_permissions rp ON rp.role_id = ra.role_id
     JOIN permissions p ON p.id = rp.permission_id
     WHERE ra.user_id = $1 AND (ra.workspace_id = $2 OR ra.workspace_id IS NULL)`,
    [userId, workspaceId],
  );
  return result.rows.some((permission) => permissionMatches(permission, requested));
}

async function loadSlackUserRoleNames(pool: Queryable, companyId: string, workspaceId: string, slackUserId: string): Promise<string[]> {
  const result = await pool.query(
    `SELECT DISTINCT r.name
     FROM users u
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE u.company_id = $1
       AND u.slack_user_id = $2
       AND (ra.workspace_id = $3 OR ra.workspace_id IS NULL)
     ORDER BY r.name`,
    [companyId, slackUserId, workspaceId],
  );
  return result.rows.map((row) => row.name);
}

async function requirePermissionForWorkspace(
  context: RouteContext,
  workspace: any,
  requested: { action: string; resource: string },
  options: { allowIfNoAssignments?: boolean } = {},
): Promise<{ ok: true; actorUserId: string | null; actorSlackUserId: string | null; roles: string[] } | { ok: false }> {
  const assignmentsExist = await hasRoleAssignments(context.state.pool, workspace.id);
  if (!assignmentsExist && options.allowIfNoAssignments) return { ok: true, actorUserId: null, actorSlackUserId: null, roles: [] };

  const sessionActor = await resolveSessionActor(context.state.pool, context.req, workspace.id);
  if (sessionActor) {
    if (!(await userHasPermission(context.state.pool, sessionActor.userId, workspace.id, requested))) {
      await audit(context.state.pool, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: sessionActor.userId,
        eventType: "rbac.denied",
        resourceType: requested.resource,
        outcome: "deny",
        metadata: { action: requested.action, slackUserId: sessionActor.slackUserId, roles: sessionActor.roles },
      });
      sendJson(context.res, 403, { error: "RBAC denied", requested, roles: sessionActor.roles });
      return { ok: false };
    }
    return { ok: true, actorUserId: sessionActor.userId, actorSlackUserId: sessionActor.slackUserId, roles: sessionActor.roles };
  }

  const slackUserId = actorSlackUserId(context.req);
  if (!slackUserId) {
    sendJson(context.res, 401, { error: "Missing or invalid Operant admin session" });
    return { ok: false };
  }

  const result = await context.state.pool.query(
    `SELECT u.id AS user_id, r.name AS role_name
     FROM users u
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE u.company_id = $1
       AND u.slack_user_id = $2
       AND (ra.workspace_id = $3 OR ra.workspace_id IS NULL)`,
    [workspace.company_id, slackUserId, workspace.id],
  );
  const roles = result.rows.map((row) => row.role_name);
  const actorUserId = result.rows[0]?.user_id;
  if (!actorUserId || !(await userHasPermission(context.state.pool, actorUserId, workspace.id, requested))) {
    await audit(context.state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId,
      eventType: "rbac.denied",
      resourceType: requested.resource,
      outcome: "deny",
      metadata: { action: requested.action, slackUserId, roles },
    });
    sendJson(context.res, 403, { error: "RBAC denied", requested, roles });
    return { ok: false };
  }
  return { ok: true, actorUserId, actorSlackUserId: slackUserId, roles };
}

async function upsertCredential(pool: Queryable, masterKey: Buffer, workspaceId: string, kind: string, label: string, secretRefId: string, plaintext: string, slackUserId: string | null = null): Promise<void> {
  await pool.query(
    `INSERT INTO integration_credentials (workspace_id, kind, label, secret_ref_id, encrypted_value, slack_user_id, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, now())
     ON CONFLICT (workspace_id, secret_ref_id)
     DO UPDATE SET kind = EXCLUDED.kind, label = EXCLUDED.label, encrypted_value = EXCLUDED.encrypted_value, slack_user_id = EXCLUDED.slack_user_id, updated_at = now()`,
    [workspaceId, kind, label, secretRefId, encryptSecret(plaintext, masterKey), slackUserId],
  );
}

async function loadToolPolicies(pool: Queryable, workspaceId: string): Promise<ToolPolicyRecord[]> {
  const result = await pool.query(
    `SELECT tool, action, effect, slack_user_ids, role_names
     FROM tool_policies
     WHERE workspace_id = $1
     ORDER BY tool, action, effect, created_at`,
    [workspaceId],
  );
  return result.rows.map((row): ToolPolicyRecord => ({
    tool: row.tool,
    action: row.action,
    effect: row.effect,
    slackUserIds: row.slack_user_ids ?? [],
    roleNames: row.role_names ?? [],
  }));
}

async function loadPolicy(pool: Queryable, workspaceId: string) {
  const dmUsers = await pool.query(
    `SELECT conditions->'allowedDmUserIds' AS ids
     FROM policy_rules
     WHERE workspace_id = $1 AND name = 'slack-dm-allowlist' AND enabled = true
     ORDER BY priority ASC
     LIMIT 1`,
    [workspaceId],
  );
  const channelRows = await pool.query(
    `SELECT channel_id, name, enabled, require_mention, allowed_user_ids, denied_user_ids
     FROM channel_policies
     WHERE workspace_id = $1
     ORDER BY channel_id`,
    [workspaceId],
  );
  const toolRows = await pool.query(
    `SELECT tool, action, effect, slack_user_ids, role_names
     FROM tool_policies
     WHERE workspace_id = $1
     ORDER BY tool, action, effect, created_at`,
    [workspaceId],
  );
  const approvalRows = await pool.query(
    `SELECT name, action_pattern, resource_pattern, approver_slack_user_ids, min_approvals, enabled
     FROM approval_policies
     WHERE workspace_id = $1
     ORDER BY created_at`,
    [workspaceId],
  );
  return {
    allowedDmUserIds: Array.isArray(dmUsers.rows[0]?.ids) ? dmUsers.rows[0].ids : [],
    channelPolicies: channelRows.rows.map((row): ChannelPolicyRecord => ({
      channelId: row.channel_id,
      name: row.name,
      enabled: row.enabled,
      requireMention: row.require_mention,
      allowedUserIds: row.allowed_user_ids ?? [],
      deniedUserIds: row.denied_user_ids ?? [],
    })),
    toolPolicies: toolRows.rows.map((row): ToolPolicyRecord => ({
      tool: row.tool,
      action: row.action,
      effect: row.effect,
      slackUserIds: row.slack_user_ids ?? [],
      roleNames: row.role_names ?? [],
    })),
    approvalPolicies: approvalRows.rows.map((row): ApprovalPolicyRecord => ({
      name: row.name,
      actionPattern: row.action_pattern,
      resourcePattern: row.resource_pattern,
      approverSlackUserIds: row.approver_slack_user_ids ?? [],
      minApprovals: row.min_approvals,
      enabled: row.enabled,
    })),
  };
}

async function replacePolicy(pool: Queryable, workspaceId: string, input: ReturnType<typeof policyUpdateSchema.parse>): Promise<void> {
  await pool.query(
    `INSERT INTO policy_rules (workspace_id, name, effect, resource, action, conditions, priority, enabled)
     VALUES ($1, 'slack-dm-allowlist', 'allow', 'slack_dm', 'message', $2, 10, true)
     ON CONFLICT (workspace_id, name)
     DO UPDATE SET conditions = EXCLUDED.conditions, enabled = true`,
    [workspaceId, { allowedDmUserIds: input.allowedDmUserIds }],
  );

  await pool.query("DELETE FROM channel_policies WHERE workspace_id = $1", [workspaceId]);
  for (const policy of input.channelPolicies) {
    await pool.query(
      `INSERT INTO channel_policies (workspace_id, channel_id, name, enabled, require_mention, allowed_user_ids, denied_user_ids)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        workspaceId,
        policy.channelId,
        policy.name ?? null,
        policy.enabled,
        policy.requireMention,
        policy.allowedUserIds,
        policy.deniedUserIds,
      ],
    );
  }

  await pool.query("DELETE FROM tool_policies WHERE workspace_id = $1", [workspaceId]);
  for (const policy of input.toolPolicies) {
    await pool.query(
      `INSERT INTO tool_policies (workspace_id, tool, action, effect, slack_user_ids, role_names)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [workspaceId, policy.tool, policy.action, policy.effect, policy.slackUserIds, policy.roleNames],
    );
  }

  await pool.query("DELETE FROM approval_policies WHERE workspace_id = $1", [workspaceId]);
  for (const policy of input.approvalPolicies) {
    await pool.query(
      `INSERT INTO approval_policies (workspace_id, name, action_pattern, resource_pattern, approver_slack_user_ids, min_approvals, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        workspaceId,
        policy.name,
        policy.actionPattern,
        policy.resourcePattern,
        policy.approverSlackUserIds,
        policy.minApprovals,
        policy.enabled,
      ],
    );
  }
}

type GeneratedOpenClawConfig = {
  config: Record<string, unknown>;
  checksum: string;
  configPath: string;
};

function isPathInside(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

async function writeOpenClawResolverWrapper(configPath: string, commandPath: string): Promise<void> {
  const dir = path.dirname(configPath);
  if (!isPathInside(dir, commandPath)) return;

  const body = "#!/bin/sh\nset -eu\nexec /usr/local/bin/node \"$@\"\n";
  const tempPath = path.join(dir, `.${path.basename(commandPath)}.${process.pid}.tmp`);
  await writeFile(tempPath, body, { mode: 0o700 });
  await chmod(tempPath, 0o700);
  await rename(tempPath, commandPath);
  await chmod(commandPath, 0o700);
}

async function writeOpenClawConfigFile(configPath: string, config: Record<string, unknown>, checksum: string): Promise<void> {
  const dir = path.dirname(configPath);
  await mkdir(dir, { recursive: true });
  const tempPath = path.join(dir, `.${path.basename(configPath)}.${process.pid}.${checksum}.tmp`);
  await writeFile(tempPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await chmod(tempPath, 0o600);
  await rename(tempPath, configPath);
  await chmod(configPath, 0o600);
}

function openClawSandboxModeFromEnv(): "off" | "docker" {
  const value = (process.env.OPERANT_OPENCLAW_SANDBOX_MODE || "off").trim().toLowerCase();
  if (value === "" || value === "off" || value === "none" || value === "false" || value === "0") return "off";
  if (value === "docker" || value === "all") return "docker";
  throw new Error("OPERANT_OPENCLAW_SANDBOX_MODE must be off or docker");
}

async function generateAndPersistOpenClawConfig(pool: Queryable, workspaceId: string): Promise<GeneratedOpenClawConfig> {
  const settings = await pool.query("SELECT model_provider, model_name FROM workspace_settings WHERE workspace_id = $1", [workspaceId]);
  const workspace = await pool.query("SELECT openclaw_gateway_url, openclaw_config_path FROM workspaces WHERE id = $1", [workspaceId]);
  const policy = await loadPolicy(pool, workspaceId);
  const configPath = workspace.rows[0]?.openclaw_config_path || process.env.OPENCLAW_CONFIG_PATH || "/operant/openclaw/openclaw.json";
  const configDir = path.dirname(configPath);
  const secretResolverCommand = process.env.OPENCLAW_SECRET_RESOLVER_COMMAND || path.join(configDir, "operant-secret-resolver");
  const secretResolverScript = process.env.OPENCLAW_SECRET_RESOLVER_SCRIPT || path.join(configDir, "operant-secret-resolver.mjs");
  const config = generateOpenClawConfig({
    workspaceId,
    gatewayUrl: workspace.rows[0]?.openclaw_gateway_url ?? process.env.OPENCLAW_GATEWAY_URL ?? "http://openclaw-gateway:18789",
    modelProvider: settings.rows[0]?.model_provider ?? "openai",
    modelName: settings.rows[0]?.model_name ?? "gpt-5",
    sandboxMode: openClawSandboxModeFromEnv(),
    dmAllowFrom: policy.allowedDmUserIds,
    channelPolicies: policy.channelPolicies,
    toolPolicies: policy.toolPolicies,
    approvalPolicies: policy.approvalPolicies,
    secretResolverCommand,
    secretResolverScript,
  });
  const checksum = checksumConfig(config);
  await writeOpenClawResolverWrapper(configPath, secretResolverCommand);
  await writeOpenClawConfigFile(configPath, config, checksum);
  await pool.query(
    `INSERT INTO openclaw_configs (workspace_id, config, config_path, checksum)
     VALUES ($1, $2, $3, $4)`,
    [workspaceId, config, configPath, checksum],
  );
  return { config, checksum, configPath };
}

async function handleBootstrap({ req, res, state }: RouteContext): Promise<void> {
  const rawBody = await readJson(req);
  const adminToken = adminLoginTokenValidation(req, rawBody);
  if (!adminToken.ok) {
    sendJson(res, adminToken.statusCode, { error: adminToken.error });
    return;
  }
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const workspace = await ensureDefaultWorkspace(client);
    await audit(client, {
      companyId: workspace.companyId,
      workspaceId: workspace.workspaceId,
      eventType: "bootstrap.completed",
      resourceType: "workspace",
      resourceId: workspace.workspaceId,
    });
    await client.query("COMMIT");
    sendJson(res, 200, workspace);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleAuthLogin(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const rawBody = await readJson(req);
  const body = z.object({
    slackUserId: slackIdSchema,
    adminLoginToken: z.string().min(1).optional(),
  }).parse(rawBody);
  const adminToken = adminLoginTokenValidation(req, rawBody);
  if (!adminToken.ok) {
    await audit(state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      eventType: "auth.login_denied",
      resourceType: "admin_session",
      outcome: "deny",
      metadata: { slackUserId: body.slackUserId, reason: "admin_login_token" },
    });
    sendJson(res, adminToken.statusCode, { error: adminToken.error });
    return;
  }
  const result = await state.pool.query(
    `SELECT u.id AS user_id, u.slack_user_id, array_agg(DISTINCT r.name) AS roles
     FROM users u
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE u.company_id = $1
       AND u.slack_user_id = $2
       AND (ra.workspace_id = $3 OR ra.workspace_id IS NULL)
     GROUP BY u.id, u.slack_user_id`,
    [workspace.company_id, body.slackUserId, workspace.id],
  );
  if (!result.rowCount) {
    const userCount = await state.pool.query(
      "SELECT COUNT(*)::int AS n FROM users WHERE company_id = $1",
      [workspace.company_id],
    );
    const bootstrapRequired = userCount.rows[0]?.n === 0;
    const code = bootstrapRequired ? "bootstrap_required" : "no_role_assignment";
    await audit(state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      eventType: "auth.login_denied",
      resourceType: "admin_session",
      outcome: "deny",
      metadata: { slackUserId: body.slackUserId, code },
    });
    sendJson(res, 403, {
      error: bootstrapRequired ? "Workspace not bootstrapped" : "No Operant role assignment for Slack user",
      code,
    });
    return;
  }
  const { token, tokenHash } = createSessionToken();
  const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000);
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const session = await client.query(
      `INSERT INTO admin_sessions (user_id, workspace_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)
       RETURNING id, expires_at`,
      [result.rows[0].user_id, workspace.id, tokenHash, expiresAt],
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: result.rows[0].user_id,
      eventType: "auth.login",
      resourceType: "admin_session",
      resourceId: session.rows[0].id,
    });
    await client.query("COMMIT");
    sendJson(res, 200, {
      token,
      sessionId: session.rows[0].id,
      expiresAt: session.rows[0].expires_at,
      user: {
        id: result.rows[0].user_id,
        slackUserId: result.rows[0].slack_user_id,
        roles: result.rows[0].roles ?? [],
      },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleAuthMe(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const actor = await resolveSessionActor(state.pool, context.req, workspace.id);
  if (!actor) {
    sendJson(res, 401, { error: "Missing or invalid Operant admin session" });
    return;
  }
  sendJson(res, 200, { user: actor, workspaceId: workspace.id });
}

async function handleAuthLogout(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const token = sessionTokenFromRequest(req);
  if (token) {
    const client = await state.pool.connect();
    try {
      await client.query("BEGIN");
      const actor = await resolveSessionActor(client, req, workspace.id);
      await client.query("UPDATE admin_sessions SET revoked_at = now() WHERE token_hash = $1", [hashSessionToken(token)]);
      if (actor) {
        await audit(client, {
          companyId: workspace.company_id,
          workspaceId: workspace.id,
          actorUserId: actor.userId,
          eventType: "auth.logout",
          resourceType: "admin_session",
        });
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }
  sendJson(res, 200, { ok: true });
}

async function handleGetSettings(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:read", resource: "workspace" });
  if (!allowed.ok) return;
  const settings = await state.pool.query("SELECT model_provider, model_name, retention_days FROM workspace_settings WHERE workspace_id = $1", [workspace.id]);
  sendJson(res, 200, {
    companyId: workspace.company_id,
    companyName: workspace.company_name,
    workspaceId: workspace.id,
    workspaceName: workspace.name,
    slackTeamId: workspace.slack_team_id,
    openclawGatewayUrl: workspace.openclaw_gateway_url,
    modelProvider: settings.rows[0]?.model_provider ?? "openai",
    modelName: settings.rows[0]?.model_name ?? "gpt-5",
    retentionDays: settings.rows[0]?.retention_days ?? 90,
  });
}

async function handleUpdateSettings(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:update", resource: "workspace" });
  if (!allowed.ok) return;
  const input = workspaceSettingsUpdateSchema.parse(await readJson(req));
  const currentSettings = await state.pool.query("SELECT model_provider, model_name, retention_days FROM workspace_settings WHERE workspace_id = $1", [workspace.id]);
  const modelProvider = input.modelProvider ?? currentSettings.rows[0]?.model_provider ?? "openai";
  const modelName = input.modelName ?? currentSettings.rows[0]?.model_name ?? "gpt-5";
  const retentionDays = input.retentionDays ?? currentSettings.rows[0]?.retention_days ?? 90;

  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    if (input.companyName) {
      await client.query("UPDATE companies SET name = $1 WHERE id = $2", [input.companyName, workspace.company_id]);
    }
    await client.query(
      `UPDATE workspaces
       SET name = $1,
           slack_team_id = $2,
           openclaw_gateway_url = $3
       WHERE id = $4`,
      [
        input.workspaceName ?? workspace.name,
        input.slackTeamId === undefined ? workspace.slack_team_id : input.slackTeamId,
        input.openclawGatewayUrl ?? workspace.openclaw_gateway_url,
        workspace.id,
      ],
    );
    await client.query(
      `UPDATE workspace_settings
       SET model_provider = $1, model_name = $2, retention_days = $3, updated_at = now()
       WHERE workspace_id = $4`,
      [modelProvider, modelName, retentionDays, workspace.id],
    );
    let generated: GeneratedOpenClawConfig | null = null;
    if (input.modelProvider || input.modelName || input.openclawGatewayUrl) {
      generated = await generateAndPersistOpenClawConfig(client, workspace.id);
    }
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "settings.updated",
      resourceType: "workspace",
      resourceId: workspace.id,
      metadata: {
        changed: Object.keys(input),
        configChecksum: generated?.checksum,
      },
    });
    await client.query("COMMIT");
    sendJson(res, 200, {
      ok: true,
      settings: {
        companyName: input.companyName ?? workspace.company_name,
        workspaceName: input.workspaceName ?? workspace.name,
        slackTeamId: input.slackTeamId === undefined ? workspace.slack_team_id : input.slackTeamId,
        openclawGatewayUrl: input.openclawGatewayUrl ?? workspace.openclaw_gateway_url,
        modelProvider,
        modelName,
        retentionDays,
      },
      config: generated ? { checksum: generated.checksum, configPath: generated.configPath } : null,
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleCredentials(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const rawBody = await readJson(req);
  const input = credentialInputSchema.parse(rawBody);
  const workspace = await getWorkspace(state.pool);
  const roleAssignmentsExist = await hasRoleAssignments(state.pool, workspace.id);
  if (!roleAssignmentsExist) {
    const adminToken = adminLoginTokenValidation(req, rawBody);
    if (!adminToken.ok) {
      await audit(state.pool, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        eventType: "credentials.bootstrap_denied",
        resourceType: "workspace",
        outcome: "deny",
        metadata: { reason: "admin_login_token" },
      });
      sendJson(res, adminToken.statusCode, { error: adminToken.error });
      return;
    }
    if (!input.adminSlackUserId) {
      await audit(state.pool, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        eventType: "credentials.bootstrap_denied",
        resourceType: "workspace",
        outcome: "deny",
        metadata: { reason: "owner_slack_user_id" },
      });
      sendJson(res, 400, { error: "First credential setup requires an adminSlackUserId to create the workspace owner" });
      return;
    }
    const missingSecrets = [
      input.slackBotToken ? null : "slackBotToken",
      input.slackAppToken ? null : "slackAppToken",
      input.modelApiKey ? null : "modelApiKey",
    ].filter((name): name is string => name !== null);
    if (missingSecrets.length > 0) {
      await audit(state.pool, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        eventType: "credentials.bootstrap_denied",
        resourceType: "workspace",
        outcome: "deny",
        metadata: { reason: "missing_secrets", missingSecrets },
      });
      sendJson(res, 400, { error: `First credential setup requires ${missingSecrets.join(", ")}` });
      return;
    }
  }
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "credentials:write", resource: "integration" }, { allowIfNoAssignments: true });
  if (!allowed.ok) return;
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const existingApprovalPolicy = await client.query(
      `SELECT approver_slack_user_ids
       FROM approval_policies
       WHERE workspace_id = $1 AND name = 'risky-actions'
       LIMIT 1`,
      [workspace.id],
    );
    const existingApprovalSlackUserIds = Array.isArray(existingApprovalPolicy.rows[0]?.approver_slack_user_ids)
      ? existingApprovalPolicy.rows[0].approver_slack_user_ids
      : [];
    const approvalSlackUserIds = Array.from(new Set([
      ...(input.adminSlackUserId ? [input.adminSlackUserId] : []),
      ...(input.approvalSlackUserIds.length > 0 ? input.approvalSlackUserIds : existingApprovalSlackUserIds),
    ].filter(Boolean)));
    if (approvalSlackUserIds.length === 0) {
      await client.query("ROLLBACK");
      sendJson(res, 400, { error: "At least one approval user is required for the default risky-actions approval policy" });
      return;
    }
    const allowedDmUserIds = Array.from(new Set([
      ...(input.adminSlackUserId ? [input.adminSlackUserId] : []),
      ...input.allowedDmUserIds,
    ].filter(Boolean)));
    if (input.companyName) {
      await client.query("UPDATE companies SET name = $1 WHERE id = $2", [input.companyName, workspace.company_id]);
    }
    await client.query(
      `UPDATE workspaces
       SET name = $1, slack_team_id = COALESCE($2, slack_team_id)
       WHERE id = $3`,
      [input.workspaceName ?? workspace.name, input.slackTeamId ?? null, workspace.id],
    );
    await client.query(
      `UPDATE workspace_settings
       SET model_provider = $1, model_name = $2, updated_at = now()
       WHERE workspace_id = $3`,
      [input.modelProvider, input.modelName, workspace.id],
    );

    if (input.slackBotToken) {
      await upsertCredential(client, state.masterKey, workspace.id, "slack", "Slack bot token", buildSecretRefId(workspace.id, "slack/botToken"), input.slackBotToken);
    }
    if (input.slackAppToken) {
      await upsertCredential(client, state.masterKey, workspace.id, "slack", "Slack app token", buildSecretRefId(workspace.id, "slack/appToken"), input.slackAppToken);
    }
    if (input.modelApiKey) {
      await upsertCredential(
        client,
        state.masterKey,
        workspace.id,
        "model",
        `${input.modelProvider} API key`,
        buildSecretRefId(workspace.id, `models/${input.modelProvider}/apiKey`),
        input.modelApiKey,
      );
    }

    await client.query(
      `INSERT INTO policy_rules (workspace_id, name, effect, resource, action, conditions, priority)
       VALUES ($1, 'slack-dm-allowlist', 'allow', 'slack_dm', 'message', $2, 10)
       ON CONFLICT DO NOTHING`,
      [workspace.id, { allowedDmUserIds }],
    );
    await client.query(
      `UPDATE policy_rules
       SET conditions = $2
       WHERE workspace_id = $1 AND name = 'slack-dm-allowlist'`,
      [workspace.id, { allowedDmUserIds }],
    );

    await client.query("DELETE FROM channel_policies WHERE workspace_id = $1 AND name = 'Credential setup allowlist'", [workspace.id]);
    for (const channelId of input.allowedChannelIds) {
      await client.query(
        `INSERT INTO channel_policies (workspace_id, channel_id, name, enabled, require_mention, allowed_user_ids)
         VALUES ($1, $2, 'Credential setup allowlist', true, true, $3)
         ON CONFLICT (workspace_id, channel_type, channel_id)
         DO UPDATE SET name = COALESCE(channel_policies.name, EXCLUDED.name), enabled = true, require_mention = true, allowed_user_ids = EXCLUDED.allowed_user_ids, updated_at = now()`,
        [workspace.id, channelId, []],
      );
    }

    await client.query(
      `DELETE FROM tool_policies
       WHERE workspace_id = $1
         AND COALESCE(array_length(slack_user_ids, 1), 0) = 0
         AND COALESCE(array_length(role_names, 1), 0) = 0
         AND ((tool = 'slack' AND action IN ('messages', 'reactions', 'pins')) OR (tool = 'exec' AND action = '*'))`,
      [workspace.id],
    );
    await client.query(
      `INSERT INTO tool_policies (workspace_id, tool, action, effect)
       VALUES
         ($1, 'slack', 'messages', 'allow'),
         ($1, 'slack', 'reactions', 'allow'),
         ($1, 'slack', 'pins', 'approval_required'),
         ($1, 'exec', '*', 'approval_required')`,
      [workspace.id],
    );

    await client.query(
      `INSERT INTO approval_policies (workspace_id, name, action_pattern, resource_pattern, approver_slack_user_ids, min_approvals, enabled)
       VALUES ($1, 'risky-actions', 'exec:*', '*', $2, 1, true)
       ON CONFLICT DO NOTHING`,
      [workspace.id, approvalSlackUserIds],
    );
    await client.query(
      `UPDATE approval_policies SET approver_slack_user_ids = $2 WHERE workspace_id = $1 AND name = 'risky-actions'`,
      [workspace.id, approvalSlackUserIds],
    );

    if (input.adminSlackUserId) {
      const user = await client.query(
        `INSERT INTO users (company_id, slack_user_id, name)
         VALUES ($1, $2, 'Workspace Owner')
         ON CONFLICT (company_id, slack_user_id) DO UPDATE SET slack_user_id = EXCLUDED.slack_user_id
         RETURNING id`,
        [workspace.company_id, input.adminSlackUserId],
      );
      await client.query(
        `INSERT INTO role_assignments (role_id, user_id, workspace_id)
         SELECT r.id, $2, $3 FROM roles r WHERE r.company_id = $1 AND r.name = 'owner'
         ON CONFLICT DO NOTHING`,
        [workspace.company_id, user.rows[0].id, workspace.id],
      );
    }

    const generated = await generateAndPersistOpenClawConfig(client, workspace.id);
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      eventType: "credentials.updated",
      resourceType: "workspace",
      resourceId: workspace.id,
      metadata: {
        slackConfigured: true,
        modelProvider: input.modelProvider,
        allowedDmUsers: allowedDmUserIds.length,
        allowedChannels: input.allowedChannelIds.length,
        configChecksum: generated.checksum,
      },
    });
    await client.query("COMMIT");
    sendJson(res, 200, {
      ok: true,
      workspaceId: workspace.id,
      configPath: generated.configPath,
      checksum: generated.checksum,
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleListIntegrationCredentials(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "integrations:read", resource: "integration" });
  if (!allowed.ok) return;
  const result = await state.pool.query(
    `SELECT id, kind, label, secret_ref_id, slack_user_id, created_at, updated_at
     FROM integration_credentials
     WHERE workspace_id = $1
     ORDER BY kind, slack_user_id NULLS FIRST, label, created_at`,
    [workspace.id],
  );
  sendJson(res, 200, { credentials: result.rows });
}

async function handleUpsertIntegrationCredential(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "credentials:write", resource: "integration" });
  if (!allowed.ok) return;
  const input = integrationCredentialInputSchema.parse(await readJson(req));
  const slackUserId = input.slackUserId ?? null;
  const secretRefId = buildSecretRefId(workspace.id, `integrations/${input.kind}/${input.key}`, { slackUserId });
  const baseLabel = `${input.kind}:${input.key}`;
  const label = input.label ?? (slackUserId ? `${baseLabel} (user ${slackUserId})` : baseLabel);
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    await upsertCredential(client, state.masterKey, workspace.id, input.kind, label, secretRefId, input.secretValue, slackUserId);
    const result = await client.query(
      `SELECT id, kind, label, secret_ref_id, slack_user_id, created_at, updated_at
       FROM integration_credentials
       WHERE workspace_id = $1 AND secret_ref_id = $2`,
      [workspace.id, secretRefId],
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "integration_credential.upserted",
      resourceType: "integration_credential",
      resourceId: result.rows[0]?.id,
      metadata: { kind: input.kind, key: input.key, secretRefId, slackUserId },
    });
    await client.query("COMMIT");
    sendJson(res, 200, { credential: result.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleGenerateConfig(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:update", resource: "workspace" });
  if (!allowed.ok) return;
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const generated = await generateAndPersistOpenClawConfig(client, workspace.id);
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "openclaw.config.generated",
      resourceType: "openclaw_config",
      resourceId: generated.checksum,
    });
    await client.query("COMMIT");
    sendJson(res, 200, generated);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleGetConfig(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:read", resource: "workspace" });
  if (!allowed.ok) return;
  const result = await state.pool.query(
    `SELECT config, config_path, checksum, generated_at
     FROM openclaw_configs
     WHERE workspace_id = $1
     ORDER BY generated_at DESC
     LIMIT 1`,
    [workspace.id],
  );
  sendJson(res, result.rowCount ? 200 : 404, result.rows[0] ?? { error: "No generated OpenClaw config yet" });
}

async function handleOpenClawChecksIndex(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:read", resource: "workspace" });
  if (!allowed.ok) return;
  sendJson(res, 200, {
    checks: openClawCheckNames(),
    gatewayUrl: workspace.openclaw_gateway_url,
  });
}

async function handleOpenClawCheck(context: RouteContext): Promise<void> {
  const { res, state, url } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:read", resource: "workspace" });
  if (!allowed.ok) return;
  const check = url.pathname.replace("/api/openclaw/checks/", "");
  if (!isOpenClawCheckName(check)) {
    sendJson(res, 400, { error: "Unsupported OpenClaw check", supported: openClawCheckNames() });
    return;
  }
  const latestConfig = await state.pool.query(
    `SELECT config_path
     FROM openclaw_configs
     WHERE workspace_id = $1
     ORDER BY generated_at DESC
     LIMIT 1`,
    [workspace.id],
  );
  const configPath = latestConfig.rows[0]?.config_path ?? workspace.openclaw_config_path;
  const result = await runOpenClawCheck({
    check,
    configPath,
    gatewayToken: process.env.OPENCLAW_GATEWAY_TOKEN,
    extraEnv: openClawCommandExtraEnv(workspace),
    timeoutMs: Number(process.env.OPENCLAW_CHECK_TIMEOUT_MS || 20_000),
  });
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    eventType: `openclaw.check.${check}`,
    resourceType: "openclaw_check",
    outcome: result.exitCode === 0 ? "success" : "failure",
    metadata: {
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      command: result.command,
      stderr: result.stderr.slice(0, 2000),
    },
  });
  sendJson(res, result.exitCode === 0 ? 200 : 502, result);
}

async function latestPipedreamInvocation(pool: Queryable, workspaceId: string) {
  const result = await pool.query(
    `SELECT created_at, outcome, metadata->>'app' AS app, metadata->>'action' AS action
     FROM audit_logs
     WHERE workspace_id = $1
       AND event_type = 'pipedream.invocation'
     ORDER BY created_at DESC
     LIMIT 1`,
    [workspaceId],
  );
  const row = result.rows[0];
  return row ? {
    timestamp: row.created_at,
    status: row.outcome,
    app: row.app ?? null,
    action: row.action ?? null,
  } : null;
}

async function handlePipedreamDiagnostics(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:read", resource: "workspace" });
  if (!allowed.ok) return;

  const [pluginCommand, oauth, lastInvocation] = await Promise.all([
    runOpenClawCommand(["plugins", "list", "--json"], {
      extraEnv: openClawObservationCommandExtraEnv(workspace),
      timeoutMs: Number(process.env.OPENCLAW_CHECK_TIMEOUT_MS || 20_000),
    }),
    checkPipedreamOAuthHandshake(process.env),
    latestPipedreamInvocation(state.pool, workspace.id),
  ]);
  const plugin = pluginCommand.exitCode === 0
    ? summarizeOperantPluginDiagnostic(pluginCommand.json)
    : { ok: false, status: "unknown" as const, id: "operant" as const };

  sendJson(res, 200, {
    env: buildPipedreamEnvDiagnostics(process.env),
    plugin: {
      ...plugin,
      command: pluginCommand.command,
      exitCode: pluginCommand.exitCode,
      timedOut: pluginCommand.timedOut,
      stderr: pluginCommand.stderr.slice(0, 500),
    },
    oauth,
    lastInvocation,
  });
}

async function persistOpenClawObservations(client: Queryable, workspace: any, statusJson: unknown, sessionsJson: unknown | null, tasksJson: unknown | null, usageCostJson: unknown | null) {
  const status = extractOpenClawStatusObservations(statusJson);
  const sessionRows = sessionsJson ? extractOpenClawSessionsObservations(sessionsJson) : [];
  const sessionsByKey = new Map(status.sessions.map((session) => [session.key, session]));
  for (const session of sessionRows) {
    sessionsByKey.set(session.key, {
      ...sessionsByKey.get(session.key),
      ...session,
      metadata: {
        ...(sessionsByKey.get(session.key)?.metadata ?? {}),
        ...session.metadata,
      },
      usage: session.usage ?? sessionsByKey.get(session.key)?.usage ?? null,
    });
  }
  const observedSessions = Array.from(sessionsByKey.values());
  const tasks = tasksJson ? extractOpenClawTaskObservations(tasksJson) : [];
  const usageCost = usageCostJson ? extractOpenClawUsageCostObservations(usageCostJson) : { snapshots: [], totals: null, cacheStatus: null };
  let sessionsUpserted = 0;
  let usageInserted = 0;
  let usageSkipped = 0;
  let usageCostInserted = 0;
  let usageCostUpdated = 0;
  let usageCostSkipped = 0;
  let jobsUpserted = 0;

  for (const observed of observedSessions) {
    const sessionMetadata = redactRecordForPersistence(observed.metadata);
    const session = await client.query(
      `INSERT INTO sessions (workspace_id, openclaw_session_key, status, last_event_at, metadata)
       VALUES ($1, $2, 'observed', $3, $4)
       ON CONFLICT (workspace_id, openclaw_session_key)
       DO UPDATE SET status = 'observed',
                     last_event_at = GREATEST(sessions.last_event_at, EXCLUDED.last_event_at),
                     metadata = sessions.metadata || EXCLUDED.metadata
       RETURNING id`,
      [workspace.id, observed.key, observed.lastEventAt ?? new Date(), sessionMetadata],
    );
    sessionsUpserted += 1;
    if (observed.runId) {
      const jobMetadata = redactRecordForPersistence({
        source: "openclaw.session",
        openclawSessionKey: observed.key,
        openclawSessionRunId: observed.runId,
        openclawSessionId: observed.metadata.openclawSessionId ?? null,
        model: observed.metadata.model ?? null,
        kind: observed.metadata.kind ?? null,
      });
      const existingJob = await client.query(
        `SELECT id FROM jobs WHERE workspace_id = $1 AND openclaw_run_id = $2 ORDER BY created_at DESC LIMIT 1`,
        [workspace.id, observed.runId],
      );
      if (existingJob.rowCount) {
        await client.query(
          `UPDATE jobs
           SET session_id = COALESCE($2, session_id),
               status = 'observed',
               started_at = COALESCE($3, started_at),
               metadata = jobs.metadata || $4
           WHERE id = $1`,
          [
            existingJob.rows[0].id,
            session.rows[0].id,
            observed.lastEventAt,
            jobMetadata,
          ],
        );
      } else {
        await client.query(
          `INSERT INTO jobs (workspace_id, session_id, openclaw_run_id, status, started_at, metadata)
           VALUES ($1, $2, $3, 'observed', $4, $5)`,
          [
            workspace.id,
            session.rows[0].id,
            observed.runId,
            observed.lastEventAt ?? new Date(),
            jobMetadata,
          ],
        );
      }
      jobsUpserted += 1;
    }
    const usage = observed.usage;
    if (!usage) continue;
    const inputTokens = usageTokenCountSchema.safeParse(usage.inputTokens);
    const outputTokens = usageTokenCountSchema.safeParse(usage.outputTokens);
    if (!inputTokens.success || !outputTokens.success) {
      usageSkipped += 1;
      continue;
    }
    const usageMetadata = redactRecordForPersistence(usage.metadata);
    const updatedAt = String(usageMetadata.updatedAt ?? "");
    const usageSource = String(usageMetadata.source ?? "");
    const existingUsage = await client.query(
      `SELECT 1
       FROM usage_events
       WHERE workspace_id = $1
         AND session_id = $2
         AND metadata->>'source' = $5
         AND metadata->>'openclawSessionKey' = $3
         AND COALESCE(metadata->>'updatedAt', '') = $4
       LIMIT 1`,
      [workspace.id, session.rows[0].id, observed.key, updatedAt, usageSource],
    );
    if (existingUsage.rowCount) continue;
    await client.query(
      `INSERT INTO usage_events (workspace_id, session_id, provider, model, input_tokens, output_tokens, tool_name, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        workspace.id,
        session.rows[0].id,
        usage.provider,
        usage.model,
        inputTokens.data,
        outputTokens.data,
        usage.toolName,
        usageMetadata,
      ],
    );
    usageInserted += 1;
  }

  for (const observed of tasks) {
    const taskMetadata = redactRecordForPersistence(observed.metadata);
    let sessionId: string | null = null;
    if (observed.sessionKey) {
      const session = await client.query(
        `SELECT id FROM sessions WHERE workspace_id = $1 AND openclaw_session_key = $2 LIMIT 1`,
        [workspace.id, observed.sessionKey],
      );
      sessionId = session.rows[0]?.id ?? null;
    }
    const existingJob = await client.query(
      `SELECT id FROM jobs WHERE workspace_id = $1 AND openclaw_run_id = $2 ORDER BY created_at DESC LIMIT 1`,
      [workspace.id, observed.runId],
    );
    if (existingJob.rowCount) {
      await client.query(
        `UPDATE jobs
         SET session_id = COALESCE($2, session_id),
             status = $3,
             started_at = COALESCE($4, started_at),
             finished_at = $5,
             metadata = jobs.metadata || $6
         WHERE id = $1`,
        [
          existingJob.rows[0].id,
          sessionId,
          observed.status,
          observed.startedAt,
          observed.finishedAt,
          taskMetadata,
        ],
      );
    } else {
      await client.query(
        `INSERT INTO jobs (workspace_id, session_id, openclaw_run_id, status, started_at, finished_at, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          workspace.id,
          sessionId,
          observed.runId,
          observed.status,
          observed.startedAt ?? new Date(),
          observed.finishedAt,
          taskMetadata,
        ],
      );
    }
    jobsUpserted += 1;
  }

  for (const snapshot of usageCost.snapshots) {
    const cost = usageCostUsdSchema.safeParse(snapshot.estimatedCostUsd);
    if (!cost.success) {
      usageCostSkipped += 1;
      continue;
    }
    const usageMetadata = redactRecordForPersistence(snapshot.metadata);
    const existingUsageCost = await client.query(
      `SELECT id
       FROM usage_events
       WHERE workspace_id = $1
         AND metadata->>'source' = 'openclaw.usage-cost'
         AND metadata->>'day' = $2
       LIMIT 1`,
      [workspace.id, snapshot.day],
    );
    if (existingUsageCost.rowCount) {
      await client.query(
        `UPDATE usage_events
         SET estimated_cost_usd = $2,
             metadata = usage_events.metadata || $3
         WHERE id = $1`,
        [existingUsageCost.rows[0].id, cost.data, usageMetadata],
      );
      usageCostUpdated += 1;
    } else {
      await client.query(
        `INSERT INTO usage_events (workspace_id, provider, model, input_tokens, output_tokens, tool_name, estimated_cost_usd, metadata)
         VALUES ($1, 'openclaw', 'usage-cost', 0, 0, 'gateway-usage-cost', $2, $3)`,
        [workspace.id, cost.data, usageMetadata],
      );
      usageCostInserted += 1;
    }
  }

  return {
    sessionsSeen: observedSessions.length,
    rawSessionCount: Math.max(status.rawSessionCount, sessionRows.length),
    statusSessionsSeen: status.sessions.length,
    listedSessionsSeen: sessionRows.length,
    sessionsUpserted,
    usageInserted,
    usageSkipped,
    usageCostSnapshotsSeen: usageCost.snapshots.length,
    usageCostInserted,
    usageCostUpdated,
    usageCostSkipped,
    usageCostTotals: usageCost.totals,
    usageCostCacheStatus: usageCost.cacheStatus,
    tasksSeen: tasks.length,
    jobsUpserted,
    taskSummary: status.taskSummary,
  };
}

async function handleSyncOpenClawObservations(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "observability:sync", resource: "openclaw_observation" });
  if (!allowed.ok) return;
  const latestConfig = await state.pool.query(
    `SELECT config_path
     FROM openclaw_configs
     WHERE workspace_id = $1
     ORDER BY generated_at DESC
     LIMIT 1`,
    [workspace.id],
  );
  const configPath = latestConfig.rows[0]?.config_path ?? workspace.openclaw_config_path;
  const commandParams = {
    configPath,
    gatewayToken: process.env.OPENCLAW_GATEWAY_TOKEN,
    extraEnv: openClawObservationCommandExtraEnv(workspace),
    timeoutMs: Number(process.env.OPENCLAW_SYNC_TIMEOUT_MS || 20_000),
  };
  const status = await runOpenClawCheck({ check: "status", ...commandParams });
  if (status.exitCode !== 0 || !status.json) {
    await audit(state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "openclaw.observations.sync",
      resourceType: "openclaw_observation",
      outcome: "failure",
      metadata: { command: status.command, exitCode: status.exitCode, stderr: status.stderr.slice(0, 2000) },
    });
    sendJson(res, 502, { error: "OpenClaw status sync failed", status });
    return;
  }
  const sessions = await runOpenClawCommand(["sessions", "--json"], commandParams);
  const tasks = await runOpenClawCommand(["tasks", "list", "--json"], commandParams);
  const usageCost = await runOpenClawCommand(openClawGatewayCommandArgs(["gateway", "usage-cost", "--json"], commandParams), commandParams);

  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const synced = await persistOpenClawObservations(
      client,
      workspace,
      status.json,
      sessions.exitCode === 0 ? sessions.json : null,
      tasks.exitCode === 0 ? tasks.json : null,
      usageCost.exitCode === 0 ? usageCost.json : null,
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "openclaw.observations.sync",
      resourceType: "openclaw_observation",
      metadata: {
        synced,
        statusCommand: status.command,
        sessionsCommand: sessions.command,
        sessionsExitCode: sessions.exitCode,
        sessionsStderr: sessions.stderr.slice(0, 2000),
        tasksCommand: tasks.command,
        tasksExitCode: tasks.exitCode,
        tasksStderr: tasks.stderr.slice(0, 2000),
        usageCostCommand: usageCost.command,
        usageCostExitCode: usageCost.exitCode,
        usageCostStderr: usageCost.stderr.slice(0, 2000),
      },
    });
    await client.query("COMMIT");
    sendJson(res, 200, {
      ok: true,
      synced,
      status: { command: status.command, exitCode: status.exitCode, timedOut: status.timedOut },
      sessions: { command: sessions.command, exitCode: sessions.exitCode, timedOut: sessions.timedOut, stderr: sessions.stderr.slice(0, 2000) },
      tasks: { command: tasks.command, exitCode: tasks.exitCode, timedOut: tasks.timedOut, stderr: tasks.stderr.slice(0, 2000) },
      usageCost: { command: usageCost.command, exitCode: usageCost.exitCode, timedOut: usageCost.timedOut, stderr: usageCost.stderr.slice(0, 2000) },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handlePolicyEvaluate(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "policy:read", resource: "policy" });
  if (!allowed.ok) return;
  const parsedInput = policyEvaluationSchema.parse(await readJson(req));
  const input = {
    ...parsedInput,
    userRoleNames: await loadSlackUserRoleNames(state.pool, workspace.company_id, workspace.id, parsedInput.slackUserId),
  };
  const policy = await loadPolicy(state.pool, workspace.id);
  const decision = evaluatePolicy(input, policy);
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    eventType: "policy.evaluated",
    resourceType: "policy",
    outcome: decision.effect,
    metadata: { input, decision },
  });
  sendJson(res, 200, decision);
}

async function handleGetPolicy(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "policy:read", resource: "policy" });
  if (!allowed.ok) return;
  sendJson(res, 200, await loadPolicy(state.pool, workspace.id));
}

async function handleUpdatePolicy(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "policy:update", resource: "policy" });
  if (!allowed.ok) return;
  const input = policyUpdateSchema.parse(await readJson(req));
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    await replacePolicy(client, workspace.id, input);
    const generated = await generateAndPersistOpenClawConfig(client, workspace.id);
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "policy.updated",
      resourceType: "policy",
      resourceId: workspace.id,
      metadata: {
        allowedDmUsers: input.allowedDmUserIds.length,
        channelPolicies: input.channelPolicies.length,
        toolPolicies: input.toolPolicies.length,
        approvalPolicies: input.approvalPolicies.length,
        configChecksum: generated.checksum,
      },
    });
    const savedPolicy = await loadPolicy(client, workspace.id);
    await client.query("COMMIT");
    sendJson(res, 200, {
      ok: true,
      policy: savedPolicy,
      config: {
        checksum: generated.checksum,
        configPath: generated.configPath,
      },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleCreateApproval(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "task:create", resource: "openclaw_task" });
  if (!allowed.ok) return;
  const body = z.object({
    action: policyIdentifierSchema,
    resource: policyIdentifierSchema,
    payload: metadataRecordSchema.default({}),
  }).parse(await readJson(req));
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const policy = await loadPolicy(client, workspace.id);
    const approvalRequirement = summarizeApprovalRequirement({ action: body.action, resource: body.resource }, policy);
    if (approvalRequirement.matchedPolicyCount < 1 || approvalRequirement.approverSlackUserIds.length < 1) {
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.request_denied",
        resourceType: "approval",
        outcome: "deny",
        metadata: { action: body.action, resource: body.resource, approvalRequirement },
      });
      await client.query("COMMIT");
      sendJson(res, 409, { error: "No enabled approval policy matched this request", approvalRequirement });
      return;
    }
    const payload = {
      ...redactRecordForPersistence(body.payload),
      operantApproval: approvalRequirement,
    };
    const result = await client.query(
      `INSERT INTO approvals (workspace_id, requested_by_user_id, action, resource, payload)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, workspace_id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at`,
      [workspace.id, allowed.actorUserId, body.action, body.resource, payload],
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "approval.requested",
      resourceType: "approval",
      resourceId: result.rows[0].id,
      metadata: { action: body.action, resource: body.resource, approvalRequirement },
    });
    await client.query("COMMIT");
    sendJson(res, 201, result.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function listRoleCatalog(pool: Database, companyId: string) {
  const result = await pool.query(
    `SELECT r.id, r.name, r.builtin, COALESCE(jsonb_agg(jsonb_build_object('action', p.action, 'resource', p.resource) ORDER BY p.action, p.resource) FILTER (WHERE p.id IS NOT NULL), '[]'::jsonb) AS permissions
     FROM roles r
     LEFT JOIN role_permissions rp ON rp.role_id = r.id
     LEFT JOIN permissions p ON p.id = rp.permission_id
     WHERE r.company_id = $1
     GROUP BY r.id
     ORDER BY r.name`,
    [companyId],
  );
  return result.rows;
}

async function handleListRoles(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "users:read", resource: "user" });
  if (!allowed.ok) return;
  const roles = await listRoleCatalog(state.pool, workspace.company_id);
  sendJson(res, 200, { roles });
}

async function handleUpsertRole(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "users:write", resource: "user" });
  if (!allowed.ok) return;
  const input = customRoleUpsertSchema.parse(await readJson(req));
  if (builtinRoleNames.has(input.name)) {
    sendJson(res, 409, { error: "Built-in roles cannot be overwritten", role: input.name });
    return;
  }

  const permissions = Array.from(
    new Map(input.permissions.map((permission) => [`${permission.action}\0${permission.resource}`, permission])).values(),
  );

  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const permissionRows = await client.query(
      `SELECT p.id, p.action, p.resource
       FROM permissions p
       JOIN jsonb_to_recordset($1::jsonb) AS wanted(action text, resource text)
         ON wanted.action = p.action AND wanted.resource = p.resource`,
      [JSON.stringify(permissions)],
    );
    const foundPermissions = new Set(permissionRows.rows.map((row) => `${row.action}\0${row.resource}`));
    const missingPermissions = permissions.filter((permission) => !foundPermissions.has(`${permission.action}\0${permission.resource}`));
    if (missingPermissions.length > 0) {
      await client.query("ROLLBACK");
      sendJson(res, 400, { error: "Unknown permission(s)", permissions: missingPermissions });
      return;
    }

    const role = await client.query(
      `INSERT INTO roles (company_id, name, builtin)
       VALUES ($1, $2, false)
       ON CONFLICT (company_id, name) DO UPDATE SET name = EXCLUDED.name
       WHERE roles.builtin = false
       RETURNING id`,
      [workspace.company_id, input.name],
    );
    if (!role.rowCount) {
      await client.query("ROLLBACK");
      sendJson(res, 409, { error: "Built-in roles cannot be overwritten", role: input.name });
      return;
    }

    await client.query("DELETE FROM role_permissions WHERE role_id = $1", [role.rows[0].id]);
    for (const permission of permissionRows.rows) {
      await client.query(
        `INSERT INTO role_permissions (role_id, permission_id)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING`,
        [role.rows[0].id, permission.id],
      );
    }

    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "roles.upserted",
      resourceType: "role",
      resourceId: role.rows[0].id,
      metadata: { name: input.name, permissions },
    });
    const saved = await client.query(
      `SELECT r.id, r.name, r.builtin, COALESCE(jsonb_agg(jsonb_build_object('action', p.action, 'resource', p.resource) ORDER BY p.action, p.resource) FILTER (WHERE p.id IS NOT NULL), '[]'::jsonb) AS permissions
       FROM roles r
       LEFT JOIN role_permissions rp ON rp.role_id = r.id
       LEFT JOIN permissions p ON p.id = rp.permission_id
       WHERE r.id = $1
      GROUP BY r.id`,
      [role.rows[0].id],
    );
    await client.query("COMMIT");
    sendJson(res, 200, { role: saved.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleListUsers(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "users:read", resource: "user" });
  if (!allowed.ok) return;
  const result = await state.pool.query(
    `SELECT u.id, u.email, u.name, u.slack_user_id, u.created_at,
            COALESCE(jsonb_agg(DISTINCT r.name) FILTER (WHERE r.id IS NOT NULL), '[]'::jsonb) AS roles
     FROM users u
     LEFT JOIN role_assignments ra ON ra.user_id = u.id AND (ra.workspace_id = $2 OR ra.workspace_id IS NULL)
     LEFT JOIN roles r ON r.id = ra.role_id
     WHERE u.company_id = $1
     GROUP BY u.id
     ORDER BY u.created_at`,
    [workspace.company_id, workspace.id],
  );
  sendJson(res, 200, { users: result.rows });
}

async function countOwners(pool: Queryable, workspaceId: string): Promise<number> {
  const result = await pool.query(
    `SELECT count(DISTINCT u.id)::int AS owners
     FROM users u
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE ra.workspace_id = $1 AND r.name = 'owner'`,
    [workspaceId],
  );
  return result.rows[0]?.owners ?? 0;
}

async function handleUpsertUser(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "users:write", resource: "user" });
  if (!allowed.ok) return;
  const input = userUpsertSchema.parse(await readJson(req));

  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const roleRows = await client.query(
      `SELECT id, name FROM roles WHERE company_id = $1 AND name = ANY($2::text[])`,
      [workspace.company_id, input.roles],
    );
    const foundRoles = new Set(roleRows.rows.map((row) => row.name));
    const missingRoles = input.roles.filter((role) => !foundRoles.has(role));
    if (missingRoles.length > 0) {
      await client.query("ROLLBACK");
      sendJson(res, 400, { error: "Unknown role(s)", roles: missingRoles });
      return;
    }

    const user = await client.query(
      `INSERT INTO users (company_id, slack_user_id, email, name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (company_id, slack_user_id)
       DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name
       RETURNING id, company_id, email, name, slack_user_id, created_at`,
      [workspace.company_id, input.slackUserId, input.email ?? null, input.name ?? null],
    );

    const existingOwner = await client.query(
      `SELECT 1
       FROM role_assignments ra
       JOIN roles r ON r.id = ra.role_id
       WHERE ra.user_id = $1 AND ra.workspace_id = $2 AND r.name = 'owner'
       LIMIT 1`,
      [user.rows[0].id, workspace.id],
    );
    if (existingOwner.rowCount && !input.roles.includes("owner") && (await countOwners(client, workspace.id)) <= 1) {
      await client.query("ROLLBACK");
      sendJson(res, 409, { error: "Cannot remove the last workspace owner" });
      return;
    }

    await client.query("DELETE FROM role_assignments WHERE user_id = $1 AND workspace_id = $2", [user.rows[0].id, workspace.id]);
    for (const role of roleRows.rows) {
      await client.query(
        `INSERT INTO role_assignments (role_id, user_id, workspace_id)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [role.id, user.rows[0].id, workspace.id],
      );
    }
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "users.upserted",
      resourceType: "user",
      resourceId: user.rows[0].id,
      metadata: { slackUserId: input.slackUserId, roles: input.roles },
    });
    await client.query("COMMIT");
    sendJson(res, 200, {
      user: {
        ...user.rows[0],
        roles: input.roles,
      },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleSummary(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "settings:read", resource: "workspace" }, { allowIfNoAssignments: true });
  if (!allowed.ok) return;
  const counts = await state.pool.query(
    `SELECT
       (SELECT count(*)::int FROM integration_credentials WHERE workspace_id = $1) AS credentials,
       (SELECT count(*)::int FROM channel_policies WHERE workspace_id = $1) AS channels,
       (SELECT count(*)::int FROM approvals WHERE workspace_id = $1 AND status = 'pending') AS pending_approvals,
       (SELECT count(*)::int FROM audit_logs WHERE workspace_id = $1) AS audit_events,
       (SELECT count(*)::int FROM usage_events WHERE workspace_id = $1) AS usage_events,
       (SELECT count(*)::int FROM sessions WHERE workspace_id = $1) AS sessions`,
    [workspace.id],
  );
  const latestConfig = await state.pool.query(
    `SELECT checksum, config_path, generated_at
     FROM openclaw_configs
     WHERE workspace_id = $1
     ORDER BY generated_at DESC
     LIMIT 1`,
    [workspace.id],
  );
  sendJson(res, 200, {
    companyId: workspace.company_id,
    companyName: workspace.company_name,
    workspaceId: workspace.id,
    workspaceName: workspace.name,
    slackTeamId: workspace.slack_team_id,
    openclawGatewayUrl: workspace.openclaw_gateway_url,
    counts: counts.rows[0],
    latestConfig: latestConfig.rows[0] ?? null,
    roles: defaultRolePermissions,
  });
}

async function handleSecret({ req, res, url, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const id = decodePathComponent(url.pathname.replace("/internal/openclaw/secrets/", ""));
  if (!id) {
    sendJson(res, 400, { error: "SecretRef id is not valid URL encoding" });
    return;
  }
  const parsed = parseSecretRefId(id);
  if (!parsed) {
    sendJson(res, 400, { error: "SecretRef id must start with workspaces/<workspaceId>/" });
    return;
  }
  const { workspaceId, slackUserId } = parsed;
  const credential = await state.pool.query(
    `SELECT encrypted_value FROM integration_credentials WHERE workspace_id = $1 AND secret_ref_id = $2`,
    [workspaceId, id],
  );
  await audit(state.pool, {
    workspaceId,
    eventType: "integration_credential.resolved",
    resourceType: "integration_credential",
    resourceId: id,
    outcome: credential.rowCount ? "success" : "not_found",
    metadata: { secretRefId: id, slackUserId },
  });
  if (!credential.rowCount) {
    sendJson(res, 404, { error: "Secret not found" });
    return;
  }
  sendJson(res, 200, { value: decryptSecret(credential.rows[0].encrypted_value, state.masterKey) });
}

async function handleOpenClawEvent({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const body = z.object({
    workspaceId: z.string().uuid(),
    sessionKey: openClawEventIdSchema.optional(),
    runId: openClawEventIdSchema.optional(),
    type: openClawEventTypeSchema,
    slackChannelId: openClawSlackIdSchema.optional(),
    slackUserId: openClawSlackIdSchema.optional(),
    usage: z.object({
      provider: openClawUsageLabelSchema.optional(),
      model: openClawUsageLabelSchema.optional(),
      inputTokens: usageTokenCountSchema.default(0),
      outputTokens: usageTokenCountSchema.default(0),
      toolName: openClawUsageLabelSchema.optional(),
      estimatedCostUsd: usageCostUsdSchema.optional(),
    }).optional(),
    metadata: metadataRecordSchema.default({}),
  }).parse(await readJson(req));
  const metadata = redactRecordForPersistence(body.metadata);
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const workspace = await client.query("SELECT id, company_id FROM workspaces WHERE id = $1", [body.workspaceId]);
    if (!workspace.rowCount) {
      await client.query("ROLLBACK");
      sendJson(res, 404, { error: "Workspace not found" });
      return;
    }
    let sessionId: string | null = null;
    if (body.sessionKey) {
      const session = await client.query(
        `INSERT INTO sessions (workspace_id, openclaw_session_key, slack_channel_id, slack_user_id, metadata, last_event_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (workspace_id, openclaw_session_key)
         DO UPDATE SET slack_channel_id = EXCLUDED.slack_channel_id, slack_user_id = EXCLUDED.slack_user_id, metadata = sessions.metadata || EXCLUDED.metadata, last_event_at = now()
         RETURNING id`,
        [body.workspaceId, body.sessionKey, body.slackChannelId ?? null, body.slackUserId ?? null, metadata],
      );
      sessionId = session.rows[0].id;
    }
    let jobId: string | null = null;
    if (body.runId) {
      const job = await client.query(
        `INSERT INTO jobs (workspace_id, session_id, openclaw_run_id, status, metadata)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (workspace_id, openclaw_run_id) WHERE openclaw_run_id IS NOT NULL
         DO UPDATE SET session_id = COALESCE(EXCLUDED.session_id, jobs.session_id),
                       status = EXCLUDED.status,
                       metadata = jobs.metadata || EXCLUDED.metadata
         RETURNING id`,
        [body.workspaceId, sessionId, body.runId, body.type, metadata],
      );
      jobId = job.rows[0].id;
    }
    if (body.usage) {
      await client.query(
        `INSERT INTO usage_events (workspace_id, session_id, job_id, provider, model, input_tokens, output_tokens, tool_name, estimated_cost_usd, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          body.workspaceId,
          sessionId,
          jobId,
          body.usage.provider ?? null,
          body.usage.model ?? null,
          body.usage.inputTokens,
          body.usage.outputTokens,
          body.usage.toolName ?? null,
          body.usage.estimatedCostUsd ?? null,
          metadata,
        ],
      );
    }
    await audit(client, {
      companyId: workspace.rows[0].company_id,
      workspaceId: body.workspaceId,
      eventType: `openclaw.${body.type}`,
      resourceType: "openclaw_event",
      resourceId: body.runId ?? body.sessionKey,
      metadata,
    });
    await client.query("COMMIT");
    sendJson(res, 200, { ok: true, sessionId, jobId });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handlePluginUserContext({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = pluginUserContextRequestSchema.parse(await readJson(req));
  const workspace = await getWorkspace(state.pool);
  const session = await state.pool.query(
    `SELECT slack_user_id FROM sessions
     WHERE workspace_id = $1 AND openclaw_session_key = $2
     LIMIT 1`,
    [workspace.id, input.sessionKey],
  );
  const slackUserId: string | null = session.rows[0]?.slack_user_id ?? null;
  const roles: string[] = slackUserId
    ? await loadSlackUserRoleNames(state.pool, workspace.company_id, workspace.id, slackUserId)
    : [];
  sendJson(res, 200, {
    sessionKey: input.sessionKey,
    workspaceId: workspace.id,
    slackUserId,
    roles,
  });
}

async function handlePluginPolicyCheck({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = pluginPolicyCheckRequestSchema.parse(await readJson(req));
  const workspace = await getWorkspace(state.pool);
  const toolPolicies = await loadToolPolicies(state.pool, workspace.id);
  const decision = evaluateToolOnly({ tool: input.tool, action: input.action }, { toolPolicies });
  if (input.tool.startsWith("pipedream:")) {
    const app = input.tool.slice("pipedream:".length);
    await audit(state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      eventType: "pipedream.invocation",
      resourceType: "pipedream_tool",
      resourceId: `${input.tool}/${input.action}`,
      outcome: decision.effect,
      metadata: {
        app,
        action: input.action,
        tool: input.tool,
        slackUserId: input.slackUserId,
        status: decision.effect,
        reasons: decision.reasons,
      },
    });
  }
  sendJson(res, 200, decision);
}

async function handleUsageSummary(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "usage:read", resource: "usage" });
  if (!allowed.ok) return;

  const totals = await state.pool.query(
    `SELECT count(*)::int AS events,
            COALESCE(sum(input_tokens), 0)::float8 AS input_tokens,
            COALESCE(sum(output_tokens), 0)::float8 AS output_tokens,
            COALESCE(sum(input_tokens + output_tokens), 0)::float8 AS total_tokens,
            COALESCE(sum(estimated_cost_usd), 0)::float8 AS estimated_cost_usd
     FROM usage_events
     WHERE workspace_id = $1`,
    [workspace.id],
  );
  const byModel = await state.pool.query(
    `SELECT COALESCE(provider, 'unknown') AS provider,
            COALESCE(model, 'unknown') AS model,
            count(*)::int AS events,
            COALESCE(sum(input_tokens), 0)::float8 AS input_tokens,
            COALESCE(sum(output_tokens), 0)::float8 AS output_tokens,
            COALESCE(sum(input_tokens + output_tokens), 0)::float8 AS total_tokens,
            COALESCE(sum(estimated_cost_usd), 0)::float8 AS estimated_cost_usd
     FROM usage_events
     WHERE workspace_id = $1
     GROUP BY COALESCE(provider, 'unknown'), COALESCE(model, 'unknown')
     ORDER BY estimated_cost_usd DESC, events DESC, provider, model
     LIMIT 25`,
    [workspace.id],
  );
  const byTool = await state.pool.query(
    `SELECT COALESCE(tool_name, 'model') AS tool_name,
            count(*)::int AS events,
            COALESCE(sum(input_tokens), 0)::float8 AS input_tokens,
            COALESCE(sum(output_tokens), 0)::float8 AS output_tokens,
            COALESCE(sum(input_tokens + output_tokens), 0)::float8 AS total_tokens,
            COALESCE(sum(estimated_cost_usd), 0)::float8 AS estimated_cost_usd
     FROM usage_events
     WHERE workspace_id = $1
     GROUP BY COALESCE(tool_name, 'model')
     ORDER BY estimated_cost_usd DESC, events DESC, tool_name
     LIMIT 25`,
    [workspace.id],
  );
  const byDay = await state.pool.query(
    `SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS day,
            count(*)::int AS events,
            COALESCE(sum(input_tokens), 0)::float8 AS input_tokens,
            COALESCE(sum(output_tokens), 0)::float8 AS output_tokens,
            COALESCE(sum(input_tokens + output_tokens), 0)::float8 AS total_tokens,
            COALESCE(sum(estimated_cost_usd), 0)::float8 AS estimated_cost_usd
     FROM usage_events
     WHERE workspace_id = $1
     GROUP BY date_trunc('day', created_at)
     ORDER BY day DESC
     LIMIT 30`,
    [workspace.id],
  );

  sendJson(res, 200, {
    workspaceId: workspace.id,
    totals: totals.rows[0],
    byModel: byModel.rows,
    byTool: byTool.rows,
    byDay: byDay.rows,
  });
}

const listDefinitions: Record<string, { permission: { action: string; resource: string }; query: string }> = {
  audit_logs: {
    permission: { action: "audit:read", resource: "audit_log" },
    query: `SELECT id, company_id, workspace_id, actor_user_id, event_type, resource_type, resource_id, outcome, metadata, created_at
            FROM audit_logs
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            LIMIT 200`,
  },
  approvals: {
    permission: { action: "approval:read", resource: "approval" },
    query: `SELECT id, workspace_id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at
            FROM approvals
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            LIMIT 100`,
  },
  sessions: {
    permission: { action: "session:read", resource: "session" },
    query: `SELECT id, workspace_id, openclaw_session_key, slack_channel_id, slack_user_id, status, last_event_at, metadata, created_at
            FROM sessions
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            LIMIT 100`,
  },
  jobs: {
    permission: { action: "session:read", resource: "session" },
    query: `SELECT id, workspace_id, session_id, openclaw_run_id, status, started_at, finished_at, metadata, created_at
            FROM jobs
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            LIMIT 100`,
  },
  usage_events: {
    permission: { action: "usage:read", resource: "usage" },
    query: `SELECT id, workspace_id, session_id, job_id, provider, model, input_tokens, output_tokens, tool_name, estimated_cost_usd, metadata, created_at
            FROM usage_events
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            LIMIT 100`,
  },
};

function hasWorkspaceWideListAccess(table: string, roles: string[]): boolean {
  if (roles.includes("owner") || roles.includes("admin")) return true;
  if ((table === "sessions" || table === "jobs") && (roles.includes("viewer") || roles.includes("integration_admin"))) return true;
  return false;
}

function scopedListQuery(
  table: string,
  definition: { query: string },
  workspaceId: string,
  actor: { actorUserId: string | null; actorSlackUserId: string | null; roles: string[] },
): { query: string; params: unknown[] } {
  if (hasWorkspaceWideListAccess(table, actor.roles)) return { query: definition.query, params: [workspaceId] };
  if (table === "sessions" && actor.actorSlackUserId) {
    return {
      query: `SELECT id, workspace_id, openclaw_session_key, slack_channel_id, slack_user_id, status, last_event_at, metadata, created_at
              FROM sessions
              WHERE workspace_id = $1 AND slack_user_id = $2
              ORDER BY created_at DESC
              LIMIT 100`,
      params: [workspaceId, actor.actorSlackUserId],
    };
  }
  if (table === "jobs" && actor.actorSlackUserId) {
    return {
      query: `SELECT j.id, j.workspace_id, j.session_id, j.openclaw_run_id, j.status, j.started_at, j.finished_at, j.metadata, j.created_at
              FROM jobs j
              JOIN sessions s ON s.id = j.session_id AND s.workspace_id = j.workspace_id
              WHERE j.workspace_id = $1 AND s.slack_user_id = $2
              ORDER BY j.created_at DESC
              LIMIT 100`,
      params: [workspaceId, actor.actorSlackUserId],
    };
  }
  if (table === "approvals") {
    return {
      query: `SELECT id, workspace_id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at
              FROM approvals
              WHERE workspace_id = $1
                AND (
                  requested_by_user_id = $2
                  OR COALESCE(payload->'operantApproval'->'approverSlackUserIds', '[]'::jsonb) ? $3
                )
              ORDER BY created_at DESC
              LIMIT 100`,
      params: [workspaceId, actor.actorUserId, actor.actorSlackUserId ?? ""],
    };
  }
  return { query: definition.query, params: [workspaceId] };
}

async function handleList(context: RouteContext, table: string): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const definition = listDefinitions[table];
  if (!definition) {
    sendJson(res, 400, { error: "Unsupported table" });
    return;
  }
  const allowed = await requirePermissionForWorkspace(context, workspace, definition.permission);
  if (!allowed.ok) return;
  const scopedQuery = scopedListQuery(table, definition, workspace.id, allowed);
  const result = await state.pool.query(scopedQuery.query, scopedQuery.params);
  sendJson(res, 200, { items: result.rows });
}

async function handleApprovalDecision(context: RouteContext): Promise<void> {
  const { req, res, url, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "approval:decide", resource: "approval" });
  if (!allowed.ok) return;
  const idResult = z.string().uuid().safeParse(url.pathname.split("/")[3]);
  if (!idResult.success) {
    sendJson(res, 400, { error: "Invalid approval id" });
    return;
  }
  const id = idResult.data;
  const body = z.object({ status: z.enum(["approved", "denied"]) }).parse(await readJson(req));
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const pending = await client.query(
      `SELECT payload
       FROM approvals
       WHERE id = $1 AND workspace_id = $2 AND status = 'pending'
       LIMIT 1
       FOR UPDATE`,
      [id, workspace.id],
    );
    if (!pending.rowCount) {
      await client.query("COMMIT");
      sendJson(res, 404, { error: "Pending approval not found" });
      return;
    }
    const approvalRequirement = pending.rows[0]?.payload?.operantApproval ?? {};
    const requiredApprovers = Array.isArray(approvalRequirement.approverSlackUserIds)
      ? Array.from(new Set(approvalRequirement.approverSlackUserIds.filter((value: unknown): value is string => typeof value === "string" && value.length > 0)))
      : [];
    const minApprovals = Math.max(1, Number.isInteger(Number(approvalRequirement.minApprovals)) ? Number(approvalRequirement.minApprovals) : 1);
    const actorSlackUserId = allowed.actorSlackUserId;
    if (requiredApprovers.length < 1 || minApprovals > requiredApprovers.length) {
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.decision_denied",
        resourceType: "approval",
        resourceId: id,
        outcome: "deny",
        metadata: { reason: "invalid_approval_requirement", requiredApprovers, minApprovals, actorSlackUserId },
      });
      await client.query("COMMIT");
      sendJson(res, 409, { error: "Approval is missing a valid configured approver requirement", requiredApprovers, minApprovals });
      return;
    }
    if (!actorSlackUserId || !requiredApprovers.includes(actorSlackUserId)) {
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.decision_denied",
        resourceType: "approval",
        resourceId: id,
        outcome: "deny",
        metadata: { requiredApprovers, actorSlackUserId },
      });
      await client.query("COMMIT");
      sendJson(res, 403, { error: "Approval decision requires a configured approver", requiredApprovers });
      return;
    }
    const existingDecision = await client.query(
      `SELECT status
       FROM approval_decisions
       WHERE approval_id = $1 AND workspace_id = $2 AND decided_by_user_id = $3
       LIMIT 1`,
      [id, workspace.id, allowed.actorUserId],
    );
    if (existingDecision.rowCount) {
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.decision_denied",
        resourceType: "approval",
        resourceId: id,
        outcome: "deny",
        metadata: { reason: "duplicate_decision", existingStatus: existingDecision.rows[0].status, actorSlackUserId },
      });
      await client.query("COMMIT");
      sendJson(res, 409, { error: "Approval decision already recorded", status: existingDecision.rows[0].status });
      return;
    }

    await client.query(
      `INSERT INTO approval_decisions (workspace_id, approval_id, decided_by_user_id, status)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (approval_id, decided_by_user_id)
       DO NOTHING`,
      [workspace.id, id, allowed.actorUserId, body.status],
    );

    if (body.status === "denied") {
      const result = await client.query(
        `UPDATE approvals
         SET status = 'denied', decided_by_user_id = $3, decided_at = now()
         WHERE id = $1 AND workspace_id = $2 AND status = 'pending'
         RETURNING id, workspace_id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at`,
        [id, workspace.id, allowed.actorUserId],
      );
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.denied",
        resourceType: "approval",
        resourceId: id,
      });
      await client.query("COMMIT");
      sendJson(res, 200, {
        ...result.rows[0],
        approvalDecision: { status: "denied", approvalsReceived: 0, minApprovals },
      });
      return;
    }

    const approvedDecisions = await client.query(
      `SELECT count(DISTINCT decided_by_user_id)::int AS approvals_received
       FROM approval_decisions
       WHERE approval_id = $1 AND workspace_id = $2 AND status = 'approved'`,
      [id, workspace.id],
    );
    const approvalsReceived = approvedDecisions.rows[0]?.approvals_received ?? 0;
    let result;
    if (approvalsReceived >= minApprovals) {
      result = await client.query(
        `UPDATE approvals
         SET status = 'approved', decided_by_user_id = $3, decided_at = now()
         WHERE id = $1 AND workspace_id = $2 AND status = 'pending'
         RETURNING id, workspace_id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at`,
        [id, workspace.id, allowed.actorUserId],
      );
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.approved",
        resourceType: "approval",
        resourceId: id,
        metadata: { approvalsReceived, minApprovals, actorSlackUserId },
      });
    } else {
      result = await client.query(
        `SELECT id, workspace_id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at
         FROM approvals
         WHERE id = $1 AND workspace_id = $2 AND status = 'pending'
         LIMIT 1`,
        [id, workspace.id],
      );
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.approval_recorded",
        resourceType: "approval",
        resourceId: id,
        metadata: { approvalsReceived, minApprovals, actorSlackUserId },
      });
    }
    await client.query("COMMIT");
    sendJson(res, 200, {
      ...result.rows[0],
      approvalDecision: { status: "approved", approvalsReceived, minApprovals },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleExport(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "data:export", resource: "retention" });
  if (!allowed.ok) return;
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const payload = await buildRetentionExport(client, workspace);
    const result = await client.query(
      `INSERT INTO retention_exports (workspace_id, status, requested_by_user_id, payload, completed_at)
       VALUES ($1, 'complete', $2, $3, now())
       RETURNING id, workspace_id, status, requested_by_user_id, payload, completed_at, error, created_at`,
      [workspace.id, allowed.actorUserId, payload],
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "retention.export_completed",
      resourceType: "retention_export",
      resourceId: result.rows[0].id,
      metadata: { counts: payload.counts },
    });
    await client.query("COMMIT");
    sendJson(res, 200, result.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleWipe(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "data:wipe", resource: "retention" });
  if (!allowed.ok) return;
  const body = z.object({ scope: z.enum(retentionWipeScopes) }).parse(await readJson(req));
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const request = await client.query(
      `INSERT INTO wipe_requests (workspace_id, status, requested_by_user_id, scope, payload)
       VALUES ($1, 'processing', $2, $3, '{}')
       RETURNING id, workspace_id, status, requested_by_user_id, scope, payload, completed_at, error, created_at`,
      [workspace.id, allowed.actorUserId, body.scope],
    );
    const deleted = await applyRetentionWipe(client, workspace.id, body.scope);
    const updated = await client.query(
      `UPDATE wipe_requests
       SET status = 'complete', payload = $2, completed_at = now()
       WHERE id = $1
      RETURNING id, workspace_id, status, requested_by_user_id, scope, payload, completed_at, error, created_at`,
      [request.rows[0].id, { deleted }],
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "retention.wipe_completed",
      resourceType: "wipe_request",
      resourceId: updated.rows[0].id,
      metadata: { scope: body.scope, deleted },
    });
    await client.query("COMMIT");
    sendJson(res, 200, updated.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleRetentionPurge(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "data:wipe", resource: "retention" });
  if (!allowed.ok) return;
  const settings = await state.pool.query("SELECT retention_days FROM workspace_settings WHERE workspace_id = $1", [workspace.id]);
  const retentionDays = settings.rows[0]?.retention_days ?? 90;
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const result = await applyRetentionPurge(client, workspace.id, retentionDays);
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      eventType: "retention.purge_completed",
      resourceType: "retention",
      resourceId: workspace.id,
      metadata: { retentionDays, cutoff: result.cutoff, deleted: result.deleted },
    });
    await client.query("COMMIT");
    sendJson(res, 200, {
      ok: true,
      retentionDays,
      cutoff: result.cutoff,
      deleted: result.deleted,
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

export function isPathInsideDirectory(target: string, directory: string): boolean {
  const relative = path.relative(directory, target);
  return relative === "" || (relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative));
}

async function serveStatic(res: ServerResponse, requestPath: string): Promise<void> {
  const safePath = requestPath === "/" ? "/index.html" : requestPath;
  const target = path.resolve(publicDir, `.${safePath}`);
  if (!isPathInsideDirectory(target, publicDir)) {
    sendText(res, 403, "Forbidden");
    return;
  }
  try {
    const body = await readFile(target);
    const ext = path.extname(target);
    const contentType = ext === ".html"
      ? "text/html; charset=utf-8"
      : ext === ".css"
        ? "text/css; charset=utf-8"
        : ext === ".svg"
          ? "image/svg+xml; charset=utf-8"
          : "application/javascript; charset=utf-8";
    res.writeHead(200, responseHeaders(contentType));
    res.end(body);
  } catch {
    sendText(res, 404, "Not found");
  }
}

async function route(context: RouteContext): Promise<void> {
  const { req, res, url, state } = context;
  if (req.method === "GET" && url.pathname === "/healthz") {
    sendJson(res, 200, { ok: true, service: "operant-policy-audit" });
    return;
  }
  if (req.method === "GET" && url.pathname === "/readyz") {
    await state.pool.query("SELECT 1");
    sendJson(res, 200, { ok: true });
    return;
  }
  if (req.method === "POST" && url.pathname === "/api/bootstrap") return handleBootstrap(context);
  if (req.method === "POST" && url.pathname === "/api/auth/login") return handleAuthLogin(context);
  if (req.method === "GET" && url.pathname === "/api/auth/me") return handleAuthMe(context);
  if (req.method === "POST" && url.pathname === "/api/auth/logout") return handleAuthLogout(context);
  if (req.method === "GET" && url.pathname === "/api/settings") return handleGetSettings(context);
  if (req.method === "PUT" && url.pathname === "/api/settings") return handleUpdateSettings(context);
  if (req.method === "GET" && url.pathname === "/api/summary") return handleSummary(context);
  if (req.method === "POST" && url.pathname === "/api/config/credentials") return handleCredentials(context);
  if (req.method === "GET" && url.pathname === "/api/integrations/credentials") return handleListIntegrationCredentials(context);
  if (req.method === "POST" && url.pathname === "/api/integrations/credentials") return handleUpsertIntegrationCredential(context);
  if (req.method === "POST" && url.pathname === "/api/openclaw/config") return handleGenerateConfig(context);
  if (req.method === "GET" && url.pathname === "/api/openclaw/config") return handleGetConfig(context);
  if (req.method === "GET" && url.pathname === "/api/openclaw/checks") return handleOpenClawChecksIndex(context);
  if (req.method === "POST" && url.pathname === "/api/openclaw/observations/sync") return handleSyncOpenClawObservations(context);
  if (req.method === "POST" && url.pathname.startsWith("/api/openclaw/checks/")) return handleOpenClawCheck(context);
  if (req.method === "GET" && url.pathname === "/api/pipedream/diagnostics") return handlePipedreamDiagnostics(context);
  if (req.method === "GET" && url.pathname === "/api/policy") return handleGetPolicy(context);
  if (req.method === "PUT" && url.pathname === "/api/policy") return handleUpdatePolicy(context);
  if (req.method === "POST" && url.pathname === "/api/policies") return handleUpdatePolicy(context);
  if (req.method === "POST" && url.pathname === "/api/policy/evaluate") return handlePolicyEvaluate(context);
  if (req.method === "GET" && url.pathname === "/api/roles") return handleListRoles(context);
  if (req.method === "POST" && url.pathname === "/api/roles") return handleUpsertRole(context);
  if (req.method === "GET" && url.pathname === "/api/users") return handleListUsers(context);
  if (req.method === "POST" && url.pathname === "/api/users") return handleUpsertUser(context);
  if (req.method === "GET" && url.pathname === "/api/audit") return handleList(context, "audit_logs");
  if (req.method === "GET" && url.pathname === "/api/approvals") return handleList(context, "approvals");
  if (req.method === "POST" && url.pathname === "/api/approvals") return handleCreateApproval(context);
  if (req.method === "POST" && /^\/api\/approvals\/[^/]+\/decision$/.test(url.pathname)) return handleApprovalDecision(context);
  if (req.method === "GET" && url.pathname === "/api/sessions") return handleList(context, "sessions");
  if (req.method === "GET" && url.pathname === "/api/jobs") return handleList(context, "jobs");
  if (req.method === "GET" && url.pathname === "/api/usage/summary") return handleUsageSummary(context);
  if (req.method === "GET" && url.pathname === "/api/usage") return handleList(context, "usage_events");
  if (req.method === "POST" && url.pathname === "/api/export") return handleExport(context);
  if (req.method === "POST" && url.pathname === "/api/retention/purge") return handleRetentionPurge(context);
  if (req.method === "POST" && url.pathname === "/api/wipe") return handleWipe(context);
  if (req.method === "GET" && url.pathname.startsWith("/internal/openclaw/secrets/")) return handleSecret(context);
  if (req.method === "POST" && url.pathname === "/internal/openclaw/events") return handleOpenClawEvent(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/user-context") return handlePluginUserContext(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/policy-check") return handlePluginPolicyCheck(context);
  if (req.method === "GET") return serveStatic(res, url.pathname);
  sendJson(res, 404, { error: "Not found" });
}

export function createHttpServer(state: ServerState) {
  return createServer((req, res) => {
    const host = req.headers.host ?? "localhost";
    const url = new URL(req.url ?? "/", `http://${host}`);
    route({ req, res, url, state }).catch((error: unknown) => {
      if (error instanceof JsonBodyTooLargeError) {
        sendJson(res, 413, { error: error.message });
        return;
      }
      if (error instanceof InvalidJsonBodyError) {
        sendJson(res, 400, { error: error.message });
        return;
      }
      if (error instanceof ZodError) {
        sendJson(res, 400, {
          error: "Invalid request",
          issues: error.issues.map((issue) => ({
            code: issue.code,
            path: issue.path,
            message: issue.message,
          })),
        });
        return;
      }
      const message = error instanceof Error ? error.message : "Unknown error";
      sendJson(res, 500, { error: message });
    });
  });
}

export async function createApp() {
  const pool = createPool();
  await runMigrations(pool);
  await ensureDefaultWorkspace(pool);
  const masterKey = parseMasterKey(process.env.OPERANT_SECRET_KEY);
  return createHttpServer({ pool, masterKey });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const host = process.env.OPERANT_HOST || "127.0.0.1";
  const port = Number(process.env.OPERANT_PORT || 8080);
  const server = await createApp();
  server.listen(port, host, () => {
    process.stdout.write(`Operant policy-audit listening on http://${host}:${port}\n`);
  });
}
