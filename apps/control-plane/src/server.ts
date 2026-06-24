import { createHash, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z, ZodError } from "zod";
import { createSessionToken, hashSessionToken, readBearerToken } from "./auth.js";
import { createRateLimiter } from "./rate-limit.js";
import { createPool, runMigrations, type Database } from "./db.js";
import { checksumConfig, generateOpenClawConfig, buildSecretRefId, gatewayWebSocketUrl, parseSecretRefId } from "./openclaw-config.js";
import {
  cronAddArgs,
  cronControlArgs,
  cronListArgs,
  extractCronJobId,
  extractOpenClawCronObservations,
  extractOpenClawSessionsObservations,
  extractOpenClawStatusObservations,
  extractOpenClawTaskObservations,
  extractOpenClawUsageCostObservations,
  isOpenClawCheckName,
  openClawCheckNames,
  openClawGatewayCommandArgs,
  runOpenClawCheck,
  runOpenClawCommand,
  type CronJobSpec,
} from "./openclaw-ops.js";
import { evaluatePolicy, evaluateToolOnly, summarizeApprovalRequirement } from "./policy.js";
import { createPipedreamConnectClientFromEnv, type PipedreamConnectClient } from "./pipedream.js";
import { defaultRolePermissions, permissionMatches } from "./rbac.js";
import { redactRecordForPersistence } from "./redaction.js";
import { applyRetentionPurge, applyRetentionWipe, buildRetentionExport, retentionWipeScopes } from "./retention.js";
import { decryptSecret, encryptSecret, parseMasterKey } from "./secrets.js";
import {
  chatPlatforms,
  chatPrincipalIdSchema,
  credentialInputSchema,
  customRoleUpsertSchema,
  integrationCredentialInputSchema,
  memoryEntryWriteSchema,
  memorySearchSchema,
  metadataRecordSchema,
  pluginMemorySearchSchema,
  pluginMemoryWriteSchema,
  pluginPolicyCheckRequestSchema,
  pluginSkillSearchSchema,
  pluginUserContextRequestSchema,
  scheduledWorkflowApplySchema,
  scheduledWorkflowCreateSchema,
  skillSearchSchema,
  skillWriteSchema,
  policyIdentifierSchema,
  policyUpdateSchema,
  policyEvaluationSchema,
  roleNames,
  slackIdSchema,
  teamsAadUserIdSchema,
  usageCostUsdSchema,
  usageTokenCountSchema,
  workspaceSettingsUpdateSchema,
  userUpsertSchema,
  type ApprovalPolicyRecord,
  type ChannelPolicyRecord,
  type ChatPlatform,
  type MemoryVisibility,
  type ToolPolicyRecord,
} from "./schema.js";
import { ensureDefaultWorkspace } from "./seed.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, "../../public");
const builtinRoleNames = new Set<string>(roleNames);
const openClawEventTypeSchema = z.string().min(1).max(80).regex(/^[a-z][a-z0-9_.:-]*$/);
const openClawEventIdSchema = z.string().min(1).max(512);
const openClawSlackIdSchema = z.string().min(1).max(120);
const openClawChatIdSchema = z.string().min(1).max(256);
const openClawUsageLabelSchema = z.string().min(1).max(160);
const maxJsonBodyBytes = 1024 * 1024;
const pipedreamOAuthTokenUrl = "https://api.pipedream.com/v1/oauth/token";
const pipedreamDiagnosticsTimeoutMs = Number(process.env.PIPEDREAM_DIAGNOSTICS_TIMEOUT_MS || 8_000);
const pipedreamAppSlugSchema = z.string().min(1).max(120).regex(/^[A-Za-z0-9_.-]+$/);
const pipedreamAccountIdSchema = z.string().min(1).max(180).regex(/^[A-Za-z0-9_.:-]+$/);

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

function sendJson(res: ServerResponse, statusCode: number, payload: unknown, extraHeaders?: Record<string, string>): void {
  res.writeHead(statusCode, { ...responseHeaders("application/json; charset=utf-8"), ...extraHeaders });
  res.end(JSON.stringify(payload, null, 2));
}

// Throttle failed admin-login attempts per client IP to blunt brute-forcing of
// OPERANT_ADMIN_LOGIN_TOKEN. Counts only failures; a successful login resets.
const authRateLimit = createRateLimiter({ maxFailures: 10, windowMs: 15 * 60 * 1000 });

// Immediate TCP peer. X-Forwarded-For is not trusted by default (spoofable);
// behind a reverse proxy this collapses to the proxy address, which still
// bounds the brute-force rate.
function clientIp(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? "unknown";
}

// Sends 429 (+ Retry-After) and audits a deny when the IP is over the failed-auth
// limit. Returns true when throttled so callers can `if (...) return;`.
async function enforceAuthRateLimit(
  context: RouteContext,
  workspace: { id: string; company_id: string },
  ip: string,
  fields: { eventType: string; resourceType: string; error: string },
): Promise<boolean> {
  const limited = authRateLimit.isLimited(ip);
  if (!limited.limited) return false;
  await audit(context.state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    eventType: fields.eventType,
    resourceType: fields.resourceType,
    outcome: "deny",
    metadata: { ip },
  });
  sendJson(context.res, 429, { error: fields.error }, { "retry-after": String(limited.retryAfterSeconds) });
  return true;
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
    `SELECT w.id, w.company_id, w.name, w.slack_team_id, w.teams_app_id, w.teams_tenant_id,
            w.msteams_webhook_port, w.msteams_webhook_path,
            w.openclaw_gateway_url, w.openclaw_config_path, w.created_at, c.name AS company_name
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
  actorSlackUserId?: string | null;
  actorTeamsAadUserId?: string | null;
  eventType: string;
  resourceType: string;
  resourceId?: string;
  outcome?: string;
  metadata?: Record<string, unknown>;
}) {
  await pool.query(
    `INSERT INTO audit_logs (company_id, workspace_id, actor_user_id, actor_slack_user_id, actor_teams_aad_user_id, event_type, resource_type, resource_id, outcome, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      input.companyId ?? null,
      input.workspaceId ?? null,
      input.actorUserId ?? null,
      input.actorSlackUserId ?? null,
      input.actorTeamsAadUserId ?? null,
      input.eventType,
      input.resourceType,
      input.resourceId ?? null,
      input.outcome ?? "success",
      redactRecordForPersistence(input.metadata ?? {}),
    ],
  );
}

// The plugin sends the active chat user's raw principal id; resolve which platform it
// belongs to by shape (Teams AAD ids are UUIDs, Slack ids are not) so policy and audit
// attribute it correctly instead of treating every principal as a Slack user.
function resolvePluginPrincipal(rawId: string | null | undefined): ChatPrincipal | null {
  if (!rawId) return null;
  const teams = teamsAadUserIdSchema.safeParse(rawId);
  if (teams.success) return { platform: "msteams", principalId: teams.data };
  const slack = slackIdSchema.safeParse(rawId);
  if (slack.success) return { platform: "slack", principalId: slack.data };
  return null;
}

function principalAuditIds(principal: ChatPrincipal | null): { actorSlackUserId: string | null; actorTeamsAadUserId: string | null } {
  return {
    actorSlackUserId: principal?.platform === "slack" ? principal.principalId : null,
    actorTeamsAadUserId: principal?.platform === "msteams" ? principal.principalId : null,
  };
}

function principalToolPolicyInput(principal: ChatPrincipal | null, userRoleNames: string[]) {
  const ids = principalAuditIds(principal);
  return {
    platform: principal?.platform ?? "slack",
    slackUserId: ids.actorSlackUserId,
    teamsAadUserId: ids.actorTeamsAadUserId,
    userRoleNames,
  };
}

async function loadPrincipalToolContext(
  pool: Database,
  workspace: { id: string; company_id: string },
  principal: ChatPrincipal | null,
): Promise<{ toolPolicies: ToolPolicyRecord[]; roleNames: string[] }> {
  const [toolPolicies, roleNames] = await Promise.all([
    loadToolPolicies(pool, workspace.id),
    principal
      ? loadChatPrincipalRoleNames(pool, workspace.company_id, workspace.id, principal.platform, principal.principalId)
      : Promise.resolve<string[]>([]),
  ]);
  return { toolPolicies, roleNames };
}

type ChatPrincipal = {
  platform: ChatPlatform;
  principalId: string;
};

function actorChatPrincipal(req: IncomingMessage): ChatPrincipal | null {
  if (process.env.OPERANT_ALLOW_HEADER_AUTH !== "true") return null;
  const platformHeader = req.headers["x-operant-chat-platform"];
  const platformValue = Array.isArray(platformHeader) ? platformHeader[0] : platformHeader;
  const trimmedPlatform = platformValue?.trim().toLowerCase() ?? "slack";
  const platformParse = z.enum(chatPlatforms).safeParse(trimmedPlatform);
  const platform: ChatPlatform = platformParse.success ? platformParse.data : "slack";
  const principalHeader = req.headers["x-operant-principal-id"]
    ?? (platform === "slack" ? req.headers["x-operant-slack-user-id"] ?? req.headers["x-operant-user-id"] : req.headers["x-operant-teams-aad-user-id"]);
  const value = Array.isArray(principalHeader) ? principalHeader[0] : principalHeader;
  const trimmed = value?.trim() || "";
  if (platform === "slack") {
    const parsed = slackIdSchema.safeParse(trimmed);
    return parsed.success ? { platform, principalId: parsed.data } : null;
  }
  const teamsParse = teamsAadUserIdSchema.safeParse(trimmed);
  return teamsParse.success ? { platform, principalId: teamsParse.data } : null;
}

function actorChatPrincipals(slackUserId: string | null, teamsAadUserId: string | null): ChatPrincipal[] {
  const principals: ChatPrincipal[] = [];
  if (slackUserId) principals.push({ platform: "slack", principalId: slackUserId });
  if (teamsAadUserId) principals.push({ platform: "msteams", principalId: teamsAadUserId });
  return principals;
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

// Validates the admin login token while keeping the per-IP brute-force counter
// in sync: records a failure on a wrong (401) token and clears it on success.
// handleAuthLogin manages the counter itself because it defers the reset past
// its no-role-assignment branches.
function validateAdminLoginTokenThrottled(req: IncomingMessage, payload: unknown, ip: string): { ok: true } | { ok: false; statusCode: number; error: string } {
  const result = adminLoginTokenValidation(req, payload);
  if (!result.ok) {
    if (result.statusCode === 401) authRateLimit.recordFailure(ip);
  } else {
    authRateLimit.reset(ip);
  }
  return result;
}

function decodePathComponent(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

type SessionActor = {
  userId: string;
  slackUserId: string | null;
  teamsAadUserId: string | null;
  chatPlatform: ChatPlatform | null;
  principalId: string | null;
  chatPrincipals: ChatPrincipal[];
  roles: string[];
};

async function resolveSessionActor(pool: Queryable, req: IncomingMessage, workspaceId: string): Promise<SessionActor | null> {
  const token = sessionTokenFromRequest(req);
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  const result = await pool.query(
    `SELECT u.id AS user_id, u.slack_user_id, u.teams_aad_user_id, s.principal_platform, array_agg(DISTINCT r.name) AS roles
     FROM admin_sessions s
     JOIN users u ON u.id = s.user_id
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE s.token_hash = $1
       AND s.workspace_id = $2
       AND s.revoked_at IS NULL
       AND s.expires_at > now()
       AND (ra.workspace_id = $2 OR ra.workspace_id IS NULL)
     GROUP BY u.id, u.slack_user_id, u.teams_aad_user_id, s.principal_platform`,
    [tokenHash, workspaceId],
  );
  if (!result.rowCount) return null;
  await pool.query("UPDATE admin_sessions SET last_seen_at = now() WHERE token_hash = $1", [tokenHash]);
  const row = result.rows[0];
  const principals = actorChatPrincipals(row.slack_user_id, row.teams_aad_user_id);
  const sessionPlatform: ChatPlatform | null = row.principal_platform === "msteams" || row.principal_platform === "slack"
    ? row.principal_platform
    : principals[0]?.platform ?? null;
  const primaryPrincipal = principals.find((p) => p.platform === sessionPlatform) ?? principals[0] ?? null;
  return {
    userId: row.user_id,
    slackUserId: row.slack_user_id,
    teamsAadUserId: row.teams_aad_user_id,
    chatPlatform: primaryPrincipal?.platform ?? null,
    principalId: primaryPrincipal?.principalId ?? null,
    chatPrincipals: principals,
    roles: row.roles ?? [],
  };
}

async function hasRoleAssignments(pool: Database, workspaceId: string): Promise<boolean> {
  const result = await pool.query("SELECT 1 FROM role_assignments WHERE workspace_id = $1 LIMIT 1", [workspaceId]);
  return Boolean(result.rowCount);
}

async function getUserPermissions(pool: Database, userId: string, workspaceId: string): Promise<Array<{ action: string; resource: string }>> {
  const result = await pool.query(
    `SELECT p.action, p.resource
     FROM role_assignments ra
     JOIN role_permissions rp ON rp.role_id = ra.role_id
     JOIN permissions p ON p.id = rp.permission_id
     WHERE ra.user_id = $1 AND (ra.workspace_id = $2 OR ra.workspace_id IS NULL)`,
    [userId, workspaceId],
  );
  return result.rows;
}

async function userHasPermission(pool: Database, userId: string, workspaceId: string, requested: { action: string; resource: string }): Promise<boolean> {
  const granted = await getUserPermissions(pool, userId, workspaceId);
  return granted.some((permission) => permissionMatches(permission, requested));
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

async function loadChatPrincipalRoleNames(pool: Queryable, companyId: string, workspaceId: string, platform: ChatPlatform, principalId: string): Promise<string[]> {
  if (platform === "slack") return loadSlackUserRoleNames(pool, companyId, workspaceId, principalId);
  const result = await pool.query(
    `SELECT DISTINCT r.name
     FROM users u
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE u.company_id = $1
       AND u.teams_aad_user_id = $2
       AND (ra.workspace_id = $3 OR ra.workspace_id IS NULL)
     ORDER BY r.name`,
    [companyId, principalId, workspaceId],
  );
  return result.rows.map((row) => row.name);
}

type Authorized = {
  ok: true;
  actorUserId: string | null;
  actorSlackUserId: string | null;
  actorTeamsAadUserId: string | null;
  actorChatPlatform: ChatPlatform | null;
  actorPrincipalId: string | null;
  actorChatPrincipals: ChatPrincipal[];
  roles: string[];
};

async function requirePermissionForWorkspace(
  context: RouteContext,
  workspace: any,
  requested: { action: string; resource: string },
  options: { allowIfNoAssignments?: boolean } = {},
): Promise<Authorized | { ok: false }> {
  const assignmentsExist = await hasRoleAssignments(context.state.pool, workspace.id);
  if (!assignmentsExist && options.allowIfNoAssignments) {
    return {
      ok: true,
      actorUserId: null,
      actorSlackUserId: null,
      actorTeamsAadUserId: null,
      actorChatPlatform: null,
      actorPrincipalId: null,
      actorChatPrincipals: [],
      roles: [],
    };
  }

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
        metadata: { action: requested.action, slackUserId: sessionActor.slackUserId, teamsAadUserId: sessionActor.teamsAadUserId, roles: sessionActor.roles },
      });
      sendJson(context.res, 403, { error: "RBAC denied", requested, roles: sessionActor.roles });
      return { ok: false };
    }
    return {
      ok: true,
      actorUserId: sessionActor.userId,
      actorSlackUserId: sessionActor.slackUserId,
      actorTeamsAadUserId: sessionActor.teamsAadUserId,
      actorChatPlatform: sessionActor.chatPlatform,
      actorPrincipalId: sessionActor.principalId,
      actorChatPrincipals: sessionActor.chatPrincipals,
      roles: sessionActor.roles,
    };
  }

  const chatPrincipal = actorChatPrincipal(context.req);
  if (!chatPrincipal) {
    sendJson(context.res, 401, { error: "Missing or invalid Operant admin session" });
    return { ok: false };
  }
  const slackUserId = chatPrincipal.platform === "slack" ? chatPrincipal.principalId : null;
  const teamsAadUserId = chatPrincipal.platform === "msteams" ? chatPrincipal.principalId : null;

  const result = await context.state.pool.query(
    `SELECT u.id AS user_id, u.slack_user_id, u.teams_aad_user_id, r.name AS role_name
     FROM users u
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE u.company_id = $1
       AND (
         ($2 = 'slack' AND u.slack_user_id = $3)
         OR ($2 = 'msteams' AND u.teams_aad_user_id = $3)
       )
       AND (ra.workspace_id = $4 OR ra.workspace_id IS NULL)`,
    [workspace.company_id, chatPrincipal.platform, chatPrincipal.principalId, workspace.id],
  );
  const roles = result.rows.map((row) => row.role_name);
  const actorUserId = result.rows[0]?.user_id;
  const resolvedSlackUserId = result.rows[0]?.slack_user_id ?? slackUserId;
  const resolvedTeamsAadUserId = result.rows[0]?.teams_aad_user_id ?? teamsAadUserId;
  if (!actorUserId || !(await userHasPermission(context.state.pool, actorUserId, workspace.id, requested))) {
    await audit(context.state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId,
      eventType: "rbac.denied",
      resourceType: requested.resource,
      outcome: "deny",
      metadata: { action: requested.action, chatPlatform: chatPrincipal.platform, principalId: chatPrincipal.principalId, slackUserId, teamsAadUserId, roles },
    });
    sendJson(context.res, 403, { error: "RBAC denied", requested, roles });
    return { ok: false };
  }
  return {
    ok: true,
    actorUserId,
    actorSlackUserId: resolvedSlackUserId,
    actorTeamsAadUserId: resolvedTeamsAadUserId,
    actorChatPlatform: chatPrincipal.platform,
    actorPrincipalId: chatPrincipal.principalId,
    actorChatPrincipals: actorChatPrincipals(resolvedSlackUserId, resolvedTeamsAadUserId),
    roles,
  };
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
    `SELECT tool, action, effect, slack_user_ids, teams_aad_user_ids, role_names
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
    teamsAadUserIds: row.teams_aad_user_ids ?? [],
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
  const teamsDmUsers = await pool.query(
    `SELECT conditions->'allowedTeamsDmUserIds' AS ids
     FROM policy_rules
     WHERE workspace_id = $1 AND name = 'msteams-dm-allowlist' AND enabled = true
     ORDER BY priority ASC
     LIMIT 1`,
    [workspaceId],
  );
  const channelRows = await pool.query(
    `SELECT channel_type, team_id, channel_id, name, enabled, require_mention, allowed_user_ids, denied_user_ids
     FROM channel_policies
     WHERE workspace_id = $1
     ORDER BY channel_type, team_id NULLS FIRST, channel_id`,
    [workspaceId],
  );
  const toolRows = await pool.query(
    `SELECT tool, action, effect, slack_user_ids, teams_aad_user_ids, role_names
     FROM tool_policies
     WHERE workspace_id = $1
     ORDER BY tool, action, effect, created_at`,
    [workspaceId],
  );
  const approvalRows = await pool.query(
    `SELECT name, action_pattern, resource_pattern, approver_slack_user_ids, approver_teams_user_ids, min_approvals, enabled
     FROM approval_policies
     WHERE workspace_id = $1
     ORDER BY created_at`,
    [workspaceId],
  );
  return {
    allowedDmUserIds: Array.isArray(dmUsers.rows[0]?.ids) ? dmUsers.rows[0].ids : [],
    allowedTeamsDmUserIds: Array.isArray(teamsDmUsers.rows[0]?.ids) ? teamsDmUsers.rows[0].ids : [],
    channelPolicies: channelRows.rows.map((row): ChannelPolicyRecord => ({
      channelType: row.channel_type,
      teamId: row.team_id ? row.team_id : null,
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
      teamsAadUserIds: row.teams_aad_user_ids ?? [],
      roleNames: row.role_names ?? [],
    })),
    approvalPolicies: approvalRows.rows.map((row): ApprovalPolicyRecord => ({
      name: row.name,
      actionPattern: row.action_pattern,
      resourcePattern: row.resource_pattern,
      approverSlackUserIds: row.approver_slack_user_ids ?? [],
      approverTeamsUserIds: row.approver_teams_user_ids ?? [],
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
  await pool.query(
    `INSERT INTO policy_rules (workspace_id, name, effect, resource, action, conditions, priority, enabled)
     VALUES ($1, 'msteams-dm-allowlist', 'allow', 'msteams_dm', 'message', $2, 10, true)
     ON CONFLICT (workspace_id, name)
     DO UPDATE SET conditions = EXCLUDED.conditions, enabled = true`,
    [workspaceId, { allowedTeamsDmUserIds: input.allowedTeamsDmUserIds }],
  );

  // Only delete the platforms present in this payload so a Slack-only update
  // cannot silently wipe Teams channel rows (and vice versa).
  const presentChannelTypes = Array.from(new Set(input.channelPolicies.map((policy) => policy.channelType ?? "slack")));
  if (presentChannelTypes.length > 0) {
    await pool.query(
      "DELETE FROM channel_policies WHERE workspace_id = $1 AND channel_type = ANY($2::text[])",
      [workspaceId, presentChannelTypes],
    );
  }
  for (const policy of input.channelPolicies) {
    await pool.query(
      `INSERT INTO channel_policies (workspace_id, channel_type, team_id, channel_id, name, enabled, require_mention, allowed_user_ids, denied_user_ids)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        workspaceId,
        policy.channelType ?? "slack",
        policy.teamId ?? "",
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
      `INSERT INTO tool_policies (workspace_id, tool, action, effect, slack_user_ids, teams_aad_user_ids, role_names)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [workspaceId, policy.tool, policy.action, policy.effect, policy.slackUserIds, policy.teamsAadUserIds ?? [], policy.roleNames],
    );
  }

  await pool.query("DELETE FROM approval_policies WHERE workspace_id = $1", [workspaceId]);
  for (const policy of input.approvalPolicies) {
    await pool.query(
      `INSERT INTO approval_policies (workspace_id, name, action_pattern, resource_pattern, approver_slack_user_ids, approver_teams_user_ids, min_approvals, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        workspaceId,
        policy.name,
        policy.actionPattern,
        policy.resourcePattern,
        policy.approverSlackUserIds,
        policy.approverTeamsUserIds ?? [],
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
  const workspace = await pool.query(
    `SELECT openclaw_gateway_url, openclaw_config_path, teams_app_id, teams_tenant_id,
            msteams_webhook_port, msteams_webhook_path
     FROM workspaces
     WHERE id = $1`,
    [workspaceId],
  );
  const teamsAppPassword = await pool.query(
    "SELECT 1 FROM integration_credentials WHERE workspace_id = $1 AND secret_ref_id = $2 LIMIT 1",
    [workspaceId, buildSecretRefId(workspaceId, "msteams/appPassword")],
  );
  const slackBotToken = await pool.query(
    "SELECT 1 FROM integration_credentials WHERE workspace_id = $1 AND secret_ref_id = $2 LIMIT 1",
    [workspaceId, buildSecretRefId(workspaceId, "slack/botToken")],
  );
  const slackAppToken = await pool.query(
    "SELECT 1 FROM integration_credentials WHERE workspace_id = $1 AND secret_ref_id = $2 LIMIT 1",
    [workspaceId, buildSecretRefId(workspaceId, "slack/appToken")],
  );
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
    teamsDmAllowFrom: policy.allowedTeamsDmUserIds,
    channelPolicies: policy.channelPolicies,
    toolPolicies: policy.toolPolicies,
    approvalPolicies: policy.approvalPolicies,
    slackBotTokenConfigured: Boolean(slackBotToken.rowCount),
    slackAppTokenConfigured: Boolean(slackAppToken.rowCount),
    teamsAppId: workspace.rows[0]?.teams_app_id ?? null,
    teamsAppPasswordConfigured: Boolean(teamsAppPassword.rowCount),
    teamsTenantId: workspace.rows[0]?.teams_tenant_id ?? null,
    msteamsWebhookPort: workspace.rows[0]?.msteams_webhook_port ?? null,
    msteamsWebhookPath: workspace.rows[0]?.msteams_webhook_path ?? null,
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

async function handleBootstrap(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  // In-memory throttle only: the admin-token gate must run before any DB access
  // (the no-DB bootstrap test enforces this), and at first bootstrap there is no
  // workspace yet to attribute a rate-limit audit row to.
  const ip = clientIp(req);
  const limited = authRateLimit.isLimited(ip);
  if (limited.limited) {
    sendJson(res, 429, { error: "Too many failed attempts. Try again later." }, { "retry-after": String(limited.retryAfterSeconds) });
    return;
  }
  const rawBody = await readJson(req);
  const adminToken = validateAdminLoginTokenThrottled(req, rawBody, ip);
  if (!adminToken.ok) {
    sendJson(res, adminToken.statusCode, { error: adminToken.error });
    return;
  }
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const workspace = await ensureDefaultWorkspace(client, { seed: true });
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
  const ip = clientIp(req);
  if (await enforceAuthRateLimit(context, workspace, ip, {
    eventType: "auth.login_rate_limited",
    resourceType: "admin_session",
    error: "Too many failed login attempts. Try again later.",
  })) return;
  const rawBody = await readJson(req);
  const body = z.object({
    slackUserId: slackIdSchema.optional(),
    teamsAadUserId: teamsAadUserIdSchema.optional(),
    platform: z.enum(chatPlatforms).optional(),
    adminLoginToken: z.string().min(1).optional(),
  }).superRefine((input, ctx) => {
    if (!input.slackUserId && !input.teamsAadUserId) {
      ctx.addIssue({ code: "custom", path: ["slackUserId"], message: "Provide a slackUserId, teamsAadUserId, or both" });
    }
    if (input.slackUserId && input.teamsAadUserId && !input.platform) {
      ctx.addIssue({ code: "custom", path: ["platform"], message: "When sending both slackUserId and teamsAadUserId, set platform to 'slack' or 'msteams' to disambiguate" });
    }
    if (input.platform === "slack" && !input.slackUserId) {
      ctx.addIssue({ code: "custom", path: ["slackUserId"], message: "platform 'slack' requires slackUserId" });
    }
    if (input.platform === "msteams" && !input.teamsAadUserId) {
      ctx.addIssue({ code: "custom", path: ["teamsAadUserId"], message: "platform 'msteams' requires teamsAadUserId" });
    }
  }).parse(rawBody);
  const platform: ChatPlatform = body.platform ?? (body.slackUserId ? "slack" : "msteams");
  const principalId = platform === "slack" ? body.slackUserId : body.teamsAadUserId;
  const adminToken = adminLoginTokenValidation(req, rawBody);
  if (!adminToken.ok) {
    await audit(state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      eventType: "auth.login_denied",
      resourceType: "admin_session",
      outcome: "deny",
      metadata: { slackUserId: body.slackUserId, teamsAadUserId: body.teamsAadUserId, platform, reason: "admin_login_token" },
    });
    if (adminToken.statusCode === 401) authRateLimit.recordFailure(ip);
    sendJson(res, adminToken.statusCode, { error: adminToken.error });
    return;
  }
  const result = await state.pool.query(
    `SELECT u.id AS user_id, u.slack_user_id, u.teams_aad_user_id, array_agg(DISTINCT r.name) AS roles
     FROM users u
     JOIN role_assignments ra ON ra.user_id = u.id
     JOIN roles r ON r.id = ra.role_id
     WHERE u.company_id = $1
       AND (
         ($2 = 'slack' AND u.slack_user_id = $3)
         OR ($2 = 'msteams' AND u.teams_aad_user_id = $3)
       )
       AND (ra.workspace_id = $4 OR ra.workspace_id IS NULL)
     GROUP BY u.id, u.slack_user_id, u.teams_aad_user_id`,
    [workspace.company_id, platform, principalId, workspace.id],
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
      metadata: { slackUserId: body.slackUserId, teamsAadUserId: body.teamsAadUserId, platform, code },
    });
    // No recordFailure here: these branches require a VALID admin token, so they are normal
    // setup states (workspace not bootstrapped / operator not yet provisioned). Counting them
    // would let a legitimate operator lock their own IP out. Invalid tokens record above (401).
    sendJson(res, 403, {
      error: bootstrapRequired ? "Workspace not bootstrapped" : "No Operant role assignment for chat user",
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
      `INSERT INTO admin_sessions (user_id, workspace_id, token_hash, expires_at, principal_platform)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, expires_at`,
      [result.rows[0].user_id, workspace.id, tokenHash, expiresAt, platform],
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: result.rows[0].user_id,
      eventType: "auth.login",
      resourceType: "admin_session",
      resourceId: session.rows[0].id,
      metadata: { platform },
    });
    await client.query("COMMIT");
    authRateLimit.reset(ip);
    sendJson(res, 200, {
      token,
      sessionId: session.rows[0].id,
      expiresAt: session.rows[0].expires_at,
      user: {
        id: result.rows[0].user_id,
        slackUserId: result.rows[0].slack_user_id,
        teamsAadUserId: result.rows[0].teams_aad_user_id,
        platform,
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
  sendJson(res, 200, {
    user: {
      userId: actor.userId,
      slackUserId: actor.slackUserId,
      teamsAadUserId: actor.teamsAadUserId,
      chatPlatform: actor.chatPlatform,
      principalId: actor.principalId,
      roles: actor.roles,
    },
    workspaceId: workspace.id,
  });
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
    teamsAppId: workspace.teams_app_id,
    teamsTenantId: workspace.teams_tenant_id,
    msteamsWebhookPort: workspace.msteams_webhook_port,
    msteamsWebhookPath: workspace.msteams_webhook_path,
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
           teams_app_id = $3,
           teams_tenant_id = $4,
           msteams_webhook_port = $5,
           msteams_webhook_path = $6,
           openclaw_gateway_url = $7
       WHERE id = $8`,
      [
        input.workspaceName ?? workspace.name,
        input.slackTeamId === undefined ? workspace.slack_team_id : input.slackTeamId,
        input.teamsAppId === undefined ? workspace.teams_app_id : input.teamsAppId,
        input.teamsTenantId === undefined ? workspace.teams_tenant_id : input.teamsTenantId,
        input.msteamsWebhookPort ?? workspace.msteams_webhook_port ?? 3978,
        input.msteamsWebhookPath ?? workspace.msteams_webhook_path ?? "/api/messages",
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
    if (input.modelProvider || input.modelName || input.openclawGatewayUrl || input.teamsAppId !== undefined || input.teamsTenantId !== undefined || input.msteamsWebhookPort || input.msteamsWebhookPath) {
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
        teamsAppId: input.teamsAppId === undefined ? workspace.teams_app_id : input.teamsAppId,
        teamsTenantId: input.teamsTenantId === undefined ? workspace.teams_tenant_id : input.teamsTenantId,
        msteamsWebhookPort: input.msteamsWebhookPort ?? workspace.msteams_webhook_port ?? 3978,
        msteamsWebhookPath: input.msteamsWebhookPath ?? workspace.msteams_webhook_path ?? "/api/messages",
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
    const ip = clientIp(req);
    if (await enforceAuthRateLimit(context, workspace, ip, {
      eventType: "credentials.bootstrap_rate_limited",
      resourceType: "workspace",
      error: "Too many failed attempts. Try again later.",
    })) return;
    const adminToken = validateAdminLoginTokenThrottled(req, rawBody, ip);
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
    if (!input.adminSlackUserId && !input.adminTeamsAadUserId) {
      await audit(state.pool, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        eventType: "credentials.bootstrap_denied",
        resourceType: "workspace",
        outcome: "deny",
        metadata: { reason: "owner_principal" },
      });
      sendJson(res, 400, { error: "First credential setup requires an adminSlackUserId or adminTeamsAadUserId to create the workspace owner" });
      return;
    }
    // A workspace boots with at least one chat transport (Slack bot+app pair or
    // a Teams app password) plus a model API key. The schema superRefine already
    // rejects a half-configured Slack pair and a no-transport payload; this gate
    // surfaces the friendly bootstrap-specific message.
    const slackTransportConfigured = Boolean(input.slackBotToken && input.slackAppToken);
    const teamsTransportConfigured = Boolean(input.teamsAppPassword);
    const missingSecrets: string[] = [];
    if (!slackTransportConfigured && !teamsTransportConfigured) missingSecrets.push("slackBotToken+slackAppToken or teamsAppPassword");
    if (!input.modelApiKey) missingSecrets.push("modelApiKey");
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
      `SELECT approver_slack_user_ids, approver_teams_user_ids
       FROM approval_policies
       WHERE workspace_id = $1 AND name = 'risky-actions'
       LIMIT 1`,
      [workspace.id],
    );
    const existingApprovalSlackUserIds = Array.isArray(existingApprovalPolicy.rows[0]?.approver_slack_user_ids)
      ? existingApprovalPolicy.rows[0].approver_slack_user_ids
      : [];
    const rawSlackApprovers = (rawBody && typeof rawBody === "object" && "approvalSlackUserIds" in rawBody)
      ? input.approvalSlackUserIds
      : existingApprovalSlackUserIds;
    const approvalSlackUserIds = Array.from(new Set([
      ...(input.adminSlackUserId ? [input.adminSlackUserId] : []),
      ...rawSlackApprovers,
    ].filter(Boolean)));
    const existingApprovalTeamsUserIds = Array.isArray(existingApprovalPolicy.rows[0]?.approver_teams_user_ids)
      ? existingApprovalPolicy.rows[0].approver_teams_user_ids
      : [];
    const rawTeamsApprovers = (rawBody && typeof rawBody === "object" && "approvalTeamsUserIds" in rawBody)
      ? input.approvalTeamsUserIds
      : existingApprovalTeamsUserIds;
    const approvalTeamsUserIds = Array.from(new Set([
      ...(input.adminTeamsAadUserId ? [input.adminTeamsAadUserId] : []),
      ...rawTeamsApprovers,
    ].filter(Boolean)));
    if (approvalSlackUserIds.length === 0 && approvalTeamsUserIds.length === 0) {
      await client.query("ROLLBACK");
      sendJson(res, 400, { error: "At least one Slack or Teams approval user is required for the default risky-actions approval policy" });
      return;
    }
    const allowedDmUserIds = Array.from(new Set([
      ...(input.adminSlackUserId ? [input.adminSlackUserId] : []),
      ...input.allowedDmUserIds,
    ].filter(Boolean)));
    const allowedTeamsDmUserIds = Array.from(new Set([
      ...(input.adminTeamsAadUserId ? [input.adminTeamsAadUserId] : []),
      ...input.allowedTeamsDmUserIds,
    ].filter(Boolean)));
    if (input.companyName) {
      await client.query("UPDATE companies SET name = $1 WHERE id = $2", [input.companyName, workspace.company_id]);
    }
    await client.query(
      `UPDATE workspaces
       SET name = $1,
           slack_team_id = COALESCE($2, slack_team_id),
           teams_app_id = COALESCE($3, teams_app_id),
           teams_tenant_id = COALESCE($4, teams_tenant_id),
           msteams_webhook_port = COALESCE($5, msteams_webhook_port),
           msteams_webhook_path = COALESCE($6, msteams_webhook_path)
       WHERE id = $7`,
      [
        input.workspaceName ?? workspace.name,
        input.slackTeamId ?? null,
        input.teamsAppId ?? null,
        input.teamsTenantId ?? null,
        input.msteamsWebhookPort ?? null,
        input.msteamsWebhookPath ?? null,
        workspace.id,
      ],
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
    if (input.teamsAppPassword) {
      await upsertCredential(client, state.masterKey, workspace.id, "msteams", "Microsoft Teams app password", buildSecretRefId(workspace.id, "msteams/appPassword"), input.teamsAppPassword);
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
    await client.query(
      `INSERT INTO policy_rules (workspace_id, name, effect, resource, action, conditions, priority)
       VALUES ($1, 'msteams-dm-allowlist', 'allow', 'msteams_dm', 'message', $2, 10)
       ON CONFLICT DO NOTHING`,
      [workspace.id, { allowedTeamsDmUserIds }],
    );
    await client.query(
      `UPDATE policy_rules
       SET conditions = $2
       WHERE workspace_id = $1 AND name = 'msteams-dm-allowlist'`,
      [workspace.id, { allowedTeamsDmUserIds }],
    );

    await client.query("DELETE FROM channel_policies WHERE workspace_id = $1 AND name = 'Credential setup allowlist'", [workspace.id]);
    for (const channelId of input.allowedChannelIds) {
      await client.query(
        `INSERT INTO channel_policies (workspace_id, channel_type, team_id, channel_id, name, enabled, require_mention, allowed_user_ids)
         VALUES ($1, 'slack', '', $2, 'Credential setup allowlist', true, true, $3)
         ON CONFLICT (workspace_id, channel_type, team_id, channel_id)
         DO UPDATE SET name = COALESCE(channel_policies.name, EXCLUDED.name), enabled = true, require_mention = true, allowed_user_ids = EXCLUDED.allowed_user_ids, updated_at = now()`,
        [workspace.id, channelId, []],
      );
    }
    for (const policy of input.teamsChannelPolicies) {
      await client.query(
        `INSERT INTO channel_policies (workspace_id, channel_type, team_id, channel_id, name, enabled, require_mention, allowed_user_ids)
         VALUES ($1, 'msteams', $2, $3, COALESCE($4, 'Credential setup Teams allowlist'), true, true, $5)
         ON CONFLICT (workspace_id, channel_type, team_id, channel_id)
         DO UPDATE SET name = COALESCE(channel_policies.name, EXCLUDED.name), enabled = true, require_mention = true, allowed_user_ids = EXCLUDED.allowed_user_ids, updated_at = now()`,
        [workspace.id, policy.teamId, policy.channelId, policy.name ?? null, policy.allowedUserIds],
      );
    }

    await client.query(
      `DELETE FROM tool_policies
       WHERE workspace_id = $1
         AND COALESCE(array_length(slack_user_ids, 1), 0) = 0
         AND COALESCE(array_length(teams_aad_user_ids, 1), 0) = 0
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
      `UPDATE approval_policies SET approver_slack_user_ids = $2, approver_teams_user_ids = $3 WHERE workspace_id = $1 AND name = 'risky-actions'`,
      [workspace.id, approvalSlackUserIds, approvalTeamsUserIds],
    );

    let ownerIdentityMerge: { mergedSlackUserId?: string; mergedTeamsAadUserId?: string } | null = null;
    if (input.adminSlackUserId || input.adminTeamsAadUserId) {
      // The legacy ON CONFLICT (company_id, slack_user_id) upsert cannot serve a
      // Teams-only owner: NULL slack_user_id never conflicts, so a re-run would
      // insert duplicate rows. SELECT by (slack OR teams) first, then UPDATE the
      // single match (COALESCE-linking the other principal) or INSERT a fresh row.
      const existingOwner = await client.query(
        `SELECT id, slack_user_id, teams_aad_user_id FROM users
         WHERE company_id = $1
           AND (
             ($2::text IS NOT NULL AND slack_user_id = $2)
             OR ($3::text IS NOT NULL AND teams_aad_user_id = $3)
           )`,
        [workspace.company_id, input.adminSlackUserId ?? null, input.adminTeamsAadUserId ?? null],
      );
      const distinctOwnerIds = Array.from(new Set(existingOwner.rows.map((row) => row.id)));
      if (distinctOwnerIds.length > 1) {
        await client.query("ROLLBACK");
        sendJson(res, 409, { error: "adminSlackUserId and adminTeamsAadUserId belong to different existing users; merge them via /api/users before reusing as workspace owner" });
        return;
      }
      if (distinctOwnerIds.length === 1) {
        const existingRow = existingOwner.rows[0];
        if (input.adminSlackUserId && !existingRow.slack_user_id) {
          ownerIdentityMerge = { ...(ownerIdentityMerge ?? {}), mergedSlackUserId: input.adminSlackUserId };
        }
        if (input.adminTeamsAadUserId && !existingRow.teams_aad_user_id) {
          ownerIdentityMerge = { ...(ownerIdentityMerge ?? {}), mergedTeamsAadUserId: input.adminTeamsAadUserId };
        }
      }
      const user = distinctOwnerIds.length === 1
        ? await client.query(
          `UPDATE users
           SET slack_user_id = COALESCE($2, slack_user_id),
               teams_aad_user_id = COALESCE($3, teams_aad_user_id)
           WHERE id = $1
           RETURNING id`,
          [distinctOwnerIds[0], input.adminSlackUserId ?? null, input.adminTeamsAadUserId ?? null],
        )
        : await client.query(
          `INSERT INTO users (company_id, slack_user_id, teams_aad_user_id, name)
           VALUES ($1, $2, $3, 'Workspace Owner')
           RETURNING id`,
          [workspace.company_id, input.adminSlackUserId ?? null, input.adminTeamsAadUserId ?? null],
        );
      if (ownerIdentityMerge) {
        await audit(client, {
          companyId: workspace.company_id,
          workspaceId: workspace.id,
          actorUserId: user.rows[0].id,
          eventType: "users.identity_merged",
          resourceType: "user",
          resourceId: user.rows[0].id,
          metadata: ownerIdentityMerge,
        });
      }
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
        slackConfigured: Boolean(input.slackBotToken && input.slackAppToken),
        teamsConfigured: Boolean(input.teamsAppPassword),
        modelProvider: input.modelProvider,
        allowedDmUsers: allowedDmUserIds.length,
        allowedTeamsDmUsers: allowedTeamsDmUserIds.length,
        allowedChannels: input.allowedChannelIds.length,
        teamsChannelPolicies: input.teamsChannelPolicies.length,
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

function requestOrigin(req: IncomingMessage): string {
  const host = req.headers["x-forwarded-host"]?.toString().split(",")[0]?.trim() || req.headers.host || "localhost";
  const proto = req.headers["x-forwarded-proto"]?.toString().split(",")[0]?.trim() || "http";
  return `${proto}://${host}`;
}

function pipedreamClientForResponse(res: ServerResponse): PipedreamConnectClient | null {
  const client = createPipedreamConnectClientFromEnv();
  if (!client) {
    sendJson(res, 503, {
      error: "Pipedream Connect is not configured",
      code: "pipedream_not_configured",
      required: pipedreamDiagnosticEnvKeys,
    });
    return null;
  }
  return client;
}

function pipedreamActionFromToolName(appSlug: string, toolName: string): string {
  const prefix = `${appSlug}-`;
  if (toolName.startsWith(prefix) && toolName.length > prefix.length) return toolName.slice(prefix.length);
  const dashIdx = toolName.indexOf("-");
  return dashIdx < 0 ? "*" : toolName.slice(dashIdx + 1);
}

async function handlePipedreamApps(context: RouteContext): Promise<void> {
  const { res, state, url } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "integrations:read", resource: "integration" });
  if (!allowed.ok) return;
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 40), 1), 100);
  const q = url.searchParams.get("q")?.trim() || undefined;
  const after = url.searchParams.get("after")?.trim() || undefined;
  const result = await client.listApps({ q, limit, after });
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    eventType: "pipedream.apps_searched",
    resourceType: "pipedream_app",
    metadata: { q, count: result.apps.length },
  });
  sendJson(res, 200, result);
}

async function handlePipedreamAccounts(context: RouteContext): Promise<void> {
  const { res, state, url } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "integrations:connect", resource: "integration" });
  if (!allowed.ok) return;
  if (!allowed.actorSlackUserId) {
    sendJson(res, 409, { error: "Pipedream account state requires a Slack user identity" });
    return;
  }
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const app = url.searchParams.get("app")?.trim() || undefined;
  if (app) pipedreamAppSlugSchema.parse(app);
  const accounts = await client.listAccounts({ externalUserId: allowed.actorSlackUserId, app });
  sendJson(res, 200, { accounts });
}

async function handlePipedreamAppActions(context: RouteContext): Promise<void> {
  const { res, state, url } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "integrations:read", resource: "integration" });
  if (!allowed.ok) return;
  if (!allowed.actorSlackUserId) {
    sendJson(res, 409, { error: "Pipedream action discovery requires a Slack user identity" });
    return;
  }
  const match = url.pathname.match(/^\/api\/integrations\/pipedream\/apps\/([^/]+)\/actions$/);
  const appSlug = pipedreamAppSlugSchema.parse(match ? decodeURIComponent(match[1]) : "");
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const [tools, toolPolicies] = await Promise.all([
    client.listTools({ externalUserId: allowed.actorSlackUserId, appSlug }),
    loadToolPolicies(state.pool, workspace.id),
  ]);
  const result = tools.flatMap((tool) => {
    const action = pipedreamActionFromToolName(appSlug, tool.name);
    const decision = evaluateToolOnly({ tool: `pipedream:${appSlug}`, action, platform: "slack", slackUserId: allowed.actorSlackUserId, userRoleNames: allowed.roles }, { toolPolicies });
    return decision.effect === "deny"
      ? []
      : [{
          toolName: tool.name,
          action,
          description: tool.description ?? "",
          inputSchema: tool.inputSchema,
          policy: decision,
        }];
  });
  sendJson(res, 200, { app: appSlug, actions: result });
}

async function handlePipedreamConnectToken(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "integrations:connect", resource: "integration" });
  if (!allowed.ok) return;
  if (!allowed.actorSlackUserId) {
    sendJson(res, 409, { error: "Pipedream Connect requires a Slack user identity" });
    return;
  }
  const body = z.object({ appSlug: pipedreamAppSlugSchema.optional() }).parse(await readJson(req));
  // Gate which app a user may connect by tool policy (the connect token is not
  // app-bound at the Pipedream API, so authorization must happen here). Mirrors
  // the plugin connect path so the public and plugin surfaces enforce the same rule.
  if (body.appSlug) {
    const toolPolicies = await loadToolPolicies(state.pool, workspace.id);
    const decision = evaluateToolOnly({ tool: `pipedream:${body.appSlug}`, action: "*", platform: "slack", slackUserId: allowed.actorSlackUserId, userRoleNames: allowed.roles }, { toolPolicies });
    if (decision.effect === "deny") {
      await audit(state.pool, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        actorSlackUserId: allowed.actorSlackUserId,
        eventType: "pipedream.connect_token_denied",
        resourceType: "pipedream_account",
        outcome: "deny",
        metadata: { app: body.appSlug, slackUserId: allowed.actorSlackUserId, reasons: decision.reasons },
      });
      sendJson(res, 403, { error: "policy_denied", reasons: decision.reasons });
      return;
    }
  }
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const token = await client.createConnectToken({
    externalUserId: allowed.actorSlackUserId,
    appSlug: body.appSlug,
    allowedOrigins: [requestOrigin(req)],
  });
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    eventType: "pipedream.connect_token_created",
    resourceType: "pipedream_account",
    metadata: {
      app: body.appSlug ?? null,
      slackUserId: allowed.actorSlackUserId,
      expiresAt: token.expiresAt,
    },
  });
  sendJson(res, 200, {
    app: body.appSlug ?? null,
    expiresAt: token.expiresAt,
    connectLinkUrl: token.connectLinkUrl,
  });
}

async function handlePipedreamDisconnectAccount(context: RouteContext): Promise<void> {
  const { res, state, url } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "integrations:connect", resource: "integration" });
  if (!allowed.ok) return;
  if (!allowed.actorSlackUserId) {
    sendJson(res, 409, { error: "Pipedream disconnect requires a Slack user identity" });
    return;
  }
  const accountId = pipedreamAccountIdSchema.parse(decodeURIComponent(url.pathname.replace("/api/integrations/pipedream/accounts/", "")));
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const accounts = await client.listAccounts({ externalUserId: allowed.actorSlackUserId });
  const account = accounts.find((item) => item.id === accountId);
  if (!account) {
    sendJson(res, 404, { error: "Connected account not found for this Slack user" });
    return;
  }
  await client.deleteAccount(accountId);
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    eventType: "pipedream.account_disconnected",
    resourceType: "pipedream_account",
    resourceId: accountId,
    metadata: { app: account.app, slackUserId: allowed.actorSlackUserId },
  });
  sendJson(res, 200, { ok: true, accountId });
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
  // runOpenClawCommand already scrubbed result.stdout/stderr at the source.
  sendJson(res, result.exitCode === 0 ? 200 : 502, { ...result, stderr: result.stderr.slice(0, 2000) });
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
    sendJson(res, 502, {
      error: "OpenClaw status sync failed",
      status: { command: status.command, exitCode: status.exitCode, timedOut: status.timedOut, stderr: status.stderr.slice(0, 2000) },
    });
    return;
  }
  const sessions = await runOpenClawCommand(["sessions", "--json"], commandParams);
  const tasks = await runOpenClawCommand(["tasks", "list", "--json"], commandParams);
  const usageCost = await runOpenClawCommand(openClawGatewayCommandArgs(["gateway", "usage-cost", "--json"], commandParams), commandParams);

  // runOpenClawCommand scrubbed each stderr at the source; just clip for storage.
  const sessionsStderr = sessions.stderr.slice(0, 2000);
  const tasksStderr = tasks.stderr.slice(0, 2000);
  const usageCostStderr = usageCost.stderr.slice(0, 2000);

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
        sessionsStderr,
        tasksCommand: tasks.command,
        tasksExitCode: tasks.exitCode,
        tasksStderr,
        usageCostCommand: usageCost.command,
        usageCostExitCode: usageCost.exitCode,
        usageCostStderr,
      },
    });
    await client.query("COMMIT");
    sendJson(res, 200, {
      ok: true,
      synced,
      status: { command: status.command, exitCode: status.exitCode, timedOut: status.timedOut },
      sessions: { command: sessions.command, exitCode: sessions.exitCode, timedOut: sessions.timedOut, stderr: sessionsStderr },
      tasks: { command: tasks.command, exitCode: tasks.exitCode, timedOut: tasks.timedOut, stderr: tasksStderr },
      usageCost: { command: usageCost.command, exitCode: usageCost.exitCode, timedOut: usageCost.timedOut, stderr: usageCostStderr },
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
  const channelType = parsedInput.channelType ?? "slack";
  const principalId = channelType === "msteams"
    ? parsedInput.teamsAadUserId ?? parsedInput.principalId ?? ""
    : parsedInput.slackUserId ?? parsedInput.principalId ?? "";
  const input = {
    ...parsedInput,
    userRoleNames: await loadChatPrincipalRoleNames(state.pool, workspace.company_id, workspace.id, channelType, principalId),
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
    if (approvalRequirement.matchedPolicyCount < 1 || (approvalRequirement.approverSlackUserIds.length + approvalRequirement.approverTeamsUserIds.length) < 1) {
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

  // An actor may only grant permissions it already holds. Without this, any
  // users:write holder (e.g. the built-in admin) could mint a "*"/"*" custom
  // role and assign it to itself, escalating to owner-equivalent access. Fetch
  // the actor's permission set once and match in memory rather than per grant.
  if (!allowed.actorUserId) {
    sendJson(res, 403, { error: "Cannot grant a permission you do not hold" });
    return;
  }
  const actorPermissions = await getUserPermissions(state.pool, allowed.actorUserId, workspace.id);
  for (const permission of permissions) {
    if (!actorPermissions.some((granted) => permissionMatches(granted, permission))) {
      sendJson(res, 403, { error: "Cannot grant a permission you do not hold", permission });
      return;
    }
  }

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
    `SELECT u.id, u.email, u.name, u.slack_user_id, u.teams_aad_user_id, u.teams_bot_user_id, u.teams_tenant_id, u.created_at,
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

    const matchingUsers = await client.query(
      `SELECT id
       FROM users
       WHERE company_id = $1
         AND (
           ($2::text IS NOT NULL AND slack_user_id = $2)
           OR ($3::text IS NOT NULL AND teams_aad_user_id = $3)
           OR ($4::text IS NOT NULL AND teams_bot_user_id = $4)
         )`,
      [workspace.company_id, input.slackUserId ?? null, input.teamsAadUserId ?? null, input.teamsBotUserId ?? null],
    );
    const matchingIds = Array.from(new Set(matchingUsers.rows.map((row) => row.id)));
    if (matchingIds.length > 1) {
      await client.query("ROLLBACK");
      sendJson(res, 409, { error: "Slack and Teams principals belong to different existing users" });
      return;
    }
    const user = matchingIds.length === 1
      ? await client.query(
        `UPDATE users
         SET slack_user_id = COALESCE($2, slack_user_id),
             teams_aad_user_id = COALESCE($3, teams_aad_user_id),
             teams_bot_user_id = COALESCE($4, teams_bot_user_id),
             teams_tenant_id = COALESCE($5, teams_tenant_id),
             email = $6,
             name = $7
         WHERE id = $1
         RETURNING id, company_id, email, name, slack_user_id, teams_aad_user_id, teams_bot_user_id, teams_tenant_id, created_at`,
        [
          matchingIds[0],
          input.slackUserId ?? null,
          input.teamsAadUserId ?? null,
          input.teamsBotUserId ?? null,
          input.teamsTenantId ?? null,
          input.email ?? null,
          input.name ?? null,
        ],
      )
      : await client.query(
        `INSERT INTO users (company_id, slack_user_id, teams_aad_user_id, teams_bot_user_id, teams_tenant_id, email, name)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, company_id, email, name, slack_user_id, teams_aad_user_id, teams_bot_user_id, teams_tenant_id, created_at`,
        [
          workspace.company_id,
          input.slackUserId ?? null,
          input.teamsAadUserId ?? null,
          input.teamsBotUserId ?? null,
          input.teamsTenantId ?? null,
          input.email ?? null,
          input.name ?? null,
        ],
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
      metadata: { slackUserId: input.slackUserId, teamsAadUserId: input.teamsAadUserId, roles: input.roles },
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
    teamsAppId: workspace.teams_app_id,
    teamsTenantId: workspace.teams_tenant_id,
    msteamsWebhookPort: workspace.msteams_webhook_port,
    msteamsWebhookPath: workspace.msteams_webhook_path,
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
    actorSlackUserId: slackUserId ?? null,
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
    workspaceId: z.uuid(),
    sessionKey: openClawEventIdSchema.optional(),
    runId: openClawEventIdSchema.optional(),
    type: openClawEventTypeSchema,
    channelType: z.enum(["slack", "msteams"]).default("slack"),
    principalId: openClawChatIdSchema.optional(),
    channelId: openClawChatIdSchema.optional(),
    slackChannelId: openClawSlackIdSchema.optional(),
    slackUserId: openClawSlackIdSchema.optional(),
    teamsConversationId: openClawChatIdSchema.optional(),
    teamsAadUserId: z.uuid().optional(),
    usage: z.object({
      provider: openClawUsageLabelSchema.optional(),
      model: openClawUsageLabelSchema.optional(),
      inputTokens: usageTokenCountSchema.default(0),
      outputTokens: usageTokenCountSchema.default(0),
      toolName: openClawUsageLabelSchema.optional(),
      estimatedCostUsd: usageCostUsdSchema.optional(),
    }).optional(),
    metadata: metadataRecordSchema.default({}),
  }).superRefine((input, ctx) => {
    if (input.principalId !== undefined) {
      if (input.channelType === "slack" && !slackIdSchema.safeParse(input.principalId).success) {
        ctx.addIssue({ code: "custom", path: ["principalId"], message: "Slack channelType requires a Slack-shaped principalId" });
      }
      if (input.channelType === "msteams" && !teamsAadUserIdSchema.safeParse(input.principalId).success) {
        ctx.addIssue({ code: "custom", path: ["principalId"], message: "Teams channelType requires an AAD UUID principalId" });
      }
    }
    if (!input.sessionKey) return;
    const principalForSlack = input.slackUserId
      ?? (input.principalId && slackIdSchema.safeParse(input.principalId).success ? input.principalId : undefined);
    const principalForTeams = input.teamsAadUserId
      ?? (input.principalId && teamsAadUserIdSchema.safeParse(input.principalId).success ? input.principalId : undefined);
    if (input.channelType === "slack" && !principalForSlack) {
      ctx.addIssue({ code: "custom", path: ["slackUserId"], message: "Slack sessions require slackUserId or a Slack-shaped principalId" });
    }
    if (input.channelType === "msteams" && !principalForTeams) {
      ctx.addIssue({ code: "custom", path: ["teamsAadUserId"], message: "Teams sessions require teamsAadUserId or an AAD UUID principalId" });
    }
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
      const platformChannelId = body.channelType === "msteams"
        ? body.teamsConversationId ?? null
        : body.slackChannelId ?? null;
      const platformPrincipalId = body.channelType === "msteams"
        ? body.teamsAadUserId ?? null
        : body.slackUserId ?? null;
      const chatChannelId = body.channelId ?? platformChannelId;
      const chatPrincipalId = body.principalId ?? platformPrincipalId;
      const session = await client.query(
        `INSERT INTO sessions (workspace_id, openclaw_session_key, channel_type, chat_channel_id, chat_principal_id, slack_channel_id, slack_user_id, teams_conversation_id, teams_aad_user_id, metadata, last_event_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
         ON CONFLICT (workspace_id, openclaw_session_key)
         DO UPDATE SET channel_type = EXCLUDED.channel_type,
                       chat_channel_id = EXCLUDED.chat_channel_id,
                       chat_principal_id = EXCLUDED.chat_principal_id,
                       slack_channel_id = EXCLUDED.slack_channel_id,
                       slack_user_id = EXCLUDED.slack_user_id,
                       teams_conversation_id = EXCLUDED.teams_conversation_id,
                       teams_aad_user_id = EXCLUDED.teams_aad_user_id,
                       metadata = sessions.metadata || EXCLUDED.metadata,
                       last_event_at = now()
         RETURNING id`,
        [
          body.workspaceId,
          body.sessionKey,
          body.channelType,
          chatChannelId,
          chatPrincipalId,
          body.channelType === "slack" ? body.slackChannelId ?? body.channelId ?? null : body.slackChannelId ?? null,
          body.channelType === "slack" ? body.slackUserId ?? body.principalId ?? null : body.slackUserId ?? null,
          body.channelType === "msteams" ? body.teamsConversationId ?? body.channelId ?? null : body.teamsConversationId ?? null,
          body.channelType === "msteams" ? body.teamsAadUserId ?? body.principalId ?? null : body.teamsAadUserId ?? null,
          metadata,
        ],
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
  // Pipedream tooling is Slack-only for v1, so the plugin user-context lookup
  // stays keyed on slack_user_id (Teams sessions do not surface Pipedream tools).
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
  const principal = resolvePluginPrincipal(input.principalId);
  const { toolPolicies, roleNames } = await loadPrincipalToolContext(state.pool, workspace, principal);
  const decision = evaluateToolOnly({ tool: input.tool, action: input.action, ...principalToolPolicyInput(principal, roleNames) }, { toolPolicies });
  if (input.tool.startsWith("pipedream:")) {
    const app = input.tool.slice("pipedream:".length);
    await audit(state.pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      ...principalAuditIds(principal),
      eventType: "pipedream.invocation",
      resourceType: "pipedream_tool",
      resourceId: `${input.tool}/${input.action}`,
      outcome: decision.effect,
      metadata: {
        app,
        action: input.action,
        tool: input.tool,
        platform: principal?.platform ?? null,
        principalId: principal?.principalId ?? input.principalId,
        status: decision.effect,
        reasons: decision.reasons,
      },
    });
  }
  sendJson(res, 200, decision);
}

async function handlePluginPipedreamSearchApps({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = z.object({
    q: z.string().trim().min(1).max(120).optional(),
    limit: z.number().int().min(1).max(50).default(20),
  }).parse(await readJson(req));
  const workspace = await getWorkspace(state.pool);
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const result = await client.listApps({ q: input.q, limit: input.limit });
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    eventType: "pipedream.apps_searched",
    resourceType: "pipedream_app",
    metadata: { q: input.q, count: result.apps.length, source: "plugin" },
  });
  sendJson(res, 200, result);
}

async function handlePluginPipedreamConnectToken({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = z.object({
    principalId: chatPrincipalIdSchema,
    appSlug: pipedreamAppSlugSchema.optional(),
  }).parse(await readJson(req));
  const workspace = await getWorkspace(state.pool);
  const principal = resolvePluginPrincipal(input.principalId);
  const auditIds = principalAuditIds(principal);
  if (input.appSlug) {
    const { toolPolicies, roleNames } = await loadPrincipalToolContext(state.pool, workspace, principal);
    const decision = evaluateToolOnly({ tool: `pipedream:${input.appSlug}`, action: "*", ...principalToolPolicyInput(principal, roleNames) }, { toolPolicies });
    if (decision.effect === "deny") {
      await audit(state.pool, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        ...auditIds,
        eventType: "pipedream.connect_token_denied",
        resourceType: "pipedream_account",
        outcome: "deny",
        metadata: { app: input.appSlug, platform: principal?.platform ?? null, principalId: input.principalId, reasons: decision.reasons },
      });
      sendJson(res, 403, { error: "policy_denied", reasons: decision.reasons });
      return;
    }
  }
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const token = await client.createConnectToken({
    externalUserId: input.principalId,
    appSlug: input.appSlug,
  });
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    ...auditIds,
    eventType: "pipedream.connect_token_created",
    resourceType: "pipedream_account",
    metadata: { app: input.appSlug ?? null, platform: principal?.platform ?? null, principalId: input.principalId, expiresAt: token.expiresAt, source: "plugin" },
  });
  sendJson(res, 200, {
    app: input.appSlug ?? null,
    expiresAt: token.expiresAt,
    connectLinkUrl: token.connectLinkUrl,
  });
}

async function handlePluginPipedreamAccounts({ req, res }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = z.object({
    principalId: chatPrincipalIdSchema,
    app: pipedreamAppSlugSchema.optional(),
  }).parse(await readJson(req));
  const client = pipedreamClientForResponse(res);
  if (!client) return;
  const accounts = await client.listAccounts({ externalUserId: input.principalId, app: input.app });
  sendJson(res, 200, { accounts });
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
  const byUser = await state.pool.query(
    `SELECT COALESCE(s.slack_user_id, 'unattributed') AS slack_user_id,
            count(*)::int AS events,
            COALESCE(sum(u.input_tokens), 0)::float8 AS input_tokens,
            COALESCE(sum(u.output_tokens), 0)::float8 AS output_tokens,
            COALESCE(sum(u.input_tokens + u.output_tokens), 0)::float8 AS total_tokens,
            COALESCE(sum(u.estimated_cost_usd), 0)::float8 AS estimated_cost_usd
     FROM usage_events u
     LEFT JOIN sessions s ON s.id = u.session_id
     WHERE u.workspace_id = $1
     GROUP BY COALESCE(s.slack_user_id, 'unattributed')
     ORDER BY estimated_cost_usd DESC, events DESC, slack_user_id
     LIMIT 25`,
    [workspace.id],
  );

  sendJson(res, 200, {
    workspaceId: workspace.id,
    totals: totals.rows[0],
    byModel: byModel.rows,
    byTool: byTool.rows,
    byDay: byDay.rows,
    byUser: byUser.rows,
  });
}

// --- Governed memory + skills (migration 013) ---

function parseCsvParam(value: string | null): string[] {
  if (!value) return [];
  return value.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
}

type MemoryQueryOptions = {
  q?: string;
  visibility?: MemoryVisibility;
  scopeKey?: string;
  tags: string[];
  limit: number;
  // When set, restrict to team entries plus private entries owned by this principal.
  // When null, no visibility restriction (workspace-wide; owner/admin dashboard only).
  principalScope: { slackUserId: string | null; teamsAadUserId: string | null } | null;
};

async function queryMemoryEntries(pool: Queryable, workspaceId: string, opts: MemoryQueryOptions) {
  const params: unknown[] = [workspaceId];
  const where: string[] = ["workspace_id = $1"];
  if (opts.principalScope) {
    params.push(opts.principalScope.slackUserId);
    const slackIdx = params.length;
    params.push(opts.principalScope.teamsAadUserId);
    const teamsIdx = params.length;
    where.push(
      `(visibility = 'team' OR (visibility = 'private' AND (`
        + `($${slackIdx}::text IS NOT NULL AND owner_platform = 'slack' AND owner_principal_id = $${slackIdx})`
        + ` OR ($${teamsIdx}::text IS NOT NULL AND owner_platform = 'msteams' AND owner_principal_id = $${teamsIdx})`
        + `)))`,
    );
  }
  if (opts.visibility) {
    params.push(opts.visibility);
    where.push(`visibility = $${params.length}`);
  }
  if (opts.scopeKey) {
    params.push(opts.scopeKey);
    where.push(`scope_key = $${params.length}`);
  }
  if (opts.tags.length > 0) {
    params.push(opts.tags);
    where.push(`tags @> $${params.length}::text[]`);
  }
  let orderBy = "updated_at DESC";
  if (opts.q) {
    params.push(opts.q);
    const qIdx = params.length;
    where.push(`search_vector @@ plainto_tsquery('english', $${qIdx})`);
    orderBy = `ts_rank(search_vector, plainto_tsquery('english', $${qIdx})) DESC, updated_at DESC`;
  }
  params.push(opts.limit);
  const limitIdx = params.length;
  const result = await pool.query(
    `SELECT id, owner_principal_id, owner_platform, visibility, scope_key, tags, content, created_at, updated_at
     FROM memory_entries
     WHERE ${where.join(" AND ")}
     ORDER BY ${orderBy}
     LIMIT $${limitIdx}`,
    params,
  );
  return result.rows;
}

async function querySkills(pool: Queryable, workspaceId: string, opts: { q?: string; tags: string[]; limit: number }) {
  const params: unknown[] = [workspaceId];
  const where: string[] = ["workspace_id = $1"];
  if (opts.tags.length > 0) {
    params.push(opts.tags);
    where.push(`tags @> $${params.length}::text[]`);
  }
  let orderBy = "updated_at DESC";
  if (opts.q) {
    params.push(opts.q);
    const qIdx = params.length;
    where.push(`search_vector @@ plainto_tsquery('english', $${qIdx})`);
    orderBy = `ts_rank(search_vector, plainto_tsquery('english', $${qIdx})) DESC, updated_at DESC`;
  }
  params.push(opts.limit);
  const limitIdx = params.length;
  const result = await pool.query(
    `SELECT id, name, trigger_hint, body, tags, created_at, updated_at
     FROM skill_definitions
     WHERE ${where.join(" AND ")}
     ORDER BY ${orderBy}
     LIMIT $${limitIdx}`,
    params,
  );
  return result.rows;
}

// Owners/admins browse all entries on the dashboard; everyone else (and every agent
// request) is restricted to team entries plus their own private entries.
function memoryPrincipalScope(actor: Authorized): { slackUserId: string | null; teamsAadUserId: string | null } | null {
  if (actor.roles.includes("owner") || actor.roles.includes("admin")) return null;
  return { slackUserId: actor.actorSlackUserId, teamsAadUserId: actor.actorTeamsAadUserId };
}

async function handleListMemory(context: RouteContext): Promise<void> {
  const { res, url, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "memory:read", resource: "memory" });
  if (!allowed.ok) return;
  const search = memorySearchSchema.parse({
    q: url.searchParams.get("q") ?? undefined,
    visibility: url.searchParams.get("visibility") ?? undefined,
    scopeKey: url.searchParams.get("scopeKey") ?? undefined,
    tags: parseCsvParam(url.searchParams.get("tags")),
    limit: url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : undefined,
  });
  const rows = await queryMemoryEntries(state.pool, workspace.id, { ...search, principalScope: memoryPrincipalScope(allowed) });
  sendJson(res, 200, { items: rows });
}

async function handleWriteMemory(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "memory:write", resource: "memory" });
  if (!allowed.ok) return;
  if (!allowed.actorPrincipalId || !allowed.actorChatPlatform) {
    sendJson(res, 400, { error: "missing_principal_context" });
    return;
  }
  const input = memoryEntryWriteSchema.parse(await readJson(req));
  const content = redactRecordForPersistence({ content: input.content }).content as string;
  const inserted = await state.pool.query(
    `INSERT INTO memory_entries (workspace_id, owner_principal_id, owner_platform, visibility, scope_key, tags, content)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id, created_at`,
    [workspace.id, allowed.actorPrincipalId, allowed.actorChatPlatform, input.visibility, input.scopeKey ?? null, input.tags, content],
  );
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    actorTeamsAadUserId: allowed.actorTeamsAadUserId,
    eventType: "memory.written",
    resourceType: "memory",
    resourceId: inserted.rows[0].id,
    metadata: { visibility: input.visibility, scopeKey: input.scopeKey ?? null, source: "dashboard" },
  });
  sendJson(res, 201, { id: inserted.rows[0].id, createdAt: inserted.rows[0].created_at });
}

async function handleDeleteMemory(context: RouteContext): Promise<void> {
  const { res, url, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "memory:write", resource: "memory" });
  if (!allowed.ok) return;
  const idResult = z.uuid().safeParse(url.pathname.split("/")[3]);
  if (!idResult.success) {
    sendJson(res, 400, { error: "Invalid memory id" });
    return;
  }
  const id = idResult.data;
  const wide = allowed.roles.includes("owner") || allowed.roles.includes("admin");
  const result = wide
    ? await state.pool.query(`DELETE FROM memory_entries WHERE id = $1 AND workspace_id = $2 RETURNING id`, [id, workspace.id])
    : await state.pool.query(
        `DELETE FROM memory_entries
         WHERE id = $1 AND workspace_id = $2
           AND ( ($3::text IS NOT NULL AND owner_platform = 'slack' AND owner_principal_id = $3)
              OR ($4::text IS NOT NULL AND owner_platform = 'msteams' AND owner_principal_id = $4) )
         RETURNING id`,
        [id, workspace.id, allowed.actorSlackUserId, allowed.actorTeamsAadUserId],
      );
  if (!result.rowCount) {
    sendJson(res, 404, { error: "Memory entry not found" });
    return;
  }
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    actorTeamsAadUserId: allowed.actorTeamsAadUserId,
    eventType: "memory.deleted",
    resourceType: "memory",
    resourceId: id,
  });
  sendJson(res, 200, { id });
}

async function handleListSkills(context: RouteContext): Promise<void> {
  const { res, url, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "skills:read", resource: "skill" });
  if (!allowed.ok) return;
  const search = skillSearchSchema.parse({
    q: url.searchParams.get("q") ?? undefined,
    tags: parseCsvParam(url.searchParams.get("tags")),
    limit: url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : undefined,
  });
  const rows = await querySkills(state.pool, workspace.id, search);
  sendJson(res, 200, { items: rows });
}

async function handleUpsertSkill(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "skills:write", resource: "skill" });
  if (!allowed.ok) return;
  if (!allowed.actorPrincipalId || !allowed.actorChatPlatform) {
    sendJson(res, 400, { error: "missing_principal_context" });
    return;
  }
  const input = skillWriteSchema.parse(await readJson(req));
  const safe = redactRecordForPersistence({ body: input.body, triggerHint: input.triggerHint });
  const result = await state.pool.query(
    `INSERT INTO skill_definitions (workspace_id, name, trigger_hint, body, owner_principal_id, owner_platform, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (workspace_id, name)
     DO UPDATE SET trigger_hint = EXCLUDED.trigger_hint, body = EXCLUDED.body, tags = EXCLUDED.tags, updated_at = now()
     RETURNING id, name`,
    [workspace.id, input.name, safe.triggerHint as string, safe.body as string, allowed.actorPrincipalId, allowed.actorChatPlatform, input.tags],
  );
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    actorTeamsAadUserId: allowed.actorTeamsAadUserId,
    eventType: "skills.upserted",
    resourceType: "skill",
    resourceId: result.rows[0].id,
    metadata: { name: input.name, source: "dashboard" },
  });
  sendJson(res, 200, { id: result.rows[0].id, name: result.rows[0].name });
}

async function handleDeleteSkill(context: RouteContext): Promise<void> {
  const { res, url, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "skills:write", resource: "skill" });
  if (!allowed.ok) return;
  const idResult = z.uuid().safeParse(url.pathname.split("/")[3]);
  if (!idResult.success) {
    sendJson(res, 400, { error: "Invalid skill id" });
    return;
  }
  const id = idResult.data;
  const result = await state.pool.query(`DELETE FROM skill_definitions WHERE id = $1 AND workspace_id = $2 RETURNING id`, [id, workspace.id]);
  if (!result.rowCount) {
    sendJson(res, 404, { error: "Skill not found" });
    return;
  }
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    actorTeamsAadUserId: allowed.actorTeamsAadUserId,
    eventType: "skills.deleted",
    resourceType: "skill",
    resourceId: id,
  });
  sendJson(res, 200, { id });
}

// --- Governed scheduled workflows (migration 014) ---
// Operant owns the definition, RBAC, and audit; OpenClaw's cron subsystem executes.
// Materialization pushes a row into the gateway and is intentionally best-effort: when
// the control-plane device is not yet approved for cron scopes the gateway returns a
// pairing error, which we record on the row rather than failing the write — the
// governed definition stays the source of truth and can be re-applied once paired.

const WORKFLOW_COLUMNS = `id, owner_principal_id, owner_platform, name, description, schedule_kind,
  schedule_expression, timezone, target_channel, message, tools, enabled, openclaw_cron_id,
  materialization_status, materialization_error, last_materialized_at, created_at, updated_at`;

function workflowCronParams(workspace: { openclaw_gateway_url?: string | null }) {
  return {
    gatewayToken: process.env.OPENCLAW_GATEWAY_TOKEN,
    extraEnv: openClawObservationCommandExtraEnv(workspace),
    timeoutMs: Number(process.env.OPENCLAW_CHECK_TIMEOUT_MS || 20_000),
  };
}

function runWorkflowCron(workspace: { openclaw_gateway_url?: string | null }, baseArgs: string[]) {
  const params = workflowCronParams(workspace);
  return runOpenClawCommand(openClawGatewayCommandArgs(baseArgs, params), params);
}

function workflowSpecFromRow(row: any): CronJobSpec {
  return {
    name: row.name,
    scheduleKind: row.schedule_kind,
    scheduleExpression: row.schedule_expression,
    timezone: row.timezone,
    channel: row.target_channel,
    message: row.message,
    tools: row.tools ?? [],
  };
}

// (Re)apply a workflow row to the gateway and persist the resulting materialization
// status. Returns the updated row plus an apply summary for the response/audit.
async function materializeWorkflow(pool: Queryable, workspace: any, row: any): Promise<{ row: any; apply: { status: string; ok: boolean; command: string[]; exitCode: number | null; stderr: string } }> {
  let status: "materialized" | "disabled" | "error" | "pending" = "pending";
  let cronId: string | null = row.openclaw_cron_id ?? null;
  let errorText: string | null = null;
  let command: string[] = [];
  let exitCode: number | null = 0;
  let stderr = "";

  if (row.enabled) {
    const result = cronId
      ? await runWorkflowCron(workspace, cronControlArgs("enable", cronId))
      : await runWorkflowCron(workspace, cronAddArgs(workflowSpecFromRow(row)));
    command = result.command;
    exitCode = result.exitCode;
    stderr = result.stderr;
    if (result.exitCode === 0) {
      if (!cronId) cronId = extractCronJobId(result.json);
      if (!cronId) {
        // `cron add` reported success but returned no job id. Marking 'materialized'
        // without an id would re-`cron add` on the next apply and orphan a duplicate job.
        status = "error";
        errorText = "gateway accepted cron add but returned no job id";
      } else {
        status = "materialized";
        errorText = null;
      }
    } else {
      status = "error";
      errorText = (result.stderr || result.stdout || "gateway command failed").slice(0, 2000);
    }
  } else if (cronId) {
    const result = await runWorkflowCron(workspace, cronControlArgs("disable", cronId));
    command = result.command;
    exitCode = result.exitCode;
    stderr = result.stderr;
    if (result.exitCode === 0) {
      status = "disabled";
      errorText = null;
    } else {
      status = "error";
      errorText = (result.stderr || result.stdout || "gateway command failed").slice(0, 2000);
    }
  } else {
    // Disabled and never materialized: nothing to push, definition stays pending.
    status = "pending";
  }

  const updated = await pool.query(
    `UPDATE scheduled_workflows
     SET openclaw_cron_id = $2,
         materialization_status = $3,
         materialization_error = $4,
         last_materialized_at = CASE WHEN $3 = 'materialized' THEN now() ELSE last_materialized_at END,
         updated_at = now()
     WHERE id = $1
     RETURNING ${WORKFLOW_COLUMNS}`,
    [row.id, cronId, status, errorText],
  );
  return { row: updated.rows[0] ?? row, apply: { status, ok: status !== "error", command, exitCode, stderr: stderr.slice(0, 2000) } };
}

async function handleListWorkflows(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "workflow:read", resource: "workflow" });
  if (!allowed.ok) return;
  const rows = await state.pool.query(
    `SELECT ${WORKFLOW_COLUMNS} FROM scheduled_workflows WHERE workspace_id = $1 ORDER BY created_at DESC`,
    [workspace.id],
  );
  sendJson(res, 200, { items: rows.rows });
}

async function handleCreateWorkflow(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "workflow:write", resource: "workflow" });
  if (!allowed.ok) return;
  if (!allowed.actorPrincipalId || !allowed.actorChatPlatform) {
    sendJson(res, 400, { error: "missing_principal_context" });
    return;
  }
  const input = scheduledWorkflowCreateSchema.parse(await readJson(req));
  const safe = redactRecordForPersistence({ message: input.message, description: input.description ?? null });
  let inserted;
  try {
    inserted = await state.pool.query(
      `INSERT INTO scheduled_workflows
         (workspace_id, owner_principal_id, owner_platform, name, description, schedule_kind, schedule_expression, timezone, target_channel, message, tools, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING ${WORKFLOW_COLUMNS}`,
      [
        workspace.id,
        allowed.actorPrincipalId,
        allowed.actorChatPlatform,
        input.name,
        safe.description as string | null,
        input.scheduleKind,
        input.scheduleExpression,
        input.timezone ?? null,
        input.targetChannel,
        safe.message as string,
        input.tools,
        input.enabled,
      ],
    );
  } catch (error) {
    if (error && typeof error === "object" && (error as { code?: string }).code === "23505") {
      sendJson(res, 409, { error: "A workflow with that name already exists" });
      return;
    }
    throw error;
  }
  const { row, apply } = await materializeWorkflow(state.pool, workspace, inserted.rows[0]);
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    actorTeamsAadUserId: allowed.actorTeamsAadUserId,
    eventType: "workflow.created",
    resourceType: "workflow",
    resourceId: row.id,
    outcome: apply.ok ? "success" : "failure",
    metadata: {
      name: input.name,
      scheduleKind: input.scheduleKind,
      scheduleExpression: input.scheduleExpression,
      targetChannel: input.targetChannel,
      enabled: input.enabled,
      materializationStatus: row.materialization_status,
      source: "dashboard",
    },
  });
  sendJson(res, 201, { workflow: row, apply });
}

async function handleApplyWorkflow(context: RouteContext): Promise<void> {
  const { req, res, url, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "workflow:write", resource: "workflow" });
  if (!allowed.ok) return;
  const idResult = z.uuid().safeParse(url.pathname.split("/")[3]);
  if (!idResult.success) {
    sendJson(res, 400, { error: "Invalid workflow id" });
    return;
  }
  const input = scheduledWorkflowApplySchema.parse(await readJson(req));
  // Lock the row for the whole read -> materialize so two concurrent applies of an
  // un-materialized workflow cannot both `cron add` and orphan a duplicate gateway job.
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query(
      `SELECT ${WORKFLOW_COLUMNS} FROM scheduled_workflows WHERE id = $1 AND workspace_id = $2 FOR UPDATE`,
      [idResult.data, workspace.id],
    );
    if (!existing.rowCount) {
      await client.query("ROLLBACK");
      sendJson(res, 404, { error: "Workflow not found" });
      return;
    }
    let current = existing.rows[0];
    if (typeof input.enabled === "boolean" && input.enabled !== current.enabled) {
      const flipped = await client.query(
        `UPDATE scheduled_workflows SET enabled = $2, updated_at = now() WHERE id = $1 RETURNING ${WORKFLOW_COLUMNS}`,
        [current.id, input.enabled],
      );
      current = flipped.rows[0];
    }
    const { row, apply } = await materializeWorkflow(client, workspace, current);
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      actorSlackUserId: allowed.actorSlackUserId,
      actorTeamsAadUserId: allowed.actorTeamsAadUserId,
      eventType: "workflow.applied",
      resourceType: "workflow",
      resourceId: row.id,
      outcome: apply.ok ? "success" : "failure",
      metadata: { name: row.name, enabled: row.enabled, materializationStatus: row.materialization_status, source: "dashboard" },
    });
    await client.query("COMMIT");
    sendJson(res, 200, { workflow: row, apply });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function handleDeleteWorkflow(context: RouteContext): Promise<void> {
  const { res, url, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "workflow:write", resource: "workflow" });
  if (!allowed.ok) return;
  const idResult = z.uuid().safeParse(url.pathname.split("/")[3]);
  if (!idResult.success) {
    sendJson(res, 400, { error: "Invalid workflow id" });
    return;
  }
  // Lock the row for read -> cron rm -> delete (same guarantee as apply), so a concurrent apply
  // cannot `cron add` a fresh job that this delete then fails to see and orphans.
  const client = await state.pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query(
      `SELECT openclaw_cron_id FROM scheduled_workflows WHERE id = $1 AND workspace_id = $2 FOR UPDATE`,
      [idResult.data, workspace.id],
    );
    if (!existing.rowCount) {
      await client.query("ROLLBACK");
      sendJson(res, 404, { error: "Workflow not found" });
      return;
    }
    // Remove the gateway cron job BEFORE deleting the governed row. If the removal fails (gateway
    // unreachable or the control-plane device is not approved for cron scopes), keep the row marked
    // 'error' rather than orphaning a still-firing job that reconcile can no longer see or clean up.
    const cronId = existing.rows[0].openclaw_cron_id;
    let removal: { command: string[]; exitCode: number | null; stderr: string } | null = null;
    if (cronId) {
      const result = await runWorkflowCron(workspace, cronControlArgs("rm", cronId));
      removal = { command: result.command, exitCode: result.exitCode, stderr: result.stderr.slice(0, 2000) };
      if (result.exitCode !== 0) {
        await client.query(
          `UPDATE scheduled_workflows SET materialization_status = 'error', materialization_error = $2, updated_at = now() WHERE id = $1`,
          [idResult.data, (result.stderr || result.stdout || "gateway cron rm failed").slice(0, 2000)],
        );
        await audit(client, {
          companyId: workspace.company_id,
          workspaceId: workspace.id,
          actorUserId: allowed.actorUserId,
          actorSlackUserId: allowed.actorSlackUserId,
          actorTeamsAadUserId: allowed.actorTeamsAadUserId,
          eventType: "workflow.deleted",
          resourceType: "workflow",
          resourceId: idResult.data,
          outcome: "failure",
          metadata: { cronRemoved: false, retained: true, source: "dashboard" },
        });
        await client.query("COMMIT");
        sendJson(res, 502, { error: "Gateway cron removal failed; workflow retained for retry", cronRemoval: removal });
        return;
      }
    }
    await client.query(
      `DELETE FROM scheduled_workflows WHERE id = $1 AND workspace_id = $2`,
      [idResult.data, workspace.id],
    );
    await audit(client, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      actorUserId: allowed.actorUserId,
      actorSlackUserId: allowed.actorSlackUserId,
      actorTeamsAadUserId: allowed.actorTeamsAadUserId,
      eventType: "workflow.deleted",
      resourceType: "workflow",
      resourceId: idResult.data,
      metadata: { cronRemoved: cronId ? true : null, source: "dashboard" },
    });
    await client.query("COMMIT");
    sendJson(res, 200, { id: idResult.data, cronRemoval: removal });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

// Reconcile governed workflows against the live `openclaw cron list`. Drift = the executor
// disagrees with Operant's intent: the gateway job is gone, OR its enabled state differs from
// the row's `enabled`. Only when gateway state matches intent is the row marked
// materialized/disabled. Operant's definition is authoritative, so we never let the gateway's
// reality silently overwrite a mismatch.
async function handleReconcileWorkflows(context: RouteContext): Promise<void> {
  const { res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "workflow:read", resource: "workflow" });
  if (!allowed.ok) return;
  const result = await runWorkflowCron(workspace, cronListArgs());
  if (result.exitCode !== 0 || !result.json) {
    sendJson(res, 502, { error: "OpenClaw cron list failed", command: result.command, exitCode: result.exitCode, stderr: result.stderr.slice(0, 2000) });
    return;
  }
  const observed = new Map(extractOpenClawCronObservations(result.json).map((job) => [job.id, job]));
  const rows = await state.pool.query(
    `SELECT ${WORKFLOW_COLUMNS} FROM scheduled_workflows WHERE workspace_id = $1 AND openclaw_cron_id IS NOT NULL`,
    [workspace.id],
  );
  let reconciled = 0;
  let drift = 0;
  for (const row of rows.rows) {
    const job = observed.get(row.openclaw_cron_id);
    const jobMissing = !job;
    let status: string;
    if (jobMissing) status = "drift";
    else if ((job.enabled !== false) !== row.enabled) status = "drift"; // executor disagrees with intent
    else status = row.enabled ? "materialized" : "disabled";
    if (status === "drift") drift += 1;
    // Clear the id only when the gateway job is truly gone, so a later apply re-`cron add`s a
    // fresh job. A present-but-mismatched job keeps its id so apply can enable/disable it in place.
    await state.pool.query(
      `UPDATE scheduled_workflows
         SET materialization_status = $2,
             openclaw_cron_id = CASE WHEN $3 THEN NULL ELSE openclaw_cron_id END,
             updated_at = now()
       WHERE id = $1`,
      [row.id, status, jobMissing],
    );
    reconciled += 1;
  }
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    actorUserId: allowed.actorUserId,
    actorSlackUserId: allowed.actorSlackUserId,
    actorTeamsAadUserId: allowed.actorTeamsAadUserId,
    eventType: "workflow.reconciled",
    resourceType: "workflow",
    metadata: { observedJobs: observed.size, reconciled, drift, source: "dashboard" },
  });
  const fresh = await state.pool.query(
    `SELECT ${WORKFLOW_COLUMNS} FROM scheduled_workflows WHERE workspace_id = $1 ORDER BY created_at DESC`,
    [workspace.id],
  );
  sendJson(res, 200, { ok: true, observedJobs: observed.size, reconciled, drift, items: fresh.rows });
}

async function handlePluginMemoryWrite({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = pluginMemoryWriteSchema.parse(await readJson(req));
  const principal = resolvePluginPrincipal(input.principalId);
  if (!principal) {
    sendJson(res, 400, { error: "missing_principal_context" });
    return;
  }
  const workspace = await getWorkspace(state.pool);
  const content = redactRecordForPersistence({ content: input.content }).content as string;
  const inserted = await state.pool.query(
    `INSERT INTO memory_entries (workspace_id, owner_principal_id, owner_platform, visibility, scope_key, tags, content)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id, created_at`,
    [workspace.id, principal.principalId, principal.platform, input.visibility, input.scopeKey ?? null, input.tags, content],
  );
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    ...principalAuditIds(principal),
    eventType: "memory.written",
    resourceType: "memory",
    resourceId: inserted.rows[0].id,
    metadata: { visibility: input.visibility, scopeKey: input.scopeKey ?? null, platform: principal.platform, principalId: principal.principalId, source: "plugin" },
  });
  sendJson(res, 200, { id: inserted.rows[0].id, createdAt: inserted.rows[0].created_at });
}

async function handlePluginMemorySearch({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = pluginMemorySearchSchema.parse(await readJson(req));
  const principal = resolvePluginPrincipal(input.principalId);
  if (!principal) {
    sendJson(res, 400, { error: "missing_principal_context" });
    return;
  }
  const workspace = await getWorkspace(state.pool);
  const scope = principalAuditIds(principal);
  const rows = await queryMemoryEntries(state.pool, workspace.id, {
    q: input.q,
    tags: input.tags,
    limit: input.limit,
    principalScope: { slackUserId: scope.actorSlackUserId, teamsAadUserId: scope.actorTeamsAadUserId },
  });
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    ...principalAuditIds(principal),
    eventType: "memory.read",
    resourceType: "memory",
    metadata: { q: input.q ?? null, count: rows.length, platform: principal.platform, principalId: principal.principalId, source: "plugin" },
  });
  sendJson(res, 200, { entries: rows });
}

async function handlePluginSkillSearch({ req, res, state }: RouteContext): Promise<void> {
  if (!isAuthorizedInternalRequest(req)) {
    sendJson(res, 401, { error: "Unauthorized" });
    return;
  }
  const input = pluginSkillSearchSchema.parse(await readJson(req));
  const principal = resolvePluginPrincipal(input.principalId);
  if (!principal) {
    sendJson(res, 400, { error: "missing_principal_context" });
    return;
  }
  const workspace = await getWorkspace(state.pool);
  const rows = await querySkills(state.pool, workspace.id, { q: input.q, tags: input.tags, limit: input.limit });
  await audit(state.pool, {
    companyId: workspace.company_id,
    workspaceId: workspace.id,
    ...principalAuditIds(principal),
    eventType: "skills.read",
    resourceType: "skill",
    metadata: { q: input.q ?? null, count: rows.length, platform: principal.platform, principalId: principal.principalId, source: "plugin" },
  });
  sendJson(res, 200, { skills: rows });
}

const listDefinitions: Record<string, { permission: { action: string; resource: string }; query: string }> = {
  audit_logs: {
    permission: { action: "audit:read", resource: "audit_log" },
    query: `SELECT id, company_id, workspace_id, actor_user_id, actor_slack_user_id, actor_teams_aad_user_id, event_type, resource_type, resource_id, outcome, metadata, created_at
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
  actor: Authorized,
): { query: string; params: unknown[] } {
  if (hasWorkspaceWideListAccess(table, actor.roles)) return { query: definition.query, params: [workspaceId] };
  if ((table === "sessions" || table === "jobs") && actor.actorChatPrincipals.length > 0) {
    const slackId = actor.actorSlackUserId;
    const teamsId = actor.actorTeamsAadUserId;
    if (table === "sessions") {
      return {
        query: `SELECT id, workspace_id, openclaw_session_key, channel_type, chat_channel_id, chat_principal_id,
                       slack_channel_id, slack_user_id, teams_conversation_id, teams_aad_user_id,
                       status, last_event_at, metadata, created_at
                FROM sessions
                WHERE workspace_id = $1
                  AND (
                    ($2::text IS NOT NULL AND channel_type = 'slack' AND (chat_principal_id = $2 OR slack_user_id = $2))
                    OR ($3::text IS NOT NULL AND channel_type = 'msteams' AND (chat_principal_id = $3 OR teams_aad_user_id = $3))
                  )
                ORDER BY created_at DESC
                LIMIT 100`,
        params: [workspaceId, slackId, teamsId],
      };
    }
    return {
      query: `SELECT j.id, j.workspace_id, j.session_id, j.openclaw_run_id, j.status, j.started_at, j.finished_at, j.metadata, j.created_at
              FROM jobs j
              JOIN sessions s ON s.id = j.session_id AND s.workspace_id = j.workspace_id
              WHERE j.workspace_id = $1
                AND (
                  ($2::text IS NOT NULL AND s.channel_type = 'slack' AND (s.chat_principal_id = $2 OR s.slack_user_id = $2))
                  OR ($3::text IS NOT NULL AND s.channel_type = 'msteams' AND (s.chat_principal_id = $3 OR s.teams_aad_user_id = $3))
                )
              ORDER BY j.created_at DESC
              LIMIT 100`,
      params: [workspaceId, slackId, teamsId],
    };
  }
  if (table === "approvals") {
    return {
      query: `SELECT id, workspace_id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at
              FROM approvals
              WHERE workspace_id = $1
                AND (
                  requested_by_user_id = $2
                  OR ($3::text IS NOT NULL AND COALESCE(payload->'operantApproval'->'approverSlackUserIds', '[]'::jsonb) ? $3)
                  OR ($4::text IS NOT NULL AND COALESCE(payload->'operantApproval'->'approverTeamsUserIds', '[]'::jsonb) ? $4)
                )
              ORDER BY created_at DESC
              LIMIT 100`,
      params: [workspaceId, actor.actorUserId, actor.actorSlackUserId, actor.actorTeamsAadUserId],
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
  const idResult = z.uuid().safeParse(url.pathname.split("/")[3]);
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
      `SELECT payload, requested_by_user_id
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
    // Separation of duties: the requester of a risky action cannot approve their
    // own request. Self-denial is allowed — it is just the requester cancelling.
    if (body.status === "approved" && pending.rows[0].requested_by_user_id === allowed.actorUserId) {
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.decision_denied",
        resourceType: "approval",
        resourceId: id,
        outcome: "deny",
        metadata: { reason: "self_approval" },
      });
      await client.query("COMMIT");
      sendJson(res, 403, { error: "You cannot approve your own request" });
      return;
    }
    const approvalRequirement = pending.rows[0]?.payload?.operantApproval ?? {};
    const requiredSlackApprovers = Array.isArray(approvalRequirement.approverSlackUserIds)
      ? Array.from(new Set(approvalRequirement.approverSlackUserIds.filter((value: unknown): value is string => typeof value === "string" && value.length > 0)))
      : [];
    const requiredTeamsApprovers = Array.isArray(approvalRequirement.approverTeamsUserIds)
      ? Array.from(new Set(approvalRequirement.approverTeamsUserIds.filter((value: unknown): value is string => typeof value === "string" && value.length > 0)))
      : [];
    const requiredApprovers = [
      ...requiredSlackApprovers.map((value) => `slack:${value}`),
      ...requiredTeamsApprovers.map((value) => `msteams:${value}`),
    ];
    const minApprovals = Math.max(1, Number.isInteger(Number(approvalRequirement.minApprovals)) ? Number(approvalRequirement.minApprovals) : 1);
    const actorSlackUserId = allowed.actorSlackUserId;
    const actorTeamsAadUserId = allowed.actorTeamsAadUserId;
    // Prefer the principal for the platform the session was minted on so a
    // dual-linked approver's decision attributes to the active chat platform.
    const orderedPrincipals = [...allowed.actorChatPrincipals].sort((a, b) => {
      if (a.platform === allowed.actorChatPlatform) return -1;
      if (b.platform === allowed.actorChatPlatform) return 1;
      return 0;
    });
    const actorPrincipals = orderedPrincipals.map((p) => `${p.platform}:${p.principalId}`);
    const actorPrincipal = actorPrincipals.find((tag) => requiredApprovers.includes(tag))
      ?? (allowed.actorChatPlatform && allowed.actorPrincipalId ? `${allowed.actorChatPlatform}:${allowed.actorPrincipalId}` : null);
    if (requiredApprovers.length < 1 || minApprovals > requiredApprovers.length) {
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.decision_denied",
        resourceType: "approval",
        resourceId: id,
        outcome: "deny",
        metadata: { reason: "invalid_approval_requirement", requiredApprovers, minApprovals, actorSlackUserId, actorTeamsAadUserId, actorPrincipal, actorPrincipals },
      });
      await client.query("COMMIT");
      sendJson(res, 409, { error: "Approval is missing a valid configured approver requirement", requiredApprovers, minApprovals });
      return;
    }
    const matchingPrincipal = actorPrincipals.find((tag) => requiredApprovers.includes(tag));
    if (!matchingPrincipal) {
      await audit(client, {
        companyId: workspace.company_id,
        workspaceId: workspace.id,
        actorUserId: allowed.actorUserId,
        eventType: "approval.decision_denied",
        resourceType: "approval",
        resourceId: id,
        outcome: "deny",
        metadata: { requiredApprovers, actorSlackUserId, actorTeamsAadUserId, actorPrincipal, actorPrincipals },
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
        metadata: { reason: "duplicate_decision", existingStatus: existingDecision.rows[0].status, actorSlackUserId, actorTeamsAadUserId, actorPrincipal },
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
        metadata: { actorSlackUserId, actorTeamsAadUserId, actorPrincipal },
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
        metadata: { approvalsReceived, minApprovals, actorSlackUserId, actorTeamsAadUserId, actorPrincipal },
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
        metadata: { approvalsReceived, minApprovals, actorSlackUserId, actorTeamsAadUserId, actorPrincipal },
      });
    }
    await client.query("COMMIT");
    const decisionStatus = approvalsReceived >= minApprovals ? "approved" : "pending";
    sendJson(res, 200, {
      ...result.rows[0],
      approvalDecision: { status: decisionStatus, approvalsReceived, minApprovals },
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

// Revokes wiped users' Pipedream-connected accounts upstream (their OAuth grants
// live on Pipedream, not in Postgres, so the SQL wipe alone leaves them active).
// Network calls, kept OUT of the DB transaction; per-account failures are audited
// and returned rather than silently swallowed. No-op when Pipedream is unconfigured.
export async function revokePipedreamAccountsForWorkspace(
  pool: Queryable,
  workspace: { id: string; company_id: string },
  slackUserIds: string[],
  client: PipedreamConnectClient | null,
): Promise<{ configured: boolean; revoked: number; failures: Array<{ slackUserId: string; accountId?: string; error: string }> }> {
  if (!client || slackUserIds.length === 0) return { configured: Boolean(client), revoked: 0, failures: [] };
  let revoked = 0;
  const failures: Array<{ slackUserId: string; accountId?: string; error: string }> = [];
  for (const slackUserId of slackUserIds) {
    let accounts;
    try {
      accounts = await client.listAccounts({ externalUserId: slackUserId });
    } catch (error) {
      failures.push({ slackUserId, error: error instanceof Error ? error.message : "list_failed" });
      continue;
    }
    for (const account of accounts) {
      try {
        await client.deleteAccount(account.id);
        revoked += 1;
        await audit(pool, {
          companyId: workspace.company_id,
          workspaceId: workspace.id,
          actorSlackUserId: slackUserId,
          eventType: "pipedream.account_revoked",
          resourceType: "pipedream_account",
          resourceId: account.id,
          metadata: { slackUserId, app: account.app, reason: "wipe" },
        });
      } catch (error) {
        failures.push({ slackUserId, accountId: account.id, error: error instanceof Error ? error.message : "delete_failed" });
      }
    }
  }
  if (failures.length > 0) {
    await audit(pool, {
      companyId: workspace.company_id,
      workspaceId: workspace.id,
      eventType: "pipedream.revocation_failed",
      resourceType: "pipedream_account",
      outcome: "deny",
      metadata: { reason: "wipe", failures },
    });
  }
  return { configured: true, revoked, failures };
}

async function handleWipe(context: RouteContext): Promise<void> {
  const { req, res, state } = context;
  const workspace = await getWorkspace(state.pool);
  const allowed = await requirePermissionForWorkspace(context, workspace, { action: "data:wipe", resource: "retention" });
  if (!allowed.ok) return;
  const body = z.object({ scope: z.enum(retentionWipeScopes) }).parse(await readJson(req));
  // Capture connected users before the SQL wipe removes them, so their Pipedream
  // grants can be revoked upstream afterwards (a full workspace wipe only).
  const slackUserIds = body.scope === "workspace"
    ? (await state.pool.query(
        "SELECT DISTINCT slack_user_id FROM users WHERE company_id = $1 AND slack_user_id IS NOT NULL",
        [workspace.company_id],
      )).rows.map((row) => row.slack_user_id as string)
    : [];
  const client = await state.pool.connect();
  let result;
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
    result = updated.rows[0];
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  const pipedreamRevocation = await revokePipedreamAccountsForWorkspace(state.pool, workspace, slackUserIds, createPipedreamConnectClientFromEnv());
  sendJson(res, 200, { ...result, pipedreamRevocation });
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
  if (req.method === "GET" && url.pathname === "/api/integrations/pipedream/apps") return handlePipedreamApps(context);
  if (req.method === "GET" && url.pathname === "/api/integrations/pipedream/accounts") return handlePipedreamAccounts(context);
  if (req.method === "POST" && url.pathname === "/api/integrations/pipedream/connect-token") return handlePipedreamConnectToken(context);
  if (req.method === "DELETE" && url.pathname.startsWith("/api/integrations/pipedream/accounts/")) return handlePipedreamDisconnectAccount(context);
  if (req.method === "GET" && /^\/api\/integrations\/pipedream\/apps\/[^/]+\/actions$/.test(url.pathname)) return handlePipedreamAppActions(context);
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
  if (req.method === "GET" && url.pathname === "/api/memory") return handleListMemory(context);
  if (req.method === "POST" && url.pathname === "/api/memory") return handleWriteMemory(context);
  if (req.method === "DELETE" && /^\/api\/memory\/[^/]+$/.test(url.pathname)) return handleDeleteMemory(context);
  if (req.method === "GET" && url.pathname === "/api/skills") return handleListSkills(context);
  if (req.method === "POST" && url.pathname === "/api/skills") return handleUpsertSkill(context);
  if (req.method === "DELETE" && /^\/api\/skills\/[^/]+$/.test(url.pathname)) return handleDeleteSkill(context);
  if (req.method === "GET" && url.pathname === "/api/workflows") return handleListWorkflows(context);
  if (req.method === "POST" && url.pathname === "/api/workflows") return handleCreateWorkflow(context);
  if (req.method === "POST" && url.pathname === "/api/workflows/sync") return handleReconcileWorkflows(context);
  if (req.method === "POST" && /^\/api\/workflows\/[^/]+\/apply$/.test(url.pathname)) return handleApplyWorkflow(context);
  if (req.method === "DELETE" && /^\/api\/workflows\/[^/]+$/.test(url.pathname)) return handleDeleteWorkflow(context);
  if (req.method === "GET" && url.pathname.startsWith("/internal/openclaw/secrets/")) return handleSecret(context);
  if (req.method === "POST" && url.pathname === "/internal/openclaw/events") return handleOpenClawEvent(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/user-context") return handlePluginUserContext(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/policy-check") return handlePluginPolicyCheck(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/pipedream/apps") return handlePluginPipedreamSearchApps(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/pipedream/connect-token") return handlePluginPipedreamConnectToken(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/pipedream/accounts") return handlePluginPipedreamAccounts(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/memory/write") return handlePluginMemoryWrite(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/memory/search") return handlePluginMemorySearch(context);
  if (req.method === "POST" && url.pathname === "/internal/plugin/skills/search") return handlePluginSkillSearch(context);
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
      // Log the real error server-side, but do not echo it to the client: DB driver errors
      // routinely carry table/column/constraint names and query fragments.
      process.stderr.write(`unhandled request error: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
      sendJson(res, 500, { error: "Internal server error" });
    });
  });
}

export async function createApp() {
  const pool = createPool();
  await runMigrations(pool);
  await ensureDefaultWorkspace(pool, { seed: true });
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
