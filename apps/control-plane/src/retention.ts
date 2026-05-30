import type { Database } from "./db.js";

type Queryable = Pick<Database, "query">;

export const retentionWipeScopes = ["workspace", "sessions", "usage", "audit"] as const;

export type RetentionWipeScope = (typeof retentionWipeScopes)[number];

export type WipeStatement = {
  label: string;
  sql: string;
};

export type RetentionPurgeStatement = WipeStatement;

export const retentionExportQueries = {
  settings: "SELECT model_provider, model_name, retention_days, created_at, updated_at FROM workspace_settings WHERE workspace_id = $1",
  credentials: "SELECT id, kind, label, secret_ref_id, created_at, updated_at FROM integration_credentials WHERE workspace_id = $1 ORDER BY created_at",
  channelPolicies: "SELECT channel_type, team_id, channel_id, name, enabled, require_mention, allowed_user_ids, denied_user_ids, created_at, updated_at FROM channel_policies WHERE workspace_id = $1 ORDER BY channel_type, team_id, channel_id",
  policyRules: "SELECT name, effect, resource, action, conditions, priority, enabled, created_at FROM policy_rules WHERE workspace_id = $1 ORDER BY priority, created_at",
  toolPolicies: "SELECT tool, action, effect, slack_user_ids, teams_aad_user_ids, role_names, created_at FROM tool_policies WHERE workspace_id = $1 ORDER BY tool, action, effect, created_at",
  approvalPolicies: "SELECT name, action_pattern, resource_pattern, approver_slack_user_ids, approver_teams_user_ids, min_approvals, enabled, created_at FROM approval_policies WHERE workspace_id = $1 ORDER BY created_at",
  approvals: "SELECT id, requested_by_user_id, status, action, resource, payload, decided_by_user_id, decided_at, created_at FROM approvals WHERE workspace_id = $1 ORDER BY created_at",
  approvalDecisions: "SELECT id, approval_id, decided_by_user_id, status, created_at FROM approval_decisions WHERE workspace_id = $1 ORDER BY created_at",
  auditLogs: "SELECT id, actor_user_id, event_type, resource_type, resource_id, outcome, metadata, created_at FROM audit_logs WHERE workspace_id = $1 ORDER BY created_at",
  sessions: "SELECT id, openclaw_session_key, channel_type, chat_channel_id, chat_principal_id, slack_channel_id, slack_user_id, teams_conversation_id, teams_aad_user_id, status, last_event_at, metadata, created_at FROM sessions WHERE workspace_id = $1 ORDER BY created_at",
  jobs: "SELECT id, session_id, openclaw_run_id, status, started_at, finished_at, metadata, created_at FROM jobs WHERE workspace_id = $1 ORDER BY created_at",
  usageEvents: "SELECT id, session_id, job_id, provider, model, input_tokens, output_tokens, tool_name, estimated_cost_usd, metadata, created_at FROM usage_events WHERE workspace_id = $1 ORDER BY created_at",
  openclawConfigs: "SELECT id, config, config_path, checksum, generated_at FROM openclaw_configs WHERE workspace_id = $1 ORDER BY generated_at",
} as const;

export function buildWipeStatements(scope: RetentionWipeScope): WipeStatement[] {
  switch (scope) {
    case "usage":
      return [{ label: "usageEvents", sql: "DELETE FROM usage_events WHERE workspace_id = $1" }];
    case "sessions":
      return [
        {
          label: "usageEvents",
          sql: `DELETE FROM usage_events
                WHERE workspace_id = $1
                  AND (
                    session_id IN (SELECT id FROM sessions WHERE workspace_id = $1)
                    OR job_id IN (SELECT id FROM jobs WHERE workspace_id = $1)
                  )`,
        },
        { label: "jobs", sql: "DELETE FROM jobs WHERE workspace_id = $1" },
        { label: "sessions", sql: "DELETE FROM sessions WHERE workspace_id = $1" },
      ];
    case "audit":
      return [{ label: "auditLogs", sql: "DELETE FROM audit_logs WHERE workspace_id = $1" }];
    case "workspace":
      return [
        { label: "usageEvents", sql: "DELETE FROM usage_events WHERE workspace_id = $1" },
        { label: "jobs", sql: "DELETE FROM jobs WHERE workspace_id = $1" },
        { label: "sessions", sql: "DELETE FROM sessions WHERE workspace_id = $1" },
        { label: "approvalDecisions", sql: "DELETE FROM approval_decisions WHERE workspace_id = $1" },
        { label: "approvals", sql: "DELETE FROM approvals WHERE workspace_id = $1" },
        { label: "adminSessions", sql: "DELETE FROM admin_sessions WHERE workspace_id = $1" },
        { label: "auditLogs", sql: "DELETE FROM audit_logs WHERE workspace_id = $1" },
        { label: "retentionExports", sql: "DELETE FROM retention_exports WHERE workspace_id = $1" },
        { label: "openclawConfigs", sql: "DELETE FROM openclaw_configs WHERE workspace_id = $1" },
        { label: "channelPolicies", sql: "DELETE FROM channel_policies WHERE workspace_id = $1" },
        { label: "policyRules", sql: "DELETE FROM policy_rules WHERE workspace_id = $1" },
        { label: "toolPolicies", sql: "DELETE FROM tool_policies WHERE workspace_id = $1" },
        { label: "approvalPolicies", sql: "DELETE FROM approval_policies WHERE workspace_id = $1" },
        { label: "credentials", sql: "DELETE FROM integration_credentials WHERE workspace_id = $1" },
      ];
  }
}

export function buildRetentionPurgeStatements(): RetentionPurgeStatement[] {
  return [
    { label: "usageEvents", sql: "DELETE FROM usage_events WHERE workspace_id = $1 AND created_at < $2" },
    {
      label: "usageEventsLinkedToExpiredSessions",
      sql: `DELETE FROM usage_events
            WHERE workspace_id = $1
              AND (
                session_id IN (SELECT id FROM sessions WHERE workspace_id = $1 AND last_event_at < $2)
                OR job_id IN (
                  SELECT j.id
                  FROM jobs j
                  LEFT JOIN sessions s ON s.id = j.session_id AND s.workspace_id = j.workspace_id
                  WHERE j.workspace_id = $1
                    AND (j.created_at < $2 OR s.last_event_at < $2)
                )
              )`,
    },
    {
      label: "jobsLinkedToExpiredSessions",
      sql: `DELETE FROM jobs
            WHERE workspace_id = $1
              AND session_id IN (SELECT id FROM sessions WHERE workspace_id = $1 AND last_event_at < $2)`,
    },
    { label: "jobs", sql: "DELETE FROM jobs WHERE workspace_id = $1 AND created_at < $2" },
    { label: "sessions", sql: "DELETE FROM sessions WHERE workspace_id = $1 AND last_event_at < $2" },
    { label: "approvals", sql: "DELETE FROM approvals WHERE workspace_id = $1 AND created_at < $2" },
    { label: "auditLogs", sql: "DELETE FROM audit_logs WHERE workspace_id = $1 AND created_at < $2" },
  ];
}

export async function buildRetentionExport(pool: Queryable, workspace: {
  id: string;
  company_id: string;
  company_name: string;
  name: string;
  slack_team_id?: string | null;
  teams_app_id?: string | null;
  teams_tenant_id?: string | null;
  msteams_webhook_port?: number | null;
  msteams_webhook_path?: string | null;
  openclaw_gateway_url: string;
}) {
  const data: Record<string, unknown[]> = {};
  const counts: Record<string, number> = {};
  for (const [key, sql] of Object.entries(retentionExportQueries)) {
    const result = await pool.query(sql, [workspace.id]);
    data[key] = result.rows;
    counts[key] = result.rowCount ?? result.rows.length;
  }

  return {
    format: "operant.retention-export.v1",
    generatedAt: new Date().toISOString(),
    workspace: {
      id: workspace.id,
      companyId: workspace.company_id,
      companyName: workspace.company_name,
      name: workspace.name,
      slackTeamId: workspace.slack_team_id ?? null,
      teamsAppId: workspace.teams_app_id ?? null,
      teamsTenantId: workspace.teams_tenant_id ?? null,
      msteamsWebhookPort: workspace.msteams_webhook_port ?? null,
      msteamsWebhookPath: workspace.msteams_webhook_path ?? null,
      openclawGatewayUrl: workspace.openclaw_gateway_url,
    },
    counts,
    data,
  };
}

export async function applyRetentionWipe(pool: Queryable, workspaceId: string, scope: RetentionWipeScope): Promise<Record<string, number>> {
  const deleted: Record<string, number> = {};
  for (const statement of buildWipeStatements(scope)) {
    const result = await pool.query(statement.sql, [workspaceId]);
    deleted[statement.label] = result.rowCount ?? 0;
  }
  return deleted;
}

export async function applyRetentionPurge(pool: Queryable, workspaceId: string, retentionDays: number, now = new Date()): Promise<{
  cutoff: string;
  deleted: Record<string, number>;
}> {
  const cutoff = new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const deleted: Record<string, number> = {};
  for (const statement of buildRetentionPurgeStatements()) {
    const result = await pool.query(statement.sql, [workspaceId, cutoff]);
    deleted[statement.label] = result.rowCount ?? 0;
  }
  return { cutoff, deleted };
}
