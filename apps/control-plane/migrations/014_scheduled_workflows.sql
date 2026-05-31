-- Governed scheduled workflows.
-- Operant owns the definition + policy + audit of recurring agent runs; OpenClaw's
-- native cron subsystem stays the executor. A row here is the governed source of
-- truth; materialization pushes it into OpenClaw via `openclaw cron add`/`enable`/
-- `disable`/`rm`, and openclaw_cron_id pins the resulting gateway job. Reconciliation
-- compares these rows against `openclaw cron list` to surface drift. The message body
-- is redacted by the control plane before INSERT; this table holds no plaintext secrets.

CREATE TABLE IF NOT EXISTS scheduled_workflows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  owner_principal_id text NOT NULL,
  owner_platform text NOT NULL CHECK (owner_platform IN ('slack', 'msteams')),
  name text NOT NULL,
  description text,
  schedule_kind text NOT NULL CHECK (schedule_kind IN ('cron', 'every')),
  schedule_expression text NOT NULL,
  timezone text,
  target_channel text NOT NULL,
  message text NOT NULL,
  tools text[] NOT NULL DEFAULT '{}',
  enabled boolean NOT NULL DEFAULT true,
  openclaw_cron_id text,
  materialization_status text NOT NULL DEFAULT 'pending'
    CHECK (materialization_status IN ('pending', 'materialized', 'disabled', 'error', 'drift')),
  materialization_error text,
  last_materialized_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE INDEX IF NOT EXISTS scheduled_workflows_workspace_idx ON scheduled_workflows (workspace_id);
CREATE INDEX IF NOT EXISTS scheduled_workflows_cron_idx ON scheduled_workflows (workspace_id, openclaw_cron_id);
