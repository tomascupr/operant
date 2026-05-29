ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS actor_slack_user_id text;

CREATE INDEX IF NOT EXISTS audit_logs_workspace_actor_slack_user_id_idx
  ON audit_logs (workspace_id, actor_slack_user_id);
