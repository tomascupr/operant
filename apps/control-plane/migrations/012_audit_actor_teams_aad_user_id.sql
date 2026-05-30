-- Teams per-user audit attribution. Slack actors are recorded in actor_slack_user_id
-- (migration 008); Teams actors previously had no dedicated column and were either
-- mislabeled into the Slack column or only present in metadata. Add a parallel,
-- indexed column so a Teams AAD principal can be attributed and queried directly.
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_teams_aad_user_id text;

CREATE INDEX IF NOT EXISTS audit_logs_actor_teams_aad_user_id_idx
  ON audit_logs (actor_teams_aad_user_id)
  WHERE actor_teams_aad_user_id IS NOT NULL;
