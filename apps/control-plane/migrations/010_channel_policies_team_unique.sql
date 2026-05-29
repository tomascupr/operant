-- Microsoft Teams reuses channel ids across teams, so the
-- (workspace_id, channel_type, channel_id) UNIQUE constraint inherited from
-- migration 001 collides on legitimate cross-team policies. Widen the
-- constraint to include team_id. Backfill the column with the empty string so
-- we can keep it NOT NULL (Slack rows ignore it, Teams rows always carry a
-- real team id).

UPDATE channel_policies SET team_id = '' WHERE team_id IS NULL;

ALTER TABLE channel_policies ALTER COLUMN team_id SET DEFAULT '';
ALTER TABLE channel_policies ALTER COLUMN team_id SET NOT NULL;

ALTER TABLE channel_policies
  DROP CONSTRAINT IF EXISTS channel_policies_workspace_id_channel_type_channel_id_key;

DROP INDEX IF EXISTS channel_policies_workspace_id_channel_type_channel_id_key;

ALTER TABLE channel_policies
  ADD CONSTRAINT channel_policies_workspace_channel_team_key
  UNIQUE (workspace_id, channel_type, team_id, channel_id);
