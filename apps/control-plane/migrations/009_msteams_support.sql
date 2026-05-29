ALTER TABLE workspaces
  ADD COLUMN IF NOT EXISTS teams_app_id text,
  ADD COLUMN IF NOT EXISTS teams_tenant_id text,
  ADD COLUMN IF NOT EXISTS msteams_webhook_port integer NOT NULL DEFAULT 3978,
  ADD COLUMN IF NOT EXISTS msteams_webhook_path text NOT NULL DEFAULT '/api/messages';

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS teams_aad_user_id text,
  ADD COLUMN IF NOT EXISTS teams_bot_user_id text,
  ADD COLUMN IF NOT EXISTS teams_tenant_id text;

CREATE UNIQUE INDEX IF NOT EXISTS users_company_teams_aad_user_id_idx
  ON users (company_id, teams_aad_user_id)
  WHERE teams_aad_user_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_company_teams_bot_user_id_idx
  ON users (company_id, teams_bot_user_id)
  WHERE teams_bot_user_id IS NOT NULL;

ALTER TABLE channel_policies
  ADD COLUMN IF NOT EXISTS team_id text;

ALTER TABLE tool_policies
  ADD COLUMN IF NOT EXISTS teams_aad_user_ids text[] NOT NULL DEFAULT '{}';

ALTER TABLE approval_policies
  ADD COLUMN IF NOT EXISTS approver_teams_user_ids text[] NOT NULL DEFAULT '{}';

ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS channel_type text NOT NULL DEFAULT 'slack',
  ADD COLUMN IF NOT EXISTS chat_channel_id text,
  ADD COLUMN IF NOT EXISTS chat_principal_id text,
  ADD COLUMN IF NOT EXISTS teams_conversation_id text,
  ADD COLUMN IF NOT EXISTS teams_aad_user_id text;

UPDATE sessions
SET chat_channel_id = COALESCE(chat_channel_id, slack_channel_id),
    chat_principal_id = COALESCE(chat_principal_id, slack_user_id)
WHERE channel_type = 'slack';
