ALTER TABLE integration_credentials
  ADD COLUMN IF NOT EXISTS slack_user_id text;
