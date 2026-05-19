ALTER TABLE tool_policies
  ADD COLUMN IF NOT EXISTS slack_user_ids text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS role_names text[] NOT NULL DEFAULT '{}';

ALTER TABLE tool_policies
  DROP CONSTRAINT IF EXISTS tool_policies_workspace_id_tool_action_key;
