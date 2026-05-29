-- Track the chat platform the admin session was minted from so dual-identity
-- users (Slack + Teams) keep distinct sessions and approval checks know which
-- principal was active at login time.

ALTER TABLE admin_sessions
  ADD COLUMN IF NOT EXISTS principal_platform text;

-- Legacy sessions were Slack-only at mint time (Teams login did not exist).
-- Backfill them as 'slack' so resolveSessionActor does not silently misclassify
-- dual-identity users whose users row was later linked to a Teams principal.
UPDATE admin_sessions
SET principal_platform = 'slack'
WHERE principal_platform IS NULL;
