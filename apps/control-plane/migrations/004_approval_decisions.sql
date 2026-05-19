CREATE TABLE IF NOT EXISTS approval_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  approval_id uuid NOT NULL REFERENCES approvals(id) ON DELETE CASCADE,
  decided_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  status text NOT NULL CHECK (status IN ('approved', 'denied')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (approval_id, decided_by_user_id)
);

CREATE INDEX IF NOT EXISTS approval_decisions_approval_idx
  ON approval_decisions (approval_id, status);
