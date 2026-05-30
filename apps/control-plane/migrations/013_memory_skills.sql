-- Governed team memory + skills store.
-- memory_entries: per-principal knowledge with team|private visibility, keyword-searchable.
-- skill_definitions: admin-curated, named, reusable text procedures, workspace-shared.
-- Keyword search uses a Postgres-native GENERATED tsvector + GIN index (no extensions
-- beyond pgcrypto, already enabled in 001). Writes are redacted by the control plane
-- before INSERT and every read/write is audited; this schema holds no plaintext secrets.

CREATE TABLE IF NOT EXISTS memory_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  owner_principal_id text NOT NULL,
  owner_platform text NOT NULL CHECK (owner_platform IN ('slack', 'msteams')),
  visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'team')),
  scope_key text,
  tags text[] NOT NULL DEFAULT '{}',
  content text NOT NULL,
  search_vector tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS memory_entries_search_idx ON memory_entries USING GIN (search_vector);
CREATE INDEX IF NOT EXISTS memory_entries_scope_idx ON memory_entries (workspace_id, visibility, owner_principal_id);
CREATE INDEX IF NOT EXISTS memory_entries_tags_idx ON memory_entries USING GIN (tags);

CREATE TABLE IF NOT EXISTS skill_definitions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name text NOT NULL,
  trigger_hint text NOT NULL,
  body text NOT NULL,
  owner_principal_id text NOT NULL,
  owner_platform text NOT NULL CHECK (owner_platform IN ('slack', 'msteams')),
  tags text[] NOT NULL DEFAULT '{}',
  search_vector tsvector GENERATED ALWAYS AS (
    to_tsvector('english', coalesce(name, '') || ' ' || coalesce(trigger_hint, '') || ' ' || coalesce(body, ''))
  ) STORED,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE INDEX IF NOT EXISTS skill_definitions_search_idx ON skill_definitions USING GIN (search_vector);
CREATE INDEX IF NOT EXISTS skill_definitions_workspace_idx ON skill_definitions (workspace_id);
CREATE INDEX IF NOT EXISTS skill_definitions_tags_idx ON skill_definitions USING GIN (tags);
