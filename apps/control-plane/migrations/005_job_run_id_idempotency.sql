WITH duplicate_jobs AS (
  SELECT id,
         row_number() OVER (
           PARTITION BY workspace_id, openclaw_run_id
           ORDER BY created_at ASC, id ASC
         ) AS row_number
  FROM jobs
  WHERE openclaw_run_id IS NOT NULL
)
DELETE FROM jobs
WHERE id IN (
  SELECT id
  FROM duplicate_jobs
  WHERE row_number > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS jobs_workspace_openclaw_run_id_idx
  ON jobs (workspace_id, openclaw_run_id)
  WHERE openclaw_run_id IS NOT NULL;
