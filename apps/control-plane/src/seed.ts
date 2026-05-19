import type { Database } from "./db.js";
import { defaultPermissions, defaultRolePermissions } from "./rbac.js";
import type { RoleName, WorkspaceRecord } from "./schema.js";

type Queryable = Pick<Database, "query">;

export async function ensureDefaultWorkspace(pool: Queryable): Promise<WorkspaceRecord> {
  const existing = await pool.query(
    `SELECT w.id AS workspace_id, w.company_id
     FROM workspaces w
     ORDER BY w.created_at
     LIMIT 1`,
  );
  if (existing.rowCount) {
    await seedRolesAndPermissions(pool, existing.rows[0].company_id);
    return {
      companyId: existing.rows[0].company_id,
      workspaceId: existing.rows[0].workspace_id,
    };
  }

  const companyName = process.env.OPERANT_DEFAULT_COMPANY_NAME || "Acme Inc.";
  const workspaceName = process.env.OPERANT_DEFAULT_WORKSPACE_NAME || "Acme Slack";
  const company = await pool.query(
    `INSERT INTO companies (name)
     VALUES ($1)
     ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
     RETURNING id`,
    [companyName],
  );
  const companyId = company.rows[0]?.id ?? (await pool.query("SELECT id FROM companies ORDER BY created_at LIMIT 1")).rows[0].id;
  const workspace = await pool.query(
    `INSERT INTO workspaces (company_id, name, openclaw_gateway_url, openclaw_config_path)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (company_id, name) DO UPDATE
     SET openclaw_gateway_url = EXCLUDED.openclaw_gateway_url,
         openclaw_config_path = EXCLUDED.openclaw_config_path
     RETURNING id`,
    [
      companyId,
      workspaceName,
      process.env.OPENCLAW_GATEWAY_URL || "http://openclaw-gateway:18789",
      process.env.OPENCLAW_CONFIG_PATH || "/operant/openclaw/openclaw.json",
    ],
  );
  const workspaceId = workspace.rows[0]?.id ?? (await pool.query("SELECT id FROM workspaces WHERE company_id = $1 ORDER BY created_at LIMIT 1", [companyId])).rows[0].id;

  await pool.query(
    `INSERT INTO workspace_settings (workspace_id, model_provider, model_name)
     VALUES ($1, 'openai', 'gpt-5')
     ON CONFLICT (workspace_id) DO NOTHING`,
    [workspaceId],
  );

  await seedRolesAndPermissions(pool, companyId);
  return { companyId, workspaceId };
}

export async function seedRolesAndPermissions(pool: Queryable, companyId: string): Promise<void> {
  for (const permission of defaultPermissions) {
    await pool.query(
      `INSERT INTO permissions (action, resource, description)
       VALUES ($1, $2, $3)
       ON CONFLICT (action, resource) DO UPDATE SET description = EXCLUDED.description`,
      [permission.action, permission.resource, permission.description ?? ""],
    );
  }

  for (const [roleName, grants] of Object.entries(defaultRolePermissions) as Array<[RoleName, typeof defaultRolePermissions[RoleName]]>) {
    const role = await pool.query(
      `INSERT INTO roles (company_id, name, builtin)
       VALUES ($1, $2, true)
       ON CONFLICT (company_id, name) DO UPDATE SET builtin = true
       RETURNING id`,
      [companyId, roleName],
    );
    const roleId = role.rows[0].id;
    await pool.query(
      `DELETE FROM role_permissions rp
       WHERE rp.role_id = $1
         AND NOT EXISTS (
           SELECT 1
           FROM permissions p
           JOIN jsonb_to_recordset($2::jsonb) AS wanted(action text, resource text)
             ON wanted.action = p.action AND wanted.resource = p.resource
           WHERE p.id = rp.permission_id
         )`,
      [roleId, JSON.stringify(grants)],
    );
    for (const grant of grants) {
      await pool.query(
        `INSERT INTO role_permissions (role_id, permission_id)
         SELECT $1, id FROM permissions WHERE action = $2 AND resource = $3
         ON CONFLICT DO NOTHING`,
        [roleId, grant.action, grant.resource],
      );
    }
  }
}
