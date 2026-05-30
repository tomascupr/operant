import type { Permission, RoleName } from "./schema.js";

export const defaultPermissions: Permission[] = [
  { action: "*", resource: "*", description: "Unrestricted owner access" },
  { action: "settings:read", resource: "workspace", description: "Read workspace settings" },
  { action: "settings:update", resource: "workspace", description: "Update workspace settings" },
  { action: "users:read", resource: "user", description: "Read users and role assignments" },
  { action: "users:write", resource: "user", description: "Create users and update role assignments" },
  { action: "credentials:write", resource: "integration", description: "Create or update encrypted credentials" },
  { action: "integrations:read", resource: "integration", description: "Read integration summaries" },
  { action: "integrations:write", resource: "integration", description: "Configure integrations" },
  { action: "integrations:connect", resource: "integration", description: "Connect or revoke the caller's Pipedream accounts" },
  { action: "policy:read", resource: "policy", description: "Read policy" },
  { action: "policy:update", resource: "policy", description: "Update policy" },
  { action: "audit:read", resource: "audit_log", description: "Read audit logs" },
  { action: "usage:read", resource: "usage", description: "Read usage and costs" },
  { action: "approval:read", resource: "approval", description: "Read approval requests" },
  { action: "approval:decide", resource: "approval", description: "Approve or deny requests" },
  { action: "session:read", resource: "session", description: "Read sessions and jobs" },
  { action: "observability:sync", resource: "openclaw_observation", description: "Sync OpenClaw sessions, jobs, and usage into Operant" },
  { action: "task:create", resource: "openclaw_task", description: "Delegate work to OpenClaw" },
  { action: "data:export", resource: "retention", description: "Export retained data" },
  { action: "data:wipe", resource: "retention", description: "Wipe retained data" },
  { action: "memory:read", resource: "memory", description: "Read workspace memory entries" },
  { action: "memory:write", resource: "memory", description: "Create or delete memory entries" },
  { action: "skills:read", resource: "skill", description: "Read skill definitions" },
  { action: "skills:write", resource: "skill", description: "Create, update, or delete skill definitions" },
];

export const defaultRolePermissions: Record<RoleName, Array<Pick<Permission, "action" | "resource">>> = {
  owner: [{ action: "*", resource: "*" }],
  admin: [
    { action: "settings:read", resource: "workspace" },
    { action: "settings:update", resource: "workspace" },
    { action: "users:read", resource: "user" },
    { action: "users:write", resource: "user" },
    { action: "credentials:write", resource: "integration" },
    { action: "integrations:read", resource: "integration" },
    { action: "integrations:write", resource: "integration" },
    { action: "integrations:connect", resource: "integration" },
    { action: "policy:read", resource: "policy" },
    { action: "policy:update", resource: "policy" },
    { action: "audit:read", resource: "audit_log" },
    { action: "usage:read", resource: "usage" },
    { action: "approval:read", resource: "approval" },
    { action: "approval:decide", resource: "approval" },
    { action: "session:read", resource: "session" },
    { action: "observability:sync", resource: "openclaw_observation" },
    { action: "data:export", resource: "retention" },
    { action: "data:wipe", resource: "retention" },
    { action: "memory:read", resource: "memory" },
    { action: "memory:write", resource: "memory" },
    { action: "skills:read", resource: "skill" },
    { action: "skills:write", resource: "skill" },
  ],
  integration_admin: [
    { action: "settings:read", resource: "workspace" },
    { action: "credentials:write", resource: "integration" },
    { action: "integrations:read", resource: "integration" },
    { action: "integrations:write", resource: "integration" },
    { action: "integrations:connect", resource: "integration" },
    { action: "policy:read", resource: "policy" },
    { action: "session:read", resource: "session" },
    { action: "observability:sync", resource: "openclaw_observation" },
    { action: "memory:read", resource: "memory" },
    { action: "skills:read", resource: "skill" },
  ],
  billing_usage_admin: [
    { action: "settings:read", resource: "workspace" },
    { action: "usage:read", resource: "usage" },
    { action: "audit:read", resource: "audit_log" },
  ],
  member: [
    { action: "integrations:connect", resource: "integration" },
    { action: "task:create", resource: "openclaw_task" },
    { action: "session:read", resource: "session" },
    { action: "approval:read", resource: "approval" },
    { action: "approval:decide", resource: "approval" },
    { action: "memory:read", resource: "memory" },
    { action: "memory:write", resource: "memory" },
    { action: "skills:read", resource: "skill" },
  ],
  viewer: [
    { action: "settings:read", resource: "workspace" },
    { action: "users:read", resource: "user" },
    { action: "policy:read", resource: "policy" },
    { action: "audit:read", resource: "audit_log" },
    { action: "usage:read", resource: "usage" },
    { action: "session:read", resource: "session" },
    { action: "memory:read", resource: "memory" },
    { action: "skills:read", resource: "skill" },
  ],
};

export function permissionMatches(granted: Pick<Permission, "action" | "resource">, requested: Pick<Permission, "action" | "resource">): boolean {
  const actionMatches = granted.action === "*" || granted.action === requested.action;
  const resourceMatches = granted.resource === "*" || granted.resource === requested.resource;
  return actionMatches && resourceMatches;
}

export function hasPermission(roleNames: RoleName[], requested: Pick<Permission, "action" | "resource">): boolean {
  return roleNames.some((role) => {
    const grants = defaultRolePermissions[role] ?? [];
    return grants.some((granted) => permissionMatches(granted, requested));
  });
}
