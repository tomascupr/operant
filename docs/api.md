# HTTP API reference

Operant's control plane is a single `node:http` process. Every route
dispatches from the `route()` function at the bottom of
`apps/control-plane/src/server.ts`; this document is a concise map of
that chain. The source is canonical; when in doubt, grep the handler
name in `server.ts`.

## Surfaces

- **Dashboard surface (`/api/*`)**: bearer-token authenticated. The
  vanilla-JS dashboard at `/` calls these. Sign in via
  `POST /api/auth/login` to get a token; subsequent requests send
  `Authorization: Bearer <token>`.
- **Internal surface (`/internal/*`)**: authenticated with
  `OPERANT_INTERNAL_TOKEN` (timing-safe equality). Only the OpenClaw
  gateway and the Operant OpenClaw plugin call these.
- **Public health (`/healthz`, `/readyz`)**: unauthenticated. Safe for
  load balancers and the `pnpm doctor` check.

All responses are JSON unless noted, with `cache-control: no-store` and
a strict same-origin Content-Security-Policy header. The dashboard's
static assets (`/`, `/app.js`, `/styles.css`, etc.) are served by the
same process.

## Public health

| Method | Path        | Purpose                                          |
| ------ | ----------- | ------------------------------------------------ |
| GET    | `/healthz`  | Process liveness.                                |
| GET    | `/readyz`   | DB reachable, generated OpenClaw config present. |

## Bootstrap & session

| Method | Path                 | Auth        | Purpose                                                                                       |
| ------ | -------------------- | ----------- | --------------------------------------------------------------------------------------------- |
| POST   | `/api/bootstrap`     | admin login token | Idempotently ensure the default company/workspace exists. Requires `OPERANT_ADMIN_LOGIN_TOKEN` (sent as the `adminLoginToken` body field or the `x-operant-admin-login-token` header, same as login); returns `{ companyId, workspaceId }`. Returns 503 if the token is not configured, 401 if it is missing or invalid. |
| POST   | `/api/auth/login`    | none        | Exchange `{slackUserId \| teamsAadUserId, adminLoginToken}` (add `platform` when both ids are sent) for a session bearer token (`operant.sessionToken`). |
| GET    | `/api/auth/me`       | session     | Current operator: Slack and/or Teams principal, session platform, workspace, roles, permissions. |
| POST   | `/api/auth/logout`   | session     | Revoke the calling session.                                                                   |

## Workspace settings & summary

| Method | Path             | Auth        | Purpose                                                                |
| ------ | ---------------- | ----------- | ---------------------------------------------------------------------- |
| GET    | `/api/settings`  | session     | Workspace settings (company name, retention windows, defaults).        |
| PUT    | `/api/settings`  | session     | Update workspace settings.                                             |
| GET    | `/api/summary`   | session     | Readiness summary: latest config checksum, missing-credential summary. |

## Credentials

Saved values are encrypted with AES-256-GCM (`v1:<iv>:<tag>:<ciphertext>`)
and stored in Postgres. Plaintext only ever moves over the wire on
write. Reads return only existence metadata.

| Method | Path                              | Auth    | Purpose                                                                                     |
| ------ | --------------------------------- | ------- | ------------------------------------------------------------------------------------------- |
| POST   | `/api/config/credentials`         | session | Save Slack bot/app/user tokens and/or Microsoft Teams app id/password/tenant + webhook, admin login token, model API key, OpenClaw gateway token. Bootstrap needs an `adminSlackUserId` or `adminTeamsAadUserId` and Slack tokens or a Teams app password. |
| GET    | `/api/integrations/credentials`   | session | List per-tool credential metadata (kind, key, scope, last-resolved-at) for the dashboard.   |
| POST   | `/api/integrations/credentials`   | session | Upsert a per-workspace or per-Slack-user tool credential (e.g. `github/api-token`).         |

## Pipedream marketplace

These routes power the self-serve Integrations tab. They require the five
Pipedream env vars from `.env.example`. Connect links are returned to the
requesting user but never persisted in audit metadata. Pipedream is a
third-party sub-processor that stores the brokered end-user OAuth tokens
outside the Operant trust boundary; connect/invocation audit rows carry the
Slack principal in `actor_slack_user_id` for attestation. See
[compliance.md](compliance.md).

| Method | Path                                                         | Auth    | Purpose                                                                 |
| ------ | ------------------------------------------------------------ | ------- | ----------------------------------------------------------------------- |
| GET    | `/api/integrations/pipedream/apps?q=&limit=&after=`          | session | Search/list the Pipedream app catalog.                                  |
| GET    | `/api/integrations/pipedream/accounts?app=`                  | session | List the signed-in Slack user's connected Pipedream accounts.           |
| GET    | `/api/integrations/pipedream/apps/{slug}/actions`            | session | Preview MCP actions for an app, filtered through Operant tool policy.   |
| POST   | `/api/integrations/pipedream/connect-token`                  | session | Create a short-lived Pipedream Connect link for the signed-in user.     |
| DELETE | `/api/integrations/pipedream/accounts/{account_id}`          | session | Revoke one of the signed-in user's connected Pipedream accounts.        |

## OpenClaw config & operator checks

Operant generates `openclaw.json` and ships it to the gateway over a
shared volume. The gateway runs `openclaw <check>` commands and we
parse their output back.

| Method | Path                                       | Auth    | Purpose                                                                          |
| ------ | ------------------------------------------ | ------- | -------------------------------------------------------------------------------- |
| POST   | `/api/openclaw/config`                     | session | Regenerate `openclaw.json` from current policy + credentials. Returns checksum.  |
| GET    | `/api/openclaw/config`                     | session | Latest generated config.                                                         |
| GET    | `/api/openclaw/checks`                     | session | Index of available operator checks: `status`, `doctor`, `security-audit`, etc.   |
| POST   | `/api/openclaw/checks/<name>`              | session | Run an OpenClaw operator check by name. Output parsed into JSON when possible.   |
| POST   | `/api/openclaw/observations/sync`          | session | Pull sessions/tasks/usage from OpenClaw and mirror into Operant tables.          |
| GET    | `/api/pipedream/diagnostics`               | session | Validate the five `PIPEDREAM_*` env vars and report OAuth/MCP reachability.      |

## Policy

Order of evaluation: DM allowlist → channel policy → tool policy
(`tool`, `action`, optional `slackUserIds`/`roleNames` principals) →
approvals. Explicit `deny` beats `approval_required` beats `allow`.

| Method | Path                     | Auth    | Purpose                                                          |
| ------ | ------------------------ | ------- | ---------------------------------------------------------------- |
| GET    | `/api/policy`            | session | Effective policy snapshot.                                       |
| PUT    | `/api/policy`            | session | Replace the policy (channels, tools, approvals, DM allowlist).   |
| POST   | `/api/policies`          | session | Alias of `PUT /api/policy`.                                      |
| POST   | `/api/policy/evaluate`   | session | Dry-run a decision. Slack: `{tool, action, slackUserId, channelId}`; Teams: `{channelType:"msteams", tool, action, teamsAadUserId, teamId, teamsChannelId}`. |

## RBAC

Six built-in roles (`owner`, `admin`, `integration_admin`,
`billing_usage_admin`, `member`, `viewer`) plus arbitrary custom roles.
Permissions are `action:resource` tuples; `*` is a wildcard on either
side.

| Method | Path           | Auth    | Purpose                                                                |
| ------ | -------------- | ------- | ---------------------------------------------------------------------- |
| GET    | `/api/roles`   | session | List roles and their permission tuples.                                |
| POST   | `/api/roles`   | session | Create or update a custom role; built-in roles are seeded and locked.  |
| GET    | `/api/users`   | session | List workspace users with role assignments.                            |
| POST   | `/api/users`   | session | Upsert a user and assign/revoke roles.                                 |

## Memory and Skills

Governed team memory and reusable skills (migration `013_memory_skills.sql`).
Memory entries carry `team` or `private` visibility; skills are admin-curated,
named text procedures (a `name` + `triggerHint` + `body`) retrieved by the
agent — not pushed into OpenClaw's native skills runtime. Search is
Postgres-native keyword search (`tsvector` + GIN; no embeddings in v1).
Visibility is enforced server-side in SQL: an agent or non-admin only ever
sees `team` entries plus its own `private` entries — private entries never
cross principals. Every write and read is audited and content/body is
redacted before persistence.

| Method | Path                | Auth               | Purpose                                                                                          |
| ------ | ------------------- | ------------------ | ------------------------------------------------------------------------------------------------ |
| GET    | `/api/memory`       | session (`memory:read`)  | List memory entries visible to the signed-in principal (team + own private).               |
| POST   | `/api/memory`       | session (`memory:write`) | Create a memory entry. Body `{visibility:"team"\|"private", scopeKey?, tags?, content}`.    |
| DELETE | `/api/memory/<id>`  | session (`memory:write`) | Delete a memory entry. Owner/admin can delete any; others only their own entries.          |
| GET    | `/api/skills`       | session (`skills:read`)  | List skill definitions for the workspace.                                                  |
| POST   | `/api/skills`       | session (`skills:write`, owner/admin only) | Create or upsert a skill (unique by name). Body `{name, triggerHint, body, tags?}`. |
| DELETE | `/api/skills/<id>`  | session (`skills:write`, owner/admin only) | Delete a skill definition.                                                |

`memory:read`/`memory:write` resolve to resource `memory`; `skills:read`/
`skills:write` to resource `skill`. Owner and admin hold all four;
`integration_admin` and `viewer` are read-only; `member` adds `memory:write`.
`skills:write` (skill authoring) is owner/admin only.

## Activity, audit, usage, approvals

| Method | Path                     | Auth    | Purpose                                                  |
| ------ | ------------------------ | ------- | -------------------------------------------------------- |
| GET    | `/api/sessions`          | session | Agent sessions mirrored from OpenClaw.                   |
| GET    | `/api/jobs`              | session | Background jobs and their status.                        |
| GET    | `/api/audit`             | session | Token-redacted audit log.                                |
| GET    | `/api/approvals`         | session | Pending and resolved approval requests.                  |
| POST   | `/api/approvals`         | session | Create an approval request. Body `{action, resource, payload?}`. 201 on success; 409 if no enabled approval policy matches. |
| POST   | `/api/approvals/<id>/decision` | session | Decide a pending approval. Body `{status: "approved" \| "denied"}`. |
| GET    | `/api/usage`             | session | Per-event usage rows (tokens, cost).                    |
| GET    | `/api/usage/summary`     | session | Roll-up of usage and cost by model, tool, day, and Slack user (`byUser`; events with no session bucket as `unattributed`). The `byUser` rollup groups on `slack_user_id` only, so Teams-originated sessions currently roll up under `unattributed` rather than per-Teams-user. |

## Retention

| Method | Path                     | Auth    | Purpose                                                                 |
| ------ | ------------------------ | ------- | ----------------------------------------------------------------------- |
| POST   | `/api/export`            | session | Queue a workspace export (sessions, audit, usage). Returns a job ID.    |
| POST   | `/api/retention/purge`   | session | Run retention purge: delete records beyond the configured window.       |
| POST   | `/api/wipe`              | session | Queue a workspace wipe request (subject to two-person rule if enabled). |

## Internal (OpenClaw gateway + plugin)

These endpoints require `Authorization: Bearer $OPERANT_INTERNAL_TOKEN`.
They are how OpenClaw resolves secrets just-in-time and how the
Operant OpenClaw plugin asks the control plane for live policy
decisions and user context. The control plane verifies the bearer with
`crypto.timingSafeEqual`. The memory/skills routes take a `principalId`
in the body and resolve the platform (Slack or Teams) from its shape.

| Method | Path                                       | Purpose                                                                                          |
| ------ | ------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| GET    | `/internal/openclaw/secrets/<refId>`       | Resolve a SecretRef and return the plaintext value. Logs an `integration_credential.resolved` audit row. |
| POST   | `/internal/openclaw/events`                | Ingest OpenClaw lifecycle events (session start/stop, tool invocation, approval requested).      |
| POST   | `/internal/plugin/user-context`            | Fetch context for the calling Slack user: roles, allowed channels, tool entitlements.            |
| POST   | `/internal/plugin/policy-check`            | Plugin asks "can this chat user do `tool/action` in `channel`?" using the same engine as `/api/policy/evaluate`. |
| POST   | `/internal/plugin/pipedream/apps`          | Plugin searches the Pipedream app catalog for Slack self-service.                                |
| POST   | `/internal/plugin/pipedream/connect-token` | Plugin creates a Pipedream Connect link for the requesting Slack user.                           |
| POST   | `/internal/plugin/pipedream/accounts`      | Plugin lists the requesting Slack user's connected Pipedream accounts.                           |
| POST   | `/internal/plugin/memory/write`            | Write a memory entry from the agent's principal. Redaction + audit applied server-side.          |
| POST   | `/internal/plugin/memory/search`           | Keyword-search memory for the agent's principal, returning team + own private entries.           |
| POST   | `/internal/plugin/skills/search`           | Keyword-search skill definitions, returning workspace-level results.                             |

`SecretRef IDs` follow `workspaces/<workspaceId>/<path>` for shared
secrets and `workspaces/<workspaceId>/users/<slackUserId>/<path>` for
per-user credentials. The control plane derives `slackUserId` from the
ref ID and includes it in the resolved-audit row so per-user
credential pulls are attestable.

## Conventions

- **Errors** are JSON `{ "error": "<message>" }` with an appropriate
  HTTP status. zod validation failures return `{ "error": "Invalid
  request", "issues": [{ code, path, message }] }`. A few responses add
  context fields alongside `error` (for example the Pipedream-not-configured
  `503` adds `code: "pipedream_not_configured"` and `required`). `401
  unauthorized` and `403 forbidden` are distinct: `401` means the bearer
  is missing or invalid, `403` means the role lacks the permission for
  the route.
- **Pagination**: list routes (`/api/audit`, `/api/approvals`,
  `/api/sessions`, `/api/jobs`, `/api/usage`) return `{ items: [...] }`
  capped at a fixed server-side limit (200 for audit, 100 for the rest).
  They do not accept `limit`/`offset` and do not return a `total`. The
  Pipedream app-catalog route (`/api/integrations/pipedream/apps`)
  accepts its own `limit` (default 40, max 100) plus an `after` cursor;
  there is no `offset`.
- **Redaction**: token-shaped strings (Slack `xox*`/`xapp-`, OpenAI
  `sk-*`, GitHub `ghp_`/`github_pat_`, AWS `AKIA*`, Pipedream
  `ctok_`/`tok_`) and Pipedream Connect links, plus the value of any
  object key matching token/apikey/password/secret/authorization/cookie/credential,
  are scrubbed from audit rows and exports before persistence
  (`apps/control-plane/src/redaction.ts`). The same sanitizer runs on
  memory `content` and skill `body`/`triggerHint` before `INSERT`, and
  every memory/skills read, write, and delete emits an audit row.
- **Idempotency**: `POST /api/openclaw/config`, `POST /api/wipe`, and
  `POST /api/retention/purge` are idempotent by checksum or job ID.

## Adding a new endpoint

New routes go in the `route()` chain near related handlers. Keep the
pattern `if (req.method === "X" && url.pathname === "..."`, attach a
handler from the same file or a sibling module, and update this doc.
The dashboard's CSP forbids external scripts, so any new dashboard-facing
endpoint should serve JSON consumed by `apps/control-plane/public/app.js`.
