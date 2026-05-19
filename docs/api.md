# HTTP API reference

Operant's control plane is a single `node:http` process. Every route
dispatches from the `route()` function at the bottom of
`apps/control-plane/src/server.ts`; this document is a concise map of
that chain. The source is canonical — when in doubt, grep the handler
name in `server.ts`.

## Surfaces

- **Dashboard surface (`/api/*`)** — bearer-token authenticated. The
  vanilla-JS dashboard at `/` calls these. Sign in via
  `POST /api/auth/login` to get a token; subsequent requests send
  `Authorization: Bearer <token>`.
- **Internal surface (`/internal/*`)** — authenticated with
  `OPERANT_INTERNAL_TOKEN` (timing-safe equality). Only the OpenClaw
  gateway and the Operant OpenClaw plugin call these.
- **Public health (`/healthz`, `/readyz`)** — unauthenticated. Safe for
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
| POST   | `/api/bootstrap`     | none        | First-time owner bootstrap. Accepts a one-shot setup payload.                                 |
| POST   | `/api/auth/login`    | none        | Exchange `{slackUserId, adminLoginToken}` for a session bearer token (`operant.sessionToken`). |
| GET    | `/api/auth/me`       | session     | Current operator: Slack user ID, workspace, roles, permissions.                               |
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
| POST   | `/api/config/credentials`         | session | Save Slack bot/app/user tokens, admin login token, model API key, OpenClaw gateway token.   |
| GET    | `/api/integrations/credentials`   | session | List per-tool credential metadata (kind, key, scope, last-resolved-at) for the dashboard.   |
| POST   | `/api/integrations/credentials`   | session | Upsert a per-workspace or per-Slack-user tool credential (e.g. `github/api-token`).         |

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
| POST   | `/api/policy/evaluate`   | session | Dry-run a `{tool, action, slackUserId, channelId}` decision.     |

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

## Activity, audit, usage, approvals

| Method | Path                     | Auth    | Purpose                                                  |
| ------ | ------------------------ | ------- | -------------------------------------------------------- |
| GET    | `/api/sessions`          | session | Agent sessions mirrored from OpenClaw.                   |
| GET    | `/api/jobs`              | session | Background jobs and their status.                        |
| GET    | `/api/audit`             | session | Token-redacted audit log.                                |
| GET    | `/api/approvals`         | session | Pending and resolved approval requests.                  |
| POST   | `/api/approvals`         | session | Decide an approval (`approved` / `denied`).              |
| GET    | `/api/usage`             | session | Per-event usage rows (tokens, cost).                    |
| GET    | `/api/usage/summary`     | session | Roll-up of usage by model, day, and Slack user.          |

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
`crypto.timingSafeEqual`.

| Method | Path                                       | Purpose                                                                                          |
| ------ | ------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| GET    | `/internal/openclaw/secrets/<refId>`       | Resolve a SecretRef and return the plaintext value. Logs an `integration_credential.resolved` audit row. |
| POST   | `/internal/openclaw/events`                | Ingest OpenClaw lifecycle events (session start/stop, tool invocation, approval requested).      |
| POST   | `/internal/plugin/user-context`            | Fetch context for the calling Slack user: roles, allowed channels, tool entitlements.            |
| POST   | `/internal/plugin/policy-check`            | Plugin asks "can this Slack user do `tool/action` in `channel`?" — same engine as `/api/policy/evaluate`. |

`SecretRef IDs` follow `workspaces/<workspaceId>/<path>` for shared
secrets and `workspaces/<workspaceId>/users/<slackUserId>/<path>` for
per-user credentials. The control plane derives `slackUserId` from the
ref ID and includes it in the resolved-audit row so per-user
credential pulls are attestable.

## Conventions

- **Errors** are JSON `{ "error": "<message>", "code": "<snake_case>" }`
  with appropriate HTTP status. `401 unauthorized` and `403 forbidden`
  are distinct: `401` means the bearer is missing/invalid, `403` means
  the role lacks the permission for the route.
- **Pagination**: list routes accept `?limit=<n>&offset=<n>` and return
  `{ items: [...], total: <n> }`. The dashboard fetches small pages.
- **Redaction**: token-shaped strings (xox*, sk-*, AKIA*, JWT-shaped)
  are scrubbed from audit rows and exports before persistence
  (`apps/control-plane/src/redaction.ts`).
- **Idempotency**: `POST /api/openclaw/config`, `POST /api/wipe`, and
  `POST /api/retention/purge` are idempotent by checksum or job ID.

## Adding a new endpoint

New routes go in the `route()` chain near related handlers. Keep the
pattern `if (req.method === "X" && url.pathname === "..."`, attach a
handler from the same file or a sibling module, and update this doc.
The dashboard's CSP forbids external scripts, so any new dashboard-facing
endpoint should serve JSON consumed by `apps/control-plane/public/app.js`.
