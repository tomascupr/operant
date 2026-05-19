# Operant

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![verify](https://github.com/tomascupr/operant/actions/workflows/verify.yml/badge.svg)](https://github.com/tomascupr/operant/actions/workflows/verify.yml)
[![Node 24](https://img.shields.io/badge/node-24%2B-brightgreen)](package.json)
[![pnpm 11](https://img.shields.io/badge/pnpm-11%2B-f69220)](package.json)

**Slack AI that keeps employee credentials in your Postgres, not a vendor's.**

<!-- TODO before launch: replace with a real screenshot or GIF of the dashboard.
     Suggested capture: localhost:8080 Setup tab after first credential save,
     showing Slack/model SecretRef state and "Ready to run Slack acceptance".
![Operant dashboard](docs/assets/dashboard.png)
-->


Operant is an MIT-licensed control plane that lets your team mention or DM a
Slack bot to delegate work (send email, open PRs, run reports, schedule tasks)
under each employee's own OAuth tokens, with per-user policy, approval gates,
and a full audit trail. Everything runs inside your trust boundary; secrets
are AES-256-GCM-encrypted in Postgres and never leave the control plane.

### What's OpenClaw?

[OpenClaw](https://docs.openclaw.ai) is a permissively-licensed agent runtime
that handles Slack ingress (Socket Mode), agent sessions, the browser /
cloud-computer, tool execution, scheduled tasks, and approval UI. Operant
pairs with it: OpenClaw is the engine that talks to Slack and runs the agent,
Operant is the enterprise control plane wrapped around it (BYOK credentials,
RBAC, approval policy, audit, retention, usage tracking, admin dashboard).

### Get it running

```bash
pnpm install
pnpm init:env
pnpm compose:up -- -d
open http://localhost:8080
```

Sign in with the `OPERANT_ADMIN_LOGIN_TOKEN` from your generated `.env` plus
your Slack user ID. Full walkthrough in **[docs/setup.md](docs/setup.md)**.

## What's different about self-hosting

Slack AI coworkers are easy to demo and hard to trust in production. Hosted
versions store every employee's OAuth tokens in their cloud, ship one shared
admin/non-admin permission model, and pin every audit row to the workspace
instead of the human who actually triggered the action. Operant is for teams
that want the Slack-native experience without that trade.

- **Per-user credentials, not shared service accounts.** Alice's Gmail token
  and Bob's Gmail token live as separate AES-256-GCM rows in your Postgres,
  resolved per call and audited under the right human.
- **2,500+ SaaS tools, zero per-app code.** The optional
  [Operant OpenClaw plugin](apps/openclaw-plugin) bridges to Pipedream
  Connect, so each Slack user OAuths their own Gmail / Notion / HubSpot /
  Linear / GitHub account via a one-time connect link. The bot calls
  `pipedream_list_actions` and `pipedream_run_action` under that user's
  identity, gated by your Operant policy.
- **Real RBAC, not admin/non-admin.** Six built-in roles plus arbitrary
  custom `(action, resource)` permission pairs, with channel allowlists,
  per-Slack-user and per-role tool entitlements, and named-approver policies
  for risky actions.
- **One Compose project per workspace.** Postgres, Redis, OpenClaw state, and
  the generated config volume are scoped by project name so secrets never
  cross a trust boundary. Ports bind to `127.0.0.1` by default.
- **Auditable end to end.** Sessions, jobs, policy decisions, credential
  resolutions, usage/cost, exports, and wipes are recorded with token-shaped
  strings redacted before persistence.

## Architecture

One Operant deployment is one company, workspace, or trust boundary:

```text
Slack users
  -> OpenClaw Slack Socket Mode gateway
  -> OpenClaw runtime, tools, approvals, tasks, and thread replies
  -> Operant policy/audit control plane
  -> Postgres enterprise state

Operant dashboard
  -> encrypted Slack/model/tool credentials
  -> SecretRef-backed OpenClaw config
```

- `postgres`: canonical state, audit logs, encrypted credentials, policies,
  approvals, sessions, jobs, usage, exports, wipes.
- `policy-audit`: the Operant control-plane API and static admin dashboard.
- `openclaw-gateway`: the OpenClaw runtime with Slack Socket Mode,
  SecretRefs, agent sessions, usage, approvals, cron, tasks, skills,
  plugins, tools.
- `redis`: optional private queue profile for future async export/wipe
  workers.

Operant writes SecretRef-backed OpenClaw config. Plaintext secrets stay
encrypted in Postgres and are resolved at runtime through the internal
SecretRef resolver. Base Compose keeps Docker sandboxing off; the dedicated
`docker-compose.sandbox.yml` overlay opts into Docker-backed OpenClaw
sandboxing for single-trust-boundary hosts.

## Documentation

- **[Setup guide](docs/setup.md)**. The everyday operator path (stack,
  dashboard sign-in, Slack app, Pipedream Connect, integration credentials,
  sandbox overlay).
- **[Acceptance guide](docs/acceptance.md)**. Live verifiers, manual human
  post mode, strict gates, completion audit.
- **[Slack app setup](deploy/slack/README.md)**. Manifest, scopes, Socket
  Mode, token-generation helpers.

## Glossary

- **Operant**. This control plane (HTTP API, dashboard, Postgres state,
  RBAC, policy, audit).
- **OpenClaw**. The upstream agent runtime that owns Slack ingress, agent
  sessions, and tool execution. See <https://docs.openclaw.ai>.
- **`policy-audit`**. The Operant control-plane container in
  `docker-compose.yml`.
- **`openclaw-gateway`**. The OpenClaw runtime container.
- **SecretRef**. Opaque ID referencing an encrypted secret in Operant
  Postgres. OpenClaw resolves it at call time via the internal resolver
  rather than reading plaintext from disk.
- **BYOK**. Bring your own keys; Slack app token, bot token, model API
  key, and tool credentials all live in your Postgres.
- **Trust boundary**. One Compose project. Do not share Postgres volumes,
  OpenClaw state, or credentials between unrelated workspaces.

## Good First Areas

- Package a polished Helm release flow around the current chart skeleton.
- Add managed-upgrade playbooks for long-lived customer deployments.
- Build SSO/SAML/OIDC and SCIM adapters against the existing RBAC/session
  boundary.
- Extend compliance exports without exposing encrypted credential values.

## License

MIT. See [LICENSE](LICENSE).
