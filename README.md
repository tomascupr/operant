# Operant

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![verify](https://github.com/tomascupr/operant/actions/workflows/verify.yml/badge.svg)](https://github.com/tomascupr/operant/actions/workflows/verify.yml)
[![Node 24](https://img.shields.io/badge/node-24%2B-brightgreen)](package.json)

**Self-hosted agents in Slack with self-serve OAuth to 3,000+ tools.**

Hosted agents in Slack share one bot identity across your whole company.
Every employee's actions land in the audit log under "the workspace did
it." Operant doesn't. Each Slack user finds the app they need, connects
their own Gmail, Notion, GitHub, Linear, HubSpot, or other Pipedream
account, and asks the agent to work in Slack. The agent calls tools under
that human's connection, and every session, policy decision, and tool
call names the person who triggered it.

![Operant dashboard — Setup tab at first load](docs/assets/dashboard.png)

## Quickstart

```bash
pnpm install
pnpm init:env
pnpm compose:up -- -d
pnpm doctor
open http://localhost:8080
```

Sign in with the `OPERANT_ADMIN_LOGIN_TOKEN` from your generated `.env`
plus your Slack member ID (Slack profile → "Copy member ID"). The
**Setup** tab then walks you through Slack/model credentials — create
the Slack app from
[deploy/slack/manifest.yaml](deploy/slack/manifest.yaml) first
(see [deploy/slack/README.md](deploy/slack/README.md)). Full
walkthrough in **[docs/setup.md](docs/setup.md)**.

Requirements: Node 24+, pnpm 11+, Docker Compose v2.

Don't have pnpm 11 yet? Run `corepack enable` once — Node 24 ships
with Corepack and uses the pnpm version pinned in `package.json`.

## How it works

Operant pairs with [OpenClaw](https://docs.openclaw.ai), a permissively-
licensed agent runtime that owns Slack Socket Mode, agent sessions, the
browser / cloud-computer, and tool execution. Operant adds the
enterprise control plane around it: BYOK credentials, RBAC, policy,
approvals, audit, retention, usage tracking, and the admin dashboard.

```
Slack ──> OpenClaw gateway ──> Operant policy + audit ──> Postgres
                            └─> Pipedream Connect (per-user OAuth)
```

Slack app tokens, bot tokens, and model API keys live AES-256-GCM
encrypted in your Postgres. Per-user tool OAuth (Gmail / Notion / GitHub
/ ...) is held by [Pipedream Connect](https://pipedream.com/docs/connect)
under each Slack user's external ID. Custom non-Pipedream tool
credentials can also be stored encrypted in your Postgres, scoped to the
workspace or to a specific Slack user.

## Why Operant

- **Connect tools yourself.** The dashboard has an Integrations marketplace
  backed by Pipedream Connect: search apps, connect/reconnect accounts,
  preview actions, and revoke access.
- **Ask in Slack.** OpenClaw owns Slack Socket Mode, threading, files,
  browser/cloud-computer execution, and tool calling; Operant adds the
  control plane around it.
- **Act as the human.** Tool calls use the requester's Pipedream external
  user id, not a shared service account.
- **Control risky work.** Admins gate apps/actions with policy and
  named-approver rules before work runs.
- **Audit every run.** Sessions, jobs, policy decisions, Pipedream
  invocations, usage, exports, and retention events are durable and
  redacted before persistence.

## What you get

- Self-serve OAuth across 3,000+ SaaS tools via the Operant OpenClaw
  plugin and Pipedream Connect. Users can connect apps from the
  dashboard or ask the Slack agent for a connect link.
- Six built-in roles (`owner`, `admin`, `integration_admin`,
  `billing_usage_admin`, `member`, `viewer`) plus arbitrary custom
  `(action, resource)` permissions. Channel allowlists, per-Slack-user
  and per-role tool entitlements, named-approver policies for risky
  actions.
- Static same-origin admin dashboard: Setup, Health, Integrations,
  Policy, People, Approvals, Activity, Usage, Data, OpenClaw operator
  views. No bundler, no external scripts, strict CSP.
- One Postgres for state, optional Redis profile, Docker Compose
  topology with localhost-bound host ports and a per-workspace trust
  boundary. Helm chart and Fly artifacts ship for graduation.
- Sessions, jobs, policy decisions, credential resolutions, usage and
  cost, exports, retention, and wipes are recorded with token-shaped
  strings redacted before persistence.

| Capability | Operant surface |
| --- | --- |
| Slack agent runtime | OpenClaw gateway, Slack Socket Mode, sessions, tasks |
| App marketplace | Pipedream catalog search and curated local app cards |
| Per-user OAuth | Pipedream Connect accounts keyed by Slack user id |
| App/action policy | `pipedream:<app>` tool rules and role/user scopes |
| Approvals | Named approvers, minimum approvals, dashboard decisions |
| Audit and usage | Postgres audit log, sessions/jobs, per-user token and cost rows |
| Self-hosting | Docker Compose first, Helm/Fly artifacts for graduation |

![A real Operant deployment in Slack — multi-thread workspace activity from real users](docs/assets/slack-real-workspace.png)

*Above: a live Operant deployment (branded as @DuvoClaw inside
[Duvo](https://duvo.ai)) running real production conversations.*

## Docs

- **[Setup guide](docs/setup.md)**. Stack, dashboard sign-in, Slack
  app, Pipedream Connect, integration credentials, sandbox overlay.
- **[Acceptance guide](docs/acceptance.md)**. Live verifiers, manual
  human-post mode, strict gates.
- **[Slack app setup](deploy/slack/README.md)**. Manifest, scopes,
  Socket Mode, token helpers.
- **[HTTP API reference](docs/api.md)**. Dashboard and internal
  endpoints.
- **[Contributing](CONTRIBUTING.md)**. Local dev, PR expectations,
  release flow.
- **[Security policy](SECURITY.md)**. Reporting a vulnerability.
- **[Changelog](CHANGELOG.md)**. Release notes and version history.

## License

MIT. See [LICENSE](LICENSE).
