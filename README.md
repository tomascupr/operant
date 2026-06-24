# Operant

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/tag/tomascupr/operant?label=release&sort=semver&color=success)](https://github.com/tomascupr/operant/releases)
[![verify](https://github.com/tomascupr/operant/actions/workflows/verify.yml/badge.svg)](https://github.com/tomascupr/operant/actions/workflows/verify.yml)
[![Node 24](https://img.shields.io/badge/node-24%2B-brightgreen)](package.json)
[![Stars](https://img.shields.io/github/stars/tomascupr/operant?style=flat&color=yellow)](https://github.com/tomascupr/operant/stargazers)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**The MIT-licensed, self-hosted control plane for AI agents in Slack and Microsoft Teams: every action runs as the human who asked, not a shared bot, with per-user OAuth to 3,000+ tools.**

Hosted agents — now including Anthropic's
[Claude Tag](https://www.anthropic.com/news/introducing-claude-tag) — put
one shared Claude in your channels that acts for everyone. Every
employee's actions land in the audit log under "the workspace did it."
Operant doesn't. Each person finds the app they need, connects their own
Gmail, Notion, GitHub, Linear, HubSpot, or other Pipedream account, and
asks the agent to work right where they already are, in Slack or Microsoft
Teams. The agent calls tools under that human's own connection, and every
session, policy decision, and tool call names the person who triggered it.

![Operant dashboard: Setup tab at first load](docs/assets/dashboard.png)

## Quickstart

**One command** — pulls the official images, generates fresh secrets, and boots
the whole stack (Postgres + control plane + OpenClaw gateway):

```bash
curl -fsSL https://raw.githubusercontent.com/tomascupr/operant/v0.6.0/install.sh | bash
```

It writes a self-contained `operant/` directory and prints your dashboard URL
and admin login token when it finishes. Requires only Docker with the Compose
v2 plugin — no checkout, no Node, no build.

**From source** — for development, the sandbox overlay, and live acceptance:

```bash
pnpm install
pnpm init:env
pnpm compose:up -- -d
pnpm doctor
open http://localhost:8080
```

Sign in with the `OPERANT_ADMIN_LOGIN_TOKEN` from your generated `.env`
plus your Slack member ID or Microsoft Teams user ID. The **Setup** tab
then walks you through credentials for Slack, Teams, or both, plus your
model key. Create the Slack app from
[deploy/slack/manifest.yaml](deploy/slack/manifest.yaml)
(see [deploy/slack/README.md](deploy/slack/README.md)), and wire an Azure
Bot to the OpenClaw Teams channel with
[deploy/teams/README.md](deploy/teams/README.md). Either platform stands
on its own, or run both side by side on one control plane. Full
walkthrough in **[docs/setup.md](docs/setup.md)**.

Requirements: Docker with the Compose v2 plugin. The from-source path also
needs Node 24+ and pnpm 11+ (run `corepack enable` once — Node 24 ships with
Corepack and uses the pnpm version pinned in `package.json`).

### Container images

Official images are published to GHCR on every release:

| Image | Architectures |
| --- | --- |
| `ghcr.io/tomascupr/operant/control-plane` | `linux/amd64`, `linux/arm64` |
| `ghcr.io/tomascupr/operant/openclaw-gateway` | `linux/amd64` |

Tags track the release: `latest`, `0.6.0`, `0.6`. The control plane runs
standalone against any Postgres — it migrates on boot:

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host:5432/operant \
  -e OPERANT_SECRET_KEY="$(openssl rand -base64 32)" \
  ghcr.io/tomascupr/operant/control-plane:latest
```

## How it works

Operant pairs with [OpenClaw](https://docs.openclaw.ai), a permissively-
licensed agent runtime that owns chat ingress for Slack (Socket Mode) and
Microsoft Teams (an Azure Bot webhook), agent sessions, the browser /
cloud-computer, and tool execution. Operant adds the enterprise control
plane around it: BYOK credentials, RBAC, policy, approvals, audit,
retention, usage tracking, and the admin dashboard.

```
Slack ──┐
        ├─> OpenClaw gateway ──> Operant policy + audit ──> Postgres
Teams ──┘                    └─> Pipedream Connect (per-user OAuth)
```

Pipedream Connect OAuth, tool policy, and audit all key on the active chat
user's principal (a Slack member ID or a Teams AAD ID).


Slack app tokens, bot tokens, and model API keys live AES-256-GCM
encrypted in your Postgres. Per-user tool OAuth (Gmail / Notion / GitHub
/ ...) is held by [Pipedream Connect](https://pipedream.com/docs/connect)
under each Slack user's external ID. Pipedream is a third-party
sub-processor: those end-user OAuth tokens live in Pipedream's own
infrastructure, outside your Operant/Postgres trust boundary. Operant
governs and audits that access; it does not store those tokens. See
[docs/compliance.md](docs/compliance.md). Custom non-Pipedream tool
credentials can also be stored encrypted in your Postgres, scoped to the
workspace or to a specific Slack user.

## How Operant compares

Most teams reach for one of three options to put an agent in Slack or
Teams. Here is where Operant sits.

| | Hosted agent (SaaS bot) | Raw OpenClaw on its own | Operant |
| --- | --- | --- | --- |
| Self-hostable | No | Yes | Yes |
| License | Proprietary | Permissive | MIT |
| Who the tool call runs as | One shared bot identity | Runtime default | The requesting human's own OAuth connection |
| Per-human audit | Workspace-level | Session-level | Every session, policy decision, and tool call names the person who triggered it |
| RBAC + custom roles | Vendor-defined tiers | Not built in | Six built-in roles plus arbitrary `(action, resource)` grants |
| Named-approver gates | Varies | Not built in | Per app/action, with minimum-approval rules |
| Slack and Teams as one identity | Per-product | Per-channel plugin | Dual-identity: one person, one policy and audit trail across both |
| Credentials | Vendor-held | Your config files | BYOK, AES-256-GCM encrypted in your Postgres |

### Operant vs Claude Tag

Anthropic's [Claude Tag](https://www.anthropic.com/news/introducing-claude-tag)
(June 2026) is the canonical hosted agent: one always-on Claude per Slack
channel, shared by the whole team, running on Anthropic's cloud. It is the
fastest way to get an AI teammate into Slack. Operant is the self-hosted,
governed alternative for teams that can't ship their channel and tool data
to a vendor, or that need per-person identity, model choice, and policy.

| | Claude Tag | Operant |
| --- | --- | --- |
| Where it runs | Anthropic-hosted SaaS | Self-hosted in your own infrastructure |
| License | Proprietary | MIT, open source |
| Model | Opus 4.8 only | BYOK — any model (Anthropic, OpenAI, …) |
| In-channel identity | One shared Claude acts for everyone | Every action runs as the human who asked |
| Tool access | Sources connected to the shared agent | Each person's own per-user OAuth to 3,000+ tools |
| Platforms | Slack today (Teams planned) | Slack and Teams today, one identity across both |
| Governance | Admin tool/data scopes, spend limits, activity logs | RBAC + custom roles, named-approver gates, channel/tool/approval policy, retention export and wipe |
| Where your data lives | Channel history and learned memory in Anthropic's cloud | Your Postgres, inside your trust boundary, AES-256-GCM at rest |
| Autonomy | Ambient mode acts proactively across the org | Work runs when asked; risky actions gate on policy and named approvers |
| Access | Enterprise/Team contract; auto-migrates from Claude in Slack on Aug 3, 2026 | Free; clone and run |

**Pick Claude Tag** if you are all-in on Anthropic, want zero-ops, and are
comfortable with Anthropic holding your Slack and tool data. **Pick Operant**
if you need to self-host, want every action attributed to a real person,
want to choose your own model, or need RBAC, approvals, and retention you
control.

## Why Operant

- **Connect tools yourself.** The dashboard has an Integrations marketplace
  backed by Pipedream Connect: search apps, connect/reconnect accounts,
  preview actions, and revoke access.
- **Ask in Slack or Teams.** OpenClaw owns chat ingress (Slack Socket
  Mode, Teams webhook), threading, files, browser/cloud-computer
  execution, and tool calling; Operant adds the control plane around it.
- **Act as the human.** Tool calls use the requester's Pipedream external
  user id, not a shared service account.
- **Control risky work.** Admins gate apps/actions with policy and
  named-approver rules before work runs.
- **Audit every run.** Sessions, jobs, policy decisions, Pipedream
  invocations, usage, exports, and retention events are durable and
  redacted before persistence.

## What you get

- Self-serve OAuth across 3,000+ SaaS tools via the Operant OpenClaw
  plugin and Pipedream Connect. Users connect apps from the dashboard or
  ask the agent, in Slack or Teams, for a connect link.
- Six built-in roles (`owner`, `admin`, `integration_admin`,
  `billing_usage_admin`, `member`, `viewer`) plus arbitrary custom
  `(action, resource)` permissions. Channel allowlists, per-user (Slack
  member ID or Teams AAD ID) and per-role tool entitlements,
  named-approver policies for risky actions.
- Static same-origin admin dashboard: Setup, Health, Integrations,
  Policy, People, Approvals, Activity, Usage, Data, OpenClaw operator,
  Knowledge, and Workflows views. No bundler, no external scripts, strict CSP.
- Governed team memory and admin-curated skill definitions, RBAC-gated
  and audit-attested, with team/private isolation enforced server-side.
  Complementary to OpenClaw's native memory plugin: the Operant store is
  the governed, attestable path agents reach through the
  `operant_memory_*` and `operant_skills_search` tools.
- Governed scheduled workflows: define recurring agent runs (cron or
  interval) that Operant owns, RBAC-gates (authoring is owner/admin only),
  and audits, then materializes into OpenClaw's cron for execution.
  Materialization is fails-soft and reconciled back from the gateway.
- One Postgres for state, optional Redis profile, Docker Compose
  topology with localhost-bound host ports and a per-workspace trust
  boundary. Helm chart and Fly artifacts ship for graduation.
- Sessions, jobs, policy decisions, credential resolutions, usage and
  cost, exports, retention, and wipes are recorded with token-shaped
  strings redacted before persistence.

| Capability | Operant surface |
| --- | --- |
| Slack + Teams runtime | OpenClaw gateway (Slack Socket Mode, Teams webhook), sessions, tasks |
| App marketplace | Pipedream catalog search and curated local app cards |
| Per-user OAuth | Pipedream Connect accounts keyed by each chat user (Slack member ID or Teams AAD ID) |
| App/action policy | `pipedream:<app>` tool rules and role/user scopes |
| Approvals | Named approvers, minimum approvals, dashboard decisions |
| Audit and usage | Postgres audit log, sessions/jobs, per-user token and cost rows |
| Memory and skills | Dashboard Knowledge view, team/private isolation, RBAC-gated, audit-attested |
| Scheduled workflows | Dashboard Workflows view, governed cron/interval runs materialized into OpenClaw cron, RBAC-gated, audit-attested |
| Self-hosting | Docker Compose first, Helm/Fly artifacts for graduation |

![A real Operant deployment in Slack: multi-thread workspace activity from real users](docs/assets/slack-real-workspace.png)

*Above: a live Operant deployment (branded as @DuvoClaw inside
[Duvo](https://duvo.ai)) running real production conversations.*

## Roadmap

Operant ships in small, governed increments. Recent releases:

- **v0.5** Governed scheduled workflows: recurring agent runs that Operant
  authors, RBAC-gates, and audits, then materializes into OpenClaw cron.
- **v0.4** Governed team memory and admin-curated skill definitions,
  RBAC-gated and audit-attested.
- **v0.3** Microsoft Teams as a first-class dual-identity platform alongside
  Slack.

Full history in the [changelog](CHANGELOG.md). Under consideration, not yet
committed: pgvector-backed semantic memory/skill search, executable skills
and tool-chains, OpenClaw skill-file materialization, and proactive
suggestions.

## Contributing

Operant is MIT-licensed and built in the open. If it is useful to you, a
[GitHub star](https://github.com/tomascupr/operant/stargazers) helps others
find it.

- New here? Start with **[CONTRIBUTING.md](CONTRIBUTING.md)** for local dev,
  the verify gauntlet (`pnpm verify`), and PR expectations.
- Found a bug or have an idea? [Open an issue](https://github.com/tomascupr/operant/issues);
  [`good first issue`](https://github.com/tomascupr/operant/labels/good%20first%20issue)
  and [`help wanted`](https://github.com/tomascupr/operant/labels/help%20wanted)
  are good entry points.
- Security report? See **[SECURITY.md](SECURITY.md)** and disclose privately.

## Docs

- **[Setup guide](docs/setup.md)**. Stack, dashboard sign-in, Slack
  app, Pipedream Connect, integration credentials, sandbox overlay.
- **[Acceptance guide](docs/acceptance.md)**. Live verifiers for Slack
  and Microsoft Teams, manual human-post mode, strict gates.
- **[Slack app setup](deploy/slack/README.md)**. Manifest, scopes,
  Socket Mode, token helpers.
- **[Microsoft Teams app setup](deploy/teams/README.md)**. Manifest,
  Azure Bot messaging endpoint, RSC permissions.
- **[HTTP API reference](docs/api.md)**. Dashboard and internal
  endpoints.
- **[Contributing](CONTRIBUTING.md)**. Local dev, PR expectations,
  release flow.
- **[Code of conduct](CODE_OF_CONDUCT.md)**. Contributor Covenant;
  report issues to work@tomcupr.com.
- **[Security policy](SECURITY.md)**. Reporting a vulnerability.
- **[Changelog](CHANGELOG.md)**. Release notes and version history.

## License

MIT. See [LICENSE](LICENSE).
