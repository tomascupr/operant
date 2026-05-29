# Security Policy

## Reporting a vulnerability

If you find a security issue in Operant, please email
**work@tomcupr.com** with the details. Do **not** open a public GitHub issue
for security reports.

What to include:

- A description of the issue and the impact you observed.
- Steps to reproduce, ideally against a clean `pnpm compose:up -- -d` stack.
- The commit SHA and `OPENCLAW_VERSION` you tested against.

What to expect:

- An acknowledgement within 3 business days.
- A public credit in the release notes if you want one (default: yes,
  attributed to your GitHub handle; let us know if you prefer otherwise).
- A coordinated disclosure window: we will agree on a patch date with you
  before publishing the fix. The default window is 90 days from
  acknowledgement, shorter if a fix is straightforward.

## Scope

In scope for the OSS core:

- Credential leakage from Operant Postgres, the control-plane HTTP API,
  the static dashboard, or the generated OpenClaw config.
- RBAC bypass against the control-plane API.
- Slack admission policy bypass (denied user reaching the bot, undocumented
  channel access).
- Plaintext storage of any value that should be encrypted at rest.
- Local privilege escalation paths through the Compose topology.

Out of scope:

- Issues that require Docker host root or physical access.
- Findings against deployments that have disabled the documented defaults
  (sandbox overlay on a shared host, non-loopback host port binds, etc.).
- Upstream issues that belong in [OpenClaw](https://docs.openclaw.ai),
  Postgres, Redis, or Pipedream Connect. Please report those to the
  respective projects; we will mirror an advisory if Operant exposes the
  defect in a non-default way.

## Data residency and sub-processors

Operant stores Slack/model credentials and custom tool secrets AES-256-GCM
encrypted in your Postgres. When Pipedream Connect is used, the end-user
OAuth tokens it brokers are held in Pipedream's own infrastructure, outside
the Operant trust boundary; Operant governs and audits that access but does
not store those tokens. The sub-processor boundary, region, and the
two-actor audit semantics are documented in
[docs/compliance.md](docs/compliance.md).

## Known transitive issues

- `ws@8.20.0` — [GHSA-58qx-3vcg-4xpx](https://github.com/advisories/GHSA-58qx-3vcg-4xpx),
  moderate. Reaches us only through OpenClaw's `@google/genai` and
  `@mistralai/mistralai` transitive trees. Operant does not expose a
  public WebSocket surface; impact is bounded to the OpenClaw
  gateway's model HTTP clients. We track upstream and bump
  `OPENCLAW_VERSION` once the fix lands. `pnpm audit --prod` is clean.

## Supported versions

Operant is pre-1.0. We patch the latest tagged release. Older tags do not
receive backported fixes unless a customer engagement explicitly covers
them.
