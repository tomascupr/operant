# Operant docs

Operant is a self-hostable, MIT-licensed control plane that wraps OpenClaw to
put governed agents in Slack and Microsoft Teams: RBAC, per-human audit, BYOK
secrets, and named-approver policy. For the full overview and quickstart, start
at the top-level [README.md](../README.md).

**Start here**

- **[setup.md](setup.md)**. Everyday operator path: stack up, dashboard
  sign-in, Slack/Teams apps, self-serve Pipedream marketplace, integration
  credentials, OpenClaw operator pairing, scheduled workflows, sandbox overlay.
- **[api.md](api.md)**. HTTP API reference: dashboard and internal endpoints.
- **[../deploy/slack/README.md](../deploy/slack/README.md)**. Slack app
  manifest, scopes, Socket Mode setup, token-generation helpers.
- **[../deploy/teams/README.md](../deploy/teams/README.md)**. Microsoft Teams
  app manifest, Azure Bot messaging endpoint, RSC permissions.

**Going deeper**

- **[compliance.md](compliance.md)**. Sub-processor boundary, data residency,
  and the two-actor audit semantics.
- **[acceptance.md](acceptance.md)**. Live verifiers, manual human-post mode,
  strict acceptance gates, completion audit. Only needed when producing
  customer acceptance evidence.
- **[openclaw/reuse-map.md](openclaw/reuse-map.md)**. What Operant reuses from
  OpenClaw versus reimplements.
