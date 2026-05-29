# Compliance and data residency

This page records where data lives and who the sub-processors are when you
run Operant. It is scoped to the OSS control plane plus the integrations it
brokers; your own deployment choices (host, region, retention policy) sit on
top of it.

## What Operant stores, and where

Operant holds the following AES-256-GCM encrypted in your own Postgres
(`v1:<iv>:<tag>:<ciphertext>`, key `OPERANT_SECRET_KEY`, never written to
disk in plaintext):

- Slack app, bot, and (optional) user tokens.
- Model provider API keys.
- Custom non-Pipedream tool credentials, scoped to the workspace or to a
  specific Slack user.

These never leave the control plane except as SecretRefs that OpenClaw
resolves at runtime over the internal bearer. Residency for this data is
wherever you host Postgres.

## Sub-processors

| Sub-processor | Data it holds | Region | Custody |
| --- | --- | --- | --- |
| Pipedream Connect | End-user connected-app OAuth grants and tokens (Gmail, GitHub, Notion, etc.), keyed by each Slack user's external id | Pipedream US infrastructure (`us-east-1` at time of writing; confirm current region in your Pipedream project settings) | Pipedream-controlled. No self-host and no customer-managed key path. |

When the Pipedream marketplace is enabled, the OAuth tokens for the apps your
users connect are stored by Pipedream, **not** in your Postgres and **not**
inside the Operant trust boundary. Operant's role is governance and
attestation: it gates which user may connect which app (RBAC plus tool
policy), brokers short-lived connect tokens (never persisted), enforces
per-user isolation at invocation, audits every touch, and revokes grants
upstream on workspace wipe. It does not take custody of the end-user tokens.

If you need every credential inside your own trust boundary, use the native
per-user SecretRef path (custom tool credentials encrypted in your Postgres)
instead of, or alongside, the Pipedream marketplace.

## Audit attribution (two-actor model)

Audit rows carry two principals so both the operator action and the human on
whose behalf a tool ran are attestable:

- `actor_user_id` is the Operant admin/session principal that drove a
  control-plane action. It is `null` for plugin and runtime rows that
  originate from the gateway rather than an admin session.
- `actor_slack_user_id` is the Slack end-user the action was performed for.
  It is populated on the per-user Pipedream touches (connect-token mint and
  deny, disconnect, plugin invocation, wipe revocation) and on per-user
  SecretRef resolves, and is indexed for per-user queries. Workspace-level
  events (catalog search, revocation-failed summaries) leave it `null`.

`metadata.slackUserId` is retained alongside the column for back-compat with
rows written before the column existed.

## Reporting

Security and privacy concerns go to **work@tomcupr.com**. See
[SECURITY.md](../SECURITY.md) for the disclosure process and scope.
