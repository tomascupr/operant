# Fly.io Deployment Design

> **Preview — not GA.** This document describes the planned Fly.io
> shape. The supported evaluation path is Docker Compose
> (`pnpm compose:up`). Open items are tracked at the bottom of this
> file.

Fly.io is a later target. The Docker Compose path remains the primary supported
evaluation path.

Recommended Fly shape:

- One Operant control-plane app per trust boundary.
- One OpenClaw gateway Machine per trust boundary.
- A customer-owned Postgres database, or Fly Postgres when the customer accepts
  Fly-managed data residency and backup controls.
- Fly volumes for OpenClaw state and generated config.
- Secrets set with `fly secrets set`; never store Slack/model/integration
  credentials in `fly.toml`.

The current codebase is closest to Kubernetes for shared config storage because
the control plane writes `openclaw.json` and the OpenClaw gateway reads it from a
shared volume. On Fly, model this as either:

- a single Machine image that runs both containers/processes with one volume, or
- a small config-sync sidecar/job that writes generated config into the
  OpenClaw Machine volume before or during gateway startup.

Do not run multiple unrelated workspaces in one OpenClaw Machine. Keep one
gateway/runtime/state volume per company/workspace/trust boundary.

## Required Runtime Secrets

```bash
fly secrets set \
  DATABASE_URL='postgres://...' \
  OPERANT_SECRET_KEY='...' \
  OPERANT_INTERNAL_TOKEN='...' \
  OPENCLAW_GATEWAY_TOKEN='...'
```

Slack and model credentials should be entered through the Operant dashboard so
they are encrypted in Postgres and emitted to OpenClaw only as SecretRefs.

## Open Items Before Fly GA

- Choose the config-sync mechanism for the OpenClaw Machine volume.
- Add a Fly smoke script that starts both Machines, saves credentials, runs
  OpenClaw status/doctor/security checks, and proves restart persistence.
- Decide whether hosted upgrades/support are an enterprise extension.
