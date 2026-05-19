# Operant Helm Chart

This chart is a later-deployment target for one Operant trust boundary. It
deploys the control plane and OpenClaw gateway in one `StatefulSet` pod so they
can share `ReadWriteOnce` config/state volumes without requiring RWX storage.

Use one release per company/workspace/trust boundary.
The chart schema constrains `replicaCount` to `1`; run another release for
another workspace instead of scaling one release horizontally.

The StatefulSet uses a headless governing Service for stable pod identity. The
OpenClaw gateway is reached by the control plane over `127.0.0.1` inside the
shared pod and is not exposed as a Kubernetes Service by default. Enable
`openclaw.service.enabled=true` only when an operator intentionally needs
cluster-internal gateway access.

## Required Secrets

Production installs should provide an existing secret:

```bash
kubectl create secret generic operant-secrets \
  --from-literal=DATABASE_URL='postgres://...' \
  --from-literal=OPERANT_SECRET_KEY='base64-or-32-byte-key' \
  --from-literal=OPERANT_INTERNAL_TOKEN='...' \
  --from-literal=OPERANT_ADMIN_LOGIN_TOKEN='operant_admin_...' \
  --from-literal=OPENCLAW_GATEWAY_TOKEN='...'
```

Then install with:

```bash
helm install operant ./deploy/helm/operant \
  --set secrets.existingSecret=operant-secrets \
  --set database.existingSecret.name=operant-secrets \
  --set ingress.enabled=true \
  --set ingress.host=operant.example.com
```

For evaluation only, `secrets.create=true` can create the secret from values.
When doing that, set `database.url` unless `database.existingSecret.name`
points at a separate Secret that already contains `DATABASE_URL`. Do not commit
filled secret values.

## Shape

- `control-plane` container: dashboard, API, migrations, RBAC, encrypted
  credentials, policy, audit, usage, retention, OpenClaw config writer.
- `openclaw-gateway` container: OpenClaw runtime, Slack Socket Mode, thread
  replies, agent execution.
- Headless Service: governs the StatefulSet identity without publishing the
  OpenClaw gateway by default.
- `openclaw-state` PVC: persistent OpenClaw runtime state.
- `openclaw-config` PVC: generated OpenClaw config written by Operant and read
  by OpenClaw.
- Resolver ConfigMap: mounts the exec SecretRef resolver into the OpenClaw
  container.

The chart intentionally does not deploy Postgres by default. Customer-controlled
Postgres is the expected production path.
