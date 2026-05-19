# OpenClaw Feature Reuse Map

Research date: 2026-05-14. Local OpenClaw CLI: `2026.5.7 (eeef486)`. Default deployment pin refreshed to OpenClaw `2026.5.12` on 2026-05-15.

Sources:

- Local CLI: `openclaw --help`, `openclaw agent --help`, `openclaw channels capabilities --channel slack --json`, `openclaw gateway --help`, `openclaw cron --help`, `openclaw tasks --help`, `openclaw mcp --help`, `openclaw skills --help`, `openclaw plugins --help`, `openclaw security --help`, `openclaw sandbox --help`.
- Official Slack docs: https://docs.openclaw.ai/channels/slack
- Official gateway configuration docs: https://docs.openclaw.ai/gateway/configuration
- Official secrets docs: https://docs.openclaw.ai/gateway/secrets
- Official security docs: https://docs.openclaw.ai/gateway/security
- Official sandboxing docs: https://docs.openclaw.ai/gateway/sandboxing
- Official Docker docs: https://docs.openclaw.ai/install/docker

## Reuse, Do Not Rebuild

OpenClaw already owns:

- Slack Socket Mode and HTTP Request URL transports.
- Slack event handling for DMs, app mentions, channel messages, MPIMs, App Home, slash commands, interactivity, and file events.
- Slack threading/session routing and reply delivery.
- Slack live preview/native streaming behavior.
- Slack file upload/download handling.
- Slack interactive reply buttons/selects.
- Slack-native exec approval prompts and approver authorization.
- Exec approval policy snapshots through `openclaw approvals get --json
  --gateway`.
- Channel allowlists, DM allowlists, per-channel user allowlists, mention requirements, and pairing flow.
- SecretRef resolution for env/file/exec providers.
- Gateway health, doctor, security audit, status, and usage-cost commands.
- Gateway config hot reload in `gateway.reload.mode="hybrid"` for most safe
  config changes, with critical changes restarted by OpenClaw where supported.
- `openclaw secrets reload --json` to re-resolve SecretRefs and atomically swap
  the runtime secrets snapshot.
- `openclaw approvals get --json --gateway` to verify the effective exec
  approval policy OpenClaw is enforcing.
- Status/session/task observation surfaces via `openclaw status --all --json`,
  `openclaw sessions --json`, `openclaw tasks list --json`, and
  `openclaw gateway usage-cost --json`.
- Gateway scheduler and durable background task state via `openclaw cron
  <add|list|run|runs|status>` and `openclaw tasks <list|show|audit|cancel>`.
- Agent turns and reply delivery via `openclaw agent`, including channel
  delivery back to Slack when `--deliver --reply-channel slack` is used.
- MCP server configuration and channel bridge surfaces via `openclaw mcp`.
- Skill and plugin extension surfaces via `openclaw skills` and
  `openclaw plugins`.
- Tool sandboxing through Docker/SSH/OpenShell backends.

Operant must configure and observe these features instead of implementing parallel Slack logic.
Do not enter an Event Subscriptions **Request URL** for the Socket Mode path
used by Operant; OpenClaw opens the Slack WebSocket with the app-level token,
and the Slack App Manifest path is the most reliable way to apply events.

## Operant Responsibilities

- Persist canonical enterprise state in Postgres.
- Encrypt Slack/model/integration credentials before storage.
- Generate OpenClaw config from policy and credential refs.
- Give OpenClaw a SecretRef exec resolver that resolves encrypted Operant secrets at runtime.
- Apply RBAC before admin/config/policy changes.
- Maintain channel/user/tool policies and approval policies.
- Record audit/session/job/usage/approval events.
- Sync OpenClaw status sessions, task records, and usage token snapshots into
  Postgres without replacing OpenClaw's runtime/session store.
- Observe scheduled runs and durable background tasks from OpenClaw's cron/task
  surfaces instead of building a parallel scheduler in Operant.
- Treat business-tool execution, code/PR work, reports, spreadsheets, decks,
  browsing, APIs, and other agent capabilities as OpenClaw agent, MCP, skill,
  and plugin runtime concerns. Operant stores customer-owned integration
  credentials, emits SecretRefs, policy-gates access, and audits usage instead
  of implementing those tool runtimes.
- Run status/doctor/security audit commands and surface results.
- Keep each company/workspace/trust boundary on a separate OpenClaw gateway, state volume, config, and credential set.

## Slack Config Contract

Operant generates:

```json
{
  "gateway": {
    "mode": "local",
    "bind": "lan",
    "reload": { "mode": "hybrid" },
    "auth": { "mode": "token", "token": "${OPENCLAW_GATEWAY_TOKEN}" },
    "remote": {
      "url": "ws://openclaw-gateway:18789",
      "transport": "direct",
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    }
  },
  "secrets": {
    "providers": {
      "operant": {
        "source": "exec",
        "command": "/operant/openclaw/operant-secret-resolver",
        "args": ["/operant/openclaw/operant-secret-resolver.mjs"],
        "passEnv": ["OPERANT_CONTROL_PLANE_URL", "OPERANT_INTERNAL_TOKEN"],
        "jsonOnly": true,
        "allowSymlinkCommand": false
      }
    },
    "defaults": { "exec": "operant" }
  },
  "channels": {
    "slack": {
      "enabled": true,
      "mode": "socket",
      "botToken": { "source": "exec", "provider": "operant", "id": "workspaces/<id>/slack/botToken" },
      "appToken": { "source": "exec", "provider": "operant", "id": "workspaces/<id>/slack/appToken" },
      "dmPolicy": "allowlist",
      "allowFrom": ["U12345678"],
      "groupPolicy": "allowlist",
      "channels": {
        "C12345678": {
          "enabled": true,
          "requireMention": true,
          "users": ["U12345678"]
        }
      },
      "requireMention": true,
      "replyToMode": "all",
      "ackReaction": "eyes",
      "typingReaction": "pencil2",
      "thread": { "historyScope": "thread", "initialHistoryLimit": 20 },
      "streaming": { "mode": "progress", "progress": { "label": "thinking", "toolProgress": true, "commandText": "status" } },
      "execApprovals": { "enabled": true, "target": "both", "approvers": ["U12345678"] }
    }
  }
}
```

Use Slack channel IDs, not names, for `channels.slack.channels` keys.

## Security Boundary

OpenClaw docs state it is not a hostile multi-tenant boundary for mutually untrusted users sharing one gateway. Operant therefore treats one company/workspace/trust boundary as the isolation unit and deploys one dedicated OpenClaw gateway/runtime/config/state volume per boundary.

For shared enterprise Slack use, Operant narrows what one gateway can do through:

- OpenClaw Slack allowlists and per-channel policies.
- OpenClaw sandboxing.
- OpenClaw action/tool gates where supported.
- OpenClaw exec approval policy and Slack-native approval UI.
- Operant RBAC and admin approval workflows.
- Separate gateway per trust boundary for stronger isolation.

The default Compose stack keeps `/var/run/docker.sock` out of the gateway. When
Docker-backed OpenClaw sandboxing is required, operators layer
`docker-compose.sandbox.yml` onto a dedicated single-trust-boundary Docker host.
That overlay builds a gateway image with Docker CLI installed and runs the
gateway with `OPENCLAW_DOCKER_GID` added because Docker socket access is
already equivalent to broad control over that host. On startup the overlay
checks for OpenClaw's default `openclaw-sandbox:bookworm-slim` runtime image
and builds it from `deploy/openclaw/Dockerfile.sandbox-runtime` when missing.
