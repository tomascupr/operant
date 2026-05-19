# @operant/openclaw-plugin

OpenClaw plugin that bridges the [Operant](../../README.md) control plane and
Pipedream Connect into the OpenClaw gateway.

The plugin is bundled into the gateway image at build time
(`deploy/openclaw/Dockerfile.gateway`) and loaded on first boot via
`openclaw plugins install --force`. It is `private: true` and not published to
npm — distribution is through the Operant gateway image.

## Tools

- **`operant_ping`** — health check; always registered. Returns
  `{ ok, timestamp }`.
- **`pipedream_list_actions`** — `{ app: string }`. Lists Pipedream Connect
  tools for the given app slug (`gmail`, `slack`, `notion`, `github`, …),
  filtered by Operant policy for the requesting Slack user. Pipedream requires
  an explicit app — there is no list-all mode.
- **`pipedream_run_action`** — `{ toolName: string, args?: object }`. Runs the
  Pipedream tool under the Slack user's identity. Returns:
  - `{ error: "policy_denied", ... }` if Operant denies.
  - `{ status: "approval_required", ... }` if policy needs approval.
  - The Pipedream response (often a connect-link URL the user clicks once to
    OAuth their account) otherwise.

`pipedream_list_actions` and `pipedream_run_action` only register when the
five `PIPEDREAM_*` vars plus `OPERANT_MCP_SOURCE_PIPEDREAM_URL` are set in the
gateway environment; otherwise the plugin logs a warning and only
`operant_ping` is exposed.

## Environment

Always required:

- `OPERANT_CONTROL_PLANE_URL` — base URL of the Operant control plane (the
  gateway uses `http://policy-audit:8080` inside Compose).
- `OPERANT_INTERNAL_TOKEN` — bearer for `/internal/plugin/*` and SecretRef
  endpoints.

Required for Pipedream tools:

- `OPERANT_MCP_SOURCE_PIPEDREAM_URL` — default
  `https://remote.mcp.pipedream.net/v3`.
- `PIPEDREAM_PROJECT_CLIENT_ID` / `PIPEDREAM_PROJECT_CLIENT_SECRET` — project
  OAuth client from Pipedream → Project Settings → OAuth Clients.
- `PIPEDREAM_PROJECT_ID` — `proj_xxxxxxx`.
- `PIPEDREAM_ENVIRONMENT` — `development` or `production` (separate Pipedream
  token namespaces).

See [docs/setup.md → Pipedream Connect](../../docs/setup.md) for the full
setup path including the first-call OAuth connect link the Slack user clicks.

## Build & test

```bash
pnpm --filter @operant/openclaw-plugin build         # tsc → dist/
pnpm --filter @operant/openclaw-plugin test          # build then node --test dist/tests/*.test.js
```

Tests run on compiled JS, same as the control plane.

## Transport notes

The Pipedream MCP endpoint enforces the MCP Streamable HTTP transport
strictly: clients must send `Accept: application/json, text/event-stream` (or
the server returns 406) and the server always responds with a single SSE event
containing the JSON-RPC envelope. `parseSseJsonRpc` in
`src/pipedream/client.ts` extracts the JSON-RPC payload from the
`event: message\ndata: {...}` frame.

Per-user OAuth is implemented via the `x-pd-external-user-id` header; the
plugin sets it to the requester's Slack user id so each Pipedream
external-user maps 1:1 to a Slack identity. Slack `chat:write` is enough to
relay the connect-link URL — no new Slack scopes are needed.
