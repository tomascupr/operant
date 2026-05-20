# Changelog

All notable changes to Operant are documented here.
Format inspired by [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

Polish queued for the next tag — everything below is on `main` after the
v0.1.0 tag was placed on `49064d5`.

### Added
- `.nvmrc` and `.tool-versions` so fnm, nvm, asdf, mise, and Volta auto-switch to Node 24.
- `pnpm init:env` prints a "Next steps" banner with the generated admin login token, the dashboard URL on the configured port, and the next command.
- One-click Slack-app creation flow at the top of `deploy/slack/README.md` linking directly to Slack's create-from-manifest dialog.
- HTTP API reference at `docs/api.md` covering every dashboard and internal endpoint.
- Real dashboard screenshot (`docs/assets/dashboard.png`) and a real-workspace Slack screenshot (`docs/assets/slack-real-workspace.png`) in `README.md`.
- Package metadata for discoverability: `repository`, `bugs`, `homepage`, `author`, `keywords` in root `package.json`.

### Changed
- README rewritten from first principles for accuracy and brevity.
- README mentions `corepack enable` for users without pnpm 11 (Node 24 ships with Corepack and `package.json` pins `pnpm@11.0.3`).
- `deploy/fly/README.md` labeled "Preview — not GA" so evaluators don't try a half-finished deployment path.
- Repositioned from "Slack AI coworker" to **self-hosted agents in Slack** across README, `package.json`, Helm `Chart.yaml`, Slack `manifest.yaml`, and the GitHub repo description. "Slack AI" is literally Slack's own product name; "agents in Slack" frames Operant as a control plane for the agent category, not an AI assistant.

### Fixed
- CI: pnpm/action-setup picks its version from `package.json`'s `packageManager` field instead of pinning explicitly.

### Security
- Documented the `ws@8.20.0` (GHSA-58qx-3vcg-4xpx) transitive moderate in `SECURITY.md`. Reaches us only through OpenClaw's `@google/genai` and `@mistralai/mistralai`; Operant has no public WebSocket surface; `pnpm audit --prod` is clean.

## [0.1.0] - 2026-05-19

### Added
- Add manual Slack live verification path
- Add assisted manual Slack prompts
- Add raw Slack probe to final handoff
- Add manual live acceptance aliases
- Add Slack links to manual verifier prompts
- Add Slack user token exchange helper
- Add Slack user token authorship probe
- Add one-human Slack denied-policy verifier mode
- Add persistent live Compose startup
- Add scoped OpenClaw tool entitlements
- Add Slack installed manifest probe
- Add /internal/plugin/* endpoints and OperantClient
- Add PipedreamClient for Pipedream Connect MCP
- Add Pipedream catalog and tool factories
- Add Pipedream dashboard diagnostics
- Add control plane dashboard refresh


### Changed
- Always allowlist Operant plugin tools in generated OpenClaw config
- Move typebox from devDependencies to dependencies
- Send Pipedream MCP required headers (project, environment, app slug)
- Force JSON responses from Pipedream MCP (drop SSE from accept)
- Parse Pipedream SSE responses end-to-end
- Restructure docs for first-time evaluators


### Documentation
- Document Slack scope guard verification
- Document live Slack prerequisite check
- Document Operant setup and fix OpenClaw sync
- Document live DM history blocker
- Document latest manual Slack blocker
- Document Slack App Home DM requirement
- Document manual JSON prompt output
- Document Pipedream Connect plugin + sanitize plugin client errors


### Fixed
- Fix OpenClaw OpenAI runtime routing
- Fix Slack live diagnostics and OpenClaw compose setup
- Fix gateway build and bootstrap-aware dashboard sign-in


### Other
- Initial Operant control plane
- Update live acceptance evidence docs
- Make final report preserve failed live gaps
- Fail live preflight on missing Slack bot scopes
- Share Slack scope contract across verifiers
- Improve dashboard responsive safeguards
- Classify Slack scope preflight as blocked
- Cover Slack scope blocker classification
- Clarify live Slack acceptance blocker
- Track live handoff helper aliases
- Polish fresh checkout handoff helper
- Cover fresh checkout handoff helper
- Verify dashboard admin setup fields
- Detect disabled Slack Socket Mode during preflight
- Classify manual Slack acceptance as blocked
- Update live acceptance status docs
- Clarify manual live acceptance restart flow
- Update live Slack acceptance evidence
- Validate live Slack DM preflight
- Update live DM acceptance evidence
- Polish Operant docs and Slack DM probe
- Record targeted Slack DM probe evidence
- Write Slack DM probe evidence report
- Include Slack DM probe in final report
- Report automated Slack token probe evidence
- Clarify Slack verifier user tokens
- Polish OSS README
- Refresh live evidence handoff
- Nonce post-restart Slack verifier prompts
- Clarify Slack verifier OAuth setup
- Clarify manual Slack verifier nudges
- Detect app-authored Slack verifier posts
- Isolate local acceptance evidence
- Improve manual Slack E2E diagnostics
- Improve live Slack troubleshooting evidence
- Archive live verifier reports before overwrite
- Clarify manual Slack verifier prompts
- Request Slack user-authored verifier posts
- Make manual Slack verification less brittle
- Default manual Slack timeout in verifier
- Declare Slack verifier user scope
- Extend manual Slack verifier window
- Explain missed manual Slack prompts
- Cover integration credentials in synthetic smoke
- Clarify persistent Slack bot run mode
- Support one-human live acceptance handoff
- Clarify manual Slack live acceptance
- Polish live handoff verification
- Default live acceptance to one human
- Clarify manual DM acceptance nudges
- Clarify generic Slack setup docs
- Show DM probe prompt in JSON mode
- Record latest Slack DM probe evidence
- Make strict live Slack evidence opt-in for completion audit
- Scope integration credentials per Slack user
- Wire per-user integration credentials into dashboard and docs
- Scaffold @operant/openclaw-plugin workspace
- Install operant plugin into the OpenClaw gateway image
- Constrain dashboard role and model-provider inputs to dropdowns
- Generated OpenClaw config now passes config-validate for Anthropic
- Pre-fill credential form and let saved secrets stay hidden
- Declare tool contract + per-session activation on plugin manifest
- Require app slug on pipedream_list_actions; drop catalog
- Bump OpenClaw to 2026.5.18 and add launch-prep scaffolding


### Security
- Harden live Compose OpenClaw checks
- Harden live Slack verifier polling
- Harden live Slack verifier blockers
- Harden handoff verification for stale live reports
- Harden control plane release blockers


