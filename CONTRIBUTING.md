# Contributing to Operant

Thanks for considering a contribution. The core is MIT-licensed; we accept
fixes, feature work, docs, and packaging improvements.

## Before you start

- Check the open issues for existing tracking. If your change is
  non-trivial, file an issue first so we can agree on the approach before
  you invest the time.
- For substantial features, open a draft PR early and reference the issue.
  We will not silently merge controversial designs.

## Where to start

New here? Two good on-ramps:

- Issues tagged [`good first issue`](https://github.com/tomascupr/operant/labels/good%20first%20issue)
  are scoped to be safe and self-contained;
  [`help wanted`](https://github.com/tomascupr/operant/labels/help%20wanted)
  issues are larger but up for grabs.
- If nothing is tagged yet, the lowest-friction first changes are docs under
  `docs/`, a new `--self-test-*` case in a `scripts/*.mjs` CLI, or a `node:test`
  case under `apps/control-plane/tests/`. The highest-blast-radius areas are
  `server.ts` routing, the policy/RBAC engine, and migrations.

## Local setup

```bash
pnpm install
pnpm init:env          # first run only
pnpm typecheck
pnpm test
pnpm compose:up -- -d
pnpm doctor
```

The full developer gauntlet is `pnpm verify`. It additionally requires a
host PostgreSQL 17 toolchain (`initdb`, `postgres`, `psql`) and Google
Chrome on macOS, or `CHROME_PATH` set to a Chromium-flavored binary.

`pnpm test` builds first, then runs Node's test runner against compiled JS in
`dist/`. If you run `node --test` directly, rebuild first or your edits will not
be picked up:

```bash
pnpm --filter @operant/control-plane build
node --test apps/control-plane/dist/tests/policy.test.js                              # one file
node --test --test-name-pattern="<regex>" apps/control-plane/dist/tests/policy.test.js  # one test
```

## What we expect in a PR

- `pnpm typecheck` and `pnpm test` pass on your branch.
- New behavior has a `node:test` test under `apps/control-plane/tests/`
  or `apps/openclaw-plugin/tests/`.
- Heavyweight CLIs under `scripts/` stay self-testable: `pnpm verify:scripts`
  runs `node --check` plus `--self-test-*` flags for every script (including
  `node scripts/teams-live-e2e.mjs --self-test-arg-validation`). New
  chat-platform or policy code should keep dual-identity (Slack + Teams)
  behavior covered, adding both Slack and Teams cases where policy behavior
  changes.
- Migrations are append-only. Add `apps/control-plane/migrations/NNN_*.sql`
  with the next number; do not rewrite an applied migration. For example,
  migration 013 adds the `memory_entries` and `skill_definitions` tables with
  Postgres-native full-text search indexes and audit tracking; the next
  migration (014) would add an adjacent feature without rewriting 013.
- The dashboard stays vanilla JS, no external scripts or bundler. The
  strict same-origin CSP is non-negotiable.
- No secrets, real Slack tokens, or production credentials in commits.
  `.env` is gitignored; do not check in derived `.env.*` files either.
- Match the existing style. We are not strict about formatting beyond
  what `tsc` and the test suite enforce.

## Commit messages

We do not enforce Conventional Commits, but the changelog generator is
friendlier to them. Subjects in the imperative ("Add X", "Fix Y") with a
short body explaining the why. Group unrelated changes into separate
commits.

If you want a conventional prefix (`feat:`, `fix:`, `docs:`, `chore:`),
the changelog will categorize automatically. Otherwise commits land under
"Other changes".

## Releasing (maintainers)

First bump the version everywhere it is pinned:

- `package.json`, `apps/control-plane/package.json`, `apps/openclaw-plugin/package.json`
- `install.sh` (`OPERANT_VERSION` and `OPERANT_REF` defaults)
- `deploy/helm/operant/values.yaml` (`controlPlane.image.tag`) and
  `deploy/helm/operant/Chart.yaml` (`version` + `appVersion`)
- the pinned `vX.Y.Z` install URL in `README.md`, `docs/setup.md`, and the
  `docker-compose.quickstart.yml` header comment

Then cut the release:

```bash
git cliff --tag vX.Y.Z --output CHANGELOG.md
git commit -am "chore(release): vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push --follow-tags
gh release create vX.Y.Z --notes-from-tag
```

Pushing the tag triggers `.github/workflows/release.yml`, which builds and
publishes the `control-plane` (multi-arch) and `openclaw-gateway` images to
`ghcr.io/tomascupr/operant/*`. The first publish of each package is private —
set it to Public once in the GitHub package settings so `docker pull` and the
one-command installer work for everyone.

## Reporting issues

For bugs, open a GitHub issue with reproduction steps and the output of
`pnpm doctor`. For security issues, see [SECURITY.md](SECURITY.md);
do not open a public issue.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it. Report unacceptable behavior to
work@tomcupr.com.

## License

By contributing, you agree your work is licensed under the MIT License
that covers the project.
