# Contributing to Operant

Thanks for considering a contribution. The core is MIT-licensed; we accept
fixes, feature work, docs, and packaging improvements.

## Before you start

- Check the open issues for existing tracking. If your change is
  non-trivial, file an issue first so we can agree on the approach before
  you invest the time.
- For substantial features, open a draft PR early and reference the issue.
  We will not silently merge controversial designs.

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
  with the next number; do not rewrite an applied migration.
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

```bash
git cliff --tag vX.Y.Z --output CHANGELOG.md
git commit -am "Release vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push --follow-tags
gh release create vX.Y.Z --notes-from-tag
```

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
