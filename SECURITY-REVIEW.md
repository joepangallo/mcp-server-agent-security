# Security Review — release-workflow prep (2026-07-21)

Scope: `.github/workflows/publish.yml` (new), `.github/workflows/ci.yml` (SHA-pin update), `README.md` Provenance section, `SCAN-REPORT.md`. A `codex exec` review was started but did not complete within the run's time budget (a concurrent codex session was active on this machine); this adversarial self-review is the fallback record per house rules.

## Findings and dispositions

1. **Script injection via tag name in the version guard — mitigated by design.** The tag/package.json comparison in `publish.yml` reads `GITHUB_REF_NAME` as a shell environment variable inside quotes, never via `${{ }}` template interpolation, so a hostile tag name cannot inject into the shell. Verified no `${{ github.* }}` interpolation appears in any `run:` block in either workflow.
2. **Workflow token permissions — least privilege.** Both workflows set top-level `permissions: contents: read`; only the publish job adds `id-token: write` (required for OIDC trusted publishing). No `pull_request_target`, no secrets referenced.
3. **Action pinning — full commit SHAs, verified upstream.** `actions/checkout@11bd719...` (= tag v4.2.2) and `actions/setup-node@49933ea...` (= tag v4.4.0) were resolved live from the upstream repos' tag refs via the GitHub API, not copied from memory.
4. **No credential fallback — fail-closed.** `publish.yml` configures no `NODE_AUTH_TOKEN`/npm token secret. Until the npm package registers this repo + `publish.yml` as a trusted publisher, a tag push fails at `npm publish` rather than publishing with ambient credentials.
5. **Unpinned `npm install -g npm@latest` — accepted risk.** Trusted publishing requires npm >= 11.5.1; installing latest official npm at publish time follows npm's own trusted-publishing guidance. A SHA-equivalent pin is not available for npm itself; pinning a version range would go stale against the registry-side minimum. Noted, not changed.
6. **Factual drift in SCAN-REPORT.md — found and fixed.** The tarball-vs-repo diff was run before this pass edited `README.md`; the report originally claimed the working tree was byte-identical to the published 2.1.0 tarball without qualification. Reworded to scope the claim to repo HEAD at scan time and disclose the intentional README delta.
7. **Imprecise history reference — found and fixed.** "entered history four commits ago" replaced with the exact ref (`e5213a7`, HEAD~3).
8. **`npm install` vs `npm ci` in workflows — accepted.** Kept `npm install` for consistency with the pre-existing CI jobs and to avoid the known cross-platform optional-dependency lockfile drift failure mode; the dependency tree is a single pure-JS SDK package. Tests (37/37) run in CI on node 18/20/22 and again in the publish job before `npm publish`.

No changes were made to shipped package code (`index.js`, `cli.js`, `mcp/`); the npm-visible delta of this pass is the README Provenance paragraph only (`SCAN-REPORT.md` and `SECURITY-REVIEW.md` are not in the `files` allowlist and do not ship).
