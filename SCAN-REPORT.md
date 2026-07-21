# Repo Hygiene Scan — mcp-audit-server

Date: 2026-07-21
Scope: full git history (18 commits, `c2e0787` → `2ae27b6`) of `joepangallo/mcp-audit-server`, plus the published npm tarball `ledd-mcp-audit-server@2.1.0`.
Method: `gitleaks git .` (v8.30.1) over full history; manual grep passes over every blob in every commit for API keys, tokens, .env content, hardcoded endpoints/keys, client/prospect/student names, and operational details; file-by-file diff of the published npm tarball against the repo working tree.

## Verdict

**No secrets. One significant repo-only exposure: `AGENTS.md`.**

- **gitleaks: clean.** 18 commits scanned, 0 leaks.
- **Manual pass: no credential values anywhere in history.** No API keys, no tokens, no `.env` file ever committed, no deleted files in history (nothing was ever purged), no client/prospect/student names.
- **`AGENTS.md` is an internal infrastructure document** committed to this repo (working tree and history since commit `e5213a7`). It is not secret material, but it is operational detail that would circulate with the repo. See Finding 1.

## What the published npm tarball already ships

`ledd-mcp-audit-server@2.1.0` contains exactly 10 files, **all byte-identical to repo HEAD (`2ae27b6`) at scan time** — no drift between the published package and the repo. (The workflow-prep pass below subsequently added a Provenance section to `README.md`, so the working tree now intentionally differs from the published 2.1.0 README by that one section.)

`README.md`, `CHANGELOG.md`, `MIGRATION.md`, `LICENSE`, `package.json`, `cli.js`, `index.js`, `server.json`, `mcp/index.js`, `mcp/server.json`

Already public via the tarball (i.e., not new exposure if the repo were opened):

- Hosted backend default `https://audit.leddconsulting.com` (hardcoded in `index.js` as `DEFAULT_HOSTED_BASE_URL`) and default port `3091` for self-hosted mode.
- `x-api-key` auth header name; all key values come from env vars — none hardcoded.
- `package.json` already declares `repository`/`homepage`/`bugs` pointing at `github.com/joepangallo/mcp-audit-server` — the public package already names the (currently private) source repo.
- Business identity: `Ledd Consulting <leddconsulting@gmail.com>`, MIT license, MCP Registry name `io.github.joepangallo/mcp-audit-server`.
- README states hosted access requires contacting Ledd Consulting; references the private backend requirement.

**Not** in the tarball (repo-only): `AGENTS.md`, `test/` (4 files), `examples/` (2 files), `glama.json`, `package-lock.json`, `.github/`, `.gitignore`, `.npmignore` — plus all git metadata.

## Findings

### 1. `AGENTS.md` — internal infrastructure overview (MEDIUM; the only material item)

Added in commit `e5213a7` ("Add Codex context (AGENTS.md) — full infrastructure overview"), present at HEAD. ~11 KB of internal operational context that has nothing to do with this package's function:

- VPS IP `76.13.114.106` with `ssh root@76.13.114.106` and `rsync ... root@76.13.114.106:/root/vps-agents/` deploy commands (root SSH target, filesystem paths).
- Complete internal port map (3004–3099) of every microservice, including services with no public DNS.
- Names of the three auth env keys (`INTERNAL_SECRET`, `AGENT_AUTH_KEY`, `AGENT_API_KEY`) — names only, no values.
- Full private-repo inventory (~21 repos with one-line purposes), including the private backend `mcp-security-audit`.
- Revenue strategy and pricing (hourly rates, retainer bands, SaaS price points, "~$125/week passive").
- Business-operations details: swarm schedules, bot handles (@MetalTorqueBot, Discord @MT), OpenClaw gateway port, ChromaDB memory layer, "Zero-cost LLM strategy: all Claude calls use `claude -p` CLI with subscription OAuth = $0 API cost".
- Personal detail: Tampa Bay, FL; "all repos private" as a stated posture.

No credentials are exposed, and the VPS binds services to 127.0.0.1 behind nginx per the doc itself — but the file is a curated reconnaissance map (exact root SSH target + full port/service inventory + key names) and includes business-sensitive pricing/strategy. Because it entered history at `e5213a7` (HEAD~3), deleting the file at HEAD would not remove it from history: any public clone could recover it from `e5213a7`..`2ae27b6`. The states that exist: (a) repo stays private — no circulation; (b) opened as-is — file circulates in tree and history; (c) opened after removing at HEAD — still recoverable from history; (d) opened after a history rewrite (`git filter-repo`) — commit SHAs change, existing clones/anything referencing old SHAs breaks; (e) opened as a fresh-history re-init — clean, but the 18-commit development narrative is lost, which itself has signaling value in a provenance story.

### 2. Commit author identity (LOW)

All 18 commits are authored `Joe Pangallo <josephpangallo@gmail.com>` (personal Gmail), while the package's public author is `leddconsulting@gmail.com`. Opening the repo publicly and permanently links the personal address to the business identity in git metadata. (GitHub also exposes commit emails via the API for public repos.)

### 3. Superseded hosted endpoint in history (INFORMATIONAL)

Older commits reference `https://mcpaudit.metaltorque.dev` as the hosted default (switched to `audit.leddconsulting.com` in `b512f8f`). Both are public-facing domains and the old default already shipped in previously published npm versions — history adds nothing new.

### 4. Stale `.gitignore` rules (INFORMATIONAL)

`.gitignore` lists `/index.js` and `/SPEC.md` under "VPS service files (not part of this package)", yet `index.js` is tracked, is the package `main`, and ships in the tarball. The ignore rule is inert for tracked files but contradicts reality; no `SPEC.md` exists in history. Cosmetic inconsistency only.

### 5. Placeholder token in examples (INFORMATIONAL)

`examples/claude-desktop.json` contains `"GITHUB_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxx"` — an obvious placeholder (gitleaks does not flag it), but naive secret scanners run by third parties against a public repo might. Not in the tarball.

## Release-workflow prep added in this pass (local only, not pushed)

- `.github/workflows/publish.yml` (new): publishes on `v*` tags via **npm trusted publishing** (OIDC, `id-token: write`, no long-lived token) with `npm publish --provenance --access public`; verifies the tag matches `package.json` version and runs the test suite first; actions pinned by full commit SHA (`actions/checkout` v4.2.2 = `11bd719...`, `actions/setup-node` v4.4.0 = `49933ea...`).
- `.github/workflows/ci.yml` (updated): same jobs as before (node 18/20/22 test matrix + publint), actions re-pinned from mutable `@v4` tags to the same full commit SHAs; explicit `permissions: contents: read`.
- `README.md`: added a one-paragraph "Provenance" section.
- `LICENSE` (MIT) and `package.json` `repository` field: already present; unchanged.
- Test suite: 37/37 pass after changes (`npm test`, node:test).

Facts relevant to whether/when the workflow becomes operative:

- Trusted publishing requires a one-time registration on npmjs.com (package settings → Trusted Publisher: repo `joepangallo/mcp-audit-server`, workflow `publish.yml`) before a tag push will publish. Until then the workflow's publish step fails closed (no token fallback is configured).
- Provenance attestations are recorded in the public Sigstore transparency log and link back to the source repo and workflow run. With the repo private, the attestation's source links would 404 for verifiers and repo/workflow names would still enter the public log — the provenance story is only coherent once the repo is public.
- Trusted publishing needs npm ≥ 11.5.1 at publish time; the workflow installs latest npm on Node 24.
- Publishing the next version with provenance does not retroactively attest 2.1.0; the first provenance-attested version would be the next tag published through this workflow.

## Bottom line

History contains zero secret values and is publishable from a credentials standpoint. The single decision-relevant item is `AGENTS.md` (present in tree and history): opening the repo in any form that preserves current history circulates the internal infrastructure map, root SSH target, port inventory, private-repo list, and pricing/strategy detail; every path that avoids that either delays opening, rewrites history, or discards it. Everything else the repo would newly expose beyond the already-published tarball is tests, examples, CI config, and commit metadata (personal email).
