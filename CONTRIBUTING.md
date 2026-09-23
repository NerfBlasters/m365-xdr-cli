# Contributing to xdr-cli

This project is maintained by infosec people, not full-time developers. These
conventions exist to keep the repo maintainable as more people contribute and
to prepare for eventual open-source release. The reference rules live here;
for narrative learning — end-to-end walkthroughs with WHY explanations at
every non-obvious step — see [`docs/contributing-walkthrough.md`](docs/contributing-walkthrough.md).

---

## 1. The Eight Rules (TL;DR)

1. Never push directly to `main`. Open a PR.
2. Branch from `main` using `<type>/<short-description>` (or `<initials>/<topic>` for personal in-progress work).
3. Use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `security:`).
4. Sync `main` into your branch by **rebase** (preferred) or **merge** (acceptable, restricts you to squash-merge at PR time).
5. Default PR-merge is **squash**. Use rebase-and-merge only when each commit tells a meaningful story worth preserving on `main`.
6. Every PR bumps the version in `pyproject.toml` and adds a `CHANGELOG.md` entry under a new version heading. PR description states the bump level (`Bump: patch|minor|major`) with one-line rationale. Exception: PRs touching only `.github/**` are exempt — they don't change the shipped package. (Full rules in §5.)
7. Never commit secrets, tokens, real tenant data, or anything from `~/.xdr-cli/`. Full list in §8.
8. AI agents follow §7 — spec-and-plan first for non-trivial changes, human reviews diff and PR description, human approves push.

---

## 2. Branching

**Naming conventions:**

- `feat/<short-description>` — new feature
- `fix/<short-description>` — bug fix
- `docs/<short-description>` — docs-only change
- `chore/<short-description>` — tooling, deps, housekeeping
- `refactor/<short-description>` — internal restructure with no behavior change
- `test/<short-description>` — test additions or changes
- `security/<short-description>` — security-relevant change
- `<initials>/<topic>` — personal in-progress branch (a "this is mine, leave it alone" signal)

**Rules:** Branch from the latest `main`. Delete your branch after merge. No
long-lived branches except `main` itself.

**WHY:** Short-lived branches reduce merge-conflict surface area and keep
squash-merged history on `main` meaningful — each entry corresponds to one
focused change, not a months-long tangle of unrelated commits.

---

## 3. Commits

**Format:** `<type>(<optional-scope>): <subject>`

**WHY:** Readable history lets you understand at a glance what changed and why.
Security-relevant changes are findable via `git log --grep="^security"` for
audit purposes. The squash-merge title becomes the permanent commit on `main`,
so the commit message is load-bearing — write it as if it will be read in a
year.

**Types:**

| Type | When to use |
|---|---|
| `feat` | New user-visible feature or capability |
| `fix` | Bug fix |
| `docs` | Documentation-only change |
| `chore` | Tooling, dependencies, housekeeping; no behavior change |
| `refactor` | Internal restructure with no behavior change |
| `test` | Test additions or changes |
| `security` | Security-relevant change (use `git log --grep="^security"` to audit) |

**Scope:** Optional but encouraged when the change is localized. Common scopes:
`auth`, `hunt`, `sessions`, `device`, `domains`.

**Examples from repo history:**

- `feat(sessions): record investigations as JSONL training maps`
- `fix: per-surface token audiences for MDE endpoints`
- `security: validate entity values from API before use in KQL templates`
- `docs(spec): post-implementation updates to ai-harness catalog`

---

## 4. Pull Requests

**When:** Every change goes through a PR. No exceptions for "tiny fixes" —
squash-merge means the overhead is one click. Direct pushes to `main` are
forbidden.

**PR description:** The author writes it. The `.github/pull_request_template.md`
auto-populates the structure. A complete description includes: Summary, `Bump:`
line (with rationale), Test plan (automated + live smoke), Risk areas, and the
pre-merge checklist. AI agents may draft the description; the human edits it
before opening. PRs whose entire diff is under `.github/` are exempt from the
`Bump:` line, version bump, and CHANGELOG entry (see §5) — CI detects the
scope and skips those checks.

**Review model (solo maintainer):** Every change uses a PR and passing CI.
The maintainer reviews the full diff and test evidence before merging, including
AI-authored changes. Required independent approval is disabled while there is
only one maintainer; self-review and automated scanning are not independent
review. CODEOWNERS routes contributor PRs to the maintainer and documents
sensitive paths. Seek an outside reviewer for significant security changes when
available, and record review limitations in the PR. Add required approvals when
a second trusted maintainer joins.

**Higher-risk — explicit maintainer review and rationale required:**

- Anything in `src/xdr_cli/auth.py` or `src/xdr_cli/commands/auth_cmd.py`
- Device write actions in `src/xdr_cli/commands/device_cmd.py`
- Dependency additions to `pyproject.toml` and changes to `uv.lock`
- CI workflows and supply-chain config under `.github/` (`workflows/*.yml`,
  `scripts/`, `dependabot.yml`,
  `pull_request_template.md`) — these gate the supply-chain scan and are
  exempt from the CHANGELOG requirement, so review is the audit record
- AI-consumed output-contract changes: artifact receipts/previews, result
  JSONL/metadata records, or compact control-plane envelopes
- Session/history JSONL schema changes in `src/xdr_cli/_recording.py` or
  `src/xdr_cli/sessions.py` (training-map records are an AI-consumed downstream
  artifact)
- Any commit prefixed `security:`

**CI must be green before merge.** The `CI gate` aggregates tests on Python
3.11–3.14, Windows portability tests, dependency and secret scans, Bandit,
workflow lint/security checks, distribution checks, and the existing PR
version/CHANGELOG policy. Tests and dependency scanners use the committed
`uv.lock`. Run locally:

```bash
uv sync --locked --extra dev
uv run --frozen --extra dev ruff check src/ tests/ .github/scripts/
uv run --frozen --extra dev pytest tests/ -q
```

After changing dependencies, run `uv lock`, review the lockfile diff, and commit
it with `pyproject.toml`. See [CI security](docs/ci.md) for scanner behavior and
finding review. CI never uses live tenant credentials.

**Live-tenant smoke test before merge** for any change to CLI behavior. Unit
tests mock Graph and MDE; the smoke test confirms the change works against a
real tenant. The PR's "Test plan" section enumerates the exact commands run
live, with checkboxes for each.

- **Required for:** new commands, new flags, behavior changes to existing
  commands, output-shape changes, anything in the auth flow, anything that hits
  Graph or MDE.
- **Not required for:** doc-only, test-only, internal refactors with no surface
  change, dep bumps that don't change behavior.
- **Destructive commands** (`device isolate/unisolate/scan/restrict/collect-package`,
  `incidents update`): test on a non-production device or in a test tenant where
  possible. For smoke-test purposes in PRs, AI agents do not execute these even
  with tenant connectivity — smoke tests are batched at review time and the
  per-turn human-authorization model AGENTS.md §2 uses for live operation
  doesn't fit a CI/PR workflow. The human runs the destructive smoke commands.
- **Non-destructive smoke tests** may be executed by either human or AI when
  the AI's harness has tenant connectivity. The point is to capture actual output
  in the PR.

**Branch protection:** Configure a `main` ruleset requiring `CI gate`, an
up-to-date PR branch, and resolved review conversations. While solo, require
zero approving reviews and leave required CODEOWNER/last-push approval off.
Block force pushes and deletion without a routine bypass. These are GitHub settings, not guarantees
provided by committing the workflow; verify enforcement before public release.
See [CI security](docs/ci.md) for the initial setup requirements.

---

## 5. Versioning & Releases

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
`1.0.0` ships when the artifact receipt/result schemas, compact control-plane
envelopes, AGENTS.md contract, and session JSONL schema are stable enough to
commit to no breaking changes without a MAJOR bump.

**Pre-1.0 modifier (currently in effect):** While the version is `<1.0.0`,
breaking changes bump **MINOR** instead of MAJOR (orthodox SemVer pre-1.0
stance). The MAJOR slot stays at `0` until the formal `1.0.0` release.
Effectively: at `0.x`, what the table below labels MAJOR-triggers cause a MINOR
bump; what the table labels MINOR-triggers also cause a MINOR bump (no
distinction at `0.x`); PATCH-triggers still cause a PATCH bump. After `1.0.0`
ships, the table applies as written.

### What bumps what (post-1.0 rules — see modifier above)

xdr-cli's "public API" is the CLI surface plus what AI agents consume.

| Bump | Trigger |
|---|---|
| **MAJOR** | Breaking change to CLI surface or AI-consumed contract: command removed, flag renamed/removed, flag semantics changed, artifact receipt/preview/result-metadata or compact-envelope shape changed in a way that breaks parsers, **session/history JSONL schema field removed or semantically changed**, exit-code meaning changed, AGENTS.md contract change that breaks scripted agents, Python minimum-version bump |
| **MINOR** | Additive: new command, new flag, new library query, new playbook, new exit code added (existing ones unchanged), new optional field in an artifact receipt/result record or compact envelope, **new optional field in session/history JSONL records**, new supported Python version, dependency added |
| **PATCH** | Bug fix, security fix that doesn't change behavior, internal refactor, docs-only change, test additions, dependency version bump that doesn't change surface |

### How bumps happen (per-PR policy)

Every PR includes:

1. Version bump in `pyproject.toml` to whichever level matches the change.
   (`__init__.py` reads it dynamically — see §5 single source of truth below.)
2. A new section in `CHANGELOG.md` under a versioned heading
   (`## [0.4.0] - 2026-05-12`) with entries grouped by Keep-a-Changelog
   category.
3. A `Bump:` line in the PR description
   (`Bump: minor — adds new \`xdr <example> list\` command`, illustrative only)
   with one-line rationale.

The maintainer challenges the bump level during review if miscategorized. PRs
with no user-visible change (pure internal refactor, test-only, docs-only)
are still PATCH bumps — the version rolls forward as a build identifier.

**Exception — `.github/`-only PRs:** a PR whose entire diff is under
`.github/**` (CI workflows, dependabot config, guarddog config, PR template)
is exempt from all three requirements above — no version bump, no CHANGELOG
entry, no `Bump:` line. These PRs still require review per §4's higher-risk
list — that review is the audit record that replaces the CHANGELOG entry.
Nothing under `.github/` is part of the shipped
package. CI enforces the boundary: the `version-and-changelog` job skips its
checks only when every changed file is under `.github/`; one file outside it
and the full policy applies.

### Tagging and releases

Tags are not per-PR — versions roll forward continuously, but git tags happen
on demand at meaningful points (before a public demo, before a security audit,
before going public, before a deployment).

- Tag format: `vMAJOR.MINOR.PATCH` (`v0.3.0`, leading `v`).
- Workflow:
  ```bash
  git tag v0.3.0 <commit-hash>
  git push origin v0.3.0
  ```
- GitHub Releases: create from the tag; body = the matching CHANGELOG section.

### Single source of truth

`pyproject.toml` is canonical. `src/xdr_cli/__init__.py` reads it dynamically:

```python
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("xdr-cli")
except PackageNotFoundError:
    # Fallback for source-tree execution without an editable install
    # (e.g., PYTHONPATH=src). "0.0.0+unknown" is SemVer-valid build
    # metadata and makes broken installs visible in `xdr --version`.
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
```

The fallback covers source-tree-only execution (e.g., `PYTHONPATH=src` from a
checkout). `0.0.0+unknown` is SemVer-valid build metadata; if you see it in the
wild, the install is broken. A test (`tests/test_version.py`) catches drift
between `pyproject.toml` and what the package reports at runtime.

### CHANGELOG format (Keep a Changelog)

```markdown
## [0.3.0] - 2026-05-12
### Added
- `xdr <example> list` command — illustrative entry; format only, not a real command.
### Fixed
- `xdr hunt run` no longer truncates `RawEventData` when `--raw` is set.

## [0.2.0] - 2026-04-26
### Added
- Contribution guidelines (`CONTRIBUTING.md`, `docs/contributing-walkthrough.md`).
- Versioning policy and `CHANGELOG.md`.
### Changed
- `__version__` now reads from package metadata; `pyproject.toml` is the sole source of truth.
```

No `[Unreleased]` accumulator — every version-bumping PR creates its own version heading.

---

## 6. Syncing main into your branch

**Preferred: rebase onto `main`.**

```bash
git fetch origin
git rebase origin/main
# resolve any conflicts, then:
git rebase --continue
git push --force-with-lease  # required after rebase
```

Keeps your branch linear, preserves all three PR-merge options (squash,
rebase-and-merge, or merge-commit) at PR time.

**Acceptable: merge `main` into your branch.**

```bash
git fetch origin
git merge origin/main
# resolve any conflicts, then:
git commit
git push  # no force needed
```

Safer if you're not comfortable with rebase. Restricts the PR-merge to
**squash** (the default anyway) — "rebase-and-merge" won't behave well on a
branch with merge commits in it.

**`--force-with-lease` not bare `--force`:** `--with-lease` aborts the push if
the remote has new commits you haven't seen, so you can't accidentally clobber
a teammate's work; bare `--force` will overwrite anything.

**End-result:** Identical on `main` either way after squash-merge. The choice
is about your in-branch comfort, not history quality.

---

## 7. Working with AI agents

This section is rules for AI agents *contributing to* the CLI codebase. For
rules on AI agents *using* the CLI to hunt and investigate, see
[`AGENTS.md`](AGENTS.md).

- **Spec-and-plan workflow for non-trivial changes.** Spec →
  `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`. Plan →
  `docs/superpowers/plans/YYYY-MM-DD-<topic>.md`. Human approves both before
  implementation begins. These local planning files are gitignored; share them
  privately for review and do not commit them to this repository.
  "Non-trivial" = anything beyond a small isolated fix or doc tweak.

- **Doc-touching plans require code-fidelity verification.** When a spec or
  plan modifies documentation that makes factual claims about CLI behavior
  (command names, flag behavior, file paths, architecture), the plan's
  verification phase must include a step that validates those claims against
  `src/xdr_cli/`. "Extract verbatim from existing docs" is not sufficient —
  existing docs may be stale.

- **Human reviews every AI-authored commit message before commit.** Squash-merge
  titles become permanent history on `main`; bad framing there is bad forever.

- **Tests + lint pass before claiming done.** The AI must run `pytest` and
  `ruff check src/ tests/` before stating a change works. "I implemented X"
  without test/lint evidence is not done.

- **Human writes/reviews the PR description.** AI does not run `gh pr create`
  unattended. The PR description must include the `Bump:` line per §5 (except
  `.github/`-only PRs, which §5 exempts).

- **AI may not push to remote without human approval.** AI proposes the push and
  waits for approval. If approval isn't granted in the same turn, the AI **skips
  the push and continues with other work** — no blocking, no nagging.

- **AI proposes the version bump and CHANGELOG entry per §5.** Human reviews
  both before commit. AI does not unilaterally choose a bump level for a
  non-trivial change.

- **AI drafts the live-tenant smoke test plan per §4.** AI writes exact commands
  and predicted outputs into the PR description. AI may execute *non-destructive*
  smoke commands itself when its harness has tenant connectivity (capture actual
  output in the PR). **Destructive commands** (`device isolate/unisolate/scan/restrict/collect-package`,
  `incidents update`) are human-only for smoke-testing — see §4.

**Explicit non-rules:**

- AI **may** commit (with the commit-message-review rule above as the
  safeguard).
- Auth/token code does **not** get a special carve-out beyond what §4's
  higher-risk reviewer rule already covers.

---

## 8. Don't commit this

- **`token_cache.json`** — MSAL bearer tokens for your tenant. Treat as
  compromised the moment it's staged.
- **Anything under `~/.xdr-cli/`** — `config.toml` (tenant ID, app ID),
  `audit.log`, `sessions/*.jsonl` (KQL hunt results, often contain user data).
- **`.env`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, anything that smells like a credential.** PKCS#12 bundles (`.pfx`/`.p12`) are common from Azure/M365 app-registration certificate exports.
- **Real tenant identifiers in code, fixtures, docs, examples, or PR
  descriptions**: tenant GUIDs, app IDs, device IDs, real user UPNs, real IPs,
  real file hashes from real incidents. Use placeholders: `<tenant-id>`,
  `user@example.com`, `192.0.2.1` (RFC 5737 documentation IP),
  `00000000-0000-0000-0000-000000000000`.
- **Real KQL hunt results** — even a single sample row may contain user data.
  Sanitize or fabricate test fixtures.
- **Local agent scratch directories** — `.claude/`, `.cursor/`, `.windsurf/`,
  `.codex` (already gitignored). These contain conversation transcripts, agent
  settings, and sometimes accidentally captured tokens or tenant data. The
  `.gitignore` covers the common ones; verify with `git status` before commit if
  you've used a new tool.
- **Habit:** `git diff --staged` and skim before every commit. Optional
  belt-and-suspenders: run `gitleaks` or similar locally.

---

## 9. Recipes (cookbook)

Recipes are numbered so they're addressable as §9.N.

1. **"I committed to `main` by mistake"** — rescue the commits first, then reset
   local `main` to match remote. (Only if `main` hasn't been pushed yet; if it
   has, ping the maintainer before doing anything.)

   ```bash
   git branch save-my-work       # rescue the commits onto a new branch first
   git reset --hard origin/main  # local main matches remote
   git checkout save-my-work     # continue work on the new branch
   ```

2. **"I accidentally committed `token_cache.json`"** — **rotate the token in
   Entra ID immediately** (assume compromised). Then unstage and remove:

   ```bash
   git rm --cached token_cache.json
   git commit -m "chore: remove token_cache.json from tracking"
   ```

   If already pushed: rotate first, then use `git filter-repo` or BFG to scrub
   the file from history. Do not try to "git push your way out" without
   rotating.

3. **"I'm in a rebase mess and I want out"** — `git rebase --abort`. Step away,
   ask for help. Don't try to fix a broken rebase by force-pushing.

4. **"My PR has conflicts with main"** — either rebase onto main or merge main
   into your branch (see §6), resolve, push.

5. **"I need to undo my last commit but keep the changes"** —
   `git reset --soft HEAD~1`. The commit disappears; the changes stay staged.

6. **"I pushed something I shouldn't have"** — if it involved secrets, rotate
   first. Then ping the maintainer. Don't try to fix it alone.

7. **"My PR has a version conflict on rebase — `pyproject.toml` and
   `CHANGELOG.md` collide with someone else's already-merged PR"** — take the
   version that's now on `main` as the new base, bump from there to the next
   appropriate level for your change, rewrite your `CHANGELOG.md` entry under
   the new version heading, force-with-lease push.

---

## 10. Open-source readiness

This document is written assuming the repo will eventually go public. When that
happens, the commit history may be scrubbed or replayed and contributor
licensing will be addressed. (The `main` ruleset already enforces both a
required non-author review and required CI status checks — lint-and-test
3.12/3.13/3.14, version-bump and CHANGELOG check, and GuardDog supply-chain
scan — as of 2026-09-03.) Until then, these are honor-system conventions —
they exist because they're the right habits to build now, not because tooling
forces them.

---

## 11. Security disclosure

`xdr-cli` is a security tool. Vulnerabilities (auth-token handling, KQL
injection in templates or library queries, output injection in receipts,
previews, compact envelopes, or result JSONL, and session/result data leakage)
deserve responsible disclosure via a private channel — please do not open
public GitHub issues for security issues.

See [`SECURITY.md`](SECURITY.md) for the contact channel, scope, and
response-time expectations.
