# Contributing Walkthrough

This is the narrative companion to [`CONTRIBUTING.md`](../CONTRIBUTING.md).
Read it once, cover-to-cover. Three end-to-end walkthroughs are bundled here:

1. [Your first contribution (human-only)](#walkthrough-1--your-first-contribution-human-only)
2. [Your first AI-assisted contribution](#walkthrough-2--your-first-ai-assisted-contribution)
3. [A rebase walkthrough](#walkthrough-3--a-rebase-walkthrough)

Throughout, references like §5 point back to the matching section of
`CONTRIBUTING.md`, where the rules live in reference form.

---

## Walkthrough 1 — Your first contribution (human-only)

**Trigger: You want to add a small feature or fix a bug. You've cloned the repo
and you're ready to make your first change.**

### Step 1 — Preflight (one-time per clone)

Install the package in editable mode with dev tooling:

```bash
pip install -e ".[dev]"
```

This installs `pytest`, `ruff`, `respx`, and `pytest-asyncio` alongside the
package itself. Now verify all four checkpoints:

```bash
xdr --version          # expect: 0.X.Y matching pyproject.toml
pytest                 # expect: all green
ruff check src/ tests/ # expect: no output (clean)
```

If `xdr --version` prints `0.0.0+unknown`, the editable install didn't take —
see §5 for what that fallback means and fix the install before continuing. The
fallback string `"0.0.0+unknown"` is a deliberate signal that something is
broken, not a valid version.

WHY do all of this up front: every later step assumes these four work. Catching
environment problems before you touch code keeps troubleshooting separate from
development. A green baseline is your benchmark — if tests fail after your
change, you know it's your change.

### Step 2 — Sync local `main`

```bash
git checkout main
git pull --ff-only
```

The `--ff-only` flag tells git to refuse the pull if your local `main` has
commits that aren't on the remote. Without it, git would silently create a merge
commit on local `main`, polluting your history with a bogus merge of upstream
changes that didn't come through a PR. If `--ff-only` fails, your local `main`
has diverged from `origin/main` — typically because you committed directly to
local `main` (a §1 rule violation). Investigate before continuing: run `git log
HEAD..origin/main` and `git log origin/main..HEAD` to see what's where. If you
have stray commits on local `main`, move them to a branch (`git branch
save-my-work`, then `git reset --hard origin/main`) and continue.

### Step 3 — Create a branch

```bash
git checkout -b feat/domains-internal-filter
```

Name the branch to match the type of change (see §2 for the full naming
convention): `feat/` for a new feature, `fix/` for a bug fix, `docs/` for a
documentation-only change, and so on. The short description after the slash
should be readable in a `git branch -a` listing — it's the first signal to a
teammate about what you're doing.

### Step 4 — Make the change, then test and lint

Write your code. When you think you're done:

```bash
uv sync --locked --extra dev
uv run --frozen --extra dev pytest
uv run --frozen --extra dev ruff check src/ tests/ .github/scripts/
```

WHY both: CI runs both checks across Python 3.11–3.14 (see §4). If you only run
tests and miss a lint error, you'll discover it after pushing — when your
context has already shifted to "waiting for CI" rather than "writing code". Fail
fast locally. Both must be clean before moving on.

### Step 5 — Bump the version and update the changelog

> Exception: if your PR's entire diff is under `.github/` (CI/tooling
> config), skip this step — those PRs are exempt from the bump and CHANGELOG
> (see CONTRIBUTING §5). CI detects the scope automatically.

Open `pyproject.toml` and increment the version according to the bump-level
rules in §5. For a small bug fix: PATCH (`0.X.Y` → `0.X.(Y+1)`). For a new
feature: MINOR (`0.X.Y` → `0.(X+1).0`). Note the pre-1.0 modifier in §5: while
the version is `<1.0.0`, what would normally be a MAJOR bump becomes a MINOR
bump — the MAJOR slot stays at `0` until the formal `1.0.0` release.

Then open `CHANGELOG.md` and add a new section at the top:

```markdown
## [0.5.0] - 2026-04-27
### Added
- `xdr domains list --internal-only` flag to filter to verified internal domains.
```

Use Keep-a-Changelog categories: `Added`, `Changed`, `Deprecated`, `Removed`,
`Fixed`, `Security`. Date format is `YYYY-MM-DD`. Every version-bumping PR gets its own
version heading — there is no `[Unreleased]` accumulator (§5).

**After editing `pyproject.toml`, re-run the editable install to refresh package metadata:**

```bash
pip install -e ".[dev]" --quiet
```

This is required because `xdr_cli.__version__` reads the version from installed
distribution metadata via `importlib.metadata.version("xdr-cli")`. Setuptools
editable installs cache the metadata at install time — without the reinstall,
`xdr --version` and `tests/test_version.py` will still report the old version
even though `pyproject.toml` has the new one. Verify with `xdr --version`; it
should show your new version string.

### Step 6 — Review what you're about to commit

```bash
git diff
```

Skim every line before you stage. You are looking for: `token_cache.json`,
anything under `~/.xdr-cli/`, real tenant GUIDs, real user UPNs, real IPs or
file hashes from real incidents, debug `print()` calls left in, `.claude/` or
other agent scratch directories. The full no-commit list is in §8. This takes
thirty seconds and has saved real data-leak incidents.

### Step 7 — Commit

Stage your changes first, then commit with a Conventional Commits message (§3):

```bash
git add pyproject.toml CHANGELOG.md src/xdr_cli/commands/domains_cmd.py tests/test_domains_cmd.py
git commit -m "feat(domains): add list --internal-only filter"
```

The format is `<type>(<scope>): <subject>`. The scope is optional but encouraged
when the change is localized — `domains` tells reviewers exactly where to look.
The subject is present tense, lowercase, no trailing period. This message will
become the permanent commit on `main` after squash-merge, so write it as if
someone will read it a year from now.

### Step 8 — Push and set upstream tracking

```bash
git push -u origin feat/domains-internal-filter
```

```
Branch 'feat/domains-internal-filter' set up to track remote branch 'feat/domains-internal-filter' from 'origin'.
To github.com:NerfBlasters/m365-xdr-cli.git
 * [new branch]      feat/domains-internal-filter -> feat/domains-internal-filter
```

The `-u` sets upstream tracking so future `git push` (with no arguments) works
from this branch. You only need `-u` on the first push.

### Step 9 — Sync if `main` has moved

While you were working, someone else may have landed a PR. Check:

```bash
git fetch origin
git merge origin/main
```

For a first contribution, merging is the safer path — no force-push required
afterward. If the merge produces a conflict in `pyproject.toml` or
`CHANGELOG.md` because another PR bumped the same version, see recipe §9.7:
take the version now on `main` as the new base, bump from there, rewrite your
`CHANGELOG.md` entry under the new heading, and push again.

For branches where you want to preserve rebase-and-merge as an option at PR
time, see §6 and Walkthrough 3.

### Step 10 — Open the pull request

```bash
gh pr create --fill
```

Or open via the GitHub UI. Either way, the `.github/pull_request_template.md`
auto-populates the description structure. Fill in every section (§4):

- **Summary** — one paragraph on what changed and why.
- **Bump** — `Bump: minor — adds --internal-only flag, no breaking changes` with
  a one-line rationale (not for `.github/`-only PRs — exempt per §5). The
  maintainer challenges this if miscategorized.
- **Test plan (automated)** — paste the `pytest` and `ruff` output.
- **Test plan (live-tenant smoke)** — exact commands you ran against a real
  tenant, with actual output. Or "N/A — doc/test only" with a reason if the
  change is documentation or test additions only.
- **Risk areas** — what could go wrong; who should look closely.
- **Pre-merge checklist** — the template checkboxes.

### Step 11 — Run the live-tenant smoke test

For any CLI behavior change, run the commands against a real Defender tenant and
paste actual output into the PR's Test plan section (§4). This is the only place
you confirm the change works end-to-end — unit tests mock Graph and MDE; they
can't catch a wrong API field name or an unexpected tenant response shape.

```bash
xdr domains list --internal-only
```

Copy the JSON output (sanitize any real tenant GUIDs — replace with
`00000000-0000-0000-0000-000000000000` per §8) and paste it into the PR.

If your change is doc-only or test-only, write "N/A — doc/test only" and
explain why no live-tenant run is needed. Don't write N/A for a code change.

### Step 12 — Wait for CI

CI runs lint and tests on Python 3.11–3.14, plus the security and distribution
checks described in [CI security](ci.md). Require the aggregate `CI gate` (§4). A red CI is a hard
merge-block — no exceptions. If CI is red, fix locally, push again. The new
commits automatically update the PR.

```bash
git add src/xdr_cli/commands/domains_cmd.py
git commit -m "fix: handle empty domain list without IndexError"
git push
```

### Step 13 — Address review comments

Push additional commits to the same branch. They accumulate on the PR and will
all collapse at squash-merge time. Commit hygiene within the PR branch is for
your own readability during review, not for `main`'s history — `main` gets one
clean commit per PR.

### Step 14 — Squash-merge

When CI is green and the PR is approved, use the squash-merge button on GitHub.
What squash-merge actually does: every commit on your branch collapses into one
new commit on `main`. The commit message is the PR title (which should match
your Conventional Commits subject). All the intermediate commits disappear from
the permanent history — only the squashed one survives (see §3 and §4 for why
this matters).

### Step 15 — Delete the branch

```bash
git branch -d feat/domains-internal-filter
```

GitHub auto-deletes the remote branch after squash-merge if the repo option is
enabled. If not:

```bash
git push origin --delete feat/domains-internal-filter
```

No long-lived branches except `main` itself (§2). The branch served its purpose;
delete it.

---

## Walkthrough 2 — Your first AI-assisted contribution

**Trigger: You want to add a feature, but it's bigger than a one-shot fix and
you'd like Claude (or Copilot, or Codex) to help. The change touches enough that
you want a spec and a plan first.**

The spec-and-plan workflow exists because letting an AI "just go" on a
non-trivial change tends to produce code that solves a slightly wrong problem.
A spec forces shared understanding before any code is written; a plan forces
shared decomposition before implementation begins. The total time spent on
spec and plan is rarely more than 20% of the feature's time — and it eliminates
the full-rewrite that usually happens when you skip it.

### Step 1 — Initiate the brainstorm

Start a conversation with the AI. Describe the feature: what it does, what
problem it solves, what the user sees. Ask the AI to work with you on a spec.
Don't start coding yet.

This conversation is cheap. Misunderstandings here cost minutes; misunderstandings
discovered after implementation cost hours.

### Step 2 — AI produces the spec

The AI writes a spec file at
`docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`. The spec is
conversational — it describes the problem, the proposed solution, the
constraints, the non-goals, and open questions. Expect multiple revisions before
it's right.

Example location:
`docs/superpowers/specs/2026-04-28-threats-list-design.md`

The spec is a local, gitignored document. Share it privately for review;
do not commit files under `docs/superpowers/` to this repository.

### Step 3 — Human reviews and approves the spec

Read the spec carefully. This is the cheapest place to catch a misunderstanding.
A spec change is one paragraph rewritten; a code change is hours of work, tests,
and PR overhead. Push back on anything that doesn't match the intent. When the
spec matches what you actually want, approve it explicitly ("this spec is
approved, proceed to the plan").

### Step 4 — AI produces the plan

The AI writes a task-by-task implementation plan at
`docs/superpowers/plans/YYYY-MM-DD-<topic>.md`. Each task is bite-sized, with a
clear done-criterion. For behavior changes, tasks follow TDD order: tests first,
then implementation, then integration. The plan references the spec for context.

### Step 5 — Human reviews and approves the plan

Same discipline as the spec review. If a task is too large ("implement the
entire command"), push back — smaller tasks are easier to verify. When approved,
say so explicitly.

### Step 6 — AI implements task-by-task

The AI works through the plan one task at a time. Before claiming any task done,
the AI runs and reports the results of both (§7):

```bash
uv sync --locked --extra dev
uv run --frozen --extra dev pytest
uv run --frozen --extra dev ruff check src/ tests/ .github/scripts/
```

"I implemented X" without test and lint evidence is not done. The AI pastes
the output, not just a summary. If either fails, the AI fixes it before moving
on. Green tests and clean lint are the task completion criterion, not just
"the code compiles".

### Step 7 — AI proposes the version bump and CHANGELOG entry

Once implementation is complete, the AI proposes the bump level and drafts the
`CHANGELOG.md` entry per the rules in §5 and §7 (not for `.github/`-only PRs —
exempt per §5). The AI does not commit this unilaterally for a non-trivial
change.

The human reviews the proposed bump level. If the AI picked MINOR for what is
effectively a MAJOR (a breaking change to the artifact receipt/result contract
or compact control-plane envelope, for example), the human says so and the AI
adjusts. The human edits the CHANGELOG entry text if
needed — it will be read by the next person who opens `CHANGELOG.md`. When
both are right, the human applies them.

### Step 8 — Human reviews the diff and the commit message

```bash
git diff
```

The human reads the full diff. Then the human reads the AI-drafted commit
message. The commit message is edited if needed (§7 — squash-merge titles are
permanent history on `main`). The human commits:

```bash
git add <specific files>
git commit -m "feat(threats): add xdr threats list command"
```

The AI may stage files and propose the exact commit command, but the human
runs it after reviewing the staged diff.

### Step 9 — AI proposes the PR; human writes or edits the description

The AI proposes opening the PR via `gh pr create`. The human writes the PR
description — or edits the AI's draft — using the template structure (§4, §5,
§7). The `Bump:` line is required (not for `.github/`-only PRs — exempt per
§5). The human opens the PR when satisfied.

### Step 10 — AI drafts the live-tenant smoke test plan

The AI writes exact commands and predicted outputs into the PR's Test plan
section (§4, §7). If the AI's harness has tenant connectivity at the time of
review, the AI may execute non-destructive smoke commands itself and paste actual
output — read-only commands like `xdr incidents list`, `xdr hunt run`,
`xdr domains list` are safe for AI execution.

Destructive commands (`device isolate/unisolate/scan/restrict/collect-package`,
`incidents update`) are human-only for smoke testing — the per-turn authorization
model that AGENTS.md §2 uses for live operation doesn't fit a PR review workflow.
The human runs those and pastes the output.

### Step 11 — AI proposes the push; human approves

The AI proposes:

```bash
git push -u origin feat/threats-list
```

The human says yes or no in the same turn. If approval isn't granted in the
same turn, the AI skips the push and continues with other work — no blocking,
no asking again next turn (§7). This is intentional: the AI is not the decision-
maker about what lands on the remote. The human can push whenever ready.

### Step 12 — PR review and merge

Same as Walkthrough 1 steps 12–14: CI must be green, review must happen (self-
review is acceptable for small low-risk changes per §4 — non-trivial AI-assisted
changes should get a second pair of eyes), then squash-merge.

### Step 13 — Retain the spec and plan privately

Keep approved specs and plans in private storage for future reference.
Files under `docs/superpowers/` are gitignored and must not be committed to
this repository. Delete the feature branch after merge.

---

## Walkthrough 3 — A rebase walkthrough

**Trigger: You've been working on a branch for two days. You opened a PR. While
you were working, twelve commits landed on `main`. Your PR has conflicts. You
want to use this as your chance to learn rebase, because you've heard it gives
you more options at PR-merge time.**

### WHY rebase here, specifically

When `main` has moved while you were working, you have two options: merge
`main` into your branch, or rebase your branch onto `main`. Both resolve the
conflicts. But they leave your branch in different states.

If you merge `main` into your branch, a merge commit appears in your branch
history. That merge commit is permanent — GitHub's "rebase-and-merge" button
will misbehave on a branch that contains merge commits in it (it re-applies
them in ways that produce strange history on `main`). Merging effectively
restricts you to squash-merge at PR time.

If you rebase your branch onto `main`, your branch history stays linear — no
merge commits. All three merge strategies remain available at PR time: squash,
rebase-and-merge (each commit lands individually on `main`), or merge-commit.

If your branch has three commits that each tell a meaningful story worth
preserving on `main` as three separate commits, rebase is the only path that
keeps that option open. See §6 for the full tradeoff.

### Step 1 — Fetch to see what's on the remote

```bash
git fetch origin
```

This updates your local knowledge of `origin/main` without touching your working
branch. Nothing destructive happens here — you're just downloading information.

### Step 2 — Look before you leap

```bash
git log --oneline origin/main ^HEAD
```

This shows you what landed on `main` while you were gone. Read it before
starting the rebase. If a teammate's commit fundamentally changes something your
branch depends on — say, they refactored the module you're adding a method to —
you'd rather know now than discover it mid-conflict-resolution. One minute of
reading here can save twenty minutes of confused conflict resolution later.

```
a3f1b2c feat(auth): rotate token cache on 401
7e8d4f1 fix(hunt): handle empty result set without KeyError
c9a2e0d docs: update schema_pivots.md with new CloudAuditEvents columns
```

### Step 3 — Start the rebase

```bash
git rebase origin/main
```

What git does mechanically: it sets your branch's commits aside temporarily,
fast-forwards your branch to match `origin/main`, then replays your commits one
at a time on top of the new base. Each of your commits is re-applied in order,
and at each replay, conflicts can appear if the commit touches the same lines
as something that landed on `main`.

Happy path:

```
Successfully rebased and updated refs/heads/feat/domains-internal-filter.
```

Unhappy path (one of your commits touches a file that changed on `main`):

```
CONFLICT (content): Merge conflict in src/xdr_cli/commands/domains_cmd.py
error: could not apply 3a8f1c4... feat(domains): add list --internal-only filter
hint: Resolve all conflicts manually, mark them as resolved with
hint: "git add/rm <conflicted_files>", then run "git rebase --continue".
```

### Step 4 — Resolve a conflict

Open the conflicted file. You'll see conflict markers:

> ```
> <<<<<<< HEAD
>     domains = await client.get_domains()
> =======
>     domains = await client.get_all_domains(include_unverified=True)
> >>>>>>> 3a8f1c4 (feat(domains): add list --internal-only filter)
> ```

**"Ours" vs "theirs" semantics are inverted from a merge.** During a rebase:
- `<<<<<<< HEAD` (the "ours" side) is the commit from `main` — because `main`
  is now the base and `HEAD` points to where `main` is.
- `>>>>>>> <hash>` (the "theirs" side) is your commit being replayed.

This is counterintuitive. In a merge, "ours" is your branch. In a rebase,
"ours" is the base you're rebasing onto. Keep this in mind when choosing which
side to keep, or when writing the combined version.

Edit the file to the correct state (usually a combination of both sides):

```python
domains = await client.get_all_domains(include_unverified=True)
# Then filter: ...
```

Then mark it resolved and continue:

```bash
git add src/xdr_cli/commands/domains_cmd.py
git rebase --continue
```

Git will open your editor for the commit message (pre-filled with the original
message). Unless the conflict resolution changes the meaning, keep the original
message and save. Repeat for each commit that has conflicts.

### Step 5 — If you panic: abort

At any point before the rebase finishes, you can get out:

```bash
git rebase --abort
```

This returns your branch to exactly where it was before you ran `git rebase
origin/main`. Nothing is lost. Your commits are still there; your working tree
is restored. The rebase never happened.

Always available. Use freely.

WHY this matters: knowing you can always abort lowers the stakes. You don't have
to get the rebase right on the first attempt. If you hit a conflict you don't
understand, abort, go read the code that changed on `main`, come back and try
again. The abort is not a failure — it's a tool. See also recipe §9.3.

### Step 6 — Verify the result

After the rebase completes successfully:

```bash
git log --oneline
```

```
3b2c1d8 feat(domains): add list --internal-only filter
a3f1b2c feat(auth): rotate token cache on 401
7e8d4f1 fix(hunt): handle empty result set without KeyError
c9a2e0d docs: update schema_pivots.md with new CloudAuditEvents columns
...
```

Your commit(s) should appear at the top, with no merge commits anywhere in the
log. The branch is now linear on top of the latest `main`. Run tests to confirm
the resolved conflicts didn't break anything:

```bash
uv sync --locked --extra dev
uv run --frozen --extra dev pytest
uv run --frozen --extra dev ruff check src/ tests/ .github/scripts/
```

### Step 7 — Force-with-lease push

```bash
git push --force-with-lease
```

WHY `--force-with-lease` and not bare `--force` (§6):

Rebase rewrote your branch's commit hashes. The remote still has the old commit
hashes. A normal `git push` will be rejected with `non-fast-forward` — the
remote has history you're not extending, you're replacing it. A force push is
required.

But bare `--force` is dangerous: it will clobber whatever is on the remote
branch without checking, including a teammate's commits if they pushed to your
branch while you were rebasing. `--force-with-lease` checks that the remote
branch matches what you last fetched. If the remote has moved (new commits you
haven't seen), the push aborts with:

```
error: failed to push some refs to 'origin'
hint: Updates were rejected because the remote contains work that you do
hint: not have locally.
```

That abort is the protection working. Fetch, look at what changed, integrate it,
try again. Never use bare `--force` on a shared branch.

### Step 8 — Verify the PR picked up the rebase cleanly

Open the PR on GitHub and look at the Commits tab. Your commits should appear
as three commits (or however many you have) in the PR's commit list, with no
merge commit. The PR's diff should be clean — just your changes against the
current `main`, no spurious additions from the merge.

If GitHub shows your commits correctly but the diff looks wrong (includes
changes you didn't make), the rebase had a conflict resolution error somewhere.
Go back, look at the resolution carefully, and fix + push again.

### Step 9 — If the version also conflicted

If your PR bumped the version in `pyproject.toml` and someone else's PR merged
with the same `0.X.0` bump in the meantime, you'll have a version conflict
after the rebase. This is recipe §9.7:

Take the version that's now on `main` as the new base. Bump from there to the
next appropriate level for your change. Rewrite your `CHANGELOG.md` entry under
the new version heading. Force-with-lease push.

```bash
# After resolving the conflict in pyproject.toml and CHANGELOG.md:
git add pyproject.toml CHANGELOG.md
git rebase --continue
git push --force-with-lease
```

The version conflict is just a special case of a content conflict. Resolve it
the same way: decide what the right state is, edit to that state, mark resolved,
continue.
