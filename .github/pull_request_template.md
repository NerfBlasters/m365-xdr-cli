## Summary
<!-- One paragraph: what this PR does and why. Highlight breaking changes loudly. -->

## Bump
<!-- Required per CONTRIBUTING.md §5 — EXCEPT for PRs whose entire diff is under .github/ (CI/tooling config), which are exempt: leave this section blank. Pick one and add one-line rationale. -->
- [ ] **patch** — bug fix, internal refactor, docs, tests, dep bump (no surface change)
- [ ] **minor** — additive: new command/flag/library query/playbook/output-contract field
- [ ] **major** — breaking change to CLI surface, artifact/compact-output contract, AGENTS.md contract, session JSONL schema, exit-code meaning, Python minimum version
  *(Pre-1.0 modifier: at `0.x`, what would be MAJOR after 1.0 still bumps MINOR. See §5.)*

Rationale: <!-- one line -->

## Test plan
<!-- Tick each item as you do it. Sanitize tenant identifiers and secrets before pasting output. -->

### Automated
- [ ] `pytest` — N/N pass
  ```
  <paste final summary line, e.g. "294 passed, 2 warnings in 12.3s">
  ```
- [ ] `ruff check src/ tests/` — clean
  ```
  <paste, e.g. "All checks passed!">
  ```
- [ ] CI green on this PR (3.12, 3.13, 3.14)

### Live-tenant smoke test
<!-- Required for any CLI behavior change per §4. Skip for doc-only / test-only PRs.
     If skipping, write "N/A — doc/test only" and explain in one line. -->

- [ ] Smoke 1: <command> → expected: <outcome>
  ```
  <paste actual output>
  ```
- [ ] Smoke 2: ...

<!-- For destructive commands (device isolate/scan/restrict, incidents update),
     state where it was tested (test tenant / specific test device / explicit
     authorization on production). AI agents do not execute destructive
     smoke commands per AGENTS.md §2. -->

## Risk areas touched
<!-- Tick any that apply — these are the §4 higher-risk areas. -->
- [ ] `src/xdr_cli/auth.py` or `commands/auth_cmd.py` (token handling)
- [ ] `commands/device_cmd.py` write actions (isolate/scan/restrict/etc.)
- [ ] `pyproject.toml` dependencies
- [ ] Artifact receipt/preview/result-metadata or compact-envelope schema (JSON shapes AI agents consume)
- [ ] Session/history JSONL schema (`_recording.py`, `sessions.py`)
- [ ] Commit prefixed `security:`
- [ ] None — none of the above

## References
<!-- Optional. Link the spec and plan if this PR followed the spec-and-plan workflow. -->
- Spec: privately shared with reviewer (do not attach private planning files)
- Plan: privately shared with reviewer (do not attach private planning files)
- Related issues: #N

## Pre-merge checklist
- [ ] No secrets, tokens, or real tenant data in this PR (see §8). I ran `git diff` and skimmed.
- [ ] `pyproject.toml` version bumped per the level above. (N/A for .github/-only PRs — see §5)
- [ ] `CHANGELOG.md` updated under a new version heading. (N/A for .github/-only PRs — see §5)
- [ ] CI is green (or will be before merge).
- [ ] Live-tenant smoke completed (or skipped with reason above).
