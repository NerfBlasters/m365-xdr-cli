# Contributing to xdr-cli

Contribute through a pull request against `main`. Use the [contributor walkthrough](docs/contributing-walkthrough.md) for a first PR, the [backend development guide](docs/backend_development.md) for API operations and the [CI guide](docs/ci.md) for checks and repository settings.

## 1. Scope the change

Describe the user-visible outcome and how to verify it. For a fix, identify the failing behavior. Agree on the design with the maintainer when a feature introduces a new public contract, persistence model, authorization boundary or consequential tradeoff. An issue, PR discussion or private spec can capture that decision. Routine fixes and documentation corrections can go straight to a PR.

## 2. Branches

Start a topic branch from current `main`, for example `fix/result-pagination`. External contributors push the branch to their fork. Keep the diff focused and preserve other contributors' work.

## 3. Commits

Use Conventional Commit titles such as `feat(hunt): ...`, `fix(results): ...` or `docs: ...`. Squash merge is the default. The maintainer reviews the final PR title, description, diff and evidence before merge. Use rebase-and-merge when the individual commits are worth preserving.

## 4. Review and verification

Every change goes through a PR and the aggregate `CI gate`. Run focused tests during development. For Python implementation changes run the full local tests and lint before declaring the change verified. Run the relevant website, packaging or workflow checks when changing those surfaces. For prose changes, verify links, examples and claims against the CLI or source. CI runs the cross-platform and security checks. Report checks you could not run.

Choose evidence that exercises the changed boundary:

| Change | Evidence |
| --- | --- |
| Local parsing, citations, receipts, migrations or retention | Deterministic fixtures through the normal CLI entry point. Exercise malformed input, retries or partial failures where relevant. |
| Graph, MDE or portal requests, authentication, permissions or provider-specific behavior | Mocked failure coverage plus a focused live smoke test of the changed integration before merge. A public contributor can submit without tenant access; the maintainer arranges the live check. |
| Local feature that also changes a tenant read path | Exercise the local cases with fixtures and the integrated path with a representative live read. |
| Tenant or endpoint mutation | Use the repository's response-action boundaries. A human performs any destructive live smoke test in an appropriate test environment. |

The PR should state what changed, release impact, evidence and residual risk. Link CI for automated results. For live tests record the command with placeholders, outcome, backend and relevant limitations. Keep raw receipts, identifiers and private artifacts out of the public PR.

Explicit maintainer scrutiny applies to credential handling, device and Live Response writes, AI-consumed output or session contracts, dependencies, CI permissions and scanner exceptions. While there is one maintainer, the maintainer reviews every diff and seeks outside review for significant security changes when available. See the [CI guide](docs/ci.md) for intended branch protections.

## 5. Versioning and releases

For changes to the CLI, its runtime or build inputs, playbooks, and the agent investigation contract, bump `project.version` in `pyproject.toml`, synchronize `uv.lock` with `uv lock`, and add a dated version heading and entry to `CHANGELOG.md`. Explain the release impact in the PR. Use PATCH for compatible fixes and internal package changes, MINOR for additions, and MAJOR for breaking public contracts. Before 1.0, breaking changes use MINOR and should be explicitly called out. Public contracts include exit codes, flags, receipt and JSONL semantics, and instructions relied upon by investigation agents.

Contributor workflow, CI, website and test-only changes are exempt. CI skips release metadata checks for a nonempty diff confined to `.github/`, `website/`, `tests/`, `CONTRIBUTING.md`, `docs/contributing-walkthrough.md` and `docs/ci.md`. Other paths retain the existing bump requirement. A mixed PR follows the package rule. This deliberately keeps changes to operational guidance, including `AGENTS.md` and investigation docs, reviewable as release changes. Tags and GitHub Releases are cut at maintainer-selected versions.

## 6. Keeping a branch current

Fetch upstream changes and rebase or merge current `main` into your topic branch. After resolving conflicts, rerun affected checks and inspect the diff. If a published personal branch was rebased, use `git push --force-with-lease` only on that branch. Merging upstream into the branch avoids rewriting shared history.

## 7. Working with AI agents

An approved design authorizes local implementation and verification within its scope. The agent can maintain its own implementation plan and make local branch commits. A second plan document, approval of intermediate commit messages and phased delivery are optional. Return to the maintainer for a material scope change, a new product or compatibility decision, or a destructive operation. Keep private design and investigation material in the ignored local planning directories.

Agents may draft the PR title, description, version bump and changelog. Obtain authorization before pushing or opening a PR. A request to open a draft PR includes pushing the necessary topic branch to the intended remote. Maintainers retain merge and release authority. Report what was verified and any remaining gaps. Use [AGENTS.md](AGENTS.md) for tenant operations and [the review rules above](#4-review-and-verification) for live smoke tests.

## 8. Public contributions and sensitive data

Inspect the staged diff and the commits you intend to publish. Use synthetic tenant data in code, tests, docs, issues and PRs. Keep real tenant identifiers, hunt rows, access tokens, cookies, certificates, `~/.xdr-cli/` contents and local harness transcripts private. CI scans commit history, including intermediate PR commits. If a credential is exposed, revoke it and follow [SECURITY.md](SECURITY.md). Report vulnerabilities through its private channel.

## Adding a CLI command

Register commands on the existing Click group. Use explicit types, defaults and help on Click options and arguments. Use `EnumValueChoice` and `optional_multiple` from `xdr_cli.cli_params` where appropriate. Read application state from `ctx.obj`. Keep recording and mutation checks on Click's public callback interfaces.

Run `pytest tests/test_cli_contract.py tests/test_cli_params.py -q` for parser and public-surface changes. If the contract intentionally changes, review each fixture difference after regenerating with `XDR_REGENERATE_CLI_CONTRACT=1`. Preserve the stdout/stderr and exit-code contracts described in [AGENTS.md](AGENTS.md).
