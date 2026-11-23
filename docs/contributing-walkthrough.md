# Your first xdr-cli pull request

## Start a branch

Fork the public repository on GitHub and clone your fork. From that checkout, register the upstream URL from the project's GitHub page:

```bash
git remote add upstream https://github.com/NerfBlasters/m365-xdr-cli.git
git fetch upstream
git switch -c fix/result-pagination upstream/main
uv sync --locked --extra dev
```

Maintainers working in a direct clone can fetch and branch from `origin/main` instead. Check `git remote -v` before publishing.

## Make and verify the change

For example, a fix to result pagination should exercise a saved synthetic result with more than one page. Check both the selected rows and the returned offset through the CLI. This example needs no tenant credentials. Run focused tests first, then the local Python checks:

```bash
uv run --frozen --extra dev ruff check src/ tests/ .github/scripts/
uv run --frozen --extra dev pytest tests/ .github/scripts/test_guarddog_scan.py -q
```

A change to a live API request needs different evidence. Add mocked success and failure cases, then arrange the focused smoke test in [CONTRIBUTING §4](../CONTRIBUTING.md#4-review-and-verification). Contributors without a test tenant can identify that check in their PR. Use synthetic fixtures and describe live outcomes in sanitized terms. For a website change, follow the [website instructions](../website/README.md).

For the pagination fix, update the package version, lockfile and changelog. A walkthrough-only correction needs just the documentation diff and a link/command check. See [the release scope](../CONTRIBUTING.md#5-versioning-and-releases).

## Publish and review

Inspect `git status`, stage only the intended files, and review `git diff --staged`. Commit with a descriptive title, push your branch to your fork, and open a PR against upstream `main`. Explain the user-visible effect, how you verified it, and any evidence still needed. AI contributors use the same workflow with the [publication authorization in §7](../CONTRIBUTING.md#7-working-with-ai-agents).

Open the PR's Checks tab. Use the failing job's log to reproduce an error, push the correction to the same branch, and resolve review comments. A green aggregate gate and maintainer review are required for merge. The [CI guide](ci.md) explains scanner findings, distribution checks, and the protected workflow.
