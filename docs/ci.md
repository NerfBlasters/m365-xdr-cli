# CI security

CI runs for pull requests, pushes to main, weekly, and on manual dispatch.
`CI gate` succeeds only when every applicable job succeeds. Require this check
in the main branch ruleset; the PR-only version check may skip on other events.

| Check | Purpose |
| --- | --- |
| Python 3.11–3.14 and Windows tests | Correctness and supported-platform behavior |
| pip-audit | Known vulnerabilities in locked runtime, development, and build dependencies |
| GuardDog | Package metadata and source patterns associated with malicious packages |
| Gitleaks | Secrets in fetched Git history, including intermediate PR commits |
| Bandit | Medium/high-severity, high-confidence Python security patterns |
| actionlint and zizmor | Workflow correctness and GitHub Actions security |
| Distribution checks | Build, metadata validation, private-artifact rejection, clean wheel install |

Existing regression tests cover token/cookie output suppression, secret-file
permissions, and KQL parameter escaping. CI helper tests cover malformed or
incomplete scans and prohibited archive members. Tests use synthetic data and
mock services; no live tenant secrets belong in CI.

## Dependencies and GuardDog

Use uv 0.12.18. Commit `uv.lock`; run `uv lock` when requirements change. CI uses
`uv sync --locked` and exports all locked runtime/dev/build package versions,
including platform-specific versions, for scanning. Dependabot updates uv and
GitHub Actions weekly, with a seven-day cooldown for ordinary version updates.
Scanner versions and action/container digests are pinned separately; review
those pins when updating the scanners.

GuardDog runs in its own digest-pinned container, without installing its
Semgrep dependencies into the application environment. All default rules run.
The small adapter checks exact package/version coverage and rejects scanner
errors, empty output, and unknown risk labels. Native `suspicious` and
`high_risk` results block; `low` and `no_risks_detected` results do not. Raw
JSON and SARIF retain the observations, including nonblocking results.

This is a heuristic gate, not proof a dependency is safe. A package-version scan
does not attest every platform wheel against the bytes installed by uv. uv's
lock hashes protect artifact integrity during installation; review upstream
provenance and release changes for sensitive updates as well.

Reports are retained as workflow artifacts for 14 days. Once the repository is
public, GuardDog SARIF also uploads to GitHub code scanning. Private repositories
still retain reports without requiring a code-scanning subscription.

### Handling a blocked dependency

Read the native report, inspect the exact upstream release and flagged code,
and distinguish expected functionality from evidence of compromise. Scanner
errors and missing packages must be fixed or rerun; they are never clean scans.

Reviewed exceptions live in `.github/guarddog-exceptions.json`, protected by
the maintainer review policy and CODEOWNERS. Each names one exact package version, a SHA256 fingerprint of all
native rule results and the risk score, supporting evidence, a reason, and a
review/expiry window of at most 90 days. Any changed finding, package version,
scanner version, or expired exception requires renewed review. Scan errors and
incomplete coverage cannot be waived. The scan reports remain unmodified.

To review an exception, examine the full `guarddog.json` observations and the
upstream release. Calculate the fingerprint using `fingerprint(result)` from
`.github/scripts/guarddog_scan.py` only after the review; never automatically
refresh fingerprints or expiration dates. Include the rationale and evidence
in the PR for explicit maintainer review; seek an independent reviewer when available. Remove obsolete entries when
updating dependencies. Dismissing an alert in GitHub code scanning does not
change this gate. These exceptions accept documented heuristic observations;
they do not certify the entire dependency as safe.

## Workflow trust and repository settings

Actions use full commit SHAs, checkout does not retain credentials, and the
default token is read-only. Only the dependency job requests security-events
write permission for SARIF. There is no `pull_request_target`, publishing job,
or tenant credential. Keep fork workflows unprivileged and require approval
for external contributors' workflow runs. Do not add privileged self-hosted
runners for public PRs.

Before publishing, configure and verify these GitHub settings:

- Require PRs and `CI gate` on main; require the branch to be current.
- While solo, require zero approving reviews and leave required CODEOWNER
  review and last-push approval disabled. Require resolved review conversations.
  CODEOWNERS identifies sensitive files and requests maintainer review of
  contributor changes; it does not provide independent review of owner changes.
- Block force pushes and branch deletion, with no routine bypass.
- Review every PR manually, including AI/bot contributions and scanner
  exceptions. Request outside review of significant auth, credential-handling,
  or CI changes when feasible. Once another trusted maintainer joins, enable
  required approvals, CODEOWNER review, and dismissal of stale approvals.
- Enable dependency alerts, secret scanning and push protection where available.
  GitHub plan/visibility can affect ruleset and security-feature availability.

These settings are not activated merely by adding these files. Scanner jobs
execute PR-controlled code: a PR can change its own workflow or scanner policy.
The sole maintainer must inspect those changes before merging, even when CI is
green. CI and AI review do not replace an independent human reviewer. No automatic dependency merges are configured.

Company/domain denylist checks belong in the private release-review process,
not a public configuration that advertises those identifiers. Gitleaks has one
exact, path-scoped exception for a synthetic pagination cursor in tests; it
ignores inline `gitleaks:allow` bypass comments.

If package publication is added later, use PyPI Trusted Publishing and a
protected release environment, without a long-lived upload token. This CI
builds and checks distributions but does not publish them.
