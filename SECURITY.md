# Security Policy

`xdr-cli` is a security tool. Vulnerabilities deserve responsible disclosure
via private channels — please do not open public GitHub issues for security
issues.

## In scope

- Token handling in `src/xdr_cli/auth.py` and `src/xdr_cli/commands/auth_cmd.py`
  (MSAL cache, token serialization, scope confusion)
- KQL injection vectors in library queries (`src/xdr_cli/queries/*.kql`)
  and in the parameter-substitution path
- Output injection in compact envelopes, artifact receipts/previews, or result
  JSONL (e.g., crafted Defender data that could compromise an LLM consuming
  the output)
- Session/result data leakage (`~/.xdr-cli/sessions/*.jsonl`,
  `~/.xdr-cli/results/`, including stored KQL in metadata sidecars)
- Dependency vulnerabilities affecting the CLI

## Out of scope

- Vulnerabilities in Microsoft Defender XDR or Microsoft Graph itself.
  Report those directly to Microsoft via the
  [Microsoft Security Response Center (MSRC)](https://msrc.microsoft.com/).
- Vulnerabilities in third-party tools you've integrated with `xdr-cli`
  (PowerShell modules, jq, etc.) — report to those projects.

## How to report

Use GitHub's private vulnerability reporting: on the repository's **Security**
tab, click **Report a vulnerability**. (This requires a public repository
with private vulnerability reporting enabled by the maintainer; it is not
available while this repo is private.)

If GitHub private reporting isn't available, use a private contact method
published on the maintainer's GitHub profile. Do not open a public issue that
contains vulnerability details.

## Response expectations

- **Acknowledgment:** within 7 days of report
- **Triage and target fix date:** within 30 days
- **Coordinated disclosure timeline:** negotiable per severity

## Bounty

No bug bounty program. Credit in `CHANGELOG.md` and a SECURITY.md
hall-of-fame on request.
