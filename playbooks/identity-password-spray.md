# Alert Type: Password spray

## Overview

This alert fires when Defender detects a password spray attack — an attacker trying a small number of commonly-used passwords against many user accounts, avoiding per-account lockout thresholds. Covers:

- **Password Spray involving one user** — the alert targets the user(s) whose credentials were attempted or successfully compromised
- **Activity from a password-spray associated IP address** — a user signed in from an IP known to be associated with password spray campaigns

The critical question is: **did any account get compromised?** A password spray where all attempts failed is informational. A successful sign-in from a spray-associated IP requires full compromise investigation.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `EntraIdSignInEvents` | Sign-in attempts (failed and successful) from the spray IP | `AccountObjectId`, `AccountUpn`, `IPAddress`, `Country`, `ErrorCode`, `RiskLevelDuringSignIn`, `RiskState`, `ClientAppUsed`, `AuthenticationRequirement`, `ConditionalAccessStatus` |
| `IdentityLogonEvents` | On-prem / MDI logon events (if spray targets ADFS) | `AccountObjectId`, `AccountUpn`, `IPAddress`, `LogonType`, `FailureReason` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId`, `RemoteIP` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the targeted user(s), the spray source IP(s), timestamps, and success/failure status.

2. **Assess the spray scope.** How many accounts were targeted from this IP?
   ```bash
   xdr library run identity_cloud_spray_summary --param ip=<spray-ip> --param start=<start> --param end=<end>
   ```
   Key metrics:
   - **SuccessCount > 0** = at least one account was compromised. Escalate immediately.
   - **High UniqueAccounts together with a high FailCount** = classic spray pattern — the query's own Severity band flags `UniqueAccounts > 50 and FailCount > 100` (both are IP-level totals in summary mode; use `--param mode=detail` to see the individual failed sign-ins).

3. **Identify compromised accounts.** If any sign-ins succeeded:
   ```bash
   xdr library run identity_signin_context --param account_oid=<compromised-oid> --param start=<start> --param end=<end>
   ```
   For each compromised account, determine:
   - Was MFA required and satisfied? Or did the attacker bypass MFA via legacy auth?
   - `ClientAppUsed` of `Exchange ActiveSync`, `IMAP`, `SMTP`, or `Other clients` = legacy protocol that may not enforce MFA.

4. **Check for post-compromise activity.** For each successfully compromised account, pivot to `CloudAppEvents`:
   ```bash
   xdr library run qry_post_compromise_activity --param account_oid=<compromised-oid> --param ip=<spray-ip> --param start=<compromise_time> --param end=<compromise_time_plus_4h>
   ```
   Check for inbox rule creation, mail forwarding, OAuth consent, and file access.

5. **Check for inbox rule manipulation on compromised accounts.**
   ```bash
   xdr library run qry_inbox_rule_activity
   ```
   Filter by each compromised user. Attackers who gain access via password spray often immediately set up email forwarding.

6. **Analyze the error codes for failed attempts.** Different error codes reveal different situations:
   ```bash
   xdr library run identity_cloud_spray_summary --param ip=<spray-ip> --param start=<start> --param end=<end>
   ```
   The output includes error code breakdowns. Common codes: `50126` (invalid password), `50053` (account locked), `50057` (account disabled), `50076` (MFA required but not completed). A mix of `50126` across many accounts confirms a spray pattern.

7. **Check on-prem authentication.** If the organization uses ADFS or pass-through auth, the spray may also appear in MDI:
   ```bash
   xdr library run identity_brute_force_summary --param ip=<spray-ip> --param start=<start> --param end=<end>
   ```

## Pivots

| From | To | Why |
|---|---|---|
| Spray IP → all targeted accounts | `EntraIdSignInEvents` by `IPAddress` | Full scope of the spray campaign |
| Compromised account → cloud activity | `CloudAppEvents` by `AccountObjectId` + attacker IP | What did the attacker do post-compromise? |
| Compromised account → inbox rules | `qry_inbox_rule_activity` library query | Was mail forwarding established? |
| Spray IP → on-prem logons | `IdentityLogonEvents` by `IPAddress` | Was ADFS also targeted? |
| Compromised account → sign-in history | `EntraIdSignInEvents` by `AccountObjectId` | Was the account accessed before the spray (prior compromise)? |

## Common false positives

- **Legacy migration tools.** Service accounts that authenticate many users (e.g., email migration tools) can appear as spray patterns. Check whether the IP belongs to a known migration service and the `ClientAppUsed` is expected.
- **Misconfigured applications.** An app trying to authenticate with stale credentials across many accounts. Check the `Application` field — if all attempts target the same application from a known service IP, it may be a configuration issue.
- **Corporate VPN exit IPs.** If the spray IP is a corporate VPN exit, the "spray" may be many legitimate users authenticating from the same IP. Check if the IP is a known corporate egress.
- **Red team / penetration testing.** Verify with the analyst whether an authorized security assessment is in progress.

## Containment recommendations

**If no accounts were compromised (all attempts failed):**
- The spray was unsuccessful. Consider blocking the spray IP at the firewall/Conditional Access level to prevent future attempts. Review whether legacy authentication protocols are disabled tenant-wide.

**If one or more accounts were compromised:**

1. **Reset credentials for ALL compromised accounts.**
   > Suggest to the analyst: reset passwords and revoke sessions for every account that had a successful sign-in from the spray IP.

2. **Disable legacy authentication.**
   > Suggest: if any compromises used legacy protocols (IMAP, SMTP, EAS), block legacy authentication via Conditional Access tenant-wide. This is the single most impactful remediation for password spray.

3. **Enforce MFA.** If compromised accounts did not have MFA enforced, enable it immediately.

4. **Remove attacker persistence** on each compromised account:
   - Inbox rules and mail forwarding
   - OAuth app consents
   - Unauthorized MFA methods

5. **Block the spray IP.**
   > Suggest: add the spray IP to a Conditional Access named location with "Block" policy.

6. **Check for weak passwords.** The accounts that were successfully sprayed had guessable passwords. Recommend the analyst review the organization's password policy and consider deploying Microsoft Entra Password Protection (formerly Azure AD Password Protection).
