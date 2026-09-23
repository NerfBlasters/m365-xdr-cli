# Alert Type: Privilege escalation — role changes, sensitive groups, suspicious admin activity

## Overview

These alerts fire when Defender detects changes to privileged roles, sensitive group memberships, or anomalous administrative operations. Covers:

- **Addition to Exchange Organization Management role group** — a user was added to the highest Exchange admin role
- **Suspicious additions to sensitive groups** — modifications to high-privilege AD or Entra ID groups
- **Suspicious addition and removal of elevated privileges** — a user was granted and then quickly stripped of admin rights (potential "just-in-time" abuse)
- **Suspicious administrative activity** — admin operations from atypical locations, devices, or accounts
- **Administrative action submitted by an Administrator** — flagged admin action requiring review

Privilege escalation is a critical step in the attack chain — an attacker with elevated privileges can access any resource, modify security settings, and cover their tracks. These alerts should be investigated promptly.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `CloudAppEvents` | Exchange Online and Entra ID admin operations | `RawEventData.UserId` (reliable actor — `AccountObjectId`/`AccountUpn` are unreliable for these operations), `ActionType`, `Application`, `IPAddress`, `CountryCode`, `City` |
| `IdentityDirectoryEvents` | On-prem AD group membership and object changes | `AccountObjectId`, `AccountUpn`, `ActionType`, `TargetAccountUpn`, `TargetDeviceName`, `DestinationDeviceName`, `Application` |
| `EntraIdSignInEvents` | Sign-in context for the admin who made the change | `AccountObjectId`, `IPAddress`, `Country`, `City`, `RiskLevelDuringSignIn`, `Application` |
| `GraphAPIAuditEvents` | Entra ID directory changes (role assignments, group changes) | `AccountObjectId`, `ApplicationId`, `IpAddress` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the admin account that made the change, the target user/group, the specific role or group modified, and the timestamp.

2. **Identify the change.** Query the appropriate table for the specific privilege modification:

   **For Exchange role changes:**
   ```bash
   xdr library run qry_exchange_role_changes --param hours=<lookback-hours> --param actor_upn=<admin-upn>
   ```

   **For Entra ID role and group changes:**
   ```bash
   xdr library run qry_entra_role_changes --param hours=<lookback-hours> --param actor_upn=<admin-upn>
   ```

   **For on-prem AD group changes:**
   ```bash
   xdr library run ttp_ad_directory_changes --param account_oid=<admin-oid> --param start=<start> --param end=<end>
   ```

3. **Validate the admin account.** Is the account that made the change a known administrator?
   ```bash
   xdr library run identity_signin_context --param account_oid=<admin-oid> --param start=<start_minus_24h> --param end=<end>
   ```
   - Is the admin signing in from their normal location and device?
   - Is there a risk flag on the sign-in?
   - Did the admin sign in from a new IP or country shortly before making the change?

4. **Check for admin account compromise.** If the admin's sign-in looks suspicious:
   - Run `xdr library run ttp_token_theft_replay` to check for token reuse.
   - Check `CloudAppEvents` for other admin operations from the same session.
   - Check if the admin account was recently targeted by phishing or password spray.

5. **Assess the impact of the privilege change.** What access does the new role/group provide?
   - **Exchange Organization Management** — full Exchange admin. Can read all mailboxes, create transport rules, modify all Exchange settings.
   - **Global Administrator / Privileged Role Administrator** — full Entra ID admin. Can modify any tenant setting.
   - **Domain Admins / Enterprise Admins** (on-prem) — full AD control.

6. **Check what the escalated account did after gaining privileges.** If a non-admin was elevated:
   ```bash
   xdr library run qry_post_compromise_activity --param account_oid=<target-user-oid> --param ip=<actor-ip> --param start=<elevation_time> --param end=<elevation_time_plus_4h>
   ```
   Attackers who escalate privileges often immediately create persistence (new admin accounts, OAuth apps, mail forwarding) or access sensitive data.

7. **Check for "add and remove" pattern.** Some attackers grant privileges, perform a malicious action, then remove the privileges to avoid detection:
   ```bash
   xdr library run qry_privilege_grant_revoke --param hours=<lookback-hours> --param actor_upn=<admin-upn>
   ```
   A grant followed by a quick removal is suspicious — check what happened in between.

## Pivots

| From | To | Why |
|---|---|---|
| Admin account → sign-in context | `EntraIdSignInEvents` by `AccountObjectId` | Was the admin account compromised? |
| Admin account → all admin operations | `CloudAppEvents` + `GraphAPIAuditEvents` by `AccountObjectId` | What else did this admin do? |
| Escalated user → post-escalation activity | `CloudAppEvents` by escalated user's `AccountObjectId` | What did the user do with their new privileges? |
| Source IP → other admin operations | `GraphAPIAuditEvents` by `IpAddress` | Were other admin changes made from the same IP? |
| Target group → membership history | `IdentityDirectoryEvents` by group name | Have there been other recent changes to this group? |

## Common false positives

- **Legitimate admin operations.** IT teams regularly add/remove users from admin roles as part of onboarding, offboarding, or project assignments. Verify with the analyst that the change was authorized via a change management process.
- **PIM (Privileged Identity Management) activations.** If the organization uses Entra PIM, role activations are expected and time-bounded. Check if the elevation matches a PIM activation request.
- **Automated provisioning.** Identity governance tools (SailPoint, Saviynt, etc.) may modify group memberships automatically. Check if the acting account is a known provisioning service account.
- **Break-glass account usage.** Emergency admin accounts are rarely used and may trigger alerts when activated. Verify the account is a known break-glass identity and the usage was authorized.

## Containment recommendations

If the privilege escalation is unauthorized:

1. **Revert the privilege change immediately.**
   > Suggest to the analyst: remove the unauthorized user from the privileged role/group. In Exchange, use `Remove-RoleGroupMember`. In Entra ID, remove the role assignment.

2. **Investigate the admin account.** If the admin account was compromised:
   > Suggest: reset the admin's credentials, revoke sessions, and audit all changes made by that account during the compromised period.

3. **If a non-admin was escalated by an attacker:**
   - Remove the elevated privileges.
   - Check what the user did with those privileges and revert any changes.
   - If the non-admin's own account is compromised, reset their credentials as well.

4. **Review all admin changes in the window.** The privilege escalation may be one step in a broader compromise. Audit all role assignments, group changes, and admin operations in the same time window.

5. **Enable PIM if not already deployed.**
   > Suggest: Privileged Identity Management requires just-in-time activation and approval for admin roles, reducing the window for unauthorized escalation.
