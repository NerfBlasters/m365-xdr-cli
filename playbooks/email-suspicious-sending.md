# Alert Type: Suspicious email sending patterns / user restricted from sending

## Overview

These alerts fire when Defender detects abnormal outbound email behavior from a user account. Covers:

- **Suspicious email sending patterns detected** — anomalous volume, recipient patterns, or content in outbound email
- **User restricted from sending email** — Exchange Online has throttled or blocked the user's outbound email due to suspected spam or compromise

The primary concern is **account compromise used for spam or phishing campaigns**. An attacker who gains access to a legitimate mailbox often uses it to send phishing emails to internal and external recipients, leveraging the trusted sender reputation.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `EmailEvents` | Outbound email volume and recipients | `SenderFromAddress`, `RecipientEmailAddress`, `Subject`, `DeliveryAction`, `EmailDirection`, `Timestamp` |
| `CloudAppEvents` | Exchange Online operations and sign-in activity | `AccountObjectId`, `ActionType`, `IPAddress`, `CountryCode`, `City`, `Application` |
| `EntraIdSignInEvents` | Sign-in context around the suspicious sending | `AccountObjectId`, `IPAddress`, `Country`, `RiskLevelDuringSignIn`, `ErrorCode`, `Browser`, `ClientAppUsed` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the user, timestamps, and any details about the sending pattern (volume, recipients, subject lines).

2. **Quantify the outbound email.** Check the user's outbound email volume around the alert time:
   ```bash
   xdr library run qry_email_outbound_spike --param sender=<user-email> --param start=<start> --param end=<end>
   ```
   Look for sudden spikes — a user sending hundreds of emails in an hour is almost always compromised or misconfigured.

3. **Examine the content pattern.** Check what was being sent:
   ```bash
   xdr library run qry_email_outbound_detail --param sender=<user-email> --param start=<start> --param end=<end>
   ```
   Look for: generic/phishing subject lines, mass BCC, many recipients outside the organization, or repeated identical subjects.

4. **Check sign-in context.** Was the account compromised?
   ```bash
   xdr library run identity_signin_context --param account_oid=<user-oid> --param start=<start_minus_24h> --param end=<end>
   ```
   - New IP, country, or device around the time the sending started = likely compromise.
   - `ClientAppUsed` of `SMTP` or `Other clients` = legacy auth, common for compromised accounts.
   - Check if MFA was bypassed or if the sign-in used a legacy protocol that doesn't support MFA.

5. **Check for inbox rules.** Attackers often create rules to hide bounce-backs and replies to their spam:
   ```bash
   xdr library run qry_inbox_rule_activity --param account_upn=<user-upn>
   ```
   Look for rules that delete or move messages from the inbox — especially rules targeting NDR (non-delivery report) or bounce-back subjects. Note: the query's built-in scoring is BEC-oriented (finance keywords, hidden folders, hosting/anonymizing client IPs), not NDR-subject matching specifically — review the returned rules manually for NDR/postmaster/undeliverable patterns.

6. **Check for other compromise indicators.** If the account was taken over:
   - Run `xdr library run ttp_token_theft_replay` to check for token reuse from multiple IPs.
   - Check `CloudAppEvents` for OAuth app consent or mail forwarding rule creation.

## Pivots

| From | To | Why |
|---|---|---|
| User → outbound email | `EmailEvents` by `SenderFromAddress` + `EmailDirection == 'Outbound'` | Volume and pattern of suspicious sending |
| User → sign-ins | `EntraIdSignInEvents` by `AccountObjectId` | Was the account compromised? When? |
| User → inbox rules | `qry_inbox_rule_activity` library query | Is the attacker hiding evidence? |
| Source IP → other accounts | `EntraIdSignInEvents` by `IPAddress` | Did the same IP compromise other accounts? |
| Phishing subjects → recipients | `EmailEvents` by `Subject` | Who received the phishing emails sent from this account? |

## Common false positives

- **Marketing or communications teams.** Users who legitimately send high-volume email (newsletters, announcements). Verify the user's role and whether the email content matches their responsibilities.
- **Auto-reply or out-of-office storms.** Misconfigured auto-replies can generate large volumes of outbound email. Check if the sending pattern is reply-based.
- **Distribution list management.** Sending to large distribution lists may trigger volume-based alerts. Check whether the recipients are internal distribution groups.
- **Application-generated email.** Service accounts or apps sending automated notifications. Verify the `ClientAppUsed` and whether the sending account is a known application identity.

## Containment recommendations

If the account is confirmed compromised:

1. **Block outbound email immediately.**
   > Suggest to the analyst: if not already restricted by Exchange, restrict the user's outbound sending in the Exchange admin center.

2. **Reset credentials and revoke sessions.**
   > Suggest: reset the user's password, revoke all refresh tokens, and enable MFA if not already enforced.

3. **Remove attacker persistence.** Check and remove:
   - Inbox rules created by the attacker (especially rules deleting NDRs)
   - Mail forwarding rules to external addresses
   - OAuth app consents granted during the compromised session

4. **Notify recipients.** If phishing was sent to internal users, alert the organization. If sent externally, coordinate with the analyst on external notification.
