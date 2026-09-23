# Alert Type: Adversary-in-the-middle (AiTM) phishing

## Overview

This alert fires when Defender detects that a user's session may have been intercepted by an adversary-in-the-middle phishing site — a proxy that relays authentication between the user and the legitimate sign-in page, capturing both credentials and session tokens in real time.

- **Suspicious activity likely indicative of a connection to an adversary-in-the-middle (AiTM) phishing site**

AiTM attacks are **more dangerous than traditional credential phishing** because they capture the session token after MFA completion, allowing the attacker to bypass MFA entirely. The attacker doesn't need to crack a password or intercept an MFA code — they get a fully authenticated session cookie.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `EntraIdSignInEvents` | Sign-in events showing the proxy IP and stolen session | `AccountObjectId`, `AccountUpn`, `IPAddress`, `Country`, `City`, `RiskLevelDuringSignIn`, `RiskState`, `SessionId`, `UserAgent`, `Browser`, `ConditionalAccessStatus`, `AuthenticationRequirement`, `TokenIssuerType` |
| `DeviceNetworkEvents` | Device-side connection to the phishing proxy | `DeviceId`, `RemoteUrl`, `RemoteIP`, `InitiatingProcessFileName` |
| `DeviceEvents` | SmartScreen or network protection blocks | `DeviceId`, `ActionType`, `RemoteUrl`, `InitiatingProcessFileName` |
| `CloudAppEvents` | Post-compromise cloud activity using the stolen token | `AccountObjectId`, `ActionType`, `IPAddress`, `Application`, `CountryCode` |
| `UrlClickEvents` | Email URL click that led to the AiTM site | `NetworkMessageId`, `Url`, `AccountUpn`, `IsClickedThrough` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId`, `RemoteUrl`, `RemoteIP` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the user, device, the AiTM proxy URL/IP, and timestamps. The alert evidence may include the phishing URL and the legitimate service that was proxied.

2. **Identify the phishing proxy.** Check `DeviceNetworkEvents` for the connection to the AiTM site:
   ```bash
   xdr library run qry_device_connections --param device_id=<device-id> --param remote=<aitm-domain-or-ip> --param start=<start> --param end=<end>
   ```
   Also check if the URL arrived via email:
   ```bash
   xdr library run qry_url_clicks --param account_upn=<user> --param start=<start_minus_24h> --param end=<end>
   ```
   Pivot: `qry_url_clicks` defaults to `mode=detail` (per-URL rows, vs. the `mode=summary` aggregate); post-filter on `Url` to isolate the specific AiTM domain from the user's full click history.

3. **Check if the attacker obtained a session token.** Query `EntraIdSignInEvents` for sign-ins from the AiTM proxy IP or from a new IP shortly after the user's legitimate sign-in:
   ```bash
   xdr library run identity_signin_context --param account_oid=<user-oid> --param start=<signin_time> --param end=<signin_time_plus_4h>
   ```
   Look for:
   - A sign-in from a **different IP** shortly after the legitimate sign-in, with the same `SessionId` — this is the attacker replaying the stolen token.
   - `RiskLevelDuringSignIn` flagged as medium/high.
   - Sign-in from a different country or ISP than the user's normal location.
   - The attacker's sign-in may show `AuthenticationRequirement` of `singleFactorAuthentication` even though the account requires MFA — because they're using a stolen session token, not re-authenticating.

4. **Check for token theft indicators.** Cross-reference with the token theft library query:
   ```bash
   xdr library run ttp_token_theft_replay
   ```
   If the user shows sign-ins from many distinct IPs, the stolen token may have been used from multiple attacker machines.

5. **Assess post-compromise activity.** The attacker with a stolen session token will act quickly. Check `CloudAppEvents` for the attacker's IP:
   ```bash
   xdr library run qry_post_compromise_activity --param account_oid=<user-oid> --param ip=<attacker-ip> --param start=<compromise_time> --param end=<compromise_time_plus_4h>
   ```
   Common attacker actions after AiTM:
   - Inbox rule creation to intercept MFA reset notifications
   - Email forwarding to external addresses
   - OAuth app consent for persistent access
   - BEC (business email compromise) — sending phishing from the compromised account

6. **Check for inbox rule manipulation.**
   ```bash
   xdr library run qry_inbox_rule_activity
   ```
   Filter by the compromised user. AiTM attackers frequently create rules to delete security notifications.

7. **Check blast radius.** Did the AiTM campaign target other users?
   ```bash
   xdr library run qry_connection_scope --param remote=<aitm-domain-or-ip> --param start=<start_minus_24h> --param end=<end>
   ```
   Also check `UrlClickEvents` for the same URL across all users.

## Pivots

| From | To | Why |
|---|---|---|
| AiTM URL → other users | `UrlClickEvents` + `DeviceNetworkEvents` by URL/IP | Who else visited the phishing proxy? |
| User → sign-ins post-compromise | `EntraIdSignInEvents` by `AccountObjectId` | Identify the attacker's replayed session |
| Attacker IP → cloud actions | `CloudAppEvents` by `IPAddress` | What did the attacker do with the stolen token? |
| User → inbox rules | `qry_inbox_rule_activity` library query | Did the attacker create persistence in the mailbox? |
| Source email → recipients | `EmailEvents` by `NetworkMessageId` | Who else received the phishing email? |
| User → OAuth app consents | `CloudAppEvents` by `AccountObjectId` + consent ActionTypes | Did the attacker grant persistent app access? |

## Common false positives

- **Legitimate reverse proxies.** Some organizations use reverse proxies for SSO or VPN that trigger AiTM-pattern detections. Verify the proxy URL — if it belongs to a known corporate service (Zscaler, Akamai, Cloudflare Access), it's likely benign.
- **Security testing.** Red team exercises or phishing simulations using AiTM frameworks (Evilginx, Modlishka). Verify with the analyst whether a red team engagement is in progress.
- **Browser extensions.** Some browser extensions proxy authentication flows in ways that resemble AiTM. Check the `InitiatingProcessFileName` and whether the user has known extensions installed.

AiTM false positives are uncommon. **Treat these alerts as high-priority until proven otherwise.**

## Containment recommendations

AiTM compromise requires aggressive, immediate response:

1. **Revoke ALL sessions and tokens immediately.**
   > Suggest to the analyst: revoke all refresh tokens and active sessions for the user in Entra ID. This invalidates the stolen session token. A password reset alone is NOT sufficient for AiTM — the attacker has a session token, not just credentials.

2. **Reset password and re-enroll MFA.**
   > Suggest: reset the user's password and require MFA re-registration. The attacker may have registered their own MFA methods.

3. **Remove attacker persistence.** Check and remove:
   - Inbox rules (especially deletion rules targeting security notifications)
   - Mail forwarding rules
   - OAuth app consents granted from the attacker's IP
   - MFA methods added from unfamiliar locations

4. **Block the AiTM infrastructure.**
   > Suggest: add the phishing proxy URL/domain/IP to custom indicators and the Tenant Allow/Block List. Block at the network firewall level.

5. **Notify other affected users.** If the AiTM campaign targeted multiple users, repeat the containment steps for each compromised account.

6. **Purge the phishing email.**
   > Suggest: use Explorer to hard-delete the phishing email from all recipient mailboxes.
