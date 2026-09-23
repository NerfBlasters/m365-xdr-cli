# Alert Type: Anomalous token / token theft

## Overview

This alert fires when Defender detects sign-in activity consistent with a stolen or replayed authentication token. Covers:

- **Anomalous Token involving one user** — token properties (lifetime, issuer, claims) deviate from the user's baseline
- **Potential user account compromise identified through attack analysis** — behavioral analysis indicates account takeover

Token theft is a post-authentication attack — the attacker has already bypassed credentials and MFA by stealing a session or refresh token. This can happen through AiTM phishing, malware on the user's device, or token extraction from browser storage.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `EntraIdSignInEvents` | Sign-in events showing token replay from different IPs | `AccountObjectId`, `AccountUpn`, `IPAddress`, `Country`, `City`, `RiskLevelDuringSignIn`, `RiskState`, `SessionId`, `UniqueTokenId`, `TokenIssuerType`, `Browser`, `UserAgent`, `ClientAppUsed`, `ErrorCode`, `AuthenticationRequirement` |
| `CloudAppEvents` | Cloud activity from the attacker's session | `AccountObjectId`, `ActionType`, `IPAddress`, `Application`, `CountryCode`, `City` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId`, `RemoteIP` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the user, the suspicious IP(s), timestamps, and any session or token identifiers. The alert evidence may indicate which sign-in was flagged as anomalous.

2. **Run the token theft replay library query.** Get an overview of the user's sign-in IP diversity:
   ```bash
   xdr library run ttp_token_theft_replay
   ```
   Filter results by the user's UPN. A high count of distinct IPs, especially across different countries, is a strong indicator.

3. **Pull detailed sign-in history.** Query `EntraIdSignInEvents` around the alert time:
   ```bash
   xdr library run identity_signin_context --param account_oid=<user-oid> --param start=<start_minus_24h> --param end=<end>
   ```
   Look for:
   - **Same `SessionId` from different IPs** — the attacker is replaying a session token from their own machine.
   - **`AuthenticationRequirement` of `singleFactorAuthentication`** on an account that requires MFA — indicates token replay (no interactive auth needed).
   - **`TokenIssuerType`** anomalies — tokens issued by an unexpected authority.
   - **Different `UserAgent`/`Browser`** for concurrent sessions — the attacker's browser fingerprint differs from the user's.

4. **Separate the user's sessions from the attacker's.** Group sign-ins by IP and identify which IP is the user's legitimate location and which is the attacker:
   ```bash
   xdr library run identity_signin_ip_summary --param account_oid=<user-oid> --param start=<start_minus_24h> --param end=<end>
   ```
   The user's legitimate IP will have the most sign-ins and consistent browser fingerprints.

5. **Assess attacker activity.** Query `CloudAppEvents` for actions from the attacker's IP:
   ```bash
   xdr library run qry_post_compromise_activity --param account_oid=<user-oid> --param ip=<attacker-ip> --param start=<compromise_time> --param end=<compromise_time_plus_4h>
   ```
   Typical attacker actions: inbox rule creation, mail forwarding, OAuth app consent, file downloads, BEC email sending.

6. **Check for inbox rule manipulation and mail forwarding.**
   ```bash
   xdr library run qry_inbox_rule_activity
   ```
   Filter by the user. Attackers with stolen tokens frequently establish email persistence before the token is revoked.

7. **Determine the theft vector.** How was the token stolen?
   - **AiTM phishing:** Check `UrlClickEvents` and `DeviceNetworkEvents` for phishing proxy connections (see `identity-aitm-phishing.md`).
   - **Malware on device:** Check `DeviceEvents` and `DeviceProcessEvents` for infostealers or browser credential extractors on the user's device.
   - **Compromised device:** Check if the device has other alerts (malware, C2 activity).

## Pivots

| From | To | Why |
|---|---|---|
| User → sign-in IP diversity | `ttp_token_theft_replay` library query | Quick scope of the sign-in anomaly |
| User → sign-in detail | `EntraIdSignInEvents` by `AccountObjectId` | Separate legitimate sessions from attacker sessions |
| Attacker IP → cloud actions | `CloudAppEvents` by `IPAddress` | What did the attacker do with the stolen token? |
| User → inbox rules | `qry_inbox_rule_activity` library query | Attacker persistence in the mailbox |
| Attacker IP → other users | `EntraIdSignInEvents` by `IPAddress` | Did the attacker use stolen tokens from other accounts too? |
| User → device alerts | `AlertEvidence` by `AccountObjectId` or `DeviceId` | Was the token stolen via malware on the user's device? |

## Common false positives

- **VPN IP rotation.** Users switching between VPN servers can generate sign-ins from multiple IPs/countries in a short window. Check if the IPs belong to known VPN providers and the `UserAgent` is consistent.
- **Mobile roaming.** Cellular connections can change IP frequently, especially during travel. Check `DeviceName` and `OSPlatform` — if all sign-ins are from the same mobile device, it's likely benign.
- **Cloud proxy (Zscaler, Netskope).** Traffic routed through a CASB proxy may appear from multiple datacenter IPs. Verify the IPs belong to a known proxy service.
- **Shared service accounts.** Multiple users authenticating with the same service account from different locations. Verify the account type.

For all false positives, check: **did any of the unusual IPs perform suspicious post-authentication actions?** Benign IP diversity without suspicious cloud activity is likely a false positive.

## Containment recommendations

If token theft is confirmed:

1. **Revoke ALL sessions and refresh tokens immediately.**
   > Suggest to the analyst: revoke all sessions in Entra ID. This is the most critical step — it invalidates the stolen token. A password reset alone does NOT invalidate existing session tokens.

2. **Reset password and require MFA re-registration.**
   > Suggest: reset the user's password. Check MFA registration for methods added from the attacker's IP — remove any unauthorized MFA methods.

3. **Remove attacker persistence.**
   - Inbox rules created from the attacker's IP
   - Mail forwarding rules
   - OAuth app consents
   - Delegated mailbox access

4. **Investigate the theft vector.** If AiTM phishing was the vector, follow `identity-aitm-phishing.md` containment steps. If malware on the device, follow `endpoint-malware-generic.md`.

5. **Monitor for re-compromise.** Watch `EntraIdSignInEvents` for the user over the next 48 hours for sign-ins from the attacker's IP or new anomalous IPs.
