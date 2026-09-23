# Alert Type: Impossible travel activity

## Overview

This alert fires when Defender detects sign-ins from a single user account originating in geographically distant locations within a timeframe that makes physical travel between them implausible. The primary concern is **account compromise** — an attacker using stolen credentials or a replayed token from a different location while the legitimate user continues to sign in from their normal location.

Impossible travel alerts are high-signal when combined with other identity anomalies (new device, risky sign-in, inbox rule changes) and low-signal when caused by VPNs, corporate proxies, or mobile carrier IP geolocation errors.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `EntraIdSignInEvents` | Sign-in events with geo, device, risk, and auth context | `AccountObjectId`, `AccountUpn`, `IPAddress`, `Country`, `City`, `RiskLevelDuringSignIn`, `RiskState`, `Browser`, `ClientAppUsed`, `ErrorCode`, `ConditionalAccessStatus`, `AuthenticationRequirement`, `DeviceName`, `OSPlatform`, `UserAgent` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId`, `RemoteIP` |
| `IdentityLogonEvents` | On-prem / MDI logon events for the same account | `AccountObjectId`, `AccountUpn`, `IPAddress`, `DeviceName`, `LogonType` |
| `CloudAppEvents` | Post-sign-in cloud activity from the suspicious IP | `AccountObjectId`, `IPAddress`, `ActionType`, `Application` |

**Prefer `EntraIdSignInEvents` over `AADSignInEventsBeta`** — they are schema-compatible twins, but `EntraIdSignInEvents` is the newer table. See `docs/schema_pivots.md`.

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the user (`AccountObjectId`, `AccountUpn`), the two IPs, locations, and timestamps. The evidence array usually contains the sign-in pairs that triggered the alert.

2. **Pull detailed sign-in context.** Query `EntraIdSignInEvents` for the user in a window around the alert timestamps:
   ```bash
   xdr library run identity_signin_context --param account_oid=<user-oid> --param start=<start> --param end=<end>
   ```
   Look for:
   - **Risk flags:** `RiskLevelDuringSignIn` of `medium` or `high` confirms Entra ID also flagged the sign-in.
   - **ErrorCode 0** means the sign-in succeeded; non-zero means it was blocked or failed.
   - **MFA satisfaction:** `AuthenticationRequirement` of `multiFactorAuthentication` with `ConditionalAccessStatus` of `success` suggests MFA was completed — which makes token theft more likely than password-only compromise.
   - **Different devices/browsers** between the two locations strengthens the impossible-travel signal.

3. **Determine if one IP is a VPN or proxy.** Corporate VPN exit nodes and cloud proxies are the most common false positive. Check:
   - Does the IP belong to a known corporate VPN range? Compare against the organization's egress IPs (ask the analyst if not known).
   - Is the `UserAgent` or `Browser` the same across both IPs? Identical agents from different countries may indicate VPN switching, not compromise.
   - Does the IP resolve to a hosting/cloud provider? Commercial VPNs and proxies often geolocate to unexpected countries.

4. **Check sign-in baseline — is this normal for the user?** Run the baseline (defaults to a 30-day/720-hour window; pass `--param hours=168` for a 7-day window) to see if the multi-country pattern is established:
   ```bash
   xdr library run identity_signin_baseline --param account_oid=<user-oid>
   ```
   If the user signs in from both countries every day (e.g., laptop on one network, phone on another), the alert is almost certainly a false positive. A sudden new country that doesn't appear in the baseline is higher-signal.

5. **Check for token theft indicators.** Run the token theft library query for the same user:
   ```bash
   xdr library run ttp_token_theft_replay --param account_upn=<user-upn>
   ```
   If the user shows sign-ins from many distinct IPs/countries, that corroborates token theft or credential sharing.

6. **Assess post-sign-in activity from the suspicious IP.** If the sign-in from the anomalous location succeeded, check what happened next:
   ```bash
   xdr library run qry_post_compromise_activity --param account_oid=<user-oid> --param ip=<suspicious-ip> --param start=<signin_time> --param end=<signin_time_plus_2h>
   ```
   High-risk actions from the suspicious IP include: inbox rule creation, mailbox-level forwarding (`Set-Mailbox`), admin role changes, and OAuth app consent. File downloads/access are scored low-risk by `qry_post_compromise_activity` on their own — treat them as corroborating rather than high-signal.

7. **Check for lateral activity.** Did the suspicious IP appear in sign-ins for other users?
   ```bash
   xdr library run identity_ip_blast_radius --param ip=<suspicious-ip> --param start=<start> --param end=<end>
   ```
   Multiple users from the same suspicious IP may indicate a broader compromise or a shared attacker infrastructure.

## Pivots

| From | To | Why |
|---|---|---|
| User → sign-in history | `EntraIdSignInEvents` by `AccountObjectId` | Establish the user's normal sign-in geography and detect deviations |
| Suspicious IP → other users | `EntraIdSignInEvents` by `IPAddress` | Did the attacker IP compromise other accounts? |
| User → cloud actions | `CloudAppEvents` by `AccountObjectId` + `IPAddress` | What did the attacker do after signing in? |
| User → inbox rules | `qry_inbox_rule_activity` library query | Was email forwarding set up from the compromised session? |
| User → on-prem logons | `IdentityLogonEvents` by `AccountObjectId` | Did the attacker access on-prem resources (ADFS, file shares)? |
| Suspicious IP → device network | `DeviceNetworkEvents` by `RemoteIP` | Did any managed device communicate with the attacker IP? |

## Common false positives

- **Corporate VPN / proxy egress.** User connects to VPN in another country, causing sign-ins to geolocate far from their physical location. The sign-in pair will typically share the same `UserAgent`, `Browser`, and `DeviceName`. Confirm with the analyst whether the IP is a known VPN exit.
- **Mobile carrier IP geolocation errors.** Cellular ISPs sometimes geolocate IPs to the wrong city or country. The distance may appear large but the sign-ins are from the same device. Check `DeviceName` and `OSPlatform`.
- **Cloud access security broker (CASB) proxies.** Traffic routed through a CASB (e.g., Zscaler, Netskope) may appear from a datacenter country different from the user's physical location.
- **Shared accounts / service accounts.** Multiple people signing into the same account from different locations. Verify the account type — if it's a shared/service account, the alert is expected.
- **Actual travel with tight timing.** User flew between cities and signed in at both airports. Check if the time gap is plausible for air travel between those specific locations (some city pairs are closer than they appear).

For all false positives, the key question is: **did the sign-in from the anomalous location lead to any suspicious post-authentication activity?** Even a benign impossible-travel pattern warrants a quick check of `CloudAppEvents` for the suspicious IP.

## Containment recommendations

If the impossible travel is confirmed as account compromise:

1. **Revoke sessions and reset credentials.**
   > Suggest to the analyst: revoke all active sessions and reset the user's password via Entra ID. If token theft is suspected, also revoke refresh tokens.

2. **Block the suspicious IP (if not a shared resource).**
   > Suggest to the analyst: add the attacker IP to a Conditional Access named location with "block" policy, or add it to the tenant's IP blocklist.

3. **Review and remove unauthorized changes.** Check for:
   - Inbox forwarding rules created during the compromised session (use `qry_inbox_rule_activity`)
   - OAuth app consents granted from the suspicious IP
   - Admin role assignments or group membership changes

4. **If the user's device is compromised:**
   > Suggest: `xdr device isolate <device_id> --comment "<reason>"` (print the command, do not execute — containment actions are always analyst-executed)

5. **Monitor for re-compromise.** After remediation, watch `EntraIdSignInEvents` for the user over the next 24–48 hours for sign-ins from the same suspicious IP or country.
