# Alert Type: Risky sign-in — TOR, anonymous proxy, unfamiliar properties, malicious IP

## Overview

These alerts fire when Entra ID Identity Protection or Defender detects sign-ins with elevated risk indicators. Covers:

- **Activity from a TOR IP address** — sign-in from the TOR anonymization network
- **Activity from an anonymous proxy** — sign-in through an anonymizing proxy service
- **Anonymous IP address** — sign-in from an IP flagged as anonymous
- **Unfamiliar sign-in properties** — sign-in with atypical device, location, or browser for the user
- **Malicious IP address** — sign-in from an IP associated with known malicious activity
- **Suspicious impersonated activity** — sign-in that appears to impersonate a legitimate user

These are **risk signals**, not confirmed compromises. The risk level depends on whether the sign-in succeeded and whether the user's behavior afterwards is consistent with compromise.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `EntraIdSignInEvents` | Sign-in events with risk flags and geo context | `AccountObjectId`, `AccountUpn`, `IPAddress`, `Country`, `City`, `RiskLevelDuringSignIn`, `RiskLevelAggregated`, `RiskState`, `RiskEventTypes`, `ErrorCode`, `Browser`, `UserAgent`, `ClientAppUsed`, `DeviceName`, `OSPlatform`, `AuthenticationRequirement`, `ConditionalAccessStatus` |
| `CloudAppEvents` | Post-sign-in cloud activity | `AccountObjectId`, `ActionType`, `IPAddress`, `Application`, `CountryCode` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId`, `RemoteIP` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the user, IP, risk type, timestamps, and whether the sign-in succeeded or was blocked.

2. **Pull the sign-in details.** Query `EntraIdSignInEvents` for the flagged sign-in:
   ```bash
   xdr library run identity_signin_context --param account_oid=<user-oid> --param start=<start> --param end=<end>
   ```
   Critical checks:
   - **`ErrorCode == 0`** → sign-in succeeded. Requires further investigation.
   - **`ErrorCode != 0`** → sign-in failed/blocked. Lower risk — the defense worked.
   - **`ConditionalAccessStatus`** → was the sign-in blocked by Conditional Access?
   - **`RiskLevelDuringSignIn`** → how risky does Entra ID consider this sign-in?

3. **Establish the user's baseline.** Compare the flagged sign-in against the user's normal sign-in pattern:
   ```bash
   xdr library run identity_signin_baseline --param account_oid=<user-oid>
   ```
   If the flagged IP, country, or browser appears in the user's recent history, it's more likely benign.

4. **Check for TOR/proxy context.** For TOR or anonymous proxy alerts specifically:
   - Some users legitimately use TOR or VPNs for privacy (especially IT or security staff). Ask the analyst if the user has a known reason.
   - Check `IsAnonymousProxy` in `CloudAppEvents` if the same IP also generated cloud activity.
   - TOR exit nodes rotate frequently — the IP may be shared by many users and may have been recently flagged.

5. **Assess post-sign-in activity (if sign-in succeeded).** Check what the user did from the risky IP:
   ```bash
   xdr library run qry_post_compromise_activity --param account_oid=<user-oid> --param ip=<risky-ip> --param start=<signin_time> --param end=<signin_time_plus_2h>
   ```
   Benign: normal work activity consistent with the user's role.
   Suspicious: inbox rule creation, mail forwarding, OAuth consent, data downloads.

6. **Check for multi-signal correlation.** Is this risky sign-in part of a broader compromise pattern?
   - Run `xdr library run ttp_token_theft_replay` to check for token reuse.
   - Check for impossible travel — is the user also signed in from a different location at the same time?
   - Check `qry_inbox_rule_activity` for post-sign-in mailbox manipulation.

## Pivots

| From | To | Why |
|---|---|---|
| User → sign-in baseline | `EntraIdSignInEvents` by `AccountObjectId` (30-day window, identity_signin_baseline default hours=720) | Is this IP/location normal for this user? |
| Risky IP → other accounts | `EntraIdSignInEvents` by `IPAddress` | Is this IP targeting multiple accounts? |
| User → post-sign-in activity | `CloudAppEvents` by `AccountObjectId` + risky IP | Did the risky sign-in lead to suspicious actions? |
| User → inbox rules | `qry_inbox_rule_activity` library query | Was the account used to set up mail exfiltration? |
| User → token replay | `ttp_token_theft_replay` library query | Multi-IP sign-in pattern confirming compromise? |

## Common false positives

- **Legitimate TOR/VPN use.** Security professionals, researchers, or privacy-conscious users. Verify with the analyst.
- **Corporate proxy or CASB egress.** Traffic routed through Zscaler, Netskope, or similar may appear from anonymous/unfamiliar IPs. Check if the IP belongs to a known proxy provider.
- **Travel.** User signing in from a new country during business travel. Check if the new location is consistent with a travel schedule.
- **New device or browser.** "Unfamiliar sign-in properties" often fires when a user gets a new laptop, phone, or updates their browser. If the IP and location are consistent with the user's normal pattern, the new device/browser is likely benign.
- **Shared IPs with poor reputation.** Hotel Wi-Fi, airport hotspots, or mobile carrier IPs may be flagged. The IP's reputation reflects other users on the same network, not the sign-in itself.

## Containment recommendations

**If the sign-in failed or was blocked:**
- No immediate action needed. Consider blocking the IP at the Conditional Access level if it's associated with a targeted campaign.

**If the sign-in succeeded and post-compromise activity is detected:**

1. **Revoke sessions and reset credentials.**
   > Suggest to the analyst: revoke all sessions, reset the user's password, and verify MFA methods.

2. **Remove attacker persistence.** Check and remove inbox rules, mail forwarding, and OAuth consents created from the risky IP.

3. **Block the IP.**
   > Suggest: add the IP to a Conditional Access named location with "Block" policy if it's not a shared resource.

**If the sign-in succeeded but no suspicious activity is detected:**
- Confirm with the user that the sign-in was legitimate. If confirmed, dismiss the alert. If the user doesn't recognize the activity, treat as compromise and follow the steps above.
