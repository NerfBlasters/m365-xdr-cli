# Alert Type: Malicious URL click / phishing site access

## Overview

These alerts fire when a user clicks a malicious or phishing URL — either from email, from a browser, or via an HTML attachment. Covers:

- **A potentially malicious URL click was detected** — Safe Links detected a click on a known-malicious URL
- **Device tried to access a phishing site** — SmartScreen or network protection blocked a phishing navigation
- **HTML attachment phishing attempt** — an HTML attachment contained a phishing form or redirect
- **Phishing document** — a document (PDF, Office) containing phishing links was opened
- **User accessed a link in an email subsequently quarantined by ZAP** — user clicked before ZAP removed the message

The critical question is **did the user interact with the destination** — a blocked navigation is very different from a user who entered credentials on a phishing page.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `UrlClickEvents` | Safe Links click telemetry | `NetworkMessageId`, `Url`, `AccountUpn`, `ActionType`, `IsClickedThrough`, `IPAddress`, `Timestamp` |
| `EmailEvents` | Source email for the clicked URL | `NetworkMessageId`, `RecipientEmailAddress`, `SenderFromAddress`, `Subject`, `DeliveryAction` |
| `EmailUrlInfo` | All URLs in the source email | `NetworkMessageId`, `Url`, `UrlDomain` |
| `DeviceEvents` | SmartScreen/network protection blocks on endpoint | `DeviceId`, `ActionType`, `RemoteUrl`, `InitiatingProcessFileName` |
| `DeviceNetworkEvents` | Outbound connections to phishing domains | `DeviceId`, `RemoteUrl`, `RemoteIP`, `InitiatingProcessFileName` |
| `EntraIdSignInEvents` | Post-click sign-in anomalies (credential theft) | `AccountObjectId`, `IPAddress`, `Country`, `RiskLevelDuringSignIn`, `ErrorCode` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `RemoteUrl`, `AccountObjectId` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the URL, user, device, and timestamps. The evidence typically contains the URL, its verdict, and whether the click was blocked.

2. **Determine if the user clicked through.** Query `UrlClickEvents` for the specific URL and user:
   ```bash
   xdr library run qry_url_clicks --param account_upn=<user-upn> --param start=<start> --param end=<end>
   ```
   - `IsClickedThrough == true` — the user bypassed the Safe Links warning. This is the high-risk scenario.
   - `ActionType` of `ClickBlocked` — the click was prevented. Lower risk, but verify on the endpoint.

3. **Check the source email (if URL came from email).** Use the `NetworkMessageId` to find the source:
   ```bash
   xdr library run qry_email_delivery --param network_message_id=<network-message-id>
   ```
   Check whether ZAP removed the email after the click.

4. **Assess blast radius.** Did other users receive emails with the same URL?
   ```bash
   xdr library run qry_email_url_blast_radius --param url_domain=<malicious-domain> --param start=<start_minus_24h> --param end=<end>
   ```
   Then check `UrlClickEvents` for the same URL to see who else clicked.

5. **Check endpoint activity.** If the user clicked through, look for post-click execution or credential entry:
   ```bash
   xdr library run qry_device_connections --param device_id=<device-id> --param remote=<malicious-domain> --param start=<click_time> --param end=<click_time_plus_1h>
   ```
   Check `DeviceProcessEvents` for suspicious processes spawned by the browser after the click (e.g., PowerShell, cmd.exe, mshta.exe launched from chrome.exe/msedge.exe).

6. **Check for credential compromise.** If the phishing page was a credential harvester:
   - Query `EntraIdSignInEvents` for the user in the hours after the click — look for sign-ins from new IPs or countries.
   - Check `RiskLevelDuringSignIn` for Entra ID Identity Protection flags.
   - Check `CloudAppEvents` for inbox rule creation, mail forwarding, or OAuth app consent post-click.

## Pivots

| From | To | Why |
|---|---|---|
| URL → all clicks | `UrlClickEvents` by `Url` | Who else clicked this URL? |
| URL → source emails | `EmailUrlInfo` by `Url` → `EmailEvents` by `NetworkMessageId` | How was this URL distributed? |
| User → sign-ins post-click | `EntraIdSignInEvents` by `AccountObjectId` | Were credentials stolen? |
| User → device processes | `DeviceProcessEvents` by `DeviceId` + time window | Was malware downloaded after the click? |
| Malicious domain → network connections | `DeviceNetworkEvents` by `RemoteUrl` | Which devices connected to the phishing domain? |

## Common false positives

- **Safe Links re-wrap of legitimate URLs.** Some legitimate URLs are wrapped by Safe Links and flagged due to transient reputation issues. Check whether the URL destination is a well-known service.
- **Security team testing.** Phishing simulation campaigns trigger these alerts. Verify with the analyst whether a phishing test is in progress.
- **Benign redirects through flagged infrastructure.** URL shorteners or ad networks may redirect through IPs with poor reputation. Check the final destination, not just the redirect chain.
- **Automated URL pre-fetch.** Some email clients or security tools pre-fetch URLs, generating click events without user interaction. Check the `IPAddress` (a datacenter/scanner source IP vs. the user's usual network) and whether the click timestamp aligns with user working hours.

## Containment recommendations

If the user clicked through to a phishing site:

1. **If credential phishing — assume compromise.**
   > Suggest to the analyst: reset the user's password immediately, revoke all sessions, and enable MFA if not already required.

2. **Block the URL/domain.**
   > Suggest: add the URL or domain to the Tenant Allow/Block List to prevent further clicks.

3. **Purge the source email.**
   > Suggest: use Explorer to hard-delete the email by `NetworkMessageId` from all recipient mailboxes.

4. **If malware was downloaded:**
   > Suggest: `xdr device isolate <device_id> --comment "<reason>"` — print the command for the analyst. Run `xdr library run qry_file_hash_scope --param sha256=<hash>` to check if the payload reached other devices.

5. **Monitor for post-compromise activity.** Watch `EntraIdSignInEvents` and `CloudAppEvents` for the user over the next 24–48 hours.
