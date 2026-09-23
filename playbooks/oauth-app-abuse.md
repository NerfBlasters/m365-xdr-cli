# Alert Type: OAuth app abuse — suspicious apps, credential additions, unknown ISP

## Overview

These alerts fire when Defender detects suspicious activity involving OAuth applications registered in or consenting to the tenant. Covers:

- **Suspicious OAuth app file download activities** — an OAuth app is downloading files at unusual volume
- **Unusual addition of credentials to an OAuth app** — new secrets or certificates were added to an app registration
- **Unusual ISP for an OAuth App** — an app authenticated from an ISP it hasn't used before
- **OAuth application activity from an unknown ISP** — app activity from an unfamiliar network
- **App is similar to previously flagged suspicious apps** — an app matches patterns of known malicious apps
- **App metadata associated with known phishing campaign** — an app's metadata matches phishing campaign indicators
- **Increase in data usage by an overprivileged or highly privileged app** — a high-privilege app suddenly increased its data access
- **Salesforce Connected Application activity from a new IP address** — third-party SaaS app activity anomaly

OAuth abuse is a persistence and data access mechanism. Attackers grant consent to malicious apps (or add credentials to existing apps) to maintain access even after the user's password is reset.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `CloudAppEvents` | OAuth consent events, app activity | `RawEventData.UserId` (reliable actor identity — not `AccountObjectId`/`AccountUpn`), `ActionType`, `Application`, `IPAddress`, `ObjectName`, `RawEventData` |
| `OAuthAppInfo` | App registration details | `OAuthAppId`, `AppName`, `ServicePrincipalId`, `AppOwnerTenantId` |
| `EntraIdSignInEvents` | User sign-ins that triggered consent prompts | `AccountObjectId`, `ApplicationId`, `Application`, `IPAddress`, `ConditionalAccessStatus` |
| `EntraIdSpnSignInEvents` | Service principal sign-ins (app-to-API calls) | `ServicePrincipalId`, `ServicePrincipalName`, `IPAddress`, `ResourceDisplayName` |
| `GraphAPIAuditEvents` | Raw Microsoft Graph API request/response audit (RequestUri, RequestMethod, Scopes) - this codebase tracks credential adds and permission grants via `CloudAppEvents` ActionType instead (see qry_oauth_credentials.kql, qry_oauth_consent.kql) | `ApplicationId`, `AccountObjectId`, `RequestUri`, `IpAddress` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `OAuthApplicationId`, `AccountObjectId` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the app name/ID, the user who consented, the IP, and timestamps. The evidence may include the OAuth app's permissions and the specific suspicious activity.

2. **Identify the app.** Look up the app registration details:
   ```bash
   xdr library run qry_oauth_app_info --param app_id=<app-id>
   ```
   - **`AppOwnerTenantId`** — is this a first-party (Microsoft), your tenant's own app, or a third-party? Third-party apps from unknown tenants are higher risk.
   - Check the app's permissions — what data can it access?

3. **Check who consented and from where.** Query `CloudAppEvents` for consent events:
   ```bash
   xdr library run qry_oauth_consent --param app_id=<app-id> --param start=<start_minus_7d> --param end=<end>
   ```
   - Was the consent from the user's normal IP/location? If not, the consent may have been granted from a compromised session.

4. **Check for credential additions.** If the alert is about credential additions:
   ```bash
   xdr library run qry_oauth_credentials --param app_id=<app-id> --param start=<start> --param end=<end>
   ```
   Credential additions to existing apps give the attacker a way to authenticate as the app without user interaction — this is a persistence mechanism.

5. **Check the app's recent activity.** What has the app been doing?
   ```bash
   xdr library run qry_spn_activity --param spn_id=<service-principal-id> --param start=<start_minus_7d> --param end=<end>
   ```
   - A spike in sign-ins or access to new resources is suspicious.
   - Sign-ins from IPs different from the app's historical pattern suggest compromise.

6. **Check for data access.** If the app has file access permissions:
   ```bash
   xdr library run qry_app_data_access --param app_name=<app-name> --param start=<start> --param end=<end>
   ```

7. **Check the user who consented for compromise.** If a user was tricked into consenting to a malicious app, their account may be compromised:
   - Check `EntraIdSignInEvents` for the user around the consent time.
   - Check for inbox rules and mail forwarding (`qry_inbox_rule_activity` library query).

## Pivots

| From | To | Why |
|---|---|---|
| App ID → consent events | `CloudAppEvents` by app ID/name + consent ActionTypes | Who authorized this app and when? |
| App ID → SPN sign-ins | `EntraIdSpnSignInEvents` by `ServicePrincipalId` | What APIs is the app calling? |
| App ID → credential changes | `CloudAppEvents` by app ID (matched in `RawEventData`) + credential-add `ActionType`s (`Add service principal credentials`, `Update application – Certificates and secrets management`) — see `qry_oauth_credentials` | Were secrets/certs added for persistence? |
| Consenting user → sign-in context | `EntraIdSignInEvents` by `AccountObjectId` | Was the user compromised before consenting? |
| App → file access | `CloudAppEvents` by app name + file ActionTypes | Is the app exfiltrating data? |
| App owner tenant → other apps | `OAuthAppInfo` by `AppOwnerTenantId` | Are other suspicious apps from the same tenant? |
| Tenant → anomalous app sign-ins | `ttp_oauth_app_signin_anomaly` library query | Hunt for SPNs signing in from net-new IPs/countries, token reuse across multiple IPs, or public-client (non-managed-identity) workload sign-ins |
| Tenant → consent anomalies | `ttp_oauth_consent_anomaly` library query | Surface high-risk consent grants (high-risk/overprivileged scopes, recently-registered apps, register-then-consent timing, admin consent, and per-user or per-IP consent bursts) |

## Common false positives

- **Legitimate third-party SaaS apps.** Many business apps (Salesforce connectors, Zoom, DocuSign) require OAuth consent and may trigger alerts when first deployed or when their infrastructure changes. Verify with the analyst whether the app is approved by IT.
- **IT-deployed apps with new credentials.** App credential rotation is a normal operational task. Check if the credential change was made by a known admin from a corporate IP.
- **ISP changes for SaaS backends.** Cloud-hosted apps may change ISPs when their hosting provider updates infrastructure. Check if the app is known and the new ISP is a reputable cloud provider.
- **Development/test apps.** Developer test apps in non-production environments may trigger alerts. Check if the app is in a development tenant or has a test-related name.

## Containment recommendations

If the app is confirmed malicious or unauthorized:

1. **Revoke consent and disable the app.**
   > Suggest to the analyst: remove the OAuth app consent in the Entra ID Enterprise Applications blade. Disable the service principal to prevent further API calls.

2. **Remove added credentials.** If credentials were added to a legitimate app by an attacker, remove the unauthorized secrets/certificates from the app registration.

3. **Revoke tokens for affected users.** If users consented to a malicious app, their sessions may be compromised:
   > Suggest: revoke sessions and reset credentials for all users who granted consent.

4. **Block the app tenant-wide.**
   > Suggest: add the app to the "blocked apps" list in Entra ID to prevent future consent.

5. **Check for data exfiltration.** If the app had file/mail access permissions, assess what data it accessed and for how long. The window between consent and revocation is the exposure window.
