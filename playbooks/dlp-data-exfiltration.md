# Alert Type: Data exfiltration — mass download / unusual external file activity

## Overview

These alerts fire when Defender detects anomalous volume or patterns of file downloads, external sharing, or data movement by a user or application. Covers:

- **Mass download** — high-volume file downloads from SharePoint/OneDrive/cloud apps in a short window
- **Unusual amount of external file activity** — spikes in file sharing to external recipients or personal storage
- **Data theft by departing users** (Purview IRM) — policy-flagged activity by users identified as leaving the organization

The primary concern is **data loss prevention** — whether data is being exfiltrated intentionally (insider threat, compromised account) or inadvertently (user migrating files before departure).

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `CloudAppEvents` | Cloud app file operations (download, share, sync) | `AccountObjectId`, `ActionType`, `Application`, `ObjectName`, `IPAddress`, `CountryCode`, `City` |
| `DeviceFileEvents` | Local file creation from cloud downloads | `DeviceId`, `FileName`, `FolderPath`, `SHA256`, `InitiatingProcessFileName`, `FileOriginUrl` |
| `DeviceNetworkEvents` | Large outbound transfers to external destinations | `DeviceId`, `RemoteIP`, `RemoteUrl`, `RemotePort`, `InitiatingProcessFileName` |
| `EntraIdSignInEvents` | Sign-in context for the user performing downloads | `AccountObjectId`, `IPAddress`, `Country`, `City`, `RiskLevelDuringSignIn` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId`, `FileName` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the user, device, IP, timestamps, and any file names or applications referenced in the evidence.

2. **Quantify the activity.** Query `CloudAppEvents` for the user in the alert time window to assess the volume and type of file operations:
   ```bash
   xdr library run ttp_file_operation_volume --param account_oid=<user-oid> --param start=<start> --param end=<end>
   ```

3. **Identify what was accessed.** Check for sensitive content or unusual file types:
   ```bash
   xdr library run qry_file_access_detail --param account_oid=<user-oid> --param start=<start> --param end=<end>
   ```
   Look for patterns: bulk download of an entire SharePoint site, targeted access to sensitive directories, or downloads of archive files.

4. **Check the source IP and location.** Is the activity coming from the user's normal location and device, or from an unfamiliar IP?
   - Cross-reference with `EntraIdSignInEvents` for the same user and time window.
   - An unfamiliar IP or country suggests account compromise rather than insider threat.

5. **Check for external sharing.** If the alert involves file sharing, determine the recipients:
   ```bash
   xdr library run qry_external_sharing --param account_oid=<user-oid> --param start=<start> --param end=<end>
   ```
   Use `xdr domains list` to determine if sharing targets are internal or external to the tenant.

6. **Check device-side evidence.** If files were downloaded to an endpoint, look for staging or exfiltration behavior:
   ```bash
   xdr library run ttp_suspicious_downloads_exec
   ```
   Also check `DeviceFileEvents` for bulk file creation in download/temp directories, and `DeviceNetworkEvents` for large outbound transfers to cloud storage providers (Dropbox, Google Drive, personal OneDrive).

7. **Assess user context.** For Purview departing-user alerts, verify with the analyst:
   - Is the user confirmed as leaving the organization?
   - Is the download volume consistent with normal handoff activities (e.g., downloading personal files)?
   - Are the files being moved to external storage or shared with external parties?

## Pivots

| From | To | Why |
|---|---|---|
| User → cloud file activity | `CloudAppEvents` by `AccountObjectId` | What files were accessed and in what volume? |
| User → sign-in context | `EntraIdSignInEvents` by `AccountObjectId` | Is the user's session legitimate or compromised? |
| User → device files | `DeviceFileEvents` by `InitiatingProcessAccountObjectId` | Were files staged locally before exfiltration? |
| IP → other user activity | `CloudAppEvents` by `IPAddress` | Did the same IP perform exfiltration from other accounts? |
| File hashes → scope | `qry_file_hash_scope` library query | Were specific sensitive files copied to other devices? |

## Common false positives

- **OneDrive sync initialization.** A user setting up OneDrive sync on a new device triggers mass download of their entire library. Verify the `Application` is OneDrive and the device is newly enrolled.
- **SharePoint migration or backup.** IT-driven migrations or third-party backup tools can trigger mass download alerts. Verify the account is a known service account or the activity is part of a planned project.
- **Departing user downloading personal files.** Users leaving the organization may download personal photos, documents, or notes. The concern is sensitive company data, not personal files — check what was downloaded.
- **Power users with large libraries.** Some roles (legal, finance, engineering) routinely access large file volumes. Check the user's baseline activity level.

## Containment recommendations

If exfiltration is confirmed or strongly suspected:

1. **Block further downloads.**
   > Suggest to the analyst: suspend the user's cloud app sessions via Conditional Access or MCAS session policy. Revoke active tokens in Entra ID.

2. **If account compromise is suspected:**
   > Suggest: reset the user's password and revoke refresh tokens. Check for inbox forwarding rules (`qry_inbox_rule_activity` library query) that may indicate broader compromise.

3. **Preserve evidence.** Before any remediation, document the files accessed, timestamps, IPs, and volumes. This data is needed for DLP incident response and potential legal/HR follow-up.

4. **Assess data sensitivity.** Work with the analyst to determine the classification of exfiltrated files. Purview sensitivity labels (if deployed) may accelerate this.
