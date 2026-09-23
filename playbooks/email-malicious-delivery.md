# Alert Type: Malicious email delivery — ZAP removals and failed removals

## Overview

These alerts fire when Defender for Office 365 detects malicious content in email messages — either successfully removed after delivery (ZAP) or identified but not removed. Covers:

- **Email messages containing malicious file removed after delivery** — ZAP removed an attachment-based threat
- **Email messages containing malicious URL removed after delivery** — ZAP removed a URL-based threat
- **Email messages from a campaign removed after delivery** — ZAP removed messages linked to a known attack campaign
- **Email messages removed after delivery** — generic ZAP removal
- **Messages containing malicious entity not removed after delivery** — threat identified but ZAP failed or was not triggered

The critical distinction is **removed vs. not removed**. Successful ZAP means the threat was neutralized in the mailbox; failed removal means the user may still have access to the malicious content.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `EmailEvents` | Email delivery and post-delivery status | `NetworkMessageId`, `RecipientEmailAddress`, `SenderFromAddress`, `Subject`, `DeliveryAction`, `DeliveryLocation`, `LatestDeliveryAction`, `LatestDeliveryLocation`, `EmailDirection`, `ConfidenceLevel` |
| `EmailAttachmentInfo` | Attachment details (file name, hash, type) | `NetworkMessageId`, `FileName`, `FileSize`, `SHA256`, `RecipientEmailAddress` |
| `EmailUrlInfo` | URLs embedded in the email | `NetworkMessageId`, `Url`, `UrlDomain` |
| `EmailPostDeliveryEvents` | Post-delivery actions (ZAP, admin removal) | `NetworkMessageId`, `RecipientEmailAddress`, `DeliveryLocation`, `ActionType` |
| `UrlClickEvents` | User clicks on URLs in email | `NetworkMessageId`, `Url`, `AccountUpn`, `ActionType`, `IsClickedThrough` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `NetworkMessageId`, `SHA256` |

**Join spine:** `NetworkMessageId` links all email tables. Start from `EmailEvents`, join to attachments, URLs, post-delivery, and clicks.

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract `NetworkMessageId`, recipient(s), sender, subject, file hashes, URLs, and the delivery verdict. The evidence often contains the full threat assessment.

2. **Determine delivery status.** This is the most important question — was the threat delivered to the inbox, or was it caught?
   ```bash
   xdr library run qry_email_delivery --param network_message_id=<network-message-id>
   ```
   - `LatestDeliveryAction` containing `Zap` (e.g. `Zapped`) = ZAP succeeded — this matches how `qry_email_blast_radius` counts ZAP success (`countif(LatestDeliveryAction has 'Zap')`).
   - `LatestDeliveryLocation` of `Inbox` or `Mailbox` = user may have accessed the threat.

3. **Assess blast radius.** Did other users receive the same email?
   ```bash
   xdr library run qry_email_blast_radius --param sender=<sender> --param subject=<subject> --param start=<start> --param end=<end>
   ```
   If multiple recipients, check whether ZAP succeeded for all of them.

4. **Examine the malicious content.** For attachment-based threats:
   ```bash
   xdr library run qry_email_attachments --param network_message_id=<network-message-id>
   ```
   For URL-based threats:
   ```bash
   xdr library run qry_email_urls --param network_message_id=<network-message-id>
   ```

5. **Check for user interaction.** Did any recipient click a malicious URL or open the attachment?
   ```bash
   xdr library run qry_url_clicks --param account_upn=<recipient-upn> --param start=<start> --param end=<end>
   ```
   `IsClickedThrough` = `true` means the user bypassed the warning page — this significantly increases risk.

6. **Scope the threat artifact.** If you have a file hash, check if it landed on any endpoint:
   ```bash
   xdr library run qry_file_hash_scope --param sha256=<hash>
   ```
   For URLs, check `DeviceNetworkEvents` or `DeviceEvents` for connections to the malicious domain.

7. **Check for post-compromise activity.** If a user clicked through or the attachment was opened:
   - Check `DeviceProcessEvents` for suspicious process execution after the email delivery time.
   - Check `EntraIdSignInEvents` for anomalous sign-ins if the threat was credential phishing.
   - Check `CloudAppEvents` for inbox rule creation that might indicate account takeover.

## Pivots

| From | To | Why |
|---|---|---|
| `NetworkMessageId` → email details | `EmailEvents` + `EmailAttachmentInfo` + `EmailUrlInfo` | Full picture of what was delivered |
| Sender → other messages | `EmailEvents` by `SenderFromAddress` | Was this part of a broader campaign? |
| File hash → endpoints | `qry_file_hash_scope` library query | Did the attachment land on any device? |
| URL domain → clicks | `UrlClickEvents` by `Url` | Did anyone click through to the malicious site? |
| Recipient → post-delivery | `EmailPostDeliveryEvents` by `NetworkMessageId` | Was ZAP successful? |
| Recipient → sign-ins | `EntraIdSignInEvents` by `AccountObjectId` | Post-click credential compromise? |

## Common false positives

- **EICAR test files.** Security teams testing email filtering with EICAR test strings. Verify the sender is an internal security team member and the subject references a test.
- **Marketing/newsletter emails with flagged URLs.** Legitimate bulk email with tracking URLs that trigger URL reputation alerts. Check the sender domain and the URL destination.
- **Repackaged legitimate software.** Attachments flagged as PUA (potentially unwanted application) rather than malware. Check the specific threat name — PUA is lower risk than trojans or exploits.
- **Auto-forwarded external mail.** Mail forwarded from an external source that carries a flagged attachment. The threat may already have been neutralized at the external org.

## Containment recommendations

If the threat was delivered and user interaction is confirmed or suspected:

1. **Purge the message from all mailboxes.**
   > Suggest to the analyst: use Explorer in the Security portal to hard-delete the message by `NetworkMessageId` from all recipient mailboxes.

2. **If URL was clicked through:**
   > Suggest: check the user's device for compromise indicators. Consider `xdr device isolate <device_id> --comment "<reason>"` if process execution was observed post-click.

3. **If credential phishing:**
   > Suggest: reset the user's password, revoke sessions, and monitor `EntraIdSignInEvents` for the next 24–48 hours.

4. **Block the sender/domain.**
   > Suggest: add the sender domain or specific sender to the Tenant Allow/Block List if the campaign is ongoing.
