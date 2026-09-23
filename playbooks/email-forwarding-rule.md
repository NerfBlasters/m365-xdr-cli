# Alert Type: Creation of email forwarding/redirect rule

## Overview

This playbook covers alerts related to inbox rule creation or modification, including both forwarding/redirect rules and broader inbox manipulation (deletion rules, move-to-RSS, mark-as-read, etc.). Covers:

- **Creation of forwarding/redirect rule** / **Creation of email forwarding rule** — a user created a rule that forwards or redirects email
- **Suspicious inbox manipulation rule** / **Suspicious Outlook rules** — a rule was created that deletes, moves, or hides email (often used to cover tracks after account takeover)

The primary concern is **data loss prevention** — email forwarded to domains outside the organization's family of companies may exfiltrate sensitive data. Deletion and move rules are often a companion to forwarding rules: the attacker forwards mail externally and creates a second rule to delete bounce-backs or security notifications.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `CloudAppEvents` | Inbox rule creation/modification events | `ActionType`, `RawEventData.UserId`, `RawEventData.Parameters`, `IPAddress`, `CountryCode`, `City` |
| `EntraIdSignInEvents` | Sign-in context around the rule creation | `AccountObjectId`, `IPAddress`, `City`, `Country`, `RiskLevelDuringSignIn` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId` |

**Important:** In `CloudAppEvents`, filter on `RawEventData.UserId` (not `AccountId` or `AccountObjectId`) — those columns are unreliable for Exchange operations. See the "Custom CloudAppEvents query" section below for the full extraction pattern.

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the user, device, IP, and timestamps. The alert evidence often includes the rule name and forwarding destination already.

### Step 2: Establish the user's sign-in baseline

```bash
xdr library run identity_signin_baseline \
  --param account_oid=<oid> --param hours=720 --param mode=detail
```

This returns the user's 30-day sign-in cohort (top IPs, UAs, countries)
plus tenant-egress overlap. Use it to recognise which IPs in step 3 are normal
versus anomalous.

### Step 3: Inspect inbox-rule activity

```bash
xdr library run qry_inbox_rule_activity \
  --param account_upn=<user> --param hours=168 --param mode=detail
```

Single call replaces the legacy `qry_inbox_rule_audit` + `qry_inbox_rule_triggers`
+ `xdr domains list` chain. Output includes:

- Rule changes (create / set / remove / enable / disable across inbox-rules,
  transport-rules, mailbox-level forwarding via `Set-Mailbox`).
- Extracted forwarding destinations classified as internal vs external against
  `_xdr_TenantDomains`.
- BEC-tuned scoring (`Set-Mailbox` mailbox-level forwarding > rule-level
  `ForwardTo` / `RedirectTo`; finance-keyword-triggered MoveTo to hidden
  folder; hidden / zero-width rule names; rule-burst detection).
- `Severity` band: critical/high/medium/low/none.

If `Severity >= high`, escalate to step 4 immediately. If `Severity == medium`,
review the rule predicates against the user's role before deciding.

### Custom CloudAppEvents query (when library query is insufficient)

If `qry_inbox_rule_activity` doesn't cover your scenario, use this pattern:

```kql
let EndTime = now();
let StartTime = EndTime - 168h;
CloudAppEvents
| where RawEventData.UserId =~ "<user-upn>"
| where Timestamp between (StartTime .. EndTime)
| where Application == "Microsoft Exchange Online"
| where ActionType in (
    "New-InboxRule", "Set-InboxRule", "Remove-InboxRule",
    "Enable-InboxRule", "Disable-InboxRule", "UpdateInboxRules",
    "New-TransportRule", "Set-TransportRule", "Remove-TransportRule",
    "Enable-TransportRule", "Disable-TransportRule", "Set-Mailbox"
)
| extend Params = todynamic(RawEventData.Parameters)
| mv-apply p = Params on (
    summarize
        RuleName         = anyif(tostring(p.Value), tostring(p.Name) == "Name"),
        ForwardTo        = anyif(tostring(p.Value), tostring(p.Name) == "ForwardTo"),
        RedirectTo       = anyif(tostring(p.Value), tostring(p.Name) == "RedirectTo"),
        FwdAddress       = anyif(tostring(p.Value), tostring(p.Name) == "ForwardingAddress"),
        FwdSmtp          = anyif(tostring(p.Value), tostring(p.Name) == "ForwardingSmtpAddress"),
        DeliverAndFwd    = anyif(tostring(p.Value), tostring(p.Name) == "DeliverToMailboxAndForward")
)
| extend ForwardingDestination = coalesce(ForwardTo, RedirectTo, FwdSmtp, FwdAddress)
| project Timestamp, Operation = ActionType,
          UserId = tostring(RawEventData.UserId),
          RuleName, ForwardingDestination, DeliverAndFwd,
          CountryCode, City, ClientIP = IPAddress
| order by Timestamp desc
```

Key points:
- **Filter on `RawEventData.UserId`** — `AccountId` and `AccountObjectId` are unreliable for Exchange operations in `CloudAppEvents`.
- **Never project `RawEventData` directly** — it is very large and will timeout. Use `mv-apply` or `extend` to extract specific fields.
- **Cover both inbox rules and transport rules** — attackers may use either for mail exfiltration.
- An internal `ForwardingDestination` (same domain) is usually benign; external destinations warrant investigation.

### Step 4: Check for token theft / session replay

```bash
xdr library run ttp_token_theft_replay \
  --param account_upn=<user> --param hours=72 --param mode=detail
```

Catches session/token reuse from multiple IPs, AiTM-infrastructure hits, and
refresh-token replay (>24h, no MFA). The rewritten query folds in all three
patterns; you no longer need separate calls for AiTM or refresh-replay.

### Step 5 (only if 3-4 indicate compromise): Check exfil channels

```bash
xdr library run qry_mailbox_delegation \
  --param account_upn=<user> --param hours=168 --param mode=detail
```

Catches the parallel exfil channel — `Add-MailboxPermission`,
`Add-RecipientPermission`, `Set-Mailbox -GrantSendOnBehalfTo` — that lets an
attacker read mail without ever creating a rule.

Then confirm sent-email activity. `qry_email_outbound_detail` (EmailEvents-based)
is the primary check — it returns each outbound message's recipient, subject, and
delivery status for the sender:

```bash
xdr library run qry_email_outbound_detail \
  --param sender=<user> --param start=<start> --param end=<end> --param mode=detail
```

For Exchange-audit corroboration (e.g. matching the ClientIP baseline from step 2),
the `CloudAppEvents` fallback below is also available (folding it into
`qry_inbox_rule_activity` would conflate rule-operation events with message-send
events):

```bash
xdr hunt run "
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == 'Microsoft Exchange Online'
| where tostring(RawEventData.UserId) =~ '<user>'
| where ActionType == 'Send'
| extend EventData = parse_json(RawEventData)
| project Timestamp, Operation=tostring(EventData.Operation), Item=tostring(EventData.Item), ClientIP=IPAddress
| order by Timestamp desc
"
```

Exchange audit records do not consistently include recipient or subject fields
in `RawEventData`; retrieve those from email telemetry when available rather
than treating missing raw fields as evidence that no message was sent.

### Containment

(unchanged — analyst runs containment commands, not library queries)

## Pivots

| From | To | Why |
|---|---|---|
| User → sign-ins | `EntraIdSignInEvents` by `AccountObjectId` | Was the account compromised before the rule was created? |
| Forwarding destination domain | All `qry_inbox_rule_activity` results | Are other mailboxes forwarding to the same external domain? |
| Source IP | `EntraIdSignInEvents` + `CloudAppEvents` by `IPAddress` | What else did this IP do in the tenant? |
| User → other rule changes | `qry_inbox_rule_activity` filtered by `UserId` | Did the actor also create deletion/move rules to cover tracks? |

## Common false positives

- **User self-service:** User sets up forwarding to a personal account or to a colleague during PTO. Confirm with the user or their manager.
- **IT-administered transport rules:** Org-level rules created by Exchange admins. Verify the `UserId` is a known admin account.
- **Shared mailbox delegation:** Rules on shared/service mailboxes modified by authorized delegates.

For all false positives, the key question is: **does the forwarding destination belong to the organization's family of companies?** Internal forwarding is generally benign. External forwarding — even by the legitimate user — may still violate DLP policy.

## Containment recommendations

If the forwarding is confirmed malicious or unauthorized:

1. **Remove the rule immediately.**
   > Suggest to the analyst: disable or remove the inbox rule via Exchange admin center or PowerShell.

2. **If account compromise is suspected:**
   > Suggest: `xdr device isolate <device_id> --comment "<reason>"` (if the user's device is compromised)
   > Suggest: revoke sessions and reset credentials via Entra ID.

3. **Assess data exposure:** Determine how long the forwarding rule was active and what emails were forwarded. The rule's `Timestamp` in `CloudAppEvents` gives the creation time; if a `Remove-InboxRule` event exists, that bounds the window.
