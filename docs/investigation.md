# Investigation Methodology

This file defines investigation methodology and KQL authoring rules for AI agents using `xdr-cli`.

## Role

You work alongside a security analyst, helping them triage alerts, investigate incidents, hunt for threats, and document findings. You use `xdr-cli` as your instrument; the analyst makes final decisions.

## Keep the analyst informed

Investigations involve multiple queries and pivots. The analyst cannot see your reasoning unless you narrate it. **Provide brief status updates as you work:**

- State what you're looking for and why before running a query.
- When results come back, summarize what you found (or didn't) before moving to the next step.
- When you change direction — e.g., pivoting from a device to a user, or widening a time window — say so and explain why.
- If a query returns nothing, say what that rules out before trying the next approach.

Example narration flow:
> "Searching for alerts matching this device… Found one: 'Rimecud' malware prevented at 20:58 UTC. Pulling alert evidence to get file hashes, user context, and device details before hunting further."

Do not narrate every CLI flag or JSON field — keep updates at the **investigation-level**, not the tool-level.

### Investigation progress tracking

For multi-step investigations, render a markdown checklist to give the analyst visibility into what's done and what remains. Create the checklist after step 1 (establish the alert/incident), once the scope is clear.

**When to use a checklist:**
- Playbook-driven investigations — derive items from the playbook's numbered steps.
- Manual triage-ladder investigations with 3+ phases — derive items from the methodology steps below.
- Multi-entity hunts (multiple devices, users, or hashes to work through).
- Do **not** create a checklist for single-command lookups, `xdr investigate` (which sequences its own steps), or quick KQL one-offs.

**Dynamic expansion:** When a step surfaces multiple targets (e.g., blast-radius check reveals 4 devices with the same hash), expand that single item into per-entity items before proceeding. This prevents marking a multi-entity step complete after processing only the first entity.

**Skipping steps:** The checklist is a communication aid, not a rigid gate. If evidence from an earlier step makes a subsequent step unnecessary, mark it complete with a brief explanation — e.g., `- [x] Blast radius — N/A, hash found on 0 other devices`. Do not remove skipped steps; the analyst needs to see what was considered and dismissed.

**Cadence:** Re-render the checklist after each major phase completes, not after every individual query within a phase.

## Investigation methodology

Follow a **triage-ladder** pattern. Each step informs the next; don't skip ahead.

0. **Let the CLI attach telemetry.** `hunt run`, `library run`, `investigate`,
   and alert/incident `show` automatically create an optional 30-minute
   session when none exists. Other commands may attach to one existing session
   but do not create one. Session ambiguity never blocks evidence collection.
   Use manual `session start` only for deliberate labels, learning mode, or
   concurrent work. If you end a session, follow its `next_action` with a
   truthful agent assessment.
1. **Establish the alert/incident.** Start from whatever the analyst gives you — an incident ID, an alert, a device name, a user, or a hash. Pivot to the incident or alert to anchor the timeline.
   - **Check for a playbook.** Once you know the alert title, read `playbooks/index.md` and match against the alert title column. If a playbook is listed, read it now — it provides alert-specific steps, tables, pivots, and false-positive guidance that tailor the remaining steps below.
> **Shortcut:** `xdr investigate <incident_id>` wraps steps 2–5 into one command — it extracts entities from alerts, runs relevant library queries, and saves a normalized triage-ladder JSONL artifact. Parse the receipt's `data_path`; stdout contains only the receipt and up to two previews. Containment recommendations in the artifact only appear when severity is high AND classification is not false-positive/informational. Use this when you want automated triage; use the manual steps below when you need finer control.

2. **Extract evidence from alerts.** Use `--expand alerts` to pull file hashes, device IDs, user accounts, IPs, verdicts, and timestamps. This often answers key questions without additional hunting.
3. **Build the timeline.** Query for activity in a tight window around the alert's `firstActivityDateTime`. Include the right tables for the event type (e.g., `DeviceEvents` for AV detections, `EmailEvents` for mail, `DeviceLogonEvents` for logons).
4. **Assess blast radius.** Did the threat spread? For malware: other devices with the same hash. For phishing: other recipients, URL clicks, credential harvesting. For identity: sign-in anomalies, lateral movement.
5. **Determine impact.** Was the threat blocked or did it execute? Was data exfiltrated? Were credentials compromised? Distinguish prevented from delivered/executed explicitly — this is the most important determination for the analyst.
6. **Present findings.** Deliver a structured summary: timeline table, blast radius, impact assessment. State the evidence clearly so the analyst can make the call.

## Writing effective hunts

When no library query fits, write scoped KQL. Unscoped queries produce unreadable wide tables, exhaust the 10-min-per-hour CPU quota, and return noise instead of signal.

**Advanced hunting retains 30 days of data.** If an event predates the retention window, no query will find it. State this to the analyst rather than broadening queries past 30 days.

**AV/EDR detection events** appear in `DeviceEvents` (ActionType: `OtherAlertRelatedActivity`, `AntivirusDetection`, etc.), **not** in `DeviceFileEvents`. For file creation/modification/rename telemetry, use `DeviceFileEvents`. For detection and alert-correlated activity, use `DeviceEvents`.

Every custom query should:

1. **Bound by time, anchored to the incident — not to "now".** Start narrow: minutes before and after the event, using the alert's `firstActivityDateTime` / `lastActivityDateTime`. Widen to hours or days only when context demonstrably requires it. `ago(x)` scopes to when you're investigating, not when the event happened — usually wrong.
   ```kql
   | where Timestamp between(datetime(2026-04-17T08:45:00Z) .. datetime(2026-04-17T09:10:00Z))
   ```
2. **Pivot on the right entity.** Column names differ across tables
   (`AccountObjectId`, `AccountUpn`, `DeviceId`,
   `InitiatingProcessAccountObjectId`, etc.). Use `xdr schema pivot
   <Table.Column>` or `xdr schema path <SourceTable> <TargetTable>` for reviewed
   semantic routes. Use `docs/schema_pivots.md` only for physical field
   availability; a shared name is not a join contract.
3. **Cap results.** `| take 50` for exploratory; `| top 50 by Timestamp desc` for most-recent-first.
4. **Control output width — but don't discard blindly.** Use `| project` when
   you know which columns matter. For exploratory queries, inspect the two
   preview rows or run `xdr results shape <run-id>`, then use `rg` or `jq -s`
   over the saved JSONL without rerunning. The CLI no longer has projection
   flags.

### KQL pitfalls

**`in` and `!in` must use the column's actual type:** KQL rejects a
membership comparison when the right-hand values do not match the left-hand
column type. For example, `RiskLevelDuringSignIn` is an integer in this
tenant, so comparing it with string values such as `"none"` or `""` fails.
Check the column with `getschema` before filtering it; use matching numeric
values for integer enums, or explicitly convert the column with `tostring()`
when a string comparison is intentional.

**CloudAppEvents:** Never project `RawEventData` directly — it is very large and will timeout. Resolve the acting user from `RawEventData.UserId` (not `AccountId` / `AccountObjectId` / `AccountUpn`) — `CloudAppEvents` has no `AccountUpn` column. This applies to all `CloudAppEvents` queries: Exchange operations, OAuth consent/credentials, Entra role changes. See the `email-forwarding-rule` playbook for the full extraction pattern.

### When a query returns no results

1. Verify the correct table for the event type (see `docs/schema_pivots.md` and the AV detection note above).
2. Check column names — they vary across tables (e.g., `DeviceId` vs `MachineId`).
3. Widen the time window incrementally: minutes → hours → days.
4. If still empty at 30 days, the event predates retention — tell the analyst.
5. Check if the answer is already in alert evidence from `--expand alerts`.

### Methodology toolkit — optional flags

These are tools, not requirements; reach for them when the situation warrants:

- **`xdr --rationale "<prediction>" hunt run ...`** — record the hypothesis you're testing before the result lands. Useful for hypothesis-driven queries where the *prediction* is itself signal worth keeping. The rationale appears in the session JSONL on that invocation's record. The flag is accepted on every command for surface uniformity, and is recorded onto the invocation record of any command run while a session is active — `history` and `session list` included. The rationale is only omitted when no session is active, in which case no invocation record is written for any command; this is a session-presence effect, not a property of specific session/history paths.
- **`xdr session start --learning-mode`** — require an `xdr annotate` after every non-housekeeping command (commands in the bypass set — `annotate`, `session`, `history` — don't trigger the gate). Use when the investigation is also a teaching exercise (building a new playbook, refining a query pattern, capturing what worked and what didn't). Use `--skip "<reason>"` when output wasn't useful (`xdr annotate --skip "hit 400, no useful output"`). Skips are signal too; don't fake annotations.

Default investigations don't need either. Reach for them when you're capturing a methodology, not just executing one.

## Presenting results

- **Timestamps:** Show full precision from the source (e.g., `20:57:39.937` not `20:57`). Convert to the analyst's local timezone when relevant, and always note the timezone.
- **Blocked vs. executed:** Always make the distinction explicit. "Prevented" and "delivered" are not the same. A blocked threat with no execution is fundamentally different from a delivered payload.
- **Tables and timelines:** Use markdown tables for structured data. Chronological timelines are the primary format for investigation narratives.
- **Entity cross-references:** When you discover entities (users, devices, IPs, hashes), note them explicitly — the analyst may need them for follow-up in other tools.
- **Negative findings matter.** "No URL clicks were recorded" or "No sign-in anomalies found" are actionable conclusions, not filler. State what you checked and what the absence means.

## Decision boundaries

- **You recommend; the analyst decides.** Present containment options with the exact command and a one-sentence impact statement — containment actions are always analyst-executed.
- **Severity calibration:** Informational/blocked threats get a summary. Medium threats get a full timeline and blast-radius check. High/critical threats get everything plus explicit containment recommendations.
- **When to escalate:** If you find evidence of successful execution, lateral movement, data exfiltration, or credential compromise — say so prominently. These change the urgency of the response.
- **When to close:** If the threat was fully prevented, no blast radius exists, and no related suspicious activity is found — say that clearly so the analyst can close with confidence.
