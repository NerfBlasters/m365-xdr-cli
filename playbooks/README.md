# Alert-Type Investigation Playbooks

This folder contains per-alert-type playbooks that guide the LLM through investigating specific categories of alerts. Each file is a kebab-cased markdown file named after the alert type it covers.

## How playbooks are used

When an investigation begins, the agent reads `index.md` in this folder and matches the alert title(s) against the mapping table. Multiple alert titles can point to the same playbook. If a match is found, the agent **must read the linked playbook before proceeding** with the investigation. The playbook supplements — not replaces — the general methodology in `docs/investigation.md`.

## Creating a new playbook

1. Name the file using kebab-case with a group prefix based on the **investigation workflow** (e.g., `endpoint-malware-generic.md`, `identity-impossible-travel.md`, `email-malicious-delivery.md`, `dlp-data-exfiltration.md`). The prefix groups playbooks by the tables, pivots, and techniques used during investigation — not by business concern. One playbook can cover multiple alert titles.
2. Add all matching alert titles to the mapping table in `index.md`, pointing to the new file.
3. Follow this structure:

```markdown
# Alert Type: <Alert Title or Category>

## Overview
Brief description of what this alert type means and common causes (true positive vs. false positive).

## Key tables and columns
Which XDR tables to query, and which columns matter most. Reference `docs/schema_pivots.md` for authoritative names.

## Investigation steps
Ordered steps specific to this alert type, building on the triage-ladder from `docs/investigation.md`.

## Pivots
What to pivot on after initial findings (e.g., hash → other devices, user → sign-in anomalies).

## Common false positives
Known benign scenarios and how to confirm them.

## Containment recommendations
What containment actions to suggest to the analyst if the threat is confirmed.
```

4. Keep playbooks concise — they are loaded into LLM context during investigations.
