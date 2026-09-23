# Playbook Index

Map alert titles to playbook files. Multiple alerts can share the same playbook. The agent reads this index first to find the right playbook for the current investigation.

## How to use this index

1. Match the alert title (from `xdr incidents show <id> --expand alerts`) against the **Alert title** column.
2. If a match is found, read the linked playbook file before continuing the investigation.
3. If no match is found, fall back to the general methodology in `docs/investigation.md`.

Matching is **substring / fuzzy** — e.g., an alert titled `'Rimecud' malware was prevented` matches the `Rimecud` row.

## Alert → Playbook mapping

| Alert title (or keyword) | Playbook | Notes |
|---|---|---|
| `Creation of forwarding/redirect rule` | [email-forwarding-rule.md](email-forwarding-rule.md) | Inbox rule forwarding — DLP focus |
| `Creation of email forwarding rule` | [email-forwarding-rule.md](email-forwarding-rule.md) | |
| `Suspicious inbox manipulation rule` | [email-forwarding-rule.md](email-forwarding-rule.md) | Inbox manipulation — deletion/move rules to cover tracks |
| `Suspicious Outlook rules` | [email-forwarding-rule.md](email-forwarding-rule.md) | |
| `Rimecud` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | USB-propagating worms (Rimecud, Gamarue, Jenxcus) |
| `Gamarue` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Jenxcus` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Hamweq` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Autorun` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Impossible travel activity` | [identity-impossible-travel.md](identity-impossible-travel.md) | Identity anomaly — sign-in from geographically distant locations |
| `Atypical travel` | [identity-impossible-travel.md](identity-impossible-travel.md) | |
| `Mass download` | [dlp-data-exfiltration.md](dlp-data-exfiltration.md) | Bulk file downloads, external sharing, departing-user data theft |
| `Unusual amount of external file activity` | [dlp-data-exfiltration.md](dlp-data-exfiltration.md) | |
| `Data theft by departing users` | [dlp-data-exfiltration.md](dlp-data-exfiltration.md) | Purview IRM policy |
| `Email messages containing malicious file removed after delivery` | [email-malicious-delivery.md](email-malicious-delivery.md) | ZAP removals and failed removals |
| `Email messages containing malicious URL removed after delivery` | [email-malicious-delivery.md](email-malicious-delivery.md) | |
| `Email messages from a campaign removed after delivery` | [email-malicious-delivery.md](email-malicious-delivery.md) | |
| `Email messages removed after delivery` | [email-malicious-delivery.md](email-malicious-delivery.md) | |
| `Messages containing malicious entity not removed after delivery` | [email-malicious-delivery.md](email-malicious-delivery.md) | Threat identified but ZAP failed |
| `potentially malicious URL click` | [email-malicious-url-click.md](email-malicious-url-click.md) | URL clicks, phishing site access, HTML phishing |
| `Device tried to access a phishing site` | [email-malicious-url-click.md](email-malicious-url-click.md) | |
| `HTML attachment phishing attempt` | [email-malicious-url-click.md](email-malicious-url-click.md) | |
| `Phishing document` | [email-malicious-url-click.md](email-malicious-url-click.md) | |
| `User accessed a link in an email subsequently quarantined by ZAP` | [email-malicious-url-click.md](email-malicious-url-click.md) | |
| `Suspicious email sending patterns` | [email-suspicious-sending.md](email-suspicious-sending.md) | Suspicious outbound email, account used for spam |
| `User restricted from sending email` | [email-suspicious-sending.md](email-suspicious-sending.md) | |
| `Command and Control behavior` | [endpoint-command-and-control.md](endpoint-command-and-control.md) | C2 beaconing, suspicious network connections |
| `Connection to a custom network indicator` | [endpoint-command-and-control.md](endpoint-command-and-control.md) | |
| `Suspicious connection blocked by network protection` | [endpoint-command-and-control.md](endpoint-command-and-control.md) | |
| `Horizontal port scan` | [endpoint-command-and-control.md](endpoint-command-and-control.md) | |
| `malware was detected` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | Generic AV/EDR detections (no family-specific playbook) |
| `malware was prevented` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `detected on one endpoint` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Malware incident` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Malware detection` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Multiple threat families` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Suspicious files incident` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Unwanted software incident` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `Endpoint attack notifications` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | Drive-by download, infostealer campaigns |
| `hacktool was detected` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `unwanted software was detected` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `unwanted software was prevented` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | |
| `behavior was blocked` | [endpoint-malware-generic.md](endpoint-malware-generic.md) | AMSI/behavioral blocks (ClickFix, PShellCobStager, etc.) |
| `Ransomware` | [endpoint-ransomware.md](endpoint-ransomware.md) | Ransomware indicators, CVE exploitation with ransomware |
| `adversary-in-the-middle` | [identity-aitm-phishing.md](identity-aitm-phishing.md) | AiTM phishing proxy — session token theft |
| `AiTM` | [identity-aitm-phishing.md](identity-aitm-phishing.md) | |
| `Anomalous Token` | [identity-anomalous-token.md](identity-anomalous-token.md) | Token theft / replay indicators |
| `Potential user account compromise` | [identity-anomalous-token.md](identity-anomalous-token.md) | |
| `Password Spray` | [identity-password-spray.md](identity-password-spray.md) | Password spray attacks |
| `Activity from a password-spray associated IP` | [identity-password-spray.md](identity-password-spray.md) | |
| `Activity from a TOR IP address` | [identity-risky-sign-in.md](identity-risky-sign-in.md) | TOR, proxy, unfamiliar properties, malicious IP |
| `Activity from an anonymous proxy` | [identity-risky-sign-in.md](identity-risky-sign-in.md) | |
| `Anonymous IP address` | [identity-risky-sign-in.md](identity-risky-sign-in.md) | |
| `Unfamiliar sign-in properties` | [identity-risky-sign-in.md](identity-risky-sign-in.md) | |
| `Malicious IP address` | [identity-risky-sign-in.md](identity-risky-sign-in.md) | |
| `Suspicious impersonated activity` | [identity-risky-sign-in.md](identity-risky-sign-in.md) | |
| `Suspected brute-force attack` | [mdi-identity-attack.md](mdi-identity-attack.md) | MDI: Kerberos/NTLM brute-force, Golden Ticket, pass-the-ticket, LDAP/SAMR recon |
| `Suspected Golden Ticket` | [mdi-identity-attack.md](mdi-identity-attack.md) | |
| `Suspected identity theft (pass-the-ticket)` | [mdi-identity-attack.md](mdi-identity-attack.md) | |
| `Security principal reconnaissance (LDAP)` | [mdi-identity-attack.md](mdi-identity-attack.md) | |
| `User and group membership reconnaissance (SAMR)` | [mdi-identity-attack.md](mdi-identity-attack.md) | |
| `Suspicious OAuth app` | [oauth-app-abuse.md](oauth-app-abuse.md) | OAuth app abuse, credential additions, unknown ISP |
| `Unusual addition of credentials to an OAuth app` | [oauth-app-abuse.md](oauth-app-abuse.md) | |
| `Unusual ISP for an OAuth App` | [oauth-app-abuse.md](oauth-app-abuse.md) | |
| `OAuth application activity from an unknown ISP` | [oauth-app-abuse.md](oauth-app-abuse.md) | |
| `App is similar to previously flagged suspicious apps` | [oauth-app-abuse.md](oauth-app-abuse.md) | |
| `App metadata associated with known phishing campaign` | [oauth-app-abuse.md](oauth-app-abuse.md) | |
| `Increase in data usage by an overprivileged` | [oauth-app-abuse.md](oauth-app-abuse.md) | |
| `Salesforce Connected Application activity` | [oauth-app-abuse.md](oauth-app-abuse.md) | |
| `Addition to Exchange Organization Management` | [privilege-escalation.md](privilege-escalation.md) | Privilege escalation — role/group changes, suspicious admin activity |
| `Suspicious additions to sensitive groups` | [privilege-escalation.md](privilege-escalation.md) | |
| `Suspicious addition and removal of elevated privileges` | [privilege-escalation.md](privilege-escalation.md) | |
| `Suspicious administrative activity` | [privilege-escalation.md](privilege-escalation.md) | |
| `Administrative action submitted by an Administrator` | [privilege-escalation.md](privilege-escalation.md) | |
