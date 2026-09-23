# Alert Type: Ransomware indicators

## Overview

These alerts fire when Defender detects activity consistent with ransomware — either active encryption, pre-ransomware staging, or exploitation of vulnerabilities commonly used in ransomware campaigns. Covers:

- **'CVE' detected including Ransomware on one endpoint** — exploitation followed by ransomware indicators
- **Multi-stage incident including Ransomware on one endpoint** — ransomware as part of a multi-stage attack chain
- **Ransomware-related behavioral detections** — mass file renames, shadow copy deletion, recovery mode tampering

Ransomware alerts are **always high-urgency**. Even if the encryption was blocked, the attacker likely has a foothold and may retry or pivot. Speed of containment directly determines the blast radius.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `DeviceFileEvents` | Mass file renames (encryption activity) | `DeviceId`, `DeviceName`, `ActionType`, `FileName`, `FolderPath`, `SHA256`, `InitiatingProcessFileName` |
| `DeviceEvents` | AV detections, behavioral blocks, shadow copy deletion | `DeviceId`, `ActionType`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `AdditionalFields` |
| `DeviceProcessEvents` | Ransomware process execution, LOLBin abuse | `DeviceId`, `FileName`, `ProcessCommandLine`, `SHA256`, `InitiatingProcessFileName`, `AccountName` |
| `DeviceRegistryEvents` | Persistence and recovery mode tampering | `DeviceId`, `RegistryKey`, `RegistryValueName`, `RegistryValueData` |
| `DeviceNetworkEvents` | C2 communication, lateral movement | `DeviceId`, `RemoteIP`, `RemoteUrl`, `RemotePort`, `InitiatingProcessFileName` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `SHA256`, `DeviceId`, `FileName` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`. **Move fast — ransomware is time-critical.**

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the device, file hashes, process names, user account, and timestamps. Note the MITRE techniques — look for `T1486` (Data Encrypted for Impact).

2. **Determine if encryption is active or was blocked.** Run the ransomware indicators library query:
   ```bash
   xdr library run ttp_ransomware_mass-rename
   ```
   This checks for mass file renames (the hallmark of active encryption). Filter by the device name. The query emits a `mass-rename` signal only once renamed files in a 30-minute window reach the `threshold` (default 50), so any mass-rename hit already indicates >=50 renames — a strong sign encryption is in progress or recently completed. Other query signals, such as shadow-copy deletion or ransom-note creation, can surface without a mass-rename hit. To see the per-extension file count, run with `--param mode=detail` and read the `xN` in each mass-rename row's `Detail` (e.g. `.locked x73`). Note: the summary field `MassRenameCount` counts mass-rename signal bins, not individual files.

3. **Check for shadow copy deletion.** Ransomware typically deletes Volume Shadow Copies before encrypting:
   ```bash
   xdr library run ttp_shadow_copy_deletion --param device_id=<device-id> --param start=<start> --param end=<end>
   ```
   Shadow copy deletion + mass renames = confirmed ransomware execution.

4. **Build the attack chain.** Trace how the ransomware was delivered and executed:
   ```bash
   xdr library run qry_process_tree --param device_name=<device-name> --param hours=4
   ```
   Common chains: phishing → macro → PowerShell → ransomware binary; RDP brute-force → PsExec → ransomware; CVE exploitation → webshell → ransomware.

5. **Identify the ransomware binary.** Get the file hash and check scope:
   ```bash
   xdr library run qry_file_hash_scope --param sha256=<ransomware-hash>
   ```
   If the binary is on multiple devices, the attack is already spreading.

6. **Check for lateral movement.** Ransomware operators often move laterally before deploying the payload:
   ```bash
   xdr library run ttp_lateral_movement_rdp
   ```
   Also check for PsExec, WMI, or SMB-based lateral movement:
   ```bash
   xdr library run ttp_lateral_psexec_wmi --param device_id=<device-id> --param hours=4
   ```

7. **Check the compromised account.** What account was used to run the ransomware?
   ```bash
   xdr library run ttp_malware_execution --param device_id=<device-id> --param sha256=<ransomware-hash> --param start=<start> --param end=<end>
   ```
   If a domain admin account was used, the blast radius is potentially the entire domain.

## Pivots

| From | To | Why |
|---|---|---|
| Ransomware hash → other devices | `qry_file_hash_scope` library query | Is the ransomware on other endpoints? |
| Device → process tree | `qry_process_tree` library query | Full attack chain from initial access to encryption |
| Device → lateral movement | `ttp_lateral_movement_rdp` + SMB/PsExec checks | Did the attacker spread to other devices before encrypting? |
| Compromised account → other sign-ins | `EntraIdSignInEvents` / `IdentityLogonEvents` by account | Where else did this account authenticate? |
| Device → network activity | `DeviceNetworkEvents` by `DeviceId` | C2 infrastructure and exfiltration before encryption |
| Device → new services | `ttp_new_service_creation` library query | Persistence mechanisms installed before ransomware deployment |

## Common false positives

- **Legitimate bulk file operations.** Software deployments, data migrations, or backup tools that rename or move large numbers of files. Check the `InitiatingProcessFileName` — known backup software (Veeam, Commvault) or deployment tools (SCCM, Intune) are likely benign.
- **File conversion utilities.** Tools that batch-convert file formats (e.g., image converters, document processors) can trigger mass-rename detections. Check if the new file extensions are known formats, not random strings.
- **Developer build processes.** Build tools that generate many output files with consistent naming patterns. Check if the device belongs to a developer and the process is a known compiler or build system.

Ransomware false positives are rare and the cost of a missed detection is catastrophic. **Err on the side of containment** — isolate first, investigate second.

## Containment recommendations

**Act immediately — do not wait for full investigation before containment.**

1. **Isolate the affected device(s).**
   > Suggest: `xdr device isolate <device_id> --comment "<reason>"` — for every device where the ransomware hash or process has been confirmed. Network isolation stops encryption of network shares and prevents further lateral movement.

2. **Disable the compromised account.**
   > Suggest: if the ransomware ran under a domain account, disable that account in Active Directory immediately. If a domain admin account was used, treat the entire domain as compromised.

3. **Block the ransomware binary.**
   > Suggest: add the ransomware SHA256 to custom indicators with "Block and remediate" action across the tenant.

4. **Block C2 infrastructure.**
   > Suggest: add any identified C2 IPs/domains to custom indicators and network firewall block lists.

5. **Assess data exfiltration.** Modern ransomware operators exfiltrate data before encrypting (double extortion). Check `DeviceNetworkEvents` for large outbound transfers to cloud storage or unfamiliar IPs in the hours before encryption.

6. **Escalate.** Ransomware incidents warrant immediate escalation to the security operations lead and potentially to incident response retainers or legal counsel.
