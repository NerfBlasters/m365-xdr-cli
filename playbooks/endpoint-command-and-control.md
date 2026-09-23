# Alert Type: Command and control behavior / suspicious network connections

## Overview

These alerts fire when Defender detects network activity consistent with command-and-control (C2) communication or connections to known-malicious infrastructure. Covers:

- **Command and Control behavior was detected** — behavioral detection of C2 patterns (beaconing, encoded traffic, tunneling)
- **Connection to a custom network indicator** — device connected to an IP/URL/domain on a custom indicator list
- **Suspicious connection blocked by network protection** — network protection prevented a connection to a malicious destination
- **Horizontal port scan initiated** — a device is scanning other hosts on the network

C2 detection is high-signal — if the behavior is real, it means an attacker has an active foothold and is communicating with their infrastructure. However, false positives from legitimate software with beacon-like patterns are common.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `DeviceNetworkEvents` | Outbound network connections from the device | `DeviceId`, `DeviceName`, `RemoteIP`, `RemoteUrl`, `RemotePort`, `LocalPort`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `Timestamp` |
| `DeviceEvents` | Network protection blocks, SmartScreen events | `DeviceId`, `ActionType`, `RemoteUrl`, `RemoteIP`, `InitiatingProcessFileName` |
| `DeviceProcessEvents` | Process that initiated the C2 connection | `DeviceId`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `SHA256`, `AccountName` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `RemoteIP`, `RemoteUrl`, `DeviceId`, `FileName` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the device, remote IP/URL/domain, process name, file hash, and timestamps. The evidence usually identifies the process responsible for the network activity.

2. **Identify the initiating process.** Determine what program is making the suspicious connections:
   ```bash
   xdr library run qry_device_connections --param device_id=<device-id> --param remote=<suspicious-ip-or-domain> --param start=<start> --param end=<end>
   ```
   - A known LOLBin (powershell.exe, rundll32.exe, mshta.exe) connecting to an external IP is high-risk.
   - A legitimate application (browser, Teams, OneDrive) connecting to a flagged IP is more likely a false positive.

3. **Check for beaconing patterns.** Use the library query to detect periodic DNS or network callbacks:
   ```bash
   xdr library run ttp_dns_beaconing
   ```
   Also check for DNS tunneling via high subdomain diversity:
   ```bash
   xdr library run dns_subdomain_diversity
   ```
   Both queries exclude tenant-owned domains via `_xdr_TenantDomains` — corp-internal DNS traffic is filtered automatically. Filter results by the device in question.

4. **Build the process tree.** Understand how the C2 process was launched:
   ```bash
   xdr library run qry_process_tree --param device_name=<device-name> --param hours=2
   ```
   Look for: download → execute chains, script interpreters launching network-capable processes, or living-off-the-land binaries chained together.

5. **Check for encoded commands.** If PowerShell is involved:
   ```bash
   xdr library run ttp_encoded_powershell
   ```
   Base64-encoded PowerShell with network activity is a strong C2 indicator.

6. **Assess lateral movement.** Did the compromised device reach out to other internal hosts?
   ```bash
   xdr library run ttp_lateral_movement_rdp
   ```
   Also check `DeviceNetworkEvents` for connections to internal IP ranges on non-standard ports:
   ```bash
   xdr library run ttp_internal_lateral_connections --param device_id=<device-id> --param start=<start> --param end=<end>
   ```

7. **Scope the C2 infrastructure.** Check if other devices are connecting to the same remote IP/domain:
   ```bash
   xdr library run qry_connection_scope --param remote=<suspicious-ip-or-domain> --param start=<start_minus_24h> --param end=<end>
   ```

## Pivots

| From | To | Why |
|---|---|---|
| Remote IP/URL → other devices | `DeviceNetworkEvents` by `RemoteIP` or `RemoteUrl` | Is this C2 talking to other compromised devices? |
| Process → process tree | `qry_process_tree` library query | How was the C2 process launched? |
| Process hash → scope | `qry_file_hash_scope` library query | Is the C2 binary on other devices? |
| Device → DNS patterns | `ttp_dns_beaconing` library query | Periodic callbacks confirming C2 |
| Device → lateral movement | `ttp_lateral_movement_rdp` + `DeviceNetworkEvents` private IPs | Has the attacker moved laterally? |
| Device → new services | `ttp_new_service_creation` library query | Did the attacker install persistent services? |

## Common false positives

- **Legitimate software with beacon-like behavior.** Update checkers, telemetry agents, and monitoring tools often make periodic HTTP requests that resemble C2 beaconing. Check the process name and publisher — signed software from known vendors is usually benign.
- **VPN or proxy software.** VPN clients maintain persistent connections to external IPs that may trigger behavioral C2 detection. Verify the process is a known VPN client.
- **Custom network indicators with broad scope.** If an IP was added to a custom indicator list based on threat intel, verify the indicator is still relevant and not a shared hosting IP that also serves legitimate content.
- **CDN or cloud service IPs.** Some C2 frameworks use cloud services (Azure, AWS, Cloudflare) as fronting. The IP may host both malicious and legitimate content — investigate the specific URL path, not just the IP.

## Containment recommendations

If C2 activity is confirmed:

1. **Isolate the device immediately.**
   > Suggest: `xdr device isolate <device_id> --comment "<reason, e.g. C2 containment>"` — print the command for the analyst. Network isolation cuts C2 communication while preserving forensic evidence.

2. **Block the C2 infrastructure.**
   > Suggest: add the C2 IP/domain to custom indicators with "Block and remediate" action. Also block at the network firewall/proxy level.

3. **Investigate the full attack chain.** Use `qry_process_tree` to trace back to initial access — was it a phishing email, drive-by download, or exploitation? This determines whether other devices may be compromised through the same vector.

4. **Check for persistence.** Before remediation, check `DeviceRegistryEvents` for new services, scheduled tasks, or run keys created by the attacker:
   ```bash
   xdr library run ttp_new_service_creation
   ```

5. **Collect investigation package.**
   > Suggest: `xdr device collect-package <device_id>` — for full forensic analysis if the incident is high-severity.
