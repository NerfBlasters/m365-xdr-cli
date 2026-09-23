# Alert Type: MDI identity attacks — Golden Ticket, pass-the-ticket, brute-force, reconnaissance

## Overview

These alerts come from Microsoft Defender for Identity (MDI), which monitors on-premises Active Directory traffic. Covers:

- **Suspected Golden Ticket usage (encryption downgrade)** — a Kerberos ticket was forged using the KRBTGT hash
- **Suspected identity theft (pass-the-ticket)** — a Kerberos ticket was stolen from one machine and replayed on another
- **Suspected brute-force attack (Kerberos, NTLM)** — high-volume authentication failures against one or more accounts
- **Security principal reconnaissance (LDAP)** — enumeration of users, groups, or computers via LDAP queries
- **User and group membership reconnaissance (SAMR)** — enumeration via SAMR protocol

MDI alerts are **on-premises focused** and indicate that an attacker may already have a foothold in the Active Directory environment. These are typically more advanced than cloud-only identity attacks.

## Key tables and columns

| Table | Use | Key columns |
|---|---|---|
| `IdentityLogonEvents` | On-prem authentication events (Kerberos, NTLM) | `AccountObjectId`, `AccountUpn`, `IPAddress`, `DeviceName`, `DestinationDeviceName`, `LogonType`, `Protocol`, `FailureReason`, `Application` |
| `IdentityDirectoryEvents` | Directory changes and queries (LDAP, SAMR) | `AccountObjectId`, `AccountUpn`, `ActionType`, `TargetAccountUpn`, `TargetDeviceName`, `DestinationDeviceName`, `DestinationIPAddress`, `Protocol`, `Application` |
| `IdentityQueryEvents` | AD query activity (reconnaissance) | `AccountObjectId`, `AccountUpn`, `ActionType`, `QueryType`, `QueryTarget`, `DeviceName`, `DestinationDeviceName`, `DestinationIPAddress` |
| `DeviceNetworkEvents` | Network connections from the source device (join with `IdentityQueryEvents` to identify the process behind LDAP traffic) | `DeviceId`, `DeviceName`, `RemoteUrl`, `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessAccountName` |
| `DeviceLogonEvents` | MDE device-side logon telemetry | `DeviceId`, `AccountName`, `AccountDomain`, `LogonType`, `RemoteIP`, `RemoteDeviceName` |
| `AlertEvidence` | Pre-extracted entities from the alert | `EntityType`, `EvidenceRole`, `AccountObjectId`, `DeviceId`, `RemoteIP` |

## Investigation steps

These supplement the general triage-ladder in `docs/investigation.md`.

1. **Pull alert evidence.** `xdr incidents show <id> --expand alerts` — extract the source account, source device/IP, target device/account, and the specific attack type. MDI alerts typically include both the actor and the target.

2. **Determine the attack type and respond accordingly.**

   **For Golden Ticket / pass-the-ticket:**
   These are advanced attacks indicating the attacker has high-level AD access. Query `IdentityLogonEvents` to see the forged/stolen ticket in use:
   ```bash
   xdr library run identity_onprem_logon_activity --param account_oid=<account-oid> --param start=<start> --param end=<end>
   ```
   Look for: Kerberos authentication from unexpected devices, accessing resources the account doesn't normally use, or tickets with anomalous properties.

   **For brute-force attacks:**
   Assess the scope and success rate:
   ```bash
   xdr library run identity_brute_force_summary --param ip=<attacker-ip> --param start=<start> --param end=<end>
   ```
   If `Successes > 0`, the attacker compromised at least one account — escalate.

   **For reconnaissance (LDAP/SAMR):**
   Check what was enumerated:
   ```bash
   xdr library run ttp_ad_recon_queries --param account_oid=<account-oid> --param start=<start> --param end=<end>
   ```
   Reconnaissance is often the precursor to lateral movement or privilege escalation.

3. **Identify the source device.** The source IP/device in the alert is the machine the attacker is operating from:
   ```bash
   xdr library run qry_device_logons --param device_name=<source-device> --param start=<start_minus_24h> --param end=<end>
   ```
   This device may be compromised — check for malware, C2, or unauthorized access.

   **For LDAP reconnaissance: identify the process behind the traffic.** MDI sees wire-level LDAP queries but not which process sent them. Join `IdentityQueryEvents` with `DeviceNetworkEvents` to correlate LDAP destinations with the initiating process on the source device:
   ```bash
   xdr library run ttp_ldap_process_attribution --param device_name=<source-device> --param start=<start> --param end=<end>
   ```
   If the results show SCCM (`ccmexec.exe`), Group Policy (`svchost.exe -k netsvcs … gpsvc`), or other known admin tools, the alert is a false positive. Unexpected processes (LOLBins, scripts, unknown executables) warrant deeper investigation.

4. **Check for lateral movement.** Did the attacker move to other systems?
   ```bash
   xdr library run ttp_lateral_movement_rdp
   ```
   Also check `IdentityLogonEvents` for the compromised account authenticating to other servers:
   ```bash
   xdr library run ttp_lateral_targets --param account_oid=<account-oid> --param start=<start> --param end=<end>
   ```

5. **Check for privilege escalation.** Did the attacker modify group memberships or directory objects?
   ```bash
   xdr library run ttp_ad_directory_changes --param account_oid=<account-oid> --param start=<start> --param end=<end>
   ```

6. **Correlate with cloud activity.** If the compromised account also has cloud access, check `EntraIdSignInEvents` and `CloudAppEvents` for cloud-side impact:
   ```bash
   xdr library run identity_signin_context --param account_oid=<account-oid> --param start=<start> --param end=<end>
   ```

## Pivots

| From | To | Why |
|---|---|---|
| Source device → logon events | `DeviceLogonEvents` by `DeviceName` | Who else logged into the attacker's source machine? |
| Compromised account → lateral targets | `IdentityLogonEvents` by `AccountObjectId` | Where did the attacker move laterally? |
| Compromised account → directory changes | `IdentityDirectoryEvents` by `AccountObjectId` | Did the attacker escalate privileges? |
| Source IP → other attacks | `IdentityLogonEvents` + `IdentityQueryEvents` by `IPAddress` | Is this IP attacking other systems? |
| Compromised account → cloud sign-ins | `EntraIdSignInEvents` by `AccountObjectId` | Did the attacker pivot to cloud resources? |
| Compromised account → process execution | `DeviceProcessEvents` by `AccountName` | What did the attacker run on compromised devices? |

## Common false positives

- **Legitimate admin tools.** LDAP/SAMR reconnaissance alerts can fire from legitimate admin tools (SCCM, vulnerability scanners, IT automation). Check if the source device and account are known admin assets.
- **Service accounts with wide authentication scope.** Accounts that authenticate to many servers (backup agents, monitoring) can trigger brute-force or anomalous logon alerts. Verify the account is a known service account.
- **Domain controller health checks.** Routine AD replication and health monitoring can generate LDAP query volume. Check if the source is a known domain controller or monitoring server.
- **Password rotation events.** Bulk password changes (e.g., LAPS rotation) can trigger Kerberos anomaly detections. Check if the timing aligns with a known rotation schedule.

For Golden Ticket and pass-the-ticket alerts, **false positives are rare**. Treat these as high-priority.

## Containment recommendations

**For brute-force (no successful compromise):**
- Block the source IP at the firewall. Review whether account lockout policies are sufficient. No further action needed if all attempts failed.

**For brute-force with successful compromise, or for Golden Ticket / pass-the-ticket:**

1. **Disable the compromised account.**
   > Suggest to the analyst: disable the account in Active Directory immediately. If a privileged account was compromised, assume the attacker has domain-level access.

2. **Isolate the source device.**
   > Suggest: `xdr device isolate <device_id> --comment "<reason>"` — the device the attacker is operating from.

3. **For Golden Ticket specifically:**
   > Suggest: the KRBTGT account password must be reset **twice** (due to password history) to invalidate all forged tickets. This is a high-impact operation that should be coordinated with the AD team.

4. **For pass-the-ticket:**
   > Suggest: reset the compromised account's password (to block new authentication using the old password) and isolate the device the ticket was stolen from. Note: a password reset does NOT invalidate a Kerberos ticket the attacker has already stolen — a stolen TGT is encrypted with the KRBTGT key, not the user's password, and remains valid until it expires (up to ~10 hours, renewable to 7 days). To force immediate invalidation of a stolen TGT, the KRBTGT password must be reset twice (as in the Golden Ticket step above); until then, contain via device isolation and account disable and monitor until the ticket lifetime lapses.

5. **Check for persistence.** Look for new services, scheduled tasks, and group membership changes made by the attacker across all devices they accessed.

6. **Escalate.** Golden Ticket and pass-the-ticket attacks indicate advanced threat actors with significant AD access. Escalate to the security operations lead and consider engaging incident response specialists.

**For reconnaissance (LDAP/SAMR):**
- Reconnaissance alone is not damaging, but it typically precedes an attack. Investigate the source device and account for other indicators of compromise. If the account is confirmed compromised, follow the containment steps above.
