# KQL query library

The library is a catalog of packaged Advanced Hunting (KQL) queries that
ship inside the CLI. Each entry is one `.kql` file under
`src/xdr_cli/queries/` with a short `-- key: value` front-matter header
that declares its name, description, tier, parameters, and the reference
lists it consumes. The CLI currently ships 69 such files, and you can add
your own (see [Custom queries](#custom-queries)).

## Commands

| Task | Command |
|---|---|
| Browse the catalog | `xdr library list` |
| Filter by keyword | `xdr library list --search powershell` |
| Filter by tier | `xdr library list --tier r1` |
| Inspect one entry | `xdr library show NAME` |
| Render the resolved KQL without running it | `xdr hunt library-show NAME -p key=value` |
| Run an entry | `xdr library run NAME -p key=value [-p key=value ...]` |
| Raise the per-call API timeout | `xdr library run NAME --timeout 240` |
| Keep JSON-string columns unexpanded | `xdr library run NAME --raw` |
| Print the KQL a run actually sent | `xdr results query <run-id>` |

Notes:

- `--search` is a case-insensitive substring match against the entry name
  and description. `--tier` must be one of the tiers present in the catalog
  (an unknown value is rejected with an `invalid` receipt).
- `-p/--param` is repeatable. Pass one `key=value` per flag; values are not
  comma-separated. A parameter name the query does not declare is rejected
  rather than silently dropped, so a typo such as `accont_upn=` cannot turn
  a scoped hunt into a tenant-wide sweep.
- A required parameter has no default; omitting it fails before any API
  call. Omit an optional parameter to use its declared default. An explicit
  empty value still undergoes validation (`-p mode=` is invalid).
- `hunt library-show` validates parameters exactly as `library run` does, so
  the KQL it renders is the KQL a run would send.
- Parameter problems fail with exit 5 and one of these codes:
  `LIBRARY_UNKNOWN_ENTRY` (no such query; `suggestions` lists near matches),
  `LIBRARY_UNKNOWN_PARAM` (undeclared name, or an item without `=`),
  `LIBRARY_MISSING_PARAM` (a required parameter was omitted), or
  `LIBRARY_INVALID_PARAM` (the value fails its type or format check, including
  dates, durations, and integers). Each carries a `help_command` pointing at
  `xdr library show NAME`. Problems in a query file's own KQL, such as a
  placeholder placed inside a comment or a verbatim literal, are authoring
  errors rather than parameter errors and are reported as `QUERY_ERROR`. Empty scope
  defaults only mean "match all" when the query implements that condition;
  declaring a default alone does not change how the KQL filters rows.
- `library list` and `library run` both print a JSON receipt first; the
  full rows live in the JSONL file named by the receipt's `data_path`, and
  `xdr results rows <run-id>` pages through them.
- `library show NAME` returns the descriptor only: parameters with their
  type, format, allowed values and defaults, the tables and declared output
  fields, consumed lists, required permissions, a cost hint, and example
  invocations. It does not dump the KQL body; `xdr hunt library-show NAME
  -p key=value` renders the substituted query, and `xdr results query` after
  a run for that.

## Tiers

Every `.kql` file must declare `-- tier:` with one of these eight values,
enforced by the loader (`_VALID_TIERS` in `src/xdr_cli/queries/__init__.py`):

`r1`, `r2`, `r3`, `n`, `beta`, `pivot`, `utility`, `deprecated`

What is documented about them comes from the loader and from the
methodology contract tests in `tests/test_queries_methodology.py`:

| Tier | Documented contract |
|---|---|
| `r1`, `r2`, `n`, `beta` | "Finding" tiers. Each query emits a `Severity = case(...)` band and projects `SchemaVersion`. `r1`, `r2` and `n` must also expose a time anchor (`hours=N` or `start=`/`end=`). |
| `r3` | Projects `SchemaVersion`; no `Severity` band required. In the shipped catalog the `r3` entries are entity-scoped queries, most anchored with `start=`/`end=` and defaulting to `mode=detail` (the two `identity_signin_*` summaries are the exceptions). |
| `pivot` | Projects `SchemaVersion`; exempt from the `Severity` requirement. In the shipped catalog these are entity-scoped lookups (by message ID, hash, app ID, device, remote, ...) that default to `mode=detail`. |
| `utility` | Exempt from all methodology checks. Currently only `sys_schema_probe`. |
| `deprecated` | An alias shim. The file must also declare `-- alias_of: <target>`; `library run` loads the target's body instead, accepts and validates the target's parameters, and prints a stderr warning. `library show` and `library list` keep the alias's name and description but report the target's parameters, tables, and cost hint. |
| `beta` | Treated as a finding tier by the tests; the shipped entries prefix their description with `(beta)`. |

There is no documented definition of what distinguishes `r1` from `r2`
from `r3`, or what `n` stands for, anywhere in `docs/`, `AGENTS.md` or the
README. The table above records only the behaviour the tests enforce; do
not read more into the labels than that.

Every non-utility, non-deprecated query also declares a `mode` parameter
with allowed values `summary` and `detail`. Finding-tier queries default to
`summary` (one scored row per entity with `Severity`, `Score`,
`TopEvidence` and `ListHealth`); pivot queries and most `r3` queries
default to `detail` (raw matching rows). Check the Parameters column
below for each entry's actual default.

## Catalog

Generated from the `library list` artifact. `*` marks a required
parameter; `=value` shows the declared default. Descriptions are shown as
the query declares them.

### `dns_` — DNS analytics

| Query | Tier | Description | Parameters |
|---|---|---|---|
| `dns_subdomain_diversity` | r1 | High unique-subdomain count per parent domain — DNS tunneling / data exfil indicator with burst-hour concentration scoring and tenant-data-as-list | `hours` =24, `device_name`, `mode` =summary |

### `identity_` — Entra ID and on-prem identity

| Query | Tier | Description | Parameters |
|---|---|---|---|
| `identity_brute_force_summary` | r2 | On-prem brute-force summary by source IP — Severity-banded, attempt/success/target counts | `ip`*, `start`*, `end`*, `account_upn`, `mode` =summary |
| `identity_cloud_spray_summary` | r2 | Cloud password-spray scope by attacker IP — Severity-banded, error-code distribution, suppression list aware | `ip`*, `start`*, `end`*, `mode` =summary |
| `identity_ip_blast_radius` | r3 | Find all users who successfully signed in from a specific IP — identifies lateral targeting or shared attacker infrastructure | `ip`*, `start`*, `end`*, `mode` =detail |
| `identity_onprem_logon_activity` | r3 | On-prem Kerberos/NTLM logon detail for an account or source IP — used for Golden Ticket, pass-the-ticket, and lateral movement investigation | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `identity_signin_baseline` | r3 | Per-user sign-in baseline — top IPs / UAs / Countries / ASNs by frequency, distinct-counts, last-seen | `account_oid`*, `hours` =720, `mode` =summary |
| `identity_signin_context` | r3 | Per-user sign-in history with risk / CA / token / device fields | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `identity_signin_ip_summary` | r3 | Per-user sign-ins by IP/Country/City with external-source flagging | `account_oid`*, `start`*, `end`*, `mode` =summary |

### `qry_` — scoped lookups and audit queries

| Query | Tier | Description | Parameters |
|---|---|---|---|
| `qry_app_data_access` | pivot | File downloads, access, and uploads by an OAuth app — data exfiltration detection | `app_name`*, `start`*, `end`*, `mode` =detail |
| `qry_connection_scope` | pivot | All devices connecting to a specific remote IP or domain — scopes C2 infrastructure or phishing campaign blast radius | `remote`*, `start`*, `end`*, `mode` =detail |
| `qry_delivery_vector` | pivot | How a file arrived on a device — download URL, origin IP, parent process. Traces the delivery vector for malware. | `device_id`*, `sha256`*, `start`*, `end`*, `mode` =detail |
| `qry_device_connections` | pivot | Process on a device connecting to a specific remote IP or domain — identifies C2 communication, phishing proxy connections, or post-click endpoint activity | `device_id`*, `remote`*, `start`*, `end`*, `mode` =detail |
| `qry_device_logons` | pivot | Logon events on a specific device or from a specific remote IP — identifies who accessed a compromised machine | `device_name`*, `start`*, `end`*, `mode` =detail |
| `qry_email_attachments` | pivot | Attachment details (name, size, hash) for a specific email by NetworkMessageId | `network_message_id`*, `mode` =detail |
| `qry_email_blast_radius` | pivot | Other recipients of the same email by sender and subject — assesses campaign scope and ZAP success rate | `sender`*, `subject`*, `start`*, `end`*, `mode` =detail |
| `qry_email_delivery` | pivot | Delivery status of a specific email by NetworkMessageId — determines if ZAP succeeded or the threat reached the inbox | `network_message_id`*, `mode` =detail |
| `qry_email_outbound_detail` | pivot | Individual outbound emails for a sender — examines content patterns, recipients, and delivery status | `sender`*, `start`*, `end`*, `mode` =detail |
| `qry_email_outbound_spike` | r2 | Hourly outbound email volume for a sender — rate-of-change Severity band against 7-day baseline | `sender`*, `start`*, `end`*, `mode` =summary |
| `qry_email_url_blast_radius` | pivot | Recipients who received email containing a specific URL or domain — scopes phishing campaign reach | `url_domain`*, `start`*, `end`*, `mode` =detail |
| `qry_email_urls` | pivot | Embedded URLs in a specific email by NetworkMessageId | `network_message_id`*, `mode` =detail |
| `qry_entra_role_changes` | r1 | Entra role and group membership changes — actor/target scope, privileged-role weighting, new-IP-for-actor (30d), self-add and rapid add+revoke detection | `hours` =72, `actor_upn`, `target_upn`, `mode` =summary |
| `qry_exchange_role_changes` | r1 | Exchange Online role assignments — actor scope, privileged-role weighting, new-IP-for-actor (30d), external-source detection, add+revoke pairs | `hours` =72, `actor_upn`, `mode` =summary |
| `qry_external_sharing` | pivot | External sharing recipients and anonymous links created by an account — data exfiltration via sharing | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `qry_file_access_detail` | pivot | Specific files downloaded or synced by an account — identifies targeted access to sensitive content | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `qry_file_hash_scope` | pivot | Find all devices with a specific file hash | `sha256`*, `hours` =720, `mode` =detail |
| `qry_inbox_rule_activity` | r1 | Exchange rule changes (inbox + transport + mailbox forwarding) with extracted predicates, forwarding-destination classification, and BEC-specific scoring | `hours` =168, `account_upn`, `mode` =summary |
| `qry_inbox_rule_audit` | **deprecated** (alias of `qry_inbox_rule_activity`) | Deprecated; use qry_inbox_rule_activity. | — |
| `qry_inbox_rule_triggers` | **deprecated** (alias of `qry_inbox_rule_activity`) | Deprecated; use qry_inbox_rule_activity. | — |
| `qry_mailbox_delegation` | n | Exchange mailbox delegation grants — FullAccess / SendAs / SendOnBehalf, with internal/external delegate classification | `hours` =168, `account_upn`, `mode` =summary |
| `qry_oauth_app_info` | pivot | OAuth app registration details — app name, service principal ID, and owner tenant (first-party vs third-party) | `app_id`*, `mode` =detail |
| `qry_oauth_consent` | pivot | Who consented to an OAuth app and from where — identifies suspicious or coerced consent events | `app_id`*, `start`*, `end`*, `mode` =detail |
| `qry_oauth_credentials` | pivot | Credential additions (secrets, certificates) to an OAuth app — persistence mechanism detection | `app_id`*, `start`*, `end`*, `mode` =detail |
| `qry_post_compromise_activity` | r2 | Cloud actions taken by an account from a given IP after compromise — ActionType-taxonomy scored | `account_oid`*, `ip`*, `start`*, `end`*, `mode` =summary |
| `qry_privilege_grant_revoke` | r1 | Add-then-revoke role correlation across Entra ID and Exchange Online — short-gap pairs, privileged-role weighting, new-IP-for-actor, self-grant detection | `hours` =72, `actor_upn`, `target_upn`, `mode` =summary |
| `qry_process_tree` | pivot | Full process ancestry for a device in a time window | `device_name`*, `hours` =1, `mode` =detail |
| `qry_spn_activity` | r2 | Per-SPN sign-in activity — per-day rollup with multi-country Severity annotation | `spn_id`*, `start`*, `end`*, `mode` =summary |
| `qry_url_clicks` | pivot | Safe Links click activity — by NetworkMessageId, user UPN, or URL domain. Shows whether users clicked through warnings. | `account_upn`*, `start`*, `end`*, `mode` =detail |

### `sys_` — utilities

| Query | Tier | Description | Parameters |
|---|---|---|---|
| `sys_schema_probe` | utility | Enumerate tables/columns available in this tenant (run first in a new environment) | — |

### `ttp_` — technique detections

| Query | Tier | Description | Parameters |
|---|---|---|---|
| `ttp_ad_directory_changes` | r3 | On-prem AD group membership changes, account modifications, and computer account creation by a specific account | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `ttp_ad_recon_queries` | r3 | LDAP/SAMR reconnaissance activity — AD queries by a specific account or source IP | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `ttp_adcs_abuse` | beta | (beta) ADCS abuse signals — template enrollment by non-admin, SAN/requester mismatch, ESC8 NTLM-relay artefacts | `hours` =72, `account_upn`, `mode` =summary |
| `ttp_conditional_access_tamper` | n | Conditional Access policy add/update/disable/delete (CloudAppEvents) correlated with actor sign-in context (new IP vs 30d baseline, off-hours, RiskLevel/anonymizing IP within 30m) — Storm-1167 / Tycoon2FA admin-token tamper pattern | `hours` =72, `actor_upn`, `mode` =summary |
| `ttp_credential_dumping` | n | T1003 LSASS credential dumping — comsvcs.dll MiniDump, procdump -ma lsass, rundll32 MiniDumpW, mimikatz / sekurlsa / lsadump cmdline literals, nanodump / dumpert / pypykatz / SilentTrinity, taskmgr -d, sqldumper LOLBin, plus DeviceEvents OpenProcess/ReadProcessMemory against lsass.exe with signer-allowlist and KnownGoodSigners suppression | `hours` =24, `device_id`, `account_upn`, `mode` =summary |
| `ttp_defender_av_tampering` | n | Defender AV / Sense tampering — disable, exclusion, definition removal, service stop, tamper attempts, registry-policy poke | `hours` =24, `device_name`, `mode` =summary |
| `ttp_device_code_flow_abuse` | beta | (beta) Device-code flow abuse — net-new location, off-hours completion, rapid multi-completion | `hours` =24, `account_upn`, `mode` =summary |
| `ttp_discovery_recon` | n | AD / share enumeration — BloodHound, SharpHound, PowerView, net/nltest, LDAP-burst — correlated by device | `hours` =24, `device_name`, `account_upn`, `mode` =summary |
| `ttp_dll_sideloading` | r2 | DLL loaded from the same user-writable directory as the loading process — sideloading / hijack indicator with hijack-target awareness and signer suppression | `hours` =24, `device_name`, `account_upn`, `mode` =summary |
| `ttp_dns_beaconing` | r1 | Periodic DNS queries with low inter-arrival jitter (CV) — C2 beaconing detector with tenant-data-as-list, 30-day novelty, off-hours bias | `hours` =24, `device_name`, `mode` =summary |
| `ttp_encoded_powershell` | r1 | Base64-encoded PowerShell with decoded payload (single + double-decode), AMSI/ETW bypass detection, format-string + char-array obfuscation heuristics, parent attribution | `hours` =24, `device_name`, `account_upn`, `mode` =summary |
| `ttp_facedancer_webview2` | r2 | FaceDancer / DLL proxy sideloading — rename + replace correlation in user-writable paths, WebView2 target awareness | `hours` =24, `device_name`, `mode` =summary |
| `ttp_file_operation_volume` | r3 | File operation volume by type for an account — quantifies download, upload, share, and access activity | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `ttp_impossible_travel` | r1 | Geographically improbable consecutive sign-ins via geo_distance + time delta + implied velocity, additive scoring with MFA / internal / known-egress suppression | `hours` =24, `account_upn`, `mode` =summary |
| `ttp_internal_lateral_connections` | r3 | Connections from a device to private IPs on non-standard ports — lateral movement indicator | `device_id`*, `start`*, `end`*, `mode` =detail |
| `ttp_kerberos_delegation_abuse` | beta | (beta) Kerberos delegation abuse — RBCD self-grant, S4U2Self/S4U2Proxy chains, sensitive-SPN TGS by low-priv accounts | `hours` =72, `account_upn`, `mode` =summary |
| `ttp_lateral_movement_rdp` | r1 | Successful RDP logons (LogonType=RemoteInteractive) with novelty, fan-out, failed-then-success scoring, tunnel detection, off-hours, and KnownRemoteSupportTools suppression | `hours` =6, `source_account`, `target_device`, `source_ip`, `mode` =summary |
| `ttp_lateral_psexec_wmi` | r1 | Lateral movement via PsExec / WMI / PSRemoting / remote schtasks — cross-device fan-out, unsigned tooling, suspicious cmdline, suppression-list aware | `hours` =24, `device_id`, `account_upn`, `mode` =summary |
| `ttp_lateral_targets` | r3 | Summarize successful on-prem authentication destinations for an account — identifies lateral movement targets | `account_oid`*, `start`*, `end`*, `mode` =detail |
| `ttp_ldap_process_attribution` | r2 | Correlate MDI LDAP recon with initiating process on source device — Severity-banded for triage | `device_name`*, `start`*, `end`*, `lookback` =0d, `mode` =summary |
| `ttp_malware_execution` | r3 | Check if a specific file (by hash or name) executed on a device — determines prevented vs. executed verdict | `device_id`*, `sha256`*, `start`*, `end`*, `mode` =detail |
| `ttp_new_service_creation` | r1 | New service registrations (ImagePath / ServiceDll / FailureCommand) scored by parent process, binary path, signer, and 30-day rarity | `hours` =24, `device_name`, `account_upn`, `mode` =summary |
| `ttp_oauth_app_signin_anomaly` | n | SPN sign-in anomalies — net-new IPs/countries, token reuse across IPs, public-client workload sign-ins | `hours` =24, `service_principal_id`, `mode` =summary |
| `ttp_oauth_consent_anomaly` | n | Broad-scan OAuth consent grants scored by requested scope, app age, consent-burst per user, per-IP cross-user burst, same-session register-then-consent, admin-consent | `hours` =168, `account_upn`, `application_id`, `mode` =summary |
| `ttp_ransomware_mass-rename` | r1 | Late-stage ransomware activity — mass rename + extension-entropy + shadow copy deletion + backup deletion + ransom note creation. For early-warning, see ttp_ransomware_precursors. | `hours` =6, `threshold` =50, `device_name`, `mode` =summary |
| `ttp_ransomware_precursors` | n | Pre-deployment ransomware kill-chain — recon, AV tamper, backup kill, operator tooling, DA acquisition | `hours` =72, `device_name`, `mode` =summary |
| `ttp_registry_persistence` | r3 | Run/RunOnce/Services registry modifications on a device — persistence mechanism detection | `device_id`*, `start`*, `end`*, `mode` =detail |
| `ttp_rmm_first_seen` | n | First-seen RMM tool (AnyDesk, ScreenConnect, ConnectWise Control, NinjaRMM, Atera, Splashtop, TeamViewer, etc.) on a device — process or file-create with no occurrence in the prior 30d. Highest-fidelity initial-access signal in the SMB threat model (Akira, BlackBasta, Storm-0867, ScatteredSpider). | `hours` =24, `device_id`, `mode` =summary |
| `ttp_shadow_copy_deletion` | r3 | Detect shadow copy deletion and recovery mode tampering — a hallmark of ransomware pre-encryption staging | `device_id`*, `start`*, `end`*, `mode` =detail |
| `ttp_suspicious_downloads_exec` | r2 | Executables / scripts run from user-writable paths with at least one behavioural indicator — multi-signal scored | `hours` =24, `device_name`, `account_upn`, `mode` =summary |
| `ttp_token_theft_replay` | r1 | Per-session sign-in fingerprint anomalies (SessionId / UniqueTokenId reuse from different IPs / UAs / Countries / JA4) + AiTM infra hits + refresh-token replay (>24h, no-MFA) | `hours` =24, `account_upn`, `session_id`, `mode` =summary |

## Parameter typing and escaping

Parameters are not pasted into the KQL as raw text. The loader assigns a
catalog-wide type to each parameter by name (`_parameter_contract`), then
validates the value and renders the `{name}` placeholder according to its
KQL context (`_render_parameters`).

| Type | Parameter names | Accepted values | Placement in KQL |
|---|---|---|---|
| `enum` | `mode` | `summary` or `detail` | inside a quoted literal |
| `integer` | `hours`, `threshold` | positive integer (`1`, `24`, `720`) | outside quotes |
| `datetime` | `start`, `end` | ISO-8601 date or timestamp (`2026-10-01`, `2026-10-01T08:00:00Z`) | outside quotes |
| `duration` | `lookback` | KQL duration literal (`30m`, `6h`, `7d`) | outside quotes |
| `string` | everything else (`account_upn`, `device_name`, `sha256`, `ip`, `*_id`, ...) | any text without control characters; `sha256` must be exactly 64 hex characters and `ip`/`source_ip` a valid IPv4 or IPv6 address | inside a quoted literal |

Rules the renderer enforces:

- A string or enum placeholder must sit inside an ordinary single- or
  double-quoted KQL string literal, for example `DeviceName == "{device_name}"`.
  The value is escaped as literal content: backslashes are doubled and the
  enclosing quote character is backslash-escaped. A value containing
  quotes, `|`, or other operator characters therefore stays data and
  cannot change the query's shape.
- A typed placeholder (`{hours}`, `{start}`, `{end}`, `{lookback}`,
  `{threshold}`) must stay outside quotes, for example
  `ago({hours}h)` or `between (datetime({start}) .. datetime({end}))`.
  The value is validated against its literal format before substitution,
  so `-p hours=24h` or `-p start=yesterday` is rejected.
- Placeholders are not substituted inside `//` or `/* */` comments, are
  refused inside verbatim (`@"..."`) literals, and are refused inside
  multiline (` ``` `) literals.
- A placeholder that appears in the KQL but is never substituted (for
  example, one that occurs only inside a comment) fails the run. A declared
  parameter whose placeholder does not appear in the body at all is
  accepted and has no effect.

## Custom queries

Drop `.kql` files into `~/.xdr-cli/queries/` (or `$XDR_CLI_HOME/queries/`
when you isolate configuration per tenant). The file stem becomes the
query name and a user file with the same stem as a builtin overrides it.
Front-matter is a run of `-- key: value` lines at the top of the file;
the first non-`--` line starts the KQL body.

| Key | Required | Meaning |
|---|---|---|
| `-- tier:` | yes | One of the eight tier values above. |
| `-- description:` | recommended | One line shown by `library list` and `library show`. |
| `-- params:` | if the body has placeholders | Comma-separated names; `name` is required, `name=` declares an empty default, `name=value` declares a default. |
| `-- lists:` | no | Comma-separated list-block names the body references as `_xdr_<Name>`. |
| `-- alias_of:` | only with `tier: deprecated` | Name of the live query to forward to. |
| `-- agent_hint:` | no | Multi-line hint (continuation lines start with `--` and two spaces). |
| `-- name:` | no | Accepted but ignored; the query name always comes from the file stem. |

Complete example, `~/.xdr-cli/queries/my_device_processes.kql`:

```sql
-- description: My custom query
-- tier: r3
-- params: device_name, hours=24
DeviceProcessEvents
| where Timestamp > ago({hours}h)
| where DeviceName == "{device_name}"
| take 100
```

Run it with `xdr library run my_device_processes -p device_name=WS-01`.
Because `device_name` has no default it is required. To make it optional,
use `-- params: device_name=, hours=24` and change its filter to
`where isempty("{device_name}") or DeviceName == "{device_name}"` if an empty
value should mean "match all". The `hours` parameter controls the explicit
`Timestamp` filter above; declaring it alone would not bound the query.

A malformed file (missing `-- tier:`, an unknown tier, or `tier:
deprecated` without `alias_of`) is skipped with a stderr warning rather
than aborting the whole command, so one bad file never hides the rest of
the library. A skipped file with a new name does not appear in `library
list`; a skipped file that shares a builtin's name leaves the builtin in
effect, so check stderr if your override seems to be ignored.

## Reference lists

Many queries consume tenant and IOC reference data through list blocks:
`let _xdr_<ListName> = dynamic([...]);` declarations that the loader
synthesises from `~/.xdr-cli/lists/<ListName>.txt` and prepends to the
body before parameter substitution. Seed the directory once with
`xdr lists init`. A list that is missing, empty, over its size cap, or
not a known block name resolves to an empty `dynamic([])` and the query
still runs, so an unseeded allowlist admits every row and an unseeded
denylist matches nothing: results silently lose coverage rather than
failing. Summary rows carry a `ListHealth` column that reports each
block's value count, staleness, and source so you can spot this. See
[lists.md](lists.md) for the file format, seeded blocks, and TTL headers.

## Reproducing a run

Every `library run` stores the fully rendered KQL (lists prepended,
parameters substituted and escaped) alongside its result. Print it with:

```bash
xdr results query <run-id>
```

The run ID is in the receipt that `library run` prints. The output is the
exact text sent to the Advanced Hunting API, suitable for pasting into the
Defender portal or attaching to a case.
