# Live Response and device-page coverage

This matrix records which GUI operations the CLI implements and how each one
was validated. The evidence levels are kept separate on purpose:

- **cli-live**: the CLI command itself ran end to end against a development
  tenant (agent-run, read-only or reversible, with cleanup verified).
- **backend-live**: the backend operation ran against a development tenant,
  but the CLI command around it has not.
- **synthetic**: unit tests with synthetic fixtures only.
- **source**: the request contract comes from Microsoft's shipped portal
  client or documentation, and nothing has run live yet.
- **unavailable**: not exposed by this backend. The CLI fails locally with
  `BACKEND_CAPABILITY_UNAVAILABLE` (exit 3) and does not fall back.
- **gap**: not implemented.

A mock never establishes live coverage. Live runs used one Windows 11 device
in one development tenant. Availability on other devices still depends on
tenant settings, RBAC role, OS and sensor version.

## Live Response sessions (portal-cookie, V3 `liveResponseApi`)

| GUI operation | CLI command | Official backend | Evidence |
|---|---|---|---|
| Command reference | `live-response catalog` | local | cli-live (31 rows), synthetic |
| Initiate session | `live-response connect MACHINE --wait N` | unavailable | cli-live, synthetic |
| Session details | `live-response show SESSION` | unavailable | cli-live, synthetic |
| Session list | `live-response sessions` (locally known sessions) | unavailable | synthetic; no tenant-wide list contract |
| Disconnect | `live-response disconnect SESSION` | unavailable | cli-live, synthetic |
| Command definitions | used by `exec` and shortcuts | unavailable | backend-live (21 Windows definitions) |
| dir | `live-response dir --wait`, `exec` | unavailable | cli-live, synthetic |
| findfile | `live-response findfile --wait` | unavailable | cli-live, synthetic |
| fileinfo | `live-response fileinfo` | unavailable | backend-live, synthetic |
| getfile + download | `live-response getfile --output`, `download` | `batch` | cli-live for `getfile --output` (360,448-byte system binary, independent SHA-256 matches receipt, local copy removed, session closed); backend-live (37-byte test file, exact SHA-256 round trip); standalone `download`: synthetic CLI |
| putfile | `live-response putfile` | `batch` | backend-live, synthetic |
| run (library script) | `live-response run` | `batch` | backend-live (benign script), synthetic |
| Command output | `live-response output` | `batch output` | cli-live, synthetic |
| jobs / command log | `live-response history` | unavailable | cli-live, synthetic |
| status | `live-response status --wait` | `batch status` | backend-live, synthetic |
| Background `&`, `fg` | trailing `&`; `status --wait` | n/a | synthetic |
| `> file` output pipe | trailing `> FILE` (local save) | n/a | synthetic |
| Cancel (Ctrl+C) | `live-response cancel` (portal-side only) | `batch cancel` | synthetic |
| processes, registry, services, drivers, connections, persistence, scheduledtasks, startupfolders, cd | `exec` | unavailable | synthetic |
| remediate file | `exec` | unavailable | backend-live (temporary test file), synthetic |
| analyze, undo | `exec` | unavailable | synthetic; not run live |
| collect, isolate, release, scan (macOS/Linux console) | `exec` | unavailable | docs only; not in the observed Windows definitions |
| processdump | `exec`, only when a session's definitions offer it | unavailable | source (feature-gated) |
| help | `exec --command 'help X'`, `catalog` | local | synthetic |
| cls, trace | not applicable (console presentation) | local | n/a |

A command can report `completed` and still carry errors. Records show
`error_count`, and getfile downloads and `> FILE` saves happen only at zero
errors.

## Live Response library

| GUI operation | CLI command | Official backend | Evidence |
|---|---|---|---|
| List | `live-response library list` / `show` | yes | cli-live (list, empty library), backend-live, synthetic |
| Upload (overwrite, parameters description) | `library upload --from-file` | yes | backend-live (portal), synthetic |
| Download | `library download` | unavailable (no API route) | backend-live (portal, exact SHA-256) |
| Delete | `library delete` | yes | backend-live (portal), synthetic |

## Official one-shot actions

| Operation | CLI command | Evidence |
|---|---|---|
| runliveresponse (PutFile, RunScript, GetFile) | `live-response batch submit` | synthetic |
| status / per-command output | `batch status`, `batch output` | synthetic |
| result download link | `batch download --index N` | synthetic |
| cancel | `batch cancel` | synthetic |

## Device page

| GUI operation | CLI command | Official backend | Evidence |
|---|---|---|---|
| Isolate / release, restrict / unrestrict, AV scan, collect package, action status | existing `device` commands | yes | existing coverage |
| Download investigation package | `device download-package` | unavailable | existing coverage |
| Manual tags | `device tags list/set/add/remove` | add/remove only | cli-live (read, add, remove; original tags restored); whole-set replacement: synthetic only |
| Action availability | `device action-permissions` | unavailable | cli-live (11 rows), synthetic |
| Cancel response action | `device cancel-action` | unavailable | source, synthetic |
| Contain / release containment (unmanaged devices) | `device contain`, `device uncontain` | unavailable | source, synthetic; not run live |
| Automated investigation | `device start-investigation` | yes (records the comment) | source; protocol selector read live (dotnet-ui), never started live; synthetic CLI |
| Action history (Action center) | `device action-history [--limit N]` | machine actions only (excludes portal Live Response) | backend-live (7-day window, 19 rows matching the native count, pagination complete), synthetic CLI |
| Collect support logs | `device collect-support-logs` | unavailable | source, synthetic. Collection attempt returned HTTP 403; separately, tenant context reported the feature disabled. No collection was created. The new feature preflight was run live with reads only: `TENANT_FEATURE_UNAVAILABLE` after two GET requests, no mutation |
| Support-log download | — | — | gap: download host/transfer contract unverified, and no completed collection exists to test against |
| Troubleshooting mode (fixed 4 hours) | `device troubleshoot --on/--off` | unavailable | source, synthetic; not run live; portal stop eligibility via feature/configuration variant is not checked |
| Asset value, criticality, exclusion state | — | — | gap: source contract only |
| Offboard, stop and quarantine, forensic artifacts, policy sync, expert consultation, Logic App playbooks | — | — | gap: no device-page wire contract inventoried |

The portal's action-availability response reported support-log collection as
allowed while the tenant feature was off. Availability is not authorization
and does not prove a feature is enabled.

Before submitting, `collect-support-logs` reads the tenant's feature settings,
in the same order as the portal. If `LogsCollection` is off, it stops with
`TENANT_FEATURE_UNAVAILABLE` (exit 3), even when the newer diagnostic-package
feature is on. If `LogsCollection` is on but `EnableCollectDiagnosticPackage`
is also on, the tenant uses the newer protocol, which the CLI does not
implement, and it stops with `BACKEND_CAPABILITY_UNAVAILABLE` (exit 3). In
both cases nothing is sent to the device. A plain HTTP 403 (exit 7) still
means the service refused the request; the status alone does not identify the cause.
