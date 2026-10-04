# xdr-cli

**Microsoft Defender XDR investigation CLI — for humans and AI agents.**

[![CI](https://github.com/NerfBlasters/m365-xdr-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/NerfBlasters/m365-xdr-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

`xdr` lets a SOC analyst — or an AI agent working on their behalf — triage
incidents, run advanced hunting, and take response actions in Microsoft
Defender XDR from a terminal. Every large read is saved as a private JSONL
artifact and summarised by a one-line receipt, so results are greppable,
pipeable, and small enough for an agent's context window.

![xdr-cli guided investigation demo](docs/media/investigate.gif)

*Demo tenant; tenant and object identifiers replaced for publication.*

## Experimental portal-cookie backend

See [support and limitations](docs/portal_cookie.md) for validated behavior and
known portal gaps, including superseded actions and partial device fields.

Backend selection defaults to `auto`: official Graph/MDE credentials take
precedence; when only tenant-bound portal cookies are available, commands use
cookie mode automatically. The cookie backend supports hunting (including library
and schema hunting workflows),
incident/alert lists and detail, expanded incident evidence, guided investigations,
Entra domains, and device show/timeline. Graph-backed reads retain the existing
Graph response contract; native device detail still has partial field mapping
and retains raw portal fields. Hostname resolution requires an exact, unambiguous
match among MDE devices in the portal's 180-day inventory view.

Cookie authentication also supports incident status, classification, determination,
and comment updates; Quick/Full antivirus scans; Selective/Full isolation and
unisolation; investigation-package collection/download; and execution restriction.
Use `xdr device unrestrict DEVICE_ID --comment "Recovery reason" --yes` to
remove the restriction. Both authentication backends support this recovery action.
Unsupported operations return `BACKEND_CAPABILITY_UNAVAILABLE` without silently
falling back to MSAL. Native device and action responses differ from official APIs.
Device output lists unavailable fields under `portal_source.unavailable_fields`.
Device enrichment maps management, tags, value, group, IP adapters, and available
exclusion/cloud/merge metadata while preserving source differences. Known bitness
values map to `osArchitecture`; the deprecated processor field is
not inferred. Native `lastSeen` follows portal observation semantics, which differ
from the official API's last full device report.

Cookie-only action status uses a private local device association saved after
a correlated submission or successful status read. For an action first seen on
this installation, supply the device association:
`xdr --backend portal-cookie device action-status ACTION_ID --device MACHINE_ID`.
It matches the exact action and device even when the portal returns other
actions. Recognized scan, collection, isolation and restriction response types
map to official operation names; unknown subtypes remain unmapped. Status values
and raw fields retain the portal contract. A missing action in the portal's latest
response does not establish absence from historical records. Action Center history
can report `Completed` for failed actions, so it is not used as a success-status
fallback.
After a successful read, `action-status ACTION_ID` can omit `--device` on this
installation and tenant. Missing or corrupt associations require `--device` again;
the CLI always reads current status remotely. Association files under
`~/.xdr-cli/action_associations/` contain IDs only and use private permissions.

`xdr domains list` combines Entra tenant domains and MDI-observed Active Directory
domains in cookie mode. Each private JSONL row has `source` (`entra` or
`active-directory`), `name`, and provider-specific fields. Same-named domains are
kept separate. Use `--source entra` or `--source active-directory` to select one
inventory. The official backend supports Entra only: default combined listing
preserves Entra results and returns exit 14 for missing AD coverage; use
`domains list --source entra` for an explicit official-only read. AD search is
capped at 100 records, with `has_more`, reported counts and source coverage in
the receipt. Partial results return exit 14; observed AD domains do not establish
Entra verification or exhaustive forest coverage.

Download a completed investigation package without requesting a new collection:

```bash
xdr --backend portal-cookie device download-package ACTION_ID --device MACHINE_ID --output package.zip
```

The command requires a succeeded package-collection action, downloads the ZIP
without extracting it, and emits a JSON envelope with its path, byte count and
SHA-256. The destination directory must already exist. Output uses owner-only
permissions and is published atomically after transfer and ZIP-container checks.
Existing paths require `--force`; a symlink is replaced without writing to its
target. The default transfer limit is 1 GiB; use `--max-bytes N` to change it.
Portal cookies stay on the portal origin; archive transfers use a separate client
and signed URLs are excluded from output. Package download currently requires
the portal-cookie backend.

For a fresh cookie-only setup, create `~/.xdr-cli/config.toml` with:

```toml
tenant_id = "<tenant-id>"
```

Replace `<tenant-id>` with your tenant ID. Import the browser session with
`xdr auth portal-cookie COOKIE_SOURCE`, then run commands normally:

```bash
xdr hunt run "print CookieAuthProbe = 1"
xdr auth status
```

No backend flag or setting is needed for a cookie-only setup. Explicit
`--backend official|portal-cookie` overrides the configured preference; set
`api_backend = "official"` or `"portal-cookie"` to pin a backend, or `"auto"` to
restore automatic selection. `auth status` reports the selected backend.

Automatic selection checks local credentials, not remote validity. A configured
app secret or matching MSAL access/refresh token keeps official auth preferred,
even if an access token has expired. Failed authentication, permissions, or API
requests never cause a retry through another backend. A damaged MSAL cache is
not treated as absent. No client ID or secret is required for cookie mode. The authenticated portal
tenant must match configuration; expired sessions require fresh cookies.
`auth status` reports stored credentials without asserting the session is valid.
New cookie-mode [sessions](docs/sessions.md) use the `automatic` identity
placeholder without consulting MSAL; manual start requires stored tenant-bound cookies.
With automatic selection, `auth login` can establish MSAL credentials even when
cookies are currently selected; subsequent commands then prefer official auth.
Explicit cookie mode directs `auth login` to cookie import. `auth logout` removes
credentials for the selected backend, preserving the other store. This local
logout does not revoke the browser session at Microsoft.
Query results retain unknown truncation unless completion is established;
optional portal query diagnostics are saved privately in hunt artifact metadata.
`xdr auth portal-login` is retired; use `portal-cookie` instead.
See [device timeline](docs/device_timeline.md) for timeline output and credential details.

## What it does

- **Incidents and alerts** — list, filter, show (with alerts and evidence
  expanded), and update status/classification.
- **Guided investigation** — `xdr investigate <id>` pulls the incident,
  extracts devices/users/IPs/hashes, runs the relevant hunting queries, and
  prints suggested next steps with ready-to-run commands.
- **Advanced hunting** — run ad-hoc KQL, or pick from a library of 66 hunting
  queries (process trees, Kerberos delegation abuse, token replay, inbox rules,
  OAuth consent anomalies, lateral movement, ransomware precursors, …) that
  take typed parameters and are escaped before they reach the API. Three are
  marked beta; see [the library reference](docs/library.md).
- **Response actions** — isolate, release, scan, restrict execution, and
  collect investigation packages, with confirmation, `--dry-run`, and a local
  audit log.
- **Built for agents** — compact JSON receipts on stdout, progress on stderr,
  one-line structured errors with a `corrected_argv` hint, and an
  [`AGENTS.md`](AGENTS.md) that tells Claude Code, Copilot CLI, or Codex
  exactly how to drive it.
- **Playbooks** — alert-title → [playbook](playbooks/index.md) mapping for
  common Defender alerts (BEC, forwarding rules, ransomware, AiTM, C2, …).
- **A schema graph that grows with your investigations** — learns identifier
  connections from saved hunts, validates promising pivots, and explores new
  locations when you explicitly end a session. Export it to BloodHound to
  navigate across tables. See [Schema discovery](#schema-discovery-and-sessions).
- **An improvement loop built in** — investigations are recorded locally as
  sessions: every command, the hypothesis behind it (`--rationale`), the
  lesson after it (learning mode), and an outcome-and-friction assessment when
  the session ends. `xdr history stats` turns that record into failure rates
  and library coverage gaps. See [Built to improve with use](#built-to-improve-with-use).
- **Extras for deeper work** — an *unofficial* device-timeline download that
  reaches back ~180 days (see [Device timeline](docs/device_timeline.md)).

## Is it for you?

Use `xdr` if you work incidents in Defender XDR and want to do it from a
shell — because you script, because you pair with an AI agent, or because
clicking through the portal is slower than typing. It talks to the same
Microsoft Graph security and Defender for Endpoint APIs the portal uses, with
your own Entra app registration and your own delegated permissions; nothing
leaves your machine except the API calls.

It is **not** a SIEM, a scheduler, or a replacement for the portal's action
center. Response actions require explicit commands and confirmation; schema
upkeep can run automatically when you explicitly end an investigation session.

## Install

Requires **Python 3.11+**. `pipx` gives `xdr` its own isolated environment and
puts the command on your PATH, which matters when an agent spawns it as a
subprocess.

### Linux / macOS

```bash
pipx install "git+https://github.com/NerfBlasters/m365-xdr-cli.git"
xdr --version
```

### Windows (PowerShell)

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
# refresh PATH in this session so pipx and xdr are visible without reopening
$env:Path = [Environment]::GetEnvironmentVariable("Path","User") + ";" + [Environment]::GetEnvironmentVariable("Path","Machine")

pipx install "git+https://github.com/NerfBlasters/m365-xdr-cli.git"
xdr --version
```

### Updating

```bash
pipx upgrade xdr-cli        # or: pipx reinstall xdr-cli
```

Developers: see [Development](#development) for an editable install.

## Set up the Entra app registration

`xdr` authenticates as *you* through an app registration in your tenant. One
registration can be shared by everyone on the team.

1. **Azure Portal → Microsoft Entra ID → App registrations → New registration.**
   Name it (`xdr-cli`), choose **Single tenant**, and add a
   **Public client/native** redirect URI of `http://localhost`. If anyone
   will sign in on Windows, also add
   `ms-appx-web://Microsoft.AAD.BrokerPlugin/<client-id>` (your application
   ID from step 2), which the Windows sign-in broker (WAM) requires.
2. From **Overview**, copy the **Application (client) ID** and
   **Directory (tenant) ID**.
3. **API permissions → Add a permission.** Add these **delegated** permissions:

   | API | Permission | Used by |
   |---|---|---|
   | Microsoft Graph | `SecurityIncident.ReadWrite.All` | `incidents list/show/update`, `investigate` |
   | Microsoft Graph | `SecurityAlert.Read.All` | `alerts list/show` |
   | Microsoft Graph | `ThreatHunting.Read.All` | `hunt run`, `library run`, `investigate`, `schema` |
   | Microsoft Graph | `Domain.Read.All` | Entra portion of `domains list` |
   | WindowsDefenderATP¹ | `Machine.Read` | `device show`, `device action-status`, hostname lookups |
   | WindowsDefenderATP | `Machine.Isolate` | `device isolate` / `unisolate` |
   | WindowsDefenderATP | `Machine.Scan` | `device scan` |
   | WindowsDefenderATP | `Machine.CollectForensics` | `device collect-package` |
   | WindowsDefenderATP | `Machine.RestrictExecution` | `device restrict`, `device unrestrict` |
   | WindowsDefenderATP | `AdvancedQuery.Read` | Hunting fallback only (see below) |

   ¹ Under **APIs my organization uses**, search for *WindowsDefenderATP*.
   Defender for Endpoint tokens are still issued for the legacy
   `api.securitycenter.microsoft.com` audience even though requests go to
   `api.security.microsoft.com`; that is why these live under
   WindowsDefenderATP rather than Microsoft Graph.

   Grant only the permissions needed by the commands you intend to use.
   `SecurityAlert.ReadWrite.All` also works for alerts but is not needed:
   `xdr` never modifies alerts.

   Hunting goes through Microsoft Graph. If Graph hunting returns 403 or 404,
   `xdr` retries the query once against the
   [Defender for Endpoint hunting API](https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api)
   (`api.security.microsoft.com/api/advancedqueries/run`), which needs
   `AdvancedQuery.Read` and only sees Defender for Endpoint tables. Microsoft
   began retiring that API in January 2026, so configure
   [Graph hunting](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0)
   and treat the fallback as temporary.
4. **Grant admin consent** for your tenant. Every permission above is
   delegated, so a Cloud Application Administrator, Application
   Administrator, or Privileged Role Administrator can grant it
   ([Microsoft's requirements](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent#prerequisites)).
   Security Administrator alone cannot. The service-principal setup
   described under [Configuration](#configuration) uses Microsoft Graph
   *application* permissions, which need Privileged Role Administrator.
5. **Authentication → Advanced settings → Allow public client flows → Yes.**

The signed-in user also needs the Defender roles that match what they run
(Security Reader for triage; *Active remediation actions* for device
actions). The app registration cannot grant more than the user has.

If you add a permission after signing in, run `xdr auth logout && xdr auth
login` afterwards. Until then `xdr` keeps using the cached access token
issued before the change, and the new permission fails with
`PERMISSION_MISSING_SCOPE` until that token expires (up to about 90 minutes).

## Quick start

```bash
# 1. Sign in. Opens an interactive sign-in (the WAM broker on Windows, your
#    browser elsewhere); if neither can start, e.g. on a headless host, it
#    prints a device code instead. tenant_id and client_id are saved to
#    ~/.xdr-cli/config.toml.
xdr auth login --tenant-id <TENANT_ID> --client-id <CLIENT_ID>
xdr auth status

# 2. Copy the reference-list templates the hunting library reads (internal
#    subnets, known-good signers, tenant domains, …) into ~/.xdr-cli/lists/.
#    Generic lists (signers, private subnets, remote-support tools) ship with
#    defaults; tenant-specific ones such as TenantDomains start empty.
xdr lists init

# 3. Look around. --expand alerts includes each alert's evidence.
xdr incidents list --since 7d --severity high
xdr incidents show 42 --expand alerts
xdr alerts list --since 24h

# 4. Investigate one incident end to end.
xdr investigate --auto-enrich 42

# 5. Hunt.
xdr hunt run "DeviceProcessEvents | where Timestamp > ago(1d) | where FileName == 'powershell.exe' | take 10"
xdr library list --search kerberos
xdr library run qry_process_tree --param device_name=WS-01

# 6. Close the session; bounded schema upkeep runs, then follow the feedback action.
xdr session end
```

Global flags go **before** the subcommand: `xdr --quiet incidents list`,
`xdr --no-interactive investigate 42`.

### Reading results

Any command that can return a lot of data prints a **receipt** followed by at
most two preview rows, and saves the complete result as JSONL under
`~/.xdr-cli/results/`. When there are more rows than previews, the receipt's
`context.results_command` is the exact command to page through them:

```json
{"status":"success","schema_version":1,"run_id":"20261004T015710757111Z-41a96c5113e3","data_path":"/home/me/.xdr-cli/results/2026-10-04/20261004T015710757111Z-41a96c5113e3.jsonl","meta_path":"/home/me/.xdr-cli/results/2026-10-04/20261004T015710757111Z-41a96c5113e3.meta.json","rows":2,"server_truncation_state":"unknown","execution_time_ms":1537,"session_id":null,"session_label":null,"session_attachment":"unattached","incident_id":null,"alert_id":null,"context":{"shown":2,"total":2,"has_more":false}}
{"id":"2","severity":"high","status":"active","displayName":"Multi-stage incident involving Credential access & Lateral movement on multiple endpoints", …}
{"id":"1","severity":"high","status":"active","displayName":"'Ceprolad' detected on one endpoint", …}
```

The preview rows above are abridged; real rows are the full API objects
(previews larger than 4 KB are replaced by a `preview_omitted` marker).

Work with the artifact using whatever you already use — `jq`, `rg`, Python —
or the built-in `xdr results` commands. `incidents show`, `alerts show`, and
`investigate` split their output into typed rows (`record_type` of `incident`,
`alert`, `evidence`, `entity`, …), so one kind can be selected directly:

```bash
xdr incidents show 42 --expand alerts   # note the receipt's data_path
jq -r 'select(.record_type=="alert") | "\(.severity)\t\(.title)"' "$DATA_PATH"
xdr results shape <run-id>            # which fields exist, with types and counts
xdr results rows <run-id> --type evidence
xdr results query <run-id>            # the KQL behind a hunt or library run
```

Artifacts are never deleted automatically. `xdr results prune --older-than 30 --yes`
removes eligible old results and retires automatic discovery evidence for them;
explicit observation and proposal evidence remains protected. See
[evidence retention](docs/schema_graph.md#results-privacy-and-evidence-retention).

### Response actions

```bash
xdr device show <device-id>
xdr device isolate <device-id> --comment "Incident 42" --dry-run   # preview
xdr device isolate <device-id> --comment "Incident 42" --yes       # do it
xdr device unisolate <device-id> --comment "Remediated" --yes
xdr device scan <device-id> --scan-type Full
xdr device restrict <device-id> --comment "Suspicious activity" --yes
xdr device unrestrict <device-id> --comment "Recovery approved" --yes
xdr device collect-package <device-id>
xdr device action-status <action-id>
```

`isolate`, `unisolate`, and `restrict` require `--comment`. Every action asks
for confirmation unless you pass `--yes`, and refuses to run non-interactively
without it. `--dry-run` is available on all actions except `unisolate`.

## For AI agents

`xdr` is designed to be driven by an agent. Point the agent at
[`AGENTS.md`](AGENTS.md) — it covers invocation rules, output shapes, exit
codes, and the investigation methodology in
[`docs/investigation.md`](docs/investigation.md) and [`playbooks/`](playbooks/index.md).
The short version:

- Large reads emit JSON receipts and previews; progress and warnings go to
  **stderr**. Lifecycle and raw-render commands have their own output shapes
  documented in [AGENTS.md](AGENTS.md#3-artifact-and-compact-output-shapes).
  Never merge streams with `2>&1`.
- Progress is auto-silenced when stdout is piped; `--quiet` suppresses progress,
  `--no-quiet` forces it on. Configuration warnings can still appear on stderr.
- Without a TTY on stdin and stdout (or with `--no-interactive`), `xdr` never
  prompts. Commands that would ask for confirmation (response actions,
  `incidents update`, `results prune`) refuse with exit 6 unless `--yes` is
  passed.
  `auth login` is a separate interactive flow: agents should ask a human to
  perform it, rather than treating `--no-interactive` as unattended login.
- Failures before durable output are one JSON error line with a stable `code`
  and `exit_code`; usage errors may include a `corrected_argv` hint.
- Explicit `session end` emits a closure record with feedback instructions,
  then a maintenance record. Upkeep can return exit 14 after the session is
  safely closed; cancellation returns 130. Do not retry the session end.
- Exit codes: 0 ok · 1 internal · 2 auth · 3 upstream API · 4 config ·
  5 query · 6 usage · 7 permission · 8 not found · 9 rate-limited ·
  10 timeout · 11 network · 12 artifact I/O · 13 conflict · 14 partial
  success · 130 cancelled.

```bash
# In a Claude Code / Copilot CLI / Codex prompt:
"Use xdr-cli to investigate incident 4421: run `xdr investigate --auto-enrich 4421`,
read the receipt's data_path, and summarise the alerts, entities, and recommended
actions. Do not run any `xdr device` command without asking me."
```

## Built to improve with use

Every investigation can leave a structured record of how the tool performed,
so gaps show up as data rather than anecdotes. The record stays on your
machine under `~/.xdr-cli/sessions/`; nothing is sent anywhere.

- **Sessions record every command.** `hunt run`, `library run`,
  `investigate`, and `incidents`/`alerts show` start a session automatically
  (or start one yourself with `xdr session start --label incident-42`). Each
  invocation becomes one JSONL record with the command and redacted
  arguments, the KQL and tables it touched, the library query and parameters,
  the exit and error code, duration, and row count.
- **`--rationale` captures intent before the result.**
  `xdr --rationale "expect RDP from WS-01 to the DC" hunt run "…"` stores the
  hypothesis on that command's record, so a review can compare what was
  expected with what came back.
- **Learning mode captures the lesson after.** In a session started with
  `xdr session start --learning-mode`, each command must be followed by
  `xdr annotate "<what this showed>"`, or `xdr annotate --skip "<why it wasn't
  useful>"`, before the next one runs. A skip is recorded as signal too.
- **Feedback closes each session.** `xdr session end` returns a `next_action`
  asking for an assessment, which `xdr session feedback` appends with an
  outcome (`completed-smoothly`, `completed-with-friction`,
  `incomplete-blocked`) and friction categories (`output-handling`,
  `query-or-schema`, `library-discovery`, `auth-or-permission`,
  `latency-or-timeout`, …). The agent's assessment and the analyst's are
  separate entries (`--source agent` / `--source analyst`). Entries are
  append-only and never overwritten, and agents are told never to invent
  analyst feedback.
- **`xdr history stats` turns the record into metrics:** failure rate and top
  error codes, hand-written versus library hunts, and *table coverage gaps*
  (tables queried with ad-hoc KQL that a library query already covers). Scope
  it to one `--session` or to all of an `--operator`'s sessions, narrow with
  `--incident`, `--command`, or `--since`, and use `--by-actor` to separate
  parallel agents (`XDR_ACTOR`).

```bash
xdr session start --learning-mode --label incident-42
xdr --rationale "token replay from a new ASN" library run ttp_token_theft_replay
xdr annotate "two sign-ins from one ASN; both were the user's VPN"
xdr session end
xdr session feedback <session-id> --source agent --outcome completed-with-friction \
  --category library-discovery --comment "needed three searches to find the replay query"
xdr history stats --operator <initials> --since 30d   # initials prefix your session IDs
```

The tool supplies the evidence; people decide what to change. A recurring
friction category, a repeated error code, or a coverage gap is the starting
point for a new library query, a playbook, or a fix (see
[CONTRIBUTING.md](CONTRIBUTING.md)). The schema graph below improves the same
way, from the hunts you have already run. Details:
[docs/sessions.md](docs/sessions.md).

## Schema discovery and sessions

The schema graph helps you find the same identifiers across differently named
fields and tables. Collection mines saved hunt results first, recovers physical
field origins from their KQL, then validates promising pairs with targeted
queries. Exploration searches for saved identifiers in other cached tables and
nested fields. Shared values establish correlation evidence, not join safety.

```bash
xdr schema status
xdr schema collect --local-only       # mine saved results without tenant queries
xdr schema collect --plan-only        # preview focused validation
xdr schema collect                   # validate promising field pairs
xdr schema collect --explore          # discover additional identifier locations
xdr schema pivot DeviceNetworkEvents.DeviceId
xdr schema path DeviceNetworkEvents DeviceProcessEvents
```

Hunts and investigations automatically start sessions when needed. Explicit
`xdr session end` closes the session and prints its feedback action before
refreshing stale schema, validating saved overlaps, and exploring new locations.
The default exploration budget is five queries and the overall upkeep deadline
is 90 seconds. Automatic session expiry never runs upkeep. Set
`schema_collect_on_session_end = false` to disable all three stages, or use
`xdr session end --no-maintenance` to skip once.

Completed query evidence is reused when collection runs again. Expected scope
exclusions, such as tables without a time column, are reported separately from
unfinished work. Use the receipt's recovery instructions for failures or partial
completion. With no eligible saved identifiers, exploration has no seeds to query.

See [schema graph](docs/schema_graph.md) for evidence thresholds, query budgets,
BloodHound export and portable bundles, and [sessions](docs/sessions.md) for
attachment, feedback, cancellation and the two-record output contract.

## Command reference

| Command | Description |
|---|---|
| `xdr auth login / status / logout` | Interactive sign-in (device-code fallback), status, clear tokens |
| `xdr auth portal-cookie / portal-logout` | Import or remove portal-session credentials for the experimental cookie backend and [device timeline](docs/device_timeline.md) |
| `xdr incidents list / show / update` | List, view (`--expand alerts` adds alerts and their evidence), update status/classification |
| `xdr alerts list / show` | List and view alerts |
| `xdr investigate ID [--auto-enrich]` | Guided investigation of one incident |
| `xdr hunt run KQL` | Ad-hoc advanced hunting (`--from-file`, `--from-stdin`, `--timeout`) |
| `xdr hunt library-show NAME -p k=v` | Render a library query's resolved KQL without running it |
| `xdr library list / show / run` | Browse (`--search`, `--tier`) and run library queries (`-p key=value`, repeatable) |
| `xdr lists init` | Seed `~/.xdr-cli/lists/` reference data used by library queries |
| `xdr device show / isolate / unisolate / scan / restrict / unrestrict / collect-package / action-status` | Device details and response actions |
| `xdr device download-package` | Download an existing investigation ZIP using portal-cookie auth |
| `xdr device timeline DEVICE` | Download a device's portal timeline (unofficial API) |
| `xdr results list / show / head / rows / query / shape / prune` | Browse and manage local result artifacts |
| `xdr schema status` / `xdr schema diagnostics` | Cache-only state of the tenant schema cache and semantic graph; `status` prints the exact `next_command` |
| `xdr schema collect` / `--local-only` / `--explore` | Mine saved results, validate focused pairs, or discover additional identifier locations; rerun to continue |
| `xdr schema discoveries` / `pivot` / `path` | Explain observed and reviewed identifier routes between tables |
| `xdr schema refresh` / `tables` / `show` | Refresh and query the physical table/column cache |
| `xdr schema repair-overlay` / `xdr schema migrate-cache` | Local repair of overlay and cache state (no tenant calls) |
| `xdr schema bundle export` / `xdr schema bundle inspect` / `xdr schema bundle import` | Move schema state between machines as a content-bound archive |
| `xdr schema export-opengraph` | Export the pivot graph for BloodHound — full [guide](docs/schema_graph.md) |
| `xdr schema observe` / `discoveries` / `candidates` | Explicit identifier probes and empirical discovery reports |
| `xdr schema candidate-review` / `candidate-proposal` | Inspect private evidence or draft a non-promoting core proposal |
| `xdr schema correlate` / `prune-evidence` / `validate-core` | Offline artifact correlation, evidence retirement, and packaged graph validation |
| `xdr session start / end / resume / list / show / feedback` | Investigation sessions, learning mode, and append-only feedback — see [Built to improve with use](#built-to-improve-with-use) |
| `xdr history [stats]`, `xdr annotate` | Browse recorded invocations, aggregate failure and coverage metrics, record a lesson |
| `xdr domains list` | Source-labelled Entra and observed AD domains; `--source` selects one inventory |

Global options: `--quiet/-q`, `--no-quiet`, `--no-interactive`, `--debug`,
`--rationale TEXT` (record intent on the session log), `--version/-v`.
Every command has `--help`.

## Configuration

`~/.xdr-cli/config.toml` (created by `xdr auth login`; set `XDR_CLI_HOME` to
relocate the whole directory, e.g. one per tenant):

```toml
tenant_id = "…"
client_id = "…"
auth_mode = "device_code"       # or "client_credentials" (see below)
client_secret = ""
api_timeout = 120               # seconds; raise for heavy hunts
session_timeout_seconds = 1800  # automatic-session inactivity timeout
schema_stale_seconds = 86400    # cached schema is visibly stale after this age
schema_collect_on_session_end = true  # master switch for all session-end schema maintenance
schema_refresh_on_session_end = true  # refresh only if physical cache is missing/stale
schema_explore_on_session_end = true  # discover new locations after focused validation
schema_explore_max_queries = 5        # exploration queries per explicit session end (1-1000)
schema_maintenance_timeout_seconds = 90  # overall foreground upkeep deadline; maximum 3600
schema_collection_stale_seconds = 604800  # nonblocking semantic-collection reminder
default_limit = 25              # incidents/alerts list when --limit is omitted
```

| Path | Purpose |
|---|---|
| `~/.xdr-cli/config.toml` | Configuration (`0600` on POSIX) |
| `~/.xdr-cli/token_cache.json` | MSAL token cache (`0600`) |
| `~/.xdr-cli/portal_cookies.json` | Imported portal session cookies (`0600`) |
| `~/.xdr-cli/audit.log` | Local log of attempted state-changing commands (response actions, incident updates, auth changes, `lists init`, schema repair/import) and `investigate` runs. Written with redacted argv when the command is dispatched, before it runs, so `--dry-run` and declined attempts appear too; `--help` and argument errors do not, and outcomes are not recorded (`0600`) |
| `~/.xdr-cli/lists/*.txt` | Reference lists for library queries |
| `~/.xdr-cli/queries/*.kql` | Your own library queries (see [docs/library.md](docs/library.md)) |
| `~/.xdr-cli/results/YYYY-MM-DD/` | Result artifacts and metadata |
| `~/.xdr-cli/schema/`, `sessions/` | Schema cache; session histories |

Environment: `XDR_CLI_HOME` (config directory), `XDR_SESSION` (attach to a
session), `XDR_ACTOR` (name parallel actors in one session),
`MDE_REFRESH_TOKEN` (device timeline, CI use).

**Service-principal auth.** Set `auth_mode = "client_credentials"` and
`client_secret` in `config.toml`, and give the app registration
*application* permissions with admin consent. The application names match the
table above except `Machine.Read.All` (for `Machine.Read`) and
`AdvancedQuery.Read.All` (for `AdvancedQuery.Read`). Tokens are acquired
automatically; `xdr auth login` is not needed. The `authenticated` field from
`xdr auth status` reports cached delegated-account presence, not whether the
service-principal credentials are valid. It can be false with working app
credentials or true if an earlier delegated account remains cached.

## Troubleshooting

**`xdr auth status` shows `"configured": false`** — run
`xdr auth login --tenant-id <ID> --client-id <ID>` once; the values are saved.

**`NOT_AUTHENTICATED` / `AUTH_LOGIN_REQUIRED`** — run `xdr auth login` again.

**`PERMISSION_MISSING_SCOPE` (exit 7) or `AADSTS65001`** — a permission in
the table above is missing or not consented. In *API permissions*, every row
must show *Granted for &lt;tenant&gt;*. Remember there are two token audiences
(Microsoft Graph and WindowsDefenderATP); consent covers both only if both
sets of permissions are present.

**`AADSTS50011` / redirect URI mismatch** — add `http://localhost` under
*Authentication → Public client/native*.

**Sign-in never completes** — enable *Allow public client flows* on the
registration. On Windows, also check the broker redirect URI from setup
step 1. If no browser or broker can start (for example over SSH), `xdr`
prints a device code instead; enter it in any browser.

**`API_TIMEOUT` (exit 10) on a hunt that works in the portal** — raise the
per-call timeout: `xdr library run <name> --timeout 240`, or set
`api_timeout = 240` in `config.toml`.

**`--param` only kept the first value** — `-p` is repeatable, not
comma-separated: `-p account_upn=alice@corp.com -p mode=detail`.

More in [docs/troubleshooting.md](docs/troubleshooting.md).

## Documentation

| | |
|---|---|
| [AGENTS.md](AGENTS.md) | How an AI agent should drive `xdr` |
| [docs/investigation.md](docs/investigation.md) | Investigation methodology and KQL-writing guidance |
| [playbooks/](playbooks/index.md) | Alert-specific investigation playbooks |
| [docs/library.md](docs/library.md) | The KQL query library: tiers, every query, parameters, custom queries |
| [docs/lists.md](docs/lists.md) | Reference lists (tenant domains, subnets, IOC feeds) used by library queries |
| [docs/sessions.md](docs/sessions.md) | Investigation sessions and feedback |
| [docs/schema_graph.md](docs/schema_graph.md) | Schema cache, semantic pivots, BloodHound export |
| [docs/device_timeline.md](docs/device_timeline.md) | Unofficial device-timeline download and portal auth |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Longer troubleshooting reference |
| [docs/ci.md](docs/ci.md) | What CI checks on every PR |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## Development

```bash
git clone https://github.com/NerfBlasters/m365-xdr-cli.git
cd m365-xdr-cli
uv sync --locked --extra dev
uv run --frozen --extra dev pytest tests/ -q
uv run --frozen --extra dev ruff check src/ tests/
```

`pip install -e ".[dev]"` in a virtualenv works too.

## Contributing and security

Contributions are welcome — read [`CONTRIBUTING.md`](CONTRIBUTING.md)
(branching, commits, versioning, AI-agent guidelines, the don't-commit list)
and the [contributing walkthrough](docs/contributing-walkthrough.md) first.

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md),
not in public issues.

## License

[MIT](LICENSE)
