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

## What it does

- **Incidents and alerts** — list, filter, show (with alerts and their
  evidence), and update status, classification, determination and comments.
- **Guided investigation** — `xdr investigate <id>` pulls the incident,
  extracts devices/users/IPs/hashes, runs the relevant hunting queries, and
  prints suggested next steps with ready-to-run commands.
- **Advanced hunting** — run ad-hoc KQL, or pick from a library of 66 hunting
  queries (process trees, Kerberos delegation abuse, token replay, inbox rules,
  OAuth consent anomalies, lateral movement, ransomware precursors, …) that
  take typed parameters and are escaped before they reach the API. Three are
  marked beta; see [the library reference](docs/library.md).
- **Response actions** — isolate/release, scan, restrict/unrestrict execution,
  collect and download investigation packages, with confirmation, `--dry-run`,
  and a local audit log.
- **Two ways to sign in** — reuse your logged-in Defender portal session
  (minutes to set up, no app registration), or register an Entra app and use
  Microsoft's supported APIs. See [Two ways to sign in](#two-ways-to-sign-in).
- **Built for agents** — compact JSON receipts on stdout, progress on stderr,
  one-line structured errors with a `corrected_argv` hint, and an
  [`AGENTS.md`](AGENTS.md) that tells Claude Code, Copilot CLI, or Codex
  exactly how to drive it.
- **Playbooks** — alert-title → [playbook](playbooks/index.md) mapping for
  common Defender alerts (BEC, forwarding rules, ransomware, AiTM, C2, …).
- **Optional extras** — a schema graph that learns identifier pivots from your
  saved hunts (exportable to BloodHound), local investigation sessions with
  an improvement loop, and an *unofficial* device-timeline download that
  reaches back ~180 days. None of these are needed to work an incident.

## Is it for you?

Use `xdr` if you work incidents in Defender XDR and want to do it from a
shell — because you script, because you pair with an AI agent, or because
clicking through the portal is slower than typing. Nothing leaves your
machine except the API calls to Microsoft, made either with your own browser
session or with your own Entra app registration and delegated permissions.

It is **not** a SIEM, a scheduler, or a replacement for the portal's action
center. Response actions require an explicit command, a comment, and a
confirmation.

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

## Two ways to sign in

| | **Portal cookie** (quick start) | **Entra app registration** |
|---|---|---|
| Setup | Minutes: copy one request from your browser's DevTools | Register an app, add permissions, get admin consent |
| Talks to | The Defender portal's own `apiproxy` interface — **undocumented and unsupported by Microsoft; can break without notice** | Microsoft Graph security and Defender for Endpoint APIs — documented and supported |
| Credential | Your browser session cookie: a bearer credential for *you*, subject to the same expiry, Conditional Access and sign-in-frequency rules as the portal. Renewal is manual (re-import). | MSAL tokens with refresh; or a service principal for automation |
| Covers | Hunting, incidents, alerts, investigate, domains, device show/timeline, every response action, package download | Everything except package download and the AD domain inventory |
| Permissions | Whatever your user already has in the portal (Defender RBAC applies) | Delegated permissions you grant, plus the user's Defender roles |

Start with the portal cookie if you want to try the tool today. Set up the app
registration when you need a supported path, CI/automation, or a team-wide
credential. Both can coexist; `xdr` picks the official backend when its
credentials are present and the cookie otherwise (`--backend` overrides).
Details, limits and error codes: [docs/portal_cookie.md](docs/portal_cookie.md).

## Quick start (portal cookie)

1. Tell `xdr` which tenant you are in. Create `~/.xdr-cli/config.toml` (or
   add the line to an existing one). The Directory (tenant) ID is on the Entra
   admin center's Overview page, and in Defender portal URLs as `tid=`.

   ```toml
   tenant_id = "<TENANT_ID>"
   ```

2. Capture your session, import it, and start investigating:

```bash
# 2. Capture your portal session (tested with Microsoft Edge):
#    - sign in to https://security.microsoft.com and open any device's
#      Timeline tab
#    - open DevTools (F12) > Network, filter for "apiproxy"
#    - right-click the timeline request > Copy > "Copy as cURL (bash)"
#    - save the clipboard to a file, e.g. ~/mde-curl.txt
xdr auth portal-cookie ~/mde-curl.txt      # stores the cookie (0600) and
                                           # shreds the source file
xdr auth status                            # backend: portal-cookie

# 3. Look around.
xdr incidents list --since 7d --severity high
xdr incidents show <ID> --expand alerts    # <ID> is .id from the list

# 4. Investigate one incident end to end.
xdr investigate --auto-enrich <ID>

# 5. Hunt.
xdr hunt run "DeviceProcessEvents | where Timestamp > ago(1d) | where FileName == 'powershell.exe' | take 10"
xdr library list --search kerberos
xdr library run qry_process_tree --param device_name=WS-01
```

Optional: `xdr lists init` copies the reference-list templates the hunting
library reads (internal subnets, known-good signers, tenant domains, …) into
`~/.xdr-cli/lists/`. Generic lists ship with defaults; tenant-specific ones
such as `TenantDomains` start empty. Not needed for `incidents` or
`investigate`.

When a command answers with exit 2 in cookie mode, the session has expired:
capture and import a fresh cookie. `xdr auth logout` deletes the local cookie
only; it does not sign you out of the portal.

Global flags go **before** the subcommand: `xdr --quiet incidents list`,
`xdr --no-interactive investigate 42`, `xdr --backend official hunt run …`.

## Setting up the Entra app registration

`xdr` can instead authenticate as *you* through an app registration in your
tenant, over Microsoft's supported APIs. One registration can be shared by
everyone on the team.

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
   Defender for Endpoint tokens are still issued for the
   `api.securitycenter.microsoft.com` audience even though requests go to
   `api.security.microsoft.com`; that is why these live under
   WindowsDefenderATP rather than Microsoft Graph.

   The minimum for the quick start above is the first three Graph rows plus
   `Machine.Read` (used by `investigate` to enrich devices). Grant only what
   the commands you intend to use need. `device download-package` and the
   Active Directory part of `domains list` have no official API and stay
   cookie-only.

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
6. Sign in. This opens an interactive sign-in (the WAM broker on Windows,
   your browser elsewhere); if neither can start, e.g. on a headless host, it
   prints a device code instead. `tenant_id` and `client_id` are saved to
   `~/.xdr-cli/config.toml`.

   ```bash
   xdr auth login --tenant-id <TENANT_ID> --client-id <CLIENT_ID>
   xdr auth status                            # main.backend: official
   ```

The signed-in user also needs the Defender roles that match what they run
(Security Reader for triage; *Active remediation actions* for device
actions). The app registration cannot grant more than the user has.

If you add a permission after signing in, run `xdr auth logout && xdr auth
login` afterwards. Until then `xdr` keeps using the cached access token
issued before the change, and the new permission fails with
`PERMISSION_MISSING_SCOPE` until that token expires (up to about 90 minutes).

## Reading results

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

## Response actions

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
xdr device download-package <action-id> --device <device-id> --output pkg.zip   # cookie backend
```

`isolate`, `unisolate`, `restrict`, and `unrestrict` require `--comment`.
Every action asks for confirmation unless you pass `--yes`, and refuses to run
non-interactively without it; declining the prompt exits 13. `--dry-run` is
available on all actions except `unisolate`. In cookie mode, device IDs must
be the 40-hex MachineId (or a hostname with exactly one match) and action IDs
must be GUIDs; `action-status` needs `--device` the first time it sees an
action on this machine.

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
- `xdr` prompts only when both stdin and stdout are TTYs; otherwise (or with
  `--no-interactive`) it never prompts. Commands that would ask for
  confirmation (response actions, `incidents update`, `results prune`) refuse
  with exit 6 unless `--yes` is passed. `auth login` and `auth portal-cookie`
  are interactive flows for a human; agents should ask rather than treat
  `--no-interactive` as unattended sign-in.
- Failures before durable output are one JSON error line with a stable `code`
  and `exit_code`; usage errors may include a `corrected_argv` hint.
  Operations the selected backend cannot perform return
  `BACKEND_CAPABILITY_UNAVAILABLE` and never fall back to the other backend.
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

## Optional: sessions and the improvement loop

Every investigation can leave a structured record of how the tool performed,
so gaps show up as data rather than anecdotes. The record stays on your
machine under `~/.xdr-cli/sessions/`; nothing is sent anywhere.

- **Sessions record every command.** `hunt run`, `library run`,
  `investigate`, `incidents show`, `alerts show`, `schema observe` and
  `schema candidate-review` start a session automatically when none is live
  (or start one yourself with `xdr session start --label incident-42`). Each
  invocation becomes one JSONL record with the command and redacted
  arguments, the KQL and tables it touched, the library query and parameters,
  the exit and error code, duration, and row count. Automatic sessions expire
  after 30 minutes of inactivity; you never have to end one.
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

An explicit `xdr session end` also runs bounded schema upkeep against the
tenant (see the next section) — up to 90 seconds by default. Pass
`--no-maintenance` to skip it once, or set `schema_collect_on_session_end =
false` to keep session end offline. Automatic expiry never runs upkeep.

```bash
xdr session start --learning-mode --label incident-42
xdr --rationale "token replay from a new ASN" library run ttp_token_theft_replay
xdr annotate "two sign-ins from one ASN; both were the user's VPN"
xdr session end
xdr session feedback <session-id> --source agent --outcome completed-with-friction \
  --category library-discovery --comment "needed three searches to find the replay query"
xdr history stats --operator <initials> --since 30d   # initials prefix your session IDs
```

Details: [docs/sessions.md](docs/sessions.md).

## Optional: schema graph

You can work incidents without ever running `xdr schema`. The schema graph is
for the moment you hold an identifier — a DeviceId, an account, a SHA-256 —
and want to know which other tables and differently named fields carry it:

```bash
xdr schema pivot DeviceNetworkEvents.DeviceId
xdr schema path DeviceNetworkEvents DeviceProcessEvents
```

It starts from a reviewed graph shipped with the tool and grows from your own
hunts: `xdr schema collect` mines the results you have already saved, recovers
field origins from their KQL, and validates promising pairs with a few
targeted queries; `--explore` searches for saved identifiers in other tables.
Shared values establish *correlation* evidence, never join safety.

```bash
xdr schema status                     # cache-only; prints the exact next_command
xdr schema collect --local-only       # mine saved results without tenant queries
xdr schema collect --plan-only        # preview focused validation
xdr schema collect                    # validate promising field pairs
xdr schema collect --explore          # discover additional identifier locations
xdr schema export-opengraph graph.json --include-tenant   # BloodHound import
```

See the full [guide](docs/schema_graph.md) for evidence thresholds,
query budgets, what session end does, BloodHound export, and portable bundles
(`xdr schema bundle export` / `xdr schema bundle inspect` /
`xdr schema bundle import`).

## Command reference

| Command | Description |
|---|---|
| `xdr auth login / status / logout` | Interactive sign-in for the official backend (device-code fallback), status for both backends, clear the selected backend's credentials |
| `xdr auth portal-cookie SOURCE / portal-logout` | Import (`--verify`, `--keep-source`) or remove a portal-session cookie — see [docs/portal_cookie.md](docs/portal_cookie.md) |
| `xdr incidents list` | `--since`, `--severity`, `--status`, `--assigned-to`, `--limit` |
| `xdr incidents show ID [--expand alerts]` / `update ID` | View (alerts include their evidence); update `--status`, `--classification`, `--determination`, `--comment` (`--dry-run`, `--yes`) |
| `xdr alerts list / show ID` | `--since`, `--severity`, `--service`, `--limit` |
| `xdr investigate ID [--auto-enrich]` | Guided investigation; without `--auto-enrich` it asks which queries to run (all, when non-interactive) |
| `xdr hunt run KQL` | Ad-hoc advanced hunting (`--from-file`, `--from-stdin`, `--timeout`, `--raw`) |
| `xdr hunt library-show NAME -p k=v` | Render a library query's resolved KQL without running it |
| `xdr library list / show NAME / run NAME` | Browse (`--search`, `--tier`) and run library queries (`-p key=value`, repeatable; `--timeout`, `--raw`) |
| `xdr lists init` | Seed `~/.xdr-cli/lists/` reference data used by library queries (`--force --yes` to overwrite) |
| `xdr device show / isolate / unisolate / scan / restrict / unrestrict / collect-package / action-status` | Device details and response actions |
| `xdr device download-package ACTION --device ID --output PATH` | Download a completed investigation ZIP (cookie backend; `--force`, `--max-bytes`) |
| `xdr device timeline DEVICE` | Download a device's portal timeline (unofficial API) — [docs/device_timeline.md](docs/device_timeline.md) |
| `xdr domains list [--source all\|entra\|active-directory]` | Source-labelled Entra and observed AD domains (AD is cookie-only) |
| `xdr results list / show / head / rows / query / shape / prune` | Browse and manage local result artifacts (`rows --type/--offset/--limit`) |
| `xdr schema status` / `xdr schema diagnostics` | Cache-only state of the schema cache and semantic graph; `status` prints the exact `next_command` |
| `xdr schema collect` [`--local-only` \| `--plan-only` \| `--explore`] | Mine saved results, validate focused pairs, or discover additional identifier locations; rerun to continue |
| `xdr schema pivot FIELD` / `xdr schema path A B` / `xdr schema discoveries` | Explain reviewed and empirical identifier routes |
| `xdr schema refresh` / `tables` / `show TABLE` | Refresh and query the physical table/column cache (`--search`) |
| `xdr schema observe` / `candidate-review` / `candidate-proposal` | Explicit identifier probes, private evidence review, non-promoting core proposals |
| `xdr schema export-opengraph PATH` | Export the graph for BloodHound (`--include-tenant`, `--include-candidates`, `--custom-nodes`) |
| `xdr schema bundle export` / `xdr schema bundle inspect` / `xdr schema bundle import` | Move schema state between machines as a content-bound archive |
| `xdr schema repair-overlay` / `xdr schema migrate-cache` / `prune-evidence` / `correlate` / `validate-core` | Local repair, evidence retirement, offline correlation, packaged-graph validation |
| `xdr session start / end / resume / list / show / feedback` | Sessions, learning mode, append-only feedback — see [docs/sessions.md](docs/sessions.md) |
| `xdr history [stats]`, `xdr annotate` | Browse recorded invocations, aggregate failure and coverage metrics, record a lesson |

Global options: `--backend auto|official|portal-cookie`, `--quiet/-q`,
`--no-quiet`, `--no-interactive`, `--debug`, `--rationale TEXT` (record intent
on the session log), `--version/-v`. Every command has `--help`.

## Configuration

`~/.xdr-cli/config.toml` (created by `xdr auth login`, or by hand for the
cookie quick start; set `XDR_CLI_HOME` to relocate the whole directory, e.g.
one per tenant):

```toml
tenant_id = "…"                 # required for both backends
client_id = "…"                 # official backend only
auth_mode = "device_code"       # or "client_credentials" (see below)
client_secret = ""
api_backend = "auto"            # or "official" / "portal-cookie" to pin one
api_timeout = 120               # seconds; raise for heavy hunts
default_limit = 25              # incidents/alerts list when --limit is omitted
session_timeout_seconds = 1800  # automatic-session inactivity timeout
schema_stale_seconds = 86400    # cached schema is visibly stale after this age
schema_collection_stale_seconds = 604800  # nonblocking semantic-collection reminder
schema_collect_on_session_end = true  # master switch for session-end schema upkeep
schema_refresh_on_session_end = true  # refresh only if physical cache is missing/stale
schema_explore_on_session_end = true  # discover new locations after focused validation
schema_explore_max_queries = 5        # exploration queries per explicit session end (1-1000)
schema_maintenance_timeout_seconds = 90  # overall foreground upkeep deadline; maximum 3600
```

Unknown keys produce a warning on stderr.

| Path | Purpose |
|---|---|
| `~/.xdr-cli/` | Config directory (`0700` on POSIX) |
| `~/.xdr-cli/config.toml` | Configuration (`0600`) |
| `~/.xdr-cli/token_cache.json` | MSAL token cache for the official backend (`0600`) |
| `~/.xdr-cli/portal_cookies.json` | Imported portal session cookie (`0600`) |
| `~/.xdr-cli/portal_token_cache.json` | A token cache left by a sign-in flow this release does not offer; `auth portal-logout` deletes it |
| `~/.xdr-cli/action_associations/` | Action ID → device ID pairs (IDs only) learned in cookie mode |
| `~/.xdr-cli/audit.log` | Local log of attempted state-changing commands (response actions, incident updates, auth changes, `lists init`, schema repair/import) and `investigate` runs. Written with redacted argv when the command is dispatched, before it runs, so `--dry-run` and declined attempts appear too; `--help` and argument errors do not, and outcomes are not recorded (`0600`) |
| `~/.xdr-cli/lists/*.txt` | Reference lists for library queries |
| `~/.xdr-cli/queries/*.kql` | Your own library queries (see [docs/library.md](docs/library.md)) |
| `~/.xdr-cli/results/YYYY-MM-DD/` | Result artifacts and metadata |
| `~/.xdr-cli/schema/`, `sessions/` | Schema cache; session histories |

Environment: `XDR_CLI_HOME` (config directory), `XDR_SESSION` (attach to a
session), `XDR_ACTOR` (name parallel actors in one session),
`MDE_REFRESH_TOKEN` (device timeline on the official backend, CI use).

**Service-principal auth.** Set `auth_mode = "client_credentials"` and
`client_secret` in `config.toml`, and give the app registration
*application* permissions with admin consent. The application names match the
table above except `Machine.Read.All` (for `Machine.Read`) and
`AdvancedQuery.Read.All` (for `AdvancedQuery.Read`). Tokens are acquired
automatically; `xdr auth login` is not needed. `xdr auth status` reports
`main.authenticated` from the cached delegated account, not from the
service-principal credentials, so it can be false while app credentials work.

## Troubleshooting

**`xdr auth status` shows `main.configured: false`** — on the official
backend, run `xdr auth login --tenant-id <ID> --client-id <ID>` once; the
values are saved. If you meant to use a cookie, check `tenant_id` is in
`config.toml` and import the cookie with `xdr auth portal-cookie`.

**Exit 2: `NOT_AUTHENTICATED` / `AUTH_LOGIN_REQUIRED`** — official backend:
`xdr auth login` again. Cookie backend: the session expired; capture and
import a fresh cookie.

**`PERMISSION_MISSING_SCOPE` (exit 7) or `AADSTS65001`** — a permission in
the table above is missing or not consented. In *API permissions*, every row
must show *Granted for &lt;tenant&gt;*. Remember there are two token audiences
(Microsoft Graph and WindowsDefenderATP); consent covers both only if both
sets of permissions are present.

**`BACKEND_CAPABILITY_UNAVAILABLE` (exit 3)** — the selected backend cannot
do this (for example `download-package` or AD domains on the official
backend). Nothing was sent; switch with `--backend` or import a cookie.

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
| [docs/portal_cookie.md](docs/portal_cookie.md) | The portal-cookie backend: capture, limits, selection rules, errors |
| [docs/investigation.md](docs/investigation.md) | Investigation methodology and KQL-writing guidance |
| [playbooks/](playbooks/index.md) | Alert-specific investigation playbooks |
| [docs/library.md](docs/library.md) | The KQL query library: tiers, every query, parameters, custom queries |
| [docs/lists.md](docs/lists.md) | Reference lists (tenant domains, subnets, IOC feeds) used by library queries |
| [docs/sessions.md](docs/sessions.md) | Investigation sessions and feedback |
| [docs/schema_graph.md](docs/schema_graph.md) | Schema graph: discovery, session-end upkeep, BloodHound export, bundles |
| [docs/schema_pivots.md](docs/schema_pivots.md) | Generated reference of tables, shared fields and reviewed pivots |
| [docs/device_timeline.md](docs/device_timeline.md) | Unofficial device-timeline download |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Error and exit codes, longer troubleshooting reference |
| [docs/backend_development.md](docs/backend_development.md) | Adding an operation to both API backends (contributors) |
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
