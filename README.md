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

- **Incidents and alerts** — list, filter, show (with alerts and evidence
  expanded), and update status/classification.
- **Guided investigation** — `xdr investigate <id>` pulls the incident,
  extracts devices/users/IPs/hashes, runs the relevant hunting queries, and
  prints suggested next steps with ready-to-run commands.
- **Advanced hunting** — run ad-hoc KQL, or pick from a library of 69 reviewed
  queries (process trees, Kerberoasting, token replay, inbox rules, OAuth
  consent anomalies, lateral movement, ransomware precursors, …) that take
  typed parameters and are escaped before they reach the API.
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
- **Extras for deeper work** — optional investigation sessions with
  append-only feedback, and an *unofficial* device-timeline download that
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
   **Public client/native** redirect URI of `http://localhost`.
2. From **Overview**, copy the **Application (client) ID** and
   **Directory (tenant) ID**.
3. **API permissions → Add a permission.** Add these **delegated** permissions:

   | API | Permission | Used by |
   |---|---|---|
   | Microsoft Graph | `SecurityIncident.ReadWrite.All` | `incidents list/show/update`, `investigate` |
   | Microsoft Graph | `SecurityAlert.Read.All` | `alerts list/show` |
   | Microsoft Graph | `ThreatHunting.Read.All` | `hunt run`, `library run`, `investigate`, `schema` |
   | Microsoft Graph | `Domain.Read.All` | `domains list` |
   | WindowsDefenderATP¹ | `Machine.ReadWrite` ² | `device show`, hostname lookups |
   | WindowsDefenderATP | `Machine.Isolate` | `device isolate` / `unisolate` |
   | WindowsDefenderATP | `Machine.Scan` | `device scan` |
   | WindowsDefenderATP | `Machine.CollectForensics` | `device collect-package` |
   | WindowsDefenderATP | `Machine.RestrictExecution` | `device restrict` |

   ¹ Under **APIs my organization uses**, search for *WindowsDefenderATP*.
   Defender for Endpoint tokens are still issued for the legacy
   `api.securitycenter.microsoft.com` audience even though requests go to
   `api.security.microsoft.com`; that is why these live under
   WindowsDefenderATP rather than Microsoft Graph.
   ² Microsoft's [Get machine](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-by-id)
   reference lists `Machine.ReadWrite` for the by-ID lookup used by `device show`.
   [List machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines)
   also accepts `Machine.Read` for hostname lookups. Grant only the permissions
   needed by the commands you intend to use.

   Hunting goes through Microsoft Graph. The legacy Defender for Endpoint
   hunting API (`AdvancedQuery.Read`) is only used as a fallback and is being
   [retired by Microsoft](https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api);
   configure [Graph hunting](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0)
   for new deployments.
4. **Grant admin consent** for your tenant (Global Admin or Security Admin).
5. **Authentication → Advanced settings → Allow public client flows → Yes.**

The signed-in user also needs the Defender roles that match what they run
(Security Reader for triage; *Active remediation actions* for device
actions). The app registration cannot grant more than the user has.

## Quick start

```bash
# 1. Sign in. Opens an interactive sign-in (Windows Hello/WAM on Windows,
#    your browser elsewhere) and falls back to a device code if it can't.
#    tenant_id and client_id are saved to ~/.xdr-cli/config.toml.
xdr auth login --tenant-id <TENANT_ID> --client-id <CLIENT_ID>
xdr auth status

# 2. Seed the reference lists the hunting library uses (internal subnets,
#    known-good signers, tenant domains, …). Edit ~/.xdr-cli/lists/*.txt later.
xdr lists init

# 3. Look around.
xdr incidents list --since 7d --severity high
xdr incidents show 42 --expand alerts --expand evidence
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
{"status":"success","run_id":"20261004T015710757111Z-41a96c5113e3","data_path":"/home/me/.xdr-cli/results/2026-10-04/20261004T015710757111Z-41a96c5113e3.jsonl","meta_path":"/home/me/.xdr-cli/results/2026-10-04/20261004T015710757111Z-41a96c5113e3.meta.json","rows":2,"server_truncation_state":"unknown","context":{"shown":2,"total":2,"has_more":false}}
{"id":"2","severity":"high","status":"active","displayName":"Multi-stage incident involving Credential access & Lateral movement on multiple endpoints"}
{"id":"1","severity":"high","status":"active","displayName":"'Ceprolad' detected on one endpoint"}
```

Work with the artifact using whatever you already use — `jq`, `rg`, Python —
or the built-in `xdr results` commands:

```bash
jq -r 'select(.record_type=="alert") | "\(.severity)\t\(.title)"' "$DATA_PATH"
xdr results shape <run-id>            # which fields exist, with types and counts
xdr results rows <run-id> --type entity
xdr results query <run-id>            # the exact KQL that produced it
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
- Confirmation prompts are skipped automatically when stdin/stdout isn't a TTY;
  `--no-interactive` forces that. Response actions then require `--yes`.
  `auth login` is a separate interactive flow: agents should ask a human to
  perform it, rather than treating `--no-interactive` as unattended login.
- Failures before durable output are one JSON error line with a stable `code`
  and `exit_code`; usage errors may include a `corrected_argv` hint.
- Explicit `session end` emits a closure record with feedback instructions,
  then a maintenance record. Upkeep can return exit 14 after the session is
  safely closed; cancellation returns 130. Do not retry the session end.
- Exit codes: 0 ok · 2 auth · 3 upstream API · 6 usage · 7 permission ·
  8 not found · 9 rate-limited · 10 timeout · 14 partial success.

```bash
# In a Claude Code / Copilot CLI / Codex prompt:
"Use xdr-cli to investigate incident 4421: run `xdr investigate --auto-enrich 4421`,
read the receipt's data_path, and summarise the alerts, entities, and recommended
actions. Do not run any `xdr device` command without asking me."
```

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
| `xdr auth portal-cookie / portal-login / portal-logout` | Portal-session auth for the unofficial [device timeline](docs/device_timeline.md) |
| `xdr incidents list / show / update` | List, view (`--expand alerts --expand evidence`), update status/classification |
| `xdr alerts list / show` | List and view alerts |
| `xdr investigate ID [--auto-enrich]` | Guided investigation of one incident |
| `xdr hunt run KQL` | Ad-hoc advanced hunting (`--from-file`, `--from-stdin`, `--timeout`) |
| `xdr hunt library-show NAME -p k=v` | Render a library query's resolved KQL without running it |
| `xdr library list / show / run` | Browse (`--search`, `--tier`) and run library queries (`-p key=value`, repeatable) |
| `xdr lists init` | Seed `~/.xdr-cli/lists/` reference data used by library queries |
| `xdr device show / isolate / unisolate / scan / restrict / collect-package / action-status` | Device details and response actions |
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
| `xdr session start / end / resume / list / show / feedback` | Optional investigation sessions — see [docs/sessions.md](docs/sessions.md) |
| `xdr history [stats]`, `xdr annotate` | Browse and annotate recorded invocations |
| `xdr domains list` | List the tenant's verified domains |

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
default_limit = 25
```

| Path | Purpose |
|---|---|
| `~/.xdr-cli/config.toml` | Configuration (`0600` on POSIX) |
| `~/.xdr-cli/token_cache.json` | MSAL token cache (`0600`) |
| `~/.xdr-cli/portal_cookies.json` | Imported portal session cookies (`0600`) |
| `~/.xdr-cli/audit.log` | Local log of response actions, incident updates, auth changes, and `investigate` runs (raw argv; `0600`) |
| `~/.xdr-cli/lists/*.txt` | Reference lists for library queries |
| `~/.xdr-cli/queries/*.kql` | Your own library queries (see [docs/library.md](docs/library.md)) |
| `~/.xdr-cli/results/YYYY-MM-DD/` | Result artifacts and metadata |
| `~/.xdr-cli/schema/`, `sessions/` | Schema cache; session histories |

Environment: `XDR_CLI_HOME` (config directory), `XDR_SESSION` (attach to a
session), `XDR_ACTOR` (name parallel actors in one session),
`MDE_REFRESH_TOKEN` (device timeline, CI use).

**Service-principal auth.** Set `auth_mode = "client_credentials"` and
`client_secret` in `config.toml`, and give the app registration
*application* permissions with admin consent. Tokens are acquired
automatically; `xdr auth login` is not needed. The `authenticated` field from
`xdr auth status` reports cached delegated-account presence, not whether the
service-principal credentials are valid. It can be false with working app
credentials or true if an earlier delegated account remains cached.

## Troubleshooting

**`xdr auth status` shows `"configured": false`** — run
`xdr auth login --tenant-id <ID> --client-id <ID>` once; the values are saved.

**`NOT_AUTHENTICATED` / `TOKEN_EXPIRED`** — run `xdr auth login` again.

**`PERMISSION_MISSING_SCOPE` (exit 7) or `AADSTS65001`** — a permission in
the table above is missing or not consented. In *API permissions*, every row
must show *Granted for &lt;tenant&gt;*. Remember there are two token audiences
(Microsoft Graph and WindowsDefenderATP); consent covers both only if both
sets of permissions are present.

**`AADSTS50011` / redirect URI mismatch** — add `http://localhost` under
*Authentication → Public client/native*.

**Sign-in never completes** — enable *Allow public client flows* on the
registration. If the interactive sign-in can't open a browser, `xdr` falls
back to a device code; copy it to any browser.

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
