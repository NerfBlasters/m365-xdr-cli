# xdr-cli

**Microsoft 365 Defender XDR investigation CLI -- for humans and AI agents.**

A command-line tool for security analysts and AI agents to investigate incidents, hunt threats, and take response actions against the Microsoft 365 Defender / Microsoft Defender XDR APIs. Large reads save complete private JSONL artifacts and return tiny receipts; progress stays on stderr.

## Features

- **Incident management** -- list, view, and update security incidents
- **Alert triage** -- list and inspect security alerts with OData filtering
- **Advanced hunting** -- run arbitrary KQL queries and use a built-in query library
- **Device response** -- isolate, unisolate, scan, collect investigation packages
- **Guided investigation** -- automated entity extraction, enrichment, and action suggestions
- **Semantic schema graph** -- reviewed cross-table pivots, bounded tenant learning, compatibility-safe local growth, diagnostics, and portable same-tenant state bundles
- **Device timeline (unofficial)** -- paginated download of Defender for Endpoint device timeline events for up to ~180 days of history, beyond Advanced Hunting's 30-day window. Uses an unofficial `security.microsoft.com/apiproxy` endpoint, authenticated via your existing portal browser session (cookie auth — the validated path; an experimental, unverified MSAL/FOCI sign-in also exists). Subject to break without notice.
- **AI-agent friendly** -- artifact-first JSONL, corrective one-line errors, native discovery
- **Audit logging** -- all write/action commands are logged to `~/.xdr-cli/audit.log`

## Prerequisites

- Python 3.11+
- A Microsoft Entra ID (Azure AD) app registration with the required API permissions
- A Microsoft 365 Defender tenant

## Installation

### Windows (PowerShell) — pipx install

Recommended for end users and for agent-driven invocations (Claude Code, Copilot CLI, Codex) on Windows. `pipx` gives `xdr` its own isolated venv and puts the `xdr.exe` shim on your user PATH so every new PowerShell session can find it — including subprocesses spawned by agents.

```powershell
# 1. Install pipx (one-time)
python -m pip install --user pipx

# 2. Add pipx shim directory to user PATH (persistent)
python -m pipx ensurepath

# 3. Refresh PATH in the current session so pipx is visible without reopening
$env:Path = [Environment]::GetEnvironmentVariable("Path","User") + ";" + [Environment]::GetEnvironmentVariable("Path","Machine")

# 4. Clone and install xdr-cli
git clone https://github.com/NerfBlasters/m365-xdr-cli.git
cd m365-xdr-cli
pipx install .

# 5. Verify
xdr --version
xdr --help
```

If you prefer not to keep a local clone, step 4 can be replaced with a direct git install:

```powershell
pipx install "git+https://github.com/NerfBlasters/m365-xdr-cli.git"
```

### Updating (Windows)

When new commits land on the branch you installed from:

```powershell
cd C:\path\to\m365-xdr-cli
git pull
pipx reinstall xdr-cli
```

For a direct-from-git install (no local clone), use `pipx upgrade xdr-cli` instead — or `pipx reinstall xdr-cli` to force a rebuild.

### Linux / macOS — development install

```bash
# Clone and install in development mode
git clone https://github.com/NerfBlasters/m365-xdr-cli.git
cd m365-xdr-cli
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

After installation, the `xdr` command is available:

```bash
xdr --version
xdr --help
```

## Entra ID App Registration

To use xdr-cli, you need an app registration in Microsoft Entra ID with the correct API permissions.

### Step 1: Create the App Registration

1. Go to [Azure Portal](https://portal.azure.com) > **Microsoft Entra ID** > **App registrations** > **New registration**
2. Name: `xdr-cli` (or any name you prefer)
3. Supported account types: **Single tenant**
4. Redirect URI: **Public client/native** > `http://localhost`
5. Click **Register**

### Step 2: Note the IDs

From the app's Overview page, copy:
- **Application (client) ID** -- this is your `client_id`
- **Directory (tenant) ID** -- this is your `tenant_id`

### Step 3: Configure API Permissions

Go to **API permissions** > **Add a permission** > **Microsoft Graph**:

| Permission | Type | Purpose |
|---|---|---|
| `SecurityIncident.ReadWrite.All` | Delegated | List/view/update incidents |
| `SecurityAlert.ReadWrite.All` | Delegated | List/view alerts |
| `ThreatHunting.Read.All` | Delegated | Run advanced hunting queries |

Then add **APIs my organization uses** > search for **WindowsDefenderATP**:

| Permission | Type | Purpose |
|---|---|---|
| `Machine.Isolate` | Delegated | Isolate/unisolate devices |
| `Machine.Scan` | Delegated | Run AV scans |
| `Machine.CollectForensics` | Delegated | Collect investigation packages |
| `Machine.RestrictExecution` | Delegated | Restrict code execution |
| `Machine.Read.All` | Delegated | View device details |
| `AdvancedQuery.Read.All` | Delegated | Advanced hunting queries |

### Step 4: Grant Admin Consent

Click **Grant admin consent for [your tenant]** (requires Global Admin or Security Admin role).

### Step 5: Enable Public Client Flow

Go to **Authentication** > scroll to **Advanced settings** > set **Allow public client flows** to **Yes** > **Save**.

## Quick Start

> **Flag ordering:** Global flags (`--quiet`, `--debug`,
> `--no-interactive`) come before the subcommand. `--fields` and native
> `--jq`/JMESPath were removed in 0.7.0.

### Login

```bash
# Interactive device-code login — saves tenant_id/client_id to ~/.xdr-cli/config.toml
xdr auth login --tenant-id YOUR_TENANT_ID --client-id YOUR_CLIENT_ID
```

Follow the device code prompt to authenticate in your browser. Credentials are cached at `~/.xdr-cli/token_cache.json`.

### Check Auth Status

```bash
xdr auth status
xdr --quiet auth status
```

### List Incidents

```bash
# Recent high-severity incidents
xdr incidents list --severity high --since 7d

# Full rows are saved as JSONL; stdout returns a receipt plus two previews
xdr incidents list --severity high --since 24h

# Inspect/filter the receipt's data_path
rg -i 'high' /path/from/receipt.jsonl
jq -s 'map({id, displayName, severity})' <result.jsonl>
```

### View an Incident

```bash
xdr incidents show 42

# Expand alerts and evidence for deeper triage
xdr incidents show 42 --expand alerts --expand evidence
```

### Update an Incident

```bash
# Preview (no write)
xdr incidents update 42 --status resolved --classification truePositive --determination malware --dry-run

# Apply (requires confirmation unless --yes)
xdr incidents update 42 --status resolved --classification truePositive --determination malware --yes
```

### Run a Hunt Query

```bash
# Inline KQL
xdr hunt run "DeviceProcessEvents | where FileName == 'powershell.exe' | take 10"

# Discover and run the built-in library
xdr library list --search powershell
xdr library show qry_process_tree
xdr library run ttp_encoded_powershell
xdr library run qry_process_tree --param device_name=WS-01
```

Library string parameters are escaped as KQL literal data; typed duration,
integer, datetime, and enum parameters are validated before a query is sent.
Custom-query string placeholders must appear inside an ordinary quoted KQL
string literal.

### Device Actions

```bash
# View device details
xdr device show DEVICE_ID

# Isolate a device (requires confirmation; add --dry-run to preview)
xdr device isolate DEVICE_ID --comment "Incident response" --yes

# Release isolation
xdr device unisolate DEVICE_ID --comment "Remediated" --yes

# Run antivirus scan
xdr device scan DEVICE_ID --scan-type Full --comment "Post-incident"

# Restrict code execution to Microsoft-signed binaries
xdr device restrict DEVICE_ID --comment "Suspicious activity" --yes

# Collect a forensic investigation package
xdr device collect-package DEVICE_ID --comment "Evidence capture" --yes

# Check action status
xdr device action-status ACTION_ID
```

### Guided Investigation

```bash
# Auto-enrich with all relevant hunting queries (artifact-first report)
xdr investigate --auto-enrich 4421

# Interactive mode (human-friendly prompts)
xdr investigate 4421
```

The investigate command saves its complete normalized report at the receipt's
`data_path` and returns at most two preview records. It:
1. Fetches the incident, expanding alerts (evidence is not separately expanded by `investigate`, unlike `incidents show --expand evidence`)
2. Extracts entities (devices, users, file hashes, IPs)
3. Suggests and runs relevant KQL queries from the library
4. Outputs a comprehensive report with suggested containment actions

## Device Timeline

`xdr device timeline` downloads a device's Defender for Endpoint timeline —
the same event stream shown on a device's page in the Defender portal.
**This is an unofficial API integration.** It is not part of the documented
Microsoft Defender for Endpoint API, has no SLA, and can break without
notice.

### Why this exists

Advanced Hunting (`xdr hunt run`) only retains ~30 days of raw event data.
The Defender portal's device timeline retains roughly **~180 days**. When an
investigation needs to establish first-seen/earliest-activity beyond what
`hunt run` can see, `device timeline` reaches back further by talking to the
same unofficial `security.microsoft.com/apiproxy/mtp/mdeTimelineExperience`
endpoint the portal UI itself uses. Use `--hours` for a narrow window on busy
devices or `--days` for longer lookbacks; the resolved window may be at most
180 days, and anything larger is rejected before any request is made.

### Audit attribution by auth method

The timeline endpoint requires portal session credentials, which xdr-cli can
obtain two ways. They differ in what they *should* produce in your Entra
sign-in logs — but this attribution has **not been independently verified**,
so confirm it in your own tenant before relying on it:

- **`xdr auth portal-cookie` (cookie) — the validated method.** Reuses your
  *existing* logged-in security.microsoft.com browser session (paste the
  `sccauth`/`xsrf-token` `Cookie` header via **Microsoft Edge**'s DevTools
  "Copy as cURL (bash)" of the timeline apiproxy request). Because it rides a session you already
  established in a browser, it should not mint a new token or create new
  sign-in events.
- **`xdr auth portal-login` (MSAL/FOCI) — experimental, unverified.** Attempts
  an interactive sign-in with the Microsoft Azure CLI FOCI client ID via a
  *separate* MSAL instance, isolated from xdr-cli's own app registration. It
  may not succeed in every tenant. If it does, the sign-in is *expected* to be
  attributed to **"Microsoft Azure CLI"** (the FOCI client), not "xdr-cli" — by
  design — but this has not been confirmed.

`xdr auth status` reports which method is active and its `audit_app_name`
label. Treat that label as the *intended* attribution, not a verified fact
about how the activity appears in your logs.

### Three auth paths

1. **`xdr auth portal-cookie COOKIE_SOURCE`** (recommended — the validated
   path) — reuses your existing logged-in security.microsoft.com browser
   session. It takes the **whole** browser Cookie header from a file (or `-`
   for stdin) and stores it in `~/.xdr-cli/portal_cookies.json` (mode `0600`
   on POSIX; protected by the user-profile ACL on Windows). The store is bound
   to a non-reversible fingerprint of the configured tenant. Legacy unbound or
   different-tenant stores are rejected; re-run `portal-cookie` after selecting
   the intended tenant to migrate them.

   The apiproxy backend needs more than `sccauth`/`xsrf-token`: it also relies
   on the routing cookie `X-PortalEndpoint-RouteKey` (pins the request to your
   tenant's regional backend) and the session cookie `s.SessID`. Omit those and
   the backend answers with an **opaque HTTP 500** — which is why the whole
   header is required, not just a couple of cookies. To capture it, in
   **Microsoft Edge** (logged in to security.microsoft.com) open DevTools →
   **Network**, right-click the timeline **apiproxy** request → **Copy** →
   **Copy as cURL (bash)**, save it, and run (only Edge + the *bash* cURL
   variant is tested — Chrome/Firefox and the cmd/PowerShell variants are
   unverified):

   ```bash
   xdr auth portal-cookie mde-curl.txt          # a saved "Copy as cURL (bash)" or Cookie header
   pbpaste | xdr auth portal-cookie -            # or pipe it in via stdin
   ```

   xdr extracts the full `Cookie` header, forwards it verbatim (chunked
   `sccauth` — `chunks:N` + `sccauthC1…N` — included), and auto-extracts the
   XSRF token (you're prompted for it only if the header carries no
   `XSRF-TOKEN` cookie). A file is required rather than a paste prompt because
   the header runs past the ~4 KB a terminal will accept on one line.

   On a successful import, xdr makes a best-effort overwrite and deletion of
   the regular source file it validated (it holds a live session bearer
   credential) — pass `--keep-source` to keep it. Symlinks are rejected and
   file identity is rechecked before overwrite; a detected mismatch stops
   cleanup and warns you to remove the original capture manually. A source containing
   no `sccauth` cookie is rejected and left untouched (nothing is stored).
2. **`xdr auth portal-login`** (experimental, unverified) — an interactive
   MSAL sign-in (browser or device code) using the Microsoft Azure CLI FOCI
   client. It may not complete in every tenant, and its Entra sign-in-log
   attribution is unconfirmed — prefer cookie auth (above).
3. **`--refresh-token`** (env `MDE_REFRESH_TOKEN`) — for CI/non-interactive
   use: redeems a pre-obtained FOCI refresh token instead of stored portal
   auth.

**Cookie secrets are never passed as `device timeline` flags.** They're
entered only via `portal-cookie`'s hidden prompts and stored in
`~/.xdr-cli/portal_cookies.json` — never as a command-line argument.

**`--refresh-token` *can* be passed as a flag**, but prefer the
`MDE_REFRESH_TOKEN` environment variable instead. A value passed as
`--refresh-token` lands in shell history and is visible to anyone who can
run `ps` while the command is executing; the environment variable avoids
both. The flag form is also captured by session recording (its value is
redacted before being written to the session JSONL, but the flag itself is
still best avoided) — another reason to prefer `MDE_REFRESH_TOKEN`.

### Quick start

```bash
xdr auth portal-cookie mde-curl.txt
xdr device timeline my-workstation --hours 3
xdr device timeline my-workstation --days 30 --output timeline.jsonl
```

`--hours` and `--days` are mutually exclusive. When neither `--from`,
`--hours`, nor `--days` is supplied, the default lookback is seven days.

`device timeline` resolves `<hostname-or-MachineId>` to a MachineId using
the *official* MDE `machines` API (your normal `xdr auth login` credentials)
before switching to the portal apiproxy client for the timeline events
themselves — only the timeline fetch itself touches the unofficial API. With
stored cookie auth, even a supplied 40-hex MachineId is verified through the
configured official tenant before portal data is accepted.

With no `--output`, the complete stream is atomically registered under
`~/.xdr-cli/results/` and stdout is a receipt plus at most two preview rows.
Explicit `--output PATH` (optionally `--gzip`) preserves direct raw-JSONL
compatibility. It writes through an owner-only temporary file and publishes
atomically while keeping the original staging descriptor open, refusing an
existing path by default. Non-sticky group/world-writable output directories
are rejected; owner-only directories and sticky temporary directories are
supported. Add `--force` to replace an existing path; a symlink entry is
replaced rather than followed. A failed download leaves no partial destination.
A one-line event-count summary is printed to stderr.

### Identifiers & Advanced Hunting cross-reference

The `device` argument is either a **`DeviceName`** (hostname) or a 40-hex
**`DeviceId`** (MachineId). A hostname is resolved to its MachineId via the
official MDE `machines` API. A 40-hex value is normally used directly; stored
cookie auth verifies it through the configured official tenant first.

**The portal timeline's `MachineId` is the same identifier as Advanced
Hunting's `DeviceId`** (verified against live tenant data), and the hostname
is Advanced Hunting's `DeviceName`. So a `device timeline` run pivots cleanly
into Advanced Hunting on `DeviceId`. Each streamed event also carries this
pair under `Machine`:

| Timeline field | Advanced Hunting column | Meaning |
|---|---|---|
| `Machine.MachineId` (and the `device` you pass, once resolved) | `DeviceId` | 40-hex device identifier |
| `Machine.Name` | `DeviceName` | FQDN / hostname (case-insensitive) |
| `Machine.Domain` | (host domain suffix) | AD domain of the host |

The same `DeviceId` + `DeviceName` pair keys every `Device*` Advanced Hunting
table, so you can cross-reference a timeline against structured hunt data:
`DeviceInfo`, `DeviceEvents`, `DeviceFileCertificateInfo`, `DeviceFileEvents`,
`DeviceImageLoadEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`,
`DeviceNetworkInfo`, `DeviceProcessEvents`, `DeviceRegistryEvents`,
`DeviceTvmInfoGathering`, and `DeviceTvmSecureConfigurationAssessment`.

Pivot predicate (swap in any `Device*` table, e.g. via `xdr hunt run`):

```kusto
let hostname  = 'workstation-01.contoso.com';
let device_id = '0000000000000000000000000000000000000000';  // the timeline MachineId
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceId == device_id and DeviceName =~ hostname
| summarize Records = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
```

### Operational caveats

- **Unofficial and unstable.** This endpoint is not documented by Microsoft
  and is not covered by any support agreement. It can change shape or
  disappear without warning.
- **Rate limits apply.** Large windows against busy devices can hit portal-side
  throttling; use `--hours` where practical. Page size is tunable via
  `--page-size` (default 1000, max 1000) if you need to retune request cadence.
- **Coordinate with your SOC before relying on this in production.** The
  combination of "Microsoft Azure CLI" client + a non-browser (Python)
  user agent is a pattern some detection content specifically flags as
  suspicious. Loop in whoever tunes your Entra/Defender detections before
  running this against a real tenant, especially at scale.
- **Check your organization's policy on first-party-app impersonation.**
  Authenticating as the Azure CLI's own client ID to reach an API it wasn't
  built for is exactly what "impersonating a first-party Microsoft app" — a
  practice some organizations explicitly forbid — means. If in doubt, use
  `portal-cookie` instead, or don't use this feature.

## AI Agent Integration

xdr-cli is designed for AI agents and shell tooling. There is no `--json`
flag.

### Artifact-first results

Successful potentially large reads emit at most three compact JSON lines:

```json
{"status":"success","run_id":"...","data_path":"/.../run.jsonl","meta_path":"/.../run.meta.json","rows":247,"server_truncation_state":"unknown","context":{"shown":2,"total":247,"has_more":true,"results_command":"xdr results rows RUN_ID --offset 0 --limit 100","next_command":"xdr results rows RUN_ID --offset 0 --limit 100"}}
{"Timestamp":"...","DeviceName":"host1"}
{"Timestamp":"...","DeviceName":"host2"}
```

The JSONL has one complete object per physical line and no metadata header.
Expanded incident/alert/investigate payloads are split into typed records so a
grep match does not print the entire nested investigation. `xdr results show`
returns bounded provenance, `query` returns the exact KQL, and `shape` supports
`--search` plus a bounded `--limit`; `head` explicitly prints up to 100 private
rows for local review. The full sidecar remains at `meta_path`.
Treat the previews as previews: every receipt reports `shown`, `total`, and
`has_more`; follow its exact `results_command` for the complete local artifact.
`next_command` may instead identify the next action in a multi-step workflow.
Many compact control-plane commands retain JSON envelopes. Lifecycle and raw
rendering commands are deliberate exceptions: `session start`/`resume` return
a bare ID, `session end`/`feedback` return compact status objects, `annotate`
returns plain text, `session show` emits raw session JSONL, and `results query`
emits raw KQL.

Artifacts are never deleted automatically. Browse them with the `xdr results`
`list`/`show`/`head`/`query`/`shape` commands; delete old bundles only with an explicit
whole-day threshold and confirmation:

```bash
xdr results prune --older-than 30 --yes
```

Schema-observation and candidate-review bundles referenced by a tenant overlay,
plus evidence referenced by a live candidate-proposal draft, are protected.
Retire overlay references with `xdr schema prune-evidence --older-than 30 --yes`
and delete merged or abandoned proposal drafts when they are no longer needed.

Run `xdr results list` first when you need to review candidate bundles.

### Automatic sessions and feedback

Sessions are optional local telemetry and never gate an investigation.
`hunt run`, `library run`, `schema observe`, `schema candidate-review`,
`investigate`, and alert/incident `show`
automatically create a session when none exists. Other commands can attach to
one unambiguous live session but do not create one. Automatic sessions expire
after `session_timeout_seconds` of inactivity (30 minutes by default).

Use `xdr session start --concurrent` only for deliberate parallel work. When
multiple sessions remain and no incident/alert anchor matches, the command
runs unattached and prints exact POSIX and PowerShell attachment syntax.
`xdr session end` closes the session first, then returns a structured
`next_action` for append-only agent feedback. Analyst feedback can be appended
later as a separate `--source analyst` record; it never replaces prior
feedback. See
[`docs/sessions.md`](docs/sessions.md) for the complete contract.

### Stderr and Progress

Progress messages and warnings go to **stderr**. Errors before durable output
are exactly one compact JSON line on stdout with a stable code, exit class, and
corrective fields. Partial success (exit 14) emits the durable receipt/previews
first, then a final structured error naming failed suboperations. Do not use
`2>&1`.

Stderr is auto-silenced when stdout is piped. Pass `--quiet` to silence explicitly (e.g., when stderr is also piped elsewhere) or `--no-quiet` to force progress visible even when piped.

### Non-Interactive Mode

Interactive prompts are auto-skipped when stdin or stdout is not a TTY. You can force non-interactive mode with `--no-interactive`. Destructive device-action commands (`isolate`, `unisolate`, `restrict`, `scan`, `collect-package`) require `--yes` to execute without prompting.

### Shell-native filtering

```bash
rg -i 'host01' <result.jsonl>
jq -s 'sort_by(.Timestamp) | reverse | .[:20]' <result.jsonl>
xdr results shape <run-id>
```

### Example: Claude Code Integration

```
# In a Claude Code prompt:
"Use xdr-cli to investigate incident 4421. Run: xdr investigate --auto-enrich 4421
Then parse the receipt's data_path, analyze the normalized JSONL records, and
suggest remediation steps."
```

### Example: Scripting Pattern

```bash
# Get high-severity incident IDs, then enrich each. jq consumes every compact
# stdout line before selecting the first (receipt), avoiding a broken pipe.
receipt=$(xdr incidents list --severity high --since 24h | jq -cs '.[0]')
path=$(printf '%s' "$receipt" | jq -r '.data_path')
jq -r '.id' "$path" | while read -r id; do
  xdr investigate "$id"
done
```

## Semantic Schema Graph Workflow

The physical schema cache records which tables and columns exist in the current
tenant. The semantic graph records reviewed identifier meaning, safe pivot
workflows, and tenant-local empirical observations. Matching names or values do
not automatically make two fields safe to join.

Start with cache-only status and run its exact `context.next_command`:

```bash
xdr schema status

# Existing state may require one or both local upgrades first:
xdr schema repair-overlay --yes
xdr schema migrate-cache --yes

# Preview without tenant calls, then run bounded automatic collection:
xdr schema collect --plan-only
xdr schema collect

# Inspect automatic evidence decisions and usable routes:
xdr schema discoveries
xdr schema pivot DeviceNetworkEvents.DeviceId
xdr schema path DeviceNetworkEvents DeviceProcessEvents
```

`schema collect` refreshes physical availability across the probe's curated
80-table catalog (limited to the tables this tenant exposes). Its six default
entries are reviewed source identifiers, not a six-table target allowlist:
each source can test eligible string/dynamic locators across every cached table
with `Timestamp` or `TimeGenerated`. That time column only bounds each table's
independent lookback; identifier values—not timestamps—are matched across
tables. Routine collection caps that fan-out at 40 prioritized targets per
source; `--plan-only --exhaustive` previews the full eligible target catalog
and `--exhaustive` runs it. Compatible fields on one table share a bounded
table scan. Long runs checkpoint between query pages, continue automatically,
and can be restarted with `xdr schema collect --resume collect-…`. The first
post-refresh page and every continuation are pinned to one physical generation;
resumed/imported checkpoints accept only the bounded read-only schema workflow.
A failing target table is quarantined with an exact narrow retry while other
tables continue.

Concrete evidence stays in private result artifacts, while only value-free
aggregate observations enter the tenant overlay. One completed positive match
becomes an `observed` correlation-only investigation pivot. Repeated,
independent, artifact-verified sampled evidence can automatically become
`validated`. Both are usable pivots by default and both remain
`join_safe=false`; only an independently reviewed contract can establish a raw
join. Tenant-provisional interpretations never seed another fan-out.
`repair-overlay`, `migrate-cache`, `diagnostics`, every `bundle` command, and
`collect --plan-only` are cache-only; ordinary `collect` and `observe` are the
tenant-calling operations.

Export the current value-free graph for BloodHound OpenGraph, including local
tenant growth and candidate routes:

```bash
xdr schema export-opengraph current-schema.opengraph.json \
  --include-tenant \
  --include-candidates
```

Upload the JSON through BloodHound's **Quick Upload**, then run a custom query
under **Explore → Cypher**. A generic import is merged into the graph database;
it does not appear as a named graph or saved query in Explore. Node Object IDs
lead with readable schema names so the canvas remains legible. The detailed
[semantic schema graph guide](docs/schema_graph.md) includes prerequisites,
starter Cypher queries, layer/flag behavior, one-time migration from opaque
pre-0.8.1 IDs, and the generic-graph limitations.

Move accumulated state, crawl checkpoints, and their referenced evidence with
a content-bound archive:

```bash
xdr schema bundle export /mnt/transfer/schema-state.tar.gz
xdr schema bundle inspect /mnt/transfer/schema-state.tar.gz
xdr schema bundle import /mnt/transfer/schema-state.tar.gz --yes
```

Inspection is always read-only, including for foreign tenants. Activation
requires an exact tenant-fingerprint match and a collision-free destination;
credentials, configuration, cookies, locks, active-session markers, and audit
logs are never included and are rejected if injected into an archive. Inspection
streams a strict portable-member allowlist and rejects archives above 256 MiB
uncompressed. Import permits persisted tenant-local relationships only as candidates,
validates session history, refuses collisions without relying on hard-link
support, and coordinates imported session IDs with local counters. Exported
archives are owner-only on POSIX and failed validation leaves no published
output. SHA-256 and tenant fingerprints prove integrity and routing—not archive
authorship—so import only from a trusted source. See the detailed [semantic
schema graph guide](docs/schema_graph.md) for state definitions, recovery
behavior, collection bounds, automatic evidence policy, bundle contents, and import
guarantees.

## Command Reference

| Command | Description |
|---|---|
| `xdr auth login` | Authenticate interactively (WAM/browser) with device code fallback |
| `xdr auth status` | Show current authentication status (main + portal) |
| `xdr auth logout` | Clear cached credentials |
| `xdr auth portal-login` | Authenticate to the unofficial Defender portal API (MSAL) |
| `xdr auth portal-cookie` | Authenticate to the unofficial Defender portal API via browser cookies |
| `xdr auth portal-logout` | Clear cached portal credentials (MSAL cache + cookie store) |
| `xdr incidents list` | List security incidents with filtering |
| `xdr incidents show ID` | View incident details |
| `xdr incidents update ID` | Update incident status/classification |
| `xdr alerts list` | List security alerts with filtering |
| `xdr alerts show ID` | View alert details |
| `xdr hunt run KQL` | Execute an advanced hunting query |
| `xdr library list/show/run` | Discover and execute typed KQL entries |
| `xdr schema status` | Inspect cache-only maintenance, compatibility, and evidence-growth state |
| `xdr schema diagnostics` | Show build identity, registered capabilities, and automation outcomes |
| `xdr schema collect` | Run bounded, checkpointed refresh and semantic observation collection |
| `xdr schema collect --resume ID` | Continue an interrupted tenant-bound collection plan |
| `xdr schema repair-overlay` | Quarantine and repair or migrate legacy semantic overlay state |
| `xdr schema migrate-cache` | Content-bind a validated pre-digest physical cache offline |
| `xdr schema bundle inspect` | Integrity-check a portable schema bundle without authenticating its author or activating it |
| `xdr schema bundle export` | Export same-tenant schema state and referenced evidence |
| `xdr schema bundle import` | Relocate a trusted, integrity-checked, collision-free same-tenant bundle |
| `xdr schema validate-core` | Validate the packaged graph/profile and check or update its generated reference block |
| `xdr schema refresh/tables/show` | Refresh and query the tenant schema cache |
| `xdr schema pivot/path` | Explain reviewed and empirical semantic routes from the local graph/cache |
| `xdr schema observe` | Probe the tenant locator catalog with safe defaults or explicit exhaustive scope |
| `xdr schema discoveries` | Report observed/validated routes and automatic evidence decisions |
| `xdr schema candidates` | Compatibility alias for `schema discoveries` |
| `xdr schema candidate-review/candidate-proposal` | Optionally inspect private context or draft a non-promoting core JSONL proposal |
| `xdr schema prune-evidence` | Retire stale tenant observations before result pruning |
| `xdr schema correlate` | Correlate tenant-bound, digest-verified private artifacts offline |
| `xdr schema export-opengraph` | Export public or value-free tenant structure for BloodHound OpenGraph |
| `xdr results list/show/head/rows/query/shape/prune` | Browse, filter/page private rows, and explicitly prune artifacts |
| `xdr session start/end/resume/list/show/feedback` | Control optional session telemetry and append feedback |
| `xdr history` | Browse recorded invocation history |
| `xdr annotate` | Annotate an invocation in a learning-mode session |
| `xdr domains list` | List authoritative tenant domains from Microsoft Graph |
| `xdr device show ID` | View device details |
| `xdr device isolate ID --comment "<reason>"` | Isolate a device from the network (`--comment` required) |
| `xdr device unisolate ID --comment "<reason>"` | Release device from isolation (`--comment` required) |
| `xdr device scan ID` | Run antivirus scan on device |
| `xdr device collect-package ID` | Collect forensic investigation package |
| `xdr device restrict ID --comment "<reason>"` | Restrict code execution to Microsoft-signed binaries (`--comment` required) |
| `xdr device action-status ID` | Check status of a device action |
| `xdr device timeline DEVICE` | Download device timeline (unofficial API, see "Device Timeline") |
| `xdr investigate ID` | Run guided investigation workflow |

### Global Options

| Option | Description |
|---|---|
| `--quiet` / `-q` | Suppress progress messages on stderr |
| `--no-quiet` | Force progress visibility even when piped |
| `--no-interactive` | Disable interactive prompts |
| `--debug` | Enable debug logging to stderr |
| `--version` / `-v` | Show version |

## Built-in KQL Query Library

| Query | Description |
|---|---|
| `qry_process_tree` | Process tree for a device |
| `qry_file_hash_scope` | Scope of a file hash across the environment |
| `ttp_encoded_powershell` | Detect encoded PowerShell execution |
| `ttp_lateral_movement_rdp` | Detect RDP lateral movement |
| `ttp_impossible_travel` | Detect impossible travel sign-ins |
| `ttp_token_theft_replay` | Detect token theft and replay attacks |
| `ttp_dns_beaconing` | Detect DNS beaconing patterns |
| `ttp_ransomware_mass-rename` | Detect ransomware indicators |
| `ttp_new_service_creation` | Detect new service creation |
| `qry_inbox_rule_activity` | Audit suspicious inbox rule changes |

Custom queries can be placed in `~/.xdr-cli/queries/` as `.kql` files with front-matter:

```sql
-- description: My custom query
-- tier: r3
-- params: device_name
DeviceProcessEvents
| where DeviceName == "{device_name}"
| take 100
```

String placeholders must be inside a single- or double-quoted ordinary KQL
literal. The loader escapes the enclosing quote and backslashes. Conventional
typed placeholders such as `{hours}`, `{start}`, `{end}`, and `{lookback}` must
remain outside quotes and accept only their documented literal format.

## Configuration Reference

Configuration is stored in `~/.xdr-cli/config.toml`:

```toml
tenant_id = "your-tenant-id"
client_id = "your-client-id"
auth_mode = "device_code"       # or "client_credentials"
client_secret = ""              # required when auth_mode = "client_credentials"
default_limit = 25              # legacy compatibility setting; command defaults are defined by each list command
api_timeout = 120               # HTTP timeout in seconds (raise for slow library hunts)
session_timeout_seconds = 1800  # automatic-session inactivity timeout
schema_stale_seconds = 86400    # cached schema is visibly stale after this age
schema_collection_stale_seconds = 604800  # nonblocking semantic-collection reminder
```

On POSIX systems xdr enforces mode `0700` on its configuration directory and
`0600` on `config.toml`, token caches, and stored portal-cookie credentials.

### Authentication Modes

- **`device_code`** (default): Interactive browser-based login via `xdr auth login`. Best for analysts working at a terminal.
- **`client_credentials`**: Service-principal auth using a client secret. Best for automation and CI. To use it, set `auth_mode = "client_credentials"` and `client_secret = "..."` in `config.toml`. Your app registration must have **application** (not delegated) permissions and admin consent. Token acquisition happens automatically — no `xdr auth login` needed.

### Environment Variables

| Variable | Purpose |
|---|---|
| `XDR_CLI_HOME` | Override config directory (default: `~/.xdr-cli`). Useful for isolating multiple tenants or running in containers. |
| `XDR_SESSION` | Explicitly attach a command to an existing live session ID. |
| `XDR_ACTOR` | Identify parallel actors sharing one session. |
| `MDE_REFRESH_TOKEN` | Supply the unofficial device-timeline FOCI refresh token without putting it in argv. |

### Incident IDs

Microsoft Graph accepts both short numeric incident IDs (e.g., `42`, `4421`) and full Defender incident IDs. You can copy either from the Defender portal URL.

### File Locations

| Path | Purpose |
|---|---|
| `~/.xdr-cli/config.toml` | CLI configuration |
| `~/.xdr-cli/token_cache.json` | MSAL token cache (`0600` on POSIX; user-profile ACL on Windows) |
| `~/.xdr-cli/portal_cookies.json` | Imported Defender portal session cookies; sensitive |
| `~/.xdr-cli/audit.log` | Audit log of write/action commands |
| `~/.xdr-cli/queries/*.kql` | User custom KQL queries |
| `~/.xdr-cli/results/YYYY-MM-DD/` | Private result JSONL and metadata bundles |
| `~/.xdr-cli/schema/<tenant-key>/` | Tenant-scoped cached schema generations |
| `~/.xdr-cli/schema/<tenant-key>/semantic.*` | Private value-free fields, provisional interpretations, and observations |
| `~/.xdr-cli/sessions/*.jsonl` | Optional append-only session histories |
| `~/.xdr-cli/active_sessions/` | Live session markers; managed by the CLI |

## Troubleshooting

### `CLI_REMOVED_OPTION` for `--jq`, `--fields`, or hunt `--limit`

These projection/display flags were removed in 0.7.0. The one-line error
contains `corrected_argv` and migration guidance. Inspect the artifact instead:

```bash
xdr incidents list
xdr results shape <run-id>
jq -s 'map(.id)' <data_path>
```

### `xdr auth status` shows `"configured": false`

No `tenant_id` / `client_id` in `~/.xdr-cli/config.toml`. Run `xdr auth login --tenant-id <ID> --client-id <ID>` once — values are saved to the config file.

### `NOT_AUTHENTICATED` or `TOKEN_EXPIRED`

Your cached token is missing or expired. Re-run `xdr auth login`. The token cache lives at `~/.xdr-cli/token_cache.json`.

### Device-code login hangs or rejects the code

- Make sure **Allow public client flows** is enabled in the app registration's **Authentication** blade.
- Confirm redirect URI `http://localhost` is registered as a **Public client/native** redirect.

### `FORBIDDEN` / HTTP 403 on API calls

Missing scope or unconsented permission on the app registration. Re-check the permissions table above and click **Grant admin consent for [tenant]**. Scopes take effect only after consent.

### `AADSTS65001` ("user or administrator has not consented")

The app registration is missing admin consent for one of the two token audiences the CLI needs:

- Microsoft Graph (incidents, alerts) — consent for Microsoft Graph permissions
- Defender for Endpoint (hunting, device actions) — consent for WindowsDefenderATP permissions

In **API permissions**, verify every required permission shows "Granted for [tenant]" in the Status column. If any are missing, click **Grant admin consent for [tenant]** again.

### Why WindowsDefenderATP audience vs. api.security.microsoft.com endpoint?

Defender for Endpoint endpoints live at `api.security.microsoft.com/api/...` but their tokens must be issued for the **legacy `api.securitycenter.microsoft.com` audience**. This is Microsoft's current guidance (see [Defender for Endpoint APIs docs](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-nativeapp)). That's why the permissions you add in the portal are under **WindowsDefenderATP** — the audience hasn't migrated even though the endpoint URLs have.

### `AADSTS50011` / redirect URI mismatch during login

The app registration is missing the `http://localhost` redirect URI under **Authentication** > **Public client/native**.

### Incident or device not found

Incident IDs come from `xdr incidents list` or the Defender portal URL. Device IDs are machine-GUIDs — get them from `xdr incidents show <id> --expand evidence` or a hunting query.

### Inspecting HTTP traffic

Add `--debug` (global flag) to see MSAL + httpx logs on stderr:

```bash
xdr --debug incidents list --since 24h 2>debug.log
```

### Multiple tenants

Set `XDR_CLI_HOME` to isolate config/token cache per tenant:

```bash
XDR_CLI_HOME=~/.xdr-cli-prod  xdr auth login --tenant-id <PROD>  --client-id <ID>
XDR_CLI_HOME=~/.xdr-cli-dev   xdr auth login --tenant-id <DEV>   --client-id <ID>
```

### `xdr library list` reports a query is missing `-- tier:` frontmatter

The `.kql` file in the error message exists with the field, but the loader still rejects it. Two known causes:

1. **Stale build artifacts after `pipx install` / `pipx upgrade`**. Setuptools' `package-data` glob can be confused by leftover `build/`, `dist/`, or `*.egg-info/` directories pointing at files from before a rename. Clean them out and reinstall:

   ```powershell
   # from your xdr-cli source clone
   Remove-Item -Recurse -Force build, dist, src\xdr_cli.egg-info -ErrorAction SilentlyContinue
   pip cache remove "xdr*"
   pipx uninstall xdr-cli
   pipx install .
   ```

   ```bash
   # Linux / macOS
   rm -rf build dist src/xdr_cli.egg-info
   pip cache remove "xdr*"
   pipx uninstall xdr-cli
   pipx install .
   ```

2. **A user-installed `.kql` in `~/.xdr-cli/queries/` is missing `-- tier:`** (or has another malformed-frontmatter problem). Since v0.4.0 the loader skips bad files with a stderr warning rather than aborting the whole library — but the listing still won't include that query. Either delete the file or add the required frontmatter:

   ```
   -- name: my_query
   -- description: ...
   -- tier: r3        # required: r1 | r2 | r3 | n | beta | pivot | utility | deprecated
   -- params: hours=24
   ```

### `xdr library run` times out when the same query completes in the Defender GUI

Library queries with joins or aggregations can exceed the configured API
timeout even when they eventually complete in the portal. The CLI reports
this explicitly as a one-line `API_TIMEOUT` error with exit code 10; because
the failure precedes durable output, it does not create a result artifact.
Either bump the per-call timeout:

```bash
xdr library run qry_inbox_rule_activity -p account_upn=alice@corp.com --timeout 240
```

…or raise the default in `~/.xdr-cli/config.toml`:

```toml
api_timeout = 240
```

During the one-release compatibility window, render the exact resolved query
without executing it to compare with the portal:

```bash
xdr hunt library-show qry_inbox_rule_activity \
  -p account_upn=alice@corp.com
```

After a successful artifact-producing run, `xdr results query <run-id>` prints
the exact KQL stored in its metadata.

### `--param` only captured the first argument

`--param` / `-p` is a **repeatable** flag, not a comma-separated list. Pass each parameter as its own `-p` invocation:

```bash
# Wrong — sets account_upn to the literal "alice@corp.com,mode=detail"
xdr library run qry_inbox_rule_activity -p account_upn=alice@corp.com,mode=detail

# Right
xdr library run qry_inbox_rule_activity \
  -p account_upn=alice@corp.com \
  -p mode=detail
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/
```

## Contributing

Contributions welcome from infosec practitioners and developers alike.
Before opening a PR, please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for
the rules (branching, commits, PRs, versioning, AI-agent guidelines, and
the don't-commit list). New contributors should also work through the
[contributing walkthrough](docs/contributing-walkthrough.md) end-to-end.

For security vulnerability reports, see [`SECURITY.md`](SECURITY.md) —
private disclosure channel only, not public GitHub issues.

## License

MIT
