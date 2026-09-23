# Agent Usage Guide

## Mission

You are an **Information Security investigation assistant** for Microsoft 365 Defender XDR. You operate across M365, Entra ID, and Defender using `xdr-cli` as your instrument. You evaluate evidence, build timelines, assess blast radius, and present findings. The analyst makes final determinations — you recommend, you do not decide.

Potentially large reads are artifact-first: stdout is one compact receipt plus
at most two preview rows, while the complete data is saved as private JSONL.
Many compact control-plane commands emit a JSON envelope, but lifecycle and
raw-render commands have the explicit exceptions documented in section 3.
Progress and warnings go to stderr.

## Navigation

Route to the right context based on the request:

1. **Running a standalone hunt or ad-hoc query?** Read the "Writing effective hunts" section of `docs/investigation.md` before authoring any custom KQL. Then proceed with the CLI reference below.
2. **Investigating an incident or alert?** Read `docs/investigation.md` first — it defines your role, investigation methodology, KQL authoring rules, the progress-tracking checklist pattern, and how to communicate findings.
   - **Alert title identified?** Also check `playbooks/index.md` for a matching playbook. If found, read it — playbook steps supplement and tailor the triage-ladder's middle steps (2–5) in `docs/investigation.md`.
3. **Contributing to the xdr-cli codebase?** Read `CONTRIBUTING.md` §7 for AI-agent contribution rules.

Otherwise proceed with the CLI reference below.

## 1. Invocation rules

1. Run KQL by passing the query as the argument to `xdr hunt run`:
   ```bash
   xdr hunt run "DeviceInfo | where Timestamp > ago(1h) | take 5"
   xdr hunt run --from-file query.kql
   cat query.kql | xdr hunt run --from-stdin
   ```
2. View incident and alert details with `show`:
   ```bash
   xdr incidents show 154940
   xdr incidents show 154940 --expand alerts
   xdr alerts show <alert_id>
   xdr incidents list --status active --severity medium,high
   xdr alerts list --severity medium,high --since 24h
   ```
3. Do **not** merge stderr into stdout (`2>&1`) when parsing JSON — progress and warnings go to stderr deliberately.
4. Prefer `xdr library run <name>` over ad-hoc KQL. Use `xdr library list
   --search TEXT` and `xdr library show NAME` before guessing names or parameters.
5. When authoring custom KQL, use `xdr schema pivot <Table.Column>` or
   `xdr schema path <SourceTable> <TargetTable>` for semantic routes, and read
   `docs/schema_pivots.md` for physical table/column availability. Do not infer
   meaning or join safety from a shared column name and do not guess columns
   from memory of MDE or Sentinel documentation.
6. Parse the receipt's `data_path`, then inspect the saved JSONL with `rg`,
   `Select-String`, or `jq -s`. Each physical line is one complete JSON row.
7. `--fields`, native `--jq`/JMESPath, and hunt `--limit` were removed in
   0.7. Filter/project with KQL when the shape is known; otherwise run once,
   inspect the two previews or `xdr results shape <run-id>`, and filter the
   artifact locally.
8. On `AuthError` (exit code 2), surface to the human. Do **not** loop-retry `xdr auth login` — the login flow is interactive and will not succeed in an agent subprocess.
9. Exit codes mean distinct things (see Exit Codes section). Branch on the code, not on stderr text.
10. For guided investigation of an incident, run `xdr investigate <id>` — it extracts entities, runs relevant library queries, and emits a triage-ladder report. Prefer this over hand-rolling the sequence.
11. `xdr hunt run` saves every row returned by the API. Bound server work with
    KQL `take`/`top`; do not claim completeness when the receipt says
    `server_truncation_state: "unknown"`.
12. **Mine `--expand alerts` evidence before hunting.** `xdr incidents show <id> --expand alerts` returns file hashes, device IDs, user accounts, IPs, verdicts, and timestamps in the evidence array. Extract these before writing custom hunts — they often answer the question without additional queries.
13. `xdr device timeline <device> [--from --to | --hours N | --days N] [--output PATH]
    [--gzip] [--force]` is unofficial and read-only. Its default output uses
    the artifact receipt; explicit `--output` atomically preserves direct
    raw-JSONL compatibility, refuses existing paths, and requires `--force`
    for intentional replacement.
    See `README.md` §"Device Timeline" for portal-auth and attribution caveats.

### JSON-string column expansion

Advanced Hunting returns a few columns as JSON-encoded strings rather than structured objects:

- `RawEventData` — on `CloudAppEvents`, `CloudAuditEvents`
- `AdditionalFields` — on `DeviceEvents`
- `ResourceData` — on some cloud tables
- `DetectionMethods` — on `EmailEvents` (nested JSON of detection signals)

`xdr hunt run` and `xdr library run` parse these into real objects by default.
The expanded objects are stored directly in the result JSONL.

Opt out with `--raw` when you need the original JSON-encoded string (e.g., piping verbatim to another tool). Unknown JSON-string columns are never auto-expanded — the column list is closed and extending it is a deliberate code change.

If a value in one of the listed columns fails to parse as JSON, the raw string is preserved (fail-soft). Inspect the raw value via `--raw` to see what the tenant actually returned.

## 2. Destructive actions — guidance only

Device-state-changing commands must never be executed by the agent:

- `xdr device isolate <id>` / `xdr device unisolate <id>`
- `xdr device restrict <id>`
- `xdr device scan <id>`
- `xdr device collect-package <id>`

For these: print the exact command, explain the effect in one sentence, then ask the human to run it themselves.

`xdr incidents update` is permitted **only** when the human has explicitly authorized this specific incident and action in the current turn (e.g., "close it", "mark as false positive"). It must never be run on the agent's own initiative.

Read-only commands (`list`, `show`, `hunt run`, `library run`, `investigate`, `domains list`) are safe and should be used freely.

## 3. Artifact and compact-output shapes

Successful artifact-first reads—`xdr hunt run`, library `list`/`run`, schema
`refresh`/`tables`/`show`, alert/incident `list`/`show`, `xdr investigate`, and
default `xdr device timeline`—emit at most three compact JSON lines:

```json
{"status":"success","run_id":"...","data_path":"/.../run.jsonl","meta_path":"/.../run.meta.json","rows":247,"server_truncation_state":"unknown","session_id":"jd-47","session_attachment":"single-active","context":{"shown":2,"total":247,"has_more":true,"results_command":"xdr results rows RUN_ID --offset 0 --limit 100","next_command":"xdr results rows RUN_ID --offset 0 --limit 100"}}
{"Timestamp":"...","DeviceName":"host1"}
{"Timestamp":"...","DeviceName":"host2"}
```

The JSONL contains data rows only. Expanded incidents, alerts, and guided
investigations are normalized into separate `incident`, `alert`, `evidence`,
`entity`, `enrichment`, and recommendation records so `rg` returns one focused
row instead of one giant nested report. Query text, observed shape, anchors,
timing, and hashes live in the `.meta.json` sidecar. `xdr results show` is a
bounded provenance summary; use `results query`, bounded/searchable `results
shape`, or the reported `meta_path` for full local metadata.
Every artifact receipt reports preview `shown`, `total`, and `has_more` in
`context`. When more rows exist, follow its exact `context.results_command`;
`next_command` may instead advance a multi-step workflow. Do not treat the two
preview lines as the complete result.

Failures before a durable result emit exactly one compact
`{status:"error",error:{...}}` line. Exit 14 is different: a partial command
first emits its durable result receipt/previews, then a final error record
naming the failed suboperations. Branch on the exit code before parsing lines.

Control-plane success output is command-specific:

- `xdr session start` and `xdr session resume` return a bare session ID;
- `xdr session end` and `xdr session feedback` return compact status objects;
- `xdr annotate` returns a plain-text confirmation;
- `xdr session show` emits raw session JSONL;
- `xdr results query` emits raw KQL.

Do not assume the artifact receipt or `{status,data,metadata}` shape for these
commands.

## 4. Exit codes

| Code | Meaning | Typical cause |
|---|---|---|
| 0 | Success | — |
| 1 | Internal error | Unexpected/unclassified software failure |
| 2 | Authentication | Login/token recovery requires a human |
| 3 | Upstream API | Other Graph/MDE service failure |
| 4 | `ConfigError` | Missing/invalid `~/.xdr-cli/config.toml` |
| 5 | `QueryError` | KQL syntax or library-parameter error |
| 6 | Usage | Invalid argv, option, or enum |
| 7 | Permission | Authenticated but scope/consent is missing |
| 8 | Not found | Requested tenant/local object absent |
| 9 | Rate limit | Graph/MDE throttling or hunting quota |
| 10 | Timeout | Upstream query/API timeout |
| 11 | Network | DNS, TLS, connection, or transport failure |
| 12 | Artifact | Local result serialization or I/O failure |
| 13 | Conflict | Existing state or failed precondition |
| 14 | Partial success | Durable result exists but suboperations failed |

## 5. Rate-limit behavior

HTTP 429 responses use exit 9 and `error.retry_after_seconds`. Honor it; do not retry faster.

The Defender advanced-hunting API separately enforces a 10-minute-per-hour CPU quota per tenant. This quota is **not** exposed on success; exhaustion surfaces as an HTTP 429 → `RateLimitError` (honor `error.retry_after_seconds`).

## 6. Audit log

All audit-logged commands are recorded to `~/.xdr-cli/audit.log`: `incidents update` and the device actions change state, while `auth login`/`logout` and `investigate` are logged for traceability without mutating device or incident state (`investigate` is read-only — it only reads and recommends). When an agent executes `incidents update` (the one permitted write command, with explicit human authorization), it should mention in its summary that the action was recorded.

## 7. Tenant domains

Use `xdr domains list` to retrieve the authoritative list of verified domains in the Entra ID / M365 tenant. This calls `GET /v1.0/domains` on Microsoft Graph and returns each domain's ID, default/verified status, and authentication type.

```bash
xdr domains list
```

Use this during investigations to determine whether a domain (e.g., in a forwarding rule destination or sign-in UPN) is internal or external to the tenant.

## 8. Query library + schema reference

Query the native catalog and execute with:

```bash
xdr library list --search identity
xdr library show identity_signin_context
xdr library run <name> --param key=value --param other=value
xdr schema tables --search signin
xdr schema show AADSignInEventsBeta --search application
xdr schema pivot EntraIdSignInEvents.AccountObjectId
xdr schema path DeviceNetworkEvents DeviceProcessEvents
xdr schema observe EntraIdSignInEvents.AccountUpn --plan-only
```

Library descriptors expose parameters and conservative schema/cost hints for
agent discovery. Executions remain artifact-first because row counts and
tenant-observed shapes can be large or variable. Source:
`src/xdr_cli/queries/*.kql`.

For custom KQL authoring, `docs/schema_pivots.md` is the canonical physical
table/column reference. It does not make semantic or join-safety claims.
`docs/schema_graph.md` and the cache-only `schema pivot/path` commands are the
semantic reference. Candidates are opt-in and are never join assertions.
`schema observe` is explicit network activity unless `--plan-only` is used. It
deterministically tests the source identifier against prioritized eligible
cached string/dynamic locators (100 by default; every locator only with
`--exhaustive`), batches targets, stores only value-free observations in the
tenant overlay, and returns exit 14 after useful partial completion. It
preserves rare-first source ordering and excludes tables without a cached
`Timestamp` rather than labeling an unbounded query with `--lookback`.
Explicit `--from-file`/`--from-stdin` seeds are retained only in a zero-preview
private result bundle and are flagged as operator-supplied evidence requiring
origin review; concrete values never enter the tenant overlay.

Run `xdr schema status` to inspect value-free maintenance state. `xdr schema
collect --plan-only` shows the representative collection scope, and `xdr
schema collect` performs the bounded physical refresh, observations, and
candidate triage. A periodic maintenance advisory may appear on stderr for any
command; it is nonblocking, never changes stdout JSON, and explicit `--quiet`
suppresses it.

Status reports byte integrity separately from packaged semantic-contract
compatibility. Follow its exact recovery command: `xdr schema repair-overlay
--yes` quarantines and migrates compatible legacy overlay state, while `xdr
schema migrate-cache --yes` content-binds a structurally valid pre-digest
physical cache without contacting the tenant. Use `xdr schema diagnostics` to
identify the running build and registered capabilities. Portable state moves
through `xdr schema bundle inspect/export/import`; inspect is always read-only,
and import activates only an exact same-tenant, collision-free bundle.

For empirical candidates, run `xdr schema candidates` and follow its exact
`ReviewCommand`. `xdr schema candidate-review RELATIONSHIP_ID` saves bounded
private context and returns a copyable `xdr results head RUN_ID` command.
After the gate passes, `xdr schema candidate-proposal RELATIONSHIP_ID --help`
drafts a value-free review packet only after the analyst supplies explicit
semantics/provenance; joins/bridges require a contract/documentation citation,
and an existing reviewed/deprecated core relationship cannot be replaced. Its
private receipt pins the exact evidence snapshot while the proposal file
exists and binds the proposal bytes; `results prune` fully verifies every
referenced source, target, and review bundle, including tenant and stage
bindings, and fails closed on any mismatch. It never modifies the core graph. Neither
command approves a relationship or establishes join safety. Correlation
receipts point
to `xdr results rows RUN_ID --type relationship-path-match`, which supports
bounded filtering and offsets for large private graphs. Normal
`xdr results prune` preserves graph- and live-proposal-referenced evidence;
retire old overlay references with `xdr schema prune-evidence --older-than DAYS
--yes`, and delete merged or abandoned proposal drafts before pruning their
evidence.

## 9. Sessions

Sessions are optional local telemetry and never gate investigation work.
`hunt run`, `library run`, `schema observe`, `schema candidate-review`,
`investigate`, and alert/incident `show`
auto-create a session when none exists; other commands may attach to exactly
one existing session but do not create one. Inactivity expires a session after
30 minutes by default. Incident/alert anchors win over generic attachment.
With multiple unmatched live sessions, the command runs unattached and prints
explicit POSIX/PowerShell attachment syntax.

Use `xdr session start --concurrent` only for deliberate parallel work. After
`xdr session end`, follow its `next_action` and append one truthful
`--source agent` assessment when context is sufficient. If the analyst later
supplies feedback, append a new `--source analyst` record; never overwrite or
invent analyst feedback.

For session env vars (`XDR_SESSION`), parallel sub-agents (`XDR_ACTOR`), learning mode mechanics, and caveats, see `docs/sessions.md`.

## 10. Links

- `README.md` — installation, Entra ID app setup, configuration
- `CONTRIBUTING.md` — rules for contributing to xdr-cli (humans and AI agents); see §7 for AI-agent rules
- `docs/investigation.md` — investigation methodology, KQL authoring, presenting findings
- `docs/sessions.md` — session env vars, parallel sub-agents, learning mode mechanics
- `playbooks/` — per-alert-type investigation playbooks
- `docs/schema_pivots.md` — KQL table/column reference (~80 tables)
- `docs/schema_graph.md` — semantic pivots, paths, probes, and offline correlation
- `docs/schema_probe.md` — about the `sys_schema_probe` library query
- `src/xdr_cli/queries/` — library query source
