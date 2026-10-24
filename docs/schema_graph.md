# Semantic schema graph

`xdr schema` learns which Advanced Hunting fields carry the same identifier,
so you know where else a value can be searched. Example: an alert gives you a
`DeviceId` from `DeviceNetworkEvents`. Which other tables accept that value as
a search key, and is a raw KQL join on it safe?

```bash
xdr schema pivot DeviceNetworkEvents.DeviceId
```

Every row names a target field, its evidence level, and whether a join is
safe. This whole feature is optional: incident triage, hunting, and response
commands work without it. Use it when you want pivot suggestions grounded in
your own tenant, or a BloodHound picture of the schema.

Terms used throughout:

- **Physical cache** - the local copy of the tenant's table and column list,
  written by `xdr schema refresh` (one Advanced Hunting call, plus the portal's
  table listing when portal cookies exist). Every other schema command reads it;
  most never contact the tenant.
- **Packaged graph** - the reviewed, value-free semantic graph shipped in the
  package: which fields are the same identifier, how to transform them, and
  which joins are safe.
- **Overlay** - a private, per-tenant file that adds what this tenant taught
  the graph: new fields, interpretations, and aggregate observations. It
  never stores identifier values or result rows.
- **Candidate** - an unverified hypothesis that two fields share an
  identifier. Hidden from `pivot`/`path` unless you pass
  `--include-candidates`.
- **Observed** - verified tenant evidence showed at least three eligible shared
  identifiers in saved results or complete captures, or a bounded probe supported
  an empirical route. The evidence stage states which source supports it. Usable
  as a search route; not a join contract.
- **Validated** - repeated, independent observations passed a fixed machine
  policy. Still correlation-only; a join-safe edge requires a reviewed core
  change.

The physical cache answers "which tables and columns exist here?" The graph
answers "which fields may carry the same identifier, and what workflow is
safe?" Equal values justify another pivot without proving that a raw KQL join
is selective, cardinality-safe, or semantically equivalent.

The physical probe is a curated catalog, not exhaustive tenant discovery. New
refreshes record the exact requested table names and returned tables in cache
metadata under `coverage`; refresh artifact metadata also exposes `schema_coverage`.
Refresh, pivot, and path receipts report bounded coverage counts and the actual hunting execution surface
(`graph`, `mde`, `portal`, or `unknown`). A Graph-to-MDE fallback stays within the
official backend but changes that surface. Fuzzy-union omissions and unknown
server truncation never prove a table is absent or inaccessible.

`pivot` and `path` distinguish physical availability from semantic compatibility:

- `available`: a compatible top-level field was returned in the cached schema.
- `outer-available-unobserved`: JSON storage exists, but this nested path has not
  been observed locally. This remains an eligible path for explicit probing.
- `not-probed`: the table was outside the exact recorded probe scope.
- `not-observed`: the field was not returned, including inconclusive/custom scope.
- `type-conflict`: an explicit storage type conflicts with the semantic field,
  or its supplied type is unknown. A nested leaf's type is checked separately
  from its outer string/dynamic JSON storage.
- `unavailable`: the legacy label for a missing field when the cache predates
  coverage metadata; it is not proof of absence.

Only the first two states permit live probing. Missing type metadata in legacy
rows retains its previous behavior; supplied unknown types do not. Existing
routes with unusable physical fields are omitted by default; pass
`--include-unavailable` to inspect their availability labels. Historical local overlaps
are retained when current storage types prevent live validation. No public schema
reference is used as evidence that a field exists in the tenant.
When the pivot source is non-queryable, its receipt outcome is
`source-not-probed`, `source-not-observed`, `source-type-conflict`, or the legacy
`source-unavailable`. Path receipts report table-level availability; individual
steps carry their field-level state and `SourceAvailable`/`TargetAvailable` flags.

Start with the cache-only status command and run its exact
`context.next_command`:

```bash
xdr schema status
xdr schema diagnostics
xdr schema collect --plan-only
xdr schema collect
xdr schema discoveries
xdr schema pivot DeviceNetworkEvents.DeviceId
xdr schema path DeviceNetworkEvents DeviceProcessEvents
```

## What happens when you end a session

Explicit `xdr session end` closes the session first, then runs three
foreground upkeep stages for the configured tenant:

1. **Refresh** the physical cache if it is missing or stale (one query).
2. **Validation** - `schema collect` with fixed values: 30-day lookback,
   5 samples per overlap, and a 20-query budget. These are not configurable.
3. **Exploration** - `schema collect --explore` with a budget of
   `schema_explore_max_queries` (default 5, integer 1-1000). This is the only
   stage with a tunable budget. It captures recent rows (24-hour requested horizon,
   up to 25,000 rows per table), correlates privately saved rows locally, and uses
   the remaining budget for focused validation. It does not require saved seeds.

The whole run has one deadline, `schema_maintenance_timeout_seconds = 90`
(maximum 3600). Completed work is saved and reused at the next explicit end.
Controls, all in `~/.xdr-cli/config.toml` unless noted:

| Setting or flag | Effect |
|---|---|
| `session end --no-maintenance` | Skip upkeep for this one session end |
| `schema_collect_on_session_end = false` | Disable all three stages |
| `schema_refresh_on_session_end = false` | Skip only the refresh stage |
| `schema_explore_on_session_end = false` | Skip only the exploration stage |
| `schema_explore_max_queries = N` | Exploration query budget (default 5) |
| `schema_maintenance_timeout_seconds = N` | Overall deadline (default 90) |

The session is ended durably before upkeep starts, so never retry
`session end`. Partial completion (budget pause, deadline, or an upstream
failure) returns exit 14; Ctrl-C returns exit 130. Both leave a
`record_type: "session-maintenance"` record with `maintenance.status`, the
cause, and a `next_command` for recovery, normally `xdr schema collect` or
`xdr schema collect --explore`. An unconfigured tenant skips upkeep. Idle
expiry, automatic rotation, and ending an already closed session never run
upkeep; nothing is scheduled in the background. See
[session maintenance](sessions.md).

## End-to-end workflow

Inspect and, when necessary, repair local state:

```bash
xdr schema status
xdr schema diagnostics
xdr schema repair-overlay --yes
xdr schema migrate-cache --yes
```

`repair-overlay` and `migrate-cache` are recovery commands, not routine steps.
Use the recovery command reported by the actual error or diagnostics output.
`schema refresh` is the tenant-calling operation that replaces the physical
cache.

### Physical schema refresh

`getschema` is the authority for which columns this tenant can query and their
types. Refresh probes the union of the packaged table registry
(`src/xdr_cli/hunting_tables.py`), every table the Defender portal lists for this
tenant, and every table seen by the previous refresh. Missing tables are skipped
silently, so absence stays inconclusive.

`--metadata-source` selects the table listing:

| Value | Behavior |
|---|---|
| `auto` (default) | Adds the portal `huntingService/schema` listing when tenant-bound portal cookies exist. A missing or failed listing is recorded in `coverage.metadata` and the refresh still succeeds. The selected hunting backend never changes. |
| `portal` | Requires the listing. If it fails, the getschema cache is still published and the command exits 14. |
| `probe` | Uses only the getschema probe; the portal is never contacted. |

A metadata listing does not prove that a table or column can be queried, so
only getschema rows are cached. Tables and columns that are listed but not
returned by getschema are reported in `coverage.metadata.portal_only_tables` and
`coverage.metadata.portal_only_columns` (with bounded examples) and stay
unavailable. Earlier pre-release caches that stored portal-only rows are filtered
when read, so those rows never authorize a field. When the portal and getschema disagree on a column type,
getschema wins and the count appears in `coverage.metadata.type_disagreements`.
In the development tenant, seven portal types disagreed with getschema; for
example, the portal reports `DeviceTvmInfoGatheringKB.IgId` as `DateTime` while
getschema returns `string`.

`coverage.new_tables` lists tenant tables that are absent from both the packaged
registry and the reference table names. `schema init` passes its reference
snapshot, and a plain `schema refresh` reads the local snapshot when one exists,
so both commands report the same set. This is how a
newly shipped Defender table, such as `ExposureRecommendations` in the
development tenant, is detected and cached before it enters the packaged probe
registry. The full portal listing, including descriptions and entity tags,
is saved privately beside the cache as `schema.<generation>.portal.json`. The
metadata binds it by SHA-256. Receipts carry only bounded counts.

`schema init` proposes routes for tables that the reference does not know yet.
A new table's string, GUID or numeric column becomes a candidate when either of
these holds:

- its exact name matches a top-level reference endpoint column of a family whose
  endpoints exist in this tenant;
- the verified portal sidecar tags it `Machine` (Defender device) or
  `UserObjectId` (Entra user).

Each candidate targets at most three physically present hubs of that family,
preferring `DeviceInfo`, `IdentityInfo` and `EntraIdSignInEvents`. Route IDs are
deterministic (`tenant-discovery-<hash>`), and at most 100 derived routes are
validated per run; the receipt reports when the cap is reached. Candidates run
through the same bounded validation as reference routes. One becomes an
`observed` pivot only after at least three distinct sampled values match.
Weaker results stay candidates and never become reference-trusted, reviewed or
join-safe. Tables with no candidate are listed as unmapped, with
`xdr schema collect --explore` as the next step for value-overlap discovery.
In the development tenant, newer tables such as `CallActivityEvents` have neither
matching column names nor portal entity tags, so they rely on that discovery path.

Browse the physical cache to form field locators:

```bash
xdr schema tables --search sign
xdr schema show EntraIdSignInEvents --search Account
```

`tables --search` is a case-insensitive filter on table names; `show TABLE
--search` filters that table's column names. Neither contacts the tenant.

Preview collection before making tenant calls, then run routine collection or
active exploration:

```bash
xdr schema collect --plan-only
xdr schema collect --explore --plan-only
xdr schema collect
xdr schema collect --explore
```

Active discovery saves each completed query, including empty results, as private
evidence. Rerun the same command after a query-budget pause (exit 14); recent,
verified searches are reused and only remaining work is queried. Changing the
lookback, table scope, JSON depth, or result limit creates a different search.

Inspect learned routes and use them during an investigation:

```bash
xdr schema discoveries
xdr schema pivot DeviceNetworkEvents.DeviceId
xdr schema path DeviceNetworkEvents DeviceProcessEvents
```

## Local-first collection

```bash
xdr schema collect --plan-only
xdr schema collect --local-only
xdr schema collect
```

`schema collect` first mines saved hunt/library artifacts for shared identifier
values, recovering physical field origins from their saved KQL. Supported queries
include single-table projections, renames, direct nested-property access, and
summary grouping keys. Aggregate/calculated outputs are excluded. Joins, unions,
invoked functions, and unsupported let bindings are reported as coverage gaps.
The saved query remains the source of truth.

`--plan-only` performs local indexing and plans focused validation without tenant
queries or publishing graph observations. `--local-only` also publishes the local
overlap observations, with no tenant queries. With no local overlaps, collection
does not silently run broad discovery. Use `--explore` to request that explicitly.

The private, per-tenant SQLite index stores keyed identifier fingerprints and
artifact references, not a second copy of identifier values. Unchanged files are
still streamed for integrity checks, but are not reparsed or reindexed. Changed,
missing, corrupt, and wrong-tenant evidence is removed from the derived index.
Unsupported nested keys are counted as excluded instead of leaking possible
identifier values into graph field names. Common-value fanout above 100 fields is
suppressed and counted. Absence from filtered results is not a negative finding.

Local observations retain their original timestamps and are historical evidence.
They are not current-tenant validation or assertions that every value in either
field has the same meaning. Live validation checks sampled shared identifiers in
eligible target fields with an explicit time window. The planner deduplicates
field pairs, batches compatible fields, and reuses verified validations for one
day, including no-match outcomes. A no-match result does not erase historical
positive evidence; inspect both when deciding whether a pivot is useful.

The default validation budget is 20 queries per invocation. Each successful
validation is saved; exit 14 indicates useful partial completion. Rerun the
same command to re-plan remaining work. `--local-only` and `--plan-only` work
without a physical cache; validation needs cached target fields and
`Timestamp` or `TimeGenerated`. `schema status` never suggests those two
flags: when the cache is missing or stale its `next_command` is
`xdr schema refresh`, and you may still run the local-only forms yourself.

Local-derived pivots appear in normal navigation and support private
`candidate-review` context queries. They do not use `candidate-proposal`'s
contributor workflow for drafting a reviewed core change; their generic
identifier interpretations are empirical occurrence hypotheses, not authored
entity claims.
No background scheduler is installed.

Collection reuses a recent validation only when its time window matches and its
sampled identifiers cover the newly selected sample. Different uncovered samples
of the same field pair remain separate planned work; already-covered samples do
not hide them. Concurrent local-first
collectors for the same tenant return a conflict instead of executing duplicate
queries; rerun after the current collection finishes. A later invocation plans
again under the tenant lock.

Malformed identifiers are counted under `rejected_identifier_cells` and skipped.
Invalid local validation evidence is retired during collection. Discovery reads
reuse verified evidence within one operation, then discard that snapshot; the
next command verifies the original files again. Scalar JSON decoding is not
attributed to a raw column when a probe cannot reproduce that transformation.

### `collect` flags

| Flag | Default | Meaning |
|---|---|---|
| `--plan-only` | off | Preview cached capture/local work without tenant queries or observations |
| `--local-only` | off | Publish saved-result overlaps without tenant queries |
| `--explore` | off | Automatically capture recent data, correlate locally and validate focused pairs |
| `--source Table.Column` | none | Restrict identifiers for gap-filling follow-up queries; repeatable |
| `--lookback` | `24h` with explore, otherwise `30d` | Capture horizon and validation window |
| `--samples` | 5 | Identifiers per local-overlap validation (1-100) |
| `--batch-size` | 20 | Distinct target fields per validation batch (1-50); cohorts stay separate |
| `--seed-batch-size` | 20 | Identifiers per gap-filling query (1-100) |
| `--max-json-depth` | 6 | Gap-filling JSON expansion levels (0-12) |
| `--discovery-row-limit` | 2000 | Rows per gap-filling result (1-10000); does not cap raw capture |
| `--max-queries` | 300 | Overall exploration query budget, including capture and validation |
| `--max-rows` | 2000000 | Overall captured row budget |
| `--max-bytes` | 2147483648 | Overall serialized capture byte budget |
| `--deadline` | 1200 | Overall exploration deadline, seconds |
| `--max-queries-per-page` | 20 | Local validation budget; explicit use with explore overrides max-queries |
| `--timeout` | 120 | Per-query timeout, seconds (1-3600) |

`--local-only` and `--explore` are mutually exclusive. `--source` requires
`--explore` and does not restrict table capture. Supplying both query-budget flags
explicitly is a usage error. Capturing more rows does not establish semantic
review or join safety. Concrete identifiers remain in private artifacts; the
tenant graph stores value-free evidence and provenance.

## Explicit active exploration

```bash
xdr schema collect --explore --plan-only
xdr schema collect --explore
xdr schema collect --explore --lookback 2h --max-queries 100
```

`--explore` starts with recent tenant data even when no hunt results have been
saved. It refreshes missing/stale physical metadata, selects getschema-queryable
tables and verified datetime columns, and fixes one half-open capture interval.
Timed inventory tables are labelled separately from events. Untimed tables are
explicit capped state samples; the lookback does not bound them. Global
knowledge-base tables are excluded. The plan and coverage report retain reasons
for skipped or unsupported work.

Each table gets one capped query, normally up to 25,000 rows. Timed tables
select the newest rows in the requested interval. When capped, the actual
observed span is shorter and its oldest timestamp can be only partly sampled;
rows tied at that boundary are retained. Untimed inventory/state tables use a
capped sample. The result reports the requested window, observed boundary,
sample/cap flags and source counts separately. Counts from a separate source
scan are informational. Samples never establish absence elsewhere in the table.

A same-query control packet counts the exact materialized selected rows.
Matching full payload counts prove transport completeness; a cap-plus-one
sentinel distinguishes a complete source window from a sample. Size, runtime or
transport-truncation failures automatically reduce the row cap and retry, down
to a bounded minimum. No manual window selection is needed. Multiple requests
do not provide a single transactional tenant snapshot.

Full selected rows are saved as private capture artifacts with exact query,
compiler, tenant, source, interval, coverage and proof bindings. Bulk rows are
not printed. The existing local index mines identifiers and nested paths,
publishes conservative overlap evidence and runs focused validation. When both
sides are verified complete captures from the same job, tenant, schema, execution
surface and interval, it uses their saved overlap without a redundant tenant query.
At least three distinct eligible shared identifiers produce the distinct
`capture-overlap-complete` observed stage. Weaker overlaps remain candidates;
private-address-only overlaps do not meet the threshold. This stage is historical
presence evidence, never live-query validation, absence evidence or a join assertion.

Pairs involving sampled/capped captures or ordinary saved hunt/library results
remain eligible for live validation. Scalar targets share a single scan per target
table and bounded chunk, even when source fields, normalizers or identifier cohorts
differ. Each pair keeps its own cohort and exact match counts; another pair's
identifiers cannot strengthen its result. Array paths are isolated to preserve
expansion semantics. Distinct-target and query-byte limits can split large batches.
Receipts distinguish complete-capture skips, below-threshold pairs, planned live
pairs and queries, and completed queries. Identifier searches remain available for failed/incomplete timed tables. The seed/depth/
result-limit flags apply to that follow-up stage. Inventory co-occurrence
remains historical evidence when a time-bounded live validation cannot be
compiled; it does not become a join assertion.

Exploration reserves 20% of its remaining query budget, up to 50 queries, for
focused validation when at least two queries remain. Large inventory capture
therefore cannot consume the validation allocation. Unused validation capacity
does not trigger a broad identifier sweep.

One invocation advances ordinary batches automatically and honors bounded retry
and quota delays. Validation honors Retry-After with at most 10 retries, 120 seconds
per delay and 600 seconds of total waiting across capture and validation, within
the same deadline and query budget. Completed fresh validations are reused.
A true query/row/byte/deadline limit or cancellation saves a
checkpoint; rerunning resumes verified unfinished work instead of recapturing
completed tables. Intentional samples can complete the collection policy while
remaining nonexhaustive; partial success is reserved for unfinished work or failures. Inspect the final receipt and private table-coverage records:
partial coverage returns exit 14, with retry timing when applicable. No background
scheduler is installed. Parsing, evidence reads and SQLite correlation check the
same foreground deadline; unfinished indexing retains capture evidence and does
not publish an incomplete replacement graph. Existing hunt/library results remain intact and continue
to contribute local evidence. Older automatic claims are reverified under current
query/provenance contracts; incompatible claims can leave the active graph while
their source results remain under normal retention. Saved overlaps are rederived
from verified artifacts. Active capture evidence is retained during result
pruning until its handoff is durable.

## How observe compiles and crawls

When a field has a unique packaged interpretation and all competing tenant
interpretations are provisional occurrences, `observe` uses the packaged
contract. It keeps the provisional evidence and still enforces source constraints
and the ban on provisional-source fan-out. Multiple non-provisional meanings or
multiple packaged meanings remain ambiguous and return
`SCHEMA_AMBIGUOUS_SEMANTIC_FIELD` (exit 13), with bounded competing interpretation
IDs. A genuinely unknown semantic field still returns exit 8.

An unsupported source normalizer, currently including `ip-canonical`, returns
`SCHEMA_SOURCE_NOT_PROBEABLE` (exit 13) before authentication or query execution.
Cache-only pivots and offline correlation remain available. A constrained source
the compiler cannot enforce returns `SCHEMA_SOURCE_CONSTRAINED` (exit 12,
retained for compatibility); it does not indicate that writing a result failed.
Neither outcome is evidence of a confirmed or invalid relationship.

Use `observe` for one source:

```bash
xdr schema observe DeviceNetworkEvents.DeviceId --plan-only
xdr schema observe DeviceNetworkEvents.DeviceId --lookback 30d --samples 5
xdr schema observe DeviceNetworkEvents.DeviceId --plan-only --exhaustive
xdr schema observe DeviceNetworkEvents.DeviceId --exhaustive
```

The compiler groups compatible scalar targets by table. One bounded scan of a
table computes labeled `MatchRows` and `MatchedSeeds` aggregates for multiple
fields instead of rescanning that table once per field. Nested wildcard paths
are isolated when their KQL shape cannot safely share the scalar scan. Every
compiled request has a deterministic task ID and a 256 KiB byte limit.

Planning reports target counts, table counts, estimated requests, excluded
unbounded targets, selected/excluded tables, coverage, and the seed-payload
bound. Narrow or exclude expensive tables explicitly:

```bash
xdr schema observe DeviceNetworkEvents.DeviceId \
  --target-table DeviceProcessEvents \
  --target-table DeviceNetworkEvents

xdr schema observe DeviceNetworkEvents.DeviceId \
  --exclude-table CloudAppEvents
```

Target-local `APIError`, `QueryError`, and timeout failures are quarantined.
The receipt records the task ID, table, exact locators, error type/code, and a
narrow retry command, then the crawler continues with other tables. Completed
positive and no-match observations keep their real outcomes. Authentication
and rate-limit failures still stop globally because continuing would either be
impossible or violate retry guidance.

The observation receipt retains the quarantined table list and retry commands.
Partial completion returns exit 14 so gaps remain explicit.

Manually page one observation run:

```bash
xdr schema observe DeviceNetworkEvents.DeviceId \
  --exhaustive \
  --max-queries 20
```

Run the receipt’s exact `context.next_command`. It contains `--from-run`,
`--start-query`, `--schema-generation`, and the original scope. The retained
source sample is reused rather than sampled again. `context.plan_fingerprint`,
`query_start`, `query_stop`, and `page_complete` make progress auditable.

### `observe` flags

| Flag | Default | Meaning |
|---|---|---|
| `--plan-only` | off | Show the deterministic target plan; no auth or KQL |
| `--lookback` | `30d` | Source and target time window |
| `--samples` | 5 | Distinct valid source values to test (1-100) |
| `--batch-size` | 20 | Target locators per Advanced Hunting batch (1-50) |
| `--max-targets` | 100 | Target cap for a routine run (1-10000) |
| `--exhaustive` | off | Probe every eligible locator; preview first |
| `--target-table TABLE` | none | Probe only these cached tables; repeatable |
| `--exclude-table TABLE` | none | Skip a table and report the coverage gap |
| `--timeout` | `api_timeout` | Per-call HTTP timeout, seconds (1-3600) |
| `--max-queries` | none | Target table queries this invocation (1-1000) |
| `--from-run RUN_ID` | none | Reuse the source-sample artifact of a prior page |
| `--start-query N` | 0 | Zero-based table-query cursor from a prior receipt |
| `--schema-generation` | none | Require the physical-cache generation of a prior page |
| `--from-file FILE` | none | Explicit seed values, one per line |
| `--from-stdin` | off | Explicit seed values from stdin |
| `--private-debug-output` | none | Sensitive seed/query diagnostics; never share |

Explicit seeds are also supported:

```bash
xdr schema observe DeviceNetworkEvents.DeviceId --from-file seeds.txt
cat seeds.txt | xdr schema observe DeviceNetworkEvents.DeviceId --from-stdin
```

Normalized explicit values are retained in a zero-preview, tenant-bound private
artifact. Continuations can reuse that artifact. Explicit values can establish
an `observed` route, but they do not satisfy automatic `validated` evidence;
validation requires independently sampled source artifacts.

## Evidence lifecycle

The lifecycle is evidence strength, not a synonym for join safety:

| Level | Meaning | Default traversal | Join-safe |
|---|---|---:|---:|
| `candidate` | Unverified packaged or tenant hypothesis | No; opt in | No |
| `observed` | At least one completed positive empirical observation | Yes | No |
| `validated` | Repeated independent evidence passed machine policy | Yes | No |
| `reviewed` | Repository-reviewed semantic contract | Yes | Only when the edge says so |
| `deprecated` | Retained historical contract, not traversed | No | No |

A completed eligible live observation creates a bidirectional,
correlation-only `observed` investigation pivot. Local-only overlap needs at least
three distinct eligible shared identifiers; weaker overlaps stay candidates.
Private-address-only matches remain candidates because separate networks reuse
those addresses. Built-in principals and the configured tenant GUID are excluded
as discovery seeds. It is useful for discovering a
next table even though it does not authorize a raw equality join. No-match,
partial, unavailable, and malformed target results create no route.

An empirical route becomes `validated` automatically only when all of these
conditions hold:

- at least two positive observations;
- every counted source artifact is a locally reverified `source-sample` for the
  same tenant, locator, interpretation, normalizer, and lookback;
- every target artifact is digest/row-count verified and bound to the exact
  source artifact, seed count, target locator, interpretation, and aggregate;
- at least two distinct source artifacts and two distinct target artifacts;
- at least two disjoint sampled seed cohorts containing at least six distinct
  normalized identifiers in total;
- each counted run tested at least three seeds and matched at least two; and
- aggregate matched/tested seed ratio is at least 80 percent.

Automatic validation is deliberately closed to identifier contracts with
strict or separately checked value shapes: Entra object IDs and UPNs, MDE
device IDs and names, IP addresses, network message IDs, and SHA-256 hashes.
Other namespaces can still produce immediately useful `observed` routes but do
not advance to `validated` without a code-reviewed policy extension.

Metadata cannot self-promote a route: effective-graph composition opens and
rechecks the referenced evidence before passing observation IDs to the
validation policy. Imported bundles therefore retain useful observations but
cannot obtain `validated` merely by asserting an `evidence_verified` property.

Both `observed` and `validated` routes use relationship kind
`correlation-only`, unknown cardinality, and `join_safe=false`. A
`join-compatible` or bridge edge requires an independent product/documentation
contract and an ordinary repository-reviewed core change.

`schema discoveries` reports the evidence level, policy blockers, verified
positive runs, independent artifact counts, aggregate counts, integrity
problems, high-fanout concerns, and `JoinSafe`. Operator-supplied evidence is
reported separately. A private context review remains available when an
analyst wants to inspect ambiguous rows, but it is not required for automatic
tenant-local validation:

```bash
xdr schema discoveries --include-evidence-refs
xdr schema candidate-review <relationship-id>
xdr results head <candidate-review-run-id> --limit 20
```

`candidate-review` runs one bounded target query and saves rows privately
with no stdout preview. `--lookback` overrides the observation window (for
example `7d`), `--limit` caps retained target rows (1-100, default 20), and
`--timeout` overrides `config.api_timeout` in seconds.

`candidate-proposal` is a contributor workflow for drafting a value-free core
JSONL change. It does not promote tenant evidence, edit the repository, or turn
an empirical pivot into a join. Join/bridge proposals require explicit
independent-contract provenance:

```bash
xdr schema candidate-proposal <relationship-id> \
  --output proposal.jsonl \
  --relationship semantic-equivalent --direction both \
  --cardinality unknown --temporal same-retention-window \
  --confidence medium --provenance contract:microsoft-identifier
xdr schema validate-core --document docs/schema_pivots.md
```

Every semantic decision is supplied explicitly; nothing is inferred from
match counts:

| Flag | Required | Meaning |
|---|---|---|
| `--output FILE` | yes | New review-only JSONL; never overwrites |
| `--relationship` | yes | `semantic-equivalent`, `join-compatible`, `transform-required`, `bridge`, or `correlation-only` |
| `--direction` | yes | `forward`, `reverse`, or `both`, relative to the reported source/target |
| `--cardinality` | yes | `one-to-one`, `one-to-many`, `many-to-one`, `many-to-many`, or `unknown`; joins cannot use `unknown` |
| `--temporal` | yes | Reviewed time guidance as a repository-safe slug |
| `--confidence` | yes | `low`, `medium`, or `high` |
| `--provenance` | no | Review/contract citation such as `contract:microsoft-device-id`; repeatable |
| `--confirm-interpretation ID` | per endpoint | Exact candidate interpretation ID added to core; repeat for every non-core endpoint shown by `discoveries` |
| `--acknowledge-independent-contract` | conditional | Required with `contract:`/`documentation:` provenance for `join-compatible` or `bridge` claims |

`validate-core` checks the packaged graph and profile after a human-reviewed
edit to the core JSONL. `--document PATH` also checks the generated block in
a reference document, normally `docs/schema_pivots.md`; `--update-document`
atomically rewrites that block. It never contacts a tenant.

## Pivot and path semantics

`pivot` starts from a field locator and returns usable one-hop investigation
routes. `path` returns routes between tables, searching up to `--max-depth`
relationship hops (1-12, default 4). Observed and validated routes are
included by default; only true `candidate` hypotheses require
`--include-candidates`.

Rows expose `EvidenceLevel`, `Observed`, `Validated`, `Candidate`, and
`JoinSafe`. Route ranking prefers validated, then live-observed evidence. Untested
saved-result overlaps have low confidence and share the authored-route evidence
tier, where stronger route semantics rank first. Candidates remain last.
Per-step output includes transform, cardinality, temporal
guidance, confidence, provenance, entity kind, namespace, role, and physical
availability.

Use `SemanticallyReviewed` and `EmpiricallyValidated` to distinguish repository
review from tenant evidence. `SemanticallyReviewed=true` means the route's
`EvidenceLevel` is `reviewed`; it does not claim that this tenant was queried.
`EmpiricallyValidated=true` means the level is `validated` under the independent
artifact policy above. Neither flag asserts that every value joins safely or
that the route has just been tested against current tenant data. The legacy
`Validated` flag is the union of these two states and is retained for compatibility;
do not interpret it alone as live tenant confirmation. Field availability and
successful cache-only navigation are separate from empirical validation.
`EmpiricallyValidated=false` on a reviewed route identifies its reported evidence
level; it does not mean tenant evidence was checked and failed. Reviewed core
contracts keep that level even when tenant observations corroborate them.

`schema init` imports a content-bound XDRInternals snapshot. Reference mappings
start trusted, with their original provenance and conditions. Cache-only route
composition checks whether the current compiler can enforce those conditions;
unsupported conditions prevent tenant use. `TenantMatched` requires verified
evidence from the current query contract. Reference trust is separate from
semantic review and the independent-artifact `EmpiricallyValidated` policy.
Downloading a mapping or finding its outer columns is not validation of its
conditions or nested paths.

Path output distinguishes:

- `direct-join`: one reviewed join-compatible edge;
- `multi-hop-join`: every step is reviewed and join-compatible; and
- `sequential-pivot`: extract normalized values, query the next table, and
  continue. Observed and validated empirical edges are always in this class.

Tenant-provisional interpretations cannot seed another observation fan-out.
This prevents an empirical hit from recursively assigning tentative semantics
to unrelated fields.

## Nested JSON fields

Nested locators use a JSON-pointer-like suffix:

```text
CloudAppEvents.RawEventData#/UserId
DeviceEvents.AdditionalFields#/SomeKey
```

The outer dynamic column must exist in the physical cache. A nested key becomes
queryable only after the reviewed packaged graph or passive artifact-shape
ingestion establishes that exact path. Unseen arbitrary object keys are not
guessed because payload values may be tenant-specific users, devices, domains,
or copied text.

Encoded JSON strings are expanded only for the documented physical JSON-string
columns; native dynamic objects remain traversable. Free-text strings do not
create nested schema fields merely because their content resembles JSON.
Address exploration currently supports ASCII addresses only; receipts expose
that normalization scope. It does not claim Python casefold/IDNA equivalence
with KQL `tolower` for non-ASCII values.

## BloodHound OpenGraph

Export the packaged graph or the current value-free tenant graph:

```bash
xdr schema export-opengraph current-schema.opengraph.json
xdr schema export-opengraph current-schema.opengraph.json --include-tenant
xdr schema export-opengraph current-schema.opengraph.json \
  --include-tenant \
  --include-candidates
```

`--include-tenant` includes observed/validated tenant growth. The separate
`--include-candidates` flag adds unverified candidate relationships. Concrete
identifiers and private result rows never enter the export. Existing output is
not overwritten unless `--force` is explicit.

In BloodHound Community Edition, upload the file through **Quick Upload**, wait
for **File Ingest** to complete, then open **Explore → Cypher**. Generic
OpenGraph ingest merges nodes and edges into the database; it does not create a
named graph or saved query. The Quick Upload ID is an ingest job ID.

xdr-cli uses source kind `XDR_CLI`. Node Object IDs begin with readable schema
locators, such as `DeviceProcessEvents.DeviceId_XDR_CLI_Field`. Re-uploading
a replacement export merges into the existing `XDR_CLI` source; remove that
source under BloodHound database administration first if a single clean
snapshot is desired.

### Node labels and icons

BloodHound labels a node with its `name` property, then `displayname`, then
Object ID, and its Explore canvas cuts labels after 20 characters. Every
exported node therefore has a short `name`: the table name for tables, the
column (with any JSON path joined by `.`) for fields, and the entity kind or
namespace for meaning nodes. `displayname` keeps the full `Table.Column`
locator, which BloodHound shows in the entity panel. Selecting a node also
shows its canvas label unclipped.

BloodHound CE 9.5.1 uppercases imported `name` values (and Object IDs), so
canvas labels appear uppercase. The full `displayname` locator retains its
original case.

All node kinds otherwise render as the same icon. Write a styling file for
BloodHound's custom-node API alongside the export:

```bash
xdr schema export-opengraph current-schema.opengraph.json \
  --custom-nodes current-schema.custom-nodes.json
```

The file is the request body for `POST /api/v2/custom-nodes`. It gives
`XDR_Table`, `XDR_Field`, `XDR_EntityKind`, and `XDR_IdentifierNamespace` their
own Font Awesome icon and color. Send it once per BloodHound instance;
xdr-cli never contacts BloodHound itself. The example uses a session JWT (the
`session_token` from `POST /api/v2/login`). BloodHound API keys use signed
requests instead of a bearer header.

```bash
curl -X POST "https://bloodhound.example/api/v2/custom-nodes" \
  -H "Authorization: Bearer $BLOODHOUND_JWT" \
  -H "Content-Type: application/json" \
  --data @current-schema.custom-nodes.json
```

If a kind is already registered, the `POST` returns `409 Conflict`; update it
with `PUT /api/v2/custom-nodes/{kind_name}` instead. The update body wraps that
kind's styling in `config`, for example:

```json
{"config":{"icon":{"type":"font-awesome","name":"table","color":"#2F7DD1"}}}
```

`--custom-nodes` must name a different file than the export and follows the
same `--force` rule. Both files are staged before either is published, so a
staging failure leaves existing destination files unchanged. Publication is
atomic per file, not across both files. If the graph is published but styling
publication fails, the command emits a durable graph receipt followed by a
partial-success error (exit 14). `context.failed_output_path` identifies the
failed destination; `custom_nodes_path` is only reported after styling succeeds.

The table-level map shows only `XDR_Table` nodes, so every node in that view
uses the same blue table icon. To see all four styles together, run:

```cypher
MATCH p=(t:XDR_Table {xdrid:'table:DeviceInfo'})
  -[:XDR_ContainsField]->
  (f:XDR_Field {xdrid:'field:DeviceInfo.DeviceId'})
  -[:XDR_RepresentsEntity|XDR_UsesNamespace]->()
RETURN p
```

This shows a blue table, gray columns, an orange fingerprint for the entity
kind, and a green key for the identifier namespace.

### Table-level pivot map

Besides the field-level graph, the export links tables directly: one edge per
table pair and kind of pivot, summarizing the field relationships between
them. This is the most readable view on the canvas:

```cypher
MATCH p=(:XDR_Table)-[:`Join`|NormalizeJoin|SameEntity|Correlate|Bridge]->(:XDR_Table)
RETURN p
```

Keep the backticks around `Join`: BloodHound CE treats it as a reserved word.

| Edge kind | Field relationship | Meaning |
|---|---|---|
| `Join` | `join-compatible` | Same identifier on both sides; join directly |
| `NormalizeJoin` | `transform-required` | Same entity; normalize first, then join |
| `SameEntity` | `semantic-equivalent` | Same entity, but the value can change |
| `Correlate` | `correlation-only` | Shared values, not a key; match inside a time window |
| `Bridge` | `bridge` | Contract-backed link between different identifiers (none ship today) |

Each table edge carries `keys` (the `Source.Field=Target.Field` locator pairs
it summarizes), `relationshipids` (the field-level relationship IDs), `count`,
the weakest `status`/`evidencelevel` and `confidence` among them,
`direction`, `join_safe`, and `traversable`. Status and confidence are
conservative lower bounds for all listed keys. `statuses` and `confidences`
list the distinct member values; `candidatecount` makes unreviewed members
explicit. `traversable` is true only when every member is usable. Transform,
cardinality, timing, and individual evidence details stay on the field-level
edges, identified by `relationshipids`.

There is one summary per emitted start table, end table, and kind. Bidirectional
members use lexical table-name order; forward and reverse members follow their
semantic direction. Overlapping bidirectional and forward groups merge, with
`direction: "mixed"` and a `directions` list. The direction properties describe
the data; they do not create reverse BloodHound edges. For a neighborhood view
of bidirectional pivots, use an undirected pattern (`-[r]-`) and inspect the
field-level direction before constructing a directed route.

The table edge kinds are plain words so the canvas labels stay short. Other
BloodHound sources may use the same words, so always anchor table-edge queries
on `XDR_Table` at both ends, as above.

Table-to-field structure:

```cypher
MATCH p=(t:XDR_Table)-[:XDR_ContainsField]->(f:XDR_Field)
RETURN p
LIMIT 200
```

All direct semantic routes:

```cypher
MATCH p=(a:XDR_Field)-[r]-(b:XDR_Field)
RETURN p
LIMIT 200
```

Observed and validated empirical routes:

```cypher
MATCH p=(a:XDR_Field)-[r]-(b:XDR_Field)
WHERE r.status IN ["observed", "validated"]
RETURN p
LIMIT 200
```

Cross-table routes with meaning nodes:

```cypher
MATCH tablePath=
  (sourceTable:XDR_Table)
  -[:XDR_ContainsField]->
  (sourceField:XDR_Field)
  -[route]-
  (targetField:XDR_Field)
  <-[:XDR_ContainsField]-
  (targetTable:XDR_Table)
WHERE sourceTable <> targetTable
OPTIONAL MATCH sourceMeaning=
  (sourceField)-[:XDR_RepresentsEntity|XDR_UsesNamespace]->(sourceType)
OPTIONAL MATCH targetMeaning=
  (targetField)-[:XDR_RepresentsEntity|XDR_UsesNamespace]->(targetType)
RETURN tablePath, sourceMeaning, targetMeaning
LIMIT 300
```

Routes beginning at one table:

```cypher
MATCH tablePath=
  (sourceTable:XDR_Table)
  -[:XDR_ContainsField]->
  (sourceField:XDR_Field)
  -[route]-
  (targetField:XDR_Field)
  <-[:XDR_ContainsField]-
  (targetTable:XDR_Table)
WHERE sourceTable.displayname = "DeviceInfo"
  AND sourceTable <> targetTable
RETURN tablePath
LIMIT 200
```

For multi-hop routes, constrain both every node and every relationship. Run the
one-, two-, and three-hop forms separately; these avoid the `all(node IN ...)`
predicate that BloodHound's Cypher parser rejects while preventing containment
or meaning nodes from appearing in the route. The relationship type list is the
complete set of xdr-cli semantic field-to-field edge kinds.

One hop:

```cypher
MATCH left=
  (sourceTable:XDR_Table)
  -[:XDR_ContainsField]->
  (sourceField:XDR_Field),
  fieldPath=
  (sourceField)
  -[r1:XDR_SemanticEquivalent|XDR_JoinCompatible|XDR_TransformRequired|XDR_Bridge|XDR_CorrelationOnly]-
  (targetField:XDR_Field),
  right=
  (targetTable:XDR_Table)
  -[:XDR_ContainsField]->
  (targetField)
WHERE sourceTable <> targetTable
RETURN left, fieldPath, right
LIMIT 200
```

Two hops:

```cypher
MATCH left=
  (sourceTable:XDR_Table)
  -[:XDR_ContainsField]->
  (sourceField:XDR_Field),
fieldPath=
  (sourceField)
  -[r1:XDR_SemanticEquivalent|XDR_JoinCompatible|XDR_TransformRequired|XDR_Bridge|XDR_CorrelationOnly]-
  (:XDR_Field)
  -[r2:XDR_SemanticEquivalent|XDR_JoinCompatible|XDR_TransformRequired|XDR_Bridge|XDR_CorrelationOnly]-
  (targetField:XDR_Field),
right=
  (targetTable:XDR_Table)
  -[:XDR_ContainsField]->
  (targetField)
WHERE sourceTable <> targetTable
RETURN left, fieldPath, right
LIMIT 200
```

Three hops:

```cypher
MATCH left=
  (sourceTable:XDR_Table)
  -[:XDR_ContainsField]->
  (sourceField:XDR_Field),
fieldPath=
  (sourceField)
  -[r1:XDR_SemanticEquivalent|XDR_JoinCompatible|XDR_TransformRequired|XDR_Bridge|XDR_CorrelationOnly]-
  (:XDR_Field)
  -[r2:XDR_SemanticEquivalent|XDR_JoinCompatible|XDR_TransformRequired|XDR_Bridge|XDR_CorrelationOnly]-
  (:XDR_Field)
  -[r3:XDR_SemanticEquivalent|XDR_JoinCompatible|XDR_TransformRequired|XDR_Bridge|XDR_CorrelationOnly]-
  (targetField:XDR_Field),
right=
  (targetTable:XDR_Table)
  -[:XDR_ContainsField]->
  (targetField)
WHERE sourceTable <> targetTable
RETURN left, fieldPath, right
LIMIT 200
```

## Results, privacy, and evidence retention

Schema commands are artifact-first. Stdout begins with a compact receipt and
at most two preview rows. Read `context.shown`, `total`, and `has_more`; use the
exact `context.results_command` to page the full local JSONL artifact.

Source samples, explicit seeds, exact KQL, and target rows stay in private,
tenant-bound, digest-verified result artifacts. The tenant overlay stores only
value-free fields, interpretations, stable IDs, aggregate observations, and
evidence references. `--private-debug-output` is deliberately sensitive and
must not be committed or shared.

Active automatic evidence references the original hunt/library bundles, including
their complete private results. Portable exports include those referenced bundles;
they can be large and contain user identifiers. Retirement removes automatic pins
before normal result pruning, rather than silently keeping aged hunts forever.

Routine retention needs only result pruning:

```bash
xdr results prune --older-than 90 --yes
```

Result pruning retires automatic overlap, validation, and discovery
observations that reference artifacts older than the requested cutoff before
deleting those artifacts. A persistent tenant cutoff prevents subsequent
collection from mining retired artifacts again, even if a proposal still
protects their bytes. Explicit `observe` observations and live proposal pins
remain protected, so their artifacts are kept. Integrity failures stop
pruning.

`prune-evidence` is only needed when explicit observations should go too. It
rewrites the private overlay, keeps discovered fields and interpretations,
never deletes result artifacts, and persists the cutoff even when no
observations exist yet. Observations without an observation timestamp are
kept unless `--include-legacy` is passed. Run result pruning afterwards:

```bash
xdr schema prune-evidence --older-than 90 --yes
xdr schema prune-evidence --older-than 90 --include-legacy --yes
xdr results prune --older-than 90 --yes
```

Automatic discovery accepts structured identifiers and sufficiently varied
opaque identifiers, excluding generic words, process names, control characters,
and multicast addresses. Private IPs remain correlation evidence. Nested paths
use simple property names and array wildcards; dotted and SID-shaped dictionary
keys are excluded. Unsupported data contributes coverage gaps, not graph labels.
These heuristics reduce accidental value disclosure; property names supplied by
arbitrary JSON can themselves be sensitive, so tenant overlays remain private.

## Portable state bundles

Move schema state without copying credentials or the whole CLI home:

```bash
xdr schema bundle export /mnt/transfer/schema-state.tar.gz
xdr schema bundle inspect /mnt/transfer/schema-state.tar.gz
xdr schema bundle import /mnt/transfer/schema-state.tar.gz --yes
```

Inspection is read-only and works for foreign-tenant archives. Import requires
the configured tenant fingerprint and tenant key to match, a trusted archive
source, and collision-free destinations. The manifest and SHA-256 bindings
prove content integrity and routing, not authorship.

Bundles include the current and retained physical/semantic generations,
their manifests, maintenance state, and referenced evidence.
`--no-include-evidence` drops the referenced result pairs, candidate reviews,
and proposals (`--include-evidence` is the default and is required when
evidence exists). Session history is excluded by default; `--include-sessions`
adds session JSONL and sequence sidecars but never active markers. Bundles
always exclude configuration, tokens, cookies, query libraries, active-session
markers, locks, audit logs, and other machine-local state. Import permits
tenant-local persisted relationships only as candidates, validates evidence
references and session contracts, relocates absolute result/proposal paths,
and never overwrites existing files. Imported observations are useful, but
automatic validation still reopens the imported artifacts and enforces the
same source/target contracts described above.

Inspection streams every member, checking its type, size, and digest, and
rejects an archive whose uncompressed size exceeds 256 MiB; the member list
is then checked against a strict portable-namespace allowlist. Credentials,
configuration, cookies, locks, active-session markers, and audit logs are
rejected if they are injected into an archive, not merely skipped. Import
refuses collisions without relying on hard-link support, so the
no-overwrite guarantee holds on filesystems that limit or forbid hard links.
Imported session IDs are never renumbered: import refuses any session whose
number is at or below the destination's local per-initials counter, and
otherwise advances that counter so sessions started later cannot collide
with relocated history.
Exported archives and every staged member are owner-only (`0600`) on POSIX,
and a failed validation leaves no published output.

## Diagnostics and recovery

```bash
xdr schema diagnostics
```

`schema status` is cache-only and reports physical-cache state, overlay
integrity/compatibility, collection-marker age, evidence-growth counts, and an
exact `next_command`. That value is, in priority order:

1. the overlay repair command when the overlay needs repair
   (`xdr schema repair-overlay --yes`);
2. `xdr schema migrate-cache --yes` when the cache is valid but has no
   content binding;
3. `xdr schema refresh` when the cache is missing, stale, or invalid;
4. otherwise `xdr schema collect`.

It never suggests `--local-only`, `--plan-only`, or `--explore`; those are
choices you make. Collection progress lives in verified query artifacts;
rerun the same collection command to continue remaining work.

Diagnostics is also cache-only. It reports package/build identity, registered
schema capabilities, physical-cache state, overlay integrity/compatibility,
collection-marker age, and observation/passive-ingestion summaries.

Common recovery paths:

```bash
# Missing/stale/corrupt physical cache (tenant call)
xdr schema refresh

# Valid physical cache without content binding (local)
xdr schema migrate-cache --yes

# Overlay compatibility or retained-generation repair (local)
xdr schema repair-overlay --yes

# Last-resort empty overlay after repair reports no usable generation
xdr schema repair-overlay --reset-empty --yes
```

`repair-overlay` selects the newest structurally valid retained overlay
generation for the configured tenant; `--all-local` repairs every local
tenant overlay, including orphaned generations. When the overlay contract has
drifted, the exact prior overlay files are quarantined before a new
generation is atomically published:
compatible records are retained, obsolete provisional interpretations and
their dependent observations are inactivated, and unsafe nested fields are
excluded. Reviewed-contract conflicts fail closed without changing the
active state. `migrate-cache` content-binds the exact bytes of a validated
physical cache that has no digest binding yet; neither command contacts the
tenant or reads result-row values.

Maintenance advisories appear on stderr and never change stdout JSON. `--quiet`
suppresses them; `--no-quiet` forces them even when stdout is piped.

## Offline correlation

`schema correlate` joins saved result artifacts to each other without running
any KQL. Give it at least two `--input Table=run-id` pairs (run IDs from
`xdr results list`; each must be unique and declare the physical table its
rows came from). Every artifact's sidecar must prove lineage, data digest,
and binding to the active tenant; otherwise the command stops with
`SCHEMA_CORRELATION_TENANT_MISMATCH`. `--allow-tenant-mismatch` overrides
that check for intentional cross-tenant analysis of unbound or
differently-bound artifacts.

```bash
xdr schema correlate \
  --input EntraIdSignInEvents=RUN_ID_1 \
  --input CloudAppEvents=RUN_ID_2
```

Only reviewed relationships from the packaged graph are used. By default a
shared entity counts only across strong edges: `join-compatible`, not
many-to-many, and without mutable or tight-time-window temporal guidance.
`--include-contextual` adds the weaker edges (IP, UPN, hostname, and hash
matches), which the output marks `contextual` because they need the returned
temporal or surrounding-event checks. The receipt reports input, event,
entity, shared-entity, contextual-match, and structural-route counts and
whether tenant binding was verified; rows are saved privately with no stdout
preview. Follow `context.next_command`
(`xdr results rows RUN_ID --type relationship-path-match --limit 100`).
Shared entities are row evidence; a structural route alone is not.

## Command map

| Command | Network | Purpose |
|---|---:|---|
| `schema status` | No | Maintenance state and exact next command |
| `schema diagnostics` | No | Build, capability, cache, overlay, and collection summary |
| `schema refresh` | Yes | Replace the tenant physical-schema cache |
| `schema tables`, `schema show` | No | Browse cached tables and fields (`--search`) |
| `schema collect --plan-only` | No | Index saved results and preview focused validation |
| `schema collect --local-only` | No | Publish saved-result overlaps |
| `schema collect` | When candidates exist | Mine saved results and validate focused targets |
| `schema collect --explore` | When work remains | Capture recent tenant data and discover pivots locally |
| `schema observe --plan-only` | No | Preview one source's targets and request estimate |
| `schema observe` | Yes | Sample/reuse identifiers and crawl target tables |
| `schema discoveries` | No | Report observed/validated routes and policy decisions |
| `schema pivot`, `schema path` | No | Explain usable field/table routes |
| `schema candidate-review` | Yes | Optional bounded private context for one route |
| `schema candidate-proposal` | No | Draft a contributor-owned core JSONL proposal |
| `schema validate-core` | No | Validate the packaged graph/profile and check or update its generated reference block |
| `schema correlate` | No | Correlate saved artifacts offline; see [Offline correlation](#offline-correlation) |
| `schema export-opengraph` | No | Write a value-free BloodHound payload |
| `schema repair-overlay`, `schema migrate-cache` | No | Repair local state |
| `schema bundle inspect/export/import` | No | Inspect or move portable schema state |
| `schema prune-evidence` | No | Retire explicit observations before result pruning |

## Tenant initialization from XDRInternals

Run `xdr schema init` when setting up a tenant. It downloads a content-bound public
XDRInternals snapshot, refreshes physical schema across reference, packaged,
previously observed and portal-listed table names, and executes bounded,
aggregate-only validation KQL for every applicable reference mapping. The private
result contains every reference route, including missing tables and unsupported
conditions. `--reference-dir DIR` imports the four saved provider JSON documents;
`--sync-reference` explicitly replaces the cached public snapshot.

The reference starts trusted. `matched` means the saved validation query found
shared identifiers within its stated scope. `no-source-data`, `no-target-data`
and `no-overlap` remain inconclusive; they do not contradict a reference mapping.
Compiled-check failures and incompatible physical types prevent that tenant route from
being offered. Reference guidance, scope, counts and evidence run IDs accompany
routes; reference trust alone never establishes raw join safety. Existing reviewed
core join contracts retain their authored semantics.

Validation defaults to seven days, fifty source keys, a 1,000-row sample, and at
most 200 queries per invocation. Additional compiler membership-scan caps are
reported in each route's scope; a capped scan cannot establish absence. Results
are tenant-, reference-, schema- and query-bound. Repeated runs reuse verified
results for one day. A budget or service pause saves progress and returns exit 14;
follow the receipt's exact continuation command and honor `retry_after_seconds`.
`--revalidate` reruns fresh results. `--plan-only` uses local caches without tenant
queries or cache publication.

Normal `schema pivot` and `schema path` stay cache-only and omit physically
unusable routes. Use `--include-unavailable` for diagnostics. `ReferenceTrusted`
is separate from semantic review. `TenantMatched` reports a bounded reference
match; `EmpiricallyValidated` retains the stronger independent-artifact policy. Missing or corrupted validation artifacts suppress only the affected
reference routes until initialization revalidates them. Dense path searches have
a work cap and report incomplete search/truncated results in `context.path_search`.

Initialization also saves full table/column comparisons, including tenant-only
columns and type disagreements; physical types from tenant `getschema` take priority.
Refresh continues to discover tables outside the reference through the tenant
portal listing and retained cache names. Exact identifier-column names and verified
portal Entity tags create candidate mappings to available reference hubs. These
share the validation budget and become observed correlation pivots after at least
three distinct shared identifiers; weaker matches stay opt-in candidates and never
inherit reference trust or join safety. Initialization reports the 100-candidate
cap and unmapped tables as coverage gaps. Existing `schema observe` and
`schema collect --explore` workflows remain available for fields without usable
name/tag hints and tenant-specific nested paths.

### Validation compatibility and evidence retention

Route composition derives scope and conditions from the running compiler, even
before a validation ledger exists. Saved matches must still match that compiler,
reference, tenant, options and physical-schema binding. A changed contract retires
the match claim until initialization reruns. Verified failed checks remain
suppressed across unrelated schema refreshes and budget pauses until revalidated.
Unverifiable type conditions, such as a workload-dependent cloud `Target` value,
are reported as unsupported rather than promoted to unconditional user semantics.

Generic `schema observe` does not use runtime-only imported interpretations as
sources. It can still test packaged sources against new fields using self-contained
neutral provisional targets; known contextual constraints cannot be bypassed by
such a fallback. Older observations with missing interpretation definitions are
excluded from composition and reported in status and route coverage diagnostics.
Their private records and artifacts are not silently deleted.

`results prune` preserves verified evidence pinned by current reference ledgers
and live scope pointers across all local tenants. Active corruption fails pruning
closed. Per-query obsolete ledger generations are cleaned up in bounded batches;
live pointer targets remain intact. Authentication, permission, configuration and
artifact errors keep their original exit classes. Only transient rate, timeout
and network failures pause validation with exit 14 and a continuation.

Reference trust describes mapping provenance, not instruction authority. Free-form
third-party titles and guidance remain in the private artifact; automatic previews
show structured locators, conditions and reference IDs instead of that prose.
