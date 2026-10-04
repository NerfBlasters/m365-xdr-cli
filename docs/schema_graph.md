# Semantic schema graph

The physical schema cache answers “which tables and columns exist in this
tenant?” The semantic graph answers “which fields may carry the same entity
identifier, and what investigation workflow is safe?” They are separate on
purpose. Equal values can justify another investigation pivot without proving
that a raw KQL join is selective, cardinality-safe, or semantically equivalent.

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

Preview collection before making tenant calls:

```bash
xdr schema collect --plan-only
xdr schema collect --explore --plan-only
```

Run routine collection or active exploration:

```bash
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

`xdr schema candidates` remains a compatibility alias for `discoveries`.

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
The saved query remains the source of truth for both old and new artifacts.

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
validation is saved; exit 14 indicates useful partial completion. Rerun the same
command to re-plan remaining work. Local-only/plan-only can work without a physical
cache; validation needs cached target fields and Timestamp or TimeGenerated.
Refresh a missing/stale cache explicitly with `xdr schema refresh`.

Local-derived pivots appear in normal navigation and support private
`candidate-review` context queries. They do not use `candidate-proposal`'s
legacy active-probe-to-core promotion workflow; their generic identifier
interpretations are empirical occurrence hypotheses, not authored entity claims.
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


## Explicit active exploration

`schema collect --explore` takes eligible identifiers from every supported saved
hunt/library artifact. There is no fixed starter-field matrix or target-field
sweep. Searches use cached tables with `Timestamp` or `TimeGenerated` and report
tables excluded for lacking a time column. Refresh stale physical availability
explicitly with `schema refresh`.

Each query searches a batch of identifiers across a group of tables, expands
nested JSON containers, and returns explicit table, column, path, matched value,
and count fields. Substring matching narrows the scan; only exact normalized
leaf-value matches become observations. Unsupported paths, depth limits, and
result caps are reported as coverage gaps, never evidence of absence. Concrete
values and query text stay in private artifacts.

Optionally restrict which saved fields supply identifiers:

```bash
xdr schema collect --explore \
  --source DeviceNetworkEvents.DeviceId \
  --source IdentityInfo.AccountObjectId
```

Defaults are a 30-day lookback, 20 identifiers per query batch, six JSON expansion
levels, 2,000 result rows per query, a 120-second timeout, and 20 queries per
invocation. Tables are grouped into batches of at most 100. Batching and the
invocation budget divide work; they do not silently discard the remaining
identifiers or eligible tables. `--samples` controls focused local validation,
not active discovery. Use `--max-json-depth` (up to 12) or
`--discovery-row-limit` (up to 10,000) when the receipt reports those gaps.

```bash
xdr schema collect --explore --seed-batch-size 20 --max-queries-per-page 10
```

Saved search evidence is verified against its originating artifacts before reuse.
A successful search can directly add an observed pivot to a previously unknown
field, without a redundant follow-up probe. With no eligible saved identifiers,
exploration reports no work rather than starting a blind scan.

## How observe compiles and crawls

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

`candidate-proposal` is a contributor workflow for drafting a value-free core
JSONL change. It does not promote tenant evidence, edit the repository, or turn
an empirical pivot into a join. Join/bridge proposals require explicit
independent-contract provenance:

```bash
xdr schema candidate-proposal <relationship-id> --help
xdr schema validate-core --document docs/schema_pivots.md
```

## Pivot and path semantics

`pivot` starts from a field locator and returns usable one-hop investigation
routes. `path` returns routes between tables. Observed and validated routes are
included by default; only true `candidate` hypotheses require
`--include-candidates`.

Rows expose `EvidenceLevel`, `Observed`, `Validated`, `Candidate`, and
`JoinSafe`. Route ranking prefers validated, then live-observed evidence. Untested
saved-result overlaps have low confidence and share the authored-route evidence
tier, where stronger route semantics rank first. Candidates remain last.
Per-step output includes transform, cardinality, temporal
guidance, confidence, provenance, entity kind, namespace, role, and physical
availability.

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
before normal result pruning, rather than silently keeping old hunts forever.

Retire old observations before pruning their referenced results:

```bash
xdr schema prune-evidence --older-than 90 --yes
xdr results prune --older-than 90 --yes
```

Result pruning retires automatic overlap, validation, and discovery observations
that reference artifacts older than the requested cutoff before deleting those
artifacts. A persistent tenant cutoff prevents subsequent collection from mining
retired artifacts again, even if a proposal still protects their bytes. Explicit
observation and live proposal pins remain protected. `prune-evidence` also
persists the cutoff, including when no observations have been collected yet. Integrity failures stop pruning.

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

Bundles include active physical/semantic generations and referenced evidence.
They exclude configuration, tokens, cookies, query libraries, active-session
markers, locks, audit logs, and other machine-local state. Import permits
tenant-local persisted relationships only as candidates, validates evidence
references and session contracts, relocates absolute result/proposal paths,
and never overwrites existing files. Imported observations are useful, but
automatic validation still reopens the imported artifacts and enforces the
same source/target contracts described above.

Inspection streams a strict portable-member allowlist and rejects an archive
whose uncompressed size exceeds 256 MiB. Credentials, configuration, cookies,
locks, active-session markers, and audit logs are rejected if they are
injected into an archive, not merely skipped. Import refuses collisions
without relying on hard-link support, so the no-overwrite guarantee holds on
filesystems that limit or forbid hard links, and it coordinates imported
session IDs with the local per-initials session counters so relocated
history cannot collide with sessions started later on the destination.
Exported archives and every staged member are owner-only (`0600`) on POSIX,
and a failed validation leaves no published output.

## Diagnostics and recovery

```bash
xdr schema diagnostics
```

`schema status` is cache-only and reports physical-cache state, overlay
integrity/compatibility, collection-marker age, evidence-growth counts, and an
exact `next_command`. Collection progress lives in verified query artifacts;
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
generation. When the overlay contract has drifted, the exact prior overlay
files are quarantined before a new generation is atomically published:
compatible records are retained, obsolete provisional interpretations and
their dependent observations are inactivated, and unsafe nested fields are
excluded. Reviewed-contract conflicts fail closed without changing the
active state. `migrate-cache` content-binds the exact bytes of a validated
physical cache that has no digest binding yet; neither command contacts the
tenant or reads result-row values.

Maintenance advisories appear on stderr and never change stdout JSON. `--quiet`
suppresses them; `--no-quiet` forces them even when stdout is piped.

## Command map

| Command | Network | Purpose |
|---|---:|---|
| `schema status` | No | Maintenance state and exact next command |
| `schema diagnostics` | No | Build, capability, cache, overlay, and collection summary |
| `schema refresh` | Yes | Replace the tenant physical-schema cache |
| `schema tables`, `schema show` | No | Browse cached tables and fields |
| `schema collect --plan-only` | No | Index saved results and preview focused validation |
| `schema collect --local-only` | No | Publish saved-result overlaps |
| `schema collect` | When candidates exist | Mine saved results and validate focused targets |
| `schema collect --explore` | When work remains | Find saved identifiers in new fields and nested paths |
| `schema observe --plan-only` | No | Preview one source’s targets and request estimate |
| `schema observe` | Yes | Sample/reuse identifiers and crawl target tables |
| `schema discoveries` | No | Report observed/validated routes and policy decisions |
| `schema candidates` | No | Compatibility alias for `discoveries` |
| `schema pivot`, `schema path` | No | Explain usable field/table routes |
| `schema candidate-review` | Yes | Optional bounded private context for one route |
| `schema candidate-proposal` | No | Draft a contributor-owned core JSONL proposal |
| `schema validate-core` | No | Validate the packaged graph/profile and check or update its generated reference block |
| `schema correlate` | No | Correlate retained tenant-bound artifacts |
| `schema export-opengraph` | No | Write a value-free BloodHound payload |
| `schema repair-overlay`, `schema migrate-cache` | No | Repair compatible local state |
| `schema bundle inspect/export/import` | No | Inspect or move portable schema state |
| `schema prune-evidence` | No | Retire stale observations before result pruning |

Explicit session end refreshes a missing/stale physical cache, runs local-first
collection, and explores new identifier locations. The exploration budget is
`schema_explore_max_queries = 5` by default, separate from focused validation's
20-query budget. `schema_collect_on_session_end = false` disables all stages;
refresh and exploration also have individual off switches. Completed work is
reused at subsequent explicit ends; idle expiry and rotation never trigger it.
See [session maintenance](sessions.md).

Collection receipts distinguish pending work from excluded scope. Cached tables
without a usable time column, unavailable targets, and unsupported property paths
are recorded in `excluded_scope`. Completing eligible work can return success
while reporting those exclusions. Budget exhaustion, output truncation, depth
limits, and upstream failures remain partial. A valid source selector
with no saved identifiers returns not-found. Completion history outlives the
one-day refresh interval: never-tested cohorts run first, followed by the oldest
verified cohorts. Old evidence can guide scheduling without satisfying the
30-day freshness requirement for promotion.

Encoded JSON strings are expanded only for the documented physical JSON-string
columns; native dynamic objects remain traversable. Free-text strings do not
create nested schema fields merely because their content resembles JSON.
Address exploration currently supports ASCII addresses only; receipts expose
that normalization scope. It does not claim Python casefold/IDNA equivalence
with KQL `tolower` for non-ASCII values.
