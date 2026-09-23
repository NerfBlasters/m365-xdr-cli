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
xdr schema collect --plan-only --exhaustive
```

Run routine or exhaustive collection:

```bash
xdr schema collect
xdr schema collect --exhaustive
```

Collection prints a private checkpoint ID to stderr before the tenant work.
It checkpoints after bounded pages and normally continues those pages itself.
If an authentication, rate-limit, network, or process failure stops the run,
resume the exact stored plan:

```bash
xdr schema collect --resume collect-0123456789abcdef01234567
```

Do not add source or planning flags to `--resume`; the tenant-bound checkpoint
already contains the source matrix, limits, timeout, and remaining commands.
The refreshed physical schema generation is pinned before the first observe
page, and source evidence is pinned by every continuation, so a changed cache
fails closed instead of mixing generations. Resume and bundle import validate
the complete checkpoint contract; a checkpoint may invoke only `schema
refresh`, its bounded `schema observe` pages, and `schema discoveries`.

Inspect learned routes and use them during an investigation:

```bash
xdr schema discoveries
xdr schema pivot DeviceNetworkEvents.DeviceId
xdr schema path DeviceNetworkEvents DeviceProcessEvents
```

`xdr schema candidates` remains a compatibility alias for `discoveries`.

## What collection scans

The default source matrix is:

```text
DeviceNetworkEvents.DeviceId
EntraIdSignInEvents.AccountUpn
EntraIdSignInEvents.AccountObjectId
DeviceFileEvents.SHA256
EmailEvents.NetworkMessageId
CloudAppEvents.RawEventData#/UserId
```

Those are six reviewed source locators across five tables. They are not a
target-table allowlist. For each source, target planning considers eligible
string/dynamic locators across every table present in the tenant’s physical
cache. The curated physical catalog currently documents 80 tables, but a
tenant may expose fewer. A target table must have `Timestamp` or
`TimeGenerated`; that column independently bounds the scan window and is never
the correlation key.

Routine collection intentionally caps each source at 40 prioritized targets.
That makes it safe for recurring automation, but it is not full-catalog
coverage. `--plan-only --exhaustive` reports the full eligible target set;
`--exhaustive` crawls it.

Replace the source matrix with repeatable `--source` options:

```bash
xdr schema collect \
  --source DeviceNetworkEvents.DeviceId \
  --source IdentityInfo.AccountObjectId
```

Routine defaults are a 30-day lookback, five rare valid source identifiers,
20 target locators per compiler chunk, 40 targets per source, a 120-second
per-query timeout, and a checkpoint page of 20 table queries. Override the page
size without changing semantic coverage:

```bash
xdr schema collect --max-queries-per-page 10
```

Executable budgets are bounded even in imported checkpoints: target caps are
1-10,000, source matrices contain at most 100 locators, per-query timeouts are
1-3,600 seconds, checkpoint pages are 1-1,000 target-table queries, and resume
cursors cannot exceed 10,000. `--exhaustive` remains bounded by the eligible
locators in the pinned physical catalog.

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

A finished run reports `collection_outcome=complete` or
`complete-with-gaps`; an operationally paused checkpoint reports `incomplete`.
Status retains the quarantined table list instead of presenting a gapped crawl
as full coverage.

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

A completed positive observation immediately creates a bidirectional,
correlation-only `observed` investigation pivot. It is useful for discovering a
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
- at least two distinct sampled seed cohorts containing at least six distinct
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
`JoinSafe`. Route ranking prefers reviewed, then validated, then observed, then
candidate edges. Per-step output includes transform, cardinality, temporal
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
locators, such as `DeviceProcessEvents.DeviceId_XDR_CLI_Field`, because
BloodHound may render Object ID instead of `displayname` on the canvas. Exports
from older builds that used opaque IDs remain separate nodes; remove the old
`XDR_CLI` source under BloodHound database administration before uploading a
replacement if a single clean snapshot is desired.

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

Retire old observations before pruning their referenced results:

```bash
xdr schema prune-evidence --older-than 90 --yes
xdr results prune --older-than 90 --yes
```

Result pruning protects artifacts referenced by active observations,
candidate-review artifacts, and active candidate proposals. Integrity failures
stop pruning rather than silently discarding evidence.

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

Bundles include active physical/semantic generations, collection checkpoints,
and referenced evidence needed by a pending `--from-run` continuation.
They exclude configuration, tokens, cookies, query libraries, active-session
markers, locks, audit logs, and other machine-local state. Import permits
tenant-local persisted relationships only as candidates, validates evidence
references and session contracts, relocates absolute result/proposal paths,
and never overwrites existing files. Imported observations are useful, but
automatic validation still reopens the imported artifacts and enforces the
same source/target contracts described above. Imported checkpoints are also
restricted to the read-only schema child-command allowlist described in the
collection section.

## Diagnostics and recovery

```bash
xdr schema diagnostics
```

`schema status` is cache-only and reports physical-cache state, overlay
integrity/compatibility, collection-marker age, evidence-growth counts, and an
exact `next_command`. A checkpoint pinned to a missing/replaced physical
generation is reported as incompatible rather than recommended in a resume
loop; a checkpoint older than a later completed collection is superseded for
status purposes. The command shipped after the original 0.8.0 feature
build; if an installed 0.8.0 reports `CLI_UNKNOWN_COMMAND`, use `schema
diagnostics` on a current build or update/reinstall before following this
workflow.

Diagnostics is also cache-only. It reports package/build identity, registered
schema capabilities, physical-cache state, overlay integrity/compatibility,
collection-marker age, and observation/passive-ingestion summaries.

Common recovery paths:

```bash
# Missing/stale/corrupt physical cache (tenant call)
xdr schema refresh

# Compatible legacy cache without content binding (local)
xdr schema migrate-cache --yes

# Overlay compatibility or retained-generation repair (local)
xdr schema repair-overlay --yes

# Last-resort empty overlay after repair reports no usable generation
xdr schema repair-overlay --reset-empty --yes
```

Maintenance advisories appear on stderr and never change stdout JSON. `--quiet`
suppresses them; `--no-quiet` forces them even when stdout is piped.

## Command map

| Command | Network | Purpose |
|---|---:|---|
| `schema status` | No | Maintenance state and exact next command |
| `schema diagnostics` | No | Build, capability, cache, overlay, and collection summary |
| `schema refresh` | Yes | Replace the tenant physical-schema cache |
| `schema tables`, `schema show` | No | Browse cached tables and fields |
| `schema collect --plan-only` | No | Preview every configured source plan |
| `schema collect` | Yes | Refresh, crawl, checkpoint, validate, and report discoveries |
| `schema collect --resume ID` | Yes | Continue an interrupted stored plan |
| `schema observe --plan-only` | No | Preview one source’s targets and request estimate |
| `schema observe` | Yes | Sample/reuse identifiers and crawl target tables |
| `schema discoveries` | No | Report observed/validated routes and policy decisions |
| `schema candidates` | No | Compatibility alias for `discoveries` |
| `schema pivot`, `schema path` | No | Explain usable field/table routes |
| `schema candidate-review` | Yes | Optional bounded private context for one route |
| `schema candidate-proposal` | No | Draft a contributor-owned core JSONL proposal |
| `schema correlate` | No | Correlate retained tenant-bound artifacts |
| `schema export-opengraph` | No | Write a value-free BloodHound payload |
| `schema repair-overlay`, `schema migrate-cache` | No | Repair compatible local state |
| `schema bundle inspect/export/import` | No | Inspect or move portable schema state |
| `schema prune-evidence` | No | Retire stale observations before result pruning |
