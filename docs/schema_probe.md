# Schema Probe Workflow

How to discover which Advanced Hunting tables and columns your tenant
actually exposes, and turn that into a reusable pivot reference for the
SOC and for AI agents.

Three pieces work together:

- **`sys_schema_probe`** — a library KQL query that enumerates a curated
  **80-table** Advanced Hunting catalog via `union isfuzzy=true ... | getschema`,
  covering Defender XDR plus Sentinel and Entra workspace tables. Add custom
  logs and future workspace tables explicitly; KQL does not expose a
  metadata-only way to enumerate all connected-workspace tables.
- **`scripts/build_schema_pivots.py`** — a Python renderer that takes the
  probe's CSV output and produces a grep-friendly markdown doc of every
  cross-table field intersection.
- **`docs/schema_pivots.md`** — the rendered output: for each shared field
  name, the exhaustive list of tables containing it, plus worked pivot
  recipes for the common investigation chains.

---

## Why bother?

- **Tenants differ.** Which table schemas are queryable depends on licensing,
  permissions, region, and connected workspaces. The probe tells you which
  curated schemas the current hunting identity can resolve. It does **not**
  prove that a table contains recent rows or identify the tenant's licensed
  SKU by itself.
- **Pivots are non-obvious.** `AccountObjectId` reaches device processes,
  Entra sign-ins, MDI, MDCA, Graph API audit, alerts — but no single
  doc page lists all of them together. The pivot reference does.
- **KQL authors need truth, not hope.** A query that assumes
  `IdentityLogonEvents` exists fails cryptically in a tenant without
  MDI. A quick probe up-front avoids that.
- **AI agents need structured context.** The rendered doc is a compact,
  grep-friendly payload you can hand to an agent writing hunt KQL — it's
  small enough to fit in a prompt and precise enough to steer joins.

---

## Quick start

`schema refresh` is deliberate and consumes one Advanced Hunting call. Schema
browsing is cache-only and does not create or require a session.
The cache records physical availability only. Semantic equivalence and safe
route guidance come from `xdr schema pivot/path` and `docs/schema_graph.md`;
they are never inferred from matching column names in this probe.
The semantic probe planner also uses the cached `ColumnType` values to build a
closed target catalog: every string/dynamic field is eligible for deterministic
same-value observation even when its name has no public semantic record.

### 1. Run the probe

```bash
xdr schema refresh
xdr schema tables --search signin
xdr schema show AADSignInEventsBeta --search application
```

`schema tables --search` searches table names only. To search column names,
first select a table and use `schema show TABLE --search TERM`. These commands
browse physical availability; use `xdr schema collect`, `discoveries`,
`pivot`, and `path` for the growing semantic graph.

The refresh receipt names a complete data JSONL and metadata sidecar. The
probe emits one row per `(table, column)`; xdr-cli saves every API-returned
row without a local display limit. The receipt's completeness remains
`unknown` because the upstream API does not certify it.

To convert the JSON to CSV for the rendering script:

```bash
# Consume the receipt and previews, then select the first line.
receipt=$(xdr schema refresh | jq -cs '.[0]')
path=$(printf '%s' "$receipt" | jq -r '.data_path')
jq -r '[.TableName,.ColumnName,.ColumnType,.ColumnOrdinal] | @csv' "$path" > schema.csv
```

Or run the probe directly in the Defender portal and export as CSV (see below).

Expected runtime: seconds to tens of seconds (metadata-only; no event scans),
depending on the tables available in the tenant.

### 2. Rebuild the pivot reference

```bash
python3 scripts/build_schema_pivots.py schema.csv docs/schema_pivots.md
```

Re-run this any time `schema.csv` changes (new license, new connector,
Microsoft added a table). The script is deterministic — same CSV in, same
doc out — so it's safe to regenerate in a pre-commit hook or CI job.

Omit the output path to print to stdout:

```bash
python3 scripts/build_schema_pivots.py schema.csv | less
```

### 3. (Optional) sanity-check the output

```bash
python3 - <<'PY'
import csv, re
from collections import defaultdict
from pathlib import Path

truth = defaultdict(set)
with open("schema.csv") as f:
    for row in csv.DictReader(f):
        truth[row["ColumnName"]].add(row["TableName"])

pat = re.compile(r"- `([A-Za-z0-9_]+)`\s*(?:\(.*?\))?\s*→\s*([^—\n]+?)(?:\s+—|$)", re.MULTILINE)
doc = Path("docs/schema_pivots.md").read_text()
found = defaultdict(set)
for m in pat.finditer(doc):
    for t in m.group(2).split(","):
        t = t.strip()
        if t and t != "**(not present in probe)**":
            found[m.group(1)].add(t)

shared = {c for c, ts in truth.items() if len(ts) >= 2}
miss = sorted(shared - set(found))
wrong = [c for c in found if found[c] != truth.get(c, set())]
print(f"fields in doc={len(found)} shared in probe={len(shared)} missing={len(miss)} mismatches={len(wrong)}")
PY
```

Expect `missing=0 mismatches=0`. If not, some sections of the renderer
need to catch the new field — open `scripts/build_schema_pivots.py` and
add a `p(line("NewField"))` call in the right section.

---

## Running in the Defender portal (no CLI)

You don't need the `xdr` CLI to run the probe — the KQL file is portable.
Useful for comparing CLI output against the portal's own runner, for
sharing the probe with teammates who don't have the CLI installed, or
for ad-hoc exploration in a tenant where the CLI isn't configured.

1. Open the Advanced Hunting page in the Microsoft Defender portal (the
   KQL query editor, same place you'd normally hand-write hunt queries).
2. Copy the query body of
   `src/xdr_cli/queries/sys_schema_probe.kql` into the editor. The
   leading `-- name:` / `-- description:` / `-- params:` lines are the
   repo's frontmatter preamble, NOT KQL comments (KQL's single-line
   comment is `//`). Delete those `--` lines before running — or run
   `xdr hunt library-show sys_schema_probe`, the retained compatibility
   renderer that prints executable KQL with the frontmatter already stripped.
   (`xdr library show` intentionally returns a descriptor, not query text.)
3. Run the query. Expect up to ~2500 result rows (one per column across the
   tables that exist on your tenant) and seconds to tens of seconds of
   runtime — this is a metadata-only query.
4. Click **Export** → **Export results to CSV** (or the equivalent
   "download" option in your portal version). Save it wherever
   `scripts/build_schema_pivots.py` can read it.
5. Feed the exported CSV to the renderer exactly as in step 2 of the
   Quick start:

    ```bash
    python3 scripts/build_schema_pivots.py portal-export.csv docs/schema_pivots.md
    ```

The portal and CLI run the same KQL, so their schema rows should be comparable
when tenant scope, permissions, connected-workspace context, and catalog state
match. They are different execution paths; a discrepancy can reflect those
differences rather than a CLI serialization defect.

---

## What gets produced

### `schema.csv` (raw probe)

One row per `(table, column)`. Example slice:

```csv
TableName,ColumnName,ColumnType,ColumnOrdinal
AlertEvidence,Timestamp,datetime,0
AlertEvidence,AlertId,string,1
...
```

Use cases for the raw CSV:

- Grep for a specific column name across all tables: `grep ",AccountObjectId," schema.csv`
- Count columns per table: `awk -F, 'NR>1{print $1}' schema.csv | sort | uniq -c | sort -rn`
- Load into pandas / DuckDB / jq for custom analysis

### `docs/schema_pivots.md` (rendered reference)

Organized by pivot category (row identity, device, user/account,
initiating-process bundle, file, network, email, Teams, TVM, sign-ins,
cloud workloads, DLP, alerts/behaviors, anomaly flags, multi-valued
fields, etc.). Every bullet line has the form:

```markdown
- `FieldName` → Table1, Table2, Table3 — optional note
```

Plus a small **casing gotchas** section up top (`IPAddress` vs
`IpAddress`, `Categories` vs `Category`) and 8 **worked pivot recipes**
at the bottom.

Designed for search: `grep IdentityLogonEvents docs/schema_pivots.md`
returns every field that reaches that table.

---

## How to leverage it

### Investigation workflows

- **Scoping a pivot.** Start with the entity you have (a SHA256, an
  AccountObjectId, a NetworkMessageId). Grep the reference for it — you
  get the table list across the probe's curated catalog in seconds, without
  guessing which documented surface carries the field.
- **Shortlisting a pivot key.** When multiple keys exist (for example,
  `AccountObjectId`, `AccountUpn`, or `AccountSid`), the reference shows
  physical coverage. Confirm semantics and `JoinSafe` with `xdr schema pivot`
  before treating a shared column name as a join contract.
- **Avoiding silent misses.** Multi-valued fields
  (`Categories`, `ThreatTypes`, `DetectionMethods`) are called out
  explicitly — a reminder to `mv-expand` before filtering.

### KQL authoring

- **Union across surfaces.** The worked recipes (hash spread, Entra ↔
  MDE logon correlation, OAuth app triangulation, MDC ↔ MDE bridge) are
  copy-pasteable starting points.
- **Schema-gated queries.** Before shipping a hunt query to a new
  tenant, grep the probe to confirm required tables exist. If not, the
  query can short-circuit with a clear error rather than a KQL
  semantic-error stack trace.

### Onboarding a new tenant

Run the probe early when onboarding a new tenant. The CSV immediately tells
you:

- Which curated tables and columns the current hunting identity can resolve.
- Where schema-surface differences suggest checking license, role, region, or
  connector configuration separately.
- Whether recent-release tables (`EntraIdSignInEvents`,
  `MessageEvents`, `AIAgentsInfo`, `DataSecurityEvents`) are available —
  useful to know before promising an investigation capability that
  depends on them.

Schema availability is not a row-population check. Run a small, bounded query
before claiming that an available table has data for the investigation window.

### Feeding AI agents

`docs/schema_pivots.md` is ~820 lines of structured, pivot-oriented
context — small enough to include in an agent's system prompt or as a
tool-callable reference. An LLM writing a hunt query against this
reference can choose physical columns the tenant actually exposes. It must
still use semantic graph evidence and join-safety output rather than assuming
that equal column names or recurring values authorize a raw join.

Pattern: when the agent needs to author KQL, pass the pivot doc plus the
analyst's goal; the agent picks join keys from the reference rather than
guessing.

### Diffing across tenants

Running the probe in multiple tenants and diffing the CSVs surfaces schema
parity gaps between dev/prod or customer environments. Treat the diff as a
prompt to check licensing, permissions, region, and connectors—not as proof of
which SKU is licensed:

```bash
# after probing each tenant
diff <(awk -F, 'NR>1{print $1}' tenantA.csv | sort -u) \
     <(awk -F, 'NR>1{print $1}' tenantB.csv | sort -u)
```

### Pre-commit / CI integration

If the pivot doc is treated as a source artefact, gate merges on
regeneration parity:

```yaml
- name: Regenerate pivot reference
  run: python3 scripts/build_schema_pivots.py schema.csv docs/schema_pivots.md
- name: Fail if doc is stale
  run: git diff --exit-code docs/schema_pivots.md
```

(Requires a reference CSV checked in, or a stable tenant to probe during
CI. In practice, most teams will regenerate manually after a licensing
change rather than fully automate it.)

---

## Troubleshooting

- **Fewer tables returned than you expected.** `isfuzzy=true` silently
  skips tables that don't exist on the tenant. That's a feature — it
  means the probe is safe to run anywhere — but it also means "absent"
  tables are invisible. Compare against the master list in
  `src/xdr_cli/queries/sys_schema_probe.kql` (which names all 80).
- **Cache is stale.** `schema show` and `schema tables` report cache age and
  staleness directly in the compact receipt as well as artifact metadata, but
  never refresh implicitly. Run `xdr schema refresh` deliberately when tenant
  licensing/connectors change. Refresh publishes a locked generation through
  one atomic manifest swap, so readers never pair data from one generation
  with metadata from another.
- **`AIAgentsInfo` missing.** New table, preview in some regions. It may become
  queryable when Microsoft enables the schema for your tenant/region and the
  current identity has access; rerun the probe then.
- **Renderer says `(not present in probe)` for a field.** The renderer
  references a field name that doesn't appear in your CSV. Either
  Microsoft removed it, your tenant is older/different, or the field is
  license-gated. Safe to ignore or remove the `p(line("Field"))` call
  from the script.

---

## Files

| Path | Role |
|---|---|
| `src/xdr_cli/queries/sys_schema_probe.kql` | The probe query (library entry) |
| `scripts/build_schema_pivots.py` | CSV → markdown renderer |
| `docs/schema_pivots.md` | Rendered pivot reference |
| `docs/schema_probe.md` | This doc (workflow guide) |
