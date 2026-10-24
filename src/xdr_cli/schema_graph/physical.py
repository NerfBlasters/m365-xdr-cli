"""Physical-schema types and conservative coverage of the exact probe query."""

from __future__ import annotations

import re

from xdr_cli.schema_graph.model import FieldRecord

_TYPES = {
    "string": "string", "system.string": "string",
    "dynamic": "dynamic", "system.dynamic": "dynamic",
    "object": "dynamic", "system.object": "dynamic",
    "datetime": "datetime", "system.datetime": "datetime",
    "timespan": "timespan", "system.timespan": "timespan",
    "int": "int", "int32": "int", "system.int32": "int",
    "long": "long", "int64": "long", "system.int64": "long",
    "real": "real", "double": "real", "system.double": "real",
    "bool": "bool", "boolean": "bool", "system.boolean": "bool",
    "guid": "guid", "system.guid": "guid",
    "decimal": "decimal", "system.decimal": "decimal",
}
_PROBE_BRANCH = re.compile(
    r'\(\s*(?P<table>[A-Za-z][A-Za-z0-9_]*)\s*\|\s*getschema\s*'
    r'\|\s*extend\s+TableName\s*=\s*"(?P=table)"\s*\)'
)
_PROBE_SHAPE = re.compile(
    r"union\s+isfuzzy\s*=\s*true\s+TABLE(?:\s*,\s*TABLE)*\s*"
    r"\|\s*project\s+TableName\s*,\s*ColumnName\s*,\s*ColumnType\s*,\s*ColumnOrdinal\s*"
    r"\|\s*sort\s+by\s+TableName\s+asc\s*,\s*ColumnOrdinal\s+asc\s*"
)


def canonical_storage_type(value: object) -> str | None:
    """Normalize known KQL/getschema spellings without guessing unknown types."""

    return _TYPES.get(value.strip().casefold()) if isinstance(value, str) else None


def field_storage_compatible(field: FieldRecord, rows: list[dict]) -> bool:
    """Check one outer column's rows, preserving legacy missing-type support."""

    if not rows:
        return False
    storage_types = {
        canonical_storage_type(row.get("ColumnType", row.get("DataType")))
        for row in rows if "ColumnType" in row or "DataType" in row
    }
    expected_types = (
        {"string", "dynamic"} if field.locator.json_path
        else {canonical_storage_type(field.kql_type)} - {None}
    )
    return not storage_types or storage_types <= expected_types


def is_queryable_row(row: dict) -> bool:
    """Only getschema rows prove a queryable column; metadata-only rows never do.

    Rows without ``Sources`` predate metadata merging and came from getschema.
    """

    sources = row.get("Sources")
    return sources is None or (isinstance(sources, list) and "getschema" in sources)


def queryable_rows(rows: list[dict]) -> list[dict]:
    """Drop metadata-only rows, including those written by earlier cache versions."""

    return [row for row in rows if is_queryable_row(row)]


def physical_field_rows(rows: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Group queryable physical observations without hiding conflicting duplicate types."""

    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        if row.get("TableName") and row.get("ColumnName") and is_queryable_row(row):
            key = (str(row["TableName"]), str(row["ColumnName"]))
            grouped.setdefault(key, []).append(row)
    return grouped


def probe_coverage(query: str, rows: list[dict], execution_surface: str) -> dict:
    """Describe checked names, never infer absence from a fuzzy union result.

    User overrides can replace the library entry. Recognize only the complete
    row-preserving probe grammar rather than extracting table-looking strings
    from arbitrary KQL and claiming they were checked.
    """

    tables = []

    def replace_branch(match: re.Match) -> str:
        tables.append(match["table"])
        return "TABLE"

    body = re.sub(r"(?m)^\s*--[^\n]*(?:\n|$)", "", query).strip()
    shape = _PROBE_BRANCH.sub(replace_branch, body)
    scope_known = _PROBE_SHAPE.fullmatch(shape) is not None
    return {
        "method": "curated-fuzzy-union" if scope_known else "custom-query",
        "scope_known": scope_known,
        "probe_tables": sorted(set(tables)) if scope_known else None,
        "returned_tables": sorted({
            row["TableName"] for row in rows if isinstance(row.get("TableName"), str)
        }),
        "complete": False,
        "execution_surface": execution_surface,
        "absence_is_conclusive": False,
    }


def coverage_summary(coverage: dict) -> dict:
    """Bounded receipt context; complete per-table scope stays in metadata."""

    return {
        key: coverage.get(key)
        for key in ("method", "scope_known", "complete", "execution_surface",
                    "absence_is_conclusive")
    } | {
        "probe_tables": len(coverage["probe_tables"])
        if isinstance(coverage.get("probe_tables"), list) else None,
        "returned_tables": len(coverage.get("returned_tables", [])),
    } | (
        {
            "metadata_source": coverage["metadata"].get("source"),
            "metadata_status": coverage["metadata"].get("status"),
            "listed_tables": len(coverage["metadata"].get("listed_tables", [])),
            "new_tables": len(coverage.get("new_tables", [])),
        }
        if isinstance(coverage.get("metadata"), dict) else {}
    )


def portal_schema_tables(tables: list[dict]) -> dict[str, dict]:
    """Normalize a portal/XDRInternals ``Tables`` listing, dropping unsafe names.

    Both ``huntingService/schema`` and the public FullSchema snapshot use this
    record shape. Unknown .NET type spellings keep ``ColumnType`` empty rather
    than guessing.
    """

    from xdr_cli.hunting_tables import TABLE_NAME

    normalized: dict[str, dict] = {}
    for table in tables:
        name = table.get("Name")
        schema = table.get("Schema")
        if not isinstance(name, str) or not TABLE_NAME.fullmatch(name):
            continue
        columns = []
        for ordinal, column in enumerate(schema if isinstance(schema, list) else []):
            column_name = column.get("Name") if isinstance(column, dict) else None
            if not isinstance(column_name, str) or not TABLE_NAME.fullmatch(column_name):
                continue
            columns.append({
                "ColumnName": column_name,
                "ColumnType": canonical_storage_type(column.get("Type")) or "",
                "ColumnOrdinal": ordinal,
                "Entity": column.get("Entity") if isinstance(column.get("Entity"), str) else None,
                "Description": column.get("Description")
                if isinstance(column.get("Description"), str) else None,
            })
        normalized[name] = {
            "Description": table.get("Description")
            if isinstance(table.get("Description"), str) else None,
            "TableSection": table.get("TableSection"),
            "TableType": table.get("TableType"),
            "UsxResourceType": table.get("UsxResourceType"),
            "HasData": table.get("HasData") if isinstance(table.get("HasData"), bool) else None,
            "Columns": columns,
        }
    return normalized


def merge_portal_rows(rows: list[dict], portal: dict[str, dict]) -> tuple[list[dict], dict]:
    """Union getschema rows with portal-listed columns; getschema wins on type.

    A metadata listing does not prove query authorization, so only getschema
    rows are cached. Portal-only tables and columns are reported (bounded) and
    kept in the private sidecar. Every cached row gains ``Sources``.
    """

    if not portal:
        return rows, {}
    merged: dict[tuple[str, str], dict] = {}
    for row in rows:
        if not (row.get("TableName") and row.get("ColumnName")):
            continue
        key = (str(row["TableName"]), str(row["ColumnName"]))
        merged[key] = {**row, "Sources": ["getschema"]}
    getschema_tables = {key[0] for key in merged}
    type_disagreements = []
    portal_only_columns = []
    for table, info in portal.items():
        for column in info["Columns"]:
            key = (table, column["ColumnName"])
            existing = merged.get(key)
            if existing is None:
                if table in getschema_tables:
                    portal_only_columns.append(f"{table}.{column['ColumnName']}")
                continue
            existing["Sources"].append("portal-schema")
            ours = canonical_storage_type(existing.get("ColumnType"))
            if column["ColumnType"] and ours and ours != column["ColumnType"]:
                type_disagreements.append(f"{table}.{column['ColumnName']}")
    ordered = sorted(
        merged.values(),
        key=lambda row: (row["TableName"], row.get("ColumnOrdinal") or 0, row["ColumnName"]),
    )
    return ordered, {
        "listed_tables": sorted(portal),
        "portal_only_tables": sorted(set(portal) - getschema_tables),
        "unlisted_getschema_tables": sorted(getschema_tables - set(portal)),
        "portal_only_columns": len(portal_only_columns),
        "portal_only_column_examples": sorted(portal_only_columns)[:20],
        "type_disagreements": len(type_disagreements),
        "type_disagreement_examples": sorted(type_disagreements)[:20],
    }


def load_portal_sidecar(cache_meta: dict, cache_root) -> tuple[dict | None, str | None]:
    """Return the digest-verified portal listing beside a cache, or a gap reason.

    Entity tags and descriptions are discovery inputs only after this check;
    a transferred cache may legitimately lack the optional sidecar.
    """

    import hashlib
    import json
    from pathlib import Path

    binding = cache_meta.get("portal_schema")
    if not isinstance(binding, dict):
        return None, "not-recorded"
    name, digest = binding.get("path"), binding.get("sha256")
    if not isinstance(name, str) or Path(name).name != name or not isinstance(digest, str):
        return None, "invalid-binding"
    try:
        raw = (Path(cache_root) / name).read_bytes()
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unreadable"
    if hashlib.sha256(raw).hexdigest() != digest:
        return None, "digest-mismatch"
    try:
        tables = json.loads(raw)["Tables"]
    except (ValueError, KeyError, TypeError):
        return None, "malformed"
    return (tables, None) if isinstance(tables, dict) else (None, "malformed")


_IDENTIFIER_TYPES = {"string", "guid", "dynamic", "long", "int"}


def identifier_column_candidates(
    rows: list[dict],
    families: dict[str, set[tuple[str, str]]],
    *,
    tables: set[str] | None = None,
) -> list[dict]:
    """Suggest value-free family hints for columns of (new) tables by exact name.

    ``families`` maps a reference family to its top-level ``(table, column)``
    endpoints. A column whose exact name is a family endpoint column elsewhere
    becomes a *candidate* only; empirical overlap must establish any route.
    """

    by_column: dict[str, set[str]] = {}
    for family, endpoints in families.items():
        for _table, column in endpoints:
            by_column.setdefault(column, set()).add(family)
    candidates = []
    for (table, column), column_rows in sorted(physical_field_rows(rows).items()):
        if tables is not None and table not in tables:
            continue
        storage = {canonical_storage_type(row.get("ColumnType")) for row in column_rows}
        if not storage <= _IDENTIFIER_TYPES:
            continue
        for family in sorted(by_column.get(column, ())):
            peers = sorted(
                f"{peer_table}.{peer_column}"
                for peer_table, peer_column in families[family]
                if peer_column == column and peer_table != table
            )
            if peers:
                candidates.append({
                    "table": table,
                    "column": column,
                    "family": family,
                    "evidence": "exact-column-name",
                    "status": "candidate",
                    "peer_endpoints": peers[:10],
                })
    return candidates


# Portal Entity tags precise enough to suggest a family for an unfamiliar column name.
_ENTITY_FAMILIES = {"Machine": "defender-device", "UserObjectId": "entra-user"}
_PREFERRED_HUBS = ("DeviceInfo", "IdentityInfo", "EntraIdSignInEvents")
MAX_DERIVED_ROUTES = 100


def new_table_candidate_routes(
    rows: list[dict], snapshot, new_tables, *, peers_per_column=3, portal_tables=None,
    max_routes=MAX_DERIVED_ROUTES,
):
    """Synthesize name-match candidate routes from new tables to reference hubs.

    Only exact identifier-column name matches against top-level reference
    endpoints that are physically present qualify. The routes carry
    ``record["origin"] = "tenant-new-table"`` and must stay candidates until the
    same bounded validation observes real overlap.
    """

    import hashlib
    from collections import Counter

    from xdr_cli.schema_graph.reference import ReferenceEndpoint, ReferenceRoute

    present = physical_field_rows(rows)
    endpoint_counts: dict[str, Counter] = {}
    for route in snapshot.routes:
        for endpoint in (route.source, route.target):
            if not endpoint.path and (endpoint.table, endpoint.column) in present:
                endpoint_counts.setdefault(route.family, Counter())[endpoint] += 1
    families = {
        family: {(endpoint.table, endpoint.column) for endpoint in counts}
        for family, counts in endpoint_counts.items()
    }
    tables = {name for name in new_tables if isinstance(name, str)}
    candidates = identifier_column_candidates(rows, families, tables=tables)
    named = {(c["table"], c["column"], c["family"]) for c in candidates}
    for table in sorted(tables & set(portal_tables or {})):
        for column in portal_tables[table].get("Columns", []):
            family = _ENTITY_FAMILIES.get(column.get("Entity"))
            key = (table, column.get("ColumnName"), family)
            if family in endpoint_counts and key not in named and (key[0], key[1]) in present:
                candidates.append({"table": table, "column": key[1], "family": family,
                                   "evidence": "portal-entity-tag"})
    routes = []
    for candidate in candidates:
        table, column, family = candidate["table"], candidate["column"], candidate["family"]
        by_name = candidate["evidence"] == "exact-column-name"
        time_column = next(
            (name for name in ("Timestamp", "TimeGenerated") if (table, name) in present), None
        )
        source = ReferenceEndpoint(table, column, (), time_column)
        hubs = sorted(
            (
                endpoint for endpoint in endpoint_counts[family]
                if (endpoint.column == column or not by_name) and endpoint.table != table
            ),
            key=lambda endpoint: (
                endpoint.table not in _PREFERRED_HUBS,
                -endpoint_counts[family][endpoint],
                endpoint.table,
            ),
        )[:peers_per_column]
        for hub in hubs:
            digest = hashlib.sha256(
                "\0".join((table, column, family, hub.table, hub.column)).encode()
            ).hexdigest()[:16]
            routes.append(ReferenceRoute(
                id=f"tenant-discovery-{digest}",
                title=f"{table}.{column} to {hub.table}.{hub.column} (candidate)",
                family=family,
                source=source,
                target=hub,
                guidance=f"Tenant-detected table; {candidate['evidence']} only. Requires "
                         "observed overlap before use as a pivot.",
                record={"origin": "tenant-new-table", "evidence": candidate["evidence"]},
            ))
    routes.sort(key=lambda route: route.id)
    return routes[:max_routes]
