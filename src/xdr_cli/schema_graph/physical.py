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


def physical_field_rows(rows: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Group physical observations without hiding conflicting duplicate types."""

    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        if row.get("TableName") and row.get("ColumnName"):
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
    }
