"""Compile bounded identifier-led discovery without inspecting tenant state."""

from __future__ import annotations

import json
import re

from xdr_cli.json_expansion import JSON_STRING_COLUMNS
from xdr_cli.queries import _kql_escape
from xdr_cli.schema_graph.model import GraphValidationError
from xdr_cli.schema_graph.normalize import NormalizationError
from xdr_cli.schema_graph.probe import (
    MAX_PROBE_SEED_BYTES,
    PROBE_QUERY_BYTE_LIMIT,
    _normalized_expression,
    _normalized_seeds,
    validate_lookback,
)

MAX_DISCOVERY_TABLES = 100
MAX_DISCOVERY_DEPTH = 12
MAX_DISCOVERY_ROWS = 10_000
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_TIME_COLUMNS = {"Timestamp", "TimeGenerated"}


def _literal(value: str) -> str:
    return f'"{_kql_escape(value)}"'


def _leaf_normalized_expression(normalizer: str) -> str:
    expression = _normalized_expression(normalizer, "Value")
    if normalizer != "guid-lower":
        return expression
    # Python UUID normalization removes these wrappers/separators but rejects
    # any remaining suffix. KQL toguid alone silently accepts a GUID prefix.
    stripped = r'trim(@"\s+", tostring(Value))'
    unwrapped = f'replace_string(replace_string({stripped}, "urn:", ""), "uuid:", "")'
    compact = f'replace_string(trim(@"[{{}}]+", {unwrapped}), "-", "")'
    return (
        f'iff({compact} matches regex @"^[0-9a-fA-F]{{32}}$", '
        f'tostring(toguid({compact})), "")'
    )


def _prefilter_values(seeds: list[str], normalized: list[str], depth: int) -> list[str]:
    """Include JSON-escaped representations, without treating them as matches."""

    values = set(seeds) | set(normalized)
    byte_count = sum(len(value.encode("utf-8")) for value in values)
    if byte_count > PROBE_QUERY_BYTE_LIMIT:
        raise GraphValidationError("discovery prefilter exceeds the 256 KiB syntax budget")
    for value in tuple(values):
        encoded = value
        for _ in range(depth + 1):
            escaped = json.dumps(encoded, ensure_ascii=False)[1:-1]
            if escaped == encoded:
                break
            if escaped not in values:
                byte_count += len(escaped.encode("utf-8"))
                if byte_count > PROBE_QUERY_BYTE_LIMIT:
                    raise GraphValidationError(
                        "discovery prefilter exceeds the 256 KiB syntax budget"
                    )
                values.add(escaped)
            encoded = escaped
    return sorted(values)


def compile_discovery_query(
    seeds: list[str],
    *,
    normalizer: str,
    tables: list[str],
    time_column: str,
    lookback: str = "30d",
    max_depth: int = 6,
    row_limit: int = 2000,
) -> str:
    """Return deterministic KQL for the caller's cached eligible table batch.

    Only normalized exact leaf equality establishes a match. ``PathTokens``
    excludes the column name; array elements use ``"*"``. Encoded JSON is
    decoded once at eligible roots; nested strings remain scalars. Native nested
    containers support multiple wildcards. Scalar JSON decoding never changes
    an identifier.

    ``MatchingRows`` counts distinct source rows per path/value, including
    marker rows. Remaining matching containers yield ``DepthLimitReached``;
    unaddressable columns or dictionary keys yield ``UnsupportedPath``.
    Both markers have an empty ``MatchedValue`` and establish no match.
    An empty result means no exact match within this query's scope, rather
    than a global absence claim. The extra match row detects output truncation.
    Exactly one ``RowKind="receipt"`` row reports ``ReturnedRows`` after the
    limit, even for zero matches. Other rows have ``RowKind="match"`` and a
    null ``ReturnedRows``. Readers must check that receipt before claiming
    query completion; markers are included in its count.

    Limits: 1..100 seeds/tables, 2048 UTF-8 bytes per seed, depth 0..12,
    1..10000 output rows, and 256 KiB compiled query. No cache or network I/O.
    """

    if not isinstance(normalizer, str):
        raise GraphValidationError("normalizer must name a supported KQL normalizer")
    normalized_expression = _leaf_normalized_expression(normalizer)
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= 100:
        raise GraphValidationError("discovery requires between 1 and 100 seeds")
    for seed in seeds:
        if not isinstance(seed, str) or any(ord(char) < 32 or ord(char) == 127 for char in seed):
            raise GraphValidationError("discovery seed must be a string without controls")
        try:
            seed_bytes = len(seed.encode("utf-8"))
        except UnicodeError as exc:
            raise GraphValidationError("discovery seed must be valid UTF-8") from exc
        if seed_bytes > MAX_PROBE_SEED_BYTES:
            raise GraphValidationError("discovery seed exceeds the UTF-8 byte limit")
    try:
        normalized = _normalized_seeds(normalizer, seeds)
    except NormalizationError as exc:
        raise GraphValidationError(str(exc)) from exc
    if not isinstance(tables, list) or not 1 <= len(tables) <= MAX_DISCOVERY_TABLES:
        raise GraphValidationError("discovery requires between 1 and 100 eligible tables")
    if any(not isinstance(table, str) or not _IDENTIFIER.fullmatch(table) for table in tables):
        raise GraphValidationError("discovery tables must be simple table identifiers")
    if not isinstance(time_column, str) or time_column not in _TIME_COLUMNS:
        raise GraphValidationError("discovery time column must be Timestamp or TimeGenerated")
    validate_lookback(lookback)
    if type(max_depth) is not int or not 0 <= max_depth <= MAX_DISCOVERY_DEPTH:
        raise GraphValidationError("discovery depth must be an integer between 0 and 12")
    if type(row_limit) is not int or not 1 <= row_limit <= MAX_DISCOVERY_ROWS:
        raise GraphValidationError("discovery row limit must be an integer between 1 and 10000")

    prefilter_seeds = list(seeds)
    if normalizer == "guid-lower":
        # toguid also accepts compact GUIDs. A substring prefilter must not
        # exclude those representations before exact normalization occurs.
        prefilter_seeds.extend(value.replace("-", "") for value in normalized)
    prefilter = _prefilter_values(prefilter_seeds, normalized, max_depth)
    seed_literals = ", ".join(_literal(value) for value in normalized)
    row_predicate = " or ".join(f"* contains {_literal(value)}" for value in prefilter)
    value_predicate = " or ".join(
        f"tostring(Value) contains {_literal(value)}" for value in prefilter
    )
    table_list = ", ".join(sorted(set(tables)))
    json_columns = ", ".join(_literal(name) for name in sorted(JSON_STRING_COLUMNS))

    lines = [
        f"let xdr_discovery_seeds = dynamic([{seed_literals}]);",
        "let xdr_discovery_container = (Value:dynamic) {",
        "    let Parsed = parse_json(tostring(Value));",
        '    iff(gettype(Parsed) in ("dictionary", "array"), Parsed, Value)',
        "};",
        "let xdr_discovery_may_match = (Value:dynamic) {",
        f"    {value_predicate}",
        "};",
        "let xdr_discovery_step = (T:(TableName:string, ColumnName:string, PathTokens:dynamic,",
        "                     Value:dynamic, RowId:long, UnsupportedPath:bool)) {",
        "    T",
        '    | extend xdr_discovery_kind = iff(UnsupportedPath, "scalar", gettype(Value))',
        '    | extend xdr_discovery_children = iff(xdr_discovery_kind in ("dictionary", "array"),',
        "                                  Value, pack_array(Value))",
        "    | mv-expand kind=array xdr_discovery_child = xdr_discovery_children",
        "    | extend xdr_discovery_key = tostring(xdr_discovery_child[0])",
        '    | extend UnsupportedPath = UnsupportedPath or (xdr_discovery_kind == "dictionary" and',
        '        (isempty(xdr_discovery_key) or xdr_discovery_key == "*" or',
        r'         xdr_discovery_key matches regex @"[\x00-\x1f]"))',
        "    | extend PathTokens = case(",
        '        xdr_discovery_kind == "dictionary" and not(UnsupportedPath),',
        "            array_concat(PathTokens, pack_array(xdr_discovery_key)),",
        '        xdr_discovery_kind == "array", array_concat(PathTokens, dynamic(["*"])),',
        "        PathTokens),",
        '        Value = iff(xdr_discovery_kind == "dictionary", '
        "xdr_discovery_child[1], xdr_discovery_child)",
        "    | where xdr_discovery_may_match(Value)",
        "    | project TableName, ColumnName, PathTokens, Value, RowId, UnsupportedPath",
        "};",
        f"find withsource=xdr_discovery_table in ({table_list})",
        f"where {time_column} > ago({lookback}) and ({row_predicate})",
        "project pack(*)",
        "| serialize RowId = row_number()",
        "| mv-expand kind=array xdr_discovery_column = pack_",
        "| project TableName = tostring(xdr_discovery_table),",
        "          ColumnName = tostring(xdr_discovery_column[0]),",
        "          PathTokens = dynamic([]), Value = xdr_discovery_column[1], RowId",
        # Native dynamic containers are typed. Encoded strings require the
        # explicit physical JSON-column contract; arbitrary command-line text
        # must never manufacture nested field locators.
        f"| where ColumnName in ({json_columns}) or gettype(Value) in "
        '("dictionary", "array") or gettype(parse_json(tostring(Value))) !in '
        '("dictionary", "array")',
        "| extend Value = xdr_discovery_container(Value)",
        r'| extend UnsupportedPath = not(ColumnName matches regex @"^[A-Za-z][A-Za-z0-9_]*$")',
        "| where xdr_discovery_may_match(Value)",
    ]
    lines.extend("| invoke xdr_discovery_step()" for _ in range(max_depth))
    lines.extend(
        [
            '| extend DepthLimitReached = not(UnsupportedPath) and gettype(Value) in '
            '("dictionary", "array")',
            f"| extend xdr_discovery_normalized = {normalized_expression}",
            "| where UnsupportedPath or DepthLimitReached or",
            "        (isnotempty(xdr_discovery_normalized) and",
            "         set_has_element(xdr_discovery_seeds, xdr_discovery_normalized))",
            '| extend MatchedValue = iff(UnsupportedPath or DepthLimitReached, "",',
            "                            xdr_discovery_normalized), "
            "xdr_discovery_path = tostring(PathTokens)",
            "| summarize by TableName, ColumnName, xdr_discovery_path, MatchedValue,",
            "               DepthLimitReached, UnsupportedPath, RowId",
            "| summarize MatchingRows = count() by TableName, ColumnName, xdr_discovery_path,",
            "                                     MatchedValue, DepthLimitReached, UnsupportedPath",
            "| sort by TableName asc, ColumnName asc, xdr_discovery_path asc, MatchedValue asc,",
            "          DepthLimitReached asc, UnsupportedPath asc",
            "| project TableName, ColumnName, PathTokens = parse_json(xdr_discovery_path),",
            "          MatchedValue, MatchingRows, DepthLimitReached, UnsupportedPath",
            f"| take {row_limit + 1}",
            # Keep find and its receipt in one pipeline.
            # Materialize before extending RowKind so the receipt counts
            # precisely the same bounded rows, including for empty input.
            "| as hint.materialized=true xdr_discovery_limited",
            '| extend RowKind = "match", ReturnedRows = long(null)',
            "| union",
            "    (xdr_discovery_limited | summarize ReturnedRows = count()",
            '     | extend RowKind = "receipt", TableName = "", ColumnName = "",',
            '              PathTokens = dynamic([]), MatchedValue = "", MatchingRows = long(null),',
            "              DepthLimitReached = false, UnsupportedPath = false)",
            "| extend xdr_discovery_order_path = tostring(PathTokens)",
            "| sort by RowKind asc, TableName asc, ColumnName asc, xdr_discovery_order_path asc,",
            "          MatchedValue asc, DepthLimitReached asc, UnsupportedPath asc",
            "| project RowKind, TableName, ColumnName, PathTokens, MatchedValue,",
            "          MatchingRows, DepthLimitReached, UnsupportedPath, ReturnedRows",
        ]
    )
    query = "\n".join(lines)
    if len(query.encode("utf-8")) > PROBE_QUERY_BYTE_LIMIT:
        raise GraphValidationError("discovery query exceeds the 256 KiB syntax budget")
    return query
