"""Offline compiler contracts; executing the resulting KQL needs a smoke test."""

from __future__ import annotations

import json
import re

import pytest

from xdr_cli.schema_graph.discovery_query import compile_discovery_query
from xdr_cli.schema_graph.lineage import _tokens
from xdr_cli.schema_graph.model import GraphValidationError
from xdr_cli.schema_graph.normalize import NormalizationError, normalize_value


def _compile(seeds=None, **kwargs):
    options = {"normalizer": "identity", "tables": ["DeviceEvents"], "time_column": "Timestamp"}
    options.update(kwargs)
    return compile_discovery_query(["needle"] if seeds is None else seeds, **options)


def _seed_array(query):
    return json.loads(query.splitlines()[0].removeprefix("let xdr_discovery_seeds = dynamic(")[:-2])


def test_explicit_table_scope_time_bound_and_pack_contract():
    query = _compile(tables=["CloudAppEvents", "DeviceEvents"], lookback="14d")
    assert "find withsource=xdr_discovery_table in (CloudAppEvents, DeviceEvents)\n" in query
    assert 'where Timestamp > ago(14d) and (* contains "needle")\nproject pack(*)' in query
    assert "| mv-expand kind=array xdr_discovery_column = pack_" in query
    assert "ColumnName = tostring(xdr_discovery_column[0])" in query
    assert "PathTokens = dynamic([]), Value = xdr_discovery_column[1], RowId" in query
    assert "| take 2001\n| as hint.materialized=true xdr_discovery_limited" in query
    assert "union *" not in query


def test_deterministic_full_query_and_normalized_seed_deduplication():
    first = _compile(
        ["B@example.invalid", "a@example.invalid", "B@example.invalid"],
        normalizer="upn-lower",
        tables=["DeviceEvents", "CloudAppEvents", "DeviceEvents"],
    )
    second = _compile(
        ["a@example.invalid", "B@example.invalid", "B@example.invalid"],
        normalizer="upn-lower",
        tables=["CloudAppEvents", "DeviceEvents", "DeviceEvents"],
    )
    assert first == second
    assert _seed_array(first) == ["a@example.invalid", "b@example.invalid"]
    assert "in (CloudAppEvents, DeviceEvents)" in first


@pytest.mark.parametrize(
    "seed",
    [
        'x") | union ExternalTable | where ("',
        'x\\"; let injected = 1; //',
        "'; union ExternalTable; /*",
        "back\\slash",
        'quote"key',
        "a|b;find in(*)",
        "é漢字",
    ],
)
def test_seeds_cannot_inject_query_syntax(seed):
    query = _compile([seed])
    assert _seed_array(query) == [seed]
    syntax = [token for token in _tokens(query) if not token.startswith(('"', "'", '@"', "@'"))]
    assert "ExternalTable" not in syntax
    assert "injected" not in syntax
    assert syntax.count("union") == 1
    assert syntax.count("find") == 1


def test_nested_json_escaping_is_prefilter_only():
    seed = 'a"b\\c'
    query = _compile([seed], max_depth=2)
    encoded = json.dumps(seed, ensure_ascii=False)[1:-1]
    assert json.dumps(encoded, ensure_ascii=False) in query
    assert _seed_array(query) == [seed]
    exact_stage = query[query.index("| extend xdr_discovery_normalized =") :]
    assert "set_has_element(xdr_discovery_seeds, xdr_discovery_normalized)" in exact_stage
    assert "contains" not in exact_stage


def test_prefilter_substrings_and_dictionary_keys_cannot_establish_matches():
    query = _compile(["ann@example.invalid"])
    assert '* contains "ann@example.invalid"' in query
    assert 'tostring(Value) contains "ann@example.invalid"' in query
    # A longer leaf, or a dictionary key with this substring, only enters the
    # candidate scan. Membership tests use the normalized scalar value.
    assert "| where UnsupportedPath or DepthLimitReached or\n" in query
    assert "(isnotempty(xdr_discovery_normalized) and\n" in query
    assert "set_has_element(xdr_discovery_seeds, xdr_discovery_normalized))" in query
    assert (
        'Value = iff(xdr_discovery_kind == "dictionary", '
        "xdr_discovery_child[1], xdr_discovery_child)"
        in query
    )


def test_dictionary_pairs_and_array_elements_use_distinct_branches():
    query = _compile(max_depth=4)
    assert "| mv-expand kind=array xdr_discovery_child = xdr_discovery_children" in query
    assert (
        'Value = iff(xdr_discovery_kind == "dictionary", '
        "xdr_discovery_child[1], xdr_discovery_child)"
        in query
    )
    assert 'array_concat(PathTokens, dynamic(["*"]))' in query
    assert "array_concat(PathTokens, pack_array(xdr_discovery_key))" in query
    assert "array_concat(PathTokens, pack_array(ColumnName))" not in query
    assert "xdr_discovery_child[1][1]" not in query
    # Array objects are carried intact into the next step; array scalars are
    # carried intact through every remaining step, never indexed as bag pairs.
    assert "Value, pack_array(Value))" in query
    assert "| extend Value = xdr_discovery_container(Value)" in query


def test_all_depth_steps_preserve_leaf_scalars_and_allow_multiple_wildcards():
    query = _compile(max_depth=12)
    assert query.count("| invoke xdr_discovery_step()") == 12
    assert 'iff(xdr_discovery_kind in ("dictionary", "array"),' in query
    assert "Value, pack_array(Value))" in query
    assert 'iff(UnsupportedPath, "scalar", gettype(Value))' in query
    assert "array_length(PathTokens)" not in query
    assert "set_has_element(PathTokens" not in query


def test_only_root_containers_are_decoded_and_nested_strings_remain_scalars():
    query = _compile()
    container_function = query.split("let xdr_discovery_container =", 1)[1].split("};", 1)[0]
    assert "let Parsed = parse_json(tostring(Value));" in container_function
    assert 'iff(gettype(Parsed) in ("dictionary", "array"), Parsed, Value)' in container_function
    assert '"string"' not in container_function
    step = query.split("let xdr_discovery_step =", 1)[1].split("};", 1)[0]
    assert "xdr_discovery_container(Value)" not in step
    assert query.count("| extend Value = xdr_discovery_container(Value)") == 1
    assert query.index("| extend Value = xdr_discovery_container(Value)") < query.index(
        "| invoke xdr_discovery_step()"
    )


@pytest.mark.parametrize("depth", [0, 1, 6, 12])
def test_depth_limit_markers_have_empty_values_and_survive_exact_filter(depth):
    query = _compile(max_depth=depth)
    assert query.count("| invoke xdr_discovery_step()") == depth
    assert "| extend DepthLimitReached = not(UnsupportedPath) and gettype(Value) in " in query
    assert '("dictionary", "array")' in query
    assert '| extend MatchedValue = iff(UnsupportedPath or DepthLimitReached, "",' in query
    assert "| where UnsupportedPath or DepthLimitReached or" in query
    assert "DepthLimitReached, UnsupportedPath, RowId" in query


def test_unaddressable_keys_and_columns_are_gap_markers_not_verified_locators():
    query = _compile()
    assert 'isempty(xdr_discovery_key) or xdr_discovery_key == "*"' in query
    assert r'xdr_discovery_key matches regex @"[\x00-\x1f]"' in query
    assert 'not(ColumnName matches regex @"^[A-Za-z][A-Za-z0-9_]*$")' in query
    assert 'xdr_discovery_kind == "dictionary" and not(UnsupportedPath)' in query
    assert "DepthLimitReached, UnsupportedPath" in query


def test_matching_rows_are_exact_source_row_counts_not_array_occurrence_counts():
    query = _compile()
    source_query = query[query.index("find withsource=") :]
    assert source_query.index("| serialize RowId = row_number()") < source_query.index(
        "| mv-expand"
    )
    distinct_rows = query.index("| summarize by TableName")
    count_rows = query.index("| summarize MatchingRows = count()")
    assert distinct_rows < count_rows
    assert "RowId" in query[distinct_rows:count_rows]
    assert "RowId" not in query[count_rows:]
    assert "dcount(" not in query
    assert "PathTokens = parse_json(xdr_discovery_path)" in query


@pytest.mark.parametrize("limit", [1, 2000, 10000])
def test_truncation_sentinel_is_after_grouping_and_deterministic_ordering(limit):
    query = _compile(row_limit=limit)
    assert f"| take {limit + 1}\n| as hint.materialized=true xdr_discovery_limited" in query
    assert query.count("| take ") == 1
    assert query.index("MatchingRows = count()") < query.index("| sort by") < query.index("| take")


@pytest.mark.parametrize(
    ("normalizer", "seed", "normalized", "expression"),
    [
        ("identity", " AbC ", "AbC", 'trim(@"\\s+", tostring(Value))'),
        ("upn-lower", "USER@EXAMPLE.INVALID", "user@example.invalid", "tolower("),
        ("smtp-lower", "USER@EXAMPLE.INVALID", "user@example.invalid", "tolower("),
        ("domain-lower", "EXAMPLE.INVALID.", "example.invalid", "trim_end("),
        ("hostname-lower", "HOST.", "host", "trim_end("),
        ("sha1-lower", "A" * 40, "a" * 40, "tolower("),
        ("hex40-lower", "B" * 40, "b" * 40, "tolower("),
        ("sha256-lower", "C" * 64, "c" * 64, "tolower("),
        (
            "guid-lower",
            "A0B1C2D3-E4F5-4678-9ABC-0123456789AB",
            "a0b1c2d3-e4f5-4678-9abc-0123456789ab",
            "toguid(",
        ),
    ],
)
def test_supported_normalizers_apply_to_actual_leaf_values(
    normalizer,
    seed,
    normalized,
    expression,
):
    query = _compile([seed], normalizer=normalizer)
    assert _seed_array(query) == [normalized]
    final_expression = query.split("| extend xdr_discovery_normalized =", 1)[1].splitlines()[0]
    assert expression in final_expression
    assert "Value" in final_expression


def test_compact_guid_prefilter_does_not_hide_normalizable_values():
    query = _compile(["a0b1c2d3-e4f5-4678-9abc-0123456789ab"], normalizer="guid-lower")
    assert '* contains "a0b1c2d3e4f546789abc0123456789ab"' in query
    assert _seed_array(query) == ["a0b1c2d3-e4f5-4678-9abc-0123456789ab"]


@pytest.mark.parametrize(
    ("leaf", "expected"),
    [
        ("a0b1c2d3-e4f5-4678-9abc-0123456789ab", True),
        ("A0B1C2D3E4F546789ABC0123456789AB", True),
        (" {a0b1c2d3-e4f5-4678-9abc-0123456789ab} ", True),
        ("urn:uuid:a0b1c2d3-e4f5-4678-9abc-0123456789ab", True),
        ("a0b1c2d3-e4f5-4678-9abc-0123456789ab-suffix", False),
        ("a0b1c2d3e4f546789abc0123456789ab0000", False),
    ],
)
def test_guid_whole_value_guard_agrees_with_python_not_prefix_conversion(leaf, expected):
    query = _compile(["a0b1c2d3-e4f5-4678-9abc-0123456789ab"], normalizer="guid-lower")
    expression = query.split("| extend xdr_discovery_normalized =", 1)[1].splitlines()[0]
    assert 'matches regex @"^[0-9a-fA-F]{32}$"' in expression
    assert expression.strip().startswith("iff(")
    assert expression.endswith(', "")')
    # Check the emitted whole-value guard against the independent Python
    # namespace validator using valid wrappers and malicious trailing text.
    clean = leaf.strip().replace("urn:", "").replace("uuid:", "").strip("{}").replace("-", "")
    assert bool(re.fullmatch(r"[0-9a-fA-F]{32}", clean)) is expected
    if expected:
        assert normalize_value("guid-lower", leaf) == _seed_array(query)[0]
    else:
        with pytest.raises(NormalizationError):
            normalize_value("guid-lower", leaf)


def test_timegenerated_batch_has_the_same_explicit_time_bound():
    query = _compile(tables=["CustomEvents"], time_column="TimeGenerated", lookback="2h")
    assert "where TimeGenerated > ago(2h) and" in query
    assert "Timestamp >" not in query


@pytest.mark.parametrize(
    "options",
    [
        {"tables": []},
        {"tables": ["Table"] * 101},
        {"tables": "DeviceEvents"},
        {"tables": [None]},
        {"tables": ["DeviceEvents) | take 0; //"]},
        {"tables": ["*"]},
        {"tables": ["database('other').Table"]},
        {"tables": ["DeviceEvents-other"]},
        {"tables": ["1Table"]},
        {"time_column": "Timestamp or true"},
        {"time_column": "OtherTime"},
        {"time_column": None},
        {"lookback": "0d"},
        {"lookback": "-1h"},
        {"lookback": "30d); union Other //"},
        {"lookback": "1.5d"},
        {"lookback": None},
        {"max_depth": -1},
        {"max_depth": 13},
        {"max_depth": True},
        {"max_depth": 1.0},
        {"max_depth": "6"},
        {"row_limit": 0},
        {"row_limit": 10001},
        {"row_limit": True},
        {"row_limit": 2.0},
        {"row_limit": "2000 | union Other"},
        {"normalizer": "ip-canonical"},
        {"normalizer": "url-canonical"},
        {"normalizer": "tolower(Value)); union Other"},
        {"normalizer": None},
    ],
)
def test_invalid_scope_and_syntax_parameters_fail_before_query_compilation(options):
    with pytest.raises(GraphValidationError):
        _compile(**options)


@pytest.mark.parametrize(
    "seeds",
    [
        [],
        ["needle"] * 101,
        "needle",
        [None],
        [1],
        [""],
        [" \t "],
        ["line\nbreak"],
        ["carriage\rreturn"],
        ["tab\tvalue"],
        ["nul\x00value"],
        ["delete\x7fvalue"],
        ["\ud800"],
        ["é" * 1025],
    ],
)
def test_invalid_or_unbounded_seeds_are_rejected(seeds):
    with pytest.raises(GraphValidationError):
        _compile(seeds)


def test_utf8_byte_boundary_not_character_boundary():
    query = _compile(["é" * 1024])
    assert _seed_array(query) == ["é" * 1024]


@pytest.mark.parametrize(
    ("normalizer", "seed"),
    [
        ("upn-lower", "invalid"),
        ("guid-lower", "00000000-0000-0000-0000-000000000000"),
        ("sha256-lower", "not-a-digest"),
        ("domain-lower", "not a domain"),
    ],
)
def test_namespace_invalid_seeds_fail_closed(normalizer, seed):
    with pytest.raises(GraphValidationError):
        _compile([seed], normalizer=normalizer)


def test_total_query_syntax_budget_is_enforced():
    seeds = [f"{index:03d}" + "x" * 2045 for index in range(100)]
    with pytest.raises(GraphValidationError, match="syntax budget"):
        _compile(seeds)


def test_nested_escaping_budget_stops_exponential_literal_growth():
    with pytest.raises(GraphValidationError, match="syntax budget"):
        _compile(["\\" * 1000], max_depth=12)


def test_completion_receipt_counts_materialized_bounded_rows_without_repeating_scan():
    query = _compile(row_limit=3)
    assert query.count("| as hint.materialized=true xdr_discovery_limited") == 1
    assert "let xdr_discovery_limited" not in query
    assert "materialize(" not in query
    assert query.count("find withsource=") == 1
    assert query.count("| take ") == 1
    assert (
        "| take 4\n| as hint.materialized=true xdr_discovery_limited\n"
        '| extend RowKind = "match", ReturnedRows = long(null)\n| union\n'
    ) in query
    assert "(xdr_discovery_limited | summarize ReturnedRows = count()" in query
    assert '| extend RowKind = "receipt"' in query
    assert query.count('RowKind = "receipt"') == 1
    assert "| sort by RowKind asc," in query
    assert query.endswith("MatchingRows, DepthLimitReached, UnsupportedPath, ReturnedRows")


def test_completion_receipt_exists_for_zero_hits_with_consistent_column_types():
    query = _compile()
    receipt = query.split("(xdr_discovery_limited | summarize ReturnedRows = count()", 1)[1]
    # Ungrouped summarize count() emits one row containing zero for empty
    # input. No filter or take may remove that receipt after the union.
    assert "| where" not in receipt
    assert "| take" not in receipt
    assert 'TableName = "", ColumnName = ""' in receipt
    assert 'PathTokens = dynamic([]), MatchedValue = "", MatchingRows = long(null)' in receipt
    assert "DepthLimitReached = false, UnsupportedPath = false" in receipt


def test_receipt_table_alias_is_defined_in_the_consuming_pipeline_not_a_separate_let():
    query = _compile()
    # Keep the receipt on the same bounded, materialized scan.
    # The alias must precede the union in the same pipeline and name the
    # bounded data before match-only columns are added.
    source = query[query.index("find withsource=") :]
    assert ";" not in source
    assert source.index("| take 2001") < source.index("| as hint.materialized=true")
    assert source.index("| as hint.materialized=true") < source.index('| extend RowKind = "match"')
    assert source.index('| extend RowKind = "match"') < source.index("| union")
    assert source.index("| union") < source.index("(xdr_discovery_limited | summarize")
    assert source.count("xdr_discovery_limited") == 2


def test_let_and_function_names_start_with_letters_for_defender():
    query = compile_discovery_query(
        ["user@example.com"],
        normalizer="upn-lower",
        tables=["DeviceEvents"],
        time_column="Timestamp",
    )
    names = re.findall(r"^let ([A-Za-z_][A-Za-z0-9_]*)", query, re.MULTILINE)
    assert names
    assert all(name[0].isalpha() for name in names)
