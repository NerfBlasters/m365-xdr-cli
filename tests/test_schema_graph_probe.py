from __future__ import annotations

import json

import pytest

from xdr_cli.schema_graph.model import FieldLocator, GraphValidationError, InterpretationRecord
from xdr_cli.schema_graph.probe import (
    PROBE_QUERY_BYTE_LIMIT,
    aggregate_observation,
    compile_source_sampling_query,
    compile_target_probe_batches,
    compile_target_probe_query,
)


def _interpretation(locator: FieldLocator, normalizer: str = "upn-lower"):
    return InterpretationRecord(
        id=f"interp:{locator}:{'entra-upn'}:actor",
        field_id=f"field:{locator}",
        entity_kind="user",
        namespace="entra-upn",
        role="actor",
        normalizer=normalizer,
    )


def test_top_level_source_sampling_is_bounded_and_deterministic():
    locator = FieldLocator.parse("EntraIdSignInEvents.AccountUpn")
    interpretation = _interpretation(locator)
    first = compile_source_sampling_query(
        interpretation,
        locator,
        lookback="14d",
        samples=7,
        available_columns={"EntraIdSignInEvents": {"Timestamp", "AccountUpn"}},
    )
    second = compile_source_sampling_query(interpretation, locator, lookback="14d", samples=7)
    assert first.kql == second.kql
    assert first.kql.startswith("EntraIdSignInEvents\n| where Timestamp > ago(14d)")
    assert "| sort by Occurrences asc, Value asc\n| take 70" in first.kql


def test_upn_source_sampling_prefilters_and_overfetches_candidates():
    locator = FieldLocator.parse("EntraIdSignInEvents.AccountUpn")
    query = compile_source_sampling_query(_interpretation(locator), locator, samples=5)

    assert '| where __xdr_normalized contains "@"' in query.kql
    assert "| take 50\n| project Value, Occurrences" in query.kql


def test_probe_kql_applies_supported_normalizers_to_target_values():
    guid_locator = FieldLocator.parse("EntraIdSignInEvents.AccountObjectId")
    guid_query = compile_target_probe_query(
        _interpretation(guid_locator, "guid-lower"),
        guid_locator,
        ["A0B1C2D3-E4F5-4678-9ABC-0123456789AB"],
    )
    assert 'tostring(toguid(trim(@"\\s+", tostring(__xdr_value))))' in guid_query.kql

    host_locator = FieldLocator.parse("DeviceInfo.DeviceName")
    host_query = compile_target_probe_query(
        _interpretation(host_locator, "hostname-lower"),
        host_locator,
        ["HOST.EXAMPLE.COM."],
    )
    assert 'trim_end(@"[.]+", tolower(trim(@"\\s+"' in host_query.kql


def test_nested_pointer_compiles_with_escaped_bracket_access():
    locator = FieldLocator.parse(
        "CloudAppEvents.RawEventData#/Key%20With%20Space/slash~1key/quote%22key"
    )
    interpretation = _interpretation(locator)
    query = compile_source_sampling_query(interpretation, locator)
    assert (
        'parse_json(tostring(RawEventData))["Key With Space"]["slash/key"]'
        '["quote\\"key"]' in query.kql
    )
    assert query.nested is True


def test_array_wildcard_compiles_through_mv_apply():
    locator = FieldLocator.parse("CloudAppEvents.RawEventData#/Targets/*/UserId")
    interpretation = _interpretation(locator)
    query = compile_source_sampling_query(interpretation, locator)
    assert '| extend __xdr_array = parse_json(tostring(RawEventData))["Targets"]' in query.kql
    assert "| mv-apply __xdr_item = __xdr_array on (" in query.kql
    assert 'extend __xdr_value = tostring(__xdr_item["UserId"])' in query.kql
    assert query.wildcard is True


def test_multiple_wildcards_fail_closed():
    locator = FieldLocator.parse("CloudAppEvents.RawEventData#/Targets/*/Values/*/Id")
    with pytest.raises(GraphValidationError, match="at most one"):
        compile_source_sampling_query(_interpretation(locator), locator)


def test_seed_literals_cannot_change_query_structure_and_are_deduplicated():
    locator = FieldLocator.parse("EntraIdSignInEvents.AccountUpn")
    interpretation = _interpretation(locator)
    hostile = 'user\\"],DeviceEvents|take100;//@example.com'
    query = compile_target_probe_query(
        interpretation,
        locator,
        [hostile, "Normal@Example.com", "normal@example.com"],
    )
    assert query.kql.count("normal@example.com") == 1
    assert hostile not in query.kql
    assert query.kql.splitlines()[0] == "EntraIdSignInEvents"
    assert 'set_has_element(dynamic(["normal@example.com"' in query.kql
    assert "Value" not in query.kql
    assert "MatchedSeeds=dcount(__xdr_normalized)" in query.kql


def test_target_batches_are_deterministic_labelled_and_counts_only():
    first_locator = FieldLocator.parse("ZTable.OddName")
    second_locator = FieldLocator.parse("ATable.OtherName")
    targets = [
        (_interpretation(first_locator), first_locator),
        (_interpretation(second_locator), second_locator),
    ]
    batches = compile_target_probe_batches(
        targets,
        ["User@Example.com"],
        batch_size=1,
        available_columns={
            "ATable": {"OtherName", "Timestamp"},
            "ZTable": {"OddName", "Timestamp"},
        },
    )
    assert len(batches) == 2
    assert batches[0].target_locators == ("ATable.OtherName",)
    assert batches[0].table == "ATable"
    assert batches[0].task_id.startswith("probe-task:")
    assert '"TargetLocator","ATable.OtherName"' in batches[0].kql
    assert 'let _xdr_seeds = dynamic(["user@example.com"]);' in batches[0].kql
    assert "set_has_element(_xdr_seeds, __xdr_value_0)" in batches[0].kql
    assert "let __" not in batches[0].kql
    assert "__xdr_seeds_0=dcountif(__xdr_value_0" in batches[0].kql
    assert "by Value" not in batches[0].kql


def test_compatible_fields_share_one_table_scan():
    first = FieldLocator.parse("CloudAppEvents.AccountObjectId")
    second = FieldLocator.parse("CloudAppEvents.ObjectId")

    batches = compile_target_probe_batches(
        [(_interpretation(first), first), (_interpretation(second), second)],
        ["User@Example.com"],
        batch_size=20,
        available_columns={"CloudAppEvents": {"Timestamp", "AccountObjectId", "ObjectId"}},
    )

    assert len(batches) == 1
    assert batches[0].table == "CloudAppEvents"
    assert batches[0].target_locators == (
        "CloudAppEvents.AccountObjectId",
        "CloudAppEvents.ObjectId",
    )
    assert batches[0].kql.splitlines().count("CloudAppEvents") == 1
    assert batches[0].kql.count("| where Timestamp > ago(30d)") == 1
    assert batches[0].kql.count('"TargetLocator"') == 2


def test_target_batches_prioritize_reviewed_interpretations():
    reviewed_locator = FieldLocator.parse("ZTable.KnownDeviceId")
    provisional_locator = FieldLocator.parse("ATable.UnknownValue")
    reviewed = _interpretation(reviewed_locator)
    provisional_base = _interpretation(provisional_locator)
    provisional = InterpretationRecord(
        id=provisional_base.id,
        field_id=provisional_base.field_id,
        entity_kind=provisional_base.entity_kind,
        namespace=provisional_base.namespace,
        role=provisional_base.role,
        normalizer=provisional_base.normalizer,
        extra={"provisional": True},
    )

    batches = compile_target_probe_batches(
        [
            (provisional, provisional_locator),
            (reviewed, reviewed_locator),
        ],
        ["User@Example.com"],
        batch_size=1,
    )

    assert batches[0].target_locators == ("ZTable.KnownDeviceId",)
    assert batches[1].target_locators == ("ATable.UnknownValue",)


def test_target_batches_split_to_enforce_compiled_query_budget():
    targets = []
    for index in range(50):
        locator = FieldLocator.parse(f"Table{index}.Value")
        targets.append((_interpretation(locator, "identity"), locator))
    seeds = [f"seed-{index}-" + ("x" * 2000) for index in range(100)]

    batches = compile_target_probe_batches(targets, seeds, batch_size=50)

    assert len(batches) > 1
    assert all(batch.query_bytes <= PROBE_QUERY_BYTE_LIMIT for batch in batches)
    assert sum(len(batch.target_locators) for batch in batches) == 50


def test_probe_fails_closed_when_schema_has_no_temporal_column():
    locator = FieldLocator.parse("IdentityInfo.AccountUpn")
    with pytest.raises(GraphValidationError, match="no cached Timestamp or TimeGenerated"):
        compile_source_sampling_query(
            _interpretation(locator),
            locator,
            available_columns={"IdentityInfo": {"AccountUpn"}},
        )
    with pytest.raises(GraphValidationError, match="no cached Timestamp or TimeGenerated"):
        compile_target_probe_query(
            _interpretation(locator),
            locator,
            ["user@example.invalid"],
            available_columns={"IdentityInfo": {"AccountUpn"}},
        )


def test_probe_uses_timegenerated_as_a_bounding_column_not_a_match_key():
    locator = FieldLocator.parse("SigninLogs.UserPrincipalName")
    columns = {"SigninLogs": {"TimeGenerated", "UserPrincipalName"}}

    source = compile_source_sampling_query(
        _interpretation(locator), locator, lookback="7d", available_columns=columns
    )
    target = compile_target_probe_query(
        _interpretation(locator),
        locator,
        ["user@example.invalid"],
        lookback="7d",
        available_columns=columns,
    )

    assert source.kql.startswith("SigninLogs\n| where TimeGenerated > ago(7d)")
    assert target.kql.startswith("SigninLogs\n| where TimeGenerated > ago(7d)")
    assert "set_has_element" in target.kql


def test_unsupported_kql_normalizer_and_bad_bounds_fail_closed():
    locator = FieldLocator.parse("CloudAppEvents.ObjectName")
    with pytest.raises(GraphValidationError, match="no deterministic KQL prefilter"):
        compile_source_sampling_query(_interpretation(locator, "url-canonical"), locator)
    with pytest.raises(GraphValidationError, match="no deterministic KQL prefilter"):
        compile_source_sampling_query(_interpretation(locator, "ip-canonical"), locator)
    with pytest.raises(GraphValidationError, match="samples"):
        compile_source_sampling_query(_interpretation(locator), locator, samples=0)
    with pytest.raises(GraphValidationError, match="lookback"):
        compile_source_sampling_query(_interpretation(locator), locator, lookback="ago(30d)")


def test_constrained_nested_interpretation_fails_closed_until_supported():
    locator = FieldLocator.parse("CloudAppEvents.RawEventData#/TargetResources/*/id")
    base = _interpretation(locator, "guid-lower")
    constrained = InterpretationRecord(
        id=base.id,
        field_id=base.field_id,
        entity_kind=base.entity_kind,
        namespace=base.namespace,
        role=base.role,
        normalizer=base.normalizer,
        constraints=({"sibling": "type", "equals_casefold": "user"},),
    )
    with pytest.raises(GraphValidationError, match="cannot yet enforce"):
        compile_source_sampling_query(constrained, locator)
    with pytest.raises(GraphValidationError, match="cannot yet enforce"):
        compile_target_probe_query(
            constrained,
            locator,
            ["11111111-1111-1111-1111-111111111111"],
        )


def test_observation_aggregation_accepts_counts_not_values():
    observation = aggregate_observation(
        observation_id="probe:aggregate-1",
        source_interpretation="interp:a",
        target_interpretation="interp:b",
        transform="upn-lower",
        distinct_seeds=5,
        matched_seeds=3,
        probe_runs=1,
        provenance=("tenant-observation:aggregate-1",),
    )
    serialized = json.dumps(
        {
            "observation_id": observation.observation_id,
            "distinct_seeds": observation.distinct_seeds,
            "matched_seeds": observation.matched_seeds,
        }
    )
    assert "Value" not in serialized
    assert "seed" in serialized
