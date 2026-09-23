from __future__ import annotations

import json

from xdr_cli.schema_graph.discover import discover_nested_fields


def test_discovers_complex_nested_keys_and_collapses_arrays_without_values():
    secret = "sensitive-value-that-must-not-survive"
    rows = [
        {
            "RawEventData": {
                "User.Id": secret,
                "Key With Space": {"slash/key": "other-sensitive-value"},
                "Targets": [
                    {"Id": "first-sensitive-id", "Type": "User"},
                    {"Id": "second-sensitive-id", "Type": "Group"},
                ],
            }
        },
        {"RawEventData": '{"Targets":[{"Id":null}],"Flag":true}'},
    ]
    result = discover_nested_fields("CloudAppEvents", rows)
    by_locator = {str(item.locator): item for item in result.fields}

    assert "CloudAppEvents.RawEventData#/User.Id" in by_locator
    assert "CloudAppEvents.RawEventData#/Key%20With%20Space/slash~1key" in by_locator
    target_id = by_locator["CloudAppEvents.RawEventData#/Targets/*/Id"]
    assert target_id.present_rows == 2
    assert target_id.non_null_rows == 1
    assert target_id.occurrences == 3
    assert target_id.observed_types == ("null", "string")
    serialized = json.dumps(result.to_dict())
    assert secret not in serialized
    assert "first-sensitive-id" not in serialized
    assert "second-sensitive-id" not in serialized


def test_unknown_json_looking_column_is_not_parsed():
    result = discover_nested_fields(
        "DeviceEvents",
        [{"UnknownPayload": '{"UserId":"sensitive"}'}],
    )
    assert result.fields == ()
    assert result.parse_failures == 0


def test_parse_failures_and_bounds_are_explicit():
    rows = [
        {"AdditionalFields": "not-json"},
        {"AdditionalFields": {"A": {"B": {"C": "value"}}, "D": 1}},
    ]
    result = discover_nested_fields(
        "DeviceEvents",
        rows,
        max_depth=2,
        max_paths=2,
    )
    assert result.parse_failures == 1
    assert result.truncated is True
    assert len(result.fields) == 2


def test_array_scan_is_bounded_and_deterministic():
    rows = [{"DetectionMethods": {"Signals": list(range(100))}}]
    first = discover_nested_fields("EmailEvents", rows, max_array_items=3)
    second = discover_nested_fields("EmailEvents", rows, max_array_items=3)
    assert first == second
    assert first.truncated is True
    wildcard = next(item for item in first.fields if str(item.locator).endswith("#/Signals/*"))
    assert wildcard.occurrences == 3
