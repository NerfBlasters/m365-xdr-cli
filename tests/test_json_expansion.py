"""Tests for JSON-string column expansion."""

from xdr_cli.json_expansion import (
    JSON_STRING_COLUMNS,
    expand_json_string_columns,
)


def test_known_column_list_is_closed():
    # Explicitly enumerate — adding a column must be a deliberate code change,
    # not a silent behavior shift.
    assert (
        frozenset(
            {
                "RawEventData",
                "AdditionalFields",
                "ResourceData",
                "DetectionMethods",
            }
        )
        == JSON_STRING_COLUMNS
    )


def test_expand_parses_json_string_in_known_column():
    rows = [
        {
            "Timestamp": "2026-04-22T00:00:00Z",
            "RawEventData": '{"ForwardingSMTPAddress": "evil@bad.com"}',
        }
    ]
    out = expand_json_string_columns(rows)
    assert out[0]["RawEventData"] == {"ForwardingSMTPAddress": "evil@bad.com"}
    # Other columns are untouched.
    assert out[0]["Timestamp"] == "2026-04-22T00:00:00Z"


def test_expand_skips_columns_not_on_the_list():
    rows = [{"SomeOtherColumn": '{"not": "expanded"}'}]
    out = expand_json_string_columns(rows)
    assert out[0]["SomeOtherColumn"] == '{"not": "expanded"}'


def test_expand_on_empty_string_keeps_empty_string():
    rows = [{"RawEventData": ""}]
    out = expand_json_string_columns(rows)
    assert out[0]["RawEventData"] == ""


def test_expand_on_invalid_json_keeps_raw_string():
    # Fail-soft: non-JSON in a known column stays as the raw string.
    rows = [{"RawEventData": "not json at all"}]
    out = expand_json_string_columns(rows)
    assert out[0]["RawEventData"] == "not json at all"


def test_expand_on_truncated_json_keeps_raw_string():
    rows = [{"AdditionalFields": '{"ScriptContent":"#!/bin/sh\\nset -'}]
    out = expand_json_string_columns(rows)
    assert out[0]["AdditionalFields"] == '{"ScriptContent":"#!/bin/sh\\nset -'


def test_expand_handles_already_parsed_object_idempotently():
    # If upstream already parsed (shouldn't happen today, but might later),
    # don't re-parse and don't crash.
    rows = [{"RawEventData": {"already": "object"}}]
    out = expand_json_string_columns(rows)
    assert out[0]["RawEventData"] == {"already": "object"}


def test_expand_handles_null_in_known_column():
    rows = [{"RawEventData": None}]
    out = expand_json_string_columns(rows)
    assert out[0]["RawEventData"] is None


def test_expand_handles_empty_list():
    assert expand_json_string_columns([]) == []


def test_expand_handles_nested_object_in_rawevent():
    payload = '{"Outer": {"Inner": [1, 2, 3], "Flag": true}}'
    rows = [{"RawEventData": payload}]
    out = expand_json_string_columns(rows)
    assert out[0]["RawEventData"]["Outer"]["Inner"] == [1, 2, 3]
    assert out[0]["RawEventData"]["Outer"]["Flag"] is True


def test_expand_applies_to_every_row_independently():
    rows = [
        {"RawEventData": '{"a": 1}'},
        {"RawEventData": "not json"},
        {"RawEventData": '{"b": 2}'},
    ]
    out = expand_json_string_columns(rows)
    assert out[0]["RawEventData"] == {"a": 1}
    assert out[1]["RawEventData"] == "not json"
    assert out[2]["RawEventData"] == {"b": 2}


def test_expand_is_non_mutating():
    rows = [{"RawEventData": '{"a": 1}'}]
    original = rows[0]["RawEventData"]
    expand_json_string_columns(rows)
    # Caller's original data must not be clobbered.
    assert rows[0]["RawEventData"] == original
