"""Tests for output formatting."""

import json

from xdr_cli.output import OutputFormatter


def test_render_json_envelope():
    fmt = OutputFormatter()
    data = [{"id": "1", "title": "Test"}]
    result = fmt.format_output(data, metadata={"total_count": 1})
    parsed = json.loads(result)
    assert parsed["status"] == "success"
    assert parsed["data"] == data
    assert parsed["metadata"]["total_count"] == 1


def test_render_json_single_item():
    fmt = OutputFormatter()
    data = {"id": "1", "title": "Test"}
    result = fmt.format_output(data)
    parsed = json.loads(result)
    assert parsed["data"]["id"] == "1"


def test_format_output_empty_list():
    fmt = OutputFormatter()
    result = fmt.format_output([])
    parsed = json.loads(result)
    assert parsed["data"] == []
    assert parsed["status"] == "success"


def test_format_output_ignores_columns_and_title_kwargs():
    """columns/title kwargs remain accepted for call-site compatibility but do nothing."""
    fmt = OutputFormatter()
    data = [{"id": "1"}]
    result = fmt.format_output(data, columns=[{"key": "id"}], title="X")
    parsed = json.loads(result)
    assert parsed["data"] == data


def test_formatter_expands_rawevent_by_default():
    """By default, OutputFormatter parses known JSON-string columns."""
    fmt = OutputFormatter()
    data = [
        {
            "Timestamp": "t",
            "RawEventData": '{"ForwardingSMTPAddress": "evil@bad.com"}',
        }
    ]
    result = fmt.format_output(data)
    parsed = json.loads(result)
    assert parsed["data"][0]["RawEventData"] == {"ForwardingSMTPAddress": "evil@bad.com"}


def test_formatter_raw_flag_suppresses_expansion():
    """expand_json=False preserves the raw JSON-string shape."""
    fmt = OutputFormatter(expand_json=False)
    raw_payload = '{"ForwardingSMTPAddress": "evil@bad.com"}'
    data = [{"RawEventData": raw_payload}]
    result = fmt.format_output(data)
    parsed = json.loads(result)
    assert parsed["data"][0]["RawEventData"] == raw_payload


# ---------------------------------------------------------------------------
# Session metadata propagation (Task 3 Step 4)
# ---------------------------------------------------------------------------


def test_session_id_metadata_present_when_set():
    fmt = OutputFormatter(session_id="jd-47", session_label="dns-beacon-smoke")
    parsed = json.loads(fmt.format_output([]))
    assert parsed["metadata"]["session_id"] == "jd-47"
    assert parsed["metadata"]["session_label"] == "dns-beacon-smoke"


def test_session_id_metadata_keys_present_when_unset():
    """Even with no session, metadata.session_id / session_label keys are
    present in the envelope (with value None) so downstream consumers have
    a stable shape."""
    fmt = OutputFormatter()
    parsed = json.loads(fmt.format_output([]))
    assert parsed["metadata"]["session_id"] is None
    assert parsed["metadata"]["session_label"] is None


def test_caller_metadata_wins_on_collision():
    """Caller-provided metadata keys override the constructor's session
    keys. Documents the precedence rule: existing hunt metadata
    (cpu_usage, has_more) is authoritative, session keys are additive."""
    fmt = OutputFormatter(session_id="jd-47")
    parsed = json.loads(fmt.format_output([], metadata={"session_id": "explicit-override"}))
    assert parsed["metadata"]["session_id"] == "explicit-override"


def test_caller_metadata_merges_with_session_keys():
    """Both session keys and caller keys appear in the envelope when no collision."""
    fmt = OutputFormatter(session_id="jd-47", session_label="my-label")
    parsed = json.loads(fmt.format_output([], metadata={"cpu_usage": "12%", "has_more": False}))
    assert parsed["metadata"]["session_id"] == "jd-47"
    assert parsed["metadata"]["session_label"] == "my-label"
    assert parsed["metadata"]["cpu_usage"] == "12%"
    assert parsed["metadata"]["has_more"] is False
