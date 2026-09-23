"""Tests for `xdr history` browse sub-app.

The browse callback filters JSONL invocation records for a session (or
operator aggregate) and emits a JSON envelope on stdout. Seeding goes
straight to disk via plain file writes — keeps these tests fast and avoids
coupling to Recorder internals which are exercised in test_main.py /
test_sessions.py.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolated XDR_CLI_HOME for each test."""
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return home


def _seed_jsonl(home_dir, session_id, records):
    """Write `records` (list of dicts) as JSONL under sessions/<id>.jsonl."""
    path = home_dir / "sessions" / f"{session_id}.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return path


def _set_current(home_dir, session_id):
    """Write a per-session marker in active_sessions/<id>."""
    d = home_dir / "active_sessions"
    d.mkdir(parents=True, mode=0o700, exist_ok=True)
    payload = {"id": session_id, "upn": "", "label": None, "learning_mode": False}
    (d / session_id).write_text(json.dumps(payload))


# ---------------------------------------------------------------------------
# Plan-spec'd tests
# ---------------------------------------------------------------------------


def test_history_current_session(home):
    """Browse defaults to current session and excludes session_started."""
    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "hunt run",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:02:00Z",
            "session_id": "jd-1",
            "seq": 2,
            "command": "hunt library",
        },
    ]
    _seed_jsonl(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    # Returns the 2 invocation records (session_started excluded from data).
    assert len(parsed["data"]) == 2
    assert parsed["data"][0]["seq"] == 1
    assert parsed["data"][1]["seq"] == 2


def test_history_command_filter(home):
    """--command does substring match on the `command` field."""
    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "hunt run",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:02:00Z",
            "session_id": "jd-1",
            "seq": 2,
            "command": "hunt library",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:03:00Z",
            "session_id": "jd-1",
            "seq": 3,
            "command": "alerts list",
        },
    ]
    _seed_jsonl(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "--command", "hunt run"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert len(parsed["data"]) == 1
    assert parsed["data"][0]["seq"] == 1
    assert parsed["data"][0]["command"] == "hunt run"


def test_history_no_active_session_no_explicit_id_errors(home):
    result = runner.invoke(app, ["history"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" in combined.lower()


# ---------------------------------------------------------------------------
# Additional surface coverage
# ---------------------------------------------------------------------------


def test_history_session_flag_works_without_active_session(home):
    """--session bypasses the no-active-session error."""
    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-2",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-2",
            "seq": 1,
            "command": "hunt run",
        },
    ]
    _seed_jsonl(home, "jd-2", records)
    # No current_session pointer.

    result = runner.invoke(app, ["history", "--session", "jd-2"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert len(parsed["data"]) == 1
    assert parsed["data"][0]["session_id"] == "jd-2"


def test_history_incident_filter(home):
    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "hunt run",
            "anchor_incident": "INC-42",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:02:00Z",
            "session_id": "jd-1",
            "seq": 2,
            "command": "hunt run",
            "anchor_incident": "INC-99",
        },
    ]
    _seed_jsonl(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "--incident", "INC-42"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert len(parsed["data"]) == 1
    assert parsed["data"][0]["anchor_incident"] == "INC-42"


def test_history_incident_filter_normalizes_numeric_anchor(home):
    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "incidents show",
            "anchor_incident": 123,
        },
    ]
    _seed_jsonl(home, "jd-1", records)
    _set_current(home, "jd-1")
    result = runner.invoke(app, ["history", "--incident", "123"])
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)["data"]) == 1


def test_history_since_filter(home, monkeypatch):
    """--since filters records older than the duration window."""
    # Freeze "now" so the test isn't time-flaky. Patch the symbol that
    # history_cmd imports.
    from datetime import UTC, datetime

    fixed_now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=UTC)

    class _FrozenDT:
        @classmethod
        def now(cls, tz=None):  # noqa: D401 -- match datetime.now
            return fixed_now

    monkeypatch.setattr("xdr_cli.commands.history_cmd.datetime", _FrozenDT)

    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-22T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        # 48h old — should be filtered out by --since 24h.
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-22T12:00:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "hunt run",
        },
        # 1h old — should be kept by --since 24h.
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T11:00:00Z",
            "session_id": "jd-1",
            "seq": 2,
            "command": "hunt run",
        },
    ]
    _seed_jsonl(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "--since", "24h"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert len(parsed["data"]) == 1
    assert parsed["data"][0]["seq"] == 2


def test_history_since_unparseable_errors(home):
    _seed_jsonl(
        home,
        "jd-1",
        [
            {
                "kind": "session_started",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:00:00Z",
                "session_id": "jd-1",
                "upn": "j@c",
            },
            {
                "kind": "invocation",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:01:00Z",
                "session_id": "jd-1",
                "seq": 1,
                "command": "x",
            },
        ],
    )
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "--since", "not a duration"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "since" in combined.lower() or "duration" in combined.lower()


def test_history_since_pure_numeric_rejected(home):
    """`--since 30` with no unit is rejected — guards against the
    pytimeparse2 default of "bare integers = seconds" which silently
    contradicts the help text (which advertises ``24h/7d/30d``)."""
    _seed_jsonl(
        home,
        "jd-1",
        [
            {
                "kind": "session_started",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:00:00Z",
                "session_id": "jd-1",
                "upn": "j@c",
            },
        ],
    )
    _set_current(home, "jd-1")

    result = runner.invoke(
        app, ["history", "--since", "30", "--session", "jd-1"]
    )
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert (
        "could not parse" in combined.lower()
        or "missing unit" in combined.lower()
    )
    # Hint surfaces a valid suffix or the word "suffix" itself.
    assert "24h" in combined or "7d" in combined or "suffix" in combined.lower()


def test_history_operator_aggregates(home):
    """--operator aggregates records across all sessions for that operator."""
    rec_a = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "hunt run",
        },
    ]
    rec_b = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T01:00:00Z",
            "session_id": "jd-2",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T01:01:00Z",
            "session_id": "jd-2",
            "seq": 1,
            "command": "alerts list",
        },
    ]
    rec_other = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T02:00:00Z",
            "session_id": "ab-1",
            "upn": "a@b",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T02:01:00Z",
            "session_id": "ab-1",
            "seq": 1,
            "command": "hunt run",
        },
    ]
    _seed_jsonl(home, "jd-1", rec_a)
    _seed_jsonl(home, "jd-2", rec_b)
    _seed_jsonl(home, "ab-1", rec_other)

    result = runner.invoke(app, ["history", "--operator", "jd"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    sids = sorted(r["session_id"] for r in parsed["data"])
    assert sids == ["jd-1", "jd-2"]


def test_history_session_beats_operator_with_warning(home):
    """When both --session and --operator are given, --session wins; a warning
    is emitted to stderr noting --operator was ignored."""
    _seed_jsonl(
        home,
        "jd-1",
        [
            {
                "kind": "session_started",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:00:00Z",
                "session_id": "jd-1",
                "upn": "j@c",
            },
            {
                "kind": "invocation",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:01:00Z",
                "session_id": "jd-1",
                "seq": 1,
                "command": "hunt run",
            },
        ],
    )
    _seed_jsonl(
        home,
        "ab-1",
        [
            {
                "kind": "session_started",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:00:00Z",
                "session_id": "ab-1",
                "upn": "a@b",
            },
            {
                "kind": "invocation",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:02:00Z",
                "session_id": "ab-1",
                "seq": 1,
                "command": "alerts list",
            },
        ],
    )

    result = runner.invoke(
        app, ["history", "--session", "jd-1", "--operator", "ab"]
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    sids = {r["session_id"] for r in parsed["data"]}
    assert sids == {"jd-1"}
    # Warning surfaced somewhere observable.
    combined = (result.output or "") + (result.stderr or "")
    assert "operator" in combined.lower()


def test_history_chain_capture(home, monkeypatch):
    """Smoke test mirroring test_chain_capture_smoke for the new sub-app:
    invoking ``xdr history`` with an active session captures
    ``command == "history"`` on the resulting invocation record."""
    import sys

    from xdr_cli.main import run

    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": "jd-1",
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": False,
    }
    (home / "sessions" / "jd-1.jsonl").write_text(json.dumps(started) + "\n")
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(sys, "argv", ["xdr", "history"])

    with pytest.raises(SystemExit):
        run()

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [
        json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"
    ]
    assert len(invocations) == 1
    assert invocations[0]["command"] == "history"


# ---------------------------------------------------------------------------
# `xdr history stats` aggregates (Task 6)
# ---------------------------------------------------------------------------


def _stats_record(
    seq: int,
    command: str,
    *,
    timestamp: str | None = None,
    actor: str = "operator",
    cpu_usage: str | None = None,
    exit_code: int = 0,
    error: dict | str | None = None,
    tables_referenced: list[str] | None = None,
    library_query: str | None = None,
    kql: str | None = None,
    session_id: str = "jd-1",
) -> dict:
    """Compact factory for stats invocation records — keeps tests readable."""
    return {
        "kind": "invocation",
        "schema_version": 1,
        "timestamp": timestamp or f"2026-04-24T00:{seq:02d}:00Z",
        "session_id": session_id,
        "seq": seq,
        "command": command,
        "actor": actor,
        "result": {"cpu_usage": cpu_usage},
        "exit_code": exit_code,
        "error": error,
        "tables_referenced": tables_referenced,
        "library_query": library_query,
        "kql": kql,
    }


def _seed_session(home_dir, session_id, records, *, upn: str = "j@c") -> None:
    """Prepend a ``session_started`` record + write JSONL.

    ``current_session()`` hydrates from the ``session_started`` line; tests
    seeding only invocation records would otherwise hit "no active session".
    """
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": session_id,
        "upn": upn,
    }
    _seed_jsonl(home_dir, session_id, [started, *records])


def test_stats_invocation_counts(home):
    """Five invocations: 3 hunt run, 2 hunt library-run; ratio 3:2."""
    records = [
        _stats_record(1, "hunt run"),
        _stats_record(2, "hunt run"),
        _stats_record(3, "hunt run"),
        _stats_record(4, "hunt library-run"),
        _stats_record(5, "hunt library-run"),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    data = parsed["data"]
    assert data["invocations"]["total"] == 5
    assert data["invocations"]["by_command"]["hunt run"] == 3
    assert data["invocations"]["by_command"]["hunt library-run"] == 2
    assert data["hunt_ratio"]["hunt_run"] == 3
    assert data["hunt_ratio"]["hunt_library_run"] == 2
    assert data["hunt_ratio"]["ratio_explanatory"] == "3:2"


def test_stats_counts_native_and_legacy_library_run_together(home):
    records = [
        _stats_record(1, "hunt run"),
        _stats_record(2, "library run"),
        _stats_record(3, "hunt library-run"),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")
    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    ratio = json.loads(result.stdout)["data"]["hunt_ratio"]
    assert ratio["hunt_library_run"] == 2
    assert ratio["ratio_explanatory"] == "1:2"


def test_stats_cpu_sum(home):
    """cpu_usage_total sums NN%-shaped strings; None values ignored."""
    records = [
        _stats_record(1, "hunt run", cpu_usage="10%"),
        _stats_record(2, "hunt run", cpu_usage="25%"),
        _stats_record(3, "hunt run", cpu_usage=None),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["data"]["cpu_usage_total"] == "35%"


def test_stats_failure_rate(home):
    """10 records, 2 failed -> 20.0%; top_errors ranks by code/exit_code."""
    records = []
    # 8 successful records.
    for i in range(1, 9):
        records.append(_stats_record(i, "hunt run", exit_code=0))
    # 2 failures with distinct error codes.
    records.append(
        _stats_record(
            9, "hunt run", exit_code=1, error={"code": "AuthError"}
        )
    )
    records.append(
        _stats_record(
            10, "hunt run", exit_code=1, error={"code": "AuthError"}
        )
    )
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    fr = parsed["data"]["failure_rate"]
    assert fr["total"] == 10
    assert fr["failed"] == 2
    assert fr["rate_percent"] == 20.0
    # AuthError is the dominant error code -> top entry.
    assert fr["top_errors"]
    assert fr["top_errors"][0]["code"] == "AuthError"
    assert fr["top_errors"][0]["count"] == 2


def test_stats_failure_rate_zero_failures(home):
    """0 failures -> rate_percent 0.0, top_errors []."""
    records = [_stats_record(i, "hunt run", exit_code=0) for i in range(1, 4)]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    fr = parsed["data"]["failure_rate"]
    assert fr["total"] == 3
    assert fr["failed"] == 0
    assert fr["rate_percent"] == 0.0
    assert fr["top_errors"] == []


def test_stats_table_coverage_gaps(home):
    """A hunt run touched a library-covered table without using the library."""
    # CloudAppEvents is referenced by qry_inbox_rule_audit.kql / qry_inbox_rule_triggers.kql.
    records = [
        _stats_record(
            1,
            "hunt run",
            tables_referenced=["CloudAppEvents"],
            kql="CloudAppEvents | take 1",
            library_query=None,
        ),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    gaps = parsed["data"]["table_coverage_gaps"]
    tables = {g["table"] for g in gaps}
    assert "CloudAppEvents" in tables


def test_stats_table_coverage_gaps_retokenize_null(home):
    """tables_referenced is None but kql is set -> retry tokenizer."""
    records = [
        _stats_record(
            1,
            "hunt run",
            tables_referenced=None,  # write-time tokenizer "failed"
            kql="CloudAppEvents | take 1",
            library_query=None,
        ),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    gaps = parsed["data"]["table_coverage_gaps"]
    assert any(g["table"] == "CloudAppEvents" for g in gaps)


def test_stats_table_coverage_gaps_excludes_library_run(home):
    """library-run records do not produce gaps even when they hit covered tables."""
    records = [
        _stats_record(
            1,
            "hunt library-run",
            tables_referenced=["CloudAppEvents"],
            kql="CloudAppEvents | take 1",
            library_query="qry_inbox_rule_audit",
        ),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    gaps = parsed["data"]["table_coverage_gaps"]
    assert all(g["table"] != "CloudAppEvents" for g in gaps)


def test_stats_hunt_ratio_zero_denominator(home):
    """hunt_run > 0 but hunt_library_run == 0 -> "3:0" verbatim, no crash."""
    records = [
        _stats_record(1, "hunt run"),
        _stats_record(2, "hunt run"),
        _stats_record(3, "hunt run"),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["data"]["hunt_ratio"]["ratio_explanatory"] == "3:0"


def test_stats_hunt_ratio_zero_zero(home):
    """All four hunt-related counters at 0 -> "0:0" verbatim, no gcd crash."""
    # Session with only non-hunt commands — every hunt_ratio counter is 0.
    records = [
        _stats_record(1, "auth status"),
        _stats_record(2, "auth status"),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    hr = parsed["data"]["hunt_ratio"]
    assert hr["hunt_run"] == 0
    assert hr["hunt_library_run"] == 0
    assert hr["pivot"] == 0
    assert hr["investigate.hunt"] == 0
    assert hr["ratio_explanatory"] == "0:0"


def test_stats_session_duration_seconds_single_session(home):
    """Single session -> last_timestamp - first_timestamp in seconds."""
    records = [
        _stats_record(
            1, "hunt run", timestamp="2026-04-24T00:00:00Z"
        ),
        _stats_record(
            2, "hunt run", timestamp="2026-04-24T00:01:30Z"
        ),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["data"]["session_duration_seconds"] == 90.0


def test_stats_session_duration_null_for_operator_filter(home):
    """--operator -> multi-session aggregate -> session_duration_seconds is None."""
    rec_a = [
        _stats_record(
            1,
            "hunt run",
            timestamp="2026-04-24T00:00:00Z",
            session_id="jd-1",
        ),
    ]
    rec_b = [
        _stats_record(
            1,
            "hunt run",
            timestamp="2026-04-24T01:00:00Z",
            session_id="jd-2",
        ),
    ]
    # Each session needs a session_started line for list_sessions to find it.
    _seed_jsonl(
        home,
        "jd-1",
        [
            {
                "kind": "session_started",
                "schema_version": 1,
                "timestamp": "2026-04-24T00:00:00Z",
                "session_id": "jd-1",
                "upn": "j@c",
            },
            *rec_a,
        ],
    )
    _seed_jsonl(
        home,
        "jd-2",
        [
            {
                "kind": "session_started",
                "schema_version": 1,
                "timestamp": "2026-04-24T01:00:00Z",
                "session_id": "jd-2",
                "upn": "j@c",
            },
            *rec_b,
        ],
    )

    result = runner.invoke(app, ["history", "stats", "--operator", "jd"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["data"]["session_duration_seconds"] is None


def test_stats_by_actor_breakdown(home):
    """--by-actor splits invocations / hunt_ratio / cpu_usage_total /
    failure_rate per actor; excludes session_duration_seconds and
    table_coverage_gaps from the breakdown."""
    records = [
        _stats_record(
            1, "hunt run", actor="operator", cpu_usage="10%", exit_code=0
        ),
        _stats_record(
            2,
            "hunt library-run",
            actor="operator",
            cpu_usage="5%",
            exit_code=0,
        ),
        _stats_record(
            3, "hunt run", actor="path1", cpu_usage="20%", exit_code=1,
            error={"code": "AuthError"},
        ),
    ]
    _seed_session(home, "jd-1", records)
    _set_current(home, "jd-1")

    result = runner.invoke(app, ["history", "stats", "--by-actor"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    data = parsed["data"]

    # invocations.by_actor present and correct.
    by_actor_inv = data["invocations"]["by_actor"]
    assert by_actor_inv["operator"]["total"] == 2
    assert by_actor_inv["path1"]["total"] == 1

    # hunt_ratio.by_actor present.
    assert data["hunt_ratio"]["by_actor"]["operator"]["hunt_run"] == 1
    assert data["hunt_ratio"]["by_actor"]["operator"]["hunt_library_run"] == 1
    assert data["hunt_ratio"]["by_actor"]["path1"]["hunt_run"] == 1

    # cpu_usage_total.by_actor present.
    cpu_by_actor = data["cpu_usage_total_by_actor"]
    assert cpu_by_actor["operator"] == "15%"
    assert cpu_by_actor["path1"] == "20%"

    # failure_rate.by_actor present and correct (path1 has 1/1 failed).
    fr_by_actor = data["failure_rate"]["by_actor"]
    assert fr_by_actor["operator"]["failed"] == 0
    assert fr_by_actor["path1"]["failed"] == 1
    assert fr_by_actor["path1"]["rate_percent"] == 100.0

    # session_duration_seconds and table_coverage_gaps DO NOT split per-actor.
    assert "by_actor" not in (
        data.get("session_duration_seconds")
        if isinstance(data.get("session_duration_seconds"), dict)
        else {}
    )
    # They remain top-level scalars / lists, not dicts keyed by actor.
    assert isinstance(data["session_duration_seconds"], (int, float))
    assert isinstance(data["table_coverage_gaps"], list)


# ---------------------------------------------------------------------------
# Task 4: Marker resolution regression tests
# ---------------------------------------------------------------------------


def test_history_uses_xdr_session_when_flag_omitted(home, monkeypatch):
    """history honors XDR_SESSION env var when --session flag is omitted."""
    from xdr_cli.sessions import Session, set_current_session, write_session_start_record

    s = Session(id="jd-1", upn="j@c", label="probe", learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    # Seed a record so history has data to display.
    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "hunt run",
        },
    ]
    _seed_jsonl(home, "jd-1", records)

    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # Verify the session was resolved and data was returned.
    parsed = json.loads(result.stdout)
    assert len(parsed["data"]) == 1
    assert parsed["data"][0]["session_id"] == "jd-1"


def test_history_uses_marker_when_no_env_var(home, monkeypatch):
    """history honors implicit single-marker resolution when XDR_SESSION unset."""
    from xdr_cli.sessions import Session, set_current_session, write_session_start_record

    monkeypatch.delenv("XDR_SESSION", raising=False)
    s = Session(id="jd-1", upn="j@c", label="probe", learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)

    # Seed a record so history has data to display.
    records = [
        {
            "kind": "session_started",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:00:00Z",
            "session_id": "jd-1",
            "upn": "j@c",
        },
        {
            "kind": "invocation",
            "schema_version": 1,
            "timestamp": "2026-04-24T00:01:00Z",
            "session_id": "jd-1",
            "seq": 1,
            "command": "hunt run",
        },
    ]
    _seed_jsonl(home, "jd-1", records)

    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # Verify the single marker was resolved and data was returned.
    parsed = json.loads(result.stdout)
    assert len(parsed["data"]) == 1
    assert parsed["data"][0]["session_id"] == "jd-1"
