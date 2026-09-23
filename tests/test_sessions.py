"""Tests for session ID generation, counter locking, and current-session helpers."""

import json
import multiprocessing as mp
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from xdr_cli.sessions import (
    Session,
    _initials_from_upn,
    _next_counter,
    current_session,
    set_current_session,
    clear_current_session,
)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli" / "sessions").mkdir(parents=True, mode=0o700)
    return tmp_path / ".xdr-cli"




def _counter_worker(home_path: str, initials: str, q: mp.Queue) -> None:
    """Subprocess entrypoint: increment the counter once and report the value.

    Runs in a fresh interpreter so the file lock is exercised inter-process,
    not intra-process. `home` env must be propagated explicitly because pytest
    monkeypatch only affects the parent process.
    """
    os.environ["XDR_CLI_HOME"] = home_path
    from xdr_cli.sessions import _next_counter as _nc

    q.put(_nc(initials))


def _session_end_worker(home_path: str, session_id: str, upn_value: str, q: mp.Queue) -> None:
    """Subprocess entrypoint: call write_session_end_record once and report
    whether this process appended the marker (final_seq:int) or saw the
    session already ended (None).

    Runs in a fresh interpreter so the JSONL lock is exercised inter-process.
    """
    os.environ["XDR_CLI_HOME"] = home_path
    from xdr_cli.sessions import Session as _Session
    from xdr_cli.sessions import write_session_end_record as _wser

    s = _Session(id=session_id, upn=upn_value, label=None, learning_mode=False)
    q.put(_wser(s))


def test_initials_firstname_lastname():
    assert _initials_from_upn("jane.doe@corp.com") == "jd"


def test_initials_single_part_fallback():
    # Admin-style accounts have no '.' — take first 3 chars of local part.
    assert _initials_from_upn("admin@corp.com") == "adm"


def test_initials_three_parts_uses_first_last():
    assert _initials_from_upn("mary.jane.watson@corp.com") == "mw"


def test_initials_strips_non_alpha():
    # Some tenants have service accounts with digits/hyphens.
    assert _initials_from_upn("svc-01@corp.com") == "svc"


def test_next_counter_starts_at_1(home):
    assert _next_counter("jd") == 1


def test_next_counter_increments(home):
    _next_counter("jd")
    _next_counter("jd")
    assert _next_counter("jd") == 3


def test_next_counter_per_operator(home):
    _next_counter("jd")
    _next_counter("jd")
    # Different operator gets their own counter starting at 1.
    assert _next_counter("bs") == 1


def test_next_counter_concurrent_access(home):
    # Race: 20 PROCESSES incrementing simultaneously must all get unique IDs.
    # Threads share fds and would not exercise inter-process file locking;
    # multiprocessing forces real lock contention.
    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    procs = [ctx.Process(target=_counter_worker, args=(str(home), "jd", q)) for _ in range(20)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10)
        assert p.exitcode == 0

    seen = sorted(q.get_nowait() for _ in range(20))
    assert seen == list(range(1, 21))  # all unique, 1..20


def test_current_session_roundtrip(home):
    s = Session(id="jd-1", upn="jane.doe@corp.com", label=None, learning_mode=False)
    set_current_session(s)
    assert current_session() == s


def test_current_session_missing_is_none(home):
    assert current_session() is None


def test_clear_current_session(home):
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    clear_current_session(s.id)
    assert current_session() is None


def test_find_active_sessions_returns_marker_owners(home):
    from xdr_cli.sessions import find_active_sessions, set_current_session, Session
    set_current_session(Session(id="jd-1", upn="j@c", label="A", learning_mode=False))
    set_current_session(Session(id="jd-2", upn="j@c", label="B", learning_mode=True))
    actives = find_active_sessions()
    ids = sorted(s.id for s in actives)
    assert ids == ["jd-1", "jd-2"]


def test_current_session_returns_none_when_multiple_active(home):
    from xdr_cli.sessions import current_session, find_active_sessions, set_current_session, Session
    set_current_session(Session(id="jd-1", upn="j@c", label=None, learning_mode=False))
    set_current_session(Session(id="jd-2", upn="j@c", label=None, learning_mode=False))
    # current_session() returns None on ambiguity (caller decides how to error)
    assert current_session() is None
    # find_active_sessions() returns both for caller to disambiguate
    assert len(find_active_sessions()) == 2


def test_find_active_sessions_self_heals_ended_marker(home):
    from xdr_cli.sessions import (
        find_active_sessions, set_current_session, Session,
        write_session_start_record, write_session_end_record,
        _active_session_marker,
    )
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    write_session_end_record(s)
    # Marker still present on disk before the call.
    assert _active_session_marker("jd-1").exists()
    actives = find_active_sessions()
    assert actives == []
    # Self-heal removed the stale marker.
    assert not _active_session_marker("jd-1").exists()


def test_env_override_wins_over_file(home, monkeypatch):
    # Seed a real JSONL for jd-99 so hydration has something to read.
    sess_dir = home / "sessions"
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": "jd-99",
        "upn": "real-other@corp.com",
        "label": "from-env",
        "learning_mode": True,
    }
    (sess_dir / "jd-99.jsonl").write_text(json.dumps(started) + "\n")

    set_current_session(Session(id="jd-1", upn="j@c", label=None, learning_mode=False))
    monkeypatch.setenv("XDR_SESSION", "jd-99")

    s = current_session()
    # Full hydration from JSONL header — not just .id.
    assert s is not None
    assert s.id == "jd-99"
    assert s.upn == "real-other@corp.com"
    assert s.label == "from-env"
    assert s.learning_mode is True


def test_env_override_with_no_jsonl_is_invalid(home, monkeypatch):
    monkeypatch.setenv("XDR_SESSION", "adhoc-1")
    assert current_session() is None


def test_env_override_cannot_reopen_ended_session(home, monkeypatch):
    from xdr_cli.sessions import write_session_end_record, write_session_start_record

    session = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(session)
    write_session_start_record(session)
    write_session_end_record(session)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    assert current_session() is None


def test_find_active_sessions_ignores_orphan_temp_and_corrupt_marker(home):
    from xdr_cli.sessions import find_active_sessions

    active = home / "active_sessions"
    active.mkdir(parents=True)
    (active / ".jd-1.999.deadbeef.tmp").write_text("partial")
    (active / "jd-1").write_text(
        json.dumps({"id": "jd-1", "timeout_seconds": "not-an-integer"})
    )
    assert find_active_sessions() == []


def test_touch_and_anchor_updates_do_not_lose_marker_fields(home):
    from xdr_cli.sessions import (
        set_session_anchor_incident,
        touch_session,
        write_session_start_record,
    )

    session = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(session)
    write_session_start_record(session)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for _ in range(50):
            futures.append(pool.submit(touch_session, session))
            futures.append(pool.submit(set_session_anchor_incident, "jd-1", 321))
        for future in futures:
            future.result()

    resolved = current_session()
    assert resolved is not None
    assert resolved.anchor_incident == 321


def test_marker_replace_retries_transient_windows_sharing_violation(
    home, monkeypatch
):
    """A short-lived Windows sharing handle must not orphan marker state."""

    import xdr_cli.sessions as sessions_module

    real_replace = sessions_module.os.replace
    calls = 0

    def flaky_replace(source, destination):
        nonlocal calls
        calls += 1
        if calls < 3:
            raise PermissionError("simulated transient sharing violation")
        return real_replace(source, destination)

    monkeypatch.setattr(
        sessions_module, "_MARKER_REPLACE_RETRY_DELAYS", (0.0, 0.0)
    )
    monkeypatch.setattr(sessions_module.os, "replace", flaky_replace)

    session = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(session)

    assert calls == 3
    assert current_session() == session
    assert not list((home / "active_sessions").glob("*.tmp"))


def test_marker_replace_surfaces_persistent_permission_error_and_cleans_temp(
    home, monkeypatch
):
    """Bounded retries must not hide a real access-control failure."""

    import xdr_cli.sessions as sessions_module

    calls = 0

    def denied_replace(source, destination):
        nonlocal calls
        calls += 1
        raise PermissionError("simulated persistent access failure")

    monkeypatch.setattr(
        sessions_module, "_MARKER_REPLACE_RETRY_DELAYS", (0.0, 0.0)
    )
    monkeypatch.setattr(sessions_module.os, "replace", denied_replace)

    session = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    with pytest.raises(PermissionError, match="persistent access failure"):
        set_current_session(session)

    assert calls == 3
    assert not (home / "active_sessions" / "jd-1").exists()
    assert not list((home / "active_sessions").glob("*.tmp"))


def test_resolve_operator_upn_returns_account(home, monkeypatch):
    """resolve_operator_upn pulls `account` from AuthManager.get_auth_status()."""

    class _FakeAuth:
        def __init__(self, _config):
            pass

        def get_auth_status(self):
            return {"authenticated": True, "account": "jane.doe@corp.com"}

    monkeypatch.setattr("xdr_cli.auth.AuthManager", _FakeAuth)
    from xdr_cli.sessions import resolve_operator_upn

    assert resolve_operator_upn() == "jane.doe@corp.com"


def test_resolve_operator_upn_returns_none_when_unauthenticated(home, monkeypatch):
    class _FakeAuth:
        def __init__(self, _config):
            pass

        def get_auth_status(self):
            return {"authenticated": False, "account": None}

    monkeypatch.setattr("xdr_cli.auth.AuthManager", _FakeAuth)
    from xdr_cli.sessions import resolve_operator_upn

    assert resolve_operator_upn() is None


def test_resolve_operator_upn_returns_none_on_exception(home, monkeypatch):
    """Auth subsystem errors must not crash session id resolution."""

    class _BoomAuth:
        def __init__(self, _config):
            raise RuntimeError("boom")

    monkeypatch.setattr("xdr_cli.auth.AuthManager", _BoomAuth)
    from xdr_cli.sessions import resolve_operator_upn

    assert resolve_operator_upn() is None


def test_initials_collision_known_limitation(home):
    # john.doe and jane.doe both → "jd". Counter is shared. Documented limitation.
    assert _initials_from_upn("john.doe@corp.com") == "jd"
    assert _initials_from_upn("jane.doe@corp.com") == "jd"
    # Both contribute to the same .counter-jd file.
    _next_counter("jd")  # 1
    _next_counter("jd")  # 2
    assert _next_counter("jd") == 3


def test_session_end_concurrent_race_only_writes_one_marker(home):
    """N processes calling write_session_end_record simultaneously must
    serialize through the JSONL lock — exactly ONE session_ended marker
    must land on disk, the other N-1 callers must observe ``None``.

    Mirrors test_next_counter_concurrent_access: spawn-context multiprocessing
    so the file lock is exercised inter-process, not intra-process.
    """
    # Seed the JSONL with a session_started header so write_session_end_record
    # is operating on a real session file (its lock contract assumes the file
    # exists or is creatable).
    sess_dir = home / "sessions"
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": "jd-1",
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": False,
    }
    (sess_dir / "jd-1.jsonl").write_text(json.dumps(started) + "\n")

    n = 10
    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    procs = [
        ctx.Process(
            target=_session_end_worker,
            args=(str(home), "jd-1", "jane.doe@corp.com", q),
        )
        for _ in range(n)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=10)
        assert p.exitcode == 0

    results = [q.get_nowait() for _ in range(n)]
    # Exactly one process won the lock-acquisition order and got an int back;
    # the rest must have observed the marker already in place and returned None.
    winners = [r for r in results if r is not None]
    losers = [r for r in results if r is None]
    assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)}: {results}"
    assert len(losers) == n - 1, f"expected {n - 1} losers, got {len(losers)}: {results}"

    # JSONL on disk must contain exactly ONE session_ended record.
    lines = (sess_dir / "jd-1.jsonl").read_text().splitlines()
    end_records = [
        line for line in lines if line.strip() and json.loads(line).get("kind") == "session_ended"
    ]
    assert len(end_records) == 1, f"expected exactly 1 session_ended, got {len(end_records)}"


# ---------------------------------------------------------------------------
# Recorder tests (Task 3)
# ---------------------------------------------------------------------------


def test_recorder_writes_base_record(home, monkeypatch):
    from xdr_cli.sessions import Recorder, Session, set_current_session, write_session_start_record

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)

    rec = Recorder(
        session=s,
        argv=["hunt", "run", "CloudAppEvents | take 1"],
        invoked_command="hunt run",  # supplied by main.py from ctx.info_name chain
    )
    rec.flush(exit_code=0, duration_ms=123)

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    # session_started header + one invocation record.
    assert len(records) == 2
    started = json.loads(records[0])
    assert started["kind"] == "session_started"
    assert started["schema_version"] == 1

    entry = json.loads(records[1])
    assert entry["kind"] == "invocation"
    assert entry["schema_version"] == 1
    assert entry["command"] == "hunt run"
    assert entry["args"] == ["hunt", "run", "CloudAppEvents | take 1"]
    assert entry["exit_code"] == 0
    assert entry["duration_ms"] == 123
    assert entry["seq"] == 1


def test_recorder_writes_synthetic_session_started_for_env_override(home, monkeypatch):
    """XDR_SESSION pointing at a fresh adhoc id with no prior file: first
    Recorder.flush writes a synthetic session_started so the JSONL is well-
    formed for downstream load_session_metadata / list_sessions."""
    from xdr_cli.sessions import Recorder, Session

    monkeypatch.setenv("XDR_SESSION", "adhoc-1")
    s = Session(id="adhoc-1", upn="", label="env-override", learning_mode=False)

    rec = Recorder(session=s, argv=["hunt", "run", "kql"], invoked_command="hunt run")
    rec.flush(exit_code=0, duration_ms=10)

    records = (home / "sessions" / "adhoc-1.jsonl").read_text().splitlines()
    assert len(records) == 2
    started = json.loads(records[0])
    assert started["kind"] == "session_started"
    assert started["label"] == "env-override"
    assert started["learning_mode"] is False


def test_recorder_annotate_merges_fields(home, monkeypatch):
    from xdr_cli.sessions import Recorder, Session, set_current_session, write_session_start_record

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)

    rec = Recorder(session=s, argv=["hunt", "run", "kql"])
    rec.annotate("kql", "CloudAppEvents | take 1")
    rec.annotate("tables_referenced", ["CloudAppEvents"])
    rec.flush(exit_code=0, duration_ms=100)

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    entry = json.loads(records[1])
    assert entry["kql"] == "CloudAppEvents | take 1"
    assert entry["tables_referenced"] == ["CloudAppEvents"]


@pytest.mark.skipif(sys.platform == "win32", reason="Unix file permissions not enforced on Windows")
def test_recorder_fail_soft_on_write_error(home, monkeypatch, capsys):
    # Simulate a filesystem failure. Command must still succeed.
    from xdr_cli.sessions import Recorder, Session, set_current_session, write_session_start_record

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setattr(
        Recorder,
        "_do_flush",
        lambda self, *, exit_code, duration_ms: (_ for _ in ()).throw(
            OSError("simulated write failure")
        ),
    )
    rec = Recorder(session=s, argv=["hunt", "run"])
    rec.flush(exit_code=0, duration_ms=10)  # must not raise
    err = capsys.readouterr().err
    assert "session record write failed" in err


def test_recorder_no_active_session_is_noop(home):
    from xdr_cli.sessions import Recorder

    rec = Recorder(session=None, argv=["hunt", "run"])
    rec.flush(exit_code=0, duration_ms=10)  # no file written, no crash
    assert not list((home / "sessions").glob("*.jsonl"))


def test_seq_increments_across_recorders(home):
    from xdr_cli.sessions import Recorder, Session, set_current_session, write_session_start_record

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)

    Recorder(session=s, argv=["alerts", "list"]).flush(0, 1)
    Recorder(session=s, argv=["hunt", "run"]).flush(0, 1)
    Recorder(session=s, argv=["hunt", "library"]).flush(0, 1)

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    seqs = [json.loads(r)["seq"] for r in records if json.loads(r)["kind"] == "invocation"]
    assert seqs == [1, 2, 3]


def _recorder_worker(home_path: str, session_id: str, idx: int) -> None:
    """Subprocess entrypoint: build a Recorder and flush one invocation."""
    import os as _os

    _os.environ["XDR_CLI_HOME"] = home_path
    from xdr_cli.sessions import Recorder, Session

    s = Session(id=session_id, upn="j@c", label=None, learning_mode=False)
    Recorder(session=s, argv=["hunt", "run", f"q{idx}"]).flush(0, 1)


def test_concurrent_recorders_produce_unique_seqs(home):
    """Intra-session parallelism: 20 PROCESSES sharing one session must each
    produce a unique seq with no duplicates or gaps. Threads are not enough —
    inter-process file locks are what we're verifying.
    """
    from xdr_cli.sessions import Session, set_current_session

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    # Pre-create the JSONL with a session_started header so workers don't race
    # on its creation. (In real use, xdr session start does this once.)
    from xdr_cli.sessions import write_session_start_record

    write_session_start_record(s)

    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_recorder_worker, args=(str(home), "jd-1", i)) for i in range(20)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=15)
        assert p.exitcode == 0

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    seqs = sorted(json.loads(r)["seq"] for r in records if json.loads(r)["kind"] == "invocation")
    assert seqs == list(range(1, 21))


def test_recorder_captures_xdr_actor_env(home, monkeypatch):
    from xdr_cli.sessions import Recorder, Session, set_current_session, write_session_start_record

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setenv("XDR_ACTOR", "subagent-path1")

    rec = Recorder(session=s, argv=["hunt", "run"], invoked_command="hunt run")
    rec.flush(0, 10)

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    entry = json.loads(records[1])
    assert entry["actor"] == "subagent-path1"


def test_recorder_actor_defaults_to_operator(home):
    from xdr_cli.sessions import Recorder, Session, set_current_session, write_session_start_record

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)

    rec = Recorder(session=s, argv=["hunt", "run"], invoked_command="hunt run")
    rec.flush(0, 10)

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    entry = json.loads(records[1])
    assert entry["actor"] == "operator"


def test_recorder_timestamp_has_no_fractional_seconds(home):
    """Lock the ISO-8601-Z-no-fractional invariant relied on by history_cmd.

    history_cmd._iter_filtered_records uses lexicographic comparison on
    timestamp strings for the --since filter; this assumes a fixed format
    (``%Y-%m-%dT%H:%M:%SZ`` — fixed width, Z suffix, no ``%f``). A future
    Recorder change to a fractional-seconds format would silently break
    the filter for windows straddling the change. This test fails loudly
    if that happens.
    """
    import re

    from xdr_cli.sessions import (
        Recorder,
        Session,
        set_current_session,
        write_session_start_record,
    )

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)

    rec = Recorder(session=s, argv=["hunt", "run"], invoked_command="hunt run")
    rec.flush(exit_code=0, duration_ms=10)

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    # session_started + invocation
    started = json.loads(records[0])
    invocation = json.loads(records[1])
    pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    assert pattern.match(started["timestamp"]), (
        f"session_started timestamp {started['timestamp']!r} violates the "
        "ISO-8601-Z-no-fractional invariant relied on by --since filter"
    )
    assert pattern.match(invocation["timestamp"]), (
        f"invocation timestamp {invocation['timestamp']!r} violates the "
        "ISO-8601-Z-no-fractional invariant relied on by --since filter"
    )


# ---------------------------------------------------------------------------
# capture_sample tests (Task 4)
# ---------------------------------------------------------------------------


def test_capture_sample_takes_first_n():
    from xdr_cli._recording import capture_sample

    rows = [{"i": i} for i in range(10)]
    out = capture_sample(rows, limit=3)
    assert out == [{"i": 0}, {"i": 1}, {"i": 2}]


def test_capture_sample_empty_returns_empty():
    from xdr_cli._recording import capture_sample

    assert capture_sample([], limit=3) == []


def test_capture_sample_truncates_oversized_row():
    from xdr_cli._recording import capture_sample

    big = {"payload": "x" * 5000}  # JSON-encoded > 4096 cap
    out = capture_sample([big], limit=3, byte_cap=4096)
    assert len(out) == 1
    marker = out[0]
    assert marker["_truncated"] is True
    assert isinstance(marker["_original_size_bytes"], int)
    assert marker["_original_size_bytes"] > 4096


def test_capture_sample_preserves_under_cap_row_value():
    from xdr_cli._recording import capture_sample

    row = {"a": 1, "b": "small", "c": [1, 2, 3]}
    out = capture_sample([row], limit=3, byte_cap=4096)
    # Value-equal: under-cap rows are now round-tripped through json so
    # non-natively-serializable values (datetime, etc.) bake into str()
    # form before flush. Pure-JSON inputs survive that round-trip identically.
    assert out == [row]


def test_capture_sample_handles_unserializable_types():
    """A row with a datetime survives capture and is JSONL-flush-safe."""
    from datetime import datetime

    from xdr_cli._recording import capture_sample

    rows = [{"Timestamp": datetime(2026, 4, 24, 19, 30, 0), "ActionType": "X"}]
    out = capture_sample(rows)
    # Row is round-tripped through json.dumps(default=str) so all values
    # are now JSON-natively-serializable (datetime → str() form).
    assert out[0]["Timestamp"] == str(datetime(2026, 4, 24, 19, 30, 0))
    assert out[0]["ActionType"] == "X"
    # The crucial check: the result is itself JSON-serializable with no
    # default= fallback, so Recorder.flush cannot fail on this row.
    json.dumps(out)  # must not raise


# ---------------------------------------------------------------------------
# actor_needs_annotation + write_annotation (Task 8)
# ---------------------------------------------------------------------------


def _seed_jsonl(home_dir, session_id, lines):
    path = home_dir / "sessions" / f"{session_id}.jsonl"
    path.write_text("".join(json.dumps(rec) + "\n" for rec in lines))


def test_actor_needs_annotation_returns_none_for_unknown_actor(home):
    from xdr_cli.sessions import Session, actor_needs_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    assert actor_needs_annotation(s, "operator") is None


def test_actor_needs_annotation_returns_seq_when_unannotated(home):
    from xdr_cli.sessions import Session, actor_needs_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
        {"kind": "invocation", "schema_version": 1, "session_id": "jd-1",
         "actor": "operator", "seq": 1, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    assert actor_needs_annotation(s, "operator") == 1


def test_actor_needs_annotation_returns_none_after_annotation(home):
    from xdr_cli.sessions import Session, actor_needs_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
        {"kind": "invocation", "schema_version": 1, "session_id": "jd-1",
         "actor": "operator", "seq": 1, "timestamp": "t"},
        {"kind": "annotation", "schema_version": 1, "session_id": "jd-1",
         "actor": "operator", "refers_to": 1, "text": "x",
         "skipped": False, "skip_reason": None, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    assert actor_needs_annotation(s, "operator") is None


def test_actor_needs_annotation_cross_actor_clears_gate(home):
    """Annotation actor doesn't have to match invocation actor — refers_to wins."""
    from xdr_cli.sessions import Session, actor_needs_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
        {"kind": "invocation", "schema_version": 1, "session_id": "jd-1",
         "actor": "path1", "seq": 1, "timestamp": "t"},
        {"kind": "annotation", "schema_version": 1, "session_id": "jd-1",
         "actor": "orchestrator", "refers_to": 1, "text": "meta",
         "skipped": False, "skip_reason": None, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    # path1's seq=1 was annotated by orchestrator → path1 is not gated.
    assert actor_needs_annotation(s, "path1") is None


def test_actor_needs_annotation_per_actor_isolation(home):
    from xdr_cli.sessions import Session, actor_needs_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
        {"kind": "invocation", "schema_version": 1, "session_id": "jd-1",
         "actor": "A", "seq": 1, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    assert actor_needs_annotation(s, "A") == 1
    # B has no invocation → not gated.
    assert actor_needs_annotation(s, "B") is None


def test_write_annotation_appends_record_with_no_seq(home):
    from xdr_cli.sessions import Session, write_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
        {"kind": "invocation", "schema_version": 1, "session_id": "jd-1",
         "actor": "operator", "seq": 1, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    seq = write_annotation(s, actor="operator", text="note", skip_reason=None, refers_to=None)
    assert seq == 1

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    annotations = [
        json.loads(r) for r in records if json.loads(r)["kind"] == "annotation"
    ]
    assert len(annotations) == 1
    a = annotations[0]
    assert "seq" not in a
    assert a["refers_to"] == 1
    assert a["text"] == "note"
    assert a["skipped"] is False


def test_write_annotation_raises_when_no_invocation_to_annotate(home):
    from xdr_cli.exceptions import QueryError
    from xdr_cli.sessions import Session, write_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    with pytest.raises(QueryError):
        write_annotation(s, actor="operator", text="x", skip_reason=None, refers_to=None)


def test_write_annotation_validates_refers_to(home):
    from xdr_cli.exceptions import QueryError
    from xdr_cli.sessions import Session, write_annotation

    _seed_jsonl(home, "jd-1", [
        {"kind": "session_started", "schema_version": 1, "session_id": "jd-1",
         "upn": "j@c", "label": None, "learning_mode": True, "timestamp": "t"},
        {"kind": "invocation", "schema_version": 1, "session_id": "jd-1",
         "actor": "operator", "seq": 1, "timestamp": "t"},
    ])
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    with pytest.raises(QueryError):
        write_annotation(s, actor="operator", text="x", skip_reason=None, refers_to=99)


# ---------------------------------------------------------------------------
# Task 2 (R1) — Session end actually ends recording
# ---------------------------------------------------------------------------


def test_recorder_refuses_to_write_to_ended_session(home, capsys):
    from xdr_cli.sessions import (
        Recorder, Session, set_current_session,
        write_session_start_record, write_session_end_record,
        load_session_records, _active_session_marker,
    )
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    write_session_end_record(s)

    # Even though something still points at it, the recorder must refuse.
    rec = Recorder(
        session=s,
        argv=["hunt", "run", "DeviceProcessEvents | take 1"],
        invoked_command="hunt run",
    )
    rec.annotate("kql", "DeviceProcessEvents | take 1")
    rec.flush(exit_code=0, duration_ms=12)

    # JSONL must contain only session_started + session_ended — no invocation.
    lines = load_session_records("jd-1") or []
    kinds = [json.loads(line)["kind"] for line in lines]
    assert kinds == ["session_started", "session_summary", "session_ended"]
    captured = capsys.readouterr()
    assert "ended" in captured.err.lower()
    # Self-heal: marker file unlinked.
    assert not _active_session_marker("jd-1").exists()


def test_refused_flush_does_not_bump_seq_counter(home):
    """seq counter must not advance when the JSONL is sealed (session_ended).

    Invariant: .seq-<id> equals the count of kind:invocation lines.
    """
    from xdr_cli.sessions import (
        Recorder, Session, set_current_session,
        write_session_start_record, write_session_end_record,
        _seq_path, _read_int,
    )
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    write_session_end_record(s)

    rec = Recorder(session=s, argv=["hunt", "run", "X"], invoked_command="hunt run")
    rec.annotate("kql", "X")
    rec.flush(exit_code=0, duration_ms=10)

    # Counter must remain at 0 — no invocation was written.
    assert _read_int(_seq_path("jd-1")) == 0


def test_recorder_inherits_anchor_incident_from_session(home):
    from xdr_cli.sessions import (
        Recorder, Session, set_current_session, set_session_anchor_incident,
        write_session_start_record, load_session_records, current_session,
    )
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    set_session_anchor_incident("jd-1", 155278)

    # Re-resolve to pick up the persisted anchor.
    s2 = current_session()
    assert s2 is not None and s2.anchor_incident == 155278

    rec = Recorder(session=s2, argv=["hunt", "run", "X"], invoked_command="hunt run")
    rec.annotate("kql", "X")
    rec.flush(exit_code=0, duration_ms=10)

    lines = load_session_records("jd-1")
    invocations = [json.loads(line) for line in lines if json.loads(line)["kind"] == "invocation"]
    assert invocations[-1]["anchor_incident"] == 155278
