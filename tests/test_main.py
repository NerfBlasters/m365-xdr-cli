"""Tests for the CLI entry point — focus on error-envelope-to-stdout contract."""

import json
import sys
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from xdr_cli.exceptions import APIError, AuthError
from xdr_cli.main import app, run

runner = CliRunner()


def test_xdr_error_envelope_goes_to_stdout(capsys, tmp_path, monkeypatch):
    """On XDRError, JSON envelope goes to stdout — mirrors success contract.

    The previous behavior wrote error JSON to stderr, which broke consumers
    that captured stdout to a file (empty file on error) or that used
    `2>&1` merge (error JSON tangled with progress lines).
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))

    err = APIError("test API failure", status_code=400)
    with patch("xdr_cli.main.app", side_effect=err), pytest.raises(SystemExit) as exc_info:
        run()

    assert exc_info.value.code == err.exit_code  # 3

    captured = capsys.readouterr()
    assert captured.err == "", "stderr must be empty on error path"
    envelope = json.loads(captured.out)
    assert envelope["status"] == "error"
    assert envelope["error"]["type"] == "APIError"


def test_auth_error_envelope_also_goes_to_stdout(capsys, tmp_path, monkeypatch):
    """Same contract for AuthError (exit code 2) — stdout only."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))

    err = AuthError("not authenticated")
    with patch("xdr_cli.main.app", side_effect=err), pytest.raises(SystemExit) as exc_info:
        run()

    assert exc_info.value.code == 2

    captured = capsys.readouterr()
    assert captured.err == ""
    envelope = json.loads(captured.out)
    assert envelope["status"] == "error"
    assert envelope["error"]["type"] == "AuthError"


# ---------------------------------------------------------------------------
# Recorder wiring (Task 3)
# ---------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirect XDR_CLI_HOME and seed an active session via XDR_SESSION env."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli" / "sessions").mkdir(parents=True, mode=0o700)
    return tmp_path / ".xdr-cli"


def _seed_session(home_dir, session_id="jd-1"):
    """Write a session_started header to home_dir/sessions/<session_id>.jsonl."""
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": session_id,
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": False,
    }
    (home_dir / "sessions" / f"{session_id}.jsonl").write_text(json.dumps(started) + "\n")


def test_active_session_invocation_records(home, monkeypatch, capsys):
    """A simple command run with an active session writes one invocation
    record to the session JSONL."""
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(sys, "argv", ["xdr", "session", "list"])

    # session list is browse-only; runs without network.
    with pytest.raises(SystemExit) as exc_info:
        run()
    # session list exits 0 normally.
    assert exc_info.value.code in (0, None)

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r)["kind"] == "invocation"]
    assert len(invocations) == 1
    assert invocations[0]["exit_code"] == 0
    assert invocations[0]["command"] == "session list"
    assert invocations[0]["args"] == ["session", "list"]
    # First invocation in a fresh session always gets seq=1. Recorder.flush's
    # seq monotonicity is unit-tested in test_sessions.py; this asserts the
    # *wired* path produces a correctly-numbered seq end-to-end.
    assert invocations[0]["seq"] == 1


def test_keyboard_interrupt_records_exit_130(home, monkeypatch):
    """Ctrl-C mid-command must still produce a record with exit_code=130."""
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(sys, "argv", ["xdr", "session", "list"])

    def _boom(*a, **kw):
        raise KeyboardInterrupt()

    with patch("xdr_cli.commands.session_cmd.list_sessions", side_effect=_boom):
        # KeyboardInterrupt is converted to sys.exit(130) by run().
        with pytest.raises(SystemExit) as exc_info:
            run()
        assert exc_info.value.code == 130

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r)["kind"] == "invocation"]
    assert len(invocations) == 1
    assert invocations[0]["exit_code"] == 130


def test_uncaught_runtime_error_is_structured_and_recorded(home, monkeypatch, capsys):
    """Unexpected errors become one-line internal failures and are recorded."""
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(sys, "argv", ["xdr", "session", "list"])

    def _boom(*a, **kw):
        raise RuntimeError("unexpected")

    with (
        patch("xdr_cli.commands.session_cmd.list_sessions", side_effect=_boom),
        pytest.raises(SystemExit) as raised,
    ):
        run()
    assert raised.value.code == 1
    error = json.loads(capsys.readouterr().out)
    assert error["error"]["code"] == "INTERNAL_ERROR"
    assert error["error"]["original"]["type"] == "RuntimeError"

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r)["kind"] == "invocation"]
    assert len(invocations) == 1
    assert invocations[0]["exit_code"] == 1


def test_metadata_session_id_in_envelope(home, monkeypatch, capsys):
    """Active session: metadata.session_id is populated in stdout JSON."""
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(sys, "argv", ["xdr", "session", "list"])
    with pytest.raises(SystemExit):
        run()

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["metadata"]["session_id"] == "jd-1"


def test_metadata_session_id_null_outside_session(home, monkeypatch, capsys):
    """No active session: metadata.session_id is None."""
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.setattr(sys, "argv", ["xdr", "session", "list"])
    with pytest.raises(SystemExit):
        run()

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["metadata"]["session_id"] is None
    assert parsed["metadata"]["session_label"] is None


def test_chain_capture_smoke(home, monkeypatch, capsys):
    """Canary: leaf-callback wrapping captures the full subcommand chain on
    every command path. Three distinct chains is enough to verify the registry
    walk in ``_install_leaf_hook`` reaches every leaf — if a future Typer
    minor-version bump silently changes the registry shape, this test is the
    first thing to fail.

    Runs three browse-only commands and asserts each landed in the JSONL with
    the right ``command`` field. Read paths are mocked to keep the test
    network-free and deterministic.
    """
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    # Mock list_alerts as an async generator that yields nothing — keeps the
    # alerts-list code path out of the network. Note: the command imports
    # list_alerts at module import time, so we patch the *bound name* in
    # alerts_cmd, not the api module.
    async def _empty_async_gen(*args, **kwargs):
        if False:
            yield  # pragma: no cover  (makes this an async generator)

    expected_chains = [
        (["xdr", "alerts", "list"], "alerts list"),
        (["xdr", "session", "list"], "session list"),
        (["xdr", "hunt", "library"], "hunt library"),
    ]

    with patch("xdr_cli.commands.alerts_cmd.list_alerts", _empty_async_gen):
        for argv, _expected_chain in expected_chains:
            monkeypatch.setattr(sys, "argv", argv)
            with pytest.raises(SystemExit):
                run()

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"]
    captured_chains = [inv["command"] for inv in invocations]
    expected_chains_only = [chain for _, chain in expected_chains]
    assert captured_chains == expected_chains_only, (
        f"chain capture broke — got {captured_chains}, want {expected_chains_only}"
    )


# ---------------------------------------------------------------------------
# --rationale global flag (Task 7)
# ---------------------------------------------------------------------------


def test_rationale_lands_in_record(home, monkeypatch):
    """`xdr --rationale "testing X" hunt run "..."` records rationale on the
    invocation record under the active session.

    Uses ``hunt run`` because rationale only attaches to hunt-shaped commands
    (positive-list of recordable invocations); patches ``run_query`` to keep
    the test network-free.
    """
    from unittest.mock import AsyncMock

    from xdr_cli.api.hunting import HuntingResult

    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["xdr", "--rationale", "testing X", "hunt", "run", "DeviceEvents | take 1"],
    )

    fake = HuntingResult(
        schema=[{"name": "Timestamp", "type": "DateTime"}],
        results=[{"Timestamp": "2026-04-22T00:00:00Z"}],
        stats={"ExecutionTime": 0.1},
    )

    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
        pytest.raises(SystemExit),
    ):
        run()

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"]
    assert len(invocations) == 1
    assert invocations[0]["rationale"] == "testing X"
    assert invocations[0]["command"] == "hunt run"


def test_rationale_null_when_flag_absent(home, monkeypatch):
    """`xdr hunt run "..."` (no --rationale) produces an invocation record
    with rationale: null. Asserts the default-skeleton path is unchanged."""
    from unittest.mock import AsyncMock

    from xdr_cli.api.hunting import HuntingResult

    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["xdr", "hunt", "run", "DeviceEvents | take 1"],
    )

    fake = HuntingResult(
        schema=[{"name": "Timestamp", "type": "DateTime"}],
        results=[{"Timestamp": "2026-04-22T00:00:00Z"}],
        stats={"ExecutionTime": 0.1},
    )

    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
        pytest.raises(SystemExit),
    ):
        run()

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"]
    assert len(invocations) == 1
    assert invocations[0]["rationale"] is None


def test_rationale_whitespace_only_treated_as_absent(home, monkeypatch):
    """Whitespace-only --rationale should not land as a literal string in
    the record — strip + coalesce so accidental whitespace doesn't poison
    training data."""
    from unittest.mock import AsyncMock

    from xdr_cli.api.hunting import HuntingResult

    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["xdr", "--rationale", "   ", "hunt", "run", "DeviceEvents | take 1"],
    )

    fake = HuntingResult(
        schema=[{"name": "Timestamp", "type": "DateTime"}],
        results=[{"Timestamp": "2026-04-22T00:00:00Z"}],
        stats={"ExecutionTime": 0.1},
    )

    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
        pytest.raises(SystemExit),
    ):
        run()

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"]
    assert len(invocations) == 1
    assert invocations[0]["rationale"] is None


def test_rationale_silently_dropped_on_non_invocation(tmp_path, monkeypatch):
    """--rationale is accepted on every command for CLI-surface uniformity but
    only attaches to records of kind 'invocation'. On non-invocation paths
    (xdr session start, xdr session list, xdr history, xdr annotate) it is
    silently dropped — no record is written, no warning printed.

    This test asserts the silent-drop contract so a future change can't
    accidentally start emitting warnings or partial records.
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli" / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.delenv("XDR_SESSION", raising=False)
    # Stub UPN resolution so session start succeeds without a real MSAL cache.
    monkeypatch.setattr(
        "xdr_cli.commands.session_cmd.resolve_operator_upn",
        lambda: "jane.doe@corp.com",
    )

    # No active session yet. xdr --rationale "X" session start should succeed
    # and create the session WITHOUT writing an invocation record.
    result = runner.invoke(app, ["--rationale", "starting fresh", "session", "start"])
    assert result.exit_code == 0, result.output

    sid = result.output.strip().splitlines()[-1]
    records = (tmp_path / ".xdr-cli" / "sessions" / f"{sid}.jsonl").read_text().splitlines()
    # Only the session_started record — no invocation, no rationale stored.
    assert len(records) == 1
    started = json.loads(records[0])
    assert started["kind"] == "session_started"
    assert "rationale" not in started  # rationale is invocation-only


def test_rationale_recorded_on_browse_command_with_active_session(home, monkeypatch):
    """`xdr --rationale "X" session list` — invocation record is produced
    and rationale is recorded (Task R2: drop the positive-list gate so every
    invocation record captures the operator's rationale)."""
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(sys, "argv", ["xdr", "--rationale", "browsing", "session", "list"])

    with pytest.raises(SystemExit):
        run()

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"]
    assert len(invocations) == 1
    assert invocations[0]["command"] == "session list"
    # Rationale is now recorded on every invocation — no positive-list gate.
    assert invocations[0]["rationale"] == "browsing"


def test_rationale_is_recorded_on_incidents_commands(home, monkeypatch):
    """`xdr --rationale "X" incidents list` records rationale on the
    invocation record. Exercises the Task R2 fix: the positive-list gate
    (_RATIONALE_RECORD_COMMANDS) was silently dropping rationale on incidents
    commands even though they produce invocation records."""
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["xdr", "--rationale", "surveying for triage", "incidents", "list", "--limit", "1"],
    )

    # list_incidents is an async generator — stub with an async generator that
    # yields nothing so we avoid needing a live tenant.
    async def _empty_incidents(*a, **kw):
        return
        yield  # makes this an async generator

    monkeypatch.setattr(
        "xdr_cli.commands.incidents_cmd.list_incidents",
        _empty_incidents,
    )

    with pytest.raises(SystemExit):
        run()

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"]
    assert any(inv.get("rationale") == "surveying for triage" for inv in invocations)


# ---------------------------------------------------------------------------
# Hunt-requires-session gate (Task 8 Step 0)
# ---------------------------------------------------------------------------


@pytest.fixture
def gate_home(tmp_path, monkeypatch):
    """Empty home + clean env — no active session, no XDR_ACTOR leakage."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli" / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return tmp_path / ".xdr-cli"


def test_audit_log_created_mode_0600(tmp_path, monkeypatch):
    """The audit log records the user's command history — it must not be
    world-readable. It should match the 0600 of the cookie/token stores, not
    the FileHandler default of 0644."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    from xdr_cli.main import _setup_audit_log

    logger = _setup_audit_log()
    logger.info("audit entry")

    audit_path = tmp_path / ".xdr-cli" / "audit.log"
    assert audit_path.exists()
    if sys.platform != "win32":
        assert (audit_path.stat().st_mode & 0o777) == 0o600


def test_hunt_run_auto_creates_without_session(gate_home):
    result = runner.invoke(app, ["hunt", "run", "CloudAppEvents | take 1"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" not in combined.lower()
    assert list((gate_home / "sessions").glob("*.jsonl"))


def test_hunt_library_run_auto_creates_without_session(gate_home):
    result = runner.invoke(app, ["hunt", "library-run", "ttp_dns_beaconing"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" not in combined.lower()
    assert list((gate_home / "sessions").glob("*.jsonl"))


def test_investigate_auto_creates_without_session(gate_home):
    result = runner.invoke(app, ["investigate", "12345"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" not in combined.lower()
    assert list((gate_home / "sessions").glob("*.jsonl"))


def test_alerts_list_runs_without_session(gate_home):
    """Browse command — must work without session, no record written."""
    async def _empty_async_gen(*args, **kwargs):
        if False:
            yield  # pragma: no cover

    with patch("xdr_cli.commands.alerts_cmd.list_alerts", _empty_async_gen):
        result = runner.invoke(app, ["alerts", "list"])
    # No gate: exit 0. No JSONL written (no session).
    assert result.exit_code == 0, result.output
    assert not list((gate_home / "sessions").glob("*.jsonl"))


def test_hunt_library_listing_runs_without_session(gate_home):
    """`xdr hunt library` (listing only) — ungated."""
    result = runner.invoke(app, ["hunt", "library"])
    # Listing the empty default library exits 0 (no entries to print).
    assert result.exit_code == 0, result.output


def test_device_isolate_dry_run_works_without_session(gate_home):
    """Write commands record-if-present but don't gate. Dry-run must succeed."""
    result = runner.invoke(
        app,
        ["device", "isolate", "dev-1", "--comment", "test", "--dry-run"],
    )
    # Dry-run prints the plan and exits 0; gate must not block.
    assert result.exit_code == 0, result.output


def test_valid_xdr_session_env_attaches(gate_home, monkeypatch):
    """A valid explicit XDR_SESSION wins during attachment.

    Uses ``run()`` directly so the recorder's finally-flush actually runs
    (``runner.invoke`` invokes the Typer app but doesn't go through ``run()``).
    """
    from unittest.mock import AsyncMock

    from xdr_cli.api.hunting import HuntingResult

    from xdr_cli.sessions import Session, set_current_session, write_session_start_record

    session = Session(id="jd-1", upn="j@c", label="explicit", learning_mode=False)
    set_current_session(session)
    write_session_start_record(session)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    fake = HuntingResult(
        schema=[{"name": "Timestamp", "type": "DateTime"}],
        results=[{"Timestamp": "2026-04-22T00:00:00Z"}],
        stats={"ExecutionTime": 0.1},
    )

    monkeypatch.setattr(sys, "argv", ["xdr", "hunt", "run", "DeviceEvents | take 1"])
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
        pytest.raises(SystemExit),
    ):
        run()
    jsonl = gate_home / "sessions" / "jd-1.jsonl"
    assert jsonl.exists()
    lines = [json.loads(line) for line in jsonl.read_text().splitlines() if line.strip()]
    kinds = [r["kind"] for r in lines]
    assert "session_started" in kinds
    assert "invocation" in kinds


def test_help_bypasses_hunt_gate(gate_home):
    """`xdr hunt run --help` must print help, not the gate error."""
    result = runner.invoke(app, ["hunt", "run", "--help"])
    assert result.exit_code == 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" not in combined.lower()
    assert "Usage:" in combined


def test_short_help_flag_also_bypasses_gate(gate_home):
    """`-h` must behave the same as `--help`."""
    result = runner.invoke(app, ["hunt", "-h"])
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" not in combined.lower()


def test_auto_session_does_not_log_a_rejection(gate_home):
    runner.invoke(app, ["hunt", "run", "CloudAppEvents | take 1"])

    audit_path = gate_home / "audit.log"
    if audit_path.exists():
        assert "REJECTED" not in audit_path.read_text()


# ---------------------------------------------------------------------------
# Learning-mode gate (Task 8 Step 1+2)
# ---------------------------------------------------------------------------


def _seed_learning_session(home_dir, session_id="jd-1"):
    """Seed a session_started record with learning_mode=True."""
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": session_id,
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": True,
    }
    (home_dir / "sessions" / f"{session_id}.jsonl").write_text(
        json.dumps(started) + "\n"
    )


def _seed_invocation(home_dir, session_id="jd-1", actor="operator", seq=1):
    """Append a minimal invocation record so the learning-mode gate sees it.

    Used to short-circuit the "I just ran a command — now my actor is gated"
    setup. ``runner.invoke`` doesn't go through ``run()``'s finally-flush, so
    we can't rely on ``runner.invoke`` to populate an invocation record for
    the gate to find.
    """
    record = {
        "kind": "invocation",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:01:00Z",
        "session_id": session_id,
        "operator_upn": "jane.doe@corp.com",
        "actor": actor,
        "seq": seq,
        "command": "alerts list",
        "args": ["alerts", "list"],
        "exit_code": 0,
        "duration_ms": 1,
    }
    path = home_dir / "sessions" / f"{session_id}.jsonl"
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")
    # Bump the .seq sidecar so subsequent Recorder.flush() in tests gets the
    # right next seq value (not strictly needed for these gate tests).
    seq_path = home_dir / "sessions" / f".seq-{session_id}"
    seq_path.write_text(str(seq))


def test_learning_mode_gate_blocks_next_command(gate_home, monkeypatch):
    """An unannotated invocation in a learning-mode session blocks the next
    non-bypass command for the same actor."""
    _seed_learning_session(gate_home)
    _seed_invocation(gate_home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    second = runner.invoke(app, ["alerts", "list"])
    assert second.exit_code == 13
    combined = (second.output or "") + (second.stderr or "")
    assert "learning mode" in combined.lower()
    assert "annotate" in combined.lower()


def test_learning_mode_gate_allows_annotate(gate_home, monkeypatch):
    """`xdr annotate "..."` clears the gate."""
    async def _empty_async_gen(*args, **kwargs):
        if False:
            yield  # pragma: no cover

    _seed_learning_session(gate_home)
    _seed_invocation(gate_home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    annot = runner.invoke(app, ["annotate", "useful, 3 true positives"])
    assert annot.exit_code == 0, annot.output

    with patch("xdr_cli.commands.alerts_cmd.list_alerts", _empty_async_gen):
        third = runner.invoke(app, ["alerts", "list"])
    assert third.exit_code == 0, third.output


def test_annotate_with_skip(gate_home, monkeypatch):
    """`--skip "reason"` records skipped=True, clears gate."""
    async def _empty_async_gen(*args, **kwargs):
        if False:
            yield  # pragma: no cover

    _seed_learning_session(gate_home)
    _seed_invocation(gate_home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    annot = runner.invoke(app, ["annotate", "--skip", "no useful output"])
    assert annot.exit_code == 0, annot.output

    records = (gate_home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    annotations = [
        json.loads(r) for r in records if json.loads(r).get("kind") == "annotation"
    ]
    assert len(annotations) == 1
    assert annotations[0]["skipped"] is True
    assert annotations[0]["skip_reason"] == "no useful output"
    # Annotations have no seq field.
    assert "seq" not in annotations[0]

    # Gate cleared.
    with patch("xdr_cli.commands.alerts_cmd.list_alerts", _empty_async_gen):
        third = runner.invoke(app, ["alerts", "list"])
    assert third.exit_code == 0, third.output


def test_annotate_outside_learning_mode_still_works(gate_home, monkeypatch):
    """Annotations are allowed any time, not only in learning mode."""
    # Seed a non-learning-mode session with one invocation.
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": "jd-1",
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": False,
    }
    (gate_home / "sessions" / "jd-1.jsonl").write_text(json.dumps(started) + "\n")
    _seed_invocation(gate_home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    annot = runner.invoke(app, ["annotate", "noted"])
    assert annot.exit_code == 0, annot.output
    records = (gate_home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    annotations = [
        json.loads(r) for r in records if json.loads(r).get("kind") == "annotation"
    ]
    assert len(annotations) == 1


def test_learning_mode_does_not_gate_session_history_or_annotate(gate_home, monkeypatch):
    """`xdr session list/show/end`, `xdr history`, `xdr annotate` bypass the gate."""
    _seed_learning_session(gate_home)
    _seed_invocation(gate_home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    # Now there's an unannotated invocation. Bypass paths should still work.
    sl = runner.invoke(app, ["session", "list"])
    assert sl.exit_code == 0, sl.output

    h = runner.invoke(app, ["history"])
    assert h.exit_code == 0, h.output

    # annotate is itself in the bypass set.
    a = runner.invoke(app, ["annotate", "noted"])
    assert a.exit_code == 0, a.output


def test_per_actor_gate_actor_a_blocked_actor_b_free(gate_home, monkeypatch):
    """Actor A's unannotated invocation does NOT block actor B."""
    async def _empty_async_gen(*args, **kwargs):
        if False:
            yield  # pragma: no cover

    _seed_learning_session(gate_home)
    _seed_invocation(gate_home, actor="A", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    # B has no unannotated invocation — gate doesn't fire.
    monkeypatch.setenv("XDR_ACTOR", "B")
    with patch("xdr_cli.commands.alerts_cmd.list_alerts", _empty_async_gen):
        bres = runner.invoke(app, ["alerts", "list"])
    assert bres.exit_code == 0, bres.output

    # A is blocked — has unannotated invocation.
    monkeypatch.setenv("XDR_ACTOR", "A")
    ares = runner.invoke(app, ["alerts", "list"])
    assert ares.exit_code == 13


def test_self_annotate_clears_own_gate(gate_home, monkeypatch):
    """Same actor annotates own invocation → gate cleared."""
    async def _empty_async_gen(*args, **kwargs):
        if False:
            yield  # pragma: no cover

    _seed_learning_session(gate_home)
    _seed_invocation(gate_home, actor="A", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setenv("XDR_ACTOR", "A")

    annot = runner.invoke(app, ["annotate", "A's note"])
    assert annot.exit_code == 0, annot.output

    with patch("xdr_cli.commands.alerts_cmd.list_alerts", _empty_async_gen):
        third = runner.invoke(app, ["alerts", "list"])
    assert third.exit_code == 0, third.output


def test_cross_actor_refers_to_clears_target_gate(gate_home, monkeypatch):
    """Orchestrator annotates path1's seq via --refers-to → path1's gate clears."""
    async def _empty_async_gen(*args, **kwargs):
        if False:
            yield  # pragma: no cover

    _seed_learning_session(gate_home)
    _seed_invocation(gate_home, actor="path1", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    # Orchestrator annotates path1's seq.
    monkeypatch.setenv("XDR_ACTOR", "orchestrator")
    annot = runner.invoke(
        app, ["annotate", "--refers-to", "1", "orchestrator meta-annotation"]
    )
    assert annot.exit_code == 0, annot.output

    monkeypatch.setenv("XDR_ACTOR", "path1")
    with patch("xdr_cli.commands.alerts_cmd.list_alerts", _empty_async_gen):
        third = runner.invoke(app, ["alerts", "list"])
    assert third.exit_code == 0, third.output


# ---------------------------------------------------------------------------
# Concurrent sub-agents — multiprocess gate isolation
# ---------------------------------------------------------------------------


def _actor_workflow_worker(home_path, session_id, actor):
    """Subprocess: simulate run → annotate → run as a specific actor.

    The "gated invocation" steps are simulated by direct Recorder.flush()
    in the worker process (no network) — the per-actor gate is exercised
    via the real ``xdr annotate`` subprocess call between them. This gives
    us true env-var isolation (XDR_ACTOR is process-global) without
    requiring an in-process auth mock.
    """
    import os as _os
    import subprocess as _sp

    # Set os.environ for the in-process Recorder.flush() (which reads
    # XDR_CLI_HOME via get_config_home). pytest's monkeypatch.setenv on the
    # parent doesn't always propagate cleanly to spawn workers under all
    # platforms; setting explicitly here is robust.
    _os.environ["XDR_CLI_HOME"] = home_path
    _os.environ["XDR_SESSION"] = session_id
    _os.environ["XDR_ACTOR"] = actor
    env = {**_os.environ}

    # First "gated" invocation — recorded by this actor.
    from xdr_cli.sessions import Recorder, Session
    s = Session(id=session_id, upn="j@c", label=None, learning_mode=True)
    Recorder(session=s, argv=["alerts", "list"], invoked_command="alerts list").flush(
        exit_code=0, duration_ms=1
    )

    # annotate via subprocess to exercise the gate from a fresh process.
    # Use `python -m xdr_cli` so the test works on local checkouts that
    # haven't `pip install -e .` (no dependence on the `xdr` script being
    # on PATH).
    _sp.check_call(
        [sys.executable, "-m", "xdr_cli", "annotate", f"{actor} note"],
        env=env,
    )

    # Second "gated" invocation — gate should be clear after annotate.
    Recorder(session=s, argv=["alerts", "list"], invoked_command="alerts list").flush(
        exit_code=0, duration_ms=1
    )


def test_concurrent_sub_agents_independent_gates(gate_home):
    """Two PROCESSES, each with its own XDR_ACTOR. Gates do not interfere."""
    import multiprocessing as mp

    _seed_learning_session(gate_home, session_id="jd-1")

    ctx = mp.get_context("spawn")
    p1 = ctx.Process(
        target=_actor_workflow_worker,
        args=(str(gate_home), "jd-1", "path1"),
    )
    p2 = ctx.Process(
        target=_actor_workflow_worker,
        args=(str(gate_home), "jd-1", "path2"),
    )
    p1.start()
    p2.start()
    p1.join(timeout=30)
    p2.join(timeout=30)
    assert p1.exitcode == 0
    assert p2.exitcode == 0

    # Final JSONL: header + 4 invocations (2 per actor) + 2 annotates that
    # also produce invocation records (1 per actor) + 2 annotation records.
    records = (gate_home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    parsed = [json.loads(r) for r in records]
    invocations = [r for r in parsed if r["kind"] == "invocation"]
    annotations = [r for r in parsed if r["kind"] == "annotation"]
    # 4 directly-flushed invocations + 2 annotate-invocations
    assert len(invocations) == 6
    assert len(annotations) == 2
    assert {r["actor"] for r in invocations} == {"path1", "path2"}
    assert {r["actor"] for r in annotations} == {"path1", "path2"}
    # Annotations have no seq — only refers_to.
    assert all("seq" not in a for a in annotations)


# ---------------------------------------------------------------------------
# Task 2 (R1) — Universal ambiguity gate
# ---------------------------------------------------------------------------


def test_ambiguity_runs_hunt_unattached_when_multiple_active_sessions(home, monkeypatch):
    from typer.testing import CliRunner
    from xdr_cli.main import app
    from xdr_cli.sessions import set_current_session, write_session_start_record, Session

    monkeypatch.delenv("XDR_SESSION", raising=False)
    s1 = Session(id="jd-1", upn="j@c", label="A", learning_mode=False)
    s2 = Session(id="jd-2", upn="j@c", label="B", learning_mode=False)
    for s in (s1, s2):
        set_current_session(s)
        write_session_start_record(s)

    runner = CliRunner()
    result = runner.invoke(app, ["hunt", "run", "DeviceProcessEvents | take 1"])
    combined = (result.output or "") + (result.stderr or "")
    assert result.exit_code != 2
    assert "multiple live sessions" in combined.lower()
    assert "xdr_session=<id>" in combined.lower()


def test_ambiguity_does_not_block_non_hunt_with_multiple_active_sessions(home, monkeypatch):
    from typer.testing import CliRunner
    from xdr_cli.main import app
    from xdr_cli.sessions import set_current_session, write_session_start_record, Session

    monkeypatch.delenv("XDR_SESSION", raising=False)
    s1 = Session(id="jd-1", upn="j@c", label="A", learning_mode=False)
    s2 = Session(id="jd-2", upn="j@c", label="B", learning_mode=False)
    for s in (s1, s2):
        set_current_session(s)
        write_session_start_record(s)

    runner = CliRunner()
    result = runner.invoke(app, ["incidents", "list"])
    combined = (result.output or "") + (result.stderr or "")
    assert result.exit_code != 2
    assert "multiple live sessions" in combined.lower()


def test_ambiguity_gate_passes_when_xdr_session_is_set(home, monkeypatch):
    """Explicit XDR_SESSION resolves the ambiguity."""
    from typer.testing import CliRunner
    from xdr_cli.main import app
    from xdr_cli.sessions import set_current_session, write_session_start_record, Session

    s1 = Session(id="jd-1", upn="j@c", label="A", learning_mode=False)
    s2 = Session(id="jd-2", upn="j@c", label="B", learning_mode=False)
    for s in (s1, s2):
        set_current_session(s)
        write_session_start_record(s)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    runner = CliRunner()
    # session list is a help-style command that should pass through.
    result = runner.invoke(app, ["session", "list"])
    assert result.exit_code == 0, (result.output, result.stderr)


def test_ambiguity_gate_skips_help_invocations(home, monkeypatch):
    """--help on any command bypasses the ambiguity gate."""
    from typer.testing import CliRunner
    from xdr_cli.main import app
    from xdr_cli.sessions import set_current_session, write_session_start_record, Session

    monkeypatch.delenv("XDR_SESSION", raising=False)
    s1 = Session(id="jd-1", upn="j@c", label="A", learning_mode=False)
    s2 = Session(id="jd-2", upn="j@c", label="B", learning_mode=False)
    for s in (s1, s2):
        set_current_session(s)
        write_session_start_record(s)

    runner = CliRunner()
    result = runner.invoke(app, ["hunt", "run", "--help"])
    assert result.exit_code == 0


def test_annotate_does_not_re_gate_actor(home, monkeypatch):
    """After annotating, actor can run the next non-bypass command without re-annotation."""
    from typer.testing import CliRunner
    from xdr_cli.main import app
    from xdr_cli.sessions import (
        set_current_session, write_session_start_record, Session,
        Recorder, actor_needs_annotation,
    )

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=True)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    monkeypatch.setenv("XDR_ACTOR", "operator")

    # Seed an unannotated invocation as 'operator' to set up the gate.
    rec = Recorder(session=s, argv=["hunt", "run", "X | take 1"], invoked_command="hunt run")
    rec.annotate("kql", "X | take 1")
    rec.flush(exit_code=0, duration_ms=10)
    assert actor_needs_annotation(s, "operator") == 1

    runner = CliRunner()
    result = runner.invoke(app, ["annotate", "noted"])
    assert result.exit_code == 0, (result.output, result.stderr)
    # Gate must clear — the annotate's own invocation record (seq=2 or 3)
    # must NOT count against the actor.
    assert actor_needs_annotation(s, "operator") is None


# ---------------------------------------------------------------------------
# Audit-log: multi-token write-command matcher (Task 11 Bug 1)
# ---------------------------------------------------------------------------


def test_audit_log_matches_multi_token_write_command(tmp_path, monkeypatch):
    """`xdr lists init` is a multi-token entry in _WRITE_COMMANDS — the
    matcher must do a contiguous-subsequence check on argv, not the default
    token-membership check (which would never match a string with a space).

    Verifies the fix for the silent audit-log regression: prior to the fix,
    `"lists init" in sys.argv` was always False because sys.argv splits the
    command into separate tokens.
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    monkeypatch.setattr(sys, "argv", ["xdr", "lists", "init", "--help"])

    # `--help` short-circuits Typer with SystemExit(0); the audit emission
    # at the top of run() fires before app() is invoked.
    with pytest.raises(SystemExit):
        run()

    audit_path = tmp_path / ".xdr-cli" / "audit.log"
    assert audit_path.exists(), "audit.log should be created on write-command invocation"
    audit = audit_path.read_text()
    assert "CMD: lists init" in audit, (
        f"expected multi-token 'lists init' to be audit-logged, got: {audit!r}"
    )


def test_audit_log_matches_single_token_write_command(tmp_path, monkeypatch):
    """Regression guard: single-token entries (`isolate`, etc.) still match.
    The matcher's single-token branch preserves the prior `cmd in argv` behavior.
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    monkeypatch.setattr(sys, "argv", ["xdr", "device", "isolate", "--help"])

    with pytest.raises(SystemExit):
        run()

    audit_path = tmp_path / ".xdr-cli" / "audit.log"
    assert audit_path.exists()
    audit = audit_path.read_text()
    assert "CMD: device isolate" in audit, (
        f"expected single-token 'isolate' to be audit-logged, got: {audit!r}"
    )


def test_matches_write_command_helper_unit():
    """Direct unit test for the helper — covers the contiguous-subsequence
    semantics without spinning up the full CLI."""
    from xdr_cli.main import _matches_write_command

    # Single-token entries: token-membership.
    assert _matches_write_command("isolate", ["xdr", "device", "isolate"])
    assert not _matches_write_command("isolate", ["xdr", "alerts", "list"])

    # Multi-token entries: contiguous subsequence.
    assert _matches_write_command("lists init", ["xdr", "lists", "init"])
    assert _matches_write_command("lists init", ["xdr", "lists", "init", "--force"])
    # Tokens present but NOT contiguous → no match.
    assert not _matches_write_command(
        "lists init", ["xdr", "lists", "show", "init"]
    )
    # Multi-token entry must not match if argv is shorter than the entry.
    assert not _matches_write_command("lists init", ["xdr", "lists"])


def test_redact_argv_space_separated_form():
    """`--refresh-token SECRET` -> the following token is replaced; SECRET
    does not appear anywhere in the result."""
    from xdr_cli.main import _redact_argv

    argv = ["device", "timeline", "my-host", "--refresh-token", "SECRET", "--days", "1"]
    redacted = _redact_argv(argv)

    assert "SECRET" not in redacted
    assert redacted == [
        "device", "timeline", "my-host", "--refresh-token", "***REDACTED***", "--days", "1",
    ]


def test_redact_argv_inline_equals_form():
    """`--refresh-token=SECRET` -> collapsed to a single redacted token;
    SECRET does not appear anywhere in the result."""
    from xdr_cli.main import _redact_argv

    argv = ["device", "timeline", "my-host", "--refresh-token=SECRET"]
    redacted = _redact_argv(argv)

    assert "SECRET" not in " ".join(redacted)
    assert redacted == ["device", "timeline", "my-host", "--refresh-token=***REDACTED***"]


def test_redact_argv_leaves_other_args_untouched():
    """Non-secret flags/values, including ones containing '=', pass through
    unchanged."""
    from xdr_cli.main import _redact_argv

    argv = ["hunt", "run", "CloudAppEvents | where x == 1", "--fields", "a,b"]
    assert _redact_argv(argv) == argv


def test_redact_argv_handles_flag_as_last_token():
    """`--refresh-token` with no following value (malformed invocation) must
    not raise — nothing to redact, so it's a no-op on that token."""
    from xdr_cli.main import _redact_argv

    argv = ["device", "timeline", "my-host", "--refresh-token"]
    assert _redact_argv(argv) == argv


def test_redact_argv_empty_list():
    from xdr_cli.main import _redact_argv

    assert _redact_argv([]) == []
