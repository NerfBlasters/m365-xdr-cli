"""Tests for `xdr session` sub-app: start, end, resume, list, show."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolated XDR_CLI_HOME for each test, plus a sane operator UPN."""
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    # No XDR_SESSION leaks between tests.
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return home


@pytest.fixture
def upn(monkeypatch):
    """Stub MSAL/UPN resolution so tests don't hit the real auth cache."""
    monkeypatch.setattr(
        "xdr_cli.commands.session_cmd.resolve_operator_upn",
        lambda: "jane.doe@corp.com",
    )
    monkeypatch.setattr(
        "xdr_cli.sessions.resolve_operator_upn",
        lambda: "jane.doe@corp.com",
    )
    return "jane.doe@corp.com"


def test_session_start_prints_id_and_writes_files(home, upn):
    result = runner.invoke(app, ["session", "start"])
    assert result.exit_code == 0, result.output
    sid = result.stdout.strip().splitlines()[-1]
    assert sid == "jd-1"

    # JSONL with session_started header (including schema_version: 1).
    jsonl = home / "sessions" / "jd-1.jsonl"
    assert jsonl.exists()
    first = json.loads(jsonl.read_text().splitlines()[0])
    assert first["kind"] == "session_started"
    assert first["schema_version"] == 1
    assert first["session_id"] == "jd-1"
    assert first["upn"] == "jane.doe@corp.com"

    # Marker written unconditionally (no TTY gate).
    marker = home / "active_sessions" / "jd-1"
    assert marker.exists()


def test_session_start_with_label(home, upn):
    result = runner.invoke(app, ["session", "start", "--label", "dns-beacon"])
    assert result.exit_code == 0, result.output
    jsonl = home / "sessions" / "jd-1.jsonl"
    rec = json.loads(jsonl.read_text().splitlines()[0])
    assert rec["label"] == "dns-beacon"


def test_session_start_learning_mode_in_header(home, upn):
    result = runner.invoke(app, ["session", "start", "--learning-mode"])
    assert result.exit_code == 0, result.output
    jsonl = home / "sessions" / "jd-1.jsonl"
    rec = json.loads(jsonl.read_text().splitlines()[0])
    assert rec["learning_mode"] is True


def test_session_start_always_writes_marker(home, upn):
    """Per-session markers are written unconditionally — no TTY gate.

    The old single-pointer model skipped the write under non-TTY to prevent
    clobbering. Per-session markers don't share a file so this guard is gone.
    Both TTY and non-TTY callers get a marker written.
    """
    result = runner.invoke(app, ["session", "start"])
    assert result.exit_code == 0, result.output
    # Marker written regardless of TTY state.
    marker = home / "active_sessions" / "jd-1"
    assert marker.exists()
    # JSONL still written.
    assert (home / "sessions" / "jd-1.jsonl").exists()


def test_session_start_without_concurrent_rotates_ambiguous_sessions(home, upn):
    runner.invoke(app, ["session", "start", "--label", "one"])
    runner.invoke(app, ["session", "start", "--concurrent", "--label", "two"])
    markers = {
        path.name
        for path in (home / "active_sessions").iterdir()
        if path.suffix != ".lock"
    }
    assert markers == {
        "jd-1",
        "jd-2",
    }

    result = runner.invoke(app, ["session", "start", "--label", "replacement"])
    assert result.exit_code == 0, result.output
    markers = {
        path.name
        for path in (home / "active_sessions").iterdir()
        if path.suffix != ".lock"
    }
    assert markers == {"jd-3"}
    for sid in ("jd-1", "jd-2"):
        records = [
            json.loads(line)
            for line in (home / "sessions" / f"{sid}.jsonl").read_text().splitlines()
        ]
        assert records[-1]["end_reason"] == "manual-rotation"


def test_session_start_fails_when_no_auth(home, monkeypatch):
    monkeypatch.setattr("xdr_cli.commands.session_cmd.resolve_operator_upn", lambda: None)
    result = runner.invoke(app, ["session", "start"])
    assert result.exit_code == 2
    combined = (result.output or "") + (result.stderr or "")
    assert "auth login" in combined.lower()


def test_session_end_writes_marker_and_clears_pointer(home, upn):
    runner.invoke(app, ["session", "start"])
    result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 0, result.output

    jsonl = home / "sessions" / "jd-1.jsonl"
    lines = [json.loads(line) for line in jsonl.read_text().splitlines() if line.strip()]
    assert any(rec["kind"] == "session_ended" for rec in lines)
    end_rec = next(rec for rec in lines if rec["kind"] == "session_ended")
    assert end_rec["schema_version"] == 1
    assert end_rec["session_id"] == "jd-1"

    # Active marker removed by clear_current_session(s.id).
    marker = home / "active_sessions" / "jd-1"
    assert not marker.exists()


def test_session_end_idempotent_refuses_double_end(home, upn, monkeypatch):
    runner.invoke(app, ["session", "start"])
    runner.invoke(app, ["session", "end"])
    # Second end without a current session is a friendly no-op.
    result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 0
    assert "no active session" in result.output.lower()

    # But: if XDR_SESSION points at the already-ended session, refuse.
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 13
    assert "already" in result.output.lower()


def test_session_end_refuses_non_operator_actor_without_force(home, upn, monkeypatch):
    runner.invoke(app, ["session", "start"])
    monkeypatch.setenv("XDR_ACTOR", "path1")
    result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 7
    assert "actor" in result.output.lower()

    # --force overrides.
    result = runner.invoke(app, ["session", "end", "--force"])
    assert result.exit_code == 0


def test_session_resume(home, upn):
    runner.invoke(app, ["session", "start", "--label", "incident-X"])
    # Clear marker to simulate a new shell / different process context.
    (home / "active_sessions" / "jd-1").unlink()

    result = runner.invoke(app, ["session", "resume", "jd-1"])
    assert result.exit_code == 0, result.output
    assert (home / "active_sessions" / "jd-1").exists()


def test_session_resume_unknown_id(home, upn):
    result = runner.invoke(app, ["session", "resume", "nope-99"])
    assert result.exit_code == 8


def test_session_resume_rejects_ended_session(home, upn):
    runner.invoke(app, ["session", "start"])
    runner.invoke(app, ["session", "end"])
    result = runner.invoke(app, ["session", "resume", "jd-1"])
    assert result.exit_code == 13
    assert "feedback" in result.output


def test_session_list_includes_recent_sessions(home, upn):
    runner.invoke(app, ["session", "start", "--label", "alpha"])
    runner.invoke(app, ["session", "end"])
    runner.invoke(app, ["session", "start", "--label", "beta"])

    result = runner.invoke(app, ["session", "list"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    rows = parsed["data"]
    ids = {row["id"] for row in rows}
    assert "jd-1" in ids
    assert "jd-2" in ids


def test_session_show_emits_raw_jsonl(home, upn):
    runner.invoke(app, ["session", "start"])
    result = runner.invoke(app, ["session", "show", "jd-1"])
    assert result.exit_code == 0, result.output
    # Each line is a JSON object — verify by parsing.
    for line in result.stdout.splitlines():
        if line.strip():
            json.loads(line)


def test_session_show_unknown_id_returns_error(home, upn):
    result = runner.invoke(app, ["session", "show", "ghost-1"])
    assert result.exit_code == 8


def test_session_id_cannot_escape_private_session_directory(home, upn):
    outside = home.parent / "outside.jsonl"
    outside.write_text('{"kind":"session_started","secret":"must-not-read"}\n')
    result = runner.invoke(app, ["session", "show", "../../outside"])
    assert result.exit_code == 8
    assert "must-not-read" not in result.stdout
