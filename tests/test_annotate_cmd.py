"""Direct coverage for `xdr annotate` argument validation and error paths.

End-to-end gate behavior is covered in test_main.py; this file focuses on
the command's own argument-parsing and error-shape contracts.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli" / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return tmp_path / ".xdr-cli"


def _seed_session_with_invocation(home_dir, session_id="jd-1", actor="operator", seq=1):
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": session_id,
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": False,
    }
    inv = {
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
    path.write_text(json.dumps(started) + "\n" + json.dumps(inv) + "\n")


def test_annotate_no_session_fails(home):
    """No active session is a structured state conflict."""
    result = runner.invoke(app, ["annotate", "test note"])
    assert result.exit_code == 13
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" in combined.lower()


def test_annotate_text_and_skip_mutually_exclusive(home, monkeypatch):
    _seed_session_with_invocation(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    result = runner.invoke(app, ["annotate", "text here", "--skip", "no good"])
    assert result.exit_code == 6
    combined = (result.output or "") + (result.stderr or "")
    assert "mutually exclusive" in combined.lower()


def test_annotate_requires_text_or_skip(home, monkeypatch):
    _seed_session_with_invocation(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    result = runner.invoke(app, ["annotate"])
    assert result.exit_code == 6
    combined = (result.output or "") + (result.stderr or "")
    assert "annotation text" in combined.lower() or "skip" in combined.lower()


def test_annotate_with_text_writes_record(home, monkeypatch):
    _seed_session_with_invocation(home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    result = runner.invoke(app, ["annotate", "useful note"])
    assert result.exit_code == 0, result.output

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    annotations = [
        json.loads(r) for r in records if json.loads(r).get("kind") == "annotation"
    ]
    assert len(annotations) == 1
    a = annotations[0]
    assert a["text"] == "useful note"
    assert a["skipped"] is False
    assert a["skip_reason"] is None
    assert a["refers_to"] == 1
    assert a["actor"] == "operator"
    # Annotations have no seq field.
    assert "seq" not in a


def test_annotate_with_skip_writes_record(home, monkeypatch):
    _seed_session_with_invocation(home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    result = runner.invoke(app, ["annotate", "--skip", "low signal"])
    assert result.exit_code == 0, result.output

    records = (home / "sessions" / "jd-1.jsonl").read_text().splitlines()
    annotations = [
        json.loads(r) for r in records if json.loads(r).get("kind") == "annotation"
    ]
    assert len(annotations) == 1
    a = annotations[0]
    assert a["text"] is None
    assert a["skipped"] is True
    assert a["skip_reason"] == "low signal"


def test_annotate_refers_to_nonexistent_seq_fails(home, monkeypatch):
    _seed_session_with_invocation(home, actor="operator", seq=1)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    result = runner.invoke(app, ["annotate", "--refers-to", "999", "x"])
    assert result.exit_code == 5
    combined = (result.output or "") + (result.stderr or "")
    assert "999" in combined or "does not reference" in combined.lower()


def test_annotate_no_invocation_to_annotate(home, monkeypatch):
    """Active session but no invocation by this actor → friendly error."""
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

    result = runner.invoke(app, ["annotate", "x"])
    assert result.exit_code == 5
    combined = (result.output or "") + (result.stderr or "")
    assert "no invocation to annotate" in combined.lower()


def test_failed_annotate_writes_no_invocation_record(home, monkeypatch):
    """Failed annotate (no prior invocation) must not write an invocation record."""
    from xdr_cli.sessions import (
        Session,
        load_session_records,
        set_current_session,
        write_session_start_record,
    )

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    # No prior invocation to annotate — should fail (exit code 1).
    result = runner.invoke(app, ["annotate", "nothing to attach to"])
    assert result.exit_code != 0

    lines = load_session_records("jd-1") or []
    kinds = [json.loads(line)["kind"] for line in lines]
    # Must NOT contain an 'invocation' record for the failed annotate.
    assert "invocation" not in kinds
    assert "annotation" not in kinds
