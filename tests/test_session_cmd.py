"""Tests for `xdr session` sub-app: start, end, resume, list, show."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()


@pytest.mark.parametrize("flags,progress", [
    ([], False), (["--quiet"], False), (["--no-quiet"], True),
])
def test_end_maintenance_progress_respects_piped_stdout(home, upn, flags, progress):
    from xdr_cli.config import Config, save_config

    save_config(Config(tenant_id="tenant"))
    assert runner.invoke(app, ["session", "start"]).exit_code == 0
    with patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as maintain:
        result = runner.invoke(app, [*flags, "session", "end"])
    assert result.exit_code == 0, result.output
    maintain.assert_called_once()
    end_records(result)
    assert ("Session ended. Collecting schema evidence" in result.stderr) is progress


def end_records(result):
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(records) == 2
    closure, terminal = records
    assert closure["record_type"] == "session-end"
    assert terminal["record_type"] == "session-maintenance"
    assert closure["session_id"] == terminal["session_id"]
    assert closure["status"] == "success"
    assert closure["ended"] is True
    assert "--source agent" in closure["next_action"]["agent_command_template"]
    return closure, terminal


def test_end_flushes_closure_before_maintenance_and_emits_terminal_failure(home, upn, monkeypatch):
    from xdr_cli.config import Config, save_config
    from xdr_cli.exceptions import AuthError

    save_config(Config(tenant_id="tenant"))
    assert runner.invoke(app, ["session", "start"]).exit_code == 0
    events, observed = [], []
    echo = typer.echo

    def observe_echo(message=None, **kwargs):
        echo(message, **kwargs)
        if not kwargs.get("err") and json.loads(message).get("record_type") == "session-end":
            observed.append(json.loads(message))
            events.append("receipt")
            stream_flush = sys.stdout.flush

            def observe_flush():
                events.append("flush")
                stream_flush()

            monkeypatch.setattr(sys.stdout, "flush", observe_flush)

    def maintain(ctx, *, on_result):
        events.append("maintenance")
        raise AuthError("private detail")

    with (
        patch("xdr_cli.commands.session_cmd.typer.echo", side_effect=observe_echo),
        patch(
            "xdr_cli.schema_graph.session_maintenance.collect_session_schema", side_effect=maintain,
        ),
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 14, result.output
    assert events[:3] == ["receipt", "flush", "maintenance"]
    assert observed[0]["ended"] is True
    assert "next_action" in observed[0]
    _, terminal = end_records(result)
    assert terminal["error"]["exit_code"] == 14
    assert terminal["error"]["original"]["exit_code"] == 2
    assert "private detail" not in result.output


def test_end_no_maintenance_is_one_off_without_changing_default(home, upn):
    from xdr_cli.config import Config, load_config, save_config

    save_config(Config(tenant_id="tenant"))
    assert runner.invoke(app, ["session", "start"]).exit_code == 0
    with patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as maintain:
        result = runner.invoke(app, ["session", "end", "--no-maintenance"])
    assert result.exit_code == 0, result.output
    _, terminal = end_records(result)
    assert terminal["maintenance"] == {"status": "skipped", "reason": "requested"}
    assert load_config().schema_collect_on_session_end is True
    maintain.assert_not_called()


def test_end_deadline_emits_partial_retains_saved_evidence_and_stops_future_stages(home, upn):
    from xdr_cli.config import Config, save_config
    from xdr_cli.results import write_result
    from xdr_cli.sessions import session_already_ended

    save_config(Config(tenant_id="tenant", schema_maintenance_timeout_seconds=0.02))
    assert runner.invoke(app, ["session", "start"]).exit_code == 0
    saved = []

    async def validate(ctx, **kwargs):
        artifact = write_result(
            [], command="schema collect", tenant_id="tenant",
            receipt_context={"queries_executed": 1, "remaining_queries": 1},
        )
        saved.append(artifact.receipt.run_id)
        kwargs["on_result"](artifact)
        await asyncio.sleep(0.08)

    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": False})),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=validate),
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers") as explore,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
        patch("xdr_cli.commands.session_cmd.typer.prompt") as prompt,
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 14, result.output
    _, terminal = end_records(result)
    assert terminal["error"]["original"]["exit_code"] == 10
    assert terminal["error"]["original"]["error_code"] == "SESSION_SCHEMA_MAINTENANCE_TIMEOUT"
    stages = terminal["maintenance"]["result"]["context"]["stages"]
    assert stages["validation"]["status"] == "failed"
    assert stages["validation"]["result"]["run_id"] == saved[0]
    assert Path(stages["validation"]["result"]["data_path"]).is_file()
    assert stages["exploration"]["status"] == "skipped"
    assert session_already_ended("jd-1")
    explore.assert_not_called()
    complete.assert_not_called()
    prompt.assert_not_called()


def test_end_write_failure_never_claims_durable_closure_or_starts_maintenance(home, upn):
    from xdr_cli.exceptions import ArtifactError
    from xdr_cli.sessions import session_already_ended

    assert runner.invoke(app, ["session", "start"]).exit_code == 0
    with (
        patch("xdr_cli.commands.session_cmd.write_session_end_record",
              side_effect=ArtifactError("synthetic write failure")),
        patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as maintain,
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 12
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "error"
    assert "next_action" not in receipt
    assert not session_already_ended("jd-1")
    maintain.assert_not_called()


def test_end_partial_failure_preserves_underlying_auth_error_and_retry(home, upn):
    from xdr_cli.config import Config, save_config
    from xdr_cli.exceptions import AuthError, PartialSuccessError

    save_config(Config(tenant_id="tenant"))
    assert runner.invoke(app, ["session", "start"]).exit_code == 0

    def maintain(ctx, *, on_result):
        try:
            raise AuthError("private upstream context")
        except AuthError as exc:
            raise PartialSuccessError("private partial context", retry_after_seconds=90) from exc

    with patch(
        "xdr_cli.schema_graph.session_maintenance.collect_session_schema", side_effect=maintain,
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 14, result.output
    _, terminal = end_records(result)
    original = terminal["error"]["original"]
    assert original["exit_code"] == 14
    assert original["cause"]["exit_code"] == 2
    assert original["cause"]["help_command"] == "xdr auth status"
    assert terminal["error"]["retry_after_seconds"] == 90
    assert "private" not in result.output


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
        lambda **kwargs: "jane.doe@corp.com",
    )
    monkeypatch.setattr(
        "xdr_cli.sessions.resolve_operator_upn",
        lambda **kwargs: "jane.doe@corp.com",
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
    monkeypatch.setattr("xdr_cli.commands.session_cmd.resolve_operator_upn", lambda **kwargs: None)
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


def test_end_collects_after_close_with_one_receipt(home, upn):
    from xdr_cli.config import Config, save_config
    from xdr_cli.results import write_result
    from xdr_cli.sessions import session_already_ended

    save_config(Config(tenant_id="tenant"))
    runner.invoke(app, ["session", "start"])

    def collect(ctx, *, on_result):
        assert session_already_ended("jd-1")
        assert not (home / "active_sessions" / "jd-1").exists()
        assert ctx.recorder is None and ctx.no_interactive
        on_result(write_result([{"example": 1}], command="schema collect", tenant_id="tenant"))

    with patch(
        "xdr_cli.schema_graph.session_maintenance.collect_session_schema", side_effect=collect,
    ) as collect_mock:
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 0, result.output
    closure, receipt = end_records(result)
    assert receipt["maintenance"]["status"] == "success"
    assert receipt["maintenance"]["result"]["context"]["shown"] == 0
    assert receipt["maintenance"]["result"]["context"]["has_more"]
    assert "--source agent" in closure["next_action"]["agent_command_template"]
    collect_mock.assert_called_once()


@pytest.mark.parametrize("failure,expected", [
    (KeyboardInterrupt(), "cancelled"),
    (asyncio.CancelledError(), "cancelled"),
    (RuntimeError("private detail"), "failed"),
])
def test_end_survives_collection_failure(home, upn, failure, expected):
    from xdr_cli.config import Config, save_config
    from xdr_cli.sessions import session_already_ended

    save_config(Config(tenant_id="tenant"))
    runner.invoke(app, ["session", "start"])
    with patch(
        "xdr_cli.schema_graph.session_maintenance.collect_session_schema", side_effect=failure,
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == (130 if expected == "cancelled" else 14), result.output
    _, terminal = end_records(result)
    assert terminal["status"] == "partial"
    assert terminal["maintenance"]["status"] == expected
    assert "private detail" not in result.output
    assert session_already_ended("jd-1")


def test_end_async_validation_cancellation_preserves_aggregate_receipt(home, upn):
    from xdr_cli.config import Config, save_config
    from xdr_cli.sessions import session_already_ended

    save_config(Config(tenant_id="tenant"))
    assert runner.invoke(app, ["session", "start"]).exit_code == 0

    async def cancel_validation(ctx, **kwargs):
        assert session_already_ended("jd-1")
        assert ctx.recorder is None
        raise asyncio.CancelledError("private cancellation detail")

    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": False})),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=cancel_validation),
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers") as explore,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
    ):
        result = runner.invoke(app, ["session", "end"])

    assert result.exit_code == 130, result.output
    closure, receipt = end_records(result)
    assert closure["status"] == "success"
    assert receipt["status"] == "partial"
    assert receipt["session_id"] == "jd-1"
    maintenance = receipt["maintenance"]
    assert maintenance["status"] == "cancelled"
    stages = maintenance["result"]["context"]["stages"]
    assert stages["validation"]["status"] == "cancelled"
    assert stages["exploration"]["status"] == "skipped"
    assert Path(maintenance["result"]["data_path"]).is_file()
    assert session_already_ended("jd-1")
    assert not (home / "active_sessions" / "jd-1").exists()
    assert "private cancellation detail" not in result.output
    explore.assert_not_called()
    complete.assert_not_called()


def test_end_reports_partial_collection_retry(home, upn):
    from xdr_cli.config import Config, save_config
    from xdr_cli.exceptions import PartialSuccessError

    save_config(Config(tenant_id="tenant"))
    runner.invoke(app, ["session", "start"])
    with patch(
        "xdr_cli.schema_graph.session_maintenance.collect_session_schema",
        side_effect=PartialSuccessError("quota", retry_after_seconds=90),
    ):
        result = runner.invoke(app, ["session", "end"])
    _, receipt = end_records(result)
    assert result.exit_code == 14
    assert receipt["maintenance"]["status"] == "partial"
    assert receipt["maintenance"]["retry_after_seconds"] == 90
    assert receipt["maintenance"]["exit_code"] == 14


def test_end_disabled_and_no_active_do_not_collect(home, upn):
    from xdr_cli.config import Config, save_config

    save_config(Config(tenant_id="tenant", schema_collect_on_session_end=False))
    runner.invoke(app, ["session", "start"])
    with patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as collect:
        result = runner.invoke(app, ["session", "end"])
        assert end_records(result)[1]["maintenance"]["reason"] == "disabled"
        runner.invoke(app, ["session", "end"])
    collect.assert_not_called()


def test_end_real_empty_collection_does_not_create_session(home, upn):
    from xdr_cli.config import Config, save_config

    save_config(Config(
        tenant_id="tenant", schema_refresh_on_session_end=False,
        schema_explore_on_session_end=False,
    ))
    runner.invoke(app, ["session", "start"])
    with patch("xdr_cli.schema_graph.local_collection.AuthManager") as auth:
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 0, result.output
    _, receipt = end_records(result)
    assert receipt["maintenance"]["status"] == "success"
    assert receipt["maintenance"]["result"]["context"]["queries_executed"] == 0
    assert not [p for p in (home / "active_sessions").glob("jd-*") if p.suffix != ".lock"]
    auth.assert_not_called()


def test_lost_end_race_does_not_collect(home, upn):
    runner.invoke(app, ["session", "start"])
    with (
        patch("xdr_cli.commands.session_cmd.write_session_end_record", return_value=None),
        patch("xdr_cli.commands.session_cmd._collect_after_explicit_end") as collect,
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 13
    collect.assert_not_called()


@pytest.mark.parametrize("refresh,explore", [(True, True), (True, False),
                                          (False, True), (False, False)])
def test_end_forwards_refresh_explore_and_budget_to_maintenance(home, upn, refresh, explore):
    from xdr_cli.config import Config, save_config
    from xdr_cli.results import write_result
    from xdr_cli.sessions import session_already_ended

    save_config(Config(
        tenant_id="tenant", schema_refresh_on_session_end=refresh,
        schema_explore_on_session_end=explore, schema_explore_max_queries=17,
        schema_stale_seconds=0,
    ))
    runner.invoke(app, ["session", "start"])

    def maintain(ctx, *, on_result):
        assert session_already_ended("jd-1")
        assert ctx.config.schema_refresh_on_session_end is refresh
        assert ctx.config.schema_explore_on_session_end is explore
        assert ctx.config.schema_explore_max_queries == 17
        assert ctx.config.schema_stale_seconds == 0
        assert ctx.session_id is None
        assert ctx.session_attachment == "unattached"
        assert ctx.anchor_incident is None and ctx.anchor_alert is None
        on_result(write_result(
            [], command="schema collect session-maintenance", tenant_id="tenant",
            receipt_context={"refresh_enabled": refresh, "explore_enabled": explore},
        ))

    with patch(
        "xdr_cli.schema_graph.session_maintenance.collect_session_schema", side_effect=maintain,
    ) as collect:
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 0, result.output
    _, receipt = end_records(result)
    assert receipt["maintenance"]["status"] == "success"
    assert receipt["maintenance"]["result"]["context"]["refresh_enabled"] is refresh
    assert receipt["maintenance"]["result"]["context"]["explore_enabled"] is explore
    collect.assert_called_once()


def test_end_master_switch_overrides_enabled_refresh_and_explore(home, upn):
    from xdr_cli.config import Config, save_config

    save_config(Config(
        tenant_id="tenant", schema_collect_on_session_end=False,
        schema_refresh_on_session_end=True, schema_explore_on_session_end=True,
    ))
    runner.invoke(app, ["session", "start"])
    with patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as collect:
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 0
    assert end_records(result)[1]["maintenance"] == {"status": "skipped", "reason": "disabled"}
    collect.assert_not_called()


def test_end_maintenance_does_not_attach_to_another_active_session(home, upn, monkeypatch):
    from xdr_cli.config import Config, save_config
    from xdr_cli.results import write_result

    save_config(Config(tenant_id="tenant"))
    runner.invoke(app, ["session", "start"])
    runner.invoke(app, ["session", "start", "--concurrent"])
    other_session = home / "sessions" / "jd-2.jsonl"
    before = other_session.read_bytes()
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    def maintain(ctx, *, on_result):
        assert ctx.recorder is None and ctx.no_interactive
        assert ctx.session_id is None and ctx.session_attachment == "unattached"
        assert ctx._auth is None and ctx._client is None
        on_result(write_result([], command="schema collect", tenant_id="tenant"))

    with patch(
        "xdr_cli.schema_graph.session_maintenance.collect_session_schema", side_effect=maintain,
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 0, result.output
    assert other_session.read_bytes() == before
    assert (home / "active_sessions" / "jd-2").exists()
    assert end_records(result)[1]["maintenance"]["result"]["session_id"] is None


def test_rotation_and_no_active_end_never_run_session_maintenance(home, upn):
    from xdr_cli.config import Config, save_config

    save_config(Config(tenant_id="tenant"))
    with patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as collect:
        no_active = runner.invoke(app, ["session", "end"])
        runner.invoke(app, ["session", "start"])
        rotation = runner.invoke(app, ["session", "start"])
    assert no_active.exit_code == rotation.exit_code == 0
    collect.assert_not_called()


def test_end_auth_failure_remains_sanitized_with_recovery(home, upn):
    from xdr_cli.config import Config, save_config
    from xdr_cli.exceptions import AuthError
    from xdr_cli.sessions import session_already_ended

    save_config(Config(tenant_id="tenant"))
    runner.invoke(app, ["session", "start"])
    with patch(
        "xdr_cli.schema_graph.session_maintenance.collect_session_schema",
        side_effect=AuthError("private authentication detail"),
    ):
        result = runner.invoke(app, ["session", "end"])
    assert result.exit_code == 14
    maintenance = end_records(result)[1]["maintenance"]
    assert maintenance["status"] == "failed"
    assert maintenance["exit_code"] == 2
    assert maintenance["next_command"] == "xdr auth status"
    assert "private authentication detail" not in result.output
    assert session_already_ended("jd-1")
