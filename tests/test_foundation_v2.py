"""Focused contracts for the 0.7 artifact/session/discovery foundation."""

from __future__ import annotations

import hashlib
import json
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from xdr_cli.api.hunting import HuntingResult
from xdr_cli.auth import _missing_scope_error
from xdr_cli.client import APISurface, XDRClient
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    AuthError,
    ConfigError,
    ConflictError,
    ExitCode,
    ForbiddenError,
    NetworkError,
    NotFoundError,
    PartialSuccessError,
    QueryError,
    RateLimitError,
    TimeoutError,
    UsageError,
    XDRError,
)
from xdr_cli.main import app
from xdr_cli.sessions import (
    Session,
    append_session_feedback,
    clear_current_session,
    find_active_sessions,
    load_session_records,
    resolve_session_for_invocation,
    set_current_session,
    write_session_end_record,
    write_session_start_record,
)

runner = CliRunner()


def _home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / ".xdr-cli"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.setattr("xdr_cli.sessions.resolve_operator_upn", lambda: "jane.doe@corp.com")
    monkeypatch.setattr(
        "xdr_cli.commands.session_cmd.resolve_operator_upn",
        lambda: "jane.doe@corp.com",
    )
    return home


def test_exit_taxonomy_has_unique_recovery_classes():
    cases = [
        (XDRError(), ExitCode.INTERNAL_ERROR),
        (AuthError(), ExitCode.AUTH_ERROR),
        (APIError(), ExitCode.UPSTREAM_API_ERROR),
        (ConfigError(), ExitCode.CONFIG_ERROR),
        (QueryError(), ExitCode.QUERY_ERROR),
        (UsageError(), ExitCode.USAGE_ERROR),
        (ForbiddenError(), ExitCode.PERMISSION_ERROR),
        (NotFoundError(), ExitCode.NOT_FOUND),
        (RateLimitError(), ExitCode.RATE_LIMIT),
        (TimeoutError("timeout"), ExitCode.TIMEOUT),
        (NetworkError(), ExitCode.NETWORK_ERROR),
        (ArtifactError(), ExitCode.ARTIFACT_ERROR),
        (ConflictError(), ExitCode.CONFLICT),
        (PartialSuccessError(), ExitCode.PARTIAL_SUCCESS),
    ]
    assert [int(error.exit_code) for error, _ in cases] == list(range(1, 15))
    assert all(error.exit_code == expected for error, expected in cases)


def test_library_discovery_is_native_and_artifact_first(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(app, ["library", "list", "--search", "process_tree"])
    assert result.exit_code == 0, result.output
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert records[0]["rows"] >= 1
    saved = Path(records[0]["data_path"])
    assert any(
        json.loads(line)["name"] == "qry_process_tree"
        for line in saved.read_text().splitlines()
    )

    shown = runner.invoke(app, ["library", "show", "qry_process_tree"])
    assert shown.exit_code == 0
    descriptor = json.loads(shown.stdout)["data"]
    assert descriptor["required_permissions"]["any_of"] == [
        {
            "resource": "Microsoft Graph",
            "permission": "ThreatHunting.Read.All",
            "path": "primary",
        },
        {
            "resource": "WindowsDefenderATP",
            "permission": "AdvancedQuery.Read.All",
            "path": "fallback",
        },
    ]
    assert any(param["name"] == "device_name" for param in descriptor["parameters"])

    typed = runner.invoke(app, ["library", "show", "identity_signin_context"])
    typed_descriptor = json.loads(typed.stdout)["data"]
    params = {item["name"]: item for item in typed_descriptor["parameters"]}
    assert params["account_oid"]["format"] == "tenant identifier"
    assert params["start"]["type"] == "datetime"
    assert params["mode"]["allowed"] == ["summary", "detail"]
    assert "EntraIdSignInEvents" in typed_descriptor["schema_hint"]["tables"]
    assert typed_descriptor["schema_hint"]["declared_output_fields"]


def test_library_tier_validation_uses_unfiltered_catalog(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(
        app,
        ["library", "list", "--tier", "r1", "--search", "no-such-entry"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout.splitlines()[0])["rows"] == 0


def test_library_run_rejects_invalid_typed_parameter(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(
        app,
        [
            "library",
            "run",
            "identity_signin_context",
            "--param",
            "account_oid=abc",
            "--param",
            "start=2026-01-01",
            "--param",
            "end=2026-01-02",
            "--param",
            "mode=verbose",
        ],
    )
    assert result.exit_code == 5
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "LIBRARY_INVALID_PARAM"
    assert error["allowed"] == ["summary", "detail"]


def test_unknown_library_entry_has_stable_corrective_error(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(app, ["library", "show", "qry_process_tre"])
    assert result.exit_code == 5
    assert len(result.stdout.splitlines()) == 1
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "LIBRARY_UNKNOWN_ENTRY"
    assert error["help_command"] == "xdr library list --search qry_process_tre"


def test_schema_show_is_cache_only_and_reports_staleness(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    tenant_key = hashlib.sha256(b"default").hexdigest()[:12]
    cache = home / "schema" / tenant_key
    cache.mkdir(parents=True)
    serialized = (
        '{"TableName":"DeviceEvents","ColumnName":"Timestamp","ColumnType":"DateTime","ColumnOrdinal":0}\n'
        '{"TableName":"DeviceEvents","ColumnName":"ActionType","ColumnType":"String","ColumnOrdinal":1}\n'
    )
    (cache / "schema.jsonl").write_bytes(serialized.encode("utf-8"))
    old = (datetime.now(UTC) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
    (cache / "schema.meta.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "refreshed_at": old,
                "row_count": 2,
                "data_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
                "data_bytes": len(serialized.encode()),
            }
        )
    )
    session = Session(
        id="jd-1",
        upn="jane.doe@corp.com",
        label="schema-review",
        learning_mode=False,
        last_activity_at=datetime.now(UTC).isoformat(),
    )
    set_current_session(session)
    write_session_start_record(session)

    result = runner.invoke(app, ["schema", "show", "DeviceEvents", "--search", "Action"])
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["session_id"] == "jd-1"
    assert receipt["session_label"] == "schema-review"
    assert receipt["context"]["cache"]["stale"] is True
    metadata = json.loads(Path(receipt["meta_path"]).read_text())
    assert metadata["cache"]["stale"] is True
    assert json.loads(Path(receipt["data_path"]).read_text())["ColumnName"] == "ActionType"


def test_schema_refresh_reuses_existing_probe_and_populates_cache(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    fake = HuntingResult(
        schema=[{"name": "TableName"}, {"name": "ColumnName"}],
        results=[
            {
                "TableName": "DeviceEvents",
                "ColumnName": "Timestamp",
                "ColumnType": "DateTime",
                "ColumnOrdinal": 0,
            }
        ],
        stats={},
    )
    client = AsyncMock()
    client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch("xdr_cli.commands.schema_cmd.run_query", new=AsyncMock(return_value=fake)),
    ):
        result = runner.invoke(app, ["schema", "refresh"])
    assert result.exit_code == 0, result.output
    metadata = json.loads(Path(json.loads(result.stdout.splitlines()[0])["meta_path"]).read_text())
    assert metadata["library_entry"] == "sys_schema_probe"
    assert "union isfuzzy=true" in metadata["query"]
    manifests = list((home / "schema").rglob("current.json"))
    assert len(manifests) == 1
    generation = json.loads(manifests[0].read_text())["generation"]
    assert (manifests[0].parent / f"schema.{generation}.jsonl").exists()
    assert (manifests[0].parent / f"schema.{generation}.meta.json").exists()


def test_invalid_schema_cache_has_artifact_recovery_error(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    tenant_key = hashlib.sha256(b"default").hexdigest()[:12]
    cache = home / "schema" / tenant_key
    cache.mkdir(parents=True)
    (cache / "schema.jsonl").write_text('{"TableName":"DeviceEvents"}\n')
    (cache / "schema.meta.json").write_text("not-json")
    result = runner.invoke(app, ["schema", "tables"])
    assert result.exit_code == 12
    assert len(result.stdout.splitlines()) == 1
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "SCHEMA_CACHE_INVALID"
    assert error["help_command"] == "xdr schema refresh"


def test_schema_show_valid_table_with_no_column_match_is_empty_success(
    tmp_path, monkeypatch
):
    home = _home(tmp_path, monkeypatch)
    tenant_key = hashlib.sha256(b"default").hexdigest()[:12]
    cache = home / "schema" / tenant_key
    cache.mkdir(parents=True)
    serialized = '{"TableName":"DeviceEvents","ColumnName":"Timestamp"}\n'
    (cache / "schema.jsonl").write_bytes(serialized.encode("utf-8"))
    (cache / "schema.meta.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "refreshed_at": datetime.now(UTC).isoformat(),
                "row_count": 1,
                "data_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
                "data_bytes": len(serialized.encode()),
                "server_truncation_state": "unknown",
            }
        )
    )
    result = runner.invoke(
        app,
        ["schema", "show", "DeviceEvents", "--search", "DoesNotExist"],
    )
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["rows"] == 0
    assert receipt["context"]["filter"]["matches"] == 0


def test_failed_schema_generation_does_not_replace_prior_cache(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    tenant_key = hashlib.sha256(b"default").hexdigest()[:12]
    cache = home / "schema" / tenant_key
    cache.mkdir(parents=True)
    serialized = '{"TableName":"PriorTable","ColumnName":"PriorColumn"}\n'
    (cache / "schema.jsonl").write_bytes(serialized.encode("utf-8"))
    (cache / "schema.meta.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "refreshed_at": datetime.now(UTC).isoformat(),
                "row_count": 1,
                "data_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
                "data_bytes": len(serialized.encode()),
                "server_truncation_state": "unknown",
            }
        )
    )
    fake = HuntingResult(
        schema=[],
        results=[{"TableName": "NewTable", "ColumnName": "NewColumn"}],
        stats={},
    )
    import os

    real_replace = os.replace

    def fail_metadata_publish(source, destination):
        if str(destination).endswith(".meta.json") and ".meta.json.tmp" in str(source):
            raise OSError("simulated metadata publish failure")
        return real_replace(source, destination)

    client = AsyncMock()
    client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch("xdr_cli.commands.schema_cmd.run_query", new=AsyncMock(return_value=fake)),
        patch("xdr_cli.commands.schema_cmd.os.replace", side_effect=fail_metadata_publish),
    ):
        failed = runner.invoke(app, ["schema", "refresh"])
    assert failed.exit_code == 12
    assert not (cache / "current.json").exists()

    prior = runner.invoke(app, ["schema", "tables"])
    assert prior.exit_code == 0, prior.output
    data_path = Path(json.loads(prior.stdout.splitlines()[0])["data_path"])
    assert json.loads(data_path.read_text())["TableName"] == "PriorTable"


def test_concurrent_schema_refreshes_publish_one_coherent_generation(
    tmp_path, monkeypatch
):
    from xdr_cli.commands.schema_cmd import _active_cache_paths, _schema_refresh
    from xdr_cli.config import Config
    from xdr_cli.context import AppContext

    _home(tmp_path, monkeypatch)
    fake = HuntingResult(
        schema=[],
        results=[{"TableName": "DeviceEvents", "ColumnName": "Timestamp"}],
        stats={},
    )

    class FakeClient:
        async def close(self):
            return None

    async def fake_run_query(client, query):
        await asyncio.sleep(0.01)
        return fake

    def refresh():
        asyncio.run(_schema_refresh(AppContext(config=Config())))

    with (
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=FakeClient()),
        patch("xdr_cli.commands.schema_cmd.run_query", side_effect=fake_run_query),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        futures = [pool.submit(refresh) for _ in range(2)]
        for future in futures:
            future.result()

    data_path, meta_path = _active_cache_paths("")
    rows = [json.loads(line) for line in data_path.read_text().splitlines()]
    metadata = json.loads(meta_path.read_text())
    assert rows == fake.results
    assert metadata["row_count"] == len(rows)
    assert metadata["generation"] in data_path.name


def test_recordable_command_auto_creates_but_browse_does_not(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    session, mode = resolve_session_for_invocation("schema tables")
    assert session is None
    assert mode == "unattached"

    session, mode = resolve_session_for_invocation("hunt run")
    assert session is not None
    assert session.automatic is True
    assert mode == "automatic-created"
    assert (home / "sessions" / f"{session.id}.jsonl").exists()


def test_hunt_artifact_inherits_session_anchor_with_explicit_provenance(
    tmp_path,
    monkeypatch,
):
    _home(tmp_path, monkeypatch)
    session = Session(
        id="jd-1",
        upn="jane.doe@corp.com",
        label="incident-123",
        learning_mode=False,
        anchor_incident=123,
        anchor_provenance="graph-response",
        last_activity_at=datetime.now(UTC).isoformat(),
    )
    set_current_session(session)
    write_session_start_record(session)
    fake = HuntingResult(
        schema=[{"name": "Timestamp", "type": "DateTime"}],
        results=[{"Timestamp": "2026-07-31T00:00:00Z"}],
        stats={},
    )
    client = AsyncMock()
    client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
    ):
        result = runner.invoke(app, ["hunt", "run", "DeviceInfo | take 1"])

    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    metadata = json.loads(Path(receipt["meta_path"]).read_text())
    assert receipt["incident_id"] == "123"
    assert metadata["anchors"]["provenance"] == {
        "incident_id": "session-inherited"
    }


def test_ambiguous_sessions_are_nonblocking_and_unattached(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    for sid in ("jd-1", "jd-2"):
        session = Session(
            id=sid,
            upn="jane.doe@corp.com",
            label=sid,
            learning_mode=False,
            last_activity_at=datetime.now(UTC).isoformat(),
        )
        set_current_session(session)
        write_session_start_record(session)
    session, mode = resolve_session_for_invocation("hunt run")
    assert session is None
    assert mode == "ambiguous-unattached"


def test_incident_anchor_matches_then_rotates_automatic_session(
    tmp_path,
    monkeypatch,
    capsys,
):
    _home(tmp_path, monkeypatch)
    first, mode = resolve_session_for_invocation(
        "incidents show",
        anchor_incident=101,
    )
    assert first is not None and mode == "automatic-created"
    matched, mode = resolve_session_for_invocation(
        "investigate",
        anchor_incident=101,
    )
    assert matched is not None and matched.id == first.id
    assert mode == "anchor-match"

    rotated, mode = resolve_session_for_invocation(
        "incidents show",
        anchor_incident=202,
    )
    assert rotated is not None and rotated.id != first.id
    assert rotated.anchor_incident == 202
    assert mode == "automatic-rotated"
    prior = [json.loads(line) for line in load_session_records(first.id) or []]
    assert prior[-1]["end_reason"] == "automatic-rotation"
    notice = capsys.readouterr().err
    assert f"xdr session feedback {first.id} --source agent" in notice


def test_idle_timeout_retires_marker_and_keeps_history(tmp_path, monkeypatch, capsys):
    home = _home(tmp_path, monkeypatch)
    session = Session(
        id="jd-1",
        upn="jane.doe@corp.com",
        label="old",
        learning_mode=False,
        last_activity_at=(datetime.now(UTC) - timedelta(minutes=31)).isoformat(),
        timeout_seconds=1800,
    )
    set_current_session(session)
    write_session_start_record(session)
    assert find_active_sessions() == []
    assert not (home / "active_sessions" / "jd-1").exists()
    records = [json.loads(line) for line in load_session_records("jd-1") or []]
    assert records[-1]["kind"] == "session_ended"
    assert records[-1]["end_reason"] == "idle-timeout"
    assert "xdr session feedback jd-1 --source agent" in capsys.readouterr().err


def test_feedback_is_append_only_after_end(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    session = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(session)
    write_session_start_record(session)
    write_session_end_record(session)
    clear_current_session(session.id)
    first = append_session_feedback(
        session.id,
        source="agent",
        outcome="completed-with-friction",
        categories=["output-handling"],
        comment="large output",
    )
    second = append_session_feedback(
        session.id,
        source="analyst",
        outcome="completed-smoothly",
        comment="much better",
    )
    assert first["feedback_seq"] == 1
    assert second["feedback_seq"] == 2
    assert first["feedback_id"] != second["feedback_id"]
    records = [json.loads(line) for line in load_session_records(session.id) or []]
    assert [record["kind"] for record in records][-3:] == [
        "session_ended",
        "session_feedback",
        "session_feedback",
    ]


def test_feedback_storage_primitive_rejects_invalid_category(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    session = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(session)
    write_session_start_record(session)
    with pytest.raises(UsageError) as exc_info:
        append_session_feedback(
            session.id,
            source="agent",
            outcome="completed-smoothly",
            categories=["typo-category"],
        )
    assert exc_info.value.allowed


def test_session_end_returns_agent_and_later_analyst_syntax(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(app, ["session", "start", "--label", "test"])
    assert result.exit_code == 0
    ended = runner.invoke(app, ["session", "end"])
    assert ended.exit_code == 0
    receipt = json.loads(ended.stdout)
    assert "--source agent" in receipt["next_action"]["agent_command_template"]
    assert "--source analyst" in receipt["next_action"]["analyst_command_template"]
    assert "completed-with-friction" in receipt["next_action"]["allowed_outcomes"]
    assert "Never replace prior feedback" in receipt["next_action"]["message"]


def test_parse_failures_are_one_line_and_repair_oriented(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(
        app,
        ["hunt", "run", "DeviceEvents | take 1", "--limit", "2"],
    )
    assert result.exit_code == 6
    assert len(result.stdout.splitlines()) == 1
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "CLI_REMOVED_OPTION"
    assert error["corrected_argv"] == ["xdr", "hunt", "run", "DeviceEvents | take 1"]


def test_removed_option_correction_preserves_adjacent_valid_option(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(
        app,
        ["hunt", "run", "DeviceEvents | take 1", "--jq", "--raw"],
    )
    assert result.exit_code == 6
    error = json.loads(result.stdout)["error"]
    assert error["corrected_argv"] == [
        "xdr",
        "hunt",
        "run",
        "DeviceEvents | take 1",
        "--raw",
    ]


@pytest.mark.parametrize("argv", [[], ["alerts"], ["library"], ["results"], ["schema"]])
def test_no_args_group_help_is_success_not_an_auth_or_usage_failure(
    tmp_path,
    monkeypatch,
    argv,
):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(app, argv)
    assert result.exit_code == 0
    assert "Usage:" in result.stdout
    assert '"status":"error"' not in result.stdout


@pytest.mark.parametrize(
    "argv",
    [
        ["--not-a-real-option"],
        ["alerts", "--not-a-real-option"],
        ["auth", "--not-a-real-option"],
        ["device", "--not-a-real-option"],
        ["domains", "--not-a-real-option"],
        ["history", "--not-a-real-option"],
        ["hunt", "--not-a-real-option"],
        ["incidents", "--not-a-real-option"],
        ["investigate", "--not-a-real-option"],
        ["library", "--not-a-real-option"],
        ["lists", "--not-a-real-option"],
        ["results", "--not-a-real-option"],
        ["schema", "--not-a-real-option"],
        ["session", "--not-a-real-option"],
        ["annotate", "--not-a-real-option"],
    ],
)
def test_every_top_level_surface_has_one_line_parse_errors(
    tmp_path,
    monkeypatch,
    argv,
):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(app, argv)
    assert result.exit_code == 6
    assert len(result.stdout.splitlines()) == 1
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "CLI_UNKNOWN_OPTION"
    assert error["exit_code"] == 6


def test_no_scattered_numeric_typer_exits_remain():
    source_root = Path(__file__).parents[1] / "src" / "xdr_cli"
    pattern = re.compile(r"raise\s+typer\.Exit\s*\(\s*code\s*=")
    offenders = [
        str(path.relative_to(source_root))
        for path in source_root.rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_invalid_enum_lists_exact_allowed_values(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    result = runner.invoke(
        app,
        [
            "session",
            "feedback",
            "missing",
            "--source",
            "robot",
            "--outcome",
            "completed-smoothly",
        ],
    )
    assert result.exit_code == 6
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "CLI_INVALID_ENUM"
    assert error["allowed"] == ["agent", "analyst"]


def test_http_recovery_classes_are_distinct():
    client = XDRClient(get_token=lambda scopes: "token")

    def response(status, body=None, headers=None, url="https://graph.microsoft.com/v1.0/security/x"):
        return httpx.Response(
            status,
            json=body or {"error": {"code": "Error", "message": "failed"}},
            headers=headers,
            request=httpx.Request("GET", url),
        )

    cases = [
        (401, AuthError),
        (403, ForbiddenError),
        (404, NotFoundError),
        (409, ConflictError),
        (429, RateLimitError),
        (400, QueryError),
    ]
    for status, expected in cases:
        url = (
            "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
            if status == 400
            else "https://graph.microsoft.com/v1.0/security/x"
        )
        try:
            client._check_response(response(status, url=url))
        except Exception as error:
            assert isinstance(error, expected)
        else:
            raise AssertionError(f"{status} did not raise")


def test_forbidden_error_names_the_endpoint_permission():
    client = XDRClient(get_token=lambda scopes: "token")
    response = httpx.Response(
        403,
        json={"error": {"code": "Forbidden", "message": "denied"}},
        request=httpx.Request(
            "POST",
            "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
        ),
    )
    with pytest.raises(ForbiddenError) as raised:
        client._check_response(response)
    assert "ThreatHunting.Read.All" in raised.value.message
    assert raised.value.original["type"] == "Forbidden"
    assert raised.value.original["status"] == 403
    assert raised.value.original["message"] == "denied"
    assert "Forbidden" in raised.value.original["detail"]


def test_explicit_token_consent_failure_is_permission_not_auth():
    error = _missing_scope_error(
        "https://graph.microsoft.com/.default",
        "AADSTS65001: consent required",
    )
    assert error.exit_code == ExitCode.PERMISSION_ERROR
    assert error.error_code == "PERMISSION_MISSING_SCOPE"
    assert error.suggestions[0]["reason"] == "admin_consent"


def test_upstream_request_ids_survive_normalization():
    client = XDRClient(get_token=lambda scopes: "token")
    response = httpx.Response(
        500,
        json={
            "error": {
                "code": "InternalError",
                "message": "failed",
                "innerError": {"request-id": "body-id"},
            }
        },
        headers={"client-request-id": "header-id"},
        request=httpx.Request("GET", "https://graph.microsoft.com/v1.0/security/x"),
    )
    try:
        client._check_response(response)
    except Exception as error:
        assert error.request_ids == {
            "client-request-id": "header-id",
            "request-id": "body-id",
        }


def test_malformed_success_body_is_an_upstream_api_error():
    client = XDRClient(get_token=lambda scopes: "token")
    response = httpx.Response(
        200,
        text="<html>not json</html>",
        request=httpx.Request("GET", "https://graph.microsoft.com/v1.0/security/x"),
    )
    with pytest.raises(APIError) as raised:
        client._decode_response(response)
    assert raised.value.error_code == "API_MALFORMED_RESPONSE"
    assert raised.value.exit_code == ExitCode.UPSTREAM_API_ERROR


async def test_transport_and_timeout_are_distinct(monkeypatch):
    client = XDRClient(get_token=lambda scopes: "token", timeout=7)
    transport = AsyncMock()
    transport.request.side_effect = httpx.ConnectError("dns failed")
    try:
        await client._request("GET", transport, "/")
    except Exception as error:
        assert isinstance(error, NetworkError)

    transport.request.side_effect = httpx.ReadTimeout("slow")
    try:
        await client._request("GET", transport, "/")
    except Exception as error:
        assert isinstance(error, TimeoutError)
