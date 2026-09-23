"""Tests for hunt CLI commands."""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from xdr_cli._recording import _parse_execution_time_ms
from xdr_cli.main import app, run

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers (Task 4 integration tests)
# ---------------------------------------------------------------------------


def _seed_session(home_dir, session_id="jd-1"):
    """Write a session_started header so the recorder lands invocations onto
    a well-formed JSONL. Mirrors the helper in test_main.py."""
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


@pytest.fixture
def session_home(tmp_path, monkeypatch):
    """tmp XDR_CLI_HOME plus a seeded jd-1 session targeted by XDR_SESSION."""
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    return home


def _read_invocation(home_dir, session_id="jd-1"):
    """Return the single invocation record from the session JSONL."""
    records = (
        home_dir / "sessions" / f"{session_id}.jsonl"
    ).read_text(encoding="utf-8").splitlines()
    invocations = [json.loads(r) for r in records if json.loads(r)["kind"] == "invocation"]
    assert len(invocations) == 1, f"expected 1 invocation, got {len(invocations)}: {records}"
    return invocations[0]


def _artifact_stdout(output: str):
    return [json.loads(line) for line in output.splitlines()]


def test_hunt_library_lists_queries(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()
    (tmp_path / ".xdr-cli" / "queries").mkdir()

    result = runner.invoke(app, ["hunt", "library"])
    assert result.exit_code == 0
    receipt = json.loads(result.stdout.splitlines()[0])
    rows = [
        json.loads(line)
        for line in Path(receipt["data_path"]).read_text(encoding="utf-8").splitlines()
    ]
    by_name = {row["name"]: row for row in rows}
    names = set(by_name)
    assert "qry_process_tree" in names
    assert "qry_file_hash_scope" in names
    assert "sys_schema_probe" in names
    # Packaged KQL is UTF-8. Reading it through Windows' ANSI code page turns
    # this em dash into mojibake before the artifact is written.
    description = by_name["dns_subdomain_diversity"]["description"]
    assert "—" in description
    assert "â€" not in description


def test_hunt_run_saves_every_api_returned_row(session_home, monkeypatch):
    """Every API-returned row is retained in the durable artifact."""
    from unittest.mock import AsyncMock, patch
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(
        schema=[{"name": "Timestamp", "type": "DateTime"}],
        results=[{"Timestamp": f"2026-04-22T00:00:{i:02d}Z"} for i in range(5)],
        stats={"ExecutionTime": 0.1},
    )
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
    ):
        result = runner.invoke(
            app,
            ["hunt", "run", "DeviceEvents | take 5"],
        )
    assert result.exit_code == 0
    receipt, *previews = _artifact_stdout(result.output)
    assert receipt["rows"] == 5
    assert receipt["server_truncation_state"] == "unknown"
    assert len(previews) == 2
    saved = [
        json.loads(line)
        for line in Path(receipt["data_path"]).read_text(encoding="utf-8").splitlines()
    ]
    assert len(saved) == 5


def test_hunt_run_receipt_marks_upstream_completeness_unknown(session_home, monkeypatch):
    from unittest.mock import AsyncMock, patch
    from xdr_cli.api.hunting import HuntingResult

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
    ):
        result = runner.invoke(
            app,
            ["hunt", "run", "DeviceEvents | take 1"],
        )
    assert result.exit_code == 0
    receipt, preview = _artifact_stdout(result.output)
    assert receipt["server_truncation_state"] == "unknown"
    assert receipt["rows"] == 1
    assert preview["Timestamp"] == "2026-04-22T00:00:00Z"


@patch("xdr_cli.commands.hunt_cmd.AuthManager")
@patch("xdr_cli.commands.hunt_cmd.XDRClient")
def test_hunt_run_inline(mock_client_cls, mock_auth_cls, session_home, monkeypatch):
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        return_value={
            "Schema": [{"Name": "DeviceName", "Type": "String"}],
            "Results": [{"DeviceName": "WS-01"}],
            "Stats": {"ExecutionTime": 0.5},
        }
    )
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["hunt", "run", "DeviceEvents | take 1"])
    assert result.exit_code == 0
    parsed, preview = _artifact_stdout(result.output)
    assert preview["DeviceName"] == "WS-01"
    # ExecutionTime 0.5s in stats → 500ms in metadata.execution_time_ms.
    assert parsed["execution_time_ms"] == 500
    # cpu_usage was always-empty noise from a stats key Defender never returns;
    # dropped in favour of an honest envelope.
    assert "cpu_usage" not in parsed
    # The pre-rename `execution_time` key is gone — caller assertions must
    # migrate to execution_time_ms (which carries an integer, not a float).
    assert "execution_time" not in parsed


def test_hunt_run_expands_rawevent_by_default(session_home, monkeypatch):
    """`hunt run` returns parsed RawEventData unless --raw is passed."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(
        schema=[{"name": "RawEventData"}],
        results=[{"RawEventData": '{"ForwardingSMTPAddress": "x@y.com"}'}],
        stats={},
    )
    mock_client = MagicMock()
    mock_client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.XDRClient", return_value=mock_client),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
    ):
        result = runner.invoke(app, ["hunt", "run", "CloudAppEvents | take 1"])

    assert result.exit_code == 0, result.output
    import json as _json

    parsed = [_json.loads(line) for line in result.stdout.splitlines()]
    assert parsed[1]["RawEventData"] == {"ForwardingSMTPAddress": "x@y.com"}


def test_hunt_run_raw_flag_preserves_json_string(session_home, monkeypatch):
    """`--raw` disables JSON-string column expansion."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from xdr_cli.api.hunting import HuntingResult

    raw_payload = '{"ForwardingSMTPAddress": "x@y.com"}'
    fake = HuntingResult(
        schema=[{"name": "RawEventData"}],
        results=[{"RawEventData": raw_payload}],
        stats={},
    )
    mock_client = MagicMock()
    mock_client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.XDRClient", return_value=mock_client),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
    ):
        result = runner.invoke(app, ["hunt", "run", "CloudAppEvents | take 1", "--raw"])

    assert result.exit_code == 0, result.output
    import json as _json

    parsed = [_json.loads(line) for line in result.stdout.splitlines()]
    assert parsed[1]["RawEventData"] == raw_payload


def test_hunt_run_from_file_strips_frontmatter(session_home, tmp_path, monkeypatch):
    """--from-file must strip `-- key: value` comments before sending to API.

    KQL uses `//` for comments, not `--`. Sending raw frontmatter to the API
    caused `API 400: Missing expression` — so the --from-file path must
    delegate to parse_frontmatter() the same way library queries do.
    """
    kql_file = tmp_path / "custom.kql"
    kql_file.write_text(
        "-- name: custom\n"
        "-- description: handcrafted query\n"
        "-- params:\n"
        "DeviceInfo | take 1\n"
    )

    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(schema=[], results=[], stats={})
    run_query_mock = AsyncMock(return_value=fake)
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.run_query", new=run_query_mock),
    ):
        result = runner.invoke(app, ["hunt", "run", "--from-file", str(kql_file)])

    assert result.exit_code == 0, result.output
    # run_query was called with (client, kql_string); the kql_string must not
    # contain any "-- " frontmatter lines.
    sent_kql = run_query_mock.call_args.args[1]
    assert "-- name:" not in sent_kql
    assert "-- description:" not in sent_kql
    assert "-- params:" not in sent_kql
    assert sent_kql.strip() == "DeviceInfo | take 1"


# ---------------------------------------------------------------------------
# Hunt-specific recorder capture (Task 4)
# ---------------------------------------------------------------------------


def test_hunt_run_records_kql_and_tables(session_home, monkeypatch):
    """`hunt run` in an active session writes kql + tables_referenced."""
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(
        schema=[{"name": "DeviceName", "type": "String"}],
        results=[{"DeviceName": "WS-01"}],
        stats={"ExecutionTime": "00:00:00.250"},
    )
    monkeypatch.setattr(
        sys, "argv", ["xdr", "hunt", "run", "DeviceProcessEvents | take 1"]
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

    inv = _read_invocation(session_home)
    assert inv["kql"] == "DeviceProcessEvents | take 1"
    assert inv["tables_referenced"] == ["DeviceProcessEvents"]
    assert inv["kql_hash"] is not None
    # Plain `hunt run` is not a library query; library_query stays None.
    assert inv["library_query"] is None
    assert inv["params"] == {}


def test_hunt_run_records_result_block(session_home, monkeypatch):
    """`hunt run` annotates the result.* nested block (row_count, sample_rows,
    execution_time_ms parsed from the stats string)."""
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(
        schema=[{"name": "Timestamp", "type": "DateTime"}],
        results=[{"Timestamp": f"2026-04-22T00:00:{i:02d}Z"} for i in range(5)],
        stats={"ExecutionTime": "00:00:01.500"},
    )
    monkeypatch.setattr(
        sys, "argv", ["xdr", "hunt", "run", "DeviceEvents | take 5"]
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

    inv = _read_invocation(session_home)
    res = inv["result"]
    assert res["row_count"] == 5
    assert res["execution_time_ms"] == 1500
    assert res["has_more"] is False
    # Artifact-first execution records a bounded sample from all returned rows.
    assert isinstance(res["sample_rows"], list)
    assert len(res["sample_rows"]) == 3
    assert res["sample_rows"][0]["Timestamp"] == "2026-04-22T00:00:00Z"


def test_hunt_run_columns_projected_from_schema(session_home, monkeypatch):
    """Recorded projected columns derive from the returned API schema."""
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(
        schema=[
            {"name": "Timestamp", "type": "DateTime"},
            {"name": "DeviceName", "type": "String"},
        ],
        results=[{"Timestamp": "2026-04-22T00:00:00Z", "DeviceName": "WS-01"}],
        stats={},
    )
    monkeypatch.setattr(sys, "argv", ["xdr", "hunt", "run", "DeviceInfo | take 1"])
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
        pytest.raises(SystemExit),
    ):
        run()

    inv = _read_invocation(session_home)
    assert inv["columns_projected"] == ["Timestamp", "DeviceName"]


def test_removed_fields_flag_returns_structured_migration_error(session_home):
    result = runner.invoke(
        app,
        ["--fields", "Timestamp", "hunt", "run", "DeviceInfo | take 1"],
    )
    assert result.exit_code == 6
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "CLI_REMOVED_OPTION"
    assert error["corrected_argv"] == [
        "xdr", "hunt", "run", "DeviceInfo | take 1",
    ]


def test_hunt_library_run_records_library_name_and_params(session_home, monkeypatch):
    """`hunt library-run` propagates the query name and params dict to the
    recorder."""
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(
        schema=[{"name": "Timestamp"}],
        results=[],
        stats={},
    )
    # qry_process_tree declares params: device_name (required), hours=1.
    # Pass device_name through to verify params land in the recorder. (Was
    # previously sys_schema_probe + -p table=DeviceInfo, but that query
    # declares no params so the loader's unknown-param rejection now
    # correctly raises.)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "xdr",
            "hunt",
            "library-run",
            "qry_process_tree",
            "-p",
            "device_name=host01",
        ],
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

    inv = _read_invocation(session_home)
    assert inv["library_query"] == "qry_process_tree"
    assert inv["params"] == {"device_name": "host01"}


def test_hunt_run_no_session_auto_creates_before_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli" / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.delenv("XDR_SESSION", raising=False)

    result = runner.invoke(app, ["hunt", "run", "DeviceInfo | take 1"])
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "")
    assert "no active session" not in combined.lower()
    assert list((tmp_path / ".xdr-cli" / "sessions").glob("*.jsonl"))


def test_hunt_run_sample_rows_expanded_without_raw(session_home, monkeypatch):
    """Default (no --raw): sample_rows[i].RawEventData is an expanded object,
    matching what the operator saw on stdout."""
    from xdr_cli.api.hunting import HuntingResult

    raw_payload = '{"ForwardingSMTPAddress": "x@y.com"}'
    fake = HuntingResult(
        schema=[{"name": "RawEventData"}],
        results=[{"RawEventData": raw_payload}],
        stats={},
    )
    monkeypatch.setattr(
        sys, "argv", ["xdr", "hunt", "run", "CloudAppEvents | take 1"]
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

    inv = _read_invocation(session_home)
    sample = inv["result"]["sample_rows"]
    assert len(sample) == 1
    assert sample[0]["RawEventData"] == {"ForwardingSMTPAddress": "x@y.com"}


def test_hunt_run_sample_rows_raw_strings_with_raw_flag(session_home, monkeypatch):
    """With --raw: sample_rows mirrors stdout — RawEventData stays a string."""
    from xdr_cli.api.hunting import HuntingResult

    raw_payload = '{"ForwardingSMTPAddress": "x@y.com"}'
    fake = HuntingResult(
        schema=[{"name": "RawEventData"}],
        results=[{"RawEventData": raw_payload}],
        stats={},
    )
    monkeypatch.setattr(
        sys, "argv", ["xdr", "hunt", "run", "CloudAppEvents | take 1", "--raw"]
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

    inv = _read_invocation(session_home)
    sample = inv["result"]["sample_rows"]
    assert len(sample) == 1
    assert sample[0]["RawEventData"] == raw_payload  # unparsed string


# ---------------------------------------------------------------------------
# _parse_execution_time_ms direct unit tests (Task 4 follow-up)
# ---------------------------------------------------------------------------


class TestParseExecutionTimeMs:
    """Unit-level coverage for each branch of ``_parse_execution_time_ms``.

    The end-to-end hunt-run tests above only exercise the duration-string
    happy path. These tests pin down all four observable shapes the helper
    must accept (and the one shape it must reject), so future refactors
    don't silently drop a branch.
    """

    def test_duration_string_parses_to_milliseconds(self):
        # ``HH:MM:SS.fff`` → integer ms, including the fractional component.
        assert _parse_execution_time_ms("00:00:00.123") == 123

    def test_numeric_seconds_path(self):
        # Some fixtures / older responses surface ExecutionTime as a float
        # (seconds). Multiply by 1000, round to int.
        assert _parse_execution_time_ms(1.5) == 1500

    def test_none_passthrough(self):
        # Missing ExecutionTime in stats → None straight back.
        assert _parse_execution_time_ms(None) is None

    def test_unparseable_string_returns_none(self):
        # Anything we cannot interpret falls through to None — never a
        # half-parsed integer that downstream consumers would mistake for
        # a real measurement.
        assert _parse_execution_time_ms("not a duration") is None


# ---------------------------------------------------------------------------
# `xdr hunt library` param rendering (Task 11 Bug 2)
# ---------------------------------------------------------------------------


def test_hunt_library_renders_three_param_states_distinctly(tmp_path, monkeypatch):
    """The library listing must distinguish `None` (required) from `""`
    (declared empty default — scope-pass-through idiom) from a non-empty
    default.

    `qry_inbox_rule_activity` declares `hours=168, account_upn=, mode=summary`,
    covering all three QueryParam.default states:

      - hours       -> "(168)"     (declared default)
      - account_upn -> "()"        (declared empty default)
      - mode        -> "(summary)" (declared default)

    Prior to the fix, `account_upn=""` rendered as `account_upn=required`
    because `if p.default` is False on empty strings — inverting the loader's
    three-state contract documented in xdr_cli/queries/__init__.py.

    To also cover the `None` (truly required) case, we synthesize a query
    with one missing-default param via QueryInfo/QueryParam directly.
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    from xdr_cli.queries import QueryInfo, QueryParam

    fake_required = QueryInfo(
        name="qry_required_only",
        description="synthetic required-only param",
        params=[QueryParam(name="device_id", default=None)],
        source="builtin",
    )

    with patch(
        "xdr_cli.commands.library_cmd.list_queries",
        return_value=[fake_required],
    ):
        result = runner.invoke(app, ["hunt", "library"])
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    rows = [
        json.loads(line)
        for line in Path(receipt["data_path"]).read_text(encoding="utf-8").splitlines()
    ]
    rendered = {q["name"]: q["parameters"] for q in rows}
    # None (no `=` declared) → "required"
    assert rendered["qry_required_only"][0]["required"] is True

    # Now exercise the full three-state contract with a real built-in query.
    result2 = runner.invoke(app, ["hunt", "library"])
    assert result2.exit_code == 0, result2.output
    receipt2 = json.loads(result2.stdout.splitlines()[0])
    rows2 = [
        json.loads(line)
        for line in Path(receipt2["data_path"]).read_text(encoding="utf-8").splitlines()
    ]
    by_name = {q["name"]: q["parameters"] for q in rows2}
    inbox = by_name.get("qry_inbox_rule_activity")
    assert inbox is not None, f"qry_inbox_rule_activity missing from listing: {list(by_name)}"

    # Declared default with value → "(168)" / "(summary)"
    defaults = {param["name"]: param["default"] for param in inbox}
    assert defaults["hours"] == "168"
    assert defaults["account_upn"] == ""
    assert defaults["mode"] == "summary"
    assert next(p for p in inbox if p["name"] == "account_upn")["required"] is False


# ---------------------------------------------------------------------------
# hunt library-show — render a query without executing it
# ---------------------------------------------------------------------------


def test_hunt_library_show_prints_rendered_kql(tmp_path, monkeypatch):
    """`library-show <name> -p key=value` prints the substituted KQL to stdout
    without contacting the API. Useful for debugging substitution / pasting
    into the Defender GUI."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    user_queries = tmp_path / ".xdr-cli" / "queries"
    user_queries.mkdir(parents=True)
    (user_queries / "synth_show.kql").write_text(
        "-- name: synth_show\n"
        "-- description: synthetic query for library-show test\n"
        "-- tier: r1\n"
        "-- params: hours=24, account_upn=\n"
        "DeviceInfo\n"
        "| where Timestamp > ago({hours}h)\n"
        "| where '{account_upn}' == '' or AccountUpn =~ '{account_upn}'\n"
    )

    result = runner.invoke(
        app,
        [
            "hunt",
            "library-show",
            "synth_show",
            "-p",
            "account_upn=alice@corp.com",
            "-p",
            "hours=72",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ago(72h)" in result.output
    assert "AccountUpn =~ 'alice@corp.com'" in result.output


def test_hunt_run_execution_time_falls_back_to_wall_clock(session_home, monkeypatch):
    """Graph's runHuntingQuery returns no `stats` field at all. When stats
    is empty, metadata.execution_time_ms must fall back to client-measured
    wall-clock instead of being None — the field is the operator's primary
    signal for "how long did this take" and is always populated."""
    from unittest.mock import AsyncMock, patch
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(
        schema=[{"name": "DeviceName"}],
        results=[{"DeviceName": "WS-01"}],
        stats={},  # Graph response shape — no ExecutionTime.
    )
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
    ):
        result = runner.invoke(
            app, ["hunt", "run", "DeviceEvents | take 1"]
        )
    assert result.exit_code == 0, result.output
    parsed = _artifact_stdout(result.output)[0]
    et = parsed["execution_time_ms"]
    assert isinstance(et, int) and et >= 0, et


def test_hunt_run_timeout_flag_overrides_config(session_home, monkeypatch):
    """`--timeout 240` must construct XDRClient with timeout=240, not the
    config default. Library hunts with summarise/join chains routinely run
    past the default — the per-call override is the escape hatch.
    """
    from unittest.mock import AsyncMock, MagicMock, patch
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(schema=[], results=[], stats={})

    captured_kwargs: dict = {}

    def capture_client(**kwargs):
        captured_kwargs.update(kwargs)
        client = MagicMock()
        client.close = AsyncMock()
        return client

    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.XDRClient", side_effect=capture_client),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
    ):
        result = runner.invoke(
            app,
            ["hunt", "run", "DeviceInfo | take 1", "--timeout", "240"],
        )
    assert result.exit_code == 0, result.output
    assert captured_kwargs.get("timeout") == 240, captured_kwargs


def test_hunt_library_run_timeout_flag_overrides_config(session_home, monkeypatch):
    """Same override contract for `library-run --timeout`."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from xdr_cli.api.hunting import HuntingResult

    fake = HuntingResult(schema=[], results=[], stats={})
    captured_kwargs: dict = {}

    def capture_client(**kwargs):
        captured_kwargs.update(kwargs)
        client = MagicMock()
        client.close = AsyncMock()
        return client

    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.XDRClient", side_effect=capture_client),
        patch(
            "xdr_cli.commands.hunt_cmd.run_query",
            new=AsyncMock(return_value=fake),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "hunt",
                "library-run",
                "qry_process_tree",
                "-p",
                "device_name=host01",
                "--timeout",
                "300",
            ],
        )
    assert result.exit_code == 0, result.output
    assert captured_kwargs.get("timeout") == 300, captured_kwargs


def test_hunt_library_show_unknown_query_errors(tmp_path, monkeypatch):
    """Unknown query names exit non-zero with a QueryError naming the query."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli" / "queries").mkdir(parents=True)

    result = runner.invoke(app, ["hunt", "library-show", "no_such_query"])
    assert result.exit_code != 0
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "QUERY_ERROR"
    assert "no_such_query" in error["message"]
