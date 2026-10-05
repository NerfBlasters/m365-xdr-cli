import asyncio
import hashlib
from unittest.mock import AsyncMock, patch

import pytest

from xdr_cli._lock import exclusive_lock
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    AuthError,
    ConflictError,
    LocalNotFoundError,
    PartialSuccessError,
    RateLimitError,
    TimeoutError as XDRTimeoutError,
)
from xdr_cli.results import write_result
from xdr_cli.schema_graph.session_maintenance import collect_session_schema


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    return AppContext(Config(tenant_id="tenant", schema_explore_max_queries=2), quiet=True)


def stage_result(callback, command, *, remaining=0):
    callback(
        write_result(
            [],
            command=command,
            tenant_id="tenant",
            receipt_context={"queries_executed": 1, "remaining_queries": remaining},
        )
    )


@pytest.mark.parametrize("cache_state", ["fresh", "stale", "missing"])
def test_refresh_precedes_validation_and_budgeted_exploration(ctx, cache_state, capsys):
    events, results = [], []

    async def refresh(ctx, *, on_result):
        events.append("refresh")
        stage_result(on_result, "schema refresh")

    async def validate(ctx, **kwargs):
        events.append("validation")
        assert kwargs["mark_complete"] is False
        stage_result(kwargs["on_result"], "schema collect")

    async def explore(ctx, **kwargs):
        events.append("exploration")
        assert kwargs["max_queries"] == 2
        assert kwargs["mark_complete"] is False
        stage_result(kwargs["on_result"], "schema collect")

    initial = ([], {"stale": cache_state != "fresh"})
    if cache_state == "missing":
        initial = LocalNotFoundError("schema cache", "tenant")
    with (
        patch(
            "xdr_cli.commands.schema_cmd._load_cache", side_effect=[initial, ([], {"stale": False})]
        ),
        patch("xdr_cli.commands.schema_cmd._schema_refresh", side_effect=refresh),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=validate),
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers", side_effect=explore),
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
    ):
        collect_session_schema(ctx, on_result=results.append)
    assert events == (["refresh"] if cache_state != "fresh" else []) + ["validation", "exploration"]
    assert not capsys.readouterr().out
    assert len(results) == 1
    assert results[0].receipt.context["queries_executed"] == len(events)
    complete.assert_called_once()


def test_stage_toggles_skip_network_work_but_keep_validation(ctx):
    ctx.config.schema_refresh_on_session_end = False
    ctx.config.schema_explore_on_session_end = False
    results = []
    with (
        patch(
            "xdr_cli.commands.schema_cmd._load_cache", side_effect=LocalNotFoundError("cache", "x")
        ),
        patch("xdr_cli.commands.schema_cmd._schema_refresh", new_callable=AsyncMock) as refresh,
        patch(
            "xdr_cli.schema_graph.local_collection.collect_local", new_callable=AsyncMock
        ) as local,
        patch(
            "xdr_cli.schema_graph.discovery.explore_saved_identifiers", new_callable=AsyncMock
        ) as explore,
    ):
        collect_session_schema(ctx, on_result=results.append)
    local.assert_awaited_once()
    refresh.assert_not_called()
    explore.assert_not_called()
    stages = results[0].receipt.context["stages"]
    assert stages["refresh"]["reason"] == stages["exploration"]["reason"] == "disabled"


def test_validation_budget_pause_does_not_starve_exploration(ctx):
    async def validate(ctx, **kwargs):
        stage_result(kwargs["on_result"], "schema collect", remaining=10)
        raise PartialSuccessError("budget", help_command="xdr schema collect")

    results = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": False})),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=validate),
        patch(
            "xdr_cli.schema_graph.discovery.explore_saved_identifiers", new_callable=AsyncMock
        ) as explore,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
        pytest.raises(PartialSuccessError),
    ):
        collect_session_schema(ctx, on_result=results.append)
    explore.assert_awaited_once()
    complete.assert_not_called()
    assert results[0].receipt.context["stages"]["validation"]["status"] == "partial"


@pytest.mark.parametrize(
    "error", [AuthError("auth"), RateLimitError(retry_after=90)]
)
def test_validation_upstream_failure_stops_exploration(ctx, error):
    async def validate(ctx, **kwargs):
        stage_result(kwargs["on_result"], "schema collect", remaining=10)
        raise PartialSuccessError(
            "stopped", retry_after_seconds=error.retry_after_seconds
        ) from error

    results = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": False})),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=validate),
        patch(
            "xdr_cli.schema_graph.discovery.explore_saved_identifiers", new_callable=AsyncMock
        ) as explore,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
        pytest.raises(PartialSuccessError) as exc,
    ):
        collect_session_schema(ctx, on_result=results.append)
    assert exc.value.__cause__ is error
    explore.assert_not_called()
    complete.assert_not_called()
    assert results[0].receipt.context["stages"]["exploration"]["reason"] == "previous-stage-failed"


def test_refresh_failure_preserves_stage_receipt_and_stops(ctx):
    results = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": True})),
        patch(
            "xdr_cli.commands.schema_cmd._schema_refresh",
            new_callable=AsyncMock,
            side_effect=AuthError("private"),
        ),
        patch(
            "xdr_cli.schema_graph.local_collection.collect_local", new_callable=AsyncMock
        ) as local,
        pytest.raises(AuthError),
    ):
        collect_session_schema(ctx, on_result=results.append)
    local.assert_not_called()
    assert results[0].receipt.context["stages"]["refresh"]["status"] == "failed"


def test_pipeline_lock_prevents_duplicate_refresh(ctx, tmp_path):
    root = tmp_path / "schema" / hashlib.sha256(b"tenant").hexdigest()[:12]
    root.mkdir(parents=True)
    with (
        exclusive_lock(root / ".session-maintenance", timeout=0),
        patch("xdr_cli.commands.schema_cmd._load_cache") as load,
        pytest.raises(ConflictError),
    ):
        collect_session_schema(ctx)
    load.assert_not_called()


@pytest.mark.parametrize("blocked_stage", ["refresh", "validation", "exploration"])
def test_deadline_stops_queries_saves_prior_receipts_and_skips_future_stages(ctx, blocked_stage):
    # Leave room for local artifact writes and scheduling on loaded CI hosts.
    # The blocked operation still exceeds the complete shared budget.
    ctx.config.schema_maintenance_timeout_seconds = 0.2
    results, events = [], []

    def stage(name):
        async def run(ctx, **kwargs):
            events.append(name)
            if name == blocked_stage:
                await asyncio.sleep(0.8)
            stage_result(kwargs["on_result"], f"schema {name}")
        return run

    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": True})),
        patch("xdr_cli.commands.schema_cmd._schema_refresh", side_effect=stage("refresh")),
        patch(
            "xdr_cli.schema_graph.local_collection.collect_local", side_effect=stage("validation")
        ),
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers",
              side_effect=stage("exploration")),
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
        pytest.raises(XDRTimeoutError) as exc,
    ):
        collect_session_schema(ctx, on_result=results.append)
    assert exc.value.exit_code == 10
    assert exc.value.error_code == "SESSION_SCHEMA_MAINTENANCE_TIMEOUT"
    assert len(results) == 1
    context = results[0].receipt.context
    stages = context["stages"]
    names = ["refresh", "validation", "exploration"]
    position = names.index(blocked_stage)
    assert events == names[:position + 1]
    assert stages[blocked_stage]["status"] == "failed"
    assert all(stages[name]["status"] == "success" for name in names[:position])
    assert all(stages[name]["status"] == "skipped" for name in names[position + 1:])
    assert context["maintenance_timeout_seconds"] == 0.2
    complete.assert_not_called()


def test_deadline_is_shared_across_stages_not_reset_for_each_query(ctx):
    # Each stage fits individually; their combined delay exceeds the shared
    # deadline. Avoid making correctness depend on sub-50 ms filesystem latency.
    ctx.config.schema_maintenance_timeout_seconds = 0.5
    results = []

    async def consume_budget(ctx, **kwargs):
        await asyncio.sleep(0.3)
        stage_result(kwargs["on_result"], "schema refresh")

    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": True})),
        patch("xdr_cli.commands.schema_cmd._schema_refresh", side_effect=consume_budget),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=consume_budget),
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers") as explore,
        pytest.raises(XDRTimeoutError),
    ):
        collect_session_schema(ctx, on_result=results.append)
    assert results[0].receipt.context["stages"]["refresh"]["status"] == "success"
    assert results[0].receipt.context["stages"]["validation"]["status"] == "failed"
    explore.assert_not_called()
