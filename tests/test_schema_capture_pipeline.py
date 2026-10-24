"""CLI and foreground automatic capture workflow contracts."""

from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.main import app
from xdr_cli.schema_graph.capture_orchestration import explore_recent_data
from xdr_cli.schema_graph.loader import load_packaged_graph


@pytest.mark.parametrize(
    "arguments,expected",
    [
        (["--explore"], {"lookback": "24h", "max_queries": 300}),
        (
            ["--explore", "--lookback", "2h", "--max-queries", "80"],
            {"lookback": "2h", "max_queries": 80},
        ),
        (["--explore", "--max-queries-per-page", "7"], {"lookback": "24h", "max_queries": 7}),
    ],
)
def test_cli_capture_defaults_and_legacy_budget(arguments, expected, tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="synthetic")),
        patch(
            "xdr_cli.schema_graph.capture_orchestration.explore_recent_data", new_callable=AsyncMock
        ) as run,
    ):
        result = CliRunner().invoke(app, ["schema", "collect", *arguments])
    assert result.exit_code == 0, result.output
    for key, value in expected.items():
        assert run.call_args.kwargs[key] == value


def test_cli_rejects_ambiguous_total_budgets(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="synthetic")):
        result = CliRunner().invoke(
            app,
            ["schema", "collect", "--explore", "--max-queries", "8", "--max-queries-per-page", "9"],
        )
    assert result.exit_code == 6


@pytest.mark.asyncio
async def test_plan_only_uses_cached_schema_without_network_or_overlay_publish(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    rows = [
        {"TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime"},
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": "string"},
        {"TableName": "ExposureGraphNodes", "ColumnName": "NodeId", "ColumnType": "string"},
    ]
    receipts = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {"stale": True})),
        patch("xdr_cli.commands.schema_cmd._schema_refresh", new_callable=AsyncMock) as refresh,
        patch("xdr_cli.schema_graph.capture_orchestration.create_client") as client,
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            plan_only=True,
            on_result=receipts.append,
        )
    refresh.assert_not_awaited()
    client.assert_not_called()
    assert receipts[0].receipt.context["networked"] is False
    assert receipts[0].receipt.context["horizon"] == "24h"
    assert receipts[0].receipt.rows == 2
    assert not list((tmp_path / "schema").glob("*/semantic.current.json"))


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupted_handoff", [False, True, "retired"])
async def test_actual_engine_sink_and_local_graph_work_without_saved_seed_results(
    tmp_path, monkeypatch, interrupted_handoff
):
    import re
    from contextlib import nullcontext

    from xdr_cli.backend_contract import OFFICIAL_PROFILE
    from xdr_cli.hunting_result import HuntingResult
    from xdr_cli.schema_graph.overlay import load_tenant_overlay

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    rows = [
        {"TableName": table, "ColumnName": "AccountUpn", "ColumnType": "string"}
        for table in ("FirstState", "SecondState")
    ]
    identifiers = ["one@example.com", "two@example.com", "three@example.com"]

    class Client:
        profile = OFFICIAL_PROFILE
        close = AsyncMock()

        async def execute_hunting(self, query):
            if query.startswith("union"):
                results = []
                for body, label in re.findall(r'\((.*?)\| extend XdrArm="([^"]+)"\)', query, re.S):
                    if "AvgBytes" in body:
                        results.append(
                            {"XdrArm": label, "AvgBytes": 100, "MaxBytes": 100, "Sampled": 3}
                        )
                    else:
                        results.append({"XdrArm": label, "Rows": 3})
            else:
                results = [
                    {
                        "__xdr_control": "v2",
                        "__xdr_more": 0,
                        "__xdr_count": 3,
                        "__xdr_bytes": 300,
                        "__xdr_total": 3,
                        "__xdr_floor": None,
                    },
                    *[
                        {
                            "__xdr_row": {
                                "AccountUpn": value,
                                "RecordType": "First" if "FirstState" in query else "Second",
                            }
                        }
                        for value in identifiers
                    ],
                ]
            return HuntingResult(
                schema=[], stats={}, results=results, metadata={"execution_surface": "graph"}
            )

    receipts = []
    client = Client()
    with (
        patch(
            "xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {"generation": "test"})
        ),
        patch("xdr_cli.schema_graph.capture_orchestration.create_client", return_value=client),
        patch("xdr_cli.schema_graph.capture_engine.mark_capture_consumed")
        if interrupted_handoff
        else nullcontext(),
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic-capture-pipeline")),
            canonical=load_packaged_graph(),
            on_result=receipts.append,
        )
    assert len(receipts) == 1
    context = receipts[0].receipt.context
    assert context["scope_complete"] is True
    assert context["capture"]["source_artifacts"] == 2
    assert context["capture"]["counters"]["rows"] == 6
    overlay = load_tenant_overlay("synthetic-capture-pipeline")
    assert len(overlay.observations) == 1
    assert overlay.observations[0].matched_seeds == 3
    assert overlay.observations[0].extra["evidence_stage"] == "capture-overlap-complete"
    assert context["local_result"]["context"]["validation_skipped_complete_capture_pairs"] == 1
    assert context["validation_queries_attempted"] == 0
    assert client.close.await_count == 1
    from xdr_cli.commands.results_cmd import _schema_evidence_references
    from xdr_cli.exceptions import ArtifactError

    protected = _schema_evidence_references()
    assert len(protected.capture_run_ids) == (2 if interrupted_handoff else 0)
    if interrupted_handoff:
        ledger = next((tmp_path / "schema").glob("*/capture-jobs/cap-*.json"))
        saved_ledger = ledger.read_bytes()
        ledger.write_text("{corrupt")
        with pytest.raises(ArtifactError):
            _schema_evidence_references()
        ledger.write_bytes(saved_ledger)
        if interrupted_handoff == "retired":
            from datetime import UTC, datetime

            from xdr_cli.schema_graph.overlay import publish_tenant_overlay

            publish_tenant_overlay(
                "synthetic-capture-pipeline", discovery_retired_before=datetime.now(UTC).isoformat()
            )
        rerun = []
        from xdr_cli.exceptions import PartialSuccessError

        with (
            patch(
                "xdr_cli.commands.schema_cmd._load_cache",
                return_value=(rows, {"generation": "test"}),
            ),
            patch("xdr_cli.schema_graph.capture_orchestration.create_client", return_value=client),
            pytest.raises(PartialSuccessError)
            if interrupted_handoff == "retired"
            else nullcontext(),
        ):
            await explore_recent_data(
                AppContext(Config(tenant_id="synthetic-capture-pipeline")),
                canonical=load_packaged_graph(),
                on_result=rerun.append,
            )
        assert rerun[0].receipt.context["capture"]["counters"]["queries"] == 0
        assert _schema_evidence_references().capture_run_ids == frozenset()
        if interrupted_handoff == "retired":
            # Explicit retirement releases its pins without reviving historical
            # data. A later fresh job must not repeat the retired-source partial.
            assert not load_tenant_overlay("synthetic-capture-pipeline").observations
            again = []
            with (
                patch(
                    "xdr_cli.commands.schema_cmd._load_cache",
                    return_value=(rows, {"generation": "test"}),
                ),
                patch(
                    "xdr_cli.schema_graph.capture_orchestration.create_client", return_value=client
                ),
            ):
                await explore_recent_data(
                    AppContext(Config(tenant_id="synthetic-capture-pipeline")),
                    canonical=load_packaged_graph(),
                    on_result=again.append,
                )
            assert again[0].receipt.context["scope_complete"] is True
            assert again[0].receipt.context["stage_failures"] == []
            assert _schema_evidence_references().capture_run_ids == frozenset()
        if interrupted_handoff == "retired":
            assert rerun[0].receipt.context["retired_capture_sources"] == 2
            assert not rerun[0].receipt.context["scope_complete"]


@pytest.mark.asyncio
async def test_refresh_consuming_final_query_budget_pauses_without_an_extra_request(
    tmp_path, monkeypatch
):
    from xdr_cli.exceptions import PartialSuccessError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    rows = [{"TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime"}]
    receipts = []
    with (
        patch(
            "xdr_cli.commands.schema_cmd._load_cache",
            side_effect=[(rows, {"stale": True}), (rows, {"stale": False})],
        ),
        patch("xdr_cli.commands.schema_cmd._schema_refresh", new_callable=AsyncMock) as refresh,
        patch("xdr_cli.schema_graph.capture_orchestration.create_client") as client,
        pytest.raises(PartialSuccessError),
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            max_queries=1,
            on_result=receipts.append,
        )
    refresh.assert_awaited_once()
    client.assert_not_called()
    assert len(receipts) == 1
    assert receipts[0].receipt.context["queries_used"] == 1
    assert receipts[0].receipt.context["capture"]["stop"]["kind"] == "budget-queries"


@pytest.mark.asyncio
async def test_capture_quota_pause_forbids_validation_and_followup_network(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from xdr_cli.backend_contract import OFFICIAL_PROFILE
    from xdr_cli.exceptions import PartialSuccessError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    rows = [{"TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime"}]
    report = {
        "job_id": "cap-job",
        "status": "paused",
        "resumed": False,
        "interval": {},
        "stop": {"kind": "rate-limited", "retry_after_seconds": 900},
        "counters": {"queries": 1},
        "captured_run_ids": [],
        "tables": [{"table": "DeviceInfo", "time_column": "Timestamp", "status": "pending"}],
    }
    client = SimpleNamespace(profile=OFFICIAL_PROFILE, close=AsyncMock())
    receipts = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {})),
        patch("xdr_cli.schema_graph.capture_orchestration.create_client", return_value=client),
        patch(
            "xdr_cli.schema_graph.capture_engine.capture_recent",
            new_callable=AsyncMock,
            return_value=report,
        ),
        patch("xdr_cli.schema_graph.local_collection.create_client") as validate_client,
        patch(
            "xdr_cli.schema_graph.discovery.explore_saved_identifiers", new_callable=AsyncMock
        ) as followup,
        pytest.raises(PartialSuccessError) as error,
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            on_result=receipts.append,
        )
    validate_client.assert_not_called()
    followup.assert_not_awaited()
    assert error.value.retry_after_seconds == 900
    assert len(receipts) == 1
    assert receipts[0].receipt.context["scope_complete"] is False


@pytest.mark.asyncio
async def test_refresh_deadline_preserves_typed_timeout(tmp_path, monkeypatch):
    import asyncio

    from xdr_cli.exceptions import TimeoutError as XDRTimeoutError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))

    async def slow_refresh(*args, **kwargs):
        await asyncio.sleep(1)

    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": True})),
        patch("xdr_cli.commands.schema_cmd._schema_refresh", side_effect=slow_refresh),
        pytest.raises(XDRTimeoutError),
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            deadline=0.01,
        )


@pytest.mark.asyncio
async def test_followup_auth_failure_preserves_original_error_after_receipt(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from xdr_cli.backend_contract import OFFICIAL_PROFILE
    from xdr_cli.exceptions import AuthError, PartialSuccessError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    rows = [{"TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime"}]
    report = {
        "job_id": None,
        "status": "partial",
        "interval": {},
        "stop": None,
        "counters": {"queries": 1},
        "captured_run_ids": [],
        "tables": [{"table": "DeviceInfo", "time_column": "Timestamp", "status": "partial"}],
    }
    original = AuthError("synthetic auth failure")

    async def failure(*args, **kwargs):
        raise PartialSuccessError("saved progress") from original

    receipts = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {})),
        patch(
            "xdr_cli.schema_graph.capture_orchestration.create_client",
            return_value=SimpleNamespace(profile=OFFICIAL_PROFILE, close=AsyncMock()),
        ),
        patch(
            "xdr_cli.schema_graph.capture_engine.capture_recent",
            new_callable=AsyncMock,
            return_value=report,
        ),
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers", side_effect=failure),
        pytest.raises(AuthError) as error,
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            on_result=receipts.append,
        )
    assert error.value is original
    assert len(receipts) == 1
    assert receipts[0].receipt.context["scope_complete"] is False


@pytest.mark.asyncio
async def test_complete_scan_with_unindexed_capture_keeps_pins(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from xdr_cli.backend_contract import OFFICIAL_PROFILE
    from xdr_cli.exceptions import PartialSuccessError
    from xdr_cli.results import write_result

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    report = {
        "job_id": "cap-20261024T000000Z-12345678",
        "status": "complete",
        "interval": {},
        "stop": None,
        "counters": {"queries": 1},
        "captured_run_ids": ["missing-run"],
        "tables": [],
    }

    async def skipped_source(ctx, **options):
        options["on_result"](
            write_result(
                [],
                command="schema collect",
                tenant_id="synthetic",
                receipt_context={
                    "scope_complete": False,
                    "local_coverage": {
                        "complete": True,
                        "required_sources_complete": False,
                        "unindexed_required_sources": 1,
                    },
                },
            )
        )
        raise PartialSuccessError("required capture source could not be indexed")

    receipts = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {})),
        patch(
            "xdr_cli.schema_graph.capture_orchestration.create_client",
            return_value=SimpleNamespace(profile=OFFICIAL_PROFILE, close=AsyncMock()),
        ),
        patch(
            "xdr_cli.schema_graph.capture_engine.capture_recent",
            new_callable=AsyncMock,
            return_value=report,
        ),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=skipped_source),
        patch("xdr_cli.schema_graph.capture_engine.mark_capture_consumed") as consumed,
        pytest.raises(PartialSuccessError),
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            on_result=receipts.append,
        )
    consumed.assert_not_called()
    assert receipts[0].receipt.context["scope_complete"] is False
    assert not receipts[0].receipt.context.get("capture_handoff_ready")


@pytest.mark.asyncio
async def test_handoff_lock_conflict_after_receipt_is_partial_with_pins_retained(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from xdr_cli.backend_contract import OFFICIAL_PROFILE
    from xdr_cli.exceptions import ConflictError, PartialSuccessError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    report = {
        "job_id": "cap-20261024T000000Z-12345678",
        "status": "complete",
        "interval": {},
        "stop": None,
        "counters": {"queries": 0},
        "captured_run_ids": [],
        "tables": [],
    }
    receipts = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {})),
        patch(
            "xdr_cli.schema_graph.capture_orchestration.create_client",
            return_value=SimpleNamespace(profile=OFFICIAL_PROFILE, close=AsyncMock()),
        ),
        patch(
            "xdr_cli.schema_graph.capture_engine.capture_recent",
            new_callable=AsyncMock,
            return_value=report,
        ),
        patch(
            "xdr_cli.schema_graph.capture_engine.mark_capture_consumed",
            side_effect=ConflictError("synthetic contention"),
        ),
        pytest.raises(PartialSuccessError) as error,
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            on_result=receipts.append,
        )
    assert len(receipts) == 1
    assert isinstance(error.value.__cause__, ConflictError)
    assert "Evidence remains protected" in error.value.message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "budget,capture_budget,reserve", [(1, 1, 0), (2, 1, 1), (5, 4, 1), (30, 24, 6), (300, 250, 50)]
)
async def test_large_capture_cannot_starve_focused_validation_budget(
    tmp_path, monkeypatch, budget, capture_budget, reserve
):
    from types import SimpleNamespace

    from xdr_cli.backend_contract import OFFICIAL_PROFILE

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    report = {
        "job_id": None,
        "status": "complete",
        "interval": {},
        "stop": None,
        "counters": {"queries": 0},
        "captured_run_ids": [],
        "tables": [],
    }
    receipts = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {})),
        patch(
            "xdr_cli.schema_graph.capture_orchestration.create_client",
            return_value=SimpleNamespace(profile=OFFICIAL_PROFILE, close=AsyncMock()),
        ),
        patch(
            "xdr_cli.schema_graph.capture_engine.capture_recent",
            new_callable=AsyncMock,
            return_value=report,
        ) as capture,
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            on_result=receipts.append,
            max_queries=budget,
        )
    assert capture.await_args.kwargs["budgets"].max_queries == capture_budget
    assert receipts[0].receipt.context["query_allocation"] == {
        "capture": capture_budget,
        "validation_reserved": reserve,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "delay,budget,expected_calls", [(20, 5, 2), (0, 5, 2), (121, 5, 1), (20, 1, 1)]
)
async def test_validation_retry_honors_delay_and_remaining_query_budget(
    delay, budget, expected_calls
):
    import time
    from types import SimpleNamespace

    from xdr_cli.exceptions import PartialSuccessError, RateLimitError
    from xdr_cli.schema_graph.capture_orchestration import _collect_with_retry

    calls = []

    async def collect(ctx, **options):
        calls.append(options)
        options["on_result"](
            SimpleNamespace(receipt=SimpleNamespace(context={"queries_attempted": 1}))
        )
        if len(calls) == 1:
            raise PartialSuccessError("saved", retry_after_seconds=delay) from RateLimitError(delay)

    with patch(
        "xdr_cli.schema_graph.capture_orchestration.asyncio.sleep", new_callable=AsyncMock
    ) as sleep:
        receipts, attempted, retries, waited, failure = await _collect_with_retry(
            collect,
            None,
            options={"_query_timeout": 30},
            deadline_at=time.monotonic() + 300,
            max_queries=budget,
            local_only=False,
            on_progress=lambda message: None,
        )
    assert len(calls) == expected_calls
    assert attempted == expected_calls
    assert len(receipts) == expected_calls
    if expected_calls == 2:
        sleep.assert_awaited_once_with(max(5, delay))
        assert calls[1]["max_queries"] == budget - 1
        assert calls[1]["timeout"] == 30
        assert (retries, waited, failure) == (1, max(5, delay), None)
    else:
        sleep.assert_not_awaited()
        assert retries == waited == 0
        assert isinstance(failure, PartialSuccessError)


@pytest.mark.asyncio
async def test_validation_retry_preserves_auth_error_and_deadline():
    import time

    from xdr_cli.exceptions import AuthError, PartialSuccessError, RateLimitError
    from xdr_cli.schema_graph.capture_orchestration import _collect_with_retry

    for original in (AuthError("synthetic"), RateLimitError(20)):

        async def collect(ctx, original=original, **options):
            raise PartialSuccessError("saved") from original

        with patch(
            "xdr_cli.schema_graph.capture_orchestration.asyncio.sleep", new_callable=AsyncMock
        ) as sleep:
            *_, failure = await _collect_with_retry(
                collect,
                None,
                options={},
                deadline_at=time.monotonic() + 1,
                max_queries=5,
                local_only=False,
                on_progress=lambda message: None,
            )
        sleep.assert_not_awaited()
        assert failure.__cause__ is original


@pytest.mark.asyncio
async def test_receiptless_throttle_never_retries_unaccounted_queries():
    import time

    from xdr_cli.exceptions import PartialSuccessError, RateLimitError
    from xdr_cli.schema_graph.capture_orchestration import _collect_with_retry

    async def collect(ctx, **options):
        raise PartialSuccessError("no durable accounting") from RateLimitError(5)

    with patch(
        "xdr_cli.schema_graph.capture_orchestration.asyncio.sleep", new_callable=AsyncMock
    ) as sleep:
        receipts, attempts, retries, waited, failure = await _collect_with_retry(
            collect,
            None,
            options={},
            deadline_at=time.monotonic() + 300,
            max_queries=5,
            local_only=False,
            on_progress=lambda message: None,
        )
    sleep.assert_not_awaited()
    assert not receipts
    assert attempts == retries == waited == 0
    assert isinstance(failure, PartialSuccessError)
