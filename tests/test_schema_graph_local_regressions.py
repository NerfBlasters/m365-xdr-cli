import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from xdr_cli.api.hunting import HuntingResult
from xdr_cli.commands.schema_cmd import _schema_candidate_review
from xdr_cli.commands.session_cmd import _collect_after_explicit_end
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import ConflictError, TokenExpiredError
from xdr_cli.main import app
from xdr_cli.results import write_result
from xdr_cli.schema_graph.effective import merge_graphs
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.local_collection import collect_local, verify_local_observation
from xdr_cli.schema_graph.model import empirical_relationship_from_observations
from xdr_cli.schema_graph.overlay import load_tenant_overlay

TENANT = "review-tenant"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    ctx = AppContext(Config(tenant_id=TENANT), no_interactive=True, quiet=True)
    artifacts = []
    values = ["a@example.com", "b@example.com", "c@example.com"]
    for table, column in [("First", "Principal"), ("Second", "Who")]:
        artifacts.append(
            write_result(
                [{column: v} for v in values],
                command="hunt run",
                query=f"{table} | project {column}",
                tenant_id=TENANT,
            )
        )
    rows = [
        {"TableName": table, "ColumnName": column, "ColumnType": "string"}
        for table, columns in [
            ("First", ["Principal", "Timestamp"]),
            ("Second", ["Who", "Timestamp"]),
        ]
        for column in columns
    ]
    return ctx, artifacts, rows


def response(matched=1):
    return HuntingResult(
        results=[
            {
                "TargetLocator": "Second.Who",
                "TargetInterpretation": "interp:Second.Who:local-upn-lower:occurrence",
                "MatchRows": matched,
                "MatchedSeeds": matched,
            }
        ],
        schema=[],
        stats={},
    )


async def collect(ctx, rows, **kwargs):
    args = dict(
        plan_only=False,
        local_only=False,
        lookback="30d",
        samples=5,
        max_queries=20,
        batch_size=20,
        timeout=120,
        schema_rows=rows,
        canonical=load_packaged_graph(),
        on_result=lambda a: None,
    )
    args.update(kwargs)
    await collect_local(ctx, **args)


def fake_client():
    return SimpleNamespace(close=AsyncMock())


@pytest.mark.asyncio
@pytest.mark.parametrize("initial_window,initial_samples", [("1h", 1), ("1h", 3), ("30d", 1)])
async def test_changed_request_revalidates_window_and_sample_coverage(
    setup,
    initial_window,
    initial_samples,
):
    ctx, artifacts, rows = setup
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch(
            "xdr_cli.schema_graph.local_collection.XDRClient",
            side_effect=lambda **kw: fake_client(),
        ),
        patch(
            "xdr_cli.schema_graph.local_collection.run_query",
            new_callable=AsyncMock,
            return_value=response(),
        ) as query,
    ):
        await collect(ctx, rows, lookback=initial_window, samples=initial_samples)
        await collect(ctx, rows, lookback="30d", samples=3)
    overlay = load_tenant_overlay(TENANT)
    live = [o for o in overlay.observations if o.extra["evidence_stage"] == "local-validation"]
    assert query.await_count == 2
    assert {(o.lookback, o.distinct_seeds) for o in live} == {
        (initial_window, initial_samples),
        ("30d", 3),
    }


@pytest.mark.asyncio
async def test_projected_local_evidence_can_be_reviewed(setup):
    ctx, artifacts, rows = setup
    await collect(ctx, rows, local_only=True)
    overlay = load_tenant_overlay(TENANT)
    rid = empirical_relationship_from_observations(overlay.observations).id
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {"stale": False})),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", side_effect=lambda **kw: fake_client()),
        patch(
            "xdr_cli.commands.schema_cmd.run_query",
            new_callable=AsyncMock,
            return_value=HuntingResult(results=[{"Who": "a@example.com"}], schema=[], stats={}),
        ) as query,
    ):
        await _schema_candidate_review(
            ctx,
            relationship_id=rid,
            lookback=None,
            limit=5,
            timeout=120,
        )
    query.assert_awaited_once()
    assert "Second" in query.call_args.args[1]


@pytest.mark.asyncio
async def test_bad_original_retracts_local_and_live_evidence(setup):
    ctx, artifacts, rows = setup
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch(
            "xdr_cli.schema_graph.local_collection.XDRClient",
            side_effect=lambda **kw: fake_client(),
        ),
        patch(
            "xdr_cli.schema_graph.local_collection.run_query",
            new_callable=AsyncMock,
            return_value=response(),
        ),
    ):
        await collect(ctx, rows)
    with open(artifacts[1].receipt.data_path, "a") as stream:
        stream.write("{}\n")
    await collect(ctx, rows, local_only=True)
    assert not load_tenant_overlay(TENANT).observations


@pytest.mark.asyncio
async def test_concurrent_collectors_do_not_duplicate_queries(setup):
    ctx, artifacts, rows = setup
    reached, release = asyncio.Event(), asyncio.Event()

    async def query(client, kql):
        reached.set()
        await release.wait()
        return response()

    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch(
            "xdr_cli.schema_graph.local_collection.XDRClient",
            side_effect=lambda **kw: fake_client(),
        ),
        patch("xdr_cli.schema_graph.local_collection.run_query", side_effect=query) as run,
    ):
        first = asyncio.create_task(collect(ctx, rows))
        await asyncio.wait_for(reached.wait(), timeout=5)
        try:
            with pytest.raises(ConflictError, match="already running"):
                await collect(ctx, rows)
        finally:
            release.set()
            await first
        # Freshness must be rechecked once a later caller acquires the lock.
        await collect(ctx, rows)
        assert run.await_count == 1


def test_session_end_preserves_original_auth_failure(setup):
    ctx, artifacts, rows = setup
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {"stale": False})),
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch(
            "xdr_cli.schema_graph.local_collection.XDRClient",
            side_effect=lambda **kw: fake_client(),
        ),
        patch(
            "xdr_cli.schema_graph.local_collection.run_query",
            new_callable=AsyncMock,
            side_effect=TokenExpiredError(),
        ),
    ):
        result = _collect_after_explicit_end(ctx)
    assert result["status"] == "partial" and result["exit_code"] == 14
    assert result["cause"]["error_type"] == "TokenExpiredError"
    assert result["cause"]["exit_code"] == 2
    assert result["next_command"] == "xdr auth status"


@pytest.mark.asyncio
async def test_invalid_address_is_rejected_without_aborting_local_only(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    for table, column in [("First", "Principal"), ("Second", "Who")]:
        write_result(
            [{column: "user@bad_domain.example"}],
            command="hunt run",
            query=f"{table} | project {column}",
            tenant_id=TENANT,
        )
    rows = [{"TableName": "Second", "ColumnName": column} for column in ["Who", "Timestamp"]]
    ctx = AppContext(Config(tenant_id=TENANT), no_interactive=True, quiet=True)
    captured = []
    await collect(ctx, rows, local_only=True, on_result=captured.append)
    assert not load_tenant_overlay(TENANT).observations
    assert captured[0].receipt.context["local_coverage"]["rejected_identifier_cells"] == 2


@pytest.mark.asyncio
async def test_discovery_verifies_each_artifact_once_per_snapshot(tmp_path, monkeypatch):
    from xdr_cli.commands.schema_cmd import _candidate_report, _read_verified_schema_artifact
    from xdr_cli.schema_graph.local_discovery import verified_values

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    artifacts, schema = [], []
    for i in range(14):
        table, field = f"Table{i}", f"Account{i}"
        artifacts.append(
            write_result(
                [{field: "a@example.com"}, {field: "b@example.com"}],
                command="hunt run",
                query=f"{table} | project {field}",
                tenant_id=TENANT,
            )
        )
        schema.extend({"TableName": table, "ColumnName": c} for c in (field, "Timestamp"))
    ctx = AppContext(Config(tenant_id=TENANT), no_interactive=True, quiet=True)
    await collect(ctx, schema, local_only=True)
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(schema, {})),
        patch(
            "xdr_cli.schema_graph.local_discovery.verified_values", wraps=verified_values
        ) as values,
        patch(
            "xdr_cli.commands.schema_cmd._read_verified_schema_artifact",
            wraps=_read_verified_schema_artifact,
        ) as reads,
        patch(
            "xdr_cli.commands.schema_cmd.load_tenant_overlay", wraps=load_tenant_overlay
        ) as loads,
    ):
        rows, *_ = _candidate_report(ctx, include_evidence_refs=False)
        assert len(rows) == 91
        assert values.call_count == 14
        assert reads.call_count == 14
        assert loads.call_count == 1
        # A later command must reverify bytes, never retain the prior snapshot.
        from pathlib import Path

        Path(artifacts[0].receipt.data_path).write_text("{}\n")
        rows, *_ = _candidate_report(ctx, include_evidence_refs=False)
        assert sum(row["MissingEvidenceArtifactCount"] > 0 for row in rows) == 13
        assert reads.call_count == 28
        assert loads.call_count == 2


@pytest.mark.asyncio
async def test_reused_route_does_not_hide_new_identifier_cohorts(setup):
    ctx, artifacts, rows = setup
    captured = []
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch(
            "xdr_cli.schema_graph.local_collection.XDRClient",
            side_effect=lambda **kw: fake_client(),
        ),
        patch(
            "xdr_cli.schema_graph.local_collection.run_query",
            new_callable=AsyncMock,
            return_value=response(),
        ) as query,
    ):
        await collect(ctx, rows)
        # Two further cohorts of the same physical field pair must both appear
        # in the next plan, not remain hidden behind the strongest old pair.
        for cohort in ("de", "fg"):
            for table, field in (("First", "Principal"), ("Second", "Who")):
                write_result(
                    [{field: f"{c}@example.com"} for c in cohort],
                    command="hunt run",
                    query=f"{table} | project {field}",
                    tenant_id=TENANT,
                )
        await collect(ctx, rows, plan_only=True, on_result=captured.append)
        assert captured[-1].receipt.context["validation_queries_planned"] == 2
        await collect(ctx, rows, on_result=captured.append)
        assert query.await_count == 3
        assert captured[-1].receipt.context["remaining_queries"] == 0
        await collect(ctx, rows, plan_only=True, on_result=captured.append)
        assert captured[-1].receipt.context["validation_queries_planned"] == 0


def test_generic_auth_failure_uses_auth_status_and_redacts_message(setup):
    from xdr_cli.exceptions import AuthError

    ctx, artifacts, rows = setup
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {"stale": False})),
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch(
            "xdr_cli.schema_graph.local_collection.XDRClient",
            side_effect=lambda **kw: fake_client(),
        ),
        patch(
            "xdr_cli.schema_graph.local_collection.run_query",
            new_callable=AsyncMock,
            side_effect=AuthError("PRIVATE diagnostic details"),
        ),
    ):
        maintenance = _collect_after_explicit_end(ctx)
    assert maintenance["cause"]["exit_code"] == 2
    assert maintenance["cause"]["help_command"] == "xdr auth status"
    assert maintenance["next_command"] == "xdr auth status"
    assert "PRIVATE diagnostic" not in json.dumps(maintenance)
