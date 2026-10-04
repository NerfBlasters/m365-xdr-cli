import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from xdr_cli.api.hunting import HuntingResult
from xdr_cli.commands.schema_cmd import _compose_effective
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import PartialSuccessError
from xdr_cli.main import app
from xdr_cli.results import write_result
from xdr_cli.schema_graph.discovery import (
    explore_saved_identifiers,
    read_search_rows,
    search_artifact,
    verify_search_observation,
)
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.overlay import load_tenant_overlay

TENANT = "discovery-test"
runner = CliRunner()


def output(*rows):
    return HuntingResult(
        schema=[],
        stats={},
        results=[
            *[
                dict(
                    RowKind="match",
                    ReturnedRows=None,
                    UnsupportedPath=False,
                    DepthLimitReached=False,
                    MatchingRows=2,
                    PathTokens=[],
                    **row,
                )
                for row in rows
            ],
            {"RowKind": "receipt", "ReturnedRows": len(rows)},
        ],
    )


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    source = write_result(
        [{"Alias": "user@example.com"}],
        command="hunt run",
        query="UnlistedSource | project Alias=UnusualAccount",
        tenant_id=TENANT,
    )
    rows = [
        {"TableName": table, "ColumnName": column, "ColumnType": "string"}
        for table in ["UnlistedSource", "PreviouslyUnknownTarget"]
        for column in ["UnusualAccount", "UncataloguedIdentity", "Timestamp"]
    ]
    return tmp_path, source, rows, AppContext(Config(tenant_id=TENANT), quiet=True)


async def explore(home, **options):
    _, _, rows, ctx = home
    args = dict(schema_rows=rows, canonical=load_packaged_graph())
    args.update(options)
    await explore_saved_identifiers(ctx, **args)


def client_mock():
    return patch(
        "xdr_cli.schema_graph.discovery.XDRClient",
        side_effect=lambda **_: SimpleNamespace(close=AsyncMock()),
    )


@pytest.mark.asyncio
async def test_discovers_connection_from_only_one_saved_table_and_reuses_search(home):
    response = output(
        dict(
            TableName="PreviouslyUnknownTarget",
            ColumnName="UncataloguedIdentity",
            MatchedValue="user@example.com",
        )
    )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=response,
        ) as query,
    ):
        await explore(home)
        await explore(home)
    assert query.await_count == 1
    assert "find withsource" in query.call_args.args[1]
    assert "UncataloguedIdentity" not in query.call_args.args[1]
    overlay = load_tenant_overlay(TENANT)
    observations = [
        o for o in overlay.observations if o.extra["evidence_stage"] == "identifier-search"
    ]
    assert len(observations) == 1
    effective = _compose_effective(
        home[2],
        tenant_id=TENANT,
        canonical=load_packaged_graph(),
        overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    assert verify_search_observation(effective.graph, observations[0], TENANT) is not None
    assert home[1].receipt.run_id in observations[0].evidence_run_ids


@pytest.mark.asyncio
async def test_negative_search_is_checkpointed_and_does_not_invent_edges(home):
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=output(),
        ) as query,
    ):
        await explore(home)
        await explore(home)
    assert query.await_count == 1
    assert not load_tenant_overlay(TENANT).observations


@pytest.mark.asyncio
async def test_no_six_source_or_five_identifier_scope_limit_and_budget_resumes(home, capsys):
    for i in range(8):
        write_result(
            [{"Principal": f"person{i}@example.com"}],
            command="hunt run",
            query=f"Source{i} | project Principal",
            tenant_id=TENANT,
        )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=output(),
        ) as query,
    ):
        with pytest.raises(PartialSuccessError):
            await explore(home, seed_batch_size=2, max_queries=2)
        receipt = json.loads(capsys.readouterr().out)
        assert receipt["context"]["coverage"]["seed_fields"] == 9
        assert receipt["context"]["queries_planned"] == 5
        assert receipt["context"]["remaining_queries"] == 3
        with pytest.raises(PartialSuccessError):
            await explore(home, seed_batch_size=2, max_queries=2)
        receipt = json.loads(capsys.readouterr().out)
        assert receipt["context"]["remaining_queries"] == 1
        await explore(home, seed_batch_size=2, max_queries=2)
        await explore(home, seed_batch_size=2, max_queries=2)
        assert query.await_count == 5


@pytest.mark.asyncio
async def test_plan_only_uses_structured_receipt_and_never_authenticates(home, capsys):
    with patch("xdr_cli.schema_graph.discovery.AuthManager") as auth:
        await explore(home, plan_only=True)
    auth.assert_not_called()
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["context"]["queries_planned"] == 1
    assert not load_tenant_overlay(TENANT).observations
    assert "user@example.com" not in json.dumps(receipt)


def test_reader_rejects_partial_api_output_and_nonexact_values():
    args = dict(
        seeds=["user@example.com"],
        normalizer="upn-lower",
        tables=["Target"],
        max_depth=6,
        row_limit=2000,
    )
    rows = output(
        dict(TableName="Target", ColumnName="Who", MatchedValue="user@example.com")
    ).results
    assert len(read_search_rows(rows, args)[0]) == 1
    with pytest.raises(ValueError, match="receipt"):
        read_search_rows(rows[:-1], args)
    rows[0]["MatchedValue"] = "another@example.com"
    with pytest.raises(ValueError, match="exact-seed"):
        read_search_rows(rows, args)


@pytest.mark.asyncio
async def test_dynamic_unknown_paths_are_verified_and_depth_gaps_are_reported(home, capsys):
    result = output(
        dict(
            TableName="PreviouslyUnknownTarget",
            ColumnName="UncataloguedIdentity",
            MatchedValue="user@example.com",
        )
    )
    result.results[0]["PathTokens"] = [
        "UnlistedVendorField",
        "*",
        "CustomIdentity",
        "*",
        "UserName",
    ]
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=result,
        ),
    ):
        await explore(home)
    overlay = load_tenant_overlay(TENANT)
    assert any(
        field.locator.json_path == tuple(result.results[0]["PathTokens"])
        for field in overlay.graph.fields.values()
    )
    capsys.readouterr()


@pytest.mark.asyncio
async def test_new_source_can_reuse_old_search_without_network(home):
    response = output(
        dict(
            TableName="PreviouslyUnknownTarget",
            ColumnName="UncataloguedIdentity",
            MatchedValue="user@example.com",
        )
    )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=response,
        ) as query,
    ):
        await explore(home)
        write_result(
            [{"AnotherName": "user@example.com"}],
            command="hunt run",
            query="NewSource | project AnotherName",
            tenant_id=TENANT,
        )
        await explore(home)
        assert query.await_count == 1
    overlay = load_tenant_overlay(TENANT)
    assert sum(o.extra["evidence_stage"] == "identifier-search" for o in overlay.observations) == 2


@pytest.mark.asyncio
async def test_changed_source_bytes_invalidate_search_evidence(home):
    response = output(
        dict(
            TableName="PreviouslyUnknownTarget",
            ColumnName="UncataloguedIdentity",
            MatchedValue="user@example.com",
        )
    )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=response,
        ),
    ):
        await explore(home)
    run = load_tenant_overlay(TENANT).observations[0].target_artifact_run_id
    Path(home[1].receipt.data_path).write_text("{}\n")
    with pytest.raises(ValueError):
        search_artifact(run, TENANT)


def test_cli_routes_active_collection_to_identifier_discovery(home):
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id=TENANT)),
        patch(
            "xdr_cli.commands.schema_cmd._load_cache",
            return_value=(home[2], {}),
        ),
        patch(
            "xdr_cli.schema_graph.discovery.explore_saved_identifiers", new_callable=AsyncMock
        ) as run,
    ):
        result = runner.invoke(app, ["schema", "collect", "--explore", "--plan-only"])
    assert result.exit_code == 0, result.output
    run.assert_awaited_once()
    assert run.call_args.kwargs["sources"] == ()


@pytest.mark.asyncio
async def test_depth_gap_does_not_repeat_query_and_larger_scope_clears_it(home, capsys):
    marker = output(
        dict(
            TableName="PreviouslyUnknownTarget", ColumnName="UncataloguedIdentity", MatchedValue=""
        )
    )
    marker.results[0]["DepthLimitReached"] = True
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            side_effect=[marker, output()],
        ) as query,
    ):
        with pytest.raises(PartialSuccessError):
            await explore(home)
        receipt = json.loads(capsys.readouterr().out)
        assert receipt["context"]["coverage_gaps"]["depth_limit_reached"] == 1
        assert "--max-json-depth 12" in receipt["context"]["next_command"]
        with pytest.raises(PartialSuccessError):
            await explore(home)
        assert query.await_count == 1
        capsys.readouterr()
        await explore(home, max_depth=12)
        receipt = json.loads(capsys.readouterr().out)
        assert receipt["context"]["coverage_gaps"] == {}
        assert receipt["context"]["scope_complete"]
        assert query.await_count == 2


@pytest.mark.asyncio
async def test_query_scope_changes_revalidate_saved_searches(home):
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=output(),
        ) as query,
    ):
        await explore(home, lookback="1h")
        await explore(home, lookback="30d")
        assert query.await_count == 2


@pytest.mark.asyncio
async def test_table_batches_cover_more_than_one_hundred_tables(home, capsys):
    schema = [{"TableName": f"Target{i}", "ColumnName": "Timestamp"} for i in range(101)]
    with patch("xdr_cli.schema_graph.discovery.AuthManager") as auth:
        await explore(home, schema_rows=schema, plan_only=True)
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["context"]["queries_planned"] == 2
    auth.assert_not_called()


@pytest.mark.asyncio
async def test_all_original_seed_dependencies_are_retained(home):
    unused = write_result(
        [{"Who": "another@example.com"}],
        command="hunt run",
        query="OtherSource | project Who",
        tenant_id=TENANT,
    )
    response = output(
        dict(
            TableName="PreviouslyUnknownTarget",
            ColumnName="UncataloguedIdentity",
            MatchedValue="user@example.com",
        )
    )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=response,
        ),
    ):
        await explore(home)
    observation = next(
        o
        for o in load_tenant_overlay(TENANT).observations
        if o.extra["evidence_stage"] == "identifier-search"
    )
    assert unused.receipt.run_id in observation.evidence_run_ids
    assert home[1].receipt.run_id in observation.evidence_run_ids


def test_expanded_projection_supports_multiple_arrays_and_encoded_containers():
    from xdr_cli.schema_graph.local_collection import pair_graph
    from xdr_cli.schema_graph.local_discovery import LocalPair
    from xdr_cli.schema_graph.probe import compile_target_context_query

    pair = LocalPair(
        "First.User",
        "Second.Data#/Outer/*/Inner/*/Principal",
        "upn-lower",
        "a",
        "b",
        1,
        "2026-10-04T00:00:00+00:00",
    )
    graph, interps = pair_graph(pair, load_packaged_graph())
    compiled = compile_target_context_query(
        interps[1],
        graph.fields[interps[1].field_id].locator,
        ["user@example.com"],
        expanded_paths=True,
    )
    assert compiled.kql.count("| mv-expand") == 2
    assert 'parse_json(tostring(__xdr_nested_1))["Inner"]' in compiled.kql


@pytest.mark.asyncio
async def test_capped_search_can_be_refined_into_smaller_batches(home, capsys):
    write_result(
        [{"Principal": "other@example.com"}],
        command="hunt run",
        query="OtherSource | project Principal",
        tenant_id=TENANT,
    )
    capped = output(
        dict(
            TableName="PreviouslyUnknownTarget", ColumnName="WhoA", MatchedValue="user@example.com"
        ),
        dict(
            TableName="PreviouslyUnknownTarget", ColumnName="WhoB", MatchedValue="user@example.com"
        ),
    )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            side_effect=[capped, output(), output()],
        ) as query,
    ):
        with pytest.raises(PartialSuccessError):
            await explore(home, row_limit=1, seed_batch_size=20)
        capsys.readouterr()
        await explore(home, row_limit=1, seed_batch_size=1)
        second = json.loads(capsys.readouterr().out)["context"]
    assert query.await_count == 3
    assert second["queries_executed"] == 2
    assert not second["coverage_gaps"]


@pytest.mark.asyncio
async def test_cached_search_skips_existing_pair_build_and_parses_sources_once(home, capsys):
    from xdr_cli.schema_graph.discovery import verified_values

    response = output(
        dict(TableName="PreviouslyUnknownTarget", ColumnName="Who", MatchedValue="user@example.com")
    )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=response,
        ),
    ):
        await explore(home)
        capsys.readouterr()
        with (
            patch("xdr_cli.schema_graph.local_collection.pair_graph") as build,
            patch("xdr_cli.schema_graph.discovery.verified_values", wraps=verified_values) as parse,
        ):
            await explore(home)
    build.assert_not_called()
    assert parse.call_count == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"TableName": "OutsideQuery"},
        {"MatchingRows": -1},
        {"DepthLimitReached": "invalid"},
        {"ColumnName": None},
    ],
)
def test_unsupported_marker_still_requires_valid_scope_and_counts(bad):
    args = dict(
        seeds=["user@example.com"],
        normalizer="upn-lower",
        tables=["Target"],
        max_depth=6,
        row_limit=2000,
    )
    rows = output(dict(TableName="Target", ColumnName="Who", MatchedValue="")).results
    rows[0].update(UnsupportedPath=True, **bad)
    with pytest.raises(ValueError):
        read_search_rows(rows, args)


@pytest.mark.parametrize(
    "unsupported,limited,expected",
    [
        (0, 0, {}),
        (1, 0, {"unsupported_paths": 1}),
        (0, 1, {"depth_limit_reached": 1}),
    ],
)
def test_graph_numeric_boolean_columns(unsupported, limited, expected):
    args = dict(
        seeds=["user@example.com"],
        normalizer="upn-lower",
        tables=["Target"],
        max_depth=6,
        row_limit=2000,
    )
    rows = output(
        dict(TableName="Target", ColumnName="Who", MatchedValue="user@example.com")
    ).results
    rows[0].update(UnsupportedPath=unsupported, DepthLimitReached=limited)
    hits, gaps = read_search_rows(rows, args)
    assert gaps == expected
    assert bool(hits) == (not unsupported and not limited)


@pytest.mark.asyncio
async def test_policy_excluded_paths_do_not_cause_permanent_partial_success(home, capsys):
    response = output(dict(TableName="PreviouslyUnknownTarget", ColumnName="Who", MatchedValue=""))
    response.results[0]["UnsupportedPath"] = True
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=response,
        ) as query,
    ):
        for _ in range(3):
            await explore(home)
            context = json.loads(capsys.readouterr().out)["context"]
            assert context["coverage_gaps"] == {}
            assert context["excluded_scope"]["unsupported_paths"] == 1
            assert context["scope_complete"]
    assert query.await_count == 1


@pytest.mark.asyncio
async def test_daily_budget_advances_before_refreshing_previous_negative_search(home):
    from datetime import UTC, datetime, timedelta

    write_result(
        [{"Principal": "another@example.com"}],
        command="hunt run",
        query="OtherSource | project Principal",
        tenant_id=TENANT,
    )
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=output(),
        ) as query,
    ):
        with pytest.raises(PartialSuccessError):
            await explore(home, max_queries=1, seed_batch_size=1)
        for path in home[0].glob("results/*/*.meta.json"):
            meta = json.loads(path.read_text())
            if meta.get("command") == "schema collect discovery":
                meta["created_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
                path.write_text(json.dumps(meta))
        with pytest.raises(PartialSuccessError):
            await explore(home, max_queries=1, seed_batch_size=1)
    queries = [call.args[1] for call in query.call_args_list]
    assert len(queries) == 2
    assert queries[0] != queries[1]


@pytest.mark.asyncio
async def test_one_uncompilable_seed_does_not_abort_other_discovery(home):
    from xdr_cli.schema_graph.discovery import saved_seeds

    seeds, coverage = saved_seeds(TENANT)
    seeds["identity", "a\\" * 1000] = next(iter(seeds.values()))
    receipts = []
    with (
        client_mock(),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch("xdr_cli.schema_graph.discovery.saved_seeds", return_value=(seeds, coverage)),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=output(),
        ) as query,
    ):
        await explore(home, on_result=receipts.append)
    assert query.await_count == 1
    assert receipts
    assert receipts[-1].receipt.to_dict()["context"]["excluded_scope"]["uncompilable_seed_scopes"]


def test_nonascii_upn_target_is_reported_without_false_match():
    args = dict(
        seeds=["kate@example.com"],
        normalizer="upn-lower",
        tables=["Target"],
        max_depth=6,
        row_limit=2000,
    )
    rows = output(
        dict(TableName="Target", ColumnName="Who", MatchedValue="Kate@example.com")
    ).results
    hits, gaps = read_search_rows(rows, args)
    assert hits == []
    assert gaps == {"unsupported_normalization_cells": 1}
