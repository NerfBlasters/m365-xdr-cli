"""Regression coverage for retirement, incomplete scopes, and source selectors."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from xdr_cli.config import Config, save_config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import LocalNotFoundError, PartialSuccessError, UsageError
from xdr_cli.main import app
from xdr_cli.results import write_result
from xdr_cli.schema_graph.bundle import export_bundle, import_bundle
from xdr_cli.schema_graph.discovery import explore_saved_identifiers, saved_seeds
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.local_collection import collect_local, verify_local_observation
from xdr_cli.schema_graph.overlay import load_tenant_overlay, publish_tenant_overlay
from xdr_cli.schema_graph.session_maintenance import collect_session_schema

TENANT = "synthetic-review-tenant"
runner = CliRunner()


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "home"
    monkeypatch.setenv("XDR_CLI_HOME", str(root))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    save_config(Config(tenant_id=TENANT))
    return root


@pytest.fixture
def ctx(home):
    return AppContext(Config(tenant_id=TENANT), no_interactive=True, quiet=True)


def hunt(table, column, value="synthetic@example.invalid"):
    return write_result(
        [{column: value}],
        command="hunt run",
        query=f"{table} | project {column}",
        tenant_id=TENANT,
    )


def schema_root(home):
    return home / "schema" / hashlib.sha256(TENANT.encode()).hexdigest()[:12]


def old_hunt():
    artifact = hunt("First", "Principal")
    path = Path(artifact.receipt.meta_path)
    metadata = json.loads(path.read_text())
    metadata["created_at"] = (datetime.now(UTC) - timedelta(days=120)).isoformat()
    path.write_text(json.dumps(metadata))
    return artifact


def bounded_first():
    return [
        {"TableName": "First", "ColumnName": name, "ColumnType": "string"}
        for name in ("Principal", "Timestamp")
    ]


def empty_search():
    return SimpleNamespace(results=[{"RowKind": "receipt", "ReturnedRows": 0}])


def fake_client(**_kwargs):
    return SimpleNamespace(close=AsyncMock())


def test_empty_prune_persists_cutoff_and_excludes_still_present_hunt(home):
    artifact = old_hunt()
    hunt("Second", "Who")
    publish_tenant_overlay(TENANT)
    assert len(saved_seeds(TENANT)[0]) == 1
    before = datetime.now(UTC) - timedelta(days=90)

    result = runner.invoke(app, ["schema", "prune-evidence", "--older-than", "90", "--yes"])

    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["context"]["removed_observations"] == 0
    cutoff = datetime.fromisoformat(
        load_tenant_overlay(TENANT).metadata["discovery_retired_before"]
    )
    assert before <= cutoff <= datetime.now(UTC) - timedelta(days=90)
    assert Path(artifact.receipt.data_path).exists()
    assert Path(artifact.receipt.meta_path).exists()
    seeds, _ = saved_seeds(TENANT)
    assert {origin["locator"] for origins in seeds.values() for origin in origins} == {"Second.Who"}


def test_empty_prune_requires_confirmation_without_advancing_cutoff(home):
    publish_tenant_overlay(TENANT)
    generation = load_tenant_overlay(TENANT).metadata["generation"]

    result = runner.invoke(
        app,
        ["--no-interactive", "schema", "prune-evidence", "--older-than", "90"],
    )

    assert result.exit_code == 6, result.output
    overlay = load_tenant_overlay(TENANT)
    assert overlay.metadata["generation"] == generation
    assert "discovery_retired_before" not in overlay.metadata


@pytest.mark.asyncio
async def test_retired_hunt_cannot_recreate_local_overlap(home, ctx):
    artifact = old_hunt()
    hunt("Second", "Who")
    prune = runner.invoke(app, ["schema", "prune-evidence", "--older-than", "90", "--yes"])
    assert prune.exit_code == 0, prune.output
    captured = []

    await collect_local(
        ctx,
        plan_only=False,
        local_only=True,
        lookback="30d",
        samples=5,
        max_queries=0,
        timeout=30,
        schema_rows=[],
        canonical=load_packaged_graph(),
        on_result=captured.append,
    )

    assert captured[0].receipt.context["candidate_pairs"] == 0
    assert not load_tenant_overlay(TENANT).observations
    assert Path(artifact.receipt.data_path).exists()


def test_empty_retirement_cutoff_survives_bundle_round_trip(home, tmp_path, monkeypatch):
    result = runner.invoke(app, ["schema", "prune-evidence", "--older-than", "90", "--yes"])
    assert result.exit_code == 0, result.output
    cutoff = load_tenant_overlay(TENANT).metadata["discovery_retired_before"]
    archive = tmp_path / "synthetic-bundle.tar.gz"
    export_bundle(home, TENANT, archive)
    destination = tmp_path / "destination"
    destination.mkdir()

    import_bundle(destination, TENANT, archive)
    monkeypatch.setenv("XDR_CLI_HOME", str(destination))

    assert load_tenant_overlay(TENANT).metadata["discovery_retired_before"] == cutoff


@pytest.mark.asyncio
async def test_unavailable_local_target_is_excluded_from_eligible_completion(home, ctx):
    hunt("First", "Principal")
    hunt("Second", "Who")
    captured = []
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager") as auth,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
    ):
        await collect_local(
            ctx,
            plan_only=False,
            local_only=False,
            lookback="30d",
            samples=5,
            max_queries=20,
            timeout=30,
            schema_rows=[],
            canonical=load_packaged_graph(),
            on_result=captured.append,
        )
    context = captured[0].receipt.context
    assert context["remaining_queries"] == 0
    assert context["coverage_gaps"] == {}
    assert context["excluded_scope"] == {"unavailable_validation_targets": 1}
    assert context["scope_complete"] is True
    assert load_tenant_overlay(TENANT).observations
    assert not (schema_root(home) / "maintenance.json").exists()
    auth.assert_not_called()
    complete.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("gap", ["tables_without_time_column", "unavailable_validation_targets"])
async def test_exploration_completes_eligible_scope_with_explicit_exclusions(home, ctx, gap):
    hunt("First", "Principal")
    rows = bounded_first()
    if gap == "tables_without_time_column":
        rows.append({"TableName": "Unbounded", "ColumnName": "Who", "ColumnType": "string"})
    else:
        hunt("Second", "Who")
        rows = [{**row, "TableName": "Third"} for row in rows]
    captured = []
    with (
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch("xdr_cli.schema_graph.discovery.XDRClient", side_effect=fake_client),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=empty_search(),
        ) as query,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
    ):
        await explore_saved_identifiers(
            ctx,
            schema_rows=rows,
            canonical=load_packaged_graph(),
            on_result=captured.append,
        )
    query.assert_awaited_once()
    context = captured[0].receipt.context
    assert context["queries_executed"] == 1
    assert context["remaining_queries"] == 0
    assert context["coverage_gaps"] == {}
    assert context["excluded_scope"][gap] == 1
    assert context["scope_complete"] is True
    assert not (schema_root(home) / "maintenance.json").exists()
    complete.assert_called_once()


def test_session_completes_after_exhausting_eligible_scope(home, ctx):
    hunt("First", "Principal")
    hunt("Second", "Who")
    captured = []
    with (
        patch(
            "xdr_cli.commands.schema_cmd._load_cache",
            return_value=(
                [{**row, "TableName": "Third"} for row in bounded_first()],
                {"stale": False},
            ),
        ),
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch("xdr_cli.schema_graph.discovery.XDRClient", side_effect=fake_client),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=empty_search(),
        ) as query,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
    ):
        collect_session_schema(ctx, on_result=captured.append)
    query.assert_awaited_once()
    assert len(captured) == 1
    stages = captured[0].receipt.context["stages"]
    assert stages["validation"]["status"] == stages["exploration"]["status"] == "success"
    assert stages["validation"]["result"]["context"]["remaining_queries"] == 0
    assert stages["exploration"]["result"]["context"]["queries_executed"] == 1
    complete.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["malformed-source", "First.Principal#bad-pointer"])
async def test_malformed_source_is_usage_error_before_queries_or_completion(home, ctx, source):
    hunt("First", "Principal")
    captured = []
    with (
        patch("xdr_cli.schema_graph.discovery.AuthManager") as auth,
        patch("xdr_cli.schema_graph.discovery.run_query") as query,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
        pytest.raises(UsageError) as error,
    ):
        await explore_saved_identifiers(
            ctx,
            schema_rows=bounded_first(),
            canonical=load_packaged_graph(),
            sources=(source,),
            on_result=captured.append,
        )
    assert error.value.exit_code == 6
    assert not captured
    auth.assert_not_called()
    query.assert_not_called()
    complete.assert_not_called()


@pytest.mark.asyncio
async def test_valid_but_absent_source_is_not_found_instead_of_empty_success(home, ctx):
    hunt("First", "Principal")
    captured = []
    with (
        patch("xdr_cli.schema_graph.discovery.AuthManager") as auth,
        patch("xdr_cli.schema_graph.discovery.run_query") as query,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
        pytest.raises(LocalNotFoundError) as error,
    ):
        await explore_saved_identifiers(
            ctx,
            schema_rows=bounded_first(),
            canonical=load_packaged_graph(),
            sources=("Missing.Principal",),
            on_result=captured.append,
        )
    assert error.value.exit_code == 8
    assert not captured
    assert not (schema_root(home) / "maintenance.json").exists()
    auth.assert_not_called()
    query.assert_not_called()
    complete.assert_not_called()


@pytest.mark.asyncio
async def test_source_pointer_is_canonicalized_before_selecting_saved_identifiers(home, ctx):
    hunt("First", "Raw", {"who_id": "synthetic@example.invalid"})
    rows = [{"TableName": "First", "ColumnName": name} for name in ("Raw", "Timestamp")]
    captured = []
    with (
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch("xdr_cli.schema_graph.discovery.XDRClient", side_effect=fake_client),
        patch(
            "xdr_cli.schema_graph.discovery.run_query",
            new_callable=AsyncMock,
            return_value=empty_search(),
        ) as query,
    ):
        await explore_saved_identifiers(
            ctx,
            schema_rows=rows,
            canonical=load_packaged_graph(),
            sources=("First.Raw#/%77ho_id",),
            on_result=captured.append,
        )
    query.assert_awaited_once()
    assert "synthetic@example.invalid" in query.call_args.args[1]
    assert captured[0].receipt.context["coverage"]["seed_identifiers"] == 1


def test_31_day_history_prefers_unseen_work_without_promoting_stale_evidence(home, ctx):
    def save_cohort(values):
        for table, column in (("First", "Principal"), ("Second", "Who")):
            write_result(
                [{column: value} for value in values],
                command="hunt run",
                query=f"{table} | project {column}",
                tenant_id=TENANT,
            )

    old = [f"old{index}@example.invalid" for index in range(4)]
    unseen = [f"new{index}@example.invalid" for index in range(3)]
    save_cohort(old)
    rows = [{"TableName": "Second", "ColumnName": name} for name in ("Who", "Timestamp")]
    queries = []

    async def respond(client, query):
        queries.append(query)
        count = len(old) if old[0] in query else len(unseen)
        return SimpleNamespace(
            results=[
                {
                    "TargetLocator": "Second.Who",
                    "TargetInterpretation": "interp:Second.Who:local-upn-lower:occurrence",
                    "MatchedSeeds": count,
                    "MatchRows": count,
                }
            ]
        )

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(days=31)

    def collect():
        import asyncio

        asyncio.run(
            collect_local(
                ctx,
                plan_only=False,
                local_only=False,
                lookback="30d",
                samples=5,
                max_queries=1,
                timeout=30,
                schema_rows=rows,
                canonical=load_packaged_graph(),
                on_result=lambda artifact: None,
            )
        )

    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch("xdr_cli.schema_graph.local_collection.XDRClient", side_effect=fake_client),
        patch("xdr_cli.schema_graph.local_collection.run_query", side_effect=respond),
    ):
        collect()
        save_cohort(unseen)
        overlay = load_tenant_overlay(TENANT)
        prior = next(
            item
            for item in overlay.observations
            if item.extra.get("evidence_stage") == "local-validation"
        )
        with patch("xdr_cli.schema_graph.local_collection.datetime", Later):
            assert verify_local_observation(overlay.graph, prior, TENANT) is None
            assert (
                verify_local_observation(
                    overlay.graph,
                    prior,
                    TENANT,
                    require_fresh=False,
                )
                is not None
            )
            with pytest.raises(PartialSuccessError):
                collect()

    assert len(queries) == 2
    assert old[0] in queries[0]
    assert unseen[0] in queries[1]
    assert old[0] not in queries[1]


@pytest.mark.parametrize("count,expected", [(1, "candidate"), (2, "candidate"), (3, "observed")])
def test_local_overlap_requires_three_distinct_values(count, expected):
    from xdr_cli.schema_graph.local_collection import local_observation, pair_graph
    from xdr_cli.schema_graph.local_discovery import LocalPair
    from xdr_cli.schema_graph.model import empirical_relationship_from_observations

    pair = LocalPair(
        "First.User", "Second.User", "upn-lower", "a", "b", count, datetime.now(UTC).isoformat()
    )
    _, interpretations = pair_graph(pair, load_packaged_graph())
    relation = empirical_relationship_from_observations((local_observation(pair, interpretations),))
    assert relation.status.value == expected


@pytest.mark.asyncio
async def test_each_explicit_source_requires_saved_seeds(home, ctx):
    hunt("First", "Principal")
    with pytest.raises(LocalNotFoundError):
        await explore_saved_identifiers(
            ctx,
            schema_rows=bounded_first(),
            canonical=load_packaged_graph(),
            plan_only=True,
            sources=("First.Principal", "Missing.Principal"),
            on_result=lambda result: None,
        )


@pytest.mark.asyncio
async def test_reverse_validation_keeps_identity_and_verifiable_evidence(home, ctx):
    from xdr_cli.schema_graph.model import empirical_relationship_from_observations

    hunt("First", "Principal")
    hunt("Second", "Who")
    response = SimpleNamespace(
        results=[
            {
                "TargetLocator": "First.Principal",
                "TargetInterpretation": "interp:First.Principal:local-upn-lower:occurrence",
                "MatchedSeeds": 1,
                "MatchRows": 1,
            }
        ]
    )
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch("xdr_cli.schema_graph.local_collection.XDRClient", side_effect=fake_client),
        patch("xdr_cli.schema_graph.local_collection.run_query", return_value=response) as query,
    ):
        await collect_local(
            ctx,
            plan_only=False,
            local_only=False,
            lookback="30d",
            samples=5,
            max_queries=1,
            timeout=30,
            schema_rows=bounded_first(),
            canonical=load_packaged_graph(),
            on_result=lambda result: None,
        )
    query.assert_awaited_once()
    overlay = load_tenant_overlay(TENANT)
    local, live = sorted(overlay.observations, key=lambda o: o.extra["evidence_stage"])
    assert {o.extra["evidence_stage"] for o in (local, live)} == {
        "local-overlap",
        "local-validation",
    }
    assert empirical_relationship_from_observations((local,)).id == (
        empirical_relationship_from_observations((live,)).id
    )
    for observation in overlay.observations:
        assert verify_local_observation(overlay.graph, observation, TENANT) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("local_only", [True, False])
async def test_private_ip_overlap_remains_candidate(home, ctx, local_only):
    from xdr_cli.commands.schema_cmd import _compose_effective

    for table, column in (("First", "Address"), ("Second", "IP")):
        write_result(
            [{column: f"10.1.2.{n}"} for n in (1, 2, 3)],
            command="hunt run",
            query=f"{table} | project {column}",
            tenant_id=TENANT,
        )
    rows = [{"TableName": "Second", "ColumnName": c} for c in ("IP", "Timestamp")]
    response = SimpleNamespace(
        results=[
            {
                "TargetLocator": "Second.IP",
                "TargetInterpretation": "interp:Second.IP:local-identity:occurrence",
                "MatchedSeeds": 3,
                "MatchRows": 3,
            }
        ]
    )
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch("xdr_cli.schema_graph.local_collection.XDRClient", side_effect=fake_client),
        patch("xdr_cli.schema_graph.local_collection.run_query", return_value=response),
    ):
        await collect_local(
            ctx,
            plan_only=False,
            local_only=local_only,
            lookback="30d",
            samples=5,
            max_queries=1,
            timeout=30,
            schema_rows=rows,
            canonical=load_packaged_graph(),
            on_result=lambda result: None,
        )
    overlay = load_tenant_overlay(TENANT)
    effective = _compose_effective(
        [],
        tenant_id=TENANT,
        canonical=load_packaged_graph(),
        overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    relations = [
        r
        for r in effective.graph.relationships.values()
        if "local-overlap" in r.extra.get("evidence_stages", [])
    ]
    assert len(relations) == 1
    assert relations[0].status.value == "candidate"


@pytest.mark.asyncio
async def test_table_addition_only_searches_new_scope(home, ctx):
    hunt("First", "Principal")
    rows = bounded_first()
    with (
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch("xdr_cli.schema_graph.discovery.XDRClient", side_effect=fake_client),
        patch("xdr_cli.schema_graph.discovery.run_query", return_value=empty_search()) as query,
    ):
        await explore_saved_identifiers(
            ctx, schema_rows=rows, canonical=load_packaged_graph(), on_result=lambda result: None
        )
        rows += [{**row, "TableName": "Second"} for row in bounded_first()]
        await explore_saved_identifiers(
            ctx, schema_rows=rows, canonical=load_packaged_graph(), on_result=lambda result: None
        )
    assert query.await_count == 2
    assert "in (Second)" in query.call_args.args[1]
    assert "in (First" not in query.call_args.args[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "second_values,expected",
    [
        ([f"u{n}@example.invalid" for n in range(6)], "observed"),
        ([f"v{n}@example.invalid" for n in range(5)], "validated"),
    ],
)
async def test_validation_needs_independent_cohorts(home, ctx, second_values, expected):
    import re
    from xdr_cli.commands.schema_cmd import _compose_effective

    def save(values):
        for table, column in (("First", "Principal"), ("Second", "Who")):
            write_result(
                [{column: value} for value in values],
                command="hunt run",
                query=f"{table} | project {column}",
                tenant_id=TENANT,
            )

    async def respond(_client, query):
        count = len(set(re.findall(r"[uv][0-9]+@example.invalid", query)))
        return SimpleNamespace(
            results=[
                {
                    "TargetLocator": "Second.Who",
                    "TargetInterpretation": "interp:Second.Who:local-upn-lower:occurrence",
                    "MatchedSeeds": count,
                    "MatchRows": count,
                }
            ]
        )

    rows = [{"TableName": "Second", "ColumnName": c} for c in ("Who", "Timestamp")]
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch("xdr_cli.schema_graph.local_collection.XDRClient", side_effect=fake_client),
        patch("xdr_cli.schema_graph.local_collection.run_query", side_effect=respond),
    ):
        for values in ([f"u{n}@example.invalid" for n in range(5)], second_values):
            save(values)
            await collect_local(
                ctx,
                plan_only=False,
                local_only=False,
                lookback="30d",
                samples=6,
                max_queries=20,
                timeout=30,
                schema_rows=rows,
                canonical=load_packaged_graph(),
                on_result=lambda result: None,
            )
    overlay = load_tenant_overlay(TENANT)
    effective = _compose_effective(
        rows,
        tenant_id=TENANT,
        canonical=load_packaged_graph(),
        overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    relations = [
        r
        for r in effective.graph.relationships.values()
        if "local-validation" in r.extra.get("evidence_stages", [])
    ]
    assert len(relations) == 1
    assert relations[0].status.value == expected


@pytest.mark.asyncio
async def test_future_search_checkpoint_is_requeried(home, ctx):
    hunt("First", "Principal")
    with (
        patch("xdr_cli.schema_graph.discovery.AuthManager"),
        patch("xdr_cli.schema_graph.discovery.XDRClient", side_effect=fake_client),
        patch("xdr_cli.schema_graph.discovery.run_query", return_value=empty_search()) as query,
    ):
        await explore_saved_identifiers(
            ctx,
            schema_rows=bounded_first(),
            canonical=load_packaged_graph(),
            on_result=lambda result: None,
        )
        for path in (home / "results").glob("*/*.meta.json"):
            meta = json.loads(path.read_text())
            if meta["command"] == "schema collect discovery":
                meta["created_at"] = (datetime.now(UTC) + timedelta(days=90)).isoformat()
                path.write_text(json.dumps(meta))
        await explore_saved_identifiers(
            ctx,
            schema_rows=bounded_first(),
            canonical=load_packaged_graph(),
            on_result=lambda result: None,
        )
    assert query.await_count == 2


@pytest.mark.asyncio
async def test_bad_pair_does_not_block_valid_pair(home, ctx):
    from xdr_cli.schema_graph.local_discovery import LocalPair

    hunt("First", "Principal")
    hunt("Second", "Who")
    from xdr_cli.schema_graph.local_discovery import discover_local

    pairs, coverage = discover_local(home / "results", schema_root(home), TENANT)
    invalid = LocalPair(
        "Bad.Column#/" + "x" * 1100,
        "Second.Who",
        "upn-lower",
        "a",
        "b",
        1,
        datetime.now(UTC).isoformat(),
    )
    captured = []
    with patch(
        "xdr_cli.schema_graph.local_collection.discover_local",
        return_value=([invalid, *pairs], coverage),
    ):
        await collect_local(
            ctx,
            plan_only=False,
            local_only=True,
            lookback="30d",
            samples=5,
            max_queries=0,
            timeout=30,
            schema_rows=[],
            canonical=load_packaged_graph(),
            on_result=captured.append,
        )
    assert len(load_tenant_overlay(TENANT).observations) == 1
    assert captured[0].receipt.context["excluded_scope"]["invalid_local_pairs"] == 1


@pytest.mark.asyncio
async def test_future_validation_cannot_be_reused_or_promoted(home, ctx):
    from dataclasses import replace

    hunt("First", "Principal")
    hunt("Second", "Who")
    rows = [{"TableName": "Second", "ColumnName": c} for c in ("Who", "Timestamp")]
    response = SimpleNamespace(
        results=[
            {
                "TargetLocator": "Second.Who",
                "TargetInterpretation": "interp:Second.Who:local-upn-lower:occurrence",
                "MatchedSeeds": 1,
                "MatchRows": 1,
            }
        ]
    )
    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch("xdr_cli.schema_graph.local_collection.XDRClient", side_effect=fake_client),
        patch("xdr_cli.schema_graph.local_collection.run_query", return_value=response) as query,
    ):

        async def collect():
            await collect_local(
                ctx,
                plan_only=False,
                local_only=False,
                lookback="30d",
                samples=5,
                max_queries=1,
                timeout=30,
                schema_rows=rows,
                canonical=load_packaged_graph(),
                on_result=lambda result: None,
            )

        await collect()
        overlay = load_tenant_overlay(TENANT)
        future = tuple(
            replace(o, observed_at=(datetime.now(UTC) + timedelta(days=90)).isoformat())
            if o.extra["evidence_stage"] == "local-validation"
            else o
            for o in overlay.observations
        )
        publish_tenant_overlay(TENANT, observations=future, replace_observations=True)
        live = next(o for o in future if o.extra["evidence_stage"] == "local-validation")
        assert verify_local_observation(overlay.graph, live, TENANT) is None
        assert verify_local_observation(overlay.graph, live, TENANT, require_fresh=False) is None
        await collect()
    assert query.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("distinct,expected", [(1, "candidate"), (3, "observed")])
async def test_repeated_rows_do_not_substitute_for_distinct_overlap(home, ctx, distinct, expected):
    from xdr_cli.commands.schema_cmd import _compose_effective

    for table, column in (("First", "Principal"), ("Second", "Who")):
        write_result(
            [{column: f"user{index % distinct}@example.invalid"} for index in range(120)],
            command="hunt run",
            query=f"{table} | project {column}",
            tenant_id=TENANT,
        )
    await collect_local(
        ctx,
        plan_only=False,
        local_only=True,
        lookback="30d",
        samples=5,
        max_queries=0,
        timeout=30,
        schema_rows=[],
        canonical=load_packaged_graph(),
        on_result=lambda result: None,
    )
    overlay = load_tenant_overlay(TENANT)
    assert len(overlay.observations) == 1
    assert overlay.observations[0].matched_seeds == distinct
    effective = _compose_effective(
        [],
        tenant_id=TENANT,
        canonical=load_packaged_graph(),
        overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    relations = [
        r
        for r in effective.graph.relationships.values()
        if "local-overlap" in r.extra.get("evidence_stages", [])
    ]
    assert len(relations) == 1
    assert relations[0].status.value == expected


@pytest.mark.asyncio
async def test_only_unbounded_tables_complete_without_network(home, ctx):
    hunt("First", "Principal")
    captured = []
    with patch("xdr_cli.schema_graph.discovery.AuthManager") as auth:
        await explore_saved_identifiers(
            ctx,
            schema_rows=[{"TableName": "First", "ColumnName": "Principal"}],
            canonical=load_packaged_graph(),
            on_result=captured.append,
        )
    auth.assert_not_called()
    context = captured[0].receipt.context
    assert context["scope_complete"] is True
    assert context["queries_planned"] == 0
    assert context["excluded_scope"] == {"tables_without_time_column": 1}
