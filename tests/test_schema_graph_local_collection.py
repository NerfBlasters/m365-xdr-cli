import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from xdr_cli.api.hunting import HuntingResult
from xdr_cli.commands.schema_cmd import _compose_effective
from xdr_cli.config import Config
from xdr_cli.main import app
from xdr_cli.results import write_result
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.overlay import load_tenant_overlay

runner = CliRunner()


@pytest.fixture
def local_results(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    for table, field in (("First", "Principal"), ("Second", "Who")):
        write_result(
            [{field: "user@example.com"}, {field: "another@example.com"}],
            command="hunt run",
            query=f"{table} | project {field}",
            tenant_id="tenant",
        )


@pytest.mark.parametrize("flags", [["--local-only"], ["--plan-only"]])
def test_local_modes_never_authenticate_and_publish_only_when_requested(local_results, flags):
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.schema_graph.local_collection.AuthManager") as auth,
    ):
        result = runner.invoke(app, ["schema", "collect", *flags])
    assert result.exit_code == 0, result.output
    auth.assert_not_called()
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["context"]["candidate_pairs"] == 1
    overlay = load_tenant_overlay("tenant")
    assert len(overlay.observations) == (1 if flags == ["--local-only"] else 0)
    if overlay.observations:
        effective = _compose_effective(
            [],
            tenant_id="tenant",
            canonical=load_packaged_graph(),
            overlays=(overlay.graph,),
            observations=overlay.observations,
        )
        local = [
            r
            for r in effective.graph.relationships.values()
            if "local-overlap" in r.extra.get("evidence_stages", [])
        ]
        assert len(local) == 1
        assert local[0].extra["join_safe"] is False


def test_empty_local_cache_does_not_trigger_exploration(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.schema_graph.local_collection.AuthManager") as auth,
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers") as explore,
    ):
        result = runner.invoke(app, ["schema", "collect"])
    assert result.exit_code == 0, result.output
    auth.assert_not_called()
    explore.assert_not_called()


def test_live_collection_queries_only_the_discovered_target_and_reuses_validation(local_results):
    rows = [
        {"TableName": "Second", "ColumnName": column, "ColumnType": "string"}
        for column in ("Who", "Timestamp", "Unrelated")
    ]
    target = "interp:Second.Who:local-upn-lower:occurrence"
    response = HuntingResult(
        results=[
            {
                "TargetLocator": "Second.Who",
                "TargetInterpretation": target,
                "MatchRows": 3,
                "MatchedSeeds": 2,
            }
        ],
        schema=[],
        stats={},
    )
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {})),
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch("xdr_cli.schema_graph.local_collection.XDRClient") as client,
        patch(
            "xdr_cli.schema_graph.local_collection.run_query",
            new_callable=AsyncMock,
            return_value=response,
        ) as query,
    ):
        client.return_value.close = AsyncMock()
        first = runner.invoke(app, ["schema", "collect"])
        assert first.exit_code == 0, first.output
        assert query.await_count == 1
        kql = query.call_args.args[1]
        assert "Second" in kql and "Unrelated" not in kql and "First\n" not in kql
        second = runner.invoke(app, ["schema", "collect"])
        assert second.exit_code == 0, second.output
        assert query.await_count == 1
    overlay = load_tenant_overlay("tenant")
    assert len(overlay.observations) == 2
    effective = _compose_effective(
        rows,
        tenant_id="tenant",
        canonical=load_packaged_graph(),
        overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    assert any(
        "local-validation" in r.extra.get("evidence_stages", [])
        for r in effective.graph.relationships.values()
    )


def test_compatible_targets_share_one_query_and_preserve_all_original_evidence(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    source = write_result(
        [{"Principal": "user@example.com"}],
        command="hunt run",
        query="First | project Principal",
        tenant_id="tenant",
    )
    target = write_result(
        [{"Who": "user@example.com", "Owner": "user@example.com"}],
        command="hunt run",
        query="Second | project Who, Owner",
        tenant_id="tenant",
    )
    rows = [
        {"TableName": "Second", "ColumnName": c, "ColumnType": "string"}
        for c in ("Who", "Owner", "Timestamp")
    ]
    result_rows = [
        {
            "TargetLocator": f"Second.{c}",
            "TargetInterpretation": f"interp:Second.{c}:local-upn-lower:occurrence",
            "MatchRows": 1,
            "MatchedSeeds": 1,
        }
        for c in ("Who", "Owner")
    ]
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(rows, {})),
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch("xdr_cli.schema_graph.local_collection.XDRClient") as client,
        patch(
            "xdr_cli.schema_graph.local_collection.run_query",
            new_callable=AsyncMock,
            return_value=HuntingResult(results=result_rows, schema=[], stats={}),
        ) as query,
    ):
        client.return_value.close = AsyncMock()
        first = runner.invoke(app, ["schema", "collect"])
        assert first.exit_code == 0, first.output
        second = runner.invoke(app, ["schema", "collect"])
        assert second.exit_code == 0, second.output
        assert query.await_count == 1
    overlay = load_tenant_overlay("tenant")
    live = [o for o in overlay.observations if o.extra.get("evidence_stage") == "local-validation"]
    assert len(live) == 2
    for observation in live:
        assert {source.receipt.run_id, target.receipt.run_id}.issubset(observation.evidence_run_ids)
    from xdr_cli.commands.results_cmd import _schema_evidence_references

    # The public pruning path must retain both originals and the validation,
    # even though a live observation's target reference is the validation run.
    retained = _schema_evidence_references().all_run_ids
    assert source.receipt.run_id in retained
    assert target.receipt.run_id in retained


@pytest.mark.parametrize("same_content", [True, False])
def test_copied_source_results_cannot_satisfy_independent_validation(same_content):
    from xdr_cli.schema_graph.local_collection import local_observation, pair_graph
    from xdr_cli.schema_graph.local_discovery import LocalPair

    canonical = load_packaged_graph()
    first = LocalPair("First.User", "Second.Who", "upn-lower", "a", "b", 4, "2026-10-03T00:00:00Z")
    second = LocalPair("First.User", "Second.Who", "upn-lower", "c", "d", 4, "2026-10-03T00:00:00Z")
    graph, interpretations = pair_graph(first, canonical)
    observations = tuple(local_observation(pair, interpretations) for pair in (first, second))

    def verified(_graph, observation, **_kwargs):
        index = observations.index(observation)
        return {
            "sampled_cohort": frozenset(f"user-{index}-{n}@example.com" for n in range(4)),
            "source_content_digest": "copy" if same_content else f"distinct-{index}",
        }

    with patch("xdr_cli.commands.schema_cmd._eligible_observation_evidence", side_effect=verified):
        effective = _compose_effective(
            [],
            tenant_id="tenant",
            canonical=canonical,
            overlays=(graph,),
            observations=observations,
        )
    discovered = [
        r
        for r in effective.graph.relationships.values()
        if r.extra.get("observation_ids") == sorted(o.observation_id for o in observations)
    ]
    assert len(discovered) == 1
    assert discovered[0].status.value == "observed"


def test_result_prune_retires_automatic_pins_and_collection_does_not_resurrect(local_results):
    from datetime import UTC, datetime, timedelta
    from xdr_cli.config import get_config_home

    for path in (get_config_home() / "results").glob("*/*.meta.json"):
        meta = json.loads(path.read_text())
        meta["created_at"] = (datetime.now(UTC) - timedelta(days=100)).isoformat()
        path.write_text(json.dumps(meta))
    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        collected = runner.invoke(app, ["schema", "collect", "--local-only"])
        assert collected.exit_code == 0, collected.output
        assert load_tenant_overlay("tenant").observations
        pruned = runner.invoke(app, ["results", "prune", "--older-than", "30", "--yes"])
        assert pruned.exit_code == 0, pruned.output
        assert not load_tenant_overlay("tenant").observations
        assert load_tenant_overlay("tenant").metadata["discovery_retired_before"]
        collected = runner.invoke(app, ["schema", "collect", "--local-only"])
        assert collected.exit_code == 0, collected.output
        assert not load_tenant_overlay("tenant").observations


def test_evidence_prune_does_not_repin_still_present_hunts(local_results):
    from datetime import UTC, datetime, timedelta
    from xdr_cli.config import get_config_home

    for path in (get_config_home() / "results").glob("*/*.meta.json"):
        meta = json.loads(path.read_text())
        meta["created_at"] = (datetime.now(UTC) - timedelta(days=100)).isoformat()
        path.write_text(json.dumps(meta))
    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        assert runner.invoke(app, ["schema", "collect", "--local-only"]).exit_code == 0
        pruned = runner.invoke(app, ["schema", "prune-evidence", "--older-than", "30", "--yes"])
        assert pruned.exit_code == 0, pruned.output
        assert not load_tenant_overlay("tenant").observations
        collected = runner.invoke(app, ["schema", "collect", "--local-only"])
        assert collected.exit_code == 0, collected.output
        assert not load_tenant_overlay("tenant").observations


@pytest.mark.parametrize("flag", ["--resume", "--exhaustive"])
def test_retired_collection_flags_never_suggest_unrelated_options(local_results, flag):
    args = ["schema", "collect", flag]
    if flag == "--resume":
        args.append("old-run")
    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        result = runner.invoke(app, args)
    assert result.exit_code == 6
    assert "CLI_REMOVED_OPTION" in result.stdout
    assert "nearest_option" not in result.stdout
