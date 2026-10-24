"""Behavioral boundaries for per-table, per-cohort validation."""

import json
import re
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.hunting_result import HuntingResult
from xdr_cli.results import write_result
from xdr_cli.schema_graph.effective import merge_graphs
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.local_collection import (
    collect_local,
    pair_graph,
    verify_local_observation,
)
from xdr_cli.schema_graph.local_discovery import LocalPair
from xdr_cli.schema_graph.local_validation import ValidationTarget, compile_batches, compile_query
from xdr_cli.schema_graph.model import FieldLocator, GraphValidationError
from xdr_cli.schema_graph.overlay import load_tenant_overlay


def target(key, locator="Target.Who", normalizer="upn-lower", seeds=("one@example.invalid",)):
    pair = LocalPair(
        "Source.User", locator, normalizer, "a", "b", len(seeds), "2026-10-24T00:00:00Z"
    )
    _, interps = pair_graph(pair, load_packaged_graph())
    return ValidationTarget(key, interps[1], FieldLocator.parse(locator), seeds)


def test_different_cohorts_same_locator_share_one_scan_and_keep_independent_counts():
    entries = [
        target("first"),
        target("second", seeds=("two@example.invalid",)),
        target("third", locator="Target.Owner", normalizer="identity", seeds=("ABC",)),
    ]
    batches = compile_batches(entries, lookback="24h", time_column="Timestamp", batch_size=20)
    assert len(batches) == 1
    assert batches[0].kql.count("\nTarget\n") == 1
    assert {item.pair_key for item in batches[0].targets} == {"first", "second", "third"}
    assert batches[0].kql.count("count_distinctif(") == 3
    assert "set_has_element(_xdr_seeds_0, __xdr_value_0)" in batches[0].kql
    assert "set_has_element(_xdr_seeds_1, __xdr_value_1)" in batches[0].kql


def test_array_expansions_are_isolated_without_cross_product_or_extra_cohort_scans():
    entries = [
        target("one", "Target.Data#/Users/*/Id"),
        target("two", "Target.Data#/Users/*/Id", seeds=("two@example.invalid",)),
        target("three", "Target.Data#/Owners/*/Id"),
        target("four"),
    ]
    batches = compile_batches(entries, lookback="24h", time_column="Timestamp")
    assert len(batches) == 3
    assert sorted(len(batch.targets) for batch in batches) == [1, 1, 2]
    assert all(batch.kql.count("mv-expand __xdr_nested_") <= 1 for batch in batches)


def test_query_byte_budget_splits_many_cohorts_and_rejects_unbounded_seeds():
    entries = [
        target(
            str(index),
            normalizer="identity",
            seeds=tuple(f"{index}-{n}-" + "x" * 1900 for n in range(100)),
        )
        for index in range(3)
    ]
    batches = compile_batches(entries, lookback="24h", time_column="Timestamp")
    assert len(batches) == 3
    assert all(len(batch.kql.encode()) <= 256 * 1024 for batch in batches)
    with pytest.raises(GraphValidationError):
        compile_query(
            [target("bad", normalizer="identity", seeds=("x" * 2049,))],
            lookback="24h",
            time_column="Timestamp",
        )
    with pytest.raises(GraphValidationError):
        compile_query([target("same"), target("same")], lookback="24h", time_column="Timestamp")


@pytest.mark.asyncio
async def test_same_target_different_cohorts_remain_separate_and_reverify(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    tenant = "cohort-boundary"
    for table, values in (("First", ["one", "two", "three"]), ("Other", ["four", "five", "six"])):
        write_result(
            [{"Who": value + "@example.invalid"} for value in values],
            command="hunt run",
            query=f"{table} | project Who",
            tenant_id=tenant,
        )
    write_result(
        [
            {"Who": value + "@example.invalid"}
            for value in ["one", "two", "three", "four", "five", "six"]
        ],
        command="hunt run",
        query="Target | project Who",
        tenant_id=tenant,
    )
    schema = [
        {"TableName": "Target", "ColumnName": name, "ColumnType": kind}
        for name, kind in [("Who", "string"), ("Timestamp", "datetime")]
    ]

    async def respond(client, query):
        labels = re.findall(
            r'"PairKey","([^"]+)","TargetLocator","([^"]+)","TargetInterpretation","([^"]+)"', query
        )
        return HuntingResult(
            results=[
                {
                    "PairKey": key,
                    "TargetLocator": locator,
                    "TargetInterpretation": interp,
                    "MatchedSeeds": 3 if index == 0 else 0,
                    "MatchRows": 3 if index == 0 else 0,
                }
                for index, (key, locator, interp) in enumerate(labels)
            ],
            schema=[],
            stats={},
        )

    options = dict(
        plan_only=False,
        local_only=False,
        lookback="24h",
        samples=3,
        max_queries=10,
        timeout=30,
        schema_rows=schema,
        canonical=load_packaged_graph(),
        on_result=lambda result: None,
    )
    with (
        patch("xdr_cli.schema_graph.local_collection.create_client") as client,
        patch("xdr_cli.schema_graph.local_collection.run_query", side_effect=respond) as query,
    ):
        client.return_value.close = AsyncMock()
        await collect_local(AppContext(Config(tenant_id=tenant)), **options)
        overlay = load_tenant_overlay(tenant)
        observations = [
            o for o in overlay.observations if o.extra["evidence_stage"] == "local-validation"
        ]
        assert sorted(o.matched_seeds for o in observations) == [0, 3]
        graph = merge_graphs(load_packaged_graph(), overlay.graph)
        assert all(verify_local_observation(graph, o, tenant) for o in observations)
        await collect_local(AppContext(Config(tenant_id=tenant)), **options)
        assert query.await_count == 1
        # Rebinding a result row to the other pair's cohort cannot acquire evidence.
        forged = replace(
            observations[0],
            extra={**observations[0].extra, "local_pair": observations[1].extra["local_pair"]},
        )
        assert verify_local_observation(graph, forged, tenant) is None
        artifact = next(
            (tmp_path / "results").glob(
                "*/" + observations[0].target_artifact_run_id + ".meta.json"
            )
        )
        meta = json.loads(artifact.read_text())
        meta["local_validation"]["samples"] = 1
        artifact.write_text(json.dumps(meta))
        assert all(verify_local_observation(graph, o, tenant) is None for o in observations)
