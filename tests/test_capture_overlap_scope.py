"""Complete-capture shortcuts preserve evidence scope and conservative status."""

import hashlib
from dataclasses import replace
from unittest.mock import patch

import pytest

from tests.capture_fakes import FakeHunting
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.schema_graph.capture_artifacts import ResultCaptureSink
from xdr_cli.schema_graph.capture_engine import CaptureBudgets, capture_recent
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.local_collection import collect_local, verify_local_observation
from xdr_cli.schema_graph.model import empirical_relationship_from_observations
from xdr_cli.schema_graph.overlay import load_tenant_overlay
from xdr_cli.schema_graph.reference_state import physical_schema_digest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "count,cap,separate_jobs,expected_stage,skipped",
    [
        (3, 10, False, "capture-overlap-complete", 1),
        (2, 10, False, "local-overlap", 1),
        (4, 3, False, "local-overlap", 0),
        (3, 10, True, "local-overlap", 0),
    ],
)
async def test_shortcut_requires_same_complete_job_and_three_eligible_values(
    tmp_path, monkeypatch, count, cap, separate_jobs, expected_stage, skipped
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    tenant = "capture-scope"
    schema = [
        {"TableName": table, "ColumnName": "Who", "ColumnType": "string"}
        for table in ("FirstState", "SecondState")
    ]
    data = {
        table: [{"Who": f"person-{n}@example.invalid", "RecordType": table} for n in range(count)]
        for table in ("FirstState", "SecondState")
    }
    sink = ResultCaptureSink(tenant_id=tenant)
    groups = (
        [("FirstState",), ("SecondState",)] if separate_jobs else [("FirstState", "SecondState")]
    )
    for tables in groups:
        await capture_recent(
            FakeHunting(data),
            schema_rows=schema,
            tables=tables,
            binding={
                "tenant_fingerprint": hashlib.sha256(tenant.encode()).hexdigest(),
                "backend": "official",
                "schema_digest": physical_schema_digest(schema),
                "horizon_seconds": 86400,
            },
            state_dir=tmp_path / "jobs",
            sink=sink,
            budgets=CaptureBudgets(request_rows=cap, min_request_rows=1),
        )
    results = []
    with patch("xdr_cli.schema_graph.local_collection.create_client") as client:
        await collect_local(
            AppContext(Config(tenant_id=tenant)),
            plan_only=False,
            local_only=False,
            lookback="24h",
            samples=5,
            max_queries=20,
            timeout=30,
            schema_rows=schema,
            canonical=load_packaged_graph(),
            on_result=results.append,
        )
    client.assert_not_called()  # Unbounded untimed checks remain excluded.
    overlay = load_tenant_overlay(tenant)
    assert len(overlay.observations) == 1
    observation = overlay.observations[0]
    assert observation.extra["evidence_stage"] == expected_stage
    assert results[-1].receipt.context["validation_skipped_complete_capture_pairs"] == skipped
    if count == 2:
        assert (
            results[-1].receipt.context["local_coverage"]["complete_capture_pairs_below_threshold"]
            == 1
        )
    assert verify_local_observation(overlay.graph, observation, tenant) is not None
    relationship = empirical_relationship_from_observations(
        (observation,), verified_observation_ids=frozenset({observation.observation_id})
    )
    assert relationship.status.value == ("candidate" if count == 2 else "observed")
    assert relationship.extra["join_safe"] is False
    if expected_stage == "local-overlap":
        forged = replace(
            observation, extra={**observation.extra, "evidence_stage": "capture-overlap-complete"}
        )
        assert verify_local_observation(overlay.graph, forged, tenant) is None
