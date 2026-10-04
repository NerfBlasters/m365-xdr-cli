"""Offline behavioral regressions from the independent final data review."""

import json
import re
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from xdr_cli.commands.schema_cmd import _candidate_report, _compose_effective
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.json_expansion import expand_json_string_columns
from xdr_cli.results import write_result
from xdr_cli.schema_graph.discovery_query import compile_discovery_query
from xdr_cli.schema_graph.lineage import recover_field_origins
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.local_collection import collect_local
from xdr_cli.schema_graph.local_discovery import row_identifiers
from xdr_cli.schema_graph.overlay import load_tenant_overlay

TENANT = "synthetic-final-review"
SCHEMA = [{"TableName": "Second", "ColumnName": c} for c in ("Who", "Timestamp")]


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return AppContext(Config(tenant_id=TENANT), quiet=True, no_interactive=True)


def save_cohort(values):
    for table, column in (("First", "Principal"), ("Second", "Who")):
        write_result(
            [{column: value} for value in values],
            command="hunt run",
            query=f"{table} | project {column}",
            tenant_id=TENANT,
        )


async def collect(ctx, *, local_only=False):
    await collect_local(
        ctx,
        plan_only=False,
        local_only=local_only,
        lookback="30d",
        samples=6,
        max_queries=20,
        timeout=30,
        schema_rows=SCHEMA,
        canonical=load_packaged_graph(),
        on_result=lambda result: None,
    )


def empirical_relations():
    overlay = load_tenant_overlay(TENANT)
    effective = _compose_effective(
        SCHEMA,
        tenant_id=TENANT,
        canonical=load_packaged_graph(),
        overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    return [r for r in effective.graph.relationships.values() if r.extra.get("evidence_stages")]


@pytest.mark.asyncio
async def test_existing_disjoint_evidence_survives_an_added_superset(ctx):
    """Use durable source/probe artifacts and the real evidence verifier/composer."""
    left = [f"member-{n}@example.invalid" for n in range(3)]
    right = [f"member-{n}@example.invalid" for n in range(3, 6)]

    async def respond(_client, query):
        count = len(set(re.findall(r"member-[0-5]@example.invalid", query)))
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

    with (
        patch("xdr_cli.schema_graph.local_collection.AuthManager"),
        patch(
            "xdr_cli.schema_graph.local_collection.XDRClient",
            side_effect=lambda **kwargs: SimpleNamespace(close=AsyncMock()),
        ),
        patch("xdr_cli.schema_graph.local_collection.run_query", side_effect=respond) as query,
    ):
        for values in (left, right):
            save_cohort(values)
            await collect(ctx)
        before = empirical_relations()
        assert len(before) == 1
        assert before[0].status.value == "validated"
        save_cohort(left + right)
        await collect(ctx)

    assert query.await_count == 3
    after = empirical_relations()
    assert len(after) == 1
    assert after[0].id == before[0].id
    assert after[0].status.value == "validated"


@pytest.mark.asyncio
async def test_available_weak_candidate_is_reported_truthfully(ctx):
    save_cohort(["one@example.invalid"])
    with patch("xdr_cli.schema_graph.local_collection.AuthManager") as auth:
        await collect(ctx, local_only=True)
    auth.assert_not_called()
    with patch("xdr_cli.commands.schema_cmd._load_cache", return_value=(SCHEMA, {})):
        rows, _, _, effective = _candidate_report(ctx, include_evidence_refs=False)
    assert len(rows) == 1
    row = rows[0]
    assert effective.graph.relationships[row["RelationshipId"]].status.value == "candidate"
    assert row["EvidenceArtifactsAvailable"] is True
    assert row["Status"] == "candidate"
    assert row["EvidenceLevel"] == "candidate"
    assert row["LifecycleState"] != "inactive-evidence-unavailable"


@pytest.mark.parametrize("error", [ValueError("numeric decoder limit"), RecursionError()])
def test_decoder_rejection_preserves_raw_value_and_other_columns(error):
    rows = [{"RawEventData": '{"who": "one@example.invalid"}', "Other": "unchanged"}]
    with patch("xdr_cli.json_expansion.json.loads", side_effect=error):
        expanded = expand_json_string_columns(rows)
    assert expanded == rows
    assert expanded is not rows
    assert expanded[0] is not rows[0]


def test_encoded_json_is_decoded_at_root_only_not_at_nested_discovery_steps():
    """Compiler assertions are offline contracts, not a KQL execution substitute."""
    encoded = json.dumps({"who": "one@example.invalid"})
    origins = recover_field_origins("Events | project RawEventData")
    root_values = list(row_identifiers({"RawEventData": encoded}, origins, Counter()))
    assert root_values == [("Events.RawEventData#/who", "upn-lower", "one@example.invalid")]
    assert list(row_identifiers({"RawEventData": {"message": encoded}}, origins, Counter())) == []

    query = compile_discovery_query(
        ["one@example.invalid"],
        normalizer="upn-lower",
        tables=["Events"],
        time_column="Timestamp",
        max_depth=3,
    )
    step = query.split("let xdr_discovery_step =", 1)[1].split("};", 1)[0]
    root, descendants = query.split("| invoke xdr_discovery_step()", 1)
    assert "xdr_discovery_container(Value)" in root
    assert "RawEventData" in root
    assert "xdr_discovery_container(Value)" not in step
    assert "parse_json(tostring(Value))" not in step
    assert "xdr_discovery_container(Value)" not in descendants
    assert "parse_json(tostring(Value))" not in descendants
