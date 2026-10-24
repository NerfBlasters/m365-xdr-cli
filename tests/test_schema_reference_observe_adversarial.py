"""Imported reference meanings must not bypass scope or orphan saved observations."""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from xdr_cli.commands import schema_cmd
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import ConflictError
from xdr_cli.hunting_result import HuntingResult
from xdr_cli.schema_graph.catalog import exhaustive_probe_targets
from xdr_cli.schema_graph.effective import compose_effective_graph
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.model import Graph
from xdr_cli.schema_graph.overlay import load_tenant_overlay, publish_tenant_overlay
from xdr_cli.schema_graph.probe import aggregate_observation
from xdr_cli.schema_graph.reference import publish_snapshot
from xdr_cli.schema_graph.reference_routes import compose_reference_routes

_GUID_SEEDS = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
)
_DEVICE_SEEDS = tuple(f"{index:040x}" for index in (0x123456789ABC, 0x23456789ABCD, 0x3456789ABCDE))


def _snapshot(home, rows, source, target, *, family, route_id="reference-route", path=None):
    tables = {source[0], target[0]}
    record = {
        "id": route_id, "title": "Scoped test route", "family": family,
        "from": {"table": source[0], "column": source[1], "timeColumn": "Timestamp"},
        "to": {"table": target[0], "column": target[1], "timeColumn": "Timestamp"},
        "guidance": "Preserve the reference contract.",
    }
    if path:
        record["from"]["path"] = path
    data = {
        "schema": [{"Name": table, "Schema": [
            {"Name": row["ColumnName"], "Type": row["ColumnType"]}
            for row in rows if row["TableName"] == table
        ]} for table in sorted(tables)],
        "relations": {"version": 1, "relations": [record]},
        "structured": {"version": 1, "entries": []}, "actions": [],
    }
    return publish_snapshot(home, {key: json.dumps(value).encode() for key, value in data.items()})


def _rows(*tables):
    return [{"TableName": table, "ColumnName": column, "ColumnType": storage}
            for table, columns in tables for column, storage in columns]


class _MockHunting:
    def __init__(self):
        self.queries = []

    async def execute_hunting(self, query):
        self.queries.append(query)
        pairs = re.findall(r'"TargetLocator","([^"]+)","TargetInterpretation","([^"]+)"', query)
        assert pairs, "Only synthetic target aggregation should run in this test"
        return HuntingResult([], [
            {"TargetLocator": locator, "TargetInterpretation": interpretation,
             "MatchedSeeds": 3, "MatchRows": 3}
            for locator, interpretation in pairs
        ], {})

    async def close(self):
        pass


async def _observe(ctx, seed_file, source, target):
    await schema_cmd._schema_observe(
        ctx, locator=source, lookback="7d", samples=3, batch_size=20, max_targets=100,
        target_tables=(target,), exclude_tables=(), timeout=None, private_debug_output=None,
        plan_only=False, from_file=seed_file, from_stdin=False, from_run=None,
        start_query=0, max_queries=None, required_schema_generation=None,
    )


@pytest.mark.asyncio
async def test_reference_process_source_refuses_before_backend_creation(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    rows = _rows(
        ("DeviceProcessEvents", [("ProcessUniqueId", "string"), ("DeviceId", "string"),
                                 ("ProcessCreationTime", "datetime"), ("Timestamp", "datetime")]),
        ("DeviceEvents", [("InitiatingProcessUniqueId", "string"), ("DeviceId", "string"),
                          ("Timestamp", "datetime")]),
    )
    _snapshot(tmp_path, rows, ("DeviceProcessEvents", "ProcessUniqueId"),
              ("DeviceEvents", "InitiatingProcessUniqueId"), family="process-start-key")
    monkeypatch.setattr(schema_cmd, "_load_cache", lambda ctx: (rows, {"generation": "test"}))
    monkeypatch.setattr(schema_cmd, "create_client",
                        lambda *a, **kw: pytest.fail("backend created"))
    ctx = AppContext(Config(tenant_id="synthetic"), quiet=True)
    with pytest.raises(ConflictError) as caught:
        await _observe(ctx, None, "DeviceProcessEvents.ProcessUniqueId", "DeviceEvents")
    assert caught.value.error_code == "SCHEMA_REFERENCE_SOURCE_UNSUPPORTED"
    assert int(caught.value.exit_code) == 13
    assert not load_tenant_overlay("synthetic").observations


@pytest.mark.asyncio
@pytest.mark.parametrize("derived", [False, True])
async def test_imported_targets_persist_neutral_dependencies_and_remain_composable(
    tmp_path, monkeypatch, derived,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    if derived:
        source, target, column = "DeviceInfo", "NovelEvents", "DeviceId"
        rows = _rows(*[(table, [(column, "string"), ("Timestamp", "datetime")])
                       for table in (source, "DeviceEvents", target)])
        _snapshot(tmp_path, rows, (source, column), ("DeviceEvents", column),
                  family="defender-device")
        seeds = _DEVICE_SEEDS
    else:
        source, target, column = "IdentityInfo", "IdentityLogonEvents", "AccountObjectId"
        rows = _rows(*[(table, [(column, "string"), ("Timestamp", "datetime")])
                       for table in (source, target)])
        _snapshot(tmp_path, rows, (source, column), (target, column), family="entra-user")
        seeds = _GUID_SEEDS
    seed_file = tmp_path / "operator-seeds.txt"
    seed_file.write_text("\n".join(seeds) + "\n")
    monkeypatch.setattr(schema_cmd, "_load_cache", lambda ctx: (rows, {"generation": "test"}))
    hunting = _MockHunting()
    monkeypatch.setattr(schema_cmd, "create_client", lambda *a, **kw: hunting)
    ctx = AppContext(Config(tenant_id="synthetic"), quiet=True)
    await _observe(ctx, seed_file, source + "." + column, target)
    overlay = load_tenant_overlay("synthetic")
    assert len(hunting.queries) == 1
    assert len(overlay.observations) == 1
    observation = overlay.observations[0]
    assert observation.target_interpretation.endswith(":neutral")
    assert observation.target_interpretation in overlay.graph.interpretations
    interpretation = overlay.graph.interpretations[observation.target_interpretation]
    assert interpretation.extra["provisional"] is True
    assert interpretation.field_id in overlay.graph.fields
    effective = schema_cmd._compose_effective(
        rows, tenant_id="synthetic", canonical=load_packaged_graph(), overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    assert not effective.observation_gaps
    assert observation.target_interpretation in effective.graph.interpretations


def test_contextual_imported_target_cannot_be_replaced_by_unconstrained_provisional(tmp_path):
    rows = _rows(
        ("IdentityInfo", [("AccountObjectId", "string"), ("Timestamp", "datetime")]),
        ("AuditLogs", [("TargetResources", "dynamic"), ("Timestamp", "datetime")]),
    )
    snapshot = _snapshot(
        tmp_path, rows, ("AuditLogs", "TargetResources"), ("IdentityInfo", "AccountObjectId"),
        family="entra-user", route_id="audit-target-resource-id-account-object-id", path="[].id",
    )
    core = load_packaged_graph()
    graph = compose_reference_routes(compose_effective_graph(rows, canonical=core),
                                     snapshot, rows).graph
    source = next(item for item in core.interpretations.values()
                  if str(core.fields[item.field_id].locator) == "IdentityInfo.AccountObjectId")
    imported = frozenset(set(graph.interpretations) - set(core.interpretations))
    targets, additions = exhaustive_probe_targets(
        rows, graph, source, excluded_interpretation_ids=imported,
    )
    locators = {str(target.field.locator) for target in targets}
    assert "AuditLogs.TargetResources#/*/id" not in locators
    assert not any(str(additions.fields[item.field_id].locator) == "AuditLogs.TargetResources#/*/id"
                   for item in additions.interpretations.values())


def test_legacy_orphan_observations_are_retired_without_breaking_composition(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    observation = aggregate_observation(
        observation_id="probe:legacy-orphan", source_interpretation="interp:ephemeral-source",
        target_interpretation="interp:ephemeral-target", transform="identity", distinct_seeds=0,
        matched_seeds=0, matched_rows=0, probe_runs=1, provenance=("legacy:reference-import",),
        outcome="no-match",
    )
    publish_tenant_overlay("synthetic", graph=Graph(), observations=(observation,))
    overlay = load_tenant_overlay("synthetic")
    effective = schema_cmd._compose_effective(
        [], tenant_id="synthetic", canonical=load_packaged_graph(), overlays=(overlay.graph,),
        observations=overlay.observations,
    )
    assert len(effective.observation_gaps) == 1
    assert not any("ephemeral" in identifier for identifier in effective.graph.interpretations)


def test_stix_feed_prefix_comparison_keeps_provenance_case():
    from xdr_cli.schema_graph.reference import ReferenceEndpoint, ReferenceRoute
    from xdr_cli.schema_graph.reference_query import compile_reference_query

    rows = _rows(*[(table, [("Id", "string"), ("TenantId", "string"),
                            ("TimeGenerated", "datetime"), ("Data", "dynamic"),
                            ("IsDeleted", "bool"), ("StixType", "string")])
                   for table in ("ThreatIntelObjects", "ThreatIntelIndicators")])
    route = ReferenceRoute(
        "stix-relationship-source-threat-intel-indicators", "STIX source", "stix-object",
        ReferenceEndpoint("ThreatIntelObjects", "Data", ("source_ref",), "TimeGenerated"),
        ReferenceEndpoint("ThreatIntelIndicators", "Data", ("id",), "TimeGenerated"),
        "Match workspace plus feed provenance; preserve source and target roles.", {},
    )
    compiled = compile_reference_query(route, rows)
    assert compiled.scope["source_key_columns"] == ["TenantId", "FeedKey"]
    expressions = re.findall(r"extend __p1 = ([^\n]+)", compiled.query)
    assert len(expressions) == 2
    # The reference uses exact equality for the Id prefix. Case folding would
    # falsely equate FeedA---relationship and feeda---indicator in one workspace.
    assert all("tolower(" not in expression for expression in expressions)


@pytest.mark.parametrize("scoped", [False, True])
def test_ledger_reader_retries_generation_retired_by_a_concurrent_writer(
    tmp_path, monkeypatch, scoped,
):
    from xdr_cli.schema_graph import reference_state

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    options = {"lookback": "7d", "samples": 50, "row_limit": 1000}
    arguments = dict(reference_digest="a" * 64, schema_digest="b" * 64, options=options)
    reference_state.save_validation_state(
        tmp_path, "synthetic", routes={"route": {"status": "pending", "progress": 1}}, **arguments,
    )
    root = reference_state.validation_root(tmp_path, "synthetic")
    pointer = (root / f"scope.{reference_state.validation_key('a' * 64, 'b' * 64, options)}.json"
               if scoped else root / "current.json")
    original_generation = json.loads(pointer.read_text())["file"]
    original_read = reference_state._read_document
    published = False

    def interleaved_read(path):
        nonlocal published
        original_bytes = original_read(path)
        if path == pointer and not published:
            # Model a writer advancing the pointer and eagerly collecting the
            # immutable generation after this reader already fetched old bytes.
            published = True
            reference_state.save_validation_state(
                tmp_path, "synthetic", routes={"route": {"status": "pending", "progress": 2}},
                **arguments,
            )
            assert not (root / original_generation).exists()
        return original_bytes

    monkeypatch.setattr(reference_state, "_read_document", interleaved_read)
    value = reference_state.load_validation_state(
        tmp_path, "synthetic", reference_digest="a" * 64, schema_digest="b" * 64,
        options=options if scoped else None,
    )
    assert published and value["routes"]["route"]["progress"] == 2


def test_missing_generation_with_unchanged_pointer_remains_an_integrity_error(
    tmp_path, monkeypatch,
):
    from xdr_cli.schema_graph import reference_state
    from xdr_cli.schema_graph.reference import ReferenceError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    reference_state.save_validation_state(
        tmp_path, "synthetic", reference_digest="a" * 64, schema_digest="b" * 64,
        options={"lookback": "7d", "samples": 50, "row_limit": 1000}, routes={},
    )
    root = reference_state.validation_root(tmp_path, "synthetic")
    pointer_before = (root / "current.json").read_bytes()
    filename = json.loads(pointer_before)["file"]
    (root / filename).unlink()
    with pytest.raises(ReferenceError):
        reference_state.load_validation_state(
            tmp_path, "synthetic", reference_digest="a" * 64, schema_digest="b" * 64,
        )
    assert (root / "current.json").read_bytes() == pointer_before


def test_semantically_equal_ledger_generation_has_identical_persisted_bytes(tmp_path, monkeypatch):
    from xdr_cli.schema_graph import reference_state

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    options = {"lookback": "7d", "samples": 50, "row_limit": 1000}
    arguments = dict(reference_digest="a" * 64, schema_digest="b" * 64)
    reference_state.save_validation_state(
        tmp_path, "synthetic", options=options,
        routes={"route": {"status": "pending", "progress": 1}}, **arguments,
    )
    root = reference_state.validation_root(tmp_path, "synthetic")
    first_pointer = json.loads((root / "current.json").read_text())
    first_bytes = (root / first_pointer["file"]).read_bytes()
    content_key = hashlib.sha256(first_bytes).hexdigest()[:24]
    assert first_pointer["file"] == f"validation.{content_key}.json"
    reference_state.save_validation_state(
        tmp_path, "synthetic", options=dict(reversed(list(options.items()))),
        routes={"route": {"progress": 1, "status": "pending"}}, **arguments,
    )
    second_pointer = json.loads((root / "current.json").read_text())
    assert second_pointer["file"] == first_pointer["file"]
    # A content-addressed generation may not change its bytes merely because
    # two callers constructed equivalent dictionaries in a different order.
    assert (root / second_pointer["file"]).read_bytes() == first_bytes
    assert second_pointer["sha256"] == first_pointer["sha256"]
