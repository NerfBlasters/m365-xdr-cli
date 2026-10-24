"""Physical checks must not turn reference knowledge or incomplete scans into evidence."""

from importlib.resources import files

import pytest

from xdr_cli.hunting_tables import PROBE_TABLES
from xdr_cli.schema_graph.effective import (
    EffectiveGraph,
    FieldAvailability,
    compose_effective_graph,
)
from xdr_cli.schema_graph.catalog import exhaustive_probe_targets
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.physical import coverage_summary, probe_coverage
from xdr_cli.schema_graph.traversal import pivot


def _probe(*tables):
    branches = ",\n".join(
        f'({table} | getschema | extend TableName = "{table}")' for table in tables
    )
    return (
        f"union isfuzzy=true\n{branches}\n"
        "| project TableName, ColumnName, ColumnType, ColumnOrdinal\n"
        "| sort by TableName asc, ColumnOrdinal asc"
    )


def test_packaged_probe_scope_is_known_but_fuzzy_absence_is_not_conclusive():
    query = files("xdr_cli.queries").joinpath("sys_schema_probe.kql").read_text()
    coverage = probe_coverage(query, [{"TableName": "DeviceInfo"}], "mde")

    assert coverage["scope_known"] is True
    assert coverage["probe_tables"] == list(PROBE_TABLES)
    assert {"DeviceInfo", "SigninLogs", "AuditLogs"} <= set(coverage["probe_tables"])
    assert coverage["returned_tables"] == ["DeviceInfo"]
    assert coverage["execution_surface"] == "mde"
    assert coverage["complete"] is False
    assert coverage["absence_is_conclusive"] is False
    assert isinstance(coverage_summary(coverage)["probe_tables"], int)


@pytest.mark.parametrize("query", [
    'DeviceInfo | getschema | extend TableName = "DeviceInfo"',
    _probe("DeviceInfo") + " | take 1",
    _probe("DeviceInfo").replace('TableName = "DeviceInfo"', 'TableName = "OtherTable"'),
    _probe("DeviceInfo").replace("| getschema", "| where false | getschema"),
    'print Text="DeviceInfo | getschema"',
])
def test_custom_queries_never_inherit_packaged_probe_coverage(query):
    coverage = probe_coverage(query, [], "graph")
    assert coverage["scope_known"] is False
    assert coverage["probe_tables"] is None
    assert coverage["method"] == "custom-query"


def test_missing_unchecked_table_differs_from_unobserved_checked_table():
    coverage = probe_coverage(_probe("DeviceInfo"), [], "graph")
    effective = compose_effective_graph([], coverage=coverage)
    assert effective.field_availability["field:DeviceInfo.DeviceId"] is (
        FieldAvailability.NOT_OBSERVED
    )
    assert effective.field_availability["field:CloudAppEvents.AccountObjectId"] is (
        FieldAvailability.NOT_PROBED
    )
    assert not effective.queryable_fields
    # Old snapshots lack scope; preserve their label without granting queryability.
    legacy = compose_effective_graph([])
    assert legacy.field_availability["field:DeviceInfo.DeviceId"] is FieldAvailability.UNAVAILABLE
    assert not legacy.queryable_fields


@pytest.mark.parametrize("physical_type", ["Int64", "Dynamic", "MysteryType", None])
def test_incompatible_or_unknown_explicit_storage_type_blocks_existing_field(physical_type):
    effective = compose_effective_graph([
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": physical_type},
    ])
    identifier = "field:DeviceInfo.DeviceId"
    assert effective.field_availability[identifier] is FieldAvailability.TYPE_CONFLICT
    assert identifier not in effective.queryable_fields


@pytest.mark.parametrize("physical_type", ["String", "System.String", " string "])
def test_equivalent_storage_spellings_remain_queryable(physical_type):
    effective = compose_effective_graph([
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": physical_type},
    ])
    assert "field:DeviceInfo.DeviceId" in effective.queryable_fields


@pytest.mark.parametrize("physical_type", ["String", "Dynamic", "System.Object"])
def test_nested_leaf_type_does_not_conflict_with_json_outer_storage(physical_type):
    identifier = "field:CloudAppEvents.RawEventData#/UserId"
    effective = compose_effective_graph([
        {"TableName": "CloudAppEvents", "ColumnName": "RawEventData", "ColumnType": physical_type},
    ])
    assert effective.field_availability[identifier] is FieldAvailability.OUTER_AVAILABLE_UNOBSERVED
    assert identifier in effective.queryable_fields


def test_conflicting_duplicate_physical_types_cannot_grant_queryability():
    effective = compose_effective_graph([
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": physical_type}
        for physical_type in ("String", "Int64")
    ])
    assert "field:DeviceInfo.DeviceId" not in effective.queryable_fields


def test_target_catalog_cannot_reintroduce_a_field_with_incompatible_storage():
    graph = load_packaged_graph()
    source = graph.interpretations["interp:DeviceInfo.DeviceId:mde-device-id:subject"]
    rows = [
        {"TableName": table, "ColumnName": "DeviceId", "ColumnType": physical_type}
        for table, physical_type in (
            ("DeviceInfo", "String"),
            ("DeviceNetworkEvents", "Dynamic"),
            ("DeviceFileEvents", "String"),
        )
    ]
    targets, _additions = exhaustive_probe_targets(rows, graph, source)
    locators = {str(target.field.locator) for target in targets}
    assert "DeviceNetworkEvents.DeviceId" not in locators
    assert "DeviceFileEvents.DeviceId" in locators


@pytest.mark.parametrize("state", [
    "not-probed", "not-observed", "type-conflict", "future-unknown-state",
])
def test_new_unknown_states_do_not_become_queryable_through_negative_gates(state):
    graph = load_packaged_graph()
    availability = {identifier: state for identifier in graph.fields}
    effective = EffectiveGraph(graph, availability)
    assert not effective.queryable_fields
    steps = pivot(graph, "DeviceInfo.DeviceId", field_availability=availability)
    assert steps
    assert all(not step.source_available and not step.target_available for step in steps)
