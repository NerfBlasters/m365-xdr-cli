from __future__ import annotations

from xdr_cli.schema_graph.catalog import (
    exhaustive_probe_targets,
    graph_from_artifact_shapes,
    normalized_kql_type,
)
from xdr_cli.schema_graph.artifact_metadata import ArtifactShapeField
from xdr_cli.schema_graph.model import (
    FieldLocator,
    FieldRecord,
    Graph,
    InterpretationRecord,
    field_id,
    interpretation_id,
)
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.overlay import load_tenant_overlay, publish_tenant_overlay


def _source_graph() -> tuple[Graph, InterpretationRecord]:
    graph = Graph()
    locator = FieldLocator.parse("KnownTable.AccountUpn")
    graph.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="string"))
    source = InterpretationRecord(
        id=interpretation_id(locator, "entra-upn", "subject"),
        field_id=field_id(locator),
        entity_kind="user",
        namespace="entra-upn",
        role="subject",
        normalizer="upn-lower",
    )
    graph.add(source)
    return graph, source


def test_exhaustive_catalog_includes_cross_name_string_and_dynamic_fields():
    graph, source = _source_graph()
    rows = [
        {"TableName": "KnownTable", "ColumnName": "AccountUpn", "ColumnType": "String"},
        {"TableName": "OddTable", "ColumnName": "Initiator", "ColumnType": "System.String"},
        {"TableName": "OddTable", "ColumnName": "Payload", "ColumnType": "Dynamic"},
        {"TableName": "OddTable", "ColumnName": "Count", "ColumnType": "Int64"},
    ]
    targets, additions = exhaustive_probe_targets(rows, graph, source)
    assert [str(item.field.locator) for item in targets] == [
        "OddTable.Initiator",
        "OddTable.Payload",
    ]
    assert all(item.provisional for item in targets)
    assert all(item.interpretation.namespace == "entra-upn" for item in targets)
    assert "field:OddTable.Count" not in additions.fields


def test_sidecar_catalog_accepts_only_lossless_string_leaf_paths():
    shapes = (
        ArtifactShapeField(
            FieldLocator.parse("CloudAppEvents.RawEventData#/User.Id"),
            ("string",),
            2,
            2,
            "physical-shape",
        ),
        ArtifactShapeField(
            FieldLocator.parse("CloudAppEvents.RawEventData#/Count"),
            ("integer",),
            2,
            2,
            "physical-shape",
        ),
        ArtifactShapeField(
            FieldLocator.parse("CloudAppEvents.RawEventData#/Legacy"),
            ("string",),
            1,
            1,
            "legacy-shape-ambiguous",
        ),
    )
    graph = graph_from_artifact_shapes(shapes, provenance="artifact-shape:test")
    assert list(graph.fields) == ["field:CloudAppEvents.RawEventData#/User.Id"]


def test_getschema_type_normalization_is_closed():
    assert normalized_kql_type("System.String") == "string"
    assert normalized_kql_type("System.Object") == "dynamic"
    assert normalized_kql_type("DateTime") is None


def test_exhaustive_catalog_cannot_bypass_a_reviewed_nested_constraint():
    graph = load_packaged_graph()
    source = graph.interpretations[
        "interp:EntraIdSignInEvents.AccountObjectId:entra-object-id:subject"
    ]
    rows = [
        {
            "TableName": "EntraIdSignInEvents",
            "ColumnName": "AccountObjectId",
            "ColumnType": "String",
        },
        {
            "TableName": "CloudAppEvents",
            "ColumnName": "RawEventData",
            "ColumnType": "Dynamic",
        },
    ]

    targets, additions = exhaustive_probe_targets(rows, graph, source)

    assert "CloudAppEvents.RawEventData#/TargetResources/*/id" not in {
        str(item.field.locator) for item in targets
    }
    assert (
        "interp:CloudAppEvents.RawEventData#/TargetResources/*/id:entra-object-id:neutral"
        not in additions.interpretations
    )


def test_provisional_interpretation_carries_its_canonical_field_dependency(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    graph = load_packaged_graph()
    source = graph.interpretations[
        "interp:DeviceNetworkEvents.DeviceId:mde-device-id:subject"
    ]
    rows = [
        {
            "TableName": "DeviceNetworkEvents",
            "ColumnName": "DeviceId",
            "ColumnType": "String",
        },
        {
            "TableName": "DeviceFileEvents",
            "ColumnName": "SHA256",
            "ColumnType": "String",
        },
    ]

    targets, additions = exhaustive_probe_targets(rows, graph, source)

    provisional = next(
        item for item in targets if str(item.field.locator) == "DeviceFileEvents.SHA256"
    )
    assert provisional.provisional is True
    assert additions.fields[provisional.field.id] == graph.fields[provisional.field.id]
    additions.validate_references()
    publish_tenant_overlay("tenant", graph=additions)
    assert provisional.interpretation.id in load_tenant_overlay(
        "tenant"
    ).graph.interpretations


def test_persisted_provisional_target_stays_provisional_and_reviewed_wins():
    graph, source = _source_graph()
    target_locator = FieldLocator.parse("TargetTable.AccountUpn")
    target_field = FieldRecord(
        id=field_id(target_locator), locator=target_locator, kql_type="string"
    )
    graph.add(target_field)
    provisional = InterpretationRecord(
        id=interpretation_id(target_locator, "entra-upn", "neutral"),
        field_id=target_field.id,
        entity_kind="user",
        namespace="entra-upn",
        role="neutral",
        normalizer="upn-lower",
        extra={"status": "candidate", "provisional": True, "private": True},
    )
    graph.add(provisional)
    rows = [
        {
            "TableName": "TargetTable",
            "ColumnName": "AccountUpn",
            "ColumnType": "String",
        }
    ]

    provisional_targets, _ = exhaustive_probe_targets(rows, graph, source)
    assert provisional_targets[0].provisional is True

    reviewed = InterpretationRecord(
        id=interpretation_id(target_locator, "entra-upn", "subject"),
        field_id=target_field.id,
        entity_kind="user",
        namespace="entra-upn",
        role="subject",
        normalizer="upn-lower",
    )
    graph.add(reviewed)
    mixed_targets, _ = exhaustive_probe_targets(rows, graph, source)
    assert len(mixed_targets) == 1
    assert mixed_targets[0].interpretation.id == reviewed.id
    assert mixed_targets[0].provisional is False
