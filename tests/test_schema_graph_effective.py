from __future__ import annotations

import pytest

from xdr_cli.schema_graph.effective import (
    FieldAvailability,
    compose_effective_graph,
    merge_graphs,
)
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.model import (
    Cardinality,
    Confidence,
    Direction,
    FieldLocator,
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    ObservationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    field_id,
    interpretation_id,
    relationship_id,
)


def test_nested_field_distinguishes_outer_availability_from_observation():
    rows = [
        {"TableName": "CloudAppEvents", "ColumnName": "RawEventData"},
        {"TableName": "IdentityInfo", "ColumnName": "AccountUpn"},
    ]
    nested_id = "field:CloudAppEvents.RawEventData#/UserId"
    effective = compose_effective_graph(rows)
    assert (
        effective.field_availability[nested_id]
        is FieldAvailability.OUTER_AVAILABLE_UNOBSERVED
    )
    assert nested_id in effective.queryable_fields

    observed = compose_effective_graph(rows, observed_nested_fields={nested_id})
    assert observed.field_availability[nested_id] is FieldAvailability.AVAILABLE


def test_graph_merge_is_order_independent_and_conflicts_fail_closed():
    canonical = load_packaged_graph()
    assert [record.to_dict() for record in merge_graphs(canonical).records()] == [
        record.to_dict() for record in merge_graphs(Graph(), canonical).records()
    ]

    locator = FieldLocator.parse("DeviceInfo.DeviceId")
    conflict = Graph()
    conflict.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="long"))
    with pytest.raises(GraphValidationError, match="conflicting graph record"):
        merge_graphs(canonical, conflict)


def test_graph_merge_canonicalizes_equivalent_extra_key_order():
    locator = FieldLocator.parse("ExampleTable.ExampleField")
    first = Graph()
    second = Graph()
    first.add(
        FieldRecord(
            id=field_id(locator),
            locator=locator,
            kql_type="string",
            extra={"alpha": 1, "beta": {"one": 1, "two": 2}},
        )
    )
    second.add(
        FieldRecord(
            id=field_id(locator),
            locator=locator,
            kql_type="string",
            extra={"beta": {"two": 2, "one": 1}, "alpha": 1},
        )
    )

    assert [item.to_dict() for item in merge_graphs(first, second).records()] == [
        item.to_dict() for item in merge_graphs(second, first).records()
    ]


def test_promoted_core_reconciles_tenant_annotations_but_not_contract_changes():
    locator = FieldLocator.parse("FutureTable.FutureId")
    identifier = field_id(locator)
    semantic_id = interpretation_id(locator, "future-id", "neutral")
    canonical = Graph()
    canonical.add(FieldRecord(id=identifier, locator=locator, kql_type="string"))
    canonical.add(
        InterpretationRecord(
            id=semantic_id,
            field_id=identifier,
            entity_kind="future-entity",
            namespace="future-id",
            role="neutral",
            normalizer="identity",
        )
    )
    retained_overlay = Graph()
    retained_overlay.add(
        FieldRecord(
            id=identifier,
            locator=locator,
            kql_type="string",
            extra={"provenance": ["tenant-schema"], "private": True},
        )
    )
    retained_overlay.add(
        InterpretationRecord(
            id=semantic_id,
            field_id=identifier,
            entity_kind="future-entity",
            namespace="future-id",
            role="neutral",
            normalizer="identity",
            extra={
                "status": "candidate",
                "provisional": True,
                "private": True,
            },
        )
    )

    effective = compose_effective_graph(
        [{"TableName": "FutureTable", "ColumnName": "FutureId"}],
        canonical=canonical,
        overlays=(retained_overlay,),
    )
    assert effective.graph.fields[identifier].extra == {}
    assert effective.graph.interpretations[semantic_id].extra == {}
    assert effective.field_availability[identifier] is FieldAvailability.AVAILABLE

    conflicting_overlay = Graph()
    conflicting_overlay.add(
        FieldRecord(id=identifier, locator=locator, kql_type="long")
    )
    with pytest.raises(GraphValidationError, match="packaged contract"):
        compose_effective_graph(
            [], canonical=canonical, overlays=(conflicting_overlay,)
        )


def test_tenant_observations_create_observed_pivots_but_never_replace_reviewed_edges():
    canonical = load_packaged_graph()
    observation = ObservationRecord(
        observation_id="probe:device-events-direct",
        source_interpretation="interp:DeviceNetworkEvents.DeviceId:mde-device-id:subject",
        target_interpretation="interp:DeviceProcessEvents.DeviceId:mde-device-id:subject",
        transform="hex40-lower",
        distinct_seeds=5,
        matched_seeds=4,
        probe_runs=2,
        provenance=("tenant-observation:device-events-direct",),
        outcome="matched",
    )
    effective = compose_effective_graph([], canonical=canonical, observations=(observation,))
    discoveries = [
        item
        for item in effective.graph.relationships.values()
        if item.status.value == "observed"
        and "probe:device-events-direct" in item.extra.get("observation_ids", [])
    ]
    assert len(discoveries) == 1
    assert discoveries[0].relationship.value == "correlation-only"
    assert discoveries[0].cardinality.value == "unknown"
    assert discoveries[0].extra["join_safe"] is False


def test_tenant_only_relationship_cannot_self_assert_reviewed_status():
    canonical = load_packaged_graph()
    source = "interp:DeviceInfo.DeviceId:mde-device-id:subject"
    target = "interp:EmailEvents.NetworkMessageId:network-message-id:subject"
    endpoints = sorted((source, target))
    overlay = Graph()
    overlay.add(
        RelationshipRecord(
            id=relationship_id(
                endpoints[0],
                endpoints[1],
                RelationshipKind.SEMANTIC_EQUIVALENT,
                Direction.BOTH,
                "identity",
            ),
            source=endpoints[0],
            target=endpoints[1],
            relationship=RelationshipKind.SEMANTIC_EQUIVALENT,
            direction=Direction.BOTH,
            transform="identity",
            cardinality=Cardinality.MANY_TO_MANY,
            temporal="unknown",
            status=RelationshipStatus.REVIEWED,
            confidence=Confidence.HIGH,
            provenance=("reviewed:self-asserted",),
        )
    )

    with pytest.raises(GraphValidationError, match="candidate, observed, or"):
        compose_effective_graph([], canonical=canonical, overlays=(overlay,))


def test_no_match_observation_never_creates_a_candidate_edge():
    canonical = load_packaged_graph()
    observation = ObservationRecord(
        observation_id="probe:no-match",
        source_interpretation="interp:DeviceNetworkEvents.DeviceId:mde-device-id:subject",
        target_interpretation="interp:DeviceProcessEvents.DeviceId:mde-device-id:subject",
        transform="hex40-lower",
        distinct_seeds=5,
        matched_seeds=0,
        probe_runs=1,
        provenance=("tenant-observation:no-match",),
        outcome="no-match",
    )
    effective = compose_effective_graph([], canonical=canonical, observations=(observation,))
    assert not any(
        "probe:no-match" in item.extra.get("observation_ids", [])
        for item in effective.graph.relationships.values()
    )
