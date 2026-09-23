from __future__ import annotations

from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.model import (
    Cardinality,
    Confidence,
    Direction,
    FieldLocator,
    FieldRecord,
    InterpretationRecord,
    ObservationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    candidate_relationship_from_observation,
    field_id,
    interpretation_id,
    relationship_id,
)
from xdr_cli.schema_graph.traversal import GraphPath, pivot, table_paths


def _add_candidate(graph):
    locator = FieldLocator.parse("DeviceProcessEvents.DeviceId")
    physical_id = field_id(locator)
    semantic_id = interpretation_id(locator, "mde-device-id", "subject")
    graph.add(FieldRecord(id=physical_id, locator=locator, kql_type="string"))
    graph.add(
        InterpretationRecord(
            id=semantic_id,
            field_id=physical_id,
            entity_kind="device",
            namespace="mde-device-id",
            role="subject",
            normalizer="hex40-lower",
        )
    )
    graph.add(
        candidate_relationship_from_observation(
            ObservationRecord(
                observation_id="probe:perfect",
                source_interpretation="interp:DeviceInfo.DeviceId:mde-device-id:subject",
                target_interpretation=semantic_id,
                transform="hex40-lower",
                distinct_seeds=1000,
                matched_seeds=1000,
                probe_runs=100,
                provenance=("tenant-observation:perfect",),
            )
        )
    )


def test_pivot_is_reviewed_only_by_default_even_for_perfect_candidate():
    graph = load_packaged_graph()
    _add_candidate(graph)
    reviewed = pivot(graph, "DeviceInfo.DeviceId")
    assert "DeviceNetworkEvents.DeviceId" in {step.target_locator for step in reviewed}
    assert all(not step.candidate for step in reviewed)

    with_candidates = pivot(graph, "DeviceInfo.DeviceId", include_candidates=True)
    assert len(with_candidates) == len(reviewed) + 1
    assert any(
        step.target_locator == "DeviceProcessEvents.DeviceId" and step.candidate
        for step in with_candidates
    )


def test_direct_path_is_symmetric_and_reports_join_semantics():
    graph = load_packaged_graph()
    forward = table_paths(graph, "DeviceInfo", "DeviceNetworkEvents")
    reverse = table_paths(graph, "DeviceNetworkEvents", "DeviceInfo")
    assert len(forward) == len(reverse) >= 1
    assert forward[0].direct_join is True
    assert reverse[0].direct_join is True
    assert forward[0].hop_count == 1
    assert forward[0].all_steps_join_compatible is True
    assert forward[0].route_kind == "direct-join"
    assert forward[0].steps[0].cardinality == "one-to-many"
    assert reverse[0].steps[0].cardinality == "many-to-one"
    assert forward[0].steps[0].traversal_direction == "forward"
    assert reverse[0].steps[0].traversal_direction == "reverse"
    assert forward[0].steps[0].source_namespace == "mde-device-id"
    assert forward[0].steps[0].provenance == ("curated:mde-device-id-contract",)


def test_packaged_event_and_attachment_routes_have_source_relative_cardinality():
    graph = load_packaged_graph()
    routes = {
        (step.source_locator, step.target_locator): step.cardinality
        for source in (
            "DeviceImageLoadEvents.DeviceId",
            "EmailAttachmentInfo.NetworkMessageId",
        )
        for step in pivot(graph, source)
    }

    assert routes[("DeviceImageLoadEvents.DeviceId", "DeviceInfo.DeviceId")] == (
        "many-to-one"
    )
    assert routes[("EmailAttachmentInfo.NetworkMessageId", "EmailEvents.NetworkMessageId")] == (
        "many-to-one"
    )


def test_route_kind_distinguishes_multi_hop_joins_from_sequential_pivots():
    graph = load_packaged_graph()
    multi_hop = next(
        route
        for route in table_paths(graph, "EntraIdSignInEvents", "CloudAppEvents")
        if route.hop_count > 1 and route.all_steps_join_compatible
    )
    transform_step = next(
        step
        for step in pivot(graph, "EntraIdSignInEvents.AccountUpn")
        if step.relationship is RelationshipKind.TRANSFORM_REQUIRED
    )

    assert multi_hop.direct_join is False
    assert multi_hop.route_kind == "multi-hop-join"
    assert GraphPath((transform_step,)).route_kind == "sequential-pivot"


def test_path_ranking_prefers_reviewed_direct_join_over_candidate():
    graph = load_packaged_graph()
    _add_candidate(graph)
    paths = table_paths(
        graph,
        "DeviceInfo",
        "DeviceProcessEvents",
        include_candidates=True,
    )
    assert len(paths) >= 2
    assert paths[0].direct_join is True
    assert paths[0].steps[0].candidate is False
    assert any(path.steps[0].candidate for path in paths)


def test_unavailable_fields_are_retained_but_ranked_lower():
    graph = load_packaged_graph()
    only_source = {"field:DeviceInfo.DeviceId"}
    step = pivot(graph, "DeviceInfo.DeviceId", available_fields=only_source)[0]
    assert step.source_available is True
    assert step.target_available is False
    assert step.rank[4] == 1


def test_relationship_constructor_rejects_noncanonical_bidirectional_order():
    source = "interp:z"
    target = "interp:a"
    try:
        RelationshipRecord(
            id=relationship_id(source, target, "semantic-equivalent", "both", "identity"),
            source=source,
            target=target,
            relationship=RelationshipKind.SEMANTIC_EQUIVALENT,
            direction=Direction.BOTH,
            transform="identity",
            cardinality=Cardinality.UNKNOWN,
            temporal="unknown",
            status=RelationshipStatus.REVIEWED,
            confidence=Confidence.LOW,
            provenance=("test",),
        )
    except ValueError as exc:
        assert "endpoints must be sorted" in str(exc)
    else:
        raise AssertionError("noncanonical endpoints were accepted")
