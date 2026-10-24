from __future__ import annotations

from dataclasses import replace

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


def test_empirical_evidence_ranks_before_authored_status():
    step = pivot(load_packaged_graph(), "DeviceInfo.DeviceId")[0]
    validated = replace(step, evidence_level="validated")
    observed = replace(step, evidence_level="observed")
    assert validated.rank < observed.rank < step.rank
    assert GraphPath((validated,)).rank < GraphPath((observed,)).rank < GraphPath((step,)).rank


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

    assert routes[("DeviceImageLoadEvents.DeviceId", "DeviceInfo.DeviceId")] == ("many-to-one")
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


def test_unvalidated_overlap_does_not_hide_a_stronger_route():
    step = pivot(load_packaged_graph(), "DeviceInfo.DeviceId")[0]
    overlap = replace(
        step,
        evidence_level="observed",
        confidence="low",
        relationship=RelationshipKind.CORRELATION_ONLY,
    )
    validated = replace(overlap, evidence_level="validated", confidence="high")
    assert validated.rank < step.rank < overlap.rank
    assert GraphPath((validated,)).rank < GraphPath((step,)).rank < GraphPath((overlap,)).rank


def test_trusted_reference_route_is_default_and_preserves_guidance():
    graph = load_packaged_graph()
    original = pivot(graph, "DeviceInfo.DeviceId")[0]
    relationship = graph.relationships[original.relationship_id]
    info = {"id": "synthetic-device-route", "guidance": "Check event time", "digest": "abc"}
    reference_id = relationship_id(
        relationship.source,
        relationship.target,
        RelationshipKind.CORRELATION_ONLY,
        relationship.direction,
        relationship.transform,
    )
    del graph.relationships[relationship.id]
    graph.relationships[reference_id] = replace(
        relationship,
        id=reference_id,
        status=RelationshipStatus.REFERENCE_TRUSTED,
        relationship=RelationshipKind.CORRELATION_ONLY,
        extra={"reference_routes": [info]},
    )
    steps = pivot(graph, "DeviceInfo.DeviceId")
    reference = next(s for s in steps if s.relationship_id == reference_id)
    assert reference.evidence_level == "reference-trusted"
    assert reference.candidate is False
    assert reference.reference_routes == (info,)
    assert reference.evidence_rank < replace(reference, evidence_level="candidate").evidence_rank


def test_nonqueryable_fields_are_opt_in_when_filtering_routes():
    graph = load_packaged_graph()
    available = {field_id("DeviceInfo.DeviceId")}
    assert pivot(graph, "DeviceInfo.DeviceId", available_fields=available)
    assert (
        pivot(graph, "DeviceInfo.DeviceId", available_fields=available, include_unavailable=False)
        == []
    )
    assert (
        table_paths(
            graph,
            "DeviceInfo",
            "DeviceNetworkEvents",
            available_fields=available,
            include_unavailable=False,
        )
        == []
    )
    assert table_paths(
        graph,
        "DeviceInfo",
        "DeviceNetworkEvents",
        available_fields=available,
        include_unavailable=True,
    )


def _dense_device_graph(size=12):
    from xdr_cli.schema_graph.model import Graph

    graph = Graph()
    interpretations = []
    for n in range(size):
        locator = FieldLocator.parse(f"Table{n}.DeviceId")
        field = FieldRecord(field_id(locator), locator, "string")
        interpretation = InterpretationRecord(
            interpretation_id(locator, "mde-device-id", "subject"),
            field.id,
            "device",
            "mde-device-id",
            "subject",
            "hex40-lower",
        )
        graph.add(field)
        graph.add(interpretation)
        interpretations.append(interpretation)
    for n, source in enumerate(interpretations):
        for target in interpretations[n + 1 :]:
            source_id, target_id = sorted((source.id, target.id))
            graph.add(
                RelationshipRecord(
                    relationship_id(
                        source_id,
                        target_id,
                        RelationshipKind.CORRELATION_ONLY,
                        Direction.BOTH,
                        "hex40-lower",
                    ),
                    source_id,
                    target_id,
                    RelationshipKind.CORRELATION_ONLY,
                    Direction.BOTH,
                    "hex40-lower",
                    Cardinality.UNKNOWN,
                    "check-event-time",
                    RelationshipStatus.REFERENCE_TRUSTED,
                    Confidence.MEDIUM,
                    ("synthetic",),
                )
            )
    return graph


def test_dense_path_search_caps_generated_states_and_reports_incomplete():
    graph = _dense_device_graph()
    diagnostics = {}
    paths = table_paths(
        graph,
        "Table0",
        "Table11",
        max_depth=12,
        max_paths=100,
        max_expansions=20,
        diagnostics=diagnostics,
    )
    assert diagnostics["generated_states"] == 20
    assert diagnostics["expansion_limit_reached"] is True
    assert diagnostics["search_complete"] is False
    assert any(path.direct_join is False and path.hop_count == 1 for path in paths)
    assert paths == table_paths(
        graph, "Table0", "Table11", max_depth=12, max_paths=100, max_expansions=20
    )


def test_path_result_limit_has_explicit_truncation_diagnostics():
    graph = _dense_device_graph(5)
    diagnostics = {}
    paths = table_paths(graph, "Table0", "Table4", max_paths=1, diagnostics=diagnostics)
    assert len(paths) == 1
    assert paths[0].hop_count == 1
    assert diagnostics["paths_truncated"] is True
    assert diagnostics["search_complete"] is False
    assert diagnostics["expansion_limit_reached"] is False


def test_complete_path_search_reports_complete():
    diagnostics = {}
    paths = table_paths(
        load_packaged_graph(), "DeviceInfo", "DeviceNetworkEvents", diagnostics=diagnostics
    )
    assert paths
    assert diagnostics["search_complete"] is True
    assert diagnostics["paths_truncated"] is False


def test_queryable_endpoints_do_not_allow_an_unavailable_intermediate():
    graph = _dense_device_graph(3)
    graph.relationships = {
        key: relation
        for key, relation in graph.relationships.items()
        if {relation.source, relation.target} != {
            interpretation_id("Table0.DeviceId", "mde-device-id", "subject"),
            interpretation_id("Table2.DeviceId", "mde-device-id", "subject"),
        }
    }
    available = {field_id("Table0.DeviceId"), field_id("Table2.DeviceId")}
    assert table_paths(graph, "Table0", "Table2", available_fields=available)
    assert (
        table_paths(
            graph, "Table0", "Table2", available_fields=available, include_unavailable=False
        )
        == []
    )
