from __future__ import annotations

import io
from dataclasses import replace
from unittest.mock import patch

import pytest

from xdr_cli.schema_graph.loader import (
    GraphRegistry,
    _read_json_resource,
    load_graph_stream,
    load_packaged_graph,
    load_packaged_profile,
)
from xdr_cli.schema_graph.model import (
    Cardinality,
    Confidence,
    Direction,
    FieldLocator,
    FieldRecord,
    GraphValidationError,
    ObservationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    candidate_relationship_from_observation,
    field_id,
    interpretation_id,
    relationship_id,
    empirical_relationship_from_observations,
)


def test_locator_parses_nested_json_path_and_rejects_ambiguous_input():
    locator = FieldLocator.parse("CloudAppEvents.RawEventData.User.Id")
    assert locator.table == "CloudAppEvents"
    assert locator.column == "RawEventData"
    assert locator.json_path == ("User", "Id")
    assert str(locator) == "CloudAppEvents.RawEventData#/User/Id"

    complex_locator = FieldLocator.parse(
        "DeviceEvents.AdditionalFields#/Key%20With%20Space/key.with.dot/slash~1key/tilde~0key"
    )
    assert complex_locator.json_path == (
        "Key With Space",
        "key.with.dot",
        "slash/key",
        "tilde~key",
    )
    assert str(complex_locator) == (
        "DeviceEvents.AdditionalFields#/Key%20With%20Space/key.with.dot/slash~1key/tilde~0key"
    )

    for invalid in (
        "DeviceId",
        "DeviceEvents.",
        ".DeviceId",
        "A.B.c-d",
        "A.B#bad",
        "A.B#/bad~escape",
        "A.B#/bad%ZZescape",
    ):
        with pytest.raises(GraphValidationError):
            FieldLocator.parse(invalid)


def test_field_round_trip_preserves_unknown_optional_fields():
    source = {
        "schema_version": 1,
        "record_type": "field",
        "id": "field:DeviceEvents.AdditionalFields#/Member",
        "locator": "DeviceEvents.AdditionalFields#/Member",
        "table": "DeviceEvents",
        "column": "AdditionalFields",
        "json_path": "/Member",
        "kql_type": "dynamic",
        "future_hint": {"safe": True},
    }
    record = FieldRecord.from_dict(source)
    assert record.to_dict() == source


def test_field_constructor_rejects_locator_that_cannot_form_a_reloadable_id():
    locator = FieldLocator(
        table="CloudAppEvents",
        column="RawEventData",
        json_path=("x" * 1100,),
    )
    with pytest.raises(GraphValidationError, match="stable id"):
        FieldRecord(id=f"field:{locator}", locator=locator, kql_type="string")


def test_stable_ids_include_role_and_relationship_semantics():
    locator = FieldLocator.parse("IdentityInfo.AccountObjectId")
    assert field_id(locator) == "field:IdentityInfo.AccountObjectId"
    assert (
        interpretation_id(locator, "entra-object-id", "subject")
        == "interp:IdentityInfo.AccountObjectId:entra-object-id:subject"
    )
    assert relationship_id("interp:a", "interp:b", "bridge", "forward", "identity") == (
        relationship_id("interp:a", "interp:b", "bridge", "forward", "identity")
    )


def test_observation_can_only_create_low_trust_semantic_candidate():
    observation = ObservationRecord(
        observation_id="probe:run-1",
        source_interpretation="interp:a",
        target_interpretation="interp:b",
        transform="identity",
        distinct_seeds=100,
        matched_seeds=100,
        probe_runs=100,
        provenance=("tenant-observation:run-1",),
    )
    relationship = candidate_relationship_from_observation(observation)
    assert relationship.relationship is RelationshipKind.SEMANTIC_EQUIVALENT
    assert relationship.status is RelationshipStatus.CANDIDATE
    assert relationship.cardinality is Cardinality.UNKNOWN
    assert relationship.confidence is Confidence.MEDIUM


def test_observation_accepts_refresh_generation_ids_that_begin_with_a_digit():
    observation = ObservationRecord(
        observation_id="probe:run-generation",
        source_interpretation="interp:a",
        target_interpretation="interp:b",
        transform="identity",
        distinct_seeds=1,
        matched_seeds=1,
        probe_runs=1,
        provenance=("tenant-observation:run-generation",),
        schema_generation="20260801T081707111182Z-599d4afc231f",
        observed_at="2026-08-01T08:17:07Z",
        lookback="30d",
    )

    assert observation.schema_generation.startswith("20260801")
    assert ObservationRecord.from_dict(observation.to_dict()) == observation


def test_observation_preserves_unknown_current_version_extensions():
    observation = ObservationRecord(
        observation_id="probe:future-extension",
        source_interpretation="interp:a",
        target_interpretation="interp:b",
        transform="identity",
        distinct_seeds=3,
        matched_seeds=2,
        probe_runs=1,
        provenance=("tenant-observation:future-extension",),
    )
    serialized = observation.to_dict()
    serialized["future_evidence_contract"] = {"batch_digest": "abc"}

    loaded = ObservationRecord.from_dict(serialized)

    assert loaded.extra == {"future_evidence_contract": {"batch_digest": "abc"}}
    assert loaded.to_dict() == serialized


def test_join_compatible_candidate_fails_closed():
    source = "interp:DeviceEvents.DeviceId:mde-device-id:subject"
    target = "interp:DeviceInfo.DeviceId:mde-device-id:subject"
    value = {
        "schema_version": 1,
        "record_type": "relationship",
        "id": relationship_id(source, target, "join-compatible", "both", "identity"),
        "from": source,
        "to": target,
        "relationship": "join-compatible",
        "direction": "both",
        "transform": "identity",
        "cardinality": "unknown",
        "temporal": "overlap-preferred",
        "status": "candidate",
        "confidence": "high",
        "provenance": ["tenant-observation:test"],
    }
    with pytest.raises(GraphValidationError, match="reviewed cardinality"):
        RelationshipRecord.from_dict(value)


def test_loader_validates_registry_references_and_dangling_endpoints():
    registry = GraphRegistry(
        entity_kinds=frozenset({"device"}),
        namespaces=frozenset({"mde-device-id"}),
        roles=frozenset({"subject"}),
        normalizers=frozenset({"identity"}),
    )
    field_line = (
        '{"schema_version":1,"record_type":"field",'
        '"id":"field:DeviceInfo.DeviceId","locator":"DeviceInfo.DeviceId",'
        '"table":"DeviceInfo","column":"DeviceId","json_path":null,'
        '"kql_type":"string"}\n'
    )
    dangling = (
        '{"schema_version":1,"record_type":"interpretation",'
        '"id":"interp:Missing.DeviceId:mde-device-id:subject",'
        '"field_id":"field:Missing.DeviceId","entity_kind":"device",'
        '"namespace":"mde-device-id","role":"subject","normalizer":"identity",'
        '"constraints":[]}\n'
    )
    with pytest.raises(GraphValidationError, match="missing field"):
        load_graph_stream(io.StringIO(field_line + dangling), registry)


def test_bidirectional_relationship_endpoints_are_canonicalized():
    observation = ObservationRecord(
        observation_id="probe:ordered",
        source_interpretation="interp:z",
        target_interpretation="interp:a",
        transform="identity",
        distinct_seeds=3,
        matched_seeds=2,
        probe_runs=2,
        provenance=("tenant-observation:ordered",),
    )
    relationship = candidate_relationship_from_observation(observation)
    assert relationship.source == "interp:a"
    assert relationship.target == "interp:z"


def test_empirical_pivot_advances_only_verified_sampled_evidence():
    first = ObservationRecord(
        observation_id="probe:empirical-one",
        source_interpretation="interp:z",
        target_interpretation="interp:a",
        transform="identity",
        distinct_seeds=5,
        matched_seeds=4,
        probe_runs=1,
        provenance=("tenant-observation:one",),
        source_artifact_run_id="source-one",
        target_artifact_run_id="target-one",
        outcome="matched",
        extra={"evidence_verified": True, "source_evidence_kind": "sampled"},
    )
    observed = empirical_relationship_from_observations((first,))
    assert observed.status is RelationshipStatus.OBSERVED
    assert observed.relationship is RelationshipKind.CORRELATION_ONLY
    assert observed.extra["join_safe"] is False

    second = ObservationRecord(
        observation_id="probe:empirical-two",
        source_interpretation=first.source_interpretation,
        target_interpretation=first.target_interpretation,
        transform=first.transform,
        distinct_seeds=5,
        matched_seeds=4,
        probe_runs=1,
        provenance=("tenant-observation:two",),
        source_artifact_run_id="source-two",
        target_artifact_run_id="target-two",
        outcome="matched",
        extra={"evidence_verified": True, "source_evidence_kind": "sampled"},
    )
    self_asserted = empirical_relationship_from_observations((first, second))
    assert self_asserted.status is RelationshipStatus.OBSERVED

    validated = empirical_relationship_from_observations(
        (first, second),
        verified_observation_ids=frozenset(
            {first.observation_id, second.observation_id}
        ),
    )
    assert validated.status is RelationshipStatus.VALIDATED
    assert validated.relationship is RelationshipKind.CORRELATION_ONLY

    operator_supplied = empirical_relationship_from_observations(
        (
            first,
            replace(
                second,
                extra={
                    "evidence_verified": True,
                    "source_evidence_kind": "operator-supplied",
                },
            ),
        ),
        verified_observation_ids=frozenset({first.observation_id}),
    )
    assert operator_supplied.status is RelationshipStatus.OBSERVED


def test_packaged_graph_loads_and_contains_reviewed_device_join():
    graph = load_packaged_graph()
    assert len(graph.fields) >= 30
    assert "field:CloudAppEvents.RawEventData#/UserId" in graph.fields
    relationship = next(
        item for item in graph.relationships.values() if item.id == "rel:3f49086ab32a525667f2978c"
    )
    assert relationship.relationship is RelationshipKind.JOIN_COMPATIBLE
    assert relationship.status is RelationshipStatus.REVIEWED
    assert relationship.direction is Direction.BOTH
    assert any(item.status is RelationshipStatus.CANDIDATE for item in graph.relationships.values())
    profile = load_packaged_profile(graph)
    assert set(profile["field_ids"]) == set(graph.fields)
    assert profile["scope"] == "reviewed-starter-fields"
    assert profile["availability_claim"] == "none; tenant cache is authoritative"


def test_corrupt_packaged_registry_becomes_graph_validation_error(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "broken.json").write_text("{not-json", encoding="utf-8")

    with (
        patch("xdr_cli.schema_graph.loader.resources.files", return_value=tmp_path),
        pytest.raises(GraphValidationError, match="invalid JSON"),
    ):
        _read_json_resource("broken.json")
