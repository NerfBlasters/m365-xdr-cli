"""Compose canonical graph data with tenant-local physical availability."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.model import (
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    ObservationRecord,
    RelationshipRecord,
    RelationshipStatus,
    empirical_relationship_from_observations,
)


class FieldAvailability(StrEnum):
    AVAILABLE = "available"
    OUTER_AVAILABLE_UNOBSERVED = "outer-available-unobserved"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class EffectiveGraph:
    graph: Graph
    field_availability: dict[str, FieldAvailability]

    @property
    def queryable_fields(self) -> set[str]:
        """Fields whose top-level storage exists in the tenant schema."""

        return {
            field_id
            for field_id, state in self.field_availability.items()
            if state is not FieldAvailability.UNAVAILABLE
        }


def merge_graphs(*graphs: Graph) -> Graph:
    """Set-like, order-independent merge that rejects conflicting stable IDs."""

    merged = Graph()
    records = [record for graph in graphs for record in graph.records()]
    canonical_records = []
    for record in records:
        value = json.loads(json.dumps(record.to_dict(), sort_keys=True))
        canonical_records.append(type(record).from_dict(value))
    for record in sorted(
        canonical_records,
        key=lambda item: (
            item.RECORD_TYPE,
            item.id,
            json.dumps(item.to_dict(), sort_keys=True, separators=(",", ":")),
        ),
    ):
        merged.add(record)
    merged.validate_references()
    return merged


def _field_contract(record: FieldRecord) -> tuple:
    return (record.schema_version, record.locator, record.kql_type)


def _interpretation_contract(record: InterpretationRecord) -> tuple:
    return (
        record.schema_version,
        record.field_id,
        record.entity_kind,
        record.namespace,
        record.role,
        record.normalizer,
        record.constraints,
    )


def _relationship_contract(record: RelationshipRecord) -> tuple:
    return (
        record.schema_version,
        record.source,
        record.target,
        record.relationship,
        record.direction,
        record.transform,
        record.cardinality,
        record.temporal,
        record.status,
        record.confidence,
        record.provenance,
    )


def _reconcile_promoted_overlay(canonical: Graph, overlay: Graph) -> Graph:
    """Drop annotation-only duplicates after tenant records enter core.

    Stable field and interpretation IDs name their semantic contract, while
    tenant-only provenance/private/provisional annotations live in ``extra``.
    Once an identical contract ships in core, the repository record is
    authoritative. Actual contract differences remain hard conflicts.
    """

    reconciled = Graph()
    for record in overlay.fields.values():
        packaged = canonical.fields.get(record.id)
        if packaged is None:
            reconciled.add(record)
        elif _field_contract(packaged) != _field_contract(record):
            raise GraphValidationError(
                f"tenant overlay field {record.id} conflicts with the packaged contract: "
                f"packaged={_field_contract(packaged)!r}, "
                f"tenant={_field_contract(record)!r}"
            )
    for record in overlay.interpretations.values():
        packaged = canonical.interpretations.get(record.id)
        if packaged is None:
            reconciled.add(record)
        elif _interpretation_contract(packaged) != _interpretation_contract(record):
            raise GraphValidationError(
                "tenant overlay interpretation "
                f"{record.id} conflicts with the packaged contract: "
                f"packaged={_interpretation_contract(packaged)!r}, "
                f"tenant={_interpretation_contract(record)!r}"
            )
    for record in overlay.relationships.values():
        packaged = canonical.relationships.get(record.id)
        if packaged is None:
            if record.status not in {
                RelationshipStatus.CANDIDATE,
                RelationshipStatus.OBSERVED,
                RelationshipStatus.VALIDATED,
            }:
                raise GraphValidationError(
                    "tenant-only relationships must be candidate, observed, or "
                    f"machine-validated: {record.id}"
                )
            if (
                record.status
                in {
                    RelationshipStatus.OBSERVED,
                    RelationshipStatus.VALIDATED,
                }
                and record.extra.get("validation_policy") != "tenant-search-pivot-v1"
            ):
                raise GraphValidationError(
                    f"tenant empirical relationship has an unknown policy: {record.id}"
                )
            reconciled.add(record)
            continue
        annotation_only_duplicate = _relationship_contract(packaged) == (
            _relationship_contract(record)
        )
        reviewed_promotion = (
            record.status is RelationshipStatus.CANDIDATE
            and packaged.status in {RelationshipStatus.REVIEWED, RelationshipStatus.DEPRECATED}
            and (
                packaged.schema_version,
                packaged.source,
                packaged.target,
                packaged.relationship,
                packaged.direction,
                packaged.transform,
            )
            == (
                record.schema_version,
                record.source,
                record.target,
                record.relationship,
                record.direction,
                record.transform,
            )
        )
        if not annotation_only_duplicate and not reviewed_promotion:
            raise GraphValidationError(
                "tenant overlay relationship "
                f"{record.id} conflicts with the packaged contract: "
                f"packaged={_relationship_contract(packaged)!r}, "
                f"tenant={_relationship_contract(record)!r}"
            )
    return reconciled


def compose_effective_graph(
    schema_rows: list[dict],
    *,
    canonical: Graph | None = None,
    overlays: tuple[Graph, ...] = (),
    observations: tuple[ObservationRecord, ...] = (),
    observed_nested_fields: set[str] | None = None,
    verified_observation_ids: frozenset[str] = frozenset(),
) -> EffectiveGraph:
    """Apply one physical-schema snapshot without mutating semantic records."""

    canonical_graph = canonical or load_packaged_graph()
    reconciled_overlays = tuple(
        _reconcile_promoted_overlay(canonical_graph, overlay) for overlay in overlays
    )
    base = merge_graphs(canonical_graph, *reconciled_overlays)
    discoveries = _discovery_overlay(
        base,
        observations,
        verified_observation_ids=verified_observation_ids,
    )
    graph = merge_graphs(base, discoveries)
    physical = {
        (str(row.get("TableName")), str(row.get("ColumnName")))
        for row in schema_rows
        if row.get("TableName") and row.get("ColumnName")
    }
    observed_nested = set(observed_nested_fields or ())
    # A nested field in a tenant overlay is persisted proof that passive shape
    # ingestion observed that exact path. Canonical records may be repeated in
    # the overlay intentionally, so derive availability before graph merging.
    for overlay in overlays:
        observed_nested.update(
            record.id for record in overlay.fields.values() if record.locator.json_path
        )
    availability: dict[str, FieldAvailability] = {}
    for record in graph.fields.values():
        outer_exists = (record.locator.table, record.locator.column) in physical
        if not outer_exists:
            state = FieldAvailability.UNAVAILABLE
        elif not record.locator.json_path or record.id in observed_nested:
            state = FieldAvailability.AVAILABLE
        else:
            state = FieldAvailability.OUTER_AVAILABLE_UNOBSERVED
        availability[record.id] = state
    return EffectiveGraph(graph=graph, field_availability=availability)


def _discovery_overlay(
    canonical: Graph,
    observations: tuple[ObservationRecord, ...],
    *,
    verified_observation_ids: frozenset[str],
) -> Graph:
    """Aggregate positive observations into usable tenant discovery edges."""

    grouped: dict[str, list[ObservationRecord]] = {}
    for observation in observations:
        for endpoint in (
            observation.source_interpretation,
            observation.target_interpretation,
        ):
            if endpoint not in canonical.interpretations:
                raise GraphValidationError(
                    f"tenant observation references missing interpretation {endpoint}"
                )
        if observation.outcome != "matched" or observation.matched_seeds < 1:
            # Negative and incomplete evidence is retained in the overlay but
            # cannot assert that a semantic route exists.
            continue
        discovery = empirical_relationship_from_observations(
            (observation,),
            verified_observation_ids=verified_observation_ids,
        )
        if discovery.id in canonical.relationships:
            # Observations may corroborate reviewed/public candidates, but can
            # never replace their repository-controlled record.
            continue
        grouped.setdefault(discovery.id, []).append(observation)
    overlay = Graph()
    for items in grouped.values():
        overlay.add(
            empirical_relationship_from_observations(
                tuple(items),
                verified_observation_ids=verified_observation_ids,
            )
        )
    return overlay
