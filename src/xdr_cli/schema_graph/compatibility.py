"""Cache-only compatibility audit and loss-aware tenant-overlay migration."""

from __future__ import annotations

from dataclasses import dataclass

from xdr_cli.schema_graph.artifact_metadata import passive_locator_is_reviewed
from xdr_cli.schema_graph.model import (
    FieldRecord,
    Graph,
    InterpretationRecord,
    ObservationRecord,
    RelationshipRecord,
    RelationshipStatus,
)


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


def _is_private_provisional(record: InterpretationRecord) -> bool:
    return (
        record.extra.get("provisional") is True
        and record.extra.get("private") is True
    )


def _is_legacy_passive_field(record: FieldRecord) -> bool:
    provenance = record.extra.get("provenance", ())
    return (
        bool(record.locator.json_path)
        and isinstance(provenance, (list, tuple))
        and any(value == "artifact-shape" for value in provenance)
        and not passive_locator_is_reviewed(record.locator)
    )


def _reviewed_promotion(
    packaged: RelationshipRecord, tenant: RelationshipRecord
) -> bool:
    return (
        tenant.status is RelationshipStatus.CANDIDATE
        and packaged.status
        in {RelationshipStatus.REVIEWED, RelationshipStatus.DEPRECATED}
        and (
            packaged.schema_version,
            packaged.source,
            packaged.target,
            packaged.relationship,
            packaged.direction,
            packaged.transform,
        )
        == (
            tenant.schema_version,
            tenant.source,
            tenant.target,
            tenant.relationship,
            tenant.direction,
            tenant.transform,
        )
    )


@dataclass(frozen=True, slots=True)
class OverlayCompatibility:
    """Value-free audit result; record identifiers are kept private in memory."""

    state: str
    obsolete_interpretation_ids: frozenset[str]
    unsafe_passive_field_ids: frozenset[str]
    dependent_observation_ids: frozenset[str]
    dependent_relationship_ids: frozenset[str]
    hard_conflict_ids: frozenset[str]

    @property
    def needs_migration(self) -> bool:
        return self.state == "needs-migration"

    def to_status_dict(self) -> dict[str, object]:
        """Return a value-free summary suitable for normal command output."""

        reasons: list[str] = []
        if self.obsolete_interpretation_ids:
            reasons.append("obsolete-provisional-interpretations")
        if self.unsafe_passive_field_ids:
            reasons.append("legacy-passive-fields-require-review")
        if self.dependent_observation_ids:
            reasons.append("legacy-observations-require-recollection")
        if self.dependent_relationship_ids:
            reasons.append("dependent-relationships-inactive")
        if self.hard_conflict_ids:
            reasons.append("hard-semantic-contract-conflicts")
        return {
            "state": self.state,
            "reasons": reasons,
            "obsolete_interpretation_count": len(self.obsolete_interpretation_ids),
            "unsafe_passive_field_count": len(self.unsafe_passive_field_ids),
            "ineligible_observation_count": len(self.dependent_observation_ids),
            "inactive_relationship_count": len(self.dependent_relationship_ids),
            "hard_conflict_count": len(self.hard_conflict_ids),
        }


@dataclass(frozen=True, slots=True)
class OverlayMigration:
    graph: Graph
    observations: tuple[ObservationRecord, ...]
    source_compatibility: OverlayCompatibility
    compatibility: OverlayCompatibility

    def summary(self) -> dict[str, int]:
        return {
            "retained_field_count": len(self.graph.fields),
            "retained_interpretation_count": len(self.graph.interpretations),
            "retained_relationship_count": len(self.graph.relationships),
            "retained_observation_count": len(self.observations),
            "inactivated_field_count": len(
                self.source_compatibility.unsafe_passive_field_ids
            ),
            "inactivated_interpretation_count": len(
                self.source_compatibility.obsolete_interpretation_ids
            ),
            "inactivated_relationship_count": len(
                self.source_compatibility.dependent_relationship_ids
            ),
            "inactivated_observation_count": len(
                self.source_compatibility.dependent_observation_ids
            ),
        }


def audit_overlay_compatibility(
    graph: Graph,
    observations: tuple[ObservationRecord, ...],
    canonical: Graph,
) -> OverlayCompatibility:
    """Compare durable tenant state with the current packaged contracts.

    The audit never reads result rows or contacts a tenant.  It treats
    provisional drift as migratable legacy evidence and reviewed/private
    contract drift as a hard conflict requiring manual reconciliation.
    """

    hard: set[str] = set()
    obsolete: set[str] = set()
    unsafe_fields = {
        record.id
        for record in graph.fields.values()
        if _is_legacy_passive_field(record)
        and record.id not in canonical.fields
    }

    for record in graph.fields.values():
        packaged = canonical.fields.get(record.id)
        if packaged is not None and _field_contract(packaged) != _field_contract(record):
            hard.add(record.id)

    current_normalizers: dict[tuple[str, str], set[str]] = {}
    for record in canonical.interpretations.values():
        current_normalizers.setdefault(
            (record.entity_kind, record.namespace), set()
        ).add(record.normalizer)

    for record in graph.interpretations.values():
        packaged = canonical.interpretations.get(record.id)
        if packaged is not None:
            if _interpretation_contract(packaged) != _interpretation_contract(record):
                if _is_private_provisional(record):
                    obsolete.add(record.id)
                else:
                    hard.add(record.id)
            continue
        if record.field_id in unsafe_fields:
            obsolete.add(record.id)
            continue
        allowed = current_normalizers.get((record.entity_kind, record.namespace))
        if (
            _is_private_provisional(record)
            and allowed
            and record.normalizer not in allowed
        ):
            obsolete.add(record.id)

    dependent_relationships: set[str] = set()
    for record in graph.relationships.values():
        packaged = canonical.relationships.get(record.id)
        if record.source in obsolete or record.target in obsolete:
            dependent_relationships.add(record.id)
            continue
        if packaged is not None and not (
            _relationship_contract(packaged) == _relationship_contract(record)
            or _reviewed_promotion(packaged, record)
        ):
            hard.add(record.id)

    dependent_observations: set[str] = set()
    combined_interpretations = {
        **canonical.interpretations,
        **graph.interpretations,
    }
    for observation in observations:
        if (
            observation.source_interpretation in obsolete
            or observation.target_interpretation in obsolete
        ):
            dependent_observations.add(observation.observation_id)
            continue
        source = combined_interpretations.get(observation.source_interpretation)
        target = combined_interpretations.get(observation.target_interpretation)
        if source is None or target is None:
            # Older observation records were intentionally allowed to carry
            # external interpretation references. Absence alone is not enough
            # to reinterpret or discard them; explicit obsolete endpoints are.
            continue
        # Probe observations persist the source normalizer in ``transform``.
        # A mismatch is direct evidence that the run predates the current
        # source contract and must be recollected, even if the source stable ID
        # itself now resolves to a packaged interpretation.
        if observation.transform != source.normalizer:
            dependent_observations.add(observation.observation_id)

    if hard:
        state = "incompatible"
    elif obsolete or unsafe_fields or dependent_observations or dependent_relationships:
        state = "needs-migration"
    else:
        state = "compatible"
    return OverlayCompatibility(
        state=state,
        obsolete_interpretation_ids=frozenset(obsolete),
        unsafe_passive_field_ids=frozenset(unsafe_fields),
        dependent_observation_ids=frozenset(dependent_observations),
        dependent_relationship_ids=frozenset(dependent_relationships),
        hard_conflict_ids=frozenset(hard),
    )


def migrate_overlay(
    graph: Graph,
    observations: tuple[ObservationRecord, ...],
    canonical: Graph,
) -> OverlayMigration:
    """Build one compatible active graph while leaving originals to quarantine."""

    audit = audit_overlay_compatibility(graph, observations, canonical)
    if audit.hard_conflict_ids:
        return OverlayMigration(
            graph=graph,
            observations=observations,
            source_compatibility=audit,
            compatibility=audit,
        )

    migrated = Graph()
    for record in graph.fields.values():
        if record.id in audit.unsafe_passive_field_ids:
            continue
        packaged = canonical.fields.get(record.id)
        if packaged is None or _field_contract(packaged) == _field_contract(record):
            # Keep core-equivalent dependencies: tenant overlay generations are
            # deliberately self-validating without requiring the packaged graph.
            migrated.add(record)
    for record in graph.interpretations.values():
        if record.id in audit.obsolete_interpretation_ids:
            continue
        if record.field_id not in migrated.fields and record.field_id not in canonical.fields:
            continue
        packaged = canonical.interpretations.get(record.id)
        if packaged is None or _interpretation_contract(packaged) == _interpretation_contract(
            record
        ):
            migrated.add(record)
    for record in graph.relationships.values():
        if record.id in audit.dependent_relationship_ids:
            continue
        packaged = canonical.relationships.get(record.id)
        if packaged is None or _relationship_contract(packaged) == _relationship_contract(
            record
        ):
            migrated.add(record)
    migrated.validate_references()
    retained_observations = tuple(
        item
        for item in observations
        if item.observation_id not in audit.dependent_observation_ids
        and (
            item.source_interpretation in migrated.interpretations
            or item.source_interpretation in canonical.interpretations
        )
        and (
            item.target_interpretation in migrated.interpretations
            or item.target_interpretation in canonical.interpretations
        )
    )
    post = audit_overlay_compatibility(migrated, retained_observations, canonical)
    return OverlayMigration(
        graph=migrated,
        observations=retained_observations,
        source_compatibility=audit,
        compatibility=post,
    )
