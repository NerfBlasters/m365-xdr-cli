"""Deterministic reviewed-by-default traversal over the semantic graph."""

from __future__ import annotations

from dataclasses import dataclass

from xdr_cli.schema_graph.model import (
    Direction,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
)

_RELATION_WEIGHT = {
    RelationshipKind.JOIN_COMPATIBLE: 0,
    RelationshipKind.SEMANTIC_EQUIVALENT: 10,
    RelationshipKind.TRANSFORM_REQUIRED: 20,
    RelationshipKind.BRIDGE: 30,
    RelationshipKind.CORRELATION_ONLY: 40,
}
_CONFIDENCE_PENALTY = {"high": 0, "medium": 5, "low": 10}
_CARDINALITY_PENALTY = {
    "one-to-one": 0,
    "one-to-many": 1,
    "many-to-one": 1,
    "many-to-many": 8,
    "unknown": 10,
}
_LOSSY_TRANSFORMS = {"url-canonical"}


@dataclass(frozen=True, slots=True)
class GraphStep:
    source_interpretation: str
    target_interpretation: str
    source_locator: str
    target_locator: str
    relationship_id: str
    relationship: RelationshipKind
    relationship_direction: str
    traversal_direction: str
    transform: str
    cardinality: str
    temporal: str
    confidence: str
    provenance: tuple[str, ...]
    source_entity_kind: str
    source_namespace: str
    source_role: str
    target_entity_kind: str
    target_namespace: str
    target_role: str
    evidence_level: str
    candidate: bool
    source_available: bool
    target_available: bool
    source_availability: str
    target_availability: str

    @property
    def weight(self) -> int:
        unavailable = 50 if not self.source_available or not self.target_available else 0
        unobserved = 15 * sum(
            state == "outer-available-unobserved"
            for state in (self.source_availability, self.target_availability)
        )
        evidence = {
            "reviewed": 0,
            "validated": 20,
            "observed": 60,
            "candidate": 100,
        }.get(self.evidence_level, 100)
        lossy = 10 if self.transform in _LOSSY_TRANSFORMS else 0
        cardinality = _CARDINALITY_PENALTY[self.cardinality]
        confidence = _CONFIDENCE_PENALTY[self.confidence]
        temporal = 5 if self.temporal == "unknown" else 0
        return (
            _RELATION_WEIGHT[self.relationship]
            + unavailable
            + unobserved
            + evidence
            + lossy
            + cardinality
            + confidence
            + temporal
        )

    @property
    def rank(self) -> tuple[int, ...]:
        """Documented deterministic preference dimensions for one edge."""

        return (
            {
                "reviewed": 0,
                "validated": 1,
                "observed": 2,
                "candidate": 3,
            }.get(self.evidence_level, 3),
            _RELATION_WEIGHT[self.relationship],
            int(self.transform in _LOSSY_TRANSFORMS),
            _CARDINALITY_PENALTY[self.cardinality],
            int(not self.source_available or not self.target_available),
            sum(
                state == "outer-available-unobserved"
                for state in (self.source_availability, self.target_availability)
            ),
            _CONFIDENCE_PENALTY[self.confidence],
            int(self.temporal == "unknown"),
        )


@dataclass(frozen=True, slots=True)
class GraphPath:
    steps: tuple[GraphStep, ...]

    @property
    def weight(self) -> int:
        return sum(step.weight for step in self.steps)

    @property
    def rank(self) -> tuple:
        """Prefer reviewed, strong, short, selective, available routes."""

        return (
            sum(
                {
                    "reviewed": 0,
                    "validated": 1,
                    "observed": 2,
                    "candidate": 3,
                }.get(step.evidence_level, 3)
                for step in self.steps
            ),
            max(_RELATION_WEIGHT[step.relationship] for step in self.steps),
            sum(_RELATION_WEIGHT[step.relationship] for step in self.steps),
            len(self.steps),
            sum(step.transform in _LOSSY_TRANSFORMS for step in self.steps),
            sum(step.cardinality in {"many-to-many", "unknown"} for step in self.steps),
            sum(not step.source_available or not step.target_available for step in self.steps),
            sum(_CONFIDENCE_PENALTY[step.confidence] for step in self.steps),
            sum(step.temporal == "unknown" for step in self.steps),
        )

    @property
    def direct_join(self) -> bool:
        return (
            len(self.steps) == 1 and self.steps[0].relationship is RelationshipKind.JOIN_COMPATIBLE
        )

    @property
    def hop_count(self) -> int:
        return len(self.steps)

    @property
    def all_steps_join_compatible(self) -> bool:
        return bool(self.steps) and all(
            step.relationship is RelationshipKind.JOIN_COMPATIBLE for step in self.steps
        )

    @property
    def route_kind(self) -> str:
        if self.direct_join:
            return "direct-join"
        if self.all_steps_join_compatible:
            return "multi-hop-join"
        return "sequential-pivot"


def _directions(relationship: RelationshipRecord) -> tuple[tuple[str, str], ...]:
    if relationship.direction is Direction.BOTH:
        return (
            (relationship.source, relationship.target),
            (relationship.target, relationship.source),
        )
    if relationship.direction is Direction.FORWARD:
        return ((relationship.source, relationship.target),)
    return ((relationship.target, relationship.source),)


def _step(
    graph: Graph,
    relationship: RelationshipRecord,
    source: str,
    target: str,
    available_fields: set[str] | None,
    field_availability: dict[str, str] | None,
) -> GraphStep:
    source_interpretation = graph.interpretations[source]
    target_interpretation = graph.interpretations[target]
    source_field = graph.fields[source_interpretation.field_id]
    target_field = graph.fields[target_interpretation.field_id]

    def state(field_id: str) -> str:
        if field_availability is not None:
            return str(field_availability.get(field_id, "unavailable"))
        if available_fields is None or field_id in available_fields:
            return "available"
        return "unavailable"

    source_state = state(source_field.id)
    target_state = state(target_field.id)
    traversal_direction = "forward" if source == relationship.source else "reverse"
    cardinality = relationship.cardinality.value
    if traversal_direction == "reverse":
        cardinality = {
            "one-to-many": "many-to-one",
            "many-to-one": "one-to-many",
        }.get(cardinality, cardinality)
    return GraphStep(
        source_interpretation=source,
        target_interpretation=target,
        source_locator=str(source_field.locator),
        target_locator=str(target_field.locator),
        relationship_id=relationship.id,
        relationship=relationship.relationship,
        relationship_direction=relationship.direction.value,
        traversal_direction=traversal_direction,
        transform=relationship.transform,
        cardinality=cardinality,
        temporal=relationship.temporal,
        confidence=relationship.confidence.value,
        provenance=relationship.provenance,
        source_entity_kind=source_interpretation.entity_kind,
        source_namespace=source_interpretation.namespace,
        source_role=source_interpretation.role,
        target_entity_kind=target_interpretation.entity_kind,
        target_namespace=target_interpretation.namespace,
        target_role=target_interpretation.role,
        evidence_level=relationship.status.value,
        candidate=relationship.status is RelationshipStatus.CANDIDATE,
        source_available=source_state != "unavailable",
        target_available=target_state != "unavailable",
        source_availability=source_state,
        target_availability=target_state,
    )


def _adjacency(
    graph: Graph,
    *,
    include_candidates: bool,
    available_fields: set[str] | None,
    field_availability: dict[str, str] | None,
) -> dict[str, list[GraphStep]]:
    adjacency: dict[str, list[GraphStep]] = {}
    for relationship in sorted(graph.relationships.values(), key=lambda item: item.id):
        if relationship.status is RelationshipStatus.DEPRECATED:
            continue
        if relationship.status is RelationshipStatus.CANDIDATE and not include_candidates:
            continue
        for source, target in _directions(relationship):
            adjacency.setdefault(source, []).append(
                _step(
                    graph,
                    relationship,
                    source,
                    target,
                    available_fields,
                    field_availability,
                )
            )
    for steps in adjacency.values():
        steps.sort(key=lambda item: (item.rank, item.relationship_id, item.target_interpretation))
    return adjacency


def _interpretations_for_locator(graph: Graph, locator: str) -> list[InterpretationRecord]:
    matches = [
        interpretation
        for interpretation in graph.interpretations.values()
        if str(graph.fields[interpretation.field_id].locator) == locator
    ]
    if not matches:
        raise GraphValidationError(f"unknown semantic field locator: {locator}")
    return sorted(matches, key=lambda item: item.id)


def pivot(
    graph: Graph,
    locator: str,
    *,
    include_candidates: bool = False,
    available_fields: set[str] | None = None,
    field_availability: dict[str, str] | None = None,
) -> list[GraphStep]:
    adjacency = _adjacency(
        graph,
        include_candidates=include_candidates,
        available_fields=available_fields,
        field_availability=field_availability,
    )
    result = []
    for interpretation in _interpretations_for_locator(graph, locator):
        result.extend(adjacency.get(interpretation.id, ()))
    return sorted(
        result,
        key=lambda item: (
            item.rank,
            item.target_locator,
            item.target_interpretation,
            item.relationship_id,
        ),
    )


def table_paths(
    graph: Graph,
    source_table: str,
    target_table: str,
    *,
    max_depth: int = 4,
    max_paths: int = 10,
    include_candidates: bool = False,
    available_fields: set[str] | None = None,
    field_availability: dict[str, str] | None = None,
) -> list[GraphPath]:
    if max_depth < 1 or max_depth > 12:
        raise GraphValidationError("max_depth must be between 1 and 12")
    if max_paths < 1:
        raise GraphValidationError("max_paths must be positive")
    source_ids = sorted(
        interpretation.id
        for interpretation in graph.interpretations.values()
        if graph.fields[interpretation.field_id].locator.table == source_table
    )
    target_ids = {
        interpretation.id
        for interpretation in graph.interpretations.values()
        if graph.fields[interpretation.field_id].locator.table == target_table
    }
    if not source_ids or not target_ids:
        return []
    adjacency = _adjacency(
        graph,
        include_candidates=include_candidates,
        available_fields=available_fields,
        field_availability=field_availability,
    )
    found: list[GraphPath] = []

    def walk(current: str, steps: tuple[GraphStep, ...], visited: frozenset[str]) -> None:
        if len(steps) >= max_depth:
            return
        for next_step in adjacency.get(current, ()):
            if next_step.target_interpretation in visited:
                continue
            next_steps = (*steps, next_step)
            if next_step.target_interpretation in target_ids:
                found.append(GraphPath(next_steps))
                continue
            walk(
                next_step.target_interpretation,
                next_steps,
                visited | {next_step.target_interpretation},
            )

    for source_id in source_ids:
        walk(source_id, (), frozenset({source_id}))
    found.sort(
        key=lambda path: (
            path.rank,
            tuple(step.relationship_id for step in path.steps),
            tuple(step.target_interpretation for step in path.steps),
        )
    )
    return found[:max_paths]
