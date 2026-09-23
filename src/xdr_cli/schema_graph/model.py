"""Pure data model and invariants for the semantic schema graph."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar
from urllib.parse import quote, unquote_to_bytes

GRAPH_SCHEMA_VERSION = 1
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_STABLE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/#~%*-]{0,1023}$")
_ARTIFACT_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class GraphValidationError(ValueError):
    """A graph record is malformed, inconsistent, or unsafe to load."""


class RelationshipKind(StrEnum):
    SEMANTIC_EQUIVALENT = "semantic-equivalent"
    JOIN_COMPATIBLE = "join-compatible"
    TRANSFORM_REQUIRED = "transform-required"
    BRIDGE = "bridge"
    CORRELATION_ONLY = "correlation-only"


class RelationshipStatus(StrEnum):
    CANDIDATE = "candidate"
    OBSERVED = "observed"
    VALIDATED = "validated"
    REVIEWED = "reviewed"
    DEPRECATED = "deprecated"


class Direction(StrEnum):
    FORWARD = "forward"
    REVERSE = "reverse"
    BOTH = "both"


class Cardinality(StrEnum):
    ONE_TO_ONE = "one-to-one"
    ONE_TO_MANY = "one-to-many"
    MANY_TO_ONE = "many-to-one"
    MANY_TO_MANY = "many-to-many"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class FieldLocator:
    """Parsed top-level or JSON-Pointer-addressed physical field locator."""

    table: str
    column: str
    json_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.table) or not _IDENTIFIER.fullmatch(self.column):
            raise GraphValidationError("field locator table and column must be identifiers")
        if any(
            not isinstance(segment, str) or not segment or any(ord(char) < 32 for char in segment)
            for segment in self.json_path
        ):
            raise GraphValidationError("nested locator path segments cannot be empty/control")

    @classmethod
    def parse(cls, value: str) -> FieldLocator:
        if not isinstance(value, str):
            raise GraphValidationError("field locator must be a string")
        if "#" in value:
            outer, marker, fragment = value.partition("#")
            if "#" in fragment or not marker or not fragment.startswith("/"):
                raise GraphValidationError("nested locator must contain one #/ JSON Pointer")
            outer_parts = outer.split(".")
            if len(outer_parts) != 2 or any(
                not _IDENTIFIER.fullmatch(part) for part in outer_parts
            ):
                raise GraphValidationError("nested locator outer field must be Table.Column")
            if _BAD_PERCENT_ESCAPE.search(fragment):
                raise GraphValidationError("nested locator contains an invalid percent escape")
            try:
                pointer = unquote_to_bytes(fragment).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise GraphValidationError("nested locator is not valid UTF-8") from exc
            segments = pointer.removeprefix("/").split("/")
            decoded = tuple(cls._unescape_pointer_segment(segment) for segment in segments)
            if any(not segment or any(ord(char) < 32 for char in segment) for segment in decoded):
                raise GraphValidationError("nested locator path segments cannot be empty/control")
            return cls(table=outer_parts[0], column=outer_parts[1], json_path=decoded)

        parts = value.split(".")
        if len(parts) < 2 or any(not _IDENTIFIER.fullmatch(part) for part in parts):
            raise GraphValidationError(
                "field locator must be Table.Column with optional dotted shorthand or #/ pointer"
            )
        return cls(table=parts[0], column=parts[1], json_path=tuple(parts[2:]))

    @staticmethod
    def _unescape_pointer_segment(value: str) -> str:
        if re.search(r"~(?![01])", value):
            raise GraphValidationError("nested locator contains an invalid JSON Pointer escape")
        return value.replace("~1", "/").replace("~0", "~")

    @staticmethod
    def _escape_pointer_segment(value: str) -> str:
        return value.replace("~", "~0").replace("/", "~1")

    @property
    def json_pointer(self) -> str | None:
        if not self.json_path:
            return None
        return "/" + "/".join(self._escape_pointer_segment(item) for item in self.json_path)

    def __str__(self) -> str:
        outer = f"{self.table}.{self.column}"
        if not self.json_path:
            return outer
        return outer + "#" + quote(self.json_pointer or "", safe="/~*")


def field_id(locator: str | FieldLocator) -> str:
    parsed = locator if isinstance(locator, FieldLocator) else FieldLocator.parse(locator)
    value = f"field:{parsed}"
    if not _STABLE_ID.fullmatch(value):
        raise GraphValidationError("field locator is too long or cannot form a stable id")
    return value


def interpretation_id(locator: str | FieldLocator, namespace: str, role: str) -> str:
    parsed = locator if isinstance(locator, FieldLocator) else FieldLocator.parse(locator)
    for label, value in (("namespace", namespace), ("role", role)):
        if not _STABLE_ID.fullmatch(value):
            raise GraphValidationError(f"{label} is not a stable identifier")
    value = f"interp:{parsed}:{namespace}:{role}"
    if not _STABLE_ID.fullmatch(value):
        raise GraphValidationError("interpretation semantics cannot form a stable id")
    return value


def relationship_id(
    source: str,
    target: str,
    relationship: RelationshipKind | str,
    direction: Direction | str,
    transform: str,
) -> str:
    if str(direction) == Direction.BOTH.value and target < source:
        source, target = target, source
    payload = json.dumps(
        [source, target, str(relationship), str(direction), transform],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"rel:{hashlib.sha256(payload.encode()).hexdigest()[:24]}"


def _check_common(record: dict[str, Any], expected_type: str) -> dict[str, Any]:
    if record.get("schema_version") != GRAPH_SCHEMA_VERSION:
        raise GraphValidationError(
            f"unsupported graph schema version: {record.get('schema_version')!r}"
        )
    if record.get("record_type") != expected_type:
        raise GraphValidationError(
            f"expected record_type {expected_type!r}, got {record.get('record_type')!r}"
        )
    stable_id = record.get("id")
    if not isinstance(stable_id, str) or not _STABLE_ID.fullmatch(stable_id):
        raise GraphValidationError("record id is missing or is not a stable identifier")
    return record


def _extras(record: dict[str, Any], known: set[str]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in known}


def _with_extras(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    collisions = base.keys() & extra.keys()
    if collisions:
        raise GraphValidationError(
            f"extra fields cannot replace graph contract keys: {sorted(collisions)}"
        )
    return {**base, **extra}


@dataclass(frozen=True, slots=True)
class FieldRecord:
    RECORD_TYPE: ClassVar[str] = "field"

    id: str
    locator: FieldLocator
    kql_type: str
    extra: dict[str, Any] = field(default_factory=dict, compare=False)
    schema_version: int = GRAPH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.id != field_id(self.locator):
            raise GraphValidationError("field id does not match its locator")
        if not isinstance(self.kql_type, str) or not self.kql_type:
            raise GraphValidationError("field kql_type must be a non-empty string")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> FieldRecord:
        record = _check_common(value, cls.RECORD_TYPE)
        locator = FieldLocator.parse(record.get("locator"))
        if record["id"] != field_id(locator):
            raise GraphValidationError("field id does not match its locator")
        if record.get("table") != locator.table or record.get("column") != locator.column:
            raise GraphValidationError("field table/column do not match its locator")
        expected_path = locator.json_pointer
        if record.get("json_path") != expected_path:
            raise GraphValidationError("field json_path does not match its locator")
        kql_type = record.get("kql_type")
        if not isinstance(kql_type, str) or not kql_type:
            raise GraphValidationError("field kql_type must be a non-empty string")
        known = {
            "schema_version",
            "record_type",
            "id",
            "locator",
            "table",
            "column",
            "json_path",
            "kql_type",
        }
        return cls(
            id=record["id"],
            locator=locator,
            kql_type=kql_type,
            extra=_extras(record, known),
        )

    def to_dict(self) -> dict[str, Any]:
        return _with_extras(
            {
                "schema_version": self.schema_version,
                "record_type": self.RECORD_TYPE,
                "id": self.id,
                "locator": str(self.locator),
                "table": self.locator.table,
                "column": self.locator.column,
                "json_path": self.locator.json_pointer,
                "kql_type": self.kql_type,
            },
            self.extra,
        )


@dataclass(frozen=True, slots=True)
class InterpretationRecord:
    RECORD_TYPE: ClassVar[str] = "interpretation"

    id: str
    field_id: str
    entity_kind: str
    namespace: str
    role: str
    normalizer: str
    constraints: tuple[dict[str, Any], ...] = ()
    extra: dict[str, Any] = field(default_factory=dict, compare=False)
    schema_version: int = GRAPH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.field_id.startswith("field:"):
            raise GraphValidationError("interpretation field_id is invalid")
        locator = FieldLocator.parse(self.field_id.removeprefix("field:"))
        expected = interpretation_id(locator, self.namespace, self.role)
        if self.id != expected:
            raise GraphValidationError("interpretation id does not match its semantics")
        if not self.entity_kind or not self.normalizer:
            raise GraphValidationError("interpretation semantic fields cannot be empty")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> InterpretationRecord:
        record = _check_common(value, cls.RECORD_TYPE)
        required = ("field_id", "entity_kind", "namespace", "role", "normalizer")
        if any(not isinstance(record.get(name), str) or not record[name] for name in required):
            raise GraphValidationError("interpretation semantic fields must be non-empty strings")
        constraints = record.get("constraints", [])
        if not isinstance(constraints, list) or any(
            not isinstance(item, dict) for item in constraints
        ):
            raise GraphValidationError("interpretation constraints must be a list of objects")
        known = {
            "schema_version",
            "record_type",
            "id",
            "field_id",
            "entity_kind",
            "namespace",
            "role",
            "normalizer",
            "constraints",
        }
        return cls(
            id=record["id"],
            field_id=record["field_id"],
            entity_kind=record["entity_kind"],
            namespace=record["namespace"],
            role=record["role"],
            normalizer=record["normalizer"],
            constraints=tuple(constraints),
            extra=_extras(record, known),
        )

    def to_dict(self) -> dict[str, Any]:
        return _with_extras(
            {
                "schema_version": self.schema_version,
                "record_type": self.RECORD_TYPE,
                "id": self.id,
                "field_id": self.field_id,
                "entity_kind": self.entity_kind,
                "namespace": self.namespace,
                "role": self.role,
                "normalizer": self.normalizer,
                "constraints": list(self.constraints),
            },
            self.extra,
        )


@dataclass(frozen=True, slots=True)
class RelationshipRecord:
    RECORD_TYPE: ClassVar[str] = "relationship"

    id: str
    source: str
    target: str
    relationship: RelationshipKind
    direction: Direction
    transform: str
    cardinality: Cardinality
    temporal: str
    status: RelationshipStatus
    confidence: Confidence
    provenance: tuple[str, ...]
    extra: dict[str, Any] = field(default_factory=dict, compare=False)
    schema_version: int = GRAPH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not value
            for value in (self.source, self.target, self.transform, self.temporal)
        ):
            raise GraphValidationError("relationship semantic fields must be non-empty strings")
        if self.direction is Direction.BOTH and self.target < self.source:
            raise GraphValidationError("bidirectional relationship endpoints must be sorted")
        if self.id != relationship_id(
            self.source,
            self.target,
            self.relationship,
            self.direction,
            self.transform,
        ):
            raise GraphValidationError("relationship id does not match its semantic identity")
        if not self.provenance:
            raise GraphValidationError("relationship provenance cannot be empty")
        if self.relationship is RelationshipKind.JOIN_COMPATIBLE and (
            self.cardinality is Cardinality.UNKNOWN or self.status is RelationshipStatus.CANDIDATE
        ):
            raise GraphValidationError("join-compatible relationships require reviewed cardinality")
        if self.status in {RelationshipStatus.OBSERVED, RelationshipStatus.VALIDATED} and (
            self.relationship is not RelationshipKind.CORRELATION_ONLY
            or self.direction is not Direction.BOTH
            or self.cardinality is not Cardinality.UNKNOWN
        ):
            raise GraphValidationError(
                "observed/validated empirical relationships must be bidirectional "
                "correlation-only pivots with unknown cardinality"
            )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RelationshipRecord:
        record = _check_common(value, cls.RECORD_TYPE)
        try:
            relationship = RelationshipKind(record.get("relationship"))
            direction = Direction(record.get("direction"))
            cardinality = Cardinality(record.get("cardinality"))
            status = RelationshipStatus(record.get("status"))
            confidence = Confidence(record.get("confidence"))
        except ValueError as exc:
            raise GraphValidationError(f"invalid relationship enum: {exc}") from exc
        required = ("from", "to", "transform", "temporal")
        if any(not isinstance(record.get(name), str) or not record[name] for name in required):
            raise GraphValidationError("relationship semantic fields must be non-empty strings")
        provenance = record.get("provenance")
        if (
            not isinstance(provenance, list)
            or not provenance
            or any(not isinstance(item, str) or not item for item in provenance)
        ):
            raise GraphValidationError("relationship provenance must be a non-empty string list")
        expected_id = relationship_id(
            record["from"], record["to"], relationship, direction, record["transform"]
        )
        if record["id"] != expected_id:
            raise GraphValidationError("relationship id does not match its semantic identity")
        known = {
            "schema_version",
            "record_type",
            "id",
            "from",
            "to",
            "relationship",
            "direction",
            "transform",
            "cardinality",
            "temporal",
            "status",
            "confidence",
            "provenance",
        }
        return cls(
            id=record["id"],
            source=record["from"],
            target=record["to"],
            relationship=relationship,
            direction=direction,
            transform=record["transform"],
            cardinality=cardinality,
            temporal=record["temporal"],
            status=status,
            confidence=confidence,
            provenance=tuple(provenance),
            extra=_extras(record, known),
        )

    def to_dict(self) -> dict[str, Any]:
        return _with_extras(
            {
                "schema_version": self.schema_version,
                "record_type": self.RECORD_TYPE,
                "id": self.id,
                "from": self.source,
                "to": self.target,
                "relationship": self.relationship.value,
                "direction": self.direction.value,
                "transform": self.transform,
                "cardinality": self.cardinality.value,
                "temporal": self.temporal,
                "status": self.status.value,
                "confidence": self.confidence.value,
                "provenance": list(self.provenance),
            },
            self.extra,
        )


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    """Value-free aggregate evidence from one deterministic probe run."""

    observation_id: str
    source_interpretation: str
    target_interpretation: str
    transform: str
    distinct_seeds: int
    matched_seeds: int
    probe_runs: int
    provenance: tuple[str, ...]
    matched_rows: int = 0
    source_artifact_run_id: str | None = None
    target_artifact_run_id: str | None = None
    outcome: str = "observed"
    schema_generation: str | None = None
    observed_at: str | None = None
    lookback: str | None = None
    extra: dict[str, Any] = field(default_factory=dict, compare=False)
    schema_version: int = GRAPH_SCHEMA_VERSION

    RECORD_TYPE: ClassVar[str] = "observation"

    def __post_init__(self) -> None:
        if not _STABLE_ID.fullmatch(self.observation_id):
            raise GraphValidationError("observation id is not stable")
        if (
            self.distinct_seeds < 0
            or self.matched_seeds < 0
            or self.matched_rows < 0
            or self.probe_runs < 1
        ):
            raise GraphValidationError("observation counts are invalid")
        if self.matched_seeds > self.distinct_seeds:
            raise GraphValidationError("matched seeds cannot exceed distinct seeds")
        if not self.provenance:
            raise GraphValidationError("observation provenance cannot be empty")
        if any(
            not isinstance(value, str) or not value
            for value in (
                self.source_interpretation,
                self.target_interpretation,
                self.transform,
            )
        ):
            raise GraphValidationError("observation semantic fields cannot be empty")
        allowed_outcomes = {
            "matched",
            "no-match",
            "empty",
            "partial",
            "throttled",
            "unavailable",
            "inconclusive",
            "observed",
        }
        if self.outcome not in allowed_outcomes:
            raise GraphValidationError("observation outcome is invalid")
        if self.schema_generation is not None and not _ARTIFACT_RUN_ID.fullmatch(
            self.schema_generation
        ):
            raise GraphValidationError("observation schema generation is invalid")
        for run_id in (self.source_artifact_run_id, self.target_artifact_run_id):
            if run_id is not None and (
                not isinstance(run_id, str) or not _ARTIFACT_RUN_ID.fullmatch(run_id)
            ):
                raise GraphValidationError("observation artifact run id is invalid")
        if self.observed_at is not None:
            try:
                observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise GraphValidationError("observation timestamp is invalid") from exc
            if observed.tzinfo is None:
                raise GraphValidationError("observation timestamp must include a timezone")
        if self.lookback is not None and not re.fullmatch(r"[1-9][0-9]{0,4}[smhd]", self.lookback):
            raise GraphValidationError("observation lookback is invalid")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ObservationRecord:
        record = _check_common(value, cls.RECORD_TYPE)
        provenance = record.get("provenance")
        if (
            not isinstance(provenance, list)
            or not provenance
            or any(not isinstance(item, str) or not item for item in provenance)
        ):
            raise GraphValidationError("observation provenance must be a non-empty string list")
        counts = (
            record.get("distinct_seeds"),
            record.get("matched_seeds"),
            record.get("probe_runs"),
            record.get("matched_rows", 0),
        )
        if any(not isinstance(item, int) for item in counts):
            raise GraphValidationError("observation counts must be integers")
        known = {
            "schema_version",
            "record_type",
            "id",
            "source_interpretation",
            "target_interpretation",
            "transform",
            "distinct_seeds",
            "matched_seeds",
            "matched_rows",
            "source_artifact_run_id",
            "target_artifact_run_id",
            "probe_runs",
            "outcome",
            "schema_generation",
            "observed_at",
            "lookback",
            "provenance",
        }
        return cls(
            observation_id=record["id"],
            source_interpretation=record.get("source_interpretation", ""),
            target_interpretation=record.get("target_interpretation", ""),
            transform=record.get("transform", ""),
            distinct_seeds=counts[0],
            matched_seeds=counts[1],
            probe_runs=counts[2],
            provenance=tuple(provenance),
            matched_rows=counts[3],
            source_artifact_run_id=record.get("source_artifact_run_id"),
            target_artifact_run_id=record.get("target_artifact_run_id"),
            outcome=record.get("outcome", "observed"),
            schema_generation=record.get("schema_generation"),
            observed_at=record.get("observed_at"),
            lookback=record.get("lookback"),
            extra=_extras(record, known),
        )

    def to_dict(self) -> dict[str, Any]:
        return _with_extras(
            {
                "schema_version": self.schema_version,
                "record_type": self.RECORD_TYPE,
                "id": self.observation_id,
                "source_interpretation": self.source_interpretation,
                "target_interpretation": self.target_interpretation,
                "transform": self.transform,
                "distinct_seeds": self.distinct_seeds,
                "matched_seeds": self.matched_seeds,
                "matched_rows": self.matched_rows,
                "source_artifact_run_id": self.source_artifact_run_id,
                "target_artifact_run_id": self.target_artifact_run_id,
                "probe_runs": self.probe_runs,
                "outcome": self.outcome,
                "schema_generation": self.schema_generation,
                "observed_at": self.observed_at,
                "lookback": self.lookback,
                "provenance": list(self.provenance),
            },
            self.extra,
        )


def candidate_relationship_from_observation(
    observation: ObservationRecord,
) -> RelationshipRecord:
    """Construct the only relationship an empirical observation may create.

    Observations can prioritize semantic-equivalence review. They cannot
    construct joins, bridges, reviewed state, or high-confidence assertions.
    """

    direction = Direction.BOTH
    relationship = RelationshipKind.SEMANTIC_EQUIVALENT
    source, target = sorted((observation.source_interpretation, observation.target_interpretation))
    stable_id = relationship_id(
        source,
        target,
        relationship,
        direction,
        observation.transform,
    )
    confidence = (
        Confidence.MEDIUM
        if observation.probe_runs >= 2
        and observation.distinct_seeds >= 3
        and observation.matched_seeds >= 2
        else Confidence.LOW
    )
    return RelationshipRecord(
        id=stable_id,
        source=source,
        target=target,
        relationship=relationship,
        direction=direction,
        transform=observation.transform,
        cardinality=Cardinality.UNKNOWN,
        temporal="unknown",
        status=RelationshipStatus.CANDIDATE,
        confidence=confidence,
        provenance=observation.provenance,
        extra={"observation_ids": [observation.observation_id]},
    )


def empirical_relationship_from_observations(
    observations: tuple[ObservationRecord, ...],
    *,
    verified_observation_ids: frozenset[str] = frozenset(),
) -> RelationshipRecord:
    """Construct an observed or validated tenant-local investigation pivot.

    One eligible positive run proves an observed avenue. The caller supplies
    IDs whose tenant-bound artifacts, freshness, semantic contract, namespace
    validator, and seed-cohort independence were reverified; only those can
    strengthen the route to a validated pivot. This policy never creates a raw
    equality join or bridge.
    """

    positive = tuple(
        item for item in observations if item.outcome == "matched" and item.matched_seeds > 0
    )
    if not positive:
        raise GraphValidationError("empirical pivot requires a positive observation")
    first = positive[0]
    semantic_coordinates = {
        (
            item.source_interpretation,
            item.target_interpretation,
            item.transform,
        )
        for item in positive
    }
    if len(semantic_coordinates) != 1:
        raise GraphValidationError("empirical pivot observations have mixed semantics")
    source, target = sorted((first.source_interpretation, first.target_interpretation))
    relationship = RelationshipKind.CORRELATION_ONLY
    direction = Direction.BOTH
    validation_eligible = tuple(
        item
        for item in positive
        if item.observation_id in verified_observation_ids
    )
    evidence_pairs = {
        (item.source_artifact_run_id, item.target_artifact_run_id)
        for item in validation_eligible
        if item.source_artifact_run_id is not None and item.target_artifact_run_id is not None
    }
    source_artifacts = {
        item.source_artifact_run_id
        for item in validation_eligible
        if item.source_artifact_run_id is not None
    }
    target_artifacts = {
        item.target_artifact_run_id
        for item in validation_eligible
        if item.target_artifact_run_id is not None
    }
    tested = sum(item.distinct_seeds for item in validation_eligible)
    matched = sum(item.matched_seeds for item in validation_eligible)
    validation_passed = (
        len(validation_eligible) >= 2
        and len(evidence_pairs) >= 2
        and len(source_artifacts) >= 2
        and len(target_artifacts) >= 2
        and tested >= 6
        and all(
            item.distinct_seeds >= 3 and item.matched_seeds >= 2 for item in validation_eligible
        )
        and matched / tested >= 0.8
    )
    status = RelationshipStatus.VALIDATED if validation_passed else RelationshipStatus.OBSERVED
    confidence = Confidence.HIGH if validation_passed else Confidence.MEDIUM
    observation_ids = sorted(item.observation_id for item in positive)
    return RelationshipRecord(
        id=relationship_id(
            source,
            target,
            relationship,
            direction,
            first.transform,
        ),
        source=source,
        target=target,
        relationship=relationship,
        direction=direction,
        transform=first.transform,
        cardinality=Cardinality.UNKNOWN,
        temporal="bounded-lookback-search",
        status=status,
        confidence=confidence,
        provenance=tuple(sorted({value for item in positive for value in item.provenance})),
        extra={
            "observation_ids": observation_ids,
            "validation_policy": "tenant-search-pivot-v1",
            "validation_decision": ("passed" if validation_passed else "observed-only"),
            "join_safe": False,
        },
    )


@dataclass(slots=True)
class Graph:
    fields: dict[str, FieldRecord] = field(default_factory=dict)
    interpretations: dict[str, InterpretationRecord] = field(default_factory=dict)
    relationships: dict[str, RelationshipRecord] = field(default_factory=dict)

    def add(self, record: FieldRecord | InterpretationRecord | RelationshipRecord) -> None:
        if isinstance(record, FieldRecord):
            destination = self.fields
        elif isinstance(record, InterpretationRecord):
            destination = self.interpretations
        else:
            destination = self.relationships
        prior = destination.get(record.id)
        if prior is not None and prior.to_dict() != record.to_dict():
            raise GraphValidationError(f"conflicting graph record id: {record.id}")
        destination[record.id] = record

    def validate_references(self) -> None:
        for interpretation in self.interpretations.values():
            if interpretation.field_id not in self.fields:
                raise GraphValidationError(
                    f"interpretation {interpretation.id} references missing field "
                    f"{interpretation.field_id}"
                )
        for relationship in self.relationships.values():
            for endpoint in (relationship.source, relationship.target):
                if endpoint not in self.interpretations:
                    raise GraphValidationError(
                        f"relationship {relationship.id} references missing interpretation "
                        f"{endpoint}"
                    )

    def records(self) -> list[FieldRecord | InterpretationRecord | RelationshipRecord]:
        return [
            *sorted(self.fields.values(), key=lambda item: item.id),
            *sorted(self.interpretations.values(), key=lambda item: item.id),
            *sorted(self.relationships.values(), key=lambda item: item.id),
        ]
