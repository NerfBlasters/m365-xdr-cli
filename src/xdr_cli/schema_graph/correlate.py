"""Offline event/entity correlation over private result artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from xdr_cli.config import get_config_home
from xdr_cli.exceptions import ArtifactError, ConflictError, LocalNotFoundError
from xdr_cli.schema_graph.model import (
    Cardinality,
    Direction,
    FieldLocator,
    Graph,
    InterpretationRecord,
    RelationshipKind,
    RelationshipStatus,
)
from xdr_cli.schema_graph.normalize import NormalizationError, normalize_value

_RUN_ID = re.compile(r"[A-Za-z0-9-]+")


@dataclass(frozen=True, slots=True)
class ArtifactInput:
    table: str
    run_id: str
    metadata: dict[str, Any]
    rows: tuple[dict[str, Any], ...]
    lineage: str
    tenant_fingerprint: str | None


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    records: tuple[dict[str, Any], ...]
    entity_count: int
    edge_count: int
    shared_entity_count: int
    contextual_match_count: int
    structural_route_count: int


def load_artifact_input(table: str, run_id: str) -> ArtifactInput:
    if not _RUN_ID.fullmatch(run_id):
        raise ArtifactError(
            "Result run ID contains invalid characters",
            help_command="xdr results list",
        )
    root = (get_config_home() / "results").resolve()
    matches = list(root.glob(f"*/{run_id}*.meta.json"))
    exact = [path for path in matches if path.name == f"{run_id}.meta.json"]
    selected = exact or matches
    if not selected:
        error = LocalNotFoundError("result", run_id)
        error.help_command = "xdr results list"
        raise error
    if len(selected) != 1:
        raise ConflictError(
            f"Result ID prefix {run_id!r} is ambiguous",
            help_command="xdr results list",
        )
    try:
        meta_path = selected[0].resolve()
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        metadata_run_id = metadata["run_id"]
        selected_run_id = meta_path.name.removesuffix(".meta.json")
        data_path = Path(metadata["data_path"]).resolve()
        registered_meta_path = Path(metadata["meta_path"]).resolve()
        if (
            not isinstance(metadata_run_id, str)
            or not metadata_run_id.startswith(run_id)
            or selected_run_id != metadata_run_id
            or registered_meta_path != meta_path
            or not data_path.is_relative_to(root)
            or data_path.parent != meta_path.parent
            or data_path.name != f"{metadata_run_id}.jsonl"
        ):
            raise ValueError("metadata, requested run ID, and artifact paths are inconsistent")
        raw_data = data_path.read_bytes()
        expected_digest = metadata.get("data_sha256")
        if not isinstance(expected_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_digest
        ):
            raise ValueError("artifact has no valid data digest; regenerate it with this version")
        if hashlib.sha256(raw_data).hexdigest() != expected_digest:
            raise ValueError("artifact data digest does not match its metadata")
        rows = tuple(
            json.loads(line)
            for line in raw_data.decode("utf-8").splitlines()
            if line.strip()
        )
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ArtifactError(
            f"Result artifact is unreadable or invalid: {exc}",
            help_command=f"xdr results show {run_id}",
        ) from exc
    if not isinstance(metadata, dict) or any(not isinstance(row, dict) for row in rows):
        raise ArtifactError(
            "Result artifact metadata and rows must be JSON objects",
            help_command=f"xdr results show {run_id}",
        )
    if metadata.get("row_count") != len(rows):
        raise ArtifactError(
            "Result artifact row count does not match its metadata",
            help_command=f"xdr results show {run_id}",
        )
    tenant_binding = metadata.get("tenant_binding")
    tenant_key = (
        tenant_binding.get("sha256")
        if isinstance(tenant_binding, dict) and tenant_binding.get("state") == "bound"
        else None
    )
    if tenant_key is not None and (
        not isinstance(tenant_key, str) or not re.fullmatch(r"[0-9a-f]{64}", tenant_key)
    ):
        raise ArtifactError(
            "Result artifact tenant binding is invalid",
            help_command=f"xdr results show {run_id}",
        )
    lineage = metadata.get("physical_lineage")
    lineage_table = (
        lineage.get("table")
        if isinstance(lineage, dict) and lineage.get("kind") == "physical"
        else None
    )
    if lineage_table is None:
        # Compatibility for artifacts written before physical_lineage was a
        # first-class sidecar field. Only the same conservative parser used at
        # result publication may establish legacy lineage.
        from xdr_cli.schema_graph.ingest import infer_direct_table_lineage

        query = metadata.get("query")
        lineage_table = infer_direct_table_lineage(query) if isinstance(query, str) else None
    if lineage_table != table:
        detail = "unknown" if lineage_table is None else repr(lineage_table)
        raise ArtifactError(
            f"Result {metadata['run_id']} has {detail} physical lineage, not {table!r}; "
            "correlate only direct single-table artifacts",
            help_command=f"xdr results show {run_id}",
        )
    return ArtifactInput(
        table=table,
        run_id=metadata["run_id"],
        metadata=metadata,
        rows=rows,
        lineage="physical",
        tenant_fingerprint=tenant_key,
    )


def _nested_values(value: object, path: tuple[str, ...]) -> list[object]:
    if not path:
        return [value]
    head, *tail = path
    if head == "*":
        if not isinstance(value, list):
            return []
        return [result for item in value for result in _nested_values(item, tuple(tail))]
    if not isinstance(value, dict) or head not in value:
        return []
    return _nested_values(value[head], tuple(tail))


def _locator_values(row: dict[str, Any], locator: FieldLocator) -> list[object]:
    if locator.column not in row:
        return []
    value = row[locator.column]
    if locator.json_path and isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    return _nested_values(value, locator.json_path)


def _entity_id(interpretation_id: str, normalized: str) -> str:
    digest = hashlib.sha256(f"{interpretation_id}\0{normalized}".encode()).hexdigest()
    return f"entity:{digest}"


def _strong_relationship(relationship) -> bool:
    """Return whether equality is strong enough for the default shared count."""

    return (
        relationship.relationship is RelationshipKind.JOIN_COMPATIBLE
        and relationship.cardinality is not Cardinality.MANY_TO_MANY
        and "mutable" not in relationship.temporal
        and "tight-time-window" not in relationship.temporal
    )


def _reviewed_path(
    relationships: list,
    source: str,
    target: str,
    *,
    max_depth: int = 4,
) -> tuple | None:
    """Return the deterministic shortest reviewed path between interpretations."""

    adjacency: dict[str, list[tuple[str, object]]] = {}
    for relationship in relationships:
        directions = []
        if relationship.direction in {Direction.FORWARD, Direction.BOTH}:
            directions.append((relationship.source, relationship.target))
        if relationship.direction in {Direction.REVERSE, Direction.BOTH}:
            directions.append((relationship.target, relationship.source))
        for start, end in directions:
            adjacency.setdefault(start, []).append((end, relationship))
    for edges in adjacency.values():
        edges.sort(key=lambda item: (item[1].id, item[0]))

    queue: list[tuple[str, tuple, frozenset[str]]] = [(source, (), frozenset({source}))]
    while queue:
        current, path, visited = queue.pop(0)
        if len(path) >= max_depth:
            continue
        for next_id, relationship in adjacency.get(current, ()):
            if next_id in visited:
                continue
            next_path = (*path, relationship)
            if next_id == target:
                return next_path
            queue.append((next_id, next_path, visited | {next_id}))
    return None


def correlate_inputs(
    graph: Graph,
    inputs: tuple[ArtifactInput, ...],
    *,
    include_contextual: bool = False,
) -> CorrelationResult:
    relationships = [
        relationship
        for relationship in graph.relationships.values()
        if relationship.status is RelationshipStatus.REVIEWED
        and (_strong_relationship(relationship) or include_contextual)
    ]
    reviewed_ids = {
        endpoint
        for relationship in relationships
        for endpoint in (relationship.source, relationship.target)
    }
    by_table: dict[str, list[InterpretationRecord]] = {}
    for interpretation in graph.interpretations.values():
        locator = graph.fields[interpretation.field_id].locator
        if interpretation.id in reviewed_ids:
            by_table.setdefault(locator.table, []).append(interpretation)

    records: list[dict[str, Any]] = []
    entities: dict[str, dict[str, Any]] = {}
    occurrences: dict[str, list[tuple[str, str, object]]] = {}
    edge_count = 0
    for artifact in inputs:
        records.append(
            {
                "record_type": "declared-input",
                "id": f"input:{artifact.run_id}",
                "run_id": artifact.run_id,
                "source_table": artifact.table,
                "lineage": artifact.lineage,
                "tenant_bound": artifact.tenant_fingerprint is not None,
            }
        )
        interpretations = sorted(by_table.get(artifact.table, ()), key=lambda item: item.id)
        for row_number, row in enumerate(artifact.rows, start=1):
            event_id = f"event:{artifact.run_id}:{row_number}"
            event_edges = []
            for interpretation in interpretations:
                locator = graph.fields[interpretation.field_id].locator
                for raw_value in _locator_values(row, locator):
                    occurrences.setdefault(interpretation.id, []).append(
                        (artifact.run_id, event_id, raw_value)
                    )
                    try:
                        normalized = normalize_value(interpretation.normalizer, raw_value)
                    except NormalizationError:
                        continue
                    entity_id = _entity_id(interpretation.id, normalized)
                    entities.setdefault(
                        entity_id,
                        {
                            "record_type": "entity",
                            "id": entity_id,
                            "entity_kind": interpretation.entity_kind,
                            "namespace": interpretation.namespace,
                            "interpretation_id": interpretation.id,
                            "value": normalized,
                        },
                    )
                    event_edges.append(
                        {
                            "record_type": "event-entity-edge",
                            "event_id": event_id,
                            "entity_id": entity_id,
                            "locator": str(locator),
                            "interpretation_id": interpretation.id,
                            "role": interpretation.role,
                            "lineage": "physical-sidecar",
                        }
                    )
            records.append(
                {
                    "record_type": "event",
                    "id": event_id,
                    "run_id": artifact.run_id,
                    "row_number": row_number,
                    "source_table": artifact.table,
                }
            )
            records.extend(event_edges)
            edge_count += len(event_edges)

    structural_records: list[dict[str, Any]] = []
    declared_interpretations = sorted(
        {
            interpretation.id
            for artifact in inputs
            for interpretation in by_table.get(artifact.table, ())
        }
    )
    for source_index, source_id in enumerate(declared_interpretations):
        for target_id in declared_interpretations[source_index + 1 :]:
            source_locator = graph.fields[graph.interpretations[source_id].field_id].locator
            target_locator = graph.fields[graph.interpretations[target_id].field_id].locator
            if source_locator.table == target_locator.table:
                continue
            path = _reviewed_path(relationships, source_id, target_id)
            if path is None:
                continue
            path_is_strong = all(_strong_relationship(item) for item in path)
            digest = hashlib.sha256(
                f"{source_id}\0{target_id}\0{'/'.join(item.id for item in path)}".encode()
            ).hexdigest()[:24]
            structural_records.append(
                {
                    "record_type": "structural-route",
                    "id": f"route:{digest}",
                    "source_interpretation": source_id,
                    "target_interpretation": target_id,
                    "source_locator": str(source_locator),
                    "target_locator": str(target_locator),
                    "relationship_ids": [item.id for item in path],
                    "relationships": [item.relationship.value for item in path],
                    "hop_count": len(path),
                    "match_strength": "strong" if path_is_strong else "contextual",
                    "row_match": "not-evaluated",
                }
            )
    records.extend(sorted(structural_records, key=lambda item: item["id"]))

    strong_matches = 0
    contextual_matches = 0
    match_records: list[dict[str, Any]] = []
    interpretation_ids = sorted(occurrences)
    for source_index, source_id in enumerate(interpretation_ids):
        for target_id in interpretation_ids[source_index + 1 :]:
            source_interp = graph.interpretations[source_id]
            target_interp = graph.interpretations[target_id]
            if (
                source_interp.namespace != target_interp.namespace
                or source_interp.normalizer != target_interp.normalizer
            ):
                continue
            path = _reviewed_path(relationships, source_id, target_id)
            if path is None:
                continue
            path_is_strong = all(_strong_relationship(item) for item in path)
            if not path_is_strong and not include_contextual:
                continue
            endpoint_values: list[dict[str, list[tuple[str, str]]]] = []
            for endpoint in (source_id, target_id):
                values: dict[str, list[tuple[str, str]]] = {}
                for run_id, event_id, raw_value in occurrences.get(endpoint, ()):
                    try:
                        normalized = normalize_value(source_interp.normalizer, raw_value)
                    except NormalizationError:
                        continue
                    values.setdefault(normalized, []).append((run_id, event_id))
                endpoint_values.append(values)
            shared_values = sorted(endpoint_values[0].keys() & endpoint_values[1].keys())
            for normalized in shared_values:
                source_occurrences = endpoint_values[0][normalized]
                target_occurrences = endpoint_values[1][normalized]
                if not any(
                    source_run != target_run
                    for source_run, _source_event in source_occurrences
                    for target_run, _target_event in target_occurrences
                ):
                    continue
                source_entity = _entity_id(source_id, normalized)
                target_entity = _entity_id(target_id, normalized)
                for identifier, interpretation in (
                    (source_entity, source_interp),
                    (target_entity, target_interp),
                ):
                    entities.setdefault(
                        identifier,
                        {
                            "record_type": "entity",
                            "id": identifier,
                            "entity_kind": interpretation.entity_kind,
                            "namespace": interpretation.namespace,
                            "interpretation_id": interpretation.id,
                            "value": normalized,
                        },
                    )
                strength = "strong" if path_is_strong else "contextual"
                if strength == "strong":
                    strong_matches += 1
                else:
                    contextual_matches += 1
                match_digest = hashlib.sha256(
                    (
                        f"{'/'.join(item.id for item in path)}\0"
                        f"{source_id}\0{target_id}\0{normalized}"
                    ).encode()
                ).hexdigest()[:24]
                match_records.append(
                    {
                        "record_type": "relationship-path-match",
                        "id": f"match:{match_digest}",
                        "relationship_ids": [item.id for item in path],
                        "relationships": [item.relationship.value for item in path],
                        "hop_count": len(path),
                        "source_entity_id": source_entity,
                        "target_entity_id": target_entity,
                        "source_interpretation": source_id,
                        "target_interpretation": target_id,
                        "transforms": [item.transform for item in path],
                        "cardinalities": [item.cardinality.value for item in path],
                        "temporal_guidance": [item.temporal for item in path],
                        "confidences": [item.confidence.value for item in path],
                        "provenance": [list(item.provenance) for item in path],
                        "match_strength": strength,
                        "temporal_evaluation": (
                            "not-required"
                            if strength == "strong"
                            else "required-not-evaluated"
                        ),
                        "source_event_ids": sorted(
                            {item[1] for item in source_occurrences}
                        ),
                        "target_event_ids": sorted(
                            {item[1] for item in target_occurrences}
                        ),
                    }
                )
    records.extend(entities[key] for key in sorted(entities))
    records.extend(sorted(match_records, key=lambda item: item["id"]))
    return CorrelationResult(
        records=tuple(records),
        entity_count=len(entities),
        edge_count=edge_count,
        shared_entity_count=strong_matches,
        contextual_match_count=contextual_matches,
        structural_route_count=len(structural_records),
    )
