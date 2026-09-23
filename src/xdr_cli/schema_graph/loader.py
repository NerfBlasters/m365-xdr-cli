"""Load and validate packaged or caller-provided semantic graph data."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, TextIO

from xdr_cli.schema_graph.model import (
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    RelationshipRecord,
)


@dataclass(frozen=True, slots=True)
class GraphRegistry:
    entity_kinds: frozenset[str]
    namespaces: frozenset[str]
    roles: frozenset[str]
    normalizers: frozenset[str]


def _read_json_resource(name: str) -> dict[str, Any]:
    data_root = resources.files("xdr_cli.schema_graph").joinpath("data")
    try:
        with data_root.joinpath(name).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise GraphValidationError(f"packaged {name} is invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise GraphValidationError(f"packaged {name} must be a JSON object")
    return payload


def load_registry() -> GraphRegistry:
    vocabulary = _read_json_resource("entity-kinds.json")
    transforms = _read_json_resource("transforms.json")
    if vocabulary.get("schema_version") != 1 or transforms.get("schema_version") != 1:
        raise GraphValidationError("unsupported packaged graph registry version")

    def string_set(source: dict[str, Any], key: str) -> frozenset[str]:
        values = source.get(key)
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(item, str) or not item for item in values)
        ):
            raise GraphValidationError(f"registry {key} must be a non-empty string list")
        if len(values) != len(set(values)):
            raise GraphValidationError(f"registry {key} contains duplicates")
        return frozenset(values)

    transform_values = transforms.get("transforms")
    if not isinstance(transform_values, list) or not transform_values:
        raise GraphValidationError("transform registry must be a non-empty list")
    normalizers = []
    for item in transform_values:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise GraphValidationError("each transform registry item requires an id")
        normalizers.append(item["id"])
    if len(normalizers) != len(set(normalizers)):
        raise GraphValidationError("transform registry contains duplicate ids")
    return GraphRegistry(
        entity_kinds=string_set(vocabulary, "entity_kinds"),
        namespaces=string_set(vocabulary, "namespaces"),
        roles=string_set(vocabulary, "roles"),
        normalizers=frozenset(normalizers),
    )


def _record_from_dict(value: dict[str, Any]):
    record_type = value.get("record_type")
    if record_type == FieldRecord.RECORD_TYPE:
        return FieldRecord.from_dict(value)
    if record_type == InterpretationRecord.RECORD_TYPE:
        return InterpretationRecord.from_dict(value)
    if record_type == RelationshipRecord.RECORD_TYPE:
        return RelationshipRecord.from_dict(value)
    raise GraphValidationError(f"unknown graph record_type: {record_type!r}")


def load_graph_stream(handle: TextIO, registry: GraphRegistry | None = None) -> Graph:
    graph = Graph()
    active_registry = registry or load_registry()
    for line_number, line in enumerate(handle, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GraphValidationError(f"invalid graph JSONL at line {line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise GraphValidationError(f"graph line {line_number} must be a JSON object")
        record = _record_from_dict(value)
        if isinstance(record, InterpretationRecord):
            if record.entity_kind not in active_registry.entity_kinds:
                raise GraphValidationError(f"unknown entity kind: {record.entity_kind}")
            if record.namespace not in active_registry.namespaces:
                raise GraphValidationError(f"unknown identifier namespace: {record.namespace}")
            if record.role not in active_registry.roles:
                raise GraphValidationError(f"unknown field role: {record.role}")
            if record.normalizer not in active_registry.normalizers:
                raise GraphValidationError(f"unknown normalizer: {record.normalizer}")
        elif isinstance(record, RelationshipRecord):
            if record.transform not in active_registry.normalizers:
                raise GraphValidationError(f"unknown relationship transform: {record.transform}")
        graph.add(record)
    graph.validate_references()
    return graph


def load_graph_path(path: str | Path, registry: GraphRegistry | None = None) -> Graph:
    with Path(path).open("r", encoding="utf-8") as handle:
        return load_graph_stream(handle, registry)


def load_packaged_graph() -> Graph:
    data_root = resources.files("xdr_cli.schema_graph").joinpath("data")
    with data_root.joinpath("semantic-graph.jsonl").open("r", encoding="utf-8") as handle:
        return load_graph_stream(handle)


def load_packaged_profile(graph: Graph | None = None) -> dict[str, Any]:
    """Load the portable value-free E5 coverage profile."""

    active_graph = graph or load_packaged_graph()
    data_root = resources.files("xdr_cli.schema_graph").joinpath("data", "profiles")
    with data_root.joinpath("microsoft-e5-observed.jsonl").open(
        "r", encoding="utf-8"
    ) as handle:
        lines = [line for line in handle if line.strip()]
    if len(lines) != 1:
        raise GraphValidationError("packaged E5 profile must contain exactly one record")
    try:
        profile = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise GraphValidationError(f"packaged E5 profile is invalid JSON: {exc}") from exc
    if (
        not isinstance(profile, dict)
        or profile.get("schema_version") != 1
        or profile.get("record_type") != "profile"
        or profile.get("id") != "profile:microsoft-e5-observed"
        or profile.get("license_assumption") != "microsoft-e5"
        or profile.get("scope") != "reviewed-starter-fields"
        or profile.get("availability_claim") != "none; tenant cache is authoritative"
    ):
        raise GraphValidationError("packaged E5 starter profile contract is invalid")
    field_ids = profile.get("field_ids")
    if (
        not isinstance(field_ids, list)
        or not field_ids
        or len(field_ids) != len(set(field_ids))
        or any(item not in active_graph.fields for item in field_ids)
    ):
        raise GraphValidationError("packaged E5 profile field references are invalid")
    return profile
