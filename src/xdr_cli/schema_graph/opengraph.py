"""Deterministic generic BloodHound OpenGraph adapter for the public graph."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from xdr_cli.schema_graph.model import Graph, RelationshipStatus

_ID_LABELS = {
    "table": "Table",
    "field": "Field",
    "entity-kind": "EntityKind",
    "namespace": "IdentifierNamespace",
}
_UNSAFE_ID_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_READABLE_ID_PREFIX = 192


def _safe_id(stable_id: str) -> str:
    """Return a stable, globally namespaced ID that stays readable in BloodHound.

    BloodHound maps an OpenGraph node's root ``id`` to ``objectid`` and may use
    that value as the canvas label. Preserve the meaningful part first, then
    append the xdr-cli record namespace. A digest is needed only when unsafe
    characters or truncation make the transformation non-reversible.
    """

    record_kind, separator, meaningful = stable_id.partition(":")
    label = _ID_LABELS.get(record_kind, "Node")
    if not separator or not meaningful:
        meaningful = stable_id
    raw = f"{meaningful}_XDR_CLI_{label}"
    safe = _UNSAFE_ID_CHARS.sub("_", raw).strip("._-")
    changed = safe != raw
    if len(safe) > _MAX_READABLE_ID_PREFIX:
        safe = safe[:_MAX_READABLE_ID_PREFIX].rstrip("._-")
        changed = True
    if not safe:
        safe = f"XDR_CLI_{label}"
        changed = True
    if changed:
        digest = hashlib.sha256(stable_id.encode("utf-8")).hexdigest()[:16]
        safe = f"{safe}_{digest}"
    return safe


def _endpoint(stable_id: str) -> dict[str, str]:
    return {"match_by": "id", "value": _safe_id(stable_id)}


def _edge_kind(relationship: str) -> str:
    return "XDR_" + "".join(part.title() for part in relationship.split("-"))


def export_opengraph(graph: Graph, *, include_candidates: bool = False) -> dict[str, Any]:
    """Emit a generic graph payload conforming to OpenGraph ingest constraints."""

    table_ids = {
        record.locator.table: f"table:{record.locator.table}" for record in graph.fields.values()
    }
    entity_ids = {
        record.entity_kind: f"entity-kind:{record.entity_kind}"
        for record in graph.interpretations.values()
    }
    namespace_ids = {
        record.namespace: f"namespace:{record.namespace}"
        for record in graph.interpretations.values()
    }
    nodes: list[dict[str, Any]] = []
    for table, stable_id in sorted(table_ids.items()):
        nodes.append(
            {
                "id": _safe_id(stable_id),
                "kinds": ["XDR_Table"],
                "properties": {"displayname": table, "xdrid": stable_id},
            }
        )
    for record in sorted(graph.fields.values(), key=lambda item: item.id):
        nodes.append(
            {
                "id": _safe_id(record.id),
                "kinds": ["XDR_Field"],
                "properties": {
                    "displayname": str(record.locator),
                    "xdrid": record.id,
                    "locator": str(record.locator),
                    "kqltype": record.kql_type,
                    "nested": bool(record.locator.json_path),
                },
            }
        )
    for entity_kind, stable_id in sorted(entity_ids.items()):
        nodes.append(
            {
                "id": _safe_id(stable_id),
                "kinds": ["XDR_EntityKind"],
                "properties": {"displayname": entity_kind, "xdrid": stable_id},
            }
        )
    for namespace, stable_id in sorted(namespace_ids.items()):
        nodes.append(
            {
                "id": _safe_id(stable_id),
                "kinds": ["XDR_IdentifierNamespace"],
                "properties": {"displayname": namespace, "xdrid": stable_id},
            }
        )

    edges: list[dict[str, Any]] = []
    for record in sorted(graph.fields.values(), key=lambda item: item.id):
        edges.append(
            {
                "start": _endpoint(table_ids[record.locator.table]),
                "end": _endpoint(record.id),
                "kind": "XDR_ContainsField",
                "properties": {"traversable": False},
            }
        )
    for interpretation in sorted(graph.interpretations.values(), key=lambda item: item.id):
        common = {
            "role": interpretation.role,
            "normalizer": interpretation.normalizer,
            "traversable": False,
        }
        edges.extend(
            [
                {
                    "start": _endpoint(interpretation.field_id),
                    "end": _endpoint(entity_ids[interpretation.entity_kind]),
                    "kind": "XDR_RepresentsEntity",
                    "properties": common,
                },
                {
                    "start": _endpoint(interpretation.field_id),
                    "end": _endpoint(namespace_ids[interpretation.namespace]),
                    "kind": "XDR_UsesNamespace",
                    "properties": common,
                },
            ]
        )
    for relationship in sorted(graph.relationships.values(), key=lambda item: item.id):
        if relationship.status is RelationshipStatus.DEPRECATED:
            continue
        if relationship.status is RelationshipStatus.CANDIDATE and not include_candidates:
            continue
        source = graph.interpretations[relationship.source]
        target = graph.interpretations[relationship.target]
        edges.append(
            {
                "start": _endpoint(source.field_id),
                "end": _endpoint(target.field_id),
                "kind": _edge_kind(relationship.relationship.value),
                "properties": {
                    "xdrid": relationship.id,
                    "direction": relationship.direction.value,
                    "transform": relationship.transform,
                    "cardinality": relationship.cardinality.value,
                    "temporal": relationship.temporal,
                    "status": relationship.status.value,
                    "evidencelevel": relationship.status.value,
                    "confidence": relationship.confidence.value,
                    "join_safe": (relationship.relationship.value == "join-compatible"),
                    "traversable": relationship.status
                    in {
                        RelationshipStatus.OBSERVED,
                        RelationshipStatus.VALIDATED,
                        RelationshipStatus.REVIEWED,
                    },
                },
            }
        )
    return {
        "metadata": {"source_kind": "XDR_CLI"},
        "graph": {"nodes": nodes, "edges": edges},
    }
