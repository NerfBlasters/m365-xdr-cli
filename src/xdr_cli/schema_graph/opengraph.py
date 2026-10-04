"""Deterministic generic BloodHound OpenGraph adapter for the public graph."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from xdr_cli.schema_graph.model import (
    Confidence,
    Direction,
    Graph,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
)

_ID_LABELS = {
    "table": "Table",
    "field": "Field",
    "entity-kind": "EntityKind",
    "namespace": "IdentifierNamespace",
}
_UNSAFE_ID_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_READABLE_ID_PREFIX = 192

# Table-to-table edge kinds. Plain words keep BloodHound's edge labels short;
# they only ever connect XDR_Table nodes, so anchored queries stay unambiguous.
_TABLE_EDGE_KINDS = {
    RelationshipKind.JOIN_COMPATIBLE: "Join",
    RelationshipKind.TRANSFORM_REQUIRED: "NormalizeJoin",
    RelationshipKind.SEMANTIC_EQUIVALENT: "SameEntity",
    RelationshipKind.CORRELATION_ONLY: "Correlate",
    RelationshipKind.BRIDGE: "Bridge",
}
_USABLE_STATUSES = {
    RelationshipStatus.OBSERVED,
    RelationshipStatus.VALIDATED,
    RelationshipStatus.REVIEWED,
}
_STATUS_RANK = {
    RelationshipStatus.CANDIDATE: 0,
    RelationshipStatus.OBSERVED: 1,
    RelationshipStatus.VALIDATED: 2,
    RelationshipStatus.REVIEWED: 3,
}
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

# Request body for BloodHound CE's POST /api/v2/custom-nodes. Icons must be
# free, solid Font Awesome names; colors must be #RRGGBB.
_CUSTOM_NODE_STYLES = {
    "XDR_Table": ("table", "#2F7DD1"),
    "XDR_Field": ("table-columns", "#7A8899"),
    "XDR_EntityKind": ("fingerprint", "#C2410C"),
    "XDR_IdentifierNamespace": ("key", "#0F8F74"),
}


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


def _exported(relationship: RelationshipRecord, include_candidates: bool) -> bool:
    if relationship.status is RelationshipStatus.DEPRECATED:
        return False
    return include_candidates or relationship.status is not RelationshipStatus.CANDIDATE


def _field_name(locator: Any) -> str:
    return ".".join((locator.column, *locator.json_path))


def _table_pivot_edges(graph: Graph, *, include_candidates: bool) -> list[dict[str, Any]]:
    """Summarize field-level relationships as one edge per table pair and kind."""

    groups: dict[
        tuple[str, str, RelationshipKind], list[tuple[str, str, RelationshipRecord]]
    ] = {}
    for relationship in graph.relationships.values():
        if not _exported(relationship, include_candidates):
            continue
        source = graph.fields[graph.interpretations[relationship.source].field_id].locator
        target = graph.fields[graph.interpretations[relationship.target].field_id].locator
        if source.table == target.table:
            continue
        if relationship.direction is Direction.BOTH:
            start, end = sorted((source, target), key=lambda locator: locator.table)
            direction = Direction.BOTH.value
        elif relationship.direction is Direction.FORWARD:
            start, end = source, target
            direction = Direction.FORWARD.value
        else:
            start, end = target, source
            direction = Direction.FORWARD.value
        key = (start.table, end.table, relationship.relationship)
        groups.setdefault(key, []).append((f"{start}={end}", direction, relationship))

    edges: list[dict[str, Any]] = []
    for (start_table, end_table, kind), members in sorted(
        groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2].value)
    ):
        records = [record for _, _, record in members]
        # These are lower bounds for *all* listed keys, not an endorsement
        # borrowed from a stronger member. Detailed evidence stays on fields.
        status = min((record.status for record in records), key=_STATUS_RANK.__getitem__)
        confidence = min(
            (record.confidence for record in records), key=_CONFIDENCE_RANK.__getitem__
        )
        directions = sorted({direction for _, direction, _ in members})
        edges.append(
            {
                "start": _endpoint(f"table:{start_table}"),
                "end": _endpoint(f"table:{end_table}"),
                "kind": _TABLE_EDGE_KINDS[kind],
                "properties": {
                    "keys": sorted(pair for pair, _, _ in members),
                    "relationshipids": sorted(record.id for record in records),
                    "count": len(records),
                    "status": status.value,
                    "evidencelevel": status.value,
                    "confidence": confidence.value,
                    "statuses": sorted({record.status.value for record in records}),
                    "confidences": sorted({record.confidence.value for record in records}),
                    "candidatecount": sum(
                        record.status is RelationshipStatus.CANDIDATE for record in records
                    ),
                    "direction": directions[0] if len(directions) == 1 else "mixed",
                    "directions": directions,
                    "join_safe": kind is RelationshipKind.JOIN_COMPATIBLE,
                    "traversable": all(record.status in _USABLE_STATUSES for record in records),
                },
            }
        )
    return edges


def bloodhound_custom_nodes() -> dict[str, Any]:
    """Return the BloodHound CE custom-node registration for exported node kinds."""

    return {
        "custom_types": {
            kind: {"icon": {"type": "font-awesome", "name": icon, "color": color}}
            for kind, (icon, color) in sorted(_CUSTOM_NODE_STYLES.items())
        }
    }


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
                "properties": {"displayname": table, "name": table, "xdrid": stable_id},
            }
        )
    for record in sorted(graph.fields.values(), key=lambda item: item.id):
        nodes.append(
            {
                "id": _safe_id(record.id),
                "kinds": ["XDR_Field"],
                "properties": {
                    "displayname": str(record.locator),
                    "name": _field_name(record.locator),
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
                "properties": {"displayname": entity_kind, "name": entity_kind, "xdrid": stable_id},
            }
        )
    for namespace, stable_id in sorted(namespace_ids.items()):
        nodes.append(
            {
                "id": _safe_id(stable_id),
                "kinds": ["XDR_IdentifierNamespace"],
                "properties": {"displayname": namespace, "name": namespace, "xdrid": stable_id},
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
        if not _exported(relationship, include_candidates):
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
                    "traversable": relationship.status in _USABLE_STATUSES,
                },
            }
        )
    edges.extend(_table_pivot_edges(graph, include_candidates=include_candidates))
    return {
        "metadata": {"source_kind": "XDR_CLI"},
        "graph": {"nodes": nodes, "edges": edges},
    }
