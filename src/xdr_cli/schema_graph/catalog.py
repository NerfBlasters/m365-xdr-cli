"""Deterministic tenant locator catalog and provisional probe targets."""

from __future__ import annotations

from dataclasses import dataclass

from xdr_cli.schema_graph.artifact_metadata import ArtifactShapeField
from xdr_cli.schema_graph.model import (
    FieldLocator,
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    field_id,
    interpretation_id,
)
from xdr_cli.schema_graph.probe import supports_probe_prefilter

_STRING_TYPES = {"string", "system.string"}
_DYNAMIC_TYPES = {"dynamic", "system.dynamic", "object", "system.object"}


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    field: FieldRecord
    interpretation: InterpretationRecord
    provisional: bool


def normalized_kql_type(value: object) -> str | None:
    """Return the probeable KQL type represented by a getschema value."""

    if not isinstance(value, str):
        return None
    lowered = value.strip().casefold()
    if lowered in _STRING_TYPES:
        return "string"
    if lowered in _DYNAMIC_TYPES:
        return "dynamic"
    return None


def physical_catalog_graph(schema_rows: list[dict], known: Graph) -> Graph:
    """Materialize every eligible top-level tenant field plus known nested fields."""

    catalog = Graph()
    for row in schema_rows:
        table = row.get("TableName")
        column = row.get("ColumnName")
        kql_type = normalized_kql_type(row.get("ColumnType"))
        if not isinstance(table, str) or not isinstance(column, str) or kql_type is None:
            continue
        try:
            locator = FieldLocator(table=table, column=column)
        except GraphValidationError:
            continue
        identifier = field_id(locator)
        if identifier not in known.fields:
            catalog.add(
                FieldRecord(
                    id=identifier,
                    locator=locator,
                    kql_type=kql_type,
                    extra={"provenance": ["tenant-schema"], "private": True},
                )
            )

    return catalog


def graph_from_artifact_shapes(
    shapes: tuple[ArtifactShapeField, ...],
    *,
    provenance: str,
    known: Graph | None = None,
) -> Graph:
    """Convert safely attributed sidecar paths into self-consistent fields.

    Known stable IDs reuse the exact reviewed record. This preserves the
    observation signal without creating a conflicting private variant.
    """

    graph = Graph()
    for shape in shapes:
        if shape.lineage != "physical-shape" or "string" not in shape.observed_types:
            continue
        record = FieldRecord(
            id=field_id(shape.locator),
            locator=shape.locator,
            kql_type="string",
            extra={
                "provenance": [provenance],
                "private": True,
            },
        )
        graph.add(known.fields.get(record.id, record) if known is not None else record)
    return graph


def exhaustive_probe_targets(
    schema_rows: list[dict],
    graph: Graph,
    source: InterpretationRecord,
) -> tuple[tuple[ProbeTarget, ...], Graph]:
    """Plan every eligible locator under one reviewed source interpretation.

    The returned graph contains only new private field/interpretation records.
    A provisional interpretation means "tested as this namespace", not that
    every value in the target field has that semantic type.
    """

    if not supports_probe_prefilter(source.normalizer):
        raise GraphValidationError(
            f"normalizer {source.normalizer!r} has no deterministic KQL prefilter"
        )
    additions = physical_catalog_graph(schema_rows, graph)
    combined_fields = {**graph.fields, **additions.fields}
    eligible_outer = {
        (str(row.get("TableName")), str(row.get("ColumnName")))
        for row in schema_rows
        if normalized_kql_type(row.get("ColumnType")) is not None
        and row.get("TableName")
        and row.get("ColumnName")
    }
    existing_by_field: dict[str, list[InterpretationRecord]] = {}
    for item in graph.interpretations.values():
        existing_by_field.setdefault(item.field_id, []).append(item)

    targets: list[ProbeTarget] = []
    for field in sorted(combined_fields.values(), key=lambda item: str(item.locator)):
        if field.id == source.field_id or (
            field.locator.table,
            field.locator.column,
        ) not in eligible_outer:
            continue
        applicable = [
            item
            for item in existing_by_field.get(field.id, [])
            if item.entity_kind == source.entity_kind
            and item.namespace == source.namespace
            and item.normalizer == source.normalizer
        ]
        compatible = sorted(
            (item for item in applicable if not item.constraints),
            key=lambda item: item.id,
        )
        if compatible:
            targets.extend(
                ProbeTarget(
                    field,
                    item,
                    item.extra.get("provisional") is True,
                )
                for item in compatible
            )
            continue
        if applicable:
            # A reviewed constrained interpretation is evidence that this
            # field is polymorphic. Creating an unconstrained provisional copy
            # would bypass the constraint and misclassify sibling-dependent
            # values. Fail closed until the compiler can enforce it.
            continue
        identifier = interpretation_id(field.locator, source.namespace, "neutral")
        provisional = InterpretationRecord(
            id=identifier,
            field_id=field.id,
            entity_kind=source.entity_kind,
            namespace=source.namespace,
            role="neutral",
            normalizer=source.normalizer,
            extra={
                "status": "candidate",
                "provisional": True,
                "private": True,
                "provenance": ["tenant-probe-plan"],
            },
        )
        prior = graph.interpretations.get(identifier)
        if prior is not None and prior.to_dict() != provisional.to_dict():
            raise GraphValidationError(
                f"provisional interpretation conflicts with {identifier}"
            )
        if prior is None:
            if field.id not in additions.fields:
                # Overlay generations validate independently of the packaged
                # graph, so every provisional interpretation must carry its
                # exact field dependency even when the field is canonical.
                additions.add(field)
            additions.add(provisional)
        targets.append(ProbeTarget(field, prior or provisional, True))

    # A locator can have multiple reviewed compatible roles. Probe it once,
    # preferring a reviewed interpretation over a provisional one.
    by_locator: dict[str, ProbeTarget] = {}
    for target in targets:
        key = str(target.field.locator)
        prior = by_locator.get(key)
        if prior is None or (prior.provisional and not target.provisional):
            by_locator[key] = target
    return tuple(by_locator[key] for key in sorted(by_locator)), additions
