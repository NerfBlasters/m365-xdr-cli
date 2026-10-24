"""Compose trusted public mappings with current tenant physical availability."""

from __future__ import annotations

from dataclasses import replace

from xdr_cli.schema_graph.effective import (
    EffectiveGraph,
    FieldAvailability,
    compose_effective_graph,
    merge_graphs,
)
from xdr_cli.schema_graph.model import (
    Cardinality,
    Confidence,
    Direction,
    FieldRecord,
    InterpretationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    field_id,
    interpretation_id,
    relationship_id,
)
from xdr_cli.schema_graph.physical import canonical_storage_type, queryable_rows
from xdr_cli.schema_graph.reference import REFERENCE_URLS, ReferenceRoute, ReferenceSnapshot
from xdr_cli.schema_graph.reference_query import FAMILY_NORMALIZERS

_FAMILIES = {
    "defender-device": ("device", "mde-device-id", "hex40-lower"),
    "entra-device": ("device", "entra-device-id", "guid-lower"),
    "entra-user": ("user", "entra-object-id", "guid-lower"),
    "entra-session": ("session", "entra-session-id", "text-lower"),
    "entra-token": ("session", "entra-token-id", "identity"),
    "oauth-client": ("application", "oauth-client-id", "guid-lower"),
    "service-principal": ("service-principal", "entra-service-principal-id", "guid-lower"),
    "email-message": ("email-message", "network-message-id", "identity"),
    "file-sha1": ("hash", "sha1", "sha1-lower"),
    "file-sha256": ("hash", "sha256", "sha256-lower"),
    "azure-resource": ("cloud-resource", "azure-resource-id", "text-lower"),
}
DISABLED_VALIDATION = frozenset({
    "contradicted", "schema-mismatch", "query-failed", "invalid-shape", "evidence-unavailable",
})


def family_contract(route: ReferenceRoute) -> tuple[str, str, str]:
    """Explicit namespaces prevent same-looking IDs from becoming aliases."""

    kind, namespace, normalizer = _FAMILIES.get(
        route.family, ("identifier", "xdrinternals-" + route.family,
                       {"lower": "text-lower", "upper": "text-upper"}.get(
                           FAMILY_NORMALIZERS.get(route.family), "identity")),
    )
    return kind, namespace, normalizer


def route_transform(route: ReferenceRoute) -> str:
    if route.family == "entra-token" and any(
        e.table == "AADGraphActivityLogs" and e.column == "SignInActivityId"
        for e in (route.source, route.target)
    ):
        return "token-unpad"
    return family_contract(route)[2]


def route_schema_status(route: ReferenceRoute, schema_rows: list[dict]) -> str:
    physical = {(r.get("TableName"), r.get("ColumnName")): r for r in queryable_rows(schema_rows)}
    for endpoint in (route.source, route.target):
        row = physical.get((endpoint.table, endpoint.column))
        if row is None:
            return "schema-unavailable"
        storage = canonical_storage_type(row.get("ColumnType"))
        allowed = {"string", "dynamic"} if endpoint.path else {"string", "guid", "long", "int"}
        if storage not in allowed:
            return "type-conflict"
    return "available"


def reference_catalog(
    snapshot: ReferenceSnapshot, schema_rows: list[dict], states: dict[str, dict] | None = None,
) -> list[dict]:
    """Every upstream mapping has a row, including unavailable/inconclusive routes."""

    records = []
    for route in snapshot.routes:
        state = (states or {}).get(route.id, {})
        physical = route_schema_status(route, schema_rows)
        validation = state.get("status", "pending")
        trusted = route.record.get("origin") != "tenant-new-table"
        unverified = [value for value in state.get("constraints_applied", [])
                      if value.startswith("condition-unverifiable:")]
        records.append({
            "ReferenceId": route.id, "Title": route.title, "Family": route.family,
            "Source": str(route.source.locator), "Target": str(route.target.locator),
            "ReferenceTrusted": trusted and validation not in DISABLED_VALIDATION,
            "MappingOrigin": "reference" if trusted else "tenant-new-table",
            "ReferenceValidationState": validation,
            "TenantSchema": physical,
            "TenantUsable": (physical == "available"
                             and validation not in DISABLED_VALIDATION
                             | {"unsupported", "schema-unavailable"} and not unverified),
            "UnverifiableConditions": unverified,
            "Guidance": route.guidance, "SourceUrl": REFERENCE_URLS["relations"],
            "ReferenceDigest": snapshot.digest,
            "ValidationRunId": state.get("run_id"),
            "ValidationCounts": state.get("counts"),
            "ValidationScope": state.get("validation_scope", "reference-assumption"),
            "ValidationWarnings": state.get("warnings", []),
            "ValidationConstraints": state.get("constraints_applied", []),
        })
    return records


def compose_reference_routes(
    effective: EffectiveGraph,
    snapshot: ReferenceSnapshot,
    schema_rows: list[dict],
    *,
    states: dict[str, dict] | None = None,
    coverage: dict | None = None,
) -> EffectiveGraph:
    """Keep reviewed core authoritative; add usable, provenance-bound reference routes.

    Reference trust is neither a candidate hypothesis nor manual semantic review
    nor machine empirical validation. Conditions remain attached to each route.
    """

    graph = merge_graphs(effective.graph)
    physical = {(r.get("TableName"), r.get("ColumnName")): r for r in schema_rows}
    public_fields = snapshot.fields
    available_nested = {
        key for key, value in effective.field_availability.items()
        if value is FieldAvailability.AVAILABLE and graph.fields[key].locator.json_path
    }
    catalog = reference_catalog(snapshot, schema_rows, states)
    for route, record in zip(snapshot.routes, catalog, strict=True):
        if not record["TenantUsable"]:
            continue
        kind, namespace, normalizer = family_contract(route)
        transform = route_transform(route)
        trusted = record["MappingOrigin"] == "reference"
        endpoints = []
        for endpoint in (route.source, route.target):
            locator = endpoint.locator
            identifier = field_id(locator)
            if identifier not in graph.fields:
                physical_type = physical[(endpoint.table, endpoint.column)].get("ColumnType")
                documented_type = public_fields.get(
                    (endpoint.table, endpoint.column), {}
                ).get("Type")
                kql_type = "string" if endpoint.path else (
                    canonical_storage_type(physical_type or documented_type) or "string"
                )
                graph.add(FieldRecord(identifier, locator, kql_type,
                                      extra={"provenance": ["xdrinternals:" + snapshot.digest]}))
            existing = [i for i in graph.interpretations.values()
                        if i.field_id == identifier and i.namespace == namespace
                        and i.normalizer == normalizer and i.entity_kind == kind
                        and i.extra.get("provisional") is not True]
            if existing:
                interp = min(existing, key=lambda i: i.id)
            else:
                interp_id = interpretation_id(locator, namespace, "subject")
                interp = graph.interpretations.get(interp_id)
                if interp is None:
                    interp = InterpretationRecord(
                        interp_id, identifier, kind, namespace, "subject", normalizer,
                        constraints=(
                            ({"sibling": "type", "equals_casefold": "user"},)
                            if route.id == "audit-target-resource-id-account-object-id"
                            and endpoint == route.source else ()
                        ),
                        extra={"reference_trusted": trusted, "reference_digest": snapshot.digest,
                               **({} if trusted else {"provisional": True})},
                    )
                    graph.add(interp)
                elif (interp.entity_kind, interp.normalizer) != (kind, normalizer):
                    # An existing reviewed meaning is not replaced by a downloaded hint.
                    endpoints = []
                    break
            endpoints.append(interp)
        if len(endpoints) != 2 or endpoints[0].id == endpoints[1].id:
            continue
        pair = {i.id for i in endpoints}
        existing_relations = [r for r in graph.relationships.values()
                              if {r.source, r.target} == pair
                              and r.status is RelationshipStatus.REVIEWED
                              and r.transform == transform]
        info = {"id": route.id, "validation": record["ReferenceValidationState"],
                "guidance": route.guidance, "url": REFERENCE_URLS["relations"],
                "digest": snapshot.digest, "validation_run_id": record["ValidationRunId"],
                "counts": record["ValidationCounts"], "scope": record["ValidationScope"],
                "warnings": record["ValidationWarnings"],
                "constraints_applied": record["ValidationConstraints"],
                "origin": record["MappingOrigin"],
                "source": str(route.source.locator), "target": str(route.target.locator)}
        if existing_relations:
            if not trusted:
                continue
            for relation in existing_relations:
                extra = {**relation.extra,
                         "reference_routes": [*relation.extra.get("reference_routes", []), info]}
                graph.relationships[relation.id] = replace(relation, extra=extra)
        else:
            source, target = sorted(i.id for i in endpoints)
            rel_id = relationship_id(source, target, RelationshipKind.CORRELATION_ONLY,
                                     Direction.BOTH, transform)
            prior = graph.relationships.get(rel_id)
            if prior is not None and prior.status is not RelationshipStatus.REFERENCE_TRUSTED:
                continue
            if not trusted and prior is not None:
                continue
            infos = [*(prior.extra.get("reference_routes", []) if prior else []), info]
            observed = (not trusted and record["ReferenceValidationState"] == "matched"
                        and (record["ValidationCounts"] or {}).get("MatchedSourceValues", 0) >= 3
                        and "candidate-identifier-quality:v1" in record["ValidationConstraints"])
            graph.relationships[rel_id] = RelationshipRecord(
                rel_id, source, target, RelationshipKind.CORRELATION_ONLY, Direction.BOTH,
                transform, Cardinality.UNKNOWN, "reference-conditions-apply",
                (RelationshipStatus.REFERENCE_TRUSTED if trusted else
                 RelationshipStatus.OBSERVED if observed else RelationshipStatus.CANDIDATE),
                Confidence.MEDIUM if trusted or observed else Confidence.LOW,
                (("xdrinternals:" if trusted else "tenant-new-table:") + snapshot.digest,),
                extra={"reference_routes" if trusted else "tenant_discoveries": infos},
            )
        state = (states or {}).get(route.id, {})
        if state.get("status") == "matched":
            available_nested.update(
                field_id(e.locator) for e in (route.source, route.target) if e.path
            )
    result = compose_effective_graph(schema_rows, canonical=graph,
                                     observed_nested_fields=available_nested, coverage=coverage)
    return replace(result, observation_gaps=effective.observation_gaps)


def compare_physical_schema(snapshot: ReferenceSnapshot, schema_rows: list[dict]) -> list[dict]:
    """Compare complete table/column sets without treating fuzzy absence as proof."""
    tenant = {}
    for row in queryable_rows(schema_rows):
        tenant.setdefault(row["TableName"], {})[row["ColumnName"]] = canonical_storage_type(
            row.get("ColumnType")
        )
    reference = {name: {c["ColumnName"]: c["ColumnType"] for c in table["Columns"]}
                 for name, table in snapshot.normalized_tables.items()}
    records = []
    for name in sorted(set(tenant) | set(reference)):
        actual, expected = tenant.get(name, {}), reference.get(name, {})
        disagreements = [{"Column": column, "TenantType": actual[column],
                          "ReferenceType": expected[column]}
                         for column in sorted(actual.keys() & expected.keys())
                         if actual[column] and expected[column]
                         and actual[column] != expected[column]]
        records.append({
            "record_type": "schema-table-comparison", "TableName": name,
            "ReferenceKnown": name in reference, "TenantObserved": name in tenant,
            "ReferenceColumns": len(expected), "TenantColumns": len(actual),
            "TenantOnlyColumns": sorted(actual.keys() - expected.keys()),
            "ReferenceOnlyColumns": sorted(expected.keys() - actual.keys()),
            "TypeDisagreements": disagreements, "TypeAuthority": "tenant-getschema",
            "AbsenceIsConclusive": False,
        })
    return records


def tenant_candidate_routes(snapshot, schema_rows, *, cache_meta=None, cache_root=None):
    """Recreate deterministic proposals using only physical schema and verified hints."""
    from xdr_cli.schema_graph.physical import load_portal_sidecar, new_table_candidate_routes

    new_tables = sorted({r["TableName"] for r in schema_rows} - set(snapshot.table_names))
    portal, sidecar_gap = (load_portal_sidecar(cache_meta, cache_root)
                           if cache_meta is not None and cache_root is not None
                           else (None, "not-recorded"))
    proposals = new_table_candidate_routes(
        schema_rows, snapshot, new_tables, portal_tables=portal, max_routes=101,
    )
    selected = tuple(proposals[:100])
    return selected, {
        "new_tables": new_tables,
        "unmapped_new_tables": sorted(set(new_tables) - {r.source.table for r in selected}),
        "candidate_route_cap_reached": len(proposals) > 100,
        "portal_hint_gap": sidecar_gap,
    }


def safe_reference_previews(artifact):
    """Keep third-party prose in the artifact, outside automatic agent previews."""
    def project(value):
        if isinstance(value, list):
            return [project(item) for item in value]
        if isinstance(value, dict):
            hidden = any(key.casefold() in {"title", "guidance"} for key in value)
            result = {key: project(item) for key, item in value.items()
                      if key.casefold() not in {"title", "guidance"}}
            if hidden:
                result["ReferenceText"] = "untrusted-reference-text-in-artifact"
            return result
        return value

    return replace(artifact,
                   preview_records=tuple(project(row) for row in artifact.preview_records))
