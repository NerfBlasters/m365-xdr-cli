"""Deterministic Markdown rendering for the reviewed semantic graph."""

from __future__ import annotations

from xdr_cli.schema_graph.model import Graph, RelationshipKind

BEGIN_MARKER = "<!-- BEGIN GENERATED SEMANTIC GRAPH -->"
END_MARKER = "<!-- END GENERATED SEMANTIC GRAPH -->"


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_semantic_reference(graph: Graph) -> str:
    """Render the exact reviewed/candidate route inventory from graph records."""

    lines = [
        BEGIN_MARKER,
        "## Generated semantic route inventory",
        "",
        "This table is generated from the packaged graph. Tenant availability is",
        "reported at runtime by `xdr schema pivot` and `xdr schema path`.",
        "",
        "| Source | Target | Relationship | Workflow | Cardinality | Confidence | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for relationship in sorted(graph.relationships.values(), key=lambda item: item.id):
        source = graph.interpretations[relationship.source]
        target = graph.interpretations[relationship.target]
        source_locator = graph.fields[source.field_id].locator
        target_locator = graph.fields[target.field_id].locator
        workflow = (
            "direct join"
            if relationship.relationship is RelationshipKind.JOIN_COMPATIBLE
            else "query → extract → query"
        )
        lines.append(
            "| "
            + " | ".join(
                _cell(item)
                for item in (
                    source_locator,
                    target_locator,
                    relationship.relationship.value,
                    workflow,
                    relationship.cardinality.value,
                    relationship.confidence.value,
                    relationship.status.value,
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "Do not infer a route from the physical same-name appendix below. Use the",
            "generated inventory or the runtime commands, which also return transforms,",
            "roles, namespaces, provenance, temporal guidance, and tenant availability.",
            END_MARKER,
        ]
    )
    return "\n".join(lines)
