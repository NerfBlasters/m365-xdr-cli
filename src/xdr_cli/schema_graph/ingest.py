"""Fail-soft passive ingestion of safely attributed result shapes."""

from __future__ import annotations

import re
from typing import Any

from xdr_cli.kql_parse import extract_tables
from xdr_cli.schema_graph.artifact_metadata import nested_fields_from_artifact_metadata
from xdr_cli.schema_graph.catalog import graph_from_artifact_shapes
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.overlay import publish_tenant_overlay

_UNSAFE_LINEAGE_OPERATOR = re.compile(
    r"(?im)(?:^|\|)\s*(?:"
    r"extend|project(?:-[A-Za-z][A-Za-z-]*)?(?:\s|$)|summarize|distinct|"
    r"parse(?:-[A-Za-z][A-Za-z-]*)?|evaluate|invoke|"
    r"make-series|mv-apply|mv-expand|join|lookup|union"
    r")\b"
)
_UNSAFE_SOURCE = re.compile(r"\b(?:externaldata|datatable|union|join|lookup)\b", re.I)


def infer_direct_table_lineage(kql: str) -> str | None:
    """Recognize only simple row-preserving, single-table query shapes.

    This intentionally rejects projections, aliases, joins, calculated fields,
    and other operators that could make a result column look physical when it
    is not. False negatives merely skip passive learning.
    """

    if (
        not isinstance(kql, str)
        or _UNSAFE_SOURCE.search(kql)
        or _UNSAFE_LINEAGE_OPERATOR.search(kql)
    ):
        return None
    tables = extract_tables(kql)
    if len(tables) != 1:
        return None
    code_lines = [
        line.strip()
        for line in kql.splitlines()
        if line.strip() and not line.lstrip().startswith("--")
    ]
    if not code_lines or not re.match(rf"^{re.escape(tables[0])}(?:\s|\||$)", code_lines[0]):
        return None
    return tables[0]


def ingest_artifact_shape(
    tenant_id: str,
    table: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Publish string-valued nested locators; never retain artifact values."""

    shapes = nested_fields_from_artifact_metadata(table, metadata)
    graph = graph_from_artifact_shapes(
        shapes,
        provenance="artifact-shape",
        known=load_packaged_graph(),
    )
    if not graph.fields:
        return {"status": "no-eligible-paths", "field_count": 0}
    published = publish_tenant_overlay(tenant_id, graph=graph)
    return {
        "status": "published",
        "field_count": len(graph.fields),
        "semantic_generation": published["generation"],
    }
