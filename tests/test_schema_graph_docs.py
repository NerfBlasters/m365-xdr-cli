from __future__ import annotations

from pathlib import Path

from scripts.render_schema_graph_docs import rendered_document


def test_schema_pivot_semantic_reference_is_generated_without_drift():
    path = Path("docs/schema_pivots.md")
    current = path.read_text(encoding="utf-8")
    assert rendered_document(current) == current
