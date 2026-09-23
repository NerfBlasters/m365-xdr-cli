#!/usr/bin/env python3
"""Render/check the semantic block in docs/schema_pivots.md."""

from __future__ import annotations

import argparse
from pathlib import Path

from xdr_cli.schema_graph.docs import BEGIN_MARKER, END_MARKER, render_semantic_reference
from xdr_cli.schema_graph.loader import load_packaged_graph


def rendered_document(document: str) -> str:
    block = render_semantic_reference(load_packaged_graph())
    if BEGIN_MARKER not in document or END_MARKER not in document:
        separator = "\n\n" if document.endswith("\n") else "\n"
        return document + separator + block + "\n"
    prefix, remainder = document.split(BEGIN_MARKER, 1)
    _old, suffix = remainder.split(END_MARKER, 1)
    return prefix + block + suffix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--document",
        type=Path,
        default=Path("docs/schema_pivots.md"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    current = args.document.read_text(encoding="utf-8")
    expected = rendered_document(current)
    if args.check:
        if current != expected:
            print(f"{args.document} semantic graph block is stale")
            return 1
        return 0
    args.document.write_text(expected, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
