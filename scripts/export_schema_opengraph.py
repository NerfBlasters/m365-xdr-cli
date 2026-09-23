#!/usr/bin/env python3
"""Export the packaged public semantic schema as generic OpenGraph JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.opengraph import export_opengraph


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="Write to a file instead of stdout.")
    parser.add_argument("--include-candidates", action="store_true")
    args = parser.parse_args()
    payload = json.dumps(
        export_opengraph(load_packaged_graph(), include_candidates=args.include_candidates),
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
