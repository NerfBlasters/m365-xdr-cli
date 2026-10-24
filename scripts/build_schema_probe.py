#!/usr/bin/env python3
"""Render/check src/xdr_cli/queries/sys_schema_probe.kql from the table registry."""

from __future__ import annotations

import argparse
from pathlib import Path

from xdr_cli.hunting_tables import render_schema_probe


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--query",
        type=Path,
        default=Path("src/xdr_cli/queries/sys_schema_probe.kql"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render_schema_probe()
    if args.check:
        if args.query.read_text(encoding="utf-8") != expected:
            print(f"{args.query} is stale; run scripts/build_schema_probe.py")
            return 1
        return 0
    args.query.write_text(expected, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
