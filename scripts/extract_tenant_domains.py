#!/usr/bin/env python3
"""Extract inline tenant FQDNs from legacy DNS queries into ~/.xdr-cli/lists/TenantDomains.txt.

Run once per developer before the R1 rewrite of ttp_dns_beaconing and
dns_subdomain_diversity replaces the inline strings with `_xdr_TenantDomains`
references.

Idempotent: preserves existing values; emits the merged set in deterministic
sorted order so re-runs produce the same git diff. Prints the proposed diff
to stdout. Use ``--dry-run`` to skip the disk write.

Exit codes:
    0 — success (file written, or already up to date, or dry-run)
    2 — usage error (bad CLI args)
    3 — environment error (xdr_cli not importable; run ``pip install -e .`` first)
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import os
import re
import sys
import tempfile
from pathlib import Path

# Wrap the import so a fresh clone without `pip install -e .` produces a
# useful error instead of a bare ModuleNotFoundError traceback. The script
# is intended to be run from a developer checkout.
try:
    from xdr_cli.config import get_config_home
except ModuleNotFoundError as exc:  # pragma: no cover — environment guard
    sys.stderr.write(
        f"error: {exc}. Run 'pip install -e .' from the repo root first.\n"
    )
    sys.exit(3)

LEGACY_QUERIES = ["ttp_dns_beaconing.kql", "dns_subdomain_diversity.kql"]
QUERIES_DIR = Path(__file__).parent.parent / "src" / "xdr_cli" / "queries"
KNOWN_GOOD_SEED = (
    Path(__file__).parent.parent
    / "src" / "xdr_cli" / "lists_seed" / "KnownGoodParentDomains.txt"
)

# Match string literals inside dynamic([...]) and `!in (...)` blocks.
DYN_BLOCK = re.compile(r"dynamic\(\[(.*?)\]\)", re.DOTALL)
NIN_BLOCK = re.compile(r"!in\s*\(([^)]*)\)", re.DOTALL)
STRING_LITERAL = re.compile(r"['\"]([^'\"]+)['\"]")


def _load_cdn_allowlist() -> set[str]:
    """Return the lower-cased entries from KnownGoodParentDomains.txt seed."""
    if not KNOWN_GOOD_SEED.exists():
        return set()
    result: set[str] = set()
    for line in KNOWN_GOOD_SEED.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            result.add(stripped.lower())
    return result


def _is_cdn_domain(domain: str, cdn_allowlist: set[str]) -> bool:
    """Return True if *domain* is a known CDN entry or a subdomain of one."""
    d = domain.lower()
    if d in cdn_allowlist:
        return True
    # subdomain match: foo.microsoft.com ends with .microsoft.com
    return any(d.endswith("." + entry) for entry in cdn_allowlist)


def extract_domains(text: str) -> set[str]:
    found: set[str] = set()
    for block_re in (DYN_BLOCK, NIN_BLOCK):
        for block in block_re.findall(text):
            for match in STRING_LITERAL.findall(block):
                # Heuristic: a tenant domain has a dot and is not a column name
                # or operator. Skip CIDR strings, table names, KQL keywords.
                if "." in match and not match.startswith(("@", "//")) and "/" not in match:
                    found.add(match.lower())
    return found


def filter_cdn_domains(
    domains: set[str], cdn_allowlist: set[str]
) -> tuple[set[str], list[str]]:
    """Split *domains* into (tenant_domains, skipped_cdn_list).

    Returns the surviving tenant domains and a sorted list of the domains that
    were filtered because they matched (or are subdomains of) an entry in
    *cdn_allowlist*.
    """
    tenant: set[str] = set()
    skipped: list[str] = []
    for d in domains:
        if _is_cdn_domain(d, cdn_allowlist):
            skipped.append(d)
        else:
            tenant.add(d)
    return tenant, sorted(skipped)


def _atomic_write_text(target: Path, content: str) -> None:
    """Atomic same-filesystem write via tempfile + os.replace.

    A Ctrl-C between truncate and write must not corrupt the existing tenant
    list; tempfile + replace ensures the target either contains the old
    content or the new content, never a partial write.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=target.parent, prefix=target.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the proposed merged file to stdout without writing.",
    )
    args = parser.parse_args(argv)

    cdn_allowlist = _load_cdn_allowlist()

    all_domains: set[str] = set()
    for fname in LEGACY_QUERIES:
        path = QUERIES_DIR / fname
        if not path.exists():
            print(f"[skip] {path} not found", file=sys.stderr)
            continue
        all_domains.update(extract_domains(path.read_text()))

    # Filter out public CDN / ad-tech domains that appear in the query
    # allowlist but are NOT tenant-owned.
    all_domains, skipped = filter_cdn_domains(all_domains, cdn_allowlist)
    if skipped:
        preview = skipped[:10]
        remainder = len(skipped) - len(preview)
        summary = ", ".join(preview)
        if remainder > 0:
            summary += f" … and {remainder} more"
        print(
            f"# Skipped {len(skipped)} likely-CDN domains: {summary}",
            file=sys.stderr,
        )

    if not all_domains:
        print("No tenant domains found in legacy queries. Nothing to migrate.")
        return 0

    target = get_config_home() / "lists" / "TenantDomains.txt"

    # Read existing values + headers (if any). Existing values are merged
    # with the extracted set; the merged set is sorted before writing so
    # the output is deterministic across re-runs and machines.
    existing_values: set[str] = set()
    existing_headers: list[str] = []
    if target.exists():
        for line in target.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                existing_headers.append(line)
            elif stripped:
                existing_values.add(stripped.lower())

    merged_values = sorted(all_domains | existing_values)

    # Add the migration provenance headers on first migration only.
    headers = list(existing_headers)
    has_fetched = any(h.startswith("# fetched:") for h in headers)
    if not has_fetched:
        headers.insert(0, "# source: legacy-inline-migration")
        headers.insert(0, f"# fetched: {dt.datetime.now(dt.UTC).isoformat()}")

    out_lines = headers + [""] + merged_values if headers else merged_values
    new_content = "\n".join(out_lines) + "\n"

    new_only = sorted(set(merged_values) - existing_values)

    if args.dry_run:
        print("# --- DRY RUN: would write to", target, "---")
        sys.stdout.write(new_content)
        if new_only:
            print(f"# +{len(new_only)} new value(s) merged:", file=sys.stderr)
            for d in new_only:
                print(f"#   + {d}", file=sys.stderr)
        else:
            print(f"# all {len(all_domains)} extracted values already present.", file=sys.stderr)
        return 0

    if target.exists() and target.read_text(encoding="utf-8") == new_content:
        print(f"All {len(all_domains)} extracted domains already present. No changes.")
        return 0

    _atomic_write_text(target, new_content)
    print(f"Wrote {len(merged_values)} merged values to {target}")
    if new_only:
        print(f"  +{len(new_only)} new:")
        for d in new_only:
            print(f"    + {d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
