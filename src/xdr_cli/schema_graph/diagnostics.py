"""Build identity and stable schema capability registration."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from xdr_cli import __version__

SCHEMA_CAPABILITIES = (
    {"id": "maintenance-status-v1", "command": "schema status"},
    {"id": "build-diagnostics-v1", "command": "schema diagnostics"},
    {"id": "overlay-compatibility-v1", "command": "schema repair-overlay"},
    {"id": "physical-cache-migration-v1", "command": "schema migrate-cache"},
    {"id": "bounded-collection-v1", "command": "schema collect"},
    {"id": "resumable-table-crawl-v1", "command": "schema collect --resume"},
    {"id": "empirical-pivot-lifecycle-v1", "command": "schema discoveries"},
    {"id": "portable-bundle-inspect-v1", "command": "schema bundle inspect"},
    {"id": "portable-bundle-export-v1", "command": "schema bundle export"},
    {"id": "portable-bundle-import-v1", "command": "schema bundle import"},
)


def source_commit() -> str | None:
    supplied = os.environ.get("XDR_CLI_SOURCE_COMMIT")
    if supplied:
        return supplied
    repository = Path(__file__).resolve().parents[3]
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = completed.stdout.strip()
    return commit if len(commit) == 40 else None


def build_diagnostics(maintenance: dict[str, Any]) -> dict[str, Any]:
    """Return cache-only build and schema automation diagnostics."""

    return {
        "package_version": __version__,
        "source_commit": source_commit(),
        "schema_capabilities": list(SCHEMA_CAPABILITIES),
        "maintenance": maintenance,
    }
