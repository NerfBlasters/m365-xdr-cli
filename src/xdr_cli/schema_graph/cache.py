"""Content-bound physical schema cache validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_GENERATION = re.compile(r"[A-Za-z0-9_-]{1,128}")


def _read_legacy_pair(
    root: Path, *, expected_tenant_key: str
) -> tuple[Path, Path, str, bytes, list[dict[str, Any]], dict[str, Any]]:
    """Validate every non-digest legacy cache invariant before local binding."""

    paths = active_schema_cache_paths(root)
    if paths is None:
        raise ValueError("schema cache manifest is missing")
    data_path, meta_path, generation = paths
    if data_path.parent.resolve() != root.resolve() or meta_path.parent.resolve() != root.resolve():
        raise ValueError("schema cache generation path escapes its tenant directory")
    raw = data_path.read_bytes()
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("schema cache metadata must be a JSON object")
    if metadata.get("generation") != generation:
        raise ValueError("schema cache metadata does not match its generation")
    if root.name != expected_tenant_key or metadata.get("tenant_key") != expected_tenant_key:
        raise ValueError("schema cache tenant binding does not match its directory")
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("schema cache rows must be JSON objects")
    if metadata.get("row_count") != len(rows):
        raise ValueError("schema cache row count does not match metadata")
    return data_path, meta_path, generation, raw, rows, metadata


def schema_cache_status(root: Path, *, expected_tenant_key: str) -> dict[str, Any]:
    """Classify the active physical cache without changing local state."""

    try:
        paths = active_schema_cache_paths(root)
        if paths is None:
            return {"state": "missing", "generation": None, "migration_command": None}
        data_path, meta_path, generation = paths
        try:
            _rows, metadata = load_schema_cache_pair(
                data_path, meta_path, expected_generation=generation
            )
            if (
                root.name != expected_tenant_key
                or metadata.get("tenant_key") != expected_tenant_key
            ):
                raise ValueError("schema cache tenant binding does not match its directory")
            return {
                "state": "verified",
                "generation": generation,
                "metadata": metadata,
                "migration_command": None,
            }
        except ValueError as strict_error:
            _data, _meta, _generation, _raw, _rows, metadata = _read_legacy_pair(
                root, expected_tenant_key=expected_tenant_key
            )
            if "data_sha256" in metadata or "data_bytes" in metadata:
                raise strict_error
            return {
                "state": "legacy-unbound",
                "generation": generation,
                "metadata": metadata,
                "migration_command": "xdr schema migrate-cache --yes",
            }
    except (OSError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "state": "invalid",
            "generation": None,
            "error": str(exc),
            "migration_command": None,
        }


def migrate_legacy_schema_cache(
    root: Path, *, expected_tenant_key: str
) -> dict[str, Any]:
    """Content-bind a valid pre-digest cache while preserving its old metadata."""

    data_path, meta_path, generation, raw, rows, metadata = _read_legacy_pair(
        root, expected_tenant_key=expected_tenant_key
    )
    if "data_sha256" in metadata or "data_bytes" in metadata:
        # A partially present or mismatching binding is corruption, not legacy.
        load_schema_cache_pair(data_path, meta_path, expected_generation=generation)
        return {
            "state": "already-verified",
            "generation": generation,
            "row_count": len(rows),
            "quarantine_path": None,
        }
    quarantine = root / "quarantine" / (
        "cache-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(4)
    )
    quarantine.mkdir(parents=True, mode=0o700)
    old_meta = quarantine / meta_path.name
    shutil.copy2(meta_path, old_meta)
    if os.name == "posix":
        old_meta.chmod(0o600)
    migrated = dict(metadata)
    migrated.update(
        {
            "data_sha256": hashlib.sha256(raw).hexdigest(),
            "data_bytes": len(raw),
            "binding_origin": "local-legacy-migration",
            "bound_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    temporary = root / f".{generation}.migrate.meta.{secrets.token_hex(4)}.tmp"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(migrated, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o600)
        os.replace(temporary, meta_path)
    finally:
        temporary.unlink(missing_ok=True)
    load_schema_cache_pair(data_path, meta_path, expected_generation=generation)
    return {
        "state": "migrated",
        "generation": generation,
        "row_count": len(rows),
        "data_bytes": len(raw),
        "quarantine_path": str(quarantine.resolve()),
    }


def active_schema_cache_paths(root: Path) -> tuple[Path, Path, str] | None:
    """Resolve the active immutable cache pair without trusting its contents."""

    manifest = root / "current.json"
    if not manifest.is_file():
        return None
    value = json.loads(manifest.read_text(encoding="utf-8"))
    generation = value["generation"]
    if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
        raise ValueError("schema cache manifest has an invalid generation")
    return (
        root / f"schema.{generation}.jsonl",
        root / f"schema.{generation}.meta.json",
        generation,
    )


def load_schema_cache_pair(
    data_path: Path,
    meta_path: Path,
    *,
    expected_generation: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load an exact cache pair after digest, size, identity, and count checks."""

    raw = data_path.read_bytes()
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("schema cache metadata must be a JSON object")
    if expected_generation is not None and metadata.get("generation") != expected_generation:
        raise ValueError("schema cache metadata does not match its generation")
    expected_digest = metadata.get("data_sha256")
    expected_bytes = metadata.get("data_bytes")
    if (
        not isinstance(expected_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
        or not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or expected_bytes != len(raw)
        or hashlib.sha256(raw).hexdigest() != expected_digest
    ):
        raise ValueError("schema cache content digest or byte count does not match")
    rows = [
        json.loads(line)
        for line in raw.decode("utf-8").splitlines()
        if line.strip()
    ]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("schema cache rows must be JSON objects")
    if metadata.get("row_count") != len(rows):
        raise ValueError("schema cache row count does not match metadata")
    return rows, metadata
