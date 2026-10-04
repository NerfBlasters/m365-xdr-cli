"""Fail-soft, value-free schema maintenance status and advisory state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xdr_cli.config import get_config_home
from xdr_cli.schema_graph.cache import schema_cache_status


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or UTC).astimezone(UTC)


def _tenant_root(tenant_id: str) -> Path:
    tenant_key = hashlib.sha256(tenant_id.encode()).hexdigest()[:12]
    return get_config_home() / "schema" / tenant_key


def _passive_ingestion_status() -> dict[str, Any]:
    outcomes: dict[str, int] = {}
    invalid_sidecars = 0
    results_root = get_config_home() / "results"
    if results_root.is_dir():
        for path in results_root.glob("*/*.meta.json"):
            try:
                metadata = json.loads(path.read_text(encoding="utf-8"))
                ingestion = metadata.get("schema_catalog_ingestion")
                if not isinstance(ingestion, dict):
                    continue
                outcome = ingestion.get("status")
                if isinstance(outcome, str):
                    outcomes[outcome] = outcomes.get(outcome, 0) + 1
            except (OSError, TypeError, UnicodeError, json.JSONDecodeError):
                invalid_sidecars += 1
    return {
        "attempts": sum(outcomes.values()),
        "outcomes": dict(sorted(outcomes.items())),
        "invalid_sidecars_skipped": invalid_sidecars,
    }


def _semantic_evidence_status(
    tenant_id: str, current: datetime
) -> dict[str, int | str]:
    from xdr_cli.schema_graph.overlay import load_tenant_overlay_from_root

    try:
        observations = load_tenant_overlay_from_root(_tenant_root(tenant_id)).observations
    except Exception:
        return {
            "total": 0,
            "readiness_eligible": 0,
            "legacy_or_stale": 0,
            "eligibility_scope": "timestamp-horizon-only",
        }
    cutoff = current.timestamp() - (90 * 86400)
    eligible = 0
    for item in observations:
        observed = _parse_time(item.observed_at)
        if observed is not None and observed.timestamp() >= cutoff:
            eligible += 1
    return {
        "total": len(observations),
        "readiness_eligible": eligible,
        "legacy_or_stale": len(observations) - eligible,
        "eligibility_scope": "timestamp-horizon-only",
    }


def _schema_cache_state(root: Path) -> dict[str, Any]:
    """Return the cache-only physical generation classification."""

    return schema_cache_status(root, expected_tenant_key=root.name)


def _current_generation_time(root: Path, manifest_name: str, prefix: str) -> datetime | None:
    """Read only the small current manifest/metadata pair for advisory use."""

    try:
        manifest = json.loads((root / manifest_name).read_text(encoding="utf-8"))
        generation = manifest["generation"]
        if not isinstance(generation, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,128}", generation
        ):
            return None
        metadata = json.loads(
            (root / f"{prefix}.{generation}.meta.json").read_text(encoding="utf-8")
        )
        if metadata.get("generation") != generation:
            return None
        return _parse_time(metadata.get("refreshed_at"))
    except (KeyError, OSError, TypeError, json.JSONDecodeError):
        return None


def maintenance_advisory_status(
    tenant_id: str,
    *,
    cache_stale_seconds: int,
    collection_stale_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return fixed-cost maintenance guidance for the global stderr hook.

    This deliberately avoids hashing schema generations, composing overlays,
    or scanning historical result sidecars. Explicit ``xdr schema status`` and
    ``diagnostics`` perform those complete checks.
    """

    if not tenant_id:
        return {"due": False, "reasons": [], "next_command": "xdr auth login"}
    current = (now or datetime.now(UTC)).astimezone(UTC)
    root = _tenant_root(tenant_id)
    reasons: list[str] = []
    cache_time = _current_generation_time(root, "current.json", "schema")
    if cache_time is None:
        reasons.append("physical-cache-missing-or-invalid")
    elif (current - cache_time).total_seconds() > cache_stale_seconds:
        reasons.append("physical-cache-stale")

    collection_path = root / "maintenance.json"
    try:
        collection = json.loads(collection_path.read_text(encoding="utf-8"))
        collected = _parse_time(collection.get("completed_at"))
    except (OSError, TypeError, json.JSONDecodeError):
        collected = None
    if collected is None:
        reasons.append("semantic-collection-never-run-or-invalid")
    elif (current - collected).total_seconds() > collection_stale_seconds:
        reasons.append("semantic-collection-stale")

    semantic_manifest = root / "semantic.current.json"
    if semantic_manifest.is_file():
        if _current_generation_time(root, semantic_manifest.name, "semantic") is None:
            reasons.append("semantic-overlay-invalid")
    elif root.is_dir() and next(root.glob("semantic.*.jsonl"), None) is not None:
        reasons.append("semantic-overlay-needs-repair")

    return {
        "due": bool(reasons),
        "reasons": reasons,
        "next_command": (
            "xdr schema repair-overlay --yes"
            if any(reason.startswith("semantic-overlay-") for reason in reasons)
            else "xdr schema refresh"
            if any(reason.startswith("physical-cache-") for reason in reasons)
            else "xdr schema collect"
        ),
    }


def maintenance_status(
    tenant_id: str,
    *,
    cache_stale_seconds: int,
    collection_stale_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Inspect complete maintenance state without creating directories or raising.

    This explicit status path includes historical overlay and passive-ingestion
    scans. Ordinary commands use :func:`maintenance_advisory_status` instead.
    """

    current = (now or datetime.now(UTC)).astimezone(UTC)
    if not tenant_id:
        from xdr_cli.schema_graph.overlay import tenant_overlay_status

        overlay = tenant_overlay_status(tenant_id)
        overlay_due = overlay["state"] in {
            "invalid",
            "legacy-unbound",
            "needs-migration",
            "incompatible",
        }
        status = {
            "configured": False,
            "due": overlay_due,
            "reasons": (
                ["semantic-overlay-" + overlay["state"]] if overlay_due else []
            ),
            "next_command": overlay["repair_command"] or "xdr auth login",
        }
        if overlay_due:
            status["semantic_overlay"] = overlay
        return status
    root = _tenant_root(tenant_id)
    cache = _schema_cache_state(root)
    collection_path = root / "maintenance.json"
    try:
        collection = (
            json.loads(collection_path.read_text(encoding="utf-8"))
            if collection_path.is_file()
            else None
        )
    except (OSError, json.JSONDecodeError):
        collection = {"invalid": True}

    reasons: list[str] = []
    cache_metadata = cache.get("metadata", {}) if isinstance(cache, dict) else {}
    cache_time = _parse_time(cache_metadata.get("refreshed_at"))
    if cache is None or cache.get("state") == "missing":
        cache_state = "missing"
        reasons.append("physical-cache-missing")
    elif cache.get("state") == "legacy-unbound":
        cache_state = "legacy-unbound"
        reasons.append("physical-cache-legacy-unbound")
    elif cache.get("state") == "invalid" or cache_time is None:
        cache_state = "invalid"
        reasons.append("physical-cache-invalid")
    else:
        cache_age = max(0, int((current - cache_time).total_seconds()))
        cache_state = "stale" if cache_age > cache_stale_seconds else "fresh"
        if cache_state == "stale":
            reasons.append("physical-cache-stale")

    collected = (
        _parse_time(collection.get("completed_at"))
        if isinstance(collection, dict) and not collection.get("invalid")
        else None
    )
    if collection is None:
        collection_state = "never-run"
        reasons.append("semantic-collection-never-run")
        collection_age = None
    elif collected is None:
        collection_state = "invalid"
        reasons.append("semantic-collection-state-invalid")
        collection_age = None
    else:
        collection_age = max(0, int((current - collected).total_seconds()))
        collection_state = (
            "stale" if collection_age > collection_stale_seconds else "fresh"
        )
        if collection_state == "stale":
            reasons.append("semantic-collection-stale")
    summary = collection.get("summary", {}) if isinstance(collection, dict) else {}
    has_gaps = isinstance(summary, dict) and bool(
        summary.get("quarantined_tables") or summary.get("coverage_gaps")
        or summary.get("remaining_queries")
    )
    if has_gaps:
        reasons.append("semantic-collection-incomplete")
    from xdr_cli.schema_graph.overlay import tenant_overlay_status

    overlay = tenant_overlay_status(tenant_id)
    if overlay["state"] in {
        "invalid",
        "legacy-unbound",
        "needs-migration",
        "incompatible",
    }:
        reasons.append("semantic-overlay-" + overlay["state"])
    return {
        "configured": True,
        "due": bool(reasons),
        "reasons": reasons,
        "physical_cache": {
            "state": cache_state,
            "refreshed_at": cache_time.isoformat().replace("+00:00", "Z")
            if cache_time
            else None,
            "age_seconds": (
                max(0, int((current - cache_time).total_seconds())) if cache_time else None
            ),
        },
        "semantic_collection": {
            "state": collection_state,
            "outcome": (
                "complete-with-gaps" if has_gaps else "complete"
            ) if collected is not None else None,
            "completed_at": collected.isoformat().replace("+00:00", "Z")
            if collected
            else None,
            "age_seconds": collection_age,
        },
        "semantic_overlay": overlay,
        "semantic_evidence": _semantic_evidence_status(tenant_id, current),
        "passive_ingestion": _passive_ingestion_status(),
        "next_command": (
            overlay["repair_command"]
            or (
                "xdr schema migrate-cache --yes"
                if cache_state == "legacy-unbound"
                else "xdr schema refresh"
                if cache_state in {"invalid", "missing", "stale"}
                else "xdr schema collect"
            )
        ),
    }


def mark_collection_complete(tenant_id: str, summary: dict[str, Any]) -> Path:
    """Atomically record a successful full maintenance collection."""

    root = _tenant_root(tenant_id)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix":
        root.chmod(0o700)
    path = root / "maintenance.json"
    temporary = root / f".maintenance.{secrets.token_hex(6)}.tmp"
    payload = {
        "schema_version": 1,
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "summary": summary,
    }
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o600)
        os.replace(temporary, path)
        if os.name == "posix":
            path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return path
