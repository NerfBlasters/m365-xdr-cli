"""Tenant/reference/schema-bound validation ledger, with private artifact receipts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from xdr_cli.results import tenant_fingerprint
from xdr_cli.schema_graph.reference import ReferenceError, _atomic_json, _read_document

_SAFE_FILE = re.compile(r"validation\.[a-f0-9]{24}\.json\Z")


def validation_root(home: Path, tenant_id: str) -> Path:
    key = hashlib.sha256((tenant_id or "default").encode()).hexdigest()[:12]
    return home / "schema" / key / "reference-validation"


def validation_key(reference_digest: str, schema_digest: str, options: dict) -> str:
    value = json.dumps(
        [reference_digest, schema_digest, options], sort_keys=True, separators=(",", ":")
    )

    return hashlib.sha256(value.encode()).hexdigest()[:24]


def physical_schema_digest(rows: list[dict]) -> str:
    """Bind validation to physical columns/types, independent of refresh ordering."""
    values = sorted((str(r.get("TableName")), str(r.get("ColumnName")),
                     str(r.get("ColumnType"))) for r in rows)
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def save_validation_state(
    home: Path, tenant_id: str, *, reference_digest: str, schema_digest: str,
    options: dict, routes: dict[str, dict],
) -> dict:
    root = validation_root(home, tenant_id)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    value = {"schema_version": 1, "tenant_fingerprint": tenant_fingerprint(tenant_id),
             "reference_digest": reference_digest, "schema_digest": schema_digest,
             "options": options, "routes": routes}
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:24]
    filename = f"validation.{digest}.json"
    _atomic_json(root / filename, value)
    raw = (root / filename).read_bytes()
    _atomic_json(root / "current.json", {"file": filename,
                                         "sha256": hashlib.sha256(raw).hexdigest()})
    _atomic_json(root / f"scope.{validation_key(reference_digest, schema_digest, options)}.json",
                 {"file": filename, "sha256": hashlib.sha256(raw).hexdigest()})
    return value


def load_validation_state(
    home: Path, tenant_id: str, *, reference_digest: str, schema_digest: str,
    options: dict | None = None,
) -> dict | None:
    root = validation_root(home, tenant_id)
    current = root / "current.json"
    if options is not None:
        scoped = root / f"scope.{validation_key(reference_digest, schema_digest, options)}.json"
        if scoped.exists():
            current = scoped
    if not current.exists():
        return None
    try:
        manifest = json.loads(_read_document(current))
        filename = manifest["file"]
        if not isinstance(filename, str) or not _SAFE_FILE.fullmatch(filename):
            raise ReferenceError("reference validation manifest has an unsafe path")
        raw = _read_document(root / filename)
        if hashlib.sha256(raw).hexdigest() != manifest.get("sha256"):
            raise ReferenceError("reference validation ledger digest mismatch")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ReferenceError("reference validation ledger must be an object")
        if value.get("schema_version") != 1:
            raise ReferenceError("unsupported reference validation ledger")
        if value.get("tenant_fingerprint") != tenant_fingerprint(tenant_id):
            raise ReferenceError("reference validation ledger tenant mismatch")
        if (value.get("reference_digest"), value.get("schema_digest")) != (
            reference_digest, schema_digest,
        ):
            return None
        if options is not None and value.get("options") != options:
            return None
        if not isinstance(value.get("routes"), dict):
            raise ReferenceError("reference validation records must be an object")
        if any(not isinstance(key, str) or not isinstance(record, dict)
               for key, record in value["routes"].items()):
            raise ReferenceError("reference validation route records must be objects")
        return value
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ReferenceError):
            raise
        raise ReferenceError("reference validation ledger is unreadable") from exc


def verify_validation_record(home: Path, tenant_id: str, route_id: str, record: dict) -> bool:
    """Positive/negative execution claims must reopen the exact saved result."""

    if not isinstance(record, dict):
        return False
    run_id = record.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        return False
    paths = list((home / "results").glob(f"*/{run_id}.meta.json"))
    if len(paths) != 1:
        return False
    try:
        metadata = json.loads(_read_document(paths[0]))
        if not isinstance(metadata, dict):
            return False
        stage = metadata.get("reference_validation", {})
        if not isinstance(stage, dict) or not isinstance(metadata.get("tenant_binding"), dict):
            return False
        if (metadata.get("run_id") != run_id
                or metadata.get("command") != "schema init validation"
                or metadata.get("tenant_binding", {}).get("sha256") != tenant_fingerprint(tenant_id)
                or stage.get("reference_id") != route_id
                or any(stage.get(key) != record.get(key) for key in (
                    "reference_digest", "schema_digest", "options", "constraints_applied",
                    "validation_scope", "time_policy", "warnings",
                ))
                or metadata.get("query_sha256") != record.get("query_sha256")
                or not isinstance(metadata.get("query"), str)
                or hashlib.sha256(metadata["query"].encode()).hexdigest()
                != record.get("query_sha256")):
            return False
        data = paths[0].with_name(f"{run_id}.jsonl")
        raw = _read_document(data)
        if hashlib.sha256(raw).hexdigest() != metadata.get("data_sha256"):
            return False
        rows = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
        if rows != [record.get("counts")] or metadata.get("row_count") != 1:
            return False
        if record.get("status") == "query-failed":
            return rows == [{"RouteId": route_id, "ErrorCode": record.get("error_code")}]
        from xdr_cli.schema_graph.reference_validation import classify_counts

        return classify_counts(rows[0], route_id) == record.get("status")
    except (OSError, KeyError, TypeError, ValueError):
        return False


def reference_status(home: Path, tenant_id: str, schema_rows: list[dict]) -> dict:
    """Value-free local health, including missing result evidence and setup progress."""
    from collections import Counter

    from xdr_cli.schema_graph.reference import load_snapshot

    try:
        snapshot = load_snapshot(home)
        if snapshot is None:
            return {"state": "missing", "next_command": "xdr schema init"}
        ledger = load_validation_state(
            home, tenant_id, reference_digest=snapshot.digest,
            schema_digest=physical_schema_digest(schema_rows),
        )
        records = (ledger or {}).get("routes", {})
        states = Counter(records.get(route.id, {}).get("status", "pending")
                         for route in snapshot.routes)
        invalid = sum(not verify_validation_record(home, tenant_id, key, record)
                      for key, record in records.items() if record.get("run_id"))
        pending = states["pending"] + states["planned"]
        failed = states["query-failed"] + states["invalid-shape"]
        return {"state": "needs-validation" if pending or invalid or failed else "initialized",
                "reference_digest": snapshot.digest, "reference_routes": len(snapshot.routes),
                "validation_states": dict(states), "invalid_evidence_records": invalid,
                "next_command": "xdr schema init --skip-refresh" if pending or invalid or failed
                else "xdr schema pivot DeviceInfo.DeviceId"}
    except (ReferenceError, OSError) as exc:
        return {"state": "invalid", "reason": str(exc),
                "next_command": "xdr schema init --sync-reference --revalidate"}
