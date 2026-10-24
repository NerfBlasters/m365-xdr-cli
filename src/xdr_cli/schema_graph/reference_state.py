"""Tenant/reference/schema-bound validation ledger, with private artifact receipts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from xdr_cli.exceptions import ArtifactError
from xdr_cli.results import tenant_fingerprint
from xdr_cli.schema_graph.overlay import schema_evidence_lock
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


def _save_validation_state_unlocked(
    home: Path, tenant_id: str, *, reference_digest: str, schema_digest: str,
    options: dict, routes: dict[str, dict],
) -> dict:
    root = validation_root(home, tenant_id)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    value = {"schema_version": 1, "tenant_fingerprint": tenant_fingerprint(tenant_id),
             "reference_digest": reference_digest, "schema_digest": schema_digest,
             "options": options, "routes": routes}
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(encoded).hexdigest()[:24]
    filename = f"validation.{digest}.json"
    _atomic_json(root / filename, value)
    raw = (root / filename).read_bytes()
    _atomic_json(root / "current.json", {"file": filename,
                                         "sha256": hashlib.sha256(raw).hexdigest()})
    _atomic_json(root / f"scope.{validation_key(reference_digest, schema_digest, options)}.json",
                 {"file": filename, "sha256": hashlib.sha256(raw).hexdigest()})
    _collect_obsolete_ledgers(root)
    return value


def _collect_obsolete_ledgers(root: Path) -> None:
    """Bound cleanup; live pointer targets always remain retention authorities."""
    keep = set()
    try:
        for pointer in [root / "current.json", *root.glob("scope.*.json")]:
            name = json.loads(_read_document(pointer))["file"]
            if not isinstance(name, str) or not _SAFE_FILE.fullmatch(name):
                return
            keep.add(name)
    except (OSError, ValueError, TypeError, KeyError):
        return
    retired = 0
    for path in root.glob("validation.*.json"):
        if retired >= 64:
            break
        if _SAFE_FILE.fullmatch(path.name) and path.name not in keep and not path.is_symlink():
            try:
                path.unlink()
                retired += 1
            except OSError:
                continue


def save_validation_state(
    home: Path, tenant_id: str, *, reference_digest: str, schema_digest: str,
    options: dict, routes: dict[str, dict],
) -> dict:
    try:
        with schema_evidence_lock(help_command="xdr schema init --skip-refresh"):
            return _save_validation_state_unlocked(
                home, tenant_id, reference_digest=reference_digest, schema_digest=schema_digest,
                options=options, routes=routes,
            )
    except OSError as exc:
        raise ArtifactError(
            "Could not publish local reference validation state",
            help_command="xdr schema init --skip-refresh",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc


def publish_validation_record(home, tenant_id, *, route_id, record, counts, query, routes):
    """Publish a private aggregate and its live ledger reference under the prune lock."""
    from datetime import UTC, datetime

    from xdr_cli.results import write_result

    try:
        with schema_evidence_lock(help_command="xdr schema init --skip-refresh"):
            artifact = write_result(
                [counts], command="schema init validation", tenant_id=tenant_id,
                query=query, preview_rows=0, server_truncation_state="known-complete",
                extra_metadata={"reference_validation": {"reference_id": route_id, **record}},
            )
            routes[route_id] = {**record, "counts": counts, "run_id": artifact.receipt.run_id,
                                "validated_at": datetime.now(UTC).isoformat()}
            _save_validation_state_unlocked(
                home, tenant_id, reference_digest=record["reference_digest"],
                schema_digest=record["schema_digest"], options=record["options"], routes=routes,
            )
    except OSError as exc:
        raise ArtifactError("Could not publish local reference validation evidence",
                            original={"type": type(exc).__name__, "message": str(exc)}) from exc


def load_validation_state(
    home: Path, tenant_id: str, *, reference_digest: str, schema_digest: str,
    options: dict | None = None,
    allow_schema_mismatch: bool = False,
    _read_retries: int = 2,
) -> dict | None:
    root = validation_root(home, tenant_id)
    current = root / "current.json"
    if options is not None:
        scoped = root / f"scope.{validation_key(reference_digest, schema_digest, options)}.json"
        if scoped.exists():
            current = scoped
    if not current.exists():
        return None
    pointer_bytes = None
    try:
        pointer_bytes = _read_document(current)
        manifest = json.loads(pointer_bytes)
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
        if value.get("reference_digest") != reference_digest:
            return None
        if value.get("schema_digest") != schema_digest and not allow_schema_mismatch:
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
        if isinstance(exc, FileNotFoundError) and pointer_bytes is not None and _read_retries:
            try:
                changed = _read_document(current) != pointer_bytes
            except OSError:
                changed = False
            if changed:
                return load_validation_state(
                    home, tenant_id, reference_digest=reference_digest,
                    schema_digest=schema_digest, options=options,
                    allow_schema_mismatch=allow_schema_mismatch, _read_retries=_read_retries - 1,
                )
        raise ReferenceError("reference validation ledger is unreadable") from exc


def verify_validation_record(
    home: Path, tenant_id: str, route_id: str, record: dict, *,
    expected_tenant_fingerprint: str | None = None,
) -> bool:
    """Positive/negative execution claims must reopen the exact saved result."""

    if not isinstance(record, dict):
        return False
    fingerprint = expected_tenant_fingerprint or tenant_fingerprint(tenant_id)
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
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
                or metadata.get("tenant_binding", {}).get("sha256") != fingerprint
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
        if any(not path.is_file() or path.is_symlink() for path in (paths[0], data)):
            return False
        root = (home / "results").resolve()
        if any(not path.resolve().is_relative_to(root) for path in (paths[0], data)):
            return False
        if (metadata.get("meta_path") != str(paths[0].resolve())
                or metadata.get("data_path") != str(data.resolve())):
            return False
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


def reference_status(
    home: Path, tenant_id: str, schema_rows: list[dict], *, cache_metadata=None,
) -> dict:
    """Value-free local health, including missing result evidence and setup progress."""
    from collections import Counter
    from dataclasses import replace

    from xdr_cli.schema_graph.reference import load_snapshot
    from xdr_cli.schema_graph.reference_routes import tenant_candidate_routes

    try:
        snapshot = load_snapshot(home)
        if snapshot is None:
            return {"state": "missing", "next_command": "xdr schema init"}
        ledger = load_validation_state(
            home, tenant_id, reference_digest=snapshot.digest,
            schema_digest=physical_schema_digest(schema_rows),
            allow_schema_mismatch=True,
        )
        candidates, _gaps = tenant_candidate_routes(
            snapshot, schema_rows, cache_meta=cache_metadata,
            cache_root=validation_root(home, tenant_id).parent,
        )
        records = prepare_validation_records(
            home, tenant_id, replace(snapshot, routes=(*snapshot.routes, *candidates)),
            schema_rows, ledger,
        )
        states = Counter(records.get(route.id, {}).get("status", "pending")
                         for route in snapshot.routes)
        discovery_states = Counter(records[route.id]["status"] for route in candidates)
        all_states = states + discovery_states
        invalid = all_states["evidence-unavailable"]
        pending = all_states["pending"] + all_states["planned"]
        failed = all_states["query-failed"] + all_states["invalid-shape"]
        return {"state": "needs-validation" if pending or invalid or failed else "initialized",
                "reference_digest": snapshot.digest, "reference_routes": len(snapshot.routes),
                "validation_states": dict(states), "invalid_evidence_records": invalid,
                "discovery_validation_states": dict(discovery_states),
                "next_command": "xdr schema init --skip-refresh" if pending or invalid or failed
                else "xdr schema pivot DeviceInfo.DeviceId"}
    except (ReferenceError, OSError) as exc:
        return {"state": "invalid", "reason": str(exc),
                "next_command": "xdr schema init --sync-reference --revalidate"}


def prepare_validation_records(home, tenant_id, snapshot, schema_rows, ledger=None):
    """Bind execution claims to the CURRENT local compiler and complete tenant contract.

    This function performs no network I/O. Trusted but unvalidated mappings retain
    their current conditions; incompatible saved matches become pending again.
    """
    from xdr_cli.schema_graph import reference_query

    options = (ledger or {}).get("options", {"lookback": "7d", "samples": 50, "row_limit": 1000})
    if not isinstance(options, dict) or set(options) != {"lookback", "samples", "row_limit"}:
        raise ReferenceError("Reference validation parameters are invalid; reinitialize the tenant")
    schema_digest = physical_schema_digest(schema_rows)
    saved = (ledger or {}).get("routes", {})
    records = {}
    claims = {"matched", "no-source-data", "no-target-data", "no-overlap", "query-failed"}
    for route in snapshot.routes:
        try:
            plan = reference_query.compile_reference_query(route, schema_rows, **options)
        except reference_query.ReferenceQueryUnsupported as exc:
            physical_missing = exc.reason in {
                "source-table-unavailable", "target-table-unavailable",
                "source-column-unavailable", "target-column-unavailable",
            }
            records[route.id] = {
                "status": "schema-unavailable" if physical_missing else "unsupported",
                "reason": exc.reason, "detail": exc.detail,
            }
            continue
        except (TypeError, ValueError) as exc:
            raise ReferenceError("Reference validation parameters are incompatible") from exc
        current = {
            "reference_digest": snapshot.digest, "schema_digest": schema_digest,
            "options": options, "query_sha256": hashlib.sha256(plan.query.encode()).hexdigest(),
            "constraints_applied": list(plan.constraints_applied), "time_policy": plan.time_policy,
            "validation_scope": plan.scope, "warnings": list(plan.warnings),
        }
        if any(value.startswith("condition-unverifiable:") for value in plan.constraints_applied):
            records[route.id] = {**current, "status": "unsupported",
                                 "reason": "reference-context-required"}
            continue
        prior = saved.get(route.id, {})
        if not isinstance(prior, dict):
            raise ReferenceError("Reference validation route record must be an object")
        compatible = validation_contract_matches(prior, current, allow_old_failure_schema=True)
        if prior.get("status") in claims or prior.get("run_id"):
            if not compatible:
                records[route.id] = {**current, "status": "pending", "reason": "contract-changed",
                                     "warnings": [*current["warnings"],
                                                  "Validation contract changed; rerun schema init"]}
            elif not verify_validation_record(home, tenant_id, route.id, prior):
                records[route.id] = {**current, "status": "evidence-unavailable", "warnings": [
                    *current["warnings"], "Saved validation evidence is invalid; rerun schema init",
                ]}
            else:
                records[route.id] = dict(prior)
        elif prior.get("status") == "invalid-shape" and compatible:
            records[route.id] = {**current, "status": "invalid-shape",
                                 "reason": prior.get("reason")}
        else:
            records[route.id] = {**current, "status": "pending"}
    return records


def validation_contract_matches(prior, current, *, allow_old_failure_schema=False):
    comparable = ("reference_digest", "options", "query_sha256",
                  "constraints_applied", "time_policy", "validation_scope")
    if not allow_old_failure_schema or prior.get("status") != "query-failed":
        comparable = (*comparable, "schema_digest")
    return (all(prior.get(key) == current[key] for key in comparable)
            and isinstance(prior.get("warnings"), list)
            and all(warning in prior["warnings"] for warning in current["warnings"]))
