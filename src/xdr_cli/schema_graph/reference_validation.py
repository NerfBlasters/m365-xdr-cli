"""Bounded reference validation, resumable through tenant-bound private artifacts."""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path

from xdr_cli.api.hunting import run_query
from xdr_cli.exceptions import NetworkError, QueryError, RateLimitError, XDRError
from xdr_cli.exceptions import TimeoutError as XDRTimeoutError
from xdr_cli.schema_graph.reference import ReferenceError, ReferenceSnapshot
from xdr_cli.schema_graph.reference_query import ReferenceQueryUnsupported, compile_reference_query
from xdr_cli.schema_graph.reference_state import (
    load_validation_state,
    physical_schema_digest,
    publish_validation_record,
    save_validation_state,
    validation_contract_matches,
    verify_validation_record,
)

_COUNT_KEYS = ("SourceValues", "TargetValues", "MatchedSourceValues", "MatchRows")


def classify_counts(row: dict, route_id: str) -> str:
    if (row.get("RouteId") != route_id or any(
        type(row.get(k)) is not int or row[k] < 0 for k in _COUNT_KEYS
    )):
        raise ValueError("validation response is not the expected count-only row")
    if row["MatchedSourceValues"] > row["SourceValues"]:
        raise ValueError("matched keys exceed sampled source keys")
    if row["MatchRows"] < row["MatchedSourceValues"]:
        raise ValueError("match rows are inconsistent with matched keys")
    if row["MatchedSourceValues"]:
        return "matched"
    if not row["SourceValues"]:
        return "no-source-data"
    if not row["TargetValues"]:
        return "no-target-data"
    return "no-overlap"


def _fresh(record: dict) -> bool:
    try:
        age = (datetime.now(UTC) - datetime.fromisoformat(record["validated_at"])).total_seconds()
        return 0 <= age < 86400
    except (KeyError, TypeError, ValueError):
        return False


async def validate_reference(
    client, snapshot: ReferenceSnapshot, schema_rows: list[dict], *, home: Path,
    tenant_id: str, lookback: str = "7d", samples: int = 50, row_limit: int = 1000,
    max_queries: int = 200, revalidate: bool = False, plan_only: bool = False,
    on_progress=None,
    min_interval_seconds: float = 2.0,
    extra_routes: tuple = (),
) -> dict:
    """No-data preserves reference trust. Only successful counts assert empirical matches.

    Transient failures pause the run without converting an upstream reference
    into a false contradiction. A query error disables that compiled route for
    this schema until a successful revalidation replaces the failure.
    """
    options = {"lookback": lookback, "samples": samples, "row_limit": row_limit}
    schema_digest = physical_schema_digest(schema_rows)
    try:
        previous = load_validation_state(
            home, tenant_id, reference_digest=snapshot.digest, schema_digest=schema_digest,
            options=options, allow_schema_mismatch=True,
        )
    except ReferenceError:
        if not revalidate:
            raise
        previous = None
    records = dict(previous["routes"]) if previous else {}
    queries = reused = 0
    stopped = None
    pending = 0
    last_started = None
    for route in (*snapshot.routes, *extra_routes):
        try:
            compiled = compile_reference_query(route, schema_rows, **options)
        except ReferenceQueryUnsupported as exc:
            records[route.id] = {
                "status": "schema-unavailable" if exc.reason in {
                    "source-table-unavailable", "target-table-unavailable",
                    "source-column-unavailable", "target-column-unavailable",
                } else "unsupported", "reason": exc.reason, "detail": exc.detail,
            }
            continue
        query_hash = hashlib.sha256(compiled.query.encode()).hexdigest()
        old = records.get(route.id, {})
        base = {"query_sha256": query_hash, "reference_digest": snapshot.digest,
                "schema_digest": schema_digest, "options": options,
                "constraints_applied": list(compiled.constraints_applied),
                "warnings": list(compiled.warnings), "time_policy": compiled.time_policy,
                "validation_scope": compiled.scope}
        if any(value.startswith("condition-unverifiable:")
               for value in compiled.constraints_applied):
            records[route.id] = {**base, "status": "unsupported",
                                 "reason": "reference-context-required"}
            continue
        if (not revalidate and old.get("status") in {
            "matched", "no-source-data", "no-target-data", "no-overlap",
        } and validation_contract_matches(old, base) and _fresh(old)
                and verify_validation_record(home, tenant_id, route.id, old)):
            reused += 1
            continue
        if plan_only:
            records[route.id] = {**base, "status": "planned"}
            pending += 1
            continue
        if queries >= max_queries or stopped:
            if (old.get("status") == "query-failed"
                    and validation_contract_matches(old, base, allow_old_failure_schema=True)
                    and verify_validation_record(home, tenant_id, route.id, old)):
                records[route.id] = {**old, "revalidation_pending": True}
            else:
                records[route.id] = {**base, "status": "pending"}
            pending += 1
            continue
        if on_progress:
            on_progress(route.id, queries + 1)
        if last_started is not None:
            await asyncio.sleep(max(0, min_interval_seconds - (time.monotonic() - last_started)))
        last_started = time.monotonic()
        queries += 1
        try:
            result = await run_query(client, compiled.query)
            if len(result.results) != 1:
                raise ValueError("validation must return exactly one aggregate row")
            row = result.results[0]
            status = classify_counts(row, route.id)
            # Closed projection prevents a changed upstream response persisting identifiers.
            counts = {k: row[k] for k in ("RouteId", *_COUNT_KEYS)}
            if "ScanCapped" in row:
                if (type(row["ScanCapped"]) not in {bool, int}
                        or row["ScanCapped"] not in (0, 1)):
                    raise ValueError("ScanCapped must be zero or one")
                counts["ScanCapped"] = bool(row["ScanCapped"])
                if row["ScanCapped"]:
                    base["warnings"] = [*base["warnings"],
                                        "Target membership scan reached its row cap"]
            publish_validation_record(
                home, tenant_id, route_id=route.id, counts=counts, query=compiled.query,
                record={**base, "status": status,
                        "execution_surface": result.metadata.get("execution_surface", "unknown")},
                routes=records,
            )
        except QueryError as exc:
            counts = {"RouteId": route.id, "ErrorCode": exc.error_code}
            publish_validation_record(
                home, tenant_id, route_id=route.id, counts=counts, query=compiled.query,
                record={**base, "status": "query-failed", "error_code": exc.error_code},
                routes=records,
            )
        except ValueError as exc:
            records[route.id] = {**base, "status": "invalid-shape", "reason": str(exc)}
        except XDRError as exc:
            failure = {"error_code": exc.error_code, "exit_code": int(exc.exit_code),
                       "retry_after_seconds": exc.retry_after_seconds}
            records[route.id] = {**base, "status": "pending", "failure": failure}
            if not isinstance(exc, (RateLimitError, XDRTimeoutError, NetworkError)):
                save_validation_state(
                    home, tenant_id, reference_digest=snapshot.digest,
                    schema_digest=schema_digest, options=options, routes=records,
                )
                raise
            stopped = failure
            pending += 1
        save_validation_state(
            home, tenant_id, reference_digest=snapshot.digest, schema_digest=schema_digest,
            options=options, routes=records,
        )
    if not plan_only:
        save_validation_state(
            home, tenant_id, reference_digest=snapshot.digest, schema_digest=schema_digest,
            options=options, routes=records,
        )
    return {"routes": records, "queries": queries, "reused": reused, "pending": pending,
            "stopped": stopped, "schema_digest": schema_digest, "options": options}
