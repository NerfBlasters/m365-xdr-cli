"""Foreground capture, local correlation and focused gap validation."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime, timedelta

from xdr_cli.auth import AuthManager, bounded_token_acquisition
from xdr_cli.backends import create_client
from xdr_cli.client import XDRClient
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import (
    ArtifactError,
    AuthError,
    ConfigError,
    ConflictError,
    ForbiddenError,
    LocalNotFoundError,
    PartialSuccessError,
    PermissionError,
    RateLimitError,
)
from xdr_cli.exceptions import (
    TimeoutError as XDRTimeoutError,
)
from xdr_cli.output import err_console
from xdr_cli.results import emit_result, write_result
from xdr_cli.schema_graph.capture_plan import plan_capture
from xdr_cli.schema_graph.reference_state import physical_schema_digest


def _horizon(value: str) -> timedelta:
    from xdr_cli.schema_graph.probe import validate_lookback

    validate_lookback(value)
    return timedelta(seconds=int(value[:-1]) * {"s": 1, "h": 3600, "d": 86400, "m": 60}[value[-1]])


def _as_dict(value):
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value):
        return asdict(value)
    raise TypeError("Invalid capture report")


async def _collect_with_retry(
    collect,
    ctx,
    *,
    options,
    deadline_at,
    max_queries,
    local_only,
    on_progress,
    prior_wait_seconds=0,
):
    """Reuse durable validations after a bounded, honored tenant throttle wait."""
    options = dict(options)
    query_timeout = options.pop("_query_timeout", 120)
    receipts = []
    attempted = retries = 0
    waited = 0.0
    while True:
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            return receipts, attempted, retries, waited, TimeoutError()
        current = []
        failure = None
        try:
            async with asyncio.timeout(remaining):
                await collect(
                    ctx,
                    **options,
                    local_only=local_only or attempted >= max_queries,
                    max_queries=max(0, max_queries - attempted),
                    timeout=min(query_timeout, max(1, int(remaining))),
                    on_result=current.append,
                )
        except (PartialSuccessError, TimeoutError) as exc:
            failure = exc
        receipts.extend(current)
        if current:
            context = current[-1].receipt.context
            attempted += context.get("queries_attempted", context.get("queries_executed", 0))
        if not isinstance(failure, PartialSuccessError) or not isinstance(
            failure.__cause__, RateLimitError
        ):
            return receipts, attempted, retries, waited, failure
        delay = failure.__cause__.retry_after_seconds
        delay = 60 if delay is None else max(5, delay)
        remaining = deadline_at - time.monotonic()
        if (
            not current
            or local_only
            or attempted >= max_queries
            or retries >= 10
            or delay > 120
            or prior_wait_seconds + waited + delay > 600
            or delay >= remaining
        ):
            return receipts, attempted, retries, waited, failure
        on_progress(f"Tenant validation throttled; continuing after {delay:g} seconds.")
        # Keep individual waits short enough for foreground cancellation/status.
        rest = delay
        while rest > 0:
            chunk = min(60, rest)
            await asyncio.sleep(chunk)
            rest -= chunk
        waited += delay
        retries += 1


async def explore_recent_data(ctx, **options):
    """Keep synchronous credential acquisition within the foreground job deadline."""
    task = asyncio.current_task()
    deadline = asyncio.get_running_loop().time() + options.get("deadline", 1200)
    with bounded_token_acquisition(deadline, task.cancelling):
        return await _explore_recent_data(ctx, **options)


async def _explore_recent_data(
    ctx,
    *,
    canonical,
    plan_only=False,
    lookback="24h",
    max_queries=300,
    max_rows=2_000_000,
    max_bytes=2_147_483_648,
    deadline=1200,
    samples=5,
    batch_size=20,
    seed_batch_size=20,
    max_depth=6,
    row_limit=2000,
    timeout=120,
    sources=(),
    on_result=None,
    refresh_schema=True,
    mark_complete=True,
):
    """One automatic invocation; hard budgets leave truthful resumable progress."""
    from xdr_cli.commands.schema_cmd import _load_cache, _schema_refresh

    started = time.monotonic()
    receipts = []
    queries_used = 0
    cache_missing = False
    try:
        schema_rows, schema_metadata = _load_cache(ctx)
    except LocalNotFoundError:
        schema_rows, schema_metadata, cache_missing = [], {}, True
    if not plan_only and refresh_schema and (cache_missing or schema_metadata.get("stale")):
        try:
            async with asyncio.timeout(max(0, deadline - (time.monotonic() - started))):
                await _schema_refresh(ctx, on_result=receipts.append)
        except TimeoutError as exc:
            raise XDRTimeoutError(
                "Exploration reached its deadline during physical schema refresh.",
                help_command="xdr schema collect --explore",
            ) from exc
        queries_used += 1
        schema_rows, schema_metadata = _load_cache(ctx)
        cache_missing = False
    plan = plan_capture(schema_rows, now=datetime.now(UTC), horizon=_horizon(lookback))
    context = {
        "mode": "capture-first",
        "plan_only": plan_only,
        "networked": queries_used > 0,
        "horizon": lookback,
        "budgets": {
            "max_queries": max_queries,
            "max_rows": max_rows,
            "max_bytes": max_bytes,
            "deadline_seconds": deadline,
        },
        "cache_missing": cache_missing,
        "tables_planned": len(plan.tables),
        "exclusions": list(plan.exclusions),
    }
    if plan_only:
        context.update(
            scope_complete=False,
            networked=False,
            next_command="xdr schema init" if cache_missing else "xdr schema collect --explore",
        )
        (on_result or emit_result)(
            write_result(
                [table.to_dict() for table in plan.tables],
                command="schema collect",
                tenant_id=ctx.config.tenant_id,
                preview_rows=0,
                receipt_context=context,
                extra_metadata={"capture_plan": plan.to_dict(), **context},
            )
        )
        return

    from xdr_cli.schema_graph.capture_artifacts import ResultCaptureSink
    from xdr_cli.schema_graph.capture_engine import CaptureBudgets, capture_recent
    from xdr_cli.schema_graph.local_collection import collect_local

    tenant = ctx.config.tenant_id
    state_dir = get_config_home() / "schema" / hashlib.sha256(tenant.encode()).hexdigest()[:12]
    remaining_queries = max(0, max_queries - queries_used)
    validation_reserve = min(50, max(1, remaining_queries // 5)) if remaining_queries >= 2 else 0
    capture_query_budget = remaining_queries - validation_reserve
    context["query_allocation"] = {
        "capture": capture_query_budget,
        "validation_reserved": validation_reserve,
    }
    sink = ResultCaptureSink(tenant_id=tenant, app_ctx=ctx)
    capture = None
    stage_failures = []
    fatal = None

    def progress(message):
        if not ctx.effective_quiet:
            err_console.print(str(message), markup=False)

    if cache_missing or queries_used >= max_queries or time.monotonic() - started >= deadline:
        capture = {
            "job_id": None,
            "status": "paused",
            "resumed": False,
            "interval": {"start": plan.to_dict()["start"], "end": plan.to_dict()["end"]},
            "stop": {
                "kind": "schema-cache-missing"
                if cache_missing
                else "budget-queries"
                if queries_used >= max_queries
                else "deadline"
            },
            "counters": {"queries": 0},
            "captured_run_ids": [],
            "tables": [
                dict(table.to_dict(), table=table.name, status="pending") for table in plan.tables
            ],
        }
    else:
        client = create_client(
            ctx.config,
            timeout=min(timeout, deadline),
            auth_factory=AuthManager,
            client_factory=XDRClient,
        )
        try:
            capture = await capture_recent(
                client,
                schema_rows=schema_rows,
                binding={
                    "tenant_fingerprint": hashlib.sha256(tenant.encode()).hexdigest(),
                    "backend": client.profile.name,
                    "schema_digest": physical_schema_digest(schema_rows),
                    "schema_generation": schema_metadata.get("generation"),
                    "horizon_seconds": int(_horizon(lookback).total_seconds()),
                },
                state_dir=state_dir,
                sink=sink,
                lookback=lookback,
                budgets=CaptureBudgets(
                    max_queries=capture_query_budget,
                    max_rows=max_rows,
                    max_bytes=max_bytes,
                    deadline_seconds=max(0, deadline - (time.monotonic() - started)),
                ),
                on_progress=progress,
            )
        finally:
            await client.close()
    capture = _as_dict(capture)
    context["capture"] = {
        key: capture.get(key)
        for key in ("job_id", "resumed", "status", "interval", "stop", "counters")
    }
    context["capture"]["table_statuses"] = dict(
        Counter(table.get("status", "unknown") for table in capture.get("tables", []))
    )
    context["capture"]["source_artifacts"] = len(capture.get("captured_run_ids", []))
    context["networked"] = True
    capture_queries = capture.get("metrics", capture.get("counters", {})).get("queries", 0)
    queries_used += capture_queries
    remaining_seconds = deadline - (time.monotonic() - started)
    capture_stop = capture.get("stop") or {}
    network_paused = capture_stop.get("kind") in {
        "rate-limited",
        "network",
        "binding-changed",
        "upstream",
        "fatal",
    }
    from xdr_cli.schema_graph.capture_engine import live_capture_references

    live_references = live_capture_references(state_dir)
    closed_pending = [
        ref for ref in live_references if ref.get("status") in {"closed", "expired", "superseded"}
    ]
    pending_handoffs = {ref["job_id"] for ref in closed_pending}
    required_runs = set(capture.get("captured_run_ids", [])) | {
        ref["artifact"]["run_id"] for ref in closed_pending
    }
    from xdr_cli.schema_graph.retention import index_result_metadata, retirement_cutoff, timestamp

    cutoff = retirement_cutoff(state_dir)
    retired_sources = set()
    if cutoff is not None and required_runs:
        import json

        index = index_result_metadata(get_config_home() / "results")
        references_by_run = {ref["artifact"]["run_id"]: ref for ref in live_references}
        from xdr_cli.schema_graph.capture_contract import SliceArtifact

        for run_id in sorted(required_runs):
            paths = index.get(run_id, ())
            if len(paths) != 1:
                continue  # Required-source indexing below reports this gap.
            try:
                meta = json.loads(paths[0].read_text())
                if timestamp(meta["created_at"]) >= cutoff:
                    continue
                ref = references_by_run.get(run_id)
                if ref is None or not sink.verify(
                    ref["job_id"],
                    ref["window_id"],
                    SliceArtifact.from_dict(ref["artifact"]),
                    expected=ref.get("expected"),
                ):
                    raise ValueError("retired capture source failed integrity verification")
                retired_sources.add(run_id)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                raise ArtifactError("Cannot verify a retired pending capture source.") from exc
        required_runs -= retired_sources
        if retired_sources:
            context["retired_capture_sources"] = len(retired_sources)
            stage_failures.append({"stage": "index", "code": "capture-sources-retired"})
    local_receipts, validation_attempts, retries, waited, failure = await _collect_with_retry(
        collect_local,
        ctx,
        options={
            "plan_only": False,
            "lookback": lookback,
            "samples": samples,
            "batch_size": batch_size,
            "_query_timeout": timeout,
            "schema_rows": schema_rows,
            "canonical": canonical,
            "mark_complete": False,
            "required_source_runs": tuple(sorted(required_runs)),
            "index_deadline": started + deadline,
        },
        deadline_at=started + deadline,
        max_queries=max(0, max_queries - queries_used),
        local_only=queries_used >= max_queries or network_paused,
        on_progress=progress,
        prior_wait_seconds=capture.get("counters", {}).get("wait_seconds", 0),
    )
    queries_used += validation_attempts
    context["validation_retries"] = retries
    context["validation_wait_seconds"] = waited
    context["validation_queries_attempted"] = validation_attempts
    if isinstance(failure, PartialSuccessError):
        if isinstance(
            failure.__cause__,
            (AuthError, ConfigError, ArtifactError, PermissionError, ForbiddenError),
        ):
            fatal = failure.__cause__
        stage_failures.append(
            {
                "stage": "validation",
                "code": failure.error_code,
                "retry_after_seconds": failure.retry_after_seconds,
            }
        )
    elif failure is not None:
        stage_failures.append({"stage": "validation", "code": "deadline"})
    if local_receipts:
        context["local_result"] = local_receipts[-1].receipt.to_dict()
    followup_receipts = []
    incomplete_tables = {
        table["table"]
        for table in capture.get("tables", [])
        if table.get("status") != "complete" and table.get("time_column")
    }
    remaining_seconds = deadline - (time.monotonic() - started)
    capture_stop = capture.get("stop") or {}
    # A quota/transport stop applies to the whole invocation; never immediately
    # issue a different kind of query against the same exhausted tenant.
    if (
        incomplete_tables
        and queries_used < max_queries
        and remaining_seconds > 0
        and not stage_failures
        and capture_stop.get("kind")
        not in {
            "rate-limited",
            "network",
            "binding-changed",
            "upstream",
            "fatal",
        }
    ):
        from xdr_cli.schema_graph.discovery import explore_saved_identifiers

        try:
            async with asyncio.timeout(remaining_seconds):
                await explore_saved_identifiers(
                    ctx,
                    schema_rows=schema_rows,
                    canonical=canonical,
                    lookback=lookback,
                    max_queries=max_queries - queries_used,
                    seed_batch_size=seed_batch_size,
                    max_depth=max_depth,
                    row_limit=row_limit,
                    timeout=min(timeout, max(1, int(remaining_seconds))),
                    sources=sources,
                    target_tables=incomplete_tables,
                    on_result=followup_receipts.append,
                    mark_complete=False,
                )
        except PartialSuccessError as exc:
            if isinstance(
                exc.__cause__,
                (
                    AuthError,
                    ConfigError,
                    ConflictError,
                    ArtifactError,
                    PermissionError,
                    RateLimitError,
                    ForbiddenError,
                ),
            ):
                fatal = exc.__cause__
            stage_failures.append(
                {
                    "stage": "followup",
                    "code": exc.error_code,
                    "retry_after_seconds": exc.retry_after_seconds,
                }
            )
        except TimeoutError:
            stage_failures.append({"stage": "followup", "code": "deadline"})
    if followup_receipts:
        followup = followup_receipts[-1].receipt.context
        queries_used += followup.get("queries_attempted", followup.get("queries_executed", 0))
        context["followup_result"] = followup_receipts[-1].receipt.to_dict()
    local_complete = bool(
        local_receipts and local_receipts[-1].receipt.context.get("scope_complete", False)
    )
    context.update(
        queries_used=queries_used,
        stage_failures=stage_failures,
        scope_complete=capture.get("status") == "complete"
        and not stage_failures
        and local_complete,
        next_command="xdr schema collect --explore"
        if stage_failures or capture.get("status") != "complete" or not local_complete
        else "xdr schema discoveries",
    )
    local_coverage = (
        local_receipts[-1].receipt.context.get("local_coverage", {}) if local_receipts else {}
    )
    if (
        local_coverage.get("complete")
        and local_coverage.get("required_sources_complete")
        and local_receipts[-1].receipt.context.get("local_publication_complete")
    ):
        context["capture_handoff_ready"] = True
    if mark_complete and context["scope_complete"]:
        from xdr_cli.schema_graph.maintenance import mark_collection_complete

        mark_collection_complete(tenant, {"mode": "capture-first", "job_id": capture["job_id"]})
    (on_result or emit_result)(
        write_result(
            [
                dict(table, record_type="capture-table-coverage")
                for table in capture.get("tables", [])
            ],
            command="schema collect",
            tenant_id=tenant,
            preview_rows=0,
            receipt_context=context,
            extra_metadata={**context, "capture_report": capture},
        )
    )
    if context.get("capture_handoff_ready"):
        from xdr_cli.schema_graph.capture_engine import mark_capture_consumed

        if capture.get("job_id") and capture.get("status") in {"complete", "partial"}:
            pending_handoffs.add(capture["job_id"])
        for job_id in sorted(pending_handoffs):
            try:
                mark_capture_consumed(
                    state_dir,
                    job_id,
                    indexed_run_ids=required_runs,
                    retired_run_ids=retired_sources,
                )
            except ConflictError as exc:
                if fatal is not None:
                    break
                raise PartialSuccessError(
                    "Capture and graph results were saved; retention handoff is deferred "
                    "because another capture is running. Evidence remains protected.",
                    help_command="xdr schema collect --explore",
                    original={"type": type(exc).__name__, "code": int(exc.exit_code)},
                ) from exc
    if fatal is not None:
        raise fatal
    if not context["scope_complete"]:
        raise PartialSuccessError(
            "Capture and local discovery progress were saved; inspect coverage and continuation.",
            help_command=context["next_command"],
            retry_after_seconds=next(
                (
                    failure["retry_after_seconds"]
                    for failure in stage_failures
                    if failure.get("retry_after_seconds") is not None
                ),
                capture_stop.get("retry_after_seconds"),
            ),
        )
