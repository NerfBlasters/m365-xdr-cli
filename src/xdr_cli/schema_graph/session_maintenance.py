"""Foreground schema maintenance invoked only after an explicit session end."""

from __future__ import annotations

import asyncio
import hashlib
from contextlib import ExitStack

from filelock import Timeout as FileLockTimeout

from xdr_cli._lock import exclusive_lock
from xdr_cli.auth import bounded_token_acquisition
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import (
    ConflictError,
    LocalNotFoundError,
    PartialSuccessError,
    XDRError,
)
from xdr_cli.exceptions import (
    TimeoutError as XDRTimeoutError,
)
from xdr_cli.results import emit_result, write_result


def collect_session_schema(ctx, *, on_result=None):
    """Serialize the whole maintenance cycle, including its freshness check."""
    ctx.config.check_maintenance_config()
    root = (
        get_config_home()
        / "schema"
        / hashlib.sha256(ctx.config.tenant_id.encode()).hexdigest()[:12]
    )
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with ExitStack() as stack:
        try:
            stack.enter_context(exclusive_lock(root / ".session-maintenance", timeout=0))
        except FileLockTimeout as exc:
            raise ConflictError(
                "Session-end schema maintenance is already running for this tenant.",
                help_command="xdr schema status",
            ) from exc
        asyncio.run(_maintain(ctx, on_result=on_result))


async def _maintain(ctx, *, on_result):
    from xdr_cli.commands.schema_cmd import (
        _ensure_overlay_compatible,
        _load_cache,
        _schema_refresh,
        _semantic_graph,
    )
    from xdr_cli.schema_graph.discovery import explore_saved_identifiers
    from xdr_cli.schema_graph.local_collection import collect_local

    stages = {}
    failure = None
    partial = None
    active_stage = "refresh"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + ctx.config.schema_maintenance_timeout_seconds

    def deadline_error():
        error = XDRTimeoutError(
            "Session-end schema maintenance reached its overall deadline; saved evidence remains.",
            help_command="xdr schema collect",
        )
        error.error_code = "SESSION_SCHEMA_MAINTENANCE_TIMEOUT"
        return error

    def remaining_time():
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise deadline_error()
        return remaining

    async def run_stage(function, **kwargs):
        remaining_time()
        budget = asyncio.timeout_at(deadline)
        try:
            task = asyncio.current_task()
            with bounded_token_acquisition(deadline, task.cancelling):
                async with budget:
                    await function(ctx, **kwargs)
        except TimeoutError as exc:
            if budget.expired():
                raise deadline_error() from exc
            raise
        # Synchronous planning or a stage that handles cancellation must not
        # start later work or mark completion after the shared deadline.
        remaining_time()

    def capture(stage):
        def receive(artifact):
            receipt = artifact.receipt.to_dict()
            receipt["context"]["shown"] = 0
            receipt["context"]["has_more"] = receipt["rows"] > 0
            stages[stage] = {"status": "success", "result": receipt}

        return receive

    try:
        _ensure_overlay_compatible(ctx.config.tenant_id)
        try:
            schema_rows, metadata = _load_cache(ctx)
        except LocalNotFoundError:
            schema_rows, metadata = [], {"stale": True}
        if ctx.config.schema_refresh_on_session_end and metadata["stale"]:
            await run_stage(_schema_refresh, on_result=capture("refresh"))
            schema_rows, _ = _load_cache(ctx)
        else:
            stages["refresh"] = {
                "status": "skipped",
                "reason": "fresh" if ctx.config.schema_refresh_on_session_end else "disabled",
            }

        active_stage = "validation"
        canonical = _semantic_graph()
        try:
            await run_stage(
                collect_local,
                plan_only=False,
                local_only=False,
                lookback="30d",
                samples=5,
                max_queries=20,
                timeout=min(ctx.config.api_timeout, remaining_time()),
                schema_rows=schema_rows,
                canonical=canonical,
                on_result=capture("validation"),
                mark_complete=False,
            )
        except PartialSuccessError as exc:
            # A normal budget pause must not starve exploration. Upstream errors
            # (especially auth/quota) stop the entire maintenance cycle.
            receipt = stages.get("validation", {}).get("result", {})
            if (
                exc.__cause__ is not None
                or exc.retry_after_seconds is not None
                or not (
                    receipt.get("context", {}).get("remaining_queries", 0)
                    or receipt.get("context", {}).get("coverage_gaps")
                )
            ):
                raise
            partial = exc
            stages.setdefault("validation", {})["status"] = "partial"

        active_stage = "exploration"
        if ctx.config.schema_explore_on_session_end:
            await run_stage(
                explore_saved_identifiers,
                schema_rows=schema_rows,
                canonical=canonical,
                max_queries=ctx.config.schema_explore_max_queries,
                timeout=min(ctx.config.api_timeout, remaining_time()),
                on_result=capture("exploration"),
                mark_complete=False,
            )
        else:
            stages["exploration"] = {"status": "skipped", "reason": "disabled"}
        if partial is None:
            from xdr_cli.schema_graph.maintenance import mark_collection_complete

            remaining_time()
            mark_collection_complete(ctx.config.tenant_id, {"mode": "session-maintenance"})
    except BaseException as exc:
        failure = exc
        stages.setdefault(active_stage, {})["status"] = (
            "partial"
            if isinstance(exc, PartialSuccessError)
            else "cancelled"
            if isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError))
            else "failed"
        )
    finally:
        for stage in ("refresh", "validation", "exploration"):
            stages.setdefault(stage, {"status": "skipped", "reason": "previous-stage-failed"})
        context = {
            "mode": "session-maintenance",
            "stages": stages,
            "queries_executed": sum(
                stage.get("result", {}).get("context", {}).get("queries_executed", 0)
                for name, stage in stages.items() if name != "refresh"
            )
            + int("result" in stages["refresh"]),
            "exploration_query_budget": ctx.config.schema_explore_max_queries,
            "maintenance_timeout_seconds": ctx.config.schema_maintenance_timeout_seconds,
        }
        recovery = failure or partial
        if isinstance(recovery, XDRError):
            context["next_command"] = recovery.help_command
        (on_result or emit_result)(
            write_result(
                [],
                command="schema session-maintenance",
                tenant_id=ctx.config.tenant_id,
                preview_rows=0,
                receipt_context=context,
                extra_metadata=context,
            )
        )
    if failure is not None:
        raise failure
    if partial is not None:
        raise partial
