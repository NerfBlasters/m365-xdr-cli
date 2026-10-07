"""Shared KQL execution and session annotations for hunt and library commands.

The command boundary flushes the recorder with the final exit code and duration.
This helper records query inputs, results, and failures without owning the client.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from time import monotonic
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from xdr_cli.api.hunting import HuntingResult
    from xdr_cli.context import AppContext


def _parse_execution_time_ms(value: Any) -> int | None:
    """Best-effort parse of ``stats["ExecutionTime"]`` into integer milliseconds.

    The Graph / MDE Advanced Hunting APIs surface ``ExecutionTime`` either as
    a duration string (``"00:00:00.123"``) or, in some test fixtures and older
    responses, a numeric seconds value. We accept both shapes and return
    ``None`` on anything else so downstream consumers can rely on the field
    being a clean integer or ``None`` — never a half-parsed string.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return int(round(float(value) * 1000))
        except (ValueError, OverflowError):
            return None
    if isinstance(value, str):
        # Try duration format ``HH:MM:SS.fff`` first.
        parts = value.split(":")
        if len(parts) == 3:
            try:
                hours = int(parts[0])
                minutes = int(parts[1])
                seconds = float(parts[2])
                total_seconds = hours * 3600 + minutes * 60 + seconds
                return int(round(total_seconds * 1000))
            except (ValueError, OverflowError):
                return None
        # Fallback: bare numeric string.
        try:
            return int(round(float(value) * 1000))
        except (ValueError, OverflowError):
            return None
    return None


def capture_sample(
    rows: list[dict],
    limit: int = 3,
    byte_cap: int = 4096,
) -> list[dict]:
    """Pick the first ``limit`` rows for the recorder's ``result.sample_rows``.

    Each row whose JSON-encoded length exceeds ``byte_cap`` is replaced with a
    stable truncation marker (``{"_truncated": True, "_original_size_bytes":
    <n>}``) so downstream training-map analysers can still count/skip large
    payloads without choking on multi-megabyte ``RawEventData`` rows.

    Co-located with the Recorder rather than living inside the OutputFormatter
    so the recorder's capture timing stays explicit and testable, and the cap
    logic stays close to the on-disk schema definition.

    Returns ``[]`` for an empty input. Never raises — JSON-encode failures land
    on individual rows as truncation markers with size 0 (treating "couldn't
    measure size" the same as "too big to keep").

    Kept rows are round-tripped through ``json.loads(json.dumps(row,
    default=str))`` so values that ``json.dumps`` can only serialise via
    ``default=str`` (e.g., ``datetime``) are converted to their string forms
    *now*, not at Recorder.flush time. Recorder.flush is fail-soft; a
    serialization error at flush time silently loses the entire invocation
    record. Doing the conversion here costs one re-parse per kept row and
    guarantees the row dict is JSON-natively-serializable downstream.
    """
    out: list[dict] = []
    for row in rows[:limit]:
        try:
            serialized = json.dumps(row, default=str)
            size = len(serialized.encode("utf-8"))
        except (TypeError, ValueError):
            # Unserialisable row — record a marker rather than dropping it.
            out.append({"_truncated": True, "_original_size_bytes": 0})
            continue
        if size > byte_cap:
            out.append({"_truncated": True, "_original_size_bytes": size})
        else:
            # Round-trip so non-natively-serializable values (datetime, etc.)
            # are baked into their str() forms now — flush-time serialization
            # of the full record cannot then fail on this row.
            out.append(json.loads(serialized))
    return out


@dataclass
class QueryResult:
    """Bundle returned by :func:`run_kql_with_recording`.

    Carries both the raw API result and the post-truncation / post-expansion
    rows the caller should display. ``has_more`` is True when the API returned
    more rows than ``display_limit`` would show. ``wall_clock_ms`` is the
    client-measured request duration — used as the fallback for
    ``metadata.execution_time_ms`` since neither Graph nor MDE reliably
    return execution time in the response body.
    """

    api_result: Any  # HuntingResult — typed Any here to avoid the import
    display_rows: list[dict]
    has_more: bool
    wall_clock_ms: int = 0


async def run_kql_with_recording(
    ctx: AppContext,
    *,
    kql: str,
    library_query: str | None,
    params: dict | None,
    expand_json: bool = True,
    display_limit: int | None = None,
    runner: Callable[[], Awaitable[HuntingResult]],
) -> QueryResult:
    """Run KQL and annotate the command's recorder on success or failure.

    The runner must execute the supplied KQL. Callers own client lifecycle and
    provide the runner so patches to their API imports still take effect.
    ``display_limit=None`` retains all returned rows; ``expand_json`` controls
    expansion of known JSON-string columns. API failures propagate after their
    annotations are captured, and the outer command boundary flushes the record.
    """
    # Heavy imports deferred to keep this module light for non-KQL commands.
    from xdr_cli.json_expansion import expand_json_string_columns
    from xdr_cli.kql_parse import extract_tables

    rec = ctx.recorder

    # ---- Pre-API annotations ------------------------------------------------
    # Even if the API blows up before returning, the record captures what was
    # attempted (kql + library_query + params).
    if rec is not None:
        # extract_tables() never raises; returns [] on unparseable input.
        rec.annotate("kql", kql)
        rec.annotate("tables_referenced", extract_tables(kql))
        rec.annotate("library_query", library_query)
        rec.annotate("params", params or {})

    # ---- API call -----------------------------------------------------------
    # The caller supplies the runner closure so test patches targeting the
    # caller module's namespace (``hunt_cmd.run_query``) take effect. Client
    # lifecycle (auth, close) is the caller's responsibility for the same reason.
    api_error: Exception | None = None
    api_result: HuntingResult | None = None
    started = monotonic()
    try:
        api_result = await runner()
    except httpx.TimeoutException as e:
        # Distinct handling so the message (e.g. "Server didn't respond in
        # 30s") is captured with the distinct timeout exit code. The stderr
        # print is what makes a timeout user-visible: previously only the
        # recorder annotation captured it, which made a timeout look identical
        # to "empty results" on stdout.
        from xdr_cli.exceptions import TimeoutError as XDRTimeoutError
        from xdr_cli.output import err_console

        api_error = XDRTimeoutError(
            f"Advanced Hunting timed out: {e}",
            help_command="Retry once with --timeout <seconds> if the query is bounded.",
            original={"type": type(e).__name__, "message": str(e)},
        )
        err_console.print(
            f"[red]error:[/red] query timed out ({e}). "
            f"Raise the timeout via [bold]--timeout[/bold] or "
            f"[bold]api_timeout[/bold] in ~/.xdr-cli/config.toml."
        )
        if rec is not None:
            rec.annotate("error", f"timeout: {e}")
    except httpx.HTTPStatusError as e:
        # str(e) only includes the constructor message ("400"), not the
        # response body. Build the full message explicitly so downstream
        # training maps can see the server's explanation.
        from xdr_cli.output import err_console

        msg = f"API {e.response.status_code}: {e.response.text}"
        from xdr_cli.exceptions import APIError, query_error_from_message

        if e.response.status_code == 400:
            api_error = query_error_from_message(
                msg,
                original={
                    "type": type(e).__name__,
                    "status": e.response.status_code,
                    "message": e.response.text,
                },
            )
        else:
            api_error = APIError(
                msg,
                status_code=e.response.status_code,
                detail=e.response.text[:500],
            )
        err_console.print(f"[red]error:[/red] {msg}")
        if rec is not None:
            rec.annotate("error", msg)
    except Exception as e:  # noqa: BLE001 — captured for the record
        # Narrowed from BaseException so KeyboardInterrupt / SystemExit /
        # asyncio.CancelledError keep their normal cooperative-cancel
        # semantics. The parent recorder's flush in run()'s try/finally
        # already handles Ctrl-C for the invocation record.
        api_error = e

    # ---- Post-API recorder annotations --------------------------------------
    # Build display_rows / has_more once (success path) so we can both
    # annotate the recorder *and* hand the same rows back to the caller.
    display_rows: list[dict] = []
    has_more = False
    if api_result is not None:
        results = list(api_result.results)
        if display_limit is not None and display_limit >= 0:
            display_rows = results[:display_limit]
            has_more = len(results) > display_limit
        else:
            display_rows = results
            has_more = False
        if expand_json:
            display_rows = expand_json_string_columns(display_rows)

    if rec is not None:
        if api_error is None and api_result is not None:
            cpu_usage = (
                api_result.stats.get("resource_usage", {})
                .get("cpu", {})
                .get("total cpu", "")
            )
            columns_projected: list[str] | None = [
                col["name"] for col in api_result.schema
            ] or None
            rec.annotate("columns_projected", columns_projected)
            rec.annotate(
                "result",
                {
                    "row_count": len(api_result.results),
                    "execution_time_ms": _parse_execution_time_ms(
                        api_result.stats.get("ExecutionTime")
                    ),
                    "cpu_usage": cpu_usage or None,
                    "has_more": has_more,
                    "sample_rows": capture_sample(display_rows),
                },
            )
        else:
            # Failure path: surface the exception on the record so the
            # training map captures *which* query failed. Specific handlers
            # (TimeoutException, HTTPStatusError) already annotated "error"
            # with a richer message — only fall back to str() for generic
            # exceptions that did not set their own annotation.
            if not isinstance(api_error, (httpx.TimeoutException, httpx.HTTPStatusError)):
                rec.annotate("error", str(api_error))

    # Re-raise after the recorder has been annotated.
    # Structured XDRError subclasses retain their own recovery-specific exit
    # class at the root command boundary.
    if api_error is not None:
        raise api_error

    assert api_result is not None
    return QueryResult(
        api_result=api_result,
        display_rows=display_rows,
        has_more=has_more,
        wall_clock_ms=int((monotonic() - started) * 1000),
    )
