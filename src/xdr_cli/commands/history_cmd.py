"""Session history browsing.

`xdr history` is a top-level sub-app whose default (no-subcommand) behavior
is a browse view over the JSONL invocation records produced by the Recorder.
Top-level placement (rather than nesting under `hunt`) reflects that records
cover *all* commands, not just hunting.

Future tasks layer additional surface here:
* Task 7+: deeper rationale / training-map filters.

Task 6 lands ``xdr history stats`` (six aggregate metrics: invocations,
hunt_ratio, cpu_usage_total, table_coverage_gaps, failure_rate,
session_duration_seconds) sharing the same filter axes as the browse callback
via :func:`_iter_filtered_records`.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from math import gcd
from typing import Any

import pytimeparse2
import typer

from xdr_cli.context import AppContext
from xdr_cli.exceptions import ConflictError, UsageError
from xdr_cli.kql_parse import extract_tables
from xdr_cli.output import OutputFormatter, err_console
from xdr_cli.queries import list_queries
from xdr_cli.sessions import current_session, list_sessions, load_session_records

history_app = typer.Typer(
    name="history",
    help="Browse session records.",
    invoke_without_command=True,  # default to browse when no subcommand
    no_args_is_help=False,
)


def _parse_since(spec: str) -> timedelta:
    """Parse a duration spec into a timedelta with corrective usage errors.

    Uses pytimeparse2 so we accept ``24h``, ``7d``, ``30d``, ``90m``, ``1w``,
    ``2y``, ISO-8601 durations, etc. Returns ``None`` from pytimeparse2 means
    unparseable -- we surface a clear stderr error and exit 1 rather than
    silently fall back to a default window.

    Bare-numeric input (``"30"``, ``"30.5"``) is rejected explicitly:
    pytimeparse2 interprets it as seconds, which silently contradicts the
    help text (``24h/7d/30d``) and is almost certainly a user mistake.
    Inputs containing letters (``s/m/h/d/w/y``) or colons (``HH:MM:SS``) are
    forwarded to pytimeparse2.
    """
    stripped = spec.strip()
    # Bare integers / floats: missing-unit footgun. pytimeparse2 would happily
    # interpret "30" as 30 seconds; refuse instead and prompt for a unit.
    if stripped and stripped.replace(".", "", 1).isdigit():
        raise UsageError(
            f"Could not parse --since {spec!r}: a unit suffix is required.",
            invalid={"kind": "duration", "value": spec, "option": "--since"},
            allowed=["<number>s", "<number>m", "<number>h", "<number>d", "<number>w"],
            suggestions=[
                {
                    "reason": "duration_unit",
                    "message": "Use a value such as 24h, 7d, 90m, or 1w.",
                    "confidence": "exact",
                }
            ],
            help_command="xdr history --help",
        )
    seconds = pytimeparse2.parse(stripped)
    if seconds is None:
        raise UsageError(
            f"Could not parse --since {spec!r} as a duration.",
            invalid={"kind": "duration", "value": spec, "option": "--since"},
            suggestions=[
                {
                    "reason": "duration_format",
                    "message": "Use a value such as 24h, 7d, 90m, or 1w.",
                    "confidence": "exact",
                }
            ],
            help_command="xdr history --help",
        )
    return timedelta(seconds=float(seconds))


def _iter_filtered_records(
    *,
    session_ids: list[str],
    since: timedelta | None,
    command: str,
    incident: str,
    actor: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Iterate JSONL invocation records across `session_ids` applying filters.

    Filter semantics:
      * ``kind == "invocation"`` only (session_started/_ended excluded).
      * ``since``: keep records whose ``timestamp`` is >= now - since. ISO-8601
        UTC timestamps with the same ``Z`` suffix sort lexicographically, so a
        string compare is correct here and avoids per-record datetime parsing.
      * ``command``: substring match against the ``command`` field
        (e.g., ``"hunt"`` matches ``"hunt run"``, ``"hunt library"``,
        ``"investigate.hunt"``).
      * ``incident``: exact match against ``anchor_incident``.
      * ``actor``: exact match against the ``actor`` field — currently unused
        by any caller (``stats --by-actor`` buckets already-fetched records
        client-side via ``_bucket_by_actor``). ``None``
        (default) means "no actor filter".
    """
    cutoff_iso: str | None = None
    if since is not None:
        cutoff_dt = datetime.now(UTC) - since
        cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    for sid in session_ids:
        lines = load_session_records(sid)
        if lines is None:
            continue
        for line in lines:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("kind") != "invocation":
                continue
            if cutoff_iso is not None:
                ts = rec.get("timestamp")
                if not isinstance(ts, str) or ts < cutoff_iso:
                    continue
            if command and command not in (rec.get("command") or ""):
                continue
            if incident and str(rec.get("anchor_incident")) != str(incident):
                continue
            if actor is not None and rec.get("actor") != actor:
                continue
            yield rec


@history_app.callback()
def history_browse(
    ctx: typer.Context,
    session: str = typer.Option(
        "", "--session", help="Session ID. Defaults to the current session."
    ),
    operator: str = typer.Option(
        "",
        "--operator",
        help=(
            "Operator initials -- aggregates across that operator's sessions. "
            "Ignored when --session is also passed."
        ),
    ),
    since: str = typer.Option(
        "", "--since", help="Duration spec like 24h, 7d, 30d, 1w, 2y."
    ),
    command: str = typer.Option(
        "", "--command", help="Substring match against the `command` field."
    ),
    incident: str = typer.Option(
        "", "--incident", help="Filter records where anchor_incident == ID."
    ),
) -> None:
    """Browse invocation records (default; no subcommand needed)."""
    if ctx.invoked_subcommand is not None:
        # A subcommand will run -- this callback only sets up shared options
        # for future subcommands (e.g., stats in Task 6). Browse logic is
        # gated on the no-subcommand path.
        return

    app_ctx: AppContext = ctx.obj

    # ------------------------------------------------------------------
    # Resolve which session(s) to read from.
    # ------------------------------------------------------------------
    if session and operator:
        err_console.print(
            "[yellow]--session takes precedence; --operator ignored[/yellow]"
        )

    session_ids: list[str]
    if session:
        session_ids = [session]
    elif operator:
        session_ids = [row["id"] for row in list_sessions(operator=operator)]
    else:
        active = current_session()
        if active is None:
            raise ConflictError(
                "No active session is unambiguously available for history.",
                suggestions=[
                    {
                        "reason": "explicit_session",
                        "message": "Pass --session <id> or --operator <initials>.",
                        "confidence": "exact",
                    }
                ],
                help_command="xdr session list",
            )
        session_ids = [active.id]

    # ------------------------------------------------------------------
    # Parse --since (clear error on bad input; never silent fallback).
    # ------------------------------------------------------------------
    since_delta: timedelta | None = None
    if since:
        since_delta = _parse_since(since)

    # ------------------------------------------------------------------
    # Iterate, filter, emit.
    # ------------------------------------------------------------------
    records = list(
        _iter_filtered_records(
            session_ids=session_ids,
            since=since_delta,
            command=command,
            incident=incident,
        )
    )

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(records))


# ---------------------------------------------------------------------------
# `xdr history stats` aggregates (Task 6)
# ---------------------------------------------------------------------------

# Commands considered "hunting" for the hunt_ratio metric. Matches the
# ``command`` field set by the recorder / leaf-callback chain.
#
# ``_PIVOT`` is forward-compat scaffolding: there is no ``xdr pivot`` command
# yet (it's in the plan's Out-of-scope list), so this counter is always 0
# in current output. The field is reserved in ``hunt_ratio`` so consumers can
# rely on a stable shape across versions; when ``xdr pivot`` ships, it will
# populate this counter without a schema change.
_HUNT_RUN = "hunt run"
_HUNT_LIBRARY_RUN = "hunt library-run"
_LIBRARY_RUN = "library run"
_PIVOT = "pivot"
_INVESTIGATE_HUNT = "investigate.hunt"

_CPU_PCT_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*%\s*$")


def _parse_cpu_pct(value: Any) -> float | None:
    """Parse ``"NN%"`` or ``"NN.N%"`` to a float; return ``None`` otherwise.

    ``None`` covers both literal ``None`` and any string that doesn't match
    the percent shape (the recorder always writes the API's literal string,
    so any non-percent value indicates a fixture / future shape we should
    skip rather than guess at).
    """
    if not isinstance(value, str):
        return None
    m = _CPU_PCT_RE.match(value)
    if m is None:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _record_tables(rec: dict[str, Any]) -> list[str] | None:
    """Return the list of tables referenced by a record's KQL.

    Returns:
        - The persisted ``tables_referenced`` list if it's a list (any length).
        - ``None`` when the record has no list field AND no kql to retokenize.
        - The result of re-tokenizing ``kql`` when ``tables_referenced`` is missing.

    Note: ``extract_tables`` is fail-soft and returns ``[]`` for both
    "tokenizer ran cleanly, no tables found" and "tokenizer failed on
    non-empty input." We treat both as determinate-empty (no gap, no
    indeterminate increment). A non-empty kql string that produces ``[]``
    cannot be distinguished from a clean-empty parse — this is acknowledged
    by design; the writer-time tokenizer would have already failed and
    left ``tables_referenced=None``, so this re-tokenize is a best-effort
    second chance, not a guaranteed-correct re-parse.
    """
    tables = rec.get("tables_referenced")
    if isinstance(tables, list):
        return tables
    kql = rec.get("kql")
    if isinstance(kql, str) and kql.strip():
        retokenized = extract_tables(kql)
        if retokenized:
            return retokenized
        # Empty list from a non-empty kql still counts as "determinate" —
        # the tokenizer ran cleanly and found nothing.
        return retokenized
    return None


def _library_table_index() -> dict[str, str]:
    """Map ``table_name -> library_query_name`` covering every library .kql.

    First-write wins on collision: with multiple libraries referencing the
    same table, we pick whichever ``list_queries()`` yields first (sorted by
    name) so the output is deterministic. The metric only needs *some*
    library to attribute coverage to; the choice of which is informational.
    """
    index: dict[str, str] = {}
    try:
        for q in list_queries():
            for table in extract_tables(q.raw_kql):
                index.setdefault(table, q.name)
    except Exception:
        # list_queries() should not raise, but importlib.resources can in
        # exotic packaging setups. Fail soft: an empty index means the
        # gap metric reports zero gaps rather than crashing the whole stats
        # output.
        pass
    return index


def _compute_invocations(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(r.get("command", "") for r in records)
    return {"total": len(records), "by_command": dict(counts)}


def _compute_hunt_ratio(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(r.get("command", "") for r in records)
    hr = counts.get(_HUNT_RUN, 0)
    hlr = counts.get(_HUNT_LIBRARY_RUN, 0) + counts.get(_LIBRARY_RUN, 0)
    pivot = counts.get(_PIVOT, 0)
    inv_hunt = counts.get(_INVESTIGATE_HUNT, 0)
    if hr > 0 and hlr > 0:
        g = gcd(hr, hlr)
        ratio = f"{hr // g}:{hlr // g}"
    else:
        # Edge case: at least one denominator is 0 — emit verbatim, never
        # divide. "3:0" tells the operator "ran 3 hunt run, 0 library".
        ratio = f"{hr}:{hlr}"
    return {
        "hunt_run": hr,
        "hunt_library_run": hlr,
        "pivot": pivot,
        "investigate.hunt": inv_hunt,
        "ratio_explanatory": ratio,
    }


def _compute_cpu_total(records: list[dict[str, Any]]) -> str:
    """Sum ``result.cpu_usage`` percentages; return ``"NN%"`` (or ``"0%"``)."""
    total = 0.0
    any_seen = False
    for r in records:
        result = r.get("result") or {}
        pct = _parse_cpu_pct(result.get("cpu_usage"))
        if pct is None:
            continue
        total += pct
        any_seen = True
    if not any_seen:
        return "0%"
    # Render integers as integers ("35%", not "35.0%"); preserve fractional
    # values so two records summing to 12.5% don't lie about precision.
    if total == int(total):
        return f"{int(total)}%"
    return f"{total}%"


def _compute_failure_rate(records: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(records)
    failed_codes: list[str] = []
    for r in records:
        if r.get("exit_code", 0) != 0:
            err = r.get("error")
            # Error block may be a dict ({"code": "..."}) on richer error
            # paths or a bare string for str(api_error) writes — fall back
            # to exit_code when no structured code is available.
            code: Any = (
                err["code"]
                if isinstance(err, dict) and "code" in err
                else r.get("exit_code")
            )
            failed_codes.append(str(code))
    failed = len(failed_codes)
    rate = round((failed / total) * 100.0, 2) if total else 0.0
    top = [
        {"code": code, "count": count}
        for code, count in Counter(failed_codes).most_common(3)
    ]
    return {
        "total": total,
        "failed": failed,
        "rate_percent": rate,
        "top_errors": top,
    }


def _compute_table_coverage_gaps(
    records: list[dict[str, Any]],
    library_index: dict[str, str],
) -> tuple[list[dict[str, str]], int]:
    """Emit a row per (table, covering_library) where the operator hand-rolled
    a hunt run for a table that the library already covers.

    Returns ``(gaps, indeterminate_count)`` — indeterminate counts records
    that couldn't be tokenized (write-time AND retokenize both failed).
    """
    gaps_seen: dict[str, str] = {}  # table -> covered_by (dedupe across hits)
    indeterminate = 0
    for r in records:
        cmd = r.get("command", "")
        # Only ``hunt run`` represents "hand-rolled query". Library-run /
        # investigate.* / pivot all delegate to the library or to wrapped
        # entity-anchored KQL we don't expect operators to "library-fy".
        if cmd != _HUNT_RUN:
            continue
        # Skip records that explicitly invoked a library query (defensive —
        # a library_query value implies the operator went through the
        # library path even if command field were odd).
        if r.get("library_query"):
            continue
        tables = _record_tables(r)
        if tables is None:
            indeterminate += 1
            continue
        for table in tables:
            covered_by = library_index.get(table)
            if covered_by is None:
                continue
            gaps_seen.setdefault(table, covered_by)
    gaps = [
        {"table": table, "covered_by": covered}
        for table, covered in sorted(gaps_seen.items())
    ]
    return gaps, indeterminate


def _compute_session_duration(records: list[dict[str, Any]]) -> float | None:
    """Last-minus-first record timestamp in seconds.

    Returns:
        - ``0.0`` for a single record (no time delta).
        - The delta in seconds for multiple records.
        - ``None`` when no parseable timestamps exist (e.g., all records
          have malformed ISO strings) OR when ``--operator`` filter is
          set (multi-session intent).

    ``datetime.fromisoformat`` accepts ``Z`` suffix natively in 3.11+; we
    keep a manual fallback in case a future Python tightens parsing or a
    record has a non-standard suffix.
    """
    timestamps: list[datetime] = []
    for r in records:
        ts = r.get("timestamp")
        if not isinstance(ts, str):
            continue
        try:
            normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
            timestamps.append(datetime.fromisoformat(normalized))
        except ValueError:
            continue
    if len(timestamps) < 2:
        # Single record (or none parsed cleanly) -> 0s window. Document on
        # the field that this is the *invocation-window* duration, not the
        # session lifetime as recorded by session_started/ended.
        return 0.0 if timestamps else None
    return (max(timestamps) - min(timestamps)).total_seconds()


def _bucket_by_actor(
    records: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        actor = r.get("actor") or "operator"
        buckets.setdefault(actor, []).append(r)
    return buckets


@history_app.command("stats")
def history_stats(
    ctx: typer.Context,
    session: str = typer.Option(
        "", "--session", help="Session ID. Defaults to the current session."
    ),
    operator: str = typer.Option(
        "",
        "--operator",
        help=(
            "Operator initials -- aggregates across that operator's sessions. "
            "Ignored when --session is also passed. When set, "
            "session_duration_seconds is null because spanning multiple "
            "sessions makes a single duration meaningless."
        ),
    ),
    since: str = typer.Option(
        "", "--since", help="Duration spec like 24h, 7d, 30d, 1w, 2y."
    ),
    command: str = typer.Option(
        "", "--command", help="Substring match against the `command` field."
    ),
    incident: str = typer.Option(
        "", "--incident", help="Filter records where anchor_incident == ID."
    ),
    by_actor: bool = typer.Option(
        False,
        "--by-actor",
        help=(
            "Add a nested by_actor breakdown to invocations / hunt_ratio "
            "/ failure_rate, plus a sibling cpu_usage_total_by_actor key "
            "(cpu_usage_total itself stays a string). session_duration_seconds and "
            "table_coverage_gaps stay session-global because per-actor "
            "windows / library coverage are misleading at actor granularity."
        ),
    ),
) -> None:
    """Aggregate metrics over filtered invocation records."""
    app_ctx: AppContext = ctx.obj

    # ------------------------------------------------------------------
    # Resolve session(s) — same precedence rules as the browse callback.
    # ------------------------------------------------------------------
    if session and operator:
        err_console.print(
            "[yellow]--session takes precedence; --operator ignored[/yellow]"
        )

    multi_session = False
    session_ids: list[str]
    if session:
        session_ids = [session]
    elif operator:
        session_ids = [row["id"] for row in list_sessions(operator=operator)]
        # Operator scope spans multiple session files; even if only one
        # matches today, the *intent* is multi-session aggregation, so
        # session_duration_seconds is null.
        multi_session = True
    else:
        active = current_session()
        if active is None:
            raise ConflictError(
                "No active session is unambiguously available for history.",
                suggestions=[
                    {
                        "reason": "explicit_session",
                        "message": "Pass --session <id> or --operator <initials>.",
                        "confidence": "exact",
                    }
                ],
                help_command="xdr session list",
            )
        session_ids = [active.id]

    since_delta: timedelta | None = None
    if since:
        since_delta = _parse_since(since)

    records = list(
        _iter_filtered_records(
            session_ids=session_ids,
            since=since_delta,
            command=command,
            incident=incident,
        )
    )

    # ------------------------------------------------------------------
    # Compute metrics.
    # ------------------------------------------------------------------
    library_index = _library_table_index()
    gaps, indeterminate = _compute_table_coverage_gaps(records, library_index)

    invocations_block = _compute_invocations(records)
    hunt_ratio_block = _compute_hunt_ratio(records)
    cpu_total = _compute_cpu_total(records)
    failure_block = _compute_failure_rate(records)
    duration = (
        None if multi_session else _compute_session_duration(records)
    )

    if by_actor:
        buckets = _bucket_by_actor(records)
        invocations_block["by_actor"] = {
            actor: _compute_invocations(bucket)
            for actor, bucket in buckets.items()
        }
        hunt_ratio_block["by_actor"] = {
            actor: _compute_hunt_ratio(bucket)
            for actor, bucket in buckets.items()
        }
        failure_block["by_actor"] = {
            actor: _compute_failure_rate(bucket)
            for actor, bucket in buckets.items()
        }
        cpu_by_actor = {
            actor: _compute_cpu_total(bucket)
            for actor, bucket in buckets.items()
        }
    else:
        cpu_by_actor = None

    data: dict[str, Any] = {
        "invocations": invocations_block,
        "hunt_ratio": hunt_ratio_block,
        "cpu_usage_total": cpu_total,
        "table_coverage_gaps": gaps,
        "failure_rate": failure_block,
        "session_duration_seconds": duration,
    }
    if cpu_by_actor is not None:
        # cpu_usage_total is a string — sibling key keeps the JSON shape
        # uniform (no mixed-type "either string or dict" field). Documented
        # on --by-actor help text.
        data["cpu_usage_total_by_actor"] = cpu_by_actor

    metadata: dict[str, Any] = {"records_considered": len(records)}
    if indeterminate:
        metadata["table_coverage_indeterminate"] = indeterminate

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(data, metadata=metadata))
