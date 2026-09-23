"""Hunt commands: run KQL queries and manage the query library."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer

from xdr_cli._recording import _parse_execution_time_ms, run_kql_with_recording
from xdr_cli.api.hunting import run_query
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import UsageError
from xdr_cli.queries import load_query, parse_frontmatter, query_source_hash
from xdr_cli.results import emit_result, write_result
from xdr_cli.schema_graph.ingest import infer_direct_table_lineage

hunt_app = typer.Typer(
    name="hunt",
    help="Advanced hunting with KQL queries.",
    no_args_is_help=True,
)


@hunt_app.command("run")
def hunt_run(
    ctx: typer.Context,
    kql: str | None = typer.Argument(
        None,
        help="Inline KQL query string.",
    ),
    from_file: Path | None = typer.Option(
        None,
        "--from-file",
        help="Read KQL from a file.",
    ),
    from_stdin: bool = typer.Option(
        False,
        "--from-stdin",
        help="Read KQL from stdin.",
    ),
    raw: bool = typer.Option(
        False,
        "--raw",
        help=(
            "Keep JSON-string columns (RawEventData, AdditionalFields, "
            "ResourceData) as raw strings instead of parsing them into "
            "objects. Use when piping verbatim to another tool."
        ),
    ),
    timeout: int | None = typer.Option(
        None,
        "--timeout",
        help=(
            "Per-call HTTP timeout in seconds. Overrides config.api_timeout "
            "(default 120). Bump for hunts that aggregate or join across large "
            "tables — these can run 30-90s+ on Defender."
        ),
    ),
) -> None:
    """Run a KQL advanced hunting query."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(
        _hunt_run_with_source(app_ctx, kql, from_file, from_stdin, raw, timeout)
    )


async def _hunt_run_with_source(
    ctx: AppContext,
    kql: str | None,
    from_file: Path | None,
    from_stdin: bool,
    raw: bool,
    timeout: int | None = None,
) -> None:
    """Resolve the KQL source and dispatch to ``_hunt_run``."""
    if from_stdin:
        _, query = parse_frontmatter(sys.stdin.read())
    elif from_file:
        _, query = parse_frontmatter(from_file.read_text(encoding="utf-8"))
    elif kql:
        query = kql
    else:
        raise UsageError(
            "Provide a KQL query as an argument, --from-file, or --from-stdin.",
            allowed=["KQL", "--from-file", "--from-stdin"],
            help_command="xdr hunt run --help",
        )

    await _hunt_run(ctx, query, raw=raw, timeout=timeout)


async def _hunt_run(
    ctx: AppContext,
    kql: str,
    *,
    raw: bool = False,
    library_query: str | None = None,
    params: dict | None = None,
    timeout: int | None = None,
) -> None:
    """Execute a KQL query and emit the formatted result envelope.

    Thin wrapper over :func:`run_kql_with_recording` — the helper handles all
    recorder annotations (kql, tables_referenced, library_query, params,
    columns_projected, result.*); this function only owns the stdout
    formatting.

    Recorder semantics (Task 4 / 4.5):

    * ``kql``, ``tables_referenced``, ``library_query``, ``params``,
      ``columns_projected`` are annotated when a session is active.
      ``tables_referenced`` is best-effort — :func:`extract_tables` (called
      inside the helper) is fail-soft and returns ``[]`` on any unparseable
      input, never raising, so the field is always a list (possibly empty)
      rather than ``None``.
    * ``result.row_count`` / ``execution_time_ms`` / ``cpu_usage`` /
      ``has_more`` / ``sample_rows`` are annotated as a single ``result``
      dict after the API call returns.
    * ``--raw`` semantics: ``sample_rows`` reflects exactly what the operator
      saw on stdout. With ``--raw``, JSON-string columns stay as raw strings;
      without ``--raw``, they are expanded into nested objects. This is a
      deliberate design choice — the training map should record the agent's
      actual perspective, not a normalised view.
    """
    # Top-level hunt run: write annotations onto the parent recorder
    # (ctx.recorder), which run() flushes in its try/finally. No anchor.
    auth = AuthManager(ctx.config)
    effective_timeout = timeout if timeout is not None else ctx.config.api_timeout
    client = XDRClient(get_token=auth.get_token, timeout=effective_timeout)
    try:
        recorded = await run_kql_with_recording(
            ctx,
            kql=kql,
            invoked_command=ctx.invoked_command or "hunt run",
            library_query=library_query,
            params=params,
            anchor_incident=None,
            expand_json=not raw,
            display_limit=None,
            child_recorder=False,
            # Closure keeps the test patch on hunt_cmd.run_query effective —
            # the helper deliberately does not import run_query itself.
            runner=lambda: run_query(client, kql),
        )
    finally:
        await client.close()
    result = recorded.api_result
    expanded = recorded.display_rows

    # execution_time_ms: prefer stats["ExecutionTime"] when the API includes
    # it (rare — Graph's runHuntingQuery documents only schema/results;
    # neither endpoint reliably surfaces stats), fall back to client-measured
    # wall-clock so the field is always populated. cpu_usage is intentionally
    # not in the envelope: it's a tenant-wide quota concept ("10 min/hour")
    # and the per-call response doesn't expose it on success — quota
    # exhaustion arrives as a 429 which our HTTPStatusError handler surfaces.
    api_ms = _parse_execution_time_ms(result.stats.get("ExecutionTime"))
    execution_time_ms = api_ms if api_ms is not None else recorded.wall_clock_ms
    artifact = write_result(
        expanded,
        command=ctx.invoked_command or "hunt run",
        execution_time_ms=execution_time_ms,
        server_truncation_state="unknown",
        session_id=ctx.session_id,
        session_label=ctx.session_label,
        session_attachment=ctx.session_attachment,
        incident_id=ctx.anchor_incident,
        alert_id=ctx.anchor_alert,
        anchor_provenance=ctx.anchor_provenance,
        query=kql,
        library_entry=library_query,
        resolved_parameters=params,
        source_hash=query_source_hash(library_query) if library_query else None,
        extra_metadata={
            "api_schema": result.schema,
            "raw_json_string_columns": raw,
        },
        tenant_id=ctx.config.tenant_id,
        physical_lineage_table=infer_direct_table_lineage(kql),
    )
    emit_result(artifact)


@hunt_app.command("library")
def hunt_library(ctx: typer.Context) -> None:
    """Deprecated alias for ``xdr library list``."""
    from xdr_cli.commands.library_cmd import library_list

    typer.echo("warning: use 'xdr library list'; this alias will be removed in 1.0", err=True)
    library_list(ctx, search=None, tier=None)


@hunt_app.command("library-run")
def hunt_library_run(
    ctx: typer.Context,
    name: str = typer.Argument(
        help="Query name from the library.",
    ),
    param: list[str] | None = typer.Option(
        None,
        "--param",
        "-p",
        help="Parameter as key=value. Repeatable.",
    ),
    raw: bool = typer.Option(
        False,
        "--raw",
        help=(
            "Keep JSON-string columns (RawEventData, AdditionalFields, "
            "ResourceData) as raw strings instead of parsing them into "
            "objects. Use when piping verbatim to another tool."
        ),
    ),
    timeout: int | None = typer.Option(
        None,
        "--timeout",
        help=(
            "Per-call HTTP timeout in seconds. Overrides config.api_timeout "
            "(default 120). Library hunts that aggregate or join across large "
            "tables may need 180-300s on busy tenants."
        ),
    ),
) -> None:
    """Deprecated alias for ``xdr library run``."""
    app_ctx: AppContext = ctx.obj
    typer.echo("warning: use 'xdr library run'; this alias will be removed in 1.0", err=True)

    # Parse params
    params: dict[str, str] = {}
    for p in param or []:
        if "=" not in p:
            raise UsageError(
                f"Invalid parameter {p!r}; use key=value.",
                invalid={"kind": "parameter", "value": p},
                corrected_argv=["--param", "key=value"],
                help_command=f"xdr library show {name}",
            )
        key, value = p.split("=", 1)
        params[key.strip()] = value.strip()

    kql = load_query(name, **params)

    asyncio.run(
        _hunt_run(
            app_ctx,
            kql,
            raw=raw,
            library_query=name,
            params=params,
            timeout=timeout,
        )
    )


@hunt_app.command("library-show")
def hunt_library_show(
    ctx: typer.Context,
    name: str = typer.Argument(
        help="Query name from the library.",
    ),
    param: list[str] | None = typer.Option(
        None,
        "--param",
        "-p",
        help="Parameter as key=value. Repeatable.",
    ),
) -> None:
    """Render a library query without executing it.

    Prints the fully-substituted KQL (params resolved, list-blocks prepended)
    to stdout. No API call, no auth required. Useful for debugging param
    substitution or pasting into the Defender Advanced Hunting GUI to compare
    behaviour against the CLI execution path.
    """
    params: dict[str, str] = {}
    for p in param or []:
        if "=" not in p:
            raise UsageError(
                f"Invalid parameter {p!r}; use key=value.",
                invalid={"kind": "parameter", "value": p},
                corrected_argv=["--param", "key=value"],
                help_command=f"xdr library show {name}",
            )
        key, value = p.split("=", 1)
        params[key.strip()] = value.strip()

    kql = load_query(name, **params)
    typer.echo(kql)
