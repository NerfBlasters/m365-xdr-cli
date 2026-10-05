"""Session lifecycle commands: start, end, resume, list, show."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Literal

import click

from xdr_cli.cli_params import optional_multiple
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    AuthError,
    ConflictError,
    LocalNotFoundError,
    PartialSuccessError,
    PermissionError,
    XDRError,
    format_error_json,
)
from xdr_cli.output import OutputFormatter
from xdr_cli.sessions import (
    FEEDBACK_CATEGORIES,
    FEEDBACK_OUTCOMES,
    append_session_feedback,
    clear_current_session,
    create_session,
    current_session,
    find_active_sessions,
    list_sessions,
    load_session_metadata,
    load_session_records,
    resolve_operator_upn,
    session_already_ended,
    set_current_session,
    write_session_end_record,
)

session_app = click.Group(
    name="session",
    help="Per-hunt session lifecycle: start, end, resume, list, show.",
    no_args_is_help=True,
)


@session_app.command("start")
@click.option("--label", default="", help="Short label for this session.")
@click.option(
    "--learning-mode", is_flag=True, help="Require xdr annotate after each command in this session."
)
@click.option(
    "--quiet",
    is_flag=True,
    help=(
        "Reserved for banner suppression (no banner currently exists; the bare "
        "ID on stdout is suitable for $(xdr session start --quiet) capture "
        "as-is)."
    ),
)
@click.option(
    "--timeout",
    type=click.IntRange(min=1, max=None),
    default=1800,
    show_default=True,
    help="Inactivity timeout in seconds (default 1800 / 30 minutes).",
)
@click.option(
    "--concurrent", is_flag=True, help="Preserve active sessions and deliberately create another."
)
@click.pass_context
def session_start(
    ctx: click.Context,
    label: str,
    learning_mode: bool,
    quiet: bool,
    timeout: int,
    concurrent: bool,
) -> None:
    """Start a new session.

    Prints the session ID to stdout and writes a marker at
    ~/.xdr-cli/active_sessions/<id> so subsequent `xdr` invocations in any
    process can resolve the session without an environment variable.
    Two terminals running concurrent investigations each write their own
    marker — no shared pointer file to race on.
    """
    del quiet  # accepted for caller compat
    if ctx.obj.config.backend_profile.cookie_auth:
        from xdr_cli.portal_auth import load_portal_cookies

        if load_portal_cookies(ctx.obj.config.tenant_id) is None:
            raise AuthError(
                "No stored portal cookies. Import a browser session first.",
                help_command="xdr auth portal-cookie --help",
            )
        # Cookie storage does not attest an operator UPN. Never borrow an
        # unrelated account from the official backend's MSAL cache.
        upn = "automatic"
    else:
        upn = resolve_operator_upn(api_backend=ctx.obj.config.api_backend)
    if upn is None:
        raise AuthError(
            "No cached account. Run 'xdr auth login' first.",
            help_command="xdr auth login --help",
        )
    if not concurrent:
        active = current_session()
        sessions_to_rotate = [active] if active is not None else find_active_sessions()
        for prior in sessions_to_rotate:
            if ctx.obj.recorder is not None:
                ctx.obj.recorder.skip_record()
            write_session_end_record(prior, end_reason="manual-rotation")
            clear_current_session(prior.id)
    s = create_session(
        upn=upn,
        label=label or None,
        learning_mode=learning_mode,
        timeout_seconds=timeout,
        automatic=False,
    )
    click.echo(s.id)
    if concurrent:
        click.echo(
            f"Attach POSIX: XDR_SESSION={s.id} xdr ...\n"
            f'Attach PowerShell: $env:XDR_SESSION = "{s.id}"',
            err=True,
        )


def _collect_after_explicit_end(app_ctx: AppContext) -> dict:
    """Maintenance cannot undo a durable session end or attach to another session."""
    if (
        not getattr(app_ctx.config, "_maintenance_config_error", None)
        and not app_ctx.config.schema_collect_on_session_end
    ):
        return {"status": "skipped", "reason": "disabled"}
    if not app_ctx.config.tenant_id:
        return {"status": "skipped", "reason": "unconfigured-tenant"}
    maintenance: dict = {"status": "success"}

    def capture(artifact):
        receipt = artifact.receipt.to_dict()
        # This command emits no collection preview rows.
        receipt["context"]["shown"] = 0
        receipt["context"]["has_more"] = receipt["rows"] > 0
        maintenance["result"] = receipt

    clean_ctx = AppContext(
        config=app_ctx.config, no_interactive=True,
        quiet=app_ctx.quiet, debug=app_ctx.debug, invoked_command="schema collect",
    )
    if not app_ctx.effective_quiet:
        click.echo("Session ended. Collecting schema evidence…", err=True)
    try:
        from xdr_cli.schema_graph.session_maintenance import collect_session_schema

        app_ctx.config.check_maintenance_config()
        collect_session_schema(clean_ctx, on_result=capture)
    except (KeyboardInterrupt, asyncio.CancelledError) as exc:
        maintenance.update(
            status="cancelled", exit_code=130, error_type=type(exc).__name__,
            error_code="SESSION_SCHEMA_MAINTENANCE_CANCELLED",
        )
    except XDRError as exc:
        maintenance.update(
            status="partial" if exc.exit_code == 14 else "failed",
            exit_code=int(exc.exit_code), error_type=type(exc).__name__,
            retry_after_seconds=exc.retry_after_seconds,
            error_code=exc.error_code, help_command=exc.help_command or (
                "xdr auth status" if isinstance(exc, AuthError) else None
            ),
        )
        if isinstance(exc.__cause__, XDRError):
            cause = exc.__cause__
            maintenance["cause"] = {
                "exit_code": int(cause.exit_code), "error_type": type(cause).__name__,
                "error_code": cause.error_code, "help_command": cause.help_command or (
                    "xdr auth status" if isinstance(cause, AuthError) else None
                ),
                "suggested_fix": cause.suggested_fix,
            }
    except Exception as exc:
        maintenance.update(status="failed", exit_code=1, error_type=type(exc).__name__)
    if maintenance["status"] != "success":
        maintenance["next_command"] = maintenance.get("help_command") or "xdr schema collect"
        click.echo(
            "Session remains ended; schema collection " + maintenance["status"]
            + ". See maintenance in the receipt for recovery details.", err=True,
        )
    return maintenance


@session_app.command("end")
@click.option(
    "--force",
    is_flag=True,
    help="Override actor restriction. Required when XDR_ACTOR != 'operator'.",
)
@click.option(
    "--no-maintenance", is_flag=True, help="Skip schema upkeep for this session end only."
)
@click.pass_context
def session_end(
    ctx: click.Context,
    force: bool,
    no_maintenance: bool,
) -> None:
    """End the current session.

    Idempotent: if a session_ended marker already exists in the JSONL, refuses
    with a clear error (defends against double-end races between sub-agents).

    Actor-restricted: refuses when XDR_ACTOR is set to anything other than
    'operator' unless --force is passed. Only the orchestrator should end a
    session -- a sub-agent ending the session cuts off siblings' ability to
    write records and clear gates.
    """
    s = current_session()
    if s is None:
        env_id = os.environ.get("XDR_SESSION", "").strip()
        if env_id and session_already_ended(env_id):
            raise ConflictError(f"Session {env_id} is already ended.")
        click.echo(
            '{"status":"success","session_id":null,"ended":false,'
            '"reason":"no active session"}'
        )
        return

    actor = os.environ.get("XDR_ACTOR", "operator")
    if actor != "operator" and not force:
        raise PermissionError(
            f"Actor {actor!r} cannot end the shared session without --force.",
            corrected_argv=["xdr", "session", "end", "--force"],
            help_command="xdr session end --help",
        )

    if session_already_ended(s.id):
        raise ConflictError(f"Session {s.id} is already ended.")

    if ctx.obj.recorder is not None:
        ctx.obj.recorder.skip_record()
    final_seq = write_session_end_record(s)
    if final_seq is None:
        # Lost the race between the outer pre-check and the JSONL lock —
        # another process wrote the session_ended marker first. Surface the
        # same user-facing error as the outer check.
        raise ConflictError(f"Session {s.id} is already ended.")
    clear_current_session(s.id)
    receipt = {
        "status": "success",
        "record_type": "session-end",
        "ended": True,
        "session_id": s.id,
        "final_seq": final_seq,
        "end_reason": "explicit",
        "next_action": {
            "message": (
                "Append your agent assessment now. If the analyst supplies "
                "additional feedback later, append a new --source analyst "
                "record. Never replace prior feedback."
            ),
            "allowed_outcomes": sorted(FEEDBACK_OUTCOMES),
            "allowed_categories": sorted(FEEDBACK_CATEGORIES),
            "agent_command_template": (
                f"xdr session feedback {s.id} --source agent "
                "--outcome <outcome> [--category <category>] "
                "--comment \"<assessment>\""
            ),
            "analyst_command_template": (
                f"xdr session feedback {s.id} --source analyst "
                "--outcome <outcome> [--category <category>] "
                "--comment \"<analyst feedback>\""
            ),
        },
    }
    click.echo(json.dumps(receipt, separators=(",", ":")))
    sys.stdout.flush()
    maintenance = (
        {"status": "skipped", "reason": "requested"}
        if no_maintenance else _collect_after_explicit_end(ctx.obj)
    )
    incomplete = maintenance["status"] not in ("success", "skipped")
    cancelled = maintenance["status"] == "cancelled"
    terminal = {
        "status": "partial" if incomplete else "success",
        "record_type": "session-maintenance",
        "session_id": s.id,
        "maintenance": maintenance,
    }
    if incomplete:
        failure = PartialSuccessError(
            "Session ended durably; schema maintenance did not complete.",
            help_command=maintenance["next_command"],
            retry_after_seconds=maintenance.get("retry_after_seconds"),
            original={key: value for key, value in maintenance.items() if key != "result"},
        )
        if cancelled:
            failure.exit_code = 130
            failure.error_code = "SESSION_SCHEMA_MAINTENANCE_CANCELLED"
        terminal["error"] = json.loads(format_error_json(failure))["error"]
    click.echo(json.dumps(terminal, separators=(",", ":")))
    sys.stdout.flush()
    if incomplete:
        # The terminal record already contains the structured error. A Click
        # Exit would make the root boundary append a third legacy error row.
        raise SystemExit(130 if cancelled else 14)


@session_app.command("feedback")
@click.argument("session_id", type=str, required=True, help="Ended or active session ID.")
@click.option(
    "--source", type=click.Choice(["agent", "analyst"], case_sensitive=True), required=True
)
@click.option(
    "--outcome",
    type=click.Choice(
        ["completed-smoothly", "completed-with-friction", "incomplete-blocked"], case_sensitive=True
    ),
    required=True,
)
@click.option("--category", default=None, multiple=True, callback=optional_multiple)
@click.option("--comment", default=None)
@click.pass_context
def session_feedback(
    ctx: click.Context,
    session_id: str,
    source: Literal["agent", "analyst"],
    outcome: Literal["completed-smoothly", "completed-with-friction", "incomplete-blocked"],
    category: list[str] | None,
    comment: str | None,
) -> None:
    """Append immutable feedback; prior feedback is never overwritten."""
    del ctx
    try:
        record = append_session_feedback(
            session_id,
            source=source,
            outcome=outcome,
            categories=list(category or []),
            comment=comment,
        )
    except FileNotFoundError:
        raise LocalNotFoundError("session", session_id) from None
    click.echo(json.dumps({"status": "success", "feedback": record}, separators=(",", ":")))


@session_app.command("resume")
@click.argument("session_id", type=str, required=True, help="Session ID to resume.")
@click.pass_context
def session_resume(
    ctx: click.Context,
    session_id: str,
) -> None:
    """Resume a prior session as current."""
    s = load_session_metadata(session_id)
    if s is None:
        raise LocalNotFoundError("session", session_id)
    if session_already_ended(session_id):
        raise ConflictError(
            f"Session {session_id} has ended and cannot be resumed. "
            "Feedback can still be appended with 'xdr session feedback'.",
            help_command="xdr session feedback --help",
        )
    set_current_session(s)
    click.echo(s.id)


@session_app.command("list")
@click.option("--operator", default="", help="Filter by operator initials (e.g., 'jd').")
@click.pass_context
def session_list(
    ctx: click.Context,
    operator: str,
) -> None:
    """List all sessions found under ~/.xdr-cli/sessions/."""
    app_ctx: AppContext = ctx.obj
    rows = list_sessions(operator or None)
    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    click.echo(fmt.format_output(rows))


@session_app.command("show")
@click.argument("session_id", type=str, required=True, help="Session ID to show.")
@click.pass_context
def session_show(
    ctx: click.Context,
    session_id: str,
) -> None:
    """Print the raw JSONL records for a session."""
    records = load_session_records(session_id)
    if records is None:
        raise LocalNotFoundError("session", session_id)
    for r in records:
        click.echo(r)
