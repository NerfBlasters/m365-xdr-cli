"""Session lifecycle commands: start, end, resume, list, show."""

from __future__ import annotations

import json
import os
from typing import Literal

import click
import typer

from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    AuthError,
    ConflictError,
    LocalNotFoundError,
    PermissionError,
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

session_app = typer.Typer(
    name="session",
    help="Per-hunt session lifecycle: start, end, resume, list, show.",
    no_args_is_help=True,
)


@session_app.command("start")
def session_start(
    ctx: typer.Context,
    label: str = typer.Option("", "--label", help="Short label for this session."),
    learning_mode: bool = typer.Option(
        False,
        "--learning-mode",
        help="Require xdr annotate after each command in this session.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        help=(
            "Reserved for banner suppression (no banner currently exists; "
            "the bare ID on stdout is suitable for "
            "$(xdr session start --quiet) capture as-is)."
        ),
    ),
    timeout: int = typer.Option(
        1800,
        "--timeout",
        min=1,
        help="Inactivity timeout in seconds (default 1800 / 30 minutes).",
    ),
    concurrent: bool = typer.Option(
        False,
        "--concurrent",
        help="Preserve active sessions and deliberately create another.",
    ),
) -> None:
    """Start a new session.

    Prints the session ID to stdout and writes a marker at
    ~/.xdr-cli/active_sessions/<id> so subsequent `xdr` invocations in any
    process can resolve the session without an environment variable.
    Two terminals running concurrent investigations each write their own
    marker — no shared pointer file to race on.
    """
    del quiet  # accepted for caller compat
    upn = resolve_operator_upn()
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
    typer.echo(s.id)
    if concurrent:
        typer.echo(
            f"Attach POSIX: XDR_SESSION={s.id} xdr ...\n"
            f'Attach PowerShell: $env:XDR_SESSION = "{s.id}"',
            err=True,
        )


@session_app.command("end")
def session_end(
    ctx: typer.Context,
    force: bool = typer.Option(
        False,
        "--force",
        help="Override actor restriction. Required when XDR_ACTOR != 'operator'.",
    ),
    prompt_feedback: bool = typer.Option(
        False,
        "--prompt-feedback",
        help="After ending safely, interactively append analyst feedback.",
    ),
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
        typer.echo(
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
    typer.echo(json.dumps(receipt, separators=(",", ":")))

    if prompt_feedback and ctx.obj.is_interactive:
        selection = typer.prompt(
            "Outcome",
            type=click.Choice(
                [
                    "completed-smoothly",
                    "completed-with-friction",
                    "incomplete-blocked",
                    "skip",
                ],
                case_sensitive=True,
            ),
            default="skip",
            show_choices=True,
        )
        if selection != "skip":
            category = typer.prompt(
                "Category",
                type=click.Choice(
                    ["none", *sorted(FEEDBACK_CATEGORIES)],
                    case_sensitive=True,
                ),
                default="none",
                show_choices=True,
            )
            comment = typer.prompt("Comment (optional)", default="")
            append_session_feedback(
                s.id,
                source="analyst",
                outcome=selection,
                categories=[] if category == "none" else [category],
                comment=comment or None,
                input_mode="interactive-cli",
            )


@session_app.command("feedback")
def session_feedback(
    ctx: typer.Context,
    session_id: str = typer.Argument(help="Ended or active session ID."),
    source: Literal["agent", "analyst"] = typer.Option(..., "--source"),
    outcome: Literal[
        "completed-smoothly",
        "completed-with-friction",
        "incomplete-blocked",
    ] = typer.Option(..., "--outcome"),
    category: list[str] | None = typer.Option(None, "--category"),
    comment: str | None = typer.Option(None, "--comment"),
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
    typer.echo(json.dumps({"status": "success", "feedback": record}, separators=(",", ":")))


@session_app.command("resume")
def session_resume(
    ctx: typer.Context,
    session_id: str = typer.Argument(help="Session ID to resume."),
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
    typer.echo(s.id)


@session_app.command("list")
def session_list(
    ctx: typer.Context,
    operator: str = typer.Option(
        "", "--operator", help="Filter by operator initials (e.g., 'jd')."
    ),
) -> None:
    """List all sessions found under ~/.xdr-cli/sessions/."""
    app_ctx: AppContext = ctx.obj
    rows = list_sessions(operator or None)
    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(rows))


@session_app.command("show")
def session_show(
    ctx: typer.Context,
    session_id: str = typer.Argument(help="Session ID to show."),
) -> None:
    """Print the raw JSONL records for a session."""
    records = load_session_records(session_id)
    if records is None:
        raise LocalNotFoundError("session", session_id)
    for r in records:
        typer.echo(r)
