"""Locally remembered Live Response sessions: list from state, refresh by lookup.

``list`` reads only the private handle store, so it needs no authentication or
network. ``refresh`` fetches each remembered session's native state once and
never closes, reconnects or retries anything. Neither claims to cover sessions
opened outside this CLI: no tenant-wide session listing contract is known.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import asdict

import click

from xdr_cli.auth import AuthManager
from xdr_cli.backend_contract import Backend, UnsupportedBackendCapability
from xdr_cli.backends import create_client
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    ConfigError,
    ForbiddenError,
    LiveResponseSessionNotFoundError,
    NetworkError,
    NotAuthenticatedError,
    PartialSuccessError,
    RateLimitError,
    TimeoutError,
    UsageError,
    XDRError,
)
from xdr_cli.live_response import handles
from xdr_cli.results import emit_result, write_result

# Sessions are tracked in the portal-cookie namespace: only that backend opens them.
_NAMESPACE = "portal-cookie"
_DEVICE = re.compile(r"[0-9a-fA-F]{40}")
# A lookup failure of these kinds says nothing about one session, so stop there.
_SYSTEMIC = (NotAuthenticatedError, ForbiddenError, RateLimitError, NetworkError, TimeoutError,
             ConfigError)

_device_option = click.option(
    "--device", "machine_id", default=None, help="Only sessions for this MachineId."
)
_all_option = click.option(
    "--all", "include_closed", is_flag=True,
    help="Include sessions remembered as closed, failed or not found.",
)


def _require_sessions(ctx: AppContext, machine_id: str | None) -> None:
    if not ctx.config.backend_profile.lr_sessions:
        raise UnsupportedBackendCapability(
            "Interactive Live Response sessions need the portal-cookie backend. "
            "No request was sent and no authentication fallback was attempted.",
            suggested_fix="Use --backend portal-cookie with an imported portal cookie.",
        )
    if not ctx.config.tenant_id:
        # Remembered sessions are stored per tenant; without one there is nothing to read.
        raise ConfigError("Live Response sessions need a configured tenant_id.")
    if machine_id is not None and not _DEVICE.fullmatch(machine_id):
        raise UsageError("--device must be a 40-character MachineId.",
                         invalid={"kind": "identifier", "param": "machine_id"})


def _row(session, **extra) -> dict:
    """Public projection; raw payloads stay private."""
    data = asdict(session)
    data.pop("raw", None)
    # "unknown" for native states the CLI cannot map, never a guessed closed state.
    return {**data, "activity": handles.session_activity(session), **extra}


def _remembered(ctx: AppContext, machine_id: str | None, include_closed: bool,
                problems: list[dict]) -> list:
    """Readable remembered sessions; unreadable handles are counted in ``problems``."""
    sessions = handles.iter_sessions(ctx.config.tenant_id, _NAMESPACE, machine_id,
                                     problems=problems)
    return [s for s in sessions if include_closed or handles.is_active_session(s)]


def _emit_rows(ctx: AppContext, rows: list[dict], context: dict,
               problems: list[dict]) -> None:
    if problems:
        context = {**context, "unreadable_handles": len(problems)}
    artifact = write_result(
        rows, command=ctx.invoked_command or "device live-response sessions",
        tenant_id=ctx.config.tenant_id, session_id=ctx.session_id,
        session_label=ctx.session_label, session_attachment=ctx.session_attachment,
        server_truncation_state="known-truncated" if problems else "known-complete",
        extra_metadata={"api_backend": ctx.config.api_backend, **context},
        receipt_context=context,
    )
    emit_result(artifact)


def _unreadable(problems: list[dict]) -> PartialSuccessError:
    return PartialSuccessError(
        f"{len(problems)} remembered session handle(s) could not be read, so this list "
        "may be incomplete. Inspect ~/.xdr-cli/live_response before relying on it.",
    )


def _list(ctx: AppContext, machine_id: str | None, include_closed: bool) -> None:
    _require_sessions(ctx, machine_id)
    problems: list[dict] = []
    rows = [_row(s) for s in _remembered(ctx, machine_id, include_closed, problems)]
    _emit_rows(ctx, rows, {
        "coverage": "locally-known-sessions", "verification": "cached",
        "scope": "all" if include_closed else "active",
        "refresh_command": "xdr --backend portal-cookie device live-response sessions refresh",
    }, problems)
    if problems:
        raise _unreadable(problems)


@click.group("sessions", invoke_without_command=True)
@_device_option
@_all_option
@click.pass_context
def sessions_app(click_ctx: click.Context, machine_id: str | None, include_closed: bool) -> None:
    """Live Response sessions this CLI remembers (local state; no tenant-wide list).

    With no subcommand, lists the remembered active sessions, like ``list``.
    """
    if click_ctx.invoked_subcommand is None:
        _list(click_ctx.obj, machine_id, include_closed)


def _inherited_device(click_ctx: click.Context, machine_id: str | None) -> str | None:
    """Apply a group-level --device to the subcommand; a different value is refused."""
    parent = click_ctx.parent.params.get("machine_id") if click_ctx.parent else None
    if parent is not None and machine_id is not None and parent.lower() != machine_id.lower():
        raise UsageError("Give --device once, before or after the subcommand.",
                         invalid={"kind": "conflicting_options", "value": "--device"})
    return machine_id if machine_id is not None else parent


@sessions_app.command("list")
@_device_option
@_all_option
@click.pass_context
def sessions_list(click_ctx: click.Context, machine_id: str | None,
                  include_closed: bool) -> None:
    """List remembered sessions from local state, with no network or authentication.

    States are as last seen by this CLI; run ``sessions refresh`` to check them.
    """
    parent_all = bool(click_ctx.parent and click_ctx.parent.params.get("include_closed"))
    _list(click_ctx.obj, _inherited_device(click_ctx, machine_id),
          include_closed or parent_all)


@sessions_app.command("refresh")
@_device_option
@click.pass_context
def sessions_refresh(click_ctx: click.Context, machine_id: str | None) -> None:
    """Look up each remembered active session's current state (read-only).

    Sessions the service no longer knows are marked not found. A failed lookup
    never marks a session closed; it keeps the remembered state. Nothing is
    closed or reconnected.
    """
    ctx: AppContext = click_ctx.obj
    if click_ctx.parent and click_ctx.parent.params.get("include_closed"):
        raise UsageError("refresh checks only sessions remembered as active; --all applies "
                         "to list.", invalid={"kind": "conflicting_options", "value": "--all"})
    machine_id = _inherited_device(click_ctx, machine_id)
    _require_sessions(ctx, machine_id)
    problems: list[dict] = []
    sessions = _remembered(ctx, machine_id, False, problems)
    if not sessions:
        _emit_rows(ctx, [], _refresh_context(0, 0, 0, 0), problems)
        if problems:
            raise _unreadable(problems)
        return
    asyncio.run(_refresh(ctx, sessions, problems))


def _refresh_context(checked: int, not_checked: int, not_found: int, errors: int) -> dict:
    return {
        "coverage": "locally-known-sessions", "verification": "remote",
        "checked": checked, "not_checked": not_checked,
        "not_found": not_found, "errors": errors,
    }


async def _refresh(ctx: AppContext, sessions: list, problems: list[dict]) -> None:
    client: Backend = create_client(
        ctx.config, timeout=ctx.config.api_timeout,
        auth_factory=AuthManager, client_factory=XDRClient,
    )
    rows: list[dict] = []
    failures: list[XDRError] = []
    systemic: XDRError | None = None
    try:
        for session in sessions:
            previous = {"previous_state": session.state}
            if systemic is not None:
                rows.append(_row(session, **previous, verification="not-checked",
                                 refresh_error=None))
                continue
            try:
                current = await client.lr_get_session(session.session_id)
                rows.append(_row(current, **previous, verification="remote",
                                 refresh_error=None))
            except LiveResponseSessionNotFoundError:
                # Only the session route's own 404; any other not-found is an error row.
                try:
                    missing = handles.mark_session_missing(
                        ctx.config.tenant_id, _NAMESPACE, session.session_id
                    )
                    rows.append(_row(missing, **previous, verification="not-found",
                                     refresh_error=None))
                except XDRError as error:
                    failures.append(error)
                    rows.append(_row(session, **previous, verification="error",
                                     refresh_error=error.error_code))
            except _SYSTEMIC as error:
                systemic = error
                failures.append(error)
                rows.append(_row(session, **previous, verification="error",
                                 refresh_error=error.error_code))
            except XDRError as error:
                failures.append(error)
                rows.append(_row(session, **previous, verification="error",
                                 refresh_error=error.error_code))
    finally:
        await client.close()
    verified = [r for r in rows if r["verification"] in ("remote", "not-found")]
    if systemic is not None and not verified:
        raise systemic
    counts = {name: sum(r["verification"] == name for r in rows)
              for name in ("not-checked", "not-found", "error")}
    _emit_rows(ctx, rows, _refresh_context(
        len(verified), counts["not-checked"], counts["not-found"], counts["error"],
    ), problems)
    if problems and not failures:
        raise _unreadable(problems)
    if failures:
        partial = PartialSuccessError(
            "Some remembered sessions could not be checked; their remembered state "
            "is unchanged. Inspect rows whose verification is not remote.",
            help_command="xdr --backend portal-cookie device live-response sessions refresh",
        )
        partial.retry_after_seconds = next(
            (e.retry_after_seconds for e in failures if e.retry_after_seconds is not None),
            None,
        )
        raise partial from failures[0]
