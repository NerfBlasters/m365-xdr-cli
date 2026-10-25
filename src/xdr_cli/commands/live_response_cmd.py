"""Live Response commands: remote console sessions, command jobs and the file library.

Every console line is parsed and classified locally before anything is sent.
Commands that move data off the device, place files, execute scripts or act
on the device need confirmation (or ``--yes``); ``--dry-run`` validates
against the pinned catalog without authentication or network activity.
Submissions are never replayed after a timeout or transport loss.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import asdict
from pathlib import Path
from time import monotonic

import click

from xdr_cli.auth import AuthManager
from xdr_cli.backend_contract import Backend, UnsupportedBackendCapability
from xdr_cli.backends import create_client
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import ArtifactError, ConflictError, NotFoundError, UsageError, XDRError
from xdr_cli.live_response.catalog import LIBRARY_NAME_PATTERN, PINNED, catalog, merge_definitions
from xdr_cli.live_response.models import (
    CONFIRM_RISKS,
    LRCommandState,
    LRPlatform,
    LRRisk,
    ParsedCommand,
)
from xdr_cli.live_response.parser import build_command, parse_console_line
from xdr_cli.live_response.transfer import download_transfer
from xdr_cli.output import OutputFormatter, err_console
from xdr_cli.package_download import DEFAULT_MAX_BYTES, package_destination
from xdr_cli.results import emit_result, write_result

live_response_app = click.Group(
    name="live-response",
    help=(
        "Live Response sessions: inspect, search, fetch and place files, run library scripts.\n\n"
        "Interactive sessions need the portal-cookie backend. Console commands are "
        "classified locally; anything beyond a read needs confirmation or --yes."
    ),
    no_args_is_help=True,
)
library_app = click.Group(
    name="library", help="Tenant Live Response file library.", no_args_is_help=True,
)
live_response_app.add_command(library_app)

_PREFIX = "xdr device live-response"
_PORTAL_PREFIX = "xdr --backend portal-cookie device live-response"
_OFFICIAL_PREFIX = "xdr --backend official device live-response"
_POLL_SECONDS = 2.0
# Console text read from a file or stdin; one command, so a small cap suffices.
_MAX_COMMAND_BYTES = 64 * 1024
_MAX_OUTPUT_SAVE_BYTES = 256 * 1024 * 1024

_wait_option = click.option(
    "--wait", "wait_seconds", type=click.IntRange(min=0, max=3600), default=0, show_default=True,
    help="Poll up to this many seconds for a terminal state (0 returns immediately).",
)
_yes_option = click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
_dry_run_option = click.option(
    "--dry-run", is_flag=True, help="Validate and show what would be sent; no network.",
)
_session_argument = click.argument("session_id", type=str, required=True)
_command_id_argument = click.argument("command_id", type=str, required=True)
_output_path = click.Path(path_type=Path, dir_okay=False, allow_dash=False)

# Identifier shapes, checked locally so a dry-run fails for IDs the real call rejects.
_ID_SHAPES = {
    "machine_id": (re.compile(r"[0-9a-fA-F]{40}"), "a 40-character MachineId"),
    "session_id": (re.compile(r"CLR[A-Za-z0-9_-]{1,125}"), "a V3 session ID starting with CLR"),
    "command_id": (re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"),
                   "a command GUID"),
    "action_id": (re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"),
                  "an action GUID"),
}


def _get_client(ctx: AppContext) -> Backend:
    return create_client(
        ctx.config, timeout=ctx.config.api_timeout,
        auth_factory=AuthManager, client_factory=XDRClient,
    )


def _emit_dry_run(ctx: AppContext, data: dict) -> None:
    for key, value in data.items():
        shape = _ID_SHAPES.get(key)
        if shape is not None and not shape[0].fullmatch(str(value)):
            raise UsageError(f"{key} must be {shape[1]}.", invalid={"kind": "identifier",
                                                                     "param": key})
    _emit(ctx, {"dry_run": True, **data})


def _formatter(ctx: AppContext) -> OutputFormatter:
    return OutputFormatter(session_id=ctx.session_id, session_label=ctx.session_label)


def _emit(ctx: AppContext, data: dict, **metadata) -> None:
    click.echo(_formatter(ctx).format_output(data, metadata=metadata or None))


def _emit_rows(ctx: AppContext, rows: list[dict], *, context: dict | None = None,
               state: str = "unknown", preview_rows: int = 2) -> None:
    artifact = write_result(
        rows, command=ctx.invoked_command or "device live-response",
        tenant_id=ctx.config.tenant_id, session_id=ctx.session_id,
        session_label=ctx.session_label, session_attachment=ctx.session_attachment,
        server_truncation_state=state,
        extra_metadata={"api_backend": ctx.config.api_backend, **(context or {})},
        receipt_context=context,
        preview_rows=preview_rows,
    )
    emit_result(artifact)


async def _collect(rows: AsyncIterator) -> list[dict]:
    return [row if isinstance(row, dict) else _record(row) async for row in rows]


def _record(value) -> dict:
    """Public projection of a typed result; raw payloads stay private."""
    data = asdict(value)
    data.pop("raw", None)
    return data


def _with_client(ctx: AppContext, work: Callable[[Backend], Awaitable[None]]) -> None:
    async def run() -> None:
        client = _get_client(ctx)
        try:
            await work(client)
        finally:
            await client.close()

    asyncio.run(run())


def _require_sessions(ctx: AppContext) -> None:
    if not ctx.config.backend_profile.lr_sessions:
        raise UnsupportedBackendCapability(
            "Interactive Live Response sessions need the portal-cookie backend. "
            "No request was sent and no authentication fallback was attempted.",
            suggested_fix="Use --backend portal-cookie with an imported portal cookie.",
        )


def _confirm(ctx: AppContext, parsed: ParsedCommand, target: str, yes: bool) -> None:
    if parsed.risk not in CONFIRM_RISKS:
        return
    _confirm_text(ctx, f"run '{parsed.verb}' ({parsed.risk.value})", target, yes)


def _confirm_text(ctx: AppContext, action: str, target: str, yes: bool) -> None:
    if yes:
        return
    if not ctx.is_interactive:
        raise UsageError(
            f"Non-interactive mode requires --yes to {action}.",
            invalid={"kind": "missing_option", "value": "--yes"},
            help_command=f"{_PREFIX} --help",
        )
    err_console.print(f"[bold yellow]About to {action} on {target}.[/bold yellow]")
    if not click.confirm("Proceed?"):
        raise ConflictError("Live Response operation was cancelled by the operator.")


def _read_text(text: str | None, path: Path | None, stdin: bool, *, what: str) -> str | None:
    """Return one of TEXT, a file's contents or stdin, without placing it in argv."""
    chosen = [value for value in (text is not None, path is not None, stdin) if value]
    if len(chosen) > 1:
        raise UsageError(f"Give the {what} only once (text, file or stdin).",
                         invalid={"kind": "conflicting_options"})
    if text is not None:
        return text
    if path is not None:
        try:
            with path.open("rb") as handle:
                data = handle.read(_MAX_COMMAND_BYTES + 1)
        except OSError:
            raise ArtifactError(f"Could not read the {what} file.") from None
    elif stdin:
        data = sys.stdin.buffer.read(_MAX_COMMAND_BYTES + 1)
    else:
        return None
    if len(data) > _MAX_COMMAND_BYTES:
        raise UsageError(f"The {what} is larger than {_MAX_COMMAND_BYTES} bytes.",
                         invalid={"kind": "too_large"})
    try:
        # Windows editors often prepend a BOM; it is never part of the command.
        decoded = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UsageError(f"The {what} must be UTF-8 text.", invalid={"kind": "encoding"}) from None
    # A single trailing newline from a file or pipe is not part of the command.
    return decoded.removesuffix("\n").removesuffix("\r")


def _local_help(ctx: AppContext, parsed: ParsedCommand) -> None:
    wanted = parsed.param("command")
    spec = PINNED.get(wanted.lower()) if wanted else None
    if wanted and spec is None:
        raise UsageError("Unknown Live Response command.", invalid={"kind": "unknown_command"},
                         help_command=f"{_PREFIX} catalog")
    rows = [_spec_row(spec)] if spec else [_spec_row(item) for item in catalog()]
    _emit(ctx, {"commands": rows})


def _spec_row(spec) -> dict:
    return {
        "command": spec.name, "aliases": list(spec.aliases), "risk": spec.risk.value,
        "risk_by_value": [
            {"param": param, "value": value, "risk": risk.value}
            for param, value, risk in spec.risk_by_value
        ],
        "platforms": sorted(platform.value for platform in spec.platforms),
        "summary": spec.summary,
        "params": [
            {"param_id": p.param_id, "label": p.label, "required": p.required,
             "choices": list(p.choices) if p.choices else None, "is_path": p.is_path}
            for p in spec.params
        ],
        "flags": [
            {"flag_id": f.flag_id, "short": f.short_name, "long": f.long_name}
            for f in spec.flags
        ],
        "official_type": spec.official_type, "advanced": spec.advanced,
        "local_note": spec.local_note, "evidence": spec.evidence,
    }


def _dry_run(ctx: AppContext, parsed: ParsedCommand, target: str) -> None:
    _emit_dry_run(ctx, {
        "session_id": target, **parsed.redacted_summary(),
        "requires_confirmation": parsed.risk in CONFIRM_RISKS,
        "validated_against": "pinned-catalog",
    })


def _audit_submission(ctx: AppContext, target: str, parsed: ParsedCommand) -> None:
    """Record the classified submission without any submitted values."""
    summary = parsed.redacted_summary()
    logging.getLogger("xdr.audit").info(
        "LR: chain=%s target=%s verb=%s risk=%s params=%s flags=%s background=%s",
        ctx.invoked_command, target, summary["verb"], summary["risk"],
        ",".join(summary["params"]) or "-", ",".join(summary["flags"]) or "-",
        summary["background"],
    )


def _state_record(state: LRCommandState, *, waited: bool) -> dict:
    record = _record(state)
    session = state.session_id or "-"
    record["status_command"] = f"{_PORTAL_PREFIX} status {session} {state.command_id} --wait 60"
    if state.has_output is not False:
        record["output_command"] = f"{_PORTAL_PREFIX} output {session} {state.command_id}"
    if state.has_download:
        record["download_command"] = (
            f"{_PORTAL_PREFIX} download {session} {state.command_id} --output PATH")
    record["waited"] = waited
    return record


async def _poll(client: Backend, session_id: str | None, state: LRCommandState,
                wait_seconds: int) -> LRCommandState:
    """Read-only polling; stops at a terminal or unmapped native state."""
    deadline = monotonic() + wait_seconds
    while state.terminal is False and monotonic() < deadline:
        await asyncio.sleep(min(_POLL_SECONDS, max(0.0, deadline - monotonic())))
        state = await client.lr_get_command(session_id, state.command_id)
    return state


@contextlib.contextmanager
def _accepted(kind: str, identifier: str, recovery: list[str], *,
              completed: bool = False) -> Iterator[None]:
    """Report follow-up failures after the service accepted a submission.

    The job already exists, so whatever fails afterwards (polling, output
    saving, download) must never read as a failure that is safe to repeat:
    it keeps its own exit class but is not retryable, and names the accepted
    identifier and the read-only commands that follow it.
    """
    acceptance = f"{kind.capitalize()} {identifier} was accepted"
    if completed:
        acceptance += " and completed"
    try:
        yield
    except XDRError as error:
        error.retryable = False
        error.help_command = recovery[0]
        error.message = (f"{acceptance}, but a follow-up step "
                         f"failed: {error.message} Do not resubmit.")
        error.args = (error.message,)
        # Any generic "retry" advice would mean resubmitting; the recovery commands replace
        # it. retry_after_seconds stays: it still paces the read-only follow-up.
        error.suggested_fix = None
        error.suggestions = [{
            "reason": "submission_accepted", "confidence": "exact",
            "message": f"The {kind} was accepted; follow it instead of resubmitting.",
            "accepted_id": identifier, "commands": recovery,
        }, *error.suggestions]
        raise
    except OSError as error:
        raise ArtifactError(
            f"{acceptance}, but saving its result locally "
            "failed. Do not resubmit.",
            help_command=recovery[0],
            suggestions=[{"reason": "submission_accepted", "confidence": "exact",
                          "accepted_id": identifier, "commands": recovery}],
        ) from error
    except (KeyboardInterrupt, asyncio.CancelledError):
        err_console.print(f"Interrupted: {acceptance}; do not "
                          f"resubmit. Follow it with: {recovery[0]}")
        raise


def _command_recovery(session_id: str, command_id: str) -> list[str]:
    return [f"{_PORTAL_PREFIX} status {session_id} {command_id} --wait 60",
            f"{_PORTAL_PREFIX} output {session_id} {command_id}",
            f"{_PORTAL_PREFIX} history {session_id}"]


def _write_local_output(path: Path, rows: list[dict], *, force: bool) -> dict:
    """Save rendered command output privately and atomically, as the console's ``>`` does."""
    destination = package_destination(path, force=force)
    payload = "".join(
        (row["line"] if set(row) == {"line"} else json.dumps(row, separators=(",", ":"))) + "\n"
        for row in rows
    ).encode()
    if len(payload) > _MAX_OUTPUT_SAVE_BYTES:
        raise ArtifactError("Command output is too large to save locally.")
    # mkstemp creates the staged file 0600 on POSIX.
    descriptor, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".xdr-lr-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, destination)
        else:
            # link() never replaces a file created concurrently at the destination.
            try:
                os.link(temporary, destination)
            except FileExistsError:
                raise ConflictError(
                    "Local output already exists; use --force to replace it.") from None
            except OSError:
                raise ArtifactError("Could not publish the local output file.") from None
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {"path": str(destination), "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest()}


async def _submit(ctx: AppContext, client: Backend, session_id: str, parsed_from: Callable,
                  *, yes: bool, wait_seconds: int, force: bool = False,
                  emit_record: bool = True) -> LRCommandState | None:
    """Validate against the session's live definitions, confirm, submit once and poll."""
    session = await client.lr_get_session(session_id)
    commands, _ = merge_definitions(await client.lr_command_definitions(session_id))
    parsed: ParsedCommand = parsed_from(commands, session.platform)
    if parsed.risk is LRRisk.LOCAL:
        if parsed.verb == "help":
            _local_help(ctx, parsed)
            return None
        raise UsageError(f"'{parsed.verb}' is not sent to the device. {parsed.spec.local_note}",
                         invalid={"kind": "local_only"}, help_command=f"{_PREFIX} --help")
    if parsed.output_to is not None:
        package_destination(Path(parsed.output_to), force=force)
    _confirm(ctx, parsed, f"Live Response session {session_id}", yes)
    if parsed.risk is not LRRisk.READ:
        ctx.config.check_mutation_backend()
    _audit_submission(ctx, session_id, parsed)
    state = await client.lr_submit(session_id, parsed)
    with _accepted("command", state.command_id, _command_recovery(session_id, state.command_id)):
        state = await _poll(client, session_id, state, wait_seconds)
        record = _state_record(state, waited=wait_seconds > 0)
        record.update(risk=parsed.risk.value, background=parsed.background)
        if parsed.output_to is not None:
            if state.succeeded:
                rows = await _collect(client.lr_iter_output(session_id, state.command_id))
                record["local_output"] = _write_local_output(
                    Path(parsed.output_to), rows, force=force)
            else:
                record["local_output"] = None
                err_console.print("Command has not completed without errors; local output was "
                                  "not saved. Inspect it with the output command.")
    if emit_record:
        _emit(ctx, record)
    return state


# --- Local catalog -----------------------------------------------------------------------------


@live_response_app.command("catalog")
@click.option("--os", "platform", type=click.Choice([p.value for p in LRPlatform]),
              default=None, help="Only commands available on this platform.")
@click.option("--risk", type=click.Choice([r.value for r in LRRisk]), default=None,
              help="Only commands with this risk class.")
@click.pass_obj
def lr_catalog(ctx: AppContext, platform: str | None, risk: str | None) -> None:
    """List the pinned console command catalog (local; no authentication or network).

    A live session's server definitions may narrow syntax further; risk
    classes are always the pinned local ones.
    """
    rows = [
        _spec_row(spec) for spec in catalog()
        if (platform is None or LRPlatform(platform) in spec.platforms)
        and (risk is None or spec.risk.value == risk
             or any(r.value == risk for _, _, r in spec.risk_by_value))
    ]
    _emit_rows(ctx, rows, context={"source": "pinned-catalog"}, state="known-complete")


# --- Sessions ----------------------------------------------------------------------------------


@live_response_app.command("connect")
@click.argument("machine_id", type=str, required=True)
@click.option("--comment", "-c", default=None, help="Reason recorded locally with the request.")
@click.option("--wait", "wait_seconds", type=click.IntRange(min=0, max=600), default=0,
              show_default=True, help="Poll up to this many seconds while the session is pending.")
@_yes_option
@_dry_run_option
@click.pass_obj
def lr_connect(ctx: AppContext, machine_id: str, comment: str | None, wait_seconds: int,
               yes: bool, dry_run: bool) -> None:
    """Open a Live Response session on a device (MachineId).

    Opening a session is recorded by the service against your account. Use
    disconnect when finished; idle sessions end after 30 minutes.
    """
    if dry_run:
        _emit_dry_run(ctx, {"action": "connect", "machine_id": machine_id})
        return
    _require_sessions(ctx)
    _confirm_text(ctx, "open a Live Response session", f"device {machine_id}", yes)
    ctx.config.check_mutation_backend()

    async def work(client: Backend) -> None:
        session = await client.lr_open_session(machine_id, comment=comment)
        recovery = [f"{_PORTAL_PREFIX} show {session.session_id}",
                    f"{_PORTAL_PREFIX} disconnect {session.session_id}"]
        with _accepted("session", session.session_id, recovery):
            deadline = monotonic() + wait_seconds
            while session.state == "pending" and monotonic() < deadline:
                await asyncio.sleep(min(_POLL_SECONDS, max(0.0, deadline - monotonic())))
                session = await client.lr_get_session(session.session_id)
        record = _record(session)
        record["next_command"] = f"{_PORTAL_PREFIX} exec {session.session_id} --command-stdin"
        record["disconnect_command"] = f"{_PORTAL_PREFIX} disconnect {session.session_id}"
        _emit(ctx, record)

    _with_client(ctx, work)


@live_response_app.command("sessions")
@click.option("--device", "machine_id", default=None, help="Only sessions for this MachineId.")
@click.pass_obj
def lr_sessions(ctx: AppContext, machine_id: str | None) -> None:
    """List Live Response sessions this CLI knows about for the tenant and backend."""
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        rows = await _collect(client.lr_iter_sessions(machine_id=machine_id))
        _emit_rows(ctx, rows, context={"coverage": "locally-known-sessions"})

    _with_client(ctx, work)


@live_response_app.command("show")
@_session_argument
@click.pass_obj
def lr_show(ctx: AppContext, session_id: str) -> None:
    """Show a session's native state."""
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        _emit(ctx, _record(await client.lr_get_session(session_id)))

    _with_client(ctx, work)


@live_response_app.command("disconnect")
@_session_argument
@_yes_option
@_dry_run_option
@click.pass_obj
def lr_disconnect(ctx: AppContext, session_id: str, yes: bool, dry_run: bool) -> None:
    """Close a Live Response session. Running commands may be stopped by the service."""
    if dry_run:
        _emit_dry_run(ctx, {"action": "disconnect", "session_id": session_id})
        return
    _require_sessions(ctx)
    _confirm_text(ctx, "close the Live Response session", session_id, yes)
    ctx.config.check_mutation_backend()

    async def work(client: Backend) -> None:
        _emit(ctx, _record(await client.lr_close_session(session_id)))

    _with_client(ctx, work)


# --- Console commands --------------------------------------------------------------------------


@live_response_app.command("exec")
@_session_argument
@click.option("--command", "command_text", default=None,
              help="One console command. Prefer --command-file/--command-stdin for sensitive text.")
@click.option("--command-file", type=click.Path(path_type=Path, dir_okay=False), default=None,
              help="Read the console command from a file.")
@click.option("--command-stdin", is_flag=True, help="Read the console command from stdin.")
@click.option("--force", is_flag=True, help="Replace an existing '> FILE' local output.")
@_wait_option
@_yes_option
@_dry_run_option
@click.pass_obj
def lr_exec(ctx: AppContext, session_id: str, command_text: str | None,
            command_file: Path | None, command_stdin: bool, force: bool, wait_seconds: int,
            yes: bool, dry_run: bool) -> None:
    """Run one console command in a session, e.g. 'findfile evil.exe' or 'dir C:\\Temp'.

    A trailing '&' asks for background mode; a final '> FILE' saves the
    rendered output to a private local file once the command completes.
    Compound commands and pipes are rejected.
    """
    text = _read_text(command_text, command_file, command_stdin, what="console command")
    if text is None:
        raise UsageError("Give --command, --command-file or --command-stdin.",
                         invalid={"kind": "missing_option", "value": "--command"})
    if dry_run:
        _dry_run(ctx, parse_console_line(text), session_id)
        return
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        await _submit(
            ctx, client, session_id,
            lambda commands, platform: parse_console_line(
                text, platform=platform, commands=commands),
            yes=yes, wait_seconds=wait_seconds, force=force,
        )

    _with_client(ctx, work)


def _sugar(verb: str, params: dict, flags: frozenset[str] = frozenset(),
           background: bool = False) -> Callable:
    return lambda commands, platform: build_command(
        verb, params=params, flags=flags, platform=platform, background=background,
        commands=commands)


def _run_sugar(ctx: AppContext, session_id: str, builder: Callable, *, yes: bool,
               dry_run: bool, wait_seconds: int) -> None:
    if dry_run:
        _dry_run(ctx, builder(None, None), session_id)
        return
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        await _submit(ctx, client, session_id, builder, yes=yes, wait_seconds=wait_seconds)

    _with_client(ctx, work)


@live_response_app.command("findfile")
@_session_argument
@click.argument("name", type=str)
@_wait_option
@_dry_run_option
@click.pass_obj
def lr_findfile(ctx: AppContext, session_id: str, name: str, wait_seconds: int,
                dry_run: bool) -> None:
    """Search the device for files by name (read)."""
    _run_sugar(ctx, session_id, _sugar("findfile", {"name": name}), yes=False,
               dry_run=dry_run, wait_seconds=wait_seconds)


@live_response_app.command("fileinfo")
@_session_argument
@click.argument("path", type=str)
@_wait_option
@_dry_run_option
@click.pass_obj
def lr_fileinfo(ctx: AppContext, session_id: str, path: str, wait_seconds: int,
                dry_run: bool) -> None:
    """Show file metadata and hashes (read)."""
    _run_sugar(ctx, session_id, _sugar("fileinfo", {"path": path}), yes=False,
               dry_run=dry_run, wait_seconds=wait_seconds)


@live_response_app.command("dir")
@_session_argument
@click.argument("path", type=str, required=False, default=None)
@click.option("--full-path", is_flag=True, help="Show full paths.")
@_wait_option
@_dry_run_option
@click.pass_obj
def lr_dir(ctx: AppContext, session_id: str, path: str | None, full_path: bool,
           wait_seconds: int, dry_run: bool) -> None:
    """List a directory on the device (read)."""
    flags = frozenset({"full_path"}) if full_path else frozenset()
    _run_sugar(ctx, session_id, _sugar("dir", {"path": path}, flags), yes=False,
               dry_run=dry_run, wait_seconds=wait_seconds)


@live_response_app.command("getfile")
@_session_argument
@click.argument("path", type=str)
@click.option("--output", "-o", type=_output_path, default=None,
              help="Download the collected file here once the command completes.")
@click.option("--force", is_flag=True, help="Replace an existing --output path.")
@click.option("--max-bytes", type=click.IntRange(min=1), default=DEFAULT_MAX_BYTES,
              show_default=True, help="Maximum download size.")
@click.option("--background", is_flag=True, help="Submit in background mode.")
@click.option("--upload-only", is_flag=True,
              help="Only upload the file to the cloud (-upload_to_cloud); no download.")
@click.option("--wait", "wait_seconds", type=click.IntRange(min=0, max=3600), default=300,
              show_default=True, help="Poll up to this many seconds before downloading.")
@_yes_option
@_dry_run_option
@click.pass_obj
def lr_getfile(ctx: AppContext, session_id: str, path: str, output: Path | None, force: bool,
               max_bytes: int, background: bool, upload_only: bool, wait_seconds: int,
               yes: bool, dry_run: bool) -> None:
    """Fetch a file from the device (collect). Downloads are private and never opened."""
    if upload_only and output is not None:
        raise UsageError("--upload-only cannot be combined with --output.")
    flags = frozenset({"upload"}) if upload_only else frozenset()
    builder = _sugar("getfile", {"path": path}, flags, background)
    if output is not None and not dry_run:
        package_destination(output, force=force)
    if dry_run:
        _dry_run(ctx, builder(None, None), session_id)
        return
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        state = await _submit(ctx, client, session_id, builder, yes=yes,
                              wait_seconds=wait_seconds, emit_record=output is None)
        if state is None or output is None:
            return
        if not state.succeeded:
            skipped = "not_terminal" if state.terminal is not True else (
                "completed_with_errors" if state.state == "completed" else "failed"
            )
            _emit(ctx, {**_state_record(state, waited=wait_seconds > 0),
                        "risk": LRRisk.COLLECT.value, "background": background,
                        "downloaded": False, "download_skipped_reason": skipped})
            err_console.print("getfile has not completed without errors; nothing was "
                              "downloaded. Check status and output before using download.")
            return
        recovery = _command_recovery(session_id, state.command_id)
        with _accepted("command", state.command_id, recovery, completed=True):
            transfer = await client.lr_result_transfer(session_id, state.command_id)
            receipt = await download_transfer(transfer, output, force=force,
                                              max_bytes=max_bytes,
                                              timeout=ctx.config.api_timeout)
        _emit(ctx, {**_state_record(state, waited=wait_seconds > 0), **receipt,
                    "risk": LRRisk.COLLECT.value, "background": background, "downloaded": True})

    _with_client(ctx, work)


@live_response_app.command("putfile")
@_session_argument
@click.argument("library_name", type=str)
@click.option("--overwrite", is_flag=True, help="Overwrite the file if it exists on the device.")
@click.option("--keep", is_flag=True, help="Keep the file on the device after a restart.")
@_wait_option
@_yes_option
@_dry_run_option
@click.pass_obj
def lr_putfile(ctx: AppContext, session_id: str, library_name: str, overwrite: bool,
               keep: bool, wait_seconds: int, yes: bool, dry_run: bool) -> None:
    """Place a library file on the device (place). Upload it first with library upload."""
    flags = frozenset(name for name, on in (("overwrite", overwrite), ("keep", keep)) if on)
    _run_sugar(ctx, session_id, _sugar("putfile", {"id": library_name}, flags), yes=yes,
               dry_run=dry_run, wait_seconds=wait_seconds)


@live_response_app.command("run")
@_session_argument
@click.argument("script", type=str)
@click.option("--parameters-file", type=click.Path(path_type=Path, dir_okay=False),
              default=None, help="Read script parameters from a file (kept out of argv).")
@click.option("--parameters-stdin", is_flag=True, help="Read script parameters from stdin.")
@click.option("--background", is_flag=True, help="Submit in background mode.")
@_wait_option
@_yes_option
@_dry_run_option
@click.pass_obj
def lr_run(ctx: AppContext, session_id: str, script: str, parameters_file: Path | None,
           parameters_stdin: bool, background: bool, wait_seconds: int, yes: bool,
           dry_run: bool) -> None:
    """Run a library script on the device (execute)."""
    parameters = _read_text(None, parameters_file, parameters_stdin, what="script parameters")
    builder = _sugar("run", {"id": script, "parameters": parameters}, background=background)
    _run_sugar(ctx, session_id, builder, yes=yes, dry_run=dry_run, wait_seconds=wait_seconds)


# --- Command jobs ------------------------------------------------------------------------------


@live_response_app.command("status")
@_session_argument
@_command_id_argument
@_wait_option
@click.pass_obj
def lr_status(ctx: AppContext, session_id: str, command_id: str, wait_seconds: int) -> None:
    """Show a command's native state, optionally polling until it is terminal."""
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        state = await client.lr_get_command(session_id, command_id)
        state = await _poll(client, session_id, state, wait_seconds)
        _emit(ctx, _state_record(state, waited=wait_seconds > 0))

    _with_client(ctx, work)


@live_response_app.command("history")
@_session_argument
@click.pass_obj
def lr_history(ctx: AppContext, session_id: str) -> None:
    """List the session's command log (the console's jobs and Command log)."""
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        rows = await _collect(client.lr_iter_commands(session_id))
        _emit_rows(ctx, rows, context={"session_id": session_id})

    _with_client(ctx, work)


@live_response_app.command("output")
@_session_argument
@_command_id_argument
@click.pass_obj
def lr_output(ctx: AppContext, session_id: str, command_id: str) -> None:
    """Save a command's rendered output as a private artifact."""
    _require_sessions(ctx)

    async def work(client: Backend) -> None:
        rows = await _collect(client.lr_iter_output(session_id, command_id))
        _emit_rows(ctx, rows, context={"session_id": session_id, "command_id": command_id},
                   preview_rows=0)

    _with_client(ctx, work)


@live_response_app.command("cancel")
@_session_argument
@_command_id_argument
@_yes_option
@_dry_run_option
@click.pass_obj
def lr_cancel(ctx: AppContext, session_id: str, command_id: str, yes: bool,
              dry_run: bool) -> None:
    """Cancel a command in the portal. The device may still finish it."""
    if dry_run:
        _emit_dry_run(ctx, {"action": "cancel", "session_id": session_id,
                            "command_id": command_id})
        return
    _require_sessions(ctx)
    _confirm_text(ctx, f"cancel command {command_id}", f"session {session_id}", yes)
    ctx.config.check_mutation_backend()

    async def work(client: Backend) -> None:
        state = await client.lr_cancel(session_id, command_id)
        record = _state_record(state, waited=False)
        record["device_outcome"] = "unknown"
        _emit(ctx, record)

    _with_client(ctx, work)


@live_response_app.command("download")
@_session_argument
@_command_id_argument
@click.option("--output", "-o", type=_output_path, required=True, help="Destination file.")
@click.option("--force", is_flag=True, help="Atomically replace an existing output path.")
@click.option("--max-bytes", type=click.IntRange(min=1), default=DEFAULT_MAX_BYTES,
              show_default=True, help="Maximum download size.")
@click.pass_obj
def lr_download(ctx: AppContext, session_id: str, command_id: str, output: Path, force: bool,
                max_bytes: int) -> None:
    """Download a completed command's file (e.g. getfile) privately; never opened or extracted."""
    _require_sessions(ctx)
    package_destination(output, force=force)

    async def work(client: Backend) -> None:
        transfer = await client.lr_result_transfer(session_id, command_id)
        receipt = await download_transfer(transfer, output, force=force, max_bytes=max_bytes,
                                          timeout=ctx.config.api_timeout)
        _emit(ctx, {**receipt, "session_id": session_id, "command_id": command_id})

    _with_client(ctx, work)


# --- Library -----------------------------------------------------------------------------------


def _require_library(ctx: AppContext) -> None:
    if not ctx.config.backend_profile.lr_library:
        raise UnsupportedBackendCapability(
            "The Live Response library is not available on this backend. No request was sent.")


def _library_name(name: str) -> str:
    if not LIBRARY_NAME_PATTERN.match(name):
        raise UsageError(
            "Library file names use letters, digits, '_', '.', '-' and inner spaces.",
            invalid={"kind": "invalid_name"},
        )
    return name


@library_app.command("list")
@click.pass_obj
def library_list(ctx: AppContext) -> None:
    """List library files."""
    _require_library(ctx)

    async def work(client: Backend) -> None:
        _emit_rows(ctx, await _collect(client.lr_iter_library()))

    _with_client(ctx, work)


@library_app.command("show")
@click.argument("name", type=str)
@click.pass_obj
def library_show(ctx: AppContext, name: str) -> None:
    """Show one library file's metadata."""
    _require_library(ctx)
    _library_name(name)

    async def work(client: Backend) -> None:
        rows = [row async for row in client.lr_iter_library() if row.name == name]
        if not rows:
            raise NotFoundError("library file", name)
        _emit(ctx, _record(rows[0]))

    _with_client(ctx, work)


@library_app.command("download")
@click.argument("name", type=str)
@click.option("--output", "-o", type=_output_path, required=True, help="Destination file.")
@click.option("--force", is_flag=True, help="Atomically replace an existing output path.")
@click.option("--max-bytes", type=click.IntRange(min=1), default=DEFAULT_MAX_BYTES,
              show_default=True, help="Maximum download size.")
@click.pass_obj
def library_download(ctx: AppContext, name: str, output: Path, force: bool,
                     max_bytes: int) -> None:
    """Download a library file privately."""
    _require_library(ctx)
    _library_name(name)
    package_destination(output, force=force)

    async def work(client: Backend) -> None:
        transfer = await client.lr_library_transfer(name)
        receipt = await download_transfer(transfer, output, force=force, max_bytes=max_bytes,
                                          timeout=ctx.config.api_timeout)
        _emit(ctx, {**receipt, "name": name})

    _with_client(ctx, work)


@library_app.command("upload")
@click.option("--from-file", "path", type=click.Path(path_type=Path, exists=True, dir_okay=False),
              required=True, help="Local file to upload; its name becomes the library name.")
@click.option("--description", default=None, help="Library description.")
@click.option("--parameters-description", default=None,
              help="Describe the script's parameters (marks the script as taking parameters).")
@click.option("--overwrite", is_flag=True, help="Replace a library file with the same name.")
@_yes_option
@_dry_run_option
@click.pass_obj
def library_upload(ctx: AppContext, path: Path, description: str | None,
                   parameters_description: str | None, overwrite: bool, yes: bool,
                   dry_run: bool) -> None:
    """Upload a file to the tenant library (library-write)."""
    _library_name(path.name)
    if dry_run:
        _emit(ctx, {"dry_run": True, "action": "library upload", "name": path.name,
                    "bytes": path.stat().st_size, "overwrite": overwrite})
        return
    _require_library(ctx)
    _confirm_text(ctx, f"upload '{path.name}' to the tenant library", "the tenant", yes)
    ctx.config.check_mutation_backend()

    async def work(client: Backend) -> None:
        uploaded = await client.lr_upload_library(
            path, description=description, parameters_description=parameters_description,
            has_parameters=parameters_description is not None, overwrite=overwrite,
        )
        _emit(ctx, _record(uploaded))

    _with_client(ctx, work)


@library_app.command("delete")
@click.argument("name", type=str)
@_yes_option
@_dry_run_option
@click.pass_obj
def library_delete(ctx: AppContext, name: str, yes: bool, dry_run: bool) -> None:
    """Delete a file from the tenant library (library-write)."""
    _library_name(name)
    if dry_run:
        _emit(ctx, {"dry_run": True, "action": "library delete", "name": name})
        return
    _require_library(ctx)
    _confirm_text(ctx, f"delete '{name}' from the tenant library", "the tenant", yes)
    ctx.config.check_mutation_backend()

    async def work(client: Backend) -> None:
        await client.lr_delete_library(name)
        _emit(ctx, {"deleted": name})

    _with_client(ctx, work)


# --- Official one-shot batch -------------------------------------------------------------------

batch_app = click.Group(
    name="batch",
    help=(
        "Official API Live Response machine actions: PutFile, RunScript and GetFile in one "
        "request, without an interactive session.\n\n"
        "GetFile results are saved exactly as delivered (gzip-wrapped); the receipt's kind "
        "says so. See docs/live_response_coverage.md."
    ),
    no_args_is_help=True,
)
live_response_app.add_command(batch_app)


def _require_batch(ctx: AppContext) -> None:
    if not ctx.config.backend_profile.lr_batch:
        raise UnsupportedBackendCapability(
            "Live Response batch actions use the official API. No request was sent.",
            suggested_fix="Use --backend official, or an interactive session on portal-cookie.",
        )


def _batch_commands(texts: list[str]) -> list[ParsedCommand]:
    parsed = [parse_console_line(text) for text in texts if text.strip()]
    if not parsed:
        raise UsageError("Give at least one command.", invalid={"kind": "missing_option"})
    for command in parsed:
        if command.spec.official_type is None:
            raise UsageError(
                f"'{command.verb}' is not available in official batch actions; use an "
                "interactive session.",
                invalid={"kind": "batch_unsupported"},
                allowed=sorted(s.name for s in catalog() if s.official_type),
            )
    return parsed


def _action_record(state: LRCommandState) -> dict:
    record = _record(state)
    record["status_command"] = f"{_OFFICIAL_PREFIX} batch status {state.command_id} --wait 60"
    record["output_command"] = f"{_OFFICIAL_PREFIX} batch output {state.command_id}"
    return record


@batch_app.command("submit")
@click.argument("machine_id", type=str, required=True)
@click.option("--command", "command_texts", multiple=True, default=(),
              help="Console command (getfile, putfile, run); repeatable, in order.")
@click.option("--command-file", type=click.Path(path_type=Path, dir_okay=False), default=None,
              help="Read commands from a file, one per line (keeps script arguments out of argv).")
@click.option("--comment", "-c", required=True, help="Reason recorded with the machine action.")
@_wait_option
@_yes_option
@_dry_run_option
@click.pass_obj
def batch_submit(ctx: AppContext, machine_id: str, command_texts: tuple[str, ...],
                 command_file: Path | None, comment: str, wait_seconds: int, yes: bool,
                 dry_run: bool) -> None:
    """Submit one official runliveresponse machine action."""
    texts = list(command_texts)
    from_file = _read_text(None, command_file, False, what="command file")
    if from_file is not None:
        texts.extend(from_file.splitlines())
    parsed = _batch_commands(texts)
    if dry_run:
        _emit_dry_run(ctx, {"machine_id": machine_id,
                            "commands": [command.redacted_summary() for command in parsed]})
        return
    _require_batch(ctx)
    risks = ", ".join(sorted({command.risk.value for command in parsed}))
    _confirm_text(ctx, f"submit a Live Response batch ({risks})", f"device {machine_id}", yes)
    ctx.config.check_mutation_backend()

    async def work(client: Backend) -> None:
        for command in parsed:
            _audit_submission(ctx, machine_id, command)
        state = await client.lr_submit_batch(machine_id, parsed, comment=comment)
        recovery = [f"{_OFFICIAL_PREFIX} batch status {state.command_id} --wait 60",
                    f"{_OFFICIAL_PREFIX} batch output {state.command_id}"]
        with _accepted("batch action", state.command_id, recovery):
            state = await _poll(client, None, state, wait_seconds)
        _emit(ctx, _action_record(state))

    _with_client(ctx, work)


@batch_app.command("status")
@click.argument("action_id", type=str, required=True)
@_wait_option
@click.pass_obj
def batch_status(ctx: AppContext, action_id: str, wait_seconds: int) -> None:
    """Show a batch action's native state."""
    _require_batch(ctx)

    async def work(client: Backend) -> None:
        state = await client.lr_get_command(None, action_id)
        _emit(ctx, _action_record(await _poll(client, None, state, wait_seconds)))

    _with_client(ctx, work)


@batch_app.command("output")
@click.argument("action_id", type=str, required=True)
@click.pass_obj
def batch_output(ctx: AppContext, action_id: str) -> None:
    """Save per-command status and errors for a batch action as a private artifact."""
    _require_batch(ctx)

    async def work(client: Backend) -> None:
        rows = await _collect(client.lr_iter_output(None, action_id))
        # Native error text can repeat script arguments and paths: no previews.
        _emit_rows(ctx, rows, context={"action_id": action_id}, preview_rows=0)

    _with_client(ctx, work)


@batch_app.command("download")
@click.argument("action_id", type=str, required=True)
@click.option("--index", type=click.IntRange(min=0), default=0, show_default=True,
              help="Zero-based command index within the action.")
@click.option("--output", "-o", type=_output_path, required=True, help="Destination file.")
@click.option("--force", is_flag=True, help="Atomically replace an existing output path.")
@click.option("--max-bytes", type=click.IntRange(min=1), default=DEFAULT_MAX_BYTES,
              show_default=True, help="Maximum download size.")
@click.pass_obj
def batch_download(ctx: AppContext, action_id: str, index: int, output: Path, force: bool,
                   max_bytes: int) -> None:
    """Download a completed batch command's result privately."""
    _require_batch(ctx)
    package_destination(output, force=force)

    async def work(client: Backend) -> None:
        transfer = await client.lr_result_transfer(None, action_id, index=index)
        receipt = await download_transfer(transfer, output, force=force, max_bytes=max_bytes,
                                          timeout=ctx.config.api_timeout)
        _emit(ctx, {**receipt, "action_id": action_id, "index": index})

    _with_client(ctx, work)


@batch_app.command("cancel")
@click.argument("action_id", type=str, required=True)
@_yes_option
@_dry_run_option
@click.pass_obj
def batch_cancel(ctx: AppContext, action_id: str, yes: bool, dry_run: bool) -> None:
    """Cancel a pending batch action. Commands already running may still finish."""
    if dry_run:
        _emit_dry_run(ctx, {"action": "batch cancel", "action_id": action_id})
        return
    _require_batch(ctx)
    _confirm_text(ctx, f"cancel batch action {action_id}", "the tenant", yes)
    ctx.config.check_mutation_backend()

    async def work(client: Backend) -> None:
        record = _action_record(await client.lr_cancel(None, action_id))
        record["device_outcome"] = "unknown"
        _emit(ctx, record)

    _with_client(ctx, work)
