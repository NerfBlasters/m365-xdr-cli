"""Device commands: show, isolate, unisolate, scan, collect-package, restrict,
action-status, timeline."""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import io
import json
import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import TextIO

import typer

from xdr_cli.api.devices import (
    collect_investigation_package,
    find_device_by_hostname,
    get_action_status,
    get_device,
    isolate_device,
    restrict_code_execution,
    run_av_scan,
    unisolate_device,
)
from xdr_cli.api.timeline import stream_device_timeline
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    ArtifactError,
    AuthError,
    ConflictError,
    NotFoundError,
    UsageError,
)
from xdr_cli.output import OutputFormatter, err_console
from xdr_cli.portal_auth import PortalAuth, load_portal_cookies
from xdr_cli.portal_client import (
    BearerAuth,
    CookieAuth,
    PortalAuthStrategy,
    PortalClient,
    RefreshTokenAuth,
)
from xdr_cli.results import ResultStreamWriter, emit_result

device_app = typer.Typer(
    name="device",
    help="Device info and response actions.",
    no_args_is_help=True,
)

# A MachineId is a 40-char SHA1 hex digest. It needs no hostname resolution;
# stored-cookie timeline runs still verify it against the configured tenant.
_MACHINE_ID_RE = re.compile(r"[a-fA-F0-9]{40}")

# The apiproxy device-timeline endpoint accepts fromDate/toDate up to ~180
# days back (per the design doc); --days beyond that is rejected up front
# rather than silently truncated server-side.
_MAX_TIMELINE_DAYS = 180


def _get_client(ctx: AppContext) -> tuple[AuthManager, XDRClient]:
    auth = AuthManager(ctx.config)
    client = XDRClient(
        get_token=auth.get_token, timeout=ctx.config.api_timeout,
    )
    return auth, client


def _confirm_action(
    ctx: AppContext, action: str, target: str, yes: bool,
) -> None:
    """Confirm a destructive action. Exits if denied or non-interactive without --yes."""
    if yes:
        return
    if not ctx.is_interactive:
        raise UsageError(
            f"Non-interactive mode requires --yes for {action!r}.",
            invalid={"kind": "missing_option", "value": "--yes"},
            suggestions=[
                {
                    "reason": "confirmation_required",
                    "message": "Re-run the same device command with --yes.",
                    "confidence": "exact",
                }
            ],
            help_command="xdr device --help",
        )
    err_console.print(
        f"[bold yellow]About to {action} device "
        f"{target}.[/bold yellow]"
    )
    if not typer.confirm("Proceed?"):
        raise ConflictError(f"Device action {action!r} was cancelled by the operator.")


@device_app.command("show")
def device_show(
    ctx: typer.Context,
    device: str = typer.Argument(help="Device ID or hostname."),
) -> None:
    """Show device details."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(_device_show(app_ctx, device))


async def _device_show(ctx: AppContext, device: str) -> None:
    _, client = _get_client(ctx)
    try:
        # Try as hostname first if it doesn't look like a GUID
        if "-" not in device or len(device) < 30:
            found = await find_device_by_hostname(client, device)
            if found:
                result = found
            else:
                result = await get_device(client, device)
        else:
            result = await get_device(client, device)

        fmt = OutputFormatter(
            session_id=ctx.session_id,
            session_label=ctx.session_label,
        )
        typer.echo(fmt.format_output(result))
    finally:
        await client.close()


@device_app.command("isolate")
def device_isolate(
    ctx: typer.Context,
    device_id: str = typer.Argument(help="Device ID."),
    isolation_type: str = typer.Option(
        "Full", "--type", "-t",
        help="Isolation type: Full or Selective.",
    ),
    comment: str = typer.Option(
        ..., "--comment", "-c", help="Reason for isolation.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would happen.",
    ),
) -> None:
    """Isolate a device from the network."""
    app_ctx: AppContext = ctx.obj

    if dry_run:
        fmt = OutputFormatter(
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
        )
        typer.echo(fmt.format_output({
            "dry_run": True,
            "action": "isolate",
            "device_id": device_id,
            "type": isolation_type,
        }))
        return

    _confirm_action(app_ctx, "isolate", device_id, yes)
    asyncio.run(
        _device_action(
            app_ctx, "isolate", device_id,
            isolation_type=isolation_type, comment=comment,
        )
    )


@device_app.command("unisolate")
def device_unisolate(
    ctx: typer.Context,
    device_id: str = typer.Argument(help="Device ID."),
    comment: str = typer.Option(
        ..., "--comment", "-c",
        help="Reason for releasing isolation.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation.",
    ),
) -> None:
    """Release a device from network isolation."""
    app_ctx: AppContext = ctx.obj
    _confirm_action(app_ctx, "unisolate", device_id, yes)
    asyncio.run(
        _device_action(
            app_ctx, "unisolate", device_id, comment=comment,
        )
    )


@device_app.command("scan")
def device_scan(
    ctx: typer.Context,
    device_id: str = typer.Argument(help="Device ID."),
    scan_type: str = typer.Option(
        "Quick", "--scan-type", help="Quick or Full.",
    ),
    comment: str = typer.Option(
        "Scan triggered via xdr-cli",
        "--comment", "-c", help="Comment.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would happen.",
    ),
) -> None:
    """Run an antivirus scan on a device."""
    app_ctx: AppContext = ctx.obj

    if dry_run:
        fmt = OutputFormatter(
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
        )
        typer.echo(fmt.format_output({
            "dry_run": True,
            "action": "scan",
            "device_id": device_id,
            "scan_type": scan_type,
        }))
        return

    _confirm_action(app_ctx, f"{scan_type.lower()} scan", device_id, yes)
    asyncio.run(
        _device_action(
            app_ctx, "scan", device_id,
            scan_type=scan_type, comment=comment,
        )
    )


@device_app.command("collect-package")
def device_collect_package(
    ctx: typer.Context,
    device_id: str = typer.Argument(help="Device ID."),
    comment: str = typer.Option(
        "Forensic package requested via xdr-cli",
        "--comment", "-c", help="Comment.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would happen.",
    ),
) -> None:
    """Request a forensic investigation package."""
    app_ctx: AppContext = ctx.obj

    if dry_run:
        fmt = OutputFormatter(
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
        )
        typer.echo(fmt.format_output({
            "dry_run": True,
            "action": "collect-package",
            "device_id": device_id,
        }))
        return

    _confirm_action(app_ctx, "collect forensic package from", device_id, yes)
    asyncio.run(
        _device_action(
            app_ctx, "collect-package", device_id, comment=comment,
        )
    )


@device_app.command("restrict")
def device_restrict(
    ctx: typer.Context,
    device_id: str = typer.Argument(help="Device ID."),
    comment: str = typer.Option(
        ..., "--comment", "-c", help="Reason for restriction.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would happen.",
    ),
) -> None:
    """Restrict app execution to Microsoft-signed binaries."""
    app_ctx: AppContext = ctx.obj

    if dry_run:
        fmt = OutputFormatter(
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
        )
        typer.echo(fmt.format_output({
            "dry_run": True,
            "action": "restrict",
            "device_id": device_id,
        }))
        return

    _confirm_action(
        app_ctx, "restrict code execution on", device_id, yes,
    )
    asyncio.run(
        _device_action(
            app_ctx, "restrict", device_id, comment=comment,
        )
    )


@device_app.command("action-status")
def device_action_status(
    ctx: typer.Context,
    action_id: str = typer.Argument(help="Machine action ID."),
) -> None:
    """Check the status of a machine action."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(_action_status(app_ctx, action_id))


async def _device_action(
    ctx: AppContext, action: str, device_id: str, **kwargs,
) -> None:
    _, client = _get_client(ctx)
    try:
        action_map = {
            "isolate": lambda: isolate_device(
                client, device_id,
                isolation_type=kwargs.get("isolation_type", "Full"),
                comment=kwargs.get("comment", ""),
            ),
            "unisolate": lambda: unisolate_device(
                client, device_id,
                comment=kwargs.get("comment", ""),
            ),
            "scan": lambda: run_av_scan(
                client, device_id,
                scan_type=kwargs.get("scan_type", "Quick"),
                comment=kwargs.get("comment", ""),
            ),
            "collect-package": lambda: collect_investigation_package(
                client, device_id,
                comment=kwargs.get("comment", ""),
            ),
            "restrict": lambda: restrict_code_execution(
                client, device_id,
                comment=kwargs.get("comment", ""),
            ),
        }
        result = await action_map[action]()
        fmt = OutputFormatter(
            session_id=ctx.session_id,
            session_label=ctx.session_label,
        )
        typer.echo(
            fmt.format_output(
                result,
                metadata={
                    "action": action,
                    "device_id": device_id,
                },
            )
        )
    finally:
        await client.close()


async def _action_status(ctx: AppContext, action_id: str) -> None:
    _, client = _get_client(ctx)
    try:
        result = await get_action_status(client, action_id)
        fmt = OutputFormatter(
            session_id=ctx.session_id,
            session_label=ctx.session_label,
        )
        typer.echo(fmt.format_output(result))
    finally:
        await client.close()


# Accepted `--from`/`--to` input forms. The tz-aware variants (trailing `Z` or
# a numeric offset, both via `%z`) are the RFC3339 forms the help promises;
# without them click's default DateTime rejects a `Z` suffix. The naive forms
# are kept for convenience and coerced to UTC by `_ensure_utc`. tz-aware
# formats are listed first so a `...Z` string matches before the naive fallers.
_TIME_INPUT_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
]


def _ensure_utc(dt: datetime) -> datetime:
    """Coerce a naive datetime to UTC-aware; pass already-aware ones through.

    `stream_device_timeline`'s `Next`-cutoff compare (``parsed_from_date >
    to_date``) raises ``TypeError`` when `to_date` is naive. Typer/click's
    datetime parsing for ``--from``/``--to`` produces a naive datetime when
    the user doesn't include a UTC offset, so both options are coerced here
    before anything downstream ever sees them.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _select_portal_auth_strategy(
    ctx: AppContext, refresh_token: str | None,
) -> PortalAuthStrategy:
    """First-match-wins auth-strategy selection for `device timeline`.

    1. ``--refresh-token``/``MDE_REFRESH_TOKEN`` -> RefreshTokenAuth. Explicit
       per-run credential; wins over any stored state (CI use case).
    2. A stored ``portal_cookies.json`` -> CookieAuth. Its presence means the
       user deliberately ran `xdr auth portal-cookie` (typically because
       FOCI/MSAL is blocked in their tenant), so it takes precedence over a
       merely-cached MSAL account.
    3. A cached portal MSAL account -> BearerAuth.
    4. None of the above -> exit non-zero, naming both portal auth commands.
    """
    if refresh_token:
        return RefreshTokenAuth(ctx.config.tenant_id, refresh_token)

    stored_cookies = load_portal_cookies(ctx.config.tenant_id)
    if stored_cookies is not None:
        return CookieAuth(
            sccauth=stored_cookies.get("sccauth"),
            # .get() (not []) like every sibling key: a store missing xsrf_token
            # (hand-edited/partial/schema drift) must degrade to CookieAuth's ""
            # default, not raise KeyError. "" matches CookieAuth's own default.
            xsrf_token=stored_cookies.get("xsrf_token", ""),
            sccauth_chunks=stored_cookies.get("sccauth_chunks"),
            cookie_header=stored_cookies.get("cookie_header"),
        )

    portal_auth = PortalAuth(ctx.config)
    if portal_auth.get_auth_status().get("authenticated"):
        return BearerAuth(portal_auth)

    raise AuthError(
        "No Defender portal credentials found.",
        suggestions=[
            {
                "reason": "portal_auth",
                "message": "xdr auth portal-cookie <cookie-source>",
                "confidence": "exact",
            },
            {
                "reason": "portal_auth_experimental",
                "message": "xdr auth portal-login",
                "confidence": "exact",
            },
        ],
        help_command="xdr device timeline --help",
    )


async def _resolve_machine_id(
    client: XDRClient,
    device: str,
    *,
    verify_exact: bool = False,
) -> str:
    """Resolve `device` (hostname or MachineId) to a MachineId.

    A 40-hex-char `device` is normally used directly. With ``verify_exact``
    (stored-cookie timeline auth), it is first confirmed through the official
    tenant. Hostnames resolve via `find_device_by_hostname` against the OFFICIAL
    MDE API (the main `XDRClient`/`AuthManager`, not the portal apiproxy client),
    so device resolution attributes to the user's own app registration in the
    audit log. Only the timeline fetch itself uses the portal client.

    `find_device_by_hostname` currently returns a single match (or None);
    normalizing to a list here also lets a caller supply/mock a list of
    candidates, so a hostname resolving to more than one device is treated
    as a hard error rather than silently picking one.
    """
    if _MACHINE_ID_RE.fullmatch(device) and not verify_exact:
        return device

    if _MACHINE_ID_RE.fullmatch(device):
        found = await get_device(client, device)
        resolved = found.get("id") if isinstance(found, dict) else None
        if not isinstance(resolved, str) or resolved.casefold() != device.casefold():
            raise ConflictError(
                "The configured tenant did not return the requested MachineId. "
                "Re-import portal cookies for this tenant and retry.",
                help_command="xdr auth portal-cookie --help",
            )
        return resolved

    found = await find_device_by_hostname(client, device)
    candidates = found if isinstance(found, list) else ([found] if found else [])

    if not candidates:
        raise NotFoundError(
            "device hostname",
            device,
        )
    if len(candidates) > 1:
        names = ", ".join(
            f"{c.get('computerDnsName', '?')} ({c.get('id', '?')})"
            for c in candidates
        )
        raise ConflictError(
            f"Multiple devices match hostname {device!r}: {names}.",
            suggestions=[
                {
                    "reason": "device_disambiguation",
                    "message": "Re-run with one of the listed MachineIds.",
                    "confidence": "exact",
                }
            ],
            help_command="xdr device timeline --help",
        )

    return candidates[0]["id"]


@contextmanager
def _open_timeline_sink(output: Path | None, gzip_out: bool, *, force: bool = False):
    """Yield stdout or atomically publish an owner-only JSONL file.

    `gzip_out` only applies to file output — piping gzip bytes to stdout
    would be silently unusable by anything downstream expecting JSONL.
    """
    if output is None:
        yield sys.stdout
        return
    expanded = output.expanduser()
    destination = expanded.parent.resolve() / expanded.name
    parent_stat = destination.parent.stat()
    if os.name == "posix" and parent_stat.st_mode & 0o022 and not (
        parent_stat.st_mode & stat.S_ISVTX
    ):
        raise ArtifactError(
            f"Refusing timeline output in non-sticky shared directory: "
            f"{destination.parent}. Choose an owner-only directory or a sticky "
            "temporary directory."
        )
    if not force and os.path.lexists(destination):
        raise ConflictError(
            f"Output already exists: {destination}. Use --force to replace it.",
            invalid={"kind": "output_path", "value": str(destination)},
            help_command="xdr device timeline --help",
        )
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temp_path = Path(temp_name)
    if sys.platform != "win32":
        os.fchmod(descriptor, 0o600)
    raw = os.fdopen(os.dup(descriptor), "wb")
    compressed = gzip.GzipFile(fileobj=raw, mode="wb") if gzip_out else raw
    sink: TextIO = io.TextIOWrapper(compressed, encoding="utf-8")
    try:
        yield sink
        sink.close()
        if not raw.closed:
            raw.close()
        os.fsync(descriptor)
        descriptor_stat = os.fstat(descriptor)
        path_stat = temp_path.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or path_stat.st_dev != descriptor_stat.st_dev
            or path_stat.st_ino != descriptor_stat.st_ino
        ):
            raise ArtifactError(
                "Timeline staging file identity changed before publication; "
                "no destination was written."
            )
        os.close(descriptor)
        descriptor = -1
        try:
            if force:
                os.replace(temp_path, destination)
            else:
                os.link(temp_path, destination)
                with contextlib.suppress(OSError):
                    temp_path.unlink()
        except FileExistsError as exc:
            raise ConflictError(
                f"Output was created concurrently: {destination}. "
                "Use --force only when replacement is intentional.",
                invalid={"kind": "output_path", "value": str(destination)},
                help_command="xdr device timeline --help",
            ) from exc
        except OSError as exc:
            raise ArtifactError(
                f"Could not publish timeline output {destination}: {exc}"
            ) from exc
    except Exception:
        if not sink.closed:
            sink.close()
        if not raw.closed:
            raw.close()
        raise
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)


@device_app.command("timeline")
def device_timeline(
    ctx: typer.Context,
    device: str = typer.Argument(..., help="Device hostname or MachineId (40 hex chars)."),
    from_date: datetime | None = typer.Option(
        None, "--from", formats=_TIME_INPUT_FORMATS,
        help="RFC3339, e.g. 2026-07-24T21:00:00Z; defaults to the lookback window.",
    ),
    to_date: datetime | None = typer.Option(
        None, "--to", formats=_TIME_INPUT_FORMATS,
        help="RFC3339, e.g. 2026-07-24T21:00:00Z; defaults to now.",
    ),
    days: int | None = typer.Option(
        None, "--days", min=1,
        help="Lookback days when --from is not given (max 180; default 7).",
    ),
    hours: int | None = typer.Option(
        None, "--hours", min=1,
        help="Lookback hours when --from is not given; mutually exclusive with --days.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Atomically write owner-only JSONL here; refuses existing paths "
            "and unsafe shared directories."
        ),
    ),
    gzip_out: bool = typer.Option(
        False, "--gzip", "-z", help="Gzip the output file (.jsonl.gz).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing --output path; replaces a symlink entry, never its target.",
    ),
    page_size: int = typer.Option(1000, "--page-size", min=1, max=1000),
    refresh_token: str | None = typer.Option(
        None, "--refresh-token", envvar="MDE_REFRESH_TOKEN",
        help=(
            "CI/non-interactive: redeem this FOCI refresh token instead of "
            "stored portal auth."
        ),
    ),
) -> None:
    """Stream a device's MDE timeline into a local JSONL artifact.

    By default, stdout contains a compact receipt plus at most two event
    previews; the full stream is written incrementally without buffering.
    Explicit ``--output`` is published atomically with owner-only permissions
    and refuses an existing path unless ``--force`` is supplied. Forced output
    replaces a symlink entry rather than writing through to its target.
    Non-sticky group/world-writable output directories are rejected.

    This is a READ-ONLY command: it does not modify device state.

    Talks to TWO different APIs. `device` is resolved to a MachineId via the
    OFFICIAL MDE `machines` endpoint (xdr-cli's normal AuthManager/XDRClient)
    when it isn't already a 40-hex MachineId. Cookie-authenticated runs also
    verify an exact MachineId through that official tenant before fetching. The
    timeline events themselves
    come from the *unofficial* Defender-portal apiproxy
    (security.microsoft.com/apiproxy/mtp/...) via PortalClient, authenticated
    per the precedence in `xdr auth portal-login` / `portal-cookie` /
    --refresh-token.

    IDENTIFIERS. `device` is a DeviceName (hostname) or a 40-hex DeviceId
    (MachineId). The portal timeline's MachineId IS Advanced Hunting's
    `DeviceId`, and the hostname is `DeviceName` (verified against live data) —
    each event carries both under `Machine.MachineId` / `Machine.Name`. That
    same DeviceId + DeviceName pair keys every `Device*` Advanced Hunting table
    (DeviceInfo, DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, …), so
    a timeline pivots cleanly into a hunt:

        DeviceProcessEvents
        | where DeviceId == '<40-hex MachineId>' and DeviceName =~ '<hostname>'

    See README ("Identifiers & Advanced Hunting cross-reference") for the full
    table list.
    """
    app_ctx: AppContext = ctx.obj

    if force and output is None:
        raise UsageError(
            "--force requires --output PATH.",
            invalid={"kind": "missing_option", "value": "--output"},
            help_command="xdr device timeline --help",
        )
    if gzip_out and output is None:
        raise UsageError(
            "--gzip requires --output PATH.",
            invalid={"kind": "missing_option", "value": "--output"},
            help_command="xdr device timeline --help",
        )
    if hours is not None and days is not None:
        raise UsageError(
            "Use only one of --hours or --days.",
            invalid={
                "kind": "mutually_exclusive_options",
                "value": ["--hours", "--days"],
            },
            allowed=["--hours <N>", "--days <N>"],
            help_command="xdr device timeline --help",
        )

    resolved_to = _ensure_utc(to_date) if to_date is not None else datetime.now(UTC)
    if from_date is not None:
        resolved_from = _ensure_utc(from_date)
    elif hours is not None:
        resolved_from = resolved_to - timedelta(hours=hours)
    else:
        resolved_from = resolved_to - timedelta(days=days if days is not None else 7)

    # Cap is enforced on the RESOLVED window, not just --days: an explicit
    # --from/--to span or an hours-based window over the limit would otherwise
    # skip the guard and get silently truncated server-side.
    if resolved_from > resolved_to:
        raise UsageError(
            "--from must be at or before --to "
            f"(got {resolved_from:%Y-%m-%dT%H:%M:%SZ} after "
            f"{resolved_to:%Y-%m-%dT%H:%M:%SZ}).",
            invalid={"kind": "date_range", "value": "from_after_to"},
            help_command="xdr device timeline --help",
        )
    if resolved_to - resolved_from > timedelta(days=_MAX_TIMELINE_DAYS):
        raise UsageError(
            f"Requested timeline window ({resolved_from:%Y-%m-%d} to "
            f"{resolved_to:%Y-%m-%d}) exceeds {_MAX_TIMELINE_DAYS} days.",
            invalid={"kind": "date_range", "value": "window_too_large"},
            allowed=[f"maximum {_MAX_TIMELINE_DAYS} days"],
            help_command="xdr device timeline --help",
        )

    strategy = _select_portal_auth_strategy(app_ctx, refresh_token)

    asyncio.run(
        _device_timeline(
            app_ctx, device, resolved_from, resolved_to,
            output, gzip_out, force, page_size, strategy,
        )
    )


async def _device_timeline(
    ctx: AppContext,
    device: str,
    from_date: datetime,
    to_date: datetime,
    output: Path | None,
    gzip_out: bool,
    force: bool,
    page_size: int,
    strategy: PortalAuthStrategy,
) -> None:
    _, client = _get_client(ctx)
    try:
        machine_id = await _resolve_machine_id(
            client,
            device,
            verify_exact=isinstance(strategy, CookieAuth),
        )
    finally:
        await client.close()

    portal_client = PortalClient(auth=strategy)
    count = 0
    started = monotonic()
    artifact = None
    try:
        if output is not None:
            with _open_timeline_sink(output, gzip_out, force=force) as sink:
                async for event in stream_device_timeline(
                    portal_client,
                    machine_id,
                    from_date,
                    to_date,
                    page_size=page_size,
                ):
                    sink.write(json.dumps(event, separators=(",", ":")) + "\n")
                    count += 1
        else:
            with ResultStreamWriter(
                command=ctx.invoked_command or "device timeline",
                server_truncation_state="unknown",
                session_id=ctx.session_id,
                session_label=ctx.session_label,
                session_attachment=ctx.session_attachment,
                incident_id=ctx.anchor_incident,
                alert_id=ctx.anchor_alert,
                anchor_provenance=ctx.anchor_provenance,
                extra_metadata={
                    "machine_id": machine_id,
                    "requested_device": device,
                    "from": from_date.isoformat(),
                    "to": to_date.isoformat(),
                    "page_size": page_size,
                },
                tenant_id=ctx.config.tenant_id,
            ) as stream:
                async for event in stream_device_timeline(
                    portal_client,
                    machine_id,
                    from_date,
                    to_date,
                    page_size=page_size,
                ):
                    stream.write_row(event)
                    count += 1
                artifact = stream.finish(
                    execution_time_ms=int((monotonic() - started) * 1000)
                )
    finally:
        await portal_client.close()

    if artifact is not None:
        emit_result(artifact)
    err_console.print(
        f"[bold]{count}[/bold] timeline event(s) written for device "
        f"{machine_id} ({from_date.isoformat()} .. {to_date.isoformat()})."
    )
