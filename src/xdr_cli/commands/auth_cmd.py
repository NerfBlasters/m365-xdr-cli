"""Auth commands: login, logout, status, and the unofficial-portal
counterparts (portal-login, portal-cookie, portal-logout)."""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

import httpx
import typer

from xdr_cli.auth import AuthManager
from xdr_cli.config import ensure_config_dir, get_config_home, save_config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    APIError,
    ConfigError,
    NetworkError,
    NotAuthenticatedError,
    TimeoutError,
)
from xdr_cli.output import OutputFormatter, err_console
from xdr_cli.portal_auth import (
    PORTAL_COOKIE_AUDIT_APP_NAME,
    PORTAL_COOKIE_FILENAME,
    PortalAuth,
    load_portal_cookies,
    save_portal_cookies,
)
from xdr_cli.portal_client import CookieAuth, PortalClient
from xdr_cli.results import tenant_fingerprint

auth_app = typer.Typer(name="auth", help="Authentication management.", no_args_is_help=True)

# `-b '...'` / `--cookie '...'` in a browser "Copy as cURL (bash)" blob. The cookie
# string is single-quoted (bash) form.
_CURL_COOKIE_RE = re.compile(r"(?:-b|--cookie)\s+'([^']*)'")


def _extract_cookie_header(text: str) -> str:
    """Pull the Cookie header value out of whatever the user pasted.

    Accepts (in priority order): a browser "Copy as cURL (bash)" blob (take the
    `-b '...'`/`--cookie '...'` value); a `Cookie:`-prefixed header line; or a
    bare cookie string. Forwarding the *whole* header — not just sccauth —
    is what carries the routing (`X-PortalEndpoint-RouteKey`) and session
    (`s.SessID`) cookies the apiproxy backend requires.
    """
    match = _CURL_COOKIE_RE.search(text)
    if match:
        return match.group(1).strip()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("cookie:"):
            return stripped[len("cookie:"):].strip()
    return text.strip()


def _extract_xsrf_from_cookie_header(cookie_header: str) -> str | None:
    """Return the XSRF token carried in the cookie header, URL-decoded.

    Matches the `XSRF-TOKEN` (browser casing) or `xsrf-token` cookie. The
    stored cookie value is URL-encoded (the `:` shows as `%3A`); the
    `X-XSRF-TOKEN` request header wants the decoded value.
    """
    for pair in cookie_header.split(";"):
        name, _, value = pair.strip().partition("=")
        if name.lower() == "xsrf-token" and value:
            return unquote(value)
    return None


# Minimal authenticated apiproxy GET used by `--verify`. Any endpoint under
# apiproxy/mtp/ that requires a valid session and has no side effects works
# here — this is just a cheap "does the cookie work" ping, not something
# `device timeline` itself depends on (per the design doc, device resolution
# stays on the official Graph API, not the apiproxy).
_PORTAL_VERIFY_PATH = "ndr/machines"


@auth_app.command()
def login(
    ctx: typer.Context,
    tenant_id: str = typer.Option("", "--tenant-id", "-t", help="Azure AD tenant ID."),
    client_id: str = typer.Option("", "--client-id", "-c", help="App registration client ID."),
) -> None:
    """Authenticate interactively (WAM on Windows) with device code fallback."""
    app_ctx: AppContext = ctx.obj

    # Update config if CLI args provided
    if tenant_id:
        app_ctx.config.tenant_id = tenant_id
    if client_id:
        app_ctx.config.client_id = client_id

    if not app_ctx.config.tenant_id or not app_ctx.config.client_id:
        raise ConfigError(
            "tenant_id and client_id are required for interactive login.",
            allowed=["--tenant-id <tenant-id>", "--client-id <client-id>"],
            help_command="xdr auth login --help",
        )

    # Save updated config
    ensure_config_dir()
    save_config(app_ctx.config)

    auth = AuthManager(app_ctx.config)
    auth.login()
    info = auth.get_auth_status()

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(info))


@auth_app.command()
def logout(ctx: typer.Context) -> None:
    """Clear cached authentication tokens."""
    app_ctx: AppContext = ctx.obj
    auth = AuthManager(app_ctx.config)
    cache_path = auth._cache_path()
    cleared = cache_path.exists()
    auth.logout()

    data = {
        "authenticated": False,
        "cleared": cleared,
        "cache_file": str(cache_path),
    }

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(data))


@auth_app.command("portal-login")
def portal_login(
    ctx: typer.Context,
    tenant_id: str | None = typer.Option(
        None, "--tenant-id", help="Override the configured tenant ID."
    ),
) -> None:
    """Log in to the unofficial Defender XDR portal API (MSAL, Azure CLI FOCI).

    Experimental and unverified — cookie auth (`xdr auth portal-cookie`) is the
    validated method; prefer it. This attempts an interactive MSAL sign-in with
    the Microsoft Azure CLI client ID (FOCI) and may not succeed in every
    tenant. If it does, sign-ins are *intended* to attribute to "Microsoft
    Azure CLI" (the FOCI client), not to xdr-cli — but this has not been
    confirmed. See README §"Device Timeline".
    """
    app_ctx: AppContext = ctx.obj
    if tenant_id:
        app_ctx.config.tenant_id = tenant_id

    auth = PortalAuth(app_ctx.config)
    auth.login()
    info = auth.get_auth_status()

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(info))


async def _verify_portal_cookies(
    cookie_header: str, xsrf_token: str
) -> tuple[bool, str | None]:
    """Issue one cheap authenticated apiproxy GET to confirm the pasted
    cookies actually work. Never raises — auth/API failures ("stale paste")
    and transient network errors (DNS/connect/timeout/TLS) are both expected
    outcomes of a best-effort probe, reported back as (False, reason) rather
    than crashing the command (the cookies are already stored at this
    point)."""
    client = PortalClient(auth=CookieAuth(cookie_header=cookie_header, xsrf_token=xsrf_token))
    try:
        await client.probe(_PORTAL_VERIFY_PATH)
    except (
        NotAuthenticatedError,
        APIError,
        NetworkError,
        TimeoutError,
        httpx.HTTPError,
    ) as exc:
        return False, str(exc)
    finally:
        await client.close()
    return True, None


def _store_and_report_portal_cookies(
    app_ctx: AppContext,
    cookie_data: dict,
    verify: bool,
    *,
    cookie_header: str,
    xsrf_token: str,
) -> None:
    """Persist ``cookie_data`` (0600), optionally run the --verify probe, and
    emit the shared status envelope."""
    save_portal_cookies(cookie_data)

    verified: bool | None = None
    verify_error: str | None = None
    if verify:
        verified, verify_error = asyncio.run(
            _verify_portal_cookies(cookie_header, xsrf_token)
        )

    data: dict = {
        "authenticated": True,
        "configured": True,
        "account": None,
        "tenant": app_ctx.config.tenant_id or None,
        "client_id": None,
        "audit_app_name": PORTAL_COOKIE_AUDIT_APP_NAME,
        "stored_at": cookie_data["stored_at"],
        "verified": verified,
    }
    if verify_error:
        data["verify_error"] = verify_error

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(data))


@dataclass(frozen=True)
class _CookieSource:
    text: str
    path: Path | None
    device: int | None
    inode: int | None
    size: int


def _read_cookie_source(source: str) -> _CookieSource:
    """Read the raw cookie material from a file path, or stdin when ``source``
    is ``-``. A file is what makes the *whole* Cookie header usable: a chunked
    `sccauth` pushes it past ~4 KB, which a hidden tty prompt would truncate."""
    if source == "-":
        text = sys.stdin.read()
        return _CookieSource(text=text, path=None, device=None, inode=None, size=0)
    path = Path(source)
    descriptor: int | None = None
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise OSError("cookie source must be a regular file, not a symlink")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise OSError("cookie source changed while it was being opened")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = None
            text = handle.read()
        return _CookieSource(
            text=text,
            path=path,
            device=opened.st_dev,
            inode=opened.st_ino,
            size=opened.st_size,
        )
    except OSError as exc:
        raise ConfigError(
            f"Could not read portal cookie source: {exc}",
            invalid={"kind": "path", "value": source},
            help_command="xdr auth portal-cookie --help",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _has_sccauth_cookie(cookie_header: str) -> bool:
    """True if the header carries an `sccauth` cookie — the defining Defender
    portal session cookie (present whether or not it's chunked). Used as the
    validity gate: without it the source isn't a portal session, so we neither
    store it nor (crucially) shred the file — `_extract_cookie_header`'s lenient
    fallback would otherwise treat any non-empty file as a cookie header and
    turn a fat-fingered path into a file wipe."""
    return any(
        pair.strip().partition("=")[0].strip().lower() == "sccauth"
        for pair in cookie_header.split(";")
    )


def _shred_file(source: _CookieSource) -> bool:
    """Best-effort secure delete of a cookie source file: overwrite with random
    bytes, fsync, then unlink. Not guaranteed on SSD/CoW/journaling filesystems
    (wear-levelling may retain copies), but removes the plaintext credential
    from its obvious on-disk location. Returns False rather than touching a
    pathname that no longer identifies the exact regular file read earlier."""
    if source.path is None or source.device is None or source.inode is None:
        return False
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(source.path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (source.device, source.inode)
        ):
            return False
        remaining = opened.st_size
        while remaining:
            chunk = os.urandom(min(remaining, 1024 * 1024))
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            remaining -= len(chunk)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        current = source.path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (source.device, source.inode)
        ):
            return False
        source.path.unlink()
        return True
    except OSError:
        return False
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)


@auth_app.command("portal-cookie")
def portal_cookie(
    ctx: typer.Context,
    source: str = typer.Argument(
        ...,
        metavar="COOKIE_SOURCE",
        help="File holding the full browser Cookie header or a 'Copy as cURL (bash)' "
        "blob; use '-' to read it from stdin.",
    ),
    verify: bool = typer.Option(
        True,
        "--verify/--no-verify",
        help="After storing, make one lightweight apiproxy call to confirm the cookies work.",
    ),
    keep_source: bool = typer.Option(
        False,
        "--keep-source",
        help="Keep the cookie source file after import (default: identity-bound "
        "best-effort overwrite and delete).",
    ),
) -> None:
    """Configure portal auth from a logged-in security.microsoft.com session.

    The validated, recommended portal-auth method (the FOCI/MSAL `portal-login`
    flow is experimental and unverified). Provide the WHOLE browser Cookie
    header: in Microsoft Edge (logged in to security.microsoft.com), open
    DevTools > Network, right-click the timeline apiproxy request > Copy >
    "Copy as cURL (bash)" (the cmd/PowerShell variants are untested), save it
    to a file, and
    pass that file (or pipe it in with `-`). xdr forwards every cookie —
    including the routing (`X-PortalEndpoint-RouteKey`) and session (`s.SessID`)
    cookies the apiproxy requires, and a chunked `sccauth` (`chunks:N` +
    `sccauthC1..N`) — verbatim. The sccauth-only form omits the routing/session
    cookies and the backend answers with an opaque 500, which is why the whole
    header is required. The XSRF token is auto-extracted from the header (you're
    prompted only if it carries no `XSRF-TOKEN` cookie). Stored in
    ~/.xdr-cli/portal_cookies.json (0600), bound to the configured tenant's
    non-reversible fingerprint — cookie values never reach argv. Legacy or
    different-tenant stores must be re-imported.

    On a successful import the exact regular source file is overwritten and
    deleted on a best-effort basis; pass `--keep-source` to keep it. Symlinks
    are rejected, and cleanup stops with a warning when an identity change is
    detected. A source without an `sccauth` cookie is never shredded.
    """
    app_ctx: AppContext = ctx.obj

    opened_source = _read_cookie_source(source)
    cookie_header = _extract_cookie_header(opened_source.text)
    if not cookie_header or not _has_sccauth_cookie(cookie_header):
        error = ConfigError(
            "The source has no sccauth cookie and is not a valid Defender "
            "portal session. Nothing was stored or deleted.",
            invalid={"kind": "portal_cookie_source", "value": source},
            help_command="xdr auth portal-cookie --help",
        )
        error.error_code = "PORTAL_COOKIE_INVALID"
        raise error

    xsrf_token = _extract_xsrf_from_cookie_header(cookie_header)
    if not xsrf_token:
        err_console.print(
            "[yellow]Note:[/yellow] no XSRF-TOKEN cookie in the header; "
            "enter the xsrf-token value manually."
        )
        xsrf_token = typer.prompt("xsrf-token", hide_input=True)
    if not xsrf_token.strip():
        error = ConfigError(
            "xsrf-token must not be empty.",
            invalid={"kind": "portal_cookie", "value": "xsrf-token"},
            help_command="xdr auth portal-cookie --help",
        )
        error.error_code = "PORTAL_XSRF_TOKEN_MISSING"
        raise error

    fingerprint = tenant_fingerprint(app_ctx.config.tenant_id)
    if fingerprint is None:
        raise ConfigError(
            "A configured tenant is required before importing portal cookies. "
            "Run `xdr auth login --tenant-id <ID> --client-id <ID>` first.",
            invalid={"kind": "missing_config", "value": "tenant_id"},
            help_command="xdr auth login --help",
        )
    cookie_data: dict = {
        "cookie_header": cookie_header,
        "xsrf_token": xsrf_token,
        "stored_at": datetime.now(UTC).isoformat(),
        "tenant_fingerprint": fingerprint,
    }
    _store_and_report_portal_cookies(
        app_ctx, cookie_data, verify, cookie_header=cookie_header, xsrf_token=xsrf_token
    )

    # The cookies are stored — the source file has served its purpose. It holds
    # live session cookies, so shred it by default. Only reached past the
    # `sccauth` gate above, so a non-cookie file is never touched. stdin (`-`)
    # is not a file to shred.
    if opened_source.path is not None:
        if keep_source:
            err_console.print(
                f"[yellow]Kept cookie source[/yellow] {source} — it holds live "
                "session cookies; delete it when you're done."
            )
        else:
            if _shred_file(opened_source):
                err_console.print(f"[dim]Shredded cookie source: {source}[/dim]")
            else:
                err_console.print(
                    f"[yellow]Warning:[/yellow] could not safely shred cookie source "
                    f"{source}; the path changed or is no longer the validated regular "
                    "file. Inspect and remove the original credential capture manually."
                )


@auth_app.command("portal-logout")
def portal_logout(ctx: typer.Context) -> None:
    """Clear cached Defender portal credentials (MSAL cache + cookie store).

    Removes both ~/.xdr-cli/portal_token_cache.json and
    ~/.xdr-cli/portal_cookies.json. Does not touch the main
    ~/.xdr-cli/token_cache.json used by `xdr auth login`/`xdr auth logout`.
    Missing files are a no-op.
    """
    app_ctx: AppContext = ctx.obj
    auth = PortalAuth(app_ctx.config)
    token_cache_path = auth._cache_path()
    token_cache_cleared = token_cache_path.exists()
    auth.logout()  # clears portal_token_cache.json; no-op if absent

    cookie_path = get_config_home() / PORTAL_COOKIE_FILENAME
    cookie_cleared = cookie_path.exists()
    if cookie_path.exists():
        cookie_path.unlink()

    data = {
        "authenticated": False,
        "token_cache_cleared": token_cache_cleared,
        "cookie_cleared": cookie_cleared,
        "token_cache_file": str(token_cache_path),
        "cookie_file": str(cookie_path),
    }

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    typer.echo(fmt.format_output(data))


@auth_app.command()
def status(ctx: typer.Context) -> None:
    """Show current authentication status."""
    app_ctx: AppContext = ctx.obj
    auth = AuthManager(app_ctx.config)
    main_info = auth.get_auth_status()

    portal_auth = PortalAuth(app_ctx.config)
    portal_status = portal_auth.get_auth_status()
    msal_cached = bool(portal_status["authenticated"])
    cookie_stored = load_portal_cookies(app_ctx.config.tenant_id) is not None

    # Precedence mirrors auth-strategy selection for `device timeline`
    # (Task 8): a deliberately-configured cookie store wins over a cached
    # MSAL account, since its presence means the user ran `portal-cookie`
    # (typically because FOCI/MSAL is blocked in their tenant).
    if cookie_stored:
        method: str | None = "cookie"
        portal_authenticated = True
        portal_account = None
        portal_audit_app_name: str | None = PORTAL_COOKIE_AUDIT_APP_NAME
    elif msal_cached:
        method = "msal"
        portal_authenticated = True
        portal_account = portal_status["account"]
        portal_audit_app_name = portal_status["audit_app_name"]
    else:
        method = None
        portal_authenticated = False
        portal_account = None
        portal_audit_app_name = None

    portal_info = {
        "authenticated": portal_authenticated,
        "method": method,
        "account": portal_account,
        "tenant": app_ctx.config.tenant_id or None,
        "audit_app_name": portal_audit_app_name,
        "msal_cached": msal_cached,
        "cookie_stored": cookie_stored,
    }

    info = {"main": main_info, "portal": portal_info}

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    output = fmt.format_output(info)
    typer.echo(output)
