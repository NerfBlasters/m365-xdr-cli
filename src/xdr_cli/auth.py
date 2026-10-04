"""MSAL authentication: device code flow and client credentials."""

from __future__ import annotations

import asyncio
import multiprocessing
import time
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

import msal
from filelock import Timeout as FileLockTimeout
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

from xdr_cli._lock import exclusive_lock
from xdr_cli.config import Config, ensure_config_dir, get_config_home
from xdr_cli.exceptions import (
    AuthError,
    ConfigError,
    NetworkError,
    NotAuthenticatedError,
    PermissionError,
    XDRError,
)
from xdr_cli.exceptions import TimeoutError as XDRTimeoutError
from xdr_cli.output import err_console
from xdr_cli.secret_files import atomic_write_secret

# Default scopes — /.default defers to app registration permissions
SCOPES = ["https://graph.microsoft.com/.default"]

# Per-resource scopes. Graph (incidents/alerts) and MDE (hunting/device
# actions) have separate audiences; MSAL issues a refresh token on login
# and silently exchanges it for whichever resource's access token is needed.
# Note: MDE endpoints live under api.security.microsoft.com but tokens must
# be issued for the api.securitycenter.microsoft.com audience — this matches
# Microsoft's current guidance (see the WindowsDefenderATP footnote in the
# README permissions table).
SCOPES_GRAPH = ["https://graph.microsoft.com/.default"]
SCOPES_MDE = ["https://api.securitycenter.microsoft.com/.default"]

# Scopes pre-warmed at login so silent acquisition later doesn't pop a WAM
# prompt mid-command. Graph covers incidents/alerts/hunting; MDE covers
# device actions and the legacy hunting endpoint used as a fallback.
_ALL_LOGIN_SCOPES = [SCOPES_GRAPH, SCOPES_MDE]

_TOKEN_BUDGET: ContextVar[tuple[float, Callable[[], int]] | None] = ContextVar(
    "xdr_token_budget", default=None,
)


@contextmanager
def bounded_token_acquisition(deadline: float, cancelled: Callable[[], int]):
    """Bound synchronous token/cache I/O without leaving a writing thread behind."""
    token = _TOKEN_BUDGET.set((deadline, cancelled))
    try:
        yield
    finally:
        _TOKEN_BUDGET.reset(token)


def _token_deadline_error() -> XDRTimeoutError:
    error = XDRTimeoutError(
        "Session-end schema maintenance reached its token acquisition deadline.",
        help_command="xdr auth status",
    )
    error.error_code = "SESSION_SCHEMA_MAINTENANCE_TIMEOUT"
    return error


def _token_worker(connection, config: Config, scopes, timeout: float):
    """Own all token I/O in a process that the caller can stop and reap."""
    try:
        # get_token only uses silent acquisition; never call login or an
        # interactive/device-code fallback, including on broker platforms.
        manager = AuthManager(config, token_timeout=timeout)
        connection.send(("token", manager.get_token(scopes)))
    except XDRError as exc:
        connection.send(("error", type(exc).__name__, vars(exc)))
    except RequestsTimeout:
        error = XDRTimeoutError(
            "Noninteractive token acquisition timed out.", help_command="xdr auth status",
        )
        connection.send(("error", "TimeoutError", vars(error)))
    except RequestsConnectionError:
        error = NetworkError(
            "Noninteractive token acquisition could not connect.", help_command="xdr auth status",
        )
        connection.send(("error", "NetworkError", vars(error)))
    except Exception as exc:
        # Do not expose SDK response bodies, tokens, or arbitrary exception text.
        error = AuthError("Noninteractive token acquisition failed: " + type(exc).__name__)
        connection.send(("error", "AuthError", vars(error)))
    finally:
        connection.close()


def _acquire_bounded_token(config: Config, scopes, budget) -> str:
    deadline, cancelled = budget

    def check_budget():
        # asyncio.run's first SIGINT cancels its task while synchronous code
        # is still executing. Poll that cancellation here instead of requiring
        # a second interrupt to break the cache lock or HTTP request.
        if cancelled():
            raise asyncio.CancelledError
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _token_deadline_error()
        return remaining

    remaining = check_budget()
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(
        target=_token_worker, args=(send, config, scopes, min(config.api_timeout, remaining)),
        name="xdr-token",
    )
    started = False
    try:
        process.start()
        started = True
        send.close()
        while not receive.poll(min(0.025, check_budget())):
            if not process.is_alive():
                raise AuthError("Noninteractive token acquisition ended without a result.")
        check_budget()
        try:
            result = receive.recv()
        except EOFError as exc:
            raise AuthError("Noninteractive token acquisition ended without a result.") from exc
        if result[0] == "token":
            return result[1]
        from xdr_cli import exceptions

        error_type = getattr(exceptions, result[1], AuthError)
        if not isinstance(error_type, type) or not issubclass(error_type, XDRError):
            error_type = AuthError
        error = error_type.__new__(error_type)
        XDRError.__init__(error, result[2]["message"])
        error.__dict__.update(result[2])
        raise error
    finally:
        send.close()
        receive.close()
        if started:
            # Completion, timeout, and cancellation all guarantee that no
            # child remains able to write the cache after this call returns.
            if process.is_alive():
                process.terminate()
            process.join(timeout=0.5)
            if process.is_alive():
                process.kill()
                process.join()
            process.close()


def _missing_scope_error(scope: str, description: str) -> PermissionError:
    error = PermissionError(
        f"Admin consent is missing for scope {scope!r}: {description}",
        invalid={"kind": "permission_scope", "value": scope},
        suggestions=[
            {
                "reason": "admin_consent",
                "message": (
                    "Add the required API permission in the Entra app "
                    "registration and grant tenant admin consent."
                ),
                "confidence": "exact",
            }
        ],
        help_command="xdr auth status",
    )
    error.error_code = "PERMISSION_MISSING_SCOPE"
    return error


class AuthManager:
    """Manage OAuth2 tokens via MSAL."""

    def __init__(
        self, config: Config, *, token_timeout: float | None = None,
    ) -> None:
        self._config = config
        self._token_timeout = token_timeout if token_timeout is not None else config.api_timeout
        self._cache = msal.SerializableTokenCache()
        if _TOKEN_BUDGET.get() is None:
            self._load_cache()
        self._app: msal.ClientApplication | None = None
        self._is_confidential = (
            config.auth_mode == "client_credentials" and bool(config.client_secret)
        )

    def is_configured(self) -> bool:
        """True if tenant_id and client_id are set."""
        return bool(self._config.tenant_id and self._config.client_id)

    def _get_app(self) -> msal.ClientApplication:
        """Lazily build the MSAL app. Raises AuthError if not configured."""
        if self._app is not None:
            return self._app
        if not self.is_configured():
            raise ConfigError(
                "Not configured. Run `xdr auth login --tenant-id <ID> --client-id <ID>`."
            )
        authority = f"https://login.microsoftonline.com/{self._config.tenant_id}"
        if self._is_confidential:
            self._app = msal.ConfidentialClientApplication(
                client_id=self._config.client_id,
                client_credential=self._config.client_secret,
                authority=authority,
                token_cache=self._cache,
                validate_authority=False,
                timeout=self._token_timeout,
            )
        else:
            self._app = msal.PublicClientApplication(
                client_id=self._config.client_id,
                authority=authority,
                token_cache=self._cache,
                validate_authority=False,
                timeout=self._token_timeout,
                # Use WAM broker on Windows so the device's Primary Refresh Token
                # (PRT) is passed, satisfying Conditional Access device compliance
                # and platform policies. Falls back gracefully on non-Windows.
                enable_broker_on_windows=True,
            )
        return self._app

    def _cache_path(self) -> Path:
        return get_config_home() / "token_cache.json"

    def _load_cache(self) -> None:
        """Load token cache from disk, tolerating corruption.

        A truncated or garbage token_cache.json otherwise raises from MSAL's
        deserializer and bricks every `xdr` command with an opaque stack
        trace. Fall through to an empty in-memory cache and let the user
        re-authenticate on demand.
        """
        path = self._cache_path()
        if not path.exists():
            return
        try:
            self._cache.deserialize(path.read_text())
        except (ValueError, OSError) as exc:
            err_console.print(
                f"[yellow]Warning:[/yellow] token cache at {path} is "
                f"unreadable ({exc.__class__.__name__}: {exc}); "
                "starting with an empty cache. Re-run `xdr auth login` "
                "if commands start prompting."
            )
            self._cache = msal.SerializableTokenCache()

    def _save_cache(self) -> None:
        """Persist token cache to disk atomically."""
        if not self._cache.has_state_changed:
            return
        atomic_write_secret(self._cache_path(), self._cache.serialize())

    @contextmanager
    def _cache_transaction(self, *, timeout: float = -1):
        """Serialize cache reload/acquisition/save across xdr processes."""

        path = self._cache_path()
        ensure_config_dir()
        with exclusive_lock(path, timeout=timeout):
            refreshed = msal.SerializableTokenCache()
            if path.exists():
                try:
                    refreshed.deserialize(path.read_text())
                except (ValueError, OSError):
                    refreshed = msal.SerializableTokenCache()
            self._cache = refreshed
            # MSAL applications retain the cache object supplied at
            # construction, so rebuild lazily after replacing it. Resetting on
            # a missing path also prevents a manager created before `logout`
            # from resurrecting the deleted cache.
            self._app = None
            yield

    def get_token(self, scopes: list[str] | None = None) -> str:
        """Get a valid access token for the given scopes (Graph by default)."""
        if budget := _TOKEN_BUDGET.get():
            return _acquire_bounded_token(self._config, scopes, budget)
        try:
            with self._cache_transaction(timeout=min(5.0, self._token_timeout)):
                return self._get_token_locked(scopes)
        except FileLockTimeout as exc:
            error = XDRTimeoutError("Token cache is busy; retry after the current login finishes.")
            error.help_command = "xdr auth status"
            error.error_code = "AUTH_CACHE_LOCK_TIMEOUT"
            raise error from exc

    def _get_token_locked(self, scopes: list[str] | None = None) -> str:
        """Acquire one token while the cross-process cache lock is held."""
        scopes = scopes or SCOPES_GRAPH
        app = self._get_app()
        if self._is_confidential:
            result = app.acquire_token_for_client(scopes=scopes)
            if not result or "access_token" not in result:
                error_description = (result or {}).get("error_description", "unknown")
                if (
                    "AADSTS65001" in error_description
                    or "consent" in error_description.lower()
                ):
                    raise _missing_scope_error(scopes[0], error_description)
                raise AuthError(
                    f"Client credentials auth failed: {error_description}"
                )
            self._save_cache()
            return result["access_token"]

        accounts = app.get_accounts()
        if not accounts:
            raise NotAuthenticatedError()

        result = app.acquire_token_silent_with_error(scopes, account=accounts[0])
        if result and "access_token" in result:
            self._save_cache()
            return result["access_token"]

        error = (result or {}).get("error", "")
        error_desc = (result or {}).get("error_description", "")

        if "AADSTS65001" in error_desc or "consent" in error_desc.lower():
            raise _missing_scope_error(scopes[0], error_desc)

        # Silent acquisition signals interaction required. This can mean the
        # token genuinely expired and a re-login will fix it, OR the scope
        # isn't consented on the app registration (in which case re-login
        # won't help — the resource's API permissions need to be added in
        # Entra ID and admin-consented).
        interaction_required = (
            error == "interaction_required"
            or (result or {}).get("suberror") == "interaction_required"
        )
        if interaction_required:
            raise AuthError(
                f"Interactive authentication required for scope {scopes[0]!r}. "
                "Try `xdr auth logout && xdr auth login`. If that fails, verify "
                "the app registration has this resource's API permissions "
                "granted with admin consent."
            )

        if error or error_desc:
            raise AuthError(f"Silent token acquisition failed: {error_desc or error}")
        raise NotAuthenticatedError()

    def login(self) -> dict:
        """Authenticate interactively (browser on this machine) with device code fallback."""
        with self._cache_transaction():
            return self._login_locked()

    def _login_locked(self) -> dict:
        """Run interactive login while the cross-process cache lock is held."""
        app = self._get_app()

        # Try interactive auth first — WAM uses the device's PRT so Conditional
        # Access device-platform/compliance policies are satisfied automatically.
        # CONSOLE_WINDOW_HANDLE tells WAM this is a console (not GUI) app on Windows.
        # Falls back to device code when no display is available (headless/CI).
        try:
            result = app.acquire_token_interactive(
                scopes=SCOPES,
                prompt="select_account",
                parent_window_handle=app.CONSOLE_WINDOW_HANDLE,
            )
            if "access_token" in result:
                # Persist the primary token before attempting pre-warms —
                # if a pre-warm blows up (cancelled WAM dialog, CA block on
                # the MDE scope, headless fallback race), we still keep the
                # Graph token the user just acquired.
                self._save_cache()
                # Pre-warm token cache for all API audiences so silent
                # acquisition later doesn't pop a prompt mid-command. Each
                # pre-warm is isolated: a failure logs a hint but must not
                # invalidate the primary login.
                accounts = app.get_accounts()
                if accounts:
                    for extra_scopes in _ALL_LOGIN_SCOPES:
                        if extra_scopes == SCOPES:
                            continue
                        try:
                            warm = app.acquire_token_silent(
                                extra_scopes, account=accounts[0]
                            )
                            if not warm or "access_token" not in warm:
                                # Silent failed (new resource, first-time
                                # consent) — use WAM interactively now so
                                # later commands don't prompt.
                                err_console.print(
                                    f"[dim]Consenting scope {extra_scopes[0]}...[/dim]"
                                )
                                app.acquire_token_interactive(
                                    scopes=extra_scopes,
                                    account=accounts[0],
                                    parent_window_handle=app.CONSOLE_WINDOW_HANDLE,
                                )
                        except Exception as warm_exc:
                            err_console.print(
                                f"[yellow]Warning:[/yellow] could not pre-warm "
                                f"scope {extra_scopes[0]} ({warm_exc}); the first "
                                "command that needs it will prompt."
                            )
                self._save_cache()
                err_console.print("[bold green]Login successful.[/bold green]\n")
                return result
            # Interactive succeeded but no token — surface the error
            error_desc = result.get("error_description", result.get("error", "unknown"))
            raise AuthError(f"Interactive authentication failed: {error_desc}")
        except AuthError:
            raise
        except Exception as exc:
            # No display, broker unavailable, or unsupported platform — fall through
            err_console.print(
                f"[dim]Interactive auth unavailable ({exc}), "
                "falling back to device code...[/dim]"
            )

        # Device code fallback (headless environments or non-Windows)
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise AuthError(f"Device code flow failed: {flow.get('error_description', 'unknown')}")

        err_console.print(
            f"\n[bold]To sign in:[/bold] Visit [link]{flow['verification_uri']}[/link] "
            f"and enter code [bold cyan]{flow['user_code']}[/bold cyan]\n"
        )

        result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise AuthError(
                f"Authentication failed: {result.get('error_description', 'unknown error')}"
            )

        self._save_cache()
        err_console.print("[bold green]Login successful.[/bold green]\n")
        return result

    def logout(self) -> None:
        """Clear cached tokens."""
        path = self._cache_path()
        ensure_config_dir()
        with exclusive_lock(path, timeout=-1):
            if path.exists():
                path.unlink()
            self._cache = msal.SerializableTokenCache()
            self._app = None
        err_console.print("[bold]Logged out. Token cache cleared.[/bold]")

    def get_auth_status(self) -> dict:
        """Return current auth status as a dict (for `xdr auth status`)."""
        if not self.is_configured():
            return {
                "authenticated": False,
                "configured": False,
                "account": None,
                "hint": "Run `xdr auth login --tenant-id <ID> --client-id <ID>` to configure.",
            }
        accounts = self._get_app().get_accounts()
        if not accounts:
            return {
                "authenticated": False,
                "configured": True,
                "account": None,
                "tenant": self._config.tenant_id,
            }
        return {
            "authenticated": True,
            "configured": True,
            "account": accounts[0].get("username", "unknown"),
            "tenant": self._config.tenant_id,
        }
