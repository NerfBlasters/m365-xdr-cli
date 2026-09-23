"""MSAL authentication for the unofficial Microsoft Defender portal API.

`PortalAuth` mirrors `AuthManager` (see auth.py) but talks to the
apiproxy endpoints behind security.microsoft.com, which don't accept
app-only (client-credentials) tokens and aren't covered by a user-supplied
app registration. It always uses a public client authenticated as the FOCI
Azure CLI client id, and persists to its own token cache file so it never
collides with AuthManager's Graph/MDE token_cache.json.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

import msal

from xdr_cli._lock import exclusive_lock
from xdr_cli.config import Config, ensure_config_dir, get_config_home
from xdr_cli.exceptions import AuthError, ConfigError, NotAuthenticatedError
from xdr_cli.output import err_console
from xdr_cli.results import tenant_fingerprint
from xdr_cli.secret_files import atomic_write_secret

# FOCI public client — Azure CLI. Chosen over Teams because Azure CLI has
# http://localhost redirect URIs registered, which MSAL needs for interactive
# (browser) auth. Both work for device-code flow. Sign-in logs will attribute
# timeline activity to "Microsoft Azure CLI" — by design, see README.
PORTAL_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# Microsoft 365 Security Center resource. This is the audience the apiproxy
# endpoints under security.microsoft.com require.
PORTAL_RESOURCE = "80ccca67-54bd-44ab-8625-4b79c4dc7775"
PORTAL_SCOPES = [f"{PORTAL_RESOURCE}/.default"]

PORTAL_CACHE_FILENAME = "portal_token_cache.json"

# Cookie store for the `xdr auth portal-cookie` path — an alternative to the
# FOCI/MSAL flow above for tenants that block or assignment-restrict the
# Azure CLI client. Holds the cookie material, storage time, and a non-reversible
# tenant fingerprint; see
# save_portal_cookies()/load_portal_cookies() below.
PORTAL_COOKIE_FILENAME = "portal_cookies.json"

# Literal app name Entra sign-in logs will show for portal-timeline activity,
# since we authenticate as the FOCI Azure CLI client. Surfaced by
# get_auth_status() so callers (e.g. `xdr auth status`) can disclose it.
AUDIT_APP_NAME = "Microsoft Azure CLI"

# Cookie auth rides the analyst's existing Defender portal browser session
# rather than minting a fresh Azure CLI token issuance, so it generally does
# NOT surface as a new "Microsoft Azure CLI" sign-in event. Surfaced by
# `xdr auth status` so the cookie path isn't mislabeled with the MSAL path's
# attribution string.
PORTAL_COOKIE_AUDIT_APP_NAME = "Microsoft Defender portal (browser session)"


def _portal_cookie_path() -> Path:
    return get_config_home() / PORTAL_COOKIE_FILENAME


def save_portal_cookies(data: dict) -> None:
    """Persist portal cookie credentials to disk (0600, atomic replace).

    ``data`` is expected to contain the cookie header, XSRF token, storage
    time, and tenant fingerprint from `xdr auth portal-cookie`. Uses the same
    atomic-write-with-0600 helper as the MSAL token caches, so the cookie
    values never land on disk with permissive permissions even transiently.
    """
    atomic_write_secret(_portal_cookie_path(), json.dumps(data))


def load_portal_cookies(tenant_id: str) -> dict | None:
    """Load stored portal cookies only when bound to ``tenant_id``.

    Mirrors ``_load_cache``'s corruption tolerance for malformed JSON. A
    parseable legacy or cross-tenant store is rejected explicitly rather than
    silently selected. A truncated or garbage
    portal_cookies.json must not brick every command that checks for cookie
    auth (e.g. `xdr auth status`, `device timeline`'s auth-strategy
    selection) — fall through to None and let the user re-run
    `xdr auth portal-cookie`.
    """
    path = _portal_cookie_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (ValueError, OSError) as exc:
        err_console.print(
            f"[yellow]Warning:[/yellow] portal cookie store at {path} is "
            f"unreadable ({exc.__class__.__name__}: {exc}); ignoring. "
            "Re-run `xdr auth portal-cookie` to reconfigure."
        )
        return None
    expected = tenant_fingerprint(tenant_id)
    actual = data.get("tenant_fingerprint") if isinstance(data, dict) else None
    if expected is None or actual != expected:
        reason = "missing" if actual is None else "different"
        error = ConfigError(
            "Stored Defender portal cookies are not bound to the configured "
            f"tenant ({reason} tenant fingerprint). Re-run "
            "`xdr auth portal-cookie <cookie-source>` for this tenant.",
            invalid={"kind": "portal_cookie_tenant_binding", "value": reason},
            help_command="xdr auth portal-cookie --help",
        )
        error.error_code = "PORTAL_COOKIE_TENANT_MISMATCH"
        raise error
    return data


class PortalAuth:
    """Manage OAuth2 tokens for the unofficial Defender portal API via MSAL."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._cache = msal.SerializableTokenCache()
        self._load_cache()
        self._app: msal.PublicClientApplication | None = None

    def is_configured(self) -> bool:
        """True if tenant_id is set. client_id is hardcoded FOCI, not user-supplied."""
        return bool(self._config.tenant_id)

    def _get_app(self) -> msal.PublicClientApplication:
        """Lazily build the MSAL app. Raises AuthError if not configured."""
        if self._app is not None:
            return self._app
        if not self.is_configured():
            raise AuthError(
                "Not configured. Run `xdr auth login --tenant-id <ID>`, "
                "then `xdr auth portal-login`."
            )
        authority = f"https://login.microsoftonline.com/{self._config.tenant_id}"
        self._app = msal.PublicClientApplication(
            client_id=PORTAL_CLIENT_ID,
            authority=authority,
            token_cache=self._cache,
            validate_authority=False,
            # Use WAM broker on Windows so the device's Primary Refresh Token
            # (PRT) is passed, satisfying Conditional Access device compliance
            # and platform policies. Falls back gracefully on non-Windows.
            enable_broker_on_windows=True,
        )
        return self._app

    def _cache_path(self) -> Path:
        return get_config_home() / PORTAL_CACHE_FILENAME

    def _load_cache(self) -> None:
        """Load token cache from disk, tolerating corruption.

        A truncated or garbage portal_token_cache.json otherwise raises from
        MSAL's deserializer and bricks portal-timeline commands with an
        opaque stack trace. Fall through to an empty in-memory cache and let
        the user re-authenticate on demand.
        """
        path = self._cache_path()
        if not path.exists():
            return
        try:
            self._cache.deserialize(path.read_text())
        except (ValueError, OSError) as exc:
            err_console.print(
                f"[yellow]Warning:[/yellow] portal token cache at {path} is "
                f"unreadable ({exc.__class__.__name__}: {exc}); "
                "starting with an empty cache. Re-run `xdr auth portal-login` "
                "if commands start prompting."
            )
            self._cache = msal.SerializableTokenCache()

    def _save_cache(self) -> None:
        """Persist token cache to disk atomically."""
        if not self._cache.has_state_changed:
            return
        atomic_write_secret(self._cache_path(), self._cache.serialize())

    @contextmanager
    def _cache_transaction(self):
        """Serialize portal-cache reload/acquisition/save across processes."""

        path = self._cache_path()
        ensure_config_dir()
        with exclusive_lock(path, timeout=-1):
            refreshed = msal.SerializableTokenCache()
            if path.exists():
                try:
                    refreshed.deserialize(path.read_text())
                except (ValueError, OSError):
                    refreshed = msal.SerializableTokenCache()
            self._cache = refreshed
            # A manager instantiated before another process logs out must not
            # resurrect the deleted cache from its stale in-memory copy.
            self._app = None
            yield

    def get_token(self, force_refresh: bool = False) -> str:
        """Get a valid access token for the Defender portal (PORTAL_SCOPES).

        `force_refresh=True` bypasses MSAL's silent cache and redeems a new
        access token — used by `BearerAuth.refresh()` to recover from a portal
        401 (a still-cached token the server has since rejected).
        """
        with self._cache_transaction():
            return self._get_token_locked(force_refresh)

    def _get_token_locked(self, force_refresh: bool = False) -> str:
        """Acquire one portal token while the cache lock is held."""
        app = self._get_app()

        accounts = app.get_accounts()
        if not accounts:
            raise NotAuthenticatedError()

        result = app.acquire_token_silent_with_error(
            PORTAL_SCOPES, account=accounts[0], force_refresh=force_refresh
        )
        if result and "access_token" in result:
            self._save_cache()
            return result["access_token"]

        error = (result or {}).get("error", "")
        error_desc = (result or {}).get("error_description", "")

        # Silent acquisition signals interaction required — the cached
        # account exists but its refresh token can't silently mint a portal
        # token (expired, revoked, or first-time consent for this scope).
        interaction_required = (
            error == "interaction_required"
            or (result or {}).get("suberror") == "interaction_required"
        )
        if interaction_required:
            raise AuthError(
                "Interactive authentication required for the Defender portal. "
                "Run `xdr auth portal-login`."
            )

        if error or error_desc:
            raise AuthError(f"Silent token acquisition failed: {error_desc or error}")
        raise NotAuthenticatedError()

    def login(self) -> dict:
        """Authenticate interactively (browser on this machine) with device code fallback."""
        with self._cache_transaction():
            return self._login_locked()

    def _login_locked(self) -> dict:
        """Run portal login while the cross-process cache lock is held."""
        app = self._get_app()

        # Try interactive auth first — WAM uses the device's PRT so Conditional
        # Access device-platform/compliance policies are satisfied automatically.
        # CONSOLE_WINDOW_HANDLE tells WAM this is a console (not GUI) app on Windows.
        # Falls back to device code when no display is available (headless/CI).
        # No scope pre-warming here — there's only one scope (PORTAL_SCOPES).
        try:
            result = app.acquire_token_interactive(
                scopes=PORTAL_SCOPES,
                prompt="select_account",
                parent_window_handle=app.CONSOLE_WINDOW_HANDLE,
            )
            if "access_token" in result:
                self._save_cache()
                err_console.print("[bold green]Portal login successful.[/bold green]\n")
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
        flow = app.initiate_device_flow(scopes=PORTAL_SCOPES)
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
        err_console.print("[bold green]Portal login successful.[/bold green]\n")
        return result

    def logout(self) -> None:
        """Clear cached portal tokens."""
        path = self._cache_path()
        ensure_config_dir()
        with exclusive_lock(path, timeout=-1):
            if path.exists():
                path.unlink()
            self._cache = msal.SerializableTokenCache()
            self._app = None
        err_console.print("[bold]Logged out of Defender portal. Token cache cleared.[/bold]")

    def get_auth_status(self) -> dict:
        """Return current portal auth status as a dict (for `xdr auth status`)."""
        if not self.is_configured():
            return {
                "authenticated": False,
                "configured": False,
                "account": None,
                "tenant": None,
                "client_id": PORTAL_CLIENT_ID,
                "audit_app_name": AUDIT_APP_NAME,
            }
        accounts = self._get_app().get_accounts()
        account = accounts[0].get("username", "unknown") if accounts else None
        return {
            "authenticated": bool(accounts),
            "configured": True,
            "account": account,
            "tenant": self._config.tenant_id,
            "client_id": PORTAL_CLIENT_ID,
            "audit_app_name": AUDIT_APP_NAME,
        }
