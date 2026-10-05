"""Credential constants and cookie store for the unofficial Defender portal API.

The apiproxy endpoints behind security.microsoft.com don't accept app-only
(client-credentials) tokens and aren't covered by a user-supplied app
registration. Two credential sources are supported: a browser session
imported by `xdr auth portal-cookie` (the cookie store below) and a
pre-obtained FOCI refresh token redeemed per run by
`portal_client.RefreshTokenAuth` using the constants below.
"""

from __future__ import annotations

import json
from pathlib import Path

from xdr_cli.config import get_config_home
from xdr_cli.exceptions import ConfigError
from xdr_cli.output import err_console
from xdr_cli.results import tenant_fingerprint
from xdr_cli.secret_files import atomic_write_secret

# FOCI public client — Azure CLI. `RefreshTokenAuth` redeems a caller-supplied
# refresh token as this client, so sign-in logs attribute that activity to
# "Microsoft Azure CLI" — by design, see docs/device_timeline.md.
PORTAL_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# Microsoft 365 Security Center resource. This is the audience the apiproxy
# endpoints under security.microsoft.com require.
PORTAL_RESOURCE = "80ccca67-54bd-44ab-8625-4b79c4dc7775"
PORTAL_SCOPES = [f"{PORTAL_RESOURCE}/.default"]

# Cookie store for the `xdr auth portal-cookie` path. Holds the cookie
# material, storage time, and a non-reversible tenant fingerprint; see
# save_portal_cookies()/load_portal_cookies() below.
PORTAL_COOKIE_FILENAME = "portal_cookies.json"

# Cookie auth rides the analyst's existing Defender portal browser session
# rather than minting a fresh Azure CLI token issuance, so it generally does
# NOT surface as a new "Microsoft Azure CLI" sign-in event. Surfaced by
# `xdr auth status` so the cookie path isn't mislabeled with the refresh-token
# path's attribution.
PORTAL_COOKIE_AUDIT_APP_NAME = "Microsoft Defender portal (browser session)"


def _portal_cookie_path() -> Path:
    return get_config_home() / PORTAL_COOKIE_FILENAME


def save_portal_cookies(data: dict) -> None:
    """Persist portal cookie credentials to disk (0600, atomic replace).

    ``data`` is expected to contain the cookie header, XSRF token, storage
    time, and tenant fingerprint from `xdr auth portal-cookie`. Uses the same
    atomic-write-with-0600 helper as the official MSAL token cache, so the cookie
    values never land on disk with permissive permissions even transiently.
    """
    atomic_write_secret(_portal_cookie_path(), json.dumps(data))


def load_portal_cookies(tenant_id: str) -> dict | None:
    """Load stored portal cookies only when bound to ``tenant_id``.

    Tolerates malformed JSON the same way the official token cache loader
    does. A parseable legacy or cross-tenant store is rejected explicitly rather than
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

