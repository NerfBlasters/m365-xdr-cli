"""Shared test fixtures."""

import pytest

from xdr_cli.client import XDRClient
from xdr_cli.config import Config


@pytest.fixture()
def config_dir(tmp_path, monkeypatch):
    """Redirect XDR_CLI_HOME to a temp directory."""
    config_home = tmp_path / ".xdr-cli"
    config_home.mkdir()
    (config_home / "queries").mkdir()
    monkeypatch.setenv("XDR_CLI_HOME", str(config_home))
    return config_home


@pytest.fixture()
def mock_config():
    return Config(tenant_id="test-tenant", client_id="test-client")


@pytest.fixture()
def mock_client():
    return XDRClient(get_token=lambda scopes=None: "fake-token", timeout=5)


# ---------------------------------------------------------------------------
# MSAL authority discovery stub — prevents network calls in unit tests.
# msal.PublicClientApplication always runs tenant_discovery() during __init__,
# even when validate_authority=False.  We patch it here so tests that
# instantiate AuthManager without a full @patch("xdr_cli.auth.msal…") don't
# hit the real Microsoft login endpoint.
# ---------------------------------------------------------------------------
_FAKE_OIDC_CONFIG = {
    "token_endpoint": "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
    "authorization_endpoint": "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize",
    "issuer": "https://login.microsoftonline.com/test-tenant/v2.0",
}


@pytest.fixture(autouse=True)
def _mock_msal_tenant_discovery(monkeypatch):
    """Stub out msal's OIDC tenant-discovery HTTP call for all tests."""
    import msal.authority as _msal_authority

    monkeypatch.setattr(_msal_authority, "tenant_discovery", lambda *a, **kw: _FAKE_OIDC_CONFIG)


# ---------------------------------------------------------------------------
# respx route-priority fix — make routes with query-param constraints match
# BEFORE routes without them, so that paginate nextLink tests work correctly.
# respx matches routes in registration order (first-match wins); a route
# registered without params would otherwise shadow a more-specific route that
# includes params.  We patch RouteList to emit more-specific routes first.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _respx_specific_route_priority(monkeypatch):
    """Sort respx routes by specificity (param-constrained routes first)."""
    from respx.models import RouteList
    from respx.patterns import Params, _And

    def _has_params(route) -> bool:
        """Return True if this route's pattern includes a Params constraint."""
        pattern = route.pattern

        def _walk(p) -> bool:
            if isinstance(p, Params):
                return True
            if isinstance(p, _And):
                a, b = p.value
                return _walk(a) or _walk(b)
            return False

        return _walk(pattern)

    original_iter = RouteList.__iter__

    def sorted_iter(self):
        routes = list(original_iter(self))
        # Stable sort: routes with Params constraints come first
        return iter(sorted(routes, key=lambda r: 0 if _has_params(r) else 1))

    monkeypatch.setattr(RouteList, "__iter__", sorted_iter)
