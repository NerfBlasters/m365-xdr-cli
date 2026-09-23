"""Tests for the portal_auth module (unofficial Defender portal MSAL client).

`PortalAuth` mirrors `AuthManager` (see tests/test_auth.py) but:
- only requires `tenant_id` on `Config` (client_id is hardcoded — the Azure
  CLI FOCI public client, not a user-supplied app registration), and
- persists to its own cache file (`portal_token_cache.json`), distinct from
  the main `token_cache.json`.

This is a RED-only test file for TDD Task 1: `xdr_cli.portal_auth` does not
exist yet, so every test here is expected to fail at collection with an
ImportError until Task 2 implements `PortalAuth`.
"""

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from xdr_cli.config import Config, get_config_home
from xdr_cli.exceptions import AuthError, NotAuthenticatedError
from xdr_cli.portal_auth import PortalAuth

# FOCI public client ID for Azure CLI — literal, not imported from
# portal_auth, per task instructions (tests assert the real contract value,
# not a re-export of the implementation's own constant).
FOCI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
AUDIT_APP_NAME = "Microsoft Azure CLI"


@pytest.fixture()
def auth_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    return tmp_path / ".xdr-cli"


@pytest.fixture()
def config():
    # Note: no client_id — PortalAuth's client id is hardcoded (FOCI), unlike
    # AuthManager which requires the user's own app registration client_id.
    return Config(tenant_id="test-tenant")


# --- 1. is_configured() only needs tenant_id ---------------------------------


def test_is_configured_requires_only_tenant_id(auth_dir):
    configured = PortalAuth(Config(tenant_id="test-tenant"))
    assert configured.is_configured() is True

    not_configured = PortalAuth(Config())
    assert not_configured.is_configured() is False

    # client_id on Config is irrelevant to PortalAuth — it never reads it,
    # since the FOCI client id is hardcoded, not sourced from Config.
    still_not_configured = PortalAuth(Config(client_id="some-other-app"))
    assert still_not_configured.is_configured() is False


# --- 2. get_token() calls silent acquisition first, returns cached token ----


@patch("xdr_cli.portal_auth.msal.PublicClientApplication")
def test_get_token_returns_cached_token(mock_msal_cls, config, auth_dir):
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = [{"username": "user@test.com"}]
    mock_app.acquire_token_silent_with_error.return_value = {
        "access_token": "fake-portal-token-123",
        "token_type": "Bearer",
    }
    mock_msal_cls.return_value = mock_app

    mgr = PortalAuth(config)
    mgr._app = mock_app
    token = mgr.get_token()

    assert token == "fake-portal-token-123"
    mock_app.acquire_token_silent_with_error.assert_called_once()


def test_get_token_serializes_portal_cache_acquisition(config, auth_dir):
    active = 0
    maximum_active = 0
    guard = threading.Lock()

    def acquire(*_args, **_kwargs):
        nonlocal active, maximum_active
        with guard:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.05)
        with guard:
            active -= 1
        return {"access_token": "portal-token"}

    managers = [PortalAuth(config), PortalAuth(config)]
    apps = []
    for _manager in managers:
        app = MagicMock()
        app.get_accounts.return_value = [{"username": "user@test.com"}]
        app.acquire_token_silent_with_error.side_effect = acquire
        apps.append(app)

    results: list[str] = []
    threads = [threading.Thread(target=lambda m=m: results.append(m.get_token())) for m in managers]
    with patch("xdr_cli.portal_auth.msal.PublicClientApplication", side_effect=apps):
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert results == ["portal-token", "portal-token"]
    assert maximum_active == 1


# --- 3. get_token() raises NotAuthenticatedError when no account cached ----


def test_get_token_raises_when_not_authenticated(config, auth_dir):
    mgr = PortalAuth(config)
    with pytest.raises(NotAuthenticatedError):
        mgr.get_token()


# --- 4. get_token() raises AuthError with a useful message on interaction_required


@patch("xdr_cli.portal_auth.msal.PublicClientApplication")
def test_get_token_raises_auth_error_on_interaction_required(
    mock_msal_cls, config, auth_dir
):
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = [{"username": "user@test.com"}]
    mock_app.acquire_token_silent_with_error.return_value = {
        "error": "interaction_required",
        "error_description": "AADSTS50076: interaction required.",
    }
    mock_msal_cls.return_value = mock_app

    mgr = PortalAuth(config)
    mgr._app = mock_app

    with pytest.raises(AuthError) as exc_info:
        mgr.get_token()

    # Must not be the generic NotAuthenticatedError — this is a distinct
    # failure mode (an account exists, but silent refresh needs interaction).
    assert not isinstance(exc_info.value, NotAuthenticatedError)
    message = str(exc_info.value)
    assert message  # non-empty, useful message
    # Per the design doc, the remedy is re-running the portal login command.
    assert "portal-login" in message


# --- 5. login() falls back to device code when interactive auth fails ------


@patch("xdr_cli.portal_auth.msal.PublicClientApplication")
def test_login_device_code_flow(mock_msal_cls, config, auth_dir):
    mock_app = MagicMock()
    mock_app.acquire_token_interactive.side_effect = Exception("no display")
    mock_app.initiate_device_flow.return_value = {
        "user_code": "PORTAL-ABC",
        "verification_uri": "https://microsoft.com/devicelogin",
        "message": "Go to https://microsoft.com/devicelogin and enter code PORTAL-ABC",
    }
    mock_app.acquire_token_by_device_flow.return_value = {
        "access_token": "new-portal-token",
        "token_type": "Bearer",
    }
    mock_msal_cls.return_value = mock_app

    mgr = PortalAuth(config)
    mgr._app = mock_app
    result = mgr.login()

    assert result["access_token"] == "new-portal-token"
    mock_app.initiate_device_flow.assert_called_once()
    mock_app.acquire_token_by_device_flow.assert_called_once()


# --- 6. get_auth_status() shape -------------------------------------------


@patch("xdr_cli.portal_auth.msal.PublicClientApplication")
def test_get_auth_status_authenticated(mock_msal_cls, config, auth_dir):
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = [{"username": "user@test.com"}]
    mock_msal_cls.return_value = mock_app

    mgr = PortalAuth(config)
    mgr._app = mock_app
    status = mgr.get_auth_status()

    for key in ("account", "tenant", "authenticated", "client_id", "audit_app_name"):
        assert key in status, f"missing key {key!r} in get_auth_status()"

    assert status["authenticated"] is True
    assert status["account"] == "user@test.com"
    assert status["tenant"] == "test-tenant"
    assert status["client_id"] == FOCI_CLIENT_ID
    assert status["audit_app_name"] == AUDIT_APP_NAME


@patch("xdr_cli.portal_auth.msal.PublicClientApplication")
def test_get_auth_status_not_authenticated(mock_msal_cls, config, auth_dir):
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = []
    mock_msal_cls.return_value = mock_app

    mgr = PortalAuth(config)
    mgr._app = mock_app
    status = mgr.get_auth_status()

    for key in ("account", "tenant", "authenticated", "client_id", "audit_app_name"):
        assert key in status, f"missing key {key!r} in get_auth_status()"

    assert status["authenticated"] is False
    assert status["account"] is None
    assert status["client_id"] == FOCI_CLIENT_ID
    assert status["audit_app_name"] == AUDIT_APP_NAME


# --- 7. Token cache file is portal-specific and distinct from the main cache


def test_cache_path_is_portal_specific_and_distinct(config, auth_dir):
    mgr = PortalAuth(config)
    path = mgr._cache_path()

    assert path == get_config_home() / "portal_token_cache.json"
    assert path.name == "portal_token_cache.json"
    assert path.name != "token_cache.json"


@patch("xdr_cli.portal_auth.msal.PublicClientApplication")
def test_login_persists_to_portal_specific_cache_file(mock_msal_cls, config, auth_dir):
    """The file actually written to disk must be portal-specific, not shared
    with (or collided with) the main AuthManager's token_cache.json."""
    auth_dir.mkdir(parents=True, exist_ok=True)
    mock_app = MagicMock()
    mock_app.acquire_token_interactive.side_effect = Exception("no display")
    mock_app.initiate_device_flow.return_value = {
        "user_code": "XYZ",
        "verification_uri": "https://microsoft.com/devicelogin",
        "message": "msg",
    }
    mock_app.acquire_token_by_device_flow.return_value = {"access_token": "tok"}
    mock_cache = MagicMock()
    mock_cache.has_state_changed = True
    mock_cache.serialize.return_value = '{"cached": true}'
    mock_msal_cls.return_value = mock_app

    mgr = PortalAuth(config)
    with patch("xdr_cli.portal_auth.msal.SerializableTokenCache", return_value=mock_cache):
        mgr.login()

    assert (auth_dir / "portal_token_cache.json").exists()
    assert not (auth_dir / "token_cache.json").exists()


def test_portal_cache_transaction_does_not_resurrect_deleted_cache(config, auth_dir):
    auth_dir.mkdir(parents=True, exist_ok=True)
    cache_file = auth_dir / "portal_token_cache.json"
    cache_file.write_text("{}")
    mgr = PortalAuth(config)
    stale_cache = mgr._cache
    mgr._app = MagicMock()
    cache_file.unlink()

    with mgr._cache_transaction():
        assert mgr._cache is not stale_cache
        assert mgr._cache.serialize() in ("", "{}")
        assert mgr._app is None


# --- 8. Corrupted cache file is tolerated ----------------------------------


def test_load_cache_tolerates_corrupt_portal_cache_file(config, auth_dir):
    """A garbage portal_token_cache.json must not brick PortalAuth.__init__;
    it should fall through to a fresh, empty SerializableTokenCache."""
    auth_dir.mkdir(parents=True, exist_ok=True)
    (auth_dir / "portal_token_cache.json").write_text("{not valid json at all")

    mgr = PortalAuth(config)  # must not raise

    # Empty MSAL SerializableTokenCache serializes to "{}" (or "").
    assert mgr._cache.serialize() in ("", "{}")
