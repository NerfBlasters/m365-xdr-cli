"""Tests for auth module."""

import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from xdr_cli.auth import AuthManager, atomic_write_secret
from xdr_cli.config import Config
from xdr_cli.exceptions import NotAuthenticatedError


@pytest.fixture()
def auth_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    return tmp_path / ".xdr-cli"


@pytest.fixture()
def config():
    return Config(tenant_id="test-tenant", client_id="test-client-id")


def test_auth_manager_lazy_msal_app(config, auth_dir):
    mgr = AuthManager(config)
    assert mgr._app is None  # lazy — not built until first use
    assert mgr.is_configured()
    assert mgr._get_app() is not None
    assert mgr._app is not None  # cached after first call


def test_auth_manager_not_configured_does_not_crash(auth_dir):
    # Previously crashed on MSAL ValueError when tenant_id was empty.
    mgr = AuthManager(Config())
    assert not mgr.is_configured()
    status = mgr.get_auth_status()
    assert status == {
        "authenticated": False,
        "configured": False,
        "account": None,
        "hint": "Run `xdr auth login --tenant-id <ID> --client-id <ID>` to configure.",
    }


def test_get_token_raises_when_not_authenticated(config, auth_dir):
    mgr = AuthManager(config)
    with pytest.raises(NotAuthenticatedError):
        mgr.get_token()


@patch("xdr_cli.auth.msal.PublicClientApplication")
def test_get_token_returns_cached_token(mock_msal_cls, config, auth_dir):
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = [{"username": "user@test.com"}]
    mock_app.acquire_token_silent_with_error.return_value = {
        "access_token": "fake-token-123",
        "token_type": "Bearer",
    }
    mock_msal_cls.return_value = mock_app

    mgr = AuthManager(config)
    mgr._app = mock_app
    token = mgr.get_token()
    assert token == "fake-token-123"


def test_get_token_serializes_cache_acquisition_across_managers(config, auth_dir):
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
        return {"access_token": "token"}

    managers = [AuthManager(config), AuthManager(config)]
    apps = []
    for _manager in managers:
        app = MagicMock()
        app.get_accounts.return_value = [{"username": "user@test.com"}]
        app.acquire_token_silent_with_error.side_effect = acquire
        apps.append(app)

    results: list[str] = []
    threads = [threading.Thread(target=lambda m=m: results.append(m.get_token())) for m in managers]
    with patch("xdr_cli.auth.msal.PublicClientApplication", side_effect=apps):
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert results == ["token", "token"]
    assert maximum_active == 1


@patch("xdr_cli.auth.msal.PublicClientApplication")
def test_get_token_raises_when_silent_fails(mock_msal_cls, config, auth_dir):
    mock_app = MagicMock()
    mock_app.get_accounts.return_value = [{"username": "user@test.com"}]
    mock_app.acquire_token_silent_with_error.return_value = None
    mock_msal_cls.return_value = mock_app

    mgr = AuthManager(config)
    mgr._app = mock_app
    with pytest.raises(NotAuthenticatedError):
        mgr.get_token()


@patch("xdr_cli.auth.msal.PublicClientApplication")
def test_login_device_code_flow(mock_msal_cls, config, auth_dir):
    mock_app = MagicMock()
    # Simulate no display / broker unavailable so login falls back to device code.
    mock_app.acquire_token_interactive.side_effect = Exception("no display")
    mock_app.initiate_device_flow.return_value = {
        "user_code": "ABC-123",
        "verification_uri": "https://microsoft.com/devicelogin",
        "message": "Go to https://microsoft.com/devicelogin and enter code ABC-123",
    }
    mock_app.acquire_token_by_device_flow.return_value = {
        "access_token": "new-token",
        "token_type": "Bearer",
    }
    mock_msal_cls.return_value = mock_app

    mgr = AuthManager(config)
    mgr._app = mock_app
    result = mgr.login()
    assert result["access_token"] == "new-token"
    mock_app.initiate_device_flow.assert_called_once()


def test_logout_clears_cache(config, auth_dir):
    auth_dir.mkdir(parents=True, exist_ok=True)
    cache_file = auth_dir / "token_cache.json"
    cache_file.write_text("{}")

    mgr = AuthManager(config)
    mgr.logout()
    assert not cache_file.exists()


def test_load_cache_tolerates_corrupt_file(config, auth_dir):
    """A garbage token_cache.json must not brick `AuthManager.__init__`."""
    auth_dir.mkdir(parents=True, exist_ok=True)
    (auth_dir / "token_cache.json").write_text("{not valid json at all")

    # Should construct cleanly and fall through to an empty cache.
    mgr = AuthManager(config)
    # Empty MSAL SerializableTokenCache serializes to "{}" (or "").
    assert mgr._cache.serialize() in ("", "{}")


@patch("xdr_cli.auth.msal.PublicClientApplication")
def test_login_pre_warm_failure_does_not_discard_primary_token(
    mock_msal_cls, config, auth_dir
):
    """A failing pre-warm interactive must not roll back a successful login."""
    mock_app = MagicMock()
    mock_app.acquire_token_interactive.return_value = {
        "access_token": "primary",
        "token_type": "Bearer",
    }
    mock_app.get_accounts.return_value = [{"username": "user@test.com"}]
    # Silent pre-warm returns nothing → fallback to interactive pre-warm.
    mock_app.acquire_token_silent.return_value = None
    # Pre-warm interactive raises (cancelled WAM dialog, CA block, …).
    # First call is the primary login (already returned above); subsequent
    # calls are pre-warms that should throw.
    def interactive(*args, scopes=None, **kwargs):
        if scopes == ["https://graph.microsoft.com/.default"]:
            return {"access_token": "primary", "token_type": "Bearer"}
        raise RuntimeError("WAM dialog cancelled")
    mock_app.acquire_token_interactive.side_effect = interactive
    mock_msal_cls.return_value = mock_app

    mgr = AuthManager(config)
    mgr._app = mock_app
    result = mgr.login()

    # Primary token survives the pre-warm failure.
    assert result["access_token"] == "primary"


def test_token_cache_persisted_after_login(config, auth_dir):
    auth_dir.mkdir(parents=True, exist_ok=True)
    with patch("xdr_cli.auth.msal.PublicClientApplication") as mock_msal_cls:
        mock_app = MagicMock()
        mock_app.acquire_token_interactive.side_effect = Exception("no display")
        mock_app.initiate_device_flow.return_value = {
            "user_code": "XYZ",
            "verification_uri": "https://microsoft.com/devicelogin",
            "message": "msg",
        }
        mock_app.acquire_token_by_device_flow.return_value = {
            "access_token": "tok",
        }
        mock_cache = MagicMock()
        mock_cache.has_state_changed = True
        mock_cache.serialize.return_value = '{"cached": true}'
        mock_app.token_cache = mock_cache
        mock_msal_cls.return_value = mock_app

        mgr = AuthManager(config)
        with patch("xdr_cli.auth.msal.SerializableTokenCache", return_value=mock_cache):
            mgr.login()

        cache_file = auth_dir / "token_cache.json"
        assert cache_file.exists()


def test_cache_transaction_does_not_resurrect_cache_deleted_by_logout(config, auth_dir):
    auth_dir.mkdir(parents=True, exist_ok=True)
    cache_file = auth_dir / "token_cache.json"
    cache_file.write_text("{}")
    mgr = AuthManager(config)
    stale_cache = mgr._cache
    mgr._app = MagicMock()
    cache_file.unlink()

    with mgr._cache_transaction():
        assert mgr._cache is not stale_cache
        assert mgr._cache.serialize() in ("", "{}")
        assert mgr._app is None


# --- atomic_write_secret ------------------------------------------------


def test_atomic_write_secret_creates_parent_dirs_mode_and_replaces(tmp_path):
    target = tmp_path / "nested" / "does" / "not" / "exist" / "secret.json"
    assert not target.parent.exists()

    atomic_write_secret(target, '{"first": true}')

    assert target.exists()
    assert target.read_text() == '{"first": true}'
    # POSIX mode bits are not an access-control contract on Windows; Windows
    # privacy is enforced by the containing profile's ACL instead.
    if os.name == "posix":
        assert (target.stat().st_mode & 0o777) == 0o600

    # A second write must atomically replace the existing contents (not
    # append, not leave a stray temp file behind).
    atomic_write_secret(target, '{"second": true}')

    assert target.read_text() == '{"second": true}'
    if os.name == "posix":
        assert (target.stat().st_mode & 0o777) == 0o600
    leftover_tmp_files = list(target.parent.glob("*.tmp"))
    assert leftover_tmp_files == []
