"""Live Response handles must not cross tenant/backend/device trust boundaries."""

import json
import os

import pytest

from xdr_cli.exceptions import ConflictError, UsageError
from xdr_cli.live_response.handles import (
    get_current_directory,
    iter_sessions,
    load_session,
    remember_session,
    set_current_directory,
)
from xdr_cli.live_response.models import LRPlatform, LRSession

SESSION = "CLR00000000-0000-0000-0000-000000000001"
DEVICE = "a" * 40


def test_locator_bindings_private_files_and_no_raw_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    session = LRSession(
        SESSION, DEVICE, "running", LRPlatform.WINDOWS, raw={"download_token": "never-save-this"}
    )
    assert remember_session("tenant-a", "portal-cookie", session)
    assert load_session("tenant-b", "portal-cookie", SESSION) is None
    assert load_session("tenant-a", "official", SESSION) is None
    found = load_session("tenant-a", "portal-cookie", SESSION)
    assert found.machine_id == DEVICE
    paths = list(tmp_path.glob("live_response/**/*.json"))
    assert len(paths) == 1
    assert "never-save-this" not in paths[0].read_text()
    if os.name == "posix":
        assert paths[0].stat().st_mode & 0o777 == 0o600
    assert list(iter_sessions("tenant-a", "portal-cookie", DEVICE)) == [found]


def test_changed_device_binding_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    remember_session("t", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    with pytest.raises(ConflictError):
        remember_session("t", "portal-cookie", LRSession(SESSION, "b" * 40, "running"))
    assert load_session("t", "portal-cookie", SESSION).machine_id == DEVICE


def test_directory_survives_status_refresh(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    session = LRSession(SESSION, DEVICE, "running")
    remember_session("t", "portal-cookie", session)
    set_current_directory("t", "portal-cookie", SESSION, r"C:\Program Files")
    remember_session("t", "portal-cookie", session)
    assert get_current_directory("t", "portal-cookie", SESSION) == r"C:\Program Files"


def test_tampered_locator_cannot_change_tenant_or_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    remember_session("t", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    path = next(tmp_path.glob("live_response/**/*.json"))
    data = json.loads(path.read_text())
    data["tenant"] = "another-tenant"
    path.write_text(json.dumps(data))
    assert load_session("t", "portal-cookie", SESSION) is None


def test_path_traversal_rejected_before_local_access(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    with pytest.raises(UsageError):
        load_session("t", "portal-cookie", "CLR../../secrets")
