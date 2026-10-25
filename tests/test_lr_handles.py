"""Live Response handles must not cross tenant/backend/device trust boundaries."""

import json
import os

import pytest

from xdr_cli.exceptions import ConflictError, LocalNotFoundError, UsageError
from xdr_cli.live_response.handles import (
    get_current_directory,
    is_active_session,
    iter_sessions,
    load_session,
    mark_session_missing,
    remember_session,
    resolve_session_id,
    session_activity,
    set_current_directory,
)
from xdr_cli.live_response.models import LRPlatform, LRSession
from xdr_cli.live_response.session_aliases import SessionAliases
from xdr_cli.results import tenant_fingerprint

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
    assert len(paths) == 2
    assert found.alias == "lr-1"
    for path in paths:
        assert "never-save-this" not in path.read_text()
        if os.name == "posix":
            assert path.stat().st_mode & 0o777 == 0o600
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
    path = next(tmp_path.glob(f"live_response/**/{SESSION}.json"))
    data = json.loads(path.read_text())
    data["tenant"] = "another-tenant"
    path.write_text(json.dumps(data))
    assert load_session("t", "portal-cookie", SESSION) is None


def test_path_traversal_rejected_before_local_access(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    with pytest.raises(UsageError):
        load_session("t", "portal-cookie", "CLR../../secrets")


def _legacy_handle(home, *, session_id=SESSION, tenant="tenant-a"):
    directory = home / "live_response" / tenant_fingerprint(tenant) / "portal-cookie"
    for parent in (home / "live_response", directory.parent, directory):
        parent.mkdir(mode=0o700, exist_ok=True)
    path = directory / f"{session_id}.json"
    data = {
        "version": 1,
        "tenant": tenant_fingerprint(tenant),
        "backend": "portal-cookie",
        "session_id": session_id,
        "machine_id": DEVICE,
        "platform": "windows",
        "state": "running",
        "created_by": "analyst@example.test",
        "created_at": "2026-10-24T00:00:00Z",
        "current_directory": r"C:\Preserve this directory",
        "directory_command_id": "00000000-0000-0000-0000-000000000002",
        "directory_command_created_at": "2026-10-24T00:00:01Z",
    }
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def test_legacy_handle_gains_alias_without_rewriting_cwd_or_inventing_verification(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    path = _legacy_handle(tmp_path)
    before = json.loads(path.read_text())
    assert not (path.parent / "aliases.json").exists()
    (listed,) = list(iter_sessions("tenant-a", "portal-cookie"))
    assert listed.alias == "lr-1" and listed.last_verified_at is None
    assert listed.created_by == "analyst@example.test"
    assert listed.created_at == "2026-10-24T00:00:00Z"
    assert json.loads(path.read_text()) == {**before, "alias": "lr-1"}
    assert get_current_directory("tenant-a", "portal-cookie", SESSION) == (
        r"C:\Preserve this directory"
    )
    assert resolve_session_id("tenant-a", "portal-cookie", "LR-1") == SESSION
    assert resolve_session_id("tenant-a", "portal-cookie", SESSION) == SESSION


def test_missing_alias_is_local_not_found_and_does_not_create_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    with pytest.raises(LocalNotFoundError) as caught:
        resolve_session_id("tenant-a", "portal-cookie", "lr-1")
    assert caught.value.help_command.endswith("sessions list")
    assert not (tmp_path / "live_response").exists()


@pytest.mark.parametrize("tenant,backend", [("tenant-b", "portal-cookie"),
                                           ("tenant-a", "official")])
def test_alias_resolution_does_not_cross_namespace(tmp_path, monkeypatch, tenant, backend):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    with pytest.raises(LocalNotFoundError):
        resolve_session_id(tenant, backend, "lr-1")
    assert resolve_session_id("tenant-a", "portal-cookie", "lr-1") == SESSION


@pytest.mark.parametrize("changes", [
    {"machine_id": "b" * 40},
    {"machine_id": None},
    {"tenant": "other-namespace"},
    {"session_id": "CLR00000000-0000-0000-0000-000000000099"},
    {"version": True},
])
def test_alias_resolution_requires_original_device_bound_handle(tmp_path, monkeypatch, changes):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    path = next(tmp_path.glob(f"live_response/**/{SESSION}.json"))
    data = json.loads(path.read_text())
    data.update(changes)
    path.write_text(json.dumps(data))
    before = path.read_bytes()
    with pytest.raises(ConflictError, match="device-bound handle"):
        resolve_session_id("tenant-a", "portal-cookie", "lr-1")
    assert path.read_bytes() == before


@pytest.mark.parametrize("state", ["terminatedByUser", "terminatedBySystem", "failed",
                                   "not-found"])
def test_inactive_alias_survives_and_a_new_session_never_reuses_it(tmp_path, monkeypatch, state):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    if state == "not-found":
        inactive = mark_session_missing("tenant-a", "portal-cookie", SESSION)
    else:
        remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, state))
        inactive = load_session("tenant-a", "portal-cookie", SESSION)
    assert inactive.alias == "lr-1" and inactive.state == state
    assert not is_active_session(inactive)
    assert resolve_session_id("tenant-a", "portal-cookie", "lr-1") == SESSION
    next_id = "CLR00000000-0000-0000-0000-000000000002"
    remember_session("tenant-a", "portal-cookie", LRSession(next_id, DEVICE, "running"))
    assert load_session("tenant-a", "portal-cookie", next_id).alias == "lr-2"
    assert resolve_session_id("tenant-a", "portal-cookie", "lr-1") == SESSION
    path = next(tmp_path.glob(f"live_response/**/{SESSION}.json"))
    path.unlink()
    with pytest.raises(ConflictError):
        resolve_session_id("tenant-a", "portal-cookie", "lr-1")
    third_id = "CLR00000000-0000-0000-0000-000000000003"
    remember_session("tenant-a", "portal-cookie", LRSession(third_id, DEVICE, "running"))
    assert load_session("tenant-a", "portal-cookie", third_id).alias == "lr-3"
    registry = SessionAliases(path.parent, tenant_fingerprint("tenant-a"), "portal-cookie")
    assert registry.resolve("lr-1") == (SESSION, DEVICE)


def test_explicit_missing_observation_retains_legacy_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    path = _legacy_handle(tmp_path)
    loaded = load_session("tenant-a", "portal-cookie", SESSION)
    assert loaded.last_verified_at is None
    monkeypatch.setattr("xdr_cli.live_response.handles._now", lambda: "2026-10-25T01:02:03Z")
    refreshed = mark_session_missing("tenant-a", "portal-cookie", SESSION)
    data = json.loads(path.read_text())
    assert refreshed.alias == loaded.alias == "lr-1"
    assert refreshed.last_verified_at == "2026-10-25T01:02:03Z"
    assert refreshed.state == "not-found"
    assert data["current_directory"] == r"C:\Preserve this directory"
    assert data["directory_command_id"] == "00000000-0000-0000-0000-000000000002"
    assert data["created_at"] == "2026-10-24T00:00:00Z"


@pytest.mark.parametrize("state,activity", [
    ("running", "active"), ("pending", "active"), ("pendingResource", "active"),
    ("pendingUser", "active"), ("queued", "active"),
    ("terminatedByUser", "inactive"), ("terminatedBySystem", "inactive"),
    ("failed", "inactive"), ("not-found", "inactive"),
    ("999", "unknown"), ("unknown", "unknown"), ("", "unknown"),
])
def test_unmapped_activity_is_not_misclassified_as_dead(state, activity):
    session = LRSession(SESSION, DEVICE, state)
    assert session_activity(session) == activity
    assert is_active_session(session) == (activity != "inactive")


def test_unknown_local_sessions_stay_in_possible_active_listing(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "999"))
    second = "CLR00000000-0000-0000-0000-000000000002"
    remember_session("tenant-a", "portal-cookie", LRSession(second, DEVICE, "terminatedByUser"))
    all_sessions = list(iter_sessions("tenant-a", "portal-cookie"))
    assert len(all_sessions) == 2
    assert [s.alias for s in all_sessions if is_active_session(s)] == ["lr-1"]


def test_failed_handle_write_reserves_alias_and_raw_id_can_recover_it(tmp_path, monkeypatch):
    import xdr_cli.live_response.handles as handles

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    original_write = handles.atomic_write_secret

    def unavailable(path, text):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(handles, "atomic_write_secret", unavailable)
    assert not remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    monkeypatch.setattr(handles, "atomic_write_secret", original_write)
    second = "CLR00000000-0000-0000-0000-000000000002"
    remember_session("tenant-a", "portal-cookie", LRSession(second, DEVICE, "running"))
    assert load_session("tenant-a", "portal-cookie", second).alias == "lr-2"
    with pytest.raises(ConflictError):
        resolve_session_id("tenant-a", "portal-cookie", "lr-1")
    remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    assert load_session("tenant-a", "portal-cookie", SESSION).alias == "lr-1"
    assert resolve_session_id("tenant-a", "portal-cookie", "lr-1") == SESSION


@pytest.mark.parametrize("legacy", [False, True])
def test_loss_of_both_registry_files_cannot_reuse_a_surviving_handle_alias(
    tmp_path, monkeypatch, legacy,
):
    from xdr_cli.exceptions import ArtifactError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    if legacy:
        path = _legacy_handle(tmp_path)
    else:
        assert remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
        path = next(tmp_path.glob(f"live_response/**/{SESSION}.json"))
    assert load_session("tenant-a", "portal-cookie", SESSION).alias == "lr-1"
    assert json.loads(path.read_text())["alias"] == "lr-1"
    registry = SessionAliases(path.parent, tenant_fingerprint("tenant-a"), "portal-cookie")
    registry.path.unlink()
    registry.marker.unlink()
    second = "CLR00000000-0000-0000-0000-000000000002"
    with pytest.raises(ArtifactError, match="registry is missing"):
        registry.assign(second, DEVICE)
    assert not registry.path.exists() and not registry.marker.exists()
    # Observing either native ID remains useful without inventing/reusing aliases.
    assert load_session("tenant-a", "portal-cookie", SESSION).alias is None
    assert resolve_session_id("tenant-a", "portal-cookie", SESSION) == SESSION
    assert remember_session("tenant-a", "portal-cookie", LRSession(second, DEVICE, "running"))
    assert load_session("tenant-a", "portal-cookie", second).alias is None
    assert json.loads(path.read_text())["alias"] == "lr-1"
    assert not registry.path.exists() and not registry.marker.exists()


def test_interrupted_first_registry_write_keeps_native_handle_and_does_not_auto_reset(
    tmp_path, monkeypatch,
):
    import xdr_cli.live_response.session_aliases as aliases

    from xdr_cli.exceptions import ArtifactError

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    original_write = aliases.atomic_write_secret

    def fail_registry(path, text):
        if path.name == "aliases.json":
            raise OSError("synthetic interrupted registry write")
        original_write(path, text)

    monkeypatch.setattr(aliases, "atomic_write_secret", fail_registry)
    assert remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    path = next(tmp_path.glob(f"live_response/**/{SESSION}.json"))
    registry = SessionAliases(path.parent, tenant_fingerprint("tenant-a"), "portal-cookie")
    assert registry.marker.exists() and not registry.path.exists()
    assert "alias" not in json.loads(path.read_text())
    assert load_session("tenant-a", "portal-cookie", SESSION).alias is None
    assert resolve_session_id("tenant-a", "portal-cookie", SESSION) == SESSION
    monkeypatch.setattr(aliases, "atomic_write_secret", original_write)
    with pytest.raises(ArtifactError, match="registry is missing"):
        registry.assign(SESSION, DEVICE)
    assert load_session("tenant-a", "portal-cookie", SESSION).machine_id == DEVICE


def test_tampered_optional_alias_metadata_blocks_alias_but_preserves_native_handle(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    assert remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    path = next(tmp_path.glob(f"live_response/**/{SESSION}.json"))
    data = json.loads(path.read_text())
    data["alias"] = "lr-99"
    path.write_text(json.dumps(data))
    assert load_session("tenant-a", "portal-cookie", SESSION).alias is None
    with pytest.raises(ConflictError, match="remembered handle binding"):
        resolve_session_id("tenant-a", "portal-cookie", "lr-1")
    assert resolve_session_id("tenant-a", "portal-cookie", SESSION) == SESSION
    assert remember_session("tenant-a", "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    assert json.loads(path.read_text())["alias"] == "lr-99"
