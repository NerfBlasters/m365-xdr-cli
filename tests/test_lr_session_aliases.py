"""Alias allocation is private, immutable and bound to the native session identity."""

import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from xdr_cli.exceptions import ArtifactError, ConflictError, UsageError
from xdr_cli.live_response.session_aliases import SessionAliases, is_alias, validate_alias

TENANT = "a" * 64
DEVICE = "b" * 40
SESSION = "CLR00000000-0000-0000-0000-000000000001"


@pytest.fixture
def store(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    return SessionAliases(directory, TENANT, "portal-cookie")


def native(index):
    return f"CLR00000000-0000-0000-0000-{index:012d}"


def saved(store):
    return json.loads(store.path.read_text())


def replace(store, value):
    store.path.write_text(json.dumps(value))
    if os.name == "posix":
        store.path.chmod(0o600)


def test_read_misses_create_no_files_and_assignment_is_idempotent(store):
    assert store.alias_for(SESSION, DEVICE) is None
    assert store.resolve("LR-1") is None
    assert list(store.directory.iterdir()) == []
    assert store.assign(SESSION, DEVICE.upper()) == "lr-1"
    original = store.path.read_bytes()
    assert store.assign(SESSION, DEVICE) == "lr-1"
    assert store.alias_for(SESSION, DEVICE) == "lr-1"
    assert store.resolve("LR-1") == (SESSION, DEVICE)
    assert store.path.read_bytes() == original
    assert saved(store)["next_alias"] == 2
    if os.name == "posix":
        assert store.path.stat().st_mode & 0o777 == 0o600


def test_registry_persists_bindings_independently_of_session_handles(store):
    assert store.assign(SESSION, DEVICE) == "lr-1"
    # No per-session file is needed or removed by the registry. A new instance
    # must retain old aliases, including those whose separate handle was pruned.
    reopened = SessionAliases(store.directory, TENANT, "portal-cookie")
    assert reopened.assign(native(2), DEVICE) == "lr-2"
    assert reopened.resolve("lr-1") == (SESSION, DEVICE)
    assert reopened.resolve("lr-2") == (native(2), DEVICE)


def test_different_machine_cannot_rebind_existing_session(store):
    store.assign(SESSION, DEVICE)
    before = store.path.read_bytes()
    for operation in (store.assign, store.alias_for):
        with pytest.raises(ConflictError, match="binding"):
            operation(SESSION, "c" * 40)
    assert store.path.read_bytes() == before


@pytest.mark.parametrize("tenant,backend", [("c" * 64, "portal-cookie"), (TENANT, "official")])
def test_copied_registry_is_not_valid_in_another_namespace(store, tenant, backend):
    store.assign(SESSION, DEVICE)
    foreign = SessionAliases(store.directory, tenant, backend)
    for operation in (
        lambda: foreign.resolve("lr-1"),
        lambda: foreign.alias_for(SESSION, DEVICE),
        lambda: foreign.assign(native(2), DEVICE),
    ):
        with pytest.raises(ArtifactError):
            operation()
    assert store.resolve("lr-1") == (SESSION, DEVICE)


@pytest.mark.parametrize("value", [None, "lr-0", "lr-01", "lr--1", "lr-1/../x", "lr-1 ",
                                  "x-1", "lr-" + "9" * 30, "lr-9223372036854775808"])
def test_invalid_aliases_are_not_echoed_or_treated_as_native_ids(value):
    assert not is_alias(value)
    with pytest.raises(UsageError):
        validate_alias(value)


@pytest.mark.parametrize("session,machine", [
    ("CLR../../secret", DEVICE), ("invalid", DEVICE), (SESSION, "invalid"), (True, DEVICE),
])
def test_bad_native_identity_is_rejected_before_any_file_access(store, session, machine):
    with pytest.raises(UsageError):
        store.assign(session, machine)
    assert list(store.directory.iterdir()) == []


@pytest.mark.parametrize("change", [
    lambda d: d.update(version=True),
    lambda d: d.update(version=2),
    lambda d: d.update(next_alias=True),
    lambda d: d.update(next_alias=1),
    lambda d: d.update(next_alias=0),
    lambda d: d.update(next_alias="2"),
    lambda d: d.update(next_alias=2**63 + 1),
    lambda d: d.update(unknown="unexpected"),
    lambda d: d.update(bindings=[]),
    lambda d: d["bindings"].update({"lr-2": dict(d["bindings"]["lr-1"])}),
    lambda d: d["bindings"].update({"LR-2": {"session_id": native(2), "machine_id": DEVICE}}),
    lambda d: d["bindings"]["lr-1"].update(machine_id="invalid"),
    lambda d: d["bindings"]["lr-1"].update(session_id="invalid"),
    lambda d: d["bindings"]["lr-1"].update(extra="unexpected"),
])
def test_corrupt_registry_fails_closed_without_resetting_counter(store, change):
    store.assign(SESSION, DEVICE)
    data = saved(store)
    change(data)
    replace(store, data)
    before = store.path.read_bytes()
    with pytest.raises(ArtifactError):
        store.assign(native(3), DEVICE)
    assert store.path.read_bytes() == before


@pytest.mark.parametrize("contents", [
    "{", "null", "[]", '{"version":1,"version":1}',
    '{"a":{"duplicate":1,"duplicate":2}}',
])
def test_invalid_or_duplicate_json_keys_are_not_repaired_silently(store, contents):
    store.path.write_text(contents)
    store.path.chmod(0o600)
    with pytest.raises(ArtifactError):
        store.resolve("lr-1")
    assert store.path.read_text() == contents


def test_parallel_allocators_never_collide_or_lose_aliases(store):
    def assign(index):
        registry = SessionAliases(store.directory, TENANT, "portal-cookie")
        return registry.assign(native(index), DEVICE)

    with ThreadPoolExecutor(max_workers=8) as workers:
        allocated = list(workers.map(assign, range(1, 33)))
    assert len(set(allocated)) == 32
    assert {int(alias[3:]) for alias in allocated} == set(range(1, 33))
    for index, alias in enumerate(allocated, start=1):
        assert store.resolve(alias) == (native(index), DEVICE)
    assert saved(store)["next_alias"] == 33
    with ThreadPoolExecutor(max_workers=8) as workers:
        repeated = list(workers.map(lambda _: assign(1), range(16)))
    assert repeated == [allocated[0]] * 16
    assert saved(store)["next_alias"] == 33


def test_symlink_registry_never_reads_or_changes_target(store, tmp_path):
    target = tmp_path / "target"
    target.write_text("PRIVATE_SENTINEL")
    try:
        store.path.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation requires platform privileges")
    with pytest.raises(ArtifactError):
        store.assign(SESSION, DEVICE)
    assert target.read_text() == "PRIVATE_SENTINEL"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission modes")
def test_registry_and_directory_must_remain_private(store):
    store.assign(SESSION, DEVICE)
    store.path.chmod(0o644)
    with pytest.raises(ArtifactError):
        store.resolve("lr-1")
    store.path.chmod(0o600)
    store.directory.chmod(0o755)
    with pytest.raises(ArtifactError):
        store.assign(native(2), DEVICE)


def test_read_bound_and_full_write_leave_original_bytes_untouched(store, monkeypatch):
    import xdr_cli.live_response.session_aliases as module

    store.assign(SESSION, DEVICE)
    before = store.path.read_bytes()
    monkeypatch.setattr(module, "_MAX_BYTES", len(before))
    with pytest.raises(ArtifactError):
        store.assign(native(2), DEVICE)
    assert store.path.read_bytes() == before
    monkeypatch.setattr(module, "_MAX_BYTES", len(before) - 1)
    with pytest.raises(ArtifactError):
        store.resolve("lr-1")


def test_counter_exhaustion_never_reuses_an_existing_binding(store):
    store.assign(SESSION, DEVICE)
    data = saved(store)
    data["next_alias"] = 2**63
    replace(store, data)
    with pytest.raises(ConflictError, match="exhausted"):
        store.assign(native(2), DEVICE)
    assert store.resolve("lr-1") == (SESSION, DEVICE)


@pytest.mark.parametrize("fingerprint,backend", [(True, "portal-cookie"), (TENANT, []),
                                               ("invalid", "portal-cookie"), (TENANT, "other")])
def test_invalid_namespace_arguments_fail_with_a_typed_error(tmp_path, fingerprint, backend):
    with pytest.raises(ArtifactError):
        SessionAliases(tmp_path, fingerprint, backend)


def test_an_incomplete_persisted_write_cannot_report_alias_success(store, monkeypatch):
    from xdr_cli.secret_files import atomic_write_secret

    def incomplete(path, text):
        if path == store.marker:
            atomic_write_secret(path, text)
        else:
            path.write_text("{")
            path.chmod(0o600)

    monkeypatch.setattr("xdr_cli.live_response.session_aliases.atomic_write_secret", incomplete)
    with pytest.raises(ArtifactError):
        store.assign(SESSION, DEVICE)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes")
def test_fifo_registry_is_rejected_without_a_blocking_read(store):
    os.mkfifo(store.path, mode=0o600)
    with pytest.raises(ArtifactError):
        store.resolve("lr-1")


def test_lost_initialized_registry_never_recreates_or_reuses_aliases(store):
    assert store.assign(SESSION, DEVICE) == "lr-1"
    marker = store.marker.read_bytes()
    store.path.unlink()
    for operation in (
        lambda: store.assign(native(2), DEVICE),
        lambda: store.alias_for(SESSION, DEVICE),
        lambda: store.resolve("lr-1"),
    ):
        with pytest.raises(ArtifactError, match="registry is missing"):
            operation()
    assert not store.path.exists()
    assert store.marker.read_bytes() == marker


@pytest.mark.parametrize("operation", ["resolve", "alias_for", "assign"])
def test_existing_pre_marker_registry_is_adopted_without_rebinding(store, operation):
    assert store.assign(SESSION, DEVICE) == "lr-1"
    original = store.path.read_bytes()
    store.marker.unlink()  # Simulate the earlier valid registry format.
    if operation == "resolve":
        assert store.resolve("lr-1") == (SESSION, DEVICE)
    else:
        assert getattr(store, operation)(SESSION, DEVICE) == "lr-1"
    assert store.marker.is_file()
    assert store.path.read_bytes() == original
    store.path.unlink()
    with pytest.raises(ArtifactError, match="registry is missing"):
        store.assign(native(2), DEVICE)
    assert not store.path.exists()


def test_initialization_marker_precedes_first_registry_write_and_survives_failure(
    store, monkeypatch,
):
    from xdr_cli.secret_files import atomic_write_secret

    writes = []

    def interrupted(path, text):
        writes.append(path)
        if path == store.path:
            raise OSError("SYNTHETIC_WRITE_INTERRUPTION")
        atomic_write_secret(path, text)

    monkeypatch.setattr("xdr_cli.live_response.session_aliases.atomic_write_secret", interrupted)
    with pytest.raises(ArtifactError) as caught:
        store.assign(SESSION, DEVICE)
    assert writes == [store.marker, store.path]
    assert "SYNTHETIC_WRITE_INTERRUPTION" not in str(caught.value)
    assert store.marker.is_file() and not store.path.exists()
    monkeypatch.setattr(
        "xdr_cli.live_response.session_aliases.atomic_write_secret", atomic_write_secret,
    )
    with pytest.raises(ArtifactError, match="registry is missing"):
        store.assign(native(2), DEVICE)


def test_alias_lock_timeout_is_a_typed_value_free_local_failure(store, monkeypatch):
    from contextlib import contextmanager

    from xdr_cli._lock import Timeout

    @contextmanager
    def unavailable(path):
        raise Timeout("SYNTHETIC_PRIVATE_LOCK_PATH")
        yield

    monkeypatch.setattr("xdr_cli.live_response.session_aliases.exclusive_lock", unavailable)
    with pytest.raises(ArtifactError) as caught:
        store.assign(SESSION, DEVICE)
    assert "SYNTHETIC_PRIVATE_LOCK_PATH" not in str(caught.value)
    assert not store.marker.exists() and not store.path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission modes")
def test_initialization_marker_must_be_private(store):
    store.assign(SESSION, DEVICE)
    store.marker.chmod(0o644)
    with pytest.raises(ArtifactError):
        store.resolve("lr-1")


def test_moved_foreign_initialization_marker_cannot_authorize_a_new_registry(store):
    store.assign(SESSION, DEVICE)
    store.path.unlink()
    foreign = SessionAliases(store.directory, "f" * 64, "portal-cookie")
    with pytest.raises(ArtifactError):
        foreign.assign(native(2), DEVICE)
    assert not store.path.exists()
