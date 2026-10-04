"""Tenant-bound locators must never substitute for remote action verification."""
import json
import os

import pytest

from xdr_cli.action_associations import load_action_device, remember_action_device

ACTION = "00000000-0000-0000-0000-000000000001"
DEVICE = "a" * 40


def test_private_tenant_bound_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    assert remember_action_device("tenant-one", ACTION, DEVICE)
    assert load_action_device("tenant-one", ACTION) == DEVICE
    assert load_action_device("tenant-two", ACTION) is None
    files = list((tmp_path / "action_associations").glob("*/*.json"))
    assert len(files) == 1
    record = json.loads(files[0].read_text())
    assert set(record) == {"version", "tenant_fingerprint", "action_id", "device_id"}
    if os.name == "posix":
        assert files[0].stat().st_mode & 0o777 == 0o600
        assert files[0].parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("change", ["invalid-json", "tenant", "action", "device", "large"])
def test_corrupt_association_requires_explicit_device(tmp_path, monkeypatch, change):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    assert remember_action_device("tenant", ACTION, DEVICE)
    path = next((tmp_path / "action_associations").glob("*/*.json"))
    record = json.loads(path.read_text())
    if change == "invalid-json":
        path.write_text("{")
    elif change == "large":
        path.write_text(json.dumps(record) + " " * 4096)
    else:
        field = {
            "tenant": "tenant_fingerprint", "action": "action_id", "device": "device_id",
        }[change]
        record[field] = "wrong"
        path.write_text(json.dumps(record))
    assert load_action_device("tenant", ACTION) is None


def test_no_cross_device_overwrite_and_invalid_path(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    assert remember_action_device("tenant", ACTION, DEVICE)
    assert not remember_action_device("tenant", ACTION, "b" * 40)
    assert load_action_device("tenant", ACTION) == DEVICE
    assert not remember_action_device("tenant", "../../escape", DEVICE)
    assert load_action_device("tenant", "../../escape") is None


def test_storage_failure_is_best_effort(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    def fail(*args):
        raise OSError("disk full")
    monkeypatch.setattr("xdr_cli.action_associations.atomic_write_secret", fail)
    assert not remember_action_device("tenant", ACTION, DEVICE)
    assert load_action_device("tenant", ACTION) is None
