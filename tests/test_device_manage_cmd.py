"""Device tags, action-availability and cancel-action CLI (synthetic backend)."""
from __future__ import annotations

import json
import logging
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from xdr_cli.main import _TENANT_MUTATION_COMMANDS, app

runner = CliRunner()
_MODULE = "xdr_cli.commands.device_manage_cmd"
MACHINE = "b" * 40
ACTION = "12345678-1234-1234-1234-123456789abc"


class FakeDeviceBackend:
    def __init__(self):
        self.calls = []
        self.closed = False

    async def get_device_tags(self, machine_id):
        self.calls.append(("get", machine_id))
        return {"manual": ["vip", "lab host"], "system": ["Server"], "source": "portal-response"}

    async def set_device_tags(self, machine_id, tags, *, expected_current):
        self.calls.append(("set", machine_id, tags, expected_current))
        return {"manual": tags, "system": ["Server"], "changed": True, "verified": True,
                "atomic_compare_and_swap": False}

    async def update_device_tag(self, machine_id, tag, *, remove):
        self.calls.append(("update", machine_id, tag, remove))
        return {"manual": [tag], "verified": True}

    async def get_device_action_permissions(self, machine_id):
        self.calls.append(("permissions", machine_id))
        return {"machine_id": machine_id, "permissions": [], "authorization_granted": False}

    async def cancel_device_action(self, action_id, *, device_id, comment):
        self.calls.append(("cancel", action_id, device_id, comment))
        return {"status": "Cancelled", "cancellation_requested": True,
                "device_rollback_confirmed": False}

    async def submit_device_action(self, device_id, action, *, comment, mode=None):
        self.calls.append(("action", device_id, action, comment, mode))
        return {"id": ACTION, "type": action, "status": "Pending"}

    async def start_device_investigation(self, machine_id, *, comment):
        self.calls.append(("investigate", machine_id, comment))
        return {"machine_id": machine_id, "request_accepted": True,
                "investigation_status": "not_interpreted"}

    async def collect_device_support_logs(self, machine_id, *, comment):
        self.calls.append(("logs", machine_id, comment))
        return {"action_id": ACTION, "status": "Pending"}

    async def set_device_troubleshooting(self, machine_id, *, enabled, duration_minutes,
                                         comment):
        self.calls.append(("troubleshoot", machine_id, enabled, duration_minutes, comment))
        return {"requested_state": "on" if enabled else "off",
                "state_change_confirmed": False}

    history_complete = True

    async def iter_device_action_history(self, machine_id, *, limit=100):
        self.calls.append(("history", machine_id, limit))
        yield {"record_type": "device-action-history", "native": {"ActionType": "Isolate"}}
        yield {"record_type": "device-action-history-coverage", "machine_id": machine_id,
               "lookback_days": 7, "native_count": 1, "returned": 1,
               "complete": self.history_complete}

    async def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()


@pytest.fixture
def fake(monkeypatch):
    backend = FakeDeviceBackend()
    monkeypatch.setattr(f"{_MODULE}._get_client", Mock(return_value=backend))
    return backend


@pytest.fixture
def no_client(monkeypatch):
    client = Mock(side_effect=AssertionError("no client may be created"))
    monkeypatch.setattr(f"{_MODULE}._get_client", client)
    return client


def _invoke(*args):
    return runner.invoke(app, ["--no-interactive", "--backend", "portal-cookie", "device", *args])


def _data(result):
    return json.loads(result.stdout)["data"]


def test_mutating_chains_are_audited_and_gated():
    assert {"device tags set", "device tags add", "device tags remove",
            "device cancel-action", "device contain", "device uncontain",
            "device start-investigation"} <= _TENANT_MUTATION_COMMANDS
    assert "device action-history" not in _TENANT_MUTATION_COMMANDS
    assert "device tags list" not in _TENANT_MUTATION_COMMANDS
    assert "device action-permissions" not in _TENANT_MUTATION_COMMANDS


def test_tags_list_offers_a_guarded_set_command(fake):
    result = _invoke("tags", "list", MACHINE)
    assert result.exit_code == 0, result.output
    data = _data(result)
    assert data["manual"] == ["vip", "lab host"] and data["system"] == ["Server"]
    assert data["set_command"].startswith(
        f"xdr device tags set {MACHINE} --expect vip --expect 'lab host'")
    assert fake.closed


def test_tags_set_requires_an_expectation_and_yes(fake):
    assert _invoke("tags", "set", MACHINE, "--tag", "a", "--yes").exit_code == 6
    both = _invoke("tags", "set", MACHINE, "--tag", "a", "--expect", "x", "--expect-none",
                   "--yes")
    assert both.exit_code == 6
    assert _invoke("tags", "set", MACHINE, "--tag", "a", "--expect-none").exit_code == 6
    assert fake.calls == []


def test_tags_set_sends_desired_and_expected_sets(fake):
    result = _invoke("tags", "set", MACHINE, "--tag", "a", "--tag", "b c",
                     "--expect", "vip", "--yes")
    assert result.exit_code == 0, result.output
    assert fake.calls == [("set", MACHINE, ["a", "b c"], ["vip"])]
    assert _data(result)["atomic_compare_and_swap"] is False
    cleared = _invoke("tags", "set", MACHINE, "--expect-none", "--yes")
    assert cleared.exit_code == 0
    assert fake.calls[-1] == ("set", MACHINE, [], [])


@pytest.mark.parametrize("verb,remove", [("add", False), ("remove", True)])
def test_tag_add_and_remove(fake, verb, remove):
    result = _invoke("tags", verb, MACHINE, "triage", "--yes")
    assert result.exit_code == 0, result.output
    assert fake.calls == [("update", MACHINE, "triage", remove)]


def test_dry_runs_are_local(no_client):
    for args in (["tags", "set", MACHINE, "--tag", "a", "--expect-none", "--dry-run"],
                 ["tags", "add", MACHINE, "x", "--dry-run"],
                 ["cancel-action", ACTION, "--device", MACHINE, "-c", "why", "--dry-run"]):
        result = _invoke(*args)
        assert result.exit_code == 0, (args, result.output)
        assert _data(result)["dry_run"] is True
    no_client.assert_not_called()


def test_action_permissions_is_a_read(fake):
    result = _invoke("action-permissions", MACHINE)
    assert result.exit_code == 0, result.output
    assert _data(result)["authorization_granted"] is False


def test_cancel_action_confirms_and_reports_no_rollback(fake, monkeypatch, caplog):
    assert _invoke("cancel-action", ACTION, "--device", MACHINE, "-c", "wrong device"
                   ).exit_code == 6
    assert fake.calls == []
    args = ["--no-interactive", "--backend", "portal-cookie", "device", "cancel-action",
            ACTION, "--device", MACHINE, "-c", "wrong device", "--yes"]
    monkeypatch.setattr("sys.argv", ["xdr", *args])
    with caplog.at_level(logging.INFO, logger="xdr.audit"):
        result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert fake.calls == [("cancel", ACTION, MACHINE, "wrong device")]
    assert _data(result)["device_rollback_confirmed"] is False
    assert any("device cancel-action" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize("verb", ["contain", "uncontain"])
def test_containment_submits_named_action_after_confirmation(fake, verb):
    assert _invoke(verb, MACHINE, "-c", "IR-7").exit_code == 6
    assert _invoke(verb, MACHINE, "--yes").exit_code == 6  # --comment is required
    assert fake.calls == []
    result = _invoke(verb, MACHINE, "-c", "IR-7", "--yes")
    assert result.exit_code == 0, result.output
    assert fake.calls == [("action", MACHINE, verb, "IR-7", None)]


def test_start_investigation_confirms_and_sends_once(fake):
    assert _invoke("start-investigation", MACHINE, "-c", "IR-9").exit_code == 6
    assert fake.calls == []
    result = _invoke("start-investigation", MACHINE, "-c", "IR-9", "--yes")
    assert result.exit_code == 0, result.output
    assert fake.calls == [("investigate", MACHINE, "IR-9")]
    assert _data(result)["investigation_status"] == "not_interpreted"


def test_start_investigation_dry_run_is_local(no_client):
    result = _invoke("start-investigation", MACHINE, "-c", "IR-9", "--dry-run")
    assert result.exit_code == 0
    assert _data(result)["action"] == "start-investigation"


@pytest.mark.parametrize("complete,state", [(True, "known-complete"), (False, "unknown")])
def test_action_history_is_an_artifact_with_coverage(fake, complete, state):
    fake.history_complete = complete
    result = _invoke("action-history", MACHINE, "--limit", "50")
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["rows"] == 2 and receipt["server_truncation_state"] == state
    assert receipt["context"]["coverage"]["lookback_days"] == 7
    assert fake.calls == [("history", MACHINE, 50)]
    assert _invoke("action-history", MACHINE, "--limit", "0").exit_code == 6


def test_support_logs_and_troubleshooting(fake):
    assert {"device collect-support-logs", "device troubleshoot"} <= _TENANT_MUTATION_COMMANDS
    assert _invoke("collect-support-logs", MACHINE, "-c", "case").exit_code == 6
    assert _invoke("troubleshoot", MACHINE, "-c", "case", "--yes").exit_code == 6  # --on/--off
    assert fake.calls == []
    assert _invoke("collect-support-logs", MACHINE, "-c", "case", "--yes").exit_code == 0
    on = _invoke("troubleshoot", MACHINE, "--on", "-c", "case", "--yes")
    off = _invoke("troubleshoot", MACHINE, "--off", "-c", "case", "--yes")
    assert on.exit_code == off.exit_code == 0
    assert _data(on)["state_change_confirmed"] is False
    assert fake.calls == [
        ("logs", MACHINE, "case"),
        ("troubleshoot", MACHINE, True, None, "case"),
        ("troubleshoot", MACHINE, False, None, "case"),
    ]


def test_diagnostics_dry_runs_are_local(no_client):
    on = _invoke("troubleshoot", MACHINE, "--on", "-c", "x", "--dry-run")
    assert _data(on)["duration_minutes"] == 240
    assert _invoke("collect-support-logs", MACHINE, "-c", "x", "--dry-run").exit_code == 0


@pytest.mark.parametrize("verb", ["contain", "uncontain"])
def test_containment_dry_run_is_local(no_client, verb):
    result = _invoke(verb, MACHINE, "-c", "IR-7", "--dry-run")
    assert result.exit_code == 0
    assert _data(result) == {"dry_run": True, "action": verb, "machine_id": MACHINE}
