"""Remembered Live Response sessions: local list and read-only refresh."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from tests.lr_fakes import MACHINE
from xdr_cli.commands import live_response_sessions_cmd as module
from xdr_cli.commands.live_response_cmd import live_response_app
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    ConfigError,
    LiveResponseSessionNotFoundError,
    NetworkError,
    NotAuthenticatedError,
    NotFoundError,
    RateLimitError,
)
from xdr_cli.live_response import handles
from xdr_cli.live_response.models import LRSession
from xdr_cli.main import app

runner = CliRunner()
_PORTAL = ["--no-interactive", "--backend", "portal-cookie", "device", "live-response"]
TENANT = "synthetic-tenant"


def Session(session_id, machine_id, state, alias=None):  # noqa: N802 - mirrors the type
    return LRSession(session_id, machine_id, state, alias=alias)


def _session(n: int, state: str = "running", machine: str = MACHINE) -> LRSession:
    return LRSession(f"CLR{n:04d}", machine, state, alias=f"lr-{n}",
                     last_verified_at="2026-10-25T00:00:00Z", raw={"token": "private"})


@pytest.fixture(autouse=True)
def _mounted(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text(f'tenant_id = "{TENANT}"\n')
    (home / "config.toml").chmod(0o600)
    # Until the group is registered by live_response_cmd, mount it for these tests.
    previous = live_response_app.commands.get("sessions")
    live_response_app.add_command(module.sessions_app)
    yield
    if previous is not None and previous is not module.sessions_app:
        live_response_app.add_command(previous)


@pytest.fixture
def store(monkeypatch):
    state = {"sessions": [], "missing": [], "unreadable": 0}

    def iter_sessions(tenant, backend, machine_id=None, *, problems=None):
        assert (tenant, backend) == (TENANT, "portal-cookie")
        assert problems is not None
        problems.extend({"reason": "unreadable"} for _ in range(state["unreadable"]))
        return iter([s for s in state["sessions"]
                     if machine_id is None or s.machine_id.lower() == machine_id.lower()])

    def mark_session_missing(tenant, backend, session_id):
        state["missing"].append(session_id)
        session = next(s for s in state["sessions"] if s.session_id == session_id)
        return Session(session.session_id, session.machine_id, "not-found", session.alias)

    # Activity and the active filter stay the real handle-store rules.
    monkeypatch.setattr(module.handles, "iter_sessions", iter_sessions)
    monkeypatch.setattr(module.handles, "mark_session_missing", mark_session_missing)
    return state


@pytest.fixture
def no_client(monkeypatch):
    factory = Mock(side_effect=AssertionError("no client may be created"))
    monkeypatch.setattr(module, "create_client", factory)
    return factory


class FakeClient:
    def __init__(self, outcomes: dict):
        self.outcomes, self.calls, self.closed = outcomes, [], False

    async def lr_get_session(self, session_id):
        self.calls.append(session_id)
        outcome = self.outcomes[session_id]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def close(self):
        self.closed = True


@pytest.fixture
def client(monkeypatch):
    holder = FakeClient({})
    monkeypatch.setattr(module, "create_client", Mock(return_value=holder))
    return holder


def _invoke(*args):
    return runner.invoke(app, [*_PORTAL, "sessions", *args])


def _documents(result) -> list[dict]:
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def _rows(receipt) -> list[dict]:
    return [json.loads(line) for line in Path(receipt["data_path"]).read_text().splitlines()]


@pytest.mark.parametrize("args", [[], ["list"]])
def test_list_is_local_and_shows_only_active_sessions(store, no_client, args):
    store["sessions"] = [_session(1), _session(2, "terminatedByUser"), _session(3, "pending"),
                         _session(4, "state-7")]
    result = _invoke(*args)
    assert result.exit_code == 0, result.output
    receipt = _documents(result)[0]
    assert receipt["context"]["verification"] == "cached"
    assert receipt["context"]["coverage"] == "locally-known-sessions"
    assert receipt["context"]["scope"] == "active"
    rows = _rows(receipt)
    assert [r["alias"] for r in rows] == ["lr-1", "lr-3", "lr-4"]
    assert [r["activity"] for r in rows] == ["active", "active", "unknown"]
    assert all("raw" not in r for r in rows) and "private" not in result.output
    no_client.assert_not_called()


@pytest.mark.parametrize("args", [["--all"], ["list", "--all"]])
def test_list_all_includes_closed_sessions(store, no_client, args):
    store["sessions"] = [_session(1), _session(2, "not-found")]
    result = _invoke(*args)
    assert result.exit_code == 0, result.output
    receipt = _documents(result)[0]
    assert receipt["context"]["scope"] == "all"
    assert [r["state"] for r in _rows(receipt)] == ["running", "not-found"]


def test_list_device_filter_is_validated_locally(store, no_client):
    other = "b" * 40
    store["sessions"] = [_session(1), _session(2, machine=other)]
    result = _invoke("list", "--device", other)
    assert result.exit_code == 0, result.output
    assert [r["alias"] for r in _rows(_documents(result)[0])] == ["lr-2"]
    bad = _invoke("list", "--device", "not-a-machine")
    assert bad.exit_code == 6
    assert _documents(bad)[0]["error"]["invalid"]["kind"] == "identifier"


def test_list_needs_the_portal_cookie_backend(store, no_client):
    result = runner.invoke(app, ["--no-interactive", "--backend", "official", "device",
                                 "live-response", "sessions", "list"])
    assert result.exit_code == 3
    assert _documents(result)[0]["error"]["code"] == "BACKEND_CAPABILITY_UNAVAILABLE"
    no_client.assert_not_called()


def test_refresh_with_nothing_remembered_creates_no_client(store, no_client):
    store["sessions"] = [_session(1, "terminatedBySystem")]
    result = _invoke("refresh")
    assert result.exit_code == 0, result.output
    receipt = _documents(result)[0]
    assert receipt["rows"] == 0 and receipt["context"]["verification"] == "remote"
    no_client.assert_not_called()


def test_refresh_checks_active_sessions_once_and_marks_only_404_missing(store, client):
    store["sessions"] = [_session(1), _session(2), _session(3, "terminatedByUser")]
    client.outcomes = {
        "CLR0001": Session("CLR0001", MACHINE, "terminatedBySystem", "lr-1"),
        "CLR0002": LiveResponseSessionNotFoundError(),
    }
    result = _invoke("refresh")
    assert result.exit_code == 0, result.output
    assert client.calls == ["CLR0001", "CLR0002"] and client.closed
    assert store["missing"] == ["CLR0002"]
    receipt = _documents(result)[0]
    assert receipt["context"]["checked"] == 2 and receipt["context"]["not_found"] == 1
    rows = _rows(receipt)
    assert [(r["alias"], r["previous_state"], r["state"], r["verification"]) for r in rows] == [
        ("lr-1", "running", "terminatedBySystem", "remote"),
        ("lr-2", "running", "not-found", "not-found"),
    ]
    assert [r["activity"] for r in rows] == ["inactive", "inactive"]


def test_refresh_stops_on_systemic_failure_and_keeps_remembered_state(store, client):
    store["sessions"] = [_session(1), _session(2), _session(3)]
    client.outcomes = {
        "CLR0001": Session("CLR0001", MACHINE, "running", "lr-1"),
        "CLR0002": RateLimitError(30),
        "CLR0003": AssertionError("must not be looked up after a systemic failure"),
    }
    result = _invoke("refresh")
    assert result.exit_code == 14, result.output
    documents = _documents(result)
    receipt, error = documents[0], documents[-1]
    context = receipt["context"]
    assert (context["checked"], context["errors"], context["not_checked"]) == (1, 1, 1)
    rows = _rows(receipt)
    assert [r["verification"] for r in rows] == ["remote", "error", "not-checked"]
    assert [r["state"] for r in rows] == ["running", "running", "running"]
    assert rows[1]["refresh_error"] == "API_RATE_LIMITED" and rows[2]["refresh_error"] is None
    assert error["error"]["code"] == "PARTIAL_SUCCESS"
    assert error["error"]["retry_after_seconds"] == 30
    assert store["missing"] == []


@pytest.mark.parametrize(("failure", "exit_code"), [
    (NotAuthenticatedError("Live Response requires a renewed portal session."), 2),
    (NetworkError("Live Response request failed."), 11),
])
def test_refresh_with_nothing_verified_reports_the_systemic_failure(
    store, client, failure, exit_code,
):
    store["sessions"] = [_session(1), _session(2)]
    client.outcomes = {"CLR0001": failure}
    result = _invoke("refresh")
    assert result.exit_code == exit_code, result.output
    (error,) = _documents(result)
    assert error["status"] == "error" and client.calls == ["CLR0001"]
    assert store["missing"] == []


def test_refresh_item_error_continues_and_returns_partial(store, client):
    store["sessions"] = [_session(1), _session(2)]
    client.outcomes = {
        "CLR0001": APIError("Live Response session response has an invalid shape."),
        "CLR0002": Session("CLR0002", MACHINE, "running", "lr-2"),
    }
    result = _invoke("refresh")
    assert result.exit_code == 14, result.output
    receipt = _documents(result)[0]
    rows = _rows(receipt)
    assert [(r["verification"], r["refresh_error"]) for r in rows] == [
        ("error", "API_ERROR"), ("remote", None),
    ]
    assert rows[0]["state"] == "running" and receipt["context"]["errors"] == 1


def test_refresh_marking_failure_is_an_error_row_not_a_closed_session(store, client, monkeypatch):
    store["sessions"] = [_session(1)]
    client.outcomes = {"CLR0001": LiveResponseSessionNotFoundError()}

    def fail(*_):
        raise ArtifactError("Could not update the Live Response session handle.")

    monkeypatch.setattr(module.handles, "mark_session_missing", fail)
    result = _invoke("refresh")
    assert result.exit_code == 14, result.output
    (row,) = _rows(_documents(result)[0])
    assert row["verification"] == "error" and row["state"] == "running"
    assert row["refresh_error"] == "ARTIFACT_WRITE_FAILED"


def test_list_reads_the_real_handle_store_and_assigns_aliases(no_client):
    for n, state in ((1, "running"), (2, "terminatedByUser")):
        handles.remember_session(TENANT, "portal-cookie",
                                 LRSession(f"CLR{n:04d}", MACHINE, state))
    result = _invoke()
    assert result.exit_code == 0, result.output
    (row,) = _rows(_documents(result)[0])
    assert row["session_id"] == "CLR0001" and row["activity"] == "active"
    assert handles.session_activity(LRSession("CLR9", MACHINE, "terminatedByUser")) == "inactive"
    assert row["alias"] and row["alias"].startswith("lr-")
    no_client.assert_not_called()


@pytest.mark.parametrize("args", [
    ["--device", "b" * 40, "list"],
    ["list", "--device", "b" * 40],
    ["--device", "B" * 40, "list", "--device", "b" * 40],
])
def test_group_device_filter_reaches_the_subcommand(store, no_client, args):
    store["sessions"] = [_session(1), _session(2, machine="b" * 40)]
    result = _invoke(*args)
    assert result.exit_code == 0, result.output
    assert [r["alias"] for r in _rows(_documents(result)[0])] == ["lr-2"]


def test_conflicting_group_and_subcommand_device_is_refused(store, no_client):
    result = _invoke("--device", "b" * 40, "list", "--device", "c" * 40)
    assert result.exit_code == 6
    assert _documents(result)[0]["error"]["invalid"]["kind"] == "conflicting_options"


def test_group_all_applies_to_list(store, no_client):
    store["sessions"] = [_session(1), _session(2, "failed")]
    result = _invoke("--all", "list")
    assert result.exit_code == 0, result.output
    assert _documents(result)[0]["context"]["scope"] == "all"
    assert len(_rows(_documents(result)[0])) == 2


def test_refresh_rejects_all_instead_of_ignoring_it(store, no_client):
    store["sessions"] = [_session(1)]
    result = _invoke("--all", "refresh")
    assert result.exit_code == 6
    assert _documents(result)[0]["error"]["invalid"]["kind"] == "conflicting_options"
    no_client.assert_not_called()


def test_group_device_filter_applies_to_refresh(store, client):
    store["sessions"] = [_session(1), _session(2, machine="b" * 40)]
    client.outcomes = {"CLR0002": Session("CLR0002", "b" * 40, "running", "lr-2")}
    result = _invoke("--device", "b" * 40, "refresh")
    assert result.exit_code == 0, result.output
    assert client.calls == ["CLR0002"]


def test_missing_tenant_is_a_config_error_before_reading_state(store, no_client, tmp_path):
    (tmp_path / "home" / "config.toml").write_text("")
    result = _invoke("list")
    assert result.exit_code == 4
    assert _documents(result)[0]["error"]["code"] == "CONFIG_ERROR"


@pytest.mark.parametrize("args", [["list"], ["refresh"]])
def test_unreadable_handles_make_the_listing_partial_not_silently_complete(
    store, client, args,
):
    store["sessions"], store["unreadable"] = [_session(1)], 1
    client.outcomes = {"CLR0001": Session("CLR0001", MACHINE, "running", "lr-1")}
    result = _invoke(*args)
    assert result.exit_code == 14, result.output
    documents = _documents(result)
    receipt, error = documents[0], documents[-1]
    assert receipt["server_truncation_state"] == "known-truncated"
    assert receipt["context"]["unreadable_handles"] == 1
    assert len(_rows(receipt)) == 1
    assert error["error"]["code"] == "PARTIAL_SUCCESS"


def test_only_unreadable_handles_still_report_partial_without_a_client(store, no_client):
    store["unreadable"] = 2
    result = _invoke("refresh")
    assert result.exit_code == 14, result.output
    assert _documents(result)[0]["context"]["unreadable_handles"] == 2
    no_client.assert_not_called()


def test_a_generic_not_found_is_an_error_row_not_a_missing_session(store, client):
    store["sessions"] = [_session(1)]
    client.outcomes = {"CLR0001": NotFoundError("portal tenant metadata")}
    result = _invoke("refresh")
    assert result.exit_code == 14, result.output
    (row,) = _rows(_documents(result)[0])
    assert row["verification"] == "error" and row["state"] == "running"
    assert store["missing"] == []


def test_config_failure_stops_the_refresh(store, client):
    store["sessions"] = [_session(1), _session(2)]
    client.outcomes = {"CLR0001": ConfigError("Tenant mismatch.")}
    result = _invoke("refresh")
    assert result.exit_code == 4, result.output
    assert client.calls == ["CLR0001"]


def test_a_corrupt_real_handle_is_reported_not_silently_dropped(tmp_path, no_client):
    for n in (1, 2):
        handles.remember_session(TENANT, "portal-cookie", LRSession(f"CLR{n:04d}", MACHINE,
                                                                     "running"))
    (damaged,) = (tmp_path / "home").rglob("CLR0002.json")
    damaged.write_text("{not json")
    result = _invoke("list")
    assert result.exit_code == 14, result.output
    documents = _documents(result)
    receipt = documents[0]
    assert receipt["server_truncation_state"] == "known-truncated"
    assert receipt["context"]["unreadable_handles"] == 1
    assert [r["session_id"] for r in _rows(receipt)] == ["CLR0001"]
    assert "CLR0002" not in result.output and "not json" not in result.output
    assert documents[-1]["error"]["code"] == "PARTIAL_SUCCESS"
    no_client.assert_not_called()
