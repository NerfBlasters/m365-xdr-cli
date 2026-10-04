"""Synthetic contracts from device-action capture; never execute live actions."""
import json

import httpx
import pytest
import respx

from xdr_cli.api.devices import (
    collect_investigation_package, get_action_status, isolate_device,
    restrict_code_execution, run_av_scan,
    unisolate_device, unrestrict_code_execution,
)
from xdr_cli.backends import PortalBackend
from xdr_cli.config import Config
from xdr_cli.exceptions import APIError, NetworkError, NotFoundError, UsageError
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

BASE = "https://security.microsoft.com/apiproxy/mtp"
ACTION = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
DEVICE = "a" * 40


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    save_portal_cookies({
        "tenant_fingerprint": tenant_fingerprint("test-tenant"),
        "cookie_header": "sccauth=synthetic; XSRF-TOKEN=synthetic",
        "xsrf_token": "synthetic",
    })
    return PortalBackend(Config(tenant_id="test-tenant", api_backend="portal-cookie"), 5)


def prerequisites():
    respx.get(BASE + "/sccManagement/mgmt/TenantContext").respond(
        json={"AuthInfo": {"TenantId": "test-tenant"}},
    )
    respx.get(BASE + "/getMachine/machines").respond(json={
        "SenseMachineId": DEVICE, "OsPlatform": "Windows11", "SenseClientVersion": "1.2.3",
    })


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("action,expected_type,extras", [
    ("scan", "ScanRequest", {"Params": {"ScanType": "Full"}}),
    ("quick", "ScanRequest", {"Params": {"ScanType": "Quick"}}),
    ("isolate", "IsolationRequest", {"Action": "Isolate", "IsolationType": "Selective"}),
    ("full-isolate", "IsolationRequest", {"Action": "Isolate", "IsolationType": "Full"}),
    ("unisolate", "IsolationRequest", {"Action": "Unisolate"}),
    ("package", "ForensicsRequest", {}),
    ("restrict", "RestrictExecutionRequest", {"PolicyType": "Restrict", "ClientVersion": "1.2.3"}),
    ("unrestrict", "RestrictExecutionRequest",
     {"PolicyType": "Unrestrict", "ClientVersion": "1.2.3"}),
])
async def test_named_action_payload_and_correlated_receipt(client, action, expected_type, extras):
    prerequisites()
    route = respx.post(BASE + "/responseApiPortal/requests/create").respond(json={
        "Id": ACTION, "MachineId": DEVICE, "Status": "Pending", "Type": "Unknown",
    })
    calls = {
        "scan": lambda: run_av_scan(client, DEVICE, scan_type="Full", comment="test"),
        "quick": lambda: run_av_scan(client, DEVICE, scan_type="Quick", comment="test"),
        "unisolate": lambda: unisolate_device(client, DEVICE, comment="test"),
        "full-isolate": lambda: isolate_device(
            client, DEVICE, isolation_type="Full", comment="test",
        ),
        "isolate": lambda: isolate_device(
            client, DEVICE, isolation_type="Selective", comment="test",
        ),
        "package": lambda: collect_investigation_package(client, DEVICE, comment="test"),
        "restrict": lambda: restrict_code_execution(client, DEVICE, comment="test"),
        "unrestrict": lambda: unrestrict_code_execution(client, DEVICE, comment="test"),
    }
    try:
        result = await calls[action]()
    finally:
        await client.close()
    assert json.loads(route.calls[0].request.content) == {
        "MachineId": DEVICE, "RequestorComment": "test", "Type": expected_type,
        "OsPlatform": "Windows11", "SenseClientVersion": "1.2.3", **extras,
    }
    assert "authorization" not in route.calls[0].request.headers
    assert route.call_count == 1
    assert result["id"] == ACTION
    assert result["type"] != "Unknown"
    assert result["portal_source"]["raw"]["Type"] == "Unknown"
    assert f"--device {DEVICE}" in result["portal_source"]["status_command"]


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("state", ["Succeeded", "Failed", "Submitted"])
async def test_status_matches_identity_not_first_or_latest(client, state):
    prerequisites()
    route = respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=[
        {"RequestGuid": OTHER, "MachineId": DEVICE, "RequestStatus": "Failed"},
        {"RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": state},
    ])
    try:
        result = await get_action_status(client, ACTION, device_id=DEVICE)
    finally:
        await client.close()
    assert result["id"] == ACTION
    assert result["status"] == state
    assert result["portal_source"]["status_contract"] == "portal-native"
    assert route.calls[0].request.url.params["machineId"] == DEVICE
    assert route.calls[0].request.url.params["requestGuid"] == ACTION


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("rows,error", [
    ([], NotFoundError),
    ([{"RequestGuid": ACTION, "MachineId": "b" * 40, "RequestStatus": "Succeeded"}], APIError),
    ([{"RequestGuid": ACTION}] * 2, APIError),
    ({"value": []}, APIError),
])
async def test_status_rejects_missing_ambiguous_and_wrong_device(client, rows, error):
    prerequisites()
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=rows)
    try:
        with pytest.raises(error):
            await client.get_action_status(ACTION, DEVICE)
    finally:
        await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_unsupported_modes_and_missing_device_fail_without_network(client):
    try:
        with pytest.raises(UsageError):
            await client.get_action_status(ACTION)
        with pytest.raises(UsageError):
            await run_av_scan(client, DEVICE, scan_type="Unknown")
        with pytest.raises(UsageError):
            await isolate_device(client, DEVICE, isolation_type="Unknown")
        assert not respx.calls
    finally:
        await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_mutation_transport_outcome_never_retried(client):
    prerequisites()
    route = respx.post(BASE + "/responseApiPortal/requests/create").mock(
        side_effect=httpx.ReadError("synthetic"),
    )
    try:
        with pytest.raises(NetworkError, match="Outcome unknown") as exc:
            await run_av_scan(client, DEVICE, scan_type="Full")
        assert exc.value.retryable is False
        assert route.call_count == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("reply", [
    {"Id": ACTION, "MachineId": None, "Status": "Pending"},
    {"Id": OTHER, "MachineId": "b" * 40, "Status": "Pending"},
    {"Id": "not-a-guid", "MachineId": DEVICE, "Status": "Pending"},
])
async def test_malformed_submission_reports_uncertain_outcome(client, reply):
    prerequisites()
    route = respx.post(BASE + "/responseApiPortal/requests/create").respond(json=reply)
    try:
        with pytest.raises(APIError, match="Outcome unknown"):
            await run_av_scan(client, DEVICE, scan_type="Full")
        assert route.call_count == 1
    finally:
        await client.close()


@respx.mock
def test_cli_status_cookie_mode_with_device(client, monkeypatch):
    from typer.testing import CliRunner
    from xdr_cli.config import save_config
    from xdr_cli.main import app

    save_config(Config(tenant_id="test-tenant", api_backend="portal-cookie"))
    def no_auth(*args, **kwargs):
        raise AssertionError("MSAL must not be constructed")
    monkeypatch.setattr("xdr_cli.commands.device_cmd.AuthManager", no_auth)
    prerequisites()
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=[
        {"RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": "Succeeded"},
    ])
    result = CliRunner().invoke(app, ["device", "action-status", ACTION, "--device", DEVICE])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["data"]["id"] == ACTION


@pytest.mark.asyncio
@respx.mock
async def test_status_association_survives_new_client_and_rechecks_remote_identity(client):
    prerequisites()
    route = respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=[
        {"RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": "Submitted"},
    ])
    try:
        result = await client.get_action_status(ACTION, DEVICE)
        assert result["portal_source"]["device_association_saved"]
    finally:
        await client.close()
    second = PortalBackend(Config(tenant_id="test-tenant", api_backend="portal-cookie"), 5)
    try:
        route.respond(json=[{
            "RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": "Succeeded",
        }])
        assert (await second.get_action_status(ACTION))["status"] == "Succeeded"
        route.respond(json=[{
            "RequestGuid": ACTION, "MachineId": "b" * 40, "RequestStatus": "Succeeded",
        }])
        with pytest.raises(APIError, match="identity"):
            await second.get_action_status(ACTION)
    finally:
        await second.close()


@pytest.mark.asyncio
@respx.mock
async def test_submitted_action_survives_association_write_failure(client, monkeypatch):
    prerequisites()
    monkeypatch.setattr("xdr_cli.backends.remember_action_device", lambda *args: False)
    route = respx.post(BASE + "/responseApiPortal/requests/create").respond(json={
        "Id": ACTION, "MachineId": DEVICE, "Status": "Pending", "Type": "Unknown",
    })
    try:
        result = await run_av_scan(client, DEVICE, scan_type="Full")
        assert result["id"] == ACTION
        assert result["portal_source"]["device_association_saved"] is False
        assert f"--device {DEVICE}" in result["portal_source"]["status_command"]
        assert route.call_count == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_status_preserves_observed_action_metadata(client):
    prerequisites()
    row = {
        "RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": "Failed",
        "Type": "ScanResponse", "CreationDateTimeUtc": "2026-01-01T00:00:00Z",
        "LastUpdateTimeUtc": "2026-01-01T00:01:00Z", "Requestor": "user@example.com",
        "RequestorComment": "synthetic", "ErrorHResult": -123,
        "CancellationRequestor": None, "CancellationComment": None,
        "CancellationDateTimeUtc": None, "UnknownField": {"retained": True},
    }
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=[row])
    try:
        result = await client.get_action_status(ACTION, DEVICE)
    finally:
        await client.close()
    assert result["type"] == "RunAntiVirusScan"
    assert result["status"] == "Failed"
    assert result["requestor"] == "user@example.com"
    assert result["requestorComment"] == "synthetic"
    assert result["errorHResult"] == -123
    assert result["creationDateTimeUtc"] == row["CreationDateTimeUtc"]
    assert result["lastUpdateDateTimeUtc"] == row["LastUpdateTimeUtc"]
    assert result["cancellationRequestor"] is None
    assert result["portal_source"]["raw"] == row


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("native_type,field,value,expected", [
    ("IsolationResponse", "Action", 0, "Isolate"),
    ("IsolationResponse", "Action", 1, "Unisolate"),
    ("RestrictExecutionResponse", "PolicyType", 0, "RestrictCodeExecution"),
    ("RestrictExecutionResponse", "PolicyType", 1, "UnrestrictCodeExecution"),
    ("IsolationResponse", "Action", 2, None),
    ("IsolationResponse", "Action", False, None),
    ("IsolationResponse", "Action", "0", None),
    ("IsolationResponse", "Action", None, None),
    ("RestrictExecutionResponse", "PolicyType", 2, None),
    ("RestrictExecutionResponse", "PolicyType", True, None),
    ("RestrictExecutionResponse", "PolicyType", "1", None),
    ("RestrictExecutionResponse", "PolicyType", None, None),
    ("FutureResponse", "Action", 0, None),
])
async def test_status_maps_only_verified_action_subtypes(
    client, native_type, field, value, expected,
):
    prerequisites()
    row = {
        "RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": "Succeeded",
        "Type": native_type, field: value,
    }
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=[row])
    try:
        result = await client.get_action_status(ACTION, DEVICE)
    finally:
        await client.close()
    if expected is None:
        assert "type" not in result
    else:
        assert result["type"] == expected
    assert result["portal_source"]["raw"] == row
    assert result["portal_source"]["field_parity"] == "partial"
