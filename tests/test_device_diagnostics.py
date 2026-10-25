"""Synthetic source contracts for portal diagnostics; never contact a tenant."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.backends import PortalBackend
from xdr_cli.config import Config
from xdr_cli.device_diagnostics import OfficialDeviceDiagnostics, PortalDeviceDiagnostics
from xdr_cli.device_management import PortalDeviceManagement
from xdr_cli.exceptions import APIError, ConfigError, ConflictError, NetworkError, UsageError
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

BASE = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests"
DEVICE = "a" * 40
ACTION = "00000000-0000-0000-0000-000000000001"
NOW = datetime(2026, 10, 24, 23, 59, 59, tzinfo=UTC)
EXPIRATION = "2026-10-25T03:59:59.000Z"


class Portal(PortalBackend):
    pass


@pytest.fixture
def portal(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    save_portal_cookies(
        {
            "tenant_fingerprint": tenant_fingerprint("test-tenant"),
            "cookie_header": "sccauth=synthetic",
            "xsrf_token": "synthetic",
        }
    )
    client = Portal(Config(tenant_id="test-tenant", api_backend="portal-cookie"), 5)
    client._verified = True
    client._dm_tenant_context = AsyncMock(
        return_value={"Features": {"LogsCollection": True}}
    )
    client.get_device = AsyncMock(
        return_value={
            "id": DEVICE,
            "portal_source": {
                "raw": {
                    "SenseMachineId": DEVICE,
                    "OsPlatform": "Windows11",
                    "SenseClientVersion": "synthetic-version",
                }
            },
        }
    )
    monkeypatch.setattr("xdr_cli.device_diagnostics._now", lambda: NOW)
    return client


def accepted(**changes):
    return {"Id": ACTION, "MachineId": DEVICE, "Status": "Pending", **changes}


def active(**changes):
    return {
        "Type": "TroubleshootResponse",
        "MachineId": DEVICE,
        "TroubleshootState": 1,
        "RequestStatus": "Succeeded",
        "TroubleshootExpirationDateTimeUtc": EXPIRATION,
        **changes,
    }


@pytest.mark.asyncio
@respx.mock
async def test_support_logs_exact_request_and_accepted_status(portal):
    submit = respx.post(BASE + "/create").respond(json=accepted())
    result = await portal.collect_device_support_logs(DEVICE, comment="synthetic comment")
    assert json.loads(submit.calls[0].request.content) == {
        "MachineId": DEVICE,
        "RequestorComment": "synthetic comment",
        "Type": "LogsCollectionRequest",
        "OsPlatform": "Windows11",
        "SenseClientVersion": "synthetic-version",
    }
    assert result["type"] == "CollectSupportLogs" and result["status"] == "Pending"
    assert result["portal_source"]["device_association_saved"] is True
    assert "authorization" not in submit.calls[0].request.headers
    await portal.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "context,modern",
    [
        ({"Features": {"LogsCollection": False}}, False),
        ({"Features": {}}, False),
        ({"Features": {"LogsCollection": False, "EnableCollectDiagnosticPackage": True}}, False),
        ({"EnabledFeatures": [], "Features": {"LogsCollection": True}}, False),
        ({"Features": {"LogsCollection": True, "EnableCollectDiagnosticPackage": True}}, True),
        ({"EnabledFeatures": ["LogsCollection", "EnableCollectDiagnosticPackage"]}, True),
    ],
)
async def test_support_logs_feature_gates_prevent_lookup_and_submission(portal, context, modern):
    portal._dm_tenant_context.return_value = context
    submit = respx.post(BASE + "/create").respond(json=accepted())
    expected = UnsupportedBackendCapability if modern else APIError
    with pytest.raises(expected) as caught:
        await portal.collect_device_support_logs(DEVICE, comment="reason")
    if modern:
        assert "modern diagnostic-package" in str(caught.value)
    else:
        assert caught.value.error_code == "TENANT_FEATURE_UNAVAILABLE"
        assert "switch" not in caught.value.suggested_fix.lower()
    portal._dm_tenant_context.assert_awaited_once()
    portal.get_device.assert_not_called()
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "context",
    [
        {},
        {"EnabledFeatures": "LogsCollection"},
        {"EnabledFeatures": [True]},
        {"Features": []},
        {"Features": {"LogsCollection": "true"}},
        {"Features": {"LogsCollection": 1}},
        {"Features": {"LogsCollection": True, "EnableCollectDiagnosticPackage": 0}},
    ],
)
async def test_support_logs_invalid_feature_inventory_never_submits(portal, context):
    portal._dm_tenant_context.return_value = context
    submit = respx.post(BASE + "/create").respond(json=accepted())
    with pytest.raises(APIError):
        await portal.collect_device_support_logs(DEVICE, comment="reason")
    portal.get_device.assert_not_called()
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_support_logs_feature_inventory_must_match_configured_tenant(portal):
    portal._dm_tenant_context = PortalDeviceManagement._dm_tenant_context.__get__(portal)
    respx.get("https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext").respond(
        json={"AuthInfo": {"TenantId": "other-tenant"}, "Features": {"LogsCollection": True}}
    )
    submit = respx.post(BASE + "/create").respond(json=accepted())
    with pytest.raises(ConfigError, match="configured tenant"):
        await portal.collect_device_support_logs(DEVICE, comment="reason")
    portal.get_device.assert_not_called()
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_support_logs_enabled_list_is_authoritative_and_context_is_fresh(portal):
    portal._dm_tenant_context = PortalDeviceManagement._dm_tenant_context.__get__(portal)
    context = respx.get(
        "https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext"
    ).mock(side_effect=[
        httpx.Response(200, json={
            "AuthInfo": {"TenantId": "test-tenant"},
            "EnabledFeatures": ["LogsCollection"],
            "Features": {"LogsCollection": False, "EnableCollectDiagnosticPackage": True},
        }),
        httpx.Response(200, json={
            "AuthInfo": {"TenantId": "test-tenant"}, "EnabledFeatures": [],
        }),
    ])
    submit = respx.post(BASE + "/create").respond(json=accepted())
    await portal.collect_device_support_logs(DEVICE, comment="first request")
    with pytest.raises(APIError) as caught:
        await portal.collect_device_support_logs(DEVICE, comment="second request")
    assert caught.value.error_code == "TENANT_FEATURE_UNAVAILABLE"
    assert context.call_count == 2 and submit.call_count == 1
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_optional_portal_device_fields_are_omitted_not_invented(portal):
    portal.get_device.return_value = {"id": DEVICE, "portal_source": {"raw": {}}}
    submit = respx.post(BASE + "/create").respond(json=accepted())
    await portal.collect_device_support_logs(DEVICE, comment="test")
    body = json.loads(submit.calls[0].request.content)
    assert "OsPlatform" not in body and "SenseClientVersion" not in body
    await portal.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "changes", [{"Id": "invalid"}, {"MachineId": "b" * 40}, {"Status": 0}, {"Status": ""}]
)
async def test_acceptance_requires_correlated_native_identity_and_status(portal, changes):
    submit = respx.post(BASE + "/create").respond(json=accepted(**changes))
    with pytest.raises(APIError) as caught:
        await portal.collect_device_support_logs(DEVICE, comment="test")
    assert caught.value.error_code == "OUTCOME_UNKNOWN" and submit.call_count == 1
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_wrong_device_preflight_does_not_submit(portal):
    portal.get_device.return_value["id"] = "b" * 40
    submit = respx.post(BASE + "/create").respond(json=accepted())
    with pytest.raises(APIError, match="identity"):
        await portal.collect_device_support_logs(DEVICE, comment="test")
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_native_conflicting_device_preflight_does_not_submit(portal):
    portal.get_device.return_value["portal_source"]["raw"]["MachineId"] = "b" * 40
    submit = respx.post(BASE + "/create").respond(json=accepted())
    with pytest.raises(APIError, match="identities"):
        await portal.collect_device_support_logs(DEVICE, comment="test")
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_support_collection_transport_error_is_not_replayed_or_echoed(portal):
    route = respx.post(BASE + "/create").mock(side_effect=httpx.ReadError("SYNTHETIC_SECRET"))
    with pytest.raises(NetworkError) as caught:
        await portal.collect_device_support_logs(DEVICE, comment="secret comment")
    assert route.call_count == 1 and caught.value.retryable is False
    assert caught.value.error_code == "OUTCOME_UNKNOWN"
    assert "SYNTHETIC_SECRET" not in str(caught.value)
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_troubleshooting_on_uses_verified_enum_format_and_four_hours(portal):
    respx.get(BASE + "/latest").respond(json=[])
    submit = respx.post(BASE + "/create").respond(json=accepted())
    result = await portal.set_device_troubleshooting(
        DEVICE,
        enabled=True,
        duration_minutes=240,
        comment="temporary test",
    )
    body = json.loads(submit.calls[0].request.content)
    assert body["Type"] == "TroubleshootRequest"
    assert body["TroubleshootState"] == 1
    assert body["RequestSource"] == 2 and body["ParamsJsonFormatVersion"] == 1
    start = datetime.fromisoformat(body["TroubleshootStartDateTimeUtc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(body["TroubleshootExpirationDateTimeUtc"].replace("Z", "+00:00"))
    assert start == NOW + timedelta(seconds=2)
    assert end - start == timedelta(hours=4)
    assert result["status"] == "Pending" and result["state_change_confirmed"] is False
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_troubleshooting_off_preserves_expiration_and_omits_start(portal):
    respx.get(BASE + "/latest").respond(json=[active()])
    submit = respx.post(BASE + "/create").respond(json=accepted())
    result = await portal.set_device_troubleshooting(
        DEVICE,
        enabled=False,
        duration_minutes=None,
        comment="stop test",
    )
    body = json.loads(submit.calls[0].request.content)
    assert body["TroubleshootState"] == 0
    assert body["TroubleshootExpirationDateTimeUtc"] == EXPIRATION
    assert "TroubleshootStartDateTimeUtc" not in body
    assert result["requested_state"] == "off" and result["state_change_confirmed"] is False
    await portal.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "enabled,rows",
    [
        (True, [active()]),
        (False, []),
        (False, [active(), active()]),
        (False, [active(TroubleshootExpirationDateTimeUtc="2020-01-01T00:00:00Z")]),
        (True, [active(RequestStatus="Pending")]),
        (False, [active(RequestStatus="InProgress")]),
    ],
)
async def test_conflicting_or_unverified_troubleshoot_state_never_submits(portal, enabled, rows):
    respx.get(BASE + "/latest").respond(json=rows)
    submit = respx.post(BASE + "/create").respond(json=accepted())
    with pytest.raises(ConflictError):
        await portal.set_device_troubleshooting(
            DEVICE,
            enabled=enabled,
            duration_minutes=None,
            comment="test",
        )
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "rows",
    [
        {},
        [None],
        [active(MachineId="b" * 40)],
        [active(TroubleshootState=2)],
        [active(TroubleshootExpirationDateTimeUtc="invalid")],
        [active(TroubleshootExpirationDateTimeUtc="2026-10-25T01:00:00")],
    ],
)
async def test_malformed_native_state_cannot_be_used_to_stop(portal, rows):
    respx.get(BASE + "/latest").respond(json=rows)
    submit = respx.post(BASE + "/create").respond(json=accepted())
    with pytest.raises(APIError):
        await portal.set_device_troubleshooting(
            DEVICE,
            enabled=False,
            duration_minutes=None,
            comment="test",
        )
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enabled,duration", [(True, 1), (True, 239), (True, True), (False, 240), ("true", None)]
)
async def test_unsupported_duration_or_boolean_fails_before_device_read(portal, enabled, duration):
    with pytest.raises(UsageError):
        await portal.set_device_troubleshooting(
            DEVICE,
            enabled=enabled,
            duration_minutes=duration,
            comment="test",
        )
    portal.get_device.assert_not_called()
    await portal.close()


@pytest.mark.asyncio
async def test_official_operations_explicitly_unavailable_without_network():
    backend = OfficialDeviceDiagnostics()
    with pytest.raises(UnsupportedBackendCapability):
        await backend.collect_device_support_logs(DEVICE, comment="test")
    with pytest.raises(UnsupportedBackendCapability):
        await backend.set_device_troubleshooting(
            DEVICE,
            enabled=True,
            duration_minutes=240,
            comment="test",
        )
    with pytest.raises(UnsupportedBackendCapability):
        await backend.get_support_logs_transfer(ACTION, device_id=DEVICE)


@pytest.mark.asyncio
async def test_portal_download_gap_is_explicit_without_lookup(portal):
    with pytest.raises(UnsupportedBackendCapability):
        await portal.get_support_logs_transfer(ACTION, device_id=DEVICE)
    portal.get_device.assert_not_called()
    await portal.close()
