"""Containment is unmanaged-device isolation, with distinct identity/state guards."""

import json
from unittest.mock import AsyncMock

import pytest
import respx

from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.backends import PortalBackend
from xdr_cli.config import Config
from xdr_cli.exceptions import ConflictError
from xdr_cli.official_backend import OfficialBackend
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

DEVICE = "a" * 40
ACTION = "00000000-0000-0000-0000-000000000001"
BASE = "https://security.microsoft.com/apiproxy/mtp"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    save_portal_cookies(
        {
            "tenant_fingerprint": tenant_fingerprint("test-tenant"),
            "cookie_header": "sccauth=synthetic",
            "xsrf_token": "synthetic",
        }
    )
    client = PortalBackend(Config(tenant_id="test-tenant", api_backend="portal-cookie"), 5)
    client._verified = True
    return client


def device(managed):
    respx.get(BASE + "/getMachine/machines").respond(
        json={
            "SenseMachineId": DEVICE,
            "IsManagedByMdatp": managed,
            "OsPlatform": "Linux",
        }
    )


@pytest.mark.asyncio
@respx.mock
async def test_contain_unmanaged_without_agent_version(client):
    device(False)
    submit = respx.post(BASE + "/responseApiPortal/requests/create").respond(
        json={
            "Id": ACTION,
            "MachineId": DEVICE,
            "Status": "Pending",
        }
    )
    result = await client.submit_device_action(DEVICE, "contain", comment="synthetic")
    body = json.loads(submit.calls[0].request.content)
    assert body["Type"] == "IsolationRequest" and body["Action"] == "Isolate"
    assert body["IsolationType"] == "UnManagedDevice"
    assert "SenseClientVersion" not in body
    assert result["type"] == "Contain" and result["status"] == "Pending"
    await client.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("managed", [True, None])
async def test_managed_or_unknown_device_never_contained(client, managed):
    device(managed)
    submit = respx.post(BASE + "/responseApiPortal/requests/create").respond(json={})
    with pytest.raises(ConflictError):
        await client.submit_device_action(DEVICE, "contain", comment="synthetic")
    assert not submit.called
    await client.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("mode", [0, 1, 2, "2", None])
async def test_release_requires_native_unmanaged_containment_state(client, mode):
    device(False)
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(
        json=[
            {
                "MachineId": DEVICE,
                "Type": "IsolationResponse",
                "IsolationType": mode,
                "Action": 0,
                "RequestStatus": "Succeeded",
            }
        ]
    )
    submit = respx.post(BASE + "/responseApiPortal/requests/create").respond(
        json={
            "Id": ACTION,
            "MachineId": DEVICE,
            "Status": "Pending",
        }
    )
    if type(mode) is int and mode == 2:
        result = await client.submit_device_action(DEVICE, "uncontain", comment="synthetic")
        body = json.loads(submit.calls[0].request.content)
        assert body["Action"] == "Unisolate" and body["IsolationType"] == "UnManagedDevice"
        assert result["type"] == "Uncontain"
    else:
        with pytest.raises(ConflictError):
            await client.submit_device_action(DEVICE, "uncontain", comment="synthetic")
        assert not submit.called
    await client.close()


@pytest.mark.asyncio
async def test_official_containment_explicitly_unsupported_before_transport():
    transport = AsyncMock()
    with pytest.raises(UnsupportedBackendCapability):
        await OfficialBackend(transport).submit_device_action(DEVICE, "contain", comment="test")
    transport.post.assert_not_called()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "native_action,status",
    [
        (0, "Failed"),
        (0, "Pending"),
        (1, "Succeeded"),
        (None, "Succeeded"),
        (False, "Succeeded"),
        (0, None),
    ],
)
async def test_release_rejects_failed_pending_released_or_unknown_state(
    client, native_action, status
):
    device(False)
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(
        json=[
            {
                "MachineId": DEVICE,
                "Type": "IsolationResponse",
                "IsolationType": 2,
                "Action": native_action,
                "RequestStatus": status,
            }
        ]
    )
    submit = respx.post(BASE + "/responseApiPortal/requests/create").respond(json={})
    with pytest.raises(ConflictError):
        await client.submit_device_action(DEVICE, "uncontain", comment="synthetic")
    assert not submit.called
    await client.close()
