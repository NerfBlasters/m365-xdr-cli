"""Tests for devices API module."""

import pytest
import respx

from xdr_cli.api.devices import (
    collect_investigation_package,
    get_action_status,
    get_device,
    isolate_device,
    run_av_scan,
    unisolate_device,
)
from xdr_cli.client import XDRClient

SAMPLE_DEVICE = {
    "id": "dev-1",
    "computerDnsName": "WS-MARKETING-04",
    "osPlatform": "Windows10",
    "healthStatus": "Active",
    "riskScore": "High",
}

SAMPLE_ACTION = {
    "id": "act-1",
    "type": "Isolate",
    "status": "Pending",
    "machineId": "dev-1",
    "computerDnsName": "WS-MARKETING-04",
}


@pytest.fixture()
def client():
    return XDRClient(get_token=lambda scopes=None: "fake", timeout=5)


@respx.mock
@pytest.mark.asyncio
async def test_get_device(client):
    respx.get(
        "https://api.security.microsoft.com/api/machines/dev-1"
    ).respond(json=SAMPLE_DEVICE)
    result = await get_device(client, "dev-1")
    assert result["computerDnsName"] == "WS-MARKETING-04"


@respx.mock
@pytest.mark.asyncio
async def test_isolate_device(client):
    respx.post(
        "https://api.security.microsoft.com/api/machines/dev-1/isolate"
    ).respond(json=SAMPLE_ACTION, status_code=201)
    result = await isolate_device(
        client, "dev-1", isolation_type="Full", comment="test",
    )
    assert result["status"] == "Pending"
    assert result["type"] == "Isolate"


@respx.mock
@pytest.mark.asyncio
async def test_unisolate_device(client):
    respx.post(
        "https://api.security.microsoft.com/api/machines/dev-1/unisolate"
    ).respond(
        json={**SAMPLE_ACTION, "type": "Unisolate"}, status_code=201,
    )
    result = await unisolate_device(
        client, "dev-1", comment="releasing",
    )
    assert result["type"] == "Unisolate"


@respx.mock
@pytest.mark.asyncio
async def test_run_av_scan(client):
    respx.post(
        "https://api.security.microsoft.com/api/machines/dev-1/runAntiVirusScan"
    ).respond(
        json={**SAMPLE_ACTION, "type": "RunAntiVirusScan"},
        status_code=201,
    )
    result = await run_av_scan(
        client, "dev-1", scan_type="Quick", comment="routine",
    )
    assert result["type"] == "RunAntiVirusScan"


@respx.mock
@pytest.mark.asyncio
async def test_collect_investigation_package(client):
    respx.post(
        "https://api.security.microsoft.com/api/machines/dev-1/collectInvestigationPackage"
    ).respond(
        json={**SAMPLE_ACTION, "type": "CollectInvestigationPackage"},
        status_code=201,
    )
    result = await collect_investigation_package(
        client, "dev-1", comment="forensics",
    )
    assert result["type"] == "CollectInvestigationPackage"


@respx.mock
@pytest.mark.asyncio
async def test_get_action_status(client):
    respx.get(
        "https://api.security.microsoft.com/api/machineactions/act-1"
    ).respond(json={**SAMPLE_ACTION, "status": "Succeeded"})
    result = await get_action_status(client, "act-1")
    assert result["status"] == "Succeeded"
