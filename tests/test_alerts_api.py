"""Tests for alerts API module."""

import pytest
import respx

from xdr_cli.api.alerts import get_alert, list_alerts
from xdr_cli.client import XDRClient

SAMPLE_ALERT = {
    "id": "al-1",
    "title": "Suspicious PowerShell",
    "severity": "high",
    "category": "Execution",
    "serviceSource": "microsoftDefenderForEndpoint",
    "createdDateTime": "2025-04-01T10:00:00Z",
    "status": "new",
    "evidence": [],
}


@pytest.fixture()
def client():
    return XDRClient(get_token=lambda scopes=None: "fake", timeout=5)


@respx.mock
@pytest.mark.asyncio
async def test_list_alerts(client):
    respx.get("https://graph.microsoft.com/v1.0/security/alerts_v2").respond(
        json={"value": [SAMPLE_ALERT]}
    )
    items = []
    async for item in list_alerts(client):
        items.append(item)
    assert len(items) == 1
    assert items[0]["title"] == "Suspicious PowerShell"


@respx.mock
@pytest.mark.asyncio
async def test_list_alerts_with_filter(client):
    respx.get("https://graph.microsoft.com/v1.0/security/alerts_v2").respond(
        json={"value": [SAMPLE_ALERT]}
    )
    items = []
    async for item in list_alerts(client, odata_filter="severity eq 'high'", top=5):
        items.append(item)
    assert len(items) == 1


@respx.mock
@pytest.mark.asyncio
async def test_get_alert(client):
    respx.get("https://graph.microsoft.com/v1.0/security/alerts_v2/al-1").respond(
        json=SAMPLE_ALERT
    )
    result = await get_alert(client, "al-1")
    assert result["category"] == "Execution"
