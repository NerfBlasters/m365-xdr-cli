"""Tests for incidents API module."""

import pytest
import respx

from xdr_cli.api.incidents import get_incident, list_incidents, update_incident
from xdr_cli.client import APISurface, XDRClient


@pytest.fixture()
def client():
    return XDRClient(get_token=lambda scopes=None: "fake", timeout=5)


SAMPLE_INCIDENT = {
    "id": "1",
    "displayName": "Multi-stage phishing",
    "severity": "high",
    "status": "active",
    "assignedTo": "analyst@contoso.com",
    "createdDateTime": "2025-04-01T10:00:00Z",
    "lastUpdateDateTime": "2025-04-01T12:00:00Z",
    "alertCount": 3,
}


@respx.mock
@pytest.mark.asyncio
async def test_list_incidents(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        json={"value": [SAMPLE_INCIDENT]}
    )
    items = []
    async for item in list_incidents(client):
        items.append(item)
    assert len(items) == 1
    assert items[0]["id"] == "1"


@respx.mock
@pytest.mark.asyncio
async def test_list_incidents_with_filter(client):
    route = respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        json={"value": [SAMPLE_INCIDENT]}
    )
    items = []
    async for item in list_incidents(client, odata_filter="severity eq 'high'", top=10):
        items.append(item)
    assert len(items) == 1
    # Verify query params were sent
    request = route.calls[0].request
    assert "filter" in str(request.url)


@respx.mock
@pytest.mark.asyncio
async def test_get_incident(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents/1").respond(
        json=SAMPLE_INCIDENT
    )
    result = await get_incident(client, "1")
    assert result["displayName"] == "Multi-stage phishing"


@respx.mock
@pytest.mark.asyncio
async def test_get_incident_with_expand(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents/1").respond(
        json={**SAMPLE_INCIDENT, "alerts": [{"id": "a1"}]}
    )
    result = await get_incident(client, "1", expand=["alerts"])
    assert "alerts" in result


@respx.mock
@pytest.mark.asyncio
async def test_update_incident(client):
    respx.patch("https://graph.microsoft.com/v1.0/security/incidents/1").respond(
        json={**SAMPLE_INCIDENT, "status": "resolved"}
    )
    result = await update_incident(client, "1", {"status": "resolved"})
    assert result["status"] == "resolved"
