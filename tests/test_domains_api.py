"""Tests for domains API module."""

import pytest
import respx

from xdr_cli.api.domains import list_domains
from xdr_cli.client import XDRClient
from xdr_cli.official_backend import OfficialBackend

SAMPLE_DOMAINS = [
    {
        "id": "contoso.com",
        "authenticationType": "Managed",
        "isDefault": True,
        "isVerified": True,
    },
    {
        "id": "fabrikam.com",
        "authenticationType": "Managed",
        "isDefault": False,
        "isVerified": True,
    },
]


@pytest.fixture()
def client():
    return OfficialBackend(XDRClient(get_token=lambda scopes=None: "fake", timeout=5))


@respx.mock
@pytest.mark.asyncio
async def test_list_domains(client):
    respx.get("https://graph.microsoft.com/v1.0/domains").mock(
        return_value=respx.MockResponse(200, json={"value": SAMPLE_DOMAINS}),
    )
    result = await list_domains(client)
    assert len(result) == 2
    assert result[0]["id"] == "contoso.com"
    assert result[0]["isDefault"] is True
    assert result[1]["id"] == "fabrikam.com"


@respx.mock
@pytest.mark.asyncio
async def test_list_domains_empty(client):
    respx.get("https://graph.microsoft.com/v1.0/domains").mock(
        return_value=respx.MockResponse(200, json={"value": []}),
    )
    result = await list_domains(client)
    assert result == []


@respx.mock
@pytest.mark.asyncio
async def test_official_domains_pagination(client):
    first = "https://graph.microsoft.com/v1.0/domains"
    next_link = first + "?$skiptoken=opaque"
    respx.get(first).respond(json={"value": [SAMPLE_DOMAINS[0]], "@odata.nextLink": next_link})
    respx.get(next_link).respond(json={"value": [SAMPLE_DOMAINS[1]]})
    assert await list_domains(client) == SAMPLE_DOMAINS
    await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_official_domains_reject_foreign_pagination(client):
    from xdr_cli.exceptions import APIError

    respx.get("https://graph.microsoft.com/v1.0/domains").respond(json={
        "value": SAMPLE_DOMAINS, "@odata.nextLink": "https://example.com/domains?next=1",
    })
    with pytest.raises(APIError, match="outside"):
        await list_domains(client)
    assert len(respx.calls) == 1
    await client.close()
