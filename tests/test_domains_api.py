"""Tests for domains API module."""

import pytest
import respx

from xdr_cli.api.domains import list_domains
from xdr_cli.client import XDRClient

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
    return XDRClient(get_token=lambda scopes=None: "fake", timeout=5)


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
