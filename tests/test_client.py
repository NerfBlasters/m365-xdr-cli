"""Tests for the HTTP client."""

import pytest
import httpx
import respx

from xdr_cli.client import APISurface, XDRClient
from xdr_cli.exceptions import (
    APIError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
)


@pytest.fixture()
def mock_get_token():
    """A callable that returns a fake token."""
    return lambda scopes=None: "fake-token"


@pytest.fixture()
def client(mock_get_token):
    return XDRClient(get_token=mock_get_token, timeout=5)


@respx.mock
@pytest.mark.asyncio
async def test_get_graph_request(client):
    route = respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        json={"value": [{"id": "1"}]}
    )
    result = await client.get(APISurface.GRAPH, "incidents")
    assert result["value"][0]["id"] == "1"
    assert route.called
    assert "Bearer fake-token" in str(route.calls[0].request.headers["authorization"])


@respx.mock
@pytest.mark.asyncio
async def test_get_mde_request(client):
    respx.get("https://api.security.microsoft.com/api/machines/abc").respond(
        json={"id": "abc", "computerDnsName": "WS-01"}
    )
    result = await client.get(APISurface.MDE, "machines/abc")
    assert result["computerDnsName"] == "WS-01"


@respx.mock
@pytest.mark.asyncio
async def test_post_request(client):
    respx.post("https://api.security.microsoft.com/api/advancedhunting/run").respond(
        json={"Results": [], "Schema": [], "Stats": {}}
    )
    result = await client.post(APISurface.MDE, "advancedhunting/run", json={"Query": "test"})
    assert "Results" in result


@respx.mock
@pytest.mark.asyncio
async def test_404_raises_not_found(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents/999").respond(status_code=404)
    with pytest.raises(NotFoundError):
        await client.get(APISurface.GRAPH, "incidents/999")


@respx.mock
@pytest.mark.asyncio
async def test_403_raises_forbidden(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(status_code=403)
    with pytest.raises(ForbiddenError):
        await client.get(APISurface.GRAPH, "incidents")


@respx.mock
@pytest.mark.asyncio
async def test_429_raises_rate_limit(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        status_code=429, headers={"Retry-After": "30"}
    )
    with pytest.raises(RateLimitError) as exc_info:
        await client.get(APISurface.GRAPH, "incidents")
    assert exc_info.value.retry_after == 30


@respx.mock
@pytest.mark.asyncio
async def test_429_with_http_date_retry_after_does_not_crash(client):
    """RFC 7231 allows an HTTP-date `Retry-After`; it must parse into
    RateLimitError, not raise a ValueError that escapes the response check."""
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        status_code=429, headers={"Retry-After": "Fri, 31 Dec 2100 23:59:59 GMT"}
    )
    with pytest.raises(RateLimitError) as exc_info:
        await client.get(APISurface.GRAPH, "incidents")
    assert isinstance(exc_info.value.retry_after, int)
    assert exc_info.value.retry_after >= 0


@respx.mock
@pytest.mark.asyncio
async def test_429_without_retry_after_header_defaults_to_60(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        status_code=429
    )
    with pytest.raises(RateLimitError) as exc_info:
        await client.get(APISurface.GRAPH, "incidents")
    assert exc_info.value.retry_after == 60


@respx.mock
@pytest.mark.asyncio
async def test_500_raises_api_error(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(status_code=500)
    with pytest.raises(APIError):
        await client.get(APISurface.GRAPH, "incidents")


@respx.mock
@pytest.mark.asyncio
async def test_400_surfaces_inner_error_as_detail(client):
    """Graph's innerError flows into APIError.detail for consumer debugging."""
    respx.get(
        "https://graph.microsoft.com/v1.0/security/incidents"
    ).respond(
        status_code=400,
        json={
            "error": {
                "code": "BadRequest",
                "message": "Invalid filter clause: 'medium,high' is not a valid enum.",
                "innerError": {
                    "date": "2026-04-23T18:00:00",
                    "request-id": "abc-123-def",
                    "client-request-id": "xyz-456",
                },
            }
        },
    )
    with pytest.raises(APIError) as exc_info:
        await client.get(APISurface.GRAPH, "incidents")
    err = exc_info.value
    assert err.status_code == 400
    assert isinstance(err.detail, dict)
    assert err.detail["request-id"] == "abc-123-def"


@respx.mock
@pytest.mark.asyncio
async def test_400_falls_back_to_raw_text_when_no_inner_error(client):
    """When the body has no innerError/details, detail falls back to raw text."""
    respx.get(
        "https://graph.microsoft.com/v1.0/security/incidents"
    ).respond(status_code=400, text="unstructured failure")
    with pytest.raises(APIError) as exc_info:
        await client.get(APISurface.GRAPH, "incidents")
    assert exc_info.value.detail == "unstructured failure"


@respx.mock
@pytest.mark.asyncio
async def test_paginate_follows_next_link(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        json={
            "value": [{"id": "1"}, {"id": "2"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/incidents?$skip=2",
        }
    )
    respx.get("https://graph.microsoft.com/v1.0/security/incidents?$skip=2").respond(
        json={"value": [{"id": "3"}]}
    )
    items = []
    async for item in client.paginate(APISurface.GRAPH, "incidents"):
        items.append(item)
    assert len(items) == 3
    assert items[2]["id"] == "3"


@respx.mock
@pytest.mark.asyncio
async def test_paginate_respects_limit(client):
    respx.get("https://graph.microsoft.com/v1.0/security/incidents").respond(
        json={
            "value": [{"id": "1"}, {"id": "2"}, {"id": "3"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/incidents?$skip=3",
        }
    )
    items = []
    async for item in client.paginate(APISurface.GRAPH, "incidents", limit=2):
        items.append(item)
    assert len(items) == 2
