"""Tests for hunting API module."""

import json as _json

import pytest
import respx

from xdr_cli.api.hunting import HuntingResult, run_query
from xdr_cli.client import XDRClient


@pytest.fixture()
def client():
    return XDRClient(get_token=lambda scopes=None: "fake", timeout=5)


def _body(call) -> dict:
    """Decode a captured respx call's JSON request body."""
    return _json.loads(call.request.content.decode())


@respx.mock
@pytest.mark.asyncio
async def test_run_query_via_graph(client):
    """Graph returns lowercase keys; schema entries are normalized to lowercase."""
    route = respx.post(
        "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    ).respond(
        json={
            "schema": [
                {"name": "Timestamp", "type": "DateTime"},
                {"name": "FileName", "type": "String"},
            ],
            "results": [{"Timestamp": "2025-04-01T10:00:00Z", "FileName": "evil.exe"}],
            "stats": {"ExecutionTime": 1.5},
        }
    )
    result = await run_query(client, "DeviceEvents | take 1")
    assert isinstance(result, HuntingResult)
    assert result.results[0]["FileName"] == "evil.exe"
    assert result.stats["ExecutionTime"] == 1.5
    assert result.schema[0]["name"] == "Timestamp"
    # Graph body must be lowercase "query" — PascalCase "Query" would be a
    # regression against Graph's documented contract.
    body = _body(route.calls.last)
    assert body == {"query": "DeviceEvents | take 1"}


@respx.mock
@pytest.mark.asyncio
async def test_run_query_falls_back_to_mde_on_404(client):
    """Graph 404 (endpoint not on tenant) triggers MDE fallback; schema normalizes."""
    respx.post("https://graph.microsoft.com/v1.0/security/runHuntingQuery").respond(
        status_code=404, json={"error": {"code": "NotFound", "message": "n/a"}}
    )
    mde_route = respx.post(
        "https://api.security.microsoft.com/api/advancedhunting/run"
    ).respond(
        json={
            "Schema": [{"Name": "Timestamp", "Type": "DateTime"}],
            "Results": [{"Timestamp": "2025-04-01T10:00:00Z"}],
            "Stats": {"ExecutionTime": 1.5},
        }
    )
    result = await run_query(client, "DeviceEvents | take 1")
    assert result.schema[0]["name"] == "Timestamp"
    assert result.results[0]["Timestamp"] == "2025-04-01T10:00:00Z"
    # MDE body must be PascalCase "Query".
    body = _body(mde_route.calls.last)
    assert body == {"Query": "DeviceEvents | take 1"}


@respx.mock
@pytest.mark.asyncio
async def test_run_query_falls_back_to_mde_on_403(client):
    """Graph 403 (scope not consented) triggers MDE fallback."""
    respx.post("https://graph.microsoft.com/v1.0/security/runHuntingQuery").respond(
        status_code=403, json={"error": {"code": "Forbidden", "message": "n/a"}}
    )
    respx.post("https://api.security.microsoft.com/api/advancedhunting/run").respond(
        json={"Schema": [], "Results": [], "Stats": {}}
    )
    result = await run_query(client, "DeviceEvents | take 1")
    assert result.results == []


@respx.mock
@pytest.mark.asyncio
async def test_run_query_does_not_fall_back_on_429(client):
    """Rate-limit errors propagate — don't burn MDE quota on a Graph 429."""
    from xdr_cli.exceptions import RateLimitError
    respx.post("https://graph.microsoft.com/v1.0/security/runHuntingQuery").respond(
        status_code=429, headers={"Retry-After": "30"}, json={}
    )
    with pytest.raises(RateLimitError):
        await run_query(client, "DeviceEvents | take 1")


@respx.mock
@pytest.mark.asyncio
async def test_run_query_strips_odata_type_annotations(client):
    """Graph emits `<Field>@odata.type: #Int64` next to int64 columns to hint
    JSON-can't-distinguish-int-widths back to clients. Those annotations are
    pure protocol noise and double the column count for AI-agent consumers —
    the typed information is already in `result.schema`. Strip them.
    """
    respx.post(
        "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    ).respond(
        json={
            "schema": [
                {"name": "UserId", "type": "String"},
                {"name": "Score", "type": "Int64"},
                {"name": "IsExternal", "type": "Int64"},
            ],
            "results": [
                {
                    "UserId": "alice@corp.com",
                    "Score@odata.type": "#Int64",
                    "Score": 6,
                    "IsExternal@odata.type": "#Int64",
                    "IsExternal": 1,
                }
            ],
        }
    )
    result = await run_query(client, "X")
    assert result.results == [
        {"UserId": "alice@corp.com", "Score": 6, "IsExternal": 1}
    ], result.results
