"""Alerts API — Microsoft Graph Security v2 alerts_v2."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from xdr_cli.client import APISurface, XDRClient


async def list_alerts(
    client: XDRClient,
    *,
    odata_filter: str = "",
    top: int = 25,
    limit: int = 0,
) -> AsyncIterator[dict]:
    """List alerts with optional OData filtering."""
    params: dict[str, Any] = {"$top": top, "$orderby": "createdDateTime desc"}
    if odata_filter:
        params["$filter"] = odata_filter
    async for item in client.paginate(APISurface.GRAPH, "alerts_v2", params=params, limit=limit):
        yield item


async def get_alert(client: XDRClient, alert_id: str) -> dict:
    """Get a single alert by ID."""
    return await client.get(APISurface.GRAPH, f"alerts_v2/{alert_id}")
