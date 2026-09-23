"""Incidents API — Microsoft Graph Security v2."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from xdr_cli.client import APISurface, XDRClient


async def list_incidents(
    client: XDRClient,
    *,
    odata_filter: str = "",
    top: int = 25,
    limit: int = 0,
) -> AsyncIterator[dict]:
    """List incidents with optional OData filtering."""
    params: dict[str, Any] = {"$top": top, "$orderby": "createdDateTime desc"}
    if odata_filter:
        params["$filter"] = odata_filter
    async for item in client.paginate(APISurface.GRAPH, "incidents", params=params, limit=limit):
        yield item


async def get_incident(
    client: XDRClient,
    incident_id: str,
    *,
    expand: list[str] | None = None,
) -> dict:
    """Get a single incident by ID, optionally expanding alerts/evidence."""
    params: dict[str, str] = {}
    if expand:
        params["$expand"] = ",".join(expand)
    return await client.get(APISurface.GRAPH, f"incidents/{incident_id}", params=params or None)


async def update_incident(
    client: XDRClient,
    incident_id: str,
    payload: dict[str, Any],
) -> dict:
    """Update incident fields (status, classification, determination)."""
    return await client.patch(APISurface.GRAPH, f"incidents/{incident_id}", json=payload)


async def add_incident_comment(
    client: XDRClient,
    incident_id: str,
    comment: str,
) -> dict:
    """Post a comment on an incident.

    Microsoft Graph requires comments to land on a separate endpoint —
    they cannot be PATCHed alongside status / classification / determination.
    Reference: https://learn.microsoft.com/en-us/graph/api/security-incident-post-comments
    """
    return await client.post(
        APISurface.GRAPH,
        f"incidents/{incident_id}/comments",
        json={"comment": comment},
    )
