"""Incidents API — Microsoft Graph Security v2."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from xdr_cli.backend_contract import Backend


async def list_incidents(
    client: Backend,
    *,
    odata_filter: str = "",
    top: int = 25,
    limit: int = 0,
) -> AsyncIterator[dict]:
    """List incidents with optional OData filtering."""
    params: dict[str, Any] = {"$top": top, "$orderby": "createdDateTime desc"}
    if odata_filter:
        params["$filter"] = odata_filter
    async for item in client.list_incidents(params=params, limit=limit):
        yield item


async def get_incident(
    client: Backend,
    incident_id: str,
    *,
    expand: list[str] | None = None,
) -> dict:
    """Get a single incident by ID, optionally expanding its alerts."""
    return await client.get_incident(incident_id, expand=expand)


async def update_incident(
    client: Backend,
    incident_id: str,
    payload: dict[str, Any],
) -> dict:
    """Update incident fields (status, classification, determination)."""
    return await client.update_incident(incident_id, payload)


async def add_incident_comment(
    client: Backend,
    incident_id: str,
    comment: str,
) -> dict:
    """Post a comment on an incident.

    Microsoft Graph requires comments to land on a separate endpoint —
    they cannot be PATCHed alongside status / classification / determination.
    Reference: https://learn.microsoft.com/en-us/graph/api/security-incident-post-comments
    """
    return await client.add_incident_comment(incident_id, comment)
