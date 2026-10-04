"""Entra domain reads with bounded, same-collection pagination."""
from __future__ import annotations

from collections.abc import AsyncIterator

import httpx

from xdr_cli.backends import PortalBackend
from xdr_cli.client import APISurface, XDRClient
from xdr_cli.exceptions import APIError


async def iter_domains(client: XDRClient | PortalBackend) -> AsyncIterator[dict]:
    if isinstance(client, PortalBackend):
        async for row in client.iter_domains():
            yield row
        return
    path = "domains"
    seen_links: set[str] = set()
    seen_ids: set[str] = set()
    for _ in range(100):
        result = await client.get(APISurface.GRAPH_CORE, path)
        rows = result.get("value")
        if not isinstance(rows, list):
            raise APIError("Graph domains returned an invalid collection.")
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                    or not row["id"] or row["id"] in seen_ids):
                raise APIError("Graph domains returned invalid or duplicate records.")
            seen_ids.add(row["id"])
            yield row
        link = result.get("@odata.nextLink")
        if not link:
            return
        if not isinstance(link, str) or link in seen_links:
            raise APIError("Graph domains returned an invalid continuation.")
        seen_links.add(link)
        try:
            url = httpx.URL(link)
        except httpx.InvalidURL as exc:
            raise APIError("Graph domains returned an invalid continuation.") from exc
        if (url.scheme != "https" or url.host != "graph.microsoft.com"
                or url.port not in (None, 443) or url.path != "/v1.0/domains"
                or url.username or url.password or url.fragment or not url.query):
            raise APIError("Refusing a domain continuation outside the domain collection.")
        path = str(url)
    raise APIError("Graph domain pagination exceeded its page bound.")


async def list_domains(client: XDRClient | PortalBackend) -> list[dict]:
    """List tenant-associated Entra domains, retaining the API helper contract."""
    return [row async for row in iter_domains(client)]
