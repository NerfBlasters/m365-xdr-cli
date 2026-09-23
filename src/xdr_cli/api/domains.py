"""Domains API — Entra ID / M365 verified domains."""

from __future__ import annotations

from xdr_cli.client import APISurface, XDRClient


async def list_domains(client: XDRClient) -> list[dict]:
    """List all domains registered in the tenant."""
    result = await client.get(APISurface.GRAPH_CORE, "domains")
    return result.get("value", [])
