"""Entra domain reads through the selected operation backend."""
from collections.abc import AsyncIterator

from xdr_cli.backend_contract import Backend


async def iter_domains(client: Backend) -> AsyncIterator[dict]:
    async for row in client.iter_domains():
        yield row


async def list_domains(client: Backend) -> list[dict]:
    """List tenant-associated Entra domains."""
    return [row async for row in iter_domains(client)]
