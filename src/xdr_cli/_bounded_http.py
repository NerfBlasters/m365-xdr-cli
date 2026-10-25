"""Bounded decoding for private control-plane responses, with connection cleanup."""

from __future__ import annotations

import httpx

from xdr_cli.exceptions import APIError


async def read_bounded_response(
    client: httpx.AsyncClient,
    request: httpx.Request,
    *,
    max_bytes: int,
) -> httpx.Response:
    response = await client.send(request, stream=True)
    try:
        chunks = []
        size = 0
        async for chunk in response.aiter_bytes(chunk_size=65536):
            size += len(chunk)
            if size > max_bytes:
                raise APIError("API metadata response exceeds its local size bound.")
            chunks.append(chunk)
        headers = response.headers.copy()
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
        return httpx.Response(
            response.status_code,
            headers=headers,
            request=request,
            content=b"".join(chunks),
        )
    except httpx.DecodingError:
        raise APIError("API metadata response has an invalid content encoding.") from None
    finally:
        await response.aclose()
