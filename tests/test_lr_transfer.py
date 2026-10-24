"""Transfer failures must neither leak credentials nor publish partial evidence."""

import hashlib
from contextlib import asynccontextmanager

import httpx
import pytest
import respx

from xdr_cli.exceptions import APIError, ConflictError
from xdr_cli.live_response.transfer import SignedTransfer, download_transfer

URL = "https://synthetic.blob.core.windows.net/container/item?sig=private"


@pytest.mark.asyncio
@respx.mock
async def test_raw_file_download_is_not_forced_into_zip_and_leaks_no_auth(tmp_path):
    route = respx.get(URL).respond(content=b"plain file\x00bytes")
    target = tmp_path / "artifact.bin"
    transfer = SignedTransfer(_url=URL)
    receipt = await download_transfer(transfer, target, max_bytes=100)
    assert receipt["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert target.read_bytes() == b"plain file\x00bytes"
    assert receipt["extracted"] is False
    assert URL not in repr(transfer) and "sig=" not in repr(transfer)
    headers = route.calls[0].request.headers
    for key in ("authorization", "cookie", "x-xsrf-token", "tenant-id"):
        assert key not in headers


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"too big", headers={"content-length": "7"}),
        httpx.Response(302, headers={"location": "https://attacker.invalid/"}),
        httpx.Response(200, content=b"<html>login</html>", headers={"content-type": "text/html"}),
    ],
)
async def test_failed_transfer_never_publishes(tmp_path, response):
    respx.get(URL).mock(return_value=response)
    target = tmp_path / "artifact.bin"
    with pytest.raises(APIError):
        await download_transfer(SignedTransfer(_url=URL), target, max_bytes=3)
    assert not target.exists()
    assert not list(tmp_path.glob(".xdr-lr-*"))


@pytest.mark.asyncio
async def test_existing_output_refused_before_stream_creation(tmp_path):
    @asynccontextmanager
    async def stream():
        raise AssertionError("must not request when output exists")
        yield

    target = tmp_path / "existing"
    target.write_bytes(b"preserve")
    with pytest.raises(ConflictError):
        await download_transfer(SignedTransfer(_stream_factory=stream), target)
    assert target.read_bytes() == b"preserve"


@pytest.mark.asyncio
async def test_private_portal_stream_and_unknown_length_respect_cap(tmp_path):
    @asynccontextmanager
    async def stream():
        yield httpx.Response(200, content=b"bounded", headers={"content-length": "7"})

    target = tmp_path / "download"
    result = await download_transfer(SignedTransfer(_stream_factory=stream), target, max_bytes=7)
    assert result["bytes"] == 7
