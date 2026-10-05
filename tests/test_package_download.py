"""Archive transfer uses synthetic ZIP bytes and no real signed links."""
import hashlib
import io
import json
import os
import zipfile

import httpx
import pytest
import respx
from click.testing import CliRunner

from xdr_cli.config import Config, save_config
from xdr_cli.exceptions import APIError, ConflictError, NetworkError, RateLimitError
from xdr_cli.main import app
from xdr_cli.package_download import download_package_archive, validate_package_url
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

URL = "https://synthetic.blob.core.windows.net/packages/test.zip?sig=SECRET"
BASE = "https://security.microsoft.com/apiproxy/mtp"
ACTION = "00000000-0000-0000-0000-000000000001"
DEVICE = "a" * 40


def archive():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr("test.txt", "synthetic forensic data")
    return stream.getvalue()


@pytest.mark.asyncio
@respx.mock
async def test_private_download_hash_and_credential_isolation(tmp_path):
    data = archive()
    route = respx.get(URL).respond(content=data)
    output = tmp_path / "archive.zip"
    result = await download_package_archive(URL, output)
    assert output.read_bytes() == data
    assert result["bytes"] == len(data)
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["extracted"] is False
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    request = route.calls[0].request
    for name in ("cookie", "authorization", "x-xsrf-token", "tenant-id", "x-tid", "origin"):
        assert name not in request.headers
    assert "SECRET" not in json.dumps(result)
    assert not list(tmp_path.glob(".xdr-package-*"))


@pytest.mark.parametrize("url", [
    "http://synthetic.blob.core.windows.net/test?sig=x",
    "https://synthetic.blob.core.windows.net.evil.invalid/test?sig=x",
    "https://example.invalid/test?sig=x", "https://127.0.0.1/test?sig=x",
    "https://user:password@synthetic.blob.core.windows.net/test?sig=x",
    "https://synthetic.blob.core.windows.net:444/test?sig=x",
    "https://synthetic.blob.core.windows.net/test?sig=x#fragment",
    "https://synthetic.blob.core.windows.net/test", URL + "&sig=duplicate",
])
def test_link_origin_and_shape_rejected_without_disclosure(url):
    with pytest.raises(APIError) as exc:
        validate_package_url(url)
    assert url not in str(exc.value)


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("response,error", [
    (httpx.Response(302, headers={"Location": "https://example.invalid/"}), APIError),
    (httpx.Response(403, text="SECRET"), APIError),
    (httpx.Response(429, headers={"Retry-After": "13"}), RateLimitError),
    (httpx.Response(200, content=b"<html>not a zip</html>"), APIError),
    (httpx.Response(200, content=archive(), headers={"Content-Length": "10000"}), APIError),
])
async def test_failed_transfer_preserves_existing_output(tmp_path, response, error):
    output = tmp_path / "archive.zip"
    output.write_bytes(b"original")
    route = respx.get(URL).mock(return_value=response)
    with pytest.raises(error) as exc:
        await download_package_archive(URL, output, force=True)
    assert "SECRET" not in str(exc.value)
    assert output.read_bytes() == b"original"
    assert route.call_count == 1
    assert not list(tmp_path.glob(".xdr-package-*"))


@pytest.mark.asyncio
@respx.mock
async def test_size_limit_and_existing_destination(tmp_path):
    route = respx.get(URL).respond(content=archive())
    output = tmp_path / "archive.zip"
    output.write_bytes(b"original")
    with pytest.raises(ConflictError):
        await download_package_archive(URL, output)
    assert not route.called
    with pytest.raises(APIError, match="max-bytes"):
        await download_package_archive(URL, output, force=True, max_bytes=1)
    assert output.read_bytes() == b"original"


@pytest.mark.asyncio
@respx.mock
async def test_transport_error_hides_signed_link_and_cleans_staging(tmp_path):
    respx.get(URL).mock(side_effect=httpx.ReadError("failure at " + URL))
    with pytest.raises(NetworkError) as exc:
        await download_package_archive(URL, tmp_path / "archive.zip")
    assert "SECRET" not in str(exc.value)
    assert not list(tmp_path.iterdir())


@pytest.mark.asyncio
@respx.mock
async def test_force_replaces_symlink_entry_without_writing_target(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"preserved")
    output = tmp_path / "archive.zip"
    try:
        output.symlink_to(target)
    except OSError:
        pytest.skip("symlink unavailable")
    respx.get(URL).respond(content=archive())
    await download_package_archive(URL, output, force=True)
    assert not output.is_symlink()
    assert target.read_bytes() == b"preserved"


@pytest.mark.asyncio
@respx.mock
async def test_concurrent_destination_is_not_replaced(tmp_path):
    output = tmp_path / "archive.zip"
    def response(request):
        output.write_bytes(b"concurrent")
        return httpx.Response(200, content=archive())
    respx.get(URL).mock(side_effect=response)
    with pytest.raises(ConflictError):
        await download_package_archive(URL, output)
    assert output.read_bytes() == b"concurrent"
    assert not list(tmp_path.glob(".xdr-package-*"))


def configure(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "config"))
    save_config(Config(tenant_id="test-tenant", api_backend="portal-cookie"))
    save_portal_cookies({
        "tenant_fingerprint": tenant_fingerprint("test-tenant"),
        "cookie_header": "sccauth=PRIVATE; XSRF-TOKEN=PRIVATE", "xsrf_token": "PRIVATE",
    })
    def no_auth(*args, **kwargs):
        raise AssertionError("MSAL forbidden")
    monkeypatch.setattr("xdr_cli.commands.device_cmd.AuthManager", no_auth)
    respx.get(BASE + "/sccManagement/mgmt/TenantContext").respond(
        json={"AuthInfo": {"TenantId": "test-tenant"}},
    )


@respx.mock
@pytest.mark.parametrize("json_string", [True, False])
def test_cli_download_handles_both_link_envelopes(tmp_path, monkeypatch, json_string):
    configure(tmp_path, monkeypatch)
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=[{
        "RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": "Succeeded",
        "Type": "ForensicsResponse",
    }])
    link = respx.get(BASE + "/responseApiPortal/requests/forensics/downloaduribyguid/V2")
    if json_string:
        link.respond(json=URL)
    else:
        link.respond(text=URL, headers={"Content-Type": "text/plain"})
    blob = respx.get(URL).respond(content=archive())
    result = CliRunner().invoke(app, [
        "device", "download-package", ACTION, "--device", DEVICE,
        "--output", str(tmp_path / "archive.zip"),
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["data"]["archive_format"] == "zip"
    assert "SECRET" not in result.output and "PRIVATE" not in result.output
    assert link.calls[0].request.url.params["packageIdentity"] == "null"
    assert "cookie" in link.calls[0].request.headers
    assert "cookie" not in blob.calls[0].request.headers


@respx.mock
@pytest.mark.parametrize("state,kind,code", [
    ("Submitted", "ForensicsResponse", 13), ("Failed", "ForensicsResponse", 13),
    ("Succeeded", "ScanResponse", 6),
])
def test_non_collection_or_incomplete_action_never_requests_link(
    tmp_path, monkeypatch, state, kind, code,
):
    configure(tmp_path, monkeypatch)
    respx.get(BASE + "/responseApiPortal/requests/latest").respond(json=[{
        "RequestGuid": ACTION, "MachineId": DEVICE, "RequestStatus": state, "Type": kind,
    }])
    result = CliRunner().invoke(app, [
        "device", "download-package", ACTION, "--device", DEVICE,
        "--output", str(tmp_path / "archive.zip"),
    ])
    assert result.exit_code == code, result.output
    assert len(respx.calls) == 2
    assert not (tmp_path / "archive.zip").exists()


class PartialTransfer(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"PK" + b"x" * 65536
        raise httpx.ReadError("connection lost at " + URL)


class BoundedTransfer(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield archive()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("stream,limit,error", [
    (PartialTransfer(), 1000000, NetworkError),
    (BoundedTransfer(), 1, APIError),
])
async def test_stream_failure_without_length_never_publishes(tmp_path, stream, limit, error):
    respx.get(URL).mock(return_value=httpx.Response(200, stream=stream))
    with pytest.raises(error) as exc:
        await download_package_archive(URL, tmp_path / "package.zip", max_bytes=limit)
    assert "SECRET" not in str(exc.value)
    assert not list(tmp_path.iterdir())
