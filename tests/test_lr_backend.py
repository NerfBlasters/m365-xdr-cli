"""Synthetic Live Response lifecycle, identity and non-replay regression tests."""

import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from xdr_cli.backends import PortalBackend
from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.config import Config
from xdr_cli.exceptions import APIError, ConflictError, NetworkError, UsageError
from xdr_cli.live_response.handles import load_session
from xdr_cli.live_response.models import LRPlatform
from xdr_cli.live_response.parser import parse_console_line
from xdr_cli.official_backend import OfficialBackend
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

BASE = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi"
SESSION = "CLR00000000-0000-0000-0000-000000000001"
OTHER_SESSION = "CLR00000000-0000-0000-0000-000000000002"
COMMAND = "00000000-0000-0000-0000-000000000003"
DEVICE = "a" * 40
TENANT = "test-tenant"


def session(state=0, machine=DEVICE, identity=SESSION):
    return {
        "session_id": identity,
        "machine_id": machine,
        "session_status": state,
        "machine_info": {"machine_id": machine, "os_platform": "Windows11"},
        "start_date": "2026-10-24T00:00:00Z",
        "user": "synthetic-user",
    }


def command(state=1, **changes):
    return {
        "session_id": SESSION,
        "command_id": COMMAND,
        "command_definition_id": "dir",
        "status": state,
        "outputs": [],
        "errors": [],
        "context": {},
        **changes,
    }


@pytest.fixture
def portal(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    save_portal_cookies(
        {
            "tenant_fingerprint": tenant_fingerprint(TENANT),
            "cookie_header": "sccauth=synthetic",
            "xsrf_token": "synthetic",
        }
    )
    client = PortalBackend(Config(tenant_id=TENANT, api_backend="portal-cookie"), 5)
    client._verified = True
    return client


@pytest.mark.asyncio
@respx.mock
async def test_real_payload_windows_paths_and_session_binding(portal):
    portal._lr_session(session())
    respx.get(BASE + "/sessions/" + SESSION).respond(json=session())
    respx.get(BASE + "/get_command_definitions").respond(
        json=[
            {
                "command_definition_id": "dir",
                "params": [{"param_id": "path", "optional": True}],
                "flags": [],
            }
        ]
    )
    submit = respx.post(BASE + "/create_command").respond(json=command(0))
    parsed = parse_console_line(r'dir "C:\Program Files\A;B" > "local output.txt" &')
    result = await portal.lr_submit(SESSION, parsed)
    body = json.loads(submit.calls[0].request.content)
    assert body["params"] == [{"param_id": "path", "value": r"C:\Program Files\A;B"}]
    assert body["background_mode"] is True
    assert "local output.txt" not in body["raw_command_line"]
    assert body["current_directory"] == "C:\\"
    assert result.state == "running" and result.terminal is False
    assert "authorization" not in submit.calls[0].request.headers
    assert submit.calls[0].request.headers["x-xsrf-token"] == "synthetic"
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_session_identity_mismatch_never_installs_handle(portal):
    respx.get(BASE + "/sessions/" + SESSION).respond(json=session(identity=OTHER_SESSION))
    with pytest.raises(APIError, match="identity mismatch"):
        await portal.lr_get_session(SESSION)
    assert load_session(TENANT, "portal-cookie", OTHER_SESSION) is None
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_create_other_device_does_not_install_wrong_locator(portal):
    portal.get_device = AsyncMock(return_value={"LastSeen": "2026-10-24T00:00:00Z"})
    route = respx.post(BASE + "/create_session").respond(json=session(machine="b" * 40))
    with pytest.raises(APIError) as caught:
        await portal.lr_open_session(DEVICE, comment="synthetic")
    assert caught.value.error_code == "OUTCOME_UNKNOWN"
    assert not caught.value.retryable
    assert route.call_count == 1
    assert load_session(TENANT, "portal-cookie", SESSION) is None
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_pending_session_refuses_submission(portal):
    portal._lr_session(session(2))
    respx.get(BASE + "/sessions/" + SESSION).respond(json=session(2))
    submit = respx.post(BASE + "/create_command").respond(json=command())
    with pytest.raises(ConflictError, match="not connected"):
        await portal.lr_submit(SESSION, parse_console_line("dir"))
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_failed_command_is_observable_instead_of_application_error(portal):
    portal._lr_session(session())
    respx.get(BASE + "/commands/" + COMMAND).respond(
        json=command(2, errors=[{"message": "failure"}])
    )
    result = await portal.lr_get_command(SESSION, COMMAND)
    assert result.state == "failed" and result.terminal is True
    assert result.error_count == 1 and not result.succeeded
    output = [row async for row in portal.lr_iter_output(SESSION, COMMAND)]
    assert output[0]["record_type"] == "live-response-command-error"
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_unknown_status_is_not_completed(portal):
    portal._lr_session(session())
    respx.get(BASE + "/commands/" + COMMAND).respond(json=command(999))
    result = await portal.lr_get_command(SESSION, COMMAND)
    assert result.state == "999" and result.terminal is None
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_foreign_session_command_rejected(portal):
    portal._lr_session(session())
    respx.get(BASE + "/commands/" + COMMAND).respond(json=command(session_id=OTHER_SESSION))
    with pytest.raises(APIError, match="session mismatch"):
        await portal.lr_get_command(SESSION, COMMAND)
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_mutation_transport_failure_never_replayed(portal):
    portal._lr_session(session())
    route = respx.post(BASE + "/close_session").mock(side_effect=httpx.ReadError("sensitive-body"))
    with pytest.raises(NetworkError) as caught:
        await portal.lr_close_session(SESSION)
    assert route.call_count == 1
    assert caught.value.error_code == "OUTCOME_UNKNOWN"
    assert caught.value.retryable is False
    assert "sensitive-body" not in str(caught.value)
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_close_fetches_actual_state_without_inventing_success(portal):
    portal._lr_session(session())
    respx.post(BASE + "/close_session").respond(status_code=200, json="OK")
    respx.get(BASE + "/sessions/" + SESSION).respond(json=session(2))
    result = await portal.lr_close_session(SESSION)
    assert result.state == "pending"
    await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_server_missing_parameter_or_flag_never_submits(portal):
    portal._lr_session(session())
    respx.get(BASE + "/sessions/" + SESSION).respond(json=session())
    respx.get(BASE + "/get_command_definitions").respond(
        json=[
            {
                "command_definition_id": "dir",
                "params": [],
                "flags": [],
            }
        ]
    )
    submit = respx.post(BASE + "/create_command").respond(json=command())
    with pytest.raises(UsageError, match="parameter"):
        await portal.lr_submit(SESSION, parse_console_line("dir C:\\"))
    assert not submit.called
    await portal.close()


@pytest.mark.asyncio
async def test_official_sessions_explicitly_unsupported_without_transport():
    transport = AsyncMock()
    official = OfficialBackend(transport)
    with pytest.raises(UnsupportedBackendCapability):
        await official.lr_open_session(DEVICE, comment="test")
    transport.post.assert_not_called()


@pytest.mark.asyncio
async def test_official_batch_exact_order_and_separate_model():
    transport = AsyncMock()
    transport.post.return_value = {
        "id": COMMAND,
        "type": "LiveResponse",
        "status": "Pending",
        "machineId": DEVICE,
    }
    official = OfficialBackend(transport)
    commands = [
        parse_console_line("putfile test.txt"),
        parse_console_line("run test.ps1"),
        parse_console_line(r"getfile C:\test.txt"),
    ]
    result = await official.lr_submit_batch(DEVICE, commands, comment="synthetic")
    payload = transport.post.call_args.kwargs["json"]
    assert [c["type"] for c in payload["Commands"]] == ["PutFile", "RunScript", "GetFile"]
    assert result.session_id is None and result.terminal is False
    transport.reset_mock()
    with pytest.raises(UsageError):
        await official.lr_submit_batch(DEVICE, list(reversed(commands)), comment="synthetic")
    transport.post.assert_not_called()


@pytest.mark.asyncio
async def test_official_library_continuation_cannot_escape_operation():
    transport = AsyncMock()
    transport.get.return_value = {
        "value": [],
        "@odata.nextLink": "https://attacker.invalid/api/libraryfiles?token=x",
    }
    with pytest.raises(APIError):
        _ = [f async for f in OfficialBackend(transport).lr_iter_library()]
    assert transport.get.call_count == 1


def test_platform_is_populated_from_session_metadata(portal):
    assert portal._lr_session(session()).platform == LRPlatform.WINDOWS


@pytest.mark.asyncio
@respx.mock
async def test_metadata_cap_stops_streaming_before_all_bytes_and_closes(portal, monkeypatch):
    from xdr_cli.live_response import portal as module

    monkeypatch.setattr(module, "_MAX_METADATA_BYTES", 128 * 1024)

    class Chunks(httpx.AsyncByteStream):
        yielded = 0
        closed = False

        async def __aiter__(self):
            for _ in range(5):
                self.yielded += 1
                yield b"x" * 65536

        async def aclose(self):
            self.closed = True

    stream = Chunks()
    respx.get(BASE + "/library/get_files").respond(stream=stream)
    with pytest.raises(APIError, match="size bound"):
        _ = [f async for f in portal.lr_iter_library()]
    assert stream.yielded == 3 and stream.closed
    await portal.close()
