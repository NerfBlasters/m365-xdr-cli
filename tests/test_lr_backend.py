"""Synthetic Live Response lifecycle, identity and non-replay regression tests."""

import json
import logging
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from xdr_cli.backends import PortalBackend
from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.config import Config
from xdr_cli.exceptions import APIError, ArtifactError, ConflictError, NetworkError, UsageError
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


@pytest.mark.asyncio
@respx.mock
async def test_alias_resolves_for_session_commands_history_and_transfer(portal, caplog):
    """Every public interactive path translates aliases before portal dispatch."""
    caplog.set_level(logging.INFO, logger="xdr.audit")
    observed = portal._lr_session(session())
    assert observed.alias == "lr-1"
    assert observed.last_verified_at is not None
    respx.get(BASE + "/sessions/" + SESSION).respond(json=session())
    respx.get(BASE + "/get_command_definitions").respond(json=[
        {"command_definition_id": "dir", "params": [{"param_id": "path", "optional": True}],
         "flags": []},
    ])
    respx.post(BASE + "/create_command").respond(json=command(0))
    respx.get(BASE + "/commands/" + COMMAND).respond(
        json=command(1, context={"download_token": "synthetic-transfer-token"})
    )
    respx.get(BASE + "/sessions/" + SESSION + "/commands").respond(json=[command()])
    respx.post(BASE + "/commands/" + COMMAND + "/cancel").respond(json={})
    respx.post(BASE + "/close_session").respond(json={})
    transfer_route = respx.get(BASE + "/download_file").respond(content=b"synthetic")
    try:
        assert (await portal.lr_get_session("lr-1")).session_id == SESSION
        assert await portal.lr_command_definitions("lr-1")
        submitted = await portal.lr_submit("lr-1", parse_console_line("dir"))
        assert submitted.session_id == SESSION and submitted.session_alias == "lr-1"
        assert (await portal.lr_get_command("lr-1", COMMAND)).session_alias == "lr-1"
        assert [row async for row in portal.lr_iter_commands("lr-1")]
        await portal.lr_cancel("lr-1", COMMAND)
        assert [row async for row in portal.lr_iter_output("lr-1", COMMAND)] == []
        transfer = await portal.lr_result_transfer("lr-1", COMMAND)
        async with transfer._stream_factory() as response:
            assert await response.aread() == b"synthetic"
        assert transfer_route.call_count == 1
        assert transfer_route.calls[0].request.url.params["session_id"] == SESSION
        await portal.lr_close_session("lr-1")
        identities = [r.getMessage() for r in caplog.records
                      if r.getMessage().startswith("LR_IDENTITY:")]
        assert len(identities) == 2
        for action in ("cancel", "disconnect"):
            assert any(f"action={action}" in line and f"session_id={SESSION}" in line
                       and f"machine_id={DEVICE}" in line and "alias=lr-1" in line
                       for line in identities)
        for call in respx.calls:
            assert "lr-1" not in str(call.request.url)
            assert b"lr-1" not in call.request.content
    finally:
        await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_native_clr_session_remains_recoverable_when_alias_registry_corrupt(portal, tmp_path):
    portal._lr_session(session())
    registry = next(tmp_path.glob("live_response/**/aliases.json"))
    registry.write_text("broken")
    respx.get(BASE + "/sessions/" + SESSION).respond(json=session())
    try:
        observed = await portal.lr_get_session(SESSION)
        assert observed.session_id == SESSION and observed.alias is None
        assert load_session(TENANT, "portal-cookie", SESSION).alias is None
        with pytest.raises(ArtifactError) as caught:
            await portal.lr_get_session("lr-1")
        assert caught.value.exit_code == 12
        assert registry.read_text() == "broken"
    finally:
        await portal.close()


@pytest.mark.asyncio
async def test_preflight_not_found_does_not_mark_remembered_session_dead(portal):
    from xdr_cli.exceptions import NotFoundError

    portal._lr_session(session())
    portal.verify_tenant = AsyncMock(side_effect=NotFoundError("portal tenant metadata"))
    try:
        with pytest.raises(NotFoundError):
            await portal.lr_get_session("lr-1")
        assert load_session(TENANT, "portal-cookie", SESSION).state == "running"
    finally:
        await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_only_session_lookup_404_marks_missing_and_retains_alias(portal):
    from xdr_cli.exceptions import LiveResponseSessionNotFoundError

    portal._lr_session(session())
    respx.get(BASE + "/sessions/" + SESSION).respond(status_code=404)
    try:
        with pytest.raises(LiveResponseSessionNotFoundError):
            await portal.lr_get_session("lr-1")
        cached = load_session(TENANT, "portal-cookie", SESSION)
        assert cached.state == "not-found" and cached.alias == "lr-1"
    finally:
        await portal.close()


@pytest.mark.asyncio
@respx.mock
async def test_session_404_local_write_failure_reports_both_outcomes(portal, monkeypatch):
    portal._lr_session(session())
    respx.get(BASE + "/sessions/" + SESSION).respond(status_code=404)

    def unavailable(*args):
        raise OSError("synthetic-private-path")

    monkeypatch.setattr("xdr_cli.live_response.portal.mark_session_missing", unavailable)
    try:
        with pytest.raises(ArtifactError, match="Defender no longer knows") as caught:
            await portal.lr_get_session("lr-1")
        assert "could not be saved" in str(caught.value)
        assert SESSION in str(caught.value)
        assert caught.value.error_code == "LIVE_RESPONSE_SESSION_NOT_FOUND_STATE_UNSAVED"
        assert "synthetic-private-path" not in str(caught.value)
        assert load_session(TENANT, "portal-cookie", SESSION).state == "running"
    finally:
        await portal.close()
