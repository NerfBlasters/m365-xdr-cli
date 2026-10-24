"""Independent regressions for backend review findings; no tenant connectivity."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from xdr_cli.backends import PortalBackend
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    AuthError,
    ForbiddenError,
    NetworkError,
    RateLimitError,
    TimeoutError,
    UsageError,
    format_error_json,
)
from xdr_cli.live_response.handles import (
    apply_directory_completion,
    get_current_directory,
    mark_directory_submission,
    remember_session,
    set_current_directory,
)
from xdr_cli.live_response.models import LRSession
from xdr_cli.live_response.parser import parse_console_line
from xdr_cli.live_response.portal import LRRoute
from xdr_cli.live_response.transfer import download_transfer, open_library_source
from xdr_cli.official_backend import OfficialBackend
from xdr_cli.portal_client import CookieAuth


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [500, 502, 503, 504])
@pytest.mark.parametrize("html", [False, True])
async def test_portal_mutation_server_failure_has_recovery_and_is_never_replayed(status, html):
    calls = []

    def handler(request):
        calls.append(request)
        if html:
            return httpx.Response(
                status, text=SECRET, headers={"content-type": "text/html"}
            )
        return httpx.Response(status, json={"error": SECRET})

    client = portal(handler)
    try:
        with pytest.raises(APIError) as caught:
            await client._lr_request(LRRoute.SUBMIT, params={"session_id": SESSION}, body={})
        error = caught.value
        assert error.error_code == "OUTCOME_UNKNOWN" and not error.retryable
        assert error.status_code == status
        assert error.help_command.endswith(f"history {SESSION}")
        assert "rejected" not in str(error).lower()
        assert SECRET not in str(error) and len(calls) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_portal_mutation_unreadable_success_body_does_not_imply_rejection():
    client = portal(lambda request: httpx.Response(200, content=SECRET.encode()))
    try:
        with pytest.raises(APIError) as caught:
            await client._lr_request(LRRoute.SUBMIT, params={"session_id": SESSION}, body={})
        assert caught.value.error_code == "OUTCOME_UNKNOWN" and not caught.value.retryable
        assert caught.value.help_command.endswith(f"history {SESSION}")
        assert SECRET not in str(caught.value)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_portal_post_acceptance_command_validation_preserves_unknown_outcome(private_home):
    response = cd_result(NEW, r"C:\Temp")
    response["status"] = "invalid"
    client = portal(lambda request: httpx.Response(200, json=response))
    client.lr_get_session = AsyncMock(return_value=LRSession(SESSION, DEVICE, "running"))
    client.lr_command_definitions = AsyncMock(return_value=[{
        "command_definition_id": "cd", "params": [{"param_id": "id"}], "flags": [],
    }])
    try:
        with pytest.raises(APIError) as caught:
            await client.lr_submit(SESSION, parse_console_line(r"cd C:\Temp"))
        assert caught.value.error_code == "OUTCOME_UNKNOWN" and not caught.value.retryable
        assert caught.value.help_command.endswith(f"history {SESSION}")
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timestamp", "lock"])
async def test_accepted_cd_local_tracking_failure_keeps_exact_recovery_id(
    private_home, monkeypatch, failure
):
    response = cd_result(NEW, r"C:\Temp")
    if failure == "timestamp":
        response.pop("created_time")
    else:
        def locked(*args, **kwargs):
            raise OSError(SECRET)

        monkeypatch.setattr("xdr_cli.live_response.portal.mark_directory_submission", locked)
    posts = []

    def handler(request):
        posts.append(request)
        return httpx.Response(200, json=response)

    client = portal(handler)
    client.lr_get_session = AsyncMock(return_value=LRSession(SESSION, DEVICE, "running"))
    client.lr_command_definitions = AsyncMock(return_value=[{
        "command_definition_id": "cd", "params": [{"param_id": "id"}], "flags": [],
    }])
    try:
        with pytest.raises(ArtifactError) as caught:
            await client.lr_submit(SESSION, parse_console_line(r"cd C:\Temp"))
        error = caught.value
        assert error.error_code == "ACCEPTED_COMMAND_LOCAL_STATE_FAILED"
        assert not error.retryable and error.help_command.endswith(f"status {SESSION} {NEW}")
        assert NEW in str(error) and SECRET not in str(error)
        assert len(posts) == 1
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["malformed-directory", "local-io"])
async def test_cd_status_and_output_remain_readable_when_directory_tracking_fails(
    private_home, monkeypatch, failure
):
    set_current_directory(TENANT, "portal-cookie", SESSION, r"C:\old")
    mark_directory_submission(TENANT, "portal-cookie", SESSION, NEW, "2026-10-24T00:00:00Z")
    response = cd_result(NEW, "\0invalid" if failure == "malformed-directory" else r"C:\new")
    response["outputs"] = [{"line": "completed"}]
    if failure == "local-io":
        def unavailable(*args, **kwargs):
            raise OSError(SECRET)

        monkeypatch.setattr("xdr_cli.live_response.portal.apply_directory_completion", unavailable)
    client = portal(lambda request: httpx.Response(200, json=response))
    try:
        first = await client.lr_get_command(SESSION, NEW)
        second = await client.lr_get_command(SESSION, NEW)
        assert first.succeeded and second.succeeded
        assert first.directory_tracking == second.directory_tracking == "unavailable"
        rows = [row async for row in client.lr_iter_output(SESSION, NEW)]
        assert rows[0]["line"] == "completed"
        assert get_current_directory(TENANT, "portal-cookie", SESSION) == r"C:\old"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_accepted_close_followup_read_failure_does_not_invite_repeating_close(private_home):
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(request)
            return httpx.Response(200, json="OK")
        raise httpx.ReadError(SECRET)

    client = portal(handler)
    try:
        with pytest.raises(NetworkError) as caught:
            await client.lr_close_session(SESSION)
        assert caught.value.error_code == "OUTCOME_UNKNOWN" and not caught.value.retryable
        assert caught.value.help_command.endswith(f"show {SESSION}")
        assert len(posts) == 1 and SECRET not in str(caught.value)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_accepted_open_local_failure_keeps_verified_session_id(private_home, monkeypatch):
    response = {"session_id": SESSION, "machine_id": DEVICE, "session_status": 0}
    client = portal(lambda request: httpx.Response(200, json=response))
    client.get_device = AsyncMock(return_value={"lastSeen": "2026-10-24T00:00:00Z"})

    def unavailable(*args, **kwargs):
        raise ArtifactError(SECRET)

    monkeypatch.setattr("xdr_cli.live_response.portal.remember_session", unavailable)
    try:
        with pytest.raises(ArtifactError) as caught:
            await client.lr_open_session(DEVICE, comment="reason")
        assert caught.value.error_code == "OUTCOME_UNKNOWN" and not caught.value.retryable
        assert caught.value.help_command.endswith(f"show {SESSION}")
        assert SECRET not in str(caught.value)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 500, 502, 503, 504])
async def test_official_ambiguous_mutation_failure_is_not_retryable(status):
    backend = OfficialBackend.__new__(OfficialBackend)
    backend.transport = AsyncMock()
    backend.transport.post.side_effect = APIError(SECRET, status_code=status, detail=SECRET)
    with pytest.raises(APIError) as caught:
        await backend.lr_submit_batch(
            DEVICE, [parse_console_line(r"getfile C:\Temp\file.txt")], comment="reason"
        )
    error = caught.value
    assert error.error_code == "OUTCOME_UNKNOWN" and not error.retryable
    assert error.help_command.endswith(f"action-history {DEVICE}")
    assert SECRET not in str(error) and SECRET not in str(error.original)
    assert error.detail is None and backend.transport.post.await_count == 1


@pytest.mark.asyncio
async def test_official_post_acceptance_invalid_action_has_device_history_recovery():
    backend = OfficialBackend.__new__(OfficialBackend)
    backend.transport = AsyncMock()
    backend.transport.post.return_value = {
        "id": NEW, "type": "LiveResponse", "machineId": DEVICE, "status": None,
    }
    with pytest.raises(APIError) as caught:
        await backend.lr_submit_batch(
            DEVICE, [parse_console_line(r"getfile C:\Temp\file.txt")], comment="reason"
        )
    assert caught.value.error_code == "OUTCOME_UNKNOWN" and not caught.value.retryable
    assert caught.value.help_command.endswith(f"action-history {DEVICE}")
    assert backend.transport.post.await_count == 1

SESSION = "CLR00000000-0000-0000-0000-000000000001"
OLD = "00000000-0000-0000-0000-000000000002"
NEW = "00000000-0000-0000-0000-000000000003"
DEVICE = "a" * 40
TENANT = "synthetic-review-tenant"
SECRET = "SYNTHETIC_LR_SCRIPT_ARGUMENT_SECRET"


@pytest.fixture
def private_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    remember_session(TENANT, "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    return tmp_path


def portal(handler):
    """Construct only a synthetic transport, avoiding real credential stores."""
    client = PortalBackend.__new__(PortalBackend)
    client._tenant_id = TENANT
    client._verified = True
    client._auth = CookieAuth(cookie_header="sccauth=synthetic", xsrf_token="synthetic")
    client._client = httpx.AsyncClient(
        base_url="https://security.microsoft.com",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    return client


def cd_result(identity, directory):
    return {
        "session_id": SESSION,
        "command_id": identity,
        "command_definition_id": "cd",
        "created_time": "2026-10-24T00:00:00Z",
        "status": 1,
        "outputs": [],
        "errors": [],
        "context": {"current_directory": directory},
    }


@pytest.mark.asyncio
async def test_old_cd_status_and_history_cannot_rewind_new_directory(private_home):
    set_current_directory(TENANT, "portal-cookie", SESSION, r"C:\new")
    old = cd_result(OLD, r"C:\old")

    def respond(request):
        return httpx.Response(200, json=[old] if request.url.path.endswith("/commands") else old)

    client = portal(respond)
    try:
        await client.lr_get_command(SESSION, OLD)
        assert get_current_directory(TENANT, "portal-cookie", SESSION) == r"C:\new"
        _ = [state async for state in client.lr_iter_commands(SESSION)]
        assert get_current_directory(TENANT, "portal-cookie", SESSION) == r"C:\new"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_only_explicit_pending_cd_updates_cwd_and_history_is_side_effect_free(private_home):
    set_current_directory(TENANT, "portal-cookie", SESSION, r"C:\initial")
    mark_directory_submission(TENANT, "portal-cookie", SESSION, NEW, "2026-10-24T01:00:00Z")
    result = cd_result(NEW, r"C:\new")

    def respond(request):
        return httpx.Response(
            200, json=[result] if request.url.path.endswith("/commands") else result
        )

    client = portal(respond)
    try:
        _ = [state async for state in client.lr_iter_commands(SESSION)]
        assert get_current_directory(TENANT, "portal-cookie", SESSION) == r"C:\initial"
        await client.lr_get_command(SESSION, NEW)
        assert get_current_directory(TENANT, "portal-cookie", SESSION) == r"C:\new"
    finally:
        await client.close()


def test_newer_cd_wins_over_out_of_order_submission_and_status_refresh(private_home):
    mark_directory_submission(TENANT, "portal-cookie", SESSION, NEW, "2026-10-24T00:00:02Z")
    mark_directory_submission(TENANT, "portal-cookie", SESSION, OLD, "2026-10-24T00:00:01Z")
    remember_session(TENANT, "portal-cookie", LRSession(SESSION, DEVICE, "running"))
    apply_directory_completion(TENANT, "portal-cookie", SESSION, OLD, r"C:\old")
    assert get_current_directory(TENANT, "portal-cookie", SESSION) is None
    apply_directory_completion(TENANT, "portal-cookie", SESSION, NEW, r"C:\new")
    apply_directory_completion(TENANT, "portal-cookie", SESSION, OLD, r"C:\old")
    assert get_current_directory(TENANT, "portal-cookie", SESSION) == r"C:\new"


@pytest.mark.parametrize(
    "older,newer",
    [
        ("2026-10-24T00:00:00Z", "2026-10-24T00:00:00.100Z"),
        ("2026-10-24T01:00:00+01:00", "2026-10-24T00:00:01Z"),
    ],
)
def test_cd_order_compares_instants_not_raw_iso_text(private_home, older, newer):
    mark_directory_submission(TENANT, "portal-cookie", SESSION, OLD, older)
    mark_directory_submission(TENANT, "portal-cookie", SESSION, NEW, newer)
    apply_directory_completion(TENANT, "portal-cookie", SESSION, NEW, r"C:\new")
    assert get_current_directory(TENANT, "portal-cookie", SESSION) == r"C:\new"


@pytest.mark.asyncio
@pytest.mark.parametrize("mutating", [False, True])
async def test_official_upstream_error_cannot_echo_script_arguments(mutating):
    error = APIError("Invalid script arguments: " + SECRET, status_code=400, detail=SECRET)
    transport = AsyncMock()
    transport.get.side_effect = error
    transport.post.side_effect = error
    client = OfficialBackend(transport)
    with pytest.raises(APIError) as caught:
        if mutating:
            await client.lr_submit_batch(
                DEVICE, [parse_console_line("run test.ps1 -parameters harmless")], comment="test"
            )
        else:
            await client.lr_get_command(None, OLD)
    assert caught.value.exit_code == 3
    assert caught.value.status_code == 400
    assert SECRET not in format_error_json(caught.value)
    assert SECRET not in str(caught.value)
    assert SECRET not in repr(caught.value)


@pytest.mark.asyncio
async def test_official_sanitization_retains_throttle_class_and_delay():
    transport = AsyncMock()
    error = RateLimitError(37)
    error.original = {"status": 429, "detail": SECRET}
    transport.get.side_effect = error
    with pytest.raises(RateLimitError) as caught:
        await OfficialBackend(transport).lr_get_command(None, OLD)
    assert caught.value.exit_code == 9
    assert caught.value.retry_after_seconds == 37
    assert caught.value.retryable is True
    assert SECRET not in format_error_json(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [TimeoutError, NetworkError])
async def test_official_mutation_failure_stays_nonretryable_without_sensitive_args(error_type):
    transport = AsyncMock()
    transport.post.side_effect = error_type(SECRET)
    with pytest.raises(error_type) as caught:
        await OfficialBackend(transport).lr_submit_batch(
            DEVICE, [parse_console_line("run test.ps1")], comment="test"
        )
    assert caught.value.error_code == "OUTCOME_UNKNOWN"
    assert caught.value.retryable is False
    assert SECRET not in format_error_json(caught.value)
    assert SECRET not in str(caught.value)
    assert transport.post.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,headers,error_type,exit_code",
    [
        (401, {}, AuthError, 2),
        (440, {}, AuthError, 2),
        (302, {"location": "https://login.microsoftonline.com/"}, AuthError, 2),
        (200, {"content-type": "text/html"}, AuthError, 2),
        (403, {}, ForbiddenError, 7),
    ],
)
async def test_authenticated_transfer_retains_auth_and_permission_error_classes(
    private_home, status, headers, error_type, exit_code
):
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(status, headers=headers, content=b"synthetic-error")

    client = portal(respond)
    target = private_home / "test-download"
    try:
        transfer = client._lr_transfer("download_file", {"session_id": SESSION, "token": SECRET})
        with pytest.raises(error_type) as caught:
            await download_transfer(transfer, target)
        assert caught.value.exit_code == exit_code
        assert SECRET not in format_error_json(caught.value)
        assert len(seen) == 1
        assert not target.exists()
        assert not list(private_home.glob(".xdr-lr-*"))
    finally:
        await client.close()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes require POSIX")
@pytest.mark.parametrize("backend", ["portal", "official"])
def test_fifo_upload_rejected_promptly_before_network(private_home, backend):
    fifo = private_home / "test.txt"
    os.mkfifo(fifo)
    # A child deadline prevents reintroducing the original blocking-open hang in CI.
    code = """
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock
from xdr_cli.backends import PortalBackend
from xdr_cli.exceptions import UsageError
from xdr_cli.official_backend import OfficialBackend
async def main():
    transport = AsyncMock()
    client = (PortalBackend.__new__(PortalBackend) if sys.argv[1] == 'portal'
              else OfficialBackend(transport))
    try:
        await client.lr_upload_library(Path(sys.argv[2]), description=None,
            parameters_description=None, has_parameters=False, overwrite=False)
    except UsageError:
        transport.upload_live_response_library.assert_not_called()
        return
    raise AssertionError('FIFO was not rejected')
asyncio.run(main())
"""
    result = subprocess.run(
        [sys.executable, "-c", code, backend, str(fifo)], timeout=5, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_library_source_symlink_refused_without_reading_target(private_home):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("requires no-follow open")
    original = private_home / "original.txt"
    original.write_text(SECRET)
    link = private_home / "link.txt"
    link.symlink_to(original)
    with pytest.raises(ArtifactError), open_library_source(link):
        raise AssertionError("must not open a symlink target")
