"""Tests for `xdr device timeline` (Task 8 command + Task 9 integration tests).

Two independent mocking layers are exercised across this file:

- The MAIN MDE API (official `XDRClient`/`AuthManager`), used only for
  hostname -> MachineId resolution. Isolated by patching
  `find_device_by_hostname` directly (device resolution is not the thing
  under test here) or by supplying an already-40-hex `device` argument. Exact
  IDs short-circuit except under stored-cookie auth, where the official tenant
  is deliberately checked.
- The unofficial Defender-portal apiproxy (`PortalClient` + FOCI token
  redemption), used for the timeline events themselves. The happy-path and
  output/gzip tests exercise this for real via `respx` (token endpoint +
  apiproxy endpoint); the auth-precedence and collision tests patch
  `PortalClient`/`stream_device_timeline` directly since they're only
  concerned with *which* strategy gets built / whether a request happens
  at all.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import respx
from typer.testing import CliRunner

from xdr_cli.main import app, run
from xdr_cli.portal_client import BearerAuth, CookieAuth, RefreshTokenAuth

runner = CliRunner()

TENANT_ID = "test-tenant"
TENANT_FINGERPRINT = hashlib.sha256(TENANT_ID.encode()).hexdigest()
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
APIPROXY_BASE = "https://security.microsoft.com/apiproxy/mtp/"

# A concrete 40-hex machine ID, the same shape as a real MDE MachineId
# (SHA1 digest hex) — matches the fixture style in tests/test_timeline_api.py.
MACHINE_ID = hashlib.sha1(b"WS-MARKETING-04").hexdigest()
assert len(MACHINE_ID) == 40

HOSTNAME = "WS-MARKETING-04"


def _bound_cookie_store(**overrides) -> dict:
    data = {
        "sccauth": "S" * 300,
        "xsrf_token": "X",
        "stored_at": "now",
        "tenant_fingerprint": TENANT_FINGERPRINT,
    }
    data.update(overrides)
    return data


def _timeline_url(machine_id: str = MACHINE_ID) -> str:
    return f"{APIPROXY_BASE}mdeTimelineExperience/machines/{machine_id}/events"


async def _async_gen(items: list[dict]) -> AsyncIterator[dict]:
    for item in items:
        yield item


@pytest.fixture()
def home_dir(tmp_path, monkeypatch):
    """Isolated XDR_CLI_HOME with a tenant_id preset (needed for
    RefreshTokenAuth's token-endpoint URL and PortalAuth's MSAL authority).
    Never touches the real ~/.xdr-cli/. MDE_REFRESH_TOKEN is scrubbed so
    ambient CI/dev-shell env vars can't leak a strategy the test didn't ask
    for.
    """
    home = tmp_path / ".xdr-cli"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(f'tenant_id = "{TENANT_ID}"\n')
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("MDE_REFRESH_TOKEN", raising=False)
    monkeypatch.setattr(
        "xdr_cli.commands.device_cmd.get_device",
        AsyncMock(return_value={"id": MACHINE_ID, "computerDnsName": HOSTNAME}),
    )
    return home


# ---------------------------------------------------------------------------
# 1. Happy path with --refresh-token (end-to-end over respx)
# ---------------------------------------------------------------------------


@respx.mock
def test_happy_path_refresh_token_streams_jsonl(home_dir):
    device = {"id": MACHINE_ID, "computerDnsName": HOSTNAME}
    events = [
        {"Id": "evt-1", "ActionType": "ProcessCreated"},
        {"Id": "evt-2", "ActionType": "NetworkConnection"},
    ]

    token_route = respx.post(TOKEN_URL).respond(json={"access_token": "fake-access-token"})
    timeline_route = respx.get(_timeline_url()).respond(
        json={"Items": events, "Next": "", "Prev": None, "PartialResponseReasons": []}
    )

    with patch(
        "xdr_cli.commands.device_cmd.find_device_by_hostname",
        new=AsyncMock(return_value=device),
    ):
        result = runner.invoke(
            app,
            [
                "device", "timeline", HOSTNAME,
                "--refresh-token", "fake-refresh-token",
                "--days", "1",
            ],
        )

    assert result.exit_code == 0, result.output
    assert token_route.called
    assert timeline_route.called

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 3
    receipt, *previews = lines
    assert receipt["status"] == "success"
    assert receipt["rows"] == 2
    assert previews == events
    saved = [
        json.loads(line)
        for line in Path(receipt["data_path"]).read_text().splitlines()
    ]
    assert saved == events

    # stderr summary: event count + time range.
    assert "2" in result.stderr
    assert MACHINE_ID in result.stderr


# ---------------------------------------------------------------------------
# 1b. --from / --to accept RFC3339 (the `Z` / offset the help promises)
# ---------------------------------------------------------------------------


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_from_to_accept_rfc3339_z_and_offset(mock_client_cls, mock_stream, home_dir):
    """The help calls `--from`/`--to` RFC3339, so the `Z` (UTC) and numeric
    offset forms must parse — and resolve to the same UTC instant."""
    from datetime import UTC, datetime

    (home_dir / "portal_cookies.json").write_text(
        json.dumps(_bound_cookie_store())
    )
    mock_client_cls.return_value = AsyncMock()
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(
        app,
        [
            "device", "timeline", MACHINE_ID,
            "--from", "2026-07-24T21:00:00Z",
            "--to", "2026-07-24T16:15:00-05:00",  # == 21:15:00Z
        ],
    )

    assert result.exit_code == 0, result.output
    args = mock_stream.call_args.args
    from_date, to_date = args[2], args[3]
    assert from_date == datetime(2026, 7, 24, 21, 0, 0, tzinfo=UTC)
    assert to_date == datetime(2026, 7, 24, 21, 15, 0, tzinfo=UTC)


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_hours_resolves_a_small_lookback_window(mock_client_cls, mock_stream, home_dir):
    """--hours avoids forcing high-volume devices through a full-day pull."""
    from datetime import UTC, datetime, timedelta

    mock_client_cls.return_value = AsyncMock()
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(
        app,
        [
            "device", "timeline", MACHINE_ID,
            "--to", "2026-07-24T21:00:00Z",
            "--hours", "3",
            "--refresh-token", "fake-refresh-token",
        ],
    )

    assert result.exit_code == 0, result.output
    args = mock_stream.call_args.args
    assert args[3] == datetime(2026, 7, 24, 21, 0, 0, tzinfo=UTC)
    assert args[2] == args[3] - timedelta(hours=3)


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_hours_and_days_are_mutually_exclusive(
    mock_client_cls, mock_stream, home_dir
):
    result = runner.invoke(
        app,
        [
            "device", "timeline", MACHINE_ID,
            "--hours", "1",
            "--days", "1",
            "--refresh-token", "fake-refresh-token",
        ],
    )

    assert result.exit_code == 6
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "CLI_USAGE_ERROR"
    assert error["invalid"] == {
        "kind": "mutually_exclusive_options",
        "value": ["--hours", "--days"],
    }
    mock_client_cls.assert_not_called()
    mock_stream.assert_not_called()


# ---------------------------------------------------------------------------
# 1c. Resolved-window guards (180-day cap on the span; --from must be <= --to)
# ---------------------------------------------------------------------------


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_from_to_span_over_180_days_is_rejected(mock_client_cls, mock_stream, home_dir):
    """The 180-day cap is enforced on the RESOLVED --from/--to span, not just
    --days: an over-long explicit window is rejected up front rather than
    silently truncated server-side. No apiproxy call is made."""
    result = runner.invoke(
        app,
        [
            "device", "timeline", MACHINE_ID,
            "--from", "2025-01-01T00:00:00Z",
            "--to", "2025-12-31T00:00:00Z",  # 364 days
            "--refresh-token", "fake-refresh-token",
        ],
    )

    assert result.exit_code != 0
    assert "180" in result.stdout
    assert len(result.stdout.splitlines()) == 1
    mock_client_cls.assert_not_called()
    mock_stream.assert_not_called()


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_days_over_180_still_rejected(mock_client_cls, mock_stream, home_dir):
    """The span guard also covers the original --days>max case: with --from
    absent the span is exactly `days`."""
    result = runner.invoke(
        app,
        [
            "device", "timeline", MACHINE_ID,
            "--days", "200",
            "--refresh-token", "fake-refresh-token",
        ],
    )

    assert result.exit_code != 0
    assert "180" in result.stdout
    assert len(result.stdout.splitlines()) == 1
    mock_client_cls.assert_not_called()
    mock_stream.assert_not_called()


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_span_at_exactly_180_days_is_accepted(mock_client_cls, mock_stream, home_dir):
    """The boundary is inclusive — a window of exactly the maximum is allowed
    (guard uses `>`, not `>=`)."""
    mock_client_cls.return_value = AsyncMock()
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(
        app,
        [
            "device", "timeline", MACHINE_ID,
            "--from", "2026-01-01T00:00:00Z",
            "--to", "2026-06-30T00:00:00Z",  # exactly 180 days (2026 is not a leap year)
            "--refresh-token", "fake-refresh-token",
        ],
    )

    assert result.exit_code == 0, result.output
    mock_stream.assert_called_once()


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_from_after_to_is_rejected(mock_client_cls, mock_stream, home_dir):
    """--from later than --to is a user error (empty/negative window), rejected
    before any apiproxy call."""
    result = runner.invoke(
        app,
        [
            "device", "timeline", MACHINE_ID,
            "--from", "2026-07-24T21:00:00Z",
            "--to", "2026-07-24T20:00:00Z",
            "--refresh-token", "fake-refresh-token",
        ],
    )

    assert result.exit_code != 0
    assert "--from" in result.stdout
    assert len(result.stdout.splitlines()) == 1
    mock_client_cls.assert_not_called()
    mock_stream.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Auth strategy precedence (all four branches)
# ---------------------------------------------------------------------------


def _stub_portal_client_and_stream():
    """Patch PortalClient + stream_device_timeline so precedence tests never
    touch the network — only the auth object passed to PortalClient matters
    here."""
    mock_client_cls = MagicMock()
    mock_client_instance = AsyncMock()
    mock_client_cls.return_value = mock_client_instance
    mock_stream = MagicMock(side_effect=lambda *a, **kw: _async_gen([]))
    return mock_client_cls, mock_stream


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_refresh_token_wins_over_stored_cookie(mock_client_cls, mock_stream, home_dir):
    """--refresh-token set AND a stored portal_cookies.json present ->
    RefreshTokenAuth wins (explicit per-run credential beats stored state)."""
    (home_dir / "portal_cookies.json").write_text(
        json.dumps(_bound_cookie_store())
    )
    mock_instance = AsyncMock()
    mock_client_cls.return_value = mock_instance
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(
        app, ["device", "timeline", MACHINE_ID, "--refresh-token", "fake-refresh-token"]
    )

    assert result.exit_code == 0, result.output
    mock_client_cls.assert_called_once()
    _, kwargs = mock_client_cls.call_args
    assert isinstance(kwargs["auth"], RefreshTokenAuth)


@patch("xdr_cli.commands.device_cmd.PortalAuth")
@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_cookie_wins_over_cached_msal_account(
    mock_client_cls, mock_stream, mock_portal_auth_cls, home_dir,
):
    """No --refresh-token; stored cookie file present AND a cached MSAL
    account present -> CookieAuth wins. PortalAuth is mocked to report an
    authenticated account so this actually proves cookie beats MSAL rather
    than MSAL just being unavailable."""
    (home_dir / "portal_cookies.json").write_text(
        json.dumps(_bound_cookie_store())
    )
    mock_portal_auth_cls.return_value.get_auth_status.return_value = {
        "authenticated": True, "account": "user@test.com",
    }
    mock_instance = AsyncMock()
    mock_client_cls.return_value = mock_instance
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(app, ["device", "timeline", MACHINE_ID])

    assert result.exit_code == 0, result.output
    mock_client_cls.assert_called_once()
    _, kwargs = mock_client_cls.call_args
    assert isinstance(kwargs["auth"], CookieAuth)


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_cookie_machine_id_must_exist_in_configured_tenant(
    mock_client_cls, mock_stream, home_dir, monkeypatch,
):
    (home_dir / "portal_cookies.json").write_text(json.dumps(_bound_cookie_store()))
    monkeypatch.setattr(
        "xdr_cli.commands.device_cmd.get_device",
        AsyncMock(return_value={"id": hashlib.sha1(b"other-device").hexdigest()}),
    )

    result = runner.invoke(app, ["device", "timeline", MACHINE_ID])

    assert result.exit_code == 13
    assert "configured tenant" in result.stdout
    mock_client_cls.assert_not_called()
    mock_stream.assert_not_called()


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_chunked_cookie_store_flows_chunks_into_cookieauth(
    mock_client_cls, mock_stream, home_dir,
):
    """A stored chunked cookie file (`sccauth: chunks:N` + `sccauth_chunks`)
    is wired into CookieAuth with its chunks intact, so `device timeline`
    forwards the chunk cookies exactly as the browser does."""
    (home_dir / "portal_cookies.json").write_text(
        json.dumps(_bound_cookie_store(
            sccauth="chunks:2",
            sccauth_chunks={"sccauthC1": "A" * 4047, "sccauthC2": "B" * 89},
        ))
    )
    mock_client_cls.return_value = AsyncMock()
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(app, ["device", "timeline", MACHINE_ID])

    assert result.exit_code == 0, result.output
    _, kwargs = mock_client_cls.call_args
    auth = kwargs["auth"]
    assert isinstance(auth, CookieAuth)
    assert auth._sccauth == "chunks:2"
    assert auth._sccauth_chunks == {"sccauthC1": "A" * 4047, "sccauthC2": "B" * 89}


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_cookie_store_missing_xsrf_token_degrades_gracefully(
    mock_client_cls, mock_stream, home_dir,
):
    """A portal_cookies.json that parses but lacks `xsrf_token` (hand-edited,
    partial write, or schema drift) must NOT raise KeyError — it degrades to
    CookieAuth's empty-string default, like every sibling key does."""
    stored = _bound_cookie_store(cookie_header="sccauth=S; xsrf-token=T")
    stored.pop("xsrf_token")
    (home_dir / "portal_cookies.json").write_text(json.dumps(stored))
    mock_client_cls.return_value = AsyncMock()
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(app, ["device", "timeline", MACHINE_ID])

    assert result.exit_code == 0, result.output
    _, kwargs = mock_client_cls.call_args
    auth = kwargs["auth"]
    assert isinstance(auth, CookieAuth)
    assert auth._xsrf_token == ""


@patch("xdr_cli.commands.device_cmd.PortalAuth")
@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_cached_msal_account_used_when_no_refresh_token_or_cookie(
    mock_client_cls, mock_stream, mock_portal_auth_cls, home_dir,
):
    """No refresh token, no cookie file, cached MSAL account present ->
    BearerAuth wrapping the PortalAuth instance."""
    mock_portal_auth_instance = mock_portal_auth_cls.return_value
    mock_portal_auth_instance.get_auth_status.return_value = {
        "authenticated": True, "account": "user@test.com",
    }
    mock_instance = AsyncMock()
    mock_client_cls.return_value = mock_instance
    mock_stream.side_effect = lambda *a, **kw: _async_gen([])

    result = runner.invoke(app, ["device", "timeline", MACHINE_ID])

    assert result.exit_code == 0, result.output
    mock_client_cls.assert_called_once()
    _, kwargs = mock_client_cls.call_args
    auth = kwargs["auth"]
    assert isinstance(auth, BearerAuth)
    assert auth._portal_auth is mock_portal_auth_instance


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_no_credentials_exits_nonzero_and_names_both_portal_commands(
    mock_client_cls, mock_stream, home_dir,
):
    """No --refresh-token, no cookie file, no cached MSAL account -> exit
    non-zero, error names BOTH `xdr auth portal-login` and
    `xdr auth portal-cookie`. Nothing PortalClient-shaped is ever touched."""
    result = runner.invoke(app, ["device", "timeline", MACHINE_ID])

    assert result.exit_code != 0
    assert "portal-login" in result.stdout
    assert "portal-cookie" in result.stdout
    assert len(result.stdout.splitlines()) == 1
    mock_client_cls.assert_not_called()
    mock_stream.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Hostname collision
# ---------------------------------------------------------------------------


@patch("xdr_cli.commands.device_cmd.stream_device_timeline")
@patch("xdr_cli.commands.device_cmd.PortalClient")
def test_hostname_collision_exits_nonzero_names_both_no_apiproxy_call(
    mock_client_cls, mock_stream, home_dir,
):
    device_a = {"id": "a" * 40, "computerDnsName": "WS-DUP-01"}
    device_b = {"id": "b" * 40, "computerDnsName": "WS-DUP-02"}

    with patch(
        "xdr_cli.commands.device_cmd.find_device_by_hostname",
        new=AsyncMock(return_value=[device_a, device_b]),
    ):
        result = runner.invoke(
            app, ["device", "timeline", "WS-DUP", "--refresh-token", "fake-refresh-token"]
        )

    assert result.exit_code != 0
    assert "WS-DUP-01" in result.stdout
    assert "WS-DUP-02" in result.stdout
    assert len(result.stdout.splitlines()) == 1
    mock_client_cls.assert_not_called()
    mock_stream.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Output to file + gzip
# ---------------------------------------------------------------------------


@respx.mock
def test_output_file_gzip_round_trips(home_dir, tmp_path):
    device = {"id": MACHINE_ID, "computerDnsName": HOSTNAME}
    events = [
        {"Id": "evt-1", "ActionType": "ProcessCreated"},
        {"Id": "evt-2", "ActionType": "FileCreated"},
        {"Id": "evt-3", "ActionType": "LogonSuccess"},
    ]

    respx.post(TOKEN_URL).respond(json={"access_token": "fake-access-token"})
    respx.get(_timeline_url()).respond(
        json={"Items": events, "Next": "", "Prev": None, "PartialResponseReasons": []}
    )

    out_path = tmp_path / "out.jsonl.gz"

    with patch(
        "xdr_cli.commands.device_cmd.find_device_by_hostname",
        new=AsyncMock(return_value=device),
    ):
        result = runner.invoke(
            app,
            [
                "device", "timeline", HOSTNAME,
                "--refresh-token", "fake-refresh-token",
                "--output", str(out_path),
                "--gzip",
            ],
        )

    assert result.exit_code == 0, result.output
    assert out_path.exists()
    if sys.platform != "win32":
        assert out_path.stat().st_mode & 0o777 == 0o600
    # Nothing written to stdout when --output is used.
    assert result.stdout.strip() == ""

    with gzip.open(out_path, "rt", encoding="utf-8") as f:
        lines = [line for line in f.read().splitlines() if line.strip()]
    assert len(lines) == 3
    assert [json.loads(line) for line in lines] == events


def test_output_refuses_existing_file_and_preserves_it(tmp_path):
    from xdr_cli.commands.device_cmd import _open_timeline_sink
    from xdr_cli.exceptions import ConflictError

    output = tmp_path / "timeline.jsonl"
    output.write_text("existing")

    with pytest.raises(ConflictError), _open_timeline_sink(output, False):
        pass

    assert output.read_text() == "existing"
    assert not list(tmp_path.glob(".timeline.jsonl.*.tmp"))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_output_force_replaces_symlink_entry_not_target(tmp_path):
    from xdr_cli.commands.device_cmd import _open_timeline_sink

    target = tmp_path / "important.txt"
    target.write_text("do not overwrite")
    output = tmp_path / "timeline.jsonl"
    output.symlink_to(target)

    with _open_timeline_sink(output, False, force=True) as sink:
        sink.write('{"safe":true}\n')

    assert not output.is_symlink()
    assert output.read_text() == '{"safe":true}\n'
    assert target.read_text() == "do not overwrite"


def test_failed_output_stream_leaves_no_partial_artifact(tmp_path):
    from xdr_cli.commands.device_cmd import _open_timeline_sink

    output = tmp_path / "timeline.jsonl"
    with pytest.raises(RuntimeError), _open_timeline_sink(output, False) as sink:
        sink.write("partial")
        raise RuntimeError("stream failed")

    assert not output.exists()
    assert not list(tmp_path.glob(".timeline.jsonl.*.tmp"))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_staging_path_substitution_cannot_redirect_writes(tmp_path, monkeypatch):
    from xdr_cli.commands import device_cmd
    from xdr_cli.exceptions import ArtifactError

    output = tmp_path / "timeline.jsonl"
    target = tmp_path / "important.txt"
    target.write_text("untouched")
    real_mkstemp = device_cmd.tempfile.mkstemp

    def substitute_path(*args, **kwargs):
        descriptor, name = real_mkstemp(*args, **kwargs)
        Path(name).unlink()
        Path(name).symlink_to(target)
        return descriptor, name

    monkeypatch.setattr(device_cmd.tempfile, "mkstemp", substitute_path)

    with pytest.raises(ArtifactError), device_cmd._open_timeline_sink(
        output, False
    ) as sink:
        sink.write("must stay on the already-open descriptor")

    assert target.read_text() == "untouched"
    assert not output.exists()
    assert not list(tmp_path.glob(".timeline.jsonl.*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes only")
def test_output_rejects_nonsticky_shared_directory(tmp_path):
    from xdr_cli.commands.device_cmd import _open_timeline_sink
    from xdr_cli.exceptions import ArtifactError

    shared = tmp_path / "shared"
    shared.mkdir(mode=0o777)
    shared.chmod(0o777)
    output = shared / "timeline.jsonl"

    with pytest.raises(ArtifactError), _open_timeline_sink(output, False):
        pass

    assert not output.exists()


@pytest.mark.parametrize("flag", ["--force", "--gzip"])
def test_output_modifiers_require_output_path(home_dir, flag):
    result = runner.invoke(
        app,
        ["device", "timeline", MACHINE_ID, "--refresh-token", "token", flag],
    )

    assert result.exit_code == 6
    assert "requires --output" in result.stdout


# ---------------------------------------------------------------------------
# 4. --refresh-token redaction in session recording
# ---------------------------------------------------------------------------


@respx.mock
def test_refresh_token_redacted_in_session_recording(home_dir, monkeypatch):
    """A `device timeline ... --refresh-token SECRET` run under an active
    session must not persist SECRET to the session JSONL. The Recorder
    snapshots argv verbatim, so the raw secret is redacted at the point argv
    is captured for it (main.py's ``_redact_argv``), before the Recorder
    ever holds it. `CliRunner.invoke(app, ...)` (used by the other tests in
    this file) never goes through `run()`'s finally-flush, so this test
    drives the real entry point instead to exercise the actual write path.
    """
    session_id = "jd-1"
    (home_dir / "sessions").mkdir(parents=True, exist_ok=True)
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": session_id,
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": False,
    }
    (home_dir / "sessions" / f"{session_id}.jsonl").write_text(json.dumps(started) + "\n")
    monkeypatch.setenv("XDR_SESSION", session_id)

    device = {"id": MACHINE_ID, "computerDnsName": HOSTNAME}
    secret = "super-secret-refresh-token-do-not-persist"

    respx.post(TOKEN_URL).respond(json={"access_token": "fake-access-token"})
    respx.get(_timeline_url()).respond(
        json={"Items": [], "Next": "", "Prev": None, "PartialResponseReasons": []}
    )

    monkeypatch.setattr(
        sys, "argv",
        [
            "xdr", "device", "timeline", HOSTNAME,
            "--refresh-token", secret,
            "--days", "1",
        ],
    )

    with (
        patch(
            "xdr_cli.commands.device_cmd.find_device_by_hostname",
            new=AsyncMock(return_value=device),
        ),
        pytest.raises(SystemExit) as exc_info,
    ):
        run()
    assert exc_info.value.code in (0, None)

    jsonl_text = (home_dir / "sessions" / f"{session_id}.jsonl").read_text()
    assert secret not in jsonl_text

    records = [json.loads(line) for line in jsonl_text.splitlines()]
    invocation = next(r for r in records if r["kind"] == "invocation")
    assert "--refresh-token" in invocation["args"]
    idx = invocation["args"].index("--refresh-token")
    assert invocation["args"][idx + 1] == "***REDACTED***"
    # The rest of argv (device, --days, its value) is untouched.
    assert HOSTNAME in invocation["args"]
    assert "--days" in invocation["args"]
    assert "1" in invocation["args"]
