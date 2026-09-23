"""Tests for `xdr auth` sub-app: login, logout, status, and the unofficial
Defender-portal counterparts (portal-login, portal-cookie, portal-logout).

The portal-cookie tests are security-critical: they assert the pasted
`sccauth`/`xsrf-token` values are stored 0600 and NEVER appear anywhere in
`result.output` (the mixed stdout+stderr stream a real terminal would show).
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()

FOCI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
MSAL_AUDIT_APP_NAME = "Microsoft Azure CLI"
COOKIE_AUDIT_APP_NAME = "Microsoft Defender portal (browser session)"
TENANT_ID = "test-tenant"
TENANT_FINGERPRINT = hashlib.sha256(TENANT_ID.encode()).hexdigest()


def _bound_cookie_store(**overrides) -> dict:
    data = {
        "sccauth": "s",
        "xsrf_token": "x",
        "stored_at": "now",
        "tenant_fingerprint": TENANT_FINGERPRINT,
    }
    data.update(overrides)
    return data


def _parse_json_stdout(result) -> dict:
    """Parse the JSON envelope out of ``result.stdout``.

    click's ``CliRunner`` simulates hidden (``hide_input=True``) prompts by
    echoing the prompt label — but never the typed value — to stdout ahead
    of the command's real output (see click.testing.CliRunner.isolation's
    ``hidden_input``). Locate the envelope by its leading ``{`` and decode just
    that first JSON value — `portal-cookie` may print a shred/keep note to
    stderr *after* the envelope, which CliRunner mixes into stdout.
    """
    text = result.stdout[result.stdout.index("{"):]
    return json.JSONDecoder().raw_decode(text)[0]


@pytest.fixture()
def auth_dir(tmp_path, monkeypatch):
    """Isolated XDR_CLI_HOME — never touch the real ~/.xdr-cli/."""
    home = tmp_path / ".xdr-cli"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(f'tenant_id = "{TENANT_ID}"\n')
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    return home


# ---------------------------------------------------------------------------
# login / logout — main auth
# ---------------------------------------------------------------------------


@patch("xdr_cli.commands.auth_cmd.AuthManager")
def test_login_emits_status_envelope(mock_auth_manager_cls, auth_dir):
    mock_instance = mock_auth_manager_cls.return_value
    # login()'s real return value carries a raw MSAL token payload — assert
    # below that this never reaches stdout/stderr even though it's the
    # return value of the mocked call.
    mock_instance.login.return_value = {
        "access_token": "super-secret-login-access-token-must-not-leak",
        "token_type": "Bearer",
    }
    mock_instance.get_auth_status.return_value = {
        "authenticated": True,
        "configured": True,
        "account": "user@test.com",
        "tenant": "test-tenant",
    }

    result = runner.invoke(
        app,
        ["auth", "login", "--tenant-id", "test-tenant", "--client-id", "test-client"],
    )

    assert result.exit_code == 0, result.output
    mock_instance.login.assert_called_once()
    parsed = _parse_json_stdout(result)
    assert parsed["status"] == "success"
    assert "metadata" in parsed
    assert parsed["data"] == mock_instance.get_auth_status.return_value
    assert "super-secret-login-access-token-must-not-leak" not in result.output


def test_login_missing_tenant_or_client_id_exits_4(auth_dir):
    """Legacy config validation is normalized to one structured line."""
    result = runner.invoke(app, ["auth", "login"])

    assert result.exit_code == 4
    assert "tenant_id and client_id are required" in result.output
    assert json.loads(result.stdout.splitlines()[-1])["error"]["exit_code"] == 4


def test_logout_emits_envelope_reporting_cleared_cache(auth_dir):
    cache_file = auth_dir / "token_cache.json"
    cache_file.write_text('{"cached": true}')

    result = runner.invoke(app, ["auth", "logout"])

    assert result.exit_code == 0, result.output
    assert not cache_file.exists()

    parsed = _parse_json_stdout(result)
    assert parsed["status"] == "success"
    assert "metadata" in parsed
    assert parsed["data"]["authenticated"] is False
    assert parsed["data"]["cleared"] is True


def test_logout_missing_cache_reports_cleared_false(auth_dir):
    result = runner.invoke(app, ["auth", "logout"])

    assert result.exit_code == 0, result.output
    parsed = _parse_json_stdout(result)
    assert parsed["status"] == "success"
    assert parsed["data"]["cleared"] is False


# ---------------------------------------------------------------------------
# portal-login
# ---------------------------------------------------------------------------


@patch("xdr_cli.commands.auth_cmd.PortalAuth")
def test_portal_login_emits_status_envelope(mock_portal_auth_cls, auth_dir):
    mock_instance = mock_portal_auth_cls.return_value
    # login()'s real return value carries a raw MSAL token payload — assert
    # below that this never reaches stdout/stderr even though it's the
    # return value of the mocked call.
    mock_instance.login.return_value = {
        "access_token": "super-secret-access-token-must-not-leak",
        "token_type": "Bearer",
    }
    mock_instance.get_auth_status.return_value = {
        "authenticated": True,
        "configured": True,
        "account": "user@test.com",
        "tenant": "test-tenant",
        "client_id": FOCI_CLIENT_ID,
        "audit_app_name": MSAL_AUDIT_APP_NAME,
    }

    result = runner.invoke(app, ["auth", "portal-login"])

    assert result.exit_code == 0, result.output
    mock_instance.login.assert_called_once()
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "success"
    assert parsed["data"] == mock_instance.get_auth_status.return_value
    assert "super-secret-access-token-must-not-leak" not in result.output


@patch("xdr_cli.commands.auth_cmd.PortalAuth")
def test_portal_login_tenant_id_override_applied_before_login(mock_portal_auth_cls, auth_dir):
    mock_instance = mock_portal_auth_cls.return_value
    mock_instance.login.return_value = {"access_token": "tok"}
    mock_instance.get_auth_status.return_value = {
        "authenticated": True,
        "configured": True,
        "account": "user@test.com",
        "tenant": "override-tenant",
        "client_id": FOCI_CLIENT_ID,
        "audit_app_name": MSAL_AUDIT_APP_NAME,
    }

    result = runner.invoke(
        app, ["auth", "portal-login", "--tenant-id", "override-tenant"]
    )

    assert result.exit_code == 0, result.output
    # PortalAuth(app_ctx.config) — the config passed in must carry the override.
    (config_arg,), _kwargs = mock_portal_auth_cls.call_args
    assert config_arg.tenant_id == "override-tenant"


# ---------------------------------------------------------------------------
# portal-cookie — SECURITY CRITICAL
#
# Input is a required positional COOKIE_SOURCE: a file (or '-' for stdin)
# holding the whole browser Cookie header / "Copy as cURL" blob. There is no
# interactive sccauth/xsrf prompt path — the sccauth-only form omits the
# routing/session cookies the apiproxy needs and 500s.
# ---------------------------------------------------------------------------

# A realistic full Cookie header: routing + session + chunked sccauth + XSRF.
_FULL_COOKIE = (
    "X-PortalEndpoint-RouteKey=scuprod_southcentralus_aks; s.SessID=sess-123; "
    "sccauth=chunks:2; sccauthC1=" + "A" * 4047 + "; sccauthC2=" + "B" * 89 + "; "
    "XSRF-TOKEN=tok-abc%3Apart2"
)
_FULL_XSRF = "tok-abc:part2"  # URL-decoded from the XSRF-TOKEN cookie


def _curl_blob(cookie_value: str = _FULL_COOKIE) -> str:
    return (
        "curl 'https://security.microsoft.com/x' \\\n"
        f"  -b '{cookie_value}' \\\n"
        "  -H 'accept: */*'"
    )


def _curl_file(tmp_path, cookie_value: str = _FULL_COOKIE) -> str:
    path = tmp_path / "curl.txt"
    path.write_text(_curl_blob(cookie_value))
    return str(path)


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_stores_full_header_0600_and_never_leaks(
    mock_client_cls, auth_dir, tmp_path
):
    """A positional cookie file is parsed to the FULL Cookie header, stored
    0600, forwarded verbatim to the verify probe, and no value is ever echoed."""
    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(return_value=None)
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["auth", "portal-cookie", _curl_file(tmp_path)])

    assert result.exit_code == 0, result.output

    cookie_path = auth_dir / "portal_cookies.json"
    assert cookie_path.exists()
    if os.name == "posix":
        assert (cookie_path.stat().st_mode & 0o777) == 0o600

    stored = json.loads(cookie_path.read_text())
    assert stored["cookie_header"] == _FULL_COOKIE
    assert stored["xsrf_token"] == _FULL_XSRF  # auto-extracted + URL-decoded
    assert "stored_at" in stored and stored["stored_at"]
    assert stored["tenant_fingerprint"] == TENANT_FINGERPRINT
    assert "sccauth" not in stored  # no interactive sccauth-only form

    # Core security property: no cookie value echoed, in ANY output stream.
    assert "sess-123" not in result.output
    assert "A" * 4047 not in result.output
    assert "tok-abc" not in result.output

    parsed = _parse_json_stdout(result)
    assert parsed["status"] == "success"
    assert parsed["data"]["verified"] is True
    assert parsed["data"]["audit_app_name"] == COOKIE_AUDIT_APP_NAME
    assert parsed["data"]["account"] is None

    # The verify probe forwards the whole header.
    _, kwargs = mock_client_cls.call_args
    assert kwargs["auth"]._cookie_header == _FULL_COOKIE
    mock_client.probe.assert_awaited_once_with("ndr/machines")
    mock_client.close.assert_called_once()


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_verification_checks_http_success_not_object_shape(
    mock_client_cls, auth_dir, tmp_path
):
    """The live ndr/machines probe returns a JSON array in some tenants.

    Verification is an authentication/HTTP-success probe, so it must not route
    through the timeline client's dict-only response contract.
    """
    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(return_value=None)
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["auth", "portal-cookie", _curl_file(tmp_path)])

    assert result.exit_code == 0, result.output
    assert _parse_json_stdout(result)["data"]["verified"] is True
    mock_client.probe.assert_awaited_once_with("ndr/machines")
    mock_client.get.assert_not_called()


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_reads_source_from_stdin(mock_client_cls, auth_dir):
    """`-` reads the cookie source from stdin (bypasses the tty paste limit)."""
    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(return_value=None)
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["auth", "portal-cookie", "-"], input=_curl_blob())

    assert result.exit_code == 0, result.output
    stored = json.loads((auth_dir / "portal_cookies.json").read_text())
    assert stored["cookie_header"] == _FULL_COOKIE
    assert stored["xsrf_token"] == _FULL_XSRF


def test_portal_cookie_requires_a_source(auth_dir):
    """The cookie source is a required positional argument — no arg is a usage
    error (exit 6), and nothing is stored."""
    result = runner.invoke(app, ["auth", "portal-cookie"])

    assert result.exit_code == 6
    assert not (auth_dir / "portal_cookies.json").exists()


def test_portal_cookie_source_without_cookie_header_errors(auth_dir, tmp_path):
    """A source with no recoverable Cookie header is a clean error, not a
    store."""
    bad = tmp_path / "empty.txt"
    bad.write_text("")
    result = runner.invoke(app, ["auth", "portal-cookie", str(bad)])

    assert result.exit_code == 4
    assert not (auth_dir / "portal_cookies.json").exists()


def test_portal_cookie_missing_file_errors(auth_dir):
    result = runner.invoke(app, ["auth", "portal-cookie", "/no/such/curl.txt"])

    assert result.exit_code == 4
    assert not (auth_dir / "portal_cookies.json").exists()


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_no_verify_skips_network_call(mock_client_cls, auth_dir, tmp_path):
    mock_client_cls.return_value = AsyncMock()

    result = runner.invoke(
        app, ["auth", "portal-cookie", _curl_file(tmp_path), "--no-verify"]
    )

    assert result.exit_code == 0, result.output
    mock_client_cls.assert_not_called()
    parsed = _parse_json_stdout(result)
    assert parsed["data"]["verified"] is None


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_verify_failure_reports_verified_false_without_crashing(
    mock_client_cls, auth_dir, tmp_path
):
    from xdr_cli.exceptions import NotAuthenticatedError

    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(
        side_effect=NotAuthenticatedError("Portal session rejected (401).")
    )
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["auth", "portal-cookie", _curl_file(tmp_path)])

    # Must not crash — cookies are already safely stored even if stale.
    assert result.exit_code == 0, result.output
    assert (auth_dir / "portal_cookies.json").exists()

    parsed = _parse_json_stdout(result)
    assert parsed["data"]["verified"] is False
    assert "verify_error" in parsed["data"]


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_verify_network_error_reports_verified_false_without_crashing(
    mock_client_cls, auth_dir, tmp_path
):
    """A transient network error during --verify is tolerated like an auth
    failure: verified: false, cookies persisted, exit 0 — never a crash."""
    import httpx

    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["auth", "portal-cookie", _curl_file(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (auth_dir / "portal_cookies.json").exists()
    parsed = _parse_json_stdout(result)
    assert parsed["data"]["verified"] is False
    assert "verify_error" in parsed["data"]


# ---------------------------------------------------------------------------
# portal-cookie — source shredding (the source is a live bearer credential)
# ---------------------------------------------------------------------------


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_shreds_source_file_by_default(mock_client_cls, auth_dir, tmp_path):
    """A successfully-imported cookie source file is securely removed by
    default — it holds live session cookies."""
    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(return_value=None)
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    src = _curl_file(tmp_path)
    result = runner.invoke(app, ["auth", "portal-cookie", src])

    assert result.exit_code == 0, result.output
    assert (auth_dir / "portal_cookies.json").exists()  # imported
    assert not Path(src).exists()  # source shredded


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_portal_cookie_rejects_symlink_source_without_touching_target(auth_dir, tmp_path):
    target = tmp_path / "important.txt"
    original = _curl_blob()
    target.write_text(original)
    source = tmp_path / "capture.txt"
    source.symlink_to(target)

    result = runner.invoke(app, ["auth", "portal-cookie", str(source), "--no-verify"])

    assert result.exit_code == 4
    assert target.read_text() == original
    assert source.is_symlink()
    assert not (auth_dir / "portal_cookies.json").exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
@patch("xdr_cli.commands.auth_cmd._store_and_report_portal_cookies")
def test_portal_cookie_path_swap_never_shreds_replacement(
    mock_store, auth_dir, tmp_path
):
    source = Path(_curl_file(tmp_path))
    replacement = tmp_path / "replacement.txt"
    replacement.write_text("do not overwrite me")

    def swap_path(*_args, **_kwargs):
        source.unlink()
        source.symlink_to(replacement)

    mock_store.side_effect = swap_path
    result = runner.invoke(app, ["auth", "portal-cookie", str(source), "--no-verify"])

    assert result.exit_code == 0, result.output
    assert replacement.read_text() == "do not overwrite me"
    assert source.is_symlink()
    assert "not safely shred" in result.output


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_keep_source_preserves_file(mock_client_cls, auth_dir, tmp_path):
    """--keep-source leaves the file untouched."""
    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(return_value=None)
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    src = _curl_file(tmp_path)
    original = Path(src).read_text()
    result = runner.invoke(app, ["auth", "portal-cookie", src, "--keep-source"])

    assert result.exit_code == 0, result.output
    assert Path(src).exists()
    assert Path(src).read_text() == original  # byte-for-byte untouched


def test_portal_cookie_non_cookie_file_is_not_stored_or_shredded(auth_dir, tmp_path):
    """Wiper guard: a source with no `sccauth` cookie is not a Defender session
    — it is rejected, nothing is stored, and the file is NOT shredded."""
    notes = tmp_path / "important-notes.txt"
    notes.write_text("meeting notes: rotate the api keys next week\n")

    result = runner.invoke(app, ["auth", "portal-cookie", str(notes)])

    assert result.exit_code == 4
    assert not (auth_dir / "portal_cookies.json").exists()
    assert notes.exists()  # NOT shredded — never a valid cookie capture
    assert notes.read_text().startswith("meeting notes")  # untouched


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_shreds_even_when_verify_fails(mock_client_cls, auth_dir, tmp_path):
    """A stale-but-valid capture still imports (cookies stored) and its source
    is still shredded — verify failure doesn't leave the credential on disk."""
    from xdr_cli.exceptions import NotAuthenticatedError

    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(side_effect=NotAuthenticatedError("401"))
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    src = _curl_file(tmp_path)
    result = runner.invoke(app, ["auth", "portal-cookie", src])

    assert result.exit_code == 0, result.output
    assert not Path(src).exists()  # shredded despite verified: false


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_shreds_when_structured_transport_error_occurs(
    mock_client_cls, auth_dir, tmp_path
):
    from xdr_cli.exceptions import TimeoutError

    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(side_effect=TimeoutError("verification timed out"))
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    src = _curl_file(tmp_path)
    result = runner.invoke(app, ["auth", "portal-cookie", src])
    assert result.exit_code == 0, result.output
    assert (auth_dir / "portal_cookies.json").exists()
    assert not Path(src).exists()
    assert _parse_json_stdout(result)["data"]["verified"] is False


# ---------------------------------------------------------------------------
# portal-cookie — cookie-header / XSRF extraction helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        # bare Cookie header value (returned unchanged)
        ("sccauth=chunks:2; XSRF-TOKEN=t", "sccauth=chunks:2; XSRF-TOKEN=t"),
        # a "Cookie:" prefixed header line
        ("Cookie: a=1; b=2", "a=1; b=2"),
        ("cookie: a=1; b=2", "a=1; b=2"),
        # a Copy-as-cURL blob: extract the -b '...' value
        ("curl 'https://x' \\\n  -H 'accept: */*' \\\n  -b 'a=1; b=2' \\\n  -H 'x: y'", "a=1; b=2"),
        # --cookie long form
        ("curl 'https://x' --cookie 'a=1; b=2'", "a=1; b=2"),
    ],
)
def test_extract_cookie_header(text, expected):
    from xdr_cli.commands.auth_cmd import _extract_cookie_header

    assert _extract_cookie_header(text) == expected


@pytest.mark.parametrize(
    "header,expected",
    [
        ("sccauth=x; XSRF-TOKEN=tok%3Apart2; s.SessID=z", "tok:part2"),  # uppercase, URL-decoded
        ("xsrf-token=abc; sccauth=x", "abc"),  # lowercase name
        ("sccauth=x; s.SessID=z", None),  # no xsrf cookie present
    ],
)
def test_extract_xsrf_from_cookie_header(header, expected):
    from xdr_cli.commands.auth_cmd import _extract_xsrf_from_cookie_header

    assert _extract_xsrf_from_cookie_header(header) == expected


@patch("xdr_cli.commands.auth_cmd.PortalClient")
def test_portal_cookie_prompts_xsrf_when_header_has_no_xsrf_cookie(
    mock_client_cls, auth_dir, tmp_path
):
    """If the header carries no XSRF-TOKEN cookie, the token is prompted for
    (the only remaining prompt) and stored alongside the full header."""
    mock_client = AsyncMock()
    mock_client.probe = AsyncMock(return_value=None)
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    cookie_value = "X-PortalEndpoint-RouteKey=r; s.SessID=z; sccauth=" + "S" * 300
    result = runner.invoke(
        app, ["auth", "portal-cookie", _curl_file(tmp_path, cookie_value)],
        input="manual-xsrf-token\n",
    )

    assert result.exit_code == 0, result.output
    stored = json.loads((auth_dir / "portal_cookies.json").read_text())
    assert stored["cookie_header"] == cookie_value
    assert stored["xsrf_token"] == "manual-xsrf-token"
    assert "manual-xsrf-token" not in result.output  # hidden prompt


# ---------------------------------------------------------------------------
# portal-logout
# ---------------------------------------------------------------------------


def test_portal_logout_clears_both_portal_files_leaves_main_cache(auth_dir):
    (auth_dir / "portal_token_cache.json").write_text('{"cached": true}')
    (auth_dir / "portal_cookies.json").write_text(
        json.dumps(_bound_cookie_store())
    )
    main_cache = auth_dir / "token_cache.json"
    main_cache.write_text('{"main": true}')

    result = runner.invoke(app, ["auth", "portal-logout"])

    assert result.exit_code == 0, result.output
    assert not (auth_dir / "portal_token_cache.json").exists()
    assert not (auth_dir / "portal_cookies.json").exists()
    assert main_cache.exists()
    assert main_cache.read_text() == '{"main": true}'

    # The cookie file's credential values (written to disk above, and
    # visible to this test only via direct file I/O) must never leak into
    # any output stream via the new envelope.
    assert "sccauth" not in result.output
    assert '"s"' not in result.output
    assert '"x"' not in result.output

    parsed = _parse_json_stdout(result)
    assert parsed["status"] == "success"
    assert "metadata" in parsed
    assert parsed["data"]["authenticated"] is False
    assert parsed["data"]["token_cache_cleared"] is True
    assert parsed["data"]["cookie_cleared"] is True


def test_portal_logout_missing_files_is_a_noop(auth_dir):
    assert not (auth_dir / "portal_token_cache.json").exists()
    assert not (auth_dir / "portal_cookies.json").exists()

    result = runner.invoke(app, ["auth", "portal-logout"])

    assert result.exit_code == 0, result.output
    assert not (auth_dir / "portal_token_cache.json").exists()
    assert not (auth_dir / "portal_cookies.json").exists()

    parsed = _parse_json_stdout(result)
    assert parsed["status"] == "success"
    assert parsed["data"]["token_cache_cleared"] is False
    assert parsed["data"]["cookie_cleared"] is False


# ---------------------------------------------------------------------------
# status — extended with `portal`
# ---------------------------------------------------------------------------


@patch("xdr_cli.commands.auth_cmd.PortalAuth")
def test_status_unauthenticated_has_main_and_portal_keys(mock_portal_auth_cls, auth_dir):
    mock_portal_auth_cls.return_value.get_auth_status.return_value = {
        "authenticated": False,
        "configured": False,
        "account": None,
        "tenant": None,
        "client_id": FOCI_CLIENT_ID,
        "audit_app_name": MSAL_AUDIT_APP_NAME,
    }

    result = runner.invoke(app, ["auth", "status"])

    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    data = parsed["data"]
    assert "main" in data
    assert "portal" in data
    portal = data["portal"]
    assert portal["authenticated"] is False
    assert portal["method"] is None
    assert portal["audit_app_name"] is None
    assert portal["account"] is None
    assert portal["msal_cached"] is False
    assert portal["cookie_stored"] is False


@patch("xdr_cli.commands.auth_cmd.PortalAuth")
def test_status_cookie_present_reports_cookie_method(mock_portal_auth_cls, auth_dir):
    # No cached MSAL account — proves cookie precedence isn't just "both true".
    mock_portal_auth_cls.return_value.get_auth_status.return_value = {
        "authenticated": False,
        "configured": True,
        "account": None,
        "tenant": "test-tenant",
        "client_id": FOCI_CLIENT_ID,
        "audit_app_name": MSAL_AUDIT_APP_NAME,
    }
    (auth_dir / "portal_cookies.json").write_text(
        json.dumps(_bound_cookie_store())
    )

    result = runner.invoke(app, ["auth", "status"])

    assert result.exit_code == 0, result.output
    portal = json.loads(result.stdout)["data"]["portal"]
    assert portal["authenticated"] is True
    assert portal["method"] == "cookie"
    assert portal["audit_app_name"] == COOKIE_AUDIT_APP_NAME
    assert portal["account"] is None
    assert portal["cookie_stored"] is True
    assert portal["msal_cached"] is False


@patch("xdr_cli.commands.auth_cmd.PortalAuth")
def test_status_msal_cached_reports_msal_method_when_no_cookie(
    mock_portal_auth_cls, auth_dir
):
    mock_portal_auth_cls.return_value.get_auth_status.return_value = {
        "authenticated": True,
        "configured": True,
        "account": "user@test.com",
        "tenant": "test-tenant",
        "client_id": FOCI_CLIENT_ID,
        "audit_app_name": MSAL_AUDIT_APP_NAME,
    }

    result = runner.invoke(app, ["auth", "status"])

    assert result.exit_code == 0, result.output
    portal = json.loads(result.stdout)["data"]["portal"]
    assert portal["authenticated"] is True
    assert portal["method"] == "msal"
    assert portal["audit_app_name"] == MSAL_AUDIT_APP_NAME
    assert portal["account"] == "user@test.com"
    assert portal["cookie_stored"] is False
    assert portal["msal_cached"] is True


@patch("xdr_cli.commands.auth_cmd.PortalAuth")
def test_status_cookie_takes_precedence_over_cached_msal(mock_portal_auth_cls, auth_dir):
    """Per the design doc's auth-strategy precedence: a deliberately
    configured cookie store wins over a cached MSAL account."""
    mock_portal_auth_cls.return_value.get_auth_status.return_value = {
        "authenticated": True,
        "configured": True,
        "account": "user@test.com",
        "tenant": "test-tenant",
        "client_id": FOCI_CLIENT_ID,
        "audit_app_name": MSAL_AUDIT_APP_NAME,
    }
    (auth_dir / "portal_cookies.json").write_text(
        json.dumps(_bound_cookie_store())
    )

    result = runner.invoke(app, ["auth", "status"])

    assert result.exit_code == 0, result.output
    portal = json.loads(result.stdout)["data"]["portal"]
    assert portal["method"] == "cookie"
    assert portal["msal_cached"] is True  # both true underneath...
    assert portal["cookie_stored"] is True
    assert portal["audit_app_name"] == COOKIE_AUDIT_APP_NAME  # ...but cookie wins


def test_status_tolerates_corrupt_cookie_file(auth_dir):
    (auth_dir / "portal_cookies.json").write_text("{not valid json")

    with patch("xdr_cli.commands.auth_cmd.PortalAuth") as mock_portal_auth_cls:
        mock_portal_auth_cls.return_value.get_auth_status.return_value = {
            "authenticated": False,
            "configured": False,
            "account": None,
            "tenant": None,
            "client_id": FOCI_CLIENT_ID,
            "audit_app_name": MSAL_AUDIT_APP_NAME,
        }
        result = runner.invoke(app, ["auth", "status"])

    assert result.exit_code == 0, result.output
    portal = json.loads(result.stdout)["data"]["portal"]
    assert portal["cookie_stored"] is False  # corrupt file treated as absent


@pytest.mark.parametrize(
    "stored",
    [
        {"sccauth": "s", "xsrf_token": "x", "stored_at": "now"},
        _bound_cookie_store(tenant_fingerprint=hashlib.sha256(b"other").hexdigest()),
    ],
)
def test_status_rejects_unbound_or_wrong_tenant_cookie_store(auth_dir, stored):
    (auth_dir / "portal_cookies.json").write_text(json.dumps(stored))

    result = runner.invoke(app, ["auth", "status"])

    assert result.exit_code == 4
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "PORTAL_COOKIE_TENANT_MISMATCH"
    assert "xdr auth portal-cookie" in error["message"]
