"""Tests for incidents CLI commands."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return home


@patch("xdr_cli.commands.incidents_cmd.AuthManager")
@patch("xdr_cli.commands.incidents_cmd.XDRClient")
def test_incidents_list_json(mock_client_cls, mock_auth_cls, tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()

    async def fake_paginate(*args, **kwargs):
        yield {"id": "1", "displayName": "Test", "severity": "high", "status": "active"}

    mock_client.paginate = fake_paginate
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client
    mock_auth_cls.return_value.get_token.return_value = "tok"

    result = runner.invoke(app, ["incidents", "list"])
    assert result.exit_code == 0
    parsed, preview = [json.loads(line) for line in result.output.splitlines()]
    assert parsed["status"] == "success"
    assert parsed["rows"] == 1
    assert preview["severity"] == "high"
    assert json.loads(Path(parsed["data_path"]).read_text())["id"] == "1"


@patch("xdr_cli.commands.incidents_cmd.AuthManager")
@patch("xdr_cli.commands.incidents_cmd.XDRClient")
def test_incidents_show_json(mock_client_cls, mock_auth_cls, tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value={"id": "42", "displayName": "Phishing"})
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["incidents", "show", "42"])
    assert result.exit_code == 0
    parsed, preview = [json.loads(line) for line in result.output.splitlines()]
    assert parsed["incident_id"] == "42"
    assert preview["id"] == "42"


def test_incidents_update_rejects_invalid_determination(tmp_path, monkeypatch):
    """Invalid --determination is caught at the CLI boundary, no API call.

    The Graph API returns an opaque 'Request body is incorrect' that
    doesn't name the field. Client-side validation prints the valid enum
    set so the user can correct immediately without a round-trip.
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    result = runner.invoke(
        app,
        [
            "incidents", "update", "155181",
            "--determination", "confirmedUserActivity",
            "--status", "resolved",
            "--yes",
        ],
    )
    assert result.exit_code == 6
    combined = (result.output or "") + (result.stderr or "")
    assert "Invalid --determination" in combined
    assert "confirmedUserActivity" in combined
    # Lists the canonical replacement for the common gotcha value.
    assert "lineOfBusinessApplication" in combined


def test_incidents_update_rejects_invalid_status(tmp_path, monkeypatch):
    """--status is also validated against the API enum."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    result = runner.invoke(
        app, ["incidents", "update", "1", "--status", "closed", "--yes"],
    )
    assert result.exit_code == 6
    combined = (result.output or "") + (result.stderr or "")
    assert "Invalid --status" in combined
    assert "closed" in combined


def test_incidents_update_accepts_valid_determination(tmp_path, monkeypatch):
    """Valid enum values pass validation and reach the API layer."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()
    mock_client.patch = AsyncMock(return_value={"id": "42", "status": "resolved"})
    mock_client.close = AsyncMock()

    with (
        patch("xdr_cli.commands.incidents_cmd.AuthManager"),
        patch("xdr_cli.commands.incidents_cmd.XDRClient", return_value=mock_client),
        patch(
            "xdr_cli.commands.incidents_cmd.update_incident",
            new=AsyncMock(return_value={"id": "42", "status": "resolved"}),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "incidents", "update", "42",
                "--status", "resolved",
                "--classification", "falsePositive",
                "--determination", "notMalicious",
                "--yes",
            ],
        )
    assert result.exit_code == 0, result.output


def test_incidents_show_sets_session_anchor_incident(home, monkeypatch):
    from xdr_cli.sessions import (
        set_current_session, write_session_start_record, Session, current_session,
    )

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    async def _stub_get_incident(*a, **kw):
        return {"id": "155278", "displayName": "test"}

    with patch(
        "xdr_cli.commands.incidents_cmd.get_incident",
        new=_stub_get_incident,
    ):
        mock_client = AsyncMock()
        mock_client.close = AsyncMock()
        with (
            patch("xdr_cli.commands.incidents_cmd.AuthManager"),
            patch("xdr_cli.commands.incidents_cmd.XDRClient", return_value=mock_client),
        ):
            result = runner.invoke(app, ["incidents", "show", "155278"])
    assert result.exit_code == 0, (result.output, result.exception)

    s2 = current_session()
    assert s2 is not None and s2.anchor_incident == 155278


def test_incidents_update_posts_comment_on_separate_endpoint(home, monkeypatch):
    """--comment must POST to the comments endpoint, not be PATCHed with the incident."""
    from xdr_cli.sessions import set_current_session, write_session_start_record, Session

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    seen: list[tuple[str, str]] = []

    async def fake_update(client, incident_id, payload):
        return {"id": incident_id, **payload}

    async def fake_comment(client, incident_id, comment):
        seen.append((incident_id, comment))
        return {"id": incident_id, "comment": comment}

    mock_client = AsyncMock()
    mock_client.close = AsyncMock()

    with (
        patch("xdr_cli.commands.incidents_cmd.AuthManager"),
        patch("xdr_cli.commands.incidents_cmd.XDRClient", return_value=mock_client),
        patch("xdr_cli.commands.incidents_cmd.update_incident", new=fake_update),
        patch("xdr_cli.commands.incidents_cmd.add_incident_comment", new=fake_comment),
    ):
        result = runner.invoke(app, [
            "incidents", "update", "155278",
            "--status", "resolved",
            "--classification", "falsePositive",
            "--determination", "notMalicious",
            "--comment", "investigated",
            "--yes",
        ])
    assert result.exit_code == 0, (result.output, result.exception)
    assert seen == [("155278", "investigated")]
    # Envelope must surface that a comment was posted.
    parsed = json.loads(result.stdout)
    assert parsed["metadata"]["comment_added"] is True


def test_incidents_update_comment_only_fetches_current_state(home, monkeypatch):
    """A comment-only update (no PATCH-shaped fields) skips the PATCH and
    returns the current incident state — operator gets useful output instead
    of an empty dict.
    """
    from xdr_cli.sessions import set_current_session, write_session_start_record, Session

    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    patch_called = False
    seen_comments: list[tuple[str, str]] = []
    fake_state = {"id": "155278", "displayName": "Probe", "status": "active"}

    async def fake_update(client, incident_id, payload):
        nonlocal patch_called
        patch_called = True
        return {"id": incident_id, **payload}

    async def fake_get(client, incident_id, expand=None):
        return fake_state

    async def fake_comment(client, incident_id, comment):
        seen_comments.append((incident_id, comment))
        return {"id": incident_id, "comment": comment}

    mock_client = AsyncMock()
    mock_client.close = AsyncMock()

    with (
        patch("xdr_cli.commands.incidents_cmd.AuthManager"),
        patch("xdr_cli.commands.incidents_cmd.XDRClient", return_value=mock_client),
        patch("xdr_cli.commands.incidents_cmd.update_incident", new=fake_update),
        patch("xdr_cli.commands.incidents_cmd.get_incident", new=fake_get),
        patch("xdr_cli.commands.incidents_cmd.add_incident_comment", new=fake_comment),
    ):
        result = runner.invoke(app, [
            "incidents", "update", "155278",
            "--comment", "drive-by note",
            "--yes",
        ])
    assert result.exit_code == 0, (result.output, result.exception)
    assert patch_called is False, "comment-only update must not PATCH"
    assert seen_comments == [("155278", "drive-by note")]
    parsed = json.loads(result.stdout)
    assert parsed["data"] == fake_state
    assert parsed["metadata"]["comment_added"] is True


def test_incidents_update_reports_partial_success_when_comment_fails(home, monkeypatch):
    from xdr_cli.exceptions import APIError

    async def fake_update(client, incident_id, payload):
        return {"id": incident_id, **payload}

    async def fake_comment(client, incident_id, comment):
        raise APIError("comment endpoint unavailable", status_code=503)

    mock_client = AsyncMock()
    mock_client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.incidents_cmd.AuthManager"),
        patch("xdr_cli.commands.incidents_cmd.XDRClient", return_value=mock_client),
        patch("xdr_cli.commands.incidents_cmd.update_incident", new=fake_update),
        patch("xdr_cli.commands.incidents_cmd.add_incident_comment", new=fake_comment),
    ):
        result = runner.invoke(app, [
            "incidents", "update", "155278", "--status", "resolved",
            "--comment", "investigated", "--yes",
        ])

    assert result.exit_code == 14
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "PARTIAL_SUCCESS"
    assert error["retryable"] is False
    assert error["original"]["fields_updated"] is True
    assert error["original"]["comment_outcome"] == "unknown"
    assert "Do not repeat the full update" in error["message"]


def test_incidents_list_help_documents_output_schema(home):
    """--help documents the output schema field names."""
    result = runner.invoke(app, ["incidents", "list", "--help"])
    assert result.exit_code == 0
    out = result.output
    for field in ("id", "displayName", "severity", "status", "classification"):
        assert field in out, f"missing schema field {field} in --help"


def test_incidents_update_lists_valid_determinations_on_bad_value(home):
    result = runner.invoke(app, [
        "incidents", "update", "155278",
        "--determination", "WRONG",
        "--yes",
    ])
    assert result.exit_code == 6
    combined = (result.output or "") + (result.stderr or "")
    assert "Invalid --determination" in combined or "invalid --determination" in combined.lower()
    # Lists at least a couple of valid values so the operator can self-correct.
    assert "notMalicious" in combined and "malware" in combined


def test_incidents_update_lists_valid_classifications_on_bad_value(home):
    result = runner.invoke(app, [
        "incidents", "update", "155278",
        "--classification", "WRONG",
        "--yes",
    ])
    assert result.exit_code == 6
    combined = (result.output or "") + (result.stderr or "")
    assert "invalid --classification" in combined.lower()
    assert "falsePositive" in combined


def test_incidents_update_lists_valid_statuses_on_bad_value(home):
    result = runner.invoke(app, [
        "incidents", "update", "155278",
        "--status", "WRONG",
        "--yes",
    ])
    assert result.exit_code == 6
    combined = (result.output or "") + (result.stderr or "")
    assert "invalid --status" in combined.lower()
    assert "resolved" in combined
