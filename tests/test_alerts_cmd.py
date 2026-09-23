"""Tests for alerts CLI commands."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()


@patch("xdr_cli.commands.alerts_cmd.AuthManager")
@patch("xdr_cli.commands.alerts_cmd.XDRClient")
def test_alerts_list_json(mock_client_cls, mock_auth_cls, tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()

    async def fake_paginate(*args, **kwargs):
        yield {"id": "al-1", "title": "Test Alert", "severity": "high"}

    mock_client.paginate = fake_paginate
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["alerts", "list"])
    assert result.exit_code == 0
    parsed, preview = [json.loads(line) for line in result.output.splitlines()]
    assert parsed["status"] == "success"
    assert parsed["rows"] == 1
    assert preview["title"] == "Test Alert"
    assert json.loads(Path(parsed["data_path"]).read_text())["id"] == "al-1"


def test_alert_show_records_graph_incident_anchor_provenance(tmp_path, monkeypatch):
    home = tmp_path / ".xdr-cli"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.setattr(
        "xdr_cli.sessions.resolve_operator_upn",
        lambda: "jane.doe@corp.com",
    )
    client = AsyncMock()
    client.close = AsyncMock()
    alert = {"id": "alert-1", "incidentId": "123", "title": "Test"}
    with (
        patch("xdr_cli.commands.alerts_cmd.AuthManager"),
        patch("xdr_cli.commands.alerts_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.alerts_cmd.get_alert",
            new=AsyncMock(return_value=alert),
        ),
    ):
        result = runner.invoke(app, ["alerts", "show", "alert-1"])

    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    metadata = json.loads(Path(receipt["meta_path"]).read_text())
    assert receipt["incident_id"] == "123"
    assert receipt["alert_id"] == "alert-1"
    assert metadata["anchors"] == {
        "incident_id": "123",
        "alert_id": "alert-1",
        "provenance": {
            "incident_id": "graph-response",
            "alert_id": "argv",
        },
    }
    marker_path = next(
        path
        for path in (home / "active_sessions").iterdir()
        if path.suffix != ".lock"
    )
    marker = json.loads(marker_path.read_text())
    assert marker["anchor_incident"] == 123
    assert marker["anchor_provenance"] == "graph-response"


def test_alert_show_rotates_automatic_session_for_different_incident(
    tmp_path, monkeypatch
):
    home = tmp_path / ".xdr-cli"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.setattr(
        "xdr_cli.sessions.resolve_operator_upn", lambda: "jane.doe@corp.com"
    )
    client = AsyncMock()
    client.close = AsyncMock()
    responses = [
        {"id": "alert-a", "incidentId": "101", "evidence": []},
        {"id": "alert-b", "incidentId": "202", "evidence": []},
    ]
    with (
        patch("xdr_cli.commands.alerts_cmd.AuthManager"),
        patch("xdr_cli.commands.alerts_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.alerts_cmd.get_alert",
            new=AsyncMock(side_effect=responses),
        ),
    ):
        first = runner.invoke(app, ["alerts", "show", "alert-a"])
        second = runner.invoke(app, ["alerts", "show", "alert-b"])

    first_receipt = json.loads(first.stdout.splitlines()[0])
    second_receipt = json.loads(second.stdout.splitlines()[0])
    assert first_receipt["session_id"] != second_receipt["session_id"]
    assert second_receipt["session_attachment"] == "automatic-rotated"
    first_records = (home / "sessions" / f"{first_receipt['session_id']}.jsonl").read_text()
    assert '"end_reason": "automatic-rotation"' in first_records


def test_alert_show_reuses_session_for_two_alerts_in_same_incident(
    tmp_path, monkeypatch
):
    home = tmp_path / ".xdr-cli"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.setattr(
        "xdr_cli.sessions.resolve_operator_upn", lambda: "jane.doe@corp.com"
    )
    client = AsyncMock()
    client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.alerts_cmd.AuthManager"),
        patch("xdr_cli.commands.alerts_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.alerts_cmd.get_alert",
            new=AsyncMock(
                side_effect=[
                    {"id": "alert-a", "incidentId": "101", "evidence": []},
                    {"id": "alert-b", "incidentId": "101", "evidence": []},
                ]
            ),
        ),
    ):
        first = runner.invoke(app, ["alerts", "show", "alert-a"])
        second = runner.invoke(app, ["alerts", "show", "alert-b"])

    assert json.loads(first.stdout.splitlines()[0])["session_id"] == json.loads(
        second.stdout.splitlines()[0]
    )["session_id"]
