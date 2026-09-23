"""Tests for device CLI commands."""

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()


@patch("xdr_cli.commands.device_cmd.AuthManager")
@patch("xdr_cli.commands.device_cmd.XDRClient")
def test_device_show_json(
    mock_client_cls, mock_auth_cls, tmp_path, monkeypatch,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value={
        "id": "dev-1",
        "computerDnsName": "WS-01",
        "healthStatus": "Active",
    })
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["device", "show", "dev-1"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["data"]["computerDnsName"] == "WS-01"


@patch("xdr_cli.commands.device_cmd.AuthManager")
@patch("xdr_cli.commands.device_cmd.XDRClient")
def test_device_isolate_dry_run(
    mock_client_cls, mock_auth_cls, tmp_path, monkeypatch,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    result = runner.invoke(app, [
        "device", "isolate", "dev-1",
        "--comment", "test", "--dry-run",
    ])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["data"]["dry_run"] is True
    assert parsed["data"]["action"] == "isolate"


@patch("xdr_cli.commands.device_cmd.AuthManager")
@patch("xdr_cli.commands.device_cmd.XDRClient")
def test_device_isolate_with_yes(
    mock_client_cls, mock_auth_cls, tmp_path, monkeypatch,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value={
        "id": "act-1", "type": "Isolate", "status": "Pending",
    })
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, [
        "device", "isolate", "dev-1",
        "--comment", "containment", "--yes",
    ])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["data"]["status"] == "Pending"
