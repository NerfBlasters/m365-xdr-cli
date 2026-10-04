"""Tests for domains CLI commands."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from xdr_cli.main import app

runner = CliRunner()

SAMPLE_DOMAINS = [
    {
        "id": "contoso.com",
        "authenticationType": "Managed",
        "isDefault": True,
        "isVerified": True,
    },
    {
        "id": "fabrikam.com",
        "authenticationType": "Managed",
        "isDefault": False,
        "isVerified": True,
    },
]


@patch("xdr_cli.commands.domains_cmd.AuthManager")
@patch("xdr_cli.commands.domains_cmd.XDRClient")
def test_domains_list_json(
    mock_client_cls, mock_auth_cls, tmp_path, monkeypatch,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value={"value": SAMPLE_DOMAINS})
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["domains", "list", "--source", "entra"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout.splitlines()[0])
    rows = [json.loads(line) for line in Path(parsed["data_path"]).read_text().splitlines()]
    assert len(rows) == 2
    assert rows[0]["id"] == "contoso.com"
    assert rows[0]["source"] == "entra"


@patch("xdr_cli.commands.domains_cmd.AuthManager")
@patch("xdr_cli.commands.domains_cmd.XDRClient")
def test_domains_list_empty(
    mock_client_cls, mock_auth_cls, tmp_path, monkeypatch,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    (tmp_path / ".xdr-cli").mkdir()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value={"value": []})
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    result = runner.invoke(app, ["domains", "list", "--source", "entra"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout.splitlines()[0])
    assert parsed["rows"] == 0
