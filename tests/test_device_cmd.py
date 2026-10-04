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


def test_unrestrict_dry_run_and_confirmation_are_local(tmp_path, monkeypatch):
    from unittest.mock import Mock

    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    client = Mock(side_effect=AssertionError('No API for dry-run or missing confirmation'))
    monkeypatch.setattr('xdr_cli.commands.device_cmd._get_client', client)
    result = runner.invoke(app, [
        'device', 'unrestrict', 'dev-1', '--comment', 'recovery', '--dry-run',
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)['data']['action'] == 'unrestrict'
    result = runner.invoke(app, ['--no-interactive', 'device', 'unrestrict',
                                 'dev-1', '--comment', 'recovery'])
    assert result.exit_code == 6, result.output
    client.assert_not_called()


def test_unrestrict_requires_comment(tmp_path, monkeypatch):
    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    result = runner.invoke(app, ['device', 'unrestrict', 'dev-1', '--yes'])
    assert result.exit_code != 0
    assert '--comment' in result.output


def test_unrestrict_dispatches_and_is_audited(tmp_path, monkeypatch, caplog):
    import logging
    from unittest.mock import Mock

    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    client = AsyncMock()
    client.post.return_value = {
        'id': 'act-1', 'type': 'UnrestrictCodeExecution', 'status': 'Pending',
    }
    monkeypatch.setattr(
        'xdr_cli.commands.device_cmd._get_client', Mock(return_value=(None, client)),
    )
    args = ['device', 'unrestrict', 'dev-1', '--comment', 'recovery', '--yes']
    monkeypatch.setattr('sys.argv', ['xdr', *args])
    with caplog.at_level(logging.INFO, logger='xdr.audit'):
        result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)['metadata']['action'] == 'unrestrict'
    client.post.assert_awaited_once()
    assert client.post.call_args.args[1] == 'machines/dev-1/unrestrictCodeExecution'
    assert client.post.call_args.kwargs['json'] == {'Comment': 'recovery'}
    assert any('unrestrict' in r.message for r in caplog.records)
