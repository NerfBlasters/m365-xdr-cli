"""Collector dispatch auditing must retain identity without exposing selection or paths."""
from __future__ import annotations

import logging
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from xdr_cli.main import _TENANT_MUTATION_COMMANDS, _WRITE_COMMANDS, _redact_argv, app

CHAIN = "device live-response collect-event-logs"
R = "***REDACTED***"


@pytest.mark.parametrize("target", ["lr-1", "a" * 40, "CLR0001"])
def test_collector_redaction_keeps_target_but_not_sensitive_options(target):
    argv = ["device", "live-response", "collect-event-logs", target,
            "--log", "lr-1", "--output-dir", "a" * 40, "--comment", "CLR0001",
            "--max-total-bytes", "1000", "--min-bytes", "0"]
    assert _redact_argv(argv) == [*argv[:4], "--log", R, "--output-dir", R,
                                  "--comment", R, "--max-total-bytes", "1000",
                                  "--min-bytes", "0"]


def test_collector_dry_run_is_audited_without_client_or_output_creation(
    tmp_path, monkeypatch, caplog,
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    no_client = Mock(side_effect=AssertionError("No network allowed"))
    monkeypatch.setattr("xdr_cli.commands.live_response_cmd._get_client", no_client)
    output = tmp_path / "private-evidence"
    argv = ["--backend", "portal-cookie", "device", "live-response", "collect-event-logs",
            "lr-1", "--output-dir", str(output), "--log", "System", "--dry-run"]
    monkeypatch.setattr("sys.argv", ["xdr", *argv])
    with caplog.at_level(logging.INFO, logger="xdr.audit"):
        result = CliRunner().invoke(app, argv)
    assert result.exit_code == 0, result.output
    assert CHAIN in _WRITE_COMMANDS and CHAIN in _TENANT_MUTATION_COMMANDS
    lines = [r.getMessage() for r in caplog.records if r.name == "xdr.audit"]
    assert any(line.startswith("CMD: ") and CHAIN in line and "lr-1" in line for line in lines)
    assert all(str(output) not in line and "System" not in line for line in lines)
    assert not output.exists()
    no_client.assert_not_called()


def test_recovery_output_path_is_one_posix_argument():
    import shlex

    from xdr_cli.commands.live_response_collect_cmd import _quote_path

    value = "/private/IR O'Brien/Windows PowerShell.evtx"
    assert shlex.split("download --output " + _quote_path(value)) == [
        "download", "--output", value]


def test_recovery_output_path_quotes_powershell_apostrophes(monkeypatch):
    from types import SimpleNamespace

    from xdr_cli.commands import live_response_collect_cmd as module

    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    assert module._quote_path("C:\\IR O'Brien\\System.evtx") == "'C:\\IR O''Brien\\System.evtx'"
