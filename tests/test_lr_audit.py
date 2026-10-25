"""Live Response audit coverage and argv redaction for audit.log and sessions."""
from __future__ import annotations

import contextlib
import logging
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

import xdr_cli.main as main_module
from tests.lr_fakes import MACHINE, SESSION, FakeLRBackend
from xdr_cli.main import _TENANT_MUTATION_COMMANDS, _WRITE_COMMANDS, _redact_argv, app

runner = CliRunner()
R = "***REDACTED***"
_CHAIN = "device live-response exec"


def test_every_remote_live_response_chain_is_audited():
    from xdr_cli.commands.live_response_cmd import batch_app, library_app, live_response_app

    local = {"catalog", "sessions", "show", "status", "history", "output", "download"}
    remote = {f"device live-response {name}" for name in live_response_app.commands
              if name not in local | {"library", "batch"}}
    remote |= {f"device live-response library {name}" for name in library_app.commands
               if name in {"upload", "delete"}}
    remote |= {f"device live-response batch {name}" for name in batch_app.commands
               if name in {"submit", "cancel"}}
    assert len(remote) == 15 and remote <= _WRITE_COMMANDS
    assert {"device live-response exec", "device live-response dir"}.isdisjoint(
        _TENANT_MUTATION_COMMANDS)
    assert "device live-response run" in _TENANT_MUTATION_COMMANDS


@pytest.mark.parametrize("argv,expected", [
    (["--backend", "portal-cookie", "device", "live-response", "exec", SESSION,
      "--command", 'run s.ps1 -parameters "-k hunter2"', "--wait", "30"],
     ["--backend", "portal-cookie", "device", "live-response", "exec", SESSION,
      "--command", R, "--wait", "30"]),
    (["device", "live-response", "exec", SESSION, '--command=getfile C:\\secret.txt'],
     ["device", "live-response", "exec", SESSION, f"--command={R}"]),
    (["--rationale", "why", "device", "live-response", "getfile", SESSION,
      "C:\\Users\\a\\x.docx", "-o", "/home/a/loot.bin"],
     ["--rationale", R, "device", "live-response", "getfile", SESSION, R, "-o", R]),
    (["device", "live-response", "connect", MACHINE, "--comment", "case 12"],
     ["device", "live-response", "connect", MACHINE, "--comment", R]),
    (["device", "live-response", "status", SESSION, "42"],
     ["device", "live-response", "status", SESSION, "42"]),
])
def test_live_response_argv_keeps_only_identifiers(argv, expected):
    chain = " ".join(word for word in expected if word in {
        "device", "live-response", "exec", "getfile", "connect", "status"})
    assert _redact_argv(argv, chain) == expected


SENTINEL = "S3NTINEL"
HEX_SENTINEL = "5e" * 20


@pytest.mark.parametrize("argv,expected", [
    # Dash-prefixed values belong to the preceding option and are redacted.
    (["device", "live-response", "exec", SESSION, "--command", f"-ApiKey {SENTINEL}"],
     ["device", "live-response", "exec", SESSION, "--command", R]),
    (["device", "live-response", "exec", SESSION, f"--command=-{SENTINEL}"],
     ["device", "live-response", "exec", SESSION, f"--command={R}"]),
    # Unknown dashed tokens are dropped, and so is the token they might consume.
    (["device", "live-response", "exec", SESSION, f"-{SENTINEL}", "x"],
     ["device", "live-response", "exec", SESSION, R, R]),
    # Safe-value options keep only identifier-shaped values.
    (["device", "live-response", "status", SESSION, "7", "--wait", f"{SENTINEL}"],
     ["device", "live-response", "status", SESSION, "7", "--wait", R]),
    # Secret flags redact even identifier-shaped values.
    (["device", "live-response", "show", SESSION, "--refresh-token", "a" * 40],
     ["device", "live-response", "show", SESSION, "--refresh-token", R]),
    (["device", "live-response", "show", SESSION, f"--refresh-token={'a' * 40}"],
     ["device", "live-response", "show", SESSION, f"--refresh-token={R}"]),
])
def test_live_response_redaction_follows_click_options(argv, expected):
    assert _redact_argv(argv) == expected


def test_chain_is_resolved_from_argv_before_dispatch():
    argv = ["--backend", "portal-cookie", "--rationale", "x", "device", "live-response",
            "exec", SESSION, "--command", SENTINEL]
    assert _redact_argv(argv) == _redact_argv(argv, _CHAIN)
    assert SENTINEL not in _redact_argv(argv)


@pytest.mark.parametrize("prefix", [
    ["device", "live-response", "putfile", SESSION],
    ["device", "live-response", "run", SESSION],
    ["device", "live-response", "getfile", SESSION],
    ["device", "live-response", "library", "delete"],
])
@pytest.mark.parametrize("filename", ["a" * 40, "1234567890123456", "official", SESSION, "lr-1"])
def test_sensitive_positional_filenames_are_redacted_by_role(prefix, filename):
    assert _redact_argv([*prefix, filename]) == [*prefix, R]


def test_real_command_identifier_is_retained_by_its_argument_role():
    command_id = "00000000-0000-0000-0000-000000000003"
    argv = ["device", "live-response", "status", SESSION, command_id]
    assert _redact_argv(argv) == argv


@pytest.mark.parametrize("prefix", [
    ["--", "device", "live-response"],
    ["device", "--", "live-response"],
])
def test_group_separators_keep_child_option_semantics_and_redaction(prefix):
    argv = [*prefix, "exec", SESSION, "--command", SENTINEL]
    assert _redact_argv(argv) == [*prefix, "exec", SESSION, "--command", R]


def _persisted_text(home):
    return "\n".join(path.read_text(errors="replace")
                     for path in home.rglob("*") if path.is_file())


@pytest.mark.parametrize("args", [
    # Click usage error before the leaf hook runs (missing SESSION argument).
    ["device", "live-response", "exec", "--command", f"dir {SENTINEL}"],
    ["--", "device", "live-response", "exec", "--command", SENTINEL],
    ["device", "--", "live-response", "exec", "--command", SENTINEL],
    # Parser rejection inside the command.
    ["device", "live-response", "exec", SESSION, "--command", f"dir; {SENTINEL}"],
    # Backend capability refusal before any request.
    ["--backend", "official", "device", "live-response", "run", SESSION, f"{SENTINEL}.ps1"],
    ["--backend", "official", "device", "live-response", "run", SESSION, HEX_SENTINEL],
    # A dash-prefixed single-token value, which once passed as an "option name".
    ["device", "live-response", "exec", SESSION, "--command", f"-ApiKey {SENTINEL}",
     "--dry-run"],
    # A secret flag whose value looks like a MachineId.
    ["device", "live-response", "show", SESSION, "--refresh-token", HEX_SENTINEL],
])
def test_refused_invocations_persist_no_values(tmp_path, monkeypatch, args):
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.setattr("xdr_cli.sessions.resolve_operator_upn", lambda **kwargs: "op@x.test")
    monkeypatch.setattr("xdr_cli.commands.session_cmd.resolve_operator_upn",
                        lambda **kwargs: "op@x.test")
    monkeypatch.setattr("xdr_cli.commands.live_response_cmd._get_client",
                        Mock(side_effect=AssertionError("no client")))
    assert runner.invoke(app, ["session", "start"]).exit_code == 0
    # run() is the real entry point: it flushes the session Recorder and writes audit.log.
    monkeypatch.setattr("sys.argv", ["xdr", "--no-interactive", *args])
    with contextlib.suppress(SystemExit):
        main_module.run()
    persisted = _persisted_text(home)
    assert SENTINEL not in persisted and HEX_SENTINEL not in persisted
    # The invocation itself was recorded, with its values replaced.
    assert "live-response" in persisted and R in persisted


@pytest.mark.parametrize("args", [
    ["device", "live-respnse", "exec", SESSION, "--command", SENTINEL],
    # A later real device verb must not re-route the unknown path past the fallback.
    ["device", "live-respnse", "exec", SESSION, "--command", SENTINEL, "scan"],
    ["device", "Live-Response", "run", SESSION, f"{SENTINEL}.ps1", "show"],
])
def test_mistyped_device_paths_persist_no_values(tmp_path, monkeypatch, args):
    from xdr_cli.main import _resolve_invocation

    assert _resolve_invocation(args)[1] == "device"
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.setattr("xdr_cli.sessions.resolve_operator_upn", lambda **kwargs: "op@x.test")
    monkeypatch.setattr("xdr_cli.commands.session_cmd.resolve_operator_upn",
                        lambda **kwargs: "op@x.test")
    assert runner.invoke(app, ["session", "start"]).exit_code == 0
    monkeypatch.setattr("sys.argv", ["xdr", "--no-interactive", *args])
    with contextlib.suppress(SystemExit):
        main_module.run()
    persisted = _persisted_text(home)
    assert SENTINEL not in persisted
    assert R in persisted


def test_other_chains_keep_existing_redaction():
    argv = ["device", "timeline", "host", "--refresh-token", "tok", "--days", "2"]
    assert _redact_argv(argv, "device timeline") == [
        "device", "timeline", "host", "--refresh-token", R, "--days", "2"]
    assert _redact_argv(argv) == _redact_argv(argv, "device timeline")


def test_dispatch_and_classification_are_audited_without_values(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    backend = FakeLRBackend()
    monkeypatch.setattr("xdr_cli.commands.live_response_cmd._get_client",
                        Mock(return_value=backend))
    monkeypatch.setattr("xdr_cli.commands.live_response_cmd._POLL_SECONDS", 0)
    recorders = []
    real = main_module.Recorder

    def capture(**kwargs):
        recorder = real(**kwargs)
        recorders.append(recorder)
        return recorder

    monkeypatch.setattr(main_module, "Recorder", capture)
    args = ["--no-interactive", "--backend", "portal-cookie", "device", "live-response",
            "run", SESSION, "collect.ps1", "--parameters-stdin"]
    monkeypatch.setattr("sys.argv", ["xdr", *args])
    with caplog.at_level(logging.INFO, logger="xdr.audit"):
        result = runner.invoke(app, args, input="-Token hunter2")
    assert result.exit_code == 0, result.output
    lines = [record.getMessage() for record in caplog.records if record.name == "xdr.audit"]
    assert any(line.startswith("CMD: ") and "device live-response run" in line for line in lines)
    (classified,) = [line for line in lines if line.startswith("LR: ")]
    assert "verb=run risk=execute params=id,parameters" in classified
    assert f"target={SESSION}" in classified
    assert all("hunter2" not in line and "collect.ps1" not in line for line in lines)
    assert recorders and recorders[0].argv == [
        "--no-interactive", "--backend", "portal-cookie", "device", "live-response", "run",
        SESSION, R, "--parameters-stdin"]


def test_dry_run_is_audited_at_dispatch_but_not_classified(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    args = ["device", "live-response", "exec", SESSION, "--command", "dir C:\\x", "--dry-run"]
    monkeypatch.setattr("sys.argv", ["xdr", *args])
    with caplog.at_level(logging.INFO, logger="xdr.audit"):
        assert runner.invoke(app, args).exit_code == 0
    lines = [record.getMessage() for record in caplog.records if record.name == "xdr.audit"]
    assert [line for line in lines if line.startswith("CMD: ")] == [
        f"CMD: device live-response exec {SESSION} --command {R} --dry-run"]
    assert not [line for line in lines if line.startswith("LR: ")]

def test_mistyped_live_response_group_fails_closed():
    argv = ["device", "live-respnse", "exec", "CLR1", "--command", "run s.ps1 secret"]
    out = _redact_argv(argv)
    assert "secret" not in " ".join(out) and "run s.ps1 secret" not in out
    assert out[0] == "device"


def test_resolved_device_commands_keep_existing_redaction():
    argv = ["device", "show", "WS-01"]
    assert _redact_argv(argv) == argv


def test_session_alias_is_retained_only_in_session_argument_role():
    argv = ["device", "live-response", "getfile", "lr-1", "lr-1"]
    assert _redact_argv(argv) == [*argv[:-1], R]


def test_alias_submission_audit_contains_native_identity(tmp_path, monkeypatch, caplog):
    from dataclasses import replace

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    backend = FakeLRBackend()
    original = backend._session
    monkeypatch.setattr(backend, "_session", lambda state="running":
                        replace(original(state), alias="lr-1"))
    monkeypatch.setattr("xdr_cli.commands.live_response_cmd._get_client",
                        Mock(return_value=backend))
    args = ["--backend", "portal-cookie", "device", "live-response", "exec", "lr-1",
            "--command", "dir"]
    with caplog.at_level(logging.INFO, logger="xdr.audit"):
        result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    lines = [r.getMessage() for r in caplog.records if r.name == "xdr.audit"]
    assert any(line.startswith("LR: ") and f"target={SESSION}" in line for line in lines)
    assert any(line.startswith("LR_IDENTITY:") and f"session_id={SESSION}" in line
               and f"machine_id={MACHINE}" in line and "alias=lr-1" in line for line in lines)
