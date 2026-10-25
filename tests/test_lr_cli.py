"""Live Response CLI: local validation, confirmation, submission and transfers."""
from __future__ import annotations

import json
import stat
from pathlib import Path
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from tests.lr_fakes import MACHINE, SESSION, FakeLRBackend, timeout
from xdr_cli.live_response.models import LRLibraryFile, LRRisk
from xdr_cli.main import app

runner = CliRunner()
_MODULE = "xdr_cli.commands.live_response_cmd"
_PORTAL = ["--no-interactive", "--backend", "portal-cookie", "device", "live-response"]


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setattr(f"{_MODULE}._POLL_SECONDS", 0)


@pytest.fixture
def fake(monkeypatch):
    backend = FakeLRBackend()
    monkeypatch.setattr(f"{_MODULE}._get_client", Mock(return_value=backend))
    return backend


@pytest.fixture
def no_client(monkeypatch):
    client = Mock(side_effect=AssertionError("no client may be created"))
    monkeypatch.setattr(f"{_MODULE}._get_client", client)
    return client


def _invoke(*args, input=None):
    return runner.invoke(app, [*_PORTAL, *args], input=input)


def _json_lines(result):
    """Decode every JSON document on stdout (compact lines or pretty envelopes)."""
    decoder, text, documents, index = json.JSONDecoder(), result.stdout, [], 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        document, index = decoder.raw_decode(text, index)
        documents.append(document)
    return documents


def test_catalog_is_local_and_filterable(no_client):
    result = _invoke("catalog", "--os", "linux", "--risk", "read")
    assert result.exit_code == 0, result.output
    receipt = _json_lines(result)[0]
    assert receipt["status"] == "success" and receipt["server_truncation_state"] == "known-complete"
    rows = [json.loads(line) for line in Path(receipt["data_path"]).read_text().splitlines()]
    names = {row["command"] for row in rows}
    assert "registry" not in names and {"dir", "findfile", "remediate"} <= names
    no_client.assert_not_called()


@pytest.mark.parametrize("args", [
    ["exec", SESSION, "--command", 'run s.ps1 -parameters "-k hunter2"', "--dry-run"],
    ["run", SESSION, "s.ps1", "--parameters-stdin", "--dry-run"],
])
def test_dry_run_needs_no_client_and_echoes_no_values(no_client, args):
    result = _invoke(*args, input="-k hunter2")
    assert result.exit_code == 0, result.output
    data = _json_lines(result)[0]["data"]
    assert data["verb"] == "run" and data["risk"] == "execute"
    assert "requires_confirmation" not in data
    assert "hunter2" not in result.output
    no_client.assert_not_called()


def test_official_backend_refuses_sessions_without_a_request(no_client):
    result = runner.invoke(app, ["--backend", "official", "device", "live-response",
                                 "exec", SESSION, "--command", "dir"])
    assert result.exit_code == 3
    assert _json_lines(result)[0]["error"]["code"] == "BACKEND_CAPABILITY_UNAVAILABLE"
    no_client.assert_not_called()


def test_read_command_submits_once_and_polls_to_completion(fake):
    result = _invoke("exec", SESSION, "--command", 'findfile "evil copy.exe"', "--wait", "30")
    assert result.exit_code == 0, result.output
    data = _json_lines(result)[0]["data"]
    assert (data["state"], data["terminal"], data["risk"]) == ("completed", True, "read")
    assert "raw" not in data and "download-token" not in result.output
    assert data["output_command"].endswith(f"output {SESSION} 7")
    assert fake.calls.count("submit") == 1
    (sent,) = fake.submitted
    assert sent.params == (("name", "evil copy.exe"),) and sent.risk is LRRisk.READ
    assert fake.closed


def test_state_changing_command_dispatches_once_without_confirmation(fake):
    result = _invoke("exec", SESSION, "--command", "getfile C:\\x.txt")
    assert result.exit_code == 0, result.output
    assert fake.calls.count("submit") == 1
    assert _json_lines(result)[0]["data"]["risk"] == "collect"


def test_rejections_happen_before_submission(fake):
    for text, code in (("dir; run x.ps1", 6), ("cls", 6), ("bogus", 6)):
        result = _invoke("exec", SESSION, "--command", text)
        assert result.exit_code == code, (text, result.output)
    assert "submit" not in fake.calls


def test_session_definitions_narrow_what_can_be_sent(fake):
    fake.excluded = frozenset({"registry"})
    result = _invoke("exec", SESSION, "--command", "registry HKLM\\x")
    assert result.exit_code == 6
    assert _json_lines(result)[0]["error"]["invalid"]["kind"] == "unknown_command"


def test_session_platform_is_enforced(fake):
    from xdr_cli.live_response.models import LRPlatform

    fake.platform = LRPlatform.LINUX
    result = _invoke("exec", SESSION, "--command", "services")
    assert result.exit_code == 6
    assert _json_lines(result)[0]["error"]["invalid"]["kind"] == "platform"


def test_help_is_answered_locally(fake):
    result = _invoke("exec", SESSION, "--command", "help getfile")
    assert result.exit_code == 0, result.output
    (row,) = _json_lines(result)[0]["data"]["commands"]
    assert row["command"] == "getfile" and row["risk"] == "collect"
    assert "submit" not in fake.calls


def test_command_from_file_and_stdin_stays_out_of_argv(fake, tmp_path):
    path = tmp_path / "cmd.txt"
    path.write_text("processes -name notepad.exe\n")
    assert _invoke("exec", SESSION, "--command-file", str(path)).exit_code == 0
    assert _invoke("exec", SESSION, "--command-stdin", input="dir C:\\\n").exit_code == 0
    assert [c.console_line for c in fake.submitted] == [
        "processes -name notepad.exe", "dir C:\\"]
    both = _invoke("exec", SESSION, "--command", "dir", "--command-stdin", input="dir")
    assert both.exit_code == 6


def test_redirect_saves_rendered_output_privately(fake, tmp_path):
    fake.output = [{"line": "PID 4 System"}, {"Name": "x", "Pid": 5}]
    out = tmp_path / "procs.txt"
    result = _invoke("exec", SESSION, "--command", f'processes > "{out}"', "--wait", "5")
    assert result.exit_code == 0, result.output
    local = _json_lines(result)[0]["data"]["local_output"]
    assert out.read_text() == 'PID 4 System\n{"Name":"x","Pid":5}\n'
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert local["bytes"] == out.stat().st_size
    assert fake.submitted[0].output_to == str(out)
    again = _invoke("exec", SESSION, "--command", f'processes > "{out}"', "--wait", "5")
    assert again.exit_code == 13
    assert fake.calls.count("submit") == 1


def test_background_flag_reaches_the_backend(fake):
    result = _invoke("getfile", SESSION, "C:\\big.bin", "--background", "--wait", "0")
    assert result.exit_code == 0, result.output
    assert fake.submitted[0].background is True
    assert _json_lines(result)[0]["data"]["state"] == "running"


def test_getfile_downloads_after_completion(fake, tmp_path, monkeypatch):
    captured = {}

    async def download(transfer, dest, *, force, max_bytes, timeout):
        captured.update(dest=dest, force=force)
        return {"path": str(dest), "bytes": 3, "sha256": "0" * 64}

    monkeypatch.setattr(f"{_MODULE}.download_transfer", download)
    out = tmp_path / "sample.bin"
    result = _invoke("getfile", SESSION, "C:\\Temp\\sample.bin", "--output", str(out))
    assert result.exit_code == 0, result.output
    (record,) = _json_lines(result)
    state = receipt = record["data"]
    assert state["has_download"] is True and receipt["command_id"] == "7"
    assert captured == {"dest": out, "force": False}
    assert fake.submitted[0].console_line == "getfile C:\\Temp\\sample.bin"


@pytest.mark.parametrize("state,errors,reason", [
    ("running", 0, "not_terminal"),
    ("failed", 0, "failed"),
    ("completed", 1, "completed_with_errors"),
])
def test_getfile_does_not_download_an_unsuccessful_command(fake, tmp_path, state, errors, reason):
    fake.states, fake.error_count = [state], errors
    result = _invoke("getfile", SESSION, "C:\\a", "--output", str(tmp_path / "a"),
                     "--wait", "0")
    assert result.exit_code == 0
    assert "transfer" not in fake.calls
    (record,) = _json_lines(result)
    assert record["data"]["state"] == state
    assert record["data"]["downloaded"] is False
    assert record["data"]["download_skipped_reason"] == reason


def test_completed_with_errors_neither_downloads_nor_saves(fake, tmp_path):
    fake.error_count = 1
    result = _invoke("getfile", SESSION, "C:\\empty.txt", "--output", str(tmp_path / "e"),
                     "--wait", "5")
    assert result.exit_code == 0, result.output
    data = _json_lines(result)[0]["data"]
    assert (data["state"], data["error_count"]) == ("completed", 1)
    assert "transfer" not in fake.calls and not (tmp_path / "e").exists()
    out = tmp_path / "procs.txt"
    saved = _invoke("exec", SESSION, "--command", f'processes > "{out}"', "--wait", "5")
    assert _json_lines(saved)[0]["data"]["local_output"] is None
    assert not out.exists()


def test_unknown_error_count_still_allows_download(fake, tmp_path, monkeypatch):
    async def download(transfer, dest, **kwargs):
        return {"path": str(dest), "bytes": 1, "sha256": "0" * 64}

    monkeypatch.setattr(f"{_MODULE}.download_transfer", download)
    fake.error_count = None
    result = _invoke("getfile", SESSION, "C:\\a", "--output", str(tmp_path / "a"))
    assert result.exit_code == 0, result.output
    assert "transfer" in fake.calls
    (record,) = _json_lines(result)
    assert record["data"]["state"] == "completed"
    assert record["data"]["bytes"] == 1
    assert record["data"]["downloaded"] is True


def test_getfile_without_destination_emits_one_state_and_does_not_download(fake):
    result = _invoke("getfile", SESSION, "C:\\a")
    assert result.exit_code == 0, result.output
    (record,) = _json_lines(result)
    assert record["data"]["state"] == "completed"
    assert "transfer" not in fake.calls


def test_submit_timeout_is_not_replayed(fake):
    fake.submit_error = timeout()
    result = _invoke("putfile", SESSION, "tool.ps1", "--overwrite")
    assert result.exit_code == 10
    assert fake.calls.count("submit") == 1
    assert fake.submitted[0].flags == {"overwrite"}


def test_run_reads_parameters_from_stdin(fake):
    result = _invoke("run", SESSION, "collect.ps1", "--parameters-stdin",
                     input="-Days 2\n")
    assert result.exit_code == 0, result.output
    assert fake.submitted[0].params == (("id", "collect.ps1"), ("parameters", "-Days 2"))
    forbidden = _invoke("run", SESSION, "c.ps1", "--parameters-stdin", input="a;b")
    assert forbidden.exit_code == 6
    assert len(fake.submitted) == 1


def test_output_keeps_transcripts_private_without_stdout_preview(fake):
    fake.output = [{"line": "PRIVATE_TRANSCRIPT_SENTINEL"}]
    result = _invoke("output", SESSION, "7")
    assert result.exit_code == 0, result.output
    (receipt,) = _json_lines(result)
    assert receipt["context"]["shown"] == 0
    assert "PRIVATE_TRANSCRIPT_SENTINEL" not in result.output
    assert "PRIVATE_TRANSCRIPT_SENTINEL" in Path(receipt["data_path"]).read_text()


def test_session_lifecycle_records(fake):
    connect = _invoke("connect", MACHINE)
    assert connect.exit_code == 0, connect.output
    data = _json_lines(connect)[0]["data"]
    assert data["session_id"] == SESSION and "raw" not in data
    assert data["disconnect_command"].endswith(f"disconnect {SESSION}")
    assert fake.calls.count("open") == 1
    closed = _invoke("disconnect", SESSION)
    assert _json_lines(closed)[0]["data"]["state"] == "terminatedByUser"
    cancel = _invoke("cancel", SESSION, "7")
    assert _json_lines(cancel)[0]["data"]["device_outcome"] == "unknown"
    assert fake.calls.count("open") == 1


def test_connect_wait_polls_a_pending_session(fake, monkeypatch):
    from tests.lr_fakes import FakeLRBackend

    states = iter(["pending", "running"])
    monkeypatch.setattr(FakeLRBackend, "lr_open_session", _session_with("pending"))
    monkeypatch.setattr(FakeLRBackend, "lr_get_session", _session_with(states))
    result = _invoke("connect", MACHINE, "--wait", "10")
    assert _json_lines(result)[0]["data"]["state"] == "running"


def _session_with(states):
    async def read(self, *args, **kwargs):
        state = states if isinstance(states, str) else next(states)
        return self._session(state)
    return read


def test_connect_and_disconnect_dry_runs_are_local(no_client):
    assert _invoke("connect", MACHINE, "--dry-run").exit_code == 0
    assert _invoke("disconnect", SESSION, "--dry-run").exit_code == 0


def test_history_is_an_artifact(fake):
    history = _json_lines(_invoke("history", SESSION))[0]
    assert history["rows"] == 1


def test_library_lifecycle(fake, tmp_path):
    script = tmp_path / "collect logs.ps1"
    script.write_text("Get-Date")
    dry = _invoke("library", "upload", "--from-file", str(script), "--dry-run")
    assert _json_lines(dry)[0]["data"]["name"] == "collect logs.ps1"
    assert "upload" not in fake.calls
    uploaded = _invoke("library", "upload", "--from-file", str(script),
                       "--parameters-description", "-Days N")
    assert _json_lines(uploaded)[0]["data"]["has_parameters"] is True
    fake.library = [LRLibraryFile("collect logs.ps1", size=8)]
    assert _json_lines(_invoke("library", "show", "collect logs.ps1"))[0]["data"]["size"] == 8
    assert _invoke("library", "show", "missing.ps1").exit_code == 8
    assert _invoke("library", "delete", "../x").exit_code == 6
    assert _invoke("library", "delete", "collect logs.ps1").exit_code == 0
    assert fake.calls.count("delete") == 1


def _official(*args, input=None):
    return runner.invoke(app, ["--no-interactive", "--backend", "official", "device",
                               "live-response", "batch", *args], input=input)


def test_batch_submits_official_commands_in_order(fake, tmp_path):
    commands = tmp_path / "batch.txt"
    commands.write_text('putfile tool.ps1\nrun tool.ps1 -parameters "-Days 2"\ngetfile C:\\o.zip\n')
    result = _official("submit", MACHINE, "--command-file", str(commands), "--comment", "IR-1")
    assert result.exit_code == 0, result.output
    data = _json_lines(result)[0]["data"]
    assert data["command_id"] == "act-1" and data["status_command"].endswith("act-1 --wait 60")
    assert [c.verb for c in fake.submitted] == ["putfile", "run", "getfile"]
    assert fake.calls.count("submit_batch") == 1


def test_batch_rejects_session_only_commands_and_needs_official(fake):
    result = _official("submit", MACHINE, "--command", "dir", "--comment", "x")
    assert result.exit_code == 6
    assert _json_lines(result)[0]["error"]["invalid"]["kind"] == "batch_unsupported"
    portal = runner.invoke(app, ["--backend", "portal-cookie", "device", "live-response",
                                 "batch", "submit", MACHINE, "--command", "getfile C:\\x",
                                 "--comment", "x"])
    assert portal.exit_code == 3
    assert "submit_batch" not in fake.calls
    result = _official("submit", MACHINE, "--command", "getfile C:\\x", "--comment", "x")
    assert result.exit_code == 0, result.output
    assert fake.calls.count("submit_batch") == 1


def test_batch_dry_run_is_value_free(no_client):
    result = _official("submit", MACHINE, "--command", 'run s.ps1 -parameters "-k hunter2"',
                       "--comment", "x", "--dry-run")
    assert result.exit_code == 0
    assert _json_lines(result)[0]["data"]["commands"][0]["risk"] == "execute"
    assert "hunter2" not in result.output


# --- Failures after the service accepted a submission (adversarial review M1) ---


def _accepted_error(result, accepted_id):
    error = _json_lines(result)[-1]["error"]
    assert error["retryable"] is False
    assert accepted_id in error["message"] and "Do not resubmit" in error["message"]
    first = error["suggestions"][0]
    assert first["reason"] == "submission_accepted" and first["accepted_id"] == accepted_id
    assert error["help_command"] == first["commands"][0]
    return error


@pytest.mark.parametrize("failure", ["network", "rate-limit"])
def test_poll_failure_after_acceptance_is_not_retryable(fake, monkeypatch, failure):
    from xdr_cli.exceptions import NetworkError, RateLimitError

    async def broken(self, session_id, command_id):
        error = NetworkError("lost") if failure == "network" else RateLimitError("slow")
        error.retryable = True
        raise error

    monkeypatch.setattr(FakeLRBackend, "lr_get_command", broken)
    result = _invoke("run", SESSION, "fix.ps1", "--wait", "30")
    assert result.exit_code == (11 if failure == "network" else 9)
    error = _accepted_error(result, "7")
    assert error["help_command"] == (
        f"xdr --backend portal-cookie device live-response status {SESSION} 7 --wait 60")
    assert fake.calls.count("submit") == 1


def test_local_output_failure_after_acceptance_names_the_command(fake, tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(f"{_MODULE}._write_local_output", broken)
    result = _invoke("exec", SESSION, "--command", f"processes > {tmp_path / 'p.txt'}",
                     "--wait", "5")
    assert result.exit_code == 12
    _accepted_error(result, "7")


def test_getfile_download_failure_has_one_error_and_safe_status_recovery(fake, tmp_path,
                                                                      monkeypatch):
    from xdr_cli.exceptions import NetworkError

    async def broken(*args, **kwargs):
        raise NetworkError("reset")

    monkeypatch.setattr(f"{_MODULE}.download_transfer", broken)
    result = _invoke("getfile", SESSION, "C:\\a", "--output", str(tmp_path / "a"))
    assert result.exit_code == 11
    (record,) = _json_lines(result)
    assert record["status"] == "error"
    error = _accepted_error(result, "7")
    assert error["help_command"].startswith(
        f"xdr --backend portal-cookie device live-response status {SESSION} 7")
    assert "PATH" not in error["help_command"]
    assert "completed" in error["message"]
    assert fake.calls.count("submit") == 1


def test_getfile_upload_only_refuses_a_download_destination_without_client(no_client, tmp_path):
    result = _invoke("getfile", SESSION, "C:\\a", "--upload-only", "--output", str(tmp_path / "a"))
    assert result.exit_code == 6
    assert _json_lines(result)[0]["error"]["invalid"]["kind"] == "conflicting_options"
    no_client.assert_not_called()


def test_connect_wait_failure_keeps_the_session_id(fake, monkeypatch):
    from xdr_cli.exceptions import NetworkError

    async def broken(self, session_id):
        raise NetworkError("lost")

    monkeypatch.setattr(FakeLRBackend, "lr_open_session", _session_with("pending"))
    monkeypatch.setattr(FakeLRBackend, "lr_get_session", broken)
    result = _invoke("connect", MACHINE, "--wait", "10")
    error = _accepted_error(result, SESSION)
    assert error["suggestions"][0]["commands"][1].endswith(f"disconnect {SESSION}")


def test_batch_wait_failure_keeps_the_action_id(fake, monkeypatch):
    from xdr_cli.exceptions import NetworkError

    async def broken(self, session_id, command_id):
        raise NetworkError("lost")

    monkeypatch.setattr(FakeLRBackend, "lr_get_command", broken)
    result = _official("submit", MACHINE, "--command", "getfile C:\\x", "--comment", "IR",
                       "--wait", "10")
    error = _accepted_error(result, "act-1")
    assert error["help_command"] == (
        "xdr --backend official device live-response batch status act-1 --wait 60")


# --- Remaining review findings ---


def test_batch_output_has_no_stdout_previews(fake):
    fake.output = [{"command_index": 0, "errors": [{"message": "SYNTHETIC_SCRIPT_TOKEN"}]}]
    result = _official("output", "act-1")
    assert result.exit_code == 0, result.output
    assert "SYNTHETIC_SCRIPT_TOKEN" not in result.stdout
    (receipt,) = _json_lines(result)
    assert receipt["context"]["shown"] == 0
    saved = Path(receipt["data_path"]).read_text().splitlines()
    assert [json.loads(line) for line in saved] == fake.output


def test_cancel_dry_runs_are_local(no_client):
    guid = "0f8fad5b-d9cb-469f-a165-70867728950e"
    assert _invoke("cancel", SESSION, guid, "--dry-run").exit_code == 0
    assert _official("cancel", guid, "--dry-run").exit_code == 0
    # Dry-runs validate identifier shapes locally, still without a client.
    assert _invoke("cancel", SESSION, "7", "--dry-run").exit_code == 6
    assert _official("cancel", "act-1", "--dry-run").exit_code == 6


def test_command_file_byte_order_mark_is_ignored(fake, tmp_path):
    path = tmp_path / "cmd.txt"
    path.write_bytes(b"\xef\xbb\xbfdir C:\\\r\n")
    assert _invoke("exec", SESSION, "--command-file", str(path)).exit_code == 0
    assert fake.submitted[0].console_line == "dir C:\\"


def test_getfile_unknown_native_state_has_distinct_skip_reason(fake, monkeypatch, tmp_path):
    from dataclasses import replace
    original = fake._state
    monkeypatch.setattr(fake, "_state", lambda index: replace(original(index), terminal=None))
    result = _invoke("getfile", SESSION, "C:\\a", "--output", str(tmp_path / "a"), "--wait", "0")
    assert result.exit_code == 0, result.output
    assert _json_lines(result)[0]["data"]["download_skipped_reason"] == "state_unknown"
    assert "transfer" not in fake.calls
