"""Event-log collection over Live Response: selection, budgets, never-replay and privacy."""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from click.testing import CliRunner

from tests.lr_fakes import MACHINE, SESSION, definitions
from xdr_cli.commands import live_response_cmd
from xdr_cli.commands import live_response_collect_cmd as module
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    NetworkError,
    RateLimitError,
    TimeoutError,
    UsageError,
)
from xdr_cli.live_response import event_logs as evtx
from xdr_cli.live_response.models import LRCommandState, LRPlatform, LRSession
from xdr_cli.live_response.transfer import SignedTransfer
from xdr_cli.main import app
from xdr_cli.results import tenant_fingerprint

runner = CliRunner()
_PORTAL = ["--no-interactive", "--backend", "portal-cookie", "device", "live-response"]
TENANT = "synthetic-tenant"
# Every channel file is pre-allocated at this size, yet it can still hold records.
PREALLOCATED = 69632


def _listing(**sizes: int) -> list[dict]:
    entries = [{"path": ".", "size": 0, "isDirectory": True}]
    entries += [{"path": f"{name}.evtx", "size": size, "isDirectory": False}
                for name, size in sizes.items()]
    return [{"record_type": "live-response-output", "command_id": "dir", "output_index": 0,
             "data_type": "object", "data": entries}]


class Fake:
    """Scripted backend: per-file submit, poll and download outcomes."""

    def __init__(self, listing, *, platform=LRPlatform.WINDOWS):
        self.listing, self.platform = listing, platform
        self.submitted: list = []
        self.outcomes: dict[str, object] = {}   # basename -> exception or native state
        self.content: dict[str, bytes] = {}     # basename -> downloaded bytes
        self.statuses: dict[str, int] = {}      # basename -> download HTTP status
        self.before_download = None
        self.opened = self.closed = False
        self.close_error: BaseException | None = None
        self.close_state = "terminatedByUser"
        self.close_calls = 0
        self.open_poll_error: Exception | None = None
        self.by_id: dict[str, str] = {}

    def _session(self, state="running"):
        return LRSession(SESSION, MACHINE, state, self.platform, alias="lr-1")

    async def lr_open_session(self, machine_id, *, comment):
        self.opened = True
        return self._session("pending" if self.open_poll_error else "running")

    async def lr_get_session(self, session_id):
        if self.opened and self.open_poll_error:
            raise self.open_poll_error
        return self._session()

    async def lr_close_session(self, session_id):
        self.close_calls += 1
        if self.close_error:
            raise self.close_error
        self.closed = True
        return self._session(self.close_state)

    async def lr_command_definitions(self, session_id):
        return definitions()

    async def lr_submit(self, session_id, parsed):
        self.submitted.append(parsed)
        if parsed.verb == "dir":
            assert dict(parsed.params) == {"path": evtx.LOGS_DIR, "output": "json"}
            return self._state("dir", "completed")
        name = parsed.param("path").rsplit("\\", 1)[-1]
        outcome = self.outcomes.get(name, "completed")
        if isinstance(outcome, BaseException):
            raise outcome
        command_id = f"0000000{len(self.submitted)}-0000-0000-0000-000000000000"
        self.by_id[command_id] = name
        return self._state(command_id, "running")

    def _state(self, command_id, native):
        terminal = {"completed": True, "failed": True, "running": False}.get(native)
        return LRCommandState(command_id, MACHINE, "getfile", native, SESSION, terminal=terminal,
                              error_count=0, session_alias="lr-1")

    async def lr_get_command(self, session_id, command_id):
        if command_id == "dir":
            return self._state("dir", "completed")
        outcome = self.outcomes.get(self.by_id[command_id], "completed")
        return self._state(command_id, outcome if isinstance(outcome, str) else "completed")

    async def lr_iter_output(self, session_id, command_id):
        for row in self.listing:
            yield row

    async def lr_result_transfer(self, session_id, command_id):
        name = self.by_id[command_id]
        body = self.content.get(name, b"ElfFile\x00" + name.encode())
        if self.before_download:
            self.before_download(name)

        @asynccontextmanager
        async def stream():
            yield httpx.Response(self.statuses.get(name, 200), content=body)

        return SignedTransfer(_stream_factory=stream)

    async def close(self):
        pass

    def fetched(self) -> list[str]:
        return [p.param("path").rsplit("\\", 1)[-1] for p in self.submitted if p.verb == "getfile"]


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text(f'tenant_id = "{TENANT}"\n')
    (home / "config.toml").chmod(0o600)
    monkeypatch.setattr(live_response_cmd, "_POLL_SECONDS", 0)
    monkeypatch.setattr(module, "_POLL_SECONDS", 0)
    # Until device_cmd registers it, mount the command for these tests.
    registered = "collect-event-logs" in live_response_cmd.live_response_app.commands
    live_response_cmd.live_response_app.add_command(module.collect_event_logs)
    yield
    if not registered:
        live_response_cmd.live_response_app.commands.pop("collect-event-logs", None)


@pytest.fixture
def out(tmp_path) -> Path:
    return tmp_path / "logs"


def _use(monkeypatch, fake):
    monkeypatch.setattr(live_response_cmd, "_get_client", Mock(return_value=fake))
    return fake


def _invoke(*args):
    return runner.invoke(app, [*_PORTAL, "collect-event-logs", *args])


def _documents(result):
    """Every JSON document on stdout (compact lines or pretty envelopes)."""
    decoder, text, documents, index = json.JSONDecoder(), result.stdout, [], 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        document, index = decoder.raw_decode(text, index)
        documents.append(document)
    return documents


def _manifest(out: Path) -> dict:
    return json.loads((out / "manifest.json").read_text())


def _rows(out: Path) -> dict[str, dict]:
    return {row["log"]: row for row in _manifest(out)["rows"]}


def test_default_set_fetches_present_logs_and_reports_absent_ones(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=5000, System=4000, Other=9000)))
    result = _invoke("lr-1", "--output-dir", str(out))
    assert result.exit_code == 0, result.output
    assert fake.fetched() == ["Security.evtx", "System.evtx"]
    assert fake.submitted[1].param("path") == f"{evtx.LOGS_DIR}\\Security.evtx"
    assert (out / "Security.evtx").read_bytes() == b"ElfFile\x00Security.evtx"
    assert oct(out.stat().st_mode & 0o777) == "0o700"
    rows = _rows(out)
    assert rows["Security"]["status"] == "completed" and rows["Security"]["sha256"]
    assert rows["Security"]["recovery"] is None
    assert rows["Application"]["status"] == "absent" and "Other" not in rows
    receipt = _documents(result)[0]
    assert receipt["context"]["counts"] == {"completed": 2, "absent": 13}
    assert receipt["context"]["session_opened_here"] is False
    assert not fake.opened and not fake.closed


def test_manifest_binds_provenance(monkeypatch, out):
    _use(monkeypatch, Fake(_listing(Security=10)))
    assert _invoke("lr-1", "--output-dir", str(out), "--log", "Security").exit_code == 0
    manifest = _manifest(out)
    assert manifest["tenant_fingerprint"] == tenant_fingerprint(TENANT)
    assert (manifest["backend"], manifest["session_id"], manifest["session_alias"],
            manifest["machine_id"], manifest["session_opened_here"]) == (
        "portal-cookie", SESSION, "lr-1", MACHINE, False)
    assert TENANT not in (out / "manifest.json").read_text()


def test_small_logs_are_fetched_by_default_and_min_bytes_skips_visibly(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=5000, Quiet=PREALLOCATED)))
    assert _invoke("lr-1", "--output-dir", str(out), "--all").exit_code == 0
    assert fake.fetched() == ["Quiet.evtx", "Security.evtx"]
    fake = _use(monkeypatch, Fake(_listing(Security=500000, Quiet=PREALLOCATED)))
    two = out.parent / "two"
    assert _invoke("lr-1", "--output-dir", str(two), "--all",
                   "--min-bytes", "70000").exit_code == 0
    assert fake.fetched() == ["Security.evtx"]
    assert _rows(two)["Quiet"]["status"] == "skipped-min-bytes"


def test_explicit_logs_accept_slash_names(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(**{"Microsoft-Windows-PowerShell%4Operational": 9})))
    result = _invoke("lr-1", "--output-dir", str(out),
                     "--log", "Microsoft-Windows-PowerShell/Operational")
    assert result.exit_code == 0, result.output
    assert fake.fetched() == ["Microsoft-Windows-PowerShell%4Operational.evtx"]


def test_device_target_opens_and_closes_its_own_session(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    result = _invoke(MACHINE, "--output-dir", str(out), "--log", "Security")
    assert result.exit_code == 0, result.output
    assert fake.opened and fake.closed
    context = _documents(result)[0]["context"]
    assert context["session_opened_here"] is True and context["session_closed"] is True
    assert _manifest(out)["session_opened_here"] is True


def test_owned_session_is_closed_when_polling_the_open_fails(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    fake.open_poll_error = NetworkError("Live Response request failed.")
    result = _invoke(MACHINE, "--output-dir", str(out))
    assert result.exit_code == 11, result.output
    assert fake.closed
    error = _documents(result)[-1]["error"]
    assert error["retryable"] is False and "was accepted" in error["message"]


def test_failed_close_keeps_the_original_error_and_points_to_read_only_show(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10), platform=LRPlatform.LINUX))
    fake.close_error = NetworkError("Live Response request failed.")
    result = _invoke(MACHINE, "--output-dir", str(out))
    assert result.exit_code == 6, result.output  # the platform refusal, not the close
    error = _documents(result)[-1]["error"]
    hint = [s for s in error["suggestions"] if s["reason"] == "owned_session_not_closed"]
    # The close outcome is uncertain, so recovery inspects; it never repeats the close.
    assert hint and hint[0]["commands"] == [f"{module._PORTAL_PREFIX} show lr-1"]
    assert "do not repeat the close" in " ".join(result.stderr.split())
    assert fake.close_calls == 1


@pytest.mark.parametrize(("failure", "exit_code"), [
    (KeyboardInterrupt(), 130),
    (RuntimeError("unexpected"), 14),
])
def test_owned_session_gets_one_close_attempt_on_interruption_or_bugs(
    monkeypatch, out, failure, exit_code,
):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    fake.outcomes = {"Security.evtx": failure}
    result = _invoke(MACHINE, "--output-dir", str(out), "--log", "Security")
    assert result.exit_code == exit_code, result.output
    # Cleanup ran exactly once, and the original interruption or error still won.
    assert fake.closed and fake.close_calls == 1


def test_interrupted_close_does_not_hide_the_primary_error(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10), platform=LRPlatform.LINUX))
    fake.close_error = KeyboardInterrupt()
    result = _invoke(MACHINE, "--output-dir", str(out))
    assert result.exit_code == 6, result.output
    assert f"{module._PORTAL_PREFIX} show lr-1" in " ".join(result.stderr.split())
    assert fake.close_calls == 1


@pytest.mark.parametrize("returned", ["running", "pending", "state-9"])
def test_close_that_leaves_the_session_running_or_unknown_is_unconfirmed(
    monkeypatch, out, returned,
):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    fake.close_state = returned
    result = _invoke(MACHINE, "--output-dir", str(out), "--log", "Security")
    assert result.exit_code == 14, result.output
    context = _documents(result)[0]["context"]
    assert context["session_closed"] is False
    assert context["cleanup_recovery_command"] == f"{module._PORTAL_PREFIX} show lr-1"
    assert (out / "Security.evtx").exists()
    assert fake.close_calls == 1  # never a repeated close request
    assert "do not repeat the close" in " ".join(result.stderr.split())


def test_confirmed_close_has_no_cleanup_recovery(monkeypatch, out):
    _use(monkeypatch, Fake(_listing(Security=10)))
    result = _invoke(MACHINE, "--output-dir", str(out), "--log", "Security")
    assert result.exit_code == 0, result.output
    assert _documents(result)[0]["context"]["cleanup_recovery_command"] is None


def test_a_reused_session_is_left_open(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    fake.close_error = AssertionError("a reused session must not be closed")
    assert _invoke("lr-1", "--output-dir", str(out), "--log", "Security").exit_code == 0
    assert not fake.closed


@pytest.mark.parametrize("stage", ["download-link", "stream"])
def test_a_transfer_failure_stops_the_run(monkeypatch, out, stage):
    fake = _use(monkeypatch, Fake(_listing(Security=10, System=10)))
    if stage == "stream":
        fake.statuses = {"Security.evtx": 500}  # the stream itself fails
    else:
        fake.before_download = lambda name: (_ for _ in ()).throw(
            APIError("Live Response downloadable result could not be prepared."))
    result = _invoke("lr-1", "--output-dir", str(out))
    assert result.exit_code == 14, result.output
    # A failed stream's partial bytes cannot be accounted, so nothing else is submitted.
    assert fake.fetched() == ["Security.evtx"]
    rows = _rows(out)
    assert rows["Security"]["status"] == "accepted" and rows["Security"]["recovery"]
    assert rows["System"]["status"] == "planned"
    assert _documents(result)[0]["context"]["stopped"] == "API_ERROR"


def test_zero_remaining_budget_stops_before_another_submit(monkeypatch, out):
    # Security uses the whole budget; System is listed at 0 bytes but is never submitted.
    fake = _use(monkeypatch, Fake(_listing(Security=10, System=0)))
    fake.content = {"Security.evtx": b"x" * 600}
    result = _invoke("lr-1", "--output-dir", str(out), "--max-total-bytes", "600")
    assert result.exit_code == 14, result.output
    assert fake.fetched() == ["Security.evtx"]
    rows = _rows(out)
    assert rows["Security"]["status"] == "completed" and rows["Security"]["bytes"] == 600
    assert rows["System"]["status"] == "planned"
    assert rows["System"]["error"] == "total-budget-exhausted"
    assert _documents(result)[0]["context"]["stopped"] == "total-budget-exhausted"


def test_actual_bytes_budget_is_enforced_while_downloading(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10, System=10, Application=10)))
    # Logs grew after listing: each download is 600 bytes against a 1000-byte budget.
    fake.content = {name: b"x" * 600 for name in ("Security.evtx", "System.evtx",
                                                     "Application.evtx")}
    result = _invoke("lr-1", "--output-dir", str(out), "--max-total-bytes", "1000")
    assert result.exit_code == 14, result.output
    rows = _rows(out)
    completed = [r for r in rows.values() if r["status"] == "completed"]
    assert len(completed) == 1 and completed[0]["bytes"] == 600
    stopped = [r for r in rows.values() if r["error"] == "total-budget-exhausted"]
    assert len(stopped) == 1 and stopped[0]["status"] == "accepted"
    assert stopped[0]["recovery"] and stopped[0]["command_id"]
    assert len(fake.fetched()) == 2  # nothing submitted after the budget stopped the run
    assert _documents(result)[0]["context"]["stopped"] == "total-budget-exhausted"
    assert sum(p.stat().st_size for p in out.glob("*.evtx")) <= 1000


def test_listed_total_cap_is_checked_before_any_getfile(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=600, System=600)))
    result = _invoke("lr-1", "--output-dir", str(out), "--max-total-bytes", "1000")
    assert result.exit_code == 6, result.output
    assert fake.fetched() == []


def test_a_file_that_appears_concurrently_is_never_replaced(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    fake.before_download = lambda name: (out / name).write_bytes(b"someone else's")
    result = _invoke("lr-1", "--output-dir", str(out), "--log", "Security")
    assert result.exit_code == 14, result.output
    assert (out / "Security.evtx").read_bytes() == b"someone else's"
    row = _rows(out)["Security"]
    assert row["status"] == "accepted" and row["error"] == "STATE_CONFLICT"


def test_unknown_and_rejected_submissions_are_recorded_and_systemic_stops(monkeypatch, out):
    unknown = TimeoutError("Live Response request timed out.")
    unknown.error_code = "OUTCOME_UNKNOWN"
    fake = _use(monkeypatch, Fake(_listing(Security=10, System=10, Application=10)))
    fake.outcomes = {"Security.evtx": APIError("Rejected."), "System.evtx": unknown}
    result = _invoke("lr-1", "--output-dir", str(out))
    assert result.exit_code == 14, result.output
    rows = _rows(out)
    assert rows["Security"]["status"] == "failed"
    assert rows["System"]["status"] == "outcome-unknown"  # never resent
    assert rows["Application"]["status"] == "planned"  # timeout is systemic: stopped
    assert fake.fetched() == ["Security.evtx", "System.evtx"]


def test_rate_limit_keeps_retry_after(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10, System=10)))
    fake.outcomes = {"Security.evtx": RateLimitError(30)}
    result = _invoke("lr-1", "--output-dir", str(out))
    assert result.exit_code == 14, result.output
    assert _documents(result)[-1]["error"]["retry_after_seconds"] == 30
    assert fake.fetched() == ["Security.evtx"]


def test_unterminated_job_keeps_its_id_and_recovery(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    fake.outcomes = {"Security.evtx": "running"}
    result = _invoke("lr-1", "--output-dir", str(out), "--log", "Security", "--wait", "1")
    assert result.exit_code == 14, result.output
    row = _rows(out)["Security"]
    assert row["status"] == "accepted" and row["error"] == "not_terminal"
    status, download = row["recovery"]
    assert status.startswith(f"{module._PORTAL_PREFIX} status lr-1 {row['command_id']}")
    assert f"--output {module._quote_path(out.resolve() / 'Security.evtx')} " in download
    assert download.endswith(f"--max-bytes {module.DEFAULT_MAX_BYTES}")


def test_manifest_save_failure_after_acceptance_keeps_the_command_id(monkeypatch, out):
    fake = _use(monkeypatch, Fake(_listing(Security=10, System=10)))
    saves = {"n": 0}
    original = evtx.Manifest.save

    def flaky(self):
        saves["n"] += 1
        if saves["n"] >= 3:  # 1: initial, 2: before submit, 3: right after acceptance
            raise ArtifactError("Could not save the event-log collection manifest.")
        original(self)

    monkeypatch.setattr(evtx.Manifest, "save", flaky)
    result = _invoke("lr-1", "--output-dir", str(out))
    assert result.exit_code == 14, result.output
    receipt = _documents(result)[0]
    rows = {row["log"]: row for row in
            map(json.loads, Path(receipt["data_path"]).read_text().splitlines())}
    assert rows["Security"]["command_id"] and rows["Security"]["recovery"]
    assert receipt["context"]["stopped"] in ("ARTIFACT_WRITE_FAILED", "manifest-unwritable")
    assert fake.fetched() == ["Security.evtx"]  # the broken manifest stopped the run


def test_audit_records_native_identity_for_every_submission(monkeypatch, out, caplog):
    _use(monkeypatch, Fake(_listing(Security=10)))
    with caplog.at_level(logging.INFO, logger="xdr.audit"):
        assert _invoke("lr-1", "--output-dir", str(out), "--log", "Security").exit_code == 0
    lines = [r.getMessage() for r in caplog.records if r.name == "xdr.audit"]
    lr = [line for line in lines if line.startswith("LR: ")]
    identity = [line for line in lines if line.startswith("LR_IDENTITY: ")]
    assert len(lr) == 2 and all(f"target={SESSION}" in line for line in lr)
    assert len(identity) == 2 and all(MACHINE in line and "alias=lr-1" in line
                                      for line in identity)
    assert not any("Security" in line for line in lr + identity)


def test_dry_run_needs_no_client_and_writes_nothing(monkeypatch, out):
    factory = Mock(side_effect=AssertionError("no client"))
    monkeypatch.setattr(live_response_cmd, "_get_client", factory)
    result = _invoke(MACHINE, "--output-dir", str(out), "--all", "--dry-run")
    assert result.exit_code == 0, result.output
    data = _documents(result)[0]["data"]
    assert data["opens_session"] is True and data["selection"] == "all"
    assert data["min_bytes"] == 0 and data["logs"] is None
    assert not out.exists()
    factory.assert_not_called()


@pytest.mark.parametrize("args", [
    ["lr-1", "--log", "Security", "--all"],
    ["lr-1", "--resume"],
    ["not-a-target"],
    ["lr-1", "--log", "..\\..\\boot.ini"],
])
def test_invalid_input_is_a_usage_error_before_any_client(monkeypatch, out, args):
    factory = Mock(side_effect=AssertionError("no client"))
    monkeypatch.setattr(live_response_cmd, "_get_client", factory)
    result = _invoke(*args[:1], "--output-dir", str(out), *args[1:])
    assert result.exit_code == 6, result.output
    factory.assert_not_called()


def test_listing_names_cannot_escape_the_fixed_folder(monkeypatch, out):
    listing = _listing(Security=10)
    listing[0]["data"].append({"path": "..\\..\\Windows\\win.ini.evtx", "size": 1,
                               "isDirectory": False})
    fake = _use(monkeypatch, Fake(listing))
    result = _invoke("lr-1", "--output-dir", str(out), "--all")
    assert result.exit_code == 3, result.output
    assert fake.fetched() == []


def test_non_windows_sessions_and_nonempty_or_shared_output_dirs_are_refused(monkeypatch, out):
    _use(monkeypatch, Fake(_listing(Security=10), platform=LRPlatform.LINUX))
    assert _invoke("lr-1", "--output-dir", str(out)).exit_code == 6
    used = out.parent / "used"
    used.mkdir(mode=0o700)
    (used / "x").write_text("x")
    _use(monkeypatch, Fake(_listing(Security=10)))
    assert _invoke("lr-1", "--output-dir", str(used)).exit_code == 13
    shared = out.parent / "shared"
    shared.mkdir()
    shared.chmod(0o755)
    assert _invoke("lr-1", "--output-dir", str(shared)).exit_code == 12


def test_manifest_and_receipt_carry_no_content(monkeypatch, out):
    _use(monkeypatch, Fake(_listing(Security=10)))
    result = _invoke("lr-1", "--output-dir", str(out), "--log", "Security")
    assert result.exit_code == 0, result.output
    assert "ElfFile" not in (out / "manifest.json").read_text()
    assert "ElfFile" not in result.stdout


def test_canonical_stem_rejects_paths():
    assert evtx.canonical_stem("Security.evtx") == "Security"
    assert evtx.canonical_stem("A-B/Operational") == "A-B%4Operational"
    for bad in ("..\\x", "C:\\x", "x\\y", "", ".evtx"):
        with pytest.raises(UsageError):
            evtx.canonical_stem(bad)
