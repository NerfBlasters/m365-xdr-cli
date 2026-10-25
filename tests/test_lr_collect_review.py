"""Adversarial collector regressions for durable results and output ownership."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.lr_fakes import MACHINE
from tests.test_lr_event_logs import Fake, _documents, _invoke, _listing, _use
from xdr_cli._lock import exclusive_lock
from xdr_cli.commands import live_response_cmd
from xdr_cli.exceptions import ArtifactError
from xdr_cli.live_response import event_logs as evtx


@pytest.fixture(autouse=True)
def private_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    config = home / "config.toml"
    config.write_text('tenant_id = "test-tenant"\n')
    config.chmod(0o600)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.setattr(live_response_cmd, "_POLL_SECONDS", 0)


def test_midrun_manifest_failure_preserves_completed_result_receipt(tmp_path, monkeypatch):
    fake = _use(monkeypatch, Fake(_listing(Security=10, System=10)))
    original = evtx.Manifest.save
    calls = 0

    def save(manifest):
        nonlocal calls
        calls += 1
        if calls == 5:  # first file durable, immediately before second submission
            raise ArtifactError("synthetic manifest failure")
        return original(manifest)

    monkeypatch.setattr(evtx.Manifest, "save", save)
    out = tmp_path / "logs"
    result = _invoke(MACHINE, "--output-dir", str(out), "--log", "Security", "--log", "System")
    assert result.exit_code == 14, result.output
    receipt, *rest = _documents(result)
    assert receipt["status"] == "success"
    rows = [json.loads(line) for line in Path(receipt["data_path"]).read_text().splitlines()]
    assert rows[0]["status"] == "completed" and rows[0]["command_id"]
    assert receipt["context"]["stopped"] == "manifest-unwritable"
    assert (out / "Security.evtx").exists()
    assert fake.fetched() == ["Security.evtx"] and fake.closed
    assert rest[-1]["error"]["exit_code"] == 14


def test_download_recovery_preserves_effective_size_cap(tmp_path, monkeypatch):
    import shlex

    fake = _use(monkeypatch, Fake(_listing(Security=1)))
    fake.content["Security.evtx"] = b"x" * 200
    result = _invoke(MACHINE, "--output-dir", str(tmp_path / "logs"), "--log", "Security",
                     "--max-bytes", "100")
    assert result.exit_code == 14, result.output
    receipt = _documents(result)[0]
    row = json.loads(Path(receipt["data_path"]).read_text().splitlines()[0])
    recovery = next(cmd for cmd in row["recovery"] if " download " in cmd)
    args = shlex.split(recovery)
    assert args[args.index("--max-bytes") + 1] == "100"


def test_concurrent_output_claim_fails_before_client_creation(tmp_path, monkeypatch):
    out = tmp_path / "logs"
    out.mkdir(mode=0o700)
    held, release = threading.Event(), threading.Event()
    no_client = Mock(side_effect=AssertionError("No client for an occupied output"))
    monkeypatch.setattr(live_response_cmd, "_get_client", no_client)

    def hold():
        with exclusive_lock(out / evtx.MANIFEST):
            held.set()
            assert release.wait(5)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(hold)
        assert held.wait(5)
        try:
            result = _invoke(MACHINE, "--output-dir", str(out), "--log", "Security")
            assert result.exit_code == 13, result.output
            no_client.assert_not_called()
        finally:
            release.set()
        future.result()


def test_partial_error_explains_cleanup_when_all_logs_were_saved(tmp_path, monkeypatch):
    fake = _use(monkeypatch, Fake(_listing(Security=10)))
    fake.close_state = "running"
    result = _invoke(MACHINE, "--output-dir", str(tmp_path / "logs"), "--log", "Security")
    assert result.exit_code == 14, result.output
    error = _documents(result)[-1]["error"]
    assert "session closure is unconfirmed" in error["message"]
    assert "0 event log" not in error["message"]
