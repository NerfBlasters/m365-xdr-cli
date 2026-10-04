"""Offline runtime checks for upkeep authentication, cancellation, and recovery."""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from xdr_cli._lock import exclusive_lock
from xdr_cli.auth import AuthManager
from xdr_cli.config import Config, load_config, save_config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import TimeoutError as XDRTimeoutError
from xdr_cli.exceptions import ConfigError, NotAuthenticatedError
from xdr_cli.main import app
from xdr_cli.schema_graph.session_maintenance import collect_session_schema
from xdr_cli.sessions import create_session, session_already_ended


def _hold_token_lock(path, ready, release):
    with exclusive_lock(Path(path), timeout=2):
        ready.set()
        release.wait(5)


@contextmanager
def held_token_lock(home):
    process_context = multiprocessing.get_context("spawn")
    ready, release = process_context.Event(), process_context.Event()
    holder = process_context.Process(
        target=_hold_token_lock, args=(str(home / "token_cache.json"), ready, release),
    )
    holder.start()
    try:
        assert ready.wait(3), "synthetic holder did not acquire the token lock"
        yield
    finally:
        release.set()
        holder.join(2)
        if holder.is_alive():
            holder.kill()
            holder.join(2)


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "home"
    root.mkdir()
    (root / "token_cache.json").write_text("{}")
    monkeypatch.setenv("XDR_CLI_HOME", str(root))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return root


def test_real_token_lock_cannot_defeat_overall_maintenance_deadline(home):
    config = Config(
        tenant_id="synthetic-tenant", client_id="synthetic-client",
        schema_maintenance_timeout_seconds=0.15,
    )
    ctx = AppContext(config, no_interactive=True, quiet=True)
    captured = []

    async def validate(ctx, **kwargs):
        AuthManager(ctx.config).get_token()

    with (
        held_token_lock(home),
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {"stale": False})),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=validate),
        patch("xdr_cli.schema_graph.discovery.explore_saved_identifiers") as explore,
        patch("xdr_cli.schema_graph.maintenance.mark_collection_complete") as complete,
        patch("xdr_cli.auth.AuthManager._get_token_locked", return_value="synthetic-token"),
    ):
        started = time.monotonic()
        with pytest.raises(XDRTimeoutError):
            collect_session_schema(ctx, on_result=captured.append)
        assert time.monotonic() - started < 1.5
    assert len(captured) == 1
    assert captured[0].receipt.context["stages"]["validation"]["status"] == "failed"
    assert (home / "token_cache.json").read_text() == "{}"
    explore.assert_not_called()
    complete.assert_not_called()


@pytest.mark.skipif(os.name != "posix", reason="real POSIX SIGINT process test")
def test_first_ctrl_c_during_token_lock_preserves_closure_and_exits_130(home, tmp_path):
    save_config(Config(
        tenant_id="synthetic-tenant", client_id="synthetic-client",
        schema_maintenance_timeout_seconds=10,
    ))
    session = create_session(upn="synthetic@example.invalid", automatic=False)
    waiting = tmp_path / "waiting"
    script = tmp_path / "cancel_runtime.py"
    script.write_text(
        "import sys\n"
        "from contextlib import contextmanager\n"
        "from pathlib import Path\n"
        "from unittest.mock import patch\n"
        "from xdr_cli._lock import exclusive_lock as original_lock\n"
        "from xdr_cli.auth import AuthManager, _token_worker as original_worker\n"
        "from xdr_cli.main import run\n"
        "@contextmanager\n"
        "def watched_lock(path, **kwargs):\n"
        f"    Path({str(waiting)!r}).write_text('ready')\n"
        "    with original_lock(path, **kwargs):\n"
        "        yield\n"
        "def token_worker(*args):\n"
        "    with patch('xdr_cli.auth.exclusive_lock', watched_lock):\n"
        "        original_worker(*args)\n"
        "async def validate(ctx, **kwargs):\n"
        "    AuthManager(ctx.config).get_token()\n"
        "if __name__ == '__main__':\n"
        "    sys.argv = ['xdr', 'session', 'end']\n"
        "    with patch('xdr_cli.commands.schema_cmd._load_cache', "
        "return_value=([], {'stale': False})), "
        "patch('xdr_cli.schema_graph.local_collection.collect_local', side_effect=validate), "
        "patch('xdr_cli.auth._token_worker', token_worker):\n"
        "        run()\n"
    )
    with held_token_lock(home):
        process = subprocess.Popen(
            [sys.executable, str(script)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            started = time.monotonic()
            while (
                not waiting.exists() and process.poll() is None and time.monotonic() - started < 3
            ):
                time.sleep(0.01)
            assert waiting.exists(), "maintenance never reached the synthetic token lock"
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=2)
            assert process.returncode == 130, (stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)
    records = [json.loads(line) for line in stdout.splitlines()]
    assert len(records) == 2
    assert records[0]["record_type"] == "session-end"
    assert "next_action" in records[0]
    assert records[1]["maintenance"]["status"] == "cancelled"
    assert session_already_ended(session.id)
    assert (home / "token_cache.json").read_text() == "{}"


@pytest.mark.parametrize("entry", [
    "schema_explore_max_queries = true", "schema_maintenance_timeout_seconds = -1",
    "schema_maintenance_timeout_seconds = 1e308",
    "schema_refresh_on_session_end = 1", "schema_collect_on_sesion_end = false",
])
def test_bad_upkeep_config_does_not_block_local_recovery_or_explicit_bypass(home, entry):
    session = create_session(upn="synthetic@example.invalid", automatic=False)
    (home / "config.toml").write_text(f'tenant_id = "synthetic-tenant"\n{entry}\n')
    runner = CliRunner()
    listing = runner.invoke(app, ["session", "list"])
    assert listing.exit_code == 0, listing.output
    assert "config" in listing.stderr.lower()
    with patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as maintain:
        ended = runner.invoke(app, ["session", "end", "--no-maintenance"])
    assert ended.exit_code == 0, ended.output
    assert session_already_ended(session.id)
    assert json.loads(ended.stdout.splitlines()[1])["maintenance"]["reason"] == "requested"
    maintain.assert_not_called()


def test_misspelled_upkeep_switch_is_diagnosed_and_never_launches_queries(home):
    create_session(upn="synthetic@example.invalid", automatic=False)
    (home / "config.toml").write_text(
        'tenant_id = "synthetic-tenant"\nschema_collect_on_sesion_end = false\n'
    )
    with patch("xdr_cli.schema_graph.session_maintenance.collect_session_schema") as maintain:
        result = CliRunner().invoke(app, ["session", "end"])
    assert result.exit_code == 14, result.output
    assert "schema_collect_on_sesion_end" in result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert records[0]["ended"] is True
    assert records[1]["maintenance"]["exit_code"] == 4
    maintain.assert_not_called()


def test_unknown_nonmaintenance_key_warns_without_printing_its_value(home):
    (home / "config.toml").write_text('unexpected_key = "synthetic-private-value"\n')
    result = CliRunner().invoke(app, ["session", "list"])
    assert result.exit_code == 0
    assert "unexpected_key" in result.stderr
    assert "synthetic-private-value" not in result.output


def test_upkeep_token_deadline_cancels_synchronous_state_writer(home):
    import xdr_cli.auth as auth

    async def exercise():
        task = asyncio.current_task()
        with auth.bounded_token_acquisition(time.monotonic() + 0.1, task.cancelling):
            config = Config(tenant_id="synthetic-tenant", client_id="synthetic-client")
            AuthManager(config).get_token()

    with held_token_lock(home), pytest.raises(XDRTimeoutError):
        asyncio.run(exercise())
    assert (home / "token_cache.json").read_text() == "{}"
    assert not [child for child in multiprocessing.active_children() if child.name == "xdr-token"]


def _synthetic_token_io(connection, config, scopes, timeout):
    """Benign stand-in for a cache-writing SDK call, in a real spawned process."""
    from xdr_cli.config import get_config_home

    home = get_config_home()
    (home / "worker-ready").write_text("ready")
    if scopes == ["slow"]:
        time.sleep(2)
        (home / "token_cache.json").write_text("synthetic-late-write")
    if scopes == ["auth-error"]:
        error = NotAuthenticatedError()
        connection.send(("error", type(error).__name__, vars(error)))
    else:
        connection.send(("token", "synthetic-token"))
    connection.close()


def test_slow_token_io_process_is_reaped_before_it_can_write(home):
    import xdr_cli.auth as auth

    with (
        patch("xdr_cli.auth._token_worker", _synthetic_token_io),
        auth.bounded_token_acquisition(time.monotonic() + 1, lambda: 0),
        pytest.raises(XDRTimeoutError),
    ):
        AuthManager(Config()).get_token(["slow"])
    assert (home / "worker-ready").exists(), "synthetic I/O worker must actually start"
    assert (home / "token_cache.json").read_text() == "{}"
    assert not [child for child in multiprocessing.active_children() if child.name == "xdr-token"]


@pytest.mark.parametrize("scopes", [["success"], ["auth-error"]])
def test_bounded_worker_preserves_token_and_typed_auth_failure(home, scopes):
    import xdr_cli.auth as auth

    with (
        patch("xdr_cli.auth._token_worker", _synthetic_token_io),
        auth.bounded_token_acquisition(time.monotonic() + 3, lambda: 0),
    ):
        if scopes == ["auth-error"]:
            with pytest.raises(NotAuthenticatedError) as failure:
                AuthManager(Config()).get_token(scopes)
            assert failure.value.exit_code == 2
            assert failure.value.help_command == "xdr auth status"
        else:
            assert AuthManager(Config()).get_token(scopes) == "synthetic-token"
    assert not [child for child in multiprocessing.active_children() if child.name == "xdr-token"]


def test_auth_config_save_preserves_rejected_upkeep_settings_for_recovery(home):
    (home / "config.toml").write_text(
        'schema_collect_on_sesion_end = false\nschema_explore_max_queries = true\n'
    )
    config = load_config()
    config.tenant_id = "synthetic-tenant"
    config.client_id = "synthetic-client"
    save_config(config)
    reloaded = load_config()
    assert reloaded.tenant_id == "synthetic-tenant"
    with pytest.raises(ConfigError):
        reloaded.check_maintenance_config()
    persisted = (home / "config.toml").read_text()
    assert "schema_collect_on_sesion_end = false" in persisted
    assert "schema_explore_max_queries = true" in persisted
