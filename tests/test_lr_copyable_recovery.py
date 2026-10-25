"""Recovery follows the accepted job even when the configured backend is opposite."""

import json
import shlex

import pytest
from click.testing import CliRunner

from tests.lr_fakes import MACHINE, SESSION, FakeLRBackend
from xdr_cli.exceptions import NetworkError
from xdr_cli.live_response.models import LRCommandState
from xdr_cli.main import app

COMMAND = "00000000-0000-0000-0000-000000000001"


class FollowupFailure(FakeLRBackend):
    failed = False

    def _state(self, index):
        state = super()._state(index)
        from dataclasses import replace

        return replace(state, command_id=COMMAND)

    async def lr_submit_batch(self, machine_id, commands, *, comment):
        self.calls.append("submit_batch")
        return LRCommandState(COMMAND, machine_id, "batch", "InProgress", terminal=False)

    async def lr_get_command(self, session_id, command_id):
        self.calls.append("get_command")
        if not self.failed:
            self.failed = True
            raise NetworkError("Follow-up status read failed.", retryable=True)
        return LRCommandState(
            COMMAND, MACHINE, "batch" if session_id is None else "run",
            "Succeeded" if session_id is None else "completed",
            session_id=session_id, terminal=True,
        )


@pytest.mark.parametrize("backend,default_backend,args,submission", [
    ("portal-cookie", "official", ["run", SESSION, "test.ps1", "--wait", "30"],
     "submit"),
    ("official", "portal-cookie", ["batch", "submit", MACHINE, "--command",
     r"getfile C:\Windows\file.txt", "--comment", "test", "--wait", "30"],
     "submit_batch"),
])
def test_failed_wait_recovery_works_with_opposite_backend_default(
    tmp_path, monkeypatch, backend, default_backend, args, submission
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text(f'api_backend = "{default_backend}"\n')
    client, selected = FollowupFailure(), []

    def factory(ctx):
        selected.append(ctx.config.backend_profile.name.value)
        return client

    monkeypatch.setattr("xdr_cli.commands.live_response_cmd._get_client", factory)
    monkeypatch.setattr("xdr_cli.commands.live_response_cmd._POLL_SECONDS", 0)
    runner = CliRunner()
    result = runner.invoke(
        app, ["--no-interactive", "--backend", backend, "device", "live-response", *args]
    )
    assert result.exit_code == 11, result.output
    error = json.loads(result.stdout)["error"]
    assert not error["retryable"] and COMMAND in error["message"]
    # Execute the exact command supplied to the operator, with no inherited override.
    recovery = shlex.split(error["help_command"])
    assert recovery.pop(0) == "xdr"
    resumed = runner.invoke(app, recovery)
    assert resumed.exit_code == 0, resumed.output
    assert selected == [backend, backend]
    assert client.calls.count(submission) == 1
