"""Tests for run_kql_with_recording error-path behavior.

Verifies that:
- httpx.TimeoutException produces exit_code=3 and preserves the exception
  message in the invocation record's ``error`` field.
- httpx.HTTPStatusError produces exit_code=3 and preserves the full response
  body (not just the constructor message) in the ``error`` field.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from xdr_cli._recording import run_kql_with_recording
from xdr_cli.config import load_config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import QueryError, TimeoutError
from xdr_cli.sessions import (
    Recorder,
    Session,
    load_session_records,
    set_current_session,
    write_session_start_record,
)


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolated XDR_CLI_HOME with the sessions directory pre-created."""
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    monkeypatch.delenv("XDR_ACTOR", raising=False)
    return home


def _make_ctx(session: Session) -> AppContext:
    cfg = load_config()
    ctx = AppContext(config=cfg, invoked_command="hunt run")
    ctx.recorder = Recorder(
        session=session,
        argv=["hunt", "run", "X"],
        invoked_command="hunt run",
    )
    return ctx


def _run_and_flush(ctx: AppContext, runner) -> int:
    """Run the helper, capture the structured error exit, flush recorder."""
    caught_exit_code = 0

    async def go():
        await run_kql_with_recording(
            ctx,
            kql="DeviceEvents | limit 1",
            invoked_command="hunt run",
            runner=runner,
            library_query=None,
            params=None,
            anchor_incident=None,
            expand_json=False,
            display_limit=10,
            child_recorder=False,
        )

    try:
        asyncio.run(go())
    except (TimeoutError, QueryError) as e:
        caught_exit_code = int(e.exit_code)

    ctx.recorder.flush(exit_code=caught_exit_code, duration_ms=10)
    return caught_exit_code


def test_timeout_exit_code_is_10(home):
    """httpx.ReadTimeout must map to the distinct timeout exit class."""
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    ctx = _make_ctx(s)

    async def boom():
        raise httpx.ReadTimeout("Server didn't respond in 30s")

    exit_code = _run_and_flush(ctx, boom)
    assert exit_code == 10


def test_timeout_error_message_is_recorded(home):
    """httpx.ReadTimeout message must appear in the invocation record's error field."""
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    ctx = _make_ctx(s)

    async def boom():
        raise httpx.ReadTimeout("Server didn't respond in 30s")

    _run_and_flush(ctx, boom)

    lines = load_session_records("jd-1") or []
    invocations = [
        json.loads(line)
        for line in lines
        if json.loads(line)["kind"] == "invocation"
    ]
    assert invocations, "expected an invocation record on timeout"
    rec = invocations[-1]
    assert "didn't respond" in (rec.get("error") or ""), (
        f"timeout message not preserved: {rec.get('error')!r}"
    )


def test_timeout_prints_user_visible_error_on_stderr(home, capsys):
    """A timeout must surface a clear stderr message — not just record it.

    Reason: previously the recorder annotation was the only output, so a
    timeout looked identical to "empty results" from the operator's
    perspective. The CLI must print an unambiguous error before exiting.
    """
    s = Session(id="jd-3", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    ctx = _make_ctx(s)

    async def boom():
        raise httpx.ReadTimeout("Server didn't respond in 30s")

    _run_and_flush(ctx, boom)

    err = capsys.readouterr().err
    assert "timed out" in err.lower() or "timeout" in err.lower(), (
        f"stderr missing user-visible timeout message: {err!r}"
    )


def test_query_error_exit_code_is_5(home):
    """A hunting HTTP 400 must map to the query recovery class."""
    s = Session(id="jd-2", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    ctx = _make_ctx(s)

    async def boom():
        resp = httpx.Response(400, text="Bad query: invalid column AdditionalFields")
        raise httpx.HTTPStatusError(
            "400",
            request=httpx.Request("POST", "https://x"),
            response=resp,
        )

    exit_code = _run_and_flush(ctx, boom)
    assert exit_code == 5


def test_api_error_message_is_recorded(home):
    """httpx.HTTPStatusError response body must appear in the error field."""
    s = Session(id="jd-2", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    ctx = _make_ctx(s)

    async def boom():
        resp = httpx.Response(400, text="Bad query: invalid column AdditionalFields")
        raise httpx.HTTPStatusError(
            "400",
            request=httpx.Request("POST", "https://x"),
            response=resp,
        )

    _run_and_flush(ctx, boom)

    lines = load_session_records("jd-2") or []
    invocations = [
        json.loads(line)
        for line in lines
        if json.loads(line)["kind"] == "invocation"
    ]
    assert invocations, "expected an invocation record on API error"
    rec = invocations[-1]
    assert "AdditionalFields" in (rec.get("error") or ""), (
        f"API error response body not preserved: {rec.get('error')!r}"
    )


def test_timeout_child_recorder_exit_code_is_3(home):
    """For child_recorder=True, flush must use exit_code=3 and the JSONL
    record must carry the error message; the re-raise is the original
    httpx exception (NOT typer.Exit) so the caller can call str(e).
    """
    s = Session(id="jd-3", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)
    ctx = _make_ctx(s)

    async def boom():
        raise httpx.ReadTimeout("timed out")

    async def go():
        await run_kql_with_recording(
            ctx,
            kql="DeviceEvents | limit 1",
            invoked_command="investigate.hunt",
            runner=boom,
            library_query=None,
            params=None,
            anchor_incident=None,
            expand_json=False,
            display_limit=10,
            child_recorder=True,
        )

    # child_recorder path re-raises the ORIGINAL exception (not typer.Exit)
    # so investigate_cmd.py's wrapper can call str(e) for the JSON envelope.
    with pytest.raises(TimeoutError):
        asyncio.run(go())

    lines = load_session_records("jd-3") or []
    invocations = [
        json.loads(line)
        for line in lines
        if json.loads(line)["kind"] == "invocation"
    ]
    assert invocations, "expected child invocation record on timeout"
    rec = invocations[-1]
    assert rec["exit_code"] == 10
    assert "timed out" in (rec.get("error") or ""), (
        f"timeout message not in child record: {rec.get('error')!r}"
    )


def test_child_recorder_path_re_raises_original_exception(home):
    """When child_recorder=True, run_kql_with_recording must re-raise the
    original httpx exception (not convert to typer.Exit), so investigate's
    JSON envelope can call str(e) and get a useful error message.
    """
    s = Session(id="jd-1", upn="j@c", label=None, learning_mode=False)
    set_current_session(s)
    write_session_start_record(s)

    cfg = load_config()
    ctx = AppContext(config=cfg, invoked_command="investigate")
    ctx.recorder = Recorder(session=s, argv=["investigate", "X"], invoked_command="investigate")

    async def boom():
        raise httpx.ReadTimeout("Server didn't respond in 30s")

    async def go():
        await run_kql_with_recording(
            ctx, kql="X", invoked_command="investigate.hunt", runner=boom,
            library_query=None, params=None, anchor_incident=None,
            expand_json=False, display_limit=10, child_recorder=True,
        )

    # Child path must re-raise the ORIGINAL exception (not typer.Exit).
    with pytest.raises(TimeoutError) as excinfo:
        asyncio.run(go())
    assert "didn't respond" in str(excinfo.value)
