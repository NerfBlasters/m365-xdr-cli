"""Tests for AppContext.effective_quiet resolution logic."""

from __future__ import annotations

import sys

import pytest

from xdr_cli.context import AppContext


def _make_ctx(mock_config, *, quiet: bool | None = None) -> AppContext:
    return AppContext(config=mock_config, quiet=quiet)


def test_effective_quiet_pipe_detection(
    mock_config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Piped stdout auto-enables quiet when --quiet is unset."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    ctx = _make_ctx(mock_config, quiet=None)
    assert ctx.effective_quiet is True


def test_effective_quiet_explicit_false_beats_pipe(
    mock_config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit --no-quiet (quiet=False) beats pipe detection."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    ctx = _make_ctx(mock_config, quiet=False)
    assert ctx.effective_quiet is False


def test_effective_quiet_explicit_true_beats_tty(
    mock_config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit --quiet wins over TTY presence."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    ctx = _make_ctx(mock_config, quiet=True)
    assert ctx.effective_quiet is True


def test_effective_quiet_default_human_tty(
    mock_config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Human at a TTY with no flags gets quiet=False (progress visible)."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    ctx = _make_ctx(mock_config, quiet=None)
    assert ctx.effective_quiet is False
