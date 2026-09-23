"""Tests for the xdr lists init command — exercise the JSON contract end-to-end via the root app."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Import the ROOT app, not lists_app directly, so the JSON envelope, audit-log
# integration, --no-interactive plumbing, and OutputFormatter are exercised.
from xdr_cli.main import app

runner = CliRunner()


def _invoke(args: list[str], **kw):
    """Invoke the root `xdr` app. The CLI emits a JSON envelope by default —
    there is no `--output` flag to set.
    """
    return runner.invoke(app, list(args), **kw)


def _rows(result) -> list[dict]:
    """Parse the JSON envelope and return the data rows."""
    payload = json.loads(result.stdout)
    return payload.get("data", [])


def test_init_creates_files_first_run(config_dir):  # config_dir fixture sets XDR_CLI_HOME
    """First run on a fresh tenant copies every seed file and reports `created`."""
    result = _invoke(["lists", "init"])
    assert result.exit_code == 0, result.stdout + result.stderr
    rows = _rows(result)
    assert any(r["file"] == "InternalSubnets.txt" and r["action"] == "created" for r in rows)
    assert any(r["file"] == "KnownGoodSigners.txt" and r["action"] == "created" for r in rows)
    out_dir = Path(config_dir) / "lists"
    assert (out_dir / "InternalSubnets.txt").exists()


def test_init_idempotent_second_run(config_dir):
    """Re-running without --force preserves user-customised files and reports `existing`."""
    _invoke(["lists", "init"])
    out_dir = Path(config_dir) / "lists"
    (out_dir / "InternalSubnets.txt").write_text("# user-customised\n10.99.0.0/16\n")
    result = _invoke(["lists", "init"])
    assert result.exit_code == 0
    rows = _rows(result)
    assert any(r["file"] == "InternalSubnets.txt" and r["action"] == "existing" for r in rows)
    assert "10.99.0.0/16" in (out_dir / "InternalSubnets.txt").read_text()


def test_init_force_yes_overwrites(config_dir):
    """--force + --yes overwrites existing files without prompting."""
    _invoke(["lists", "init"])
    out_dir = Path(config_dir) / "lists"
    (out_dir / "InternalSubnets.txt").write_text("# user-customised\n")
    result = _invoke(["lists", "init", "--force", "--yes"])
    assert result.exit_code == 0
    rows = _rows(result)
    assert any(r["file"] == "InternalSubnets.txt" and r["action"] == "overwritten" for r in rows)
    assert "10.0.0.0/8" in (out_dir / "InternalSubnets.txt").read_text()
    assert "user-customised" not in (out_dir / "InternalSubnets.txt").read_text()


def test_init_force_without_yes_in_no_interactive_fails_fast(config_dir):
    """--force without --yes is a structured usage failure."""
    result = _invoke(["--no-interactive", "lists", "init", "--force"])
    assert result.exit_code == 6
    assert "requires --yes" in result.stderr or "requires --yes" in result.stdout


def test_init_atomic_on_error(config_dir, monkeypatch):
    """A mid-loop OSError must not leave partial files; tempfile + os.replace ensures atomicity."""
    # Patch the second seed-file write to raise. The first should still complete cleanly,
    # neither leaving its own file half-written nor leaving a stray .tmp.
    # Seed files are processed in sorted order; AiTMInfrastructure.txt is first.
    real_replace = __import__("os").replace
    calls = {"n": 0}
    def flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full simulation")
        return real_replace(src, dst)
    monkeypatch.setattr("os.replace", flaky_replace)
    result = _invoke(["lists", "init"])
    out_dir = Path(config_dir) / "lists"
    # The OSError propagates; CLI exits 1 (unhandled exception → Typer default).
    assert result.exit_code == 1
    # The first file (alphabetically: AiTMInfrastructure.txt) was written before the failure.
    assert (out_dir / "AiTMInfrastructure.txt").exists()
    # No leftover .tmp files from the failed second write.
    assert not any(p.suffix == ".tmp" for p in out_dir.iterdir())


def test_seed_files_packaged():
    """Regression net for the wheel-install failure mode (PEP-722 importlib.resources)."""
    import importlib.resources
    pkg = importlib.resources.files("xdr_cli.lists_seed")
    txt_files = [p.name for p in pkg.iterdir() if p.name.endswith(".txt")]
    assert len(txt_files) >= 5, (
        "lists_seed/ ships fewer than 5 .txt files — check pyproject.toml "
        "package-data and lists_seed/__init__.py"
    )
