"""xdr lists init: seed the user's lists directory from src/xdr_cli/lists_seed/.

Output is the project's standard JSON envelope (rows of {file, action,
target_path, source}) — never bespoke text. Plain-text rendering comes from
the existing OutputFormatter for free. The command is idempotent (rerun
produces `existing` rows for already-present files), atomic (each write
goes through tempfile + os.replace; a Ctrl-C / disk-full / permission
error mid-loop never leaves half-written files), and audit-logged
(registered in main._WRITE_COMMANDS).
"""

from __future__ import annotations

import contextlib
import importlib.resources
import os
import sys
import tempfile
from pathlib import Path

import typer

from xdr_cli.config import get_config_home
from xdr_cli.context import AppContext
from xdr_cli.exceptions import ConfigError, ConflictError, UsageError
from xdr_cli.output import OutputFormatter

lists_app = typer.Typer(
    name="lists",
    help="Manage tenant-data and IOC lists used by library queries.",
    no_args_is_help=True,
)


def _atomic_write(target: Path, content: bytes) -> None:
    """Write `content` to `target` atomically (tempfile + os.replace).

    The tempfile lives in `target.parent` so os.replace is a same-filesystem
    rename. On any failure the temp file is removed; the existing target is
    untouched. Ctrl-C between truncate and write cannot leave a half-written
    target.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=target.parent, prefix=target.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


@lists_app.command("init")
def lists_init(
    ctx: typer.Context,
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing files (requires --yes in non-interactive mode).",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Skip confirmation prompt when --force is used.",
    ),
) -> None:
    """Seed ~/.xdr-cli/lists/ from the in-repo lists_seed/ directory."""
    app_ctx: AppContext = ctx.obj
    out_dir = get_config_home() / "lists"

    seed_pkg = importlib.resources.files("xdr_cli.lists_seed")
    seed_files = sorted(
        (item for item in seed_pkg.iterdir() if item.name.endswith(".txt")),
        key=lambda p: p.name,
    )

    if not seed_files:
        # Wheel-install failure mode: lists_seed/ exists as an importable
        # package but its package-data was not included. Emit a hard error
        # rather than silently no-opping (which would let the analyst think
        # the lists directory is initialized when it is empty).
        error = ConfigError(
            "No seed files were packaged in xdr_cli.lists_seed.",
            suggestions=[
                {
                    "reason": "package_repair",
                    "message": "Reinstall xdr-cli or run from a complete source clone.",
                    "confidence": "exact",
                }
            ],
        )
        error.error_code = "PACKAGE_DATA_MISSING"
        raise error

    # --force without --yes: in interactive TTY, prompt; in --no-interactive
    # / no TTY, fail fast with exit code 2 so CI / agent runs never hang.
    if force and not yes:
        if app_ctx.no_interactive or not sys.stdin.isatty():
            raise UsageError(
                "xdr lists init --force requires --yes in non-interactive mode.",
                invalid={"kind": "missing_option", "value": "--yes"},
                corrected_argv=["xdr", "lists", "init", "--force", "--yes"],
                help_command="xdr lists init --help",
            )
        confirm = typer.confirm(
            f"--force will overwrite {len(seed_files)} files in {out_dir}. Continue?"
        )
        if not confirm:
            raise ConflictError("List initialization was cancelled by the operator.")

    rows: list[dict] = []
    for item in seed_files:
        target = out_dir / item.name
        target_existed = target.exists()
        if target_existed and not force:
            rows.append({
                "file": item.name,
                "action": "existing",
                "target_path": str(target),
                "source": "lists_seed",
            })
            continue
        _atomic_write(target, item.read_bytes())
        rows.append({
            "file": item.name,
            "action": "overwritten" if target_existed else "created",
            "target_path": str(target),
            "source": "lists_seed",
        })

    fmt = OutputFormatter(
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
    )
    columns = [
        {"key": "file", "header": "File"},
        {"key": "action", "header": "Action"},
        {"key": "target_path", "header": "Path", "style": "dim"},
    ]
    typer.echo(fmt.format_output(rows, columns=columns, title="xdr lists init"))
