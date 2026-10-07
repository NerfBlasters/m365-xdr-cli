"""Migration contracts: command surface and values delivered to implementations.

The fixture was captured from the pre-migration CLI. Regeneration is explicit;
review every difference. Binding runs stub every application callback before
command construction and never execute application operations or dispatch hooks.
"""

from __future__ import annotations

import copy
import functools
import inspect
import json
import os
import re
from datetime import datetime
from enum import Enum
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from xdr_cli.main import app

GOLDEN = Path(__file__).parent / "fixtures" / "cli_contract.json"


def typed(value):
    if isinstance(value, Enum):
        return {"enum": type(value).__name__, "value": value.value}
    if isinstance(value, Path):
        return {
            "path": (
                "<existing-file>"
                if value == Path(__file__)
                else "<output-path>"
                if value == Path("/tmp/xdr-contract-output")
                else str(value)
            )
        }
    if isinstance(value, datetime):
        return {"datetime": value.isoformat()}
    if isinstance(value, tuple):
        return {"tuple": [typed(v) for v in value]}
    if isinstance(value, list):
        return [typed(v) for v in value]
    if isinstance(value, dict):
        return {k: typed(v) for k, v in value.items()}
    return value


def walk(command, path=()):
    yield path, command
    if isinstance(command, click.Group):
        for name, child in sorted(command.commands.items()):
            yield from walk(child, (*path, name))


def surface(command):
    result = {}
    for path, cmd in walk(command):
        params = []
        for p in cmd.params:
            if p.name in {"install_completion", "show_completion"}:
                continue  # Explicitly approved removal.
            t = p.type
            descriptor = {"name": t.name}
            for key in (
                "choices",
                "case_sensitive",
                "min",
                "max",
                "min_open",
                "max_open",
                "clamp",
                "exists",
                "file_okay",
                "dir_okay",
                "writable",
                "readable",
                "resolve_path",
                "allow_dash",
                "formats",
            ):
                if hasattr(t, key):
                    value = getattr(t, key)
                    descriptor[key] = list(value) if isinstance(value, (list, tuple)) else value
            params.append(
                {
                    "name": p.name,
                    "kind": p.param_type_name,
                    "opts": p.opts,
                    "secondary_opts": getattr(p, "secondary_opts", []),
                    "required": p.required,
                    "multiple": p.multiple,
                    "nargs": p.nargs,
                    "is_flag": getattr(p, "is_flag", False),
                    "count": getattr(p, "count", False),
                    "hidden": getattr(p, "hidden", False),
                    "envvar": p.envvar,
                    "default": (None if p.required else typed(p.get_default(click.Context(cmd)))),
                    "type": descriptor,
                    "is_eager": p.is_eager,
                    "help": " ".join((getattr(p, "help", "") or "").split()),
                }
            )
        result[" ".join(path)] = {
            "hidden": cmd.hidden,
            "no_args_is_help": cmd.no_args_is_help,
            "invoke_without_command": getattr(cmd, "invoke_without_command", False),
            "help": " ".join((cmd.help or "").replace("\b", "").split()),
            "params": params,
        }
    return result


def stubbed(application, captured):
    application = copy.deepcopy(application)

    def recorder(original, path):
        @functools.wraps(original)
        def record(*args, **kwargs):
            kwargs.pop("ctx", None)
            captured.append({"command": " ".join(path), "values": typed(kwargs)})

        record.__signature__ = inspect.signature(original)
        return record

    for path, cmd in walk(application):
        if cmd.callback:
            cmd.callback = recorder(cmd.callback, path)
    cmd = application
    for _, child in walk(cmd):
        for p in child.params:
            # Eager version/completion callbacks can exit or touch the shell;
            # their behavior has dedicated tests, not synthetic binding calls.
            if p.is_eager:
                p.callback = None
    return cmd


def sample(param):
    t = param.type
    if isinstance(t, click.Choice):
        return str(t.choices[0])
    if isinstance(t, click.IntRange):
        return str(max(1, t.min or 1))
    if isinstance(t, click.types.IntParamType):
        return "7"
    if isinstance(t, click.DateTime):
        return "2026-10-04T12:30:00"
    if isinstance(t, click.Path):
        return __file__ if t.exists else "/tmp/xdr-contract-output"
    return "sample"


def bindings(application):
    captured = []
    cmd = stubbed(application, captured)
    runner = CliRunner()
    results = {}
    for path, leaf in walk(cmd):
        if not path or (isinstance(leaf, click.Group) and not leaf.invoke_without_command):
            continue
        required = []
        supplied = []
        flags = []
        for p in leaf.params:
            if p.is_eager:
                continue
            if isinstance(p, click.Argument):
                supplied.append(sample(p))
                if p.required:
                    required.append(sample(p))
            elif p.is_flag:
                supplied.append(p.opts[0])
                flags.extend((p.opts[0], *p.secondary_opts))
            else:
                values = [p.opts[0], sample(p)]
                if p.multiple:
                    values += values
                supplied += values
                if p.required:
                    required += values
        cases = [("required", required), ("supplied", supplied)]
        cases += [(flag, [*required, flag]) for flag in flags]
        for label, args in cases:
            captured.clear()
            result = runner.invoke(
                cmd,
                [*path, *args],
                prog_name="xdr",
                env={
                    "MDE_REFRESH_TOKEN": None,
                    "XDR_SESSION": None,
                },
            )
            assert result.exit_code == 0, (path, args, result.output, result.exception)
            record = next(v for v in reversed(captured) if v["command"] == " ".join(path))
            results[" ".join(path) + ":" + label] = record["values"]
    return results


def test_cli_contract():
    actual = {"surface": surface(app), "bindings": bindings(app)}
    if os.environ.get("XDR_REGENERATE_CLI_CONTRACT") == "1":
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    assert actual == json.loads(GOLDEN.read_text())


ERROR_CASES = [
    ["investigate", "42"],
    ["nonesuch"],
    ["incidents", "list", "--severty", "high"],
    ["domains", "list", "--source", "invalid"],
    ["device", "timeline", "sample", "--hours", "0"],
    ["incidents", "show"],
    ["incidents", "list", "--fields", "id"],
    ["incidents", "show", "--help"],
    ["incidents"],
    ["incidnets"],
    ["schema", "obesrve"],
    ["--backend", "PORTAL_COOKIE", "domains", "list"],
    ["--backend", "Entra", "domains", "list"],
    ["domains", "list", "--source", "ALL"],
    ["domains", "list", "--source", "Entra"],
    ["device", "scan", "sample", "--scan-type", "invalid"],
    ["device", "timeline", "sample", "--hours", "abc"],
    ["device", "timeline", "sample", "--hours"],
    ["device", "timeline", "sample", "--days", "0"],
    ["incidents", "list", "--limit", "abc"],
    ["incidents", "show", "sample", "extra"],
    ["schema", "observe"],
    ["schema", "observe", "sample", "--samples", "0"],
    ["schema", "observe", "sample", "--samples"],
    ["history", "--limit", "abc"],
    ["auth", "login", "--unknown"],
]


def test_cli_error_contract():
    cmd = copy.deepcopy(app)
    # All dispatch/root/group callbacks are inert. Actual parsing and the
    # production structured error boundary remain active.
    for _, child in walk(cmd):
        if child.callback:
            child.callback = lambda **kwargs: None
    records = []
    for argv in ERROR_CASES:
        result = CliRunner().invoke(cmd, argv, prog_name="xdr")
        if "--help" in argv or argv == ["incidents"]:
            assert "Usage:" in result.stdout
            assert '"status":' not in result.stdout
            records.append({"argv": argv, "exit": result.exit_code, "help": True})
        else:
            records.append(
                {
                    "argv": argv,
                    "exit": result.exit_code,
                    "stdout": json.loads(result.stdout),
                    "stderr": result.stderr,
                }
            )
    path = GOLDEN.with_name("cli_errors.json")
    if os.environ.get("XDR_REGENERATE_CLI_CONTRACT") == "1":
        path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    baseline = json.loads(path.read_text())
    # Typer 0.24.2 repeats Click 8.5's typo hint. Keep captured evidence intact;
    # compare the diagnostic with that duplicate removed. All structured fields
    # (including suggestions) remain exact matches.
    for record in baseline:
        if "stdout" not in record:
            continue
        error = record["stdout"]["error"]
        for container in (error, error["original"]):
            container["message"] = re.sub(
                r"( Did you mean '[^']+'\?)\1", r"\1", container["message"]
            )
    assert records == baseline
