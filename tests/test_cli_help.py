"""Render every command: metadata comparisons cannot detect broken help layout."""

import inspect
import re

import click
import pytest
from click.testing import CliRunner

from tests.test_cli_contract import stubbed, walk
from xdr_cli.cli_params import EnumValueChoice
from xdr_cli.main import app

COMMANDS = list(walk(app))


@pytest.mark.parametrize("width", [60, 80, 120])
@pytest.mark.parametrize("path,command", COMMANDS, ids=[" ".join(p) or "xdr" for p, _ in COMMANDS])
def test_rendered_help(path, command, width):
    result = CliRunner().invoke(
        stubbed(app, []), [*path, "--help"], terminal_width=width, max_content_width=width
    )
    assert result.exit_code == 0, result.output
    assert "Usage:" in result.stdout
    assert '[default: ""]' not in result.stdout
    assert "\b" not in result.stdout
    # Every protected paragraph must survive as physical lines, even in a narrow terminal.
    rendered_lines = [line.rstrip() for line in result.stdout.splitlines()]
    for paragraph in inspect.cleandoc(command.help or "").split("\n\n"):
        lines = paragraph.splitlines()
        if lines and lines[0].strip() == "\b":
            expected = [line.rstrip() for line in lines[1:]]
            assert any(
                rendered_lines[i : i + len(expected)] == ["  " + line for line in expected]
                for i in range(len(rendered_lines))
            ), (path, expected, result.stdout)
    for param in command.params:
        if isinstance(param.type, EnumValueChoice) and isinstance(param.default, str):
            assert f"[default: {param.default}]" in " ".join(result.stdout.split())
            assert param.type.convert(param.default, param, None).value == param.default
    if isinstance(command, click.Group):
        compact = re.sub(r"\s+", "", result.stdout)
        for child in command.commands.values():
            assert child.short_help
            assert re.sub(r"\s+", "", child.short_help) in compact


# Explicit anchors catch deletion of the protection markers themselves.
@pytest.mark.parametrize(
    "path,line",
    [
        (
            ("incidents", "list"),
            'id (str)               — Microsoft Graph incident id, e.g. "155278"',
        ),
        (("device", "timeline"), "DeviceProcessEvents"),
        (("schema", "observe"), "Inspect the deterministic scope without tenant access:"),
        (
            ("schema", "collect"),
            "xdr schema collect --plan-only previews local-overlap validation.",
        ),
        (("schema", "export-opengraph"), "--include-candidates`"),
        (
            ("schema", "repair-overlay"),
            "--all-local --yes`; `xdr schema repair-overlay --reset-empty --yes`",
        ),
    ],
)
def test_preformatted_help_anchors(path, line):
    result = CliRunner().invoke(stubbed(app, []), [*path, "--help"], terminal_width=60)
    assert result.exit_code == 0
    assert line in [row.strip() for row in result.stdout.splitlines()]
