"""Value and dispatch regressions for the framework migration."""

from enum import Enum

import click
import pytest
from click.testing import CliRunner

from xdr_cli.cli_params import EnumValueChoice, optional_multiple
from xdr_cli.main import app, _install_leaf_hook
from xdr_cli.error_boundary import StructuredGroup
from tests.test_cli_contract import stubbed


class Backend(Enum):
    COOKIE = "portal-cookie"
    OFFICIAL = "official"


@pytest.mark.parametrize("value", ["portal-cookie", "PORTAL-COOKIE", Backend.COOKIE])
def test_enum_returns_member_by_value(value):
    choice = EnumValueChoice(Backend, case_sensitive=False)
    assert choice.convert(value, None, None) is Backend.COOKIE


def test_enum_rejects_name_and_displays_values():
    choice = EnumValueChoice(Backend)
    with pytest.raises(click.BadParameter, match="'portal-cookie', 'official'"):
        choice.convert("COOKIE", None, None)
    assert choice.get_metavar(
        click.Option(["--backend"]), click.Context(click.Command("test"))
    ) == ("[portal-cookie|official]")


@pytest.mark.parametrize(
    "args, expected",
    [
        ([], None),
        (["--item", ""], [""]),
        (["--item", "a", "--item", "b"], ["a", "b"]),
    ],
)
def test_optional_multiple_preserves_omitted_empty_and_repeated(args, expected):
    captured = []

    @click.command()
    @click.option("--item", multiple=True, callback=optional_multiple)
    def command(item):
        captured.append(item)

    assert CliRunner().invoke(command, args).exit_code == 0
    assert captured == [expected]


@pytest.mark.parametrize(
    "args, expected",
    [
        ([], None),
        (["--quiet"], True),
        (["--no-quiet"], False),
        (["-q"], True),
        (["--quiet", "--no-quiet"], False),
    ],
)
def test_root_tristate_binding(args, expected):
    captured = []
    command = stubbed(app, captured)
    result = CliRunner().invoke(command, [*args, "domains", "list"])
    assert result.exit_code == 0, result.output
    assert captured[0]["values"]["quiet"] is expected


def test_backend_binding_uses_value_not_member_name():
    captured = []
    command = stubbed(app, captured)
    result = CliRunner().invoke(command, ["--backend", "portal-cookie", "domains", "list"])
    assert result.exit_code == 0, result.output
    assert captured[0]["values"]["backend"] == {"enum": "APIBackend", "value": "portal-cookie"}


@pytest.mark.parametrize(
    "args, expected",
    [([], "synthetic-env"), (["--refresh-token", "synthetic-arg"], "synthetic-arg")],
)
def test_envvar_and_explicit_value_precedence(args, expected):
    captured = []
    command = stubbed(app, captured)
    result = CliRunner().invoke(
        command, ["device", "timeline", "sample", *args], env={"MDE_REFRESH_TOKEN": "synthetic-env"}
    )
    assert result.exit_code == 0, result.output
    assert captured[-1]["values"]["refresh_token"] == expected


def test_help_and_version_bypass_config(monkeypatch):
    def forbidden():
        raise AssertionError("eager discovery must not load configuration")

    monkeypatch.setattr("xdr_cli.main.load_config", forbidden)
    for args in (["--help"], ["--version"]):
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, result.output


def test_removed_completion_flags_are_usage_errors():
    for flag in ("--install-completion", "--show-completion"):
        result = CliRunner().invoke(app, [flag])
        assert result.exit_code == 6
        assert "CLI_UNKNOWN_OPTION" in result.stdout


def test_command_hook_installation_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr("xdr_cli.main._capture_chain_from_leaf", lambda: calls.append("capture"))

    @click.group()
    def root():
        pass

    @root.command()
    def leaf():
        calls.append("body")

    _install_leaf_hook(root)
    _install_leaf_hook(root)
    for _ in range(2):
        assert CliRunner().invoke(root, ["leaf"]).exit_code == 0
    assert calls == ["capture", "body", "capture", "body"]


def test_standalone_and_embedded_interrupt_exit():
    @click.command(cls=StructuredGroup, invoke_without_command=True)
    def command():
        raise KeyboardInterrupt()

    result = CliRunner().invoke(command)
    assert result.exit_code == 130
    import json

    lines = result.stdout.splitlines()
    assert len(lines) == 1
    error = json.loads(lines[0])["error"]
    assert error["code"] == "CLI_COMMAND_FAILED"
    assert error["exit_code"] == 130
    assert command.main([], standalone_mode=False) == 130
