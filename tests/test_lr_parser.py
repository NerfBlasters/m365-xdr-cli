"""Live Response console-line parsing, classification and redaction."""
from __future__ import annotations

import pytest

from xdr_cli.exceptions import UsageError
from xdr_cli.live_response.catalog import merge_definitions
from xdr_cli.live_response.models import LRPlatform, LRRisk
from xdr_cli.live_response.parser import build_command, parse_console_line


def _kind(text: str, **kwargs) -> str:
    with pytest.raises(UsageError) as caught:
        parse_console_line(text, **kwargs)
    assert caught.value.exit_code == 6
    return caught.value.invalid["kind"]


@pytest.mark.parametrize("text", [
    "dir; run evil.ps1", "processes | findstr x", "dir && run x.ps1", "dir || run x",
    "dir\nrun x.ps1", "dir\rrun", "dir `run`", "dir\0", "getfile C:\\a & run x",
    "dir & & ", "dir >> o.txt",
])
def test_compound_syntax_is_rejected(text):
    assert _kind(text) == "compound_syntax"


def test_trailing_background_marker_sets_background():
    parsed = parse_console_line('getfile "C:\\a b.exe" &')
    assert parsed.background and parsed.param("path") == "C:\\a b.exe"
    assert parse_console_line("run x.ps1&").background
    assert not parse_console_line("dir").background


def test_output_redirection_is_a_local_save_and_is_not_sent():
    parsed = parse_console_line('processes > "out put.txt"')
    assert parsed.output_to == "out put.txt"
    assert parsed.console_line == "processes"
    assert parse_console_line("processes>o.txt &").output_to == "o.txt"
    assert parsed.redacted_summary()["local_output"] is True


@pytest.mark.parametrize("text", [
    "dir < x", "processes >", "processes > &", "processes > a > b", "dir > a b",
    "processes & > o.txt", "help dir > o.txt", "cls &",
])
def test_bad_redirection_and_misplaced_operators(text):
    assert _kind(text) in {"redirect", "compound_syntax", "local_only"}


@pytest.mark.parametrize("text", ['dir "C:\\x', 'dir "a"b', 'dir a"b"'])
def test_bad_quoting(text):
    assert _kind(text) in {"unbalanced_quote", "invalid_quoting"}


def test_operators_inside_quotes_stay_literal():
    parsed = parse_console_line('getfile "C:\\Users\\a;b & c|d > e.txt"')
    assert parsed.param("path") == "C:\\Users\\a;b & c|d > e.txt"
    assert parsed.risk is LRRisk.COLLECT
    assert not parsed.background and parsed.output_to is None


def test_windows_paths_keep_backslashes_and_registry_value_marker():
    parsed = parse_console_line("registry HKEY_CURRENT_USER\\Console\\\\ScreenBufferSize")
    assert parsed.param("id") == "HKEY_CURRENT_USER\\Console\\\\ScreenBufferSize"
    assert parsed.console_line == "registry HKEY_CURRENT_USER\\Console\\\\ScreenBufferSize"


@pytest.mark.parametrize("alias,verb", [
    ("GET", "getfile"), ("download", "getfile"), ("ls", "dir"), ("ff", "findfile"),
    ("tasklist", "processes"), ("reg", "registry"), ("PowerShell", "run"), ("put", "putfile"),
    ("autoruns", "persistence"), ("schtasks", "scheduledtasks"),
])
def test_aliases_resolve_before_classification(alias, verb):
    args = {"getfile": "c:\\x", "findfile": "x", "registry": "HKLM", "run": "s.ps1",
            "putfile": "s.ps1"}.get(verb, "")
    assert parse_console_line(f"{alias} {args}").verb == verb


@pytest.mark.parametrize("text,verb,risk", [
    ("remediate list", "remediate", LRRisk.READ),
    ("remediate -type LIST", "remediate", LRRisk.READ),
    ("remediate file c:\\m.exe", "remediate", LRRisk.EXECUTE),
    ("remediate -EntityType process -EntityKey 7960", "remediate", LRRisk.EXECUTE),
    ("analyze process 1234", "analyze", LRRisk.COLLECT),
    ("undo file c:\\m.exe", "undo", LRRisk.EXECUTE),
    ("putfile s.ps1 -overwrite -k", "putfile", LRRisk.PLACE),
    ("getfile c:\\x -u", "getfile", LRRisk.COLLECT),
    ("scan", "scan", LRRisk.DEVICE_ACTION),
    ("help dir", "help", LRRisk.LOCAL),
    ("library", "library", LRRisk.LOCAL),
])
def test_risk_follows_the_resolved_command_and_entity_type(text, verb, risk):
    parsed = parse_console_line(text)
    assert (parsed.verb, parsed.risk) == (verb, risk)


def test_entity_commands_require_a_type():
    assert _kind("remediate") == "missing_param"
    assert _kind("analyze file") == "missing_param"
    assert _kind("remediate bogus x") == "invalid_param"


def test_named_positional_label_and_flag_spellings_canonicalise():
    assert parse_console_line("processes -name notepad.exe").console_line == (
        "processes -name notepad.exe")
    assert parse_console_line("processes 123").console_line == "processes 123"
    assert parse_console_line("findfile -FileName a.txt").params == (("name", "a.txt"),)
    assert parse_console_line("dir -OUTPUT JSON -f").console_line == "dir -output json -full_path"
    parsed = parse_console_line("putfile s.ps1 -keep -o")
    assert parsed.flags == {"keep", "overwrite"}
    assert parsed.console_line == "putfile s.ps1 -overwrite -keep"


def test_choices_unknown_options_and_extra_arguments():
    assert _kind("connections xml") == "invalid_param"
    assert _kind("dir -recurse") == "invalid_param"
    assert _kind("persistence extra") == "invalid_param"
    assert _kind("processes -pid 1 -pid 2") == "invalid_param"
    assert _kind("getfile c:\\x -auto") == "invalid_param"
    assert _kind("findfile") == "missing_param"
    assert _kind("fileinfo -path") == "missing_param"
    assert _kind("") == "missing_command"


@pytest.mark.parametrize("text", [
    "run script.ps1 -APITOKEN_SENTINEL value",
    "dir -Apitoken_Sentinel",
    "getfile c:\\x -apitoken_sentinel=1",
])
def test_unknown_option_errors_never_echo_the_token(text):
    from xdr_cli.exceptions import format_error_json

    with pytest.raises(UsageError) as caught:
        parse_console_line(text)
    assert caught.value.invalid["kind"] == "invalid_param"
    assert "position" in caught.value.invalid
    rendered = format_error_json(caught.value).lower()
    assert "apitoken" not in rendered and "sentinel" not in rendered


def test_unknown_command_suggests_without_echoing():
    with pytest.raises(UsageError) as caught:
        parse_console_line("proceses")
    assert caught.value.invalid["kind"] == "unknown_command"
    assert {"command": "processes"} in caught.value.suggestions
    assert "proceses" not in caught.value.message


def test_script_parameters_forbidden_chars_and_value_free_errors():
    ok = parse_console_line('run get.ps1 -parameters "-processName Registry"')
    assert ok.console_line == 'run get.ps1 "-processName Registry"'
    assert ok.params == (("id", "get.ps1"), ("parameters", "-processName Registry"))
    with pytest.raises(UsageError) as caught:
        parse_console_line('run get.ps1 -ScriptParameters "-p secret$value"')
    assert caught.value.invalid["kind"] == "forbidden_parameter_chars"
    assert "secret" not in caught.value.message


@pytest.mark.parametrize("text,platform", [
    ("registry HKLM\\x", LRPlatform.LINUX), ("isolate", LRPlatform.WINDOWS),
    ("collect", LRPlatform.WINDOWS), ("undo file x", LRPlatform.MACOS),
])
def test_platform_applicability(text, platform):
    assert _kind(text, platform=platform) == "platform"


def test_repr_and_summary_are_value_free():
    parsed = parse_console_line('run get.ps1 -parameters "-token hunter2"')
    assert "hunter2" not in repr(parsed)
    assert parsed.redacted_summary() == {
        "verb": "run", "risk": "execute", "params": ["id", "parameters"], "flags": [],
        "background": False, "local_output": False,
    }
    assert parsed.raw_line == 'run get.ps1 -parameters "-token hunter2"'


def test_build_command_uses_the_same_validator():
    built = build_command("getfile", params={"path": "C:\\a b.txt"}, background=True)
    assert built.console_line == 'getfile "C:\\a b.txt"'
    assert built.raw_line == 'getfile "C:\\a b.txt" &'
    reparsed = parse_console_line(built.raw_line)
    assert (reparsed.spec, reparsed.params, reparsed.background) == (
        built.spec, built.params, True)
    with pytest.raises(UsageError):
        build_command("run", params={"id": "x.ps1", "parameters": "a;b"})
    with pytest.raises(UsageError):
        build_command("registry", params={"id": "HKLM"}, platform=LRPlatform.MACOS)
    with pytest.raises(UsageError):
        build_command("getfile", params={"path": "x", "bogus": "y"})


def test_session_definitions_govern_syntax_but_not_risk():
    definitions = [
        {"command_definition_id": "getfile", "default_alias": "getfile",
         "aliases": ["grab"], "params": [
             {"param_id": "path", "name": "path", "optional": False, "is_path": True,
              "isHidden": False, "is_pii": True, "valid_values": None}],
         "flags": [{"flag_id": "auto", "short_name": "a", "long_name": "auto"}]},
        {"command_definition_id": "memorysnap", "default_alias": "memorysnap",
         "aliases": None, "params": None, "flags": None},
        {"command_definition_id": "processdump", "default_alias": "processdump",
         "aliases": ["pdump"], "params": [
             {"param_id": "pid", "name": "pid", "optional": False, "is_path": False,
              "isHidden": False, "is_pii": False, "valid_values": None}], "flags": None},
        {"command_definition_id": "connect", "default_alias": "connect",
         "aliases": None, "params": None, "flags": None},
    ]
    commands, unclassified = merge_definitions(definitions)
    assert unclassified == ("memorysnap",)
    assert parse_console_line("pdump 42", commands=commands).risk is LRRisk.COLLECT
    parsed = parse_console_line("grab c:\\x -a", commands=commands)
    assert (parsed.verb, parsed.flags, parsed.risk) == ("getfile", {"auto"}, LRRisk.COLLECT)
    with pytest.raises(UsageError) as missing:
        parse_console_line("getfile", commands=commands)
    assert missing.value.invalid["kind"] == "missing_param"
    # Not offered by this session (server definitions omit it) and unclassified.
    assert _kind("dir", commands=commands) == "unknown_command"
    assert _kind("memorysnap", commands=commands) == "unknown_command"
    assert parse_console_line("help", commands=commands).risk is LRRisk.LOCAL
    assert parse_console_line("connect", commands=commands).risk is LRRisk.LOCAL
