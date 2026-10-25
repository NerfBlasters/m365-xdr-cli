"""Validate one Live Response console line against the command catalog.

Exactly one command per submission. A trailing ``&`` requests background
mode and a final ``> FILE`` saves the rendered output locally, as in the
portal console; any other operator outside double quotes is rejected so the
risk class of a submission is the class of its single resolved command.
Text inside double quotes is literal and backslashes are never escapes, so
Windows paths and registry keys pass unchanged. Error messages name
positions and kinds only; they never repeat submitted values.
"""
from __future__ import annotations

import difflib
from collections.abc import Mapping
from dataclasses import dataclass

from xdr_cli.exceptions import UsageError
from xdr_cli.live_response.catalog import PINNED
from xdr_cli.live_response.models import LRCommandSpec, LRPlatform, LRRisk, ParsedCommand

_ALWAYS_FORBIDDEN = {"\n": "newline", "\r": "carriage return", "\0": "NUL", "`": "backtick"}
# Other line and page separators a remote parser might honour, even inside quotes.
_SEPARATORS = frozenset("\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")
# Characters that need quoting in the canonical line so it re-parses identically.
_QUOTE_CHARS = frozenset(";|&<>")
_COMPOUND = {";", "|"}
_INPUT_REDIRECT = {"<"}
# Background marker and local output redirection; separate tokens even unspaced.
_OPERATORS = {"&", ">"}
# Characters the service forbids inside script parameters.
_SCRIPT_PARAMETER_FORBIDDEN = frozenset(";&|!$")
_HELP = "xdr device live-response catalog"


@dataclass(frozen=True)
class _Token:
    value: str
    quoted: bool
    position: int
    operator: bool = False


def _fail(kind: str, message: str, *, allowed: list[str] | None = None,
          suggestions: list[dict] | None = None, **details) -> UsageError:
    return UsageError(message, invalid={"kind": kind, **details}, allowed=allowed,
                      suggestions=suggestions, help_command=_HELP)


def _compound(index: int) -> UsageError:
    return _fail("compound_syntax",
                 f"Only one command per submission (operator at position {index}).",
                 position=index)


def tokenize(text: str) -> list[_Token]:
    for char, label in _ALWAYS_FORBIDDEN.items():
        if char in text:
            raise _fail("compound_syntax", f"Console text must not contain a {label}.")
    if any(char in _SEPARATORS or (ord(char) < 0x20 and char != "\t") for char in text):
        raise _fail("compound_syntax", "Console text must not contain control characters.")
    tokens: list[_Token] = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == '"':
            end = text.find('"', index + 1)
            if end < 0:
                raise _fail("unbalanced_quote", f"Unclosed double quote at position {index}.",
                            position=index)
            tokens.append(_Token(text[index + 1:end], True, index))
            index = end + 1
            if index < length and not text[index].isspace() and text[index] not in _OPERATORS:
                raise _fail("invalid_quoting",
                            f"A quoted value must be followed by whitespace (position {index}).",
                            position=index)
            continue
        if char in _OPERATORS:
            if text.startswith(char * 2, index):
                raise _compound(index)
            tokens.append(_Token(char, False, index, operator=True))
            index += 1
            continue
        start = index
        while index < length and not text[index].isspace() and text[index] not in '"&>':
            if text[index] in _COMPOUND:
                raise _compound(index)
            if text[index] in _INPUT_REDIRECT:
                raise _fail("redirect", f"Input redirection is not supported (position {index}).",
                            position=index)
            index += 1
        if index < length and text[index] == '"':
            raise _fail("invalid_quoting",
                        f"A quote must start a separate value (position {index}).",
                        position=index)
        tokens.append(_Token(text[start:index], False, start))
    return tokens


def _split_suffix(tokens: list[_Token]) -> tuple[list[_Token], str | None, bool]:
    """Peel the optional ``> FILE`` local redirection and trailing ``&``."""
    background = bool(tokens) and tokens[-1].operator and tokens[-1].value == "&"
    if background:
        tokens = tokens[:-1]
    output_to = None
    if len(tokens) >= 2 and tokens[-2].operator and tokens[-2].value == ">":
        target = tokens[-1]
        if target.operator:
            raise _fail("redirect", "Output redirection needs a local file name.",
                        position=target.position)
        output_to, tokens = target.value, tokens[:-2]
    for token in tokens:
        if token.operator:
            kind = "compound_syntax" if token.value == "&" else "redirect"
            raise _fail(kind, f"'{token.value}' is only allowed at the end of the command "
                              f"(position {token.position}).", position=token.position)
    return tokens, output_to, background


def _is_option(token: _Token) -> bool:
    return not token.quoted and len(token.value) > 1 and token.value.startswith("-")


def _bind(spec: LRCommandSpec, tokens: list[_Token]) -> tuple[dict[str, str], set[str]]:
    by_option: dict[str, str] = {}
    for param in spec.params:
        by_option[param.param_id.lower()] = param.param_id
        if param.label:
            by_option.setdefault(param.label.lower(), param.param_id)
    by_flag = {spelling: flag.flag_id for flag in spec.flags for spelling in flag.spellings}
    values: dict[str, str] = {}
    flags: set[str] = set()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _is_option(token):
            option = token.value[1:].lower()
            if option in by_flag:
                flags.add(by_flag[option])
            elif option in by_option:
                param_id = by_option[option]
                if index + 1 >= len(tokens):
                    raise _fail("missing_param", f"-{param_id} needs a value.", param=param_id)
                if param_id in values:
                    raise _fail("invalid_param", f"-{param_id} given more than once.",
                                param=param_id)
                index += 1
                values[param_id] = tokens[index].value
            else:
                # The unrecognised token may itself be sensitive: report only its position.
                raise _fail("invalid_param",
                            f"'{spec.name}' has no such option (position {token.position}).",
                            position=token.position, allowed=sorted({*by_option, *by_flag}))
        else:
            slot = next((p for p in spec.params if p.param_id not in values), None)
            if slot is None:
                raise _fail("invalid_param", f"Unexpected argument at position {token.position}.",
                            position=token.position)
            values[slot.param_id] = token.value
        index += 1
    return values, flags


def _validate(spec: LRCommandSpec, values: dict[str, str]) -> None:
    for param in spec.params:
        value = values.get(param.param_id)
        if value is None:
            if param.required:
                raise _fail("missing_param", f"'{spec.name}' requires {param.param_id}.",
                            param=param.param_id)
            continue
        if value == "":
            raise _fail("invalid_param", f"{param.param_id} must not be empty.",
                        param=param.param_id)
        if param.choices is not None:
            # Match case-insensitively but keep the definition's own spelling.
            canonical = next((c for c in param.choices if c.lower() == value.lower()), None)
            if canonical is None:
                raise _fail("invalid_param", f"{param.param_id} must be one of the allowed values.",
                            param=param.param_id, allowed=list(param.choices))
            values[param.param_id] = canonical
    if spec.name == "run" and _SCRIPT_PARAMETER_FORBIDDEN & set(values.get("parameters", "")):
        raise _fail("forbidden_parameter_chars",
                    "Script parameters must not contain ; & | ! or $.", param="parameters")


def _quote(value: str) -> str:
    if (value and not any(char.isspace() or char in _QUOTE_CHARS for char in value)
            and value[0] != "-"):
        return value
    return f'"{value}"'


def _canonical(spec: LRCommandSpec, values: dict[str, str], flags: set[str]) -> str:
    parts = [spec.name]
    positional = True
    for param in spec.params:
        value = values.get(param.param_id)
        if value is None:
            positional = False
        elif positional:
            parts.append(_quote(value))
        else:
            parts.append(f"-{param.param_id} {_quote(value)}")
    parts.extend(f"-{flag.flag_id}" for flag in spec.flags if flag.flag_id in flags)
    return " ".join(parts)


def _finish(spec: LRCommandSpec, values: dict[str, str], flags: set[str],
            platform: LRPlatform | None, *, raw_line: str, output_to: str | None,
            background: bool) -> ParsedCommand:
    _validate(spec, values)
    if platform is not None and platform not in spec.platforms:
        raise _fail("platform", f"'{spec.name}' is not available on {platform.value}.",
                    allowed=sorted(p.value for p in spec.platforms))
    if spec.risk is LRRisk.LOCAL and (output_to is not None or background):
        raise _fail("local_only", f"'{spec.name}' runs locally and takes no '>' or '&'.")
    ordered = tuple((p.param_id, values[p.param_id]) for p in spec.params
                    if p.param_id in values)
    return ParsedCommand(
        spec, ordered, frozenset(flags), spec.risk_for(values), _canonical(spec, values, flags),
        raw_line=raw_line, background=background, output_to=output_to,
    )


def parse_console_line(
    text: str, *, platform: LRPlatform | None = None,
    commands: Mapping[str, LRCommandSpec] | None = None,
) -> ParsedCommand:
    """Parse operator console text.

    ``commands`` is a session's merged alias index from ``merge_definitions``;
    the pinned catalog is used when it is absent.
    """
    index = PINNED if commands is None else commands
    tokens, output_to, background = _split_suffix(tokenize(text))
    if not tokens:
        raise _fail("missing_command", "No console command was given.")
    head = tokens[0]
    if head.quoted:
        raise _fail("unknown_command", "The command name must not be quoted.")
    spec = index.get(head.value.lower())
    if spec is None:
        close = difflib.get_close_matches(head.value.lower(), list(index), n=3)
        raise _fail("unknown_command", "Unknown Live Response command for this session.",
                    suggestions=[{"command": match} for match in close],
                    allowed=sorted({s.name for s in index.values()}))
    values, flags = _bind(spec, tokens[1:])
    return _finish(spec, values, flags, platform, raw_line=text.strip(),
                   output_to=output_to, background=background)


def build_command(
    verb: str, *, params: Mapping[str, str | None] | None = None,
    flags: frozenset[str] = frozenset(), platform: LRPlatform | None = None,
    background: bool = False, commands: Mapping[str, LRCommandSpec] | None = None,
) -> ParsedCommand:
    """Build a command from structured CLI options through the same validator."""
    spec = (PINNED if commands is None else commands).get(verb)
    if spec is None or spec.name != verb:
        raise _fail("unknown_command", "Unknown Live Response command for this session.")
    values = {key: value for key, value in (params or {}).items() if value is not None}
    unknown = ({*values} - {p.param_id for p in spec.params}) | (
        flags - {flag.flag_id for flag in spec.flags})
    if unknown:
        raise _fail("invalid_param", f"'{spec.name}' has no {', '.join(sorted(unknown))}.")
    canonical = _canonical(spec, values, set(flags))
    return _finish(spec, values, set(flags), platform, output_to=None, background=background,
                   raw_line=canonical + (" &" if background else ""))
