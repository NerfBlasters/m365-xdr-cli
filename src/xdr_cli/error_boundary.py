"""Machine-readable command-line error handling."""

from __future__ import annotations

import difflib
import re
import sys
from collections.abc import Sequence
from typing import Any

import click
from typer.core import TyperGroup

from xdr_cli.exceptions import UsageError, XDRError, format_error_json

_REMOVED_OPTIONS: dict[str, dict[str, str]] = {
    "--fields": {
        "reason": "removed_option",
        "message": (
            "Results are now saved as JSONL. Inspect columns with "
            "'xdr results shape <run-id>' and filter with rg or jq -s."
        ),
        "confidence": "exact",
    },
    "--jq": {
        "reason": "removed_option",
        "message": (
            "Native JMESPath projection was removed. Filter the saved JSONL "
            "artifact with rg or jq -s."
        ),
        "confidence": "exact",
    },
    "--limit": {
        "reason": "removed_option",
        "message": (
            "Hunt output is no longer discarded locally. Limit at the source "
            "with KQL (for example, '| take 100') or filter the saved artifact."
        ),
        "confidence": "exact",
    },
}


def _command_path(ctx: click.Context | None) -> str:
    if ctx is None:
        return "xdr"
    parts = ctx.command_path.split()
    if "xdr_cli" in parts:
        return " ".join(["xdr", *parts[parts.index("xdr_cli") + 1 :]])
    return " ".join(["xdr", *parts[1:]]) if parts else "xdr"


def _remove_option(argv: list[str], option: str) -> list[str]:
    """Remove one legacy option and its value from an argv suggestion."""

    corrected: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == option:
            # Legacy projection options accepted one value. Drop that value
            # only when one is visibly present; never consume the next valid
            # option (for example ``--jq --raw``).
            index += 1
            if index < len(argv) and not argv[index].startswith("-"):
                index += 1
            continue
        if token.startswith(f"{option}="):
            index += 1
            continue
        corrected.append(token)
        index += 1
    return corrected


def _option_names(ctx: click.Context | None) -> list[str]:
    if ctx is None:
        return []
    names: list[str] = []
    for param in ctx.command.get_params(ctx):
        if isinstance(param, click.Option):
            names.extend(param.opts)
            names.extend(param.secondary_opts)
    return sorted(set(names))


def usage_error_from_click(
    exc: click.UsageError,
    argv: Sequence[str] | None = None,
) -> UsageError:
    """Convert Click's human-only usage error into the stable v1 error shape."""

    raw_argv = list(argv or [])
    message = exc.format_message()
    invalid: dict[str, Any] | None = None
    allowed: list[str] = []
    suggestions: list[dict[str, Any]] = []
    corrected_argv: list[str] | None = None
    code = "CLI_USAGE_ERROR"

    option_match = re.search(
        r"(?:No such option|no such option)\s*:?\s*['\"]?([^'\" .]+)",
        message,
        re.I,
    )
    command_match = re.search(r"No such command ['\"]([^'\"]+)['\"]", message, re.I)
    argument_match = re.search(r"Missing (?:option|argument) ['\"]?([^'\".]+)", message, re.I)

    if isinstance(exc, click.BadParameter):
        param = exc.param
        value_match = re.search(r"['\"]([^'\"]+)['\"]", message)
        value = value_match.group(1) if value_match else message
        invalid = {
            "kind": "option" if isinstance(param, click.Option) else "argument",
            "value": value,
        }
        if param is not None and isinstance(param.type, click.Choice):
            code = "CLI_INVALID_ENUM"
            allowed = [str(choice) for choice in param.type.choices]
        else:
            code = "CLI_INVALID_VALUE"
    elif option_match:
        value = option_match.group(1).rstrip(".")
        invalid = {"kind": "option", "value": value}
        if value in _REMOVED_OPTIONS:
            code = "CLI_REMOVED_OPTION"
            suggestions.append(_REMOVED_OPTIONS[value])
            corrected_argv = ["xdr", *_remove_option(raw_argv, value)]
        else:
            code = "CLI_UNKNOWN_OPTION"
            allowed = _option_names(exc.ctx)
            close = difflib.get_close_matches(value, allowed, n=3, cutoff=0.5)
            suggestions.extend(
                {
                    "reason": "nearest_option",
                    "message": candidate,
                    "confidence": "heuristic",
                }
                for candidate in close
            )
    elif command_match:
        value = command_match.group(1)
        invalid = {"kind": "command", "value": value}
        code = "CLI_UNKNOWN_COMMAND"
        command = exc.ctx.command if exc.ctx else None
        if isinstance(command, click.Group):
            allowed = sorted(command.commands)
            close = difflib.get_close_matches(value, allowed, n=3, cutoff=0.5)
            suggestions.extend(
                {
                    "reason": "nearest_command",
                    "message": candidate,
                    "confidence": "heuristic",
                }
                for candidate in close
            )
    elif argument_match:
        invalid = {"kind": "missing_value", "value": argument_match.group(1).strip()}
        code = "CLI_MISSING_VALUE"
    elif "invalid value" in message.lower():
        code = "CLI_INVALID_VALUE"

    error = UsageError(
        message,
        invalid=invalid,
        allowed=allowed,
        suggestions=suggestions,
        corrected_argv=corrected_argv,
        help_command=f"{_command_path(exc.ctx)} --help",
        original={"type": type(exc).__name__, "message": message},
    )
    error.error_code = code
    return error


class StructuredTyperGroup(TyperGroup):
    """Root Click group that makes parse and domain errors one-line JSON."""

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        windows_expand_args: bool = True,
        **extra: Any,
    ) -> Any:
        effective_args = list(args) if args is not None else list(sys.argv[1:])
        try:
            result = super().main(
                args=args,
                prog_name=prog_name,
                complete_var=complete_var,
                standalone_mode=False,
                windows_expand_args=windows_expand_args,
                **extra,
            )
        except click.UsageError as exc:
            # Typer has already rendered the requested group help for this
            # sentinel. Treat it as successful discovery rather than a usage
            # failure (and, critically, do not append a JSON error line).
            if isinstance(exc, click.exceptions.NoArgsIsHelpError):
                if standalone_mode:
                    raise SystemExit(0) from None
                return None
            error = usage_error_from_click(exc, effective_args)
            click.echo(format_error_json(error), file=sys.stdout)
            if standalone_mode:
                raise SystemExit(int(error.exit_code)) from None
            raise error from exc
        except XDRError as error:
            click.echo(format_error_json(error), file=sys.stdout)
            if standalone_mode:
                raise SystemExit(int(error.exit_code)) from None
            raise
        except Exception as exc:
            error = XDRError(
                "An unexpected internal error reached the CLI boundary.",
                help_command="xdr --help",
                original={"type": type(exc).__name__, "message": str(exc)},
            )
            click.echo(format_error_json(error), file=sys.stdout)
            if standalone_mode:
                raise SystemExit(int(error.exit_code)) from None
            raise error from exc

        # Click converts explicit ctx.exit()/typer.Exit into an integer when
        # standalone_mode=False. Restore normal standalone process semantics.
        if standalone_mode:
            exit_code = result if isinstance(result, int) else 0
            if exit_code:
                error = XDRError(
                    "Command failed before producing a structured domain error; "
                    "see stderr for legacy context.",
                    help_command="xdr --help",
                    original={"type": "LegacyCommandExit", "exit_code": exit_code},
                )
                error.error_code = "CLI_COMMAND_FAILED"
                error.exit_code = exit_code
                click.echo(format_error_json(error), file=sys.stdout)
            raise SystemExit(exit_code)
        return result
