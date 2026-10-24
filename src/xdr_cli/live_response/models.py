"""Typed Live Response values shared by the catalog, parser, CLI and backends.

Server-native states are preserved verbatim; nothing here maps request
acceptance to completion. Raw server payloads can hold command text and
download tokens, so they never appear in ``repr``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class LRPlatform(StrEnum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"


ALL_PLATFORMS = frozenset(LRPlatform)


class LRRisk(StrEnum):
    LOCAL = "local"                  # answered or refused locally; no request is sent
    READ = "read"                    # remote job that does not change the device
    COLLECT = "collect"              # data leaves the device or is submitted for analysis
    PLACE = "place"                  # a library file is written onto the device
    EXECUTE = "execute"              # script execution, remediation or undo
    DEVICE_ACTION = "device-action"  # isolate/release/scan issued from the console
    LIBRARY_WRITE = "library-write"  # tenant library upload/update/delete


# Classes that require confirmation, --yes or --dry-run before submission.
CONFIRM_RISKS = frozenset(LRRisk) - {LRRisk.LOCAL, LRRisk.READ}


@dataclass(frozen=True)
class LRParamSpec:
    # Server ``param_id``: the key sent in a command body and accepted as ``-param_id``.
    param_id: str
    required: bool = False
    choices: tuple[str, ...] | None = None
    # Server display ``name`` (e.g. ``FileName``); also accepted as ``-name``.
    label: str | None = None
    is_path: bool = False


@dataclass(frozen=True)
class LRFlagSpec:
    flag_id: str
    short_name: str | None = None
    long_name: str | None = None

    @property
    def spellings(self) -> frozenset[str]:
        return frozenset(
            name.lower() for name in (self.flag_id, self.short_name, self.long_name) if name
        )


@dataclass(frozen=True)
class LRCommandSpec:
    # Server ``command_definition_id``; ``default_alias`` is assumed equal.
    name: str
    risk: LRRisk
    platforms: frozenset[LRPlatform]
    evidence: str
    summary: str
    aliases: tuple[str, ...] = ()
    # Positional order; each may also be given by name as ``-param_id value``.
    params: tuple[LRParamSpec, ...] = ()
    flags: tuple[LRFlagSpec, ...] = ()
    # Per-value risk overrides, e.g. ``remediate -type list`` is a read.
    risk_by_value: tuple[tuple[str, str, LRRisk], ...] = ()
    # Official runliveresponse command type, when the one-shot API supports it.
    official_type: str | None = None
    # Local-only reason or the CLI verb that replaces a console-only command.
    local_note: str | None = None
    advanced: bool = False

    def risk_for(self, values: dict[str, str]) -> LRRisk:
        for param_id, value, risk in self.risk_by_value:
            if values.get(param_id, "").lower() == value:
                return risk
        return self.risk


@dataclass(frozen=True, repr=False)
class ParsedCommand:
    spec: LRCommandSpec
    # Ordered ``(param_id, value)`` pairs, ready for the definition's params body.
    params: tuple[tuple[str, str], ...]
    # Server ``flag_id`` values.
    flags: frozenset[str]
    risk: LRRisk
    # Canonical single line built from the parsed values.
    console_line: str
    # Operator text verbatim (for raw_command_line); never logged or echoed.
    raw_line: str = ""
    # Trailing ``&``: the backend maps this to its background mode.
    background: bool = False
    # ``> PATH``: local save of the final rendered output; never sent.
    output_to: str | None = None

    @property
    def verb(self) -> str:
        return self.spec.name

    def param(self, param_id: str) -> str | None:
        return next((value for key, value in self.params if key == param_id), None)

    def redacted_summary(self) -> dict[str, Any]:
        """Value-free description safe for audit, session and error records."""
        return {
            "verb": self.verb,
            "risk": self.risk.value,
            "params": [key for key, _ in self.params],
            "flags": sorted(self.flags),
            "background": self.background,
            "local_output": self.output_to is not None,
        }

    def __repr__(self) -> str:
        return f"ParsedCommand(verb={self.verb!r}, risk={self.risk.value!r})"


@dataclass(frozen=True)
class LRSession:
    session_id: str
    machine_id: str
    state: str
    platform: LRPlatform | None = None
    created_by: str | None = None
    created_at: str | None = None
    raw: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class LRCommandState:
    command_id: str
    machine_id: str
    verb: str
    state: str
    session_id: str | None = None
    terminal: bool | None = None
    has_output: bool | None = None
    has_download: bool | None = None
    # Number of command errors the service reported; a completed command can
    # still carry errors. None when the response does not say.
    error_count: int | None = None
    raw: dict = field(default_factory=dict, repr=False)
    # Read-only status stays usable when local cwd bookkeeping cannot be updated.
    directory_tracking: str | None = None

    @property
    def succeeded(self) -> bool:
        """Completed with no reported errors: safe to download or save output."""
        return self.terminal is True and self.state == "completed" and not self.error_count


@dataclass(frozen=True)
class LRLibraryFile:
    name: str
    size: int | None = None
    sha256: str | None = None
    description: str | None = None
    has_parameters: bool | None = None
    parameters_description: str | None = None
    created_by: str | None = None
    last_updated: str | None = None
    raw: dict = field(default_factory=dict, repr=False)
