"""Pinned Live Response console command catalog.

Command ids, aliases, parameter ids and flags mirror the portal's
``get_command_definitions`` response; platform applicability comes from
Microsoft's documented command tables. Risk is a local, conservative
classification and is never taken from the server. When a session's live
definitions are available, ``merge_definitions`` uses them for syntax while
keeping the pinned risk.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import replace

from xdr_cli.live_response.models import (
    ALL_PLATFORMS,
    LRCommandSpec,
    LRFlagSpec,
    LRParamSpec,
    LRPlatform,
    LRRisk,
)

DOCS = "https://learn.microsoft.com/en-us/defender-endpoint/live-response"
# Sanitized definition metadata observed from a V3 Windows session on 2026-10-24.
PORTAL = "portal get_command_definitions (V3, Windows session, 2026-10-24)"

# Commands the shipped portal console knows but this tenant's definitions did not offer.
FRONTEND = "portal live-response.js 20261021.1 (feature-gated)"

# Portal library file-name policy (live-response.js 20261021.1).
LIBRARY_NAME_PATTERN = re.compile(r"^[\w][\w. -]*[\w]$")

_WIN = frozenset({LRPlatform.WINDOWS})
_MAC = frozenset({LRPlatform.MACOS})
_POSIX = frozenset({LRPlatform.MACOS, LRPlatform.LINUX})
_ALL = ALL_PLATFORMS

_OUTPUT = LRParamSpec("output", choices=("json", "table"))


def _param(param_id: str, *, required: bool = False, label: str | None = None,
           choices: tuple[str, ...] | None = None, is_path: bool = False) -> LRParamSpec:
    return LRParamSpec(param_id, required=required, choices=choices, label=label, is_path=is_path)


def _local(name: str, summary: str, note: str, *params: LRParamSpec,
           evidence: str = DOCS) -> LRCommandSpec:
    return LRCommandSpec(name, LRRisk.LOCAL, _ALL, evidence, summary, params=params,
                         local_note=note)


def _read(name: str, platforms, summary: str, *params: LRParamSpec, aliases=(),
          flags=()) -> LRCommandSpec:
    return LRCommandSpec(name, LRRisk.READ, platforms, PORTAL, summary, aliases=tuple(aliases),
                         params=params, flags=tuple(flags))


_ENTITY_KEY = "EntityKey"

_SPECS: tuple[LRCommandSpec, ...] = (
    # --- Console behaviour with a local or dedicated CLI equivalent; never sent. ---
    _local("help", "Show help for a command.",
           "Answered from the local catalog: xdr device live-response catalog",
           _param("command")),
    _local("cls", "Clear the console screen.", "Console presentation only; not a device action."),
    _local("trace", "Set console logging mode to debug.",
           "Console presentation only; not a device action."),
    _local("connect", "Initiate a session.", "Use: xdr device live-response connect DEVICE",
           evidence=PORTAL),
    _local("jobs", "Show running jobs.", "Use: xdr device live-response history SESSION"),
    _local("fg", "Bring a job to the foreground.",
           "Use: xdr device live-response status SESSION COMMAND_ID --wait SECONDS",
           _param("command_id", required=True, label="CommandId"), evidence=PORTAL),
    _local("status", "Show a command's status and output.",
           "Use: xdr device live-response status SESSION COMMAND_ID",
           _param("command_id", required=True, label="CommandId"), evidence=PORTAL),
    _local("library", "List or delete library files.",
           "Use: xdr device live-response library list|delete NAME"),
    # --- Basic inspection: remote jobs that do not change the device. ---
    _read("cd", _ALL, "Change the session's current directory.",
          _param("id", required=True, is_path=True)),
    _read("connections", _WIN, "Show active connections.", _OUTPUT,
          aliases=("tcpview", "get-connection", "get-connections", "connection")),
    _read("dir", _ALL, "List files and subdirectories.", _param("path", is_path=True), _OUTPUT,
          aliases=("ls",),
          flags=(LRFlagSpec("full_path", "f", "full_path"),
                 LRFlagSpec("path_only", "p", "path_only"))),
    _read("drivers", _WIN, "Show installed drivers.", _param("name"), _OUTPUT,
          aliases=("driver", "get-drivers", "get-driver")),
    _read("fileinfo", _ALL, "Get information about a file.", _param("path", is_path=True),
          aliases=("file",)),
    _read("findfile", _ALL, "Locate files by name.",
          _param("name", required=True, label="FileName"),
          aliases=("ff", "find-files", "find-file", "findfiles")),
    _read("persistence", _WIN, "Show known persistence methods.",
          aliases=("autoruns", "persistencemethod", "persistencemethods")),
    _read("processes", _ALL, "Show running processes.", _param("pid"), _param("name"), _OUTPUT,
          aliases=("process", "get-process", "get-processes", "tasklist")),
    _read("registry", _WIN, "Show registry keys and values.", _param("id", required=True),
          _OUTPUT, aliases=("reg", "get-registry")),
    _read("scheduledtasks", _WIN, "Show scheduled tasks.",
          _param("id", label="ScheduledTasksPath"), _OUTPUT,
          aliases=("schtasks", "taskschd", "get-scheduledtask", "get-scheduledtasks",
                   "scheduledtask")),
    _read("services", _WIN, "Show services.", _param("name"), _OUTPUT,
          aliases=("get-services", "get-service", "service")),
    _read("startupfolders", _WIN, "Show files in startup folders.",
          _param("path", label="FilePathInStartupFolder"),
          _param("name", label="FileNameInStartupFolder"), _OUTPUT,
          aliases=("startupfolder", "startup-folder", "startup-folders")),
    # --- Collection: data leaves the device. ---
    LRCommandSpec("getfile", LRRisk.COLLECT, _ALL, PORTAL, "Download a file from the device.",
                  aliases=("download", "get", "download-file", "downloadfile"),
                  params=(_param("path", is_path=True),),
                  flags=(LRFlagSpec("upload", "u", "upload_to_cloud"),),
                  official_type="GetFile"),
    LRCommandSpec("analyze", LRRisk.COLLECT, _WIN, PORTAL,
                  "Analyze a file or process with incrimination engines.",
                  params=(_param("type", required=True, label="EntityType",
                                 choices=("file", "process")),
                          _param("id", required=True, label=_ENTITY_KEY)),
                  advanced=True),
    LRCommandSpec("collect", LRRisk.COLLECT, _POSIX, DOCS, "Collect a forensics package.",
                  advanced=True),
    # Parameters and platforms come from the session's definitions when offered.
    LRCommandSpec("processdump", LRRisk.COLLECT, _ALL, FRONTEND,
                  "Collect a process memory dump.", aliases=("pdump",), advanced=True),
    # --- Placement and execution. ---
    LRCommandSpec("putfile", LRRisk.PLACE, _ALL, PORTAL, "Put a library file on the device.",
                  aliases=("upload", "upload-file", "put"),
                  params=(_param("id", required=True, label="FileNameInLibrary"),),
                  flags=(LRFlagSpec("overwrite", "o", "overwrite"),
                         LRFlagSpec("keep", "k", "keep")),
                  official_type="PutFile", advanced=True),
    LRCommandSpec("run", LRRisk.EXECUTE, _ALL, PORTAL, "Run a library script.",
                  aliases=("execute", "ps", "start", "powershell"),
                  params=(_param("id", required=True, label="FileNameInLibrary"),
                          _param("parameters", label="ScriptParameters")),
                  official_type="RunScript", advanced=True),
    LRCommandSpec("remediate", LRRisk.EXECUTE, _ALL, PORTAL,
                  "Remediate an entity, or list remediated entities.",
                  params=(_param("type", required=True, label="EntityType",
                                 choices=("file", "process", "service", "registry",
                                          "startupfolder", "scheduledtask", "list")),
                          _param("id", label=_ENTITY_KEY)),
                  risk_by_value=(("type", "list", LRRisk.READ),), advanced=True),
    LRCommandSpec("undo", LRRisk.EXECUTE, _WIN, PORTAL, "Restore a remediated entity.",
                  params=(_param("type", required=True, label="EntityType",
                                 choices=("file", "service", "registry", "startupfolder",
                                          "scheduledtask")),
                          _param("id", required=True, label=_ENTITY_KEY)),
                  advanced=True),
    # --- Device actions available from the console (documented; not in Windows definitions). ---
    LRCommandSpec("isolate", LRRisk.DEVICE_ACTION, _MAC, DOCS,
                  "Isolate the device from the network.", advanced=True),
    LRCommandSpec("release", LRRisk.DEVICE_ACTION, _MAC, DOCS,
                  "Release the device from isolation.", advanced=True),
    LRCommandSpec("scan", LRRisk.DEVICE_ACTION, _POSIX, DOCS, "Run a quick antivirus scan.",
                  advanced=True),
)


def catalog() -> tuple[LRCommandSpec, ...]:
    return _SPECS


_BY_NAME: dict[str, LRCommandSpec] = {spec.name: spec for spec in _SPECS}


def build_alias_index(specs: Iterable[LRCommandSpec]) -> dict[str, LRCommandSpec]:
    index: dict[str, LRCommandSpec] = {}
    for spec in specs:
        for name in (spec.name, *spec.aliases):
            existing = index.setdefault(name.lower(), spec)
            if existing is not spec:
                raise ValueError(f"alias {name!r} names both {existing.name} and {spec.name}")
    return index


PINNED: Mapping[str, LRCommandSpec] = build_alias_index(_SPECS)


def _definition_spec(pinned: LRCommandSpec, definition: Mapping) -> LRCommandSpec:
    params = []
    for raw in definition.get("params") or ():
        if raw.get("isHidden"):
            continue
        choices = raw.get("valid_values")
        params.append(LRParamSpec(
            str(raw["param_id"]), required=not raw.get("optional", True),
            choices=tuple(str(c).lower() for c in choices) if choices else None,
            label=raw.get("name"), is_path=bool(raw.get("is_path")),
        ))
    flags = tuple(
        LRFlagSpec(str(raw["flag_id"]), raw.get("short_name"), raw.get("long_name"))
        for raw in definition.get("flags") or ()
    )
    aliases = tuple(
        str(alias) for alias in (definition.get("aliases") or ())
        if str(alias).lower() != pinned.name
    )
    return replace(pinned, params=tuple(params), flags=flags, aliases=aliases, evidence=PORTAL)


def merge_definitions(
    definitions: Iterable[Mapping],
) -> tuple[dict[str, LRCommandSpec], tuple[str, ...]]:
    """Use one session's server definitions for syntax and the pinned table for risk.

    Returns the alias index for that session and the server command ids that
    have no pinned classification; those are not submittable. Pinned remote
    commands the server did not offer are left out, so they fail as unknown.
    """
    specs = [spec for spec in _SPECS if spec.risk is LRRisk.LOCAL]
    unclassified: list[str] = []
    local_names = {spec.name for spec in specs}
    for definition in definitions:
        command_id = str(definition.get("command_definition_id", "")).lower()
        pinned = _BY_NAME.get(command_id)
        if pinned is None:
            unclassified.append(command_id)
        elif command_id not in local_names:
            specs.append(_definition_spec(pinned, definition))
    return build_alias_index(specs), tuple(sorted(unclassified))
