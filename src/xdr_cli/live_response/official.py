"""Official one-shot Live Response actions; interactive sessions stay portal-only."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

from xdr_cli.client import APISurface
from xdr_cli.continuation import validate_continuation
from xdr_cli.exceptions import (
    APIError,
    ConflictError,
    NetworkError,
    TimeoutError,
    UsageError,
    XDRError,
)

from .models import LRCommandState, LRLibraryFile
from .transfer import SignedTransfer, open_library_source
from .unsupported import UnsupportedLiveResponse

_DEVICE = re.compile(r"[0-9a-fA-F]{40}")
_ACTION = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_FILE = re.compile(r"[\w][\w. -]*[\w]", re.ASCII)


def _action(value):
    if not isinstance(value, str) or not _ACTION.fullmatch(value):
        raise UsageError("Official Live Response action identifier must be a GUID.")
    return value


def _filename(value):
    if not isinstance(value, str) or len(value) > 255 or not _FILE.fullmatch(value):
        raise UsageError("A plain Live Response library filename is required.")
    return value


class OfficialLiveResponse(UnsupportedLiveResponse):
    @staticmethod
    def _lr_uncertain(error: XDRError, help_command: str | None):
        """Keep a failed mutation response distinct from a confirmed rejection."""
        message = (
            "Official Live Response request may have been accepted. Outcome unknown; "
            "inspect its state before resubmitting."
        )
        status = getattr(error, "status_code", None)
        error.message = message
        error.args = (message,)
        error.error_code = "OUTCOME_UNKNOWN"
        error.retryable = False
        error.help_command = help_command
        error.suggested_fix = "Do not repeat the mutation; inspect the existing action or library."
        error.original = {"type": type(error).__name__, "status": status} if status else None
        if hasattr(error, "detail"):
            error.detail = None
        error.invalid = None
        error.allowed = []
        error.suggestions = []
        error.corrected_argv = None
        return error

    async def _lr_call(self, operation, *, mutating=False, help_command=None):
        try:
            return await operation
        except XDRError as error:
            status = (error.original or {}).get("status")
            unknown = mutating and (
                isinstance(error, (TimeoutError, NetworkError))
                or (isinstance(status, int) and (status >= 500 or 200 <= status < 300))
            )
            if unknown:
                raise self._lr_uncertain(error, help_command) from None
            message = "Official Live Response operation failed."
            error.message = message
            error.args = (message,)
            error.original = {"type": type(error).__name__, "status": status} if status else None
            if hasattr(error, "detail"):
                error.detail = None
            error.invalid = None
            error.allowed = []
            error.suggestions = []
            error.corrected_argv = None
            raise error from None

    async def _lr_once(self, operation, *, help_command=None):
        return await self._lr_call(operation, mutating=True, help_command=help_command)

    def _lr_action(self, value, expected_id=None):
        if not isinstance(value, dict) or value.get("type") != "LiveResponse":
            raise APIError("Official action is not a Live Response action.")
        identity = value.get("id")
        if not isinstance(identity, str) or not _ACTION.fullmatch(identity):
            raise APIError("Official Live Response action has an invalid identifier.")
        if expected_id is not None and identity.lower() != expected_id.lower():
            raise APIError("Official Live Response action identity mismatch.")
        device = value.get("machineId")
        state = value.get("status")
        if (
            not isinstance(device, str)
            or not _DEVICE.fullmatch(device)
            or not isinstance(state, str)
        ):
            raise APIError("Official Live Response action lacks its device or status.")
        terminal = state in {"Succeeded", "Failed", "Cancelled", "TimeOut"}
        known = {"Pending", "InProgress", "Succeeded", "Failed", "Cancelled", "TimeOut"}
        commands = value.get("commands")
        error_count = None
        if isinstance(commands, list):
            if any(
                not isinstance(c, dict) or not isinstance(c.get("errors") or [], list)
                for c in commands
            ):
                raise APIError("Official Live Response command errors have an invalid shape.")
            error_count = sum(len(c.get("errors") or []) for c in commands)
        return LRCommandState(
            command_id=identity,
            machine_id=device,
            verb="batch",
            state=state,
            terminal=terminal if state in known else None,
            raw=value,
            error_count=error_count,
        )

    async def lr_capabilities(self, machine_id: str):
        if not isinstance(machine_id, str) or not _DEVICE.fullmatch(machine_id):
            raise UsageError("Live Response requires a 40-character MachineId.")
        return {
            "backend": "official",
            "interactive_sessions": False,
            "batch": True,
            "library": True,
            "device_id": machine_id,
            "remote_permissions": "not_checked",
            "batch_commands": ["PutFile", "RunScript", "GetFile"],
        }

    async def lr_submit_batch(self, machine_id, commands, *, comment):
        if not isinstance(machine_id, str) or not _DEVICE.fullmatch(machine_id):
            raise UsageError("Live Response requires a 40-character MachineId.")
        if (
            not commands
            or len(commands) > 100
            or not isinstance(comment, str)
            or not comment.strip()
        ):
            raise UsageError("Live Response batch requires 1–100 commands and a comment.")
        body = []
        previous = -1
        for parsed in commands:
            kind = parsed.spec.official_type
            order = {"PutFile": 0, "RunScript": 1, "GetFile": 2}.get(kind)
            if (
                order is None
                or order < previous
                or parsed.flags
                or parsed.background
                or parsed.output_to
            ):
                raise UsageError(
                    "Official batch supports PutFile, RunScript, GetFile "
                    "in that order without console flags."
                )
            previous = order
            if kind == "GetFile":
                params = [{"key": "Path", "value": parsed.param("path")}]
            elif kind == "PutFile":
                params = [{"key": "FileName", "value": parsed.param("id")}]
            else:
                params = [{"key": "ScriptName", "value": parsed.param("id")}]
                if parsed.param("parameters") is not None:
                    params.append({"key": "Args", "value": parsed.param("parameters")})
            if any(not isinstance(p["value"], str) or not p["value"] for p in params):
                raise UsageError(
                    "Official Live Response batch command is missing its file or script argument."
                )
            body.append({"type": kind, "params": params})
        recovery = f"xdr --backend official device action-history {machine_id}"
        value = await self._lr_once(
            self.transport.post(
                APISurface.MDE,
                f"machines/{machine_id}/runliveresponse",
                json={"Commands": body, "Comment": comment},
            ),
            help_command=recovery,
        )
        try:
            result = self._lr_action(value)
            if result.machine_id.lower() != machine_id.lower():
                raise APIError("Official Live Response batch response device mismatch.")
            return result
        except XDRError as error:
            raise self._lr_uncertain(error, recovery) from None

    async def lr_get_command(self, session_id, command_id):
        if session_id is not None:
            raise UsageError(
                "Official Live Response uses action IDs without interactive session IDs."
            )
        _action(command_id)
        value = await self._lr_call(
            self.transport.get(APISurface.MDE, f"machineactions/{command_id}")
        )
        return self._lr_action(value, command_id)

    async def lr_cancel(self, session_id, command_id):
        await self.lr_get_command(session_id, command_id)
        recovery = f"xdr --backend official device live-response batch status {command_id}"
        value = await self._lr_once(
            self.transport.post(
                APISurface.MDE,
                f"machineactions/{command_id}/cancel",
                json={"Comment": "Cancelled by xdr-cli operator"},
            ),
            help_command=recovery,
        )
        try:
            return self._lr_action(value, command_id)
        except XDRError as error:
            raise self._lr_uncertain(error, recovery) from None

    async def lr_result_transfer(self, session_id, command_id, *, index=0):
        action = await self.lr_get_command(session_id, command_id)
        if type(index) is not int or index < 0:
            raise UsageError("Live Response result index must be a nonnegative integer.")
        commands = action.raw.get("commands")
        if not isinstance(commands, list) or index >= len(commands):
            raise UsageError("Live Response result index is outside this action's commands.")
        command = commands[index]
        if not isinstance(command, dict) or command.get("commandStatus") != "Completed":
            raise ConflictError("Requested Live Response command has not completed.")
        value = await self._lr_call(
            self.transport.get(
                APISurface.MDE,
                f"machineactions/{command_id}/GetLiveResponseResultDownloadLink(index={index})",
            )
        )
        if not isinstance(value, dict) or not isinstance(value.get("value"), str):
            raise APIError("Official Live Response result has no download link.")
        from xdr_cli.package_download import validate_package_url

        validate_package_url(value["value"])
        return SignedTransfer(_url=value["value"])

    async def lr_iter_output(self, session_id, command_id):
        action = await self.lr_get_command(session_id, command_id)
        for index, command in enumerate(action.raw.get("commands") or []):
            yield {
                "record_type": "live-response-batch-command",
                "command_index": index,
                "command_id": command_id,
                "command_status": command.get("commandStatus"),
                "errors": command.get("errors") or [],
            }

    def _lr_library_file(self, value):
        if not isinstance(value, dict) or not isinstance(value.get("fileName"), str):
            raise APIError("Official Live Response library entry is invalid.")
        return LRLibraryFile(
            name=value["fileName"],
            size=value.get("size"),
            sha256=value.get("sha256"),
            description=value.get("description"),
            has_parameters=value.get("hasParameters"),
            parameters_description=value.get("parametersDescription"),
            created_by=value.get("createdBy"),
            last_updated=value.get("lastUpdatedTime"),
            raw=value,
        )

    async def lr_iter_library(self):
        path = "libraryfiles"
        seen = set()
        for _ in range(100):
            value = await self._lr_call(self.transport.get(APISurface.MDE, path))
            if not isinstance(value, dict) or not isinstance(value.get("value"), list):
                raise APIError("Official Live Response library is not a file collection.")
            for item in value["value"]:
                yield self._lr_library_file(item)
            link = value.get("@odata.nextLink")
            if not link:
                return
            validate_continuation(
                link,
                routes=frozenset({
                    (self.transport.cloud_profile.mde.removeprefix("https://"),
                     "/api/libraryfiles"),
                }),
                seen=seen,
            )
            path = link
        raise APIError("Official Live Response library exceeded its page bound.")

    async def lr_upload_library(
        self, path: Path, *, description, parameters_description, has_parameters, overwrite
    ):
        path = Path(path)
        _filename(path.name)
        fields = {
            "Description": description or "",
            "ParametersDescription": parameters_description or "",
            "HasParameters": str(bool(has_parameters)).lower(),
            "OverrideIfExists": str(bool(overwrite)).lower(),
        }
        with open_library_source(path) as source:
            value = await self._lr_once(
                self.transport.upload_live_response_library(source, path.name, fields),
                help_command="xdr --backend official device live-response library list",
            )
        try:
            return self._lr_library_file(value)
        except XDRError as error:
            raise self._lr_uncertain(
                error, "xdr --backend official device live-response library list"
            ) from None

    async def lr_delete_library(self, name):
        _filename(name)
        await self._lr_once(
            self.transport.delete_live_response_library(quote(name, safe="")),
            help_command="xdr --backend official device live-response library list",
        )
