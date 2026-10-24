"""Live Response V3 operations derived from the Defender portal's session client."""

from __future__ import annotations

import json
import logging
import re
from contextlib import asynccontextmanager
from dataclasses import replace
from enum import Enum
from pathlib import Path

import httpx

from xdr_cli._bounded_http import read_bounded_response
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    ConflictError,
    ForbiddenError,
    NetworkError,
    NotAuthenticatedError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    UsageError,
    XDRError,
    parse_retry_after,
)

from .handles import (
    apply_directory_completion,
    get_current_directory,
    iter_sessions,
    load_session,
    mark_directory_submission,
    remember_session,
    validate_session_id,
)
from .models import LRCommandState, LRLibraryFile, LRPlatform, LRSession, ParsedCommand
from .transfer import SignedTransfer, open_library_source
from .unsupported import UnsupportedLiveResponse

_BASE = "/apiproxy/mtp/liveResponseApi/"
_MAX_METADATA_BYTES = 64 * 1024**2
_DEVICE = re.compile(r"[0-9a-fA-F]{40}")
_COMMAND = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_FILENAME = re.compile(r"[\w][\w. -]*[\w]", re.ASCII)
_SESSION_STATES = {
    0: "running",
    1: "benign",
    2: "pending",
    3: "terminatedBySystem",
    4: "terminatedByUser",
    5: "failed",
    20: "pendingResource",
    21: "pendingUser",
}
_COMMAND_STATES = {
    0: "running",
    1: "completed",
    2: "failed",
    3: "skipped",
    4: "resumed",
    5: "submitted",
    6: "declined",
    7: "created",
    129: "pending",
    130: "waitingForResource",
}
_TERMINAL_COMMANDS = {1, 2, 3, 6}


class LRRoute(Enum):
    OPEN = ("POST", "create_session")
    SESSION = ("GET", "sessions/{identifier}")
    CLOSE = ("POST", "close_session")
    DEFINITIONS = ("GET", "get_command_definitions")
    SUBMIT = ("POST", "create_command")
    COMMAND = ("GET", "commands/{identifier}")
    COMMANDS = ("GET", "sessions/{identifier}/commands")
    CANCEL = ("POST", "commands/{identifier}/cancel")
    BACKGROUND = ("POST", "commands/{identifier}/background")
    LIBRARY = ("GET", "library/get_files")
    UPLOAD = ("POST", "library/upload_file")
    DELETE = ("DELETE", "library/delete_file")


def _filename(name: str) -> str:
    if not isinstance(name, str) or len(name) > 255 or not _FILENAME.fullmatch(name):
        raise UsageError(
            "Live Response library name must be a plain filename with letters, "
            "numbers, spaces, dots, underscores or hyphens."
        )
    return name


def _command_id(value: str) -> str:
    if not isinstance(value, str) or not _COMMAND.fullmatch(value):
        raise UsageError("Live Response command identifier must be a GUID.")
    return value


def _platform(value) -> LRPlatform | None:
    if not isinstance(value, str):
        return None
    value = value.lower()
    if "windows" in value:
        return LRPlatform.WINDOWS
    if "linux" in value:
        return LRPlatform.LINUX
    if "mac" in value:
        return LRPlatform.MACOS
    return None


class PortalLiveResponse(UnsupportedLiveResponse):
    @staticmethod
    def _lr_uncertain(error: XDRError, route: LRRoute, *, params=None, body=None):
        """A failed mutation response is not evidence that the request did not run."""
        message = (
            "Live Response request may have been accepted. Outcome unknown; "
            "inspect its state before resubmitting."
        )
        error.message = message
        error.args = (message,)
        error.error_code = "OUTCOME_UNKNOWN"
        error.retryable = False
        error.suggested_fix = "Do not repeat the mutation; use the recovery command to inspect it."
        error.invalid = None
        error.allowed = []
        error.suggestions = []
        error.corrected_argv = None
        status = getattr(error, "status_code", None)
        error.original = {"type": type(error).__name__, "status": status} if status else None
        if hasattr(error, "detail"):
            error.detail = None
        session_id = (params or {}).get("session_id") or (body or {}).get("session_id")
        if session_id:
            verb = "show" if route is LRRoute.CLOSE else "history"
            error.help_command = (
                f"xdr --backend portal-cookie device live-response {verb} {session_id}"
            )
        elif route in (LRRoute.UPLOAD, LRRoute.DELETE):
            error.help_command = "xdr --backend portal-cookie device live-response library list"
        else:
            error.suggested_fix = "Inspect the device's Live Response session in Defender."
        return error

    @staticmethod
    def _lr_local_directory_failure(error, command: LRCommandState):
        """Expose the accepted job when private cwd upkeep fails after submission."""
        recovery = (
            "xdr --backend portal-cookie device live-response status "
            f"{command.session_id} {command.command_id}"
        )
        failure = ArtifactError(
            f"Command {command.command_id} was submitted, but local working-directory "
            "tracking failed. Do not repeat the submission; inspect the accepted command.",
            help_command=recovery,
        )
        failure.error_code = "ACCEPTED_COMMAND_LOCAL_STATE_FAILED"
        failure.suggested_fix = (
            "Inspect the command and use absolute paths until tracking recovers."
        )
        return failure

    async def _lr_bounded_response(self, request: httpx.Request) -> httpx.Response:
        return await read_bounded_response(self._client, request, max_bytes=_MAX_METADATA_BYTES)

    async def _lr_request(
        self, route: LRRoute, *, identifier=None, body=None, params=None, files=None, data=None
    ):
        method, suffix = route.value
        if "{identifier}" in suffix:
            if route in (LRRoute.SESSION, LRRoute.COMMANDS):
                validate_session_id(identifier)
            else:
                _command_id(identifier)
            suffix = suffix.format(identifier=identifier)
        await self.verify_tenant()
        query = {"useV3Api": "true", **(params or {})}
        kwargs = {"params": query}
        if files is not None:
            kwargs.update(files=files, data=data)
        elif body is not None:
            kwargs["json"] = body
        request = self._client.build_request(method, _BASE + suffix, **kwargs)
        await self._auth.apply(request)
        request.headers["tenant-id"] = self._tenant_id
        request.headers["x-tid"] = self._tenant_id
        mutating = method != "GET"
        try:
            response = await self._lr_bounded_response(request)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            cls = TimeoutError if isinstance(exc, httpx.TimeoutException) else NetworkError
            error = cls("Live Response request failed.", retryable=not mutating)
            if mutating:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error from None
        except APIError as error:
            # Bounded decoding can fail after the server has already accepted a write.
            if mutating:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error from None
        if response.status_code in (401, 440) or response.is_redirect:
            raise NotAuthenticatedError("Portal Live Response authentication requires renewal.")
        if response.status_code == 403:
            raise ForbiddenError("Defender Live Response role/permissions")
        if response.status_code == 404:
            raise NotFoundError("Live Response object")
        if response.status_code == 409:
            raise ConflictError(
                "Live Response operation conflicts with current session or library state."
            )
        if response.status_code == 429:
            raise RateLimitError(parse_retry_after(response.headers.get("Retry-After")))
        if not response.is_success:
            error = APIError(
                "Live Response request was rejected.", status_code=response.status_code
            )
            if mutating and response.status_code >= 500:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error
        if "text/html" in response.headers.get("content-type", "").lower():
            error = NotAuthenticatedError("Portal Live Response returned a sign-in page.")
            if mutating:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error
        if not response.content:
            return None
        if len(response.content) > 64 * 1024**2:
            error = APIError("Live Response metadata response exceeds its local size bound.")
            if mutating:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error
        try:
            value = response.json()
        except ValueError:
            error = APIError("Live Response returned malformed JSON.")
            if mutating:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error from None
        if value == "OK" and route in (
            LRRoute.CLOSE,
            LRRoute.CANCEL,
            LRRoute.BACKGROUND,
            LRRoute.DELETE,
        ):
            return None
        if not isinstance(value, (dict, list)):
            error = APIError("Live Response returned an unexpected response shape.")
            if mutating:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error
        if isinstance(value, dict) and any(value.get(k) for k in ("error", "Error")):
            error = APIError("Live Response returned an application error.")
            if mutating:
                self._lr_uncertain(error, route, params=params, body=body)
            raise error
        return value

    def _lr_session(self, value, expected_id=None, expected_machine=None) -> LRSession:
        if not isinstance(value, dict):
            raise APIError("Live Response returned no session object.")
        identity = value.get("session_id")
        try:
            validate_session_id(identity)
        except UsageError:
            raise APIError("Live Response returned an unsupported session identifier.") from None
        if expected_id is not None and identity != expected_id:
            raise APIError("Live Response session response identity mismatch.")
        device = value.get("machine_id")
        info = value.get("machine_info") or {}
        if (
            not isinstance(info, dict)
            or not isinstance(device, str)
            or not _DEVICE.fullmatch(device)
        ):
            raise APIError("Live Response session lacks a valid device binding.")
        info_id = info.get("machine_id", device)
        if not isinstance(info_id, str) or info_id.lower() != device.lower():
            raise APIError("Live Response session contains conflicting device identifiers.")
        if expected_machine is not None and device.lower() != expected_machine.lower():
            raise APIError("Created Live Response session belongs to another device.")
        native = value.get("session_status")
        if type(native) is not int:
            raise APIError("Live Response session lacks its native status.")
        result = LRSession(
            session_id=identity,
            machine_id=device,
            state=_SESSION_STATES.get(native, str(native)),
            platform=_platform(info.get("os_platform")),
            created_by=value.get("user"),
            created_at=value.get("start_date"),
            raw=value,
        )
        try:
            remember_session(self._tenant_id, "portal-cookie", result)
        except (ArtifactError, OSError):
            error = ArtifactError(
                f"Session {identity} exists, but its private local state could not be saved.",
                help_command=(
                    f"xdr --backend portal-cookie device live-response show {identity}"
                ),
            )
            error.suggested_fix = "Check the private Live Response handle directory permissions."
            raise error from None
        return result

    async def lr_capabilities(self, machine_id: str) -> dict:
        device = await self.get_device(machine_id, enrich=False)
        return {
            "backend": "portal-cookie",
            "interactive_sessions": True,
            "batch": False,
            "library": True,
            "remote_permissions": "not_checked",
            "device_id": machine_id,
            "device_read_verified": bool(device),
            "session_listing_scope": "locally-known-sessions",
        }

    async def lr_open_session(self, machine_id: str, *, comment: str | None) -> LRSession:
        if not isinstance(machine_id, str) or not _DEVICE.fullmatch(machine_id):
            raise UsageError("Live Response requires a 40-character MachineId.")
        # Get the actual last-seen value without inventing optional portal fields.
        device = await self.get_device(machine_id, enrich=False)
        last_seen = device.get("lastSeen") or device.get("LastSeen")
        value = await self._lr_request(
            LRRoute.OPEN,
            body={
                "end_date": None,
                "machine_last_seen": last_seen,
                "machine_id": machine_id,
                "session_status": None,
                "start_date": None,
            },
        )
        try:
            return self._lr_session(value, expected_machine=machine_id)
        except (XDRError, OSError) as error:
            failure = error if isinstance(error, XDRError) else ArtifactError(
                "Could not save the accepted Live Response session."
            )
            raise self._lr_uncertain(failure, LRRoute.OPEN) from None

    async def lr_get_session(self, session_id: str) -> LRSession:
        validate_session_id(session_id)
        return self._lr_session(
            await self._lr_request(LRRoute.SESSION, identifier=session_id), session_id
        )

    async def lr_iter_sessions(self, *, machine_id: str | None):
        if machine_id is not None and not _DEVICE.fullmatch(machine_id):
            raise UsageError("Live Response device filter requires a MachineId.")
        for local in iter_sessions(self._tenant_id, "portal-cookie", machine_id):
            yield await self.lr_get_session(local.session_id)

    def _lr_known(self, session_id: str) -> LRSession:
        validate_session_id(session_id)
        session = load_session(self._tenant_id, "portal-cookie", session_id)
        if session is None:
            raise ConflictError(
                "Live Response session is not locally bound; "
                "inspect it with live-response show first."
            )
        return session

    async def lr_close_session(self, session_id: str) -> LRSession:
        self._lr_known(session_id)
        await self._lr_request(LRRoute.CLOSE, body={"session_id": session_id})
        try:
            return await self.lr_get_session(session_id)
        except XDRError as error:
            raise self._lr_uncertain(
                error, LRRoute.CLOSE, body={"session_id": session_id}
            ) from None

    async def lr_command_definitions(self, session_id: str) -> list[dict]:
        validate_session_id(session_id)
        value = await self._lr_request(LRRoute.DEFINITIONS, params={"session_id": session_id})
        if not isinstance(value, list) or any(
            not isinstance(d, dict) or not isinstance(d.get("command_definition_id"), str)
            for d in value
        ):
            raise APIError("Live Response command definitions have an invalid shape.")
        ids = [d["command_definition_id"] for d in value]
        if len(set(ids)) != len(ids):
            raise APIError("Live Response command definitions contain duplicate identities.")
        return value

    def _lr_command(self, value, session: LRSession, expected_id=None) -> LRCommandState:
        if not isinstance(value, dict):
            raise APIError("Live Response returned no command object.")
        identity = value.get("command_id")
        try:
            _command_id(identity)
        except UsageError:
            raise APIError("Live Response command has an invalid identifier.") from None
        if expected_id is not None and identity.lower() != expected_id.lower():
            raise APIError("Live Response command response identity mismatch.")
        if value.get("session_id") != session.session_id:
            raise APIError("Live Response command response session mismatch.")
        native = value.get("status")
        if type(native) is not int or not isinstance(value.get("command_definition_id"), str):
            raise APIError("Live Response command lacks its native status or definition.")
        context = value.get("context") or {}
        if not isinstance(context, dict):
            raise APIError("Live Response command context is invalid.")
        output = value.get("output") or {}
        if not isinstance(output, dict):
            raise APIError("Live Response command transfer metadata is invalid.")
        errors = value.get("errors") or []
        if not isinstance(errors, list):
            raise APIError("Live Response command errors have an invalid shape.")
        result = LRCommandState(
            command_id=identity,
            session_id=session.session_id,
            machine_id=session.machine_id,
            verb=value["command_definition_id"],
            state=_COMMAND_STATES.get(native, str(native)),
            terminal=(native in _TERMINAL_COMMANDS) if native in _COMMAND_STATES else None,
            has_output=bool(
                value.get("outputs") or value.get("errors") or value.get("powershell_transcript")
            ),
            has_download=bool(
                context.get("download_token")
                or context.get("download_url")
                or output.get("download_token")
            ),
            raw=value,
            error_count=len(errors),
        )
        return result

    def _lr_apply_directory(self, command: LRCommandState) -> None:
        if command.verb != "cd" or command.state != "completed" or command.raw.get("errors"):
            return
        value = (command.raw.get("output") or {}).get("current_directory") or (
            command.raw.get("context") or {}
        ).get("current_directory")
        if value:
            apply_directory_completion(
                self._tenant_id,
                "portal-cookie",
                command.session_id,
                command.command_id,
                value,
            )

    async def lr_submit(self, session_id: str, command: ParsedCommand) -> LRCommandState:
        local = self._lr_known(session_id)
        session = await self.lr_get_session(session_id)
        if session.machine_id.lower() != local.machine_id.lower():
            raise ConflictError("Live Response session device binding changed.")
        if session.state != "running":
            raise ConflictError(
                "Live Response session is not connected; inspect its state before submitting."
            )
        definitions = await self.lr_command_definitions(session_id)
        definition = next(
            (d for d in definitions if d["command_definition_id"] == command.verb), None
        )
        if definition is None:
            raise UsageError("Command is not exposed by this device's Live Response definitions.")
        allowed = {p["param_id"]: p for p in definition.get("params") or []}
        params = dict(command.params)
        for key, value in params.items():
            if key not in allowed:
                raise UsageError("Command parameter is not exposed by this device's definition.")
            choices = allowed[key].get("valid_values")
            if choices and value not in choices:
                raise UsageError("Command parameter is not supported by this device's definition.")
        if any(not p.get("optional", True) and key not in params for key, p in allowed.items()):
            raise UsageError("Command is missing a required device-defined parameter.")
        allowed_flags = {f["flag_id"] for f in definition.get("flags") or []}
        if not command.flags <= allowed_flags:
            raise UsageError("Command flag is not exposed by this device's definition.")
        directory = get_current_directory(self._tenant_id, "portal-cookie", session_id)
        if directory is None:
            directory = "C:\\" if session.platform == LRPlatform.WINDOWS else "/"
        value = await self._lr_request(
            LRRoute.SUBMIT,
            params={"session_id": session_id},
            body={
                "session_id": session_id,
                "command_definition_id": command.verb,
                "params": [{"param_id": k, "value": v} for k, v in command.params],
                "flags": sorted(command.flags),
                "raw_command_line": command.console_line,
                "current_directory": directory,
                "background_mode": command.background,
            },
        )
        try:
            result = self._lr_command(value, session)
        except XDRError as error:
            raise self._lr_uncertain(
                error, LRRoute.SUBMIT, params={"session_id": session_id}
            ) from None
        if command.verb == "cd":
            try:
                mark_directory_submission(
                    self._tenant_id,
                    "portal-cookie",
                    session_id,
                    result.command_id,
                    value.get("created_time"),
                )
                self._lr_apply_directory(result)
            except (ArtifactError, OSError) as error:
                raise self._lr_local_directory_failure(error, result) from None
        return result

    async def lr_get_command(self, session_id: str | None, command_id: str) -> LRCommandState:
        _command_id(command_id)
        local = self._lr_known(session_id)
        value = await self._lr_request(
            LRRoute.COMMAND, identifier=command_id, params={"session_id": session_id}
        )
        result = self._lr_command(value, local, command_id)
        try:
            self._lr_apply_directory(result)
        except (ArtifactError, OSError):
            logging.getLogger(__name__).warning(
                "Local working-directory tracking is unavailable; use absolute paths."
            )
            return replace(result, directory_tracking="unavailable")
        return result

    async def lr_iter_commands(self, session_id: str):
        local = self._lr_known(session_id)
        values = await self._lr_request(
            LRRoute.COMMANDS, identifier=session_id, params={"session_id": session_id}
        )
        if not isinstance(values, list):
            raise APIError("Live Response history is not a command list.")
        for value in values:
            yield self._lr_command(value, local)

    async def lr_cancel(self, session_id: str | None, command_id: str) -> LRCommandState:
        _command_id(command_id)
        self._lr_known(session_id)
        await self.lr_get_command(session_id, command_id)
        await self._lr_request(
            LRRoute.CANCEL, identifier=command_id, params={"session_id": session_id}
        )
        try:
            return await self.lr_get_command(session_id, command_id)
        except XDRError as error:
            raise self._lr_uncertain(
                error, LRRoute.CANCEL, params={"session_id": session_id}
            ) from None

    async def lr_iter_output(self, session_id: str | None, command_id: str):
        command = await self.lr_get_command(session_id, command_id)
        outputs = command.raw.get("outputs") or []
        if not isinstance(outputs, list):
            raise APIError("Live Response command outputs have an invalid shape.")
        for index, output in enumerate(outputs):
            if not isinstance(output, dict):
                raise APIError("Live Response command output has an invalid shape.")
            yield {
                "record_type": "live-response-output",
                "command_id": command_id,
                "output_index": index,
                **output,
            }
        transcript = command.raw.get("powershell_transcript")
        if transcript:
            yield {
                "record_type": "live-response-transcript",
                "command_id": command_id,
                "text": transcript,
            }
        for error in command.raw.get("errors") or []:
            yield {
                "record_type": "live-response-command-error",
                "command_id": command_id,
                "error": error,
            }

    def _lr_transfer(self, suffix: str, params: dict) -> SignedTransfer:
        @asynccontextmanager
        async def stream():
            await self.verify_tenant()
            request = self._client.build_request(
                "GET", _BASE + suffix, params=params, headers={"Accept-Encoding": "identity"}
            )
            await self._auth.apply(request)
            request.headers["tenant-id"] = self._tenant_id
            request.headers["x-tid"] = self._tenant_id
            response = await self._client.send(request, stream=True)
            try:
                if (
                    response.status_code in (401, 440)
                    or response.is_redirect
                    or ("text/html" in response.headers.get("content-type", "").lower())
                ):
                    raise NotAuthenticatedError(
                        "Portal Live Response transfer requires renewed authentication."
                    )
                if response.status_code == 403:
                    raise ForbiddenError("Defender Live Response file collection")
                yield response
            finally:
                await response.aclose()

        return SignedTransfer(_stream_factory=stream)

    async def lr_result_transfer(self, session_id: str | None, command_id: str, *, index: int = 0):
        if index != 0:
            raise UsageError("Portal Live Response results have one transfer per command.")
        command = await self.lr_get_command(session_id, command_id)
        if not command.succeeded:
            raise ConflictError("Live Response command has not completed successfully.")
        context = command.raw.get("context") or {}
        output = command.raw.get("output") or {}
        token = context.get("download_token") or output.get("download_token")
        if token:
            return self._lr_transfer(
                "download_file", {"session_id": session_id, "token": token, "useV3Api": "true"}
            )
        url = context.get("download_url")
        if isinstance(url, str):
            # Signed Blob URLs are downloaded without portal credentials.
            from xdr_cli.package_download import validate_package_url

            validate_package_url(url)
            return SignedTransfer(_url=url)
        raise NotFoundError("Live Response downloadable result")

    def _lr_library_file(self, value) -> LRLibraryFile:
        if not isinstance(value, dict) or not isinstance(value.get("file_name"), str):
            raise APIError("Live Response library entry is malformed.")
        return LRLibraryFile(
            name=value["file_name"],
            size=value.get("size") or value.get("file_size"),
            sha256=value.get("sha256"),
            description=value.get("description"),
            has_parameters=value.get("has_parameters"),
            parameters_description=value.get("parameters_description"),
            created_by=value.get("originating_user"),
            last_updated=value.get("last_updated_time"),
            raw=value,
        )

    async def lr_iter_library(self):
        values = await self._lr_request(LRRoute.LIBRARY)
        if not isinstance(values, list):
            raise APIError("Live Response library response is not a list.")
        for value in values:
            yield self._lr_library_file(value)

    async def lr_library_transfer(self, name: str) -> SignedTransfer:
        _filename(name)
        found = next(
            (f for f in [item async for item in self.lr_iter_library()] if f.name == name), None
        )
        if found is None:
            raise NotFoundError("Live Response library file")
        return self._lr_transfer("library/download_file", {"file_name": name, "useV3Api": "true"})

    async def lr_upload_library(
        self,
        path: Path,
        *,
        description: str | None,
        parameters_description: str | None,
        has_parameters: bool,
        overwrite: bool,
    ) -> LRLibraryFile:
        path = Path(path)
        _filename(path.name)
        with open_library_source(path) as source:
            fields = {
                "description": description,
                "has_parameters": has_parameters,
                "parameters_description": parameters_description,
                "override_if_exists": overwrite,
            }
            fields = {k: v for k, v in fields.items() if v is not None}
            value = await self._lr_request(
                LRRoute.UPLOAD,
                files={"file[]": (path.name, source, "application/octet-stream")},
                data={"file_fields": json.dumps(fields)},
            )
        try:
            return self._lr_library_file(value)
        except XDRError as error:
            raise self._lr_uncertain(error, LRRoute.UPLOAD) from None

    async def lr_delete_library(self, name: str) -> None:
        _filename(name)
        found = next(
            (f for f in [item async for item in self.lr_iter_library()] if f.name == name), None
        )
        if found is None:
            raise NotFoundError("Live Response library file")
        await self._lr_request(
            LRRoute.DELETE,
            body={
                "file_id": found.raw.get("file_id"),
                "last_updated_time": found.last_updated,
                "file_name": name,
            },
        )
