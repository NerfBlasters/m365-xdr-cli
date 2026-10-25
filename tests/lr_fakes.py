"""Synthetic Live Response backend for CLI tests; no tenant data."""
from __future__ import annotations

from dataclasses import dataclass, field

from xdr_cli.backend_contract import PORTAL_PROFILE
from xdr_cli.exceptions import TimeoutError
from xdr_cli.live_response.catalog import catalog
from xdr_cli.live_response.models import (
    LRCommandState,
    LRLibraryFile,
    LRPlatform,
    LRRisk,
    LRSession,
)

MACHINE = "a" * 40
SESSION = "CLR00000000-0000-0000-0000-000000000001"


def definitions(*, exclude: frozenset[str] = frozenset()) -> list[dict]:
    """Server-shaped definitions synthesised from the pinned catalog."""
    rows = []
    for spec in catalog():
        if spec.name in exclude or (spec.risk is LRRisk.LOCAL and spec.name != "connect"):
            continue
        rows.append({
            "command_definition_id": spec.name, "default_alias": spec.name,
            "aliases": list(spec.aliases),
            "params": [
                {"param_id": p.param_id, "name": p.label or p.param_id,
                 "optional": not p.required, "is_path": p.is_path, "isHidden": False,
                 "is_pii": True, "valid_values": list(p.choices) if p.choices else None}
                for p in spec.params
            ] or None,
            "flags": [
                {"flag_id": f.flag_id, "short_name": f.short_name, "long_name": f.long_name}
                for f in spec.flags
            ] or None,
        })
    return rows


@dataclass
class FakeLRBackend:
    profile: object = PORTAL_PROFILE
    platform: LRPlatform | None = LRPlatform.WINDOWS
    states: list[str] = field(default_factory=lambda: ["running", "completed"])
    output: list[dict] = field(default_factory=lambda: [{"line": "ok"}])
    excluded: frozenset[str] = frozenset()
    submit_error: Exception | None = None
    submitted: list = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    library: list[LRLibraryFile] = field(default_factory=list)
    closed: bool = False
    error_count: int | None = 0

    def _state(self, index: int) -> LRCommandState:
        native = self.states[min(index, len(self.states) - 1)]
        return LRCommandState(
            command_id="7", machine_id=MACHINE, verb=self.submitted[-1].verb, state=native,
            session_id=SESSION, terminal=native in {"completed", "failed"},
            has_output=True, has_download=self.submitted[-1].verb == "getfile",
            error_count=self.error_count, raw={"secret": "download-token"},
        )

    def _session(self, state: str = "running") -> LRSession:
        return LRSession(SESSION, MACHINE, state, self.platform, "analyst@example.test",
                         raw={"secret": "x"})

    async def lr_open_session(self, machine_id, *, comment):
        self.calls.append("open")
        return self._session()

    async def lr_get_session(self, session_id):
        self.calls.append("get_session")
        return self._session()

    async def lr_iter_sessions(self, *, machine_id):
        yield self._session()

    async def lr_close_session(self, session_id):
        self.calls.append("close")
        return self._session("terminatedByUser")

    async def lr_command_definitions(self, session_id):
        self.calls.append("definitions")
        return definitions(exclude=self.excluded)

    async def lr_submit(self, session_id, command):
        self.calls.append("submit")
        self.submitted.append(command)
        if self.submit_error is not None:
            raise self.submit_error
        self._polls = 0
        return self._state(0)

    async def lr_submit_batch(self, machine_id, commands, *, comment):
        self.calls.append("submit_batch")
        self.submitted.extend(commands)
        self._polls = 0
        return LRCommandState("act-1", machine_id, "batch", "pending", None, False)

    async def lr_get_command(self, session_id, command_id):
        self.calls.append("get_command")
        self._polls += 1
        return self._state(self._polls)

    async def lr_iter_commands(self, session_id):
        yield LRCommandState("7", MACHINE, "dir", "completed", SESSION, True)

    async def lr_cancel(self, session_id, command_id):
        self.calls.append("cancel")
        return LRCommandState(command_id, MACHINE, "run", "failed", SESSION, True)

    async def lr_iter_output(self, session_id, command_id):
        for row in self.output:
            yield row

    async def lr_result_transfer(self, session_id, command_id, *, index=0):
        self.calls.append("transfer")
        return object()

    async def lr_iter_library(self):
        for item in self.library:
            yield item

    async def lr_library_transfer(self, name):
        return object()

    async def lr_upload_library(self, path, *, description, parameters_description,
                                has_parameters, overwrite):
        self.calls.append("upload")
        return LRLibraryFile(path.name, description=description, has_parameters=has_parameters)

    async def lr_delete_library(self, name):
        self.calls.append("delete")

    async def close(self):
        self.closed = True


def timeout() -> TimeoutError:
    return TimeoutError("Submission outcome unknown.")
