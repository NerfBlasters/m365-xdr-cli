"""Private, immutable short names for tenant-bound Live Response sessions.

The registry deliberately outlives individual session handles: removing a
handle must not let an old alias silently address a different device later.
Callers supply the already-validated tenant/backend handle directory.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from xdr_cli._lock import Timeout as LockTimeout
from xdr_cli._lock import exclusive_lock
from xdr_cli.exceptions import ArtifactError, ConflictError, UsageError
from xdr_cli.secret_files import atomic_write_secret

_SESSION = re.compile(r"CLR[A-Za-z0-9_-]{1,125}")
_DEVICE = re.compile(r"[a-fA-F0-9]{40}")
_FINGERPRINT = re.compile(r"[a-f0-9]{64}")
_ALIAS = re.compile(r"lr-([1-9][0-9]{0,18})", re.IGNORECASE)
_MAX_ALIAS = 2**63 - 1
_MAX_BYTES = 8 * 1024**2
_FIELDS = {"version", "tenant", "backend", "next_alias", "bindings"}


def is_alias(value: object) -> bool:
    """Recognize the reserved generated-alias syntax without reading local state."""
    if not isinstance(value, str):
        return False
    match = _ALIAS.fullmatch(value)
    return match is not None and int(match.group(1)) <= _MAX_ALIAS


def validate_alias(value: str) -> str:
    """Return canonical lowercase syntax, without echoing invalid caller values."""
    if not is_alias(value):
        raise UsageError("A Live Response session alias such as lr-1 is required.")
    return value.lower()


def _identity(session_id: object, machine_id: object) -> tuple[str, str]:
    if not isinstance(session_id, str) or not _SESSION.fullmatch(session_id):
        raise UsageError("A V3 Live Response session identifier beginning with CLR is required.")
    if not isinstance(machine_id, str) or not _DEVICE.fullmatch(machine_id):
        raise UsageError("A Live Response alias requires a 40-character MachineId.")
    return session_id, machine_id.lower()


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid() -> ArtifactError:
    return ArtifactError(
        "The local Live Response alias registry is invalid or does not match this tenant/backend."
    )


class SessionAliases:
    """An atomic monotonically allocated registry within one private namespace."""

    def __init__(self, directory: Path, tenant_fingerprint: str, backend: str):
        if (
            not isinstance(tenant_fingerprint, str)
            or not _FINGERPRINT.fullmatch(tenant_fingerprint)
            or not isinstance(backend, str)
            or backend not in {"portal-cookie", "official"}
        ):
            raise ArtifactError("Live Response alias namespace is invalid.")
        self.directory = Path(directory)
        self.path = self.directory / "aliases.json"
        self.marker = self.directory / "aliases.initialized"
        self.tenant = tenant_fingerprint
        self.backend = backend

    def _check_directory(self) -> None:
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or (
            os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ArtifactError("Live Response aliases require a private directory.")

    def _empty(self) -> dict:
        return {
            "version": 1, "tenant": self.tenant, "backend": self.backend,
            "next_alias": 1, "bindings": {},
        }

    def _validate(self, value: object) -> dict:
        if (
            not isinstance(value, dict)
            or set(value) != _FIELDS
            or type(value.get("version")) is not int
            or value["version"] != 1
            or value.get("tenant") != self.tenant
            or value.get("backend") != self.backend
            or type(value.get("next_alias")) is not int
            or not 1 <= value["next_alias"] <= _MAX_ALIAS + 1
            or not isinstance(value.get("bindings"), dict)
        ):
            raise _invalid()
        seen = set()
        maximum = 0
        for alias, binding in value["bindings"].items():
            if (
                not is_alias(alias)
                or alias != alias.lower()
                or not isinstance(binding, dict)
                or set(binding) != {"session_id", "machine_id"}
            ):
                raise _invalid()
            try:
                session_id, machine_id = _identity(binding["session_id"], binding["machine_id"])
            except UsageError:
                raise _invalid() from None
            if session_id in seen or machine_id != binding["machine_id"]:
                raise _invalid()
            seen.add(session_id)
            maximum = max(maximum, int(alias[3:]))
        if value["next_alias"] <= maximum:
            raise _invalid()
        return value

    def _read_file(self, path: Path, limit: int) -> bytes | None:
        try:
            # lstat covers platforms without O_NOFOLLOW; fstat rejects special files.
            if path.is_symlink():
                raise _invalid()
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_size > limit
                or (os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600)
            ):
                raise _invalid()
            data = source.read(limit + 1)
        if len(data) > limit:
            raise _invalid()
        return data

    def _marker_bytes(self) -> bytes:
        return f"xdr-live-response-aliases-v1\n{self.tenant}\n{self.backend}\n".encode("ascii")

    def _has_marker(self) -> bool:
        marker = self._read_file(self.marker, 512)
        if marker is not None and marker != self._marker_bytes():
            raise _invalid()
        return marker is not None

    def _ensure_marker(self) -> None:
        """Persist loss detection before publishing the first alias or adopting old state."""
        if not self._has_marker():
            atomic_write_secret(self.marker, self._marker_bytes().decode("ascii"))
            if not self._has_marker():
                raise ArtifactError("Live Response alias initialization could not be verified.")

    def _read_state(self) -> tuple[dict, bool, bool]:
        self._check_directory()
        marked = self._has_marker()
        data = self._read_file(self.path, _MAX_BYTES)
        if data is None:
            if marked:
                raise ArtifactError(
                    "The initialized Live Response alias registry is missing; "
                    "aliases were not reset."
                )
            self._check_uninitialized_handles()
            return self._empty(), False, False
        try:
            parsed = json.loads(data, object_pairs_hook=_object)
        except (ValueError, UnicodeError, RecursionError):
            raise _invalid() from None
        return self._validate(parsed), True, marked

    def _check_uninitialized_handles(self) -> None:
        """A surviving handle is a second guard against deletion of both registry files."""
        for path in self.directory.glob("CLR*.json"):
            if not _SESSION.fullmatch(path.stem):
                continue
            data = self._read_file(path, 8192)
            if data is None:
                continue
            try:
                record = json.loads(data, object_pairs_hook=_object)
            except (ValueError, UnicodeError, RecursionError):
                raise _invalid() from None
            if not isinstance(record, dict) or record.get("alias") is not None:
                raise ArtifactError(
                    "Live Response handles retain alias metadata but the registry is missing; "
                    "aliases were not reset. Use native CLR session IDs and recover the registry."
                )

    def _read(self, *, adopt: bool = True) -> dict:
        registry, present, marked = self._read_state()
        if adopt and present and not marked:
            # Old registries must gain the loss marker even during lookup-only use.
            # Re-read under the writer lock; do not revive state that disappeared
            # between observing it and acquiring that lock.
            with exclusive_lock(self.path):
                registry, still_present, _ = self._read_state()
                if not still_present:
                    raise ArtifactError("Live Response alias state disappeared during migration.")
                self._ensure_marker()
        return registry

    def alias_for(self, session_id: str, machine_id: str) -> str | None:
        """Read a name; existing pre-marker registries receive one-time loss protection."""
        session_id, machine_id = _identity(session_id, machine_id)
        try:
            registry = self._read()
        except (OSError, LockTimeout):
            raise ArtifactError("Could not read the private Live Response aliases.") from None
        return self._find(registry, session_id, machine_id)

    @staticmethod
    def _find(registry: dict, session_id: str, machine_id: str) -> str | None:
        for alias, binding in registry["bindings"].items():
            if binding["session_id"] == session_id:
                if binding["machine_id"] != machine_id:
                    raise ConflictError("Live Response alias device binding changed.")
                return alias
        return None

    def resolve(self, alias: str) -> tuple[str, str] | None:
        """Read one binding; callers must also verify its native session handle."""
        alias = validate_alias(alias)
        try:
            binding = self._read()["bindings"].get(alias)
        except (OSError, LockTimeout):
            raise ArtifactError("Could not read the private Live Response aliases.") from None
        return (binding["session_id"], binding["machine_id"]) if binding else None

    def assign(self, session_id: str, machine_id: str) -> str:
        """Allocate once under the shared lock; never recycle a previously used alias."""
        session_id, machine_id = _identity(session_id, machine_id)
        try:
            self._check_directory()
            with exclusive_lock(self.path):
                registry = self._read(adopt=False)
                self._ensure_marker()
                existing = self._find(registry, session_id, machine_id)
                if existing is not None:
                    return existing
                number = registry["next_alias"]
                if number > _MAX_ALIAS:
                    raise ConflictError("The Live Response alias counter is exhausted.")
                alias = f"lr-{number}"
                registry["bindings"][alias] = {"session_id": session_id, "machine_id": machine_id}
                registry["next_alias"] = number + 1
                serialized = json.dumps(registry, separators=(",", ":"))
                if len(serialized.encode("utf-8")) > _MAX_BYTES:
                    raise ArtifactError("The private Live Response alias registry is full.")
                atomic_write_secret(self.path, serialized)
                if self._read(adopt=False) != registry:
                    raise ArtifactError("The private Live Response alias could not be verified.")
                return alias
        except (OSError, LockTimeout):
            raise ArtifactError("Could not save the private Live Response alias.") from None
