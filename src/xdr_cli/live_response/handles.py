"""Private Live Response locators, immutable aliases and last-observed session state."""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from datetime import UTC, datetime
from decimal import Decimal
from functools import lru_cache
from pathlib import Path

from xdr_cli._lock import exclusive_lock
from xdr_cli.config import ensure_config_dir, get_config_home
from xdr_cli.exceptions import ArtifactError, ConflictError, LocalNotFoundError, UsageError
from xdr_cli.results import tenant_fingerprint
from xdr_cli.secret_files import atomic_write_secret

from .models import LRPlatform, LRSession
from .session_aliases import SessionAliases, is_alias

_SESSION = re.compile(r"CLR[A-Za-z0-9_-]{1,125}")
_DEVICE = re.compile(r"[a-fA-F0-9]{40}")
_ACTIVE = frozenset({"running", "pending", "pendingResource", "pendingUser", "queued"})
_INACTIVE = frozenset({
    "benign", "terminatedBySystem", "terminatedByUser", "failed", "not-found",
})


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def session_activity(session: LRSession) -> str:
    """Unmapped native states stay unknown rather than being declared dead."""
    if session.state in _ACTIVE:
        return "active"
    if session.state in _INACTIVE:
        return "inactive"
    return "unknown"


def is_active_session(session: LRSession) -> bool:
    """Include unverified/unknown states when listing or refreshing possible live sessions."""
    return session_activity(session) != "inactive"


def validate_session_id(value: str) -> str:
    if not isinstance(value, str) or not _SESSION.fullmatch(value):
        raise UsageError("A V3 Live Response session identifier beginning with CLR is required.")
    return value


def _directory(tenant: str, backend: str, *, create: bool = False) -> tuple[Path, str]:
    fingerprint = tenant_fingerprint(tenant)
    if fingerprint is None or backend not in {"official", "portal-cookie"}:
        raise ArtifactError("Live Response handle identity is invalid.")
    home = ensure_config_dir() if create else get_config_home()
    parent = home / "live_response"
    target = parent / fingerprint / backend
    for directory in (parent, parent / fingerprint, target):
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or (
            os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ArtifactError("Live Response handle directories must be private directories.")
    return target, fingerprint


def _read(tenant: str, backend: str, session_id: str) -> dict | None:
    validate_session_id(session_id)
    try:
        directory, fingerprint = _directory(tenant, backend)
        path = directory / f"{session_id}.json"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_size > 8192
                or (os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600)
            ):
                return None
            data = json.loads(source.read(8193))
        if (
            not isinstance(data, dict)
            or type(data.get("version")) is not int or data["version"] != 1
            or data.get("tenant") != fingerprint
            or data.get("backend") != backend
            or data.get("session_id") != session_id
            or not isinstance(data.get("machine_id"), str)
            or not _DEVICE.fullmatch(data["machine_id"])
            or not isinstance(data.get("state", "unknown"), str)
        ):
            return None
        return data
    except (FileNotFoundError, ValueError, OSError):
        return None


@lru_cache(maxsize=1)
def _warn_alias_unavailable() -> None:
    logging.getLogger(__name__).warning(
        "Live Response aliases are unavailable; use the native CLR session ID. "
        "Check the private alias registry and directory permissions."
    )


def _alias(tenant: str, backend: str, session_id: str, machine_id: str) -> str | None:
    directory, fingerprint = _directory(tenant, backend)
    registry = SessionAliases(directory, fingerprint, backend)
    try:
        # Always take session -> registry locks, matching remember_session.
        with exclusive_lock(directory / f"{session_id}.json"):
            data = _read(tenant, backend, session_id)
            if data is None or data["machine_id"].lower() != machine_id.lower():
                raise ConflictError("Live Response alias device binding changed.")
            existing = registry.alias_for(session_id, machine_id)
            alias = existing or registry.assign(session_id, machine_id)
            saved = data.get("alias")
            if saved is not None and saved != alias:
                raise ConflictError("Live Response handle alias binding changed.")
            if saved is None:
                data["alias"] = alias
                atomic_write_secret(directory / f"{session_id}.json", json.dumps(data))
            return alias
    except (ArtifactError, ConflictError, OSError):
        # A native ID still addresses its independently verified handle. Never
        # repair, overwrite, or trust a broken optional alias binding here.
        _warn_alias_unavailable()
        return None


def resolve_session_id(tenant: str, backend: str, reference: str) -> str:
    """Resolve only a locally bound alias; the result is always a native CLR identifier."""
    if isinstance(reference, str) and _SESSION.fullmatch(reference):
        return reference
    if not is_alias(reference):
        raise UsageError(
            "Use a V3 session ID beginning with CLR or a generated alias such as lr-1.",
            invalid={"kind": "identifier", "param": "session_id"},
        )
    try:
        directory, fingerprint = _directory(tenant, backend)
        binding = SessionAliases(directory, fingerprint, backend).resolve(reference)
    except FileNotFoundError:
        binding = None
    if binding is None:
        error = LocalNotFoundError("Live Response session alias")
        error.help_command = "xdr --backend portal-cookie device live-response sessions list"
        raise error
    session_id, machine_id = binding
    data = _read(tenant, backend, session_id)
    if data is None or data["machine_id"].lower() != machine_id.lower():
        raise ConflictError("Live Response alias does not match a valid local device-bound handle.")
    if _alias(tenant, backend, session_id, machine_id) != reference.lower():
        raise ConflictError("Live Response alias does not match its remembered handle binding.")
    return session_id


def remember_session(tenant: str, backend: str, session: LRSession) -> bool:
    """Best effort after acceptance; refuse to replace a different device binding."""
    validate_session_id(session.session_id)
    if not _DEVICE.fullmatch(session.machine_id):
        raise UsageError("Live Response requires a 40-character MachineId.")
    try:
        directory, fingerprint = _directory(tenant, backend, create=True)
        path = directory / f"{session.session_id}.json"
        with exclusive_lock(path):
            previous = _read(tenant, backend, session.session_id)
            if previous and previous["machine_id"].lower() != session.machine_id.lower():
                raise ConflictError("Live Response session device binding changed.")
            # Reserve the immutable binding while holding the per-session lock.
            # A later handle-write failure cannot recycle this alias for another session.
            try:
                alias = SessionAliases(directory, fingerprint, backend).assign(
                    session.session_id, session.machine_id
                )
                if previous and previous.get("alias") not in (None, alias):
                    raise ConflictError("Live Response handle alias binding changed.")
            except (ArtifactError, ConflictError, OSError):
                _warn_alias_unavailable()
                alias = None
            data = {
                **(previous or {}),
                "version": 1,
                "tenant": fingerprint,
                "backend": backend,
                "session_id": session.session_id,
                "machine_id": session.machine_id.lower(),
                "platform": session.platform.value if session.platform else None,
                "created_by": session.created_by,
                "created_at": session.created_at,
                "state": session.state,
                "last_verified_at": session.last_verified_at or _now(),
                "current_directory": previous.get("current_directory") if previous else None,
            }
            if alias is not None:
                data["alias"] = alias
            atomic_write_secret(path, json.dumps(data))
        return True
    except OSError:
        return False


def load_session(tenant: str, backend: str, session_id: str) -> LRSession | None:
    data = _read(tenant, backend, session_id)
    if data is None:
        return None
    try:
        platform = LRPlatform(data["platform"]) if data.get("platform") else None
        return LRSession(
            session_id=session_id,
            machine_id=data["machine_id"],
            state=data.get("state", "unknown"),
            platform=platform,
            created_by=data.get("created_by"),
            created_at=data.get("created_at"),
            alias=_alias(tenant, backend, session_id, data["machine_id"]),
            last_verified_at=data.get("last_verified_at"),
        )
    except ValueError:
        return None


def iter_sessions(tenant: str, backend: str, machine_id: str | None = None,
                  *, problems: list[dict] | None = None):
    """Enumerate local observations only; legacy handles gain aliases without tenant queries."""
    if machine_id is not None and (
        not isinstance(machine_id, str) or not _DEVICE.fullmatch(machine_id)
    ):
        raise UsageError("Live Response device filter requires a 40-character MachineId.")
    try:
        directory, _ = _directory(tenant, backend)
    except FileNotFoundError:
        return
    for path in sorted(directory.glob("CLR*.json")):
        if not _SESSION.fullmatch(path.stem):
            continue
        session = load_session(tenant, backend, path.stem)
        if session is None:
            if problems is not None:
                problems.append({"reason": "unreadable-or-invalid"})
                continue
            raise ArtifactError(
                "A remembered Live Response session handle is invalid or unreadable. "
                "The local session listing is incomplete; inspect the private handle store "
                "and recover the session using its native CLR ID."
            )
        if machine_id is None or session.machine_id.lower() == machine_id.lower():
            yield session


def mark_session_missing(tenant: str, backend: str, session_id: str) -> LRSession:
    """Record an explicit remote 404, retaining the alias and all prior local metadata."""
    validate_session_id(session_id)
    directory, _ = _directory(tenant, backend)
    path = directory / f"{session_id}.json"
    try:
        with exclusive_lock(path):
            data = _read(tenant, backend, session_id)
            if data is None:
                raise ArtifactError("Live Response session handle disappeared during refresh.")
            data["state"] = "not-found"
            data["last_verified_at"] = _now()
            atomic_write_secret(path, json.dumps(data))
        result = load_session(tenant, backend, session_id)
        if result is None:
            raise ArtifactError("Live Response session state could not be read after refresh.")
        return result
    except OSError:
        raise ArtifactError("Could not save the refreshed Live Response session state.") from None


def get_current_directory(tenant: str, backend: str, session_id: str) -> str | None:
    data = _read(tenant, backend, session_id)
    return data.get("current_directory") if data else None


def set_current_directory(tenant: str, backend: str, session_id: str, value: str) -> None:
    if not isinstance(value, str) or len(value) > 4096 or "\0" in value:
        raise ArtifactError("Live Response returned an invalid current directory.")
    directory, _ = _directory(tenant, backend)
    path = directory / f"{session_id}.json"
    with exclusive_lock(path):
        data = _read(tenant, backend, session_id)
        if data is None:
            raise ArtifactError("Live Response session locator is unavailable.")
        data["current_directory"] = value
        atomic_write_secret(path, json.dumps(data))


def mark_directory_submission(
    tenant: str,
    backend: str,
    session_id: str,
    command_id: str,
    created_at: str,
) -> None:
    """Bind cwd changes to explicitly submitted commands, ordered by server creation time."""
    current_order = _creation_order(created_at)
    directory, _ = _directory(tenant, backend)
    path = directory / f"{session_id}.json"
    with exclusive_lock(path):
        data = _read(tenant, backend, session_id)
        if data is None:
            raise ArtifactError("Live Response session locator is unavailable.")
        previous = data.get("directory_command_created_at")
        if previous is not None and current_order <= _creation_order(previous):
            return
        data["directory_command_id"] = command_id
        data["directory_command_created_at"] = created_at
        atomic_write_secret(path, json.dumps(data))


def _creation_order(value: str) -> tuple[datetime, Decimal]:
    """Compare timestamps in UTC without losing server fractional precision."""
    if not isinstance(value, str) or len(value) > 80:
        raise ArtifactError("Live Response cd command has an invalid creation timestamp.")
    match = re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,12}))?(?:Z|[+-]\d{2}:\d{2})",
        value,
    )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if match is None or parsed.tzinfo is None:
            raise ValueError
        whole = parsed.replace(microsecond=0).astimezone(UTC)
        return whole, Decimal("0." + (match.group(1) or "0"))
    except ValueError:
        raise ArtifactError("Live Response cd command has an invalid creation timestamp.") from None


def apply_directory_completion(
    tenant: str,
    backend: str,
    session_id: str,
    command_id: str,
    value: str,
) -> None:
    """An older/historical cd result cannot rewind the saved working directory."""
    if not isinstance(value, str) or len(value) > 4096 or "\0" in value:
        raise ArtifactError("Live Response returned an invalid current directory.")
    directory, _ = _directory(tenant, backend)
    path = directory / f"{session_id}.json"
    with exclusive_lock(path):
        data = _read(tenant, backend, session_id)
        if data is None or data.get("directory_command_id") != command_id:
            return
        data["current_directory"] = value
        data["directory_command_id"] = None
        atomic_write_secret(path, json.dumps(data))
