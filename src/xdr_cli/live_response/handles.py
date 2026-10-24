"""Private tenant/backend-bound Live Response locators, never a status cache."""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from xdr_cli._lock import exclusive_lock
from xdr_cli.config import ensure_config_dir, get_config_home
from xdr_cli.exceptions import ArtifactError, ConflictError, UsageError
from xdr_cli.results import tenant_fingerprint
from xdr_cli.secret_files import atomic_write_secret

from .models import LRPlatform, LRSession

_SESSION = re.compile(r"CLR[A-Za-z0-9_-]{1,125}")
_DEVICE = re.compile(r"[a-fA-F0-9]{40}")


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
            or data.get("version") != 1
            or data.get("tenant") != fingerprint
            or data.get("backend") != backend
            or data.get("session_id") != session_id
            or not isinstance(data.get("machine_id"), str)
            or not _DEVICE.fullmatch(data["machine_id"])
        ):
            return None
        return data
    except (FileNotFoundError, ValueError, OSError):
        return None


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
                "current_directory": previous.get("current_directory") if previous else None,
            }
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
        )
    except ValueError:
        return None


def iter_sessions(tenant: str, backend: str, machine_id: str | None = None):
    """Enumerate only local handles; remote state must be fetched separately."""
    try:
        directory, _ = _directory(tenant, backend)
    except FileNotFoundError:
        return
    for path in sorted(directory.glob("CLR*.json")):
        if not _SESSION.fullmatch(path.stem):
            continue
        session = load_session(tenant, backend, path.stem)
        if session and (machine_id is None or session.machine_id.lower() == machine_id.lower()):
            yield session


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
