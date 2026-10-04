"""Private device locators for portal actions; never an authoritative status cache."""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from xdr_cli.config import ensure_config_dir, get_config_home
from xdr_cli.results import tenant_fingerprint
from xdr_cli.secret_files import atomic_write_secret

_ACTION = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_DEVICE = re.compile(r"[0-9a-fA-F]{40}")


def _path(tenant: str, action: str, *, create: bool = False) -> tuple[Path, str]:
    fingerprint = tenant_fingerprint(tenant)
    if fingerprint is None or not isinstance(action, str) or not _ACTION.fullmatch(action):
        raise ValueError("Invalid action association identity")
    home = ensure_config_dir() if create else get_config_home()
    parent = home / "action_associations"
    for directory in (parent, parent / fingerprint):
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Invalid action association directory")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Action association directory must be private")
    return parent / fingerprint / (action.lower() + ".json"), fingerprint


def load_action_device(tenant: str, action: str) -> str | None:
    """Return a valid local locator or require explicit --device on cache failure."""
    try:
        path, fingerprint = _path(tenant, action)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_size > 4096
                    or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
                    or (os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600)):
                return None
            value = json.loads(source.read(4097))
        if (not isinstance(value, dict) or type(value.get("version")) is not int
                or value["version"] != 1
                or value.get("tenant_fingerprint") != fingerprint
                or value.get("action_id") != action.lower()
                or not isinstance(value.get("device_id"), str)
                or not _DEVICE.fullmatch(value["device_id"])):
            return None
        return value["device_id"]
    except (OSError, ValueError, TypeError):
        return None


def remember_action_device(tenant: str, action: str, device: str) -> bool:
    """Best effort: storage failure must not turn an accepted action into a CLI failure."""
    try:
        if not isinstance(device, str) or not _DEVICE.fullmatch(device):
            return False
        path, fingerprint = _path(tenant, action, create=True)
        previous = load_action_device(tenant, action)
        if previous is not None and previous.casefold() != device.casefold():
            return False
        atomic_write_secret(path, json.dumps({
            "version": 1, "tenant_fingerprint": fingerprint,
            "action_id": action.lower(), "device_id": device.lower(),
        }))
        return True
    except (OSError, ValueError, TypeError):
        return False
