"""Cross-platform exclusive-lock helper. Single chokepoint for the locking choice.

All cross-process coordination on files under ~/.xdr-cli/ goes through this
module. `filelock` provides POSIX advisory locks on Linux/macOS and msvcrt
locking on Windows, so xdr-cli runs the same way regardless of where it's
invoked from. Do NOT import `fcntl` elsewhere in the package — Windows
execution depends on this single point of choice.

Notes:
  - Local filesystem only. ``filelock`` uses POSIX advisory locks (``fcntl``)
    on Linux/macOS and ``msvcrt.locking`` on Windows; both have known
    unreliability on NFSv3. ``~/.xdr-cli/`` is expected to live on a local
    filesystem.
  - ``.lock`` sidecar files (e.g. ``.counter-jd.lock``, ``.seq-jd-1.lock``)
    are intentionally left on disk by ``filelock`` after release — that's how
    the lock name persists across the next acquisition. They are safe to
    delete when no xdr-cli process is running, but normally they should be
    left alone.
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from weakref import WeakValueDictionary

from filelock import FileLock, Timeout

_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: WeakValueDictionary[str, Any] = WeakValueDictionary()


def _process_lock(lock_path: Path):
    """Return the process-local mutex for one normalized sidecar path."""

    key = os.path.normcase(os.path.abspath(os.fspath(lock_path)))
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


@contextmanager
def exclusive_lock(path: Path, *, timeout: float = 5.0):
    """Acquire an exclusive lock on `<path>.lock`. Blocks up to `timeout` seconds.

    The sidecar lock file lives next to the target so the target file itself
    is never opened/truncated by lock acquisition. A per-path process mutex
    serializes threads before the sidecar lock coordinates separate processes;
    both layers use the same overall timeout budget.
    """
    lock_path = path.with_suffix(path.suffix + ".lock")
    process_lock = _process_lock(lock_path)
    started = time.monotonic()
    acquired = (
        process_lock.acquire()
        if timeout < 0
        else process_lock.acquire(timeout=timeout)
    )
    if not acquired:
        raise Timeout(str(lock_path))
    try:
        remaining = (
            -1
            if timeout < 0
            else max(0.0, timeout - (time.monotonic() - started))
        )
        with FileLock(str(lock_path), timeout=remaining):
            yield
    finally:
        process_lock.release()
