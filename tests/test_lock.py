"""Tests for the cross-platform exclusive_lock helper."""

from __future__ import annotations

import multiprocessing as mp
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from xdr_cli._lock import exclusive_lock


def test_exclusive_lock_basic_roundtrip(tmp_path: Path) -> None:
    """A single process can acquire and release the lock without error."""
    target = tmp_path / "thing"
    target.write_text("seed")
    with exclusive_lock(target):
        target.write_text("written-under-lock")
    assert target.read_text() == "written-under-lock"


def test_exclusive_lock_creates_lock_sidecar(tmp_path: Path) -> None:
    """The lock file lives next to the target as `<target>.lock`."""
    target = tmp_path / "x"
    target.write_text("x")
    with exclusive_lock(target):
        # The sidecar should exist while the lock is held; filelock manages it.
        assert (tmp_path / "x.lock").exists()


def test_exclusive_lock_serializes_threads(tmp_path: Path) -> None:
    """A second thread cannot enter while the first holds the same path."""

    target = tmp_path / "thread-shared"
    holder_entered = threading.Event()
    release_holder = threading.Event()
    waiter_started = threading.Event()
    waiter_entered = threading.Event()

    def holder() -> None:
        with exclusive_lock(target):
            holder_entered.set()
            assert release_holder.wait(timeout=5)

    def waiter() -> None:
        waiter_started.set()
        with exclusive_lock(target):
            waiter_entered.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        holder_future = pool.submit(holder)
        assert holder_entered.wait(timeout=5)
        waiter_future = pool.submit(waiter)
        assert waiter_started.wait(timeout=5)
        assert not waiter_entered.wait(timeout=0.1)
        release_holder.set()
        holder_future.result(timeout=5)
        waiter_future.result(timeout=5)

    assert waiter_entered.is_set()


def _hold_lock_worker(target_path: str, hold_secs: float, started_path: str) -> None:
    """Acquire the lock, signal start, hold for a bit, then release."""
    from xdr_cli._lock import exclusive_lock as _excl

    with _excl(Path(target_path)):
        Path(started_path).write_text("ready")
        time.sleep(hold_secs)


def _waiter_worker(target_path: str, q: mp.Queue) -> None:
    """Try to acquire the lock; report how long acquisition took."""
    from xdr_cli._lock import exclusive_lock as _excl

    start = time.monotonic()
    with _excl(Path(target_path), timeout=10.0):
        elapsed = time.monotonic() - start
        q.put(elapsed)


def test_exclusive_lock_serializes_processes(tmp_path: Path) -> None:
    """Two processes contending must serialize, not interleave."""
    target = tmp_path / "shared"
    target.write_text("seed")
    started = tmp_path / "started.flag"

    ctx = mp.get_context("spawn")
    q: mp.Queue[float] = ctx.Queue()

    holder = ctx.Process(
        target=_hold_lock_worker,
        args=(str(target), 0.5, str(started)),
    )
    holder.start()

    # Wait until the holder has acquired the lock.
    deadline = time.monotonic() + 5.0
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists(), "holder never acquired the lock"

    waiter = ctx.Process(target=_waiter_worker, args=(str(target), q))
    waiter.start()

    holder.join(timeout=10)
    waiter.join(timeout=10)
    assert holder.exitcode == 0
    assert waiter.exitcode == 0

    elapsed = q.get_nowait()
    # Waiter must have blocked at least until holder released (~0.5s minus
    # whatever already elapsed since `started` was written; allow a slack
    # floor of 0.2s so this isn't flaky on slow CI but still fails if the
    # lock was a no-op and acquisition was instant).
    assert elapsed >= 0.2, f"waiter did not block on lock; elapsed={elapsed:.3f}s"
