"""Short-lived verified evidence snapshots, never shared across commands."""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from inspect import iscoroutinefunction

_snapshot: ContextVar[dict | None] = ContextVar("schema_evidence_snapshot", default=None)
_deadline: ContextVar[float | None] = ContextVar("schema_evidence_deadline", default=None)


class EvidenceDeadline(Exception):
    """A caller budget expired, never an invalid-evidence classification."""


@contextmanager
def evidence_deadline(deadline):
    previous = _deadline.get()
    effective = (
        previous if deadline is None else deadline if previous is None else min(previous, deadline)
    )
    token = _deadline.set(effective)
    try:
        yield
    finally:
        _deadline.reset(token)


def check_evidence_deadline():
    deadline = _deadline.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise EvidenceDeadline


@contextmanager
def evidence_snapshot():
    """Reuse evidence within one operation; nested readers share its snapshot."""
    if _snapshot.get() is not None:
        yield
        return
    token = _snapshot.set({})
    try:
        yield
    finally:
        _snapshot.reset(token)


def cached_evidence(namespace, key, load):
    check_evidence_deadline()
    snapshot = _snapshot.get()
    if snapshot is None:
        value = load()
        check_evidence_deadline()
        return value
    cache_key = (namespace, key)
    if cache_key not in snapshot:
        snapshot[cache_key] = load()
    check_evidence_deadline()
    return snapshot[cache_key]


def with_evidence_snapshot(function):
    if iscoroutinefunction(function):

        @wraps(function)
        async def async_wrapped(*args, **kwargs):
            with evidence_snapshot():
                return await function(*args, **kwargs)

        return async_wrapped

    @wraps(function)
    def wrapped(*args, **kwargs):
        with evidence_snapshot():
            return function(*args, **kwargs)

    return wrapped
