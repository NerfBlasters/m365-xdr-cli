"""Short-lived verified evidence snapshots, never shared across commands."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from inspect import iscoroutinefunction

_snapshot: ContextVar[dict | None] = ContextVar("schema_evidence_snapshot", default=None)


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
    snapshot = _snapshot.get()
    if snapshot is None:
        return load()
    cache_key = (namespace, key)
    if cache_key not in snapshot:
        snapshot[cache_key] = load()
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
