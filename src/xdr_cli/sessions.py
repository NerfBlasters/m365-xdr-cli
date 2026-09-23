"""Session lifecycle primitives: id generation, counters, current-session state.

Single owner of the on-disk layout under ``~/.xdr-cli/sessions/``. Every other
module talks to sessions through this module's public surface.

All locking goes through :mod:`xdr_cli._lock`'s ``exclusive_lock`` — never raw
``fcntl`` — so Windows execution works.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from xdr_cli._lock import exclusive_lock
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import UsageError

# Bumped when the on-disk record shape changes so loaders can sniff and adapt.
SCHEMA_VERSION = 1
DEFAULT_SESSION_TIMEOUT_SECONDS = 1800
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
FEEDBACK_SOURCES = frozenset({"agent", "analyst"})
FEEDBACK_OUTCOMES = frozenset(
    {"completed-smoothly", "completed-with-friction", "incomplete-blocked"}
)
FEEDBACK_CATEGORIES = frozenset(
    {
        "session-state",
        "output-handling",
        "parsing",
        "query-or-schema",
        "library-discovery",
        "auth-or-permission",
        "latency-or-timeout",
        "tenant-context",
        "other",
    }
)

# Windows can briefly deny replacement when another handle has the marker
# open. Keep the retry bounded; persistent ACL/access failures still surface.
_MARKER_REPLACE_RETRY_DELAYS = (
    (0.005, 0.01, 0.02, 0.04, 0.08, 0.16) if os.name == "nt" else ()
)

# Invocations whose top-level command starts with one of these are excluded
# from the learning-mode annotation gate. Bypass commands (annotate, session,
# history) can always run regardless of gate state, so their own invocation
# records must not re-gate the actor — otherwise `xdr annotate` would
# immediately re-trigger the gate it just cleared.
_ANNOTATION_GATE_SKIP_COMMANDS: frozenset[str] = frozenset({
    "annotate", "session", "history",
})


@dataclass(frozen=True)
class Session:
    """Identity + metadata for one operator session."""

    id: str
    upn: str
    label: str | None
    learning_mode: bool
    anchor_incident: int | None = None
    anchor_alert: str | None = None
    anchor_provenance: str | None = None
    last_activity_at: str | None = None
    timeout_seconds: int = DEFAULT_SESSION_TIMEOUT_SECONDS
    automatic: bool = False


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _sessions_dir() -> Path:
    """Return ~/.xdr-cli/sessions/, creating it at 0700 if missing."""
    sess = get_config_home() / "sessions"
    sess.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix":
        sess.chmod(0o700)
    return sess


def _counter_path(initials: str) -> Path:
    return _sessions_dir() / f".counter-{initials}"


def _seq_path(session_id: str) -> Path:
    return _sessions_dir() / f".seq-{session_id}"


def _feedback_seq_path(session_id: str) -> Path:
    return _sessions_dir() / f".feedback-seq-{session_id}"


def _jsonl_path(session_id: str) -> Path:
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise ValueError("invalid session ID")
    return _sessions_dir() / f"{session_id}.jsonl"


def _active_sessions_dir() -> Path:
    """Return ~/.xdr-cli/active_sessions/, creating it at 0700 if missing.

    One marker file per active session, named by session id. Replaces the
    single-pointer ``current_session`` file: per-session markers eliminate
    the multi-terminal clobber race (Terminal A and Terminal B each writing
    their own marker, no shared file) at the cost of explicit disambiguation
    when more than one session is active simultaneously.
    """
    d = get_config_home() / "active_sessions"
    d.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix":
        d.chmod(0o700)
    return d


def _active_session_marker(session_id: str) -> Path:
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise ValueError("invalid session ID")
    return _active_sessions_dir() / session_id


# ---------------------------------------------------------------------------
# UPN → initials
# ---------------------------------------------------------------------------


def _initials_from_upn(upn: str) -> str:
    """Derive operator initials from a UPN's local part.

    Rules:
      * lowercase the local part (everything before ``@``);
      * split on ``.``;
      * if there are 2+ parts: take ``parts[0][0] + parts[-1][0]``;
      * else: strip non-alphabetic characters and take the first 3 chars.

    Known v1 limitation: collisions across distinct humans are not prevented
    (e.g., ``john.doe`` and ``jane.doe`` both → ``jd``). The ``upn`` field on
    each record disambiguates at the data level; the session ID itself is
    per-initials-unique only.
    """
    local = upn.split("@", 1)[0].lower()
    parts = [p for p in local.split(".") if p]
    if len(parts) >= 2:
        return parts[0][0] + parts[-1][0]
    # Single-part fallback — strip non-alpha, take first 3.
    cleaned = re.sub(r"[^a-z]", "", local)
    return cleaned[:3]


# ---------------------------------------------------------------------------
# Counters (per-operator session counter; per-session seq counter)
# ---------------------------------------------------------------------------


def _read_int(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return int(path.read_text().strip() or "0")
    except (ValueError, OSError):
        return 0


def _bump_counter(path: Path) -> int:
    """Take an exclusive lock on `path`, read the int, increment, write back."""
    # Ensure parent dir exists (e.g., first-ever counter under a brand-new home).
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with exclusive_lock(path):
        value = _read_int(path) + 1
        path.write_text(str(value))
        if os.name == "posix":
            path.chmod(0o600)
    return value


def _next_counter(initials: str) -> int:
    """Allocate the next per-operator session counter.

    O(1) under :func:`_lock.exclusive_lock`. Creates the counter file lazily.
    """
    return _bump_counter(_counter_path(initials))


def _next_seq(session_id: str) -> int:
    """Allocate the next monotonic seq for an invocation record.

    Uses a sidecar counter file (``.seq-<id>``) under the same lock pattern as
    the operator counter — O(1) per invocation. Annotation writes do **not**
    call this (annotations have no ``seq``).
    """
    return _bump_counter(_seq_path(session_id))


def generate_session_id(upn: str) -> str:
    """Return ``"<initials>-<counter>"`` for a freshly-allocated session."""
    initials = _initials_from_upn(upn)
    n = _next_counter(initials)
    return f"{initials}-{n}"


# ---------------------------------------------------------------------------
# Active-session markers + env override hydration
# ---------------------------------------------------------------------------


def _hydrate_from_jsonl(session_id: str) -> Session | None:
    """Read the first line of the session JSONL and return a hydrated Session.

    The first line must be a ``session_started`` record. Returns ``None`` when
    the file is missing, empty, or the header line is malformed.
    """
    try:
        path = _jsonl_path(session_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            first = f.readline()
    except OSError:
        return None
    if not first.strip():
        return None
    try:
        rec = json.loads(first)
    except json.JSONDecodeError:
        return None
    if rec.get("kind") != "session_started":
        return None
    try:
        sid = str(rec.get("session_id", session_id))
        if sid != session_id or not _SESSION_ID_RE.fullmatch(sid):
            return None
        return Session(
            id=sid,
            upn=rec.get("upn", "") or "",
            label=rec.get("label"),
            learning_mode=bool(rec.get("learning_mode", False)),
            anchor_incident=rec.get("anchor_incident"),
            anchor_alert=rec.get("anchor_alert"),
            anchor_provenance=rec.get("anchor_provenance"),
            last_activity_at=rec.get("last_activity_at") or rec.get("timestamp"),
            timeout_seconds=max(
                1, int(rec.get("timeout_seconds", DEFAULT_SESSION_TIMEOUT_SECONDS))
            ),
            automatic=bool(rec.get("automatic", False)),
        )
    except (TypeError, ValueError):
        return None


def current_session() -> Session | None:
    """Return the active session, or ``None`` when no unambiguous session is in scope.

    Resolution order:

    1. ``XDR_SESSION=<id>`` env var. Hydrate an existing JSONL session.
       Invalid IDs return ``None`` rather than synthesizing state.
    2. Exactly one marker in ``~/.xdr-cli/active_sessions/`` → use it.
    3. Zero or 2+ markers → ``None``.

    Callers that need to distinguish "no session" from "ambiguous session"
    call :func:`find_active_sessions` directly and inspect the list.
    """
    env_id = os.environ.get("XDR_SESSION", "").strip()
    if env_id:
        if not _SESSION_ID_RE.fullmatch(env_id):
            return None
        if session_already_ended(env_id):
            return None
        hydrated = _hydrate_from_jsonl(env_id)
        if hydrated is not None:
            # Merge anchor_incident from marker — the marker is the live mutable
            # side; JSONL session_started is immutable and doesn't carry the anchor.
            marker = _active_session_marker(env_id)
            from_marker = _read_marker(marker) if marker.exists() else None
            if from_marker is not None:
                return from_marker
            return hydrated
        return None
    actives = find_active_sessions()
    if len(actives) == 1:
        return actives[0]
    return None


def find_active_sessions() -> list[Session]:
    """Return all sessions with active markers in ``~/.xdr-cli/active_sessions/``.

    A marker is "stale" if the session's JSONL contains a ``session_ended``
    record — that means a prior ``xdr session end`` succeeded but didn't (or
    couldn't) clear the marker. Stale markers are removed from disk on the
    fly so this function is the single self-heal path.

    Returns Sessions hydrated from JSONL when available; falls back to marker
    contents when the JSONL hasn't been written yet (env-override / mid-start
    race). Empty list when no markers exist.
    """
    out: list[Session] = []
    d = _active_sessions_dir()
    for marker in sorted(d.iterdir()):
        if not marker.is_file() or marker.suffix == ".lock":
            continue
        sid = marker.name
        # Atomic-write temporaries and arbitrary corrupt files are not session
        # markers. Ignore them instead of allowing one orphan to brick every
        # command's session resolution.
        if not _SESSION_ID_RE.fullmatch(sid):
            continue
        # Self-heal: ended sessions don't count as active.
        if _already_ended_unlocked(_jsonl_path(sid)):
            with contextlib.suppress(OSError):
                marker.unlink()
            continue
        from_jsonl = _hydrate_from_jsonl(sid)
        from_marker = _read_marker(marker)
        if (
            from_jsonl is not None
            and from_marker is not None
        ):
            # Merge marker's anchor_incident into the JSONL-hydrated session.
            # The marker is the live mutable side; JSONL is the immutable log.
            s = from_marker
        else:
            s = from_jsonl or from_marker
        if s is not None:
            if _session_expired(s):
                ended = write_session_end_record(s, end_reason="idle-timeout")
                with contextlib.suppress(OSError):
                    marker.unlink()
                if ended is not None:
                    _emit_retirement_feedback_notice(s, "idle-timeout")
                continue
            out.append(s)
    return out


def _read_marker(marker: Path) -> Session | None:
    """Parse a marker file's JSON payload back into a Session."""
    try:
        raw = marker.read_text().strip()
    except OSError:
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    try:
        sid = str(data.get("id", ""))
        if (
            not _SESSION_ID_RE.fullmatch(sid)
            or sid != marker.name
        ):
            return None
        return Session(
            id=sid,
            upn=data.get("upn", "") or "",
            label=data.get("label"),
            learning_mode=bool(data.get("learning_mode", False)),
            anchor_incident=data.get("anchor_incident"),
            anchor_alert=data.get("anchor_alert"),
            anchor_provenance=data.get("anchor_provenance"),
            last_activity_at=data.get("last_activity_at"),
            timeout_seconds=max(
                1, int(data.get("timeout_seconds", DEFAULT_SESSION_TIMEOUT_SECONDS))
            ),
            automatic=bool(data.get("automatic", False)),
        )
    except (TypeError, ValueError):
        return None


def _session_payload(s: Session) -> dict[str, Any]:
    return {
        "id": s.id,
        "upn": s.upn,
        "label": s.label,
        "learning_mode": s.learning_mode,
        "anchor_incident": s.anchor_incident,
        "anchor_alert": s.anchor_alert,
        "anchor_provenance": s.anchor_provenance,
        "last_activity_at": s.last_activity_at,
        "timeout_seconds": s.timeout_seconds,
        "automatic": s.automatic,
    }


def _write_marker_unlocked(marker: Path, session: Session) -> None:
    """Publish one marker while its marker lock is already held."""

    tmp = marker.with_name(
        f".{marker.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    )
    try:
        with tmp.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(_session_payload(session)))
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            tmp.chmod(0o600)
        attempt = 0
        while True:
            try:
                os.replace(tmp, marker)
                break
            except PermissionError:
                if attempt >= len(_MARKER_REPLACE_RETRY_DELAYS):
                    raise
                time.sleep(_MARKER_REPLACE_RETRY_DELAYS[attempt])
                attempt += 1
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()


def _mutate_marker(
    session_id: str,
    fallback: Session | None,
    transform,
) -> Session | None:
    """Lock, re-read, transform, and atomically replace one live marker."""

    marker = _active_session_marker(session_id)
    marker.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with exclusive_lock(marker):
        current = _read_marker(marker) if marker.exists() else fallback
        if current is None:
            return None
        updated = transform(current)
        _write_marker_unlocked(marker, updated)
        return updated


def set_current_session(s: Session) -> None:
    """Write a marker for session ``s`` at ``~/.xdr-cli/active_sessions/<s.id>``.

    The marker contents are a JSON-serialized Session struct so that
    :func:`find_active_sessions` can hydrate identity even before the JSONL
    has been written. JSONL hydration takes precedence on later reads.

    No TTY gate — the prior single-pointer model gated on TTY to avoid
    clobbering across parallel terminals; per-session markers don't share a
    file, so two terminals' starts don't conflict. Agents (subprocess-per-call
    contexts) get the marker for free without re-exporting ``XDR_SESSION``.
    """
    marker = _active_session_marker(s.id)
    marker.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with exclusive_lock(marker):
        _write_marker_unlocked(marker, s)


def clear_current_session(session_id: str) -> None:
    """Remove the marker for ``session_id``. No-op if absent.

    Explicit session id required — the prior no-arg form silently cleared the
    only pointer, but per-session markers mean callers must say which session
    they're ending. Use :func:`find_active_sessions` to enumerate when the
    session is unknown.
    """
    marker = _active_session_marker(session_id)
    with exclusive_lock(marker), contextlib.suppress(FileNotFoundError):
        marker.unlink()


def set_session_anchor_incident(
    session_id: str,
    incident_id: int,
    *,
    provenance: str = "argv",
) -> Session | None:
    """Update the marker for ``session_id`` to record ``incident_id`` as the
    default anchor. Subsequent :class:`Recorder` flushes inherit this value
    on records that don't explicitly set their own ``anchor_incident``.

    No-op when no marker file exists for ``session_id`` (env-override session
    that hasn't started recording yet — the inherit path still works because
    :class:`Recorder` reads from ``Session.anchor_incident`` which was
    populated by ``current_session()`` from the env var path's synth).
    """
    marker = _active_session_marker(session_id)
    if not marker.exists():
        return None
    return _mutate_marker(
        session_id,
        None,
        lambda current: replace(
            current,
            anchor_incident=incident_id,
            anchor_provenance=provenance,
        ),
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _session_expired(session: Session, *, now: datetime | None = None) -> bool:
    last = _parse_timestamp(session.last_activity_at)
    if last is None:
        return False
    current = now or datetime.now(UTC)
    # Future timestamps are treated as current activity, not as expired.
    return current >= last + timedelta(seconds=max(1, session.timeout_seconds))


def _emit_retirement_feedback_notice(session: Session, end_reason: str) -> None:
    """Offer exact append-only feedback syntax after automatic retirement."""

    print(
        f"Session {session.id} retired ({end_reason}). If you can assess the "
        "completed work, append feedback with: "
        f"xdr session feedback {session.id} --source agent "
        "--outcome completed-with-friction --comment \"<assessment>\". "
        "If the prior context is insufficient, record nothing.",
        file=sys.stderr,
    )


def touch_session(session: Session) -> Session:
    """Atomically refresh a live marker's activity timestamp."""

    now = _utc_now_iso()

    def _touch(current: Session) -> Session:
        # Preserve any newer marker anchors learned by another process. Only
        # fill missing anchors from this invocation's resolved session.
        return replace(
            current,
            anchor_incident=(
                current.anchor_incident
                if current.anchor_incident is not None
                else session.anchor_incident
            ),
            anchor_alert=current.anchor_alert or session.anchor_alert,
            anchor_provenance=(
                current.anchor_provenance or session.anchor_provenance
            ),
            last_activity_at=max(current.last_activity_at or "", now),
        )

    return _mutate_marker(session.id, session, _touch) or session


def create_session(
    *,
    upn: str | None = None,
    label: str | None = None,
    learning_mode: bool = False,
    timeout_seconds: int = DEFAULT_SESSION_TIMEOUT_SECONDS,
    automatic: bool = False,
    anchor_incident: int | None = None,
    anchor_alert: str | None = None,
    anchor_provenance: str | None = None,
) -> Session:
    """Create, persist, and activate a manual or automatic session."""

    upn = upn or resolve_operator_upn() or "automatic"
    session = Session(
        id=generate_session_id(upn),
        upn=upn,
        label=label,
        learning_mode=learning_mode,
        anchor_incident=anchor_incident,
        anchor_alert=anchor_alert,
        anchor_provenance=anchor_provenance,
        last_activity_at=_utc_now_iso(),
        timeout_seconds=max(1, timeout_seconds),
        automatic=automatic,
    )
    set_current_session(session)
    write_session_start_record(session)
    return session


_AUTO_SESSION_COMMANDS: frozenset[str] = frozenset(
    {
        "hunt run",
        "hunt library-run",
        "library run",
        "schema observe",
        "schema candidate-review",
        "investigate",
        "incidents show",
        "alerts show",
    }
)


def resolve_session_for_invocation(
    invoked_command: str | None,
    *,
    timeout_seconds: int = DEFAULT_SESSION_TIMEOUT_SECONDS,
    anchor_incident: int | None = None,
    anchor_alert: str | None = None,
) -> tuple[Session | None, str]:
    """Resolve optional telemetry without ever blocking the real command."""

    env_id = os.environ.get("XDR_SESSION", "").strip()
    if env_id:
        if _SESSION_ID_RE.fullmatch(env_id) and session_already_ended(env_id):
            return None, "ended-env"
        session = current_session()
        return (touch_session(session), "explicit-env") if session else (None, "invalid-env")

    active = find_active_sessions()
    if anchor_incident is not None:
        matches = [
            s
            for s in active
            if s.anchor_incident is not None
            and str(s.anchor_incident) == str(anchor_incident)
        ]
        if len(matches) == 1:
            return touch_session(matches[0]), "anchor-match"
    if anchor_alert is not None:
        matches = [s for s in active if s.anchor_alert == anchor_alert]
        if len(matches) == 1:
            return touch_session(matches[0]), "anchor-match"

    if len(active) == 1:
        sole = active[0]
        incident_conflict = (
            sole.automatic
            and anchor_incident is not None
            and sole.anchor_incident is not None
            and str(sole.anchor_incident) != str(anchor_incident)
        )
        alert_conflict = (
            sole.automatic
            and anchor_alert is not None
            and sole.anchor_alert is not None
            and sole.anchor_alert != anchor_alert
            and not (
                anchor_incident is not None
                and sole.anchor_incident is not None
                and str(sole.anchor_incident) == str(anchor_incident)
            )
        )
        if incident_conflict or alert_conflict:
            ended = write_session_end_record(sole, end_reason="automatic-rotation")
            clear_current_session(sole.id)
            if ended is not None:
                _emit_retirement_feedback_notice(sole, "automatic-rotation")
            created = create_session(
                label=(
                    f"incident-{anchor_incident}"
                    if anchor_incident is not None
                    else f"alert-{anchor_alert}"
                ),
                timeout_seconds=timeout_seconds,
                automatic=True,
                anchor_incident=anchor_incident,
                anchor_alert=anchor_alert,
                anchor_provenance=(
                    "graph-response" if anchor_incident is not None else "argv"
                ),
            )
            return created, "automatic-rotated"
        if anchor_incident is not None and sole.anchor_incident is None:
            sole = replace(
                sole,
                anchor_incident=anchor_incident,
                anchor_provenance="argv",
            )
        if anchor_alert is not None and sole.anchor_alert is None:
            sole = replace(sole, anchor_alert=anchor_alert, anchor_provenance="argv")
        return touch_session(sole), "single-active"

    if len(active) > 1:
        return None, "ambiguous-unattached"

    if invoked_command not in _AUTO_SESSION_COMMANDS:
        return None, "unattached"

    anchor_label = (
        f"incident-{anchor_incident}"
        if anchor_incident is not None
        else f"alert-{anchor_alert}"
        if anchor_alert
        else f"auto-{datetime.now(UTC).strftime('%Y%m%d-%H%M')}"
    )
    created = create_session(
        label=anchor_label,
        timeout_seconds=timeout_seconds,
        automatic=True,
        anchor_incident=anchor_incident,
        anchor_alert=anchor_alert,
        anchor_provenance="argv" if (anchor_incident or anchor_alert) else None,
    )
    return created, "automatic-created"


# ---------------------------------------------------------------------------
# UPN resolution from MSAL token cache
# ---------------------------------------------------------------------------


def resolve_operator_upn() -> str | None:
    """Return the cached MSAL account UPN, or ``None`` if no account is cached.

    Uses the same path ``xdr auth status`` uses — calls
    :class:`AuthManager.get_auth_status` and pulls ``account`` when
    ``authenticated`` is True. No re-implementation of token-cache reads here.
    """
    try:
        from xdr_cli.auth import AuthManager
        from xdr_cli.config import load_config

        info = AuthManager(load_config()).get_auth_status()
    except Exception:
        # MSAL discovery, network, config errors — operator UPN is best-effort.
        return None
    if not info.get("authenticated"):
        return None
    account = info.get("account")
    return account if isinstance(account, str) and account else None


# ---------------------------------------------------------------------------
# Record I/O — session_started, session_ended, list/show helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with trailing ``Z`` (no microseconds).

    Format invariant: ``%Y-%m-%dT%H:%M:%SZ`` — fixed width, no fractional
    seconds, ``Z`` suffix. ``history_cmd._iter_filtered_records`` relies on
    this shape for lexicographic ``--since`` comparison; introducing
    fractional seconds (``%f``) would silently break that filter.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_jsonl(session_id: str, record: dict) -> None:
    """Append a single JSON record to the session JSONL under file lock."""
    path = _jsonl_path(session_id)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    line = json.dumps(record, default=str) + "\n"
    with exclusive_lock(path), path.open("a", encoding="utf-8") as f:
        f.write(line)
    if os.name == "posix":
        path.chmod(0o600)


def write_session_start_record(session: Session) -> None:
    """Write the ``session_started`` line as the first JSONL record."""
    record = {
        "kind": "session_started",
        "schema_version": SCHEMA_VERSION,
        "timestamp": _utc_now_iso(),
        "session_id": session.id,
        "upn": session.upn,
        "label": session.label,
        "learning_mode": session.learning_mode,
        "anchor_incident": session.anchor_incident,
        "anchor_alert": session.anchor_alert,
        "anchor_provenance": session.anchor_provenance,
        "last_activity_at": session.last_activity_at or _utc_now_iso(),
        "timeout_seconds": session.timeout_seconds,
        "automatic": session.automatic,
    }
    _append_jsonl(session.id, record)


def _already_ended_unlocked(path: Path) -> bool:
    """Scan the JSONL at ``path`` for a ``session_ended`` record.

    Does NOT acquire the JSONL lock — callers that need source-of-truth
    semantics must hold ``exclusive_lock(path)`` before calling. Used both
    inside the write-lock guard in :func:`write_session_end_record` and from
    the friendly outer check in :func:`session_already_ended`.
    """
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("kind") == "session_ended":
                    return True
    except OSError:
        return False
    return False


def write_session_end_record(
    session: Session,
    *,
    end_reason: str = "explicit",
) -> int | None:
    """Append a ``session_ended`` record. Returns the final invocation seq,
    or ``None`` if the session was already ended (idempotent under the JSONL lock).

    The final seq is read from the sidecar ``.seq-<id>`` counter (O(1)). When
    no invocation has been recorded yet, the counter file is absent and the
    final seq is 0.

    The idempotency check runs **inside** the JSONL lock so that two concurrent
    ``xdr session end`` invocations cannot both append a marker. The CLI's
    outer :func:`session_already_ended` check is kept for the friendly
    user-facing error message; this is the source-of-truth guard.
    """
    path = _jsonl_path(session.id)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with exclusive_lock(path):
        # Re-check inside the lock — outer caller's check is for the friendly
        # error message; this is the source-of-truth guard.
        if _already_ended_unlocked(path):
            return None
        final_seq = _read_int(_seq_path(session.id))
        invocation_count = 0
        failed_count = 0
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    existing = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if existing.get("kind") == "invocation":
                    invocation_count += 1
                    if existing.get("exit_code") not in (None, 0):
                        failed_count += 1
        summary = {
            "kind": "session_summary",
            "schema_version": SCHEMA_VERSION,
            "timestamp": _utc_now_iso(),
            "session_id": session.id,
            "invocation_count": invocation_count,
            "failed_invocation_count": failed_count,
            "final_seq": final_seq,
        }
        record = {
            "kind": "session_ended",
            "schema_version": SCHEMA_VERSION,
            "timestamp": _utc_now_iso(),
            "session_id": session.id,
            "final_seq": final_seq,
            "end_reason": end_reason,
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(summary, default=str) + "\n")
            f.write(json.dumps(record, default=str) + "\n")
    return final_seq


def append_session_feedback(
    session_id: str,
    *,
    source: str,
    outcome: str,
    categories: list[str] | None = None,
    comment: str | None = None,
    input_mode: str = "noninteractive-cli",
) -> dict[str, Any]:
    """Append immutable qualitative feedback, including after session end."""

    invalid_categories = sorted(set(categories or []) - FEEDBACK_CATEGORIES)
    if source not in FEEDBACK_SOURCES:
        raise UsageError(
            f"Unknown feedback source: {source!r}.",
            invalid={"kind": "feedback_source", "value": source},
            allowed=sorted(FEEDBACK_SOURCES),
            help_command="xdr session feedback --help",
        )
    if outcome not in FEEDBACK_OUTCOMES:
        raise UsageError(
            f"Unknown feedback outcome: {outcome!r}.",
            invalid={"kind": "feedback_outcome", "value": outcome},
            allowed=sorted(FEEDBACK_OUTCOMES),
            help_command="xdr session feedback --help",
        )
    if invalid_categories:
        raise UsageError(
            f"Unknown feedback category: {', '.join(invalid_categories)}.",
            invalid={"kind": "category", "value": invalid_categories},
            allowed=sorted(FEEDBACK_CATEGORIES),
            help_command="xdr session feedback --help",
        )

    if load_session_metadata(session_id) is None:
        raise FileNotFoundError(session_id)
    path = _jsonl_path(session_id)
    with exclusive_lock(path):
        seq = _bump_counter(_feedback_seq_path(session_id))
        stamp = _utc_now_iso()
        digest = hashlib.sha256(
            f"{session_id}:{seq}:{stamp}:{os.getpid()}".encode()
        ).hexdigest()[:16]
        record = {
            "kind": "session_feedback",
            "schema_version": SCHEMA_VERSION,
            "timestamp": stamp,
            "session_id": session_id,
            "feedback_id": f"fb-{digest}",
            "feedback_seq": seq,
            "source": source,
            "outcome": outcome,
            "categories": list(categories or []),
            "comment": comment,
            "submitting_actor": os.environ.get("XDR_ACTOR", "operator"),
            "input_mode": input_mode,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
    return record


def session_already_ended(session_id: str) -> bool:
    """Return True iff the JSONL contains a ``session_ended`` record.

    O(N) line-scan — only invoked from ``xdr session end``, which is rare.
    Does not acquire the JSONL lock; this is the friendly pre-check used to
    emit a user-facing error before attempting the write. The race-safe guard
    lives inside :func:`write_session_end_record`.
    """
    try:
        path = _jsonl_path(session_id)
    except ValueError:
        return False
    return _already_ended_unlocked(path)


def load_session_metadata(session_id: str) -> Session | None:
    """Load a session's hydrated metadata from its JSONL header.

    Returns ``None`` if the JSONL is missing or malformed.
    """
    return _hydrate_from_jsonl(session_id)


def load_session_records(session_id: str) -> list[str] | None:
    """Return the raw JSONL lines for a session, or ``None`` if missing."""
    try:
        path = _jsonl_path(session_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return [line for line in text.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Recorder — accumulates fields during one CLI invocation, flushes one JSONL
# line on exit. Lifetime is exactly one Typer invocation. Constructed in the
# app callback (main.py); flushed in run()'s finally block.
# ---------------------------------------------------------------------------


def _kql_hash(kql: str) -> str:
    """Short SHA-256 prefix used as the kql_hash field on invocation records."""
    return hashlib.sha256(kql.encode("utf-8")).hexdigest()[:8]


@dataclass
class Recorder:
    """Per-invocation record accumulator.

    Construction captures immutable fields (session, argv, invoked_command,
    actor) at command start. :meth:`annotate` merges additional fields into a
    pending dict. :meth:`flush` constructs the full invocation record and
    appends it to the session JSONL. ``flush`` is **fail-soft** — any I/O
    error is logged to stderr; never raises. The whole point is that recording
    can never break the user's command.

    No-op when ``session is None`` (no active session, browse-only commands
    that ran outside a session).
    """

    session: Session | None
    argv: list[str]
    invoked_command: str | None = None
    actor: str = field(init=False)
    _pending: dict[str, Any] = field(init=False)
    _skip: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        # Capture XDR_ACTOR at construction time. Sub-agents that re-export
        # XDR_ACTOR mid-command should be rare; the construction-time snapshot
        # matches the "actor identity is per-invocation" model.
        self.actor = os.environ.get("XDR_ACTOR", "operator")
        self._pending = {}
        self._skip = False

    def skip_record(self) -> None:
        """Mark this recorder so :meth:`flush` is a no-op.

        Used by commands that surface a structured error before performing
        any meaningful work (e.g., annotate with no target invocation) and
        whose own invocation record would just be noise.
        """
        self._skip = True

    # -----------------------------------------------------------------------
    # Annotation API
    # -----------------------------------------------------------------------

    def annotate(self, key: str, value: Any) -> None:
        """Merge a single field into the pending record dict.

        Callers pass top-level keys verbatim. For nested ``result.*`` fields,
        callers pass the whole nested dict in one shot:
        ``rec.annotate("result", {"row_count": 47, ...})``. Dotted keys are
        treated as opaque top-level names — no path-walking; this keeps the
        contract simple and avoids accidental over-merging across calls.
        """
        self._pending[key] = value

    # -----------------------------------------------------------------------
    # Flush
    # -----------------------------------------------------------------------

    def flush(self, exit_code: int, duration_ms: int) -> None:
        """Construct and append the invocation record. Fail-soft on any error.

        Lock ordering is **fixed: JSONL first, then sequence counter** — taken
        in the same order by every writer to avoid deadlock between concurrent
        agents. A missing header is repaired under the JSONL lock before the
        invocation line so loaders always see a well-formed file.
        """
        if self.session is None or self._skip:
            return
        try:
            self._do_flush(exit_code=exit_code, duration_ms=duration_ms)
        except OSError as e:
            # Disk full, permission denied, lock-acquisition timeout — the
            # user's command has already produced its real output; record-
            # write failure must never propagate.
            print(f"session record write failed: {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — recording must never raise
            # Defensive: even non-OSError surprises (msal hiccup during synth
            # header, json serialization edge case) should not break the
            # caller's command. Log + return.
            print(f"session record write failed: {e}", file=sys.stderr)

    def _do_flush(self, *, exit_code: int, duration_ms: int) -> None:
        assert self.session is not None
        sid = self.session.id

        path = _jsonl_path(sid)
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with exclusive_lock(path):
            # Refuse to write to an ended session. Self-heal the stale marker
            # if present (the marker is the agent's "current session" pointer;
            # leaving it would re-trap them on every subsequent command).
            if _already_ended_unlocked(path):
                print(
                    f"session {sid} already ended; invocation record dropped. "
                    f"Run 'xdr session start' or unset XDR_SESSION.",
                    file=sys.stderr,
                )
                with contextlib.suppress(OSError):
                    _active_session_marker(sid).unlink()
                return

            # Allocate seq inside the lock, after the ended-check. This
            # preserves the invariant: seq counter == count of written
            # invocation records. Lock ordering is JSONL → seq; no other
            # writer takes seq-then-JSONL, so no deadlock.
            seq = _next_seq(sid)

            # If JSONL doesn't exist yet (env-override path), write a synthetic
            # session_started record so the file is well-formed for downstream
            # readers (load_session_metadata, list_sessions).
            if not path.exists() or path.stat().st_size == 0:
                synth = {
                    "kind": "session_started",
                    "schema_version": SCHEMA_VERSION,
                    "timestamp": _utc_now_iso(),
                    "session_id": sid,
                    "upn": self.session.upn,
                    "label": self.session.label or "env-override",
                    "learning_mode": self.session.learning_mode,
                }
                with path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(synth, default=str) + "\n")

            # Append the invocation record (still inside the JSONL lock).
            record = self._build_record(seq=seq, exit_code=exit_code, duration_ms=duration_ms)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")

    def _build_record(self, *, seq: int, exit_code: int, duration_ms: int) -> dict:
        """Compose the invocation record. Every schema field is present;
        unannotated fields land as ``None`` (or ``{}`` / ``[]`` per the
        schema) so jq paths are stable across heterogeneous commands."""
        assert self.session is not None
        # Default skeleton — every field present, nullable absent fields = None.
        record: dict[str, Any] = {
            "kind": "invocation",
            "schema_version": SCHEMA_VERSION,
            "timestamp": _utc_now_iso(),
            "session_id": self.session.id,
            "operator_upn": self.session.upn or None,
            "actor": self.actor,
            "seq": seq,
            "command": self.invoked_command or (self.argv[0] if self.argv else ""),
            "args": list(self.argv),
            "rationale": None,
            "kql": None,
            "kql_hash": None,
            "library_query": None,
            "params": {},
            "anchor_incident": self.session.anchor_incident if self.session else None,
            "tables_referenced": None,
            "columns_projected": None,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "result": {
                "row_count": None,
                "execution_time_ms": None,
                "cpu_usage": None,
                "has_more": None,
                "sample_rows": None,
            },
            "error": None,
            "hints_emitted": [],
            "envelope_size_bytes": None,
        }

        # Merge annotated fields. Callers supplied top-level keys; nested
        # `result` dicts are passed wholesale so they overwrite the skeleton's
        # default `result` block. kql_hash is computed only when kql lands.
        for key, value in self._pending.items():
            record[key] = value

        if isinstance(self._pending.get("kql"), str) and self._pending["kql"]:
            record["kql_hash"] = _kql_hash(self._pending["kql"])

        return record


def actor_needs_annotation(session: Session, actor: str) -> int | None:
    """Return the seq of ``actor``'s most-recent unannotated invocation, or
    ``None`` if every invocation by ``actor`` already has a clearing annotation.

    "Unannotated" means: no annotation record in the session JSONL has
    ``refers_to == seq``. The annotation's own ``actor`` is irrelevant — any
    actor can clear another actor's gate by passing ``--refers-to``.

    Single-pass O(N) scan over the JSONL. Acceptable on the gate hot path for
    small-to-medium sessions; revisit if learning-mode marathons surface as
    slow.
    """
    path = _jsonl_path(session.id)
    if not path.exists():
        return None
    actor_seqs: list[int] = []
    annotated_seqs: set[int] = set()
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = rec.get("kind")
                if kind == "invocation":
                    seq = rec.get("seq")
                    parts = (rec.get("command") or "").split()
                    cmd = parts[0] if parts else ""
                    if (
                        rec.get("actor") == actor
                        and isinstance(seq, int)
                        and cmd not in _ANNOTATION_GATE_SKIP_COMMANDS
                    ):
                        actor_seqs.append(seq)
                elif kind == "annotation":
                    refers = rec.get("refers_to")
                    if isinstance(refers, int):
                        annotated_seqs.add(refers)
    except OSError:
        return None
    # Most recent unannotated invocation for this actor.
    for seq in reversed(actor_seqs):
        if seq not in annotated_seqs:
            return seq
    return None


def _invocation_seq_exists(session: Session, seq: int) -> bool:
    """Return True if ``seq`` references an invocation in this session's JSONL.

    Used by :func:`write_annotation` to validate user-supplied ``--refers-to``.
    Auto-resolved seqs (from :func:`actor_needs_annotation`) skip this check —
    the caller just observed the seq in the same JSONL on the prior pass.
    """
    path = _jsonl_path(session.id)
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("kind") == "invocation" and rec.get("seq") == seq:
                    return True
    except OSError:
        return False
    return False


def write_annotation(
    session: Session,
    actor: str,
    text: str | None,
    skip_reason: str | None,
    refers_to: int | None,
) -> int:
    """Append a ``kind: "annotation"`` record to the session JSONL.

    Resolution:
      * If ``refers_to is None``, derive it from
        :func:`actor_needs_annotation` (caller's own most-recent unannotated).
      * If still ``None``, raise :class:`QueryError` — caller has nothing to
        annotate.
      * If the caller passed ``refers_to`` explicitly, validate it references
        an existing invocation in this session. Auto-resolved seqs skip
        validation — :func:`actor_needs_annotation` just observed the seq in
        the same JSONL, so a second scan would be redundant.

    Annotation records have NO ``seq`` field — annotations are derivative;
    ordering is via ``timestamp`` + ``refers_to`` (per spec amendment 17).

    Returns the resolved ``refers_to`` seq for caller convenience.

    JSONL append uses :func:`exclusive_lock` on the JSONL itself — the same
    lock as :meth:`Recorder.flush` — so annotations and invocations serialize
    against each other.
    """
    # Defer the QueryError import so sessions.py doesn't pull exceptions at
    # module import time (other consumers don't need it).
    from xdr_cli.exceptions import QueryError

    path = _jsonl_path(session.id)
    auto_resolved = False
    if refers_to is None:
        refers_to = actor_needs_annotation(session, actor)
        if refers_to is None:
            raise QueryError(
                f"No invocation to annotate for actor {actor!r} in session {session.id}."
            )
        auto_resolved = True

    if not auto_resolved:
        # Validate refers_to outside the lock — invocations are append-only, so
        # a seq that exists at check-time still exists when we later acquire
        # the lock and append. Duplicate clearing annotations from concurrent
        # annotators on the same seq are valid (both refer to a real invocation).
        if not path.exists():
            raise QueryError(
                f"Session {session.id} has no JSONL yet — cannot annotate seq {refers_to}."
            )
        if not _invocation_seq_exists(session, refers_to):
            raise QueryError(
                f"refers_to={refers_to} does not reference an invocation in session {session.id}."
            )

    record: dict[str, Any] = {
        "kind": "annotation",
        "schema_version": SCHEMA_VERSION,
        "timestamp": _utc_now_iso(),
        "session_id": session.id,
        "actor": actor,
        "refers_to": refers_to,
        "text": text,
        "skipped": skip_reason is not None,
        "skip_reason": skip_reason,
    }
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with exclusive_lock(path), path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
    return refers_to


def list_sessions(operator: str | None = None) -> list[dict]:
    """Enumerate sessions under ~/.xdr-cli/sessions/.

    Each row carries the session id, operator upn, label, started/ended
    timestamps, invocation count, and learning_mode. ``operator`` filters by
    initials prefix (e.g., ``"jd"`` matches ``jd-1``, ``jd-2``, …).
    """
    sess = _sessions_dir()
    rows: list[dict] = []
    for path in sorted(sess.glob("*.jsonl")):
        sid = path.stem
        if operator and not sid.startswith(f"{operator}-"):
            continue
        meta: dict = {
            "id": sid,
            "upn": None,
            "label": None,
            "started_at": None,
            "ended_at": None,
            "invocations": 0,
            "learning_mode": False,
        }
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    kind = rec.get("kind")
                    if kind == "session_started":
                        meta["upn"] = rec.get("upn")
                        meta["label"] = rec.get("label")
                        meta["started_at"] = rec.get("timestamp")
                        meta["learning_mode"] = bool(rec.get("learning_mode", False))
                    elif kind == "session_ended":
                        meta["ended_at"] = rec.get("timestamp")
                    elif kind == "invocation":
                        meta["invocations"] += 1
        except OSError:
            pass
        rows.append(meta)
    return rows
