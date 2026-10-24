"""Capped recent-data capture with a resumable, value-free job ledger.

Each eligible table gets one wrapped fetch: the most recent rows of the fixed
interval up to a row cap (untimed inventory tables: a capped sample). Below the
cap that is the whole interval; at the cap it is a recent sample with an observed
oldest boundary, which is fine for a discovery data dump. The control packet in the same
response proves that every selected row arrived; a size, runtime or
truncation failure halves the cap and retries. Budget, deadline, quota and
cancellation stops leave the ledger open so the next invocation resumes
without refetching finished tables.
"""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import json
import math
import os
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from filelock import Timeout

from xdr_cli._lock import exclusive_lock
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    AuthError,
    ConfigError,
    ConflictError,
    ForbiddenError,
    NetworkError,
    PermissionError,
    QueryError,
    RateLimitError,
    TimeoutError,
)
from xdr_cli.schema_graph.capture_contract import (
    BINDING_KEYS,
    COMPLETENESS_CAVEAT,
    CaptureProof,
    CaptureSink,
    CaptureSlice,
    SliceArtifact,
)
from xdr_cli.schema_graph.capture_plan import (
    KIND_STATE,
    CapturePlan,
    format_instant,
    parse_instant,
    plan_capture,
)
from xdr_cli.schema_graph.capture_query import (
    COMPILER_VERSION,
    MODE_SAMPLE,
    SliceSpec,
    compile_fetch_query,
    fetch_query_args,
    parse_wrapped,
    query_sha256,
)
from xdr_cli.schema_graph.overlay import schema_evidence_lock

LEDGER_FORMAT = "xdr-capture-job/v2"
LEGACY_LEDGER_FORMAT = "xdr-capture-job/v1"
JOBS_DIRECTORY = "capture-jobs"
PROOF_MODE = "materialized-control/v2"

PENDING = "pending"
COMPLETE = "complete"
IRRETRIEVABLE = "irretrievable"
FAILED = "failed"
_STATES = frozenset({PENDING, COMPLETE, IRRETRIEVABLE, FAILED})

_RESOURCE = re.compile(
    r"exceed|too large|too many|limit|timeout|timed out|memory|partial query failure",
    re.IGNORECASE,
)
_QUOTA = re.compile(r"quota|throttl", re.IGNORECASE)
_GENERIC_REJECTION = re.compile(r"rejected the query or its request parameters", re.IGNORECASE)
_MALFORMED = re.compile(r"malformed", re.IGNORECASE)
_TRANSIENT_FAILURES = frozenset({
    "duplicate-control-packet", "invalid-control-packet", "invalid-payload-packet",
    "unexpected-packet-columns", "protocol-invalid", "invalid-control-floor",
})
_DURATION = re.compile(r"([1-9][0-9]{0,4})([smhd])")  # same grammar as validate_lookback


@dataclass(frozen=True)
class CaptureBudgets:
    """Per-invocation limits; the job continues across invocations."""

    max_queries: int = 300
    max_rows: int = 2_000_000
    max_bytes: int = 2 * 1024**3
    deadline_seconds: float = 1200.0
    request_rows: int = 25_000  # rows captured per table
    min_request_rows: int = 100
    rate_limit_wait_seconds: int = 120
    total_wait_seconds: int = 600
    network_retries: int = 2
    job_ttl_seconds: int = 86_400

    def __post_init__(self) -> None:
        if self.max_queries < 0:
            raise ValueError("max_queries must not be negative")
        for name in ("max_rows", "max_bytes", "request_rows", "min_request_rows"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.request_rows >= 100_000:
            raise ValueError("request_rows must stay below the 100,000-row service limit")


@dataclass
class Counters:
    queries: int = 0
    fetch_queries: int = 0
    retries: int = 0
    reductions: int = 0
    wait_seconds: float = 0.0
    rows: int = 0
    bytes: int = 0

    def add(self, other: Counters) -> None:
        for key, value in asdict(other).items():
            setattr(self, key, getattr(self, key) + value)


@dataclass(frozen=True)
class Stop:
    kind: str
    retry_after_seconds: int | None = None
    message: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CaptureReport:
    job_id: str | None
    resumed: bool
    status: str  # planned | complete | partial | paused
    interval: dict
    binding: dict
    stop: Stop | None
    counters: Counters
    job_counters: Counters
    tables: list[dict]
    exclusions: list[dict]
    captured_run_ids: list[str]
    new_run_ids: list[str]
    caveat: str = COMPLETENESS_CAVEAT
    continuation: str | None = None
    handoff: str = "pending"

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id, "resumed": self.resumed, "status": self.status,
            "interval": self.interval, "binding": self.binding,
            "stop": self.stop.to_dict() if self.stop else None,
            "counters": asdict(self.counters), "job_counters": asdict(self.job_counters),
            "tables": self.tables, "exclusions": self.exclusions,
            "captured_run_ids": self.captured_run_ids, "new_run_ids": self.new_run_ids,
            "caveat": self.caveat, "continuation": self.continuation,
            "handoff": self.handoff,
        }


class _StopSignal(Exception):
    def __init__(self, stop: Stop) -> None:
        self.stop = stop
        super().__init__(stop.kind)


class _Resource(Exception):
    """The service rejected the request for size, row count or runtime."""


class _DeadlineDuringRequest(Exception):
    """The job deadline cut a running request; the table must not stall later runs."""


class _Rejected(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def parse_lookback(value: str | timedelta) -> timedelta:
    if isinstance(value, timedelta):
        return value
    match = _DURATION.fullmatch(value.strip()) if isinstance(value, str) else None
    if not match:
        raise ValueError("capture lookback must look like 24h, 1d or 90m")
    unit = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}[match.group(2)]
    return timedelta(**{unit: int(match.group(1))})


def precise_instant(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- ledger ---------------------------------------------------------------


def jobs_directory(state_dir: Path) -> Path:
    return Path(state_dir) / JOBS_DIRECTORY


def _write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            if os.name == "posix":
                temporary.chmod(0o600)
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ArtifactError(
            f"Cannot write capture checkpoint: {exc}",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc


_JOB_ID = re.compile(r"cap-\d{8}T\d{6}Z-[0-9a-f]{8}")
_WINDOW_ID = re.compile(r"w-[0-9a-f]{24}")
_RUN_ID = re.compile(r"[A-Za-z0-9-]{1,128}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class _InvalidLedger(ValueError):
    pass


def _count(value) -> bool:
    return type(value) is int and value >= 0


def _number(value) -> bool:
    return (isinstance(value, int | float) and not isinstance(value, bool)
            and math.isfinite(value) and value >= 0)


def _optional_instant(value) -> bool:
    if value is None:
        return True
    try:
        parse_instant(value)
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def _valid_counters(value) -> bool:
    fields = Counters.__dataclass_fields__
    return (isinstance(value, dict) and set(value) == set(fields)
            and all(_number(value[key]) if key == "wait_seconds" else _count(value[key])
                    for key in fields))


def _valid_artifact(artifact) -> bool:
    return (isinstance(artifact, dict)
            and set(artifact) == {"run_id", "data_sha256", "rows", "bytes"}
            and isinstance(artifact["run_id"], str)
            and bool(_RUN_ID.fullmatch(artifact["run_id"]))
            and isinstance(artifact["data_sha256"], str)
            and bool(_SHA256.fullmatch(artifact["data_sha256"]))
            and _count(artifact["rows"]) and _count(artifact["bytes"]))


def _valid_coverage(coverage, spec: SliceSpec, artifact: dict) -> bool:
    """A completed slice claims the whole interval only when it was not capped."""

    if not isinstance(coverage, dict) or coverage.get("mode") != spec.mode:
        return False
    total, truncated = coverage.get("source_total"), coverage.get("truncated")
    if not (total is None or _count(total)) or not isinstance(truncated, bool):
        return False
    if coverage.get("span_complete") is not (not truncated):
        return False
    if spec.mode == MODE_SAMPLE:
        return coverage.get("start") is None and coverage.get("end") is None
    try:
        start, end = parse_instant(coverage["start"]), parse_instant(coverage["end"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
    if end != spec.end:
        return False
    if truncated:
        return spec.start <= start < end
    return start == spec.start


def _expected_spec(data: dict, name: str, table: dict) -> SliceSpec:
    if table.get("time_column") is None:
        return SliceSpec(name, None, None, None)
    return SliceSpec(name, table["time_column"], parse_instant(data["interval"]["start"]),
                     parse_instant(data["interval"]["end"]))


def _validated_ledger(path: Path) -> dict:
    """Parse one ledger and check every field the runner or retention relies on.

    Each table has exactly one slice whose bounds and ID are recomputed from the
    job interval, so a ledger cannot narrow, drop or duplicate captured scope.
    """

    if path.is_symlink() or not path.is_file():
        raise _InvalidLedger("not a regular file")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _InvalidLedger("unreadable") from exc
    if (not isinstance(data, dict) or data.get("format") != LEDGER_FORMAT
            or not isinstance(data.get("job_id"), str)
            or not _JOB_ID.fullmatch(data["job_id"]) or path.name != f"{data['job_id']}.json"
            or data.get("status") not in {"open", "closed", "superseded", "expired"}
            or not isinstance(data.get("binding"), dict)
            or not isinstance(data.get("binding_key"), dict)
            or not isinstance(data.get("tables"), dict)
            or not isinstance(data.get("stops"), list)
            or not isinstance(data.get("exclusions"), list)
            or not _valid_counters(data.get("counters"))
            or data.get("handoff") not in {"pending", "consumed"}
            or not _optional_instant(data.get("resume_after"))
            or not isinstance(data["binding"].get("execution_surface"), str | type(None))
            or sorted(data["tables"]) != data["binding_key"].get("tables")):
        raise _InvalidLedger("invalid ledger header")
    try:
        parse_instant(data["created_at"])
        start = parse_instant(data["interval"]["start"])
        end = parse_instant(data["interval"]["end"])
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise _InvalidLedger("invalid ledger times") from exc
    created = parse_instant(data["created_at"])
    horizon = data["binding_key"].get("horizon_seconds")
    if (not start < end or type(horizon) is not int
            or (end - start).total_seconds() != horizon
            or end != created.replace(second=0, microsecond=0)):
        raise _InvalidLedger("invalid ledger interval")
    kinds = data["binding_key"].get("table_kinds")
    if not isinstance(kinds, dict) or sorted(kinds) != sorted(data["tables"]):
        raise _InvalidLedger("invalid ledger table kinds")
    for name, table in data["tables"].items():
        if (not isinstance(table, dict)
                or table.get("kind") not in {"event", "snapshot-timed", "state"}
                or table.get("time_column") not in {None, "Timestamp", "TimeGenerated"}
                or (table["kind"] == KIND_STATE) != (table["time_column"] is None)
                or not isinstance(table.get("error_code"), str | type(None))
                or not isinstance(table.get("slice"), dict)):
            raise _InvalidLedger("invalid table record")
        if kinds[name] != [table["kind"], table["time_column"]]:
            raise _InvalidLedger("table kind differs from the bound plan")
        item = table["slice"]
        try:
            spec = _expected_spec(data, name, table)
        except (KeyError, TypeError, ValueError) as exc:
            raise _InvalidLedger("invalid table bounds") from exc
        state = item.get("state")
        if (item.get("id") != _window_id(data["job_id"], spec)
                or item.get("spec") != spec.to_dict()
                or state not in _STATES
                or not isinstance(item.get("inflight"), bool)
                or not _count(item.get("attempts"))
                or not _count(item.get("protocol_failures", 0))
                or not (_count(item.get("cap")) and item["cap"] >= 1)
                or not isinstance(item.get("reason"), str | type(None))
                or not (item.get("limits") is None or (
                    isinstance(item["limits"], dict)
                    and all(_count(v) for v in item["limits"].values())))):
            raise _InvalidLedger("invalid slice record")
        artifact, coverage = item.get("artifact"), item.get("coverage")
        if state == COMPLETE:
            if (not _valid_artifact(artifact) or not _valid_coverage(coverage, spec, artifact)
                    or not (_count(item.get("row_cap")) and item["row_cap"] >= 1)):
                raise _InvalidLedger("invalid completed slice")
        elif artifact is not None or coverage is not None:
            raise _InvalidLedger("artifact on unfinished slice")
    return data


def _ledger_paths(state_dir: Path) -> list[Path]:
    directory = jobs_directory(state_dir)
    if directory.is_symlink():
        raise _InvalidLedger("capture job directory is a symlink")
    if not directory.exists():
        return []
    return sorted(path for path in directory.iterdir()
                  if path.name.startswith("cap-") and path.suffix == ".json")


def _read_ledgers(state_dir: Path) -> list[tuple[Path, dict]]:
    """Valid ledgers for job startup; invalid files are kept, never trusted or deleted."""

    ledgers = []
    for path in _ledger_paths(state_dir):
        try:
            ledgers.append((path, _validated_ledger(path)))
        except _InvalidLedger:
            continue
    return ledgers


def _legacy_ledger(path: Path) -> dict | None:
    """A v1 (pre-capped design) ledger: never resumed, but its artifacts stay pinned."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("format") != LEGACY_LEDGER_FORMAT:
        return None
    if (not isinstance(data.get("job_id"), str) or not _JOB_ID.fullmatch(data["job_id"])
            or path.name != f"{data['job_id']}.json" or not isinstance(data.get("tables"), dict)
            or not isinstance(data.get("binding"), dict)):
        raise _InvalidLedger("invalid legacy ledger header")
    for table in data["tables"].values():
        if not isinstance(table, dict) or not isinstance(table.get("slices"), list):
            raise _InvalidLedger("invalid legacy table record")
        for item in table["slices"]:
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                    or not _WINDOW_ID.fullmatch(item["id"])
                    or (item.get("artifact") is not None
                        and not _valid_artifact(item["artifact"]))):
                raise _InvalidLedger("invalid legacy slice record")
    return data


def expected_provenance(data: dict, name: str) -> dict:
    """What a completed slice's immutable artifact metadata must say about itself."""

    table = data["tables"][name]
    item = table["slice"]
    spec = SliceSpec.from_dict(item["spec"])
    return {
        "coverage": dict(item["coverage"]),
        "query_args": fetch_query_args(spec, item["row_cap"]),
        "binding": dict(data["binding"]),
        "interval": dict(data["interval"]),
        "kind": table["kind"],
    }


def live_capture_references(state_dir: Path) -> list[dict]:
    """Artifact coordinates that retention must keep, failing closed on any bad ledger.

    Open jobs, finished jobs not yet consumed by local discovery, and unconsumed
    legacy v1 jobs are pinned. Reads are lock-free (ledgers are replaced atomically).
    """

    references = []
    try:
        for path in _ledger_paths(state_dir):
            try:
                data = _validated_ledger(path)
                slices = [(table["slice"], expected_provenance(data, name))
                          for name, table in data["tables"].items()
                          if table["slice"]["state"] == COMPLETE]
                status, handoff = data["status"], data["handoff"]
            except _InvalidLedger:
                data = _legacy_ledger(path)
                if data is None:
                    raise
                # Legacy artifacts carry their own v1 proof; there is no v2 expectation.
                slices = [(item, None) for table in data["tables"].values()
                          for item in table["slices"] if item.get("artifact")]
                status, handoff = "superseded", data.get("handoff", "pending")
            if status != "open" and handoff == "consumed":
                continue
            references.extend({
                "job_id": data["job_id"], "window_id": item["id"],
                "artifact": dict(item["artifact"]), "binding": dict(data["binding"]),
                "status": status, "handoff": handoff, "expected": expected,
            } for item, expected in slices)
    except (_InvalidLedger, OSError) as exc:
        raise ArtifactError(
            f"Capture job ledger cannot be verified ({exc}); refusing to treat its "
            "artifacts as unreferenced.",
            help_command=f"Inspect or remove files under {jobs_directory(state_dir)}",
        ) from exc
    return references


def live_capture_run_ids(state_dir: Path) -> set[str]:
    return {reference["artifact"]["run_id"] for reference in live_capture_references(state_dir)}


def ledger_run_ids(state_dir: Path, *, include_closed: bool = False) -> set[str]:
    """Run IDs referenced by valid ledgers (diagnostics; not a retention authority)."""

    return {
        table["slice"]["artifact"]["run_id"]
        for _path, data in _read_ledgers(state_dir)
        if include_closed or data["status"] == "open"
        for table in data["tables"].values() if table["slice"]["artifact"]
    }


def mark_capture_consumed(state_dir: Path, job_id: str, *,
                          indexed_run_ids: set[str] | frozenset[str] | None = None,
                          retired_run_ids: set[str] | frozenset[str] = frozenset()) -> bool:
    """Release a finished job's retention pins after local discovery durably used them.

    With ``indexed_run_ids`` the pins are released only if every artifact the job
    references now was indexed, or is in ``retired_run_ids`` (artifacts the caller
    independently verified as explicitly retired by pruning, which can never be
    indexed). A concurrent run that added an artifact therefore keeps it pinned.
    Takes only the capture lock: do not call while holding
    ``schema_evidence_lock`` (the engine acquires capture before evidence).
    Open jobs stay pinned.
    """

    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        raise ValueError("invalid capture job id")
    directory = jobs_directory(state_dir)
    try:
        with exclusive_lock(directory / ".capture", timeout=5.0):
            path = directory / f"{job_id}.json"
            try:
                data = _validated_ledger(path)
                if data["status"] == "open":
                    return False
                current = {table["slice"]["artifact"]["run_id"]
                           for table in data["tables"].values() if table["slice"]["artifact"]}
                if indexed_run_ids is not None and not current <= (
                        set(indexed_run_ids) | set(retired_run_ids)):
                    return False
            except _InvalidLedger as exc:
                try:
                    data = _legacy_ledger(path)
                except _InvalidLedger:
                    data = None
                if data is None:
                    raise ArtifactError(
                        f"Capture job ledger cannot be verified ({exc}).") from exc
            data["handoff"] = "consumed"
            CaptureLedger(path, data).save()
            return True
    except Timeout as exc:
        raise ConflictError("Another schema capture job is running for this tenant.") from exc


def _window_id(job_id: str, spec: SliceSpec) -> str:
    canonical = json.dumps(spec.to_dict(), sort_keys=True, separators=(",", ":"))
    return "w-" + hashlib.sha256(f"{job_id}|{canonical}".encode()).hexdigest()[:24]


def _initial_table(job_id: str, plan: CapturePlan, table, budgets: CaptureBudgets) -> dict:
    if table.kind == KIND_STATE:
        spec = SliceSpec(table.name, None, None, None)
    else:
        spec = SliceSpec(table.name, table.time_column, plan.start, plan.end)
    return {
        "kind": table.kind, "time_column": table.time_column, "error_code": None,
        "slice": {
            "id": _window_id(job_id, spec), "spec": spec.to_dict(), "state": PENDING,
            "attempts": 0, "protocol_failures": 0, "inflight": False,
            "cap": budgets.request_rows, "artifact": None,
            "coverage": None, "reason": None, "limits": None,
        },
    }


class CaptureLedger:
    def __init__(self, path: Path, data: dict) -> None:
        self.path = path
        self.data = data

    @property
    def job_id(self) -> str:
        return self.data["job_id"]

    def save(self) -> None:
        self.data["updated_at"] = format_instant(datetime.now(UTC))
        _write_private_json(self.path, self.data)


def _comparable_binding(binding: dict, plan: CapturePlan, horizon: timedelta) -> dict:
    missing = [key for key in BINDING_KEYS if key not in binding]
    if missing:
        raise ValueError(f"capture binding is missing {', '.join(missing)}")
    if binding["horizon_seconds"] != int(horizon.total_seconds()):
        raise ValueError("capture binding horizon does not match the lookback")
    return {
        **{key: binding[key] for key in BINDING_KEYS},
        "compiler_version": COMPILER_VERSION,
        "tables": sorted(table.name for table in plan.tables),
        "table_kinds": {table.name: [table.kind, table.time_column] for table in plan.tables},
    }


def open_job(
    state_dir: Path, *, binding: dict, plan: CapturePlan, horizon: timedelta,
    budgets: CaptureBudgets, now: datetime,
) -> tuple[CaptureLedger, bool]:
    """Resume the matching open job, reuse an unconsumed finished one, or start fresh.

    Callers must hold the capture lock. Superseded and expired ledgers stay on
    disk so their artifacts remain attributable.
    """

    wanted = _comparable_binding(binding, plan, horizon)
    ttl = timedelta(seconds=budgets.job_ttl_seconds)
    resumed = None
    for path, data in _read_ledgers(state_dir):
        if data["status"] != "open":
            continue
        if parse_instant(data["created_at"]) > now + timedelta(minutes=5):
            data["status"], data["closed_reason"] = "superseded", "created-in-future"
        elif data["binding_key"] != wanted:
            data["status"], data["closed_reason"] = "superseded", "binding-changed"
        elif now - parse_instant(data["created_at"]) > ttl:
            data["status"], data["closed_reason"] = "expired", "job-ttl"
        elif resumed is None:
            resumed = CaptureLedger(path, data)
            continue
        else:
            data["status"], data["closed_reason"] = "superseded", "duplicate-open-job"
        CaptureLedger(path, data).save()
    if resumed is not None:
        return resumed, True
    # A finished job whose local-discovery handoff never completed is reused, not
    # recaptured, so an interrupted indexing step resumes from durable artifacts.
    unconsumed = [
        (data["created_at"], path, data) for path, data in _read_ledgers(state_dir)
        if data["status"] == "closed" and data["handoff"] != "consumed"
        and data["binding_key"] == wanted
        and timedelta(minutes=-5) <= now - parse_instant(data["created_at"]) <= ttl
    ]
    if unconsumed:
        _created, path, data = max(unconsumed, key=lambda entry: entry[0])
        return CaptureLedger(path, data), True
    job_id = f"cap-{now.astimezone(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
    data = {
        "format": LEDGER_FORMAT, "job_id": job_id, "status": "open",
        "created_at": format_instant(now), "binding_key": wanted,
        "binding": {**wanted, "execution_surface": None},
        "interval": {"start": format_instant(plan.start), "end": format_instant(plan.end)},
        "exclusions": list(plan.exclusions), "resume_after": None,
        "counters": asdict(Counters()), "stops": [], "handoff": "pending",
        "tables": {table.name: _initial_table(job_id, plan, table, budgets)
                   for table in plan.tables},
    }
    ledger = CaptureLedger(jobs_directory(state_dir) / f"{job_id}.json", data)
    ledger.save()
    return ledger, False


# --- execution ------------------------------------------------------------


def _row_bytes(rows: list[dict]) -> int:
    """Serialized size exactly as ``ResultStreamWriter`` writes rows (JSON + LF)."""

    return sum(len(json.dumps(row, ensure_ascii=False, separators=(",", ":"),
                              default=str).encode()) + 1 for row in rows)


class _Runner:
    _LIMIT_KEYS = ("max_rows", "max_bytes", "request_rows", "min_request_rows")

    def __init__(self, client, ledger: CaptureLedger, sink: CaptureSink,
                 budgets: CaptureBudgets, *, on_progress, clock, sleep, wall) -> None:
        self.client, self.ledger, self.sink, self.budgets = client, ledger, sink, budgets
        self.on_progress = on_progress or (lambda event: None)
        self.clock, self.sleep, self.wall = clock, sleep, wall
        self.started = clock()
        self.counters = Counters()
        self.new_run_ids: list[str] = []

    @property
    def tables(self) -> dict:
        return self.ledger.data["tables"]

    # -- request handling --

    def _remaining(self) -> float:
        return self.budgets.deadline_seconds - (self.clock() - self.started)

    def _check_limits(self) -> None:
        if self.counters.queries >= self.budgets.max_queries:
            raise _StopSignal(Stop("budget-queries"))
        if self._remaining() <= 0:
            raise _StopSignal(Stop("deadline"))

    async def _wait(self, seconds: float, kind: str, message: str | None = None) -> None:
        if seconds >= self._remaining():
            raise _StopSignal(Stop(kind, math.ceil(seconds), message))
        self.counters.wait_seconds += seconds
        self.counters.retries += 1
        await self.sleep(seconds)

    async def _execute(self, query: str):
        network_attempts = 0
        while True:
            self._check_limits()
            self.counters.queries += 1
            self.counters.fetch_queries += 1
            started = self.clock()
            try:
                result = await asyncio.wait_for(
                    self.client.execute_hunting(query), timeout=max(self._remaining(), 0.001))
            except builtins.TimeoutError as exc:
                raise _DeadlineDuringRequest() from exc
            except RateLimitError as exc:
                delay = max(1, int(exc.retry_after or 0))
                if (delay <= self.budgets.rate_limit_wait_seconds
                        and self.counters.wait_seconds + delay <= self.budgets.total_wait_seconds
                        and delay < self._remaining()):
                    await self._wait(delay, "rate-limited")
                    continue
                self.ledger.data["resume_after"] = format_instant(
                    self.wall() + timedelta(seconds=delay))
                raise _StopSignal(Stop("rate-limited", delay)) from exc
            except (AuthError, ForbiddenError, PermissionError, ConfigError):
                raise
            except ConflictError as exc:
                raise _StopSignal(Stop("upstream", message=exc.error_code)) from exc
            except NetworkError as exc:
                if network_attempts < self.budgets.network_retries:
                    await self._wait(2 * 4**network_attempts, "network", exc.error_code)
                    network_attempts += 1
                    continue
                raise _StopSignal(Stop("network", message=exc.error_code)) from exc
            except TimeoutError as exc:
                raise _Resource() from exc
            except QueryError as exc:
                if _QUOTA.search(exc.message or ""):
                    raise _StopSignal(Stop("rate-limited", message=exc.error_code)) from exc
                if _RESOURCE.search(exc.message or "") or _GENERIC_REJECTION.search(
                        exc.message or ""):
                    # Portal mode reports every 400 generically; halving is the only
                    # safe response that still ends in an explicit gap.
                    raise _Resource() from exc
                raise _Rejected(exc.error_code) from exc
            except APIError as exc:
                status = exc.status_code or 0
                if (status in {408, 413, 504} or _RESOURCE.search(exc.message or "")
                        or exc.error_code == "API_MALFORMED_RESPONSE"
                        or _MALFORMED.search(exc.message or "")):
                    # A cut-off body is most often an oversized response.
                    raise _Resource() from exc
                if status >= 500:
                    if network_attempts < self.budgets.network_retries:
                        await self._wait(2 * 4**network_attempts, "upstream", exc.error_code)
                        network_attempts += 1
                        continue
                    raise _StopSignal(Stop("upstream", message=exc.error_code)) from exc
                raise _Rejected(exc.error_code) from exc
            self._bind_surface(getattr(result, "metadata", {}) or {})
            return result, int((self.clock() - started) * 1000)

    def _bind_surface(self, metadata: dict) -> None:
        surface = metadata.get("execution_surface")
        binding = self.ledger.data["binding"]
        if binding.get("execution_surface") is None:
            binding["execution_surface"] = surface
        elif surface != binding["execution_surface"]:
            # Never mix surfaces in one job, and never leave a job that every rerun
            # would resume only to stop again: close it so the next run starts fresh.
            self.ledger.data["status"] = "superseded"
            self.ledger.data["closed_reason"] = "execution-surface-changed"
            raise _StopSignal(Stop(
                "binding-changed",
                message=f"execution surface changed from {binding['execution_surface']}",
            ))

    # -- fetching --

    def _gap(self, item: dict, reason: str) -> None:
        """Record an explicit gap with the limits that caused it, so a later run
        with larger per-invocation limits can retry instead of inheriting the gap."""

        item.update(state=IRRETRIEVABLE, reason=reason, inflight=False,
                    limits={key: getattr(self.budgets, key) for key in self._LIMIT_KEYS})

    def _reduce(self, item: dict, reason: str) -> None:
        """A capped response just shortens the span: halve the cap and retry."""

        self.counters.reductions += 1
        smaller = item["cap"] // 2
        if smaller < self.budgets.min_request_rows:
            self._gap(item, reason)
        else:
            item.update(cap=smaller, inflight=False, reason=reason)

    def _next(self) -> tuple[str, dict] | None:
        # Timed tables first (they are the bounded dump), inventory samples after;
        # within each, tables tried less often go first so one slow table cannot
        # occupy the head of every run.
        pending = [name for name, table in self.tables.items()
                   if table["slice"]["state"] == PENDING]
        if not pending:
            return None
        name = min(pending, key=lambda n: (self.tables[n]["kind"] == KIND_STATE,
                                           self.tables[n]["slice"]["attempts"], n))
        return name, self.tables[name]["slice"]

    async def _fetch(self, name: str, item: dict) -> None:
        table = self.tables[name]
        spec = SliceSpec.from_dict(item["spec"])
        rows_left = self.budgets.max_rows - self.counters.rows
        cap = min(item["cap"], self.budgets.request_rows, self.budgets.max_rows)
        if rows_left < cap:
            raise _StopSignal(Stop("budget-rows"))
        if self.counters.bytes >= self.budgets.max_bytes:
            raise _StopSignal(Stop("budget-bytes"))
        query = compile_fetch_query(spec, cap)
        item["attempts"] += 1
        item["inflight"] = True
        self.ledger.save()
        try:
            result, elapsed = await self._execute(query)
        except _DeadlineDuringRequest as exc:
            self._reduce(item, "deadline-during-request")
            raise _StopSignal(Stop("deadline", message="request exceeded job deadline")) from exc
        except _Resource:
            self._reduce(item, "resource-limit")
            return
        except _Rejected as exc:
            table["error_code"] = exc.code
            item.update(state=FAILED, reason=exc.code, inflight=False)
            return
        wrapped = parse_wrapped(result.results)
        item["inflight"] = False
        if not wrapped.complete(cap):
            # Fewer payloads than the control, or a control lost to response truncation
            # (union arm order is not guaranteed): both shrink the request and retry.
            if (not wrapped.problems and wrapped.source_count is not None) \
                    or wrapped.problems == ("missing-control-packet",):
                self._reduce(item, "fetch-incomplete")
            else:
                # One retry per run for a malformed response; reopened on resume.
                item["protocol_failures"] = item.get("protocol_failures", 0) + 1
                if item["protocol_failures"] >= 2:
                    item.update(state=FAILED, reason=wrapped.problems[0] if wrapped.problems
                                else "protocol-invalid")
            return
        size = _row_bytes(wrapped.rows)
        if size > self.budgets.max_bytes:
            self._reduce(item, "table-exceeds-byte-budget")
            return
        if self.counters.bytes + size > self.budgets.max_bytes:
            raise _StopSignal(Stop("budget-bytes"))
        self._store(name, table, item, spec, query, cap, wrapped, elapsed)

    @staticmethod
    def _coverage(spec: SliceSpec, wrapped) -> dict:
        total = wrapped.source_total
        # source_total is a separate count evaluation: telemetry only, since late
        # ingestion can change it; completeness comes from the control packet.
        # Truncation comes from the cap + 1 sentinel in the same evaluation, never
        # from the separately counted total.
        truncated = wrapped.truncated
        if spec.mode == MODE_SAMPLE:
            return {"mode": MODE_SAMPLE, "start": None, "end": None,
                    "span_complete": not truncated, "truncated": truncated,
                    "floor": None, "source_total": total}
        floor = wrapped.floor  # oldest kept timestamp, reported only when capped
        if truncated != (floor is not None) or (
                floor is not None and not spec.start <= floor < spec.end):
            return None
        return {
            "mode": spec.mode,
            "start": precise_instant(floor) if floor else format_instant(spec.start),
            "end": format_instant(spec.end), "span_complete": floor is None,
            "truncated": floor is not None,
            "floor": precise_instant(floor) if floor else None,
            "source_total": total,
        }

    def _store(self, name, table, item, spec, query, cap, wrapped, elapsed) -> None:
        coverage = self._coverage(spec, wrapped)
        if coverage is None:
            item.update(state=FAILED, reason="invalid-control-floor", inflight=False)
            return
        data = self.ledger.data
        capture = CaptureSlice(
            job_id=self.ledger.job_id, window_id=item["id"], kind=table["kind"], spec=spec,
            query=query, query_sha256=query_sha256(query),
            query_args=fetch_query_args(spec, cap), binding=dict(data["binding"]),
            interval=dict(data["interval"]), profiled_rows=wrapped.source_total,
            proof=CaptureProof(PROOF_MODE, cap, wrapped.source_count, len(wrapped.rows),
                               wrapped.source_bytes or 0),
            collected_at=format_instant(self.wall()), execution_time_ms=elapsed,
            coverage=coverage,
        )
        # Publication and the ledger pointer change together under the evidence lock so
        # a concurrent prune can never see the artifact without its live reference.
        with schema_evidence_lock(help_command="xdr schema collect --explore"):
            artifact = self.sink.write_slice(capture, wrapped.rows)
            if artifact.rows != len(wrapped.rows):
                raise ArtifactError(
                    "Capture sink stored a different row count than was verified.")
            item.update(state=COMPLETE, inflight=False, artifact=artifact.to_dict(),
                        coverage=coverage, row_cap=cap, reason=None, limits=None)
            self.ledger.save()
        self.counters.rows += artifact.rows
        self.counters.bytes += artifact.bytes
        self.new_run_ids.append(artifact.run_id)
        self.on_progress({"event": "captured", "table": name, "rows": artifact.rows,
                          "truncated": coverage["truncated"]})

    # -- lifecycle --

    def reconcile(self) -> None:
        """Re-verify reused artifacts and reopen gaps that larger limits could fill.

        An interrupted write is simply refetched: one query per table is cheap and
        keeps the ledger the only authority for coverage.
        """

        job_id = self.ledger.job_id
        current = {key: getattr(self.budgets, key) for key in self._LIMIT_KEYS}
        for name, table in self.tables.items():
            item = table["slice"]
            if item["state"] == COMPLETE:
                artifact = SliceArtifact.from_dict(item["artifact"])
                # The ledger's coverage and query claims must match the artifact's own
                # immutable metadata, not only its bytes.
                expected = expected_provenance(self.ledger.data, name)
                if not self.sink.verify(job_id, item["id"], artifact, expected=expected):
                    item.update(state=PENDING, artifact=None, coverage=None,
                                reason="artifact-unverified", cap=self.budgets.request_rows)
                    self.ledger.data["status"] = "open"
            elif item["state"] == FAILED and item["reason"] in _TRANSIENT_FAILURES:
                item.update(state=PENDING, reason=None)
                self.ledger.data["status"] = "open"
            elif item["state"] == IRRETRIEVABLE and isinstance(item.get("limits"), dict):
                limits = item["limits"]
                if any(current[key] > limits.get(key, current[key])
                       for key in ("max_rows", "max_bytes", "request_rows")) or (
                        current["min_request_rows"] < limits.get("min_request_rows", 0)):
                    item.update(state=PENDING, reason=None, limits=None,
                                cap=self.budgets.request_rows)
                    self.ledger.data["status"] = "open"
            item["inflight"] = False
            item["protocol_failures"] = 0
        self.ledger.save()

    async def run(self) -> Stop | None:
        resume_after = self.ledger.data.get("resume_after")
        if resume_after:
            remaining = (parse_instant(resume_after) - self.wall()).total_seconds()
            if remaining > 0:
                return Stop("rate-limited", math.ceil(remaining))
            self.ledger.data["resume_after"] = None
        try:
            while self.ledger.data["status"] in {"open", "closed"}:
                candidate = self._next()
                if candidate is None:
                    return None
                await self._fetch(*candidate)
                self.ledger.save()
            return None
        except _StopSignal as signal:
            return signal.stop
        except (asyncio.CancelledError, KeyboardInterrupt):
            self._finish(Stop("cancelled"))
            raise
        except BaseException as exc:
            self._finish(Stop("fatal", message=getattr(exc, "error_code", type(exc).__name__)))
            raise

    def _finish(self, stop: Stop | None) -> None:
        data = self.ledger.data
        total = Counters(**data["counters"])
        total.add(self.counters)
        data["counters"] = asdict(total)
        if stop is not None:
            data["stops"].append({**stop.to_dict(), "at": format_instant(self.wall())})
            data["stops"] = data["stops"][-50:]
        if data["status"] == "open" and not any(
                table["slice"]["state"] == PENDING for table in self.tables.values()):
            data["status"] = "closed"
        self.ledger.save()


def _table_summary(name: str, table: dict) -> dict:
    item = table["slice"]
    coverage = item["coverage"]
    rows = item["artifact"]["rows"] if item["artifact"] else 0
    total = coverage.get("source_total") if coverage else None
    fraction = (round(rows / total, 6) if total else 1.0) if item["artifact"] else 0.0
    return {
        "table": name, "kind": table["kind"], "time_column": table["time_column"],
        "status": item["state"], "captured_rows": rows, "source_total": total,
        "captured_fraction": fraction,
        "truncated": coverage["truncated"] if coverage else None, "coverage": coverage,
        "error_code": table.get("error_code"),
        "reasons": [item["reason"]] if item["reason"] and item["state"] != COMPLETE else [],
    }


def _report(ledger: CaptureLedger, runner: _Runner | None, stop: Stop | None,
            resumed: bool) -> CaptureReport:
    data = ledger.data
    tables = [_table_summary(name, table) for name, table in sorted(data["tables"].items())]
    captured = sorted(table["slice"]["artifact"]["run_id"] for table in data["tables"].values()
                      if table["slice"]["artifact"])
    pending = any(table["status"] == PENDING for table in tables)
    if data["status"] == "open" or (data["status"] == "superseded" and pending):
        status = "paused"
    elif all(table["status"] == COMPLETE for table in tables):
        status = "complete"
    else:
        status = "partial"
    return CaptureReport(
        job_id=ledger.job_id, resumed=resumed, status=status, interval=data["interval"],
        binding=data["binding"], stop=stop,
        counters=runner.counters if runner else Counters(),
        job_counters=Counters(**data["counters"]), tables=tables,
        exclusions=data["exclusions"], captured_run_ids=captured,
        new_run_ids=runner.new_run_ids if runner else [],
        continuation="Rerun the same command to resume this capture job."
        if status == "paused" else None,
        handoff=data["handoff"],
    )


async def capture_recent(
    client,
    *,
    schema_rows: list[dict],
    binding: dict,
    state_dir: Path,
    sink: CaptureSink,
    lookback: str | timedelta = "24h",
    plan_only: bool = False,
    budgets: CaptureBudgets | None = None,
    tables: tuple[str, ...] | None = None,
    on_progress: Callable[[dict], None] | None = None,
    now: Callable[[], datetime] | None = None,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], object] | None = None,
) -> CaptureReport:
    """Plan, resume or start one capture job and run it within ``budgets``."""

    budgets = budgets or CaptureBudgets()
    wall = now or (lambda: datetime.now(UTC))
    horizon = parse_lookback(lookback)
    plan = plan_capture(schema_rows, now=wall(), horizon=horizon, tables=tables)
    if plan_only:
        return CaptureReport(
            job_id=None, resumed=False, status="planned",
            interval={"start": format_instant(plan.start), "end": format_instant(plan.end)},
            binding=dict(binding), stop=None, counters=Counters(), job_counters=Counters(),
            tables=[{**table.to_dict(), "status": "planned"} for table in plan.tables],
            exclusions=list(plan.exclusions), captured_run_ids=[], new_run_ids=[],
        )
    directory = jobs_directory(state_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with exclusive_lock(directory / ".capture", timeout=1.0):
            ledger, resumed = open_job(state_dir, binding=binding, plan=plan, horizon=horizon,
                                       budgets=budgets, now=wall())
            runner = _Runner(client, ledger, sink, budgets, on_progress=on_progress,
                             clock=clock or time.monotonic, sleep=sleep or asyncio.sleep,
                             wall=wall)
            runner.reconcile()
            stop = await runner.run()
            runner._finish(stop)
            return _report(ledger, runner, stop, resumed)
    except Timeout as exc:
        raise ConflictError(
            "Another schema capture job is running for this tenant.",
            help_command="Wait for the running capture to finish, then rerun.",
        ) from exc


__all__ = [
    "CaptureBudgets", "CaptureLedger", "CaptureReport", "Counters", "Stop",
    "capture_recent", "expected_provenance", "jobs_directory", "ledger_run_ids",
    "live_capture_references",
    "live_capture_run_ids", "mark_capture_consumed", "open_job", "parse_lookback",
]
