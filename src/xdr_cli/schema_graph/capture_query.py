"""Read-only KQL for capture-first exploration, plus the wrapped-result contract.

One query captures one physical table. Timed tables return their most recent
rows inside the fixed interval, up to a row cap: below the cap that is the whole
interval, at the cap it is a recent sample whose oldest kept timestamp is
reported as an observed boundary. Untimed inventory tables return a capped
sample. Every row travels whole inside one ``__xdr_row`` packet, and one control
packet counts the same materialized rows so the caller can prove that every row
arrived without relying on a server truncation flag.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime

from xdr_cli.hunting_tables import TABLE_NAME
from xdr_cli.schema_graph.capture_plan import TIME_COLUMNS, format_instant, parse_instant

COMPILER_VERSION = "capture-query/v2"
CONTROL_MARKER = "v2"
MODE_RECENT = "recent"
MODE_SAMPLE = "sample"
CONTROL_COLUMNS = ("__xdr_count", "__xdr_bytes", "__xdr_control", "__xdr_more", "__xdr_floor",
                   "__xdr_total")
PAYLOAD_COLUMN = "__xdr_row"


@dataclass(frozen=True)
class SliceSpec:
    """One physical source table, bounded by ``[start, end)`` when it has a time column."""

    table: str
    time_column: str | None
    start: datetime | None
    end: datetime | None

    def __post_init__(self) -> None:
        if not TABLE_NAME.fullmatch(self.table):
            raise ValueError("unsafe capture table name")
        if self.time_column is None:
            if self.start is not None or self.end is not None:
                raise ValueError("untimed capture slices cannot carry time bounds")
        else:
            if self.time_column not in TIME_COLUMNS:
                raise ValueError("unsupported capture time column")
            if self.start is None or self.end is None or not self.start < self.end:
                raise ValueError("timed capture slices need start < end")

    @property
    def mode(self) -> str:
        return MODE_SAMPLE if self.time_column is None else MODE_RECENT

    def to_dict(self) -> dict:
        return {
            "table": self.table,
            "time_column": self.time_column,
            "start": format_instant(self.start) if self.start else None,
            "end": format_instant(self.end) if self.end else None,
        }

    @classmethod
    def from_dict(cls, value: dict) -> SliceSpec:
        if set(value) - {"table", "time_column", "start", "end"}:
            raise ValueError("unexpected capture slice fields")
        return cls(
            table=value["table"],
            time_column=value.get("time_column"),
            start=parse_instant(value["start"]) if value.get("start") else None,
            end=parse_instant(value["end"]) if value.get("end") else None,
        )


def kql_datetime(value: datetime) -> str:
    return f"datetime({format_instant(value)})"


def _bounded(spec: SliceSpec) -> str:
    return (f"{spec.table}\n| where {spec.time_column} >= {kql_datetime(spec.start)}"
            f" and {spec.time_column} < {kql_datetime(spec.end)}")


def compile_fetch_query(spec: SliceSpec, cap: int) -> str:
    """One wrapped capture query; ``cap + 1`` selected rows signal that more exist.

    Each row is packed into ``__xdr_payload`` before any helper column exists, so
    native columns live only inside the bag and can never collide with or be
    removed by the protocol. Row numbers are fixed inside the materialized result,
    so the control packet and the payloads describe exactly the same rows.
    """

    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        raise ValueError("fetch row cap must be positive")
    if spec.mode == MODE_SAMPLE:
        selected = f"{spec.table}\n| take {cap + 1}\n| project __xdr_payload=pack_all()"
        oldest, floor = "", "datetime(null)"
        total = f"toscalar({spec.table} | count)"
    else:
        column = spec.time_column
        selected = (f"{_bounded(spec)}\n| top {cap + 1} by {column} desc"
                    f"\n| project __xdr_payload=pack_all(), __xdr_time={column}")
        oldest = ", __xdr_oldest=min(__xdr_time)"
        floor = "iff(XdrCaptureMore, __xdr_oldest, datetime(null))"
        total = f"toscalar({_bounded(spec)} | count)"
    return (
        f"let XdrCaptureSource = materialize({selected}\n| serialize __xdr_n=row_number());\n"
        f"let XdrCaptureMore = toscalar(XdrCaptureSource | count) > {cap};\n"
        f"let XdrCaptureRows = XdrCaptureSource | where __xdr_n <= {cap};\n"
        f"union (XdrCaptureRows | summarize __xdr_count=count(), "
        f"__xdr_bytes=sum(estimate_data_size(__xdr_payload)){oldest}"
        f' | extend __xdr_control="{CONTROL_MARKER}", __xdr_more=toint(XdrCaptureMore), '
        f"__xdr_floor={floor}, __xdr_total={total}"
        f" | project __xdr_count, __xdr_bytes, __xdr_control, __xdr_more, __xdr_floor, "
        f"__xdr_total),\n"
        f"(XdrCaptureRows | project {PAYLOAD_COLUMN}=__xdr_payload)"
    )


def query_sha256(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()


def fetch_query_args(spec: SliceSpec, cap: int) -> dict:
    return {"compiler_version": COMPILER_VERSION, "slice": spec.to_dict(), "row_cap": cap,
            "mode": spec.mode}


def verify_capture_query(query_args: dict, query: str) -> bool:
    """Recompile pinned fetch arguments and require byte-identical query text."""

    try:
        if query_args.get("compiler_version") != COMPILER_VERSION:
            return False
        cap = query_args["row_cap"]
        if not isinstance(cap, int) or isinstance(cap, bool):
            return False
        spec = SliceSpec.from_dict(query_args["slice"])
        if query_args.get("mode") != spec.mode:
            return False
        return compile_fetch_query(spec, cap) == query
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


@dataclass(frozen=True)
class WrappedResult:
    source_count: int | None
    source_bytes: int | None
    more: bool | None
    floor: datetime | None
    source_total: int | None
    rows: list[dict]
    problems: tuple[str, ...]

    def complete(self, cap: int) -> bool:
        return (
            not self.problems
            and self.source_count is not None
            and self.source_count <= cap
            and len(self.rows) == self.source_count
            # The query always keeps exactly ``cap`` rows when more exist.
            and (not self.more or self.source_count == cap)
        )

    @property
    def truncated(self) -> bool:
        return bool(self.more)


def _count(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_wrapped(results: list[dict]) -> WrappedResult:
    """Separate control and payload packets; any ambiguous packet is a problem.

    Kusto's union pads each arm's missing columns with null (or "" for strings),
    so unused protocol fields must be empty while unexpected columns are rejected.
    """

    controls, rows, problems = [], [], []
    for packet in results:
        if not isinstance(packet, dict) or set(packet) - {*CONTROL_COLUMNS, PAYLOAD_COLUMN}:
            problems.append("unexpected-packet-columns")
            continue
        payload = packet.get(PAYLOAD_COLUMN)
        marker = packet.get("__xdr_control")
        if marker == CONTROL_MARKER and payload is None:
            count, size = packet.get("__xdr_count"), packet.get("__xdr_bytes")
            floor, total = packet.get("__xdr_floor"), packet.get("__xdr_total")
            more = packet.get("__xdr_more")  # 0/1: union results do not keep bool type
            try:
                floor = parse_instant(floor) if floor not in (None, "") else None
            except (TypeError, ValueError, AttributeError):
                problems.append("invalid-control-packet")
                continue
            if (not _count(count) or not isinstance(size, int | float)
                    or isinstance(size, bool) or not math.isfinite(size) or size < 0
                    or not (total is None or _count(total))
                    or type(more) is not int or more not in (0, 1)
                    or (floor is not None and not more)):
                problems.append("invalid-control-packet")
                continue
            controls.append((count, int(size), bool(more), floor, total))
        elif marker in (None, "") and isinstance(payload, dict) and all(
            packet.get(column) in (None, "") for column in CONTROL_COLUMNS
        ):
            rows.append(payload)
        else:
            problems.append("invalid-payload-packet")
    if len(controls) != 1:
        problems.append("missing-control-packet" if not controls else "duplicate-control-packet")
        return WrappedResult(None, None, None, None, None, rows, tuple(problems))
    count, size, more, floor, total = controls[0]
    return WrappedResult(count, size, more, floor, total, rows, tuple(problems))
