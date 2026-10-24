"""Frozen compiler for verifying historical v1 capture artifacts.

It is never used to start new capture jobs. Keeping the exact old fetch grammar
lets existing evidence remain verifiable after the collection strategy changes.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime

from xdr_cli.hunting_tables import TABLE_NAME
from xdr_cli.schema_graph.capture_plan import TIME_COLUMNS, format_instant, parse_instant

COMPILER_VERSION = "capture-query/v1"
CONTROL_MARKER = "v1"
PAYLOAD_COLUMN = "__xdr_row"
SOURCE_LET = "XdrCaptureSource"
_COLUMN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}")

@dataclass(frozen=True)
class SliceSpec:
    """One physical source table restricted to ``[start, end)`` and a hash partition."""

    table: str
    time_column: str | None
    start: datetime | None
    end: datetime | None
    partition: tuple[int, int] | None = None
    partition_columns: tuple[str, ...] = ()

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
        if self.partition is not None:
            index, modulus = self.partition
            if not (isinstance(index, int) and isinstance(modulus, int)
                    and modulus >= 2 and 0 <= index < modulus):
                raise ValueError("invalid capture partition")
            if not self.partition_columns:
                raise ValueError("partitioned capture slices need pinned key columns")
        if any(not _COLUMN.fullmatch(column) for column in self.partition_columns):
            raise ValueError("unsafe partition column name")

    def to_dict(self) -> dict:
        return {
            "table": self.table,
            "time_column": self.time_column,
            "start": format_instant(self.start) if self.start else None,
            "end": format_instant(self.end) if self.end else None,
            "partition": list(self.partition) if self.partition else None,
            "partition_columns": list(self.partition_columns),
        }

    @classmethod
    def from_dict(cls, value: dict) -> SliceSpec:
        partition = value.get("partition")
        return cls(
            table=value["table"],
            time_column=value.get("time_column"),
            start=parse_instant(value["start"]) if value.get("start") else None,
            end=parse_instant(value["end"]) if value.get("end") else None,
            partition=tuple(partition) if partition is not None else None,
            partition_columns=tuple(value.get("partition_columns") or ()),
        )


def kql_datetime(value: datetime) -> str:
    return f"datetime({format_instant(value)})"


def _row_hash(columns: tuple[str, ...], modulus: int) -> str:
    """Hash pinned scalar columns in a fixed order.

    ``pack_all()`` property order is not guaranteed between evaluations, so it
    cannot assign rows to partitions. A fixed scalar key always can (the key need
    not be unique or collision-free, only deterministic): rows with equal keys
    share a bucket, which can only make a bucket too large (an explicit
    gap), never move a row between two separately fetched partitions.
    """

    parts = [f"tostring({column})" for column in columns]
    key = parts[0] if len(parts) == 1 else f'strcat_delim("|", {", ".join(parts)})'
    return f"hash({key}, {modulus})"


def _source_lines(spec: SliceSpec) -> list[str]:
    lines = [spec.table]
    if spec.time_column is not None:
        lines.append(
            f"| where {spec.time_column} >= {kql_datetime(spec.start)}"
            f" and {spec.time_column} < {kql_datetime(spec.end)}"
        )
    if spec.partition is not None:
        index, modulus = spec.partition
        lines.append(f"| where {_row_hash(spec.partition_columns, modulus)} == {index}")
    return lines


def compile_fetch_query(spec: SliceSpec, cap: int) -> str:
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        raise ValueError("fetch row cap must be positive")
    source = "\n".join(_source_lines(spec))
    return (
        f"let {SOURCE_LET} = materialize({source}\n| take {cap + 1});\n"
        f"union ({SOURCE_LET} | summarize __xdr_count=count(), "
        f'__xdr_bytes=sum(estimate_data_size(*)) | extend __xdr_control="{CONTROL_MARKER}"),\n'
        f"({SOURCE_LET} | project {PAYLOAD_COLUMN}=pack_all())"
    )


def query_sha256(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()


def fetch_query_args(spec: SliceSpec, cap: int) -> dict:
    return {"compiler_version": COMPILER_VERSION, "slice": spec.to_dict(), "row_cap": cap}


def verify_capture_query(query_args: dict, query: str) -> bool:
    """Recompile pinned fetch arguments and require byte-identical query text."""

    try:
        if query_args.get("compiler_version") != COMPILER_VERSION:
            return False
        cap = query_args["row_cap"]
        if not isinstance(cap, int) or isinstance(cap, bool):
            return False
        return compile_fetch_query(SliceSpec.from_dict(query_args["slice"]), cap) == query
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
