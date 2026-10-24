"""In-memory hunting service that evaluates the capture compiler's KQL shapes."""

from __future__ import annotations

import hashlib
import json
import re

from xdr_cli.hunting_result import HuntingResult
from xdr_cli.schema_graph.capture_contract import SliceArtifact
from xdr_cli.schema_graph.capture_plan import parse_instant

_RECENT = re.compile(
    r"let XdrCaptureSource = materialize\((?P<table>\w+)\n"
    r"\| where (?P<column>\w+) >= datetime\((?P<a>[^)]+)\)"
    r" and (?P=column) < datetime\((?P<b>[^)]+)\)"
    r"\n\| top (?P<top>\d+) by (?P=column) desc\n"
)
_SAMPLE = re.compile(r"let XdrCaptureSource = materialize\((?P<table>\w+)\n\| take (?P<take>\d+)\n")


class FakeHunting:
    """Evaluate compiled capture queries over ``tables`` (lists of dict rows).

    Hooks let tests inject service behavior: ``fail(query)`` may raise;
    ``payload_limit`` drops payload packets beyond N (silent server truncation);
    ``before_fetch(query)`` can mutate data before evaluation.
    """

    def __init__(self, tables: dict[str, list[dict]], *, surface: str = "graph") -> None:
        self.tables = tables
        self.surface = surface
        self.calls: list[str] = []
        self.fail = None
        self.payload_limit: int | None = None
        self.drop_control_above: int | None = None
        self.before_fetch = None

    async def execute_hunting(self, query: str) -> HuntingResult:
        self.calls.append(query)
        if self.fail is not None:
            self.fail(query)
        if self.before_fetch is not None:
            self.before_fetch(query)
        if match := _RECENT.search(query):
            column = match["column"]
            lower, upper = parse_instant(match["a"]), parse_instant(match["b"])
            window = [row for row in self.tables.get(match["table"], [])
                      if lower <= parse_instant(row[column]) < upper]
            cap = int(match["top"]) - 1
            ordered = sorted(window, key=lambda row: parse_instant(row[column]), reverse=True)
            selected, more = ordered[:cap], len(ordered) > cap
            floor = min(parse_instant(row[column]) for row in selected) if more else None
            total = len(window)
        else:
            match = _SAMPLE.search(query)
            assert match, query
            source = self.tables.get(match["table"], [])
            cap = int(match["take"]) - 1
            selected, more = source[:cap], len(source) > cap
            floor, total = None, len(source)
        control = {"__xdr_count": len(selected),
                   "__xdr_bytes": sum(len(json.dumps(row)) // 3 for row in selected),
                   "__xdr_control": "v2", "__xdr_more": int(more),
                   "__xdr_floor": floor.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if floor else None,
                   "__xdr_total": total, "__xdr_row": None}
        payloads = [{"__xdr_count": None, "__xdr_bytes": None, "__xdr_control": "",
                     "__xdr_more": None, "__xdr_floor": None, "__xdr_total": None,
                     "__xdr_row": dict(row)} for row in selected]
        if self.payload_limit is not None:
            payloads = payloads[: self.payload_limit]
        packets = [control, *payloads]
        if self.drop_control_above is not None and len(selected) > self.drop_control_above:
            packets = payloads  # byte truncation cut the control arm
        return HuntingResult(schema=[], results=packets, stats={},
                             metadata={"execution_surface": self.surface})


class MemorySink:
    def __init__(self) -> None:
        self.slices: dict[tuple[str, str], tuple[object, list[dict], SliceArtifact]] = {}
        self.writes = 0
        self.fail_after_write = None
        self.invalid: set[str] = set()

    def write_slice(self, capture, rows):
        self.writes += 1
        payload = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        artifact = SliceArtifact(
            run_id=f"run-{self.writes:05d}",
            data_sha256=hashlib.sha256(payload.encode()).hexdigest(),
            rows=len(rows), bytes=len(payload.encode()),
        )
        self.slices[capture.job_id, capture.window_id] = (capture, list(rows), artifact)
        if self.fail_after_write is not None:
            self.fail_after_write(capture)
        return artifact

    def find_slice(self, job_id, window_id):
        entry = self.slices.get((job_id, window_id))
        return entry[2] if entry else None

    def verify(self, job_id, window_id, artifact, *, expected=None):
        entry = self.slices.get((job_id, window_id))
        if not entry or entry[2] != artifact or artifact.run_id in self.invalid:
            return False
        capture = entry[0]
        return expected is None or expected == {
            "coverage": capture.coverage, "query_args": capture.query_args,
            "binding": capture.binding, "interval": capture.interval, "kind": capture.kind,
        }

    def rows(self, table: str | None = None) -> list[dict]:
        return [row for (capture, rows, _) in self.slices.values()
                if table is None or capture.spec.table == table for row in rows]

    def capture(self, table: str):
        matches = [capture for capture, _, _ in self.slices.values()
                   if capture.spec.table == table]
        return matches[-1] if matches else None


def schema_rows(tables: dict[str, dict[str, str]]) -> list[dict]:
    rows = []
    for table, columns in tables.items():
        for ordinal, (column, kind) in enumerate(columns.items()):
            rows.append({"TableName": table, "ColumnName": column, "ColumnType": kind,
                         "ColumnOrdinal": ordinal, "Sources": ["getschema"]})
    return rows
