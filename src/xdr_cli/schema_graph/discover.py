"""Bounded, value-free discovery of nested Advanced Hunting result shapes."""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from typing import Any

from xdr_cli.json_expansion import JSON_STRING_COLUMNS
from xdr_cli.schema_graph.model import FieldLocator, GraphValidationError


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


@dataclass(frozen=True, slots=True)
class NestedFieldObservation:
    locator: FieldLocator
    observed_types: tuple[str, ...]
    present_rows: int
    non_null_rows: int
    occurrences: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "locator": str(self.locator),
            "json_pointer": self.locator.json_pointer,
            "observed_types": list(self.observed_types),
            "present_rows": self.present_rows,
            "non_null_rows": self.non_null_rows,
            "occurrences": self.occurrences,
        }


@dataclass(frozen=True, slots=True)
class NestedDiscoveryResult:
    table: str
    rows_scanned: int
    parse_failures: int
    truncated: bool
    fields: tuple[NestedFieldObservation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "table": self.table,
            "rows_scanned": self.rows_scanned,
            "parse_failures": self.parse_failures,
            "truncated": self.truncated,
            "fields": [field.to_dict() for field in self.fields],
        }


@dataclass(slots=True)
class _MutableStats:
    observed_types: set[str]
    present_rows: int = 0
    non_null_rows: int = 0
    occurrences: int = 0


def discover_nested_fields(
    table: str,
    rows: list[dict[str, Any]],
    *,
    max_depth: int = 8,
    max_paths: int = 1024,
    max_array_items: int = 32,
    max_keys_per_object: int = 256,
) -> NestedDiscoveryResult:
    """Discover nested field paths without retaining any leaf values.

    Arrays use a `*` JSON-Pointer segment, so element indexes do not create
    unstable graph fields. Only the closed JSON-string column registry is
    parsed when a value is still encoded as text.
    """

    if not table or not table[0].isalpha() or not table.replace("_", "").isalnum():
        raise GraphValidationError("table name is invalid")
    for label, value in (
        ("max_depth", max_depth),
        ("max_paths", max_paths),
        ("max_array_items", max_array_items),
        ("max_keys_per_object", max_keys_per_object),
    ):
        if value < 1:
            raise GraphValidationError(f"{label} must be positive")

    stats: dict[tuple[str, tuple[str, ...]], _MutableStats] = {}
    parse_failures = 0
    truncated = False

    for row in rows:
        row_seen: dict[tuple[str, tuple[str, ...]], list[object]] = {}

        def visit(
            column: str,
            path: tuple[str, ...],
            value: object,
            depth: int,
            row_observed: dict[tuple[str, tuple[str, ...]], list[object]] = row_seen,
        ) -> None:
            nonlocal truncated
            if path:
                key = (column, path)
                if (
                    key not in stats
                    and key not in row_observed
                    and len(stats) + len(row_observed) >= max_paths
                ):
                    truncated = True
                    return
                row_observed.setdefault(key, []).append(value)
            if depth >= max_depth:
                if isinstance(value, (dict, list)):
                    truncated = True
                return
            if isinstance(value, dict):
                keys = sorted(value)
                if len(keys) > max_keys_per_object:
                    truncated = True
                for key in keys[:max_keys_per_object]:
                    if not key or any(ord(char) < 32 for char in key):
                        continue
                    visit(column, (*path, key), value[key], depth + 1)
            elif isinstance(value, list):
                if len(value) > max_array_items:
                    truncated = True
                for item in value[:max_array_items]:
                    visit(column, (*path, "*"), item, depth + 1)

        for column in sorted(JSON_STRING_COLUMNS & row.keys()):
            value = row[column]
            if isinstance(value, str) and value:
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    parse_failures += 1
                    continue
            if isinstance(value, (dict, list)):
                visit(column, (), value, 0)

        for key, values in row_seen.items():
            current = stats.setdefault(key, _MutableStats(observed_types=set()))
            current.present_rows += 1
            current.non_null_rows += int(any(value is not None for value in values))
            current.occurrences += len(values)
            current.observed_types.update(_json_type(value) for value in values)

    observations = []
    for (column, path), current in sorted(stats.items()):
        with contextlib.suppress(GraphValidationError):
            locator = FieldLocator(table=table, column=column, json_path=path)
            observations.append(
                NestedFieldObservation(
                    locator=locator,
                    observed_types=tuple(sorted(current.observed_types)),
                    present_rows=current.present_rows,
                    non_null_rows=current.non_null_rows,
                    occurrences=current.occurrences,
                )
            )
    return NestedDiscoveryResult(
        table=table,
        rows_scanned=len(rows),
        parse_failures=parse_failures,
        truncated=truncated,
        fields=tuple(observations),
    )
