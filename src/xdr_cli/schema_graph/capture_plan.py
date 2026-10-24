"""Deterministic, network-free table selection for capture-first exploration.

Only getschema-queryable columns count. A table is bounded by its cached
``Timestamp`` or ``TimeGenerated`` column only when that column's cached type is
``datetime``; tables without either column are point-in-time state: they are
captured as a capped inventory sample rather than with a fake time window.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from xdr_cli.hunting_tables import TABLE_NAME
from xdr_cli.schema_graph.physical import canonical_storage_type, queryable_rows

TIME_COLUMNS = ("Timestamp", "TimeGenerated")
_COLUMN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}")
_FRACTION = re.compile(r"(?P<head>[^.]+)\.(?P<digits>\d+)(?P<zone>[+-]\d{2}:\d{2})?")

# Timed tables whose rows are periodic inventory reports rather than events. They
# are captured over the same interval, but repeated rows describe one entity.
SNAPSHOT_TABLES = frozenset({
    "AADRiskyUsers", "AgentsInfo", "AIAgentsInfo", "ConnectorStatusInfo",
    "DeviceBaselineComplianceAssessment", "DeviceBaselineComplianceProfiles",
    "DeviceInfo", "DeviceNetworkInfo", "DeviceTvmBrowserExtensions",
    "DeviceTvmCertificateInfo", "DeviceTvmHardwareFirmware", "DeviceTvmInfoGathering",
    "DeviceTvmSecureConfigurationAssessment", "IdentityAccountInfo", "IdentityInfo",
    "OAuthAppInfo",
})

KIND_EVENT = "event"
KIND_SNAPSHOT = "snapshot-timed"
KIND_STATE = "state"


@dataclass(frozen=True)
class CaptureTable:
    name: str
    kind: str
    time_column: str | None
    column_count: int
    key_columns: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name, "kind": self.kind,
            "time_column": self.time_column, "column_count": self.column_count,
            "key_columns": list(self.key_columns),
        }


@dataclass(frozen=True)
class CapturePlan:
    start: datetime
    end: datetime
    tables: tuple[CaptureTable, ...]
    exclusions: tuple[dict, ...]

    def to_dict(self) -> dict:
        return {
            "start": format_instant(self.start),
            "end": format_instant(self.end),
            "tables": [table.to_dict() for table in self.tables],
            "exclusions": list(self.exclusions),
        }


def format_instant(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_instant(value: str) -> datetime:
    """Parse API/ledger instants, tolerating 7-digit fractional seconds and ``Z``."""

    text = value.strip().replace("Z", "+00:00")
    match = _FRACTION.fullmatch(text)
    if match:
        text = f"{match['head']}.{match['digits'][:6].ljust(6, '0')}{match['zone'] or ''}"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def capture_interval(now: datetime, horizon: timedelta) -> tuple[datetime, datetime]:
    """Fix the half-open interval once: end is ``now`` floored to the minute."""

    if horizon <= timedelta(0):
        raise ValueError("capture horizon must be positive")
    end = now.astimezone(UTC).replace(second=0, microsecond=0)
    return end - horizon, end


def plan_capture(
    schema_rows: list[dict],
    *,
    now: datetime,
    horizon: timedelta = timedelta(hours=24),
    tables: tuple[str, ...] | None = None,
) -> CapturePlan:
    columns: dict[str, dict[str, set[str]]] = {}
    for row in queryable_rows(schema_rows):
        table, column = row.get("TableName"), row.get("ColumnName")
        if not isinstance(table, str) or not isinstance(column, str):
            continue
        storage = canonical_storage_type(row.get("ColumnType"))
        columns.setdefault(table, {}).setdefault(column, set()).add(storage or "unknown")
    start, end = capture_interval(now, horizon)
    selected, exclusions = [], []
    wanted = set(tables) if tables is not None else None
    for name in sorted(columns):
        if wanted is not None and name not in wanted:
            continue
        reason = _exclusion(name, columns[name])
        if reason:
            exclusions.append({"table": name, "reason": reason})
            continue
        time_column = next((c for c in TIME_COLUMNS if c in columns[name]), None)
        if time_column is None:
            kind = KIND_STATE
        else:
            kind = KIND_SNAPSHOT if name in SNAPSHOT_TABLES else KIND_EVENT
        selected.append(CaptureTable(
            name, kind, time_column, len(columns[name]), _key_columns(columns[name]),
        ))
    for name in sorted((wanted or set()) - set(columns)):
        exclusions.append({"table": name, "reason": "not-in-physical-cache"})
    return CapturePlan(start, end, tuple(selected), tuple(exclusions))


MAX_KEY_COLUMNS = 64


def _key_columns(columns: dict[str, set[str]]) -> tuple[str, ...]:
    """Retained scalar-key plan hints in name order; capped capture does not partition."""

    scalar = sorted(
        name for name, types in columns.items()
        if len(types) == 1 and next(iter(types)) not in {"dynamic", "unknown"}
        and _COLUMN.fullmatch(name)
    )
    return tuple(scalar[:MAX_KEY_COLUMNS])


def _exclusion(name: str, columns: dict[str, set[str]]) -> str | None:
    if not TABLE_NAME.fullmatch(name) or len(name) > 128:
        return "unsafe-table-name"  # artifact provenance accepts at most 128 characters
    if name.endswith("KB"):
        # Microsoft-wide knowledge-base catalogs contain no tenant identifiers.
        return "global-knowledge-base"
    for column in TIME_COLUMNS:
        if column in columns and columns[column] != {"datetime"}:
            return "time-column-not-datetime"
    return None
