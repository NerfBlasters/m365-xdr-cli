"""Helper utilities: time parsing, OData filter building, formatting."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from xdr_cli.exceptions import UsageError

_TIME_DELTA_RE = re.compile(r"^(\d+)([dhm])$")

_UNIT_MAP = {
    "d": "days",
    "h": "hours",
    "m": "minutes",
}


def parse_time_delta(s: str) -> datetime:
    """Parse a relative time string like '7d', '24h', '30m' into a UTC datetime."""
    match = _TIME_DELTA_RE.match(s.strip().lower())
    if not match:
        raise ValueError(f"Invalid time delta: '{s}'. Use format like '7d', '24h', '30m'.")
    amount = int(match.group(1))
    unit = _UNIT_MAP[match.group(2)]
    delta = timedelta(**{unit: amount})
    return datetime.now(tz=UTC) - delta


def split_csv(values: list[str] | None) -> list[str] | None:
    """Flatten a list that may contain comma-separated values into individual entries.

    Agents and humans type `--severity medium,high` expecting multi-value
    behavior. Typer only collects repeated flags, so the input arrives as
    `["medium,high"]`. This helper splits on commas and strips whitespace,
    so `["medium,high", "low"]` becomes `["medium", "high", "low"]`.
    """
    if not values:
        return values
    out: list[str] = []
    for v in values:
        out.extend(part.strip() for part in v.split(",") if part.strip())
    return out or None


def odata_string_literal(value: str) -> str:
    """Encode one value as an OData single-quoted string literal."""

    return "'" + value.replace("'", "''") + "'"


def validate_filter_choices(
    values: list[str] | None,
    allowed: frozenset[str],
    *,
    option: str,
    help_command: str,
) -> list[str] | None:
    """Reject unknown closed-enum filter values at the CLI boundary."""

    invalid = sorted(set(values or ()) - allowed)
    if invalid:
        error = UsageError(
            f"Invalid {option} value(s): {invalid}.",
            invalid={"kind": "enum", "value": invalid, "option": option},
            allowed=sorted(allowed),
            help_command=help_command,
        )
        error.error_code = "CLI_INVALID_ENUM"
        raise error
    return values


def build_odata_filter(
    *,
    severity: list[str] | None = None,
    status: list[str] | None = None,
    assigned_to: str | None = None,
    since: str | None = None,
    service_source: str | None = None,
) -> str:
    """Build an OData $filter string from keyword arguments."""
    parts: list[str] = []

    if severity:
        if len(severity) == 1:
            parts.append(f"severity eq {odata_string_literal(severity[0])}")
        else:
            clauses = " or ".join(
                f"severity eq {odata_string_literal(value)}" for value in severity
            )
            parts.append(f"({clauses})")

    if status:
        if len(status) == 1:
            parts.append(f"status eq {odata_string_literal(status[0])}")
        else:
            clauses = " or ".join(
                f"status eq {odata_string_literal(value)}" for value in status
            )
            parts.append(f"({clauses})")

    if assigned_to:
        parts.append(f"assignedTo eq {odata_string_literal(assigned_to)}")

    if since:
        dt = parse_time_delta(since)
        iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        parts.append(f"createdDateTime ge {iso}")

    if service_source:
        parts.append(f"serviceSource eq {odata_string_literal(service_source)}")

    return " and ".join(parts)


def format_timestamp(iso_str: str | None) -> str:
    """Format an ISO 8601 timestamp as a human-friendly relative time."""
    if not iso_str:
        return "-"
    try:
        # Handle various ISO formats
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        now = datetime.now(tz=UTC)
        diff = now - dt

        seconds = int(diff.total_seconds())
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            return f"{seconds // 60}m ago"
        elif seconds < 86400:
            return f"{seconds // 3600}h ago"
        else:
            return f"{seconds // 86400}d ago"
    except (ValueError, TypeError):
        return iso_str


def severity_style(severity: str) -> str:
    """Return a Rich style string for a severity level."""
    return {
        "high": "bold red",
        "medium": "yellow",
        "low": "cyan",
        "informational": "dim",
    }.get(severity.lower(), "")
