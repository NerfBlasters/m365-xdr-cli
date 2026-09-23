"""JSON-string column expansion for Advanced Hunting results.

Microsoft's hunting surfaces return certain columns as JSON-encoded strings
rather than structured objects (e.g. `RawEventData` on `CloudAppEvents`,
`AdditionalFields` on `DeviceEvents`). Expanding them before artifact storage
makes the saved JSONL directly searchable and keeps nested values available
to shell-native `jq` processing.

The column list is closed: adding a column is a deliberate code change,
not a runtime heuristic. Heuristic detection would occasionally false-match
and silently corrupt legitimate string columns.
"""

from __future__ import annotations

import contextlib
import json
from copy import deepcopy
from typing import Any

JSON_STRING_COLUMNS: frozenset[str] = frozenset(
    {
        "RawEventData",         # CloudAppEvents, CloudAuditEvents
        "AdditionalFields",     # DeviceEvents (verified on this tenant)
        "ResourceData",         # cloud resource tables
        "DetectionMethods",     # EmailEvents — nested JSON per MS schema docs
    }
)


def expand_json_string_columns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a copy of rows where known JSON-string columns are parsed.

    Columns outside JSON_STRING_COLUMNS are untouched. Non-string values in a
    known column (None, empty string, already-parsed dict) are passed through.
    A string value that fails to parse as JSON stays as the raw string —
    fail-soft keeps the investigation running; the hint engine (#11) will
    surface parse failures when it lands.
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        new_row = deepcopy(row)
        for col in JSON_STRING_COLUMNS:
            if col not in new_row:
                continue
            value = new_row[col]
            if not isinstance(value, str) or value == "":
                continue
            # fail-soft: keep raw string on parse failure
            with contextlib.suppress(json.JSONDecodeError):
                new_row[col] = json.loads(value)
        out.append(new_row)
    return out
