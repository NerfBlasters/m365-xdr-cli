"""Output formatting: JSON envelope on stdout, Rich-styled progress on stderr."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from xdr_cli.json_expansion import expand_json_string_columns

# stderr console for progress/warnings (never captured by pipes)
err_console = Console(stderr=True)


class OutputFormatter:
    """Emit a compact-command JSON envelope.

    The envelope's ``metadata`` block always carries ``session_id`` and
    ``session_label`` keys (both ``None`` when no session is active) so
    downstream consumers see a stable shape across commands. **Caller-
    provided metadata keys win on collision** so existing per-command
    metadata (``has_more``, ``execution_time_ms``, ``shown``, ``total``)
    remains authoritative.

    This is an additive change: callers like ``alerts list`` that previously
    omitted ``metadata`` now always emit it (with the session keys present),
    even when they pass no metadata of their own.
    """

    def __init__(
        self,
        expand_json: bool = True,
        session_id: str | None = None,
        session_label: str | None = None,
    ) -> None:
        self.expand_json = expand_json
        self.session_id = session_id
        self.session_label = session_label

    def format_output(
        self,
        data: Any,
        *,
        metadata: dict | None = None,
        columns: list | None = None,  # ignored; accepted for caller compat
        title: str = "",  # ignored; accepted for caller compat
    ) -> str:
        """Return a JSON string envelope: {status, data, metadata}.

        ``metadata`` always contains ``session_id`` and ``session_label``
        (present-but-null when no session). Caller-provided metadata keys
        override the session keys on collision.
        """
        del columns, title  # unused
        expanded = self._maybe_expand(data)
        envelope: dict[str, Any] = {"status": "success", "data": expanded}
        # Build envelope metadata: session keys first, then caller-provided
        # keys override on collision.
        envelope_metadata: dict[str, Any] = {
            "session_id": self.session_id,
            "session_label": self.session_label,
        }
        if metadata:
            envelope_metadata.update(metadata)
        envelope["metadata"] = envelope_metadata
        return json.dumps(envelope, indent=2, default=str)

    def _maybe_expand(self, data: Any) -> Any:
        """Expand known JSON-string columns unless opted out."""
        if not self.expand_json:
            return data
        # Only expand when data is a non-empty list of row dicts.
        if isinstance(data, list) and data and all(isinstance(row, dict) for row in data):
            return expand_json_string_columns(data)
        return data
