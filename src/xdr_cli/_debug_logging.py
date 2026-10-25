"""Debug diagnostics that never render bearer URLs or embedded URL credentials."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit, urlunsplit

_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _private_urls(text: str) -> str:
    def clean(match: re.Match) -> str:
        try:
            parts = urlsplit(match.group())
            # Keep route diagnostics, but drop userinfo, signed queries and fragments.
            host = parts.netloc.rsplit("@", 1)[-1]
            return urlunsplit((parts.scheme, host, parts.path, "", ""))
        except ValueError:
            return "<private URL>"

    return _URL.sub(clean, text)


class URLRedactionFilter(logging.Filter):
    """Scrub formatted record arguments before they reach any later handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _private_urls(record.getMessage())
        except (TypeError, ValueError):
            record.msg = "Debug record omitted because it could not be rendered."
        record.args = ()
        return True


class PrivateDebugFormatter(logging.Formatter):
    """Also scrub traceback text, which is rendered after ordinary logging filters."""

    def format(self, record: logging.LogRecord) -> str:
        try:
            return _private_urls(super().format(record))
        except (TypeError, ValueError):
            return "Debug record omitted because it could not be rendered."
