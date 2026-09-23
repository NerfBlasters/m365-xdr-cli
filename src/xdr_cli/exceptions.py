"""XDR CLI exception hierarchy with structured error output."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import IntEnum
from typing import Any


class ExitCode(IntEnum):
    """Stable process classes grouped by the recovery action they require."""

    SUCCESS = 0
    INTERNAL_ERROR = 1
    AUTH_ERROR = 2
    UPSTREAM_API_ERROR = 3
    CONFIG_ERROR = 4
    QUERY_ERROR = 5
    USAGE_ERROR = 6
    PERMISSION_ERROR = 7
    NOT_FOUND = 8
    RATE_LIMIT = 9
    TIMEOUT = 10
    NETWORK_ERROR = 11
    ARTIFACT_ERROR = 12
    CONFLICT = 13
    PARTIAL_SUCCESS = 14


class XDRError(Exception):
    """Base exception for all XDR CLI errors."""

    exit_code: int = ExitCode.INTERNAL_ERROR
    error_code: str = "INTERNAL_ERROR"
    suggested_fix: str | None = None

    def __init__(
        self,
        message: str = "An unexpected error occurred.",
        *,
        retryable: bool = False,
        invalid: dict[str, Any] | None = None,
        allowed: list[str] | None = None,
        suggestions: list[dict[str, Any]] | None = None,
        corrected_argv: list[str] | None = None,
        help_command: str | None = None,
        retry_after_seconds: int | None = None,
        request_ids: dict[str, str] | None = None,
        original: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.retryable = retryable
        self.invalid = invalid
        self.allowed = allowed or []
        self.suggestions = suggestions or []
        self.corrected_argv = corrected_argv
        self.help_command = help_command
        self.retry_after_seconds = retry_after_seconds
        self.request_ids = request_ids
        self.original = original
        super().__init__(message)


# --- Auth errors (exit code 2) ---


class AuthError(XDRError):
    exit_code = ExitCode.AUTH_ERROR
    error_code = "AUTH_LOGIN_REQUIRED"
    suggested_fix = (
        "Run 'xdr auth status'; if login is required, run 'xdr auth login' "
        "interactively."
    )


class NotAuthenticatedError(AuthError):
    error_code = "NOT_AUTHENTICATED"
    suggested_fix = (
        "Run 'xdr auth status'; if login is required, run 'xdr auth login' "
        "interactively."
    )

    def __init__(
        self,
        message: str | None = None,
        *,
        suggested_fix: str | None = None,
        help_command: str = "xdr auth status",
    ) -> None:
        super().__init__(
            message
            or (
                "Not authenticated. Run 'xdr auth status'; if login is required, "
                "run 'xdr auth login' interactively."
            ),
            help_command=help_command,
        )
        if suggested_fix is not None:
            self.suggested_fix = suggested_fix


class TokenExpiredError(AuthError):
    error_code = "TOKEN_EXPIRED"
    suggested_fix = (
        "Run 'xdr auth status'; if login is required, run 'xdr auth login' "
        "interactively."
    )

    def __init__(self) -> None:
        super().__init__(
            "Authentication token has expired.",
            help_command="xdr auth status",
        )


# --- API errors (exit code 3) ---


class APIError(XDRError):
    exit_code = ExitCode.UPSTREAM_API_ERROR
    error_code = "API_ERROR"

    def __init__(
        self,
        message: str = "API request failed.",
        *,
        status_code: int | None = None,
        detail: str | dict | list | None = None,
    ) -> None:
        self.status_code = status_code
        # Structured detail (dict/list from Graph's innerError or details) is
        # preferred; raw response text is a fallback for debugging.
        self.detail = detail
        super().__init__(
            message,
            original={
                "type": "HTTPError",
                "status": status_code,
                "message": message,
                "detail": detail,
            },
        )


class RateLimitError(APIError):
    exit_code = ExitCode.RATE_LIMIT
    error_code = "API_RATE_LIMITED"

    def __init__(self, retry_after: int = 0) -> None:
        self.retry_after = retry_after
        self.suggested_fix = f"Rate limited. Retry after {retry_after} seconds."
        super().__init__(
            f"API rate limit exceeded. Retry after {retry_after}s.",
            status_code=429,
        )
        self.retryable = True
        self.retry_after_seconds = retry_after


class NotFoundError(APIError):
    exit_code = ExitCode.NOT_FOUND
    error_code = "API_NOT_FOUND"

    def __init__(self, resource_type: str = "resource", resource_id: str = "") -> None:
        self.suggested_fix = f"Verify the {resource_type} ID is correct."
        identifier = f" {resource_id!r}" if resource_id else ""
        super().__init__(
            f"{resource_type}{identifier} not found.",
            status_code=404,
        )


class LocalNotFoundError(XDRError):
    """A requested local artifact/session/cache entry does not exist."""

    exit_code = ExitCode.NOT_FOUND
    error_code = "LOCAL_NOT_FOUND"

    def __init__(self, resource_type: str = "resource", resource_id: str = "") -> None:
        identifier = f" {resource_id!r}" if resource_id else ""
        super().__init__(f"{resource_type}{identifier} not found.")


class ForbiddenError(APIError):
    exit_code = ExitCode.PERMISSION_ERROR
    error_code = "PERMISSION_MISSING_SCOPE"

    def __init__(self, required_scope: str = "") -> None:
        msg = "Insufficient permissions."
        if required_scope:
            msg = f"Insufficient permissions. Required scope: {required_scope}."
        self.suggested_fix = "Check your Entra ID app permissions and RBAC roles."
        super().__init__(msg, status_code=403)


# --- Retry-After parsing (shared by both HTTP clients) ---

# Fallback wait (seconds) when a 429 carries no usable `Retry-After`.
_DEFAULT_RETRY_AFTER = 60


def parse_retry_after(value: str | None) -> int:
    """Seconds to wait from a 429 `Retry-After`, tolerant of both RFC 7231 forms.

    `Retry-After` may be a delta-seconds integer OR an HTTP-date
    ("Wed, 21 Oct 2026 07:28:00 GMT"). A bare `int()` crashes on the date form
    with a `ValueError` which — not being an `APIError` — escapes the clients'
    response checks (an uncaught traceback in a command, or bypassing a
    never-raise cookie-verify probe). Parse both forms and fall back to
    `_DEFAULT_RETRY_AFTER` on anything unrecognized; an HTTP-date already in
    the past clamps to 0.
    """
    if value is None:
        return _DEFAULT_RETRY_AFTER
    text = value.strip()
    if text.isdigit():
        return int(text)
    try:
        retry_at = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return _DEFAULT_RETRY_AFTER
    if retry_at is None:
        return _DEFAULT_RETRY_AFTER
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=UTC)
    return max(0, int((retry_at - datetime.now(UTC)).total_seconds()))


# --- Config errors (exit code 4) ---


class ConfigError(XDRError):
    exit_code = ExitCode.CONFIG_ERROR
    error_code = "CONFIG_ERROR"
    suggested_fix = "Check ~/.xdr-cli/config.toml."


# --- Query errors (exit code 5) ---


class QueryError(XDRError):
    exit_code = ExitCode.QUERY_ERROR
    error_code = "QUERY_ERROR"
    suggested_fix = "Check your KQL query syntax."


def query_error_from_message(
    message: str,
    *,
    original: dict[str, Any] | None = None,
) -> QueryError:
    """Add cache-only schema discovery when Defender names an unknown symbol."""

    table_patterns = [
        r"(?:table|tabular expression)[^'\"]*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
        r"Failed to resolve table or column expression named ['\"]([^'\"]+)['\"]",
    ]
    column_patterns = [
        r"(?:column|scalar expression)[^'\"]*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
        r"name ['\"]([^'\"]+)['\"] does not refer to any known column",
    ]
    for pattern in table_patterns:
        if match := re.search(pattern, message, re.I):
            symbol = match.group(1)
            error = QueryError(
                message,
                invalid={"kind": "table", "value": symbol},
                suggestions=[
                    {
                        "reason": "schema_discovery",
                        "message": f"xdr schema tables --search {symbol}",
                        "confidence": "exact",
                    }
                ],
                help_command=f"xdr schema tables --search {symbol}",
                original=original,
            )
            error.error_code = "QUERY_UNKNOWN_TABLE"
            return error
    for pattern in column_patterns:
        if match := re.search(pattern, message, re.I):
            symbol = match.group(1)
            error = QueryError(
                message,
                invalid={"kind": "column", "value": symbol},
                suggestions=[
                    {
                        "reason": "schema_discovery",
                        "message": "xdr schema tables",
                        "confidence": "exact",
                    }
                ],
                help_command="xdr schema tables",
                original=original,
            )
            error.error_code = "QUERY_UNKNOWN_COLUMN"
            return error
    error = QueryError(
        message,
        help_command="xdr schema tables",
        original=original,
    )
    error.error_code = "QUERY_SEMANTIC_ERROR"
    return error


class UsageError(XDRError):
    exit_code = ExitCode.USAGE_ERROR
    error_code = "CLI_USAGE_ERROR"


class PermissionError(XDRError):
    exit_code = ExitCode.PERMISSION_ERROR
    error_code = "PERMISSION_DENIED"


class NetworkError(XDRError):
    exit_code = ExitCode.NETWORK_ERROR
    error_code = "API_NETWORK_ERROR"


class TimeoutError(XDRError):
    exit_code = ExitCode.TIMEOUT
    error_code = "API_TIMEOUT"

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, retryable=True, **kwargs)


class ArtifactError(XDRError):
    exit_code = ExitCode.ARTIFACT_ERROR
    error_code = "ARTIFACT_WRITE_FAILED"
    suggested_fix = "Check free space and permissions under ~/.xdr-cli/results."


class ConflictError(XDRError):
    exit_code = ExitCode.CONFLICT
    error_code = "STATE_CONFLICT"


class PartialSuccessError(XDRError):
    exit_code = ExitCode.PARTIAL_SUCCESS
    error_code = "PARTIAL_SUCCESS"


# --- Formatters ---


def format_error_json(err: XDRError) -> str:
    """Format one fixed-shape, one-line error record for automation."""

    suggestions = list(err.suggestions)
    if err.suggested_fix and not suggestions:
        suggestions.append(
            {
                "reason": "recovery",
                "message": err.suggested_fix,
                "confidence": "exact",
            }
        )
    error_dict: dict[str, Any] = {
        "schema_version": 1,
        "type": type(err).__name__,
        "message": err.message,
        "code": err.error_code,
        "exit_code": int(err.exit_code),
        "retryable": err.retryable,
        "invalid": err.invalid,
        "allowed": err.allowed,
        "suggestions": suggestions,
        "corrected_argv": err.corrected_argv,
        "help_command": err.help_command,
        "retry_after_seconds": err.retry_after_seconds,
        "request_ids": err.request_ids,
        "original": err.original,
    }
    return json.dumps(
        {"status": "error", "error": error_dict},
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
