"""Tests for exception hierarchy."""

import json

from xdr_cli.exceptions import (
    APIError,
    AuthError,
    ConfigError,
    ForbiddenError,
    NotAuthenticatedError,
    NotFoundError,
    QueryError,
    RateLimitError,
    TokenExpiredError,
    XDRError,
    format_error_json,
    parse_retry_after,
)


def test_xdr_error_has_exit_code_1():
    err = XDRError("something broke")
    assert err.exit_code == 1
    assert str(err) == "something broke"


def test_auth_error_has_exit_code_2():
    err = AuthError("bad auth")
    assert err.exit_code == 2
    assert isinstance(err, XDRError)


def test_not_authenticated_error():
    err = NotAuthenticatedError()
    assert "xdr auth status" in err.message
    assert "xdr auth login" in err.message
    assert err.exit_code == 2
    assert "xdr auth status" in err.suggested_fix
    assert "xdr auth login" in err.suggested_fix
    assert err.help_command == "xdr auth status"


def test_token_expired_error():
    err = TokenExpiredError()
    assert err.exit_code == 2


def test_api_error_has_exit_code_3():
    err = APIError("server error", status_code=500)
    assert err.exit_code == 3
    assert err.status_code == 500


def test_rate_limit_error_has_retry_after():
    err = RateLimitError(retry_after=30)
    assert err.exit_code == 9
    assert err.retry_after == 30
    assert "30" in err.message


def test_not_found_error():
    err = NotFoundError("incident", "12345")
    assert "12345" in err.message
    assert err.status_code == 404


def test_forbidden_error():
    err = ForbiddenError("SecurityIncident.Read.All")
    assert err.status_code == 403


def test_config_error_has_exit_code_4():
    err = ConfigError("missing tenant_id")
    assert err.exit_code == 4


def test_query_error_has_exit_code_5():
    err = QueryError("KQL syntax error near 'wheree'")
    assert err.exit_code == 5


def test_format_error_json():
    err = NotAuthenticatedError()
    result = format_error_json(err)
    parsed = json.loads(result)
    assert parsed["status"] == "error"
    assert parsed["error"]["type"] == "NotAuthenticatedError"
    assert parsed["error"]["code"] == "NOT_AUTHENTICATED"
    assert parsed["error"]["suggestions"][0]["confidence"] == "exact"


def test_format_error_json_api_error():
    err = RateLimitError(retry_after=60)
    result = format_error_json(err)
    parsed = json.loads(result)
    assert parsed["error"]["type"] == "RateLimitError"
    assert parsed["error"]["retry_after_seconds"] == 60


def test_format_error_json_surfaces_detail():
    """APIError.detail flows to the envelope so consumers see which field was rejected."""
    err = APIError(
        "API 400: BadRequest — Invalid filter clause.",
        status_code=400,
        detail={"code": "BadRequest", "request-id": "abc-123"},
    )
    parsed = json.loads(format_error_json(err))
    assert parsed["error"]["original"]["status"] == 400
    assert parsed["error"]["original"]["detail"] == {
        "code": "BadRequest",
        "request-id": "abc-123",
    }


def test_format_error_json_no_detail_omits_field():
    """No detail → no stray null in the envelope."""
    err = APIError("generic failure", status_code=500)
    parsed = json.loads(format_error_json(err))
    assert parsed["error"]["original"]["detail"] is None


# --- parse_retry_after: RFC 7231 delta-seconds OR HTTP-date, never crash ---


class TestParseRetryAfter:
    def test_integer_delta_seconds(self):
        assert parse_retry_after("120") == 120

    def test_surrounding_whitespace_tolerated(self):
        assert parse_retry_after("  90 ") == 90

    def test_missing_header_falls_back_to_default(self):
        assert parse_retry_after(None) == 60

    def test_unparseable_value_falls_back_to_default(self):
        assert parse_retry_after("soon-ish") == 60

    def test_http_date_in_the_past_clamps_to_zero(self):
        assert parse_retry_after("Wed, 21 Oct 1998 07:28:00 GMT") == 0

    def test_http_date_in_the_future_returns_a_positive_int(self):
        # Exact value is now-relative; it must be a large positive int and must
        # NOT raise (the bug was a bare int() throwing ValueError on this form).
        result = parse_retry_after("Fri, 31 Dec 2100 23:59:59 GMT")
        assert isinstance(result, int)
        assert result > 0
