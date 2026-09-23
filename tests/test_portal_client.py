"""Tests for the unofficial Defender portal apiproxy client (`PortalClient`).

`PortalClient` is a side-channel HTTP client parallel to `XDRClient` (see
tests/test_client.py) that talks to `security.microsoft.com/apiproxy/mtp/`.
It is async (mirrors `httpx.AsyncClient`) and takes a single `auth`
parameter implementing the `PortalAuthStrategy` protocol — `BearerAuth`
(MSAL-backed token source) or `CookieAuth` (session cookies) — rather than
separate `portal_auth=`/`cookie_auth=` kwargs.

This is a RED-only test file for TDD Task 3: `xdr_cli.portal_client` does
not exist yet, so every test here is expected to fail at collection with a
ModuleNotFoundError until Task 4 implements `portal_client.py`.
"""

from unittest.mock import MagicMock

import httpx
import pytest
import respx

from xdr_cli.exceptions import APIError, AuthError, NotAuthenticatedError, RateLimitError
from xdr_cli.portal_client import (
    BearerAuth,
    CookieAuth,
    PortalClient,
    RefreshTokenAuth,
)

BASE_URL = "https://security.microsoft.com/apiproxy/mtp/"


@pytest.fixture()
def mock_portal_auth():
    """A MagicMock token source, standing in for `PortalAuth`.

    `BearerAuth.apply()` calls `.get_token()` synchronously (see plan Task 4
    Step 1), so a plain MagicMock — not AsyncMock — is correct here.
    """
    portal_auth = MagicMock()
    portal_auth.get_token.return_value = "fake-token"
    return portal_auth


@pytest.fixture()
def bearer_client(mock_portal_auth):
    return PortalClient(auth=BearerAuth(mock_portal_auth))


# ---------------------------------------------------------------------------
# Step 1: request/response contract (brief cases 1-3)
# ---------------------------------------------------------------------------


@respx.mock
async def test_get_sends_bearer_authorization_header(bearer_client, mock_portal_auth):
    """Case 1: BearerAuth calls portal_auth.get_token() and sends it as Bearer."""
    route = respx.get(f"{BASE_URL}some/path").respond(json={"ok": True})

    await bearer_client.get("some/path")

    assert route.called
    assert route.calls[0].request.headers["authorization"] == "Bearer fake-token"
    mock_portal_auth.get_token.assert_called_once()


@respx.mock
async def test_get_uses_apiproxy_mtp_base_url(bearer_client):
    """Case 2: base URL is https://security.microsoft.com/apiproxy/mtp/."""
    route = respx.get(
        "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/abc123/events"
    ).respond(json={"Items": []})

    await bearer_client.get("mdeTimelineExperience/machines/abc123/events")

    assert route.called


@respx.mock
async def test_probe_accepts_any_successful_json_shape(bearer_client):
    """Auth verification cares about HTTP success, not a dict-only API body."""
    route = respx.get(f"{BASE_URL}ndr/machines").respond(json=[])

    await bearer_client.probe("ndr/machines")

    assert route.called


@respx.mock
async def test_successful_response_is_json_decoded_and_returned_as_is(bearer_client):
    """Case 3: the JSON body comes back verbatim, no filtering/transformation."""
    body = {
        "Items": [{"Id": "evt-1"}, {"Id": "evt-2"}],
        "Next": None,
        "Prev": None,
        "PartialResponseReasons": [],
    }
    respx.get(f"{BASE_URL}some/path").respond(json=body)

    result = await bearer_client.get("some/path")

    assert result == body


# ---------------------------------------------------------------------------
# Step 1: 401 retry-once-then-fatal (brief cases 4-5)
# ---------------------------------------------------------------------------


@respx.mock
async def test_401_once_retries_with_freshly_fetched_token():
    """Case 4: a single 401 triggers exactly one retry with a new token."""
    portal_auth = MagicMock()
    portal_auth.get_token.side_effect = ["token1", "token2"]
    client = PortalClient(auth=BearerAuth(portal_auth))

    route = respx.get(f"{BASE_URL}some/path").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"ok": True})]
    )

    result = await client.get("some/path")

    assert result == {"ok": True}
    assert route.call_count == 2
    assert route.calls[0].request.headers["authorization"] == "Bearer token1"
    assert route.calls[1].request.headers["authorization"] == "Bearer token2"
    assert portal_auth.get_token.call_count == 2


@respx.mock
async def test_401_twice_raises_not_authenticated_with_portal_login_hint():
    """Case 5: two consecutive 401s are fatal — cap retries at 1.

    The MagicMock side_effect list has exactly two entries (token1, token2);
    a third call to get_token() would raise StopIteration, so this also
    pins that no more than one retry is attempted.
    """
    portal_auth = MagicMock()
    portal_auth.get_token.side_effect = ["token1", "token2"]
    client = PortalClient(auth=BearerAuth(portal_auth))

    route = respx.get(f"{BASE_URL}some/path").respond(status_code=401)

    with pytest.raises(NotAuthenticatedError) as exc_info:
        await client.get("some/path")

    assert route.call_count == 2
    assert "portal-login" in str(exc_info.value)


@respx.mock
async def test_401_retry_forces_a_fresh_token_via_force_refresh():
    """The retry must ask PortalAuth for a NON-cached token
    (force_refresh=True) — replaying the same MSAL-cached token the server
    just rejected can never recover. The pre-401 call uses the cache."""
    portal_auth = MagicMock()
    portal_auth.get_token.side_effect = ["token1", "token2"]
    client = PortalClient(auth=BearerAuth(portal_auth))

    respx.get(f"{BASE_URL}some/path").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"ok": True})]
    )

    await client.get("some/path")

    calls = portal_auth.get_token.call_args_list
    assert calls[0].kwargs.get("force_refresh") is False
    assert calls[1].kwargs.get("force_refresh") is True


@respx.mock
async def test_401_retry_reredeems_refresh_token_for_a_new_access_token():
    """RefreshTokenAuth caches its access token; a 401 must drop that cache and
    RE-REDEEM the refresh token so the retry carries a fresh access token
    rather than replaying the rejected one."""
    tenant_id = "11111111-2222-3333-4444-555555555555"
    token_route = respx.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    ).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "access-1"}),
            httpx.Response(200, json={"access_token": "access-2"}),
        ]
    )
    api_route = respx.get(f"{BASE_URL}some/path").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"ok": True})]
    )

    client = PortalClient(
        auth=RefreshTokenAuth(tenant_id=tenant_id, refresh_token="fake-refresh-token")
    )
    result = await client.get("some/path")

    assert result == {"ok": True}
    assert token_route.call_count == 2  # re-redeemed, not replayed
    assert api_route.calls[0].request.headers["authorization"] == "Bearer access-1"
    assert api_route.calls[1].request.headers["authorization"] == "Bearer access-2"


@respx.mock
async def test_401_with_cookie_auth_raises_immediately_without_retry():
    """A stored session cookie is static — there is nothing to refresh, so a
    401 must raise on the FIRST response instead of wasting a guaranteed-401
    retry with the same dead cookie."""
    client = PortalClient(auth=CookieAuth(cookie_header="sccauth=dead", xsrf_token="x"))
    route = respx.get(f"{BASE_URL}some/path").respond(status_code=401)

    with pytest.raises(NotAuthenticatedError) as exc_info:
        await client.get("some/path")

    assert route.call_count == 1  # NOT retried
    assert "portal-login" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Step 1: error status codes (brief cases 6-7)
# ---------------------------------------------------------------------------


@respx.mock
async def test_429_raises_rate_limit_error_with_retry_after(bearer_client):
    """Case 6: Retry-After header value flows into RateLimitError.retry_after."""
    respx.get(f"{BASE_URL}some/path").respond(
        status_code=429, headers={"Retry-After": "37"}
    )

    with pytest.raises(RateLimitError) as exc_info:
        await bearer_client.get("some/path")

    assert exc_info.value.retry_after == 37


@respx.mock
async def test_429_with_http_date_retry_after_does_not_crash(bearer_client):
    """RFC 7231 allows `Retry-After` to be an HTTP-date, not just an integer.
    It must parse into RateLimitError, not raise a ValueError that escapes
    _check_response (uncaught trace in `device timeline`; bypasses the
    never-raise catch in `_verify_portal_cookies`)."""
    respx.get(f"{BASE_URL}some/path").respond(
        status_code=429, headers={"Retry-After": "Fri, 31 Dec 2100 23:59:59 GMT"}
    )

    with pytest.raises(RateLimitError) as exc_info:
        await bearer_client.get("some/path")

    assert isinstance(exc_info.value.retry_after, int)
    assert exc_info.value.retry_after >= 0


@respx.mock
async def test_429_without_retry_after_header_defaults_to_60(bearer_client):
    """A 429 carrying no `Retry-After` still yields a sane wait, not a crash."""
    respx.get(f"{BASE_URL}some/path").respond(status_code=429)

    with pytest.raises(RateLimitError) as exc_info:
        await bearer_client.get("some/path")

    assert exc_info.value.retry_after == 60


@respx.mock
async def test_440_is_auth_expiry_with_portal_recovery_guidance():
    """Microsoft's portal uses 440 for an expired browser/login session."""
    client = PortalClient(
        auth=CookieAuth(cookie_header="sccauth=expired", xsrf_token="x")
    )
    route = respx.get(f"{BASE_URL}some/path").respond(status_code=440)

    with pytest.raises(NotAuthenticatedError) as exc_info:
        await client.get("some/path")

    error = exc_info.value
    assert route.call_count == 1
    assert error.exit_code == 2
    assert "440" in error.message
    assert "portal-cookie" in error.suggested_fix
    assert "portal-login" in error.suggested_fix
    assert error.help_command == "xdr auth status"


@respx.mock
async def test_5xx_raises_api_error(bearer_client):
    """Case 7: server errors surface as APIError."""
    respx.get(f"{BASE_URL}some/path").respond(status_code=503)

    with pytest.raises(APIError):
        await bearer_client.get("some/path")


@respx.mock
async def test_5xx_error_captures_json_body_as_detail(bearer_client):
    """A 500's response body (the server's actual error) is surfaced via
    APIError.detail so an opaque failure is diagnosable; a JSON body is kept
    structured rather than stringified."""
    body = {"error": {"code": "InternalServerError", "message": "boom"}}
    respx.get(f"{BASE_URL}some/path").respond(status_code=500, json=body)

    with pytest.raises(APIError) as exc_info:
        await bearer_client.get("some/path")

    assert exc_info.value.status_code == 500
    detail = exc_info.value.detail
    assert detail["response_body"] == body
    # The failing request's path+query is captured so the exact page/cursor
    # that broke is visible (no cookies — those are headers, not the URL).
    assert "some/path" in detail["request_path"]


@respx.mock
async def test_5xx_error_with_text_body_captures_truncated_detail(bearer_client):
    """A non-JSON (e.g. HTML error page) body is captured as a size-capped
    text snippet, not dumped in full."""
    big = "<html>" + "x" * 5000 + "</html>"
    respx.get(f"{BASE_URL}some/path").respond(status_code=500, text=big)

    with pytest.raises(APIError) as exc_info:
        await bearer_client.get("some/path")

    body_detail = exc_info.value.detail["response_body"]
    assert isinstance(body_detail, str)
    assert body_detail.startswith("<html>")
    assert len(body_detail) < 2100  # capped, not the full ~5 KB
    assert "truncated" in body_detail


@respx.mock
async def test_5xx_empty_body_captures_diagnostic_headers_as_detail(bearer_client):
    """An empty-body 500 (the signature of an edge/gateway rejection) still
    yields something actionable: the routing/correlation response headers are
    surfaced as detail so the failure isn't a total black box."""
    respx.get(f"{BASE_URL}some/path").respond(
        status_code=500,
        headers={"X-MSEdge-Ref": "Ref A: 123", "X-Cache": "CONFIG_NOCACHE"},
    )

    with pytest.raises(APIError) as exc_info:
        await bearer_client.get("some/path")

    detail = exc_info.value.detail
    assert detail["response_headers"]["x-msedge-ref"] == "Ref A: 123"
    assert "some/path" in detail["request_path"]


# ---------------------------------------------------------------------------
# Step 1: paginate_apiproxy (brief cases 8-10)
# ---------------------------------------------------------------------------


@respx.mock
async def test_paginate_apiproxy_yields_items_across_pages_in_order(bearer_client):
    """Cases 8 + 10: items flow in order across pages; the second request's
    URL is the exact base-URL join of the relative `Next` field (proving the
    duplicate `/apiproxy/mtp/` prefix is stripped, not doubled)."""
    next_relative = (
        "/apiproxy/mtp/mdeTimelineExperience/machines/abc123/events"
        "?fromDate=2026-01-01&pageSize=2&skipToken=abc123"
    )
    page1 = respx.get(
        f"{BASE_URL}mdeTimelineExperience/machines/abc123/events"
    ).respond(
        json={
            "Items": [{"Id": "evt-1"}, {"Id": "evt-2"}],
            "Next": next_relative,
            "Prev": None,
            "PartialResponseReasons": [],
        }
    )
    page2 = respx.get(
        "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/"
        "machines/abc123/events?fromDate=2026-01-01&pageSize=2&skipToken=abc123"
    ).respond(
        json={
            "Items": [{"Id": "evt-3"}],
            "Next": "",
            "Prev": None,
            "PartialResponseReasons": [],
        }
    )

    items = []
    async for item in bearer_client.paginate_apiproxy(
        "mdeTimelineExperience/machines/abc123/events", params=None
    ):
        items.append(item)

    assert [item["Id"] for item in items] == ["evt-1", "evt-2", "evt-3"]
    assert page1.called
    assert page2.called
    assert str(page2.calls[0].request.url) == (
        "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/"
        "machines/abc123/events?fromDate=2026-01-01&pageSize=2&skipToken=abc123"
    )


@respx.mock
async def test_get_preserves_plus_in_query_end_to_end(bearer_client):
    """Full-stack proof that a path carrying a raw query (as the pagination
    loop passes when following `Next`) reaches the wire with a base64
    skipToken's '+'/'/'/'=' intact — httpx must not treat '+' as a space."""
    route = respx.get(
        "https://security.microsoft.com/apiproxy/mtp/"
        "mdeTimelineExperience/machines/abc/events"
    ).respond(json={"ok": True})

    await bearer_client.get(
        "mdeTimelineExperience/machines/abc/events?pageSize=1000&skipToken=aB+cD/eF12+gh=="
    )

    sent = str(route.calls[0].request.url)
    assert "skipToken=aB+cD/eF12+gh==" in sent


@respx.mock
async def test_paginate_apiproxy_raises_api_error_on_partial_response_reasons(
    bearer_client,
):
    """Case 9: non-empty PartialResponseReasons is a hard failure, not a
    silent truncation — raise APIError carrying the reasons."""
    reasons = ["ScopeAccessDenied", "Timeout"]
    respx.get(f"{BASE_URL}mdeTimelineExperience/machines/abc123/events").respond(
        json={
            "Items": [{"Id": "evt-1"}],
            "Next": None,
            "Prev": None,
            "PartialResponseReasons": reasons,
        }
    )

    with pytest.raises(APIError) as exc_info:
        async for _ in bearer_client.paginate_apiproxy(
            "mdeTimelineExperience/machines/abc123/events", params=None
        ):
            pass

    assert exc_info.value.detail == reasons


# ---------------------------------------------------------------------------
# Step 2: CookieAuth strategy
# ---------------------------------------------------------------------------


class TestCookieAuth:
    """CookieAuth injects session cookies + XSRF header; never Authorization."""

    @respx.mock
    async def test_sets_cookie_and_xsrf_headers_and_omits_authorization(self):
        client = PortalClient(auth=CookieAuth(sccauth="S", xsrf_token="X"))
        route = respx.get(f"{BASE_URL}some/path").respond(json={"ok": True})

        result = await client.get("some/path")

        assert result == {"ok": True}
        headers = route.calls[0].request.headers
        assert headers["cookie"] == "sccauth=S; xsrf-token=X"
        assert headers["x-xsrf-token"] == "X"
        assert "authorization" not in headers

    @respx.mock
    async def test_forwards_full_cookie_header_verbatim_when_given(self):
        """When a full browser Cookie header is supplied it is forwarded byte
        for byte — this carries the routing (`X-PortalEndpoint-RouteKey`) and
        session (`s.SessID`) cookies the apiproxy backend needs, which the
        minimal `sccauth`+`xsrf-token` form omits. `cookie_header` supersedes
        the sccauth/chunks construction."""
        header = (
            "X-PortalEndpoint-RouteKey=scuprod_southcentralus_aks; "
            "s.SessID=abc; sccauth=chunks:2; sccauthC1=AA; sccauthC2=BB; "
            "XSRF-TOKEN=tok%3Apart2"
        )
        client = PortalClient(
            auth=CookieAuth(cookie_header=header, xsrf_token="tok:part2")
        )
        route = respx.get(f"{BASE_URL}some/path").respond(json={"ok": True})

        await client.get("some/path")

        headers = route.calls[0].request.headers
        assert headers["cookie"] == header
        assert headers["x-xsrf-token"] == "tok:part2"

    @respx.mock
    async def test_portal_requests_send_browser_ish_headers(self):
        """Every portal request carries Accept/Accept-Language and a non-httpx
        User-Agent — matching the proven mdeproxy reference. The default
        `python-httpx/*` UA is never sent."""
        client = PortalClient(auth=CookieAuth(sccauth="S", xsrf_token="X"))
        route = respx.get(f"{BASE_URL}some/path").respond(json={"ok": True})

        await client.get("some/path")

        headers = route.calls[0].request.headers
        assert headers["accept"] == "application/json"
        assert headers["accept-language"] == "en-us"
        assert "python-httpx" not in headers["user-agent"].lower()
        assert "xdr-cli" in headers["user-agent"].lower()

    @respx.mock
    async def test_chunked_sccauth_forwards_marker_and_chunk_cookies_in_order(self):
        """A chunked sccauth (ASP.NET ChunkingCookieManager) is sent exactly
        as the browser sends it: the `sccauth=chunks:N` marker followed by
        each `sccauthC<i>` chunk cookie, in order — NOT reassembled into one
        oversized cookie that would re-exceed the ~4 KB per-cookie limit that
        caused the chunking in the first place."""
        client = PortalClient(
            auth=CookieAuth(
                sccauth="chunks:2",
                xsrf_token="X",
                sccauth_chunks={"sccauthC1": "AAAA", "sccauthC2": "BBBB"},
            )
        )
        route = respx.get(f"{BASE_URL}some/path").respond(json={"ok": True})

        await client.get("some/path")

        headers = route.calls[0].request.headers
        assert headers["cookie"] == (
            "sccauth=chunks:2; sccauthC1=AAAA; sccauthC2=BBBB; xsrf-token=X"
        )
        assert headers["x-xsrf-token"] == "X"
        assert "authorization" not in headers


# ---------------------------------------------------------------------------
# Step 3: RefreshTokenAuth strategy (not covered by Task 3 — added in Task 4)
# ---------------------------------------------------------------------------


class TestRefreshTokenAuth:
    """RefreshTokenAuth redeems a raw refresh token, no MSAL cache. For CI."""

    @respx.mock
    async def test_apply_redeems_refresh_token_and_sends_bearer_header(self):
        tenant_id = "11111111-2222-3333-4444-555555555555"
        token_route = respx.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ).respond(json={"access_token": "redeemed-access-token"})

        client = PortalClient(
            auth=RefreshTokenAuth(tenant_id=tenant_id, refresh_token="fake-refresh-token")
        )
        route = respx.get(f"{BASE_URL}some/path").respond(json={"ok": True})

        result = await client.get("some/path")

        assert result == {"ok": True}
        assert token_route.called
        redeem_request = token_route.calls[0].request
        sent_form = dict(pair.split("=") for pair in redeem_request.content.decode().split("&"))
        assert sent_form["grant_type"] == "refresh_token"
        assert sent_form["refresh_token"] == "fake-refresh-token"
        assert route.calls[0].request.headers["authorization"] == "Bearer redeemed-access-token"

    @respx.mock
    async def test_apply_caches_redeemed_token_across_multiple_requests(self):
        """Either caching or per-apply redemption is acceptable; if this
        implementation caches, the token endpoint is hit exactly once."""
        tenant_id = "11111111-2222-3333-4444-555555555555"
        token_route = respx.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ).respond(json={"access_token": "redeemed-access-token"})

        client = PortalClient(
            auth=RefreshTokenAuth(tenant_id=tenant_id, refresh_token="fake-refresh-token")
        )
        respx.get(f"{BASE_URL}some/path").respond(json={"ok": True})

        await client.get("some/path")
        await client.get("some/path")

        assert token_route.call_count == 1

    @respx.mock
    async def test_apply_raises_autherror_on_token_endpoint_error_status(self):
        """A 4xx/5xx from the token endpoint must surface as AuthError, not a
        raw httpx.HTTPStatusError — the top-level handler only catches
        XDRError subclasses."""
        tenant_id = "11111111-2222-3333-4444-555555555555"
        respx.post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token").respond(
            status_code=400,
            json={
                "error": "invalid_grant",
                "error_description": "AADSTS70008: The refresh token has expired.",
            },
        )

        client = PortalClient(
            auth=RefreshTokenAuth(tenant_id=tenant_id, refresh_token="stale-refresh-token")
        )

        with pytest.raises(AuthError) as exc_info:
            await client.get("some/path")

        assert "400" in str(exc_info.value)
        assert "AADSTS70008" in str(exc_info.value)

    @respx.mock
    async def test_apply_raises_autherror_when_access_token_missing(self):
        """A 200 response missing `access_token` must surface as AuthError,
        not a raw KeyError."""
        tenant_id = "11111111-2222-3333-4444-555555555555"
        respx.post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token").respond(
            json={"token_type": "Bearer"}
        )

        client = PortalClient(
            auth=RefreshTokenAuth(tenant_id=tenant_id, refresh_token="fake-refresh-token")
        )

        with pytest.raises(AuthError):
            await client.get("some/path")
