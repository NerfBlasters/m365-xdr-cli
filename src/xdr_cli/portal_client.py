"""Async HTTP client for the unofficial Defender portal apiproxy API.

`PortalClient` is a side-channel client parallel to `XDRClient` (see
client.py) that talks to `security.microsoft.com/apiproxy/mtp/` — the
internal API the Defender portal's own UI uses for the device timeline.
It is unofficial/undocumented, so it gets its own client rather than
reusing `XDRClient`'s Graph/MDE surfaces.

Three interchangeable auth strategies (`BearerAuth`, `CookieAuth`,
`RefreshTokenAuth`) implement `PortalAuthStrategy.apply()`, which mutates
an outgoing `httpx.Request` in place before it is sent. `PortalClient`
takes exactly one of them via `auth=`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol

import httpx

from xdr_cli import __version__
from xdr_cli.exceptions import (
    APIError,
    AuthError,
    NetworkError,
    NotAuthenticatedError,
    RateLimitError,
    TimeoutError,
    parse_retry_after,
)
from xdr_cli.portal_auth import PORTAL_CLIENT_ID, PORTAL_SCOPES, PortalAuth

BASE_URL = "https://security.microsoft.com/apiproxy/mtp/"

# Headers every portal request carries. The apiproxy backend expects a JSON
# client (Accept/Accept-Language); the proven cookie-auth reference
# (0xThiebaut/mdeproxy) sets exactly these. The User-Agent is a plain,
# honest xdr-cli identifier — mdeproxy works with its own non-browser UA, so a
# browser UA is not required and the default `python-httpx/*` is simply
# replaced, not disguised.
_DEFAULT_HEADERS = {
    "User-Agent": f"xdr-cli/{__version__} (+https://github.com/NerfBlasters/m365-xdr-cli)",
    "Accept": "application/json",
    "Accept-Language": "en-us",
}

# The `Next` field in a paginated apiproxy response is a path rooted at
# the host (e.g. "/apiproxy/mtp/mdeTimelineExperience/..."), not relative
# to our base_url's own path. httpx.AsyncClient's base_url merge appends
# relative paths onto base_url's existing path rather than replacing it
# (see _merge_url), so passing the `Next` value through unmodified would
# double the "/apiproxy/mtp/" prefix. Strip it before handing the path to
# the client so the merge produces the same URL the browser followed.
_APIPROXY_PREFIX = "/apiproxy/mtp/"

# Portal auth rejection (401 or Microsoft's login-timeout 440) is retried at
# most once. If freshly-applied auth is still rejected, the credential itself
# is bad/expired — looping
# further would just hammer the server. Mirrors
# timeline-downloader/internal/api/client.go:125-152.
MAX_AUTH_RETRIES = 1

_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class PortalAuthStrategy(Protocol):
    """Applies auth material to an outgoing request, in place."""

    async def apply(self, request: httpx.Request) -> None: ...

    async def refresh(self) -> bool:
        """Force the next `apply()` to use a freshly-obtained credential.

        Called by `PortalClient._send` after a portal auth rejection so the retry carries a
        *new* credential rather than replaying the rejected one. Returns
        True when a refresh was possible (the retry is worth making), False
        for a static credential a 401 renders unrecoverable (e.g. a stored
        session cookie) so the caller can skip a guaranteed-401 retry.
        """
        ...


class BearerAuth:
    """MSAL-backed bearer token — the default `xdr auth portal-login` path."""

    def __init__(self, portal_auth: PortalAuth) -> None:
        self._portal_auth = portal_auth
        # Set by refresh() so the NEXT apply() bypasses MSAL's silent cache.
        # No local token caching — get_token() is called per request so MSAL's
        # own near-expiry auto-refresh keeps working across a multi-page pull.
        self._force_next = False

    async def apply(self, request: httpx.Request) -> None:
        # PortalAuth.get_token() is synchronous (MSAL's own API is sync).
        token = self._portal_auth.get_token(force_refresh=self._force_next)
        self._force_next = False
        request.headers["Authorization"] = f"Bearer {token}"

    async def refresh(self) -> bool:
        # Make the next get_token() force a fresh mint (force_refresh=True) so
        # the 401 retry isn't just a replay of the same cached, rejected token.
        self._force_next = True
        return True


class CookieAuth:
    """Session cookie + XSRF header, fed from a stored `portal_cookies.json`.

    Populated out-of-band by `xdr auth portal-cookie`; the raw secrets
    never appear on a `device timeline` command line.

    When the portal's `sccauth` value exceeds ~4 KB, ASP.NET Core's
    `ChunkingCookieManager` replaces it with the marker `chunks:N` and splits
    the real payload across sibling cookies `sccauthC1..sccauthCN`. In that
    case `sccauth` holds the `chunks:N` marker and `sccauth_chunks` holds the
    ordered `{"sccauthC1": ..., "sccauthCN": ...}` cookies. We forward all of
    them verbatim — exactly as the browser does — rather than reassembling
    into one oversized cookie, which would re-cross the per-cookie limit that
    triggered the chunking. For a non-chunked tenant `sccauth_chunks` is empty
    and the header is the plain `sccauth=<value>` form.
    """

    def __init__(
        self,
        sccauth: str | None = None,
        xsrf_token: str = "",
        sccauth_chunks: dict[str, str] | None = None,
        cookie_header: str | None = None,
    ) -> None:
        self._sccauth = sccauth
        self._xsrf_token = xsrf_token
        # Insertion order (sccauthC1..sccauthCN) is preserved through the JSON
        # store and reproduced here; the server concatenates by chunk index.
        self._sccauth_chunks = sccauth_chunks or {}
        # A full browser Cookie header, forwarded verbatim. Preferred over the
        # sccauth/chunks construction because it also carries the routing
        # (X-PortalEndpoint-RouteKey) and session (s.SessID) cookies the
        # apiproxy backend needs — the minimal form omits them, which the
        # backend answers with an opaque 500.
        self._cookie_header = cookie_header

    async def apply(self, request: httpx.Request) -> None:
        if self._cookie_header:
            request.headers["Cookie"] = self._cookie_header
        else:
            parts = [f"sccauth={self._sccauth}"]
            parts += [f"{name}={value}" for name, value in self._sccauth_chunks.items()]
            parts.append(f"xsrf-token={self._xsrf_token}")
            request.headers["Cookie"] = "; ".join(parts)
        request.headers["X-XSRF-TOKEN"] = self._xsrf_token

    async def refresh(self) -> bool:
        # A stored session cookie is static — there is nothing to refresh. A
        # 401 means the browser session itself is dead, so retrying with the
        # same cookie would just re-fail; signal "don't retry".
        return False


class RefreshTokenAuth:
    """Direct refresh-token redemption, no MSAL cache. For `--refresh-token`.

    Redeems lazily on first use and caches the resulting access token for
    the lifetime of this instance. `refresh()` drops that cache so a 401
    retry re-redeems the refresh token (the access token may simply have
    expired mid-pull) rather than replaying the rejected one.
    """

    def __init__(
        self,
        tenant_id: str,
        refresh_token: str,
        client_id: str = PORTAL_CLIENT_ID,
    ) -> None:
        self._tenant_id = tenant_id
        self._refresh_token = refresh_token
        self._client_id = client_id
        self._access_token: str | None = None

    async def _redeem(self) -> str:
        token_url = _TOKEN_URL_TEMPLATE.format(tenant_id=self._tenant_id)
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "client_id": self._client_id,
                    "refresh_token": self._refresh_token,
                    "scope": " ".join(PORTAL_SCOPES),
                },
            )
        try:
            body: dict = response.json()
        except ValueError:
            body = {}

        if response.is_error:
            detail = body.get("error_description") or body.get("error")
            message = f"Token redemption failed with status {response.status_code}."
            if detail:
                message += f" {detail}"
            message += (
                " The refresh token may be invalid or expired — supply a fresh one "
                "or run `xdr auth portal-login`."
            )
            raise AuthError(message)

        access_token = body.get("access_token")
        if not access_token:
            detail = body.get("error_description")
            message = "Token redemption response did not include an access token."
            if detail:
                message += f" {detail}"
            message += (
                " The refresh token may be invalid or expired — supply a fresh one "
                "or run `xdr auth portal-login`."
            )
            raise AuthError(message)
        return access_token

    async def apply(self, request: httpx.Request) -> None:
        if self._access_token is None:
            self._access_token = await self._redeem()
        request.headers["Authorization"] = f"Bearer {self._access_token}"

    async def refresh(self) -> bool:
        # Drop the cached access token so the next apply() re-redeems the
        # refresh token — otherwise the 401 retry replays the same expired
        # access token and is guaranteed to fail again.
        self._access_token = None
        return True


# Error response bodies are captured into APIError.detail for diagnosis. Cap
# the text fallback so an HTML error page or stack trace can't dump kilobytes
# into the error output.
_MAX_ERROR_BODY = 2000

# Response headers worth surfacing when an error carries no body — the
# signature of an edge/gateway (rather than app) failure. These are routing /
# correlation IDs, safe to show, and often the only clue for an opaque 500.
_DIAG_HEADERS = frozenset({
    "x-msedge-ref",
    "x-ms-request-id",
    "request-id",
    "x-cache",
    "x-envoy-upstream-service-time",
    "www-authenticate",
    "x-portalendpoint-routekey",
})


def _response_body_snippet(response: httpx.Response) -> str | dict | list | None:
    """The error response body: structured JSON kept as-is, else a size-capped
    text snippet, else None (empty)."""
    try:
        return response.json()
    except ValueError:
        pass
    text = response.text.strip()
    if not text:
        return None
    if len(text) > _MAX_ERROR_BODY:
        return text[:_MAX_ERROR_BODY] + "… (truncated)"
    return text


def _error_detail(response: httpx.Response) -> dict:
    """Diagnostic detail for a failed apiproxy request.

    Always carries `request_path` — the failing request's path + query string,
    which is where the paginated `fromDate`/`toDate`/`skipToken` live, so an
    opaque 404/500 shows exactly which page/cursor broke. The URL never
    contains cookies (those are request *headers*), so it is safe to surface.
    Adds `response_body` when the server returned one, or `response_headers`
    (routing/correlation IDs) for an empty-body error — the signature of an
    edge/gateway rejection.
    """
    detail: dict = {}
    request = response.request
    if request is not None:
        detail["request_path"] = request.url.raw_path.decode("ascii", "replace")

    body = _response_body_snippet(response)
    if body is not None:
        detail["response_body"] = body
    else:
        diag = {
            k.lower(): v for k, v in response.headers.items() if k.lower() in _DIAG_HEADERS
        }
        if diag:
            detail["response_headers"] = diag
    return detail


def _strip_apiproxy_prefix(next_url: str) -> str:
    """Turn a host-rooted `Next` path into one relative to our base_url.

    `next_url` looks like "/apiproxy/mtp/mdeTimelineExperience/...?...".
    httpx.AsyncClient base_url merging appends a relative path's own path
    onto base_url's path (rather than replacing it), so the leading
    "/apiproxy/mtp/" must come off first or it gets doubled.
    """
    if next_url.startswith(_APIPROXY_PREFIX):
        return next_url[len(_APIPROXY_PREFIX) :]
    return next_url.lstrip("/")


class PortalClient:
    """Async HTTP client for the unofficial Defender portal apiproxy API."""

    def __init__(self, auth: PortalAuthStrategy, timeout: int = 30) -> None:
        self._auth = auth
        self._timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=BASE_URL, timeout=timeout, headers=dict(_DEFAULT_HEADERS)
        )

    async def _send(self, path: str, params: dict[str, Any] | None) -> httpx.Response:
        retries = 0
        while True:
            request = self._client.build_request("GET", path, params=params)
            try:
                await self._auth.apply(request)
                response = await self._client.send(request)
            except httpx.TimeoutException as exc:
                raise TimeoutError(
                    f"Defender portal request timed out after {self._timeout} seconds.",
                    original={"type": type(exc).__name__, "message": str(exc)},
                ) from exc
            except httpx.TransportError as exc:
                raise NetworkError(
                    f"Defender portal transport failed: {exc}",
                    retryable=True,
                    original={"type": type(exc).__name__, "message": str(exc)},
                ) from exc
            if response.status_code in {401, 440}:
                # A portal auth rejection is only recoverable if the strategy can produce a
                # FRESH credential. refresh() forces the next apply() to
                # re-authenticate and returns False for a static credential
                # (e.g. a session cookie) whose retry would just re-fail — so
                # we don't waste a guaranteed-failure request on it.
                if retries < MAX_AUTH_RETRIES and await self._auth.refresh():
                    retries += 1
                    continue
                status = response.status_code
                recovery = (
                    "Run 'xdr auth status', then refresh portal credentials with "
                    "'xdr auth portal-cookie <cookie-source>' or "
                    "'xdr auth portal-login'."
                )
                raise NotAuthenticatedError(
                    f"Portal session rejected ({status}). Your portal credentials "
                    "look expired or invalid. Run `xdr auth portal-cookie "
                    "<cookie-source>` or `xdr auth portal-login` to refresh them.",
                    suggested_fix=recovery,
                    help_command="xdr auth status",
                )
            return response

    @staticmethod
    def _check_response(response: httpx.Response) -> None:
        if response.is_success:
            return
        status = response.status_code
        if status == 429:
            retry_after = parse_retry_after(response.headers.get("Retry-After"))
            raise RateLimitError(retry_after=retry_after)
        raise APIError(
            f"Defender portal apiproxy request failed with status {status}.",
            status_code=status,
            detail=_error_detail(response),
        )

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        """Send a GET request and return the parsed JSON body, unmodified."""
        response = await self._send(path, params)
        self._check_response(response)
        try:
            value = response.json()
        except (ValueError, TypeError) as exc:
            error = APIError(
                "Defender portal returned a malformed JSON response.",
                status_code=response.status_code,
                detail=_error_detail(response),
            )
            error.error_code = "API_MALFORMED_RESPONSE"
            raise error from exc
        if not isinstance(value, dict):
            error = APIError(
                "Defender portal returned an unexpected JSON response shape.",
                status_code=response.status_code,
                detail={"received_type": type(value).__name__},
            )
            error.error_code = "API_INVALID_RESPONSE_SHAPE"
            raise error
        return value

    async def probe(self, path: str, params: dict[str, Any] | None = None) -> None:
        """Confirm a request succeeds without imposing an endpoint body shape."""
        response = await self._send(path, params)
        self._check_response(response)

    # Reserved for the future identity-timeline path (v1.1) — intentionally
    # retained even though it has no current production caller today.
    async def paginate_apiproxy(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> AsyncIterator[dict]:
        """Yield items across apiproxy pages, following `Next` until exhausted.

        A non-empty `PartialResponseReasons` on any page is a hard failure
        (the server silently dropped part of the result set) — raised as
        `APIError` with the reasons as `detail`, not swallowed.
        """
        next_path: str | None = path
        next_params = params
        while next_path:
            data = await self.get(next_path, params=next_params)

            reasons = data.get("PartialResponseReasons") or []
            if reasons:
                raise APIError(
                    "Defender portal apiproxy returned a partial response.",
                    detail=reasons,
                )

            for item in data.get("Items", []):
                yield item

            next_url = data.get("Next") or None
            next_path = _strip_apiproxy_prefix(next_url) if next_url else None
            next_params = None  # query params are already baked into Next.

    async def close(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()
