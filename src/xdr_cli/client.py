"""Async HTTP client for Microsoft Graph Security and MDE APIs."""

from __future__ import annotations

from collections.abc import AsyncIterator
from enum import Enum
from typing import Any

import httpx

from xdr_cli.exceptions import (
    APIError,
    AuthError,
    ConflictError,
    ForbiddenError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    parse_retry_after,
    query_error_from_message,
)


class APISurface(Enum):
    """API base URL targets."""

    GRAPH = "https://graph.microsoft.com/v1.0/security/"
    GRAPH_CORE = "https://graph.microsoft.com/v1.0/"
    MDE = "https://api.security.microsoft.com/api/"


# Token audience per surface. Must match the scopes defined in auth.py.
_SURFACE_SCOPES: dict[APISurface, list[str]] = {
    APISurface.GRAPH: ["https://graph.microsoft.com/.default"],
    APISurface.GRAPH_CORE: ["https://graph.microsoft.com/.default"],
    # Tokens for the MDE endpoints at api.security.microsoft.com must use the
    # api.securitycenter.microsoft.com audience — Microsoft's current guidance.
    APISurface.MDE: ["https://api.securitycenter.microsoft.com/.default"],
}


def _required_permission(response: httpx.Response) -> str:
    """Return an authoritative permission hint for known xdr-cli endpoints."""

    path = response.request.url.path.casefold()
    if "runhuntingquery" in path:
        return "Microsoft Graph / ThreatHunting.Read.All"
    if "advancedhunting" in path:
        return "WindowsDefenderATP / AdvancedQuery.Read.All"
    if "/incidents" in path:
        return "Microsoft Graph / SecurityIncident.ReadWrite.All"
    if "/alerts_v2" in path:
        return "Microsoft Graph / SecurityAlert.ReadWrite.All"
    if "/isolate" in path or "/unisolate" in path:
        return "WindowsDefenderATP / Machine.Isolate"
    if "/runantivirusscan" in path:
        return "WindowsDefenderATP / Machine.Scan"
    if "/collectinvestigationpackage" in path:
        return "WindowsDefenderATP / Machine.CollectForensics"
    if "/restrictcodeexecution" in path:
        return "WindowsDefenderATP / Machine.RestrictExecution"
    if "/machines" in path or "/machineactions" in path:
        return "WindowsDefenderATP / Machine.Read.All"
    return ""


class XDRClient:
    """HTTP client for XDR APIs with retry, auth, and pagination."""

    def __init__(
        self,
        get_token: callable,
        timeout: int = 30,
    ) -> None:
        self._get_token = get_token
        self._timeout = timeout
        self._clients: dict[APISurface, httpx.AsyncClient] = {}

    def _get_client(self, surface: APISurface) -> httpx.AsyncClient:
        if surface not in self._clients:
            self._clients[surface] = httpx.AsyncClient(
                base_url=surface.value,
                timeout=self._timeout,
            )
        return self._clients[surface]

    def _auth_headers(self, surface: APISurface) -> dict[str, str]:
        token = self._get_token(_SURFACE_SCOPES[surface])
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _parse_api_error(
        response: httpx.Response,
    ) -> tuple[str | None, str | None, dict | None]:
        """Extract structured error info from a Graph/MDE JSON error body.

        Returns (code, message, inner_error) — inner_error is the nested
        object that Graph uses for request-id / client-request-id / details
        when available. Falls back to (None, None, None) for unparseable
        bodies.
        """
        try:
            body = response.json()
        except Exception:
            return None, None, None
        err = body.get("error") if isinstance(body, dict) else None
        if not isinstance(err, dict):
            return None, None, None
        inner = err.get("innerError") or err.get("details")
        if inner is not None and not isinstance(inner, (dict, list)):
            inner = None
        return err.get("code"), err.get("message"), inner

    def _check_response(self, response: httpx.Response) -> None:
        """Raise appropriate XDRError for error status codes."""
        if response.is_success:
            return
        status = response.status_code
        err_code, err_msg, inner = self._parse_api_error(response)
        # Prefer the structured inner error as `detail` when available;
        # fall back to raw response text (truncated) for debugging.
        detail: str | dict | list | None = inner
        if detail is None and response.text:
            detail = response.text[:500]

        request_ids = {
            key: value
            for key in ("request-id", "client-request-id", "x-ms-correlation-request-id")
            if (value := response.headers.get(key))
        }
        if isinstance(inner, dict):
            for key in ("request-id", "requestId", "client-request-id", "clientRequestId"):
                value = inner.get(key)
                if isinstance(value, str) and value:
                    request_ids[key] = value
        if status == 401:
            error = AuthError(
                err_msg or "Authentication is required.",
                help_command="xdr auth status",
                original={"type": err_code or "HTTPError", "status": status, "message": err_msg},
            )
        elif status == 403:
            error = ForbiddenError(_required_permission(response))
            error.original = {
                "type": err_code or "HTTPError",
                "status": status,
                "message": err_msg,
                "detail": detail,
            }
        elif status == 404:
            error = NotFoundError("API resource", response.request.url.path)
        elif status == 409:
            error = ConflictError(
                err_msg or "Upstream state conflict.",
                original={"type": err_code or "HTTPError", "status": status, "message": err_msg},
            )
        elif status == 429:
            retry_after = parse_retry_after(response.headers.get("Retry-After"))
            error = RateLimitError(retry_after=retry_after)
        elif status == 400 and "hunting" in str(response.request.url).lower():
            error = query_error_from_message(
                err_msg or "Advanced Hunting rejected the query.",
                original={
                    "type": err_code or "HTTPError",
                    "status": status,
                    "message": err_msg,
                    "detail": detail,
                },
            )
        else:
            if err_code or err_msg:
                msg = f"API {status}: {err_code or 'Error'} — {err_msg or 'no message'}"
            else:
                msg = f"API request failed with status {status}."
            error = APIError(msg, status_code=status, detail=detail)
        error.request_ids = request_ids or None
        raise error

    @staticmethod
    def _decode_response(response: httpx.Response) -> dict[str, Any]:
        """Decode the expected object response or raise an upstream API error."""

        try:
            value = response.json()
        except (ValueError, TypeError) as exc:
            error = APIError(
                "API returned a malformed JSON response.",
                status_code=response.status_code,
                detail=response.text[:500] if response.text else None,
            )
            error.error_code = "API_MALFORMED_RESPONSE"
            raise error from exc
        if not isinstance(value, dict):
            error = APIError(
                "API returned an unexpected JSON response shape.",
                status_code=response.status_code,
                detail={"received_type": type(value).__name__},
            )
            error.error_code = "API_INVALID_RESPONSE_SHAPE"
            raise error
        return value

    async def _request(self, method: str, client: httpx.AsyncClient, url: str, **kwargs):
        try:
            return await client.request(method, url, **kwargs)
        except httpx.TimeoutException as exc:
            raise TimeoutError(
                f"API request timed out after {self._timeout} seconds.",
                help_command="Retry once with --timeout <seconds> if the query is bounded.",
                original={"type": type(exc).__name__, "message": str(exc)},
            ) from exc
        except httpx.TransportError as exc:
            raise NetworkError(
                f"API transport failed: {exc}",
                retryable=True,
                original={"type": type(exc).__name__, "message": str(exc)},
            ) from exc

    async def get(
        self,
        surface: APISurface,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict:
        """Send a GET request and return JSON response."""
        client = self._get_client(surface)
        response = await self._request(
            "GET", client, path, params=params, headers=self._auth_headers(surface)
        )
        self._check_response(response)
        return self._decode_response(response)

    async def post(
        self,
        surface: APISurface,
        path: str,
        json: dict[str, Any] | None = None,
    ) -> dict:
        """Send a POST request and return JSON response."""
        client = self._get_client(surface)
        response = await self._request(
            "POST", client, path, json=json, headers=self._auth_headers(surface)
        )
        self._check_response(response)
        return self._decode_response(response)

    async def patch(
        self,
        surface: APISurface,
        path: str,
        json: dict[str, Any] | None = None,
    ) -> dict:
        """Send a PATCH request and return JSON response."""
        client = self._get_client(surface)
        response = await self._request(
            "PATCH", client, path, json=json, headers=self._auth_headers(surface)
        )
        self._check_response(response)
        return self._decode_response(response)

    async def paginate(
        self,
        surface: APISurface,
        path: str,
        params: dict[str, Any] | None = None,
        limit: int = 0,
    ) -> AsyncIterator[dict]:
        """Async generator that follows @odata.nextLink pagination."""
        count = 0
        client = self._get_client(surface)
        url = path
        is_absolute = False

        while True:
            if is_absolute:
                # nextLink is always an absolute URL; send via the same client
                # so auth headers and timeouts are consistent.
                response = await self._request(
                    "GET", client, url, headers=self._auth_headers(surface)
                )
            else:
                response = await self._request(
                    "GET", client, url, params=params, headers=self._auth_headers(surface)
                )

            self._check_response(response)
            data = self._decode_response(response)

            for item in data.get("value", []):
                yield item
                count += 1
                if limit and count >= limit:
                    return

            next_link = data.get("@odata.nextLink")
            if not next_link:
                return

            # nextLink is always an absolute URL
            url = next_link
            is_absolute = True
            params = None  # params are baked into the nextLink URL

    async def close(self) -> None:
        """Close all HTTP client connections."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
