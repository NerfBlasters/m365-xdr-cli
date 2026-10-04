"""Collection-bound continuation validation; query bytes are never re-encoded."""
from __future__ import annotations

import httpx

from xdr_cli.exceptions import APIError


def validate_continuation(
    link: object, *, routes: frozenset[tuple[str, str]], seen: set[str],
) -> httpx.URL:
    """Accept only HTTPS URLs for the caller's exact host/collection pairs.

    The caller chooses whether to use the URL (official API) or only its raw
    query on a fixed portal route. No credential forwarding occurs here.
    """
    if not isinstance(link, str) or link in seen:
        raise APIError("Graph returned an invalid continuation.")
    try:
        url = httpx.URL(link)
    except httpx.InvalidURL as exc:
        raise APIError("Graph returned an invalid continuation.") from exc
    if (
        (url.host, url.path) not in routes or url.scheme != "https"
        or url.port not in (None, 443) or url.username or url.password
        or url.fragment or not url.query
    ):
        raise APIError("Refusing a Graph continuation outside the named operation.")
    seen.add(link)
    return url
