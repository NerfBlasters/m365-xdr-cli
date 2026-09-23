"""MDE device timeline: URL building + streaming pagination.

Talks to the unofficial Defender portal apiproxy `mdeTimelineExperience`
endpoint via `PortalClient` (see `portal_client.py`). `stream_device_timeline`
runs its own pagination loop rather than delegating to
`PortalClient.paginate_apiproxy`, because that generic helper has no notion
of a caller-supplied `to_date` cutoff — it just follows `Next` until it's
empty or the response is partial. Here we need an additional terminator:
stop *before* issuing the next request once the `fromDate` baked into
`Next` has moved past `to_date`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit

from xdr_cli.exceptions import APIError
from xdr_cli.portal_client import _strip_apiproxy_prefix


class _PortalClientLike(Protocol):
    """The slice of `PortalClient` this module actually needs."""

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict: ...


def _format_apiproxy_time(dt: datetime) -> str:
    """7-digit fractional seconds, literal `Z` suffix.

    The apiproxy rejects standard ISO 8601 timestamps. Sub-second precision
    on `dt` is dropped, not rounded in — every reference implementation
    emits the literal `.0000000Z` suffix regardless of the input.
    """
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def _ceil_to_second(dt: datetime) -> datetime:
    """Round `dt` UP to the next whole second when it carries a sub-second part.

    `_format_apiproxy_time` can only emit whole seconds (the apiproxy takes a
    fixed `.0000000Z` suffix), so a `toDate` with a fractional part must round
    UP: truncating it DOWN asks the server for a window ending before the
    caller's bound, silently dropping events in the sub-second gap. The stream
    loop's own `parsed > to_date` post-filter then trims the resulting
    overshoot back to the exact requested instant, so the upper bound stays
    precise. (`fromDate` is left truncating-down — the lower bound is
    intentionally approximate; only `--to` is made exact.)
    """
    if dt.microsecond:
        return (dt + timedelta(seconds=1)).replace(microsecond=0)
    return dt


def build_timeline_url(
    machine_id: str,
    from_date: datetime,
    to_date: datetime,
    page_size: int = 1000,
) -> tuple[str, dict[str, str]]:
    """Build the `(path, params)` pair for a device-timeline GET.

    All param values are strings — the apiproxy is strict about that.

    `IsScrollingForward=true` is load-bearing: it makes the apiproxy start at
    `fromDate` and page FORWARD through the whole window (oldest → newest).
    Omit it and the apiproxy instead returns the newest page and a
    forward-to-now cursor that terminates on the next request, silently
    truncating history to the first ~1000 events. The reference downloader
    sets it for the same reason.
    """
    path = f"mdeTimelineExperience/machines/{machine_id}/events"
    params = {
        "fromDate": _format_apiproxy_time(from_date),
        # Round the upper bound UP to a whole second before the whole-second-only
        # format drops its fraction, so the server window doesn't end early and
        # lose events in the sub-second gap; the loop's post-filter re-trims.
        "toDate": _format_apiproxy_time(_ceil_to_second(to_date)),
        "pageSize": str(page_size),
        "generateIdentityEvents": "true",
        "includeIdentityEvents": "true",
        "supportMdiOnlyEvents": "true",
        "includeSentinelEvents": "false",
        "doNotUseCache": "false",
        "forceUseCache": "false",
        "IsScrollingForward": "true",
    }
    return path, params


# The apiproxy `Next` is a path relative to this endpoint; it does not repeat
# the segment. Our base_url supplies only "/apiproxy/mtp/", so it must be
# re-added or the follow-up request 404s.
_TIMELINE_ENDPOINT = "mdeTimelineExperience"


def _next_request_path(next_url: str) -> str:
    """Resolve the apiproxy `Next` into a path relative to `PortalClient`'s
    base_url (`/apiproxy/mtp/`).

    `Next` is a path RELATIVE TO the mdeTimelineExperience endpoint — real
    values look like
    "/machines/<id>/events?...&IsScrollingForward=True&ReportIdForScrolling=..."
    and do NOT repeat the "mdeTimelineExperience" segment. Merging that against
    base_url alone yields "/apiproxy/mtp/machines/<id>/events", which 404s and
    silently truncates the timeline to the first page — so the segment is
    re-added here, mirroring the reference downloader's `timelineAPIPrefix +
    Next`. The query string is kept verbatim (no parse_qsl round-trip, which
    would also corrupt a base64 skipToken's literal '+'). Defensive: a `Next`
    that already includes the endpoint segment is passed through unchanged.
    """
    stripped = _strip_apiproxy_prefix(next_url)
    if stripped.startswith(_TIMELINE_ENDPOINT):
        return stripped
    return f"{_TIMELINE_ENDPOINT}/{stripped.lstrip('/')}"


def _next_from_date(next_url: str) -> datetime | None:
    """Read the `fromDate` baked into a `Next` URL, for the loop terminator.

    Inspection only — the request itself follows `Next` verbatim (the stream
    loop passes the prefix-stripped path *with its query string intact* and no
    `params`), so the base64 `skipToken` is never decoded/re-encoded. Routing
    the whole query through `parse_qsl` + `client.get(params=...)` would map a
    literal `+` in the skipToken to a space and corrupt the cursor, 404-ing
    every page after the first. `fromDate` itself is `+`-free, so reading it
    this way is safe. Returns None when absent or unparseable.
    """
    value = dict(parse_qsl(urlsplit(next_url).query)).get("fromDate")
    return _parse_apiproxy_time(value) if value else None


def _parse_apiproxy_time(value: str) -> datetime | None:
    """Tolerant parse of an apiproxy timestamp (a `Next` `fromDate` or an
    event's `ActionTime`).

    The apiproxy's `.0000000Z` format carries 7 fractional digits, which
    `datetime.fromisoformat` does not reliably accept (it maxes out at 6).
    Trim the fractional part to 6 digits and normalize a trailing `Z` to
    `+00:00` before parsing. Returns `None` on any parse failure so the
    caller treats an unrecognized value as "don't filter / keep paging" rather
    than crash — mirrors timeline-downloader/internal/api/devices.go:255-260.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        i = 0
        while i < len(tail) and tail[i].isdigit():
            digits += tail[i]
            i += 1
        offset = tail[i:]
        digits = (digits + "000000")[:6]
        text = f"{head}.{digits}{offset}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


async def stream_device_timeline(
    client: _PortalClientLike,
    machine_id: str,
    from_date: datetime,
    to_date: datetime,
    page_size: int = 1000,
) -> AsyncIterator[dict]:
    """Yield device timeline events for `machine_id`, paging until exhausted.

    Runs its own pagination loop directly over `client.get` — see the
    module docstring for why this doesn't delegate to
    `PortalClient.paginate_apiproxy`. A non-empty `PartialResponseReasons`
    on any page is a hard failure (the server silently dropped part of the
    result set), raised as `APIError` rather than swallowed. The caller is
    responsible for writing/consuming the yielded events.
    """
    path, params = build_timeline_url(machine_id, from_date, to_date, page_size)

    while True:
        data = await client.get(path, params=params)

        reasons = data.get("PartialResponseReasons") or []
        if reasons:
            raise APIError(
                "Defender portal apiproxy returned a partial device timeline response.",
                detail=reasons,
            )

        # Events are yielded as-is (NO dedup): `ReportId` is a report-batch
        # identifier, not a unique key — distinct events (different ActionTime,
        # Process, etc.) routinely share one, especially the large-valued
        # OneCyber behavioral events, so deduping on it would silently drop real
        # events. Forward-scroll pagination does not re-emit events across page
        # boundaries here (verified: 0 byte-identical duplicates in a full-day
        # pull).
        #
        # They ARE filtered to the requested window: forward-scroll overshoots
        # `to_date` within the final fetched page (the apiproxy bounds
        # pagination, not individual events), so an event past `to_date` is
        # dropped to keep an explicit `--to` an exact upper bound. Events at
        # exactly `to_date` are kept; an unparseable/absent ActionTime is not
        # filtered.
        for item in data.get("Items", []):
            action_time = item.get("ActionTime")
            if action_time is not None:
                parsed = _parse_apiproxy_time(action_time)
                if parsed is not None and parsed > to_date:
                    continue
            yield item

        next_url = data.get("Next") or None
        if not next_url:
            return

        # Terminator (2): stop before requesting a window whose fromDate has
        # already moved past to_date.
        next_from_date = _next_from_date(next_url)
        if next_from_date is not None and next_from_date > to_date:
            return

        # Follow Next: re-add the mdeTimelineExperience endpoint segment (the
        # apiproxy omits it from Next) and keep the query string verbatim (no
        # params dict — parse_qsl would corrupt a base64 skipToken's '+').
        # Dropping the segment 404s and truncates the timeline to page 1.
        path, params = _next_request_path(next_url), None
