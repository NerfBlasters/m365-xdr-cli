"""Tests for the MDE device timeline API (`api/timeline.py`).

This is a RED-only test file for TDD Task 5: `xdr_cli.api.timeline` does not
exist yet, so every test here is expected to fail at collection with a
ModuleNotFoundError until Task 6 implements `timeline.py`.

`build_timeline_url` builds the `(path, params)` pair for a GET against the
unofficial Defender portal apiproxy device-timeline endpoint served by
`PortalClient` (see `portal_client.py` / `tests/test_portal_client.py`).

`stream_device_timeline` runs its OWN pagination loop directly over
`PortalClient.get(path, params)` — it does NOT wrap
`PortalClient.paginate_apiproxy`. That generic helper has no concept of a
caller-supplied `to_date` cutoff: it just follows `Next` until empty or a
partial response. `stream_device_timeline` needs an additional terminator —
stop *before* issuing the next request if the `fromDate` baked into `Next`
is already past `to_date` — so it inspects `Next` itself rather than
delegating to `paginate_apiproxy`.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import pytest

from xdr_cli.api.timeline import build_timeline_url, stream_device_timeline
from xdr_cli.exceptions import APIError

# A concrete 40-hex machine ID, the same shape as a real MDE MachineId
# (SHA1 digest hex). Deterministic so failures are easy to eyeball.
MACHINE_ID = hashlib.sha1(b"WS-MARKETING-04").hexdigest()
assert len(MACHINE_ID) == 40

FROM_DATE = datetime(2026, 4, 17, 8, 45, 0, tzinfo=UTC)
TO_DATE = datetime(2026, 4, 17, 9, 10, 0, tzinfo=UTC)


def _extract_next_from_date(next_url: str) -> str | None:
    """Pull the `fromDate` query param out of a `Next` URL.

    Uses the same urlparse/parse_qs approach the pagination loop under test
    must use to decide whether to keep paging. Kept here so the `Next`
    strings authored below unambiguously drive terminator (2): "the fromDate
    query param parsed out of Next is later than to_date -> stop".
    """
    query = urlparse(next_url).query
    values = parse_qs(query).get("fromDate")
    return values[0] if values else None


def _parse_apiproxy_time(value: str) -> datetime:
    """Parse the literal 7-digit-fraction `.0000000Z` apiproxy time format."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.0000000Z").replace(tzinfo=UTC)


def _next_url(from_date_str: str) -> str:
    """A realistic `Next` URL: apiproxy-relative path + baked-in query string."""
    return (
        f"/apiproxy/mtp/mdeTimelineExperience/machines/{MACHINE_ID}/events"
        f"?fromDate={from_date_str}&toDate=2026-04-17T09:10:00.0000000Z"
        f"&pageSize=1000&skipToken=abc123"
    )


@pytest.fixture()
def client():
    """Stand-in for `PortalClient` — only `.get` is exercised per test."""
    return AsyncMock()


# ---------------------------------------------------------------------------
# Step 1: build_timeline_url (brief case: URL builder)
# ---------------------------------------------------------------------------


def test_build_timeline_url_path_and_params():
    path, params = build_timeline_url(
        machine_id=MACHINE_ID,
        from_date=FROM_DATE,
        to_date=TO_DATE,
        page_size=1000,
    )

    assert path == f"mdeTimelineExperience/machines/{MACHINE_ID}/events"
    assert params["fromDate"] == "2026-04-17T08:45:00.0000000Z"
    assert params["toDate"] == "2026-04-17T09:10:00.0000000Z"
    assert params["pageSize"] == "1000"
    assert params["generateIdentityEvents"] == "true"
    assert params["includeIdentityEvents"] == "true"
    assert params["supportMdiOnlyEvents"] == "true"
    assert params["includeSentinelEvents"] == "false"
    assert params["doNotUseCache"] == "false"
    assert params["forceUseCache"] == "false"
    # Start at fromDate and page FORWARD through the whole window. Without this
    # the apiproxy returns the newest page and a forward-to-now cursor that
    # terminates immediately, truncating history to the first ~1000 events.
    assert params["IsScrollingForward"] == "true"
    # All values are strings — the apiproxy is strict, no bools/ints leak through.
    assert all(isinstance(v, str) for v in params.values())


def test_build_timeline_url_custom_page_size_is_stringified():
    _, params = build_timeline_url(
        machine_id=MACHINE_ID,
        from_date=FROM_DATE,
        to_date=TO_DATE,
        page_size=250,
    )
    assert params["pageSize"] == "250"


def test_build_timeline_url_converts_non_utc_tz_to_utc():
    """`from_date`/`to_date` in a non-UTC tz are converted to UTC and rendered
    with the literal 7-digit `.0000000Z` suffix the apiproxy requires."""
    edt = timezone(timedelta(hours=-4))
    from_date = datetime(2026, 4, 17, 4, 45, 0, tzinfo=edt)  # 08:45:00 UTC
    to_date = datetime(2026, 4, 17, 5, 10, 0, tzinfo=edt)  # 09:10:00 UTC

    _, params = build_timeline_url(
        machine_id=MACHINE_ID,
        from_date=from_date,
        to_date=to_date,
        page_size=1000,
    )

    assert params["fromDate"] == "2026-04-17T08:45:00.0000000Z"
    assert params["toDate"] == "2026-04-17T09:10:00.0000000Z"


def test_build_timeline_url_from_date_subseconds_truncate_down():
    """The lower bound is intentionally approximate: a `from_date` fraction
    truncates DOWN (no client-side lower-bound filter trims it)."""
    from_date = datetime(2026, 4, 17, 8, 45, 0, 123456, tzinfo=UTC)

    _, params = build_timeline_url(
        machine_id=MACHINE_ID, from_date=from_date, to_date=TO_DATE, page_size=1000,
    )

    assert params["fromDate"] == "2026-04-17T08:45:00.0000000Z"


def test_build_timeline_url_to_date_subseconds_round_up_to_not_drop_events():
    """A `to_date` with a sub-second part must round the sent `toDate` UP to
    the next whole second, not truncate down.

    The apiproxy format carries only whole seconds; truncating `09:10:30.999`
    down to `09:10:30` would ask the server for a window ending 999ms early
    and silently drop the events in that gap (the in-page `parsed > to_date`
    filter would happily have kept them). Rounding up asks for `09:10:31` and
    lets the post-filter re-trim to the exact bound."""
    to_date = datetime(2026, 4, 17, 9, 10, 30, 999999, tzinfo=UTC)

    _, params = build_timeline_url(
        machine_id=MACHINE_ID, from_date=FROM_DATE, to_date=to_date, page_size=1000,
    )

    assert params["toDate"] == "2026-04-17T09:10:31.0000000Z"


def test_build_timeline_url_to_date_whole_second_is_unchanged():
    """A `to_date` already on a whole second is not bumped up a second."""
    to_date = datetime(2026, 4, 17, 9, 10, 30, 0, tzinfo=UTC)

    _, params = build_timeline_url(
        machine_id=MACHINE_ID, from_date=FROM_DATE, to_date=to_date, page_size=1000,
    )

    assert params["toDate"] == "2026-04-17T09:10:30.0000000Z"


# ---------------------------------------------------------------------------
# Step 2: stream_device_timeline — pagination (brief case: pagination test)
# ---------------------------------------------------------------------------


async def test_stream_device_timeline_yields_items_across_pages_in_order(client):
    e1, e2, e3 = {"Id": "evt-1"}, {"Id": "evt-2"}, {"Id": "evt-3"}
    next_url = _next_url("2026-04-17T08:50:00.0000000Z")
    # Sanity: this Next's fromDate is inside the window — proves the fixture
    # actually exercises "keep paging", not accidentally terminator (2).
    assert _parse_apiproxy_time(_extract_next_from_date(next_url)) <= TO_DATE

    page1 = {"Items": [e1, e2], "Next": next_url, "Prev": None, "PartialResponseReasons": []}
    page2 = {"Items": [e3], "Next": "", "Prev": None, "PartialResponseReasons": []}
    client.get = AsyncMock(side_effect=[page1, page2])

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [e1, e2, e3]
    assert client.get.call_count == 2


async def test_stream_device_timeline_stops_when_next_is_empty(client):
    """Terminator (1): `Next == ""` ends the loop after a single page."""
    e1 = {"Id": "evt-1"}
    client.get = AsyncMock(
        return_value={"Items": [e1], "Next": "", "Prev": None, "PartialResponseReasons": []}
    )

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [e1]
    assert client.get.call_count == 1


async def test_stream_device_timeline_second_get_call_uses_stripped_next_path_and_params(
    client,
):
    """Task 5's pagination tests mock `client.get` by call sequence only and
    never assert its arguments, so nothing there catches a doubled
    `/apiproxy/mtp/` prefix or a dropped query string on the follow-up
    request. `Next` is host-rooted with its own query string baked in
    (`/apiproxy/mtp/mdeTimelineExperience/...?fromDate=...`); passing it
    straight to `PortalClient.get` would double the prefix that
    `PortalClient`'s own `base_url` already supplies. This pins that the
    second `client.get` call receives the prefix-stripped path plus the
    `Next` URL's query string (fromDate included) carried through as
    `params`."""
    e1, e2 = {"Id": "evt-1"}, {"Id": "evt-2"}
    next_from_date = "2026-04-17T08:50:00.0000000Z"
    next_url = _next_url(next_from_date)
    # Sanity: inside the window, so the loop issues the second `get` at all.
    assert _parse_apiproxy_time(_extract_next_from_date(next_url)) <= TO_DATE

    page1 = {"Items": [e1], "Next": next_url, "Prev": None, "PartialResponseReasons": []}
    page2 = {"Items": [e2], "Next": "", "Prev": None, "PartialResponseReasons": []}
    client.get = AsyncMock(side_effect=[page1, page2])

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [e1, e2]
    assert client.get.call_count == 2

    second_call = client.get.call_args_list[1]
    path = second_call.args[0]
    params = second_call.kwargs.get("params")

    # Prefix-stripped: no leading "/apiproxy/mtp/", not doubled.
    assert path.startswith(f"mdeTimelineExperience/machines/{MACHINE_ID}/events?")
    assert "apiproxy" not in path

    # Next's query string is carried VERBATIM in the path, not decoded into a
    # params dict — parse_qsl + re-encoding would corrupt a base64 skipToken.
    assert params is None
    assert f"fromDate={next_from_date}" in path
    assert "toDate=2026-04-17T09:10:00.0000000Z" in path
    assert "pageSize=1000" in path
    assert "skipToken=abc123" in path


async def test_stream_device_timeline_drops_events_past_to_date(client):
    """Forward-scroll overshoots `toDate` within the final page — the apiproxy
    bounds pagination, not individual events. Events whose ActionTime is after
    `to_date` must be filtered out so an explicit `--to` is an exact upper
    bound (events at exactly to_date are kept)."""
    inside = {"Id": "e1", "ActionTime": "2026-04-17T09:05:00.0000000Z"}
    at_edge = {"Id": "e2", "ActionTime": "2026-04-17T09:10:00.0000000Z"}  # == TO_DATE
    over1 = {"Id": "e3", "ActionTime": "2026-04-17T09:12:00.0000000Z"}
    over2 = {"Id": "e4", "ActionTime": "2026-04-17T10:30:00.0000000Z"}
    page = {
        "Items": [inside, at_edge, over1, over2],
        "Next": "",
        "Prev": None,
        "PartialResponseReasons": [],
    }
    client.get = AsyncMock(side_effect=[page])

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [inside, at_edge]  # over1/over2 filtered out


async def test_stream_device_timeline_next_is_relative_to_mdetimelineexperience(client):
    """The apiproxy `Next` is a path RELATIVE to the mdeTimelineExperience
    endpoint (e.g. `/machines/<id>/events?...&IsScrollingForward=True&
    ReportIdForScrolling=...`) — it does NOT repeat the `mdeTimelineExperience`
    segment. The follow-up request must re-add it; dropping it hits
    `/apiproxy/mtp/machines/<id>/events` and 404s, truncating the timeline to
    the first page. Mirrors the reference's `timelineAPIPrefix + Next`."""
    e1, e2 = {"Id": "evt-1"}, {"Id": "evt-2"}
    # Real-world shape: relative to mdeTimelineExperience, scroll cursor, no skipToken.
    next_url = (
        f"/machines/{MACHINE_ID}/events?fromDate=2026-04-17T08:50:00.0000000Z"
        f"&toDate=2026-04-17T09:10:00.0000000Z&pageSize=1000"
        f"&IsScrollingForward=True&ReportIdForScrolling=20539"
    )
    page1 = {"Items": [e1], "Next": next_url, "Prev": None, "PartialResponseReasons": []}
    page2 = {"Items": [e2], "Next": "", "Prev": None, "PartialResponseReasons": []}
    client.get = AsyncMock(side_effect=[page1, page2])

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [e1, e2]
    second_path = client.get.call_args_list[1].args[0]
    # Endpoint segment re-added; base_url will supply "/apiproxy/mtp/".
    assert second_path.startswith(f"mdeTimelineExperience/machines/{MACHINE_ID}/events?")
    assert "ReportIdForScrolling=20539" in second_path


async def test_stream_device_timeline_preserves_plus_in_skiptoken(client):
    """Regression: the apiproxy skipToken is base64 and can contain a literal
    '+' (also '/' and '='). Following `Next` must preserve it byte-for-byte.
    Routing the query through parse_qsl maps '+' -> space, so the re-encoded
    cursor no longer matches the one the server issued; the follow-up page 404s
    and the timeline is silently truncated to the first page (1000 events)."""
    e1, e2 = {"Id": "evt-1"}, {"Id": "evt-2"}
    next_url = (
        f"/apiproxy/mtp/mdeTimelineExperience/machines/{MACHINE_ID}/events"
        f"?fromDate=2026-04-17T08:50:00.0000000Z&toDate=2026-04-17T09:10:00.0000000Z"
        f"&pageSize=1000&skipToken=aB+cD/eF12+gh=="
    )
    page1 = {"Items": [e1], "Next": next_url, "Prev": None, "PartialResponseReasons": []}
    page2 = {"Items": [e2], "Next": "", "Prev": None, "PartialResponseReasons": []}
    client.get = AsyncMock(side_effect=[page1, page2])

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [e1, e2]
    second_call = client.get.call_args_list[1]
    path = second_call.args[0]
    assert "skipToken=aB+cD/eF12+gh==" in path  # verbatim: '+' not turned into space
    assert second_call.kwargs.get("params") is None


# ---------------------------------------------------------------------------
# Step 3: edge cases (brief: PartialResponseReasons / malformed / cutoff)
# ---------------------------------------------------------------------------


async def test_stream_device_timeline_stops_before_extra_request_when_next_fromdate_exceeds_to_date(
    client,
):
    """Terminator (2): the `fromDate` baked into `Next` is later than
    `to_date` -> stop WITHOUT issuing the extra `get`. Only one entry is
    supplied via `side_effect`: if the loop wrongly made a second call, the
    mock itself would raise on exhaustion rather than the assertions below
    silently passing."""
    e1 = {"Id": "evt-1"}
    next_url = _next_url("2026-04-17T09:15:00.0000000Z")  # 5 min past TO_DATE (09:10)
    assert _parse_apiproxy_time(_extract_next_from_date(next_url)) > TO_DATE

    page1 = {"Items": [e1], "Next": next_url, "Prev": None, "PartialResponseReasons": []}
    client.get = AsyncMock(side_effect=[page1])

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [e1]
    assert client.get.call_count == 1


async def test_stream_device_timeline_follows_next_with_malformed_from_date(client):
    """A `Next` whose `fromDate` doesn't parse is still followed — no crash,
    fall back to fetching it (mirrors
    timeline-downloader/internal/api/devices.go:255-260)."""
    e1, e2 = {"Id": "evt-1"}, {"Id": "evt-2"}
    next_url = _next_url("not-a-real-date")
    with pytest.raises(ValueError):
        _parse_apiproxy_time(_extract_next_from_date(next_url))  # sanity: genuinely malformed

    page1 = {"Items": [e1], "Next": next_url, "Prev": None, "PartialResponseReasons": []}
    page2 = {"Items": [e2], "Next": "", "Prev": None, "PartialResponseReasons": []}
    client.get = AsyncMock(side_effect=[page1, page2])

    results = [
        item
        async for item in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        )
    ]

    assert results == [e1, e2]
    assert client.get.call_count == 2


async def test_stream_device_timeline_raises_api_error_on_partial_response_reasons(client):
    """Non-empty `PartialResponseReasons` on the first page is a hard
    failure, not a silent truncation — raised as `APIError` with the
    reasons surfaced."""
    reasons = ["ScopeAccessDenied", "Timeout"]
    page1 = {
        "Items": [{"Id": "evt-1"}],
        "Next": "",
        "Prev": None,
        "PartialResponseReasons": reasons,
    }
    client.get = AsyncMock(side_effect=[page1])

    with pytest.raises(APIError) as exc_info:
        async for _ in stream_device_timeline(
            client, MACHINE_ID, FROM_DATE, TO_DATE, page_size=1000,
        ):
            pass

    assert exc_info.value.detail == reasons
