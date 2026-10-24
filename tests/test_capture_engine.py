"""Capture-first planning, query contract and capped capture engine behavior."""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from datetime import UTC, datetime, timedelta

import pytest

from tests.capture_fakes import FakeHunting, MemorySink, schema_rows
from xdr_cli.exceptions import (
    ArtifactError,
    AuthError,
    ConflictError,
    NetworkError,
    QueryError,
    RateLimitError,
    TimeoutError,
)
from xdr_cli.schema_graph import capture_engine
from xdr_cli.schema_graph.capture_engine import (
    CaptureBudgets,
    capture_recent,
    jobs_directory,
    live_capture_references,
    live_capture_run_ids,
    mark_capture_consumed,
    parse_lookback,
)
from xdr_cli.schema_graph.capture_plan import parse_instant, plan_capture
from xdr_cli.schema_graph.capture_query import (
    SliceSpec,
    compile_fetch_query,
    fetch_query_args,
    parse_wrapped,
    verify_capture_query,
)

NOW = datetime(2026, 10, 24, 4, 0, 30, tzinfo=UTC)
START = NOW.replace(second=0) - timedelta(hours=24)
END = START + timedelta(hours=24)
BINDING = {"tenant_fingerprint": "t" * 16, "backend": "official",
           "schema_digest": "d" * 16, "horizon_seconds": 86400}
EVENT_SCHEMA = {"Timestamp": "datetime", "DeviceId": "string", "ReportId": "long",
                "AdditionalFields": "dynamic"}
EVENTS = {"DeviceProcessEvents": EVENT_SCHEMA}


@pytest.fixture(autouse=True)
def _private_home(config_dir):
    """The engine takes the global evidence lock under the configured home."""

    return config_dir


def at(seconds: float) -> str:
    return (START + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def events(count: int, *, spread: float = 86400.0, offset: float = 0.0, prefix="d") -> list[dict]:
    return [{"Timestamp": at(offset + spread * i / max(count, 1)), "DeviceId": f"{prefix}{i % 7}",
             "ReportId": i, "AdditionalFields": {"n": i}} for i in range(count)]


def tables_of(count: int, rows: int = 10) -> tuple[dict, dict]:
    schema = {f"T{i}": {"Timestamp": "datetime", "K": "string"} for i in range(count)}
    data = {name: [{"Timestamp": at(i), "K": f"{name}-{i}"} for i in range(rows)]
            for name in schema}
    return schema, data


class Clock:
    def __init__(self) -> None:
        self.value = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.value

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.value += seconds


def run(service, sink, tmp_path, *, schema=EVENTS, budgets=None, binding=BINDING, now=NOW,
        clock=None):
    clock = clock or Clock()
    return asyncio.run(capture_recent(
        service, schema_rows=schema_rows(schema), binding=binding, state_dir=tmp_path,
        sink=sink, budgets=budgets or CaptureBudgets(), now=lambda: now, clock=clock,
        sleep=clock.sleep,
    ))


def in_interval(rows: list[dict]) -> list[dict]:
    return [row for row in rows if START <= parse_instant(row["Timestamp"]) < END]


def canonical(rows: list[dict]) -> Counter:
    return Counter(json.dumps(row, sort_keys=True) for row in rows)


def ledger_path(tmp_path):
    (path,) = jobs_directory(tmp_path).glob("cap-*.json")
    return path


def ledger(tmp_path) -> dict:
    return json.loads(ledger_path(tmp_path).read_text())


def summary(report) -> dict:
    return {table["table"]: table for table in report.tables}


# --- plan / query contract -------------------------------------------------


def test_plan_selects_verified_time_columns_and_explicit_kinds():
    rows = schema_rows({
        "DeviceProcessEvents": EVENT_SCHEMA,
        "DeviceInfo": {"Timestamp": "datetime", "DeviceId": "string"},
        "SigninLogs": {"TimeGenerated": "datetime", "UserPrincipalName": "string"},
        "ExposureGraphNodes": {"NodeId": "string", "NodeProperties": "dynamic"},
        "Weird": {"Timestamp": "string", "X": "string"},
        "DeviceTvmSoftwareVulnerabilitiesKB": {"CveId": "string"},
    })
    rows.append({"TableName": "PortalOnly", "ColumnName": "Timestamp", "ColumnType": "datetime",
                 "Sources": ["portal-metadata"]})
    plan = plan_capture(rows, now=NOW)
    kinds = {table.name: (table.kind, table.time_column) for table in plan.tables}
    assert kinds == {
        "DeviceInfo": ("snapshot-timed", "Timestamp"),
        "DeviceProcessEvents": ("event", "Timestamp"),
        "ExposureGraphNodes": ("state", None),
        "SigninLogs": ("event", "TimeGenerated"),
    }
    reasons = {item["table"]: item["reason"] for item in plan.exclusions}
    assert reasons == {"Weird": "time-column-not-datetime",
                       "DeviceTvmSoftwareVulnerabilitiesKB": "global-knowledge-base"}
    assert plan.end == END and plan.end - plan.start == timedelta(hours=24)


def test_queries_are_one_table_literal_bounded_and_recompile_exactly():
    recent = SliceSpec("DeviceProcessEvents", "Timestamp", START, END)
    state = SliceSpec("ExposureGraphNodes", None, None, None)
    query = compile_fetch_query(recent, 25000)
    assert "ago(" not in query and "top 25001 by Timestamp desc" in query
    assert "__xdr_n <= 25000" in query and "count) > 25000" in query
    # Rows are packed before any helper column exists, so native names cannot collide.
    assert query.index("pack_all()") < query.index("row_number()")
    assert "project __xdr_row=__xdr_payload" in query
    sample = compile_fetch_query(state, 25000)
    assert "take 25001" in sample and "toscalar(ExposureGraphNodes | count)" in sample
    for spec, text in ((recent, query), (state, sample)):
        args = fetch_query_args(spec, 25000)
        assert verify_capture_query(args, text)
        assert not verify_capture_query({**args, "row_cap": 100}, text)
        assert not verify_capture_query({**args, "row_cap": True}, text)
        assert not verify_capture_query({**args, "mode": "other"}, text)
        assert not verify_capture_query({**args, "compiler_version": "capture-query/v1"}, text)
    assert not verify_capture_query(fetch_query_args(recent, 25000),
                                    query.replace("25001", "25002"))
    with pytest.raises(ValueError):
        SliceSpec.from_dict({**recent.to_dict(), "partition": [1, 4]})
    with pytest.raises(ValueError):
        SliceSpec("T;drop", None, None, None)
    with pytest.raises(ValueError):
        SliceSpec("T", "Timestamp", END, START)


def control(count, size=10, floor=None, total=None, more=None):
    return {"__xdr_count": count, "__xdr_bytes": size, "__xdr_control": "v2",
            "__xdr_more": int(bool(floor)) if more is None else more,
            "__xdr_floor": floor, "__xdr_total": total, "__xdr_row": None}


def payload(row):
    return {"__xdr_count": None, "__xdr_bytes": None, "__xdr_control": "", "__xdr_more": None,
            "__xdr_floor": None, "__xdr_total": None, "__xdr_row": row}


@pytest.mark.parametrize(("packets", "complete", "problem"), [
    ([control(2), payload({"a": 1}), payload({"a": 2})], True, None),
    ([control(2, floor="2026-10-24T01:00:00.1234567Z", total=9), payload({"a": 1}),
      payload({"a": 2})], True, None),
    ([control(2), payload({"a": 1})], False, None),  # silent server truncation
    ([control(3)] + [payload({"a": i}) for i in range(3)], False, None),  # over cap 2
    ([payload({"a": 1})], False, "missing-control-packet"),
    ([control(1), control(1), payload({"a": 1})], False, "duplicate-control-packet"),
    ([control(True), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(-1)], False, "invalid-control-packet"),
    ([control(1, float("nan")), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(1, float("inf")), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(1, floor="soon"), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(1, total=-3), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(1, more="yes"), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(1, more=True), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(1, more=2), payload({"a": 1})], False, "invalid-control-packet"),
    ([control(1, more=1), payload({"a": 1})], False, None),  # more exist but fewer than cap
    ([control(1, floor="2026-10-24T01:00:00Z", more=0), payload({"a": 1})], False,
     "invalid-control-packet"),
    ([control(1), {**payload({"a": 1}), "__xdr_count": 1}], False, "invalid-payload-packet"),
    ([control(1), {**payload({"a": 1}), "__xdr_floor": "x"}], False, "invalid-payload-packet"),
    ([control(1), payload("not-a-row")], False, "invalid-payload-packet"),
    ([control(1), {**payload({"a": 1}), "Native": "x"}], False, "unexpected-packet-columns"),
])
def test_wrapped_result_requires_same_evaluation_proof(packets, complete, problem):
    wrapped = parse_wrapped(packets)
    assert wrapped.complete(2) is complete
    if problem:
        assert problem in wrapped.problems


def test_parse_lookback():
    assert parse_lookback("24h") == timedelta(hours=24)
    assert parse_lookback("1d") == timedelta(days=1)
    assert parse_lookback("90s") == timedelta(seconds=90)
    assert parse_lookback("99999m") == timedelta(minutes=99999)
    with pytest.raises(ValueError):
        parse_lookback("0h")
    with pytest.raises(ValueError):
        parse_lookback("24 hours")


@pytest.mark.parametrize(("text", "expected"), [
    ("2026-10-24T12:00:00.123456+02:00", datetime(2026, 10, 24, 10, 0, 0, 123456, tzinfo=UTC)),
    ("2026-10-24T12:00:00.1234567Z", datetime(2026, 10, 24, 12, 0, 0, 123456, tzinfo=UTC)),
    ("2026-10-24T12:00:00.5-03:30", datetime(2026, 10, 24, 15, 30, 0, 500000, tzinfo=UTC)),
    ("2026-10-24T12:00:00Z", datetime(2026, 10, 24, 12, 0, tzinfo=UTC)),
    ("2026-10-24T12:00:00", datetime(2026, 10, 24, 12, 0, tzinfo=UTC)),
])
def test_parse_instant_keeps_offsets_with_fractions(text, expected):
    assert parse_instant(text) == expected


# --- engine ---------------------------------------------------------------


def test_one_query_per_table_captures_small_tables_whole(tmp_path):
    data = {
        "DeviceProcessEvents": events(300) + events(5, offset=-3600),  # 5 rows before interval
        "SigninLogs": [{"TimeGenerated": at(10 * i), "UserPrincipalName": f"u{i}@x"}
                       for i in range(40)],
        "ExposureGraphNodes": [{"NodeId": f"n{i}", "NodeProperties": {}} for i in range(25)],
        "EmptyEvents": [],
    }
    schema = {"DeviceProcessEvents": EVENT_SCHEMA,
              "SigninLogs": {"TimeGenerated": "datetime", "UserPrincipalName": "string"},
              "ExposureGraphNodes": {"NodeId": "string", "NodeProperties": "dynamic"},
              "EmptyEvents": {"Timestamp": "datetime", "X": "string"}}
    service, sink = FakeHunting(data), MemorySink()
    report = run(service, sink, tmp_path, schema=schema)
    assert report.status == "complete" and report.stop is None
    assert len(service.calls) == 4 and report.counters.queries == 4
    assert canonical(sink.rows("DeviceProcessEvents")) == canonical(
        in_interval(data["DeviceProcessEvents"]))
    assert canonical(sink.rows("SigninLogs")) == canonical(data["SigninLogs"])
    tables = summary(report)
    assert tables["EmptyEvents"]["status"] == "complete"
    assert tables["EmptyEvents"]["captured_rows"] == 0
    assert sink.capture("EmptyEvents").proof.source_count == 0
    assert tables["DeviceProcessEvents"]["coverage"]["truncated"] is False
    assert tables["DeviceProcessEvents"]["coverage"]["start"] == "2026-10-23T04:00:00Z"
    assert tables["ExposureGraphNodes"]["coverage"]["mode"] == "sample"
    assert tables["ExposureGraphNodes"]["source_total"] == 25
    assert "ExposureGraphNodes" in service.calls[-1]  # inventory samples after the timed dump
    assert report.binding["execution_surface"] == "graph"
    assert ledger(tmp_path)["status"] == "closed"
    capture = sink.capture("DeviceProcessEvents")
    assert capture.proof.source_count == capture.proof.payload_count
    assert verify_capture_query(capture.query_args, capture.query)
    assert capture.coverage == tables["DeviceProcessEvents"]["coverage"]


def test_capped_table_is_a_labelled_recent_sample_of_exactly_cap_rows(tmp_path):
    data = {"DeviceProcessEvents": events(1000)}
    service, sink = FakeHunting(data), MemorySink()
    report = run(service, sink, tmp_path, budgets=CaptureBudgets(request_rows=100))
    assert report.status == "complete" and len(service.calls) == 1
    table = summary(report)["DeviceProcessEvents"]
    coverage = table["coverage"]
    assert coverage["truncated"] and coverage["span_complete"] is False
    assert table["source_total"] == 1000 and table["captured_rows"] == 100
    newest = sorted(data["DeviceProcessEvents"], key=lambda row: row["Timestamp"])[-100:]
    assert canonical(sink.rows()) == canonical(newest)
    floor = parse_instant(coverage["floor"])
    assert floor == min(parse_instant(row["Timestamp"]) for row in newest)
    assert parse_instant(coverage["start"]) == floor and coverage["end"] == "2026-10-24T04:00:00Z"


def test_timestamp_ties_still_yield_a_full_capped_sample(tmp_path):
    tied = [{"Timestamp": at(5000), "DeviceId": f"t{i}", "ReportId": i, "AdditionalFields": None}
            for i in range(10)]
    sink = MemorySink()
    report = run(FakeHunting({"DeviceProcessEvents": tied}), sink, tmp_path,
                 budgets=CaptureBudgets(request_rows=5))
    table = summary(report)["DeviceProcessEvents"]
    assert table["status"] == "complete" and table["captured_rows"] == 5
    assert table["coverage"]["truncated"] and len(sink.rows()) == 5


def test_silent_server_truncation_halves_the_cap_never_completes(tmp_path):
    data = {"DeviceProcessEvents": events(400)}
    service, sink = FakeHunting(data), MemorySink()
    service.payload_limit = 60
    report = run(service, sink, tmp_path,
                 budgets=CaptureBudgets(request_rows=1000, min_request_rows=10))
    capture = sink.capture("DeviceProcessEvents")
    assert report.status == "complete" and capture.proof.payload_count <= 60
    assert capture.proof.row_cap < 1000 and report.counters.reductions >= 4
    newest = sorted(data["DeviceProcessEvents"], key=lambda row: row["Timestamp"])
    assert canonical(sink.rows()) == canonical(newest[-capture.proof.payload_count:])


def test_resource_errors_shrink_then_gap_and_larger_limits_reopen(tmp_path):
    data = {"DeviceProcessEvents": events(500)}
    service, sink = FakeHunting(data), MemorySink()

    def fail(query):
        if "top 101 " not in query:
            raise TimeoutError("API request timed out after 120 seconds.")

    service.fail = fail
    report = run(service, sink, tmp_path, budgets=CaptureBudgets(request_rows=400))
    assert report.status == "complete"
    assert sink.capture("DeviceProcessEvents").proof.row_cap == 100

    service2, sink2 = FakeHunting(data), MemorySink()

    def always(query):
        raise TimeoutError("timed out")

    service2.fail = always
    small = run(service2, sink2, tmp_path / "gap",
                budgets=CaptureBudgets(request_rows=400, min_request_rows=200))
    table = summary(small)["DeviceProcessEvents"]
    assert small.status == "partial" and table["status"] == "irretrievable"
    assert table["reasons"] == ["resource-limit"] and not sink2.rows()
    service2.fail = None
    again = run(service2, sink2, tmp_path / "gap",
                budgets=CaptureBudgets(request_rows=400, min_request_rows=50))
    assert again.job_id == small.job_id and again.status == "complete"


def test_query_budget_pauses_and_resume_never_refetches_finished_tables(tmp_path):
    schema, data = tables_of(5)
    service, sink = FakeHunting(data), MemorySink()
    first = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=2))
    assert first.status == "paused" and first.stop.kind == "budget-queries"
    assert first.continuation and live_capture_run_ids(tmp_path) == set(first.captured_run_ids)
    reports = [first]
    for _attempt in range(10):  # bounded so a zero-progress regression fails, not hangs
        if reports[-1].status != "paused":
            break
        reports.append(run(service, sink, tmp_path, schema=schema,
                           budgets=CaptureBudgets(max_queries=2)))
        assert reports[-1].job_id == first.job_id and reports[-1].resumed
    assert reports[-1].status == "complete" and len(service.calls) == 5
    assert len(set(service.calls)) == 5  # each table fetched exactly once
    assert reports[-1].job_counters.fetch_queries == 5
    # Finished but not yet handed to local discovery: still pinned for retention.
    assert live_capture_run_ids(tmp_path) == set(reports[-1].captured_run_ids)


def test_unverified_artifact_is_refetched_on_resume(tmp_path):
    schema, data = tables_of(3)
    service, sink = FakeHunting(data), MemorySink()
    first = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=2))
    sink.invalid.add(first.captured_run_ids[0])
    final = run(service, sink, tmp_path, schema=schema)
    assert final.status == "complete" and first.captured_run_ids[0] not in final.captured_run_ids
    assert len(service.calls) == 4  # 2 + 1 refetch + 1 remaining


def test_row_and_byte_budgets_checkpoint_before_publishing(tmp_path):
    schema, data = tables_of(4, rows=30)
    service, sink = FakeHunting(data), MemorySink()
    report = run(service, sink, tmp_path, schema=schema,
                 budgets=CaptureBudgets(request_rows=30, max_rows=70))
    assert report.status == "paused" and report.stop.kind == "budget-rows"
    assert report.counters.rows <= 70
    sink2 = MemorySink()
    bytes_report = run(FakeHunting(data), sink2, tmp_path / "bytes", schema=schema,
                       budgets=CaptureBudgets(max_bytes=4000))
    assert 0 < bytes_report.counters.bytes <= 4000
    assert bytes_report.status == "paused" and bytes_report.stop.kind == "budget-bytes"


def test_table_larger_than_byte_budget_shrinks_its_span(tmp_path):
    data = {"T": [{"Timestamp": at(i), "K": "x" * 500} for i in range(400)]}
    report = run(FakeHunting(data), MemorySink(), tmp_path,
                 schema={"T": {"Timestamp": "datetime", "K": "string"}},
                 budgets=CaptureBudgets(max_bytes=40_000, min_request_rows=10))
    table = summary(report)["T"]
    assert table["status"] == "complete" and table["truncated"]
    assert report.counters.bytes <= 40_000 and report.counters.reductions >= 1


def test_short_rate_limit_waits_long_rate_limit_checkpoints(tmp_path):
    service, sink, clock = FakeHunting({"DeviceProcessEvents": events(20)}), MemorySink(), Clock()
    state = {"n": 0}

    def fail(query):
        state["n"] += 1
        if state["n"] == 1:
            raise RateLimitError(retry_after=5)
        if state["n"] == 2:
            raise RateLimitError(retry_after=900)

    service.fail = fail
    first = run(service, sink, tmp_path, clock=clock)
    assert clock.slept == [5]
    assert first.status == "paused" and first.stop.kind == "rate-limited"
    assert first.stop.retry_after_seconds == 900
    calls = len(service.calls)
    early = run(service, sink, tmp_path, now=NOW + timedelta(seconds=60))
    assert early.status == "paused" and early.stop.retry_after_seconds == 840
    assert len(service.calls) == calls  # honored the retry delay without a request
    later = run(service, sink, tmp_path, now=NOW + timedelta(seconds=901))
    assert later.status == "complete" and later.job_id == first.job_id


def test_network_errors_retry_with_backoff_then_checkpoint(tmp_path):
    service, sink, clock = FakeHunting({"DeviceProcessEvents": events(5)}), MemorySink(), Clock()

    def fail(query):
        raise NetworkError("connection reset")

    service.fail = fail
    report = run(service, sink, tmp_path, clock=clock)
    assert report.status == "paused" and report.stop.kind == "network"
    assert clock.slept == [2, 8]
    short = Clock()
    report = run(service, sink, tmp_path / "short", clock=short,
                 budgets=CaptureBudgets(deadline_seconds=5))
    assert report.stop.kind == "network" and short.slept == [2]


def test_cancellation_and_fatal_auth_leave_resumable_checkpoints(tmp_path):
    schema, data = tables_of(6, rows=5)
    service, sink = FakeHunting(data), MemorySink()
    state = {"n": 0}

    def fail(query):
        state["n"] += 1
        if state["n"] == 3:
            raise KeyboardInterrupt
        if state["n"] == 5:
            raise AuthError("Authentication is required.")

    service.fail = fail
    with pytest.raises(KeyboardInterrupt):
        run(service, sink, tmp_path, schema=schema)
    saved = ledger(tmp_path)
    assert saved["status"] == "open" and saved["stops"][-1]["kind"] == "cancelled"
    with pytest.raises(AuthError):
        run(service, sink, tmp_path, schema=schema)
    assert ledger(tmp_path)["stops"][-1]["kind"] == "fatal"
    final = run(service, sink, tmp_path, schema=schema)
    assert final.status == "complete"
    assert canonical(sink.rows()) == canonical([row for rows in data.values() for row in rows])


def test_interrupted_write_is_refetched_and_coverage_stays_authoritative(tmp_path):
    service, sink = FakeHunting({"DeviceProcessEvents": events(40)}), MemorySink()

    def crash(capture):
        sink.fail_after_write = None
        raise KeyboardInterrupt

    sink.fail_after_write = crash
    with pytest.raises(KeyboardInterrupt):
        run(service, sink, tmp_path)
    assert sink.writes == 1  # an orphan artifact exists, but the ledger never claimed it
    assert ledger(tmp_path)["tables"]["DeviceProcessEvents"]["slice"]["state"] == "pending"
    report = run(service, sink, tmp_path)
    assert report.status == "complete" and len(service.calls) == 2


def test_binding_or_surface_change_never_mixes_jobs(tmp_path):
    schema, data = tables_of(5, rows=5)
    budgets = CaptureBudgets(max_queries=2)
    service, sink = FakeHunting(data), MemorySink()
    first = run(service, sink, tmp_path, schema=schema, budgets=budgets)
    other = {**BINDING, "schema_digest": "e" * 16}
    changed = run(service, sink, tmp_path, schema=schema, budgets=budgets, binding=other)
    assert changed.job_id != first.job_id and not changed.resumed
    statuses = sorted(json.loads(path.read_text())["status"]
                      for path in jobs_directory(tmp_path).glob("cap-*.json"))
    assert statuses == ["open", "superseded"]
    service.surface = "mde"
    flipped = run(service, sink, tmp_path, schema=schema, budgets=budgets, binding=other)
    assert flipped.job_id == changed.job_id
    assert flipped.stop.kind == "binding-changed" and flipped.status == "paused"
    fresh = run(service, sink, tmp_path, schema=schema, budgets=budgets, binding=other)
    assert fresh.job_id != changed.job_id and fresh.binding["execution_surface"] == "mde"


def test_expired_job_starts_a_new_fixed_interval(tmp_path):
    schema, data = tables_of(5, rows=5)
    service, sink = FakeHunting(data), MemorySink()
    first = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=2))
    later = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=2),
                now=NOW + timedelta(hours=25))
    assert later.job_id != first.job_id and later.interval["end"] != first.interval["end"]


def test_rejected_table_fails_alone_and_report_is_partial(tmp_path):
    data = {"DeviceProcessEvents": events(30), "Broken": [{"Timestamp": at(1), "X": "y"}]}
    schema = {"DeviceProcessEvents": EVENT_SCHEMA,
              "Broken": {"Timestamp": "datetime", "X": "string"}}
    service, sink = FakeHunting(data), MemorySink()

    def fail(query):
        if "Broken" in query:
            error = QueryError("Failed to resolve scalar expression named 'X'")
            error.error_code = "QUERY_UNKNOWN_COLUMN"
            raise error

    service.fail = fail
    report = run(service, sink, tmp_path, schema=schema)
    tables = summary(report)
    assert tables["Broken"]["status"] == "failed"
    assert tables["Broken"]["error_code"] == "QUERY_UNKNOWN_COLUMN"
    assert tables["DeviceProcessEvents"]["status"] == "complete"
    assert report.status == "partial" and ledger(tmp_path)["status"] == "closed"


def test_deadline_bounds_a_slow_request(tmp_path):
    class Slow(FakeHunting):
        async def execute_hunting(self, query):
            await asyncio.sleep(5)

    report = asyncio.run(capture_recent(
        Slow({}), schema_rows=schema_rows({"T": {"Timestamp": "datetime", "K": "string"}}),
        binding=BINDING, state_dir=tmp_path, sink=MemorySink(), now=lambda: NOW,
        budgets=CaptureBudgets(deadline_seconds=0.05),
    ))
    assert report.status == "paused" and report.stop.kind == "deadline"


def test_zero_query_budget_returns_a_clean_checkpoint(tmp_path):
    service = FakeHunting({"DeviceProcessEvents": events(5)})
    report = run(service, MemorySink(), tmp_path, budgets=CaptureBudgets(max_queries=0))
    assert report.status == "paused" and report.stop.kind == "budget-queries"
    assert not service.calls


def test_concurrent_job_conflicts(tmp_path, monkeypatch):
    from filelock import Timeout

    def locked(path, timeout):
        raise Timeout(str(path))

    monkeypatch.setattr(capture_engine, "exclusive_lock", locked)
    with pytest.raises(ConflictError):
        run(FakeHunting({}), MemorySink(), tmp_path, schema={"T": {"Timestamp": "datetime"}})


def test_plan_only_makes_no_requests_or_files(tmp_path):
    service = FakeHunting({"DeviceProcessEvents": events(5)})
    report = asyncio.run(capture_recent(
        service, schema_rows=schema_rows(EVENTS), binding=BINDING, state_dir=tmp_path,
        sink=MemorySink(), plan_only=True, now=lambda: NOW,
    ))
    assert report.status == "planned" and not service.calls
    assert not jobs_directory(tmp_path).exists()


def test_ledger_is_value_free_and_private(tmp_path):
    sink = MemorySink()
    run(FakeHunting({"DeviceProcessEvents": events(30, prefix="SensitiveDeviceValue")}),
        sink, tmp_path)
    assert sink.rows()
    text = ledger_path(tmp_path).read_text()
    assert "SensitiveDeviceValue" not in text
    assert oct(ledger_path(tmp_path).stat().st_mode & 0o777) == "0o600"


def test_publication_holds_evidence_lock_with_ledger_update(tmp_path, monkeypatch):
    seen = []

    class Lock:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            seen.append("lock")

        def __exit__(self, *exc):
            seen.append("unlock")

    monkeypatch.setattr(capture_engine, "schema_evidence_lock", Lock)
    original_save = capture_engine.CaptureLedger.save

    def save(self):
        seen.append("save")
        original_save(self)

    monkeypatch.setattr(capture_engine.CaptureLedger, "save", save)
    sink = MemorySink()
    original_write = sink.write_slice
    sink.write_slice = lambda capture, rows: (seen.append("write"),
                                               original_write(capture, rows))[1]
    run(FakeHunting({"DeviceProcessEvents": events(3)}), sink, tmp_path)
    start = seen.index("lock")
    assert seen[start:start + 4] == ["lock", "write", "save", "unlock"]


def test_retention_references_are_strict_and_survive_until_handoff(tmp_path):
    service, sink = FakeHunting({"DeviceProcessEvents": events(20)}), MemorySink()
    report = run(service, sink, tmp_path)
    references = live_capture_references(tmp_path)
    assert {ref["artifact"]["run_id"] for ref in references} == set(report.captured_run_ids)
    assert {(ref["status"], ref["handoff"]) for ref in references} == {("closed", "pending")}
    # Indexing was interrupted: the rerun returns the same job without requests.
    again = run(service, sink, tmp_path)
    assert again.job_id == report.job_id and again.resumed and len(service.calls) == 1
    assert mark_capture_consumed(tmp_path, report.job_id) is True
    assert live_capture_references(tmp_path) == []
    fresh = run(service, sink, tmp_path)
    assert fresh.job_id != report.job_id and len(service.calls) == 2

    for path in jobs_directory(tmp_path).glob("cap-*.json"):
        path.unlink()
    bad = jobs_directory(tmp_path) / "cap-20261024T000000Z-00000000.json"
    bad.write_text("{not json")
    with pytest.raises(ArtifactError):
        live_capture_references(tmp_path)
    bad.unlink()
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    bad.symlink_to(target)
    with pytest.raises(ArtifactError):
        live_capture_run_ids(tmp_path)


def test_legacy_v1_ledger_artifacts_stay_pinned_until_consumed(tmp_path):
    directory = jobs_directory(tmp_path)
    directory.mkdir(parents=True)
    job_id = "cap-20261024T044441Z-d7932fe5"
    artifact = {"run_id": "run-legacy", "data_sha256": "a" * 64, "rows": 3, "bytes": 30}
    (directory / f"{job_id}.json").write_text(json.dumps({
        "format": "xdr-capture-job/v1", "job_id": job_id, "status": "open", "binding": {},
        "tables": {"T": {"slices": [{"id": "w-" + "0" * 24, "artifact": artifact}]}},
    }))
    assert [ref["artifact"]["run_id"] for ref in live_capture_references(tmp_path)] == \
        ["run-legacy"]
    report = run(FakeHunting({"DeviceProcessEvents": events(3)}), MemorySink(), tmp_path)
    assert report.job_id != job_id  # never resumed
    assert mark_capture_consumed(tmp_path, job_id)
    assert "run-legacy" not in live_capture_run_ids(tmp_path)


def _narrow_pending_scope(data):
    data["tables"]["T1"]["slice"]["spec"]["start"] = "2026-10-23T10:00:00Z"


@pytest.mark.parametrize("damage", [
    lambda d: d.pop("created_at"),
    lambda d: d["counters"].__setitem__("queries", "damaged"),
    lambda d: d["counters"].pop("rows"),
    lambda d: d["counters"].__setitem__("wait_seconds", float("nan")),
    lambda d: d.__setitem__("resume_after", "soon"),
    lambda d: d["tables"]["T1"]["slice"].pop("spec"),
    lambda d: d["tables"]["T1"]["slice"].__setitem__("attempts", -1),
    lambda d: d["tables"]["T1"]["slice"].__setitem__("cap", "x"),
    _narrow_pending_scope,
    lambda d: d["tables"]["T1"]["slice"].__setitem__("id", "w-" + "1" * 24),
    lambda d: d["tables"].pop("T1"),
    lambda d: d["tables"]["T0"]["slice"]["coverage"].__setitem__("start",
                                                                 "2026-10-23T09:00:00Z"),
    lambda d: d["tables"]["T0"]["slice"]["coverage"].__setitem__("end", "2026-10-24T09:00:00Z"),
    lambda d: d["tables"]["T0"]["slice"].__setitem__("state", "pending"),
])
def test_damaged_ledger_fails_closed_and_is_skipped_at_startup(tmp_path, damage):
    schema, data = tables_of(3, rows=5)
    service, sink = FakeHunting(data), MemorySink()
    first = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=1))
    assert first.status == "paused"
    path = ledger_path(tmp_path)
    saved = json.loads(path.read_text())
    damage(saved)
    path.write_text(json.dumps(saved))
    with pytest.raises(ArtifactError):
        live_capture_references(tmp_path)
    moved = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=1))
    assert moved.job_id != first.job_id and path.exists()  # skipped and retained


def test_sample_sentinel_marks_truncation_without_trusting_the_total(tmp_path):
    schema = {"Inv": {"NodeId": "string"}}
    exact = {"Inv": [{"NodeId": f"n{i}"} for i in range(5)]}
    report = run(FakeHunting(exact), MemorySink(), tmp_path, schema=schema,
                 budgets=CaptureBudgets(request_rows=5))
    assert summary(report)["Inv"]["coverage"]["span_complete"] is True  # exactly cap rows
    more = {"Inv": [{"NodeId": f"n{i}"} for i in range(6)]}
    report = run(FakeHunting(more), MemorySink(), tmp_path / "more", schema=schema,
                 budgets=CaptureBudgets(request_rows=5))
    coverage = summary(report)["Inv"]["coverage"]
    assert coverage["truncated"] and coverage["span_complete"] is False


def test_missing_control_is_treated_as_truncation_but_bad_controls_fail_closed(tmp_path):
    data = {"DeviceProcessEvents": events(400)}
    service, sink = FakeHunting(data), MemorySink()
    service.drop_control_above = 150
    report = run(service, sink, tmp_path, budgets=CaptureBudgets(request_rows=1000))
    capture = sink.capture("DeviceProcessEvents")
    assert report.status == "complete" and capture.proof.row_cap <= 150

    class Duplicate(FakeHunting):
        async def execute_hunting(self, query):
            result = await super().execute_hunting(query)
            result.results.insert(0, dict(result.results[0]))
            return result

    service2 = Duplicate(data)
    report = run(service2, MemorySink(), tmp_path / "dup")
    table = summary(report)["DeviceProcessEvents"]
    assert table["status"] == "failed" and len(service2.calls) == 2  # one retry, no halving


def test_resume_binds_ledger_coverage_to_the_artifact_metadata(tmp_path):
    schema = {"Inv": {"NodeId": "string"}, "T0": {"Timestamp": "datetime", "K": "string"}}
    data = {"Inv": [{"NodeId": f"n{i}"} for i in range(3)],
            "T0": [{"Timestamp": at(i), "K": str(i)} for i in range(3)]}
    service, sink = FakeHunting(data), MemorySink()
    first = run(service, sink, tmp_path, schema=schema,
                budgets=CaptureBudgets(request_rows=2, min_request_rows=1, max_queries=1))
    assert summary(first)["T0"]["coverage"]["truncated"]
    path = ledger_path(tmp_path)
    saved = json.loads(path.read_text())
    coverage = saved["tables"]["T0"]["slice"]["coverage"]
    coverage.update(truncated=False, span_complete=True, floor=None,
                    start=saved["interval"]["start"])  # still structurally valid
    path.write_text(json.dumps(saved))
    refs = live_capture_references(tmp_path)
    assert refs[0]["expected"]["coverage"]["span_complete"] is True  # retention sees the claim
    resumed = run(service, sink, tmp_path, schema=schema,
                  budgets=CaptureBudgets(request_rows=2, min_request_rows=1))
    table = summary(resumed)["T0"]
    assert table["coverage"]["truncated"] is True  # forged claim rejected, slice refetched
    assert sum("T0" in call for call in service.calls) == 2


def test_deadline_cut_request_halves_cap_and_does_not_block_other_tables(tmp_path):
    schema = {"AAA": {"Timestamp": "datetime", "K": "string"},
              "BBB": {"Timestamp": "datetime", "K": "string"}}
    data = {name: [{"Timestamp": at(i), "K": str(i)} for i in range(5)] for name in schema}

    class SlowA(FakeHunting):
        async def execute_hunting(self, query):
            if "AAA" in query and "top 25001 " in query:
                await asyncio.sleep(5)
            return await super().execute_hunting(query)

    service, sink = SlowA(data), MemorySink()
    for _attempt in range(3):
        report = asyncio.run(capture_recent(
            service, schema_rows=schema_rows(schema), binding=BINDING, state_dir=tmp_path,
            sink=sink, now=lambda: NOW, budgets=CaptureBudgets(deadline_seconds=0.2)))
    tables = summary(report)
    assert tables["BBB"]["status"] == "complete"  # the slow table no longer heads every run
    assert tables["AAA"]["status"] == "complete"
    assert sink.capture("AAA").proof.row_cap < 25000


@pytest.mark.parametrize("make_error", [
    lambda: __import__("xdr_cli.exceptions", fromlist=["APIError"]).APIError(
        "API returned a malformed JSON response.", status_code=200),
    lambda: QueryError("Portal hunting rejected the query or its request parameters."),
])
def test_truncation_like_upstream_errors_halve_instead_of_failing(tmp_path, make_error):
    service, sink = FakeHunting({"DeviceProcessEvents": events(50)}), MemorySink()

    def fail(query):
        if "top 25001 " in query:
            raise make_error()

    service.fail = fail
    report = run(service, sink, tmp_path)
    assert summary(report)["DeviceProcessEvents"]["status"] == "complete"
    assert sink.capture("DeviceProcessEvents").proof.row_cap == 12500


def test_upstream_conflict_stops_instead_of_aborting_the_job(tmp_path):
    service = FakeHunting({"DeviceProcessEvents": events(5)})

    def fail(query):
        raise ConflictError("Upstream state conflict.")

    service.fail = fail
    report = run(service, MemorySink(), tmp_path)
    assert report.status == "paused" and report.stop.kind == "upstream"


def test_protocol_glitch_after_other_attempts_retries_and_reopens_on_resume(tmp_path):
    data = {"DeviceProcessEvents": events(50)}
    state = {"n": 0}

    class Glitchy(FakeHunting):
        async def execute_hunting(self, query):
            result = await super().execute_hunting(query)
            state["n"] += 1
            if state["n"] in (2, 3):  # after a resource timeout, two duplicated controls
                result.results.insert(0, dict(result.results[0]))
            return result

    service, sink = Glitchy(data), MemorySink()

    def fail(query):
        if state["n"] == 0:
            state["n"] += 1
            raise TimeoutError("timed out")

    service.fail = fail
    first = run(service, sink, tmp_path)
    assert summary(first)["DeviceProcessEvents"]["status"] == "failed"
    service.fail = None
    again = run(service, sink, tmp_path)
    assert summary(again)["DeviceProcessEvents"]["status"] == "complete"


def test_ledger_interval_and_kinds_are_bound_to_the_plan(tmp_path):
    schema, data = tables_of(3, rows=5)
    service, sink = FakeHunting(data), MemorySink()
    first = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=1))
    path = ledger_path(tmp_path)
    for damage in ("interval", "future", "kind"):
        saved = json.loads(path.read_text())
        if damage == "interval":
            saved["interval"]["start"] = "2026-10-24T03:59:00Z"
        elif damage == "future":
            saved["created_at"] = "2099-01-01T00:00:00Z"
        else:
            saved["tables"]["T1"]["kind"] = "snapshot-timed"
        path.write_text(json.dumps(saved))
        with pytest.raises(ArtifactError):
            live_capture_references(tmp_path)
    later = run(service, sink, tmp_path, schema=schema, budgets=CaptureBudgets(max_queries=1))
    assert later.job_id != first.job_id


def test_consume_only_releases_pins_that_were_actually_indexed(tmp_path):
    schema, data = tables_of(2, rows=3)
    service, sink = FakeHunting(data), MemorySink()
    report = run(service, sink, tmp_path, schema=schema)
    ids = set(report.captured_run_ids)
    assert not mark_capture_consumed(tmp_path, report.job_id, indexed_run_ids=ids - {min(ids)})
    assert live_capture_run_ids(tmp_path) == ids
    assert mark_capture_consumed(tmp_path, report.job_id, indexed_run_ids=ids)
    assert live_capture_run_ids(tmp_path) == set()


def test_overlong_table_names_are_excluded_by_the_plan():
    name = "T" + "x" * 130
    plan = plan_capture(schema_rows({name: {"Timestamp": "datetime"}}), now=NOW)
    assert not plan.tables and plan.exclusions[0]["reason"] == "unsafe-table-name"


def test_consume_accepts_verified_retired_sources_but_not_unknown_new_ones(tmp_path):
    schema, data = tables_of(3, rows=3)
    service, sink = FakeHunting(data), MemorySink()
    report = run(service, sink, tmp_path, schema=schema)
    ids = sorted(report.captured_run_ids)
    indexed, retired, unknown = {ids[0]}, {ids[1]}, ids[2]
    assert not mark_capture_consumed(tmp_path, report.job_id, indexed_run_ids=indexed,
                                     retired_run_ids=retired)  # ids[2] neither
    assert unknown in live_capture_run_ids(tmp_path)
    assert mark_capture_consumed(tmp_path, report.job_id, indexed_run_ids=indexed,
                                 retired_run_ids=retired | {unknown})
    assert live_capture_run_ids(tmp_path) == set()
