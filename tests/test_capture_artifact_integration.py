"""Capture data cannot acquire physical lineage merely by claiming a table."""

from copy import deepcopy

import pytest

from xdr_cli.schema_graph.capture_artifacts import source_origins


def test_unknown_command_does_not_acquire_hunting_lineage():
    with pytest.raises(ValueError, match="invalid-source-command"):
        source_origins({"command": "custom capture", "query": "DeviceInfo"})


def test_hunt_lineage_still_uses_the_bounded_parser():
    origins = source_origins({"command": "hunt run", "query": "DeviceInfo | project Id=DeviceId"})
    assert str(origins.origin("Id")) == "DeviceInfo.DeviceId"
    assert origins.origin("Invented") is None


def test_capture_identity_alone_is_not_lineage():
    # Do not lazy-import the engine's compiler until the stage contract exists.
    with pytest.raises(ValueError, match="invalid-capture-contract"):
        source_origins({"command": "schema collect capture", "query": "DeviceInfo"})


@pytest.mark.parametrize("count", [True, -1, "3", 2])
def test_inconsistent_proof_never_becomes_physical_origin(monkeypatch, count):
    import hashlib
    import sys
    from datetime import UTC, datetime
    from types import SimpleNamespace

    # Isolate the adapter's proof checks; compiler itself has separate query tests.
    monkeypatch.setitem(
        sys.modules,
        "xdr_cli.schema_graph.capture_query",
        SimpleNamespace(
            verify_capture_query=lambda spec, query: True,
        ),
    )
    digest = hashlib.sha256(b"wrapped").hexdigest()
    meta = {
        "command": "schema collect capture",
        "query": "wrapped",
        "query_sha256": digest,
        "row_count": 3,
        "server_truncation_state": "known-complete",
        "physical_lineage": {"kind": "physical", "table": "DeviceInfo"},
        "schema_capture": {
            "contract_version": "schema-capture/v1",
            "query_args": {
                "compiler_version": "capture-query/v2",
                "slice": {"table": "DeviceInfo"},
                "row_cap": 100,
            },
            "query_sha256": digest,
            "table": "DeviceInfo",
            "job_id": "job",
            "window_id": "slice",
            "schema_digest": "a" * 64,
            "backend": "official",
            "execution_surface": "graph",
            "collected_at": datetime.now(UTC).isoformat(),
            "source_count": count,
            "payload_count": 3,
            "completeness": "complete",
        },
    }
    with pytest.raises(ValueError, match="invalid-capture-completeness-proof"):
        source_origins(deepcopy(meta))


def capture_metadata():
    import hashlib
    from datetime import UTC, datetime

    from xdr_cli.schema_graph.capture_legacy import (
        SliceSpec,
        compile_fetch_query,
        fetch_query_args,
    )

    spec = SliceSpec(
        "DeviceInfo",
        "Timestamp",
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )
    query = compile_fetch_query(spec, 100)
    digest = hashlib.sha256(query.encode()).hexdigest()
    return {
        "command": "schema collect capture",
        "query": query,
        "query_sha256": digest,
        "row_count": 3,
        "server_truncation_state": "known-complete",
        "physical_lineage": {"kind": "physical", "table": "DeviceInfo"},
        "schema_capture": {
            "contract_version": "schema-capture/v1",
            "stage": "capture",
            "kind": "snapshot-timed",
            **{key: spec.to_dict()[key] for key in ("time_column", "start", "end", "partition")},
            "query_args": fetch_query_args(spec, 100),
            "query_sha256": digest,
            "table": "DeviceInfo",
            "job_id": "job",
            "window_id": "slice",
            "schema_digest": "a" * 64,
            "backend": "official",
            "execution_surface": "graph",
            "collected_at": datetime.now(UTC).isoformat(),
            "source_count": 3,
            "payload_count": 3,
            "completeness": "complete",
            "proof": {
                "mode": "materialized-control/v1",
                "row_cap": 100,
                "source_count": 3,
                "payload_count": 3,
                "source_bytes_estimate": 42,
            },
        },
    }


def test_actual_capture_compiler_recovers_original_columns():
    meta = capture_metadata()
    origins = source_origins(meta)
    assert str(origins.origin("DeviceId")) == "DeviceInfo.DeviceId"
    assert str(origins.origin("AdditionalFields")) == "DeviceInfo.AdditionalFields"


@pytest.mark.parametrize("change", ["query", "table", "cap", "count", "status", "physical"])
def test_actual_capture_provenance_rejects_inconsistent_claims(change):
    meta = capture_metadata()
    if change == "query":
        meta["query"] += " | project DeviceId"
    elif change == "table":
        meta["schema_capture"]["table"] = "OtherTable"
    elif change == "cap":
        meta["schema_capture"]["query_args"]["row_cap"] = 2
    elif change == "count":
        meta["row_count"] = 4
    elif change == "status":
        meta["server_truncation_state"] = "unknown"
    else:
        meta["physical_lineage"]["table"] = "OtherTable"
    with pytest.raises(ValueError):
        source_origins(meta)


def test_capture_rows_feed_incremental_local_graph_and_reject_tampering(tmp_path, monkeypatch):
    import json
    from pathlib import Path

    from xdr_cli.results import write_result
    from xdr_cli.schema_graph.local_discovery import discover_local, pair_values

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    tenant = "synthetic-capture-tenant"
    meta = capture_metadata()
    captured = write_result(
        [
            {"DeviceId": value}
            for value in ("a1b2c3d4e5f60718", "a1b2c3d4e5f60719", "a1b2c3d4e5f60720")
        ],
        command="schema collect capture",
        query=meta["query"],
        tenant_id=tenant,
        physical_lineage_table="DeviceInfo",
        server_truncation_state="known-complete",
        extra_metadata={"schema_capture": meta["schema_capture"]},
        preview_rows=0,
    )
    write_result(
        [{"DeviceId": "a1b2c3d4e5f60718"}],
        command="hunt run",
        query="DeviceEvents | project DeviceId",
        tenant_id=tenant,
    )
    pairs, coverage = discover_local(tmp_path / "results", tmp_path / "index", tenant)
    assert coverage["processed_artifacts"] == 2
    assert len(pairs) == 1
    assert {pairs[0].source, pairs[0].target} == {"DeviceInfo.DeviceId", "DeviceEvents.DeviceId"}
    assert pair_values(pairs[0], tmp_path / "results", tenant) == ["a1b2c3d4e5f60718"]
    sidecar = Path(captured.receipt.meta_path)
    changed = json.loads(sidecar.read_text())
    changed["schema_capture"]["table"] = "SpoofedTable"
    sidecar.write_text(json.dumps(changed))
    pairs, _ = discover_local(tmp_path / "results", tmp_path / "index", tenant)
    assert pairs == []


def test_sink_persists_full_rows_and_verifies_resume_coordinates(tmp_path, monkeypatch):
    import hashlib
    from datetime import UTC, datetime

    from xdr_cli.schema_graph.capture_artifacts import ResultCaptureSink
    from xdr_cli.schema_graph.capture_contract import CaptureProof, CaptureSlice
    from xdr_cli.schema_graph.capture_query import SliceSpec, compile_fetch_query, fetch_query_args

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    tenant = "synthetic-capture"
    spec = SliceSpec(
        "DeviceInfo",
        "Timestamp",
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )
    query = compile_fetch_query(spec, 100)
    capture = CaptureSlice(
        job_id="cap-job",
        window_id="w-window",
        kind="snapshot-timed",
        spec=spec,
        query=query,
        query_sha256=hashlib.sha256(query.encode()).hexdigest(),
        query_args=fetch_query_args(spec, 100),
        binding={
            "tenant_fingerprint": hashlib.sha256(tenant.encode()).hexdigest(),
            "backend": "official",
            "execution_surface": "graph",
            "schema_digest": "a" * 64,
        },
        interval={"start": spec.to_dict()["start"], "end": spec.to_dict()["end"]},
        profiled_rows=1,
        proof=CaptureProof("materialized-control/v2", 100, 1, 1, 42),
        coverage={
            "mode": "recent",
            "start": spec.to_dict()["start"],
            "end": spec.to_dict()["end"],
            "span_complete": True,
            "truncated": False,
            "floor": None,
            "source_total": 1,
        },
        collected_at=datetime.now(UTC).isoformat(),
        execution_time_ms=10,
    )
    sink = ResultCaptureSink(tenant_id=tenant)
    artifact = sink.write_slice(
        capture, [{"DeviceId": "abcdef0123456789", "Nested": {"Full": True}}]
    )
    assert artifact.rows == 1
    assert sink.verify("cap-job", "w-window", artifact)
    assert not sink.verify("cap-job", "different-window", artifact)
    assert sink.find_slice("cap-job", "w-window") == artifact
    assert ResultCaptureSink(tenant_id="other").find_slice("cap-job", "w-window") is None


def test_finished_index_scan_cannot_claim_missing_required_source_was_indexed(tmp_path):
    from xdr_cli.schema_graph.local_discovery import discover_local

    _, coverage = discover_local(
        tmp_path / "results", tmp_path / "index", "synthetic", required_runs=("missing-capture",)
    )
    assert coverage["complete"] is True
    assert coverage["required_sources_complete"] is False
    assert coverage["unindexed_required_sources"] == 1


def v2_capture_metadata(mode="recent", truncated=False, at_cap=False):
    from datetime import UTC, datetime

    from xdr_cli.schema_graph.capture_query import SliceSpec, compile_fetch_query, fetch_query_args

    meta = capture_metadata()
    spec = SliceSpec(
        "DeviceInfo",
        "Timestamp" if mode == "recent" else None,
        datetime(2026, 1, 1, tzinfo=UTC) if mode == "recent" else None,
        datetime(2026, 1, 2, tzinfo=UTC) if mode == "recent" else None,
    )
    cap = 3 if truncated or at_cap else 5
    query = compile_fetch_query(spec, cap)
    import hashlib

    digest = hashlib.sha256(query.encode()).hexdigest()
    meta.update(query=query, query_sha256=digest)
    stage = meta["schema_capture"]
    stage.update(
        query_args=fetch_query_args(spec, cap),
        query_sha256=digest,
        time_column=spec.time_column,
        start=spec.to_dict()["start"],
        end=spec.to_dict()["end"],
        partition=None,
        kind="state" if mode == "sample" else "snapshot-timed",
        proof={
            "mode": "materialized-control/v2",
            "row_cap": cap,
            "source_count": 3,
            "payload_count": 3,
            "source_bytes_estimate": 42,
        },
    )
    floor = "2026-01-01T12:00:00Z" if truncated and mode == "recent" else None
    stage["coverage"] = {
        "mode": mode,
        "start": floor or spec.to_dict()["start"],
        "end": spec.to_dict()["end"],
        "span_complete": not truncated,
        "truncated": truncated,
        "floor": floor,
        # This is separate count telemetry, never the truncation/completeness proof.
        "source_total": 100,
    }
    return meta


@pytest.mark.parametrize(
    "mode,truncated,at_cap",
    [
        ("recent", False, False),
        ("recent", True, True),
        ("sample", True, True),
        ("sample", False, True),
    ],
)
def test_v2_sources_keep_explicit_sampling_labels_without_losing_lineage(mode, truncated, at_cap):
    meta = v2_capture_metadata(mode, truncated, at_cap)
    assert str(source_origins(meta).origin("DeviceId")) == "DeviceInfo.DeviceId"
    assert meta["schema_capture"]["coverage"]["span_complete"] is not truncated


@pytest.mark.parametrize("mutation", ["mode", "floor", "span", "count"])
def test_v2_coverage_drift_cannot_masquerade_as_a_complete_window(mutation):
    meta = v2_capture_metadata("recent", truncated=True)
    coverage = meta["schema_capture"]["coverage"]
    if mutation == "mode":
        coverage["mode"] = "sample"
    elif mutation == "floor":
        coverage["start"] = coverage["floor"] = "2025-01-01T00:00:00Z"
    elif mutation == "span":
        coverage["span_complete"] = True
    else:
        # A CAP+1 sentinel and clipped output must keep exactly CAP rows.
        meta["schema_capture"]["query_args"]["row_cap"] = 4
    with pytest.raises(ValueError):
        source_origins(meta)
