"""Verified physical origins for privately captured source rows.

Capture queries wrap rows in a transport protocol, so the ordinary KQL lineage
parser cannot establish their origins. This adapter accepts only the exact
versioned capture compiler contract and a consistent same-query completeness
proof. It never infers origins from a free-form table label.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

from xdr_cli.schema_graph.capture_contract import CAPTURE_COMMAND, CONTRACT_VERSION
from xdr_cli.schema_graph.lineage import FieldOrigins, recover_field_origins

SOURCE_COMMANDS = frozenset({"hunt run", "library run", CAPTURE_COMMAND})
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9-]{1,128}\Z")


def source_origins(meta: dict) -> FieldOrigins:
    """Establish physical lineage, including independently checked capture proofs."""
    if meta.get("command") == CAPTURE_COMMAND:
        return capture_origins(meta)
    if meta.get("command") not in SOURCE_COMMANDS:
        raise ValueError("invalid-source-command")
    return recover_field_origins(meta["query"])


def capture_origins(meta: dict) -> FieldOrigins:
    spec = meta.get("schema_capture")
    if not isinstance(spec, dict) or spec.get("contract_version") != CONTRACT_VERSION:
        raise ValueError("invalid-capture-contract")
    args = spec.get("query_args")
    version = args.get("compiler_version") if isinstance(args, dict) else None
    if version == "capture-query/v1":
        from xdr_cli.schema_graph.capture_legacy import verify_capture_query

        proof_mode = "materialized-control/v1"
    elif version == "capture-query/v2":
        from xdr_cli.schema_graph.capture_query import verify_capture_query

        proof_mode = "materialized-control/v2"
    else:
        raise ValueError("invalid-capture-compiler-version")

    query = meta.get("query")
    if not isinstance(query, str) or not verify_capture_query(spec.get("query_args", {}), query):
        raise ValueError("invalid-capture-query")
    digest = hashlib.sha256(query.encode()).hexdigest()
    if spec.get("query_sha256") != digest or meta.get("query_sha256") != digest:
        raise ValueError("invalid-capture-query-digest")
    table = spec.get("table")
    args = spec.get("query_args")
    slice_args = args.get("slice") if isinstance(args, dict) else None
    if not isinstance(slice_args, dict) or slice_args.get("table") != table:
        raise ValueError("invalid-capture-table")
    if not isinstance(table, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", table):
        raise ValueError("invalid-capture-table")
    if meta.get("physical_lineage") != {"kind": "physical", "table": table}:
        raise ValueError("invalid-capture-physical-origin")
    for name in ("job_id", "window_id"):
        if not isinstance(spec.get(name), str) or not _ID.fullmatch(spec[name]):
            raise ValueError("invalid-capture-coordinate")
    if not isinstance(spec.get("schema_digest"), str) or not _HEX.fullmatch(spec["schema_digest"]):
        raise ValueError("invalid-capture-schema-binding")
    if not isinstance(spec.get("backend"), str) or not spec["backend"]:
        raise ValueError("invalid-capture-backend")
    if not isinstance(spec.get("execution_surface"), str) or not spec["execution_surface"]:
        raise ValueError("invalid-capture-surface")
    collected = datetime.fromisoformat(spec["collected_at"].replace("Z", "+00:00"))
    if collected.tzinfo is None or collected > datetime.now(UTC):
        raise ValueError("invalid-capture-time")
    count, payload = spec.get("source_count"), spec.get("payload_count")
    cap = args.get("row_cap")
    if (
        type(count) is not int
        or type(payload) is not int
        or type(cap) is not int
        or not 0 <= count == payload <= cap
        or meta.get("row_count") != payload
        or spec.get("completeness") != "complete"
        or meta.get("server_truncation_state") != "known-complete"
    ):
        raise ValueError("invalid-capture-completeness-proof")
    for key in ("time_column", "start", "end", "partition"):
        if key not in spec or spec[key] != slice_args.get(key):
            raise ValueError("invalid-capture-slice-coordinate")
    if spec.get("stage") != "capture" or spec.get("kind") not in {
        "state" if slice_args.get("time_column") is None else "event",
        "state" if slice_args.get("time_column") is None else "snapshot-timed",
    }:
        raise ValueError("invalid-capture-stage-kind")
    proof = spec.get("proof")
    if (
        not isinstance(proof, dict)
        or proof.get("mode") != proof_mode
        or any(
            proof.get(key) != value
            for key, value in (
                ("row_cap", cap),
                ("source_count", count),
                ("payload_count", payload),
            )
        )
        or type(proof.get("source_bytes_estimate")) is not int
        or proof["source_bytes_estimate"] < 0
    ):
        raise ValueError("invalid-capture-proof-binding")
    if version == "capture-query/v2":
        verify_selected_coverage(spec.get("coverage"), args, count)
    # Query recompilation proves these are complete, unprojected source rows.
    return FieldOrigins(table, {}, passthrough=True)


def verify_selected_coverage(coverage, query_args, count):
    """Check source-scope labels independently of complete packet transport."""
    from xdr_cli.schema_graph.capture_plan import parse_instant

    args = query_args["slice"]
    mode = query_args["mode"]
    if not isinstance(coverage, dict) or coverage.get("mode") != mode:
        raise ValueError("invalid-capture-coverage")
    if (
        type(coverage.get("truncated")) is not bool
        or type(coverage.get("span_complete")) is not bool
    ):
        raise ValueError("invalid-capture-coverage")
    total = coverage.get("source_total")
    if total is not None and (type(total) is not int or total < 0):
        raise ValueError("invalid-capture-coverage-total")
    if mode == "sample":
        if (
            coverage.get("start") is not None
            or coverage.get("end") is not None
            or coverage.get("floor") is not None
            or coverage["span_complete"] != (not coverage["truncated"])
            or (coverage["truncated"] and count != query_args["row_cap"])
        ):
            raise ValueError("invalid-sample-coverage")
        return
    if (
        (coverage["truncated"] and count != query_args["row_cap"])
        or mode != "recent"
        or coverage.get("end") != args["end"]
        or coverage["span_complete"] != (not coverage["truncated"])
    ):
        raise ValueError("invalid-recent-coverage")
    floor = coverage.get("floor")
    if coverage["truncated"]:
        if (
            floor is None
            or coverage.get("start") != floor
            or not parse_instant(args["start"]) <= parse_instant(floor) < parse_instant(args["end"])
        ):
            raise ValueError("invalid-recent-coverage")
    elif floor is not None or coverage.get("start") != args["start"]:
        raise ValueError("invalid-recent-coverage")


class ResultCaptureSink:
    """Persist source rows privately; engine locks artifact plus ledger publication."""

    def __init__(self, *, tenant_id: str | None = None, tenant_fingerprint=None, app_ctx=None):
        self.tenant_id = tenant_id
        actual = hashlib.sha256(tenant_id.strip().encode()).hexdigest() if tenant_id else None
        if actual and tenant_fingerprint and actual != tenant_fingerprint:
            raise ValueError("different-capture-tenant")
        self.tenant_fingerprint = actual or tenant_fingerprint
        if not isinstance(self.tenant_fingerprint, str) or not _HEX.fullmatch(
            self.tenant_fingerprint
        ):
            raise ValueError("invalid-capture-tenant")
        self.app_ctx = app_ctx

    def write_slice(self, capture, rows):
        from xdr_cli.results import write_result
        from xdr_cli.schema_graph.capture_contract import COMPLETENESS_CAVEAT, SliceArtifact

        if not self.tenant_id:
            raise ValueError("capture-write-needs-tenant")
        proof = capture.proof
        if (
            proof.mode
            != "materialized-control/" + capture.query_args["compiler_version"].rsplit("/", 1)[-1]
            or proof.payload_count != len(rows)
            or proof.source_count != len(rows)
            or len(rows) > proof.row_cap
        ):
            raise ValueError("invalid-capture-completeness-proof")
        if capture.binding.get("tenant_fingerprint") != self.tenant_fingerprint:
            raise ValueError("different-capture-tenant")
        spec = {
            "contract_version": CONTRACT_VERSION,
            "stage": "capture",
            "job_id": capture.job_id,
            "window_id": capture.window_id,
            "table": capture.spec.table,
            "kind": capture.kind,
            "query_args": capture.query_args,
            "query_sha256": capture.query_sha256,
            "time_column": capture.spec.time_column,
            "start": capture.spec.to_dict()["start"],
            "end": capture.spec.to_dict()["end"],
            "partition": capture.spec.to_dict().get("partition"),
            "schema_digest": capture.binding["schema_digest"],
            "backend": capture.binding["backend"],
            "execution_surface": capture.binding["execution_surface"],
            "binding": capture.binding,
            "interval": capture.interval,
            "completeness": "complete",
            "completeness_caveat": COMPLETENESS_CAVEAT,
            "source_count": proof.source_count,
            "payload_count": proof.payload_count,
            "proof": proof.to_dict(),
            "coverage": capture.coverage,
            "collected_at": capture.collected_at,
        }
        # Reject inconsistent provenance before publishing any usable artifact.
        capture_origins(
            {
                "schema_capture": spec,
                "query": capture.query,
                "query_sha256": capture.query_sha256,
                "row_count": len(rows),
                "server_truncation_state": "known-complete",
                "physical_lineage": {"kind": "physical", "table": capture.spec.table},
            }
        )
        session = {}
        if self.app_ctx is not None:
            session = {
                "session_id": self.app_ctx.session_id,
                "session_label": self.app_ctx.session_label,
                "session_attachment": self.app_ctx.session_attachment,
                "incident_id": self.app_ctx.anchor_incident,
                "alert_id": self.app_ctx.anchor_alert,
                "anchor_provenance": self.app_ctx.anchor_provenance,
            }
        artifact = write_result(
            rows,
            command=CAPTURE_COMMAND,
            query=capture.query,
            execution_time_ms=capture.execution_time_ms,
            server_truncation_state="known-complete",
            tenant_id=self.tenant_id,
            physical_lineage_table=capture.spec.table,
            preview_rows=0,
            extra_metadata={"schema_capture": spec},
            **session,
        )
        return SliceArtifact(
            run_id=artifact.receipt.run_id,
            data_sha256=artifact.metadata["data_sha256"],
            rows=artifact.metadata["row_count"],
            bytes=Path(artifact.receipt.data_path).stat().st_size,
        )

    def _read(self, path, job_id, window_id, *, expected=None):
        from xdr_cli.config import get_config_home
        from xdr_cli.schema_graph.capture_contract import SliceArtifact
        from xdr_cli.schema_graph.local_discovery import artifact_metadata

        root = get_config_home() / "results"
        meta, data = artifact_metadata(
            path, root, self.tenant_fingerprint, respect_retirement=False
        )
        if meta.get("command") != CAPTURE_COMMAND:
            raise ValueError("invalid-capture-command")
        capture_origins(meta)
        spec = meta["schema_capture"]
        if spec["job_id"] != job_id or spec["window_id"] != window_id:
            raise ValueError("different-capture-coordinate")
        if expected is not None and (
            not isinstance(expected, dict)
            or set(expected) != {"coverage", "query_args", "binding", "interval", "kind"}
            or any(spec.get(key) != value for key, value in expected.items())
        ):
            raise ValueError("capture-ledger-artifact-contract-mismatch")
        import json

        digest, rows, size = hashlib.sha256(), 0, 0
        with data.open("rb") as stream:
            for line in stream:
                digest.update(line)
                size += len(line)
                if line.strip():
                    if not isinstance(json.loads(line), dict):
                        raise ValueError("invalid-capture-row")
                    rows += 1
        if digest.hexdigest() != meta["data_sha256"] or rows != meta["row_count"]:
            raise ValueError("invalid-capture-bytes")
        return SliceArtifact(meta["run_id"], digest.hexdigest(), rows, size)

    def find_slice(self, job_id, window_id):
        from xdr_cli.config import get_config_home

        for path in sorted((get_config_home() / "results").glob("*/*.meta.json"), reverse=True):
            try:
                return self._read(path, job_id, window_id)
            except (ValueError, OSError, KeyError, TypeError, RecursionError):
                continue
        return None

    def verify(self, job_id, window_id, artifact, *, expected=None):
        from xdr_cli.config import get_config_home

        if not isinstance(artifact.run_id, str) or not _ID.fullmatch(artifact.run_id):
            return False
        paths = list((get_config_home() / "results").glob(f"*/{artifact.run_id}.meta.json"))
        if len(paths) != 1:
            return False
        try:
            return self._read(paths[0], job_id, window_id, expected=expected) == artifact
        except (ValueError, OSError, KeyError, TypeError, RecursionError):
            return False
