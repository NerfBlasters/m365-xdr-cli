"""Engine/sink contract for capture-first exploration (no I/O, no engine imports).

The engine decides what to fetch and proves completeness with the same-query
control packet. A sink persists one verified or unverified slice as a private
result bundle and reports what it stored. Ledgers are value-free: they hold
IDs, bounds, counts and hashes, never captured identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from xdr_cli.schema_graph.capture_query import SliceSpec

CONTRACT_VERSION = "schema-capture/v1"
CAPTURE_COMMAND = "schema collect capture"
CAPTURE_STAGE = "capture"

# Slice completeness values written to artifact metadata and the ledger.
COMPLETE = "complete"  # control packet present, count <= row cap, payloads == count
BINDING_KEYS = ("tenant_fingerprint", "backend", "schema_digest", "horizon_seconds")
COMPLETENESS_CAVEAT = (
    "every selected row arrived (same-query control count); a table covers the whole "
    "interval only when span_complete is true, otherwise it is a capped recent sample "
    "(timed) or inventory sample (untimed); later ingestion, updates or deletions are "
    "not reflected"
)


@dataclass(frozen=True)
class CaptureProof:
    """Same-evaluation evidence from one wrapped fetch."""

    mode: str  # "materialized-control/v2"
    row_cap: int
    source_count: int
    payload_count: int
    source_bytes_estimate: int

    def to_dict(self) -> dict:
        return {
            "mode": self.mode, "row_cap": self.row_cap,
            "source_count": self.source_count, "payload_count": self.payload_count,
            "source_bytes_estimate": self.source_bytes_estimate,
        }


@dataclass(frozen=True)
class CaptureSlice:
    """Everything a sink needs to write and bind one slice artifact."""

    job_id: str
    window_id: str  # deterministic slice key
    kind: str  # event | snapshot-timed | state
    spec: SliceSpec
    query: str
    query_sha256: str
    query_args: dict  # capture_query.fetch_query_args(...); recompiles to ``query``
    binding: dict  # BINDING_KEYS plus compiler_version and observed execution_surface
    interval: dict  # {"start", "end"} of the whole job, ISO instants
    profiled_rows: int | None
    proof: CaptureProof
    collected_at: str
    execution_time_ms: int
    # {"mode": "recent"|"sample", "start", "end", "span_complete", "truncated",
    #  "floor", "source_total"}: what the stored rows cover. span_complete is true only
    #  when the cap was not reached; otherwise the rows are a recent (or inventory) sample.
    coverage: dict | None = None


@dataclass(frozen=True)
class SliceArtifact:
    run_id: str
    data_sha256: str
    rows: int
    bytes: int

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id, "data_sha256": self.data_sha256,
            "rows": self.rows, "bytes": self.bytes,
        }

    @classmethod
    def from_dict(cls, value: dict) -> SliceArtifact:
        return cls(
            run_id=str(value["run_id"]), data_sha256=str(value["data_sha256"]),
            rows=int(value["rows"]), bytes=int(value["bytes"]),
        )


class CaptureSink(Protocol):
    def write_slice(self, capture: CaptureSlice, rows: list[dict]) -> SliceArtifact:
        """Durably write exactly ``rows`` (unwrapped originals) for a complete slice."""

    def find_slice(self, job_id: str, window_id: str) -> SliceArtifact | None:
        """Return a verified artifact already written for this slice, if any."""

    def verify(self, job_id: str, window_id: str, artifact: SliceArtifact, *,
               expected: dict | None = None) -> bool:
        """Re-verify a ledger-referenced artifact before reusing it on resume.

        ``expected`` = {coverage, query_args, binding, interval, kind} that the
        artifact's immutable metadata must match exactly (None for legacy v1).
        """
