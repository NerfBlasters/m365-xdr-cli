"""Browse and explicitly prune local result artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer

from xdr_cli.config import get_config_home
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    ArtifactError,
    ConflictError,
    LocalNotFoundError,
    UsageError,
)
from xdr_cli.output import err_console
from xdr_cli.schema_graph.overlay import (
    load_tenant_overlay_from_root,
    local_overlay_roots,
    schema_evidence_lock,
)

results_app = typer.Typer(
    name="results",
    help="Browse locally saved investigation result artifacts.",
    no_args_is_help=True,
)
_TABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_ARTIFACT_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_STABLE_SCHEMA_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:/#~%*-]{0,1023}")
_MAX_PROPOSAL_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class _EvidenceReferences:
    overlay_run_ids: frozenset[str]
    proposal_run_ids: frozenset[str]
    proposal_paths: tuple[str, ...]
    legacy_proposal_paths: tuple[str, ...]

    @property
    def all_run_ids(self) -> frozenset[str]:
        return self.overlay_run_ids | self.proposal_run_ids


def _results_root() -> Path:
    return get_config_home() / "results"


def _emit(value: Any) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str))


def _metadata_paths() -> list[Path]:
    root = _results_root()
    if not root.exists():
        return []
    return sorted(root.glob("*/*.meta.json"), reverse=True)


def _proposal_integrity_error(message: str, run_id: str | None = None) -> ArtifactError:
    help_command = f"xdr results show {run_id}" if run_id else "xdr results list"
    error = ArtifactError(
        "Cannot safely prune results because an extant candidate proposal is "
        f"not receipt-bound: {message}. Restore the exact proposal, sidecar, and "
        "referenced evidence bundles, or delete the abandoned proposal draft "
        "before retrying pruning.",
        help_command=help_command,
        suggestions=[
            {
                "reason": "inspect_proposal_binding",
                "message": help_command,
                "confidence": "exact",
            }
        ],
    )
    error.error_code = "SCHEMA_PROPOSAL_INTEGRITY_FAILED"
    return error


def _sorted_stable_ids(value: Any, *, pattern: re.Pattern[str]) -> list[str] | None:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value)
        or value != sorted(set(value))
    ):
        return None
    return value


def _verify_candidate_proposal_evidence_bundles(
    proposal_metadata: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    proposal_run_id: str | None,
) -> None:
    """Verify every proposal evidence bundle, its tenant, stage, and binding."""

    proposal_tenant = proposal_metadata.get("tenant_binding")
    expected_tenant = (
        proposal_tenant.get("sha256") if isinstance(proposal_tenant, dict) else None
    )
    if not isinstance(expected_tenant, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_tenant
    ):
        raise _proposal_integrity_error(
            "proposal result is not bound to one tenant", proposal_run_id
        )

    observation_ids = set(snapshot["validated_observation_ids"])
    source_ids = set(snapshot["source_artifact_run_ids"])
    target_ids = set(snapshot["target_artifact_run_ids"])
    review_ids = set(snapshot["review_artifact_run_ids"])
    if not observation_ids or not source_ids or not target_ids or not review_ids:
        raise _proposal_integrity_error(
            "evidence snapshot omits required observation or artifact IDs",
            proposal_run_id,
        )

    verified: dict[str, tuple[dict[str, Any], list[dict[str, Any]], int]] = {}
    for evidence_run_id in sorted(source_ids | target_ids | review_ids):
        matches = [
            path
            for path in _metadata_paths()
            if path.name == f"{evidence_run_id}.meta.json"
        ]
        if len(matches) != 1:
            raise _proposal_integrity_error(
                f"referenced evidence {evidence_run_id} is missing or ambiguous",
                evidence_run_id,
            )
        try:
            bundle = _verified_result_rows(matches[0])
        except ArtifactError as exc:
            raise _proposal_integrity_error(
                f"referenced evidence {evidence_run_id} failed integrity validation",
                evidence_run_id,
            ) from exc
        binding = bundle[0].get("tenant_binding")
        if not isinstance(binding, dict) or binding.get("sha256") != expected_tenant:
            raise _proposal_integrity_error(
                f"referenced evidence {evidence_run_id} has the wrong tenant binding",
                evidence_run_id,
            )
        if bundle[2] < 1:
            raise _proposal_integrity_error(
                f"referenced evidence {evidence_run_id} is empty", evidence_run_id
            )
        verified[evidence_run_id] = bundle

    for source_id in source_ids:
        source_meta = verified[source_id][0]
        if source_meta.get("probe_stage") not in {"source-sample", "source-explicit"}:
            raise _proposal_integrity_error(
                f"referenced source evidence {source_id} has the wrong probe stage",
                source_id,
            )
    for target_id in target_ids:
        target_meta = verified[target_id][0]
        if (
            target_meta.get("probe_stage") != "target-batch"
            or target_meta.get("source_artifact_run_id") not in source_ids
        ):
            raise _proposal_integrity_error(
                f"referenced target evidence {target_id} is not bound to a source bundle",
                target_id,
            )
    expected_relationship = proposal_metadata["candidate_proposal"][
        "source_candidate_relationship_id"
    ]
    for review_id in review_ids:
        review = verified[review_id][0].get("candidate_review")
        if (
            not isinstance(review, dict)
            or review.get("relationship_id") != expected_relationship
            or review.get("observation_id") not in observation_ids
            or review.get("source_artifact_run_id") not in source_ids
        ):
            raise _proposal_integrity_error(
                f"referenced review evidence {review_id} has the wrong candidate binding",
                review_id,
            )


def _verified_candidate_proposal_references(
    meta_path: Path, metadata: dict[str, Any]
) -> tuple[set[str], str, bool] | None:
    """Verify a live proposal, its evidence snapshot, and binding result bundle."""

    proposal = metadata.get("candidate_proposal")
    if proposal is None:
        return None
    run_id = metadata.get("run_id") if isinstance(metadata.get("run_id"), str) else None
    current_shape = {
        "proposal_path",
        "source_candidate_relationship_id",
        "proposed_relationship_id",
        "proposal_sha256",
        "proposal_bytes",
        "evidence_snapshot",
        "binding_sha256",
    }
    legacy_shape = {
        "proposal_path",
        "source_candidate_relationship_id",
        "proposed_relationship_id",
        "evidence_snapshot",
    }
    proposal_keys = frozenset(proposal) if isinstance(proposal, dict) else frozenset()
    if not isinstance(proposal, dict) or proposal_keys not in {
        frozenset(current_shape),
        frozenset(legacy_shape),
    }:
        raise _proposal_integrity_error("binding metadata has an invalid shape", run_id)
    is_legacy = proposal_keys == frozenset(legacy_shape)
    proposal_path_value = proposal.get("proposal_path")
    if not isinstance(proposal_path_value, str) or not proposal_path_value:
        raise _proposal_integrity_error("proposal path is invalid", run_id)
    proposal_path = Path(proposal_path_value)
    if not proposal_path.is_absolute():
        raise _proposal_integrity_error("proposal path is not absolute", run_id)
    if is_legacy and not proposal_path.exists():
        return None
    if any(
        not isinstance(proposal.get(key), str)
        or not _STABLE_SCHEMA_ID.fullmatch(proposal[key])
        for key in (
            "source_candidate_relationship_id",
            "proposed_relationship_id",
        )
    ):
        raise _proposal_integrity_error("relationship IDs are invalid", run_id)
    if not is_legacy:
        binding_sha256 = proposal.get("binding_sha256")
        unsigned_binding = {
            key: value for key, value in proposal.items() if key != "binding_sha256"
        }
        expected_binding = hashlib.sha256(
            json.dumps(unsigned_binding, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        if (
            not isinstance(binding_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", binding_sha256)
            or binding_sha256 != expected_binding
        ):
            raise _proposal_integrity_error("binding digest does not match", run_id)

    snapshot = proposal["evidence_snapshot"]
    snapshot_required = {
        "overlay_generation",
        "validated_observation_ids",
        "source_artifact_run_ids",
        "target_artifact_run_ids",
        "review_artifact_run_ids",
        "sha256",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != snapshot_required:
        raise _proposal_integrity_error("evidence snapshot has an invalid shape", run_id)
    overlay_generation = snapshot.get("overlay_generation")
    if overlay_generation is not None and (
        not isinstance(overlay_generation, str)
        or not _ARTIFACT_RUN_ID.fullmatch(overlay_generation)
    ):
        raise _proposal_integrity_error("overlay generation is invalid", run_id)
    observation_ids = _sorted_stable_ids(
        snapshot.get("validated_observation_ids"), pattern=_STABLE_SCHEMA_ID
    )
    evidence_lists = {
        key: _sorted_stable_ids(snapshot.get(key), pattern=_ARTIFACT_RUN_ID)
        for key in (
            "source_artifact_run_ids",
            "target_artifact_run_ids",
            "review_artifact_run_ids",
        )
    }
    if observation_ids is None or any(value is None for value in evidence_lists.values()):
        raise _proposal_integrity_error("evidence IDs are invalid or not canonical", run_id)
    unsigned_snapshot = {key: value for key, value in snapshot.items() if key != "sha256"}
    expected_snapshot = hashlib.sha256(
        json.dumps(unsigned_snapshot, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    if snapshot.get("sha256") != expected_snapshot:
        raise _proposal_integrity_error("evidence snapshot digest does not match", run_id)

    _verify_candidate_proposal_evidence_bundles(
        metadata,
        snapshot,
        proposal_run_id=run_id,
    )

    try:
        _verified_meta, result_rows, _total = _verified_result_rows(meta_path)
    except ArtifactError as exc:
        raise _proposal_integrity_error(
            "binding result artifact failed integrity validation", run_id
        ) from exc
    if not proposal_path.exists():
        return None
    if not proposal_path.is_file():
        raise _proposal_integrity_error("proposal path is not a regular file", run_id)
    proposal_size = proposal.get("proposal_bytes")
    proposal_digest = proposal.get("proposal_sha256")
    if not is_legacy and (
        not isinstance(proposal_size, int)
        or proposal_size < 1
        or proposal_size > _MAX_PROPOSAL_BYTES
        or not isinstance(proposal_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", proposal_digest)
    ):
        raise _proposal_integrity_error("proposal byte metadata is invalid", run_id)
    try:
        actual_size = proposal_path.stat().st_size
        if actual_size < 1 or actual_size > _MAX_PROPOSAL_BYTES:
            raise _proposal_integrity_error("proposal byte count is unsafe", run_id)
        if not is_legacy and actual_size != proposal_size:
            raise _proposal_integrity_error("proposal byte count does not match", run_id)
        raw = proposal_path.read_bytes()
        external_rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise _proposal_integrity_error(f"proposal file is unreadable: {exc}", run_id) from exc
    if not is_legacy and hashlib.sha256(raw).hexdigest() != proposal_digest:
        raise _proposal_integrity_error("proposal file digest does not match", run_id)
    if any(not isinstance(row, dict) for row in external_rows) or external_rows != result_rows:
        raise _proposal_integrity_error(
            "proposal rows do not match the binding result artifact", run_id
        )
    references = {run_id} if run_id is not None else set()
    for values in evidence_lists.values():
        references.update(values or ())
    return references, str(proposal_path), is_legacy


def _schema_evidence_references() -> _EvidenceReferences:
    """Return verified result IDs retained by overlays and live proposals."""

    schema_root = get_config_home() / "schema"
    overlay_run_ids: set[str] = set()
    observation_ids: set[str] = set()
    if schema_root.exists():
        for root in local_overlay_roots():
            manifest = root / "semantic.current.json"
            if not manifest.is_file():
                raise ArtifactError(
                    "Cannot safely prune results while a schema overlay has retained "
                    f"generations but no current manifest: {root}.",
                    help_command="xdr schema repair-overlay --all-local --yes",
                )
            try:
                overlay = load_tenant_overlay_from_root(root)
            except ArtifactError as exc:
                raise ArtifactError(
                    "Cannot safely prune results while a current schema overlay is "
                    f"unreadable: {root}. Repair or restore the overlay first.",
                    help_command="xdr schema repair-overlay --all-local --yes",
                ) from exc
            if overlay.metadata.get("integrity_state") != "verified":
                raise ArtifactError(
                    "Cannot safely prune results while a current schema overlay has "
                    "no content digest. Migrate it before pruning.",
                    help_command="xdr schema repair-overlay --all-local --yes",
                )
            for record in overlay.observations:
                observation_ids.add(record.observation_id)
                for run_id in (
                    record.source_artifact_run_id,
                    record.target_artifact_run_id,
                ):
                    if isinstance(run_id, str):
                        overlay_run_ids.add(run_id)
    proposal_run_ids: set[str] = set()
    proposal_paths: set[str] = set()
    legacy_proposal_paths: set[str] = set()
    for meta_path in _metadata_paths():
        try:
            metadata = _load_meta(meta_path)
        except ArtifactError as exc:
            raise _result_integrity_error(
                f"Cannot safely prune unreadable result metadata: {meta_path}"
            ) from exc
        review = metadata.get("candidate_review")
        if (
            isinstance(review, dict)
            and review.get("observation_id") in observation_ids
            and isinstance(metadata.get("run_id"), str)
        ):
            overlay_run_ids.add(metadata["run_id"])
        verified_proposal = _verified_candidate_proposal_references(meta_path, metadata)
        if verified_proposal is not None:
            references, proposal_path, is_legacy = verified_proposal
            proposal_run_ids.update(references)
            proposal_paths.add(proposal_path)
            if is_legacy:
                legacy_proposal_paths.add(proposal_path)
    return _EvidenceReferences(
        overlay_run_ids=frozenset(overlay_run_ids),
        proposal_run_ids=frozenset(proposal_run_ids),
        proposal_paths=tuple(sorted(proposal_paths)),
        legacy_proposal_paths=tuple(sorted(legacy_proposal_paths)),
    )


def _results_prune_plan(
    cutoff: datetime,
) -> tuple[list[tuple[Path, Path | None]], dict[str, Any]]:
    """Build a prune plan; caller holds the schema evidence-reference lock."""

    targets: list[tuple[Path, Path | None]] = []
    references = _schema_evidence_references()
    protected_bundles = 0
    protected_overlay_bundles = 0
    protected_proposal_bundles = 0
    for meta_path in _metadata_paths():
        try:
            meta = _load_meta(meta_path)
            created_at = datetime.fromisoformat(
                str(meta["created_at"]).replace("Z", "+00:00")
            )
        except (ArtifactError, KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
            raise _result_integrity_error(
                f"Cannot safely prune invalid result metadata: {meta_path}"
            ) from exc
        if created_at >= cutoff:
            continue
        run_id = meta.get("run_id")
        if run_id in references.all_run_ids:
            protected_bundles += 1
            protected_overlay_bundles += int(run_id in references.overlay_run_ids)
            protected_proposal_bundles += int(run_id in references.proposal_run_ids)
            continue
        data_path = _registered_data_path(meta.get("data_path"))
        try:
            registered_meta_path = Path(meta["meta_path"]).resolve()
        except (KeyError, OSError, TypeError) as exc:
            raise _result_integrity_error(
                f"Cannot safely prune inconsistent result metadata: {meta_path}"
            ) from exc
        if (
            not isinstance(run_id, str)
            or meta_path.name != f"{run_id}.meta.json"
            or registered_meta_path != meta_path.resolve()
            or data_path is None
            or data_path.parent != meta_path.resolve().parent
            or data_path.name != f"{run_id}.jsonl"
        ):
            raise _result_integrity_error(
                f"Cannot safely prune inconsistent result bundle: {meta_path}",
                run_id if isinstance(run_id, str) else None,
            )
        targets.append(
            (
                meta_path,
                data_path if data_path.is_file() else None,
            )
        )
    return targets, {
        "total": protected_bundles,
        "overlay": protected_overlay_bundles,
        "proposal": protected_proposal_bundles,
        "proposal_paths": list(references.proposal_paths),
        "legacy_proposal_paths": list(references.legacy_proposal_paths),
    }


def _registered_data_path(value: Any) -> Path | None:
    """Return only JSONL paths contained by the system-owned results root."""

    if not isinstance(value, str) or not value:
        return None
    candidate = Path(value).resolve()
    root = _results_root().resolve()
    if not candidate.is_relative_to(root) or candidate.suffix != ".jsonl":
        return None
    return candidate


def _load_meta(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(
            f"Cannot read result metadata: {exc}",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc
    if not isinstance(value, dict):
        raise ArtifactError(f"Invalid result metadata: {path}")
    return value


def _physical_lineage_summary(meta: dict[str, Any]) -> tuple[str, str | None]:
    """Return supported correlation lineage without exposing private metadata."""

    lineage = meta.get("physical_lineage")
    if not isinstance(lineage, dict):
        return "legacy-unknown", None
    table = lineage.get("table")
    if (
        lineage.get("kind") == "physical"
        and isinstance(table, str)
        and _TABLE_NAME.fullmatch(table)
    ):
        return "physical", table
    return str(lineage.get("kind") or "unknown"), None


def _result_integrity_error(message: str, run_id: str | None = None) -> ArtifactError:
    help_command = f"xdr results show {run_id}" if run_id else "xdr results list"
    error = ArtifactError(
        message,
        help_command=help_command,
        suggestions=[
            {
                "reason": "inspect_result_integrity",
                "message": help_command,
                "confidence": "exact",
            }
        ],
    )
    error.error_code = "RESULT_INTEGRITY_FAILED"
    return error


def _verified_result_rows(
    meta_path: Path,
    *,
    limit: int | None = None,
    offset: int = 0,
    record_type: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    """Load a result bundle only after exact path, digest, and count validation."""

    meta = _load_meta(meta_path)
    run_id = meta.get("run_id")
    data_path = _registered_data_path(meta.get("data_path"))
    if (
        not isinstance(run_id, str)
        or meta_path.name != f"{run_id}.meta.json"
        or data_path is None
        or data_path.parent != meta_path.parent.resolve()
        or data_path.name != f"{run_id}.jsonl"
        or Path(str(meta.get("meta_path", ""))).resolve() != meta_path.resolve()
    ):
        raise _result_integrity_error(
            "Result metadata does not exactly identify its local bundle.", run_id
        )
    digest = hashlib.sha256()
    rows: list[dict[str, Any]] = []
    row_count = 0
    matching_count = 0
    try:
        with data_path.open("rb") as handle:
            for line in handle:
                digest.update(line)
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("result row is not a JSON object")
                row_count += 1
                if record_type is not None and value.get("record_type") != record_type:
                    continue
                if matching_count >= offset and (limit is None or len(rows) < limit):
                    rows.append(value)
                matching_count += 1
    except OSError as exc:
        raise _result_integrity_error(f"Cannot read result data: {exc}", run_id) from exc
    except (ValueError, json.JSONDecodeError) as exc:
        raise _result_integrity_error(f"Cannot parse result data: {exc}", run_id) from exc
    if digest.hexdigest() != meta.get("data_sha256"):
        raise _result_integrity_error(
            "Result data integrity check failed; the saved JSONL was modified.", run_id
        )
    if meta.get("row_count") != row_count:
        raise _result_integrity_error(
            "Result row count does not match its metadata.", run_id
        )
    return meta, rows, matching_count


def _find_meta(run_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9-]+", run_id):
        raise UsageError(
            "Invalid result run ID.",
            invalid={"kind": "run_id", "value": run_id},
            help_command="xdr results list",
        )
    matches = list(_results_root().glob(f"*/{run_id}*.meta.json"))
    exact = [path for path in matches if path.name == f"{run_id}.meta.json"]
    selected = exact or matches
    if not selected:
        error = LocalNotFoundError("result", run_id)
        error.error_code = "RESULT_NOT_FOUND"
        error.help_command = "xdr results list"
        raise error
    if len(selected) > 1:
        raise ConflictError(
            f"Result ID prefix '{run_id}' is ambiguous; provide the complete run ID.",
            help_command="xdr results list",
        )
    return selected[0]


@results_app.command("list")
def results_list(
    limit: int = typer.Option(100, "--limit", min=1, max=1000),
) -> None:
    """List results, storage use, and copyable physical correlation inputs.

    Example: `xdr results list`. A non-null `correlate_input` can be passed to
    `xdr schema correlate --input TABLE=RUN_ID` alongside a second artifact.
    """

    paths = _metadata_paths()
    rows: list[dict[str, Any]] = []
    total_bytes = 0
    for path in paths:
        try:
            meta = _load_meta(path)
        except (ArtifactError, OSError, ValueError, json.JSONDecodeError):
            continue
        data_path = _registered_data_path(meta.get("data_path"))
        bundle_bytes = path.stat().st_size
        if data_path is not None and data_path.is_file():
            bundle_bytes += data_path.stat().st_size
        total_bytes += bundle_bytes
        if len(rows) < limit:
            lineage_state, lineage_table = _physical_lineage_summary(meta)
            correlate_input = (
                f"{lineage_table}={meta.get('run_id')}" if lineage_table else None
            )
            rows.append(
                {
                    "run_id": meta.get("run_id"),
                    "created_at": meta.get("created_at"),
                    "command": meta.get("command"),
                    "rows": meta.get("row_count"),
                    "bundle_bytes": bundle_bytes,
                    "data_path": meta.get("data_path"),
                    "physical_lineage_state": lineage_state,
                    "physical_lineage_table": lineage_table,
                    "correlate_input": correlate_input,
                }
            )
    _emit(
        {
            "status": "success",
            "data": rows,
            "metadata": {
                "shown": len(rows),
                "total": len(paths),
                "aggregate_stored_bytes": total_bytes,
            },
        }
    )


@results_app.command("show")
def results_show(run_id: str = typer.Argument()) -> None:
    """Show bounded provenance and correlation input for one result.

    Example: `xdr results show RUN_ID`. For physically attributed artifacts,
    copy `correlate_input` into `xdr schema correlate --input TABLE=RUN_ID`.
    """

    meta_path = _find_meta(run_id)
    meta = _load_meta(meta_path)
    lineage_state, lineage_table = _physical_lineage_summary(meta)
    correlate_input = (
        f"{lineage_table}={meta.get('run_id')}" if lineage_table else None
    )
    data = {
        "run_id": meta.get("run_id"),
        "created_at": meta.get("created_at"),
        "command": meta.get("command"),
        "rows": meta.get("row_count"),
        "data_path": meta.get("data_path"),
        "meta_path": meta.get("meta_path"),
        "execution_time_ms": meta.get("execution_time_ms"),
        "server_truncation_state": meta.get("server_truncation_state"),
        "session": meta.get("session"),
        "anchors": meta.get("anchors"),
        "library_entry": meta.get("library_entry"),
        "query_available": isinstance(meta.get("query"), str),
        "query_sha256": meta.get("query_sha256"),
        "data_sha256": meta.get("data_sha256"),
        "tenant_binding_state": (
            meta.get("tenant_binding", {}).get("state")
            if isinstance(meta.get("tenant_binding"), dict)
            else "legacy-unbound"
        ),
        "source_hash": meta.get("source_hash"),
        "maximum_serialized_row_bytes": meta.get("maximum_serialized_row_bytes"),
        "physical_lineage_state": lineage_state,
        "physical_lineage_table": lineage_table,
        "correlate_input": correlate_input,
        "correlate_command_template": (
            f"xdr schema correlate --input {correlate_input} "
            "--input OTHER_TABLE=OTHER_RUN_ID"
            if correlate_input
            else None
        ),
    }
    _emit({"status": "success", "data": data})


@results_app.command("query")
def results_query(run_id: str = typer.Argument()) -> None:
    """Print the exact KQL stored with one result."""

    meta_path = _find_meta(run_id)
    meta = _load_meta(meta_path)
    query = meta.get("query")
    if not isinstance(query, str):
        error = LocalNotFoundError("stored query for result", run_id)
        error.error_code = "RESULT_QUERY_NOT_FOUND"
        error.help_command = f"xdr results show {run_id}"
        raise error
    typer.echo(query)


@results_app.command("head")
def results_head(
    run_id: str = typer.Argument(help="Run ID or unambiguous prefix from `xdr results list`."),
    limit: int = typer.Option(
        20,
        "--limit",
        min=1,
        max=100,
        help="Maximum private rows to print (1-100; default 20).",
    ),
) -> None:
    """Print a bounded preview of private saved rows; never contacts the tenant.

    Example: `xdr results head 20260801T084128011506Z-a01d707cfd37 --limit 20`

    Output may contain investigation values. Do not paste it into public issues
    or documentation. Use `xdr results show RUN_ID` for value-free provenance.
    """

    meta_path = _find_meta(run_id)
    meta, rows, total = _verified_result_rows(meta_path, limit=limit)
    _emit(
        {
            "status": "success",
            "data": rows,
            "metadata": {
                "run_id": meta.get("run_id"),
                "shown": len(rows),
                "total": total,
                "has_more": total > len(rows),
                "privacy": "private-investigation-values",
            },
        }
    )


@results_app.command("rows")
def results_rows(
    run_id: str = typer.Argument(
        help="Run ID or unambiguous prefix from `xdr results list`."
    ),
    record_type: str | None = typer.Option(
        None,
        "--type",
        help=(
            "Exact `record_type` filter, for example `relationship-path-match`."
        ),
    ),
    offset: int = typer.Option(
        0,
        "--offset",
        min=0,
        help="Skip this many matching rows before printing (default 0).",
    ),
    limit: int = typer.Option(
        100,
        "--limit",
        min=1,
        max=1000,
        help="Maximum private matching rows to print (1-1000; default 100).",
    ),
) -> None:
    """Inspect filtered or paginated private result rows; cache-only.

    Example: `xdr results rows RUN_ID --type relationship-path-match --limit
    100`

    Output may contain investigation values. The entire bundle is still
    verified before filtered rows are returned. Use `--offset N` when
    `metadata.has_more` is true.
    """

    if record_type is not None and not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9-]{0,127}", record_type
    ):
        raise UsageError(
            "Invalid result record type filter.",
            help_command="xdr results rows --help",
        )
    meta_path = _find_meta(run_id)
    meta, rows, total = _verified_result_rows(
        meta_path,
        limit=limit,
        offset=offset,
        record_type=record_type,
    )
    next_offset = offset + len(rows)
    _emit(
        {
            "status": "success",
            "data": rows,
            "metadata": {
                "run_id": meta.get("run_id"),
                "record_type": record_type,
                "offset": offset,
                "shown": len(rows),
                "total": total,
                "has_more": next_offset < total,
                "next_command": (
                    f"xdr results rows {meta.get('run_id')} "
                    + (f"--type {record_type} " if record_type else "")
                    + f"--offset {next_offset} --limit {limit}"
                    if next_offset < total
                    else None
                ),
                "privacy": "private-investigation-values",
            },
        }
    )


@results_app.command("shape")
def results_shape(
    run_id: str = typer.Argument(),
    search: str | None = typer.Option(None, "--search"),
    limit: int = typer.Option(100, "--limit", min=1, max=1000),
) -> None:
    """Show observed JSON paths, types, and field presence counts."""

    meta_path = _find_meta(run_id)
    meta = _load_meta(meta_path)
    shape = meta.get("observed_shape", [])
    if not isinstance(shape, list):
        shape = []
    if search:
        needle = search.casefold()
        shape = [
            row
            for row in shape
            if isinstance(row, dict)
            and needle in str(row.get("path", "")).casefold()
        ]
    total = len(shape)
    shown = shape[:limit]
    _emit(
        {
            "status": "success",
            "data": shown,
            "metadata": {
                "run_id": meta.get("run_id"),
                "row_count": meta.get("row_count"),
                "shown": len(shown),
                "total": total,
                "has_more": total > len(shown),
                "search": search,
                "full_shape_meta_path": str(meta_path.resolve()),
                "maximum_serialized_row_bytes": meta.get(
                    "maximum_serialized_row_bytes"
                ),
            },
        }
    )


@results_app.command("prune")
def results_prune(
    ctx: typer.Context,
    older_than: int = typer.Option(
        ...,
        "--older-than",
        min=1,
        help="Delete artifacts older than this many days.",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm deletion."),
) -> None:
    """Delete old unreferenced result bundles; preserve schema/proposal evidence.

    Example: `xdr results prune --older-than 90 --yes`

    Bundles referenced by the tenant schema graph or an extant candidate
    proposal are skipped after their integrity bindings are verified. Any
    proposal mismatch stops pruning. Prune stale overlay evidence, and delete
    merged or abandoned proposal JSONL drafts, before rerunning this command.
    """

    app_ctx: AppContext = ctx.obj
    cutoff = datetime.now(UTC) - timedelta(days=older_than)
    with schema_evidence_lock(help_command="xdr results prune --help"):
        targets, _protected_preview = _results_prune_plan(cutoff)

    approved = yes
    if targets and not yes:
        if not app_ctx.is_interactive:
            raise UsageError(
                "Non-interactive pruning requires --yes.",
                corrected_argv=[
                    "xdr",
                    "results",
                    "prune",
                    "--older-than",
                    str(older_than),
                    "--yes",
                ],
                help_command="xdr results prune --help",
            )
        err_console.print(f"Delete {len(targets)} result bundle(s)?")
        if not typer.confirm("Proceed?"):
            raise ConflictError("Result pruning was cancelled by the operator.")
        approved = True

    removed_files = 0
    removed_bytes = 0
    with schema_evidence_lock(help_command="xdr results prune --help"):
        targets, protected = _results_prune_plan(cutoff)
        if targets and not approved:
            raise ConflictError(
                "The result set changed while preparing the prune operation. Review "
                "the new plan and rerun the command.",
                help_command="xdr results prune --help",
            )
        try:
            for meta_path, data_path in targets:
                for path in (data_path, meta_path):
                    if path is None or not path.exists():
                        continue
                    removed_bytes += path.stat().st_size
                    path.unlink()
                    removed_files += 1

            root = _results_root()
            if root.exists():
                for date_dir in root.iterdir():
                    if date_dir.is_dir() and not any(date_dir.iterdir()):
                        date_dir.rmdir()
                if not any(root.iterdir()):
                    root.rmdir()
        except OSError as exc:
            raise ArtifactError(
                f"Could not prune result artifacts: {exc}",
                original={"type": type(exc).__name__, "message": str(exc)},
            ) from exc

    _emit(
        {
            "status": "success",
            "data": {
                "removed_bundles": len(targets),
                "removed_files": removed_files,
                "removed_bytes": removed_bytes,
                "protected_schema_evidence_bundles": protected["total"],
                "protected_overlay_evidence_bundles": protected["overlay"],
                "protected_candidate_proposal_bundles": protected["proposal"],
                "protected_candidate_proposal_paths": protected["proposal_paths"],
                "legacy_candidate_proposal_paths": protected[
                    "legacy_proposal_paths"
                ],
                "legacy_candidate_proposal_guidance": (
                    "Regenerate live legacy drafts with `xdr schema "
                    "candidate-proposal ...` for byte binding, or delete merged/"
                    "abandoned drafts to release their evidence."
                    if protected["legacy_proposal_paths"]
                    else None
                ),
                "next_command": (
                    f"xdr schema prune-evidence --older-than {older_than} --yes"
                    if protected["overlay"]
                    else None
                ),
            },
        }
    )
