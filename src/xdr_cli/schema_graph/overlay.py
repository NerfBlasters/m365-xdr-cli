"""Atomic private tenant semantic graph generations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import Timeout as FileLockTimeout

from xdr_cli._lock import exclusive_lock
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import ArtifactError, ConflictError
from xdr_cli.schema_graph.model import (
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    ObservationRecord,
    RelationshipRecord,
)

_GENERATION = re.compile(r"[A-Za-z0-9_-]{1,128}")
_RETAIN_GENERATIONS = 3
_NO_EXPECTED_GENERATION = object()


@dataclass(frozen=True, slots=True)
class TenantSemanticOverlay:
    """Value-free tenant-local graph records and empirical observations."""

    graph: Graph
    observations: tuple[ObservationRecord, ...]
    metadata: dict[str, Any]


def _overlay_root(tenant_id: str) -> Path:
    root = _overlay_path(tenant_id)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix":
        root.chmod(0o700)
    return root


def _overlay_path(tenant_id: str) -> Path:
    tenant_key = hashlib.sha256((tenant_id or "default").encode()).hexdigest()[:12]
    return get_config_home() / "schema" / tenant_key


def schema_evidence_lock_path() -> Path:
    """Return the global lock target protecting overlays and their evidence."""

    root = get_config_home()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix":
        root.chmod(0o700)
    return root / ".schema-evidence-references"


@contextmanager
def schema_evidence_lock(*, help_command: str):
    """Acquire the global evidence lock with actionable contention errors."""

    try:
        with exclusive_lock(schema_evidence_lock_path()):
            yield
    except FileLockTimeout as exc:
        raise ConflictError(
            "Another schema evidence publication, repair, or result prune is still "
            "running. Retry the original command after it finishes.",
            retryable=True,
            help_command=help_command,
        ) from exc


def local_overlay_roots() -> tuple[Path, ...]:
    """Return local tenant roots containing an overlay manifest or generation."""

    schema_root = get_config_home() / "schema"
    if not schema_root.is_dir():
        return ()
    return tuple(
        sorted(
            root
            for root in schema_root.iterdir()
            if root.is_dir()
            and (
                (root / "semantic.current.json").exists()
                or any(root.glob("semantic.*.jsonl"))
            )
        )
    )


def _read_generation(root: Path) -> str | None:
    manifest = root / "semantic.current.json"
    if not manifest.exists():
        return None
    try:
        generation = json.loads(manifest.read_text(encoding="utf-8"))["generation"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"Semantic overlay manifest is invalid: {exc}") from exc
    if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
        raise ArtifactError("Semantic overlay manifest has an invalid generation")
    return generation


def load_tenant_overlay(tenant_id: str) -> TenantSemanticOverlay:
    root = _overlay_root(tenant_id)
    return load_tenant_overlay_from_root(root)


def load_tenant_overlay_from_root(root: Path) -> TenantSemanticOverlay:
    """Load and validate an existing overlay directory without creating it."""

    generation = _read_generation(root)
    if generation is None:
        return TenantSemanticOverlay(
            graph=Graph(),
            observations=(),
            metadata={
                "generation": None,
                "field_count": 0,
                "interpretation_count": 0,
                "observation_count": 0,
                "refreshed_at": None,
                "integrity_state": "missing",
            },
        )
    return _load_generation(root, generation)


def _load_generation(root: Path, generation: str) -> TenantSemanticOverlay:
    """Load one immutable generation, independent of the current manifest."""

    if not _GENERATION.fullmatch(generation):
        raise ArtifactError("Semantic overlay generation name is invalid")
    data_path = root / f"semantic.{generation}.jsonl"
    meta_path = root / f"semantic.{generation}.meta.json"
    graph = Graph()
    observations: list[ObservationRecord] = []
    try:
        raw = data_path.read_bytes()
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(metadata, dict) or metadata.get("generation") != generation:
            raise ValueError("metadata does not match its generation")
        expected_digest = metadata.get("data_sha256")
        expected_bytes = metadata.get("data_bytes")
        if expected_digest is None and expected_bytes is None:
            integrity_state = "legacy-unbound"
        elif (
            not isinstance(expected_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
            or not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes < 0
            or expected_bytes != len(raw)
            or hashlib.sha256(raw).hexdigest() != expected_digest
        ):
            raise ValueError("content digest or byte count does not match")
        else:
            integrity_state = "verified"
        for line in raw.decode("utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            record_type = record.get("record_type")
            if record_type == FieldRecord.RECORD_TYPE:
                graph.add(FieldRecord.from_dict(record))
            elif record_type == InterpretationRecord.RECORD_TYPE:
                graph.add(InterpretationRecord.from_dict(record))
            elif record_type == RelationshipRecord.RECORD_TYPE:
                graph.add(RelationshipRecord.from_dict(record))
            elif record_type == ObservationRecord.RECORD_TYPE:
                observations.append(ObservationRecord.from_dict(record))
            else:
                raise GraphValidationError(
                    f"unsupported tenant overlay record type: {record_type!r}"
                )
    except (
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
        GraphValidationError,
    ) as exc:
        raise ArtifactError(f"Semantic overlay generation is invalid: {exc}") from exc
    try:
        graph.validate_references()
    except GraphValidationError as exc:
        raise ArtifactError(f"Semantic overlay references are invalid: {exc}") from exc
    expected_counts = {
        "field_count": len(graph.fields),
        "interpretation_count": len(graph.interpretations),
        "relationship_count": len(graph.relationships),
        "observation_count": len(observations),
    }
    if any(metadata.get(key, 0) != value for key, value in expected_counts.items()):
        raise ArtifactError("Semantic overlay metadata counts do not match its records")
    metadata = dict(metadata)
    metadata["integrity_state"] = integrity_state
    return TenantSemanticOverlay(
        graph=graph,
        observations=tuple(observations),
        metadata=metadata,
    )


def load_tenant_observations(
    tenant_id: str,
) -> tuple[tuple[ObservationRecord, ...], dict[str, Any]]:
    """Compatibility view for callers interested only in observations."""

    overlay = load_tenant_overlay(tenant_id)
    return overlay.observations, overlay.metadata


def tenant_overlay_status(tenant_id: str) -> dict[str, Any]:
    """Return value-free current-generation health without changing local state."""

    root = _overlay_path(tenant_id)
    manifest = root / "semantic.current.json"
    retained = len(list(root.glob("semantic.*.jsonl"))) if root.is_dir() else 0
    if not manifest.is_file():
        if retained:
            return {
                "state": "invalid",
                "generation": None,
                "integrity_state": "orphaned-generations",
                "retained_generations": retained,
                "repair_command": "xdr schema repair-overlay --yes",
                "error": (
                    "The current overlay manifest is missing while retained "
                    "generations exist."
                ),
            }
        return {
            "state": "missing",
            "generation": None,
            "integrity_state": "missing",
            "retained_generations": retained,
            "repair_command": None,
        }
    try:
        overlay = load_tenant_overlay_from_root(root)
    except ArtifactError as exc:
        return {
            "state": "invalid",
            "generation": None,
            "integrity_state": "invalid",
            "retained_generations": retained,
            "repair_command": "xdr schema repair-overlay --yes",
            "error": str(exc),
        }
    integrity = overlay.metadata.get("integrity_state", "invalid")
    from xdr_cli.schema_graph.compatibility import audit_overlay_compatibility
    from xdr_cli.schema_graph.loader import load_packaged_graph

    compatibility = audit_overlay_compatibility(
        overlay.graph,
        overlay.observations,
        load_packaged_graph(),
    )
    return {
        "state": (
            "incompatible"
            if compatibility.state == "incompatible"
            else "needs-migration"
            if compatibility.state == "needs-migration"
            else "valid"
            if integrity == "verified"
            else "legacy-unbound"
        ),
        "generation": overlay.metadata.get("generation"),
        "integrity_state": integrity,
        "compatibility": compatibility.to_status_dict(),
        "retained_generations": retained,
        "repair_command": (
            "xdr schema repair-overlay --yes"
            if integrity != "verified" or compatibility.state != "compatible"
            else None
        ),
    }


def _publish_empty_generation(root: Path) -> dict[str, Any]:
    """Publish an empty verified generation while the overlay lock is held."""

    generation = (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(6)
    )
    data_path = root / f"semantic.{generation}.jsonl"
    meta_path = root / f"semantic.{generation}.meta.json"
    manifest = root / "semantic.current.json"
    data_tmp = root / f".{generation}.reset.jsonl.tmp"
    meta_tmp = root / f".{generation}.reset.meta.tmp"
    manifest_tmp = root / f".{generation}.reset.current.tmp"
    metadata = {
        "schema_version": 1,
        "generation": generation,
        "refreshed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "field_count": 0,
        "interpretation_count": 0,
        "relationship_count": 0,
        "observation_count": 0,
        "data_sha256": hashlib.sha256(b"").hexdigest(),
        "data_bytes": 0,
    }
    try:
        with data_tmp.open("xb") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        with meta_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(metadata, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        with manifest_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps({"generation": generation}, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        for path in (data_tmp, meta_tmp, manifest_tmp):
            if os.name == "posix":
                path.chmod(0o600)
        os.replace(data_tmp, data_path)
        os.replace(meta_tmp, meta_path)
        os.replace(manifest_tmp, manifest)
    except OSError as exc:
        raise ArtifactError(f"Could not publish empty semantic overlay: {exc}") from exc
    finally:
        data_tmp.unlink(missing_ok=True)
        meta_tmp.unlink(missing_ok=True)
        manifest_tmp.unlink(missing_ok=True)
    return metadata


def _quarantine_overlay_files(root: Path) -> Path:
    """Copy exact overlay artifacts to a private recovery directory."""

    quarantine = root / "quarantine" / (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(4)
    )
    quarantine.mkdir(parents=True, mode=0o700)
    paths = [root / "semantic.current.json"]
    paths.extend(root.glob("semantic.*.jsonl"))
    paths.extend(root.glob("semantic.*.meta.json"))
    for path in paths:
        if path.is_file():
            shutil.copy2(path, quarantine / path.name)
    if os.name == "posix":
        for path in quarantine.iterdir():
            path.chmod(0o600)
    return quarantine


def _write_replacement_generation_locked(
    root: Path,
    graph: Graph,
    observations: tuple[ObservationRecord, ...],
    *,
    migration: dict[str, Any],
) -> dict[str, Any]:
    """Atomically publish a complete replacement while repair locks are held."""

    graph.validate_references()
    generation = (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(6)
    )
    data_path = root / f"semantic.{generation}.jsonl"
    meta_path = root / f"semantic.{generation}.meta.json"
    manifest = root / "semantic.current.json"
    data_tmp = root / f".{generation}.migrate.jsonl.tmp"
    meta_tmp = root / f".{generation}.migrate.meta.tmp"
    manifest_tmp = root / f".{generation}.migrate.current.tmp"
    records = [
        *(record.to_dict() for record in graph.records()),
        *(item.to_dict() for item in observations),
    ]
    records.sort(key=lambda item: (item["record_type"], item["id"]))
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "generation": generation,
        "refreshed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "field_count": len(graph.fields),
        "interpretation_count": len(graph.interpretations),
        "relationship_count": len(graph.relationships),
        "observation_count": len(observations),
        "migration": migration,
    }
    try:
        digest = hashlib.sha256()
        byte_count = 0
        with data_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            for record in records:
                line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                handle.write(line)
                encoded = line.encode("utf-8")
                digest.update(encoded)
                byte_count += len(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        metadata["data_sha256"] = digest.hexdigest()
        metadata["data_bytes"] = byte_count
        with meta_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(metadata, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        with manifest_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps({"generation": generation}, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        for path in (data_tmp, meta_tmp, manifest_tmp):
            if os.name == "posix":
                path.chmod(0o600)
        os.replace(data_tmp, data_path)
        os.replace(meta_tmp, meta_path)
        os.replace(manifest_tmp, manifest)
    except OSError as exc:
        raise ArtifactError(f"Could not publish migrated semantic overlay: {exc}") from exc
    finally:
        data_tmp.unlink(missing_ok=True)
        meta_tmp.unlink(missing_ok=True)
        manifest_tmp.unlink(missing_ok=True)
    return metadata


def _repair_overlay_from_root(
    root: Path, *, reset_empty: bool, all_local_context: bool = False
) -> dict[str, Any]:
    """Select, integrity-bind, or compatibly migrate one locked overlay root."""

    generations = sorted(
        (
            path.name.removeprefix("semantic.").removesuffix(".jsonl")
            for path in root.glob("semantic.*.jsonl")
        ),
        reverse=True,
    )
    selected: TenantSemanticOverlay | None = None
    selected_generation: str | None = None
    for generation in generations:
        if not _GENERATION.fullmatch(generation):
            continue
        try:
            candidate = _load_generation(root, generation)
        except ArtifactError:
            continue
        selected = candidate
        selected_generation = generation
        break
    if selected is None or selected_generation is None:
        if reset_empty:
            quarantine = _quarantine_overlay_files(root)
            metadata = _publish_empty_generation(root)
            return {
                "generation": metadata["generation"],
                "integrity_state": "verified",
                "compatibility_state": "compatible",
                "field_count": 0,
                "relationship_count": 0,
                "observation_count": 0,
                "reset_empty": True,
                "quarantine_path": str(quarantine.resolve()),
                "next_command": "xdr schema collect",
            }
        raise ArtifactError(
            "No valid retained semantic overlay generation is available to repair. "
            f"The invalid files remain at {root}. To preserve them in quarantine "
            "and activate an empty verified overlay, run the reset command.",
            help_command=(
                "xdr schema repair-overlay --all-local --reset-empty --yes"
                if all_local_context
                else "xdr schema repair-overlay --reset-empty --yes"
            ),
        )

    from xdr_cli.schema_graph.compatibility import (
        audit_overlay_compatibility,
        migrate_overlay,
    )
    from xdr_cli.schema_graph.loader import load_packaged_graph

    # Integrity and semantic compatibility are separate.  A generation may be
    # byte-valid yet contain provisional records derived from a prior packaged
    # contract.  Quarantine exact source bytes before publishing a replacement.
    canonical = load_packaged_graph()
    compatibility = audit_overlay_compatibility(
        selected.graph, selected.observations, canonical
    )
    if compatibility.state == "incompatible":
        raise ConflictError(
            "The tenant semantic overlay is byte-valid but has reviewed semantic "
            "contract conflicts that cannot be migrated automatically. The active "
            "generation was not changed.",
            help_command="xdr schema status",
        )
    migration_summary: dict[str, Any] | None = None
    quarantine_path: str | None = None
    if compatibility.needs_migration:
        migrated = migrate_overlay(selected.graph, selected.observations, canonical)
        if migrated.compatibility.state != "compatible":
            raise ConflictError(
                "The tenant semantic overlay could not be made compatible without "
                "reinterpreting evidence. The active generation was not changed.",
                help_command="xdr schema status",
            )
        quarantine = _quarantine_overlay_files(root)
        migration_summary = migrated.summary()
        migration_summary.update(
            {
                "source_generation": selected_generation,
                "reason": "semantic-contract-upgrade",
            }
        )
        metadata = _write_replacement_generation_locked(
            root,
            migrated.graph,
            migrated.observations,
            migration=migration_summary,
        )
        selected_generation = str(metadata["generation"])
        quarantine_path = str(quarantine.resolve())
    elif selected.metadata.get("integrity_state") != "verified":
        # Bind only after compatibility has passed. Hard-conflict repair is a
        # strictly read-only operation and must leave even legacy metadata exact.
        data_path = root / f"semantic.{selected_generation}.jsonl"
        meta_path = root / f"semantic.{selected_generation}.meta.json"
        raw = data_path.read_bytes()
        metadata = {
            key: value
            for key, value in selected.metadata.items()
            if key != "integrity_state"
        }
        metadata["data_sha256"] = hashlib.sha256(raw).hexdigest()
        metadata["data_bytes"] = len(raw)
        metadata["binding_origin"] = "local-legacy-migration"
        meta_tmp = root / f".{selected_generation}.repair.meta.tmp"
        try:
            with meta_tmp.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(metadata, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                meta_tmp.chmod(0o600)
            os.replace(meta_tmp, meta_path)
        finally:
            meta_tmp.unlink(missing_ok=True)

    manifest = root / "semantic.current.json"
    manifest_tmp = root / f".{selected_generation}.repair.current.tmp"
    try:
        with manifest_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(
                json.dumps(
                    {"generation": selected_generation}, separators=(",", ":")
                )
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            manifest_tmp.chmod(0o600)
        os.replace(manifest_tmp, manifest)
    finally:
        manifest_tmp.unlink(missing_ok=True)
    repaired = _load_generation(root, selected_generation)
    final_compatibility = audit_overlay_compatibility(
        repaired.graph, repaired.observations, canonical
    )
    return {
        "generation": selected_generation,
        "integrity_state": repaired.metadata.get("integrity_state"),
        "compatibility_state": final_compatibility.state,
        "field_count": len(repaired.graph.fields),
        "relationship_count": len(repaired.graph.relationships),
        "observation_count": len(repaired.observations),
        "reset_empty": False,
        "quarantine_path": quarantine_path,
        "migration": migration_summary,
        "next_command": "xdr schema status",
    }


def repair_tenant_overlay(
    tenant_id: str, *, reset_empty: bool = False
) -> dict[str, Any]:
    """Select the newest valid retained generation and atomically make it current."""

    root = _overlay_root(tenant_id)
    with schema_evidence_lock(help_command="xdr schema repair-overlay --help"):
        try:
            with exclusive_lock(root / ".semantic"):
                return _repair_overlay_from_root(root, reset_empty=reset_empty)
        except FileLockTimeout as exc:
            raise ConflictError(
                "This tenant overlay is being updated. Retry repair after the "
                "active schema command finishes.",
                retryable=True,
                help_command="xdr schema repair-overlay --help",
            ) from exc


def repair_all_local_overlays(*, reset_empty: bool = False) -> tuple[dict[str, Any], ...]:
    """Repair every local tenant overlay, including roots with missing manifests."""

    repaired: list[dict[str, Any]] = []
    with schema_evidence_lock(help_command="xdr schema repair-overlay --help"):
        for root in local_overlay_roots():
            try:
                with exclusive_lock(root / ".semantic"):
                    item = _repair_overlay_from_root(
                        root, reset_empty=reset_empty, all_local_context=True
                    )
                    item["overlay_path"] = str(root.resolve())
                    repaired.append(item)
            except FileLockTimeout as exc:
                raise ConflictError(
                    f"Local tenant overlay {root} is being updated. Retry after the "
                    "active schema command finishes.",
                    retryable=True,
                    help_command="xdr schema repair-overlay --all-local --yes",
                ) from exc
    return tuple(repaired)


def _add_reconciled_overlay_record(
    graph: Graph,
    record: FieldRecord | InterpretationRecord | RelationshipRecord,
) -> None:
    """Retain prior private annotations when a new dependency is core-equivalent."""

    if isinstance(record, FieldRecord):
        prior = graph.fields.get(record.id)
        annotation_only_duplicate = prior is not None and (
            prior.schema_version,
            prior.locator,
            prior.kql_type,
        ) == (
            record.schema_version,
            record.locator,
            record.kql_type,
        )
    elif isinstance(record, InterpretationRecord):
        prior = graph.interpretations.get(record.id)
        annotation_only_duplicate = prior is not None and (
            prior.schema_version,
            prior.field_id,
            prior.entity_kind,
            prior.namespace,
            prior.role,
            prior.normalizer,
            prior.constraints,
        ) == (
            record.schema_version,
            record.field_id,
            record.entity_kind,
            record.namespace,
            record.role,
            record.normalizer,
            record.constraints,
        )
    else:
        prior = graph.relationships.get(record.id)
        annotation_only_duplicate = prior is not None and prior.to_dict() == record.to_dict()
    if annotation_only_duplicate:
        return
    graph.add(record)


def _merge_records(
    prior: TenantSemanticOverlay,
    new_graph: Graph,
    new_observations: tuple[ObservationRecord, ...],
    *,
    replace_observations: bool = False,
) -> tuple[Graph, dict[str, ObservationRecord]]:
    graph = Graph()
    for record in (*prior.graph.records(), *new_graph.records()):
        _add_reconciled_overlay_record(graph, record)
    observations = (
        {}
        if replace_observations
        else {item.observation_id: item for item in prior.observations}
    )
    for item in new_observations:
        existing = observations.get(item.observation_id)
        if existing is not None and existing.to_dict() != item.to_dict():
            raise GraphValidationError(
                f"conflicting tenant observation id: {item.observation_id}"
            )
        observations[item.observation_id] = item
    return graph, observations


def _validate_result_reference(run_id: str) -> None:
    """Fail closed unless a newly referenced private result is still intact."""

    results_root = (get_config_home() / "results").resolve()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", run_id):
        raise ArtifactError(
            f"Cannot publish semantic evidence because result ID {run_id!r} is invalid.",
            help_command="xdr results list",
        )
    matches = list(results_root.glob(f"*/{run_id}.meta.json"))
    try:
        if len(matches) != 1:
            raise ValueError("result metadata is missing or ambiguous")
        meta_path = matches[0].resolve()
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        data_path = Path(metadata["data_path"]).resolve()
        registered_meta = Path(metadata["meta_path"]).resolve()
        raw = data_path.read_bytes()
        if (
            metadata.get("run_id") != run_id
            or registered_meta != meta_path
            or not data_path.is_relative_to(results_root)
            or data_path.parent != meta_path.parent
            or data_path.name != f"{run_id}.jsonl"
            or hashlib.sha256(raw).hexdigest() != metadata.get("data_sha256")
        ):
            raise ValueError("result registration or content digest does not match")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ArtifactError(
            f"Cannot publish semantic evidence because referenced result {run_id!r} "
            f"is unavailable or invalid: {exc}",
            help_command=f"xdr results show {run_id}",
        ) from exc


def publish_tenant_overlay(
    tenant_id: str,
    *,
    graph: Graph | None = None,
    observations: tuple[ObservationRecord, ...] = (),
    replace_observations: bool = False,
    expected_generation: str | None | object = _NO_EXPECTED_GENERATION,
) -> dict[str, Any]:
    """Merge value-free records and atomically publish one tenant generation."""

    root = _overlay_root(tenant_id)
    with schema_evidence_lock(help_command="xdr schema status"):
        try:
            with exclusive_lock(root / ".semantic"):
                return _publish_tenant_overlay_locked(
                    root,
                    graph=graph or Graph(),
                    observations=observations,
                    replace_observations=replace_observations,
                    expected_generation=expected_generation,
                )
        except FileLockTimeout as exc:
            raise ConflictError(
                "This tenant overlay is being updated. Retry the original command "
                "after the active schema command finishes.",
                retryable=True,
                help_command="xdr schema status",
            ) from exc


def _publish_tenant_overlay_locked(
    root: Path,
    *,
    graph: Graph,
    observations: tuple[ObservationRecord, ...],
    replace_observations: bool,
    expected_generation: str | None | object,
) -> dict[str, Any]:
    """Publish one generation while global and tenant overlay locks are held."""

    if not (root / "semantic.current.json").is_file() and any(
        root.glob("semantic.*.jsonl")
    ):
        raise ArtifactError(
            "Cannot publish while retained semantic generations have no current "
            "manifest. Repair the overlay before collecting more evidence.",
            help_command="xdr schema repair-overlay --yes",
        )
    prior = load_tenant_overlay_from_root(root)
    if (
        expected_generation is not _NO_EXPECTED_GENERATION
        and prior.metadata.get("generation") != expected_generation
    ):
        raise ConflictError(
            "The tenant overlay changed after it was inspected; no stale replacement "
            "was published. Review and rerun the command.",
            help_command="xdr schema prune-evidence --help",
        )
    for observation in observations:
        for run_id in (
            observation.source_artifact_run_id,
            observation.target_artifact_run_id,
        ):
            if isinstance(run_id, str):
                _validate_result_reference(run_id)
    merged_graph, merged_observations = _merge_records(
        prior,
        graph,
        observations,
        replace_observations=replace_observations,
    )
    merged_graph.validate_references()
    for record in merged_graph.records():
        serialized = record.to_dict()
        if isinstance(record, FieldRecord):
            FieldRecord.from_dict(serialized)
        elif isinstance(record, InterpretationRecord):
            InterpretationRecord.from_dict(serialized)
        elif isinstance(record, RelationshipRecord):
            RelationshipRecord.from_dict(serialized)
    for observation in merged_observations.values():
        ObservationRecord.from_dict(observation.to_dict())
    generation = (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(6)
    )
    data_path = root / f"semantic.{generation}.jsonl"
    meta_path = root / f"semantic.{generation}.meta.json"
    manifest = root / "semantic.current.json"
    data_tmp = root / f".{generation}.semantic.jsonl.tmp"
    meta_tmp = root / f".{generation}.semantic.meta.tmp"
    manifest_tmp = root / f".{generation}.semantic.current.tmp"
    metadata = {
        "schema_version": 1,
        "generation": generation,
        "refreshed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "field_count": len(merged_graph.fields),
        "interpretation_count": len(merged_graph.interpretations),
        "relationship_count": len(merged_graph.relationships),
        "observation_count": len(merged_observations),
    }
    records = [
        *(record.to_dict() for record in merged_graph.records()),
        *(item.to_dict() for item in merged_observations.values()),
    ]
    records.sort(key=lambda item: (item["record_type"], item["id"]))
    cleanup_failures = 0
    try:
        data_digest = hashlib.sha256()
        data_bytes = 0
        with data_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            for item in records:
                line = json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
                handle.write(line)
                encoded = line.encode("utf-8")
                data_digest.update(encoded)
                data_bytes += len(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        metadata["data_sha256"] = data_digest.hexdigest()
        metadata["data_bytes"] = data_bytes
        with meta_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(metadata, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        with manifest_tmp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(
                json.dumps({"generation": generation}, separators=(",", ":")) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        for path in (data_tmp, meta_tmp, manifest_tmp):
            if os.name == "posix":
                path.chmod(0o600)
        os.replace(data_tmp, data_path)
        os.replace(meta_tmp, meta_path)
        os.replace(manifest_tmp, manifest)
    except OSError as exc:
        raise ArtifactError(f"Could not publish semantic overlay: {exc}") from exc
    finally:
        for temporary in (data_tmp, meta_tmp, manifest_tmp):
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                cleanup_failures += 1

    # The manifest replacement above is the commit point. Retention is
    # deliberately fail-soft so a locked old generation (common on Windows)
    # cannot turn a successful commit into a reported failure and unsafe retry.
    try:
        generations = sorted(
            path.name.removeprefix("semantic.").removesuffix(".jsonl")
            for path in root.glob("semantic.*.jsonl")
            if _GENERATION.fullmatch(
                path.name.removeprefix("semantic.").removesuffix(".jsonl")
            )
        )
        for old_generation in generations[:-_RETAIN_GENERATIONS]:
            for old_path in (
                root / f"semantic.{old_generation}.jsonl",
                root / f"semantic.{old_generation}.meta.json",
            ):
                try:
                    old_path.unlink(missing_ok=True)
                except OSError:
                    cleanup_failures += 1
    except OSError:
        cleanup_failures += 1
    metadata["retention_cleanup_state"] = (
        "complete" if cleanup_failures == 0 else "incomplete"
    )
    metadata["retention_cleanup_failure_count"] = cleanup_failures
    return metadata


def publish_tenant_observations(
    tenant_id: str,
    new_observations: tuple[ObservationRecord, ...],
) -> dict[str, Any]:
    """Compatibility wrapper for observation-only publication."""

    return publish_tenant_overlay(tenant_id, observations=new_observations)
