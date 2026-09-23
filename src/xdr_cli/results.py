"""Private, artifact-first storage for data-bearing CLI results."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO, TypeAlias

from xdr_cli.config import get_config_home
from xdr_cli.exceptions import ArtifactError

ARTIFACT_SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 1
DEFAULT_PREVIEW_ROWS = 2
DEFAULT_PREVIEW_BYTE_CAP = 4096


@dataclass(frozen=True)
class ResultReceipt:
    """Compact first stdout record for an artifact-first command."""

    status: str
    schema_version: int
    run_id: str
    data_path: str
    meta_path: str
    rows: int
    server_truncation_state: str
    execution_time_ms: int | None
    session_id: str | None
    session_label: str | None
    session_attachment: str = "unattached"
    incident_id: str | None = None
    alert_id: str | None = None
    context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        if value["context"] is None:
            value.pop("context")
        return value


@dataclass(frozen=True)
class ResultArtifact:
    """Paths, metadata, and bounded previews returned by :func:`write_result`."""

    receipt: ResultReceipt
    metadata: dict[str, Any]
    preview_records: tuple[dict[str, Any], ...]

    def stdout_lines(self) -> list[str]:
        records = [self.receipt.to_dict(), *self.preview_records]
        return [
            json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)
            for record in records
        ]


def _completed_receipt_context(
    context: dict[str, Any] | None,
    *,
    run_id: str,
    row_count: int,
    preview_count: int,
) -> dict[str, Any]:
    """Make artifact-first stdout completeness and local continuation explicit."""

    completed = dict(context or {})
    completed.setdefault("shown", preview_count)
    completed.setdefault("total", row_count)
    completed.setdefault("has_more", row_count > preview_count)
    if row_count > preview_count:
        results_command = f"xdr results rows {run_id} --offset 0 --limit 100"
        completed.setdefault("results_command", results_command)
        completed.setdefault("next_command", results_command)
    return completed


def _new_run_id(now: datetime) -> str:
    stamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}-{secrets.token_hex(6)}"


def tenant_fingerprint(tenant_id: str | None) -> str | None:
    """Return a non-reversible, collision-resistant tenant binding."""

    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return None
    return hashlib.sha256(tenant_id.strip().encode("utf-8")).hexdigest()


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


_ShapeToken: TypeAlias = tuple[str, str]
_ShapePath: TypeAlias = tuple[_ShapeToken, ...]


def _walk_shape(value: Any, prefix: _ShapePath = ()) -> Iterable[tuple[_ShapePath, Any]]:
    if prefix:
        yield prefix, value
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*prefix, ("property", str(key)))
            yield from _walk_shape(child, child_path)
    elif isinstance(value, list):
        item_path = (*prefix, ("array", ""))
        for child in value:
            yield from _walk_shape(child, item_path)


def _legacy_shape_path(path: _ShapePath) -> str:
    rendered = ""
    for kind, value in path:
        if kind == "array":
            rendered += "[]"
        else:
            rendered = f"{rendered}.{value}" if rendered else value
    return rendered


def _shape_pointer(path: _ShapePath) -> str:
    segments = [
        "*" if kind == "array" else value.replace("~", "~0").replace("/", "~1")
        for kind, value in path
    ]
    return "/" + "/".join(segments)


def _update_shape(
    shape: dict[_ShapePath, dict[str, Any]],
    row: dict[str, Any],
) -> None:
    seen_paths: set[_ShapePath] = set()
    for path, value in _walk_shape(row):
        entry = shape.setdefault(
            path,
            {"types": set(), "present_count": 0, "non_null_count": 0},
        )
        entry["types"].add(_json_type(value))
        if path not in seen_paths:
            entry["present_count"] += 1
            if value is not None:
                entry["non_null_count"] += 1
            seen_paths.add(path)


def _finalize_shape(shape: dict[_ShapePath, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            # ``path`` remains for v1 consumers. The token sequence is the
            # lossless form: unlike dotted text it distinguishes object keys
            # containing dots/[] from actual nesting and array traversal.
            "path": _legacy_shape_path(path),
            "path_tokens": [
                {"kind": kind, **({"value": value} if kind == "property" else {})}
                for kind, value in path
            ],
            # Arrays use the schema-graph wildcard extension ``*``.
            "json_pointer": _shape_pointer(path),
            "types": sorted(entry["types"]),
            "present_count": entry["present_count"],
            "non_null_count": entry["non_null_count"],
        }
        for path, entry in sorted(shape.items())
    ]


def _private_directory(path: Path) -> None:
    try:
        config_home = get_config_home()
        results_root = config_home / "results"
        for directory in (config_home, results_root, path):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name == "posix":
                directory.chmod(0o700)
    except OSError as exc:
        raise ArtifactError(
            f"Cannot create private result directory: {exc}",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc


def _private_temp(path: Path):
    try:
        handle = path.open("x", encoding="utf-8", newline="\n")
        if os.name == "posix":
            path.chmod(0o600)
        return handle
    except OSError as exc:
        raise ArtifactError(
            f"Cannot create private result file: {exc}",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc


def _write_json_file(path: Path, value: dict[str, Any]) -> None:
    with _private_temp(path) as handle:
        json.dump(
            value,
            handle,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _merge_extra_metadata(
    metadata: dict[str, Any], extra_metadata: dict[str, Any] | None
) -> None:
    if not extra_metadata:
        return
    collisions = metadata.keys() & extra_metadata.keys()
    if collisions:
        raise ValueError(
            f"extra result metadata cannot replace contract keys: {sorted(collisions)}"
        )
    metadata.update(extra_metadata)


class ResultStreamWriter:
    """Incrementally build one atomic result bundle without buffering rows."""

    def __init__(
        self,
        *,
        command: str,
        server_truncation_state: str = "unknown",
        session_id: str | None = None,
        session_label: str | None = None,
        session_attachment: str = "unattached",
        incident_id: str | None = None,
        alert_id: str | None = None,
        anchor_provenance: dict[str, str] | None = None,
        query: str | None = None,
        library_entry: str | None = None,
        resolved_parameters: dict[str, Any] | None = None,
        source_hash: str | None = None,
        extra_metadata: dict[str, Any] | None = None,
        receipt_context: dict[str, Any] | None = None,
        preview_rows: int = DEFAULT_PREVIEW_ROWS,
        preview_byte_cap: int = DEFAULT_PREVIEW_BYTE_CAP,
        now: datetime | None = None,
        tenant_id: str | None = None,
        physical_lineage_table: str | None = None,
    ) -> None:
        if server_truncation_state not in {
            "known-complete",
            "known-truncated",
            "unknown",
        }:
            raise ValueError(
                "server_truncation_state must be known-complete, "
                "known-truncated, or unknown"
            )
        if preview_rows < 0:
            raise ValueError("preview_rows must be non-negative")
        if preview_byte_cap < 1:
            raise ValueError("preview_byte_cap must be positive")

        self.command = command
        self.server_truncation_state = server_truncation_state
        self.session_id = session_id
        self.session_label = session_label
        self.session_attachment = session_attachment
        self.incident_id = incident_id
        self.alert_id = alert_id
        self.anchor_provenance = dict(anchor_provenance or {})
        self.query = query
        self.library_entry = library_entry
        self.resolved_parameters = resolved_parameters or {}
        self.source_hash = source_hash
        self.extra_metadata = extra_metadata or {}
        self.receipt_context = receipt_context or None
        self.preview_rows = preview_rows
        self.preview_byte_cap = preview_byte_cap
        self.created = (now or datetime.now(UTC)).astimezone(UTC)
        self.tenant_id = tenant_id
        self.physical_lineage_table = physical_lineage_table
        self.run_id = _new_run_id(self.created)
        self.result_dir = (
            get_config_home() / "results" / self.created.strftime("%Y-%m-%d")
        )
        _private_directory(self.result_dir)
        self.data_path = (self.result_dir / f"{self.run_id}.jsonl").resolve()
        self.meta_path = (self.result_dir / f"{self.run_id}.meta.json").resolve()
        self.data_tmp = self.result_dir / f".{self.run_id}.jsonl.tmp"
        self.meta_tmp = self.result_dir / f".{self.run_id}.meta.json.tmp"
        self._handle: TextIO = _private_temp(self.data_tmp)
        self._shape: dict[_ShapePath, dict[str, Any]] = {}
        self._previews: list[dict[str, Any]] = []
        self._row_count = 0
        self._max_row_bytes = 0
        self._data_hasher = hashlib.sha256()
        self._promoted: list[Path] = []
        self._finished = False

    def __enter__(self) -> ResultStreamWriter:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if not self._finished:
            self.abort()

    def write_row(self, row: dict[str, Any]) -> None:
        if self._finished:
            raise RuntimeError("result stream is already finalized")
        if not isinstance(row, dict):
            raise TypeError("artifact rows must be JSON objects")
        serialized = json.dumps(
            row,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        normalized = json.loads(serialized)
        row_bytes = len(serialized.encode("utf-8"))
        self._handle.write(serialized)
        self._handle.write("\n")
        self._data_hasher.update(serialized.encode("utf-8") + b"\n")
        self._row_count += 1
        self._max_row_bytes = max(self._max_row_bytes, row_bytes)
        _update_shape(self._shape, normalized)
        if len(self._previews) < self.preview_rows:
            if row_bytes <= self.preview_byte_cap:
                self._previews.append(normalized)
            else:
                self._previews.append(
                    {
                        "record_type": "preview_omitted",
                        "row_number": self._row_count,
                        "size_bytes": row_bytes,
                        "reason": "row_exceeds_preview_byte_cap",
                    }
                )

    def finish(self, *, execution_time_ms: int | None = None) -> ResultArtifact:
        if self._finished:
            raise RuntimeError("result stream is already finalized")
        try:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()
            query_hash = (
                hashlib.sha256(self.query.encode("utf-8")).hexdigest()
                if self.query is not None
                else None
            )
            metadata: dict[str, Any] = {
                "schema_version": ARTIFACT_SCHEMA_VERSION,
                "run_id": self.run_id,
                "command": self.command,
                "created_at": self.created.isoformat().replace("+00:00", "Z"),
                "data_path": str(self.data_path),
                "meta_path": str(self.meta_path),
                "row_count": self._row_count,
                "observed_shape": _finalize_shape(self._shape),
                "maximum_serialized_row_bytes": self._max_row_bytes,
                "data_sha256": self._data_hasher.hexdigest(),
                "execution_time_ms": execution_time_ms,
                "server_truncation_state": self.server_truncation_state,
                "session": {
                    "id": self.session_id,
                    "label": self.session_label,
                    "attachment": self.session_attachment,
                },
                "anchors": {
                    "incident_id": self.incident_id,
                    "alert_id": self.alert_id,
                    "provenance": self.anchor_provenance,
                },
                "library_entry": self.library_entry,
                "resolved_parameters": self.resolved_parameters,
                "query": self.query,
                "query_sha256": query_hash,
                "source_hash": self.source_hash,
                "physical_lineage": (
                    {"kind": "physical", "table": self.physical_lineage_table}
                    if self.physical_lineage_table is not None
                    else {"kind": "unknown", "table": None}
                ),
                "tenant_binding": {
                    "state": "bound" if tenant_fingerprint(self.tenant_id) else "unbound",
                    "sha256": tenant_fingerprint(self.tenant_id),
                },
            }
            _merge_extra_metadata(metadata, self.extra_metadata)
            _ingest_shape_if_attributed(
                metadata,
                tenant_id=self.tenant_id,
                physical_lineage_table=self.physical_lineage_table,
            )
            _write_json_file(self.meta_tmp, metadata)
            os.replace(self.data_tmp, self.data_path)
            self._promoted.append(self.data_path)
            os.replace(self.meta_tmp, self.meta_path)
            self._promoted.append(self.meta_path)
            self._finished = True
            receipt = ResultReceipt(
                status="success",
                schema_version=RECEIPT_SCHEMA_VERSION,
                run_id=self.run_id,
                data_path=str(self.data_path),
                meta_path=str(self.meta_path),
                rows=self._row_count,
                server_truncation_state=self.server_truncation_state,
                execution_time_ms=execution_time_ms,
                session_id=self.session_id,
                session_label=self.session_label,
                session_attachment=self.session_attachment,
                incident_id=self.incident_id,
                alert_id=self.alert_id,
                context=_completed_receipt_context(
                    self.receipt_context,
                    run_id=self.run_id,
                    row_count=self._row_count,
                    preview_count=len(self._previews),
                ),
            )
            return ResultArtifact(
                receipt=receipt,
                metadata=metadata,
                preview_records=tuple(self._previews),
            )
        except Exception as exc:
            self.abort()
            if isinstance(exc, ArtifactError):
                raise
            raise ArtifactError(
                f"Could not finalize result artifact: {exc}",
                original={"type": type(exc).__name__, "message": str(exc)},
            ) from exc

    def abort(self) -> None:
        if not self._handle.closed:
            self._handle.close()
        for path in (self.data_tmp, self.meta_tmp, *self._promoted):
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)
        self._finished = True


def write_result(
    rows: Iterable[dict[str, Any]],
    *,
    command: str,
    execution_time_ms: int | None = None,
    server_truncation_state: str = "unknown",
    session_id: str | None = None,
    session_label: str | None = None,
    session_attachment: str = "unattached",
    incident_id: str | None = None,
    alert_id: str | None = None,
    anchor_provenance: dict[str, str] | None = None,
    query: str | None = None,
    library_entry: str | None = None,
    resolved_parameters: dict[str, Any] | None = None,
    source_hash: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
    receipt_context: dict[str, Any] | None = None,
    preview_rows: int = DEFAULT_PREVIEW_ROWS,
    preview_byte_cap: int = DEFAULT_PREVIEW_BYTE_CAP,
    now: datetime | None = None,
    tenant_id: str | None = None,
    physical_lineage_table: str | None = None,
) -> ResultArtifact:
    """Write data-only JSONL plus a metadata sidecar and return tiny previews.

    Final paths are all-or-nothing. If serialization, fsync, or either rename
    fails, temporary and already-promoted files from this attempt are removed.
    """

    if server_truncation_state not in {"known-complete", "known-truncated", "unknown"}:
        raise ValueError(
            "server_truncation_state must be known-complete, known-truncated, or unknown"
        )
    if preview_rows < 0:
        raise ValueError("preview_rows must be non-negative")
    if preview_byte_cap < 1:
        raise ValueError("preview_byte_cap must be positive")

    created = (now or datetime.now(UTC)).astimezone(UTC)
    run_id = _new_run_id(created)
    result_dir = get_config_home() / "results" / created.strftime("%Y-%m-%d")
    _private_directory(result_dir)

    data_path = (result_dir / f"{run_id}.jsonl").resolve()
    meta_path = (result_dir / f"{run_id}.meta.json").resolve()
    data_tmp = result_dir / f".{run_id}.jsonl.tmp"
    meta_tmp = result_dir / f".{run_id}.meta.json.tmp"

    shape: dict[_ShapePath, dict[str, Any]] = {}
    previews: list[dict[str, Any]] = []
    row_count = 0
    max_row_bytes = 0
    data_hasher = hashlib.sha256()
    promoted: list[Path] = []

    try:
        with _private_temp(data_tmp) as handle:
            for row in rows:
                if not isinstance(row, dict):
                    raise TypeError("artifact rows must be JSON objects")
                serialized = json.dumps(
                    row,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    default=str,
                )
                normalized = json.loads(serialized)
                encoded_bytes = serialized.encode("utf-8")
                row_bytes = len(encoded_bytes)
                handle.write(serialized)
                handle.write("\n")
                data_hasher.update(encoded_bytes + b"\n")
                row_count += 1
                max_row_bytes = max(max_row_bytes, row_bytes)
                _update_shape(shape, normalized)
                if len(previews) < preview_rows:
                    if row_bytes <= preview_byte_cap:
                        previews.append(normalized)
                    else:
                        previews.append(
                            {
                                "record_type": "preview_omitted",
                                "row_number": row_count,
                                "size_bytes": row_bytes,
                                "reason": "row_exceeds_preview_byte_cap",
                            }
                        )
            handle.flush()
            os.fsync(handle.fileno())

        query_hash = (
            hashlib.sha256(query.encode("utf-8")).hexdigest()
            if query is not None
            else None
        )
        metadata: dict[str, Any] = {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "run_id": run_id,
            "command": command,
            "created_at": created.isoformat().replace("+00:00", "Z"),
            "data_path": str(data_path),
            "meta_path": str(meta_path),
            "row_count": row_count,
            "observed_shape": _finalize_shape(shape),
            "maximum_serialized_row_bytes": max_row_bytes,
            "data_sha256": data_hasher.hexdigest(),
            "execution_time_ms": execution_time_ms,
            "server_truncation_state": server_truncation_state,
            "session": {
                "id": session_id,
                "label": session_label,
                "attachment": session_attachment,
            },
            "anchors": {
                "incident_id": incident_id,
                "alert_id": alert_id,
                "provenance": dict(anchor_provenance or {}),
            },
            "library_entry": library_entry,
            "resolved_parameters": resolved_parameters or {},
            "query": query,
            "query_sha256": query_hash,
            "source_hash": source_hash,
            "physical_lineage": (
                {"kind": "physical", "table": physical_lineage_table}
                if physical_lineage_table is not None
                else {"kind": "unknown", "table": None}
            ),
            "tenant_binding": {
                "state": "bound" if tenant_fingerprint(tenant_id) else "unbound",
                "sha256": tenant_fingerprint(tenant_id),
            },
        }
        _merge_extra_metadata(metadata, extra_metadata)

        _ingest_shape_if_attributed(
            metadata,
            tenant_id=tenant_id,
            physical_lineage_table=physical_lineage_table,
        )

        _write_json_file(meta_tmp, metadata)
        os.replace(data_tmp, data_path)
        promoted.append(data_path)
        os.replace(meta_tmp, meta_path)
        promoted.append(meta_path)

        receipt = ResultReceipt(
            status="success",
            schema_version=RECEIPT_SCHEMA_VERSION,
            run_id=run_id,
            data_path=str(data_path),
            meta_path=str(meta_path),
            rows=row_count,
            server_truncation_state=server_truncation_state,
            execution_time_ms=execution_time_ms,
            session_id=session_id,
            session_label=session_label,
            session_attachment=session_attachment,
            incident_id=incident_id,
            alert_id=alert_id,
            context=_completed_receipt_context(
                receipt_context,
                run_id=run_id,
                row_count=row_count,
                preview_count=len(previews),
            ),
        )
        return ResultArtifact(
            receipt=receipt,
            metadata=metadata,
            preview_records=tuple(previews),
        )
    except Exception as exc:
        for path in (data_tmp, meta_tmp, *promoted):
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)
        if isinstance(exc, ArtifactError):
            raise
        raise ArtifactError(
            f"Could not write result artifact: {exc}",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc


def _ingest_shape_if_attributed(
    metadata: dict[str, Any],
    *,
    tenant_id: str | None,
    physical_lineage_table: str | None,
) -> None:
    """Learn structural paths without allowing passive failure to lose results."""

    if tenant_id is None or physical_lineage_table is None:
        return
    try:
        from xdr_cli.schema_graph.ingest import ingest_artifact_shape

        metadata["schema_catalog_ingestion"] = ingest_artifact_shape(
            tenant_id,
            physical_lineage_table,
            metadata,
        )
    except Exception as exc:
        metadata["schema_catalog_ingestion"] = {
            "status": "failed",
            "error_type": type(exc).__name__,
        }


def emit_result(artifact: ResultArtifact) -> None:
    """Write one receipt and at most two preview records to stdout."""

    for line in artifact.stdout_lines():
        print(line)
