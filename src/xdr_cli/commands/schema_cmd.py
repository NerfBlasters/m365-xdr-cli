"""Tenant schema cache backed by the existing sys_schema_probe query."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import tarfile
import tempfile
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from filelock import Timeout as FileLockTimeout

from xdr_cli._lock import exclusive_lock
from xdr_cli.api.hunting import run_query
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.config import get_config_home
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    AuthError,
    ConflictError,
    LocalNotFoundError,
    PartialSuccessError,
    QueryError,
    RateLimitError,
    UsageError,
)
from xdr_cli.exceptions import (
    TimeoutError as XDRTimeoutError,
)
from xdr_cli.queries import load_query, query_source_hash
from xdr_cli.results import emit_result, tenant_fingerprint, write_result
from xdr_cli.schema_graph.bundle import (
    DEFAULT_COLLECTION_SOURCES,
    MAX_COLLECTION_SOURCES,
    _link_no_replace,
    export_bundle,
    import_bundle,
    inspect_bundle,
    validate_collection_checkpoint,
)
from xdr_cli.schema_graph.cache import (
    load_schema_cache_pair,
    migrate_legacy_schema_cache,
    schema_cache_status,
)
from xdr_cli.schema_graph.catalog import exhaustive_probe_targets
from xdr_cli.schema_graph.correlate import correlate_inputs, load_artifact_input
from xdr_cli.schema_graph.diagnostics import build_diagnostics
from xdr_cli.schema_graph.docs import BEGIN_MARKER, END_MARKER, render_semantic_reference
from xdr_cli.schema_graph.effective import (
    EffectiveGraph,
    FieldAvailability,
    compose_effective_graph,
)
from xdr_cli.schema_graph.loader import load_packaged_graph, load_packaged_profile
from xdr_cli.schema_graph.maintenance import maintenance_status, mark_collection_complete
from xdr_cli.schema_graph.model import (
    Cardinality,
    Confidence,
    Direction,
    FieldLocator,
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    ObservationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    empirical_relationship_from_observations,
)
from xdr_cli.schema_graph.model import relationship_id as build_relationship_id
from xdr_cli.schema_graph.normalize import NormalizationError, normalize_value
from xdr_cli.schema_graph.opengraph import export_opengraph
from xdr_cli.schema_graph.overlay import (
    TenantSemanticOverlay,
    load_tenant_overlay,
    publish_tenant_overlay,
    repair_all_local_overlays,
    repair_tenant_overlay,
    schema_evidence_lock,
    tenant_overlay_status,
)
from xdr_cli.schema_graph.probe import (
    PROBE_QUERY_BYTE_LIMIT,
    aggregate_observation,
    bounded_time_column,
    compile_source_sampling_query,
    compile_target_context_query,
    compile_target_probe_batches,
    validate_lookback,
    worst_case_seed_payload_bytes,
)
from xdr_cli.schema_graph.traversal import GraphStep, pivot, table_paths

schema_app = typer.Typer(
    name="schema",
    help=(
        "Maintain the tenant physical-schema cache and semantic graph, inspect "
        "reviewed or empirical identifier routes, and move content-bound local "
        "state. Start with `xdr schema status` and run its `next_command`. Use "
        "`xdr schema collect --plan-only` before collection; inspect routes with "
        "`xdr schema pivot DeviceNetworkEvents.DeviceId` or `xdr schema path "
        "DeviceNetworkEvents CloudAppEvents`. Use `xdr schema refresh` only when "
        "you explicitly need to replace the physical cache. Multi-row receipts "
        "preview two rows; follow `context.results_command` for the complete "
        "local result."
    ),
    no_args_is_help=True,
)
bundle_app = typer.Typer(
    name="bundle",
    help=(
        "Inspect, export, and import portable content-bound schema state. Start "
        "with `xdr schema bundle export FILE.tar.gz`, integrity-check it with "
        "`xdr schema bundle inspect FILE.tar.gz`, then import only into a collision-free "
        "same-tenant home with `xdr schema bundle import FILE.tar.gz --yes`."
    ),
    no_args_is_help=True,
)
schema_app.add_typer(bundle_app)

_CANDIDATE_EVIDENCE_DAYS = 90
_COLLECTION_CHECKPOINT_VERSION = 1
_COLLECTION_RESUME_ID = re.compile(r"collect-[0-9a-f]{24}")


def _cache_paths(tenant_id: str) -> tuple[Path, Path]:
    tenant_key = hashlib.sha256((tenant_id or "default").encode()).hexdigest()[:12]
    root = get_config_home() / "schema" / tenant_key
    try:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if os.name == "posix":
            root.chmod(0o700)
    except OSError as exc:
        raise ArtifactError(
            f"Cannot create private schema cache directory: {exc}",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc
    return root / "schema.jsonl", root / "schema.meta.json"


def _active_cache_paths(tenant_id: str) -> tuple[Path, Path]:
    """Resolve the atomically published cache generation, with legacy fallback."""

    legacy_data, legacy_meta = _cache_paths(tenant_id)
    manifest = legacy_data.parent / "current.json"
    if not manifest.exists():
        return legacy_data, legacy_meta
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
        generation = value["generation"]
        if not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", generation):
            raise ValueError("invalid generation id")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ArtifactError(
            f"Schema cache manifest is unreadable or invalid: {exc}",
            help_command="xdr schema refresh",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc
    root = legacy_data.parent
    return root / f"schema.{generation}.jsonl", root / f"schema.{generation}.meta.json"


def _load_cache(ctx: AppContext) -> tuple[list[dict], dict]:
    data_path, meta_path = _active_cache_paths(ctx.config.tenant_id)
    if not data_path.exists() or not meta_path.exists():
        error = LocalNotFoundError("schema cache", ctx.config.tenant_id or "default")
        error.error_code = "SCHEMA_CACHE_MISSING"
        error.help_command = "xdr schema refresh"
        error.suggestions = [
            {
                "reason": "cache_refresh",
                "message": "xdr schema refresh",
                "confidence": "exact",
            }
        ]
        raise error
    try:
        generation_match = re.fullmatch(r"schema\.([A-Za-z0-9_-]{1,128})\.jsonl", data_path.name)
        rows, metadata = load_schema_cache_pair(
            data_path,
            meta_path,
            expected_generation=(
                generation_match.group(1) if generation_match is not None else None
            ),
        )
        refreshed = datetime.fromisoformat(metadata["refreshed_at"].replace("Z", "+00:00"))
        if refreshed.tzinfo is None:
            refreshed = refreshed.replace(tzinfo=UTC)
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        error = ArtifactError(
            f"Schema cache is unreadable or invalid: {exc}",
            help_command="xdr schema refresh",
            original={"type": type(exc).__name__, "message": str(exc)},
        )
        error.error_code = "SCHEMA_CACHE_INVALID"
        raise error from exc
    age = int((datetime.now(UTC) - refreshed).total_seconds())
    metadata["age_seconds"] = max(0, age)
    metadata["stale"] = age > ctx.config.schema_stale_seconds
    return rows, metadata


def _temporal_column_missing(table: str, *, operation: str) -> ConflictError:
    """Return one stable, actionable precondition error for bounded probes."""

    command = f"xdr schema show {table} --search Time"
    error = ConflictError(
        f"{table} has no cached Timestamp or TimeGenerated column, so {operation} "
        "cannot enforce the requested lookback. These columns bound each table "
        "scan independently and are not correlation keys. Inspect the cached "
        "table and choose a bounded source/target, or refresh after the tenant "
        "schema changes.",
        help_command=command,
        suggestions=[
            {
                "reason": "inspect_temporal_column",
                "message": command,
                "confidence": "exact",
            }
        ],
    )
    error.error_code = "SCHEMA_PROBE_TEMPORAL_COLUMN_MISSING"
    return error


@schema_app.command("refresh")
def schema_refresh(ctx: typer.Context) -> None:
    """Refresh the tenant's table/column cache with one Advanced Hunting call.

    Run this first on a new workstation or tenant, and again when schema output
    reports a stale cache. Next: `xdr schema tables`.

    Example: `xdr schema refresh`
    """
    asyncio.run(_schema_refresh(ctx.obj))


async def _schema_refresh(ctx: AppContext) -> None:
    query = load_query("sys_schema_probe")
    client = XDRClient(
        get_token=AuthManager(ctx.config).get_token,
        timeout=ctx.config.api_timeout,
    )
    try:
        result = await run_query(client, query)
    finally:
        await client.close()
    rows = list(result.results)
    legacy_data, _legacy_meta = _cache_paths(ctx.config.tenant_id)
    root = legacy_data.parent
    generation = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(6)
    data_path = root / f"schema.{generation}.jsonl"
    meta_path = root / f"schema.{generation}.meta.json"
    data_tmp = root / f".{generation}.jsonl.tmp"
    meta_tmp = root / f".{generation}.meta.json.tmp"
    manifest = root / "current.json"
    manifest_tmp = root / f".{generation}.current.tmp"
    try:
        with exclusive_lock(root / ".refresh"):
            data_digest = hashlib.sha256()
            data_bytes = 0
            # Pin LF on every platform because the integrity metadata is computed
            # from the UTF-8 bytes below.  Text-mode CRLF translation would make
            # a Windows refresh fail its own cache validation.
            with data_tmp.open("x", encoding="utf-8", newline="\n") as handle:
                for row in rows:
                    line = json.dumps(row, separators=(",", ":"), default=str) + "\n"
                    handle.write(line)
                    encoded = line.encode("utf-8")
                    data_digest.update(encoded)
                    data_bytes += len(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            metadata = {
                "schema_version": 1,
                "generation": generation,
                "refreshed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "tenant_key": hashlib.sha256(
                    (ctx.config.tenant_id or "default").encode()
                ).hexdigest()[:12],
                "row_count": len(rows),
                "data_sha256": data_digest.hexdigest(),
                "data_bytes": data_bytes,
                "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
                "server_truncation_state": "unknown",
            }
            with meta_tmp.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(metadata, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                data_tmp.chmod(0o600)
                meta_tmp.chmod(0o600)
            os.replace(data_tmp, data_path)
            os.replace(meta_tmp, meta_path)

            # Only this final single-file replace publishes the new pair.
            # A crash before it leaves the prior generation authoritative.
            with manifest_tmp.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps({"generation": generation}, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                manifest_tmp.chmod(0o600)
            os.replace(manifest_tmp, manifest)
            if os.name == "posix":
                data_path.chmod(0o600)
                meta_path.chmod(0o600)
                manifest.chmod(0o600)
    except OSError as exc:
        raise ArtifactError(
            f"Could not refresh the private schema cache: {exc}",
            help_command="xdr schema refresh",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc
    finally:
        data_tmp.unlink(missing_ok=True)
        meta_tmp.unlink(missing_ok=True)
        manifest_tmp.unlink(missing_ok=True)
    emit_result(
        write_result(
            rows,
            command=ctx.invoked_command or "schema refresh",
            server_truncation_state="unknown",
            session_id=ctx.session_id,
            session_label=ctx.session_label,
            session_attachment=ctx.session_attachment,
            incident_id=ctx.anchor_incident,
            alert_id=ctx.anchor_alert,
            anchor_provenance=ctx.anchor_provenance,
            query=query,
            library_entry="sys_schema_probe",
            source_hash=query_source_hash("sys_schema_probe"),
            extra_metadata={
                "schema_cache_path": str(data_path.resolve()),
                "schema_cache_generation": generation,
            },
            receipt_context={"schema_cache_generation": generation},
            tenant_id=ctx.config.tenant_id,
        )
    )


@schema_app.command("tables")
def schema_tables(
    ctx: typer.Context,
    search: str | None = typer.Option(
        None,
        "--search",
        help="Case-insensitive table-name filter, for example `Device`.",
    ),
) -> None:
    """List valid tenant table names from the local cache; never calls the tenant.

    Examples: `xdr schema tables`; `xdr schema tables --search sign`

    Use a returned table with `xdr schema show TABLE` or as either argument to
    `xdr schema path SOURCE_TABLE TARGET_TABLE`.
    """
    app_ctx: AppContext = ctx.obj
    rows, cache = _load_cache(app_ctx)
    tables = sorted({str(row.get("TableName")) for row in rows if row.get("TableName")})
    if search:
        tables = [table for table in tables if search.casefold() in table.casefold()]
    emit_result(
        write_result(
            [{"TableName": table} for table in tables],
            command=app_ctx.invoked_command or "schema tables",
            server_truncation_state=cache.get("server_truncation_state", "unknown"),
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            incident_id=app_ctx.anchor_incident,
            alert_id=app_ctx.anchor_alert,
            anchor_provenance=app_ctx.anchor_provenance,
            extra_metadata={"cache": cache, "search": search},
            receipt_context={
                "cache": {
                    "stale": cache["stale"],
                    "age_seconds": cache["age_seconds"],
                    "refreshed_at": cache["refreshed_at"],
                }
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("show")
def schema_show(
    ctx: typer.Context,
    table: str = typer.Argument(
        help="Exact table from `xdr schema tables`, for example `DeviceNetworkEvents`."
    ),
    search: str | None = typer.Option(
        None,
        "--search",
        help="Case-insensitive column-name filter, for example `Account`.",
    ),
) -> None:
    """List valid columns for one cached tenant table; never calls the tenant.

    Examples: `xdr schema show DeviceNetworkEvents`; `xdr schema show
    EntraIdSignInEvents --search Account`

    Form a field locator as `Table.Column`. Nested JSON locators use an RFC 6901
    pointer, for example `CloudAppEvents.RawEventData#/UserId`.
    """
    app_ctx: AppContext = ctx.obj
    rows, cache = _load_cache(app_ctx)
    table_rows = [
        row for row in rows if str(row.get("TableName", "")).casefold() == table.casefold()
    ]
    if not table_rows:
        error = LocalNotFoundError("schema table", table)
        error.error_code = "SCHEMA_UNKNOWN_TABLE"
        error.help_command = f"xdr schema tables --search {table}"
        error.suggestions = [
            {
                "reason": "schema_discovery",
                "message": f"xdr schema tables --search {table}",
                "confidence": "exact",
            }
        ]
        raise error
    selected = table_rows
    if search:
        selected = [
            row
            for row in selected
            if search.casefold() in str(row.get("ColumnName", "")).casefold()
        ]
    emit_result(
        write_result(
            selected,
            command=app_ctx.invoked_command or "schema show",
            server_truncation_state=cache.get("server_truncation_state", "unknown"),
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            incident_id=app_ctx.anchor_incident,
            alert_id=app_ctx.anchor_alert,
            anchor_provenance=app_ctx.anchor_provenance,
            extra_metadata={"cache": cache, "table": table, "search": search},
            receipt_context={
                "cache": {
                    "stale": cache["stale"],
                    "age_seconds": cache["age_seconds"],
                    "refreshed_at": cache["refreshed_at"],
                },
                "filter": {
                    "table": table,
                    "search": search,
                    "matches": len(selected),
                },
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


def _semantic_graph() -> Graph:
    try:
        return load_packaged_graph()
    except (OSError, GraphValidationError) as exc:
        error = ArtifactError(
            f"Packaged semantic graph is unreadable or invalid: {exc}",
            help_command="python -m pip install --force-reinstall xdr-cli",
            original={"type": type(exc).__name__, "message": str(exc)},
        )
        error.error_code = "SEMANTIC_GRAPH_INVALID"
        raise error from exc


def _compose_effective(
    schema_rows: list[dict],
    *,
    tenant_id: str,
    canonical: Graph,
    overlays: tuple[Graph, ...],
    observations: tuple[ObservationRecord, ...],
) -> EffectiveGraph:
    """Compose tenant state or return an actionable, stable conflict contract."""

    from xdr_cli.schema_graph.compatibility import audit_overlay_compatibility

    for overlay in overlays:
        compatibility = audit_overlay_compatibility(overlay, observations, canonical)
        if compatibility.state == "needs-migration":
            error = ConflictError(
                "The tenant semantic overlay requires compatibility repair before "
                "it can be composed with this build.",
                help_command="xdr schema repair-overlay --yes",
                original={
                    "type": "OverlayCompatibilityError",
                    "state": compatibility.state,
                    "summary": compatibility.to_status_dict(),
                },
            )
            error.error_code = "SCHEMA_OVERLAY_COMPATIBILITY_REQUIRED"
            raise error

    try:
        observed_graph = compose_effective_graph(
            schema_rows,
            canonical=canonical,
            overlays=overlays,
            observations=observations,
        )
        active_observations = []
        sampled_cohorts: dict[
            tuple[str, str, str], list[tuple[ObservationRecord, frozenset[str]]]
        ] = {}
        for observation in observations:
            if observation.outcome != "matched" or observation.matched_seeds < 1:
                continue
            evidence = _eligible_observation_evidence(
                observed_graph.graph,
                observation,
                tenant_id=tenant_id,
            )
            if evidence is None:
                continue
            active_observations.append(observation)
            cohort = evidence.get("sampled_cohort")
            if not isinstance(cohort, frozenset):
                continue
            key = (
                min(
                    observation.source_interpretation,
                    observation.target_interpretation,
                ),
                max(
                    observation.source_interpretation,
                    observation.target_interpretation,
                ),
                observation.transform,
            )
            sampled_cohorts.setdefault(key, []).append((observation, cohort))
        verified_observation_ids = set()
        for items in sampled_cohorts.values():
            cohorts = {cohort for _observation, cohort in items}
            union = {value for cohort in cohorts for value in cohort}
            if len(cohorts) >= 2 and len(union) >= 6:
                verified_observation_ids.update(
                    observation.observation_id for observation, _cohort in items
                )
        return compose_effective_graph(
            schema_rows,
            canonical=canonical,
            overlays=overlays,
            observations=tuple(active_observations),
            verified_observation_ids=frozenset(verified_observation_ids),
        )
    except GraphValidationError as exc:
        error = ConflictError(
            "The tenant semantic overlay conflicts with the packaged graph and "
            f"cannot be composed safely: {exc}. Inspect overlay status and repair "
            "or explicitly reset the tenant overlay before retrying.",
            help_command="xdr schema repair-overlay --help",
            suggestions=[
                {
                    "reason": "inspect_overlay_integrity",
                    "message": "xdr schema status",
                    "confidence": "exact",
                },
                {
                    "reason": "inspect_recovery_options",
                    "message": "xdr schema repair-overlay --help",
                    "confidence": "exact",
                },
            ],
            original={"type": type(exc).__name__, "message": str(exc)},
        )
        error.error_code = "SCHEMA_EFFECTIVE_GRAPH_CONFLICT"
        raise error from exc


def _ensure_overlay_compatible(tenant_id: str) -> None:
    """Fail once, cache-only, before a multi-step collection is started."""

    status = tenant_overlay_status(tenant_id)
    if status["state"] in {"missing", "valid"}:
        return
    if status["state"] in {"needs-migration", "legacy-unbound"}:
        error = ConflictError(
            "The tenant semantic overlay must be upgraded before collection.",
            help_command="xdr schema repair-overlay --yes",
            original={"type": "OverlayCompatibilityError", "status": status},
        )
        error.error_code = "SCHEMA_OVERLAY_COMPATIBILITY_REQUIRED"
        raise error
    error = ArtifactError(
        "The tenant semantic overlay is not safe to use for collection.",
        help_command=status.get("repair_command") or "xdr schema status",
        original={"type": "OverlayStateError", "status": status},
    )
    error.error_code = "SCHEMA_OVERLAY_INVALID"
    raise error


def _rendered_schema_document(document: str, graph: Graph, *, allow_initialize: bool) -> str:
    block = render_semantic_reference(graph)
    begin_count = document.count(BEGIN_MARKER)
    end_count = document.count(END_MARKER)
    if begin_count == end_count == 0:
        if not allow_initialize:
            raise ValueError("generated semantic graph markers are missing")
        separator = "\n\n" if document.endswith("\n") else "\n"
        return document + separator + block + "\n"
    if begin_count != 1 or end_count != 1:
        raise ValueError("expected exactly one generated semantic graph begin/end marker pair")
    begin_at = document.index(BEGIN_MARKER)
    end_at = document.index(END_MARKER)
    if end_at < begin_at:
        raise ValueError("generated semantic graph end marker precedes begin marker")
    prefix, remainder = document.split(BEGIN_MARKER, 1)
    _old, suffix = remainder.split(END_MARKER, 1)
    return prefix + block + suffix


@schema_app.command("validate-core")
def schema_validate_core(
    ctx: typer.Context,
    document: Path | None = typer.Option(
        None,
        "--document",
        help="Also check a generated reference, normally `docs/schema_pivots.md`.",
    ),
    update_document: bool = typer.Option(
        False,
        "--update-document",
        help="Atomically refresh the generated block in `--document`.",
    ),
) -> None:
    """Validate the packaged graph/profile and optionally its generated docs.

    Examples: `xdr schema validate-core`; `xdr schema validate-core --document
    docs/schema_pivots.md`; `xdr schema validate-core --document
    docs/schema_pivots.md --update-document`

    Use this after a human-reviewed edit to the core JSONL. It never contacts a
    tenant and never promotes a candidate automatically.
    """

    app_ctx: AppContext = ctx.obj
    if update_document and document is None:
        raise UsageError(
            "--update-document requires --document PATH.",
            corrected_argv=[
                "xdr",
                "schema",
                "validate-core",
                "--document",
                "docs/schema_pivots.md",
                "--update-document",
            ],
            help_command="xdr schema validate-core --help",
        )
    try:
        graph = load_packaged_graph()
    except (OSError, GraphValidationError) as exc:
        error = ArtifactError(
            f"Core semantic graph validation failed: {exc}",
            help_command=(
                "inspect src/xdr_cli/schema_graph/data/semantic-graph.jsonl, "
                "then rerun xdr schema validate-core"
            ),
        )
        error.error_code = "SEMANTIC_GRAPH_INVALID"
        raise error from exc
    try:
        profile = load_packaged_profile(graph)
    except (OSError, GraphValidationError) as exc:
        error = ArtifactError(
            f"Packaged semantic profile is unreadable or invalid: {exc}",
            help_command="xdr schema validate-core --help",
        )
        error.error_code = "SEMANTIC_PROFILE_INVALID"
        raise error from exc
    records = [record.to_dict() for record in graph.records()]
    serialized = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in records
    )
    document_state = "not-requested"
    document_path = None
    if document is not None:
        document_path = document.expanduser().resolve()
        try:
            current = document_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ArtifactError(
                f"Cannot read semantic reference document: {exc}",
                help_command="xdr schema validate-core --help",
            ) from exc
        try:
            expected = _rendered_schema_document(current, graph, allow_initialize=update_document)
        except ValueError as exc:
            missing = current.count(BEGIN_MARKER) == 0 and current.count(END_MARKER) == 0
            error = ConflictError(
                f"Cannot validate generated semantic graph block in "
                f"{document_path}: {exc}. "
                f"Required markers are {BEGIN_MARKER!r} followed by "
                f"{END_MARKER!r}.",
                help_command=(
                    f"xdr schema validate-core --document {document_path} --update-document"
                    if missing
                    else "xdr schema validate-core --help"
                ),
            )
            error.error_code = (
                "SEMANTIC_DOCUMENT_MARKERS_MISSING"
                if missing
                else "SEMANTIC_DOCUMENT_MARKERS_INVALID"
            )
            raise error from exc
        if current == expected:
            document_state = "current"
        elif not update_document:
            error = ConflictError(
                f"Generated semantic graph block is stale: {document_path}",
                help_command=(
                    f"xdr schema validate-core --document {document_path} --update-document"
                ),
            )
            error.error_code = "SEMANTIC_DOCUMENT_STALE"
            raise error
        else:
            temporary = document_path.with_name(f".{document_path.name}.{secrets.token_hex(6)}.tmp")
            try:
                with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                    handle.write(expected)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, document_path)
            except OSError as exc:
                raise ArtifactError(
                    f"Cannot update semantic reference document: {exc}",
                    help_command="xdr schema validate-core --help",
                ) from exc
            finally:
                temporary.unlink(missing_ok=True)
            document_state = "updated"
    row = {
        "GraphState": "valid",
        "GraphSha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "Fields": len(graph.fields),
        "Interpretations": len(graph.interpretations),
        "Relationships": len(graph.relationships),
        "Profile": profile["id"],
        "ProfileFields": len(profile["field_ids"]),
        "Document": str(document_path) if document_path else None,
        "DocumentState": document_state,
    }
    emit_result(
        write_result(
            [row],
            command=app_ctx.invoked_command or "schema validate-core",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={"value_free": True},
            receipt_context=row,
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("status")
def schema_status(ctx: typer.Context) -> None:
    """Inspect physical cache, overlay compatibility, and collection state locally.

    Example: `xdr schema status`

    This never authenticates or runs KQL. It reports physical-cache state,
    overlay integrity and compatibility separately, observation eligibility,
    passive-ingestion outcomes, 90-day observation-horizon counts, and the
    collection marker. Run its exact
    `next_command`; recovery may require `xdr schema repair-overlay --yes` or
    `xdr schema migrate-cache --yes` before collection.
    """

    app_ctx: AppContext = ctx.obj
    status = maintenance_status(
        app_ctx.config.tenant_id,
        cache_stale_seconds=app_ctx.config.schema_stale_seconds,
        collection_stale_seconds=app_ctx.config.schema_collection_stale_seconds,
    )
    emit_result(
        write_result(
            [status],
            command=app_ctx.invoked_command or "schema status",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={"value_free": True},
            receipt_context={
                "due": status["due"],
                "reasons": status["reasons"],
                "next_command": status["next_command"],
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("diagnostics")
def schema_diagnostics(ctx: typer.Context) -> None:
    """Show build identity, capabilities, and cache-only automation state.

    Example: `xdr schema diagnostics`

    Reports the package version, source commit when detectable, registered
    schema capabilities, and the same maintenance summary as `xdr schema
    status`. It never authenticates or runs KQL.
    """

    app_ctx: AppContext = ctx.obj
    maintenance = maintenance_status(
        app_ctx.config.tenant_id,
        cache_stale_seconds=app_ctx.config.schema_stale_seconds,
        collection_stale_seconds=app_ctx.config.schema_collection_stale_seconds,
    )
    row = build_diagnostics(maintenance)
    emit_result(
        write_result(
            [row],
            command=app_ctx.invoked_command or "schema diagnostics",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={"value_free": True},
            receipt_context={
                "package_version": row["package_version"],
                "source_commit": row["source_commit"],
                "capabilities": len(row["schema_capabilities"]),
                "next_command": maintenance["next_command"],
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("repair-overlay")
def schema_repair_overlay(
    ctx: typer.Context,
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help=(
            "Confirm selecting a valid generation and, when required, publishing "
            "a compatible migrated replacement."
        ),
    ),
    all_local: bool = typer.Option(
        False,
        "--all-local",
        help="Repair every local tenant overlay, including orphaned generations.",
    ),
    reset_empty: bool = typer.Option(
        False,
        "--reset-empty",
        help=(
            "If no generation is valid, preserve all files in quarantine and "
            "activate an empty verified overlay."
        ),
    ),
) -> None:
    """Repair integrity and migrate compatible legacy semantic-overlay state.

    Examples: `xdr schema repair-overlay --yes`; `xdr schema repair-overlay
    --all-local --yes`; `xdr schema repair-overlay --reset-empty --yes`

    Inspect first with `xdr schema status`. This command never contacts the
    tenant or reads result-row values. It selects the newest structurally valid
    retained generation. A compatible pre-digest generation receives an exact
    byte binding. Contract drift causes the exact prior overlay files to be
    quarantined before a new generation is atomically published: compatible
    records are retained, obsolete provisional interpretations and dependent
    observations are inactivated, and unsafe legacy nested fields are excluded.
    Reviewed contract conflicts fail closed without changing the active state.
    Use `--reset-empty` only when every retained generation is invalid.
    """

    app_ctx: AppContext = ctx.obj
    if not yes:
        raise UsageError(
            "Overlay repair requires --yes because it can select an older retained "
            "generation or publish a migrated replacement.",
            corrected_argv=[
                "xdr",
                "schema",
                "repair-overlay",
                *(["--all-local"] if all_local else []),
                *(["--reset-empty"] if reset_empty else []),
                "--yes",
            ],
            help_command="xdr schema repair-overlay --help",
        )
    try:
        repaired_rows = (
            list(repair_all_local_overlays(reset_empty=reset_empty))
            if all_local
            else [repair_tenant_overlay(app_ctx.config.tenant_id, reset_empty=reset_empty)]
        )
    except ArtifactError as exc:
        exc.error_code = "SCHEMA_OVERLAY_REPAIR_FAILED"
        if exc.help_command is None:
            exc.help_command = "xdr schema repair-overlay --help"
        raise
    if not repaired_rows:
        raise ArtifactError(
            "No local tenant semantic overlays were found to repair.",
            help_command="xdr schema status",
        )
    next_commands = sorted({row["next_command"] for row in repaired_rows})
    emit_result(
        write_result(
            repaired_rows,
            command=app_ctx.invoked_command or "schema repair-overlay",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={"value_free": True},
            receipt_context={
                "repaired_overlays": len(repaired_rows),
                "reset_overlays": sum(bool(row.get("reset_empty")) for row in repaired_rows),
                "next_commands": next_commands,
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("migrate-cache")
def schema_migrate_cache(
    ctx: typer.Context,
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Confirm locally binding the exact bytes of a validated legacy cache.",
    ),
) -> None:
    """Content-bind a valid pre-digest physical schema cache; cache-only.

    Example: `xdr schema migrate-cache --yes`

    Run `xdr schema status` first. The command validates generation and tenant
    identity, JSON-object rows, and row count; copies the old metadata to the
    reported private quarantine directory; and records SHA-256 and byte count
    over the exact existing JSONL. It never authenticates, runs KQL, or changes
    cached row bytes. Partial or incorrect digest metadata is corruption and
    requires `xdr schema refresh` instead.
    """

    app_ctx: AppContext = ctx.obj
    if not yes:
        raise UsageError(
            "Physical cache migration requires --yes because it replaces active "
            "metadata after preserving the original in quarantine.",
            corrected_argv=["xdr", "schema", "migrate-cache", "--yes"],
            help_command="xdr schema migrate-cache --help",
        )
    legacy_data, _legacy_meta = _cache_paths(app_ctx.config.tenant_id)
    root = legacy_data.parent
    tenant_key = hashlib.sha256((app_ctx.config.tenant_id or "default").encode()).hexdigest()[:12]
    status = schema_cache_status(root, expected_tenant_key=tenant_key)
    if status["state"] == "missing":
        error = LocalNotFoundError("schema cache", app_ctx.config.tenant_id or "default")
        error.error_code = "SCHEMA_CACHE_MISSING"
        error.help_command = "xdr schema refresh"
        raise error
    if status["state"] == "invalid":
        error = ArtifactError(
            f"Legacy schema cache cannot be migrated safely: {status.get('error')}",
            help_command="xdr schema refresh",
        )
        error.error_code = "SCHEMA_CACHE_INVALID"
        raise error
    try:
        with exclusive_lock(root / ".refresh"):
            row = migrate_legacy_schema_cache(root, expected_tenant_key=tenant_key)
    except FileLockTimeout as exc:
        raise ConflictError(
            "The physical schema cache is being refreshed or migrated. Retry after "
            "the active command finishes.",
            retryable=True,
            help_command="xdr schema status",
        ) from exc
    except (OSError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        error = ArtifactError(
            f"Legacy schema cache cannot be migrated safely: {exc}",
            help_command="xdr schema refresh",
            original={"type": type(exc).__name__, "message": str(exc)},
        )
        error.error_code = "SCHEMA_CACHE_INVALID"
        raise error from exc
    emit_result(
        write_result(
            [row],
            command=app_ctx.invoked_command or "schema migrate-cache",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={"value_free": True},
            receipt_context={
                "state": row["state"],
                "generation": row["generation"],
                "next_command": "xdr schema status",
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


def _emit_bundle_result(app_ctx: AppContext, row: dict[str, Any], command: str) -> None:
    emit_result(
        write_result(
            [row],
            command=app_ctx.invoked_command or command,
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={"value_free": True},
            receipt_context={
                "state": row.get("state", "integrity-checked"),
                "next_command": row.get("next_command", "xdr schema status"),
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@bundle_app.command("inspect")
def schema_bundle_inspect(ctx: typer.Context, archive: Path) -> None:
    """Integrity-check and summarize a bundle without activation or auth.

    Example: `xdr schema bundle inspect /mnt/transfer/schema-state.tar.gz`

    Streams and validates the exact portable-member allowlist, 256 MiB
    per-member and aggregate uncompressed limits, SHA-256 bindings,
    source-build metadata, and tenant identity. This proves integrity, not who
    authored the unsigned archive. Foreign-tenant bundles remain inspectable
    but are never activation-eligible.
    """

    try:
        inspected = inspect_bundle(archive, retain_files=False)
    except (OSError, ValueError, tarfile.TarError) as exc:
        error = ArtifactError(
            f"Schema bundle is unreadable or invalid: {exc}",
            suggestions=[
                {
                    "reason": "recovery",
                    "message": (
                        "Recreate the archive with `xdr schema bundle export`; "
                        "do not import a bundle that fails inspection."
                    ),
                    "confidence": "exact",
                }
            ],
            help_command="xdr schema bundle inspect --help",
            original={"type": type(exc).__name__, "message": str(exc)},
        )
        error.error_code = "SCHEMA_BUNDLE_INVALID"
        raise error from exc
    row = inspected.summary()
    row["path"] = str(archive.resolve())
    row["state"] = "integrity-checked"
    row["next_command"] = shlex.join(["xdr", "schema", "bundle", "import", str(archive), "--yes"])
    _emit_bundle_result(ctx.obj, row, "schema bundle inspect")


@bundle_app.command("export")
def schema_bundle_export(
    ctx: typer.Context,
    output: Path,
    include_evidence: bool = typer.Option(
        True,
        "--include-evidence/--no-include-evidence",
        help=(
            "Include result pairs, candidate reviews, and proposals referenced by "
            "active semantic evidence (default: enabled and required when present)."
        ),
    ),
    include_sessions: bool = typer.Option(
        False,
        "--include-sessions",
        help="Include session JSONL and sequence sidecars, but never active markers.",
    ),
) -> None:
    """Export current same-tenant schema state as a portable tar.gz bundle.

    Examples: `xdr schema bundle export /mnt/transfer/schema-state.tar.gz`;
    `xdr schema bundle export schema-state.tar.gz --include-sessions`

    Includes current and retained physical/semantic generations, manifests,
    maintenance state, and referenced evidence by default. Optional session
    history excludes active markers. Configuration, credentials, cookies,
    locks, and audit logs are never exported. OUTPUT must not already exist.
    """

    app_ctx: AppContext = ctx.obj
    try:
        with schema_evidence_lock(help_command="xdr schema bundle export --help"):
            row = export_bundle(
                get_config_home(),
                app_ctx.config.tenant_id,
                output,
                include_evidence=include_evidence,
                include_sessions=include_sessions,
            )
    except FileExistsError as exc:
        error = ConflictError(
            str(exc),
            help_command="xdr schema bundle export --help",
        )
        error.error_code = "SCHEMA_BUNDLE_COLLISION"
        raise error from exc
    except (OSError, ValueError, tarfile.TarError) as exc:
        error = ArtifactError(
            f"Schema bundle could not be exported: {exc}",
            suggestions=[
                {
                    "reason": "recovery",
                    "message": (
                        "Run `xdr schema status`, resolve the reported local-state "
                        "problem, and retry with a new output path."
                    ),
                    "confidence": "exact",
                }
            ],
            help_command="xdr schema bundle export --help",
            original={"type": type(exc).__name__, "message": str(exc)},
        )
        error.error_code = "SCHEMA_BUNDLE_EXPORT_FAILED"
        raise error from exc
    row["state"] = "exported"
    row["next_command"] = shlex.join(["xdr", "schema", "bundle", "inspect", str(output)])
    _emit_bundle_result(app_ctx, row, "schema bundle export")


@bundle_app.command("import")
def schema_bundle_import(
    ctx: typer.Context,
    archive: Path,
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help=("Confirm import of an integrity-checked same-tenant bundle from a trusted source."),
    ),
) -> None:
    """Import a trusted, integrity-checked same-tenant bundle; cache-only.

    Example: `xdr schema bundle import /mnt/transfer/schema-state.tar.gz --yes`

    The configured tenant fingerprint must exactly match. Import allowlists
    portable paths, refuses every destination collision, relocates and verifies
    evidence/proposal bindings, permits only candidate tenant relationships,
    validates inactive sessions, and rolls back files created by an interrupted
    attempt. Manifest hashes prove integrity, not archive authorship: run
    `xdr schema bundle inspect ARCHIVE` and trust the source. No authentication
    or tenant call occurs.
    """

    if not yes:
        raise UsageError(
            "Schema bundle import requires --yes because it activates local state.",
            corrected_argv=["xdr", "schema", "bundle", "import", str(archive), "--yes"],
            help_command="xdr schema bundle import --help",
        )
    app_ctx: AppContext = ctx.obj
    try:
        with schema_evidence_lock(help_command="xdr schema bundle import --help"):
            row = import_bundle(get_config_home(), app_ctx.config.tenant_id, archive)
    except FileExistsError as exc:
        error = ConflictError(
            str(exc),
            help_command=shlex.join(["xdr", "schema", "bundle", "inspect", str(archive)]),
        )
        error.error_code = "SCHEMA_BUNDLE_COLLISION"
        raise error from exc
    except (OSError, ValueError, tarfile.TarError) as exc:
        error = ArtifactError(
            f"Schema bundle could not be imported: {exc}",
            suggestions=[
                {
                    "reason": "recovery",
                    "message": (
                        "Run the reported `xdr schema bundle inspect` command and "
                        "import only an integrity-checked same-tenant bundle from "
                        "a trusted source."
                    ),
                    "confidence": "exact",
                }
            ],
            help_command=shlex.join(["xdr", "schema", "bundle", "inspect", str(archive)]),
            original={"type": type(exc).__name__, "message": str(exc)},
        )
        error.error_code = "SCHEMA_BUNDLE_IMPORT_FAILED"
        raise error from exc
    _emit_bundle_result(app_ctx, row, "schema bundle import")


def _child_receipts(stdout: str) -> tuple[dict | None, dict | None]:
    """Return the last success and error envelopes emitted by a child command."""

    success = None
    error = None
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        if value.get("status") == "success":
            success = value
        elif value.get("status") == "error":
            error = value
    return success, error


def _sanitized_child_error(receipt: dict | None) -> dict | None:
    """Retain actionable, value-free child failure details for collection reports."""

    if not isinstance(receipt, dict) or not isinstance(receipt.get("error"), dict):
        return None
    error = receipt["error"]
    sanitized = {
        key: error[key]
        for key in ("code", "retryable", "retry_after_seconds", "help_command")
        if error.get(key) is not None
    }
    original = error.get("original")
    if isinstance(original, dict):
        bounded = {
            key: original[key]
            for key in ("type", "failed_batch", "completed_targets")
            if original.get(key) is not None
        }
        if bounded:
            sanitized["details"] = bounded
    return sanitized or None


def _render_collection_command(
    *,
    selected_sources: tuple[str, ...],
    using_default_sources: bool,
    lookback: str,
    samples: int,
    batch_size: int,
    max_targets: int,
    exhaustive: bool,
    timeout: int,
    max_queries_per_page: int,
) -> str:
    """Render a copyable command equivalent to a successful collection plan."""

    arguments = [
        "xdr",
        "schema",
        "collect",
        "--lookback",
        lookback,
        "--samples",
        str(samples),
        "--batch-size",
        str(batch_size),
        "--timeout",
        str(timeout),
        "--max-queries-per-page",
        str(max_queries_per_page),
    ]
    if exhaustive:
        arguments.append("--exhaustive")
    else:
        arguments.extend(("--max-targets", str(max_targets)))
    if not using_default_sources:
        for source in selected_sources:
            arguments.extend(("--source", source))
    return " ".join(arguments)


def _collection_checkpoint_path(tenant_id: str, resume_id: str) -> Path:
    """Return a tenant-bound private checkpoint path for a collection run."""

    if not _COLLECTION_RESUME_ID.fullmatch(resume_id):
        raise UsageError(
            "invalid schema collection resume ID",
            help_command="xdr schema collect --help",
        )
    tenant_key = hashlib.sha256((tenant_id or "default").encode()).hexdigest()[:12]
    root = get_config_home() / "schema" / tenant_key / "collection-checkpoints"
    try:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if os.name == "posix":
            root.chmod(0o700)
    except OSError as exc:
        raise ArtifactError(f"Cannot create schema collection checkpoint directory: {exc}") from exc
    return root / f"{resume_id}.json"


def _write_collection_checkpoint(path: Path, payload: dict[str, Any]) -> None:
    """Atomically publish a private collection checkpoint after every child page."""

    temporary = path.parent / f".{path.name}.{secrets.token_hex(4)}.tmp"
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise ArtifactError(f"Cannot publish schema collection checkpoint: {exc}") from exc


def _load_collection_checkpoint(path: Path, *, tenant_id: str) -> dict[str, Any]:
    """Load a resumable checkpoint and enforce its tenant and shape contract."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        error = LocalNotFoundError("schema collection checkpoint", path.stem)
        error.help_command = "xdr schema collect --help"
        raise error from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"Schema collection checkpoint is unreadable: {exc}") from exc
    expected_tenant = tenant_fingerprint(tenant_id)
    try:
        validate_collection_checkpoint(
            value,
            filename=path.name,
            tenant_hash=expected_tenant,
        )
    except ValueError as exc:
        raise ArtifactError(
            "Schema collection checkpoint failed its tenant or shape contract.",
            help_command="xdr schema collect --plan-only",
        ) from exc
    return value


def _child_continuation_arguments(row: dict[str, Any]) -> list[str] | None:
    """Validate and unwrap one observe continuation emitted by a child receipt."""

    command = row.get("NextCommand")
    if not isinstance(command, str) or not command:
        return None
    try:
        arguments = shlex.split(command)
    except ValueError as exc:
        raise ArtifactError("Schema observe emitted an invalid continuation command.") from exc
    if arguments[:3] != ["xdr", "schema", "observe"]:
        raise ArtifactError("Schema observe emitted an unsafe continuation command.")
    return arguments[1:]


def _run_collection_process(
    argv: list[str],
    *,
    timeout: int,
    env: dict[str, str],
    cwd: Path,
    output_limit: int,
) -> subprocess.CompletedProcess[str]:
    """Run one schema child while retaining at most ``output_limit + 1`` bytes.

    Both pipes are drained concurrently so a noisy child cannot deadlock. As
    soon as either stream crosses the control-output cap, the child is killed;
    excess bytes are discarded rather than buffered in memory or on disk.
    """
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limited = {"stdout": False, "stderr": False}
    kill_lock = threading.Lock()

    def drain(name: str, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                buffer = buffers[name]
                remaining = output_limit + 1 - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(buffer) > output_limit or len(chunk) > remaining:
                    limited[name] = True
                    with kill_lock, contextlib.suppress(OSError):
                        process.kill()
        finally:
            with contextlib.suppress(OSError):
                stream.close()

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        with contextlib.suppress(OSError):
            process.kill()
        process.wait()
        for thread in threads:
            thread.join()
        raise subprocess.TimeoutExpired(
            argv,
            timeout,
            output=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
        ) from exc
    for thread in threads:
        thread.join()
    completed = subprocess.CompletedProcess(
        argv,
        return_code,
        bytes(buffers["stdout"]).decode("utf-8", "replace"),
        bytes(buffers["stderr"]).decode("utf-8", "replace"),
    )
    completed.stdout_limited = limited["stdout"]  # type: ignore[attr-defined]
    completed.stderr_limited = limited["stderr"]  # type: ignore[attr-defined]
    return completed


def _run_collection_child(
    arguments: list[str],
    *,
    app_ctx: AppContext,
    ordinal: int,
    total: int,
) -> dict:
    label = " ".join(arguments[:3])
    if not app_ctx.effective_quiet:
        print(f"[{ordinal:02d}/{total:02d}] RUN  {label}", file=sys.stderr, flush=True)
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["XDR_SCHEMA_MAINTENANCE_CHILD"] = "1"
    started = datetime.now(UTC)
    query_timeout = app_ctx.config.api_timeout
    max_queries = 1
    if "--timeout" in arguments:
        query_timeout = int(arguments[arguments.index("--timeout") + 1])
    if "--max-queries" in arguments:
        max_queries = int(arguments[arguments.index("--max-queries") + 1])
    # Bound startup/auth/shutdown and local artifact work in addition to each
    # child's per-request HTTP timeout. Four hours is the hard safety ceiling
    # even for explicitly large pages; normal defaults resolve to 41 minutes.
    process_timeout = max(60, min(4 * 60 * 60, query_timeout * max_queries + 60))
    output_limit = 1024 * 1024

    try:
        completed = _run_collection_process(
            [sys.executable, "-I", "-m", "xdr_cli", *arguments],
            timeout=process_timeout,
            env=environment,
            cwd=Path(sys.executable).resolve().parent,
            output_limit=output_limit,
        )
        stdout = completed.stdout or ""
        stdout_limited = bool(getattr(completed, "stdout_limited", False)) or (
            len(stdout.encode("utf-8")) > output_limit
        )
        stderr_text = completed.stderr or ""
        stderr_limited = bool(getattr(completed, "stderr_limited", False)) or (
            len(stderr_text.encode("utf-8")) > output_limit
        )
        exit_code = completed.returncode
        if stdout_limited or stderr_limited:
            exit_code = 12
            success_receipt = None
            child_error = {"code": "CHILD_OUTPUT_LIMIT", "retryable": False}
        else:
            success_receipt, error_receipt = _child_receipts(stdout)
            child_error = _sanitized_child_error(error_receipt)
    except subprocess.TimeoutExpired:
        exit_code = 10
        success_receipt = None
        child_error = {"code": "CHILD_PROCESS_TIMEOUT", "retryable": True}
    except OSError:
        exit_code = 1
        success_receipt = None
        child_error = {"code": "CHILD_PROCESS_ERROR", "retryable": True}
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    if not app_ctx.effective_quiet:
        state = "OK" if exit_code == 0 else "FAIL"
        detail = f"exit={exit_code}, {duration_ms / 1000:.1f}s"
        if isinstance(success_receipt, dict) and success_receipt.get("run_id"):
            detail += f", receipt={success_receipt['run_id']}"
        print(
            f"[{ordinal:02d}/{total:02d}] {state:<4} {label} — {detail}",
            file=sys.stderr,
            flush=True,
        )
    context = success_receipt.get("context") if isinstance(success_receipt, dict) else None
    retry_command = "xdr " + " ".join(arguments)
    return {
        "Command": label,
        "Arguments": arguments,
        "ExitCode": exit_code,
        "DurationMs": duration_ms,
        "RunId": (success_receipt.get("run_id") if isinstance(success_receipt, dict) else None),
        "ErrorCode": child_error.get("code") if child_error else None,
        "Retryable": child_error.get("retryable") if child_error else None,
        "HelpCommand": child_error.get("help_command") if child_error else None,
        "RetryCommand": retry_command if exit_code != 0 else None,
        "ErrorDetails": child_error.get("details") if child_error else None,
        "Outcome": context.get("outcome") if isinstance(context, dict) else None,
        "TargetsProbed": (context.get("targets_probed") if isinstance(context, dict) else None),
        "TargetsCompleted": (
            context.get("targets_completed") if isinstance(context, dict) else None
        ),
        "PageComplete": (context.get("page_complete") if isinstance(context, dict) else None),
        "PlanFingerprint": (
            context.get("plan_fingerprint") if isinstance(context, dict) else None
        ),
        "NextCommand": (context.get("next_command") if isinstance(context, dict) else None),
        "QuarantinedTables": (
            context.get("quarantined_tables") if isinstance(context, dict) else None
        ),
        "SchemaGeneration": (
            context.get("schema_cache_generation") if isinstance(context, dict) else None
        ),
    }


def _execute_collection_checkpoint(
    *,
    app_ctx: AppContext,
    resume_id: str,
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
) -> None:
    """Run and checkpoint collection pages until completion or an operational stop."""

    if checkpoint.get("state") == "complete":
        raise ConflictError(
            "This schema collection checkpoint is already complete.",
            help_command="xdr schema discoveries",
        )
    plan = checkpoint["plan"]
    current_semantic_digest = hashlib.sha256(
        "".join(
            json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
            for record in _semantic_graph().records()
        ).encode()
    ).hexdigest()
    if plan.get("semantic_contract_sha256") != current_semantic_digest:
        raise ConflictError(
            "The packaged semantic contract changed after this collection was planned; "
            "the checkpoint was not resumed.",
            help_command="xdr schema collect --plan-only",
        )
    pending = [list(command) for command in checkpoint["pending_commands"]]
    rows = [dict(row) for row in checkpoint["rows"]]
    seen_continuations = set(checkpoint.get("seen_continuations", []))
    using_default_sources = bool(plan["using_default_sources"])
    operational_failure: dict[str, Any] | None = None

    while pending:
        arguments = pending[0]
        row = _run_collection_child(
            arguments,
            app_ctx=app_ctx,
            ordinal=len(rows) + 1,
            total=len(rows) + len(pending),
        )
        rows.append(row)
        is_refresh = arguments == ["schema", "refresh"]
        invalid_refresh_receipt = (
            is_refresh
            and row["ExitCode"] == 0
            and not isinstance(row.get("SchemaGeneration"), str)
        )
        if invalid_refresh_receipt:
            row.update(
                {
                    "ExitCode": 12,
                    "ErrorCode": "SCHEMA_REFRESH_RECEIPT_INVALID",
                    "Retryable": False,
                    "HelpCommand": "xdr schema refresh",
                    "RetryCommand": "xdr schema refresh",
                    "Outcome": "refresh-receipt-invalid",
                }
            )
        elif is_refresh and isinstance(row.get("SchemaGeneration"), str):
            generation = row["SchemaGeneration"]
            plan["schema_generation"] = generation
            for command in pending[1:]:
                if command[:2] == ["schema", "observe"] and "--schema-generation" not in command:
                    command.extend(("--schema-generation", generation))
        is_observe = arguments[:2] == ["schema", "observe"]
        default_unavailable = (
            using_default_sources
            and is_observe
            and row["ErrorCode"] == "SCHEMA_FIELD_UNAVAILABLE"
        )
        quarantined_partial = (
            is_observe
            and row["ErrorCode"] == "PARTIAL_SUCCESS"
            and row["RunId"] is not None
        )
        if default_unavailable:
            row["Outcome"] = "source-unavailable"
            pending.pop(0)
        elif row["ExitCode"] != 0 and not quarantined_partial:
            operational_failure = row
        else:
            continuation = None
            if is_observe and row["PageComplete"] is False:
                continuation = _child_continuation_arguments(row)
                if continuation is None:
                    raise ArtifactError(
                        "An incomplete schema observe page omitted its continuation command."
                    )
                rendered = shlex.join(continuation)
                if rendered in seen_continuations or continuation == arguments:
                    raise ConflictError(
                        "Schema collection refused a repeated observe continuation.",
                        help_command=f"xdr results show {row['RunId']}",
                    )
                seen_continuations.add(rendered)
            if quarantined_partial:
                row["Outcome"] = "completed-with-quarantined-targets"
            if continuation is None:
                pending.pop(0)
            else:
                pending[0] = continuation

        checkpoint.update(
            {
                "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "pending_commands": pending,
                "rows": rows,
                "seen_continuations": sorted(seen_continuations),
                "state": "paused" if operational_failure else "running",
            }
        )
        _write_collection_checkpoint(checkpoint_path, checkpoint)
        if operational_failure is not None:
            break

    skipped = [row for row in rows if row.get("Outcome") == "source-unavailable"]
    empty_sources = [row for row in rows if row.get("Outcome") == "source-no-valid-identifiers"]
    quarantined = [
        row for row in rows if row.get("Outcome") == "completed-with-quarantined-targets"
    ]
    quarantined_tables = sorted(
        {
            str(table)
            for row in quarantined
            for table in (row.get("QuarantinedTables") or [])
        }
    )
    marker_path = None
    if not pending:
        marker_path = mark_collection_complete(
            app_ctx.config.tenant_id,
            {
                "sources": plan["selected_sources"],
                "lookback": plan["lookback"],
                "samples": plan["samples"],
                "batch_size": plan["batch_size"],
                "max_targets": plan["max_targets"],
                "exhaustive": plan["exhaustive"],
                "skipped_unavailable_sources": len(skipped),
                "empty_sources": len(empty_sources),
                "quarantined_tables": quarantined_tables,
            },
        )
        checkpoint.update(
            {
                "state": "complete",
                "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "maintenance_marker": str(marker_path),
            }
        )
        _write_collection_checkpoint(checkpoint_path, checkpoint)

    next_command = (
        "xdr schema discoveries"
        if not pending
        else shlex.join(["xdr", "schema", "collect", "--resume", resume_id])
    )
    artifact = write_result(
        rows,
        command=app_ctx.invoked_command or "schema collect",
        server_truncation_state="known-complete",
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
        session_attachment=app_ctx.session_attachment,
        extra_metadata={
            "resume_id": resume_id,
            "sources": plan["selected_sources"],
            "maintenance_marker": str(marker_path) if marker_path else None,
        },
        receipt_context={
            "resume_id": resume_id,
            "sources": len(plan["selected_sources"]),
            "commands": len(rows),
            "pending_commands": len(pending),
            "skipped_unavailable_sources": len(skipped),
            "empty_sources": len(empty_sources),
            "quarantined_pages": len(quarantined),
            "quarantined_tables": quarantined_tables,
            "collection_outcome": (
                "complete-with-gaps" if quarantined_tables else "complete"
            )
            if not pending
            else "incomplete",
            "failed": 1 if operational_failure else 0,
            "maintenance_complete": marker_path is not None,
            "next_command": next_command,
        },
        tenant_id=app_ctx.config.tenant_id,
    )
    emit_result(artifact)
    if operational_failure is not None:
        raise PartialSuccessError(
            "Schema collection paused after an operational failure; completed pages "
            "and the exact continuation were checkpointed.",
            help_command=next_command,
            original={
                "type": "PartialSchemaCollection",
                "failed_command": operational_failure["Command"],
                "code": operational_failure["ErrorCode"],
                "resume_id": resume_id,
            },
        )


@schema_app.command("collect")
def schema_collect(
    ctx: typer.Context,
    sources: list[str] | None = typer.Option(
        None,
        "--source",
        help=(
            "Reviewed source locator; repeat up to 100 times to replace the defaults. "
            "Discover valid locators with `xdr schema tables` then `xdr schema show TABLE`."
        ),
    ),
    lookback: str = typer.Option(
        "30d",
        "--lookback",
        help="Source/target time window, for example `7d` or `30d`.",
    ),
    samples: int = typer.Option(
        5,
        "--samples",
        min=1,
        max=100,
        help="Rare, valid source identifiers selected per source (1-100; default 5).",
    ),
    batch_size: int = typer.Option(
        20,
        "--batch-size",
        min=1,
        max=50,
        help="Target locators per Advanced Hunting query (1-50; default 20).",
    ),
    max_targets: int = typer.Option(
        40,
        "--max-targets",
        min=1,
        max=10_000,
        help="Targets per source for a bounded routine collection (1-10000; default 40).",
    ),
    exhaustive: bool = typer.Option(
        False,
        "--exhaustive",
        help="Probe every eligible locator for every source; review `--plan-only` first.",
    ),
    timeout: int = typer.Option(
        120,
        "--timeout",
        min=1,
        max=3_600,
        help="Per-query HTTP timeout in seconds (1-3600; default 120).",
    ),
    max_queries_per_page: int = typer.Option(
        20,
        "--max-queries-per-page",
        min=1,
        max=1_000,
        help=(
            "Checkpoint after this many target-table queries (1-1000) and "
            "continue automatically (default 20)."
        ),
    ),
    resume: str | None = typer.Option(
        None,
        "--resume",
        help="Resume an interrupted collection from its tenant-bound checkpoint ID.",
    ),
    plan_only: bool = typer.Option(
        False,
        "--plan-only",
        help="Compile every source plan from the existing cache; make no tenant calls.",
    ),
) -> None:
    """Refresh and collect the value-free tenant graph with one CLI command.

    Discover valid source locators with `xdr schema tables` and `xdr schema
    show DeviceNetworkEvents`.

    Examples: `xdr schema collect --plan-only`; `xdr schema collect`; `xdr
    schema collect --source DeviceNetworkEvents.DeviceId --lookback 7d`; `xdr
    schema collect --plan-only --exhaustive`; `xdr schema collect --resume
    collect-0123456789abcdef01234567`

    A routine run refreshes the curated 80-table physical catalog, then uses
    six reviewed source identifiers to probe up to 40 eligible targets per
    source across every cached table. The six sources are not a target-table
    allowlist. `Timestamp` or `TimeGenerated` bounds each table's lookback;
    normalized identifier values, not timestamps, are matched. Long crawls
    checkpoint between bounded query pages and continue automatically; the
    receipt's `resume_id` restarts the exact pinned plan after interruption. Use
    `--plan-only --exhaustive` to preview all eligible targets,
    or repeated `--source Table.Column` to replace the source matrix. Matches
    become observed investigation pivots, while repeated independent verified
    evidence can validate the pivot. Neither state claims raw join safety or
    seeds another fan-out automatically. Empty
    default sources and tenant-unavailable defaults are recorded explicitly but
    do not fail maintenance; custom-source and operational failures do.
    """

    app_ctx: AppContext = ctx.obj
    if resume is not None:
        resume_conflicts = (
            sources is not None
            or plan_only
            or lookback != "30d"
            or samples != 5
            or batch_size != 20
            or max_targets != 40
            or exhaustive
            or timeout != 120
            or max_queries_per_page != 20
        )
        if resume_conflicts:
            raise UsageError(
                "--resume cannot be combined with collection planning options; "
                "the checkpoint already contains the exact plan",
                help_command="xdr schema collect --help",
            )
        checkpoint_path = _collection_checkpoint_path(app_ctx.config.tenant_id, resume)
        try:
            with exclusive_lock(checkpoint_path):
                checkpoint = _load_collection_checkpoint(
                    checkpoint_path, tenant_id=app_ctx.config.tenant_id
                )
                _ensure_overlay_compatible(app_ctx.config.tenant_id)
                _execute_collection_checkpoint(
                    app_ctx=app_ctx,
                    resume_id=resume,
                    checkpoint_path=checkpoint_path,
                    checkpoint=checkpoint,
                )
        except FileLockTimeout as exc:
            raise ConflictError(
                "Another process is already running this schema collection checkpoint.",
                retryable=True,
                help_command=f"xdr schema collect --resume {resume}",
            ) from exc
        return
    try:
        validate_lookback(lookback)
    except GraphValidationError as exc:
        raise UsageError(str(exc), help_command="xdr schema collect --help") from exc
    if exhaustive and max_targets != 40:
        raise UsageError(
            "choose either --exhaustive or a custom --max-targets value",
            help_command="xdr schema collect --help",
        )
    using_default_sources = sources is None
    selected_sources = tuple(sources or DEFAULT_COLLECTION_SOURCES)
    if len(selected_sources) > MAX_COLLECTION_SOURCES:
        raise UsageError(
            f"schema collection accepts at most {MAX_COLLECTION_SOURCES} sources",
            help_command="xdr schema collect --help",
        )
    if len(selected_sources) != len(set(selected_sources)):
        raise UsageError(
            "schema collection sources must be unique",
            help_command="xdr schema collect --help",
        )
    for source in selected_sources:
        try:
            FieldLocator.parse(source)
        except GraphValidationError as exc:
            raise UsageError(
                f"invalid collection source {source!r}: {exc}",
                help_command="xdr schema show TABLE",
            ) from exc

    _ensure_overlay_compatible(app_ctx.config.tenant_id)
    if plan_only:
        # Planning is cache-only. Fail once with the cache's exact recovery
        # command instead of spawning one failing child for every source.
        _load_cache(app_ctx)

    execution_command = _render_collection_command(
        selected_sources=selected_sources,
        using_default_sources=using_default_sources,
        lookback=lookback,
        samples=samples,
        batch_size=batch_size,
        max_targets=max_targets,
        exhaustive=exhaustive,
        timeout=timeout,
        max_queries_per_page=max_queries_per_page,
    )

    commands: list[list[str]] = []
    if not plan_only:
        commands.append(["schema", "refresh"])
    target_arguments = ["--exhaustive"] if exhaustive else ["--max-targets", str(max_targets)]
    for source in selected_sources:
        commands.append(
            [
                "schema",
                "observe",
                source,
                "--lookback",
                lookback,
                "--samples",
                str(samples),
                "--batch-size",
                str(batch_size),
                "--timeout",
                str(timeout),
                *(
                    ["--max-queries", str(max_queries_per_page)]
                    if not plan_only
                    else []
                ),
                *target_arguments,
                *(["--plan-only"] if plan_only else []),
            ]
        )
    if not plan_only:
        commands.append(["schema", "discoveries"])

    if not plan_only:
        resume_id = f"collect-{secrets.token_hex(12)}"
        checkpoint_path = _collection_checkpoint_path(app_ctx.config.tenant_id, resume_id)
        checkpoint = {
            "schema_version": _COLLECTION_CHECKPOINT_VERSION,
            "tenant_fingerprint": tenant_fingerprint(app_ctx.config.tenant_id),
            "resume_id": resume_id,
            "state": "running",
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "plan": {
                "selected_sources": list(selected_sources),
                "using_default_sources": using_default_sources,
                "lookback": lookback,
                "samples": samples,
                "batch_size": batch_size,
                "max_targets": None if exhaustive else max_targets,
                "exhaustive": exhaustive,
                "timeout": timeout,
                "max_queries_per_page": max_queries_per_page,
                "semantic_contract_sha256": hashlib.sha256(
                    "".join(
                        json.dumps(
                            record.to_dict(),
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                        for record in _semantic_graph().records()
                    ).encode()
                ).hexdigest(),
            },
            "pending_commands": commands,
            "rows": [],
            "seen_continuations": [],
        }
        _write_collection_checkpoint(checkpoint_path, checkpoint)
        if not app_ctx.effective_quiet:
            print(
                f"Schema collection checkpoint {resume_id}; resume with `xdr schema "
                f"collect --resume {resume_id}`.",
                file=sys.stderr,
                flush=True,
            )
        try:
            with exclusive_lock(checkpoint_path):
                _execute_collection_checkpoint(
                    app_ctx=app_ctx,
                    resume_id=resume_id,
                    checkpoint_path=checkpoint_path,
                    checkpoint=checkpoint,
                )
        except FileLockTimeout as exc:
            raise ConflictError(
                "Another process acquired the new schema collection checkpoint.",
                retryable=True,
                help_command=f"xdr schema collect --resume {resume_id}",
            ) from exc
        return

    rows = []
    for ordinal, arguments in enumerate(commands, start=1):
        row = _run_collection_child(
            arguments,
            app_ctx=app_ctx,
            ordinal=ordinal,
            total=len(commands),
        )
        rows.append(row)
        if arguments == ["schema", "refresh"] and row["ExitCode"] != 0:
            break
    skipped = [
        row
        for row in rows
        if using_default_sources
        and row["ExitCode"] != 0
        and row["ErrorCode"] == "SCHEMA_FIELD_UNAVAILABLE"
    ]
    for row in skipped:
        row["Outcome"] = "source-unavailable"
    failed = [row for row in rows if row["ExitCode"] != 0 and row not in skipped]
    empty_sources = [row for row in rows if row.get("Outcome") == "source-no-valid-identifiers"]
    marker_path = None
    if not plan_only and not failed:
        marker_path = mark_collection_complete(
            app_ctx.config.tenant_id,
            {
                "sources": list(selected_sources),
                "lookback": lookback,
                "samples": samples,
                "batch_size": batch_size,
                "max_targets": None if exhaustive else max_targets,
                "exhaustive": exhaustive,
                "skipped_unavailable_sources": len(skipped),
                "empty_sources": len(empty_sources),
            },
        )
    next_command = (
        execution_command
        if plan_only and not failed
        else (
            "xdr schema discoveries"
            if not failed
            else next(
                (
                    row.get("HelpCommand") or row.get("RetryCommand")
                    for row in failed
                    if row.get("HelpCommand") or row.get("RetryCommand")
                ),
                "xdr schema status",
            )
        )
    )
    artifact = write_result(
        rows,
        command=app_ctx.invoked_command or "schema collect",
        server_truncation_state="known-complete",
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
        session_attachment=app_ctx.session_attachment,
        extra_metadata={
            "plan_only": plan_only,
            "sources": list(selected_sources),
            "maintenance_marker": str(marker_path) if marker_path else None,
        },
        receipt_context={
            "plan_only": plan_only,
            "sources": len(selected_sources),
            "commands": len(rows),
            "skipped_unavailable_sources": len(skipped),
            "empty_sources": len(empty_sources),
            "failed": len(failed),
            "maintenance_complete": marker_path is not None,
            "next_command": next_command,
        },
        tenant_id=app_ctx.config.tenant_id,
    )
    emit_result(artifact)
    if failed:
        raise PartialSuccessError(
            "Schema collection finished with failed steps; "
            "successful child artifacts remain saved.",
            help_command=next_command,
            original={
                "type": "PartialSchemaCollection",
                "failed_commands": [row["Command"] for row in failed],
                "failures": [
                    {
                        "command": row["Command"],
                        "code": row["ErrorCode"],
                        "retryable": row["Retryable"],
                        "help_command": row["HelpCommand"] or row["RetryCommand"],
                        "details": row["ErrorDetails"],
                    }
                    for row in failed
                ],
            },
        )


@schema_app.command("export-opengraph")
def schema_export_opengraph(
    ctx: typer.Context,
    output: Path = typer.Argument(
        help="Destination `.json` file, for example `schema-graph.opengraph.json`."
    ),
    include_tenant: bool = typer.Option(
        False,
        "--include-tenant",
        help=(
            "Include this tenant's value-free provisional fields and "
            "observed/validated pivots."
        ),
    ),
    include_candidates: bool = typer.Option(
        False,
        "--include-candidates",
        help="Include unreviewed candidate relationships in the visualization.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing destination file.",
    ),
) -> None:
    """Export value-free schema structure as BloodHound OpenGraph JSON.

    Examples: `xdr schema export-opengraph schema-graph.opengraph.json`; `xdr
    schema export-opengraph current-schema.opengraph.json --include-tenant
    --include-candidates`

    The public graph is exported by default. Add `--include-tenant` for the
    local value-free overlay, including observed/validated pivots, and add
    `--include-candidates` only for unverified hypotheses. Upload the resulting
    generic graph with BloodHound Quick
    Upload, then run a custom query under Explore -> Cypher. Generic imports are
    merged into the graph database and do not create a named graph or saved
    query in Explore. Node IDs lead with their readable schema name because
    BloodHound may use Object ID as the canvas label. No concrete identifier
    values are exported. Usable schema routes carry `traversable=true` for graph
    exploration, but they do not assert an attack-path privilege.
    """

    app_ctx: AppContext = ctx.obj
    graph = _semantic_graph()
    overlay_generation = None
    if include_tenant:
        overlay = load_tenant_overlay(app_ctx.config.tenant_id)
        graph = _compose_effective(
            [],
            tenant_id=app_ctx.config.tenant_id,
            canonical=graph,
            overlays=(overlay.graph,),
            observations=overlay.observations,
        ).graph
        overlay_generation = overlay.metadata.get("generation")
    expanded_output = output.expanduser()
    # Resolve the directory for a stable publication location, but never
    # resolve the final component: with --force that would follow a planted
    # symlink and replace its target rather than the named export entry.
    destination = expanded_output.parent.resolve() / expanded_output.name
    if destination.exists() and not force:
        raise ConflictError(
            f"OpenGraph destination already exists: {destination}",
            help_command="xdr schema export-opengraph --help",
        )
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                export_opengraph(graph, include_candidates=include_candidates),
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o600)
        if force:
            os.replace(temporary, destination)
        else:
            _link_no_replace(temporary, destination)
            temporary.unlink()
    except FileExistsError as exc:
        raise ConflictError(
            f"OpenGraph destination already exists: {destination}",
            help_command="xdr schema export-opengraph --help",
        ) from exc
    except OSError as exc:
        raise ArtifactError(
            f"Could not export OpenGraph file: {exc}",
            original={"type": type(exc).__name__, "message": str(exc)},
        ) from exc
    finally:
        if "temporary" in locals():
            temporary.unlink(missing_ok=True)
    emit_result(
        write_result(
            [
                {
                    "OutputPath": str(destination),
                    "Layer": "public+tenant" if include_tenant else "public",
                    "CandidatesIncluded": include_candidates,
                    "Fields": len(graph.fields),
                    "Relationships": len(graph.relationships),
                }
            ],
            command=app_ctx.invoked_command or "schema export-opengraph",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={
                "output_path": str(destination),
                "value_free": True,
                "include_tenant": include_tenant,
                "include_candidates": include_candidates,
                "tenant_overlay_generation": overlay_generation,
            },
            receipt_context={
                "output_path": str(destination),
                "value_free": True,
                "layer": "public+tenant" if include_tenant else "public",
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


def _locator_availability(effective, locator: str) -> str:
    canonical = str(FieldLocator.parse(locator))
    for record in effective.graph.fields.values():
        if str(record.locator) == canonical:
            return effective.field_availability[record.id].value
    raise GraphValidationError(f"unknown semantic field locator: {locator}")


def _semantic_step_row(step: GraphStep, ordinal: int) -> dict:
    workflow = (
        "direct-join"
        if step.relationship.value == "join-compatible"
        else "sequential-query-extract-query"
    )
    return {
        "Step": ordinal,
        "Source": step.source_locator,
        "Target": step.target_locator,
        "Relationship": step.relationship.value,
        "RelationshipDirection": step.relationship_direction,
        "TraversalDirection": step.traversal_direction,
        "Workflow": workflow,
        "Transform": step.transform,
        "Cardinality": step.cardinality,
        "TemporalGuidance": step.temporal,
        "Confidence": step.confidence,
        "Provenance": list(step.provenance),
        "SourceEntityKind": step.source_entity_kind,
        "SourceNamespace": step.source_namespace,
        "SourceRole": step.source_role,
        "TargetEntityKind": step.target_entity_kind,
        "TargetNamespace": step.target_namespace,
        "TargetRole": step.target_role,
        "EvidenceLevel": step.evidence_level,
        "Observed": step.evidence_level == "observed",
        "Validated": step.evidence_level in {"validated", "reviewed"},
        "JoinSafe": step.relationship is RelationshipKind.JOIN_COMPATIBLE,
        "Candidate": step.candidate,
        "SourceAvailable": step.source_available,
        "TargetAvailable": step.target_available,
        "SourceAvailability": step.source_availability,
        "TargetAvailability": step.target_availability,
        "RelationshipId": step.relationship_id,
    }


def _semantic_receipt_context(cache: dict, **extra) -> dict:
    return {
        "cache": {
            "stale": cache["stale"],
            "age_seconds": cache["age_seconds"],
            "refreshed_at": cache["refreshed_at"],
        },
        **extra,
    }


def _interpretation_for_locator(graph: Graph, locator: str) -> InterpretationRecord:
    canonical = str(FieldLocator.parse(locator))
    matches = [
        item
        for item in graph.interpretations.values()
        if str(graph.fields[item.field_id].locator) == canonical
    ]
    if len(matches) != 1:
        detail = "unknown" if not matches else "polymorphic"
        raise GraphValidationError(f"{detail} semantic field locator: {canonical}")
    return matches[0]


def _seed_lines(value: str) -> list[str]:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines or len(lines) > 100:
        raise GraphValidationError("seed input must contain between 1 and 100 non-empty lines")
    return lines


def _ordered_normalized_values(
    values: list[object],
    normalizer: str,
    *,
    limit: int | None = None,
) -> tuple[list[str], int]:
    """Normalize and deduplicate values without discarding ranked input order."""

    selected: list[str] = []
    seen: set[str] = set()
    rejected = 0
    for value in values:
        try:
            normalized = normalize_value(normalizer, value)
        except NormalizationError:
            rejected += 1
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        selected.append(normalized)
        if limit is not None and len(selected) == limit:
            break
    return selected, rejected


def _verified_schema_artifact(
    run_id: str | None, *, tenant_id: str | None = None
) -> tuple[dict, list[dict]] | None:
    if run_id is None:
        return None
    root = (get_config_home() / "results").resolve()
    matches = list(root.glob(f"*/{run_id}.meta.json"))
    if len(matches) != 1:
        return None
    try:
        meta_path = matches[0].resolve()
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        data_path = Path(metadata["data_path"]).resolve()
        if (
            metadata.get("run_id") != run_id
            or Path(metadata["meta_path"]).resolve() != meta_path
            or not data_path.is_relative_to(root)
            or data_path.parent != meta_path.parent
            or data_path.name != f"{run_id}.jsonl"
        ):
            return None
        raw = data_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != metadata.get("data_sha256"):
            return None
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if any(not isinstance(row, dict) for row in rows):
            return None
        if metadata.get("row_count") != len(rows):
            return None
        if tenant_id is not None:
            binding = metadata.get("tenant_binding")
            if not isinstance(binding, dict) or binding.get("sha256") != tenant_fingerprint(
                tenant_id
            ):
                return None
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return metadata, rows


def _result_artifact_available(run_id: str | None, *, tenant_id: str | None = None) -> bool:
    return _verified_schema_artifact(run_id, tenant_id=tenant_id) is not None


def _observation_evidence_coordinates(
    graph: Graph, observation: ObservationRecord
) -> tuple[FieldLocator, str, FieldLocator]:
    """Resolve evidence direction from the observation, not canonical edge order."""

    source = graph.interpretations[observation.source_interpretation]
    target = graph.interpretations[observation.target_interpretation]
    return (
        graph.fields[source.field_id].locator,
        source.normalizer,
        graph.fields[target.field_id].locator,
    )


def _observation_artifacts_match(
    observation: ObservationRecord,
    *,
    source_locator: FieldLocator,
    source_normalizer: str,
    target_locator: FieldLocator,
    tenant_id: str,
) -> bool:
    """Verify evidence identity, stage provenance, target, and aggregate counts."""

    source = _verified_schema_artifact(observation.source_artifact_run_id, tenant_id=tenant_id)
    target = _verified_schema_artifact(observation.target_artifact_run_id, tenant_id=tenant_id)
    if source is None or target is None:
        return False
    source_meta, source_rows = source
    target_meta, target_rows = target
    source_stage = source_meta.get("probe_stage")
    bounded_predicates = (
        (
            f"| where Timestamp > ago({observation.lookback})",
            f"| where TimeGenerated > ago({observation.lookback})",
        )
        if observation.lookback is not None
        else ()
    )
    source_window_bound = bool(bounded_predicates) and (
        (
            source_stage == "source-sample"
            and any(
                predicate in str(source_meta.get("query", ""))
                for predicate in bounded_predicates
            )
        )
            or (
                source_stage == "source-explicit"
                and source_meta.get("lookback") == observation.lookback
                and source_meta.get("seed_source") in {"file", "stdin"}
            )
        )
    if (
        source_stage not in {"source-sample", "source-explicit"}
        or source_meta.get("locator") != str(source_locator)
        or source_meta.get("source_interpretation") != observation.source_interpretation
        or source_meta.get("source_normalizer") != source_normalizer
        or target_meta.get("probe_stage") != "target-batch"
        or target_meta.get("source_locator") != str(source_locator)
        or target_meta.get("source_artifact_run_id") != observation.source_artifact_run_id
        or target_meta.get("selected_seed_count") != observation.distinct_seeds
        or not isinstance(target_meta.get("probe_run"), str)
        or not target_meta["probe_run"]
        or not isinstance(target_meta.get("batch"), int)
        or str(target_locator) not in target_meta.get("target_locators", [])
        or not bounded_predicates
        or not source_window_bound
        or not any(
            predicate in str(target_meta.get("query", ""))
            for predicate in bounded_predicates
        )
    ):
        return False
    valid_source_seeds, _rejected = _ordered_normalized_values(
        [row.get("Value") for row in source_rows if row.get("Value") not in (None, "")],
        source_meta["source_normalizer"],
        limit=observation.distinct_seeds,
    )
    if len(valid_source_seeds) < observation.distinct_seeds:
        return False
    matching_rows = [
        row
        for row in target_rows
        if row.get("TargetLocator") == str(target_locator)
        and row.get("TargetInterpretation") == observation.target_interpretation
    ]
    return len(matching_rows) == 1 and (
        matching_rows[0].get("MatchedSeeds") == observation.matched_seeds
        and matching_rows[0].get("MatchRows") == observation.matched_rows
    )


_AUTO_VALIDATION_NAMESPACES = {
    "entra-object-id": "guid-lower",
    "entra-upn": "upn-lower",
    "mde-device-id": "hex40-lower",
    "mde-device-name": "hostname-lower",
    "network-ip": "ip-canonical",
    "network-message-id": "identity",
    "sha256": "sha256-lower",
}


def _identifier_has_entropy(namespace: str, value: str) -> bool:
    """Apply closed namespace-specific shape/entropy gates after normalization."""

    if namespace == "network-message-id":
        return (
            8 <= len(value) <= 512
            and not any(character.isspace() or ord(character) < 32 for character in value)
            and len(set(value.casefold())) >= 4
        )
    if namespace == "mde-device-name":
        return len(value) >= 3 and len(set(value.casefold())) >= 3
    return True


def _eligible_observation_evidence(
    graph: Graph,
    observation: ObservationRecord,
    *,
    tenant_id: str,
) -> dict[str, Any] | None:
    """Reverify one active observation and return its sampled validation cohort."""

    observed_at = _observation_timestamp(observation.observed_at)
    cutoff = datetime.now(UTC) - timedelta(days=_CANDIDATE_EVIDENCE_DAYS)
    if observed_at is None or observed_at < cutoff or observation.lookback is None:
        return None
    try:
        source = graph.interpretations[observation.source_interpretation]
        target = graph.interpretations[observation.target_interpretation]
        source_locator, source_normalizer, target_locator = _observation_evidence_coordinates(
            graph, observation
        )
    except KeyError:
        return None
    if (
        source.namespace != target.namespace
        or source.entity_kind != target.entity_kind
        or source.normalizer != target.normalizer
        or observation.transform != target.normalizer
    ):
        return None
    if not _observation_artifacts_match(
        observation,
        source_locator=source_locator,
        source_normalizer=source_normalizer,
        target_locator=target_locator,
        tenant_id=tenant_id,
    ):
        return None
    source_artifact = _verified_schema_artifact(
        observation.source_artifact_run_id,
        tenant_id=tenant_id,
    )
    if source_artifact is None or source_artifact[0].get("probe_stage") != "source-sample":
        return {"sampled_cohort": None}
    expected_normalizer = _AUTO_VALIDATION_NAMESPACES.get(source.namespace)
    if expected_normalizer != source.normalizer:
        return {"sampled_cohort": None}
    _source_meta, source_rows = source_artifact
    values, _rejected = _ordered_normalized_values(
        [row.get("Value") for row in source_rows if row.get("Value") not in (None, "")],
        source.normalizer,
        limit=observation.distinct_seeds,
    )
    cohort = frozenset(
        value for value in values if _identifier_has_entropy(source.namespace, value)
    )
    if len(cohort) < observation.distinct_seeds:
        return {"sampled_cohort": None}
    return {"sampled_cohort": cohort}


def _candidate_review_artifacts(
    relationship_id: str,
    *,
    tenant_id: str,
    eligible_observations: dict[str, ObservationRecord] | None = None,
    expected_target_locators: dict[str, FieldLocator] | None = None,
) -> list[str]:
    root = get_config_home() / "results"
    expected_tenant = tenant_fingerprint(tenant_id)
    run_ids = []
    for path in root.glob("*/*.meta.json") if root.exists() else ():
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        review = metadata.get("candidate_review")
        binding = metadata.get("tenant_binding")
        observation = (
            eligible_observations.get(review.get("observation_id"))
            if isinstance(review, dict) and eligible_observations is not None
            else None
        )
        if (
            not isinstance(review, dict)
            or review.get("relationship_id") != relationship_id
            or not isinstance(binding, dict)
            or binding.get("sha256") != expected_tenant
            or (eligible_observations is not None and observation is None)
            or (
                observation is not None
                and review.get("source_artifact_run_id") != observation.source_artifact_run_id
            )
            or (
                observation is not None
                and expected_target_locators is not None
                and (
                    (expected_target := expected_target_locators.get(observation.observation_id))
                    is None
                    or review.get("target_locator") != str(expected_target)
                )
            )
        ):
            continue
        run_id = metadata.get("run_id")
        target_locator = review.get("target_locator")
        review_lookback = review.get("lookback")
        bounded_predicates = (
            (
                f"| where Timestamp > ago({review_lookback})",
                f"| where TimeGenerated > ago({review_lookback})",
            )
            if isinstance(review_lookback, str)
            else ()
        )
        if (
            not isinstance(run_id, str)
            or not isinstance(target_locator, str)
            or not bounded_predicates
            or not any(
                predicate in str(metadata.get("query", ""))
                for predicate in bounded_predicates
            )
        ):
            continue
        try:
            target_table = FieldLocator.parse(target_locator).table
            verified = load_artifact_input(target_table, run_id)
        except (ArtifactError, GraphValidationError, LocalNotFoundError, ConflictError):
            continue
        if verified.tenant_fingerprint == expected_tenant and verified.rows:
            run_ids.append(run_id)
    return sorted(set(run_ids))


def _observation_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _initialize_private_probe_debug(path: Path | None) -> None:
    if path is None:
        return
    try:
        with path.open("x", encoding="utf-8", newline="\n"):
            pass
        if os.name == "posix":
            path.chmod(0o600)
    except OSError as exc:
        raise ArtifactError(f"Could not create private probe debug log: {exc}") from exc


def _append_private_probe_debug(path: Path | None, event: dict) -> None:
    if path is None:
        return
    try:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
            handle.flush()
    except OSError as exc:
        raise ArtifactError(f"Could not write private probe debug log: {exc}") from exc


def _estimated_probe_requests(targets: tuple, batch_size: int) -> tuple[int, int]:
    """Return table and lower-bound request counts for a value-free plan."""

    scalar_counts: dict[str, int] = {}
    wildcard_requests = 0
    tables = set()
    for target in targets:
        locator = target.field.locator
        tables.add(locator.table)
        if "*" in locator.json_path:
            wildcard_requests += 1
        else:
            scalar_counts[locator.table] = scalar_counts.get(locator.table, 0) + 1
    requests = wildcard_requests + sum(
        (count + batch_size - 1) // batch_size for count in scalar_counts.values()
    )
    return len(tables), requests


def _narrow_probe_retry_command(
    *,
    source_locator: FieldLocator,
    table: str,
    lookback: str,
    samples: int,
    batch_size: int,
    timeout: int | None,
) -> str:
    arguments = [
        "xdr",
        "schema",
        "observe",
        str(source_locator),
        "--target-table",
        table,
        "--exhaustive",
        "--lookback",
        lookback,
        "--samples",
        str(samples),
        "--batch-size",
        str(batch_size),
    ]
    if timeout is not None:
        arguments.extend(("--timeout", str(timeout)))
    return shlex.join(arguments)


@schema_app.command("observe")
def schema_observe(
    ctx: typer.Context,
    locator: str = typer.Argument(
        help=(
            "Reviewed source locator, such as `DeviceNetworkEvents.DeviceId`; "
            "discover fields with `xdr schema show TABLE`."
        )
    ),
    lookback: str = typer.Option(
        "30d",
        "--lookback",
        help="Source/target time window, for example `7d`, `24h`, or `30d`.",
    ),
    samples: int = typer.Option(
        5,
        "--samples",
        min=1,
        max=100,
        help="Maximum distinct valid source values to test (1-100).",
    ),
    batch_size: int = typer.Option(
        20,
        "--batch-size",
        min=1,
        max=50,
        help="Target locators per Advanced Hunting batch (1-50).",
    ),
    max_targets: int = typer.Option(
        100,
        "--max-targets",
        min=1,
        max=10_000,
        help="Total target cap for a safe routine run (1-10000; default 100).",
    ),
    exhaustive: bool = typer.Option(
        False,
        "--exhaustive",
        help="Probe every eligible locator; review `--plan-only` first.",
    ),
    target_tables: list[str] | None = typer.Option(
        None,
        "--target-table",
        help="Probe only this cached target table; repeat for more tables.",
    ),
    exclude_tables: list[str] | None = typer.Option(
        None,
        "--exclude-table",
        help="Exclude this cached target table and report the coverage gap; repeatable.",
    ),
    timeout: int | None = typer.Option(
        None,
        "--timeout",
        min=1,
        max=3_600,
        help="Per-call HTTP timeout in seconds (1-3600); overrides config.api_timeout.",
    ),
    private_debug_output: Path | None = typer.Option(
        None,
        "--private-debug-output",
        dir_okay=False,
        help="Write sensitive seed/query diagnostics; never commit or share publicly.",
    ),
    plan_only: bool = typer.Option(
        False,
        "--plan-only",
        help="Show the deterministic target plan without authentication or KQL execution.",
    ),
    from_file: Path | None = typer.Option(
        None,
        "--from-file",
        exists=True,
        dir_okay=False,
        help=(
            "Read explicit seed values, one per line; save them in a private, "
            "tenant-bound evidence artifact instead of sampling the source."
        ),
    ),
    from_stdin: bool = typer.Option(
        False,
        "--from-stdin",
        help=(
            "Read explicit seed values from stdin and save them as private, "
            "tenant-bound source evidence."
        ),
    ),
    from_run: str | None = typer.Option(
        None,
        "--from-run",
        help="Reuse the exact tenant-bound source-sample artifact from a prior page.",
    ),
    start_query: int = typer.Option(
        0,
        "--start-query",
        min=0,
        help="Zero-based table-query cursor from a prior receipt (default 0).",
    ),
    max_queries: int | None = typer.Option(
        None,
        "--max-queries",
        min=1,
        max=1_000,
        help="Maximum target table queries to execute in this invocation (1-1000).",
    ),
    schema_generation: str | None = typer.Option(
        None,
        "--schema-generation",
        help="Require the pinned physical-cache generation from a prior page.",
    ),
) -> None:
    """Probe where sampled identifiers recur and save only value-free observations.

    Inspect the deterministic scope without tenant access:
    `xdr schema observe DeviceNetworkEvents.DeviceId --plan-only`

    Run a bounded smoke test:
    `xdr schema observe DeviceNetworkEvents.DeviceId --lookback 30d --samples 5
    --max-targets 40`

    Targets come from eligible string/dynamic locators across every cached
    tenant table, not only the source table. Routine runs stop at 100
    prioritized targets. Use `--plan-only --exhaustive` to inspect full scope,
    then `--exhaustive` to run it. Use repeatable `--target-table TABLE` for a
    narrow retry or `--exclude-table TABLE` for a visible coverage exclusion.
    Completed positive observations are investigation pivots even when another
    target table fails. Inspect evidence state with `xdr schema discoveries`.
    `Timestamp` or `TimeGenerated`
    only bounds each table's independent lookback; normalized identifier values
    are the match key.

    `--from-file seeds.txt` and `--from-stdin` retain normalized seeds in a
    zero-preview private result artifact so later candidate review can verify
    them. Discovery reports flag their operator-supplied origin; those values
    can establish an observed pivot but do not satisfy automatic validation.
    """
    if sum((from_file is not None, from_stdin, from_run is not None)) > 1:
        raise typer.BadParameter("choose only one of --from-file, --from-stdin, or --from-run")
    try:
        validate_lookback(lookback)
    except GraphValidationError as exc:
        raise UsageError(str(exc), help_command="xdr schema observe --help") from exc
    if exhaustive and max_targets != 100:
        raise UsageError(
            "choose either --exhaustive or a custom --max-targets value",
            help_command="xdr schema observe --help",
        )
    selected_target_tables = tuple(target_tables or ())
    selected_exclude_tables = tuple(exclude_tables or ())
    if len(selected_target_tables) != len(set(selected_target_tables)) or len(
        selected_exclude_tables
    ) != len(set(selected_exclude_tables)):
        raise UsageError(
            "schema target-table filters must be unique",
            help_command="xdr schema observe --help",
        )
    overlap = sorted(set(selected_target_tables) & set(selected_exclude_tables))
    if overlap:
        raise UsageError(
            f"target tables cannot be both included and excluded: {overlap}",
            help_command="xdr schema observe --help",
        )
    asyncio.run(
        _schema_observe(
            ctx.obj,
            locator=locator,
            lookback=lookback,
            samples=samples,
            batch_size=batch_size,
            max_targets=None if exhaustive else max_targets,
            target_tables=selected_target_tables,
            exclude_tables=selected_exclude_tables,
            timeout=timeout,
            private_debug_output=private_debug_output,
            plan_only=plan_only,
            from_file=from_file,
            from_stdin=from_stdin,
            from_run=from_run,
            start_query=start_query,
            max_queries=max_queries,
            required_schema_generation=schema_generation,
        )
    )


async def _schema_observe(
    ctx: AppContext,
    *,
    locator: str,
    lookback: str,
    samples: int,
    batch_size: int,
    max_targets: int | None,
    target_tables: tuple[str, ...],
    exclude_tables: tuple[str, ...],
    timeout: int | None,
    private_debug_output: Path | None,
    plan_only: bool,
    from_file: Path | None,
    from_stdin: bool,
    from_run: str | None,
    start_query: int,
    max_queries: int | None,
    required_schema_generation: str | None,
) -> None:
    schema_rows, cache = _load_cache(ctx)
    current_schema_generation = str(cache.get("generation") or "legacy")
    if (
        required_schema_generation is not None
        and required_schema_generation != current_schema_generation
    ):
        raise ConflictError(
            "The physical schema generation changed after the probe page was "
            "planned; no mixed-generation evidence was collected.",
            help_command=f"xdr schema observe {locator} --plan-only --exhaustive",
            original={
                "type": "SchemaProbeGenerationChanged",
                "required_generation": required_schema_generation,
                "current_generation": current_schema_generation,
            },
        )
    tenant_overlay = load_tenant_overlay(ctx.config.tenant_id)
    effective = _compose_effective(
        schema_rows,
        tenant_id=ctx.config.tenant_id,
        canonical=_semantic_graph(),
        overlays=(tenant_overlay.graph,),
        observations=tenant_overlay.observations,
    )
    try:
        source = _interpretation_for_locator(effective.graph, locator)
    except GraphValidationError as exc:
        error = LocalNotFoundError("semantic field", locator)
        error.error_code = "SCHEMA_UNKNOWN_SEMANTIC_FIELD"
        error.help_command = f"xdr schema show {locator.split('.', 1)[0]}"
        raise error from exc
    if source.constraints:
        raise ArtifactError(
            "The source locator has constraints the probe compiler cannot enforce; "
            "choose an unconstrained reviewed source from schema pivot output.",
            help_command=f"xdr schema pivot {locator}",
        )
    if source.extra.get("provisional") is True:
        error = ArtifactError(
            "A tenant-provisional interpretation cannot seed another observation fan-out.",
            help_command="xdr schema discoveries",
        )
        error.error_code = "SCHEMA_PROVISIONAL_SOURCE_REJECTED"
        raise error
    if source.field_id not in effective.queryable_fields:
        error = LocalNotFoundError("tenant schema field", locator)
        error.error_code = "SCHEMA_FIELD_UNAVAILABLE"
        error.help_command = f"xdr schema show {FieldLocator.parse(locator).table}"
        raise error
    available_columns: dict[str, set[str]] = {}
    for row in schema_rows:
        if row.get("TableName") and row.get("ColumnName"):
            available_columns.setdefault(str(row["TableName"]), set()).add(str(row["ColumnName"]))
    source_locator = effective.graph.fields[source.field_id].locator
    if (
        from_file is None
        and not from_stdin
        and bounded_time_column(source_locator.table, available_columns) is None
    ):
        raise _temporal_column_missing(
            source_locator.table,
            operation=f"source sampling with --lookback {lookback}",
        )
    catalog_targets, planned_graph = exhaustive_probe_targets(schema_rows, effective.graph, source)
    unbounded_targets = tuple(
        target
        for target in catalog_targets
        if bounded_time_column(target.field.locator.table, available_columns) is None
    )
    all_targets = tuple(target for target in catalog_targets if target not in unbounded_targets)
    all_targets = tuple(
        sorted(
            all_targets,
            key=lambda target: (
                target.provisional,
                str(target.field.locator),
                target.interpretation.id,
            ),
        )
    )
    cached_tables = set(available_columns)
    unknown_filters = sorted((set(target_tables) | set(exclude_tables)) - cached_tables)
    if unknown_filters:
        raise UsageError(
            f"target table filters are not present in the physical cache: {unknown_filters}",
            help_command="xdr schema tables",
        )
    prefilter_target_count = len(all_targets)
    if target_tables:
        allowed = set(target_tables)
        all_targets = tuple(
            target for target in all_targets if target.field.locator.table in allowed
        )
    if exclude_tables:
        excluded = set(exclude_tables)
        all_targets = tuple(
            target for target in all_targets if target.field.locator.table not in excluded
        )
    targets = all_targets[:max_targets] if max_targets is not None else all_targets
    selected_graph = Graph()
    for target in targets:
        if target.field.id in planned_graph.fields:
            selected_graph.add(target.field)
        if target.interpretation.id in planned_graph.interpretations:
            selected_graph.add(target.interpretation)
    planned_graph = selected_graph
    coverage = "bounded-validation" if max_targets is not None else "exhaustive"
    if target_tables or exclude_tables:
        coverage += "-filtered"
    target_table_count, request_count_estimate = _estimated_probe_requests(targets, batch_size)
    if plan_only:
        plan_rows = [
            {
                "TargetLocator": str(target.field.locator),
                "TargetInterpretation": target.interpretation.id,
                "Provisional": target.provisional,
                "KqlType": target.field.kql_type,
                "QueryByteLimit": PROBE_QUERY_BYTE_LIMIT,
            }
            for target in targets
        ]
        emit_result(
            write_result(
                plan_rows,
                command=ctx.invoked_command or "schema observe --plan-only",
                server_truncation_state="known-complete",
                session_id=ctx.session_id,
                session_label=ctx.session_label,
                session_attachment=ctx.session_attachment,
                extra_metadata={
                    "source_locator": str(source_locator),
                    "target_count": len(targets),
                    "eligible_target_count": len(all_targets),
                    "catalog_target_count": len(catalog_targets),
                    "excluded_unbounded_target_count": len(unbounded_targets),
                    "excluded_filter_target_count": prefilter_target_count - len(all_targets),
                    "target_tables": list(target_tables),
                    "excluded_tables": list(exclude_tables),
                    "target_table_count": target_table_count,
                    "batch_count": request_count_estimate,
                    "request_count_estimate": request_count_estimate,
                    "batch_size": batch_size,
                    "coverage": coverage,
                    "networked": False,
                    "query_byte_limit": PROBE_QUERY_BYTE_LIMIT,
                    "worst_case_seed_payload_bytes": worst_case_seed_payload_bytes(samples),
                },
                receipt_context={
                    "source_locator": str(source_locator),
                    "targets_planned": len(targets),
                    "eligible_targets": len(all_targets),
                    "catalog_targets": len(catalog_targets),
                    "excluded_unbounded_targets": len(unbounded_targets),
                    "excluded_filter_targets": prefilter_target_count - len(all_targets),
                    "target_tables": list(target_tables),
                    "excluded_tables": list(exclude_tables),
                    "tables_planned": target_table_count,
                    "batches_planned": request_count_estimate,
                    "requests_planned": request_count_estimate,
                    "coverage": coverage,
                    "networked": False,
                    "query_byte_limit": PROBE_QUERY_BYTE_LIMIT,
                    "worst_case_seed_payload_bytes": worst_case_seed_payload_bytes(samples),
                },
                tenant_id=ctx.config.tenant_id,
            )
        )
        return
    _initialize_private_probe_debug(private_debug_output)
    client = XDRClient(
        get_token=AuthManager(ctx.config).get_token,
        timeout=timeout if timeout is not None else ctx.config.api_timeout,
    )
    stage_run_ids: list[str] = []
    source_artifact_run_id: str | None = None
    try:
        if from_run is not None:
            verified_source = load_artifact_input(source_locator.table, from_run)
            expected_tenant = tenant_fingerprint(ctx.config.tenant_id)
            if verified_source.tenant_fingerprint != expected_tenant:
                raise ConflictError(
                    "The retained source sample belongs to a different tenant.",
                    help_command=f"xdr results show {from_run}",
                )
            metadata = verified_source.metadata
            probe_stage = metadata.get("probe_stage")
            if (
                probe_stage not in {"source-sample", "source-explicit"}
                or metadata.get("locator") != str(source_locator)
                or metadata.get("source_interpretation") != source.id
                or metadata.get("source_normalizer") != source.normalizer
            ):
                raise ArtifactError(
                    "The retained source sample does not match this probe source contract.",
                    help_command=f"xdr results show {from_run}",
                )
            raw_seeds = [
                str(row["Value"])
                for row in verified_source.rows
                if isinstance(row, dict) and row.get("Value") not in (None, "")
            ]
            seed_source = (
                "sampled"
                if probe_stage == "source-sample"
                else str(metadata.get("seed_source") or "operator-supplied")
            )
            source_artifact_run_id = verified_source.run_id
            stage_run_ids.append(verified_source.run_id)
        elif from_file is not None:
            try:
                raw_seeds = _seed_lines(from_file.read_text(encoding="utf-8"))
            except OSError as exc:
                raise ArtifactError(
                    f"Could not read probe seed file: {exc}",
                    help_command="xdr schema observe --help",
                ) from exc
            except GraphValidationError as exc:
                raise UsageError(
                    f"probe seed file is invalid: {exc}",
                    help_command="xdr schema observe --help",
                ) from exc
            seed_source = "file"
        elif from_stdin:
            try:
                raw_seeds = _seed_lines(sys.stdin.read())
            except GraphValidationError as exc:
                raise UsageError(
                    f"probe seed stdin is invalid: {exc}",
                    help_command="xdr schema observe --help",
                ) from exc
            seed_source = "stdin"
        else:
            compiled = compile_source_sampling_query(
                source,
                source_locator,
                lookback=lookback,
                samples=samples,
                available_columns=available_columns,
            )
            _append_private_probe_debug(
                private_debug_output,
                {
                    "event": "source-query",
                    "source_locator": str(source_locator),
                    "kql": compiled.kql,
                },
            )
            result = await run_query(client, compiled.kql)
            _append_private_probe_debug(
                private_debug_output,
                {
                    "event": "source-result",
                    "source_locator": str(source_locator),
                    "rows": result.results,
                },
            )
            source_artifact = write_result(
                result.results,
                command="schema observe source-sample",
                server_truncation_state="known-complete",
                session_id=ctx.session_id,
                session_label=ctx.session_label,
                session_attachment=ctx.session_attachment,
                query=compiled.kql,
                extra_metadata={
                    "probe_stage": "source-sample",
                    "locator": str(source_locator),
                    "source_interpretation": source.id,
                    "source_normalizer": source.normalizer,
                },
                preview_rows=0,
                tenant_id=ctx.config.tenant_id,
                physical_lineage_table=source_locator.table,
            )
            stage_run_ids.append(source_artifact.receipt.run_id)
            source_artifact_run_id = source_artifact.receipt.run_id
            raw_seeds = [
                str(row["Value"])
                for row in result.results
                if isinstance(row, dict) and row.get("Value") not in (None, "")
            ]
            seed_source = "sampled"

        if seed_source == "sampled":
            seeds, rejected_seed_count = _ordered_normalized_values(
                list(raw_seeds), source.normalizer, limit=samples
            )
        else:
            seeds = []
            seen_seeds = set()
            rejected_seed_count = 0
            for value in raw_seeds:
                try:
                    normalized = normalize_value(source.normalizer, value)
                except NormalizationError as exc:
                    raise UsageError(
                        f"probe seed input is invalid: {exc}",
                        help_command="xdr schema observe --help",
                    ) from exc
                if normalized not in seen_seeds:
                    seen_seeds.add(normalized)
                    seeds.append(normalized)
        if not seeds and seed_source != "sampled":
            raise ArtifactError(
                "Source sampling returned no valid identifier values after normalization; "
                "widen the lookback or choose another reviewed source.",
                help_command=(
                    f"xdr schema observe {source_locator} --lookback 30d --samples 10 --plan-only"
                ),
            )
        if not seeds:
            semantic_metadata = publish_tenant_overlay(
                ctx.config.tenant_id,
                graph=planned_graph,
            )
            emit_result(
                write_result(
                    [],
                    command=ctx.invoked_command or "schema observe",
                    server_truncation_state="known-complete",
                    session_id=ctx.session_id,
                    session_label=ctx.session_label,
                    session_attachment=ctx.session_attachment,
                    incident_id=ctx.anchor_incident,
                    alert_id=ctx.anchor_alert,
                    anchor_provenance=ctx.anchor_provenance,
                    extra_metadata={
                        "source_locator": str(source_locator),
                        "seed_source": seed_source,
                        "seed_count": 0,
                        "rejected_seed_count": rejected_seed_count,
                        "target_count": len(targets),
                        "eligible_target_count": len(all_targets),
                        "catalog_target_count": len(catalog_targets),
                        "excluded_unbounded_target_count": len(unbounded_targets),
                        "coverage": coverage,
                        "batch_count": 0,
                        "completed_batches": 0,
                        "failed_batch": None,
                        "stage_run_ids": stage_run_ids,
                        "semantic_cache": semantic_metadata,
                        "outcome": "source-no-valid-identifiers",
                    },
                    receipt_context={
                        "source_locator": str(source_locator),
                        "outcome": "source-no-valid-identifiers",
                        "seed_count": 0,
                        "rejected_seed_count": rejected_seed_count,
                        "targets_probed": 0,
                        "targets_completed": 0,
                        "matched_targets": 0,
                        "next_command": (
                            f"xdr schema observe {source_locator} --lookback 30d --samples 10"
                        ),
                    },
                    tenant_id=ctx.config.tenant_id,
                )
            )
            return
        if seed_source in {"file", "stdin"}:
            source_artifact = write_result(
                [{"Value": value} for value in seeds],
                command="schema observe source-explicit",
                server_truncation_state="known-complete",
                session_id=ctx.session_id,
                session_label=ctx.session_label,
                session_attachment=ctx.session_attachment,
                extra_metadata={
                    "probe_stage": "source-explicit",
                    "locator": str(source_locator),
                    "source_interpretation": source.id,
                    "source_normalizer": source.normalizer,
                    "seed_source": seed_source,
                    "lookback": lookback,
                },
                preview_rows=0,
                tenant_id=ctx.config.tenant_id,
                physical_lineage_table=source_locator.table,
            )
            stage_run_ids.append(source_artifact.receipt.run_id)
            source_artifact_run_id = source_artifact.receipt.run_id
        _append_private_probe_debug(
            private_debug_output,
            {
                "event": "normalized-seeds",
                "source_locator": str(source_locator),
                "seed_source": seed_source,
                "raw_seed_values": raw_seeds,
                "normalized_seed_values": seeds,
                "rejected_seed_count": rejected_seed_count,
            },
        )
        batches = compile_target_probe_batches(
            [(target.interpretation, target.field.locator) for target in targets],
            seeds,
            lookback=lookback,
            batch_size=batch_size,
            available_columns=available_columns,
        )
        plan_fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "schema_generation": current_schema_generation,
                    "source": str(source_locator),
                    "lookback": lookback,
                    "tasks": [
                        {
                            "task_id": batch.task_id,
                            "table": batch.table,
                            "targets": list(batch.target_locators),
                        }
                        for batch in batches
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if start_query > len(batches):
            raise UsageError(
                f"--start-query {start_query} exceeds the {len(batches)} planned queries",
                help_command=f"xdr schema observe {source_locator} --plan-only --exhaustive",
            )
        query_stop = (
            min(len(batches), start_query + max_queries)
            if max_queries is not None
            else len(batches)
        )
        selected_batches = batches[start_query:query_stop]
        page_target_count = sum(len(batch.target_locators) for batch in selected_batches)
        _append_private_probe_debug(
            private_debug_output,
            {
                "event": "target-plan",
                "batches": [
                    {
                        "batch": number,
                        "target_locators": list(compiled.target_locators),
                        "query_bytes": compiled.query_bytes,
                        "kql": compiled.kql,
                    }
                    for number, compiled in enumerate(batches, start=1)
                ],
            },
        )
        observations = []
        report_rows = []
        schema_generation = str(cache.get("generation") or "legacy")
        probe_run = secrets.token_hex(16)
        observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        failed_batch: dict | None = None
        failed_tasks: list[dict] = []
        completed_batches = 0
        for batch_number, compiled in enumerate(selected_batches, start=start_query + 1):
            try:
                result = await run_query(client, compiled.kql)
            except Exception as exc:
                _append_private_probe_debug(
                    private_debug_output,
                    {
                        "event": "target-error",
                        "batch": batch_number,
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    },
                )
                if isinstance(exc, (AuthError, RateLimitError)):
                    raise
                if not isinstance(exc, (APIError, QueryError, XDRTimeoutError)):
                    raise
                retry_command = _narrow_probe_retry_command(
                    source_locator=source_locator,
                    table=compiled.table,
                    lookback=lookback,
                    samples=samples,
                    batch_size=batch_size,
                    timeout=timeout,
                )
                failure = {
                    "batch": batch_number,
                    "task_id": compiled.task_id,
                    "table": compiled.table,
                    "target_count": len(compiled.target_locators),
                    "target_locators": list(compiled.target_locators),
                    "error_type": type(exc).__name__,
                    "error_code": getattr(exc, "error_code", None),
                    "retryable": getattr(exc, "retryable", False),
                    "retry_command": retry_command,
                }
                failed_tasks.append(failure)
                if failed_batch is None:
                    failed_batch = failure
                continue
            _append_private_probe_debug(
                private_debug_output,
                {
                    "event": "target-result",
                    "batch": batch_number,
                    "target_locators": list(compiled.target_locators),
                    "rows": result.results,
                },
            )
            target_artifact = write_result(
                result.results,
                command="schema observe target-batch",
                server_truncation_state="known-complete",
                session_id=ctx.session_id,
                session_label=ctx.session_label,
                session_attachment=ctx.session_attachment,
                query=compiled.kql,
                extra_metadata={
                    "probe_stage": "target-batch",
                    "probe_run": probe_run,
                    "batch": batch_number,
                    "task_id": compiled.task_id,
                    "target_table": compiled.table,
                    "source_locator": str(source_locator),
                    "source_artifact_run_id": source_artifact_run_id,
                    "selected_seed_count": len(seeds),
                    "target_locators": list(compiled.target_locators),
                    "query_bytes": compiled.query_bytes,
                },
                preview_rows=0,
                tenant_id=ctx.config.tenant_id,
            )
            stage_run_ids.append(target_artifact.receipt.run_id)
            completed_batches += 1
            rows_by_locator: dict[str, dict] = {}
            for row in result.results:
                if not isinstance(row, dict):
                    continue
                target_locator = row.get("TargetLocator")
                expected_interpretation = dict(
                    zip(
                        compiled.target_locators,
                        compiled.interpretation_ids,
                        strict=True,
                    )
                ).get(str(target_locator))
                if (
                    target_locator not in compiled.target_locators
                    or row.get("TargetInterpretation") != expected_interpretation
                    or target_locator in rows_by_locator
                ):
                    continue
                rows_by_locator[str(target_locator)] = row
            target_by_locator = {str(target.field.locator): target for target in targets}
            for target_locator, target_interpretation in zip(
                compiled.target_locators,
                compiled.interpretation_ids,
                strict=True,
            ):
                row = rows_by_locator.get(target_locator)
                matched_seeds = 0
                matched_rows = 0
                outcome = "partial"
                if row is not None:
                    candidate_seeds = row.get("MatchedSeeds", 0)
                    candidate_rows = row.get("MatchRows", 0)
                    if (
                        isinstance(candidate_seeds, int)
                        and not isinstance(candidate_seeds, bool)
                        and isinstance(candidate_rows, int)
                        and not isinstance(candidate_rows, bool)
                        and 0 <= candidate_seeds <= len(seeds)
                        and candidate_rows >= candidate_seeds
                    ):
                        matched_seeds = candidate_seeds
                        matched_rows = candidate_rows
                        outcome = "matched" if matched_seeds else "no-match"
                digest = hashlib.sha256(
                    f"{probe_run}\0{target_interpretation}".encode()
                ).hexdigest()[:24]
                probe_id = f"probe:{digest}"
                target = target_by_locator[target_locator]
                observation = aggregate_observation(
                    observation_id=probe_id,
                    source_interpretation=source.id,
                    target_interpretation=target.interpretation.id,
                    transform=target.interpretation.normalizer,
                    distinct_seeds=len(seeds),
                    matched_seeds=matched_seeds,
                    matched_rows=matched_rows,
                    source_artifact_run_id=source_artifact_run_id,
                    target_artifact_run_id=target_artifact.receipt.run_id,
                    probe_runs=1,
                    provenance=(f"tenant-observation:{digest}",),
                    outcome=outcome,
                    schema_generation=schema_generation,
                    observed_at=observed_at,
                    lookback=lookback,
                )
                observation = replace(
                    observation,
                    extra={
                        "evidence_verified": True,
                        "source_evidence_kind": (
                            "sampled" if seed_source == "sampled" else "operator-supplied"
                        ),
                        "seed_source": seed_source,
                        "probe_task_id": compiled.task_id,
                    },
                )
                observations.append(observation)
        report_rows = [item.to_dict() for item in observations]
        semantic_metadata = publish_tenant_overlay(
            ctx.config.tenant_id,
            graph=planned_graph,
            observations=tuple(observations),
        )
    except Exception as exc:
        _append_private_probe_debug(
            private_debug_output,
            {
                "event": "observe-error",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            },
        )
        raise
    finally:
        await client.close()

    emit_result(
        write_result(
            report_rows,
            command=ctx.invoked_command or "schema observe",
            server_truncation_state="known-complete",
            session_id=ctx.session_id,
            session_label=ctx.session_label,
            session_attachment=ctx.session_attachment,
            incident_id=ctx.anchor_incident,
            alert_id=ctx.anchor_alert,
            anchor_provenance=ctx.anchor_provenance,
            extra_metadata={
                "source_locator": str(source_locator),
                "seed_source": seed_source,
                "seed_count": len(seeds),
                "rejected_seed_count": rejected_seed_count,
                "target_count": len(targets),
                "eligible_target_count": len(all_targets),
                "catalog_target_count": len(catalog_targets),
                "excluded_unbounded_target_count": len(unbounded_targets),
                "coverage": coverage,
                "batch_count": len(batches),
                "completed_batches": completed_batches,
                "failed_batch": failed_batch,
                "failed_tasks": failed_tasks,
                "target_table_count": len({batch.table for batch in batches}),
                "plan_fingerprint": plan_fingerprint,
                "query_start": start_query,
                "query_stop": query_stop,
                "page_complete": query_stop == len(batches),
                "stage_run_ids": stage_run_ids,
                "semantic_cache": semantic_metadata,
            },
            receipt_context={
                "source_locator": str(source_locator),
                "seed_count": len(seeds),
                "rejected_seed_count": rejected_seed_count,
                "targets_probed": page_target_count,
                "targets_completed": len(observations),
                "targets_failed": sum(int(item["target_count"]) for item in failed_tasks),
                "requests_planned": len(batches),
                "requests_completed": completed_batches,
                "requests_failed": len(failed_tasks),
                "query_start": start_query,
                "query_stop": query_stop,
                "page_complete": query_stop == len(batches),
                "plan_fingerprint": plan_fingerprint,
                "quarantined_tables": sorted({str(item["table"]) for item in failed_tasks}),
                "excluded_unbounded_targets": len(unbounded_targets),
                "matched_targets": sum(item.outcome == "matched" for item in observations),
                "warning": (
                    "completed positive observations are usable investigation pivots; "
                    "they do not establish raw join safety"
                ),
                **(
                    {
                        "next_command": shlex.join(
                            [
                                "xdr",
                                "schema",
                                "observe",
                                str(source_locator),
                                "--from-run",
                                str(source_artifact_run_id),
                                "--start-query",
                                str(query_stop),
                                "--schema-generation",
                                current_schema_generation,
                                "--lookback",
                                lookback,
                                "--samples",
                                str(samples),
                                "--batch-size",
                                str(batch_size),
                                *(["--max-queries", str(max_queries)] if max_queries else []),
                                *(
                                    ["--exhaustive"]
                                    if max_targets is None
                                    else ["--max-targets", str(max_targets)]
                                ),
                                *sum((["--target-table", item] for item in target_tables), []),
                                *sum((["--exclude-table", item] for item in exclude_tables), []),
                            ]
                        )
                    }
                    if query_stop < len(batches)
                    else (
                        {"next_command": str(failed_tasks[0]["retry_command"])}
                        if failed_tasks
                        else {}
                    )
                ),
            },
            tenant_id=ctx.config.tenant_id,
        )
    )
    if failed_batch is not None:
        raise PartialSuccessError(
            "Completed schema observations were saved, but one or more target-table "
            "queries were quarantined.",
            original={
                "type": "PartialSchemaObservation",
                "failed_batch": failed_batch,
                "failed_tasks": failed_tasks,
                "completed_targets": len(observations),
                "next_command": failed_tasks[0]["retry_command"],
            },
        )


@schema_app.command("candidate-review")
def schema_candidate_review(
    ctx: typer.Context,
    relationship_id: str = typer.Argument(
        help="Discovery ID from `xdr schema discoveries --include-evidence-refs`."
    ),
    lookback: str | None = typer.Option(
        None,
        "--lookback",
        help="Override the observation window, for example `7d` or `30d`.",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        min=1,
        max=100,
        help="Maximum private target rows to retain (1-100; default 20).",
    ),
    timeout: int | None = typer.Option(
        None,
        "--timeout",
        min=1,
        help="HTTP timeout in seconds; overrides config.api_timeout.",
    ),
) -> None:
    """Optionally collect bounded private context for one empirical pivot.

    Example: `xdr schema candidate-review rel:0123456789abcdef01234567`

    Get a real relationship ID with `xdr schema discoveries
    --include-evidence-refs`. This selects the newest fully verified retained
    source/target evidence pair, falling back past corrupt newer bundles, runs
    one bounded target query, saves rows privately with no stdout preview, and
    returns an `xdr results head RUN_ID` inspection command. This is optional
    analyst context: automatic observed/validated decisions do not depend on it,
    and it never changes join safety or core graph status.
    """

    asyncio.run(
        _schema_candidate_review(
            ctx.obj,
            relationship_id=relationship_id,
            lookback=lookback,
            limit=limit,
            timeout=timeout,
        )
    )


async def _schema_candidate_review(
    ctx: AppContext,
    *,
    relationship_id: str,
    lookback: str | None,
    limit: int,
    timeout: int | None,
) -> None:
    schema_rows, _cache = _load_cache(ctx)
    tenant_overlay = load_tenant_overlay(ctx.config.tenant_id)
    effective = _compose_effective(
        schema_rows,
        tenant_id=ctx.config.tenant_id,
        canonical=_semantic_graph(),
        overlays=(tenant_overlay.graph,),
        observations=tenant_overlay.observations,
    )
    relationship = effective.graph.relationships.get(relationship_id)
    if relationship is None or relationship.status not in {
        RelationshipStatus.OBSERVED,
        RelationshipStatus.VALIDATED,
    }:
        error = LocalNotFoundError("schema discovery relationship", relationship_id)
        error.error_code = "SCHEMA_CANDIDATE_NOT_FOUND"
        error.help_command = "xdr schema discoveries --include-evidence-refs"
        raise error
    candidate_observations = [
        item
        for item in tenant_overlay.observations
        if item.outcome == "matched"
        and item.matched_seeds > 0
        and empirical_relationship_from_observations((item,)).id == relationship_id
    ]
    cutoff = datetime.now(UTC) - timedelta(days=_CANDIDATE_EVIDENCE_DAYS)
    matching = [
        item
        for item in candidate_observations
        if item.outcome == "matched"
        and item.matched_seeds > 0
        and item.source_artifact_run_id is not None
        and item.target_artifact_run_id is not None
        and (observed := _observation_timestamp(item.observed_at)) is not None
        and observed >= cutoff
    ]
    matching.sort(key=lambda item: (item.observed_at or "", item.observation_id))
    observation = None
    for candidate in reversed(matching):
        (
            candidate_source_locator,
            candidate_source_normalizer,
            candidate_target_locator,
        ) = _observation_evidence_coordinates(effective.graph, candidate)
        if _observation_artifacts_match(
            candidate,
            source_locator=candidate_source_locator,
            source_normalizer=candidate_source_normalizer,
            target_locator=candidate_target_locator,
            tenant_id=ctx.config.tenant_id,
        ):
            observation = candidate
            break
    if observation is None:
        source_command = "xdr schema discoveries --include-evidence-refs"
        if candidate_observations:
            source_record = effective.graph.interpretations[
                candidate_observations[-1].source_interpretation
            ]
            source_value = effective.graph.fields[source_record.field_id].locator
            source_command = f"xdr schema observe {source_value} --lookback 30d"
        error = LocalNotFoundError("retained verified source evidence", relationship_id)
        error.error_code = "SCHEMA_CANDIDATE_SOURCE_EVIDENCE_MISSING"
        error.help_command = source_command
        error.suggestions = [
            {
                "reason": "collect_sampled_evidence",
                "message": source_command,
                "confidence": "exact",
            }
        ]
        raise error
    source = effective.graph.interpretations[observation.source_interpretation]
    target = effective.graph.interpretations[observation.target_interpretation]
    source_locator = effective.graph.fields[source.field_id].locator
    target_locator = effective.graph.fields[target.field_id].locator
    source_artifact = load_artifact_input(
        source_locator.table, observation.source_artifact_run_id or ""
    )
    source_stage = source_artifact.metadata.get("probe_stage")
    if (
        source_stage not in {"source-sample", "source-explicit"}
        or source_artifact.metadata.get("locator") != str(source_locator)
        or source_artifact.metadata.get("source_interpretation") != source.id
        or source_artifact.metadata.get("source_normalizer") != source.normalizer
        or source_artifact.tenant_fingerprint != tenant_fingerprint(ctx.config.tenant_id)
        or (
            source_stage == "source-explicit"
            and (
                source_artifact.metadata.get("lookback") != observation.lookback
                or source_artifact.metadata.get("seed_source") not in {"file", "stdin"}
            )
        )
    ):
        raise ArtifactError(
            "Candidate source evidence is not a same-tenant schema-observe input; "
            "rerun the source with xdr schema observe.",
            help_command="xdr schema observe --help",
        )
    seeds, rejected_seed_count = _ordered_normalized_values(
        [row.get("Value") for row in source_artifact.rows if row.get("Value") not in (None, "")],
        target.normalizer,
        limit=observation.distinct_seeds,
    )
    if not seeds:
        raise ArtifactError(
            "Candidate source evidence contains no valid sampled values; recollect "
            "the reviewed source.",
            help_command=f"xdr schema observe {source_locator} --lookback 30d",
        )
    selected_lookback = lookback or observation.lookback or "30d"
    try:
        validate_lookback(selected_lookback)
    except GraphValidationError as exc:
        raise UsageError(
            f"candidate context query could not be compiled: {exc}",
            help_command="xdr schema candidate-review --help",
        ) from exc
    review_available_columns = {
        str(row["TableName"]): {
            str(item["ColumnName"])
            for item in schema_rows
            if item.get("TableName") == row.get("TableName") and item.get("ColumnName")
        }
        for row in schema_rows
        if row.get("TableName")
    }
    if bounded_time_column(target_locator.table, review_available_columns) is None:
        raise _temporal_column_missing(
            target_locator.table,
            operation=f"candidate review with --lookback {selected_lookback}",
        )
    try:
        compiled = compile_target_context_query(
            target,
            target_locator,
            seeds[:100],
            lookback=selected_lookback,
            limit=limit,
            available_columns=review_available_columns,
        )
    except (GraphValidationError, NormalizationError) as exc:
        raise UsageError(
            f"candidate context query could not be compiled: {exc}",
            help_command="xdr schema candidate-review --help",
        ) from exc
    client = XDRClient(
        get_token=AuthManager(ctx.config).get_token,
        timeout=timeout if timeout is not None else ctx.config.api_timeout,
    )
    try:
        result = await run_query(client, compiled.kql)
    finally:
        await client.close()
    artifact = write_result(
        result.results[:limit],
        command=ctx.invoked_command or "schema candidate-review",
        server_truncation_state="known-complete",
        session_id=ctx.session_id,
        session_label=ctx.session_label,
        session_attachment=ctx.session_attachment,
        incident_id=ctx.anchor_incident,
        alert_id=ctx.anchor_alert,
        anchor_provenance=ctx.anchor_provenance,
        query=compiled.kql,
        extra_metadata={
            "candidate_review": {
                "relationship_id": relationship_id,
                "observation_id": observation.observation_id,
                "source_artifact_run_id": source_artifact.run_id,
                "source_locator": str(source_locator),
                "target_locator": str(target_locator),
                "lookback": selected_lookback,
                "limit": limit,
                "seed_count": len(seeds),
                "rejected_retained_seed_count": rejected_seed_count,
            }
        },
        receipt_context={
            "relationship_id": relationship_id,
            "target_locator": str(target_locator),
            "private_context_rows": min(len(result.results), limit),
            "seed_count": len(seeds),
            "rejected_retained_seed_count": rejected_seed_count,
            "next_command": "RESULTS_HEAD_COMMAND_IN_METADATA",
            "warning": (
                "optional context does not change automatic evidence state or join safety"
            ),
        },
        preview_rows=0,
        tenant_id=ctx.config.tenant_id,
        physical_lineage_table=target_locator.table,
    )
    artifact.receipt.context["next_command"] = (
        f"xdr results head {artifact.receipt.run_id} --limit {limit}"
    )
    emit_result(artifact)
    if artifact.receipt.rows == 0:
        raise PartialSuccessError(
            "Candidate review saved a verified empty optional context artifact; "
            "automatic observed/validated state is unchanged. Retry with a wider "
            "--lookback only if private context is still useful.",
            help_command=(f"xdr schema candidate-review {relationship_id} --lookback 30d"),
            original={
                "type": "EmptyCandidateContext",
                "run_id": artifact.receipt.run_id,
            },
        )


def _candidate_report(
    app_ctx: AppContext, *, include_evidence_refs: bool
) -> tuple[list[dict], dict, TenantSemanticOverlay, EffectiveGraph]:
    """Build deterministic candidate rows for CLI reporting and proposals."""

    schema_rows, cache = _load_cache(app_ctx)
    tenant_overlay = load_tenant_overlay(app_ctx.config.tenant_id)
    effective = _compose_effective(
        schema_rows,
        tenant_id=app_ctx.config.tenant_id,
        canonical=_semantic_graph(),
        overlays=(tenant_overlay.graph,),
        observations=tenant_overlay.observations,
    )
    grouped: dict[str, list] = {}
    for observation in tenant_overlay.observations:
        source_id, target_id = sorted(
            (
                observation.source_interpretation,
                observation.target_interpretation,
            )
        )
        relationship_id = build_relationship_id(
            source_id,
            target_id,
            RelationshipKind.CORRELATION_ONLY,
            Direction.BOTH,
            observation.transform,
        )
        grouped.setdefault(relationship_id, []).append(observation)

    rows = []
    for relationship_id in sorted(grouped):
        observations = grouped[relationship_id]
        positive_observations = [
            item
            for item in observations
            if item.outcome == "matched" and item.matched_seeds > 0
        ]
        if not positive_observations:
            # Negative evidence is retained for future comparisons, but by
            # itself it does not describe a relationship worth reporting.
            continue
        relationship = effective.graph.relationships.get(relationship_id)
        active = relationship is not None and relationship.status in {
            RelationshipStatus.OBSERVED,
            RelationshipStatus.VALIDATED,
        }
        if relationship is None:
            relationship = empirical_relationship_from_observations(
                tuple(positive_observations)
            )
        source = effective.graph.interpretations[relationship.source]
        target = effective.graph.interpretations[relationship.target]
        source_locator = effective.graph.fields[source.field_id].locator
        target_locator = effective.graph.fields[target.field_id].locator
        cutoff = datetime.now(UTC) - timedelta(days=_CANDIDATE_EVIDENCE_DAYS)
        eligible_observations = [
            item
            for item in observations
            if (observed := _observation_timestamp(item.observed_at)) is not None
            and observed >= cutoff
        ]
        observed_matched = [
            item
            for item in eligible_observations
            if item.outcome == "matched" and item.matched_seeds > 0
        ]
        missing_reference_observations = []
        missing_evidence = set()
        mismatched_evidence = []
        matched = []
        observation_target_locators: dict[str, FieldLocator] = {}
        for item in observed_matched:
            if item.source_artifact_run_id is None or item.target_artifact_run_id is None:
                missing_reference_observations.append(item.observation_id)
                continue
            unavailable_run_ids = {
                run_id
                for run_id in (
                    item.source_artifact_run_id,
                    item.target_artifact_run_id,
                )
                if not _result_artifact_available(run_id, tenant_id=app_ctx.config.tenant_id)
            }
            if unavailable_run_ids:
                missing_evidence.update(unavailable_run_ids)
                continue
            (
                observed_source_locator,
                observed_source_normalizer,
                observed_target_locator,
            ) = _observation_evidence_coordinates(effective.graph, item)
            if not _observation_artifacts_match(
                item,
                source_locator=observed_source_locator,
                source_normalizer=observed_source_normalizer,
                target_locator=observed_target_locator,
                tenant_id=app_ctx.config.tenant_id,
            ):
                mismatched_evidence.append(item.observation_id)
                continue
            matched.append(item)
            observation_target_locators[item.observation_id] = observed_target_locator
        missing_evidence = sorted(missing_evidence)
        validation_matched = []
        validation_cohorts: list[frozenset[str]] = []
        for item in matched:
            evidence = _eligible_observation_evidence(
                effective.graph,
                item,
                tenant_id=app_ctx.config.tenant_id,
            )
            cohort = evidence.get("sampled_cohort") if evidence is not None else None
            if isinstance(cohort, frozenset):
                validation_matched.append(item)
                validation_cohorts.append(cohort)
        blocking_reasons = []
        if len(validation_matched) < 2:
            blocking_reasons.append("needs-at-least-two-verified-sampled-positive-runs")
        window_keys = {
            (item.observed_at[:10], item.lookback)
            for item in validation_matched
            if item.observed_at is not None and item.lookback is not None
        }
        observation_days = {item[0] for item in window_keys}
        evidence_pairs = {
            (item.source_artifact_run_id, item.target_artifact_run_id)
            for item in validation_matched
            if item.source_artifact_run_id is not None and item.target_artifact_run_id is not None
        }
        if len(evidence_pairs) < 2:
            blocking_reasons.append("needs-at-least-two-independent-evidence-bundles")
        distinct_cohorts = set(validation_cohorts)
        distinct_identifiers = {
            value for cohort in distinct_cohorts for value in cohort
        }
        if len(distinct_cohorts) < 2:
            blocking_reasons.append("needs-at-least-two-distinct-sampled-seed-cohorts")
        if len(distinct_identifiers) < 6:
            blocking_reasons.append("needs-at-least-six-distinct-sampled-identifiers")
        if (
            len(
                {
                    item.source_artifact_run_id
                    for item in validation_matched
                    if item.source_artifact_run_id is not None
                }
            )
            < 2
        ):
            blocking_reasons.append("needs-at-least-two-independent-source-bundles")
        if (
            len(
                {
                    item.target_artifact_run_id
                    for item in validation_matched
                    if item.target_artifact_run_id is not None
                }
            )
            < 2
        ):
            blocking_reasons.append("needs-at-least-two-independent-target-bundles")
        if any(item.distinct_seeds < 3 for item in validation_matched):
            blocking_reasons.append("positive-run-tested-fewer-than-three-seeds")
        if any(item.matched_seeds < 2 for item in validation_matched):
            blocking_reasons.append("positive-run-matched-fewer-than-two-seeds")
        review_artifacts = _candidate_review_artifacts(
            relationship_id,
            tenant_id=app_ctx.config.tenant_id,
            eligible_observations={item.observation_id: item for item in matched},
            expected_target_locators=observation_target_locators,
        )
        readiness_tested = sum(item.distinct_seeds for item in validation_matched)
        readiness_matches = sum(item.matched_seeds for item in validation_matched)
        if readiness_tested and readiness_matches / readiness_tested < 0.8:
            blocking_reasons.append("aggregate-match-ratio-below-80-percent")
        concerns = []
        excluded_observations = len(observations) - len(eligible_observations)
        if excluded_observations:
            concerns.append("legacy-or-stale-observations-excluded-from-readiness")
        if any(
            item.outcome in {"partial", "throttled", "unavailable", "inconclusive"}
            for item in eligible_observations
        ):
            concerns.append("incomplete-observations-excluded-from-readiness")
        if missing_reference_observations:
            concerns.append("positive-runs-missing-evidence-refs-excluded")
        if missing_evidence:
            concerns.append("positive-runs-missing-evidence-excluded")
        if mismatched_evidence:
            concerns.append("positive-runs-provenance-mismatch-excluded")
        if any(item.extra.get("source_evidence_kind") == "operator-supplied" for item in matched):
            concerns.append("operator-supplied-source-values-require-origin-review")
        if len({item.lookback for item in matched if item.lookback is not None}) > 1:
            concerns.append("positive-runs-used-inconsistent-lookback-windows")
        if any(item.outcome == "no-match" for item in observations):
            concerns.append("positive-and-no-match-runs-need-time-window-review")
        if any(
            item.matched_seeds and item.matched_rows / item.matched_seeds > 1000 for item in matched
        ):
            concerns.append("high-row-fanout-needs-selectivity-review")
        row = {
            "RelationshipId": relationship_id,
            "Source": str(source_locator),
            "Target": str(target_locator),
            "SourceInterpretation": source.id,
            "TargetInterpretation": target.id,
            "EntityKind": source.entity_kind,
            "Namespace": source.namespace,
            "Normalizer": source.normalizer,
            "Relationship": relationship.relationship.value,
            "Status": relationship.status.value if active else "inactive",
            "EvidenceLevel": relationship.status.value if active else "inactive",
            "Confidence": relationship.confidence.value,
            "EvidenceGate": "passed" if not blocking_reasons else "insufficient",
            "BlockingReasons": blocking_reasons,
            "AutomatedConcerns": concerns,
            "ReviewDecision": "programmatic",
            "LifecycleState": (
                "validated-investigation-pivot"
                if active and relationship.status is RelationshipStatus.VALIDATED
                else "observed-investigation-pivot"
                if active and not blocking_reasons
                else "inactive-evidence-unavailable"
                if not active
                else "observed-collect-more-evidence"
            ),
            "CanonicalUpdatePolicy": "tenant-local-programmatic-pivot",
            "CanonicalGraphPath": "src/xdr_cli/schema_graph/data/semantic-graph.jsonl",
            "CanonicalValidationCommand": (
                "xdr schema validate-core --document docs/schema_pivots.md"
            ),
            "DocumentationUpdateCommand": (
                "xdr schema validate-core --document docs/schema_pivots.md --update-document"
            ),
            "PositiveRuns": len(observed_matched),
            "ValidatedPositiveRuns": len(validation_matched),
            "ObservedPositiveRuns": len(observed_matched),
            "ExcludedInvalidPositiveRuns": len(observed_matched) - len(matched),
            "IndependentObservationWindows": len(window_keys),
            "IndependentObservationDays": len(observation_days),
            "IndependentSeedCohorts": len(distinct_cohorts),
            "DistinctValidatedSourceIdentifiers": len(distinct_identifiers),
            "ProbeRuns": sum(item.probe_runs for item in eligible_observations),
            "DistinctSeedObservations": sum(item.distinct_seeds for item in observed_matched),
            "MatchedSeeds": sum(item.matched_seeds for item in observed_matched),
            "MatchedRows": sum(item.matched_rows for item in observed_matched),
            "ReadinessDistinctSeedObservations": readiness_tested,
            "ReadinessMatchedSeeds": readiness_matches,
            "ReadinessMatchedRows": sum(item.matched_rows for item in validation_matched),
            "EvidenceArtifactsAvailable": not (
                missing_reference_observations or missing_evidence or mismatched_evidence
            ),
            "MissingEvidenceReferenceCount": len(missing_reference_observations),
            "MissingEvidenceArtifactCount": len(missing_evidence),
            "MismatchedEvidenceArtifactCount": len(mismatched_evidence),
            "ContextReviewArtifactsAvailable": bool(review_artifacts),
            "ExcludedLegacyOrStaleObservations": excluded_observations,
            "EvidenceHorizonDays": _CANDIDATE_EVIDENCE_DAYS,
            "ReviewCommand": f"xdr schema candidate-review {relationship_id}",
            "ProposalCommand": (f"xdr schema candidate-proposal {relationship_id} --help"),
            "MaximumEmpiricalClaim": "correlation-only-search-pivot",
            "JoinSafe": False,
            "OptionalContextChecks": [
                "inspect private matching rows when investigation context is ambiguous",
                "review high-fanout or polymorphic fields before relying on a route",
            ],
            "CorePromotionRequirements": [
                "use an independent product contract for any join-compatible claim",
                "review the repository diff and generated schema reference",
            ],
        }
        if include_evidence_refs:
            row["ValidatedObservationIds"] = sorted(
                item.observation_id for item in validation_matched
            )
            row["ValidatedSourceArtifactRunIds"] = sorted(
                {
                    item.source_artifact_run_id
                    for item in validation_matched
                    if item.source_artifact_run_id is not None
                }
            )
            row["ValidatedTargetArtifactRunIds"] = sorted(
                {
                    item.target_artifact_run_id
                    for item in validation_matched
                    if item.target_artifact_run_id is not None
                }
            )
            row["SourceArtifactRunIds"] = sorted(
                {
                    item.source_artifact_run_id
                    for item in observations
                    if item.source_artifact_run_id is not None
                }
            )
            row["TargetArtifactRunIds"] = sorted(
                {
                    item.target_artifact_run_id
                    for item in observations
                    if item.target_artifact_run_id is not None
                }
            )
            row["MissingEvidenceArtifactRunIds"] = missing_evidence
            row["ContextReviewArtifactRunIds"] = review_artifacts
        rows.append(row)
    return rows, cache, tenant_overlay, effective


def _emit_schema_discoveries(app_ctx: AppContext, *, include_evidence_refs: bool) -> None:
    """Emit the shared discoveries/candidates artifact."""

    rows, cache, tenant_overlay, _effective = _candidate_report(
        app_ctx, include_evidence_refs=include_evidence_refs
    )
    emit_result(
        write_result(
            rows,
            command=app_ctx.invoked_command or "schema discoveries",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={
                "cache": cache,
                "semantic_cache": tenant_overlay.metadata,
                "candidate_count": len(rows),
                "discovery_count": len(rows),
                "value_free": True,
                "private_evidence_refs": include_evidence_refs,
            },
            receipt_context={
                "candidate_count": len(rows),
                "discovery_count": len(rows),
                "value_free": True,
                "evidence_gate_passed": sum(item["EvidenceGate"] == "passed" for item in rows),
                "warning": (
                    "observed pivots are investigation avenues; evidence alone does "
                    "not establish raw join safety"
                ),
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("discoveries")
def schema_discoveries(
    ctx: typer.Context,
    include_evidence_refs: bool = typer.Option(
        False,
        "--include-evidence-refs",
        help="Include private result run IDs needed for local evidence inspection.",
    ),
) -> None:
    """Explain observed and validated tenant pivots with value-free evidence.

    Example: `xdr schema discoveries`

    A completed positive probe is an observed investigation pivot, not merely
    a possible relationship. Repeated independent evidence can advance it to a
    validated pivot. Neither state claims a raw equality join is safe.
    """

    _emit_schema_discoveries(ctx.obj, include_evidence_refs=include_evidence_refs)


@schema_app.command("candidates")
def schema_candidates(
    ctx: typer.Context,
    include_evidence_refs: bool = typer.Option(
        False,
        "--include-evidence-refs",
        help="Include private result run IDs needed for local evidence inspection.",
    ),
) -> None:
    """Compatibility alias for `xdr schema discoveries`.

    Example: `xdr schema candidates`

    Optionally generate private context with the row's `ReviewCommand`, for example `xdr
    schema candidate-review rel:0123456789abcdef01234567`; inspect its returned
    `xdr results head RUN_ID` command, then use the row's
    `ProposalCommand` only for a contributor-owned core change. A proposal
    requires explicit human semantics and never modifies the packaged graph.
    """

    _emit_schema_discoveries(ctx.obj, include_evidence_refs=include_evidence_refs)


@schema_app.command("candidate-proposal")
def schema_candidate_proposal(
    ctx: typer.Context,
    relationship_id: str = typer.Argument(
        metavar="RELATIONSHIP_ID",
        help="Evidence-ready ID from `xdr schema discoveries`.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        dir_okay=False,
        help="New review-only JSONL file; an existing path is never overwritten.",
    ),
    relationship: RelationshipKind = typer.Option(
        ...,
        "--relationship",
        help="Human-reviewed relationship claim; never inferred from matches.",
    ),
    direction: Direction = typer.Option(
        ...,
        "--direction",
        help="Human-reviewed direction relative to the reported source and target.",
    ),
    cardinality: Cardinality = typer.Option(
        ...,
        "--cardinality",
        help="Human-reviewed cardinality; joins cannot use `unknown`.",
    ),
    temporal: str = typer.Option(
        ...,
        "--temporal",
        help="Reviewed time guidance as a repository-safe slug/phrase.",
    ),
    confidence: Confidence = typer.Option(
        ...,
        "--confidence",
        help="Human-reviewed confidence; empirical counts do not choose it.",
    ),
    provenance: list[str] | None = typer.Option(
        None,
        "--provenance",
        help=(
            "Repository-safe review/contract citation; repeatable, for example "
            "`contract:microsoft-device-id`."
        ),
    ),
    confirmed_interpretations: list[str] | None = typer.Option(
        None,
        "--confirm-interpretation",
        help=(
            "Exact candidate interpretation ID being added to core; repeat for "
            "every non-core endpoint shown by `schema discoveries`."
        ),
    ),
    acknowledge_independent_contract: bool = typer.Option(
        False,
        "--acknowledge-independent-contract",
        help=(
            "Required with contract:/documentation: provenance for join-compatible "
            "or bridge claims."
        ),
    ),
) -> None:
    """Draft reviewed core JSONL without modifying or promoting the graph.

    Start with `xdr schema discoveries`, run the row's optional `ReviewCommand`, and
    inspect the private context. Then copy the exact interpretation IDs and
    supply every semantic decision explicitly.

    Example: `xdr schema candidate-proposal
    rel:0123456789abcdef01234567 --output proposal.jsonl --relationship
    semantic-equivalent --direction both --cardinality unknown --temporal
    same-retention-window --confidence medium --provenance
    contract:microsoft-identifier`

    The output contains only value-free missing field/interpretation records
    plus one reviewed relationship. It is a proposal for ordinary human code
    review, never an automatic edit to the packaged graph. Its private receipt
    binds the exact evidence generation and proposal bytes, and protects
    referenced bundles while the proposal file exists. It refuses to replace
    reviewed/deprecated core semantics.
    """

    with schema_evidence_lock(help_command="xdr schema candidate-proposal --help"):
        _schema_candidate_proposal_locked(
            ctx=ctx,
            relationship_id=relationship_id,
            output=output,
            relationship=relationship,
            direction=direction,
            cardinality=cardinality,
            temporal=temporal,
            confidence=confidence,
            provenance=provenance,
            confirmed_interpretations=confirmed_interpretations,
            acknowledge_independent_contract=acknowledge_independent_contract,
        )


def _schema_candidate_proposal_locked(
    *,
    ctx: typer.Context,
    relationship_id: str,
    output: Path,
    relationship: RelationshipKind,
    direction: Direction,
    cardinality: Cardinality,
    temporal: str,
    confidence: Confidence,
    provenance: list[str] | None,
    confirmed_interpretations: list[str] | None,
    acknowledge_independent_contract: bool,
) -> None:
    """Create one proposal while evidence publication and pruning are locked."""

    app_ctx: AppContext = ctx.obj
    rows, _cache, overlay, effective = _candidate_report(app_ctx, include_evidence_refs=True)
    report = next(
        (row for row in rows if row["RelationshipId"] == relationship_id),
        None,
    )
    if report is None:
        error = LocalNotFoundError("schema candidate relationship", relationship_id)
        error.error_code = "SCHEMA_CANDIDATE_NOT_FOUND"
        error.help_command = "xdr schema discoveries"
        raise error
    if report["EvidenceGate"] != "passed":
        error = ConflictError(
            "Discovery evidence is not ready for a core proposal. Resolve the "
            "reported automatic-policy blockers by collecting more independent "
            "sampled evidence.",
            help_command="xdr schema discoveries --include-evidence-refs",
            original={
                "type": "CandidateEvidenceInsufficient",
                "blocking_reasons": report["BlockingReasons"],
            },
        )
        error.error_code = "SCHEMA_CANDIDATE_EVIDENCE_INSUFFICIENT"
        raise error
    citations = tuple(provenance or ())
    if not citations or any(
        not re.fullmatch(
            r"(?:contract|curated|documentation|reviewed):[A-Za-z0-9_.:/-]{1,200}",
            item,
        )
        for item in citations
    ):
        raise UsageError(
            "Provide at least one repository-safe --provenance citation prefixed "
            "with contract:, curated:, documentation:, or reviewed:.",
            help_command="xdr schema candidate-proposal --help",
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/;-]{0,255}", temporal):
        raise UsageError(
            "--temporal must be a non-empty repository-safe slug/phrase without "
            "spaces or tenant values.",
            help_command="xdr schema candidate-proposal --help",
        )
    if relationship in {RelationshipKind.JOIN_COMPATIBLE, RelationshipKind.BRIDGE} and not (
        acknowledge_independent_contract
    ):
        raise UsageError(
            "Join-compatible and bridge proposals require "
            "--acknowledge-independent-contract; empirical equality is insufficient.",
            help_command="xdr schema candidate-proposal --help",
        )
    if relationship in {RelationshipKind.JOIN_COMPATIBLE, RelationshipKind.BRIDGE} and not any(
        item.startswith(("contract:", "documentation:")) for item in citations
    ):
        raise UsageError(
            "Join-compatible and bridge proposals require at least one "
            "contract: or documentation: provenance citation for the independent "
            "semantic contract.",
            help_command="xdr schema candidate-proposal --help",
        )

    candidate = effective.graph.relationships[relationship_id]
    core = _semantic_graph()
    missing_interpretations = {
        endpoint
        for endpoint in (candidate.source, candidate.target)
        if endpoint not in core.interpretations
    }
    if set(confirmed_interpretations or ()) != missing_interpretations:
        raise UsageError(
            "--confirm-interpretation values must exactly match the non-core "
            f"candidate endpoints: {sorted(missing_interpretations)}",
            help_command="xdr schema discoveries",
        )

    source_id = candidate.source
    target_id = candidate.target
    if direction is Direction.BOTH and target_id < source_id:
        source_id, target_id = target_id, source_id
    try:
        proposed_relationship = RelationshipRecord(
            id=build_relationship_id(
                source_id,
                target_id,
                relationship,
                direction,
                candidate.transform,
            ),
            source=source_id,
            target=target_id,
            relationship=relationship,
            direction=direction,
            transform=candidate.transform,
            cardinality=cardinality,
            temporal=temporal,
            status=RelationshipStatus.REVIEWED,
            confidence=confidence,
            provenance=citations,
        )
    except GraphValidationError as exc:
        raise UsageError(
            f"Candidate proposal semantics are invalid: {exc}",
            help_command="xdr schema candidate-proposal --help",
        ) from exc
    existing_core_relationship = core.relationships.get(proposed_relationship.id)
    if (
        existing_core_relationship is not None
        and existing_core_relationship.status is not RelationshipStatus.CANDIDATE
    ):
        error = ConflictError(
            "The proposed semantic identity already exists as a "
            f"{existing_core_relationship.status.value} core relationship. A "
            "candidate proposal cannot replace reviewed or deprecated core "
            "semantics; inspect the existing route and make any intentional core "
            "change as a separate repository review.",
            help_command=f"xdr schema pivot {report['Source']}",
            original={
                "type": "ExistingCoreRelationship",
                "relationship_id": proposed_relationship.id,
                "status": existing_core_relationship.status.value,
            },
        )
        error.error_code = "SCHEMA_PROPOSAL_CORE_RELATIONSHIP_EXISTS"
        raise error
    proposal_records = []
    for interpretation_id_value in sorted(missing_interpretations):
        interpretation = effective.graph.interpretations[interpretation_id_value]
        field = effective.graph.fields[interpretation.field_id]
        if field.id not in core.fields and all(
            item.get("id") != field.id for item in proposal_records
        ):
            proposal_records.append(
                FieldRecord(
                    id=field.id,
                    locator=field.locator,
                    kql_type=field.kql_type,
                ).to_dict()
            )
        proposal_records.append(
            InterpretationRecord(
                id=interpretation.id,
                field_id=interpretation.field_id,
                entity_kind=interpretation.entity_kind,
                namespace=interpretation.namespace,
                role=interpretation.role,
                normalizer=interpretation.normalizer,
                constraints=interpretation.constraints,
            ).to_dict()
        )
    proposal_records.append(proposed_relationship.to_dict())
    try:
        validation_graph = Graph()
        for record in core.records():
            if record.id != proposed_relationship.id:
                validation_graph.add(record)
        for record in proposal_records:
            if record["record_type"] == "field":
                validation_graph.add(FieldRecord.from_dict(record))
            elif record["record_type"] == "interpretation":
                validation_graph.add(InterpretationRecord.from_dict(record))
            else:
                validation_graph.add(RelationshipRecord.from_dict(record))
        validation_graph.validate_references()
    except GraphValidationError as exc:
        raise ConflictError(
            f"Candidate proposal conflicts with the packaged graph: {exc}",
            help_command="xdr schema validate-core --help",
        ) from exc

    evidence_snapshot = {
        "overlay_generation": overlay.metadata.get("generation"),
        "validated_observation_ids": report.get("ValidatedObservationIds", []),
        "source_artifact_run_ids": report.get("ValidatedSourceArtifactRunIds", []),
        "target_artifact_run_ids": report.get("ValidatedTargetArtifactRunIds", []),
        "review_artifact_run_ids": report.get("ContextReviewArtifactRunIds", []),
    }
    snapshot_payload = json.dumps(evidence_snapshot, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    evidence_snapshot["sha256"] = hashlib.sha256(snapshot_payload).hexdigest()
    current_overlay = load_tenant_overlay(app_ctx.config.tenant_id)
    if current_overlay.metadata.get("generation") != evidence_snapshot["overlay_generation"]:
        error = ConflictError(
            "Tenant schema evidence changed while preparing the candidate proposal. "
            "Rerun discoveries and review the new evidence snapshot.",
            retryable=True,
            help_command="xdr schema discoveries --include-evidence-refs",
        )
        error.error_code = "SCHEMA_PROPOSAL_EVIDENCE_CHANGED"
        raise error

    proposal_bytes = "".join(
        json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for record in proposal_records
    ).encode("utf-8")
    proposal_sha256 = hashlib.sha256(proposal_bytes).hexdigest()
    proposal_binding = {
        "proposal_path": str(output.resolve()),
        "source_candidate_relationship_id": relationship_id,
        "proposed_relationship_id": proposed_relationship.id,
        "proposal_sha256": proposal_sha256,
        "proposal_bytes": len(proposal_bytes),
        "evidence_snapshot": evidence_snapshot,
    }
    proposal_binding_payload = json.dumps(
        proposal_binding, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    proposal_binding["binding_sha256"] = hashlib.sha256(proposal_binding_payload).hexdigest()
    if not output.parent.is_dir():
        raise UsageError(
            f"Proposal output directory does not exist: {output.parent}",
            help_command="xdr schema candidate-proposal --help",
        )
    try:
        with output.open("xb") as handle:
            handle.write(proposal_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            output.chmod(0o600)
    except FileExistsError as exc:
        raise ConflictError(
            f"Proposal output already exists and was not overwritten: {output}",
            help_command="xdr schema candidate-proposal --help",
        ) from exc
    except OSError as exc:
        with contextlib.suppress(OSError):
            output.unlink(missing_ok=True)
        raise ArtifactError(
            f"Could not write candidate proposal: {exc}",
            help_command="xdr schema candidate-proposal --help",
        ) from exc

    try:
        artifact = write_result(
            proposal_records,
            command=app_ctx.invoked_command or "schema candidate-proposal",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={
                "value_free": True,
                "proposal_path": str(output.resolve()),
                "source_candidate_relationship_id": relationship_id,
                "candidate_proposal": proposal_binding,
                "automatic_promotion": False,
            },
            receipt_context={
                "relationship_id": proposed_relationship.id,
                "proposal_path": str(output.resolve()),
                "records": len(proposal_records),
                "automatic_promotion": False,
                "evidence_snapshot_sha256": evidence_snapshot["sha256"],
                "proposal_sha256": proposal_sha256,
                "next_commands": [
                    "review and merge the approved JSONL records into "
                    "src/xdr_cli/schema_graph/data/semantic-graph.jsonl, replacing "
                    "any same-ID candidate record",
                    "xdr schema validate-core --document docs/schema_pivots.md",
                    "xdr schema validate-core --document docs/schema_pivots.md --update-document",
                    "git diff -- src/xdr_cli/schema_graph/data/semantic-graph.jsonl "
                    "docs/schema_pivots.md",
                ],
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    except Exception as exc:
        try:
            output.unlink()
        except OSError as cleanup_exc:
            error = PartialSuccessError(
                "Candidate proposal JSONL was written, but its binding result "
                "artifact failed and the proposal could not be removed. Preserve "
                "the reported file for manual review; do not treat it as a "
                "receipt-bound promotion proposal.",
                help_command="xdr schema candidate-proposal --help",
                original={
                    "type": "OrphanedCandidateProposal",
                    "proposal_path": str(output.resolve()),
                    "artifact_error_type": type(exc).__name__,
                    "cleanup_error_type": type(cleanup_exc).__name__,
                },
            )
            error.error_code = "SCHEMA_PROPOSAL_PARTIAL_PUBLICATION"
            raise error from exc
        raise
    emit_result(artifact)


@schema_app.command("prune-evidence")
def schema_prune_evidence(
    ctx: typer.Context,
    older_than: int = typer.Option(
        ...,
        "--older-than",
        min=1,
        help="Remove tenant observations older than this many days.",
    ),
    include_legacy: bool = typer.Option(
        False,
        "--include-legacy",
        help="Also remove legacy observations that have no observation timestamp.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Confirm the overlay rewrite; required when non-interactive.",
    ),
) -> None:
    """Prune stale value-free observations so referenced results can be deleted.

    Example: `xdr schema prune-evidence --older-than 90 --yes`

    This rewrites only the private tenant overlay. It preserves discovered
    fields and interpretations and never deletes result artifacts; run `xdr
    results prune --older-than 90 --yes` afterwards to remove now-unreferenced
    bundles. Legacy timestamp-free evidence is retained unless
    `--include-legacy` is explicit.
    """

    app_ctx: AppContext = ctx.obj
    overlay = load_tenant_overlay(app_ctx.config.tenant_id)
    cutoff = datetime.now(UTC) - timedelta(days=older_than)
    removed = []
    retained = []
    for observation in overlay.observations:
        observed = _observation_timestamp(observation.observed_at)
        should_remove = (observed is not None and observed < cutoff) or (
            observed is None and include_legacy
        )
        (removed if should_remove else retained).append(observation)
    if removed and not yes:
        if not app_ctx.is_interactive:
            raise UsageError(
                "Non-interactive schema evidence pruning requires --yes.",
                corrected_argv=[
                    "xdr",
                    "schema",
                    "prune-evidence",
                    "--older-than",
                    str(older_than),
                    "--yes",
                ],
                help_command="xdr schema prune-evidence --help",
            )
        if not typer.confirm(f"Remove {len(removed)} tenant observation(s)?"):
            raise ConflictError("Schema evidence pruning was cancelled by the operator.")
    metadata = overlay.metadata
    if removed:
        metadata = publish_tenant_overlay(
            app_ctx.config.tenant_id,
            observations=tuple(retained),
            replace_observations=True,
            expected_generation=overlay.metadata.get("generation"),
        )
    emit_result(
        write_result(
            [
                {
                    "RemovedObservations": len(removed),
                    "RetainedObservations": len(retained),
                    "OlderThanDays": older_than,
                    "IncludedLegacy": include_legacy,
                }
            ],
            command=app_ctx.invoked_command or "schema prune-evidence",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            extra_metadata={"semantic_cache": metadata, "value_free": True},
            receipt_context={
                "removed_observations": len(removed),
                "retained_observations": len(retained),
                "next_command": f"xdr results prune --older-than {older_than} --yes",
            },
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("correlate")
def schema_correlate(
    ctx: typer.Context,
    inputs: list[str] = typer.Option(
        ...,
        "--input",
        help="Explicit source table and private run ID as Table=run-id. Repeatable.",
    ),
    include_contextual: bool = typer.Option(
        False,
        "--include-contextual",
        help=(
            "Include weak/mutable relationships such as IP, UPN, hostname, and hash "
            "matches; these require the returned temporal/context checks."
        ),
    ),
    allow_tenant_mismatch: bool = typer.Option(
        False,
        "--allow-tenant-mismatch",
        help=(
            "Explicitly allow unbound or differently tenant-bound legacy artifacts; "
            "use only for intentional cross-tenant analysis."
        ),
    ),
) -> None:
    """Correlate saved query artifacts offline; never executes KQL.

    Example: `xdr schema correlate --input EntraIdSignInEvents=RUN_ID_1 --input
    CloudAppEvents=RUN_ID_2 --include-contextual`

    Find run IDs with `xdr results list`. Each input must declare its physical
    source table, and its sidecar must independently prove lineage, data digest,
    and the active tenant binding.
    Contextual matches are excluded by default because IPs, UPNs, hostnames,
    and hashes need the returned temporal or surrounding-event checks.
    """
    if len(inputs) < 2:
        raise typer.BadParameter("provide at least two --input Table=run-id values")
    parsed = []
    for value in inputs:
        table, separator, run_id = value.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", table):
            raise typer.BadParameter("each --input must be Table=run-id")
        parsed.append(load_artifact_input(table, run_id))
    if len({item.run_id for item in parsed}) != len(parsed):
        raise typer.BadParameter("each input run ID must be unique")
    active_tenant = tenant_fingerprint(ctx.obj.config.tenant_id)
    input_tenants = {item.tenant_fingerprint for item in parsed}
    tenant_mismatch = (
        active_tenant is None
        or None in input_tenants
        or len(input_tenants) != 1
        or input_tenants != {active_tenant}
    )
    if tenant_mismatch and not allow_tenant_mismatch:
        error = ConflictError(
            "Correlation inputs are unbound, cross-tenant, or do not match the active "
            "tenant. Regenerate legacy artifacts, select same-tenant inputs, or explicitly "
            "acknowledge intentional cross-tenant analysis.",
            help_command="xdr schema correlate --help",
        )
        error.error_code = "SCHEMA_CORRELATION_TENANT_MISMATCH"
        raise error
    result = correlate_inputs(
        _semantic_graph(),
        tuple(parsed),
        include_contextual=include_contextual,
    )
    app_ctx: AppContext = ctx.obj
    artifact = write_result(
        result.records,
        command=app_ctx.invoked_command or "schema correlate",
        server_truncation_state="known-complete",
        session_id=app_ctx.session_id,
        session_label=app_ctx.session_label,
        session_attachment=app_ctx.session_attachment,
        incident_id=app_ctx.anchor_incident,
        alert_id=app_ctx.anchor_alert,
        anchor_provenance=app_ctx.anchor_provenance,
        preview_rows=0,
        extra_metadata={
            "private_graph": True,
            "tenant_mismatch_allowed": allow_tenant_mismatch,
            "inputs": [
                {
                    "table": item.table,
                    "run_id": item.run_id,
                    "row_count": item.metadata.get("row_count"),
                    "server_truncation_state": item.metadata.get("server_truncation_state"),
                    "session": item.metadata.get("session"),
                    "anchors": item.metadata.get("anchors"),
                    "query_sha256": item.metadata.get("query_sha256"),
                    "lineage": item.lineage,
                }
                for item in parsed
            ],
        },
        receipt_context={
            "input_artifacts": len(parsed),
            "events": sum(len(item.rows) for item in parsed),
            "entities": result.entity_count,
            "event_entity_edges": result.edge_count,
            "shared_entities": result.shared_entity_count,
            "contextual_matches": result.contextual_match_count,
            "structural_routes": result.structural_route_count,
            "include_contextual": include_contextual,
            "tenant_binding_verified": not tenant_mismatch,
            "next_command": "RESULTS_ROWS_COMMAND_IN_METADATA",
            "warning": "shared entities are row evidence; structural paths alone are not",
        },
        tenant_id=app_ctx.config.tenant_id,
    )
    artifact.receipt.context["next_command"] = (
        f"xdr results rows {artifact.receipt.run_id} --type relationship-path-match --limit 100"
    )
    emit_result(artifact)


@schema_app.command("pivot")
def schema_pivot(
    ctx: typer.Context,
    locator: str = typer.Argument(
        help=(
            "Semantic locator (`Table.Column` or nested `Table.Column#/path`); "
            "discover columns with `xdr schema show TABLE`."
        )
    ),
    include_candidates: bool = typer.Option(
        False,
        "--include-candidates",
        help="Also include unverified candidate hypotheses after usable routes.",
    ),
) -> None:
    """Find fields that can carry the same semantic identifier; cache-only.

    Example: `xdr schema pivot EntraIdSignInEvents.AccountUpn`

    Discover valid fields first: `xdr schema show EntraIdSignInEvents`

    Reviewed, validated, and observed routes are returned by default. Add
    `--include-candidates` only for unverified hypotheses. A returned pivot is a
    search route; check `EvidenceLevel`, `JoinSafe`, `Relationship`, `Workflow`,
    and `Transform` before deciding whether raw equality or a KQL join is safe.
    """
    app_ctx: AppContext = ctx.obj
    schema_rows, cache = _load_cache(app_ctx)
    tenant_overlay = load_tenant_overlay(app_ctx.config.tenant_id)
    semantic_cache = tenant_overlay.metadata
    effective = _compose_effective(
        schema_rows,
        tenant_id=app_ctx.config.tenant_id,
        canonical=_semantic_graph(),
        overlays=(tenant_overlay.graph,),
        observations=tenant_overlay.observations,
    )
    graph = effective.graph
    available = effective.queryable_fields
    try:
        canonical_locator = str(FieldLocator.parse(locator))
        source_availability = _locator_availability(effective, canonical_locator)
        reviewed_steps = pivot(
            graph,
            canonical_locator,
            include_candidates=False,
            available_fields=available,
            field_availability=effective.field_availability,
        )
        all_steps = pivot(
            graph,
            canonical_locator,
            include_candidates=True,
            available_fields=available,
            field_availability=effective.field_availability,
        )
    except GraphValidationError as exc:
        error = LocalNotFoundError("semantic field", locator)
        error.error_code = "SCHEMA_UNKNOWN_SEMANTIC_FIELD"
        table = locator.split(".", 1)[0]
        error.help_command = f"xdr schema show {table}"
        raise error from exc

    steps = all_steps if include_candidates else reviewed_steps
    candidate_count = len(all_steps) - len(reviewed_steps)
    if source_availability == FieldAvailability.UNAVAILABLE.value:
        outcome = "source-unavailable"
    elif source_availability == FieldAvailability.OUTER_AVAILABLE_UNOBSERVED.value:
        outcome = "source-unobserved"
    else:
        outcome = (
            "routes-found" if steps else ("candidate-only" if candidate_count else "disconnected")
        )
    result_rows = [_semantic_step_row(step, 1) for step in steps]
    emit_result(
        write_result(
            result_rows,
            command=app_ctx.invoked_command or "schema pivot",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            incident_id=app_ctx.anchor_incident,
            alert_id=app_ctx.anchor_alert,
            anchor_provenance=app_ctx.anchor_provenance,
            extra_metadata={
                "cache": cache,
                "semantic_cache": semantic_cache,
                "semantic_graph_schema_version": 1,
                "locator": canonical_locator,
                "include_candidates": include_candidates,
                "outcome": outcome,
                "source_availability": source_availability,
                "candidate_routes": candidate_count,
            },
            receipt_context=_semantic_receipt_context(
                cache,
                locator=canonical_locator,
                outcome=outcome,
                source_availability=source_availability,
                candidate_routes=candidate_count,
                warning="pivot compatibility does not automatically mean raw join safety",
            ),
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@schema_app.command("path")
def schema_path(
    ctx: typer.Context,
    source_table: str = typer.Argument(
        help="Source table from `xdr schema tables`, for example `DeviceNetworkEvents`."
    ),
    target_table: str = typer.Argument(
        help="Target table from `xdr schema tables`, for example `CloudAppEvents`."
    ),
    max_depth: int = typer.Option(
        4,
        "--max-depth",
        min=1,
        max=12,
        help="Maximum relationship hops to search (1-12).",
    ),
    include_candidates: bool = typer.Option(
        False,
        "--include-candidates",
        help="Also include paths containing unverified candidate hypotheses.",
    ),
) -> None:
    """Find reviewed or empirical investigation routes between tables; cache-only.

    Example: `xdr schema path EntraIdSignInEvents CloudAppEvents`

    Discover valid table names with `xdr schema tables`. Observed and validated
    pivots are included by default; `--include-candidates` adds unverified
    hypotheses. Read `RouteKind`, `EvidenceLevel`, and
    `AllStepsJoinCompatible`: a sequential pivot is useful for investigation
    but is not a raw multi-table join recipe.
    """
    app_ctx: AppContext = ctx.obj
    schema_rows, cache = _load_cache(app_ctx)
    tenant_overlay = load_tenant_overlay(app_ctx.config.tenant_id)
    semantic_cache = tenant_overlay.metadata
    effective = _compose_effective(
        schema_rows,
        tenant_id=app_ctx.config.tenant_id,
        canonical=_semantic_graph(),
        overlays=(tenant_overlay.graph,),
        observations=tenant_overlay.observations,
    )
    graph = effective.graph
    available = effective.queryable_fields
    physical_tables = {str(row.get("TableName")) for row in schema_rows if row.get("TableName")}
    semantic_tables = {record.locator.table for record in graph.fields.values()}
    known_tables = physical_tables | semantic_tables
    for table in (source_table, target_table):
        if table not in known_tables:
            error = LocalNotFoundError("schema table", table)
            error.error_code = "SCHEMA_UNKNOWN_TABLE"
            error.help_command = f"xdr schema tables --search {table}"
            error.suggestions = [
                {
                    "reason": "schema_discovery",
                    "message": f"xdr schema tables --search {table}",
                    "confidence": "exact",
                }
            ]
            raise error
    reviewed_paths = table_paths(
        graph,
        source_table,
        target_table,
        max_depth=max_depth,
        include_candidates=False,
        available_fields=available,
        field_availability=effective.field_availability,
    )
    all_candidate_paths = table_paths(
        graph,
        source_table,
        target_table,
        max_depth=max_depth,
        include_candidates=True,
        available_fields=available,
        field_availability=effective.field_availability,
    )
    paths = all_candidate_paths if include_candidates else reviewed_paths
    candidate_only = bool(all_candidate_paths) and not reviewed_paths
    source_state = "available" if source_table in physical_tables else "unavailable"
    target_state = "available" if target_table in physical_tables else "unavailable"
    outcome = "routes-found" if paths else ("candidate-only" if candidate_only else "disconnected")
    result_rows = []
    for path_ordinal, route in enumerate(paths, start=1):
        for step_ordinal, step in enumerate(route.steps, start=1):
            result_rows.append(
                {
                    "Path": path_ordinal,
                    "PathWeight": route.weight,
                    "DirectJoin": route.direct_join,
                    "RouteKind": route.route_kind,
                    "HopCount": route.hop_count,
                    "AllStepsJoinCompatible": route.all_steps_join_compatible,
                    **_semantic_step_row(step, step_ordinal),
                }
            )
    emit_result(
        write_result(
            result_rows,
            command=app_ctx.invoked_command or "schema path",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            incident_id=app_ctx.anchor_incident,
            alert_id=app_ctx.anchor_alert,
            anchor_provenance=app_ctx.anchor_provenance,
            extra_metadata={
                "cache": cache,
                "semantic_cache": semantic_cache,
                "semantic_graph_schema_version": 1,
                "source_table": source_table,
                "target_table": target_table,
                "max_depth": max_depth,
                "include_candidates": include_candidates,
                "outcome": outcome,
                "source_availability": source_state,
                "target_availability": target_state,
            },
            receipt_context=_semantic_receipt_context(
                cache,
                source_table=source_table,
                target_table=target_table,
                outcome=outcome,
                source_availability=source_state,
                target_availability=target_state,
                paths=len(paths),
                warning="a schema path is an investigation route, not proof of event correlation",
            ),
            tenant_id=app_ctx.config.tenant_id,
        )
    )
