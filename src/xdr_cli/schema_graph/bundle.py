"""Portable, content-bound schema-state bundles with cache-only inspection."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from xdr_cli import __version__
from xdr_cli._lock import exclusive_lock
from xdr_cli.results import tenant_fingerprint
from xdr_cli.schema_graph.cache import schema_cache_status
from xdr_cli.schema_graph.diagnostics import SCHEMA_CAPABILITIES, source_commit
from xdr_cli.schema_graph.model import FieldLocator, GraphValidationError, RelationshipStatus
from xdr_cli.schema_graph.overlay import load_tenant_overlay_from_root

BUNDLE_SCHEMA_VERSION = 1
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_COLLECTION_ID = re.compile(r"collect-[0-9a-f]{24}")
_SESSION_ID = re.compile(r"([a-z]{1,3})-([1-9][0-9]*)")
_GENERATION = re.compile(r"[A-Za-z0-9_-]{1,128}")
_DURATION = re.compile(r"[1-9][0-9]{0,4}[smhd]")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TABLE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}")
_RESULT_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_MAX_FILES = 20_000
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_COLLECTION_SOURCES = (
    "DeviceNetworkEvents.DeviceId",
    "EntraIdSignInEvents.AccountUpn",
    "EntraIdSignInEvents.AccountObjectId",
    "DeviceFileEvents.SHA256",
    "EmailEvents.NetworkMessageId",
    "CloudAppEvents.RawEventData#/UserId",
)
MAX_COLLECTION_SOURCES = 100
_MAX_COLLECTION_TARGETS = 10_000
_MAX_COLLECTION_TIMEOUT = 3_600
_MAX_COLLECTION_QUERIES_PER_PAGE = 1_000


@dataclass(frozen=True, slots=True)
class InspectedBundle:
    manifest: dict[str, Any]
    files: dict[str, bytes]
    member_names: tuple[str, ...]
    payload_bytes: int

    def summary(self) -> dict[str, Any]:
        sensitivity = sorted(
            {
                item["sensitivity"]
                for item in self.manifest["files"]
                if item.get("sensitivity")
            }
        )
        return {
            "schema_version": self.manifest["schema_version"],
            "tenant_key": self.manifest["tenant_key"],
            "source_version": self.manifest["source_build"]["version"],
            "file_count": len(self.member_names),
            "total_bytes": self.payload_bytes,
            "sensitivity": sensitivity,
            "includes_results": any(
                name.startswith("results/") for name in self.member_names
            ),
            "includes_sessions": any(
                name.startswith("sessions/") for name in self.member_names
            ),
            "activation_eligible": False,
        }


def _safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or any(not part or part == "." for part in path.parts)
    ):
        raise ValueError(f"bundle member path is unsafe: {name!r}")
    return path.as_posix()


def _portable_member_sensitivity(name: str, tenant_key: str) -> str:
    """Return the required sensitivity for one supported portable member."""

    path = PurePosixPath(name)
    parts = path.parts
    if len(parts) == 3 and parts[:2] == ("schema", tenant_key):
        filename = parts[2]
        if filename in {
            "current.json",
            "maintenance.json",
            "schema.jsonl",
            "schema.meta.json",
            "semantic.current.json",
            "semantic.jsonl",
            "semantic.meta.json",
        }:
            return "value-free-schema"
        for prefix in ("schema.", "semantic."):
            if not filename.startswith(prefix):
                continue
            remainder = filename.removeprefix(prefix)
            for suffix in (".jsonl", ".meta.json"):
                if remainder.endswith(suffix) and _GENERATION.fullmatch(
                    remainder.removesuffix(suffix)
                ):
                    return "value-free-schema"
    if (
        len(parts) == 4
        and parts[:3] == ("schema", tenant_key, "collection-checkpoints")
        and parts[3].endswith(".json")
        and _COLLECTION_ID.fullmatch(parts[3].removesuffix(".json"))
    ):
        return "value-free-schema"
    if len(parts) == 3 and parts[0] == "results" and _RESULT_DATE.fullmatch(parts[1]):
        filename = parts[2]
        for suffix in (".jsonl", ".meta.json"):
            if filename.endswith(suffix) and _RUN_ID.fullmatch(
                filename.removesuffix(suffix)
            ):
                return "tenant-result-evidence"
    if (
        len(parts) == 2
        and parts[0] == "proposals"
        and parts[1].endswith(".jsonl")
        and _RUN_ID.fullmatch(parts[1].removesuffix(".jsonl"))
    ):
        return "reviewed-candidate-proposal"
    if len(parts) == 2 and parts[0] == "sessions":
        filename = parts[1]
        if filename.endswith(".jsonl") and _SESSION_ID.fullmatch(
            filename.removesuffix(".jsonl")
        ):
            return "investigation-session-history"
        for prefix in (".seq-", ".feedback-seq-"):
            if filename.startswith(prefix) and _SESSION_ID.fullmatch(
                filename.removeprefix(prefix)
            ):
                return "investigation-session-history"
    raise ValueError(f"bundle member is outside the portable namespace: {name}")


def _validate_inventory_contract(
    inventory: dict[str, dict[str, Any]], manifest: dict[str, Any], tenant_key: str
) -> None:
    """Bind every portable path and sensitivity to the declared bundle model."""

    result_members: dict[str, set[tuple[str, str]]] = {}
    proposal_ids: set[str] = set()
    for name, item in inventory.items():
        expected_sensitivity = _portable_member_sensitivity(name, tenant_key)
        if item["sensitivity"] != expected_sensitivity:
            raise ValueError(f"bundle member sensitivity is invalid: {name}")
        path = PurePosixPath(name)
        if path.parts[0] == "results":
            filename = path.name
            suffix = ".meta.json" if filename.endswith(".meta.json") else ".jsonl"
            run_id = filename.removesuffix(suffix)
            result_members.setdefault(run_id, set()).add((path.parent.as_posix(), suffix))
        elif path.parts[0] == "proposals":
            proposal_ids.add(path.name.removesuffix(".jsonl"))

    declared_runs = set(manifest.get("referenced_result_ids", ()))
    declared_proposals = set(manifest.get("candidate_proposal_result_ids", ()))
    if set(result_members) != declared_runs:
        raise ValueError("bundle result members do not match the manifest inventory")
    for run_id, members in result_members.items():
        parents = {parent for parent, _suffix in members}
        suffixes = {suffix for _parent, suffix in members}
        if len(parents) != 1 or suffixes != {".jsonl", ".meta.json"}:
            raise ValueError(f"bundle result pair is incomplete or ambiguous: {run_id}")
    if proposal_ids != declared_proposals or not declared_proposals.issubset(
        declared_runs
    ):
        raise ValueError("bundle proposal members do not match the manifest inventory")


def inspect_bundle(path: Path, *, retain_files: bool = True) -> InspectedBundle:
    """Stream and fully verify an archive without writing extracted files.

    ``retain_files=False`` is the bounded-memory inspection path used by the
    read-only CLI and export self-check. Import retains verified payload bytes
    because it must relocate metadata before staging the result.
    """

    files: dict[str, bytes] = {}
    observed: dict[str, tuple[int, str]] = {}
    manifest_raw: bytes | None = None
    with tarfile.open(path, mode="r|*") as archive:
        total_bytes = 0
        for member_count, member in enumerate(archive, start=1):
            if member_count > _MAX_FILES + 1:
                raise ValueError("bundle contains too many files")
            name = _safe_name(member.name)
            if not member.isfile() or member.issym() or member.islnk():
                raise ValueError(f"bundle member is not a regular file: {name}")
            if member.size < 0 or member.size > _MAX_FILE_BYTES:
                raise ValueError(f"bundle member has an unsafe size: {name}")
            total_bytes += member.size
            if total_bytes > _MAX_TOTAL_BYTES:
                raise ValueError("bundle total uncompressed size exceeds the safety limit")
            if name in observed:
                raise ValueError(f"bundle contains a duplicate member: {name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError(f"bundle member cannot be read: {name}")
            digest = hashlib.sha256()
            buffer = io.BytesIO() if retain_files or name == "manifest.json" else None
            bytes_read = 0
            while bytes_read <= member.size:
                chunk = handle.read(min(1024 * 1024, member.size + 1 - bytes_read))
                if not chunk:
                    break
                bytes_read += len(chunk)
                digest.update(chunk)
                if buffer is not None:
                    buffer.write(chunk)
            if bytes_read != member.size:
                raise ValueError(f"bundle member size changed while reading: {name}")
            value = buffer.getvalue() if buffer is not None else b""
            observed[name] = (member.size, digest.hexdigest())
            if name == "manifest.json":
                manifest_raw = value
            elif retain_files:
                files[name] = value
    try:
        manifest = json.loads((manifest_raw or b"").decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"bundle manifest is missing or invalid: {exc}") from exc
    if manifest_raw is None:
        raise ValueError("bundle manifest is missing or invalid")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("bundle manifest schema version is unsupported")
    declared = manifest.get("files")
    if not isinstance(declared, list):
        raise ValueError("bundle manifest file inventory is invalid")
    inventory: dict[str, dict[str, Any]] = {}
    for item in declared:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("bundle manifest file entry is invalid")
        name = _safe_name(item["path"])
        if name == "manifest.json" or name in inventory:
            raise ValueError("bundle manifest file inventory is duplicated")
        if (
            not isinstance(item.get("bytes"), int)
            or isinstance(item.get("bytes"), bool)
            or item["bytes"] < 0
            or not isinstance(item.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            or not isinstance(item.get("sensitivity"), str)
            or not item["sensitivity"]
        ):
            raise ValueError("bundle manifest file binding is invalid")
        inventory[name] = item
    payload_observed = {name: item for name, item in observed.items() if name != "manifest.json"}
    if set(inventory) != set(payload_observed):
        raise ValueError("bundle members do not match the manifest inventory")
    for name, (size, digest) in payload_observed.items():
        item = inventory[name]
        if item.get("bytes") != size or item.get("sha256") != digest:
            raise ValueError(f"bundle member digest or size does not match: {name}")
    tenant_key = manifest.get("tenant_key")
    tenant_hash = manifest.get("tenant_fingerprint")
    if not isinstance(tenant_key, str) or not re.fullmatch(r"[0-9a-f]{12}", tenant_key):
        raise ValueError("bundle tenant key is invalid")
    if not isinstance(tenant_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", tenant_hash):
        raise ValueError("bundle tenant fingerprint is invalid")
    source_build = manifest.get("source_build")
    if (
        not isinstance(source_build, dict)
        or not isinstance(source_build.get("version"), str)
        or not isinstance(source_build.get("capabilities"), list)
        or any(not isinstance(item, str) or not item for item in source_build["capabilities"])
    ):
        raise ValueError("bundle source build identity is invalid")
    for key in ("referenced_result_ids", "candidate_proposal_result_ids"):
        values = manifest.get(key, [])
        if not isinstance(values, list) or any(
            not isinstance(item, str) or not _RUN_ID.fullmatch(item) for item in values
        ):
            raise ValueError(f"bundle {key} is invalid")
    _validate_inventory_contract(inventory, manifest, tenant_key)
    return InspectedBundle(
        manifest=manifest,
        files=files,
        member_names=tuple(sorted(inventory)),
        payload_bytes=sum(size for size, _digest in payload_observed.values()),
    )


def _link_no_replace(source: Path, destination: Path) -> None:
    """Publish without replacement, including on hardlink-limited filesystems."""

    try:
        os.link(source, destination, follow_symlinks=False)
        return
    except FileExistsError:
        raise
    except OSError as exc:
        fallback_errors = {
            errno.EACCES,
            errno.EPERM,
            errno.EXDEV,
            errno.ENOSYS,
            getattr(errno, "ENOTSUP", errno.EPERM),
            getattr(errno, "EOPNOTSUPP", errno.EPERM),
        }
        if exc.errno not in fallback_errors:
            raise
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(destination, flags, 0o600)
    try:
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            descriptor = -1
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        if os.name == "posix":
            destination.chmod(0o600)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _result_files(home: Path, run_id: str) -> tuple[Path, Path]:
    if not _RUN_ID.fullmatch(run_id):
        raise ValueError(f"overlay references an invalid result ID: {run_id!r}")
    data = list((home / "results").glob(f"*/{run_id}.jsonl"))
    meta = list((home / "results").glob(f"*/{run_id}.meta.json"))
    if len(data) != 1 or len(meta) != 1 or data[0].parent != meta[0].parent:
        raise ValueError(f"referenced result pair is missing or ambiguous: {run_id}")
    results_root = (home / "results").resolve()
    if (
        data[0].is_symlink()
        or meta[0].is_symlink()
        or not data[0].resolve().is_relative_to(results_root)
        or not meta[0].resolve().is_relative_to(results_root)
    ):
        raise ValueError(f"referenced result pair has an unsafe path: {run_id}")
    return data[0], meta[0]


def _positive_int(value: str, *, maximum: int | None = None) -> bool:
    try:
        parsed = int(value)
    except ValueError:
        return False
    return str(parsed) == value and parsed >= 1 and (maximum is None or parsed <= maximum)


def _validate_collection_child(
    arguments: list[str], *, filename: str, plan: dict[str, Any] | None = None
) -> str | None:
    """Validate a checkpoint child and return its retained source run, if any."""

    if arguments in (["schema", "refresh"], ["schema", "discoveries"]):
        return None
    if len(arguments) < 3 or arguments[:2] != ["schema", "observe"]:
        raise ValueError(f"collection checkpoint child command is unsafe: {filename}")
    try:
        FieldLocator.parse(arguments[2])
    except GraphValidationError as exc:
        raise ValueError(f"collection checkpoint source locator is invalid: {filename}") from exc

    value_flags = {
        "--lookback",
        "--samples",
        "--batch-size",
        "--max-targets",
        "--timeout",
        "--max-queries",
        "--from-run",
        "--start-query",
        "--schema-generation",
        "--target-table",
        "--exclude-table",
    }
    repeatable = {"--target-table", "--exclude-table"}
    boolean_flags = {"--exhaustive"}
    values: dict[str, list[str]] = {}
    booleans: set[str] = set()
    index = 3
    while index < len(arguments):
        flag = arguments[index]
        if flag in boolean_flags:
            if flag in booleans:
                raise ValueError(f"collection checkpoint option is duplicated: {filename}")
            booleans.add(flag)
            index += 1
            continue
        if flag not in value_flags or index + 1 >= len(arguments):
            raise ValueError(f"collection checkpoint option is unsafe: {filename}")
        if flag not in repeatable and flag in values:
            raise ValueError(f"collection checkpoint option is duplicated: {filename}")
        values.setdefault(flag, []).append(arguments[index + 1])
        index += 2

    required = {"--lookback", "--samples", "--batch-size", "--timeout", "--max-queries"}
    target_scope_is_ambiguous = ("--max-targets" in values) == (
        "--exhaustive" in booleans
    )
    if not required.issubset(values) or target_scope_is_ambiguous:
        raise ValueError(f"collection checkpoint observe plan is incomplete: {filename}")
    if not _DURATION.fullmatch(values["--lookback"][0]):
        raise ValueError(f"collection checkpoint lookback is invalid: {filename}")
    integer_contracts = {
        "--samples": 100,
        "--batch-size": 50,
        "--max-targets": _MAX_COLLECTION_TARGETS,
        "--timeout": _MAX_COLLECTION_TIMEOUT,
        "--max-queries": _MAX_COLLECTION_QUERIES_PER_PAGE,
    }
    for flag, maximum in integer_contracts.items():
        if flag in values and not _positive_int(values[flag][0], maximum=maximum):
            raise ValueError(f"collection checkpoint integer option is invalid: {filename}")
    if "--start-query" in values:
        try:
            start_query = int(values["--start-query"][0])
        except ValueError as exc:
            raise ValueError(f"collection checkpoint cursor is invalid: {filename}") from exc
        if (
            str(start_query) != values["--start-query"][0]
            or start_query < 0
            or start_query > _MAX_COLLECTION_TARGETS
        ):
            raise ValueError(f"collection checkpoint cursor is invalid: {filename}")
    if "--schema-generation" in values and not _GENERATION.fullmatch(
        values["--schema-generation"][0]
    ):
        raise ValueError(f"collection checkpoint generation is invalid: {filename}")
    for flag in repeatable:
        if any(not _TABLE.fullmatch(table) for table in values.get(flag, [])):
            raise ValueError(f"collection checkpoint table filter is invalid: {filename}")
    if set(values.get("--target-table", ())) & set(values.get("--exclude-table", ())):
        raise ValueError(f"collection checkpoint table filters conflict: {filename}")
    if plan is not None:
        expected_values = {
            "--lookback": str(plan["lookback"]),
            "--samples": str(plan["samples"]),
            "--batch-size": str(plan["batch_size"]),
            "--timeout": str(plan["timeout"]),
            "--max-queries": str(plan["max_queries_per_page"]),
        }
        if any(values.get(flag) != [expected] for flag, expected in expected_values.items()):
            raise ValueError(
                f"collection checkpoint child diverges from its declared plan: {filename}"
            )
        if plan["exhaustive"]:
            scope_matches = "--exhaustive" in booleans and "--max-targets" not in values
        else:
            scope_matches = (
                "--exhaustive" not in booleans
                and values.get("--max-targets") == [str(plan["max_targets"])]
            )
        if (
            not scope_matches
            or values.get("--target-table")
            or values.get("--exclude-table")
        ):
            raise ValueError(
                f"collection checkpoint child diverges from its declared plan: {filename}"
            )
        has_source_run = "--from-run" in values
        has_cursor = "--start-query" in values
        if has_source_run != has_cursor:
            raise ValueError(
                f"collection checkpoint continuation is incomplete: {filename}"
            )
    run_id = values.get("--from-run", [None])[0]
    if run_id is not None and not _RUN_ID.fullmatch(run_id):
        raise ValueError(f"collection checkpoint result ID is invalid: {filename}")
    return run_id


def validate_collection_checkpoint(
    value: Any, *, filename: str, tenant_hash: str
) -> set[str]:
    """Validate a resumable crawl checkpoint and return retained source runs."""

    resume_id = filename.removesuffix(".json")
    plan = value.get("plan") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or not _COLLECTION_ID.fullmatch(resume_id)
        or value.get("resume_id") != resume_id
        or value.get("schema_version") != 1
        or value.get("tenant_fingerprint") != tenant_hash
        or value.get("state") not in {"running", "paused", "complete"}
        or not isinstance(plan, dict)
        or not isinstance(value.get("pending_commands"), list)
        or not isinstance(value.get("rows"), list)
        or not isinstance(value.get("seen_continuations", []), list)
        or any(not isinstance(item, str) for item in value.get("seen_continuations", []))
    ):
        raise ValueError(f"collection checkpoint contract is invalid: {filename}")
    selected_sources = plan.get("selected_sources")
    if (
        not isinstance(selected_sources, list)
        or not selected_sources
        or len(selected_sources) > MAX_COLLECTION_SOURCES
        or len(selected_sources) != len(set(selected_sources))
        or not isinstance(plan.get("using_default_sources"), bool)
        or (
            plan.get("using_default_sources") is True
            and selected_sources != list(DEFAULT_COLLECTION_SOURCES)
        )
        or not isinstance(plan.get("lookback"), str)
        or not _DURATION.fullmatch(plan["lookback"])
        or not isinstance(plan.get("samples"), int)
        or isinstance(plan.get("samples"), bool)
        or not 1 <= plan["samples"] <= 100
        or not isinstance(plan.get("batch_size"), int)
        or isinstance(plan.get("batch_size"), bool)
        or not 1 <= plan["batch_size"] <= 50
        or not isinstance(plan.get("exhaustive"), bool)
        or not isinstance(plan.get("timeout"), int)
        or isinstance(plan.get("timeout"), bool)
        or not 1 <= plan["timeout"] <= _MAX_COLLECTION_TIMEOUT
        or not isinstance(plan.get("max_queries_per_page"), int)
        or isinstance(plan.get("max_queries_per_page"), bool)
        or not 1
        <= plan["max_queries_per_page"]
        <= _MAX_COLLECTION_QUERIES_PER_PAGE
        or not isinstance(plan.get("semantic_contract_sha256"), str)
        or not _SHA256.fullmatch(plan["semantic_contract_sha256"])
        or (plan["exhaustive"] and plan.get("max_targets") is not None)
        or (
            not plan["exhaustive"]
            and (
                not isinstance(plan.get("max_targets"), int)
                or isinstance(plan.get("max_targets"), bool)
                or not 1 <= plan["max_targets"] <= _MAX_COLLECTION_TARGETS
            )
        )
        or (
            plan.get("schema_generation") is not None
            and (
                not isinstance(plan["schema_generation"], str)
                or not _GENERATION.fullmatch(plan["schema_generation"])
            )
        )
    ):
        raise ValueError(f"collection checkpoint plan is invalid: {filename}")
    try:
        for source in selected_sources:
            if not isinstance(source, str):
                raise GraphValidationError("source is not text")
            FieldLocator.parse(source)
    except GraphValidationError as exc:
        raise ValueError(f"collection checkpoint sources are invalid: {filename}") from exc
    if value["state"] == "complete" and value["pending_commands"]:
        raise ValueError(f"complete collection checkpoint has pending work: {filename}")
    if value["state"] != "complete" and not value["pending_commands"]:
        raise ValueError(f"incomplete collection checkpoint has no pending work: {filename}")

    run_ids = set()
    pending_commands = value["pending_commands"]
    if len(pending_commands) > len(selected_sources) + 2:
        raise ValueError(f"collection checkpoint has excess pending work: {filename}")
    pending_sources = []
    for index, arguments in enumerate(pending_commands):
        if not isinstance(arguments, list) or not arguments or any(
            not isinstance(argument, str) for argument in arguments
        ):
            raise ValueError(f"collection checkpoint commands are invalid: {filename}")
        run_id = _validate_collection_child(arguments, filename=filename, plan=plan)
        if run_id is not None:
            run_ids.add(run_id)
        if arguments == ["schema", "refresh"]:
            if index != 0:
                raise ValueError(f"collection checkpoint refresh is out of order: {filename}")
        elif arguments == ["schema", "discoveries"]:
            if index != len(pending_commands) - 1:
                raise ValueError(
                    f"collection checkpoint discoveries is out of order: {filename}"
                )
        else:
            pending_sources.append(arguments[2])
    if len(pending_sources) != len(set(pending_sources)) or not set(
        pending_sources
    ).issubset(selected_sources):
        raise ValueError(f"collection checkpoint pending sources are invalid: {filename}")

    generation = plan.get("schema_generation")
    pending_refresh = ["schema", "refresh"] in pending_commands
    if generation is None:
        if value["state"] == "complete" or pending_commands[0] != ["schema", "refresh"]:
            raise ValueError(f"collection checkpoint generation is missing: {filename}")
        for arguments in pending_commands[1:]:
            if arguments[:2] != ["schema", "observe"]:
                continue
            if any(
                flag in arguments
                for flag in ("--schema-generation", "--from-run", "--start-query")
            ):
                raise ValueError(
                    f"pre-refresh collection checkpoint is pre-pinned: {filename}"
                )
    elif pending_refresh:
        raise ValueError(f"collection checkpoint refresh conflicts with generation: {filename}")
    else:
        for arguments in pending_commands:
            if arguments[:2] != ["schema", "observe"]:
                continue
            position = arguments.index("--schema-generation") + 1
            if arguments[position] != generation:
                raise ValueError(f"collection checkpoint generation is mixed: {filename}")

    commands = []
    for row in value["rows"]:
        if not isinstance(row, dict):
            raise ValueError(f"collection checkpoint rows are invalid: {filename}")
        arguments = row.get("Arguments")
        if isinstance(arguments, list):
            commands.append(arguments)
    for arguments in commands:
        if not isinstance(arguments, list) or not arguments or any(
            not isinstance(argument, str) for argument in arguments
        ):
            raise ValueError(f"collection checkpoint commands are invalid: {filename}")
        run_id = _validate_collection_child(arguments, filename=filename, plan=plan)
        if run_id is not None:
            run_ids.add(run_id)
    return run_ids


def _checkpoint_referenced_runs(raw: bytes, *, filename: str, tenant_hash: str) -> set[str]:
    """Decode one portable crawl checkpoint and return retained source runs."""

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"collection checkpoint is invalid: {filename}") from exc
    return validate_collection_checkpoint(value, filename=filename, tenant_hash=tenant_hash)


def _validate_export_payloads(
    payloads: dict[str, tuple[bytes, str]], manifest: dict[str, Any], manifest_raw: bytes
) -> None:
    """Reject an oversized or internally invalid export before creating output."""

    if len(payloads) > _MAX_FILES:
        raise ValueError("bundle contains too many files")
    total_bytes = len(manifest_raw)
    if len(manifest_raw) > _MAX_FILE_BYTES:
        raise ValueError("bundle member has an unsafe size: manifest.json")
    inventory = {item["path"]: item for item in manifest["files"]}
    _validate_inventory_contract(inventory, manifest, manifest["tenant_key"])
    for name, (value, _sensitivity) in payloads.items():
        if len(value) > _MAX_FILE_BYTES:
            raise ValueError(f"bundle member has an unsafe size: {name}")
        total_bytes += len(value)
        if total_bytes > _MAX_TOTAL_BYTES:
            raise ValueError("bundle total uncompressed size exceeds the safety limit")


def export_bundle(
    home: Path,
    tenant_id: str,
    output: Path,
    *,
    include_evidence: bool = True,
    include_sessions: bool = False,
) -> dict[str, Any]:
    """Export current tenant schema state and its referenced evidence."""

    home = home.resolve()
    if output.exists():
        raise FileExistsError(f"bundle output already exists: {output}")
    fingerprint = tenant_fingerprint(tenant_id)
    if fingerprint is None:
        raise ValueError("a configured tenant is required for bundle export")
    tenant_key = hashlib.sha256(tenant_id.encode()).hexdigest()[:12]
    schema_root = home / "schema" / tenant_key
    if not schema_root.is_dir():
        raise ValueError("tenant schema state is missing")
    payloads: dict[str, tuple[bytes, str]] = {}
    payload_bytes = 0

    def add_payload(name: str, source: Path | bytes, sensitivity: str) -> None:
        """Add one bounded payload without reading an oversized source first."""

        nonlocal payload_bytes
        if name in payloads:
            raise ValueError(f"bundle payload is duplicated: {name}")
        if len(payloads) >= _MAX_FILES:
            raise ValueError("bundle contains too many files")
        if isinstance(source, Path):
            try:
                size = source.stat().st_size
            except OSError as exc:
                raise ValueError(f"bundle source is unavailable: {name}") from exc
            if size < 0 or size > _MAX_FILE_BYTES:
                raise ValueError(f"bundle member has an unsafe size: {name}")
            if payload_bytes + size > _MAX_TOTAL_BYTES:
                raise ValueError("bundle total uncompressed size exceeds the safety limit")
            value = source.read_bytes()
            if len(value) != size:
                raise ValueError(f"bundle source size changed while reading: {name}")
        else:
            value = source
            size = len(value)
            if size > _MAX_FILE_BYTES:
                raise ValueError(f"bundle member has an unsafe size: {name}")
            if payload_bytes + size > _MAX_TOTAL_BYTES:
                raise ValueError("bundle total uncompressed size exceeds the safety limit")
        payloads[name] = (value, sensitivity)
        payload_bytes += size

    allowed = (
        "current.json",
        "maintenance.json",
        "semantic.current.json",
    )
    for source in sorted(schema_root.iterdir()):
        if not source.is_file() or source.is_symlink():
            continue
        if source.name in allowed or (
            source.name.startswith(("schema.", "semantic."))
            and source.name.endswith((".jsonl", ".json"))
        ):
            add_payload(
                f"schema/{tenant_key}/{source.name}",
                source,
                "value-free-schema",
            )
    checkpoint_run_ids: set[str] = set()
    checkpoint_root = schema_root / "collection-checkpoints"
    if checkpoint_root.is_dir():
        for source in sorted(checkpoint_root.glob("collect-*.json")):
            if not source.is_file() or source.is_symlink():
                raise ValueError(f"collection checkpoint has an unsafe path: {source.name}")
            raw = source.read_bytes()
            checkpoint_run_ids.update(
                _checkpoint_referenced_runs(
                    raw,
                    filename=source.name,
                    tenant_hash=fingerprint,
                )
            )
            add_payload(
                f"schema/{tenant_key}/collection-checkpoints/{source.name}",
                raw,
                "value-free-schema",
            )
    overlay = load_tenant_overlay_from_root(schema_root)
    active_observation_ids = {item.observation_id for item in overlay.observations}
    referenced_run_ids = checkpoint_run_ids | {
            run_id
            for observation in overlay.observations
            for run_id in (
                observation.source_artifact_run_id,
                observation.target_artifact_run_id,
            )
            if run_id is not None
        }
    proposal_paths: dict[str, Path] = {}
    results_root = home / "results"
    if results_root.is_dir():
        for meta_path in results_root.glob("*/*.meta.json"):
            try:
                metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            binding = metadata.get("tenant_binding")
            run_id = metadata.get("run_id")
            if (
                not isinstance(binding, dict)
                or binding.get("sha256") != fingerprint
                or not isinstance(run_id, str)
                or not _RUN_ID.fullmatch(run_id)
            ):
                continue
            review = metadata.get("candidate_review")
            if (
                isinstance(review, dict)
                and review.get("observation_id") in active_observation_ids
            ):
                referenced_run_ids.add(run_id)
            proposal = metadata.get("candidate_proposal")
            snapshot = proposal.get("evidence_snapshot") if isinstance(proposal, dict) else None
            observation_ids = (
                set(snapshot.get("validated_observation_ids", []))
                if isinstance(snapshot, dict)
                and isinstance(snapshot.get("validated_observation_ids"), list)
                else set()
            )
            if not observation_ids or not observation_ids.issubset(active_observation_ids):
                continue
            evidence_ids: set[str] = set()
            for key in (
                "source_artifact_run_ids",
                "target_artifact_run_ids",
                "review_artifact_run_ids",
            ):
                values = snapshot.get(key)
                if not isinstance(values, list) or any(
                    not isinstance(value, str) or not _RUN_ID.fullmatch(value)
                    for value in values
                ):
                    raise ValueError(f"candidate proposal evidence list is invalid: {run_id}")
                evidence_ids.update(values)
            proposal_path = proposal.get("proposal_path")
            if not isinstance(proposal_path, str) or not Path(proposal_path).is_absolute():
                raise ValueError(f"candidate proposal path is invalid: {run_id}")
            proposal_paths[run_id] = Path(proposal_path)
            referenced_run_ids.update(evidence_ids)
            referenced_run_ids.add(run_id)
    referenced_runs = sorted(referenced_run_ids)
    if (referenced_runs or proposal_paths) and not include_evidence:
        raise ValueError("active overlay has result references; include evidence to export it")
    for run_id in referenced_runs:
        data_path, meta_path = _result_files(home, run_id)
        for source in (data_path, meta_path):
            relative = source.relative_to(home).as_posix()
            add_payload(relative, source, "tenant-result-evidence")
    for run_id, proposal_path in sorted(proposal_paths.items()):
        try:
            proposal_size = proposal_path.stat().st_size
            if proposal_size < 0 or proposal_size > _MAX_FILE_BYTES:
                raise ValueError(
                    f"candidate proposal has an unsafe size: {run_id}"
                )
            if payload_bytes + proposal_size > _MAX_TOTAL_BYTES:
                raise ValueError(
                    "bundle total uncompressed size exceeds the safety limit"
                )
            raw = proposal_path.read_bytes()
        except OSError as exc:
            raise ValueError(f"candidate proposal is unavailable: {run_id}") from exc
        if len(raw) != proposal_size:
            raise ValueError(f"candidate proposal size changed while reading: {run_id}")
        metadata_path = _result_files(home, run_id)[1]
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        binding = metadata["candidate_proposal"]
        unsigned_binding = {
            key: value for key, value in binding.items() if key != "binding_sha256"
        }
        expected_binding = hashlib.sha256(
            json.dumps(
                unsigned_binding, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        snapshot = binding.get("evidence_snapshot")
        unsigned_snapshot = (
            {key: value for key, value in snapshot.items() if key != "sha256"}
            if isinstance(snapshot, dict)
            else {}
        )
        if (
            binding.get("proposal_bytes") != len(raw)
            or binding.get("proposal_sha256") != hashlib.sha256(raw).hexdigest()
            or binding.get("binding_sha256") != expected_binding
            or not isinstance(snapshot, dict)
            or snapshot.get("sha256")
            != hashlib.sha256(
                json.dumps(
                    unsigned_snapshot, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
        ):
            raise ValueError(f"candidate proposal content binding mismatch: {run_id}")
        result_data = _result_files(home, run_id)[0].read_bytes()
        if [
            json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()
        ] != [
            json.loads(line)
            for line in result_data.decode("utf-8").splitlines()
            if line.strip()
        ]:
            raise ValueError(f"candidate proposal rows do not match its result: {run_id}")
        add_payload(
            f"proposals/{run_id}.jsonl",
            raw,
            "reviewed-candidate-proposal",
        )
    portable_files = {name: item[0] for name, item in payloads.items()}
    for name, value in portable_files.items():
        if name.startswith("results/") and name.endswith(".meta.json"):
            _validate_result_pair(name, value, portable_files, fingerprint)
    if include_sessions:
        sessions_root = home / "sessions"
        if sessions_root.is_dir():
            for source in sorted(sessions_root.iterdir()):
                if source.is_file() and not source.is_symlink() and (
                    source.suffix == ".jsonl" or source.name.startswith((".seq-", ".feedback-seq-"))
                ):
                    add_payload(
                        f"sessions/{source.name}",
                        source,
                        "investigation-session-history",
                    )
    inventory = [
        {
            "path": name,
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "sensitivity": sensitivity,
        }
        for name, (value, sensitivity) in sorted(payloads.items())
    ]
    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "tenant_key": tenant_key,
        "tenant_fingerprint": fingerprint,
        "source_build": {
            "version": __version__,
            "source_commit": source_commit(),
            "capabilities": [item["id"] for item in SCHEMA_CAPABILITIES],
        },
        "referenced_result_ids": referenced_runs,
        "candidate_proposal_result_ids": sorted(proposal_paths),
        "files": inventory,
    }
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    _validate_export_payloads(payloads, manifest, manifest_bytes)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.parent / f".{output.name}.{secrets.token_hex(6)}.tmp"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        with tarfile.open(temporary, mode="w:gz") as archive:
            members = [("manifest.json", manifest_bytes)]
            members.extend(
                (name, item[0]) for name, item in sorted(payloads.items())
            )
            for name, value in members:
                info = tarfile.TarInfo(name)
                info.size = len(value)
                info.mode = 0o600
                info.mtime = 0
                archive.addfile(info, io.BytesIO(value))
        if os.name == "posix":
            temporary.chmod(0o600)
        inspected = inspect_bundle(temporary, retain_files=False)
        _link_no_replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    summary = inspected.summary()
    summary.update({"path": str(output.resolve()), "referenced_results": len(referenced_runs)})
    return summary


def _validate_result_pair(
    name: str, value: bytes, files: dict[str, bytes], tenant_hash: str
) -> tuple[str, bytes]:
    metadata = json.loads(value.decode("utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError(f"result metadata is not an object: {name}")
    run_id = Path(name).name.removesuffix(".meta.json")
    if metadata.get("run_id") != run_id or not _RUN_ID.fullmatch(run_id):
        raise ValueError(f"result metadata identity mismatch: {name}")
    data_name = name.removesuffix(".meta.json") + ".jsonl"
    raw = files.get(data_name)
    if raw is None or hashlib.sha256(raw).hexdigest() != metadata.get("data_sha256"):
        raise ValueError(f"result data binding mismatch: {run_id}")
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows) or metadata.get("row_count") != len(rows):
        raise ValueError(f"result row count mismatch: {run_id}")
    binding = metadata.get("tenant_binding")
    if not isinstance(binding, dict) or binding.get("sha256") != tenant_hash:
        raise ValueError(f"result tenant binding mismatch: {run_id}")
    return run_id, raw


def _validate_session_payloads(files: dict[str, bytes]) -> None:
    """Reject malformed session history and counter sidecars before staging."""

    for name, raw in files.items():
        if not name.startswith("sessions/"):
            continue
        filename = PurePosixPath(name).name
        if filename.endswith(".jsonl"):
            session_id = filename.removesuffix(".jsonl")
            try:
                rows = [
                    json.loads(line)
                    for line in raw.decode("utf-8").splitlines()
                    if line.strip()
                ]
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"imported session JSONL is invalid: {name}") from exc
            if (
                not rows
                or any(not isinstance(row, dict) for row in rows)
                or rows[0].get("kind") != "session_started"
                or any(row.get("session_id") != session_id for row in rows)
            ):
                raise ValueError(f"imported session history is invalid: {name}")
            continue
        try:
            counter = int(raw.decode("ascii").strip())
        except (UnicodeError, ValueError) as exc:
            raise ValueError(f"imported session sidecar is invalid: {name}") from exc
        if counter < 0:
            raise ValueError(f"imported session sidecar is invalid: {name}")


def import_bundle(home: Path, tenant_id: str, archive: Path) -> dict[str, Any]:
    """Validate, relocate, and publish a same-tenant bundle with rollback."""

    home = home.resolve()
    inspected = inspect_bundle(archive)
    tenant_hash = tenant_fingerprint(tenant_id)
    tenant_key = hashlib.sha256(tenant_id.encode()).hexdigest()[:12]
    if (
        tenant_hash is None
        or inspected.manifest["tenant_fingerprint"] != tenant_hash
        or inspected.manifest["tenant_key"] != tenant_key
    ):
        raise ValueError("foreign-tenant bundles are inspection-only and cannot be activated")
    rewritten = dict(inspected.files)
    imported_runs: set[str] = set()
    declared_value = inspected.manifest.get("referenced_result_ids")
    proposal_value = inspected.manifest.get("candidate_proposal_result_ids", [])
    if not isinstance(declared_value, list) or not isinstance(proposal_value, list):
        raise ValueError("bundle result or proposal inventory is invalid")
    declared_runs = set(declared_value)
    proposal_runs = set(proposal_value)
    if any(
        not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id)
        for run_id in declared_runs
    ):
        raise ValueError("bundle result inventory contains an invalid run ID")
    if not proposal_runs.issubset(declared_runs):
        raise ValueError("bundle proposal inventory is not part of its result inventory")
    for name, value in list(rewritten.items()):
        if name.startswith("results/") and name.endswith(".meta.json"):
            run_id, result_raw = _validate_result_pair(
                name, value, rewritten, tenant_hash
            )
            imported_runs.add(run_id)
            relative = PurePosixPath(name)
            data_destination = (home / Path(*relative.parts[:-1]) / f"{run_id}.jsonl").resolve()
            meta_destination = (home / Path(*relative.parts)).resolve()
            metadata = json.loads(value.decode("utf-8"))
            metadata["data_path"] = str(data_destination)
            metadata["meta_path"] = str(meta_destination)
            if run_id in proposal_runs:
                proposal_name = f"proposals/{run_id}.jsonl"
                proposal_raw = rewritten.get(proposal_name)
                proposal = metadata.get("candidate_proposal")
                if proposal_raw is None or not isinstance(proposal, dict):
                    raise ValueError(f"candidate proposal bundle is incomplete: {run_id}")
                if (
                    proposal.get("proposal_bytes") != len(proposal_raw)
                    or proposal.get("proposal_sha256")
                    != hashlib.sha256(proposal_raw).hexdigest()
                    or [
                        json.loads(line)
                        for line in proposal_raw.decode("utf-8").splitlines()
                        if line.strip()
                    ]
                    != [
                        json.loads(line)
                        for line in result_raw.decode("utf-8").splitlines()
                        if line.strip()
                    ]
                ):
                    raise ValueError(f"candidate proposal content binding mismatch: {run_id}")
                snapshot = proposal.get("evidence_snapshot")
                unsigned_proposal = {
                    key: item
                    for key, item in proposal.items()
                    if key != "binding_sha256"
                }
                unsigned_snapshot = (
                    {
                        key: item
                        for key, item in snapshot.items()
                        if key != "sha256"
                    }
                    if isinstance(snapshot, dict)
                    else {}
                )
                if (
                    proposal.get("binding_sha256")
                    != hashlib.sha256(
                        json.dumps(
                            unsigned_proposal,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest()
                    or not isinstance(snapshot, dict)
                    or snapshot.get("sha256")
                    != hashlib.sha256(
                        json.dumps(
                            unsigned_snapshot,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest()
                ):
                    raise ValueError(f"candidate proposal binding is invalid: {run_id}")
                evidence_ids: set[str] = set()
                for key in (
                    "source_artifact_run_ids",
                    "target_artifact_run_ids",
                    "review_artifact_run_ids",
                ):
                    values = snapshot.get(key)
                    if not isinstance(values, list) or any(
                        not isinstance(item, str) or not _RUN_ID.fullmatch(item)
                        for item in values
                    ):
                        raise ValueError(
                            f"candidate proposal evidence list is invalid: {run_id}"
                        )
                    evidence_ids.update(values)
                if not evidence_ids.issubset(declared_runs):
                    raise ValueError(f"candidate proposal evidence is incomplete: {run_id}")
                proposal_destination = (home / "proposals" / f"{run_id}.jsonl").resolve()
                proposal["proposal_path"] = str(proposal_destination)
                unsigned = {
                    key: item
                    for key, item in proposal.items()
                    if key != "binding_sha256"
                }
                if "binding_sha256" in proposal:
                    proposal["binding_sha256"] = hashlib.sha256(
                        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                metadata["candidate_proposal"] = proposal
                metadata["proposal_path"] = str(proposal_destination)
            rewritten[name] = (
                json.dumps(metadata, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode()
    if imported_runs != declared_runs:
        raise ValueError("bundle result pairs do not match its evidence references")
    checkpoint_runs = set()
    checkpoint_prefix = f"schema/{tenant_key}/collection-checkpoints/"
    for name, value in rewritten.items():
        if name.startswith(checkpoint_prefix):
            checkpoint_runs.update(
                _checkpoint_referenced_runs(
                    value,
                    filename=PurePosixPath(name).name,
                    tenant_hash=tenant_hash,
                )
            )
    if not checkpoint_runs.issubset(declared_runs):
        raise ValueError("imported collection checkpoint evidence is incomplete")
    _validate_session_payloads(rewritten)
    destinations = {
        name: (home / Path(*PurePosixPath(name).parts)).resolve()
        for name in rewritten
    }
    resolved_home = home.resolve()
    if any(resolved_home not in path.parents for path in destinations.values()):
        raise ValueError("bundle destination escapes the configured home")
    staging = home / f".bundle-import-{secrets.token_hex(8)}"
    moved: list[Path] = []
    created_directories: list[Path] = []

    def ensure_destination_directory(directory: Path) -> None:
        missing: list[Path] = []
        current = directory
        while current != home and not current.exists():
            missing.append(current)
            current = current.parent
        for item in reversed(missing):
            item.mkdir(mode=0o700)
            created_directories.append(item)

    session_numbers: dict[Path, set[int]] = {}
    for name in rewritten:
        if not name.startswith("sessions/") or not name.endswith(".jsonl"):
            continue
        match = _SESSION_ID.fullmatch(PurePosixPath(name).name.removesuffix(".jsonl"))
        if match is None:
            raise ValueError(f"imported session has an invalid ID: {name}")
        counter = home / "sessions" / f".counter-{match.group(1)}"
        session_numbers.setdefault(counter, set()).add(int(match.group(2)))
    counter_updates: dict[Path, tuple[bytes | None, bytes]] = {}
    updated_counters: list[Path] = []
    counter_locks = contextlib.ExitStack()
    try:
        for name, value in rewritten.items():
            staged = staging / Path(*PurePosixPath(name).parts)
            staged.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            staged.write_bytes(value)
            if os.name == "posix":
                staged.chmod(0o600)
        staged_schema = staging / "schema" / tenant_key
        overlay = load_tenant_overlay_from_root(staged_schema)
        if any(
            relationship.status is not RelationshipStatus.CANDIDATE
            for relationship in overlay.graph.relationships.values()
        ):
            raise ValueError(
                "imported tenant overlays may contain candidate relationships only"
            )
        cache = schema_cache_status(staged_schema, expected_tenant_key=tenant_key)
        if cache["state"] not in {"missing", "verified"}:
            raise ValueError(f"imported physical cache is {cache['state']}")
        observation_runs = {
            run_id
            for item in overlay.observations
            for run_id in (item.source_artifact_run_id, item.target_artifact_run_id)
            if run_id is not None
        }
        if not observation_runs.issubset(declared_runs):
            raise ValueError("imported overlay evidence references are incomplete")

        # Session allocation uses the same per-initials counter locks. Hold every
        # affected lock through collision checks, publication, and rollback so a
        # concurrent session start cannot reserve an ID while history is imported.
        for counter in sorted(session_numbers):
            ensure_destination_directory(counter.parent)
            counter_locks.enter_context(exclusive_lock(counter))
        for counter, numbers in session_numbers.items():
            prior = counter.read_bytes() if counter.exists() else None
            try:
                prior_value = int((prior or b"0").decode().strip() or "0")
            except (UnicodeError, ValueError) as exc:
                raise ValueError(f"local session counter is invalid: {counter.name}") from exc
            reserved = sorted(number for number in numbers if number <= prior_value)
            if reserved:
                initials = counter.name.removeprefix(".counter-")
                raise FileExistsError(
                    "bundle import would reuse a locally reserved session ID: "
                    f"{initials}-{reserved[0]}"
                )
            desired = max(prior_value, max(numbers))
            counter_updates[counter] = (prior, str(desired).encode())

        collisions = [str(path) for path in destinations.values() if path.exists()]
        if collisions:
            raise FileExistsError(
                f"bundle import would overwrite existing state: {collisions[0]}"
            )
        for name, destination in destinations.items():
            ensure_destination_directory(destination.parent)
            source = staging / Path(*PurePosixPath(name).parts)
            _link_no_replace(source, destination)
            moved.append(destination)
            source.unlink()
        for counter, (_prior, desired) in counter_updates.items():
            ensure_destination_directory(counter.parent)
            temporary = counter.parent / f".{counter.name}.{secrets.token_hex(4)}.tmp"
            try:
                temporary.write_bytes(desired)
                if os.name == "posix":
                    temporary.chmod(0o600)
                os.replace(temporary, counter)
            finally:
                temporary.unlink(missing_ok=True)
            updated_counters.append(counter)
    except Exception:
        for counter in reversed(updated_counters):
            prior = counter_updates[counter][0]
            if prior is None:
                counter.unlink(missing_ok=True)
            else:
                counter.write_bytes(prior)
        for destination in reversed(moved):
            destination.unlink(missing_ok=True)
        for directory in reversed(created_directories):
            with contextlib.suppress(OSError):
                directory.rmdir()
        raise
    finally:
        counter_locks.close()
        if staging.exists():
            shutil.rmtree(staging)
    return {
        "state": "imported",
        "tenant_key": tenant_key,
        "files": len(rewritten),
        "results": len(imported_runs),
        "sessions": sum(name.startswith("sessions/") for name in rewritten),
        "next_command": "xdr schema status",
    }
