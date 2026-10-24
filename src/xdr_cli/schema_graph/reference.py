"""Content-bound XDRInternals snapshots; downloaded text is data, never code."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from xdr_cli._lock import exclusive_lock
from xdr_cli.schema_graph.model import FieldLocator

REFERENCE_URLS = {
    "schema": "https://xdrinternals.com/FullSchema-latest.json",
    "relations": "https://xdrinternals.com/data/column-relations.json",
    "structured": "https://xdrinternals.com/data/structured-columns/index.json",
    "actions": "https://xdrinternals.com/ActionTypeSchema-latest.json",
}
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PATH = re.compile(r"(?:\[\]|[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\])*\Z")
_GENERATION = re.compile(r"[A-Za-z0-9_-]{1,100}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


class ReferenceError(ValueError):
    """A reference snapshot is malformed, incompatible or not content-bound."""


@dataclass(frozen=True)
class ReferenceEndpoint:
    table: str
    column: str
    path: tuple[str, ...] = ()
    time_column: str | None = None

    @property
    def locator(self) -> FieldLocator:
        return FieldLocator(self.table, self.column, self.path)

    @classmethod
    def parse(cls, value: object) -> ReferenceEndpoint:
        if not isinstance(value, dict):
            raise ReferenceError("reference endpoint must be an object")
        table, column = value.get("table"), value.get("column")
        time_column = value.get("timeColumn")
        if not all(isinstance(x, str) and _IDENTIFIER.fullmatch(x) for x in (table, column)):
            raise ReferenceError("reference endpoint names must be KQL identifiers")
        if time_column is not None and (
            not isinstance(time_column, str) or not _IDENTIFIER.fullmatch(time_column)
        ):
            raise ReferenceError("reference time column must be a KQL identifier")
        path = value.get("path")
        if path is None:
            parts = ()
        elif isinstance(path, str) and _PATH.fullmatch(path):
            parts = tuple("*" if x == "[]" else x for x in re.findall(
                r"\[\]|[A-Za-z_][A-Za-z0-9_]*", path
            ))
        else:
            raise ReferenceError("unsupported reference endpoint path syntax")
        return cls(table, column, parts, time_column)


@dataclass(frozen=True)
class ReferenceRoute:
    id: str
    title: str
    family: str
    source: ReferenceEndpoint
    target: ReferenceEndpoint
    guidance: str
    record: dict[str, Any]


@dataclass(frozen=True)
class ReferenceSnapshot:
    schema: tuple[dict, ...]
    routes: tuple[ReferenceRoute, ...]
    structured: dict
    actions: tuple[dict, ...]
    digest: str
    generation: str | None = None
    metadata: dict | None = None

    @property
    def table_names(self) -> tuple[str, ...]:
        return tuple(sorted(table["Name"] for table in self.schema))

    @property
    def fields(self) -> dict[tuple[str, str], dict]:
        return {(t["Name"], c["Name"]): c for t in self.schema for c in t["Schema"]}

    @property
    def normalized_tables(self) -> dict[str, dict]:
        from xdr_cli.schema_graph.physical import portal_schema_tables

        return portal_schema_tables(list(self.schema))


def _parse_document(raw: bytes, name: str):
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ReferenceError(f"reference {name} exceeds the document size limit")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReferenceError(f"reference {name} is not supported JSON") from exc


def snapshot_digest(documents: dict[str, bytes]) -> str:
    pairs = [(name, hashlib.sha256(documents[name]).hexdigest()) for name in sorted(REFERENCE_URLS)]
    return hashlib.sha256(json.dumps(pairs, separators=(",", ":")).encode()).hexdigest()


def parse_snapshot(
    documents: dict[str, bytes], *, generation=None, metadata=None,
) -> ReferenceSnapshot:
    if set(documents) != set(REFERENCE_URLS):
        raise ReferenceError("reference snapshot requires all four provider documents")
    data = {name: _parse_document(raw, name) for name, raw in documents.items()}
    schema, relation_data = data["schema"], data["relations"]
    if not isinstance(schema, list) or not schema or len(schema) > 5000:
        raise ReferenceError("reference schema must be a bounded nonempty table list")
    table_names = set()
    for table in schema:
        if not isinstance(table, dict) or not isinstance(table.get("Name"), str):
            raise ReferenceError("reference table lacks its name")
        if not _IDENTIFIER.fullmatch(table["Name"]) or table["Name"] in table_names:
            raise ReferenceError("reference table names must be unique KQL identifiers")
        table_names.add(table["Name"])
        columns = table.get("Schema")
        if not isinstance(columns, list) or len(columns) > 10000:
            raise ReferenceError("reference table columns must be a bounded list")
        seen = set()
        for column in columns:
            if (not isinstance(column, dict) or not isinstance(column.get("Name"), str)
                    or not isinstance(column.get("Type"), str) or column["Name"] in seen):
                raise ReferenceError("reference columns require unique names and explicit types")
            seen.add(column["Name"])
    if (not isinstance(relation_data, dict) or relation_data.get("version") != 1
            or not isinstance(relation_data.get("relations"), list)):
        raise ReferenceError("unsupported reference relationship format")
    if len(relation_data["relations"]) > 10000:
        raise ReferenceError("reference route count exceeds the limit")
    routes = []
    seen_ids = set()
    for item in relation_data["relations"]:
        if not isinstance(item, dict) or any(
            not isinstance(item.get(key), str) or not item[key] for key in ("id", "title", "family")
        ):
            raise ReferenceError("reference route requires id, title and family")
        if (len(item["id"]) > 256 or not re.fullmatch(r"[A-Za-z0-9_-]+", item["id"])
                or item["id"] in seen_ids):
            raise ReferenceError("reference route IDs must be unique safe identifiers")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,127}", item["family"]):
            raise ReferenceError("reference families must be bounded identifier slugs")
        seen_ids.add(item["id"])
        guidance = item.get("guidance", "")
        if not isinstance(guidance, str) or len(guidance) > 32768:
            raise ReferenceError("reference guidance must be bounded text")
        routes.append(ReferenceRoute(
            item["id"], item["title"], item["family"], ReferenceEndpoint.parse(item.get("from")),
            ReferenceEndpoint.parse(item.get("to")), guidance, item,
        ))
    structured, actions = data["structured"], data["actions"]
    if (not isinstance(structured, dict) or structured.get("version") != 1
            or not isinstance(structured.get("entries"), list) or not isinstance(actions, list)):
        raise ReferenceError("unsupported structured-column or action-type format")
    return ReferenceSnapshot(tuple(schema), tuple(routes), structured, tuple(actions),
                             snapshot_digest(documents), generation, metadata)


def reference_root(home: Path) -> Path:
    return home / "reference" / "xdrinternals"


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def publish_snapshot(home: Path, documents: dict[str, bytes], *, origins: dict | None = None):
    parsed = parse_snapshot(documents)
    root = reference_root(home)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    with exclusive_lock(root / ".sync"):
        generation = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(4)
        directory = root / generation
        directory.mkdir(mode=0o700)
        descriptors = {}
        for name, raw in documents.items():
            path = directory / f"{name}.json"
            with path.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                path.chmod(0o600)
            descriptors[name] = {**(origins or {}).get(name, {}),
                                 "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                                 "url": REFERENCE_URLS[name]}
        metadata = {"schema_version": 1, "parser_version": 1, "generation": generation,
                    "digest": parsed.digest, "retrieved_at": datetime.now(UTC).isoformat(),
                    "documents": descriptors}
        _atomic_json(directory / "manifest.json", metadata)
        _atomic_json(root / "current.json", {"generation": generation})
    return parse_snapshot(documents, generation=generation, metadata=metadata)


def load_snapshot(home: Path) -> ReferenceSnapshot | None:
    root = reference_root(home)
    if not (root / "current.json").exists():
        return None
    try:
        generation = json.loads(_read_document(root / "current.json"))["generation"]
        if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
            raise ReferenceError("invalid reference generation")
        directory = root / generation
        metadata = json.loads(_read_document(directory / "manifest.json"))
        if not isinstance(metadata, dict):
            raise ReferenceError("reference manifest must be an object")
        if metadata.get("schema_version") != 1 or metadata.get("generation") != generation:
            raise ReferenceError("reference manifest generation/version mismatch")
        documents = {}
        for name in REFERENCE_URLS:
            spec = metadata["documents"][name]
            if not isinstance(spec, dict):
                raise ReferenceError("reference document descriptor must be an object")
            raw = _read_document(directory / f"{name}.json")
            if (not isinstance(spec.get("sha256"), str) or not _DIGEST.fullmatch(spec["sha256"])
                    or len(raw) != spec["bytes"]
                    or hashlib.sha256(raw).hexdigest() != spec["sha256"]):
                raise ReferenceError(f"reference {name} failed content verification")
            documents[name] = raw
        parsed = parse_snapshot(documents, generation=generation, metadata=metadata)
        if parsed.digest != metadata.get("digest"):
            raise ReferenceError("reference snapshot digest mismatch")
        return parsed
    except (OSError, KeyError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ReferenceError):
            raise
        raise ReferenceError("reference snapshot is unreadable or invalid") from exc


def _read_document(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ReferenceError("reference document exceeds the size limit")
    return raw


def sync_reference(home: Path, *, client: httpx.Client | None = None) -> ReferenceSnapshot:
    """Download public definitions, with no tenant credentials or identifier values."""

    owned = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    try:
        documents, origins = {}, {}
        for name, url in REFERENCE_URLS.items():
            with client.stream("GET", url) as response:
                response.raise_for_status()
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > MAX_DOCUMENT_BYTES:
                        raise ReferenceError(f"reference {name} exceeds the document size limit")
                documents[name] = bytes(data)
                origins[name] = {"etag": response.headers.get("etag"),
                                 "last_modified": response.headers.get("last-modified")}
        return publish_snapshot(home, documents, origins=origins)
    finally:
        if owned:
            client.close()


def import_reference_directory(home: Path, directory: Path) -> ReferenceSnapshot:
    """Load an explicit local snapshot; useful for deterministic/offline setup."""

    return publish_snapshot(home, {
        name: _read_document(directory / f"{name}.json") for name in REFERENCE_URLS
    })
