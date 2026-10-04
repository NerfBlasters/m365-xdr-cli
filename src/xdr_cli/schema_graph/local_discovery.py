"""Incremental private identifier index over existing hunting artifacts.

The index is disposable derived state. Only keyed fingerprints and provenance
are stored, never identifier values. Graph evidence is always reverified against
the original artifacts rather than trusting this index as an authority.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from xdr_cli._lock import exclusive_lock
from xdr_cli.json_expansion import JSON_STRING_COLUMNS
from xdr_cli.schema_graph.evidence_cache import cached_evidence
from xdr_cli.schema_graph.lineage import UnsupportedLineage, recover_field_origins
from xdr_cli.schema_graph.model import FieldLocator, GraphValidationError
from xdr_cli.schema_graph.normalize import NormalizationError, normalize_value

POLICY = "local-overlap-v4-bounded-physical-json"
MAX_VALUE_BYTES = 2048
MAX_VALUE_FIELDS = 100


def identifier(value: object) -> tuple[str, str] | None:
    selected = _classify_identifier(value)
    if selected is None:
        return None
    normalizer, candidate = selected
    # Index exactly the values the probe compiler can reproduce.
    return normalizer, normalize_value(normalizer, candidate)


def _classify_identifier(value: object) -> tuple[str, str] | None:
    """Normalize identifiable strings without claiming an entity namespace."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    if value.upper().startswith("S-1-") and not re.fullmatch(
        r"S-1-5-21-(?:\d+-){3}\d+", value, re.IGNORECASE
    ):
        # Built-in/well-known principals recur across unrelated entities.
        return None
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        return None
    if size > MAX_VALUE_BYTES:
        return None
    try:
        parsed = ipaddress.ip_address(value)
        if not (parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast):
            return "identity", value
        return None
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
        return ("guid-lower", value.lower()) if len(set(value)) >= 5 else None
    if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        # KQL tolower does not reproduce Python casefold/IDNA for Unicode.
        return ("upn-lower", value.lower()) if value.isascii() else None
    if (
        len(value) >= 8
        and len(set(value.lower())) >= 4
        and not any(c.isspace() for c in value)
        and not re.fullmatch(r"\d{4}-\d\d-\d\d[T ].*", value)
    ):
        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            return "sha256-lower", value.lower()
        if re.fullmatch(r"[0-9a-fA-F]{40}", value):
            return "hex40-lower", value.lower()
        if re.fullmatch(r"S-1-(?:\d+-){2,}\d+", value, re.IGNORECASE):
            return "identity", value
        # Opaque identifiers need more structure than ordinary shared vocabulary
        # (process names, action types, vendors). Field names alone prove nothing.
        if (
            len(value) >= 16
            and len(set(value.lower())) >= 8
            and re.fullmatch(r"[A-Za-z0-9_-]+", value)
            and any(c.isalpha() for c in value)
            and any(c.isdigit() for c in value)
        ):
            return "identity", value
    return None


def discoverable_path(path: tuple[str, ...]) -> bool:
    """Allow schema-shaped property names without a shipped property catalog.

    Keys that look like values (addresses, GUIDs, hashes, controls) remain private
    evidence and are reported as excluded rather than becoming graph labels.
    """
    return len(path) <= 12 and all(
        segment == "*"
        or (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", segment) is not None
            and re.fullmatch(r"[0-9a-fA-F-]{32,}", segment) is None
            and (
                not any(char.isdigit() for char in segment)
                or segment.lower() in {"ipv4", "ipv6", "sha1", "sha256", "md5"}
            )
        )
        for segment in path
    )


def _leaves(value: object, path: tuple[str, ...] = (), depth: int = 0):
    if depth > 12:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _leaves(child, (*path, key), depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from _leaves(child, (*path, "*"), depth + 1)
    else:
        yield path, value


def row_identifiers(row: dict, origins, coverage: Counter, tenant_fingerprint=None):
    for column, value in row.items():
        origin = origins.origin(column)
        if origin is None:
            coverage["unattributed_cells"] += 1
            continue
        if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
            if origin.column not in JSON_STRING_COLUMNS or origin.json_path:
                coverage["free_text_json_cells_excluded"] += 1
                continue
            if len(value) > 262144:
                coverage["oversized_json_cells"] += 1
                continue
            try:
                value = json.loads(value)
            except (ValueError, RecursionError):
                coverage["unparseable_json_cells"] += 1
                continue
        for path, scalar in _leaves(value):
            try:
                locator = FieldLocator(origin.table, origin.column, (*origin.json_path, *path))
                # Leave room for interpretation namespace/role prefixes in the
                # bounded stable IDs used by the semantic graph.
                if len(str(locator)) > 768:
                    coverage["unsupported_paths"] += 1
                    continue
            except GraphValidationError:
                coverage["unsupported_paths"] += 1
                continue
            if locator.json_path and not discoverable_path(locator.json_path):
                coverage["private_nested_paths_excluded"] += 1
                continue
            try:
                normalized = identifier(scalar)
            except NormalizationError:
                coverage["rejected_identifier_cells"] += 1
                continue
            if normalized is None:
                if isinstance(scalar, str) and "@" in scalar and not scalar.isascii():
                    coverage["unsupported_normalization_cells"] += 1
                coverage["non_identifier_cells"] += 1
                continue
            if tenant_fingerprint and normalized[0] == "guid-lower" and (
                hashlib.sha256(normalized[1].encode()).hexdigest() == tenant_fingerprint
            ):
                coverage["tenant_constant_cells_excluded"] += 1
                continue
            yield str(locator), normalized[0], normalized[1]


def artifact_metadata(path: Path, root: Path, tenant: str) -> tuple[dict, Path]:
    """Validate registration and tenant binding before opening any data file."""
    meta = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict):
        raise ValueError("invalid-metadata")
    if type(meta.get("row_count")) is not int or meta["row_count"] < 0:
        raise ValueError("invalid-row-count")
    created = meta.get("created_at")
    if (
        not isinstance(created, str)
        or datetime.fromisoformat(created.replace("Z", "+00:00")).tzinfo is None
    ):
        raise ValueError("invalid-evidence-time")
    if datetime.fromisoformat(created.replace("Z", "+00:00")) > datetime.now(UTC):
        raise ValueError("future-evidence-time")
    from xdr_cli.schema_graph.retention import retirement_cutoff, timestamp

    cutoff = retirement_cutoff(root.parent / "schema" / tenant[:12])
    if cutoff is not None and timestamp(created) < cutoff:
        raise ValueError("retired-discovery-evidence")
    binding = meta.get("tenant_binding") or {}
    if not isinstance(binding, dict):
        raise ValueError("different-or-unbound-tenant")
    if binding.get("state") != "bound" or binding.get("sha256") != tenant:
        raise ValueError("different-or-unbound-tenant")
    run_id = meta.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", run_id):
        raise ValueError("invalid-run-id")
    data = Path(meta["data_path"]).resolve()
    if (
        path.is_symlink()
        or data.name != f"{run_id}.jsonl"
        or path.name != f"{run_id}.meta.json"
        or data.parent != path.resolve().parent
        or not data.is_relative_to(root.resolve())
        or Path(meta["meta_path"]).resolve() != path.resolve()
    ):
        raise ValueError("invalid-artifact-registration")
    query = meta.get("query")
    if not isinstance(query, str) or hashlib.sha256(query.encode()).hexdigest() != meta.get(
        "query_sha256"
    ):
        raise ValueError("invalid-query-digest")
    return meta, data


def verified_values(meta_path: Path, root: Path, tenant: str, *, tenant_id: str | None = None):
    """Stream a verified artifact; caller must discard yields if validation fails."""
    meta, data = artifact_metadata(meta_path, root, tenant)
    origins = recover_field_origins(meta["query"])
    coverage: Counter = Counter()
    constant_fingerprint = (
        hashlib.sha256(tenant_id.strip().lower().encode()).hexdigest() if tenant_id else tenant
    )
    digest = hashlib.sha256()
    rows = 0
    with data.open("rb") as stream:
        for line in stream:
            digest.update(line)
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except RecursionError as exc:
                raise ValueError("artifact-json-complexity-limit") from exc
            if not isinstance(row, dict):
                raise ValueError("non-object-row")
            rows += 1
            yield from row_identifiers(row, origins, coverage, constant_fingerprint)
    if digest.hexdigest() != meta.get("data_sha256") or rows != meta.get("row_count"):
        raise ValueError("invalid-data-digest-or-count")


@dataclass(frozen=True)
class LocalPair:
    source: str
    target: str
    normalizer: str
    source_run: str
    target_run: str
    shared_values: int
    observed_at: str

    def __post_init__(self):
        FieldLocator.parse(self.source)
        FieldLocator.parse(self.target)
        if self.normalizer not in {
            "identity",
            "guid-lower",
            "upn-lower",
            "sha256-lower",
            "hex40-lower",
        }:
            raise ValueError("unsupported-local-normalizer")
        if type(self.shared_values) is not int or self.shared_values < 1:
            raise ValueError("invalid-local-overlap-count")
        for run in (self.source_run, self.target_run):
            if not isinstance(run, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", run):
                raise ValueError("invalid-local-artifact-id")
        if datetime.fromisoformat(self.observed_at.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("invalid-local-evidence-time")

    def to_dict(self) -> dict:
        return {
            "SourceLocator": self.source,
            "TargetLocator": self.target,
            "Normalizer": self.normalizer,
            "SharedIdentifiers": self.shared_values,
            "SourceRun": self.source_run,
            "TargetRun": self.target_run,
            "EvidenceStage": "local-overlap",
            "JoinSafe": False,
        }


def discover_local(
    root: Path,
    index_root: Path,
    tenant_id: str,
    *,
    max_artifacts: int | None = None,
) -> tuple[list[LocalPair], dict]:
    """Incrementally index artifacts and return cross-table shared identifiers.

    An optional artifact budget pauses at transaction boundaries. Incomplete
    scans return no publishable pairs, so incomplete retraction cannot activate
    stale evidence. The next call resumes unchanged completed artifacts.
    """
    tenant = hashlib.sha256(tenant_id.strip().encode()).hexdigest()
    index_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        index_root.chmod(0o700)
    with exclusive_lock(index_root / ".local-discovery"):
        key_path = index_root / "local-discovery.key"
        db_path = index_root / "local-discovery.sqlite3"
        if not key_path.exists():
            # A missing key invalidates all prior fingerprints.
            db_path.unlink(missing_ok=True)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
        key = key_path.read_bytes()
        if len(key) != 32:
            raise ValueError("invalid-local-index-key")
        fd = os.open(db_path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(db_path)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS artifacts (
                    run TEXT PRIMARY KEY, stamp TEXT, meta TEXT, digest TEXT,
                    created TEXT, coverage TEXT);
                CREATE TABLE IF NOT EXISTS identifiers (
                    run TEXT, locator TEXT, normalizer TEXT, fingerprint TEXT,
                    PRIMARY KEY(run, locator, normalizer, fingerprint));
                CREATE INDEX IF NOT EXISTS by_value
                    ON identifiers(normalizer, fingerprint, locator);
            """)
            version = f"{POLICY}:{tenant}"
            if db.execute("SELECT value FROM state WHERE key='version'").fetchone() != (version,):
                db.executescript(
                    "DELETE FROM identifiers; DELETE FROM artifacts; DELETE FROM state;"
                )
                db.execute("INSERT INTO state VALUES ('version', ?)", (version,))
                db.commit()
            coverage: Counter = Counter()
            seen = set()
            for path in sorted(root.glob("*/*.meta.json")):
                try:
                    header = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(header, dict) and header.get("command") not in {
                        "hunt run",
                        "library run",
                    }:
                        coverage["other_command_artifacts"] += 1
                        continue
                    meta, data = artifact_metadata(path, root, tenant)
                    if meta.get("command") not in {"hunt run", "library run"}:
                        continue
                    run = meta["run_id"]
                    seen.add(run)
                    stat = data.stat()
                    # Filesystems can have coarse timestamps, so a same-size
                    # rewrite can evade stat-based invalidation. Hash bytes even
                    # on cache hits; unchanged rows need no parsing or indexing.
                    with data.open("rb") as stream:
                        content_digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    coverage["integrity_bytes_read"] += stat.st_size
                    if content_digest != meta.get("data_sha256"):
                        raise ValueError("invalid-data-digest-or-count")
                    stamp = hashlib.sha256(
                        (
                            path.read_text()
                            + content_digest
                            + repr(
                                (
                                    stat.st_size,
                                    stat.st_mtime_ns,
                                    stat.st_ctime_ns,
                                    stat.st_ino,
                                )
                            )
                        ).encode()
                    ).hexdigest()
                    prior = db.execute(
                        "SELECT stamp,coverage FROM artifacts WHERE run=?", (run,)
                    ).fetchone()
                    if prior and prior[0] == stamp:
                        coverage["cached_artifacts"] += 1
                        coverage.update(json.loads(prior[1]))
                        continue
                    if (
                        max_artifacts is not None
                        and coverage["processed_artifacts"] >= max_artifacts
                    ):
                        return [], dict(coverage, complete=False)
                    local: Counter = Counter()
                    origins = recover_field_origins(meta["query"])
                    digest = hashlib.sha256()
                    rows = 0
                    with db:
                        db.execute("DELETE FROM identifiers WHERE run=?", (run,))
                        with data.open("rb") as stream:
                            for line in stream:
                                digest.update(line)
                                if not line.strip():
                                    continue
                                row = json.loads(line)
                                if not isinstance(row, dict):
                                    raise ValueError("non-object-row")
                                rows += 1
                                for locator, normalizer, value in row_identifiers(
                                    row, origins, local,
                                    hashlib.sha256(tenant_id.strip().lower().encode()).hexdigest()
                                ):
                                    fingerprint = hmac.new(
                                        key, (normalizer + "\0" + value).encode(), hashlib.sha256
                                    ).hexdigest()
                                    db.execute(
                                        "INSERT OR IGNORE INTO identifiers VALUES (?,?,?,?)",
                                        (run, locator, normalizer, fingerprint),
                                    )
                        if digest.hexdigest() != meta.get("data_sha256") or rows != meta.get(
                            "row_count"
                        ):
                            raise ValueError("invalid-data-digest-or-count")
                        local["indexed_rows"] = rows
                        db.execute(
                            "INSERT OR REPLACE INTO artifacts VALUES (?,?,?,?,?,?)",
                            (
                                run,
                                stamp,
                                str(path.resolve()),
                                meta["data_sha256"],
                                meta["created_at"],
                                json.dumps(dict(local)),
                            ),
                        )
                    coverage["processed_artifacts"] += 1
                    coverage["bytes_read"] += stat.st_size
                    coverage.update(local)
                except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
                    # Registration/tenant errors also remove previously indexed
                    # artifacts at sweep time. Never keep an old row after error.
                    run = path.name.removesuffix(".meta.json")
                    with db:
                        db.execute("DELETE FROM identifiers WHERE run=?", (run,))
                        db.execute("DELETE FROM artifacts WHERE run=?", (run,))
                    reason = str(exc) if isinstance(exc, UnsupportedLineage) else type(exc).__name__
                    if str(exc) in {
                        "different-or-unbound-tenant",
                        "invalid-data-digest-or-count",
                        "invalid-query-digest",
                        "invalid-artifact-registration",
                    }:
                        reason = str(exc)
                    coverage[f"skipped:{reason}"] += 1
            for (run,) in db.execute("SELECT run FROM artifacts").fetchall():
                if run not in seen:
                    with db:
                        db.execute("DELETE FROM identifiers WHERE run=?", (run,))
                        db.execute("DELETE FROM artifacts WHERE run=?", (run,))
                    coverage["retracted_artifacts"] += 1
            query = """
                WITH eligible AS (
                    SELECT normalizer,fingerprint FROM identifiers
                    GROUP BY normalizer,fingerprint HAVING COUNT(DISTINCT locator) <= ?
                )
                SELECT a.locator,b.locator,a.normalizer,a.run,b.run,
                       COUNT(DISTINCT a.fingerprint),min(sa.created,sb.created)
                FROM identifiers a JOIN identifiers b
                  ON a.fingerprint=b.fingerprint AND a.normalizer=b.normalizer
                 AND a.locator < b.locator AND a.run != b.run
                JOIN eligible e ON a.normalizer=e.normalizer AND a.fingerprint=e.fingerprint
                JOIN artifacts sa ON sa.run=a.run JOIN artifacts sb ON sb.run=b.run
                WHERE sa.digest != sb.digest
                GROUP BY a.locator,b.locator,a.normalizer,a.run,b.run
                ORDER BY COUNT(DISTINCT a.fingerprint) DESC,a.locator,b.locator,a.run,b.run
            """
            pairs = [
                LocalPair(*row)
                for row in db.execute(query, (MAX_VALUE_FIELDS,))
                if FieldLocator.parse(row[0]).table != FieldLocator.parse(row[1]).table
            ]
            coverage["suppressed_frequent_values"] = db.execute(
                """
                SELECT count(*) FROM (
                    SELECT 1 FROM identifiers GROUP BY normalizer,fingerprint
                    HAVING count(DISTINCT locator)>?)""",
                (MAX_VALUE_FIELDS,),
            ).fetchone()[0]
            return pairs, dict(coverage, complete=True, candidate_evidence_pairs=len(pairs))


def pair_values(pair: LocalPair, root: Path, tenant_id: str) -> list[str]:
    """Reverify both original results and recover exact shared values privately."""
    tenant = hashlib.sha256(tenant_id.strip().encode()).hexdigest()
    groups = []
    for run, locator in ((pair.source_run, pair.source), (pair.target_run, pair.target)):

        def load_values(run_id=run):
            paths = list(root.glob(f"*/{run_id}.meta.json"))
            if len(paths) != 1:
                raise ValueError("missing-or-ambiguous-artifact")
            values = {}
            for field, normalizer, value in verified_values(
                paths[0], root, tenant, tenant_id=tenant_id
            ):
                values.setdefault((field, normalizer), set()).add(value)
            return values

        values = cached_evidence(
            "local-identifiers",
            (str(root.resolve()), tenant, run),
            load_values,
        )
        groups.append(values.get((locator, pair.normalizer), set()))
    shared = sorted(groups[0] & groups[1])
    if len(shared) != pair.shared_values:
        raise ValueError("local-overlap-evidence-changed")
    return shared
