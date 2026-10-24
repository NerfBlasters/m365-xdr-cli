"""Retire automatic discovery evidence without weakening explicit evidence pins."""

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

AUTOMATIC_STAGES = frozenset(
    {"local-overlap", "capture-overlap-complete", "local-validation", "identifier-search"}
)


class MetadataIndex(defaultdict):
    def __init__(self):
        super().__init__(list)
        self.created_times = {}


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("evidence timestamp must be timezone-aware")
    return parsed


def index_result_metadata(results_root):
    """One directory traversal per locked publication/prune operation."""
    paths = MetadataIndex()
    for path in results_root.glob("*/*.meta.json"):
        paths[path.name.removesuffix(".meta.json")].append(path)
    return paths


def retired_observation(observation, cutoff, results_root, *, metadata_paths=None):
    if cutoff is None or observation.extra.get("evidence_stage") not in AUTOMATIC_STAGES:
        return False
    if metadata_paths is None:
        metadata_paths = index_result_metadata(results_root)
    for run in observation.evidence_run_ids:
        paths = metadata_paths.get(run, ())
        if len(paths) != 1:
            return True
        times = getattr(metadata_paths, "created_times", {})
        try:
            if run not in times:
                meta = json.loads(paths[0].read_text())
                times[run] = timestamp(meta["created_at"])
            created = times[run]
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            # An invalid automatic reference is not a retention authority.
            # Explicit observations/proposals are handled separately, fail closed.
            times[run] = None
            return True
        if created is None or created < cutoff:
            return True
    return False


def retirement_cutoff(overlay_root: Path):
    from xdr_cli.schema_graph.evidence_cache import cached_evidence
    from xdr_cli.schema_graph.overlay import load_tenant_overlay_from_root

    value = cached_evidence(
        "discovery-retirement",
        str(overlay_root),
        lambda: load_tenant_overlay_from_root(overlay_root).metadata.get(
            "discovery_retired_before"
        ),
    )
    return timestamp(value) if value else None


def verified_reference_validation_references(home: Path) -> frozenset[str]:
    """Protect only live current/scope ledger evidence, across every local tenant.

    The caller holds the schema evidence lock. Immutable historical ledger files
    are not retention authorities. Missing or corrupt active state fails closed
    before a destructive result prune can publish retirement or remove evidence.
    """
    from xdr_cli.exceptions import ArtifactError
    from xdr_cli.schema_graph.probe import validate_lookback
    from xdr_cli.schema_graph.reference import _read_document
    from xdr_cli.schema_graph.reference_state import validation_key, verify_validation_record

    digest_pattern = re.compile(r"[a-f0-9]{64}\Z")
    ledger_pattern = re.compile(r"validation\.[a-f0-9]{24}\.json\Z")
    scope_pattern = re.compile(r"scope\.[a-f0-9]{24}\.json\Z")
    references: set[str] = set()

    def fail(detail):
        error = ArtifactError(
            "Cannot safely prune results because active reference validation "
            f"evidence is invalid: {detail}. Restore the exact state/evidence or "
            "rerun schema init for the affected tenant before pruning.",
            help_command="xdr schema init --skip-refresh --revalidate",
        )
        error.error_code = "SCHEMA_REFERENCE_VALIDATION_INTEGRITY_FAILED"
        return error

    for root in sorted((home / "schema").glob("*/reference-validation")):
        try:
            if root.is_symlink() or root.parent.is_symlink() or not root.is_dir():
                raise ValueError("reference validation root is not a local directory")
            current = root / "current.json"
            scopes = sorted(root.glob("scope.*.json"))
            if not current.exists():
                if scopes or any(root.glob("validation.*.json")):
                    raise ValueError("reference validation current manifest is missing")
                continue
            checked_ledgers = {}
            for pointer in (current, *scopes):
                if pointer != current and not scope_pattern.fullmatch(pointer.name):
                    raise ValueError("reference validation scope filename is invalid")
                if pointer.is_symlink() or not pointer.is_file():
                    raise ValueError("reference validation pointer is not a local file")
                manifest = json.loads(_read_document(pointer))
                if not isinstance(manifest, dict):
                    raise ValueError("reference validation pointer must be an object")
                filename = manifest.get("file")
                if not isinstance(filename, str) or not ledger_pattern.fullmatch(filename):
                    raise ValueError("reference validation pointer has an unsafe filename")
                path = root / filename
                if path.is_symlink() or not path.is_file():
                    raise ValueError("referenced validation ledger is missing or unsafe")
                raw = _read_document(path)
                if hashlib.sha256(raw).hexdigest() != manifest.get("sha256"):
                    raise ValueError("reference validation ledger digest mismatch")
                ledger = json.loads(raw)
                if not isinstance(ledger, dict) or ledger.get("schema_version") != 1:
                    raise ValueError("reference validation ledger version/shape is invalid")
                fingerprint = ledger.get("tenant_fingerprint")
                if (
                    not isinstance(fingerprint, str)
                    or not digest_pattern.fullmatch(fingerprint)
                    or fingerprint[:12] != root.parent.name
                ):
                    raise ValueError("reference validation tenant binding mismatch")
                for key in ("reference_digest", "schema_digest"):
                    if not isinstance(ledger.get(key), str) or not digest_pattern.fullmatch(
                        ledger[key]
                    ):
                        raise ValueError("reference validation contract digest is invalid")
                options = ledger.get("options")
                if (
                    not isinstance(options, dict)
                    or set(options) != {"lookback", "samples", "row_limit"}
                    or type(options.get("samples")) is not int
                    or not 1 <= options["samples"] <= 1000
                    or type(options.get("row_limit")) is not int
                    or not 1 <= options["row_limit"] <= 10000
                ):
                    raise ValueError("reference validation options are invalid")
                validate_lookback(options["lookback"])
                scope_key = validation_key(
                    ledger["reference_digest"],
                    ledger["schema_digest"],
                    options,
                )
                if pointer != current and pointer.name != f"scope.{scope_key}.json":
                    raise ValueError("reference validation scope binding mismatch")
                routes = ledger.get("routes")
                if not isinstance(routes, dict) or any(
                    not isinstance(key, str) or not isinstance(record, dict)
                    for key, record in routes.items()
                ):
                    raise ValueError("reference validation route records are invalid")
                if filename in checked_ledgers:
                    continue
                checked_ledgers[filename] = ledger
                for route_id, record in routes.items():
                    claims = {
                        "matched",
                        "no-source-data",
                        "no-target-data",
                        "no-overlap",
                        "query-failed",
                    }
                    if record.get("run_id") is None and record.get("status") not in claims:
                        continue
                    if not isinstance(
                        record.get("schema_digest"), str
                    ) or not digest_pattern.fullmatch(record["schema_digest"]):
                        raise ValueError("reference validation record schema digest is invalid")
                    if (
                        record.get("reference_digest") != ledger["reference_digest"]
                        or record.get("options") != options
                        or (
                            record.get("schema_digest") != ledger["schema_digest"]
                            and record.get("status") != "query-failed"
                        )
                    ):
                        raise ValueError("reference validation record/ledger contract mismatch")
                    if not verify_validation_record(
                        home,
                        "",
                        route_id,
                        record,
                        expected_tenant_fingerprint=fingerprint,
                    ):
                        raise ValueError(f"referenced result for route {route_id} is invalid")
                    references.add(record["run_id"])
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            raise fail(str(exc)) from exc
    return frozenset(references)


def verified_capture_references(home: Path) -> frozenset[str]:
    """Retain verified artifacts referenced by unfinished capture jobs in every tenant.

    Caller holds the global evidence lock; capture writers hold that same lock
    while publishing a bundle and its ledger reference. Ledgers are atomically
    replaced, so pruning never takes the per-job execution lock.
    """
    from xdr_cli.exceptions import ArtifactError
    from xdr_cli.schema_graph.capture_artifacts import ResultCaptureSink
    from xdr_cli.schema_graph.capture_contract import SliceArtifact
    from xdr_cli.schema_graph.capture_engine import live_capture_references

    protected: set[str] = set()
    index = index_result_metadata(home / "results")
    for root in sorted((home / "schema").glob("*/capture-jobs")):
        try:
            if root.is_symlink() or not root.is_dir():
                raise ValueError("unsafe capture ledger directory")
            references = live_capture_references(root.parent)
            for reference in references:
                run_id = reference["artifact"]["run_id"]
                paths = index.get(run_id, ())
                if len(paths) != 1:
                    raise ValueError("capture evidence is missing or ambiguous")
                meta = json.loads(paths[0].read_text())
                tenant = meta["tenant_binding"]["sha256"]
                if not isinstance(tenant, str) or not tenant.startswith(root.parent.name):
                    raise ValueError("capture ledger belongs to a different tenant")
                sink = ResultCaptureSink(tenant_fingerprint=tenant)
                spec = meta["schema_capture"]
                if spec["binding"] != reference["binding"]:
                    raise ValueError("capture ledger/artifact binding mismatch")
                found = sink._read(
                    paths[0],
                    reference["job_id"],
                    reference["window_id"],
                    expected=reference.get("expected"),
                )
                if found != SliceArtifact.from_dict(reference["artifact"]):
                    raise ValueError("capture evidence failed verification")
                protected.add(run_id)
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            raise ArtifactError(
                "Cannot safely prune results while unfinished capture evidence is invalid. "
                "Restore the capture ledger and artifacts before retrying pruning.",
                help_command="xdr schema collect --explore",
            ) from exc
    return frozenset(protected)
