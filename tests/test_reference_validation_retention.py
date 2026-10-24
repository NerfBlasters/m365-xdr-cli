"""Active reference evidence is retained; historical ledger files have no authority."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from xdr_cli.main import app
from xdr_cli.results import write_result
from xdr_cli.schema_graph.reference_state import save_validation_state, validation_root
from xdr_cli.schema_graph.retention import verified_reference_validation_references

OPTIONS = {"lookback": "7d", "samples": 50, "row_limit": 1000}
REFERENCE_DIGEST = "a" * 64
SCHEMA_DIGEST = "b" * 64
OLD = datetime.now(UTC) - timedelta(days=100)
runner = CliRunner()


def seed_result(tenant="first", *, schema_digest=SCHEMA_DIGEST, status="matched"):
    route_id = "synthetic-route"
    query = "Events | take 1"
    base = {
        "reference_digest": REFERENCE_DIGEST,
        "schema_digest": schema_digest,
        "options": dict(OPTIONS),
        "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
        "constraints_applied": [],
        "validation_scope": "synthetic",
        "time_policy": "time-bounded",
        "warnings": [],
    }
    counts = (
        {"RouteId": route_id, "ErrorCode": "QUERY_ERROR"}
        if status == "query-failed"
        else {
            "RouteId": route_id,
            "SourceValues": 1,
            "TargetValues": 1,
            "MatchedSourceValues": 1,
            "MatchRows": 1,
            "ScanCapped": False,
        }
    )
    if status in {"no-source-data", "no-target-data", "no-overlap"}:
        counts.update(MatchedSourceValues=0, MatchRows=0)
        if status in {"no-source-data", "no-target-data"}:
            counts["TargetValues"] = 0
        if status == "no-source-data":
            counts["SourceValues"] = 0
    artifact = write_result(
        [counts],
        command="schema init validation",
        query=query,
        tenant_id=tenant,
        now=OLD,
        preview_rows=0,
        extra_metadata={"reference_validation": {"reference_id": route_id, **base}},
    )
    record = {**base, "run_id": artifact.receipt.run_id, "status": status, "counts": counts}
    if status == "query-failed":
        record["error_code"] = "QUERY_ERROR"
    return artifact, record


def save(home, record, tenant="first", *, schema_digest=SCHEMA_DIGEST, options=None):
    return save_validation_state(
        home,
        tenant,
        reference_digest=REFERENCE_DIGEST,
        schema_digest=schema_digest,
        options=options or OPTIONS,
        routes={"synthetic-route": record},
    )


def prune():
    return runner.invoke(
        app, ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"]
    )


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    return tmp_path


def test_prune_retains_active_reference_results_for_all_tenants_without_overlays(home):
    active = []
    for tenant in ("first", "second"):
        artifact, record = seed_result(tenant)
        save(home, record, tenant)
        active.append(artifact)
    unrelated = write_result([{"ordinary": True}], command="hunt run", now=OLD)
    assert not list((home / "schema").glob("*/semantic.current.json"))
    result = prune()
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)["data"]
    assert data["protected_reference_validation_bundles"] == 2
    assert data["protected_schema_evidence_bundles"] == 2
    assert data["removed_bundles"] == 1
    assert not Path(unrelated.receipt.data_path).exists()
    for artifact in active:
        assert Path(artifact.receipt.data_path).exists()
        assert Path(artifact.receipt.meta_path).exists()


def test_historical_unreferenced_ledgers_cannot_pin_results_or_block_prune(home):
    old, record = seed_result()
    save(home, record)
    active, new_record = seed_result()
    save(home, new_record)
    root = validation_root(home, "first")
    (root / ("validation." + "f" * 24 + ".json")).write_text("invalid historical ledger")
    assert verified_reference_validation_references(home) == {active.receipt.run_id}
    result = prune()
    assert result.exit_code == 0, result.output
    assert not Path(old.receipt.data_path).exists()
    assert Path(active.receipt.data_path).exists()


def test_current_and_distinct_live_scopes_retain_their_evidence(home):
    first, record = seed_result()
    save(home, record)
    changed_schema = "c" * 64
    second, record = seed_result(schema_digest=changed_schema)
    save(home, record, schema_digest=changed_schema)
    assert verified_reference_validation_references(home) == {
        first.receipt.run_id,
        second.receipt.run_id,
    }
    result = prune()
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["data"]["protected_reference_validation_bundles"] == 2


@pytest.mark.parametrize(
    "status", ["no-source-data", "no-target-data", "no-overlap", "query-failed"]
)
def test_inconclusive_and_failure_execution_evidence_is_retained(home, status):
    artifact, record = seed_result(status=status)
    save(home, record)
    result = prune()
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["data"]["protected_reference_validation_bundles"] == 1
    assert Path(artifact.receipt.data_path).exists()


@pytest.mark.parametrize(
    "damage",
    [
        "missing-data",
        "missing-meta",
        "data-digest",
        "query",
        "stage",
        "tenant",
        "counts",
        "duplicate-run",
        "manifest",
        "ledger",
        "missing-manifest",
        "missing-ledger",
        "scope-key",
        "ledger-tenant",
    ],
)
def test_active_reference_corruption_fails_closed_before_any_result_deletion(home, damage):
    artifact, record = seed_result()
    save(home, record)
    unrelated = write_result([{"ordinary": True}], command="hunt run", now=OLD)
    meta_path = Path(artifact.receipt.meta_path)
    data_path = Path(artifact.receipt.data_path)
    root = validation_root(home, "first")
    manifest_path = root / "current.json"
    manifest = json.loads(manifest_path.read_text())
    ledger_path = root / manifest["file"]
    if damage == "missing-data":
        data_path.unlink()
    elif damage == "missing-meta":
        meta_path.unlink()
    elif damage == "data-digest":
        data_path.write_text("{}\n")
    elif damage in {"query", "stage", "tenant", "counts"}:
        metadata = json.loads(meta_path.read_text())
        if damage == "query":
            metadata["query"] += " | take 0"
        elif damage == "stage":
            metadata["reference_validation"]["reference_id"] = "another-route"
        elif damage == "tenant":
            metadata["tenant_binding"]["sha256"] = "f" * 64
        else:
            metadata["row_count"] = 2
        meta_path.write_text(json.dumps(metadata))
    elif damage == "duplicate-run":
        duplicate = meta_path.parent.parent / "duplicate"
        duplicate.mkdir()
        (duplicate / meta_path.name).write_bytes(meta_path.read_bytes())
    elif damage == "manifest":
        manifest_path.write_text("[]")
    elif damage == "ledger":
        ledger_path.write_text("{}")
    elif damage == "missing-manifest":
        manifest_path.unlink()
    elif damage == "missing-ledger":
        ledger_path.unlink()
    elif damage == "scope-key":
        (root / ("scope." + "e" * 24 + ".json")).write_text(json.dumps(manifest))
    elif damage == "ledger-tenant":
        ledger = json.loads(ledger_path.read_text())
        ledger["tenant_fingerprint"] = "f" * 64
        raw = json.dumps(ledger).encode()
        ledger_path.write_bytes(raw)
        manifest["sha256"] = hashlib.sha256(raw).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
    before = Path(unrelated.receipt.data_path).read_bytes()
    result = prune()
    assert result.exit_code == 12, result.output
    assert json.loads(result.stdout)["error"]["code"] == (
        "SCHEMA_REFERENCE_VALIDATION_INTEGRITY_FAILED"
    )
    assert Path(unrelated.receipt.data_path).read_bytes() == before
    assert Path(unrelated.receipt.meta_path).exists()


@pytest.mark.parametrize("status,accepted", [("matched", False), ("query-failed", True)])
def test_only_verified_query_failures_may_cross_ledger_schema_binding(home, status, accepted):
    artifact, record = seed_result(status=status)
    save(home, record, schema_digest="c" * 64)
    result = prune()
    assert result.exit_code == (0 if accepted else 12), result.output
    assert Path(artifact.receipt.data_path).exists()


@pytest.mark.parametrize("change", ["reference", "options"])
def test_query_failure_carryover_cannot_cross_reference_or_options_binding(home, change):
    artifact, record = seed_result(status="query-failed")
    if change == "reference":
        record["reference_digest"] = "d" * 64
    else:
        record["options"] = {**OPTIONS, "lookback": "1d"}
    save(home, record)
    result = prune()
    assert result.exit_code == 12, result.output
    assert Path(artifact.receipt.data_path).exists()
