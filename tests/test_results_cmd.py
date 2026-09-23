"""CLI tests for local result browsing and explicit cleanup."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from xdr_cli.main import app
from xdr_cli.results import write_result
from xdr_cli.schema_graph.model import ObservationRecord
from xdr_cli.schema_graph.overlay import publish_tenant_overlay

runner = CliRunner()


def _seed(tmp_path, monkeypatch, *, now=None, query="DeviceInfo | take 1"):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    return write_result(
        [{"DeviceName": "host1"}],
        command="hunt run",
        query=query,
        now=now,
    )


def test_results_list_show_query_and_shape(tmp_path, monkeypatch):
    artifact = _seed(tmp_path, monkeypatch)
    run_id = artifact.receipt.run_id

    listed = runner.invoke(app, ["results", "list"])
    assert listed.exit_code == 0, listed.output
    list_value = json.loads(listed.output)
    assert list_value["data"][0]["run_id"] == run_id
    assert list_value["metadata"]["aggregate_stored_bytes"] > 0

    shown = runner.invoke(app, ["results", "show", run_id])
    shown_data = json.loads(shown.output)["data"]
    assert shown_data["query_available"] is True
    assert "query" not in shown_data
    assert shown_data["meta_path"] == artifact.receipt.meta_path

    queried = runner.invoke(app, ["results", "query", run_id])
    assert queried.output == "DeviceInfo | take 1\n"

    headed = runner.invoke(app, ["results", "head", run_id, "--limit", "1"])
    head_value = json.loads(headed.output)
    assert head_value["data"] == [{"DeviceName": "host1"}]
    assert head_value["metadata"]["privacy"] == "private-investigation-values"

    shaped = runner.invoke(app, ["results", "shape", run_id])
    shape = json.loads(shaped.output)
    assert shape["data"][0]["path"] == "DeviceName"
    assert shape["metadata"]["row_count"] == 1


def test_results_head_rejects_tampered_data(tmp_path, monkeypatch):
    artifact = _seed(tmp_path, monkeypatch)
    Path(artifact.receipt.data_path).write_text('{"DeviceName":"tampered"}\n')

    headed = runner.invoke(app, ["results", "head", artifact.receipt.run_id])

    assert headed.exit_code == 12
    assert json.loads(headed.stdout)["error"]["code"] == "RESULT_INTEGRITY_FAILED"


def test_results_rows_filters_and_paginates_records_after_large_prefix(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    artifact = write_result(
        [
            *[
                {"record_type": "event", "id": f"event:{index}"}
                for index in range(150)
            ],
            *[
                {
                    "record_type": "relationship-path-match",
                    "id": f"match:{index}",
                    "value": f"private-{index}",
                }
                for index in range(3)
            ],
        ],
        command="schema correlate",
        preview_rows=0,
    )

    first = runner.invoke(
        app,
        [
            "results",
            "rows",
            artifact.receipt.run_id,
            "--type",
            "relationship-path-match",
            "--limit",
            "2",
        ],
    )
    assert first.exit_code == 0, first.output
    first_value = json.loads(first.stdout)
    assert [row["id"] for row in first_value["data"]] == ["match:0", "match:1"]
    assert first_value["metadata"]["total"] == 3
    assert first_value["metadata"]["has_more"] is True
    assert "--offset 2 --limit 2" in first_value["metadata"]["next_command"]

    second = runner.invoke(
        app,
        [
            "results",
            "rows",
            artifact.receipt.run_id,
            "--type",
            "relationship-path-match",
            "--offset",
            "2",
            "--limit",
            "2",
        ],
    )
    second_value = json.loads(second.stdout)
    assert [row["id"] for row in second_value["data"]] == ["match:2"]
    assert second_value["metadata"]["has_more"] is False
    assert second_value["metadata"]["next_command"] is None


def test_results_prune_requires_yes_noninteractive(tmp_path, monkeypatch):
    old = datetime.now(UTC) - timedelta(days=40)
    artifact = _seed(tmp_path, monkeypatch, now=old)

    refused = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30"],
    )
    assert refused.exit_code != 0
    assert Path(artifact.receipt.data_path).exists()

    pruned = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert pruned.exit_code == 0, pruned.output
    assert json.loads(pruned.output)["data"]["removed_bundles"] == 1
    assert not Path(artifact.receipt.data_path).exists()


def test_results_prune_preserves_candidate_proposal_evidence_until_draft_removed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    old = datetime.now(UTC) - timedelta(days=40)
    source = write_result(
        [{"Value": "source"}],
        command="schema observe source-sample",
        now=old,
        tenant_id="tenant",
        extra_metadata={"probe_stage": "source-sample"},
    )
    target = write_result(
        [{"Value": "target"}],
        command="schema observe target-batch",
        now=old,
        tenant_id="tenant",
        extra_metadata={
            "probe_stage": "target-batch",
            "source_artifact_run_id": source.receipt.run_id,
        },
    )
    review = write_result(
        [{"Value": "review"}],
        command="schema candidate-review",
        now=old,
        tenant_id="tenant",
        extra_metadata={
            "candidate_review": {
                "relationship_id": "rel:candidate",
                "observation_id": "probe:test",
                "source_artifact_run_id": source.receipt.run_id,
            }
        },
    )
    proposal_path = tmp_path / "candidate-proposal.jsonl"
    proposal_rows = [{"record_type": "relationship", "id": "rel:test"}]
    proposal_bytes = (
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in proposal_rows
        )
    ).encode()
    proposal_path.write_bytes(proposal_bytes)
    snapshot = {
        "overlay_generation": "generation-A",
        "validated_observation_ids": ["probe:test"],
        "source_artifact_run_ids": [source.receipt.run_id],
        "target_artifact_run_ids": [target.receipt.run_id],
        "review_artifact_run_ids": [review.receipt.run_id],
    }
    snapshot["sha256"] = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    binding = {
        "proposal_path": str(proposal_path.resolve()),
        "source_candidate_relationship_id": "rel:candidate",
        "proposed_relationship_id": "rel:test",
        "proposal_sha256": hashlib.sha256(proposal_bytes).hexdigest(),
        "proposal_bytes": len(proposal_bytes),
        "evidence_snapshot": snapshot,
    }
    binding["binding_sha256"] = hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    proposal = write_result(
        proposal_rows,
        command="schema candidate-proposal",
        now=old,
        extra_metadata={"candidate_proposal": binding},
        tenant_id="tenant",
    )

    protected = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert protected.exit_code == 0, protected.output
    protected_data = json.loads(protected.stdout)["data"]
    assert protected_data["removed_bundles"] == 0
    assert protected_data["protected_candidate_proposal_bundles"] == 4
    assert protected_data["protected_overlay_evidence_bundles"] == 0
    assert protected_data["protected_candidate_proposal_paths"] == [
        str(proposal_path.resolve())
    ]
    for artifact in (source, target, review, proposal):
        assert Path(artifact.receipt.data_path).exists()

    source_data_path = Path(source.receipt.data_path)
    source_bytes = source_data_path.read_bytes()
    source_data_path.write_text("tampered\n")
    tampered_evidence = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert tampered_evidence.exit_code == 12
    assert json.loads(tampered_evidence.stdout)["error"]["code"] == (
        "SCHEMA_PROPOSAL_INTEGRITY_FAILED"
    )
    source_data_path.write_bytes(source_bytes)

    source_data_path.unlink()
    missing_data = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert missing_data.exit_code == 12
    assert json.loads(missing_data.stdout)["error"]["code"] == (
        "SCHEMA_PROPOSAL_INTEGRITY_FAILED"
    )
    source_data_path.write_bytes(source_bytes)

    source_meta_path = Path(source.receipt.meta_path)
    hidden_meta_path = source_meta_path.with_suffix(".hidden")
    source_meta_path.rename(hidden_meta_path)
    missing_sidecar = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert missing_sidecar.exit_code == 12
    assert json.loads(missing_sidecar.stdout)["error"]["code"] == (
        "SCHEMA_PROPOSAL_INTEGRITY_FAILED"
    )
    hidden_meta_path.rename(source_meta_path)

    source_metadata = json.loads(source_meta_path.read_text())
    wrong_tenant_metadata = dict(source_metadata)
    wrong_tenant_metadata["tenant_binding"] = {
        "state": "bound",
        "sha256": "0" * 64,
    }
    source_meta_path.write_text(json.dumps(wrong_tenant_metadata))
    wrong_tenant = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert wrong_tenant.exit_code == 12
    assert json.loads(wrong_tenant.stdout)["error"]["code"] == (
        "SCHEMA_PROPOSAL_INTEGRITY_FAILED"
    )
    source_meta_path.write_text(json.dumps(source_metadata))

    proposal_path.write_text('{"id":"rel:tampered","record_type":"relationship"}\n')
    tampered_proposal = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert tampered_proposal.exit_code == 12
    assert json.loads(tampered_proposal.stdout)["error"]["code"] == (
        "SCHEMA_PROPOSAL_INTEGRITY_FAILED"
    )
    for artifact in (source, target, review, proposal):
        assert Path(artifact.receipt.data_path).exists()
    proposal_path.write_bytes(proposal_bytes)

    proposal_meta_path = Path(proposal.receipt.meta_path)
    proposal_metadata = json.loads(proposal_meta_path.read_text())
    proposal_metadata["candidate_proposal"]["evidence_snapshot"][
        "source_artifact_run_ids"
    ] = []
    proposal_meta_path.write_text(json.dumps(proposal_metadata))
    tampered_snapshot = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert tampered_snapshot.exit_code == 12
    assert json.loads(tampered_snapshot.stdout)["error"]["code"] == (
        "SCHEMA_PROPOSAL_INTEGRITY_FAILED"
    )
    for artifact in (source, target, review, proposal):
        assert Path(artifact.receipt.data_path).exists()
    proposal_meta_path.write_text(json.dumps(proposal.metadata))

    proposal_path.unlink()
    pruned = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert pruned.exit_code == 0, pruned.output
    assert json.loads(pruned.stdout)["data"]["removed_bundles"] == 4


def test_results_prune_verifies_live_legacy_proposal_and_allows_deletion_release(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    old = datetime.now(UTC) - timedelta(days=40)
    source = write_result(
        [{"Value": "source"}],
        command="schema observe source-sample",
        now=old,
        tenant_id="tenant",
        extra_metadata={"probe_stage": "source-sample"},
    )
    target = write_result(
        [{"Value": "target"}],
        command="schema observe target-batch",
        now=old,
        tenant_id="tenant",
        extra_metadata={
            "probe_stage": "target-batch",
            "source_artifact_run_id": source.receipt.run_id,
        },
    )
    review = write_result(
        [{"Value": "review"}],
        command="schema candidate-review",
        now=old,
        tenant_id="tenant",
        extra_metadata={
            "candidate_review": {
                "relationship_id": "rel:candidate",
                "observation_id": "probe:legacy",
                "source_artifact_run_id": source.receipt.run_id,
            }
        },
    )
    proposal_rows = [{"record_type": "relationship", "id": "rel:legacy"}]
    proposal_path = tmp_path / "legacy-proposal.jsonl"
    proposal_path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in proposal_rows
        )
    )
    snapshot = {
        "overlay_generation": "generation-A",
        "validated_observation_ids": ["probe:legacy"],
        "source_artifact_run_ids": [source.receipt.run_id],
        "target_artifact_run_ids": [target.receipt.run_id],
        "review_artifact_run_ids": [review.receipt.run_id],
    }
    snapshot["sha256"] = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    proposal = write_result(
        proposal_rows,
        command="schema candidate-proposal",
        now=old,
        extra_metadata={
            "candidate_proposal": {
                "proposal_path": str(proposal_path.resolve()),
                "source_candidate_relationship_id": "rel:candidate",
                "proposed_relationship_id": "rel:legacy",
                "evidence_snapshot": snapshot,
            }
        },
        tenant_id="tenant",
    )

    protected = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert protected.exit_code == 0, protected.output
    protected_data = json.loads(protected.stdout)["data"]
    assert protected_data["removed_bundles"] == 0
    assert protected_data["legacy_candidate_proposal_paths"] == [
        str(proposal_path.resolve())
    ]
    for artifact in (source, target, review, proposal):
        assert Path(artifact.receipt.data_path).exists()

    proposal_path.unlink()
    released = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert released.exit_code == 0, released.output
    assert json.loads(released.stdout)["data"]["removed_bundles"] == 4


def test_results_rejects_path_traversal(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    result = runner.invoke(app, ["results", "show", "../config"])
    assert result.exit_code != 0


def test_prune_never_follows_tampered_data_path_outside_results(tmp_path, monkeypatch):
    old = datetime.now(UTC) - timedelta(days=40)
    artifact = _seed(tmp_path, monkeypatch, now=old)
    outside = tmp_path / "must-survive.jsonl"
    outside.write_text('{"important":true}\n')
    meta_path = Path(artifact.receipt.meta_path)
    metadata = json.loads(meta_path.read_text())
    metadata["data_path"] = str(outside)
    meta_path.write_text(json.dumps(metadata))

    result = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert result.exit_code == 12
    assert outside.exists()
    assert Path(artifact.receipt.data_path).exists()


def test_prune_never_redirects_deletion_to_a_protected_bundle(tmp_path, monkeypatch):
    old = datetime.now(UTC) - timedelta(days=40)
    unprotected = _seed(tmp_path, monkeypatch, now=old, query="DeviceInfo | take 1")
    protected = _seed(tmp_path, monkeypatch, now=old, query="DeviceInfo | take 2")
    observation = ObservationRecord(
        observation_id="probe:protected-redirection",
        source_interpretation="interp:Source.Value:namespace:role",
        target_interpretation="interp:Target.Value:namespace:role",
        transform="identity",
        distinct_seeds=3,
        matched_seeds=2,
        source_artifact_run_id=protected.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:protected-redirection",),
        outcome="matched",
    )
    publish_tenant_overlay("", observations=(observation,))
    meta_path = Path(unprotected.receipt.meta_path)
    metadata = json.loads(meta_path.read_text())
    metadata["data_path"] = protected.receipt.data_path
    meta_path.write_text(json.dumps(metadata))

    result = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )

    assert result.exit_code == 12
    assert Path(protected.receipt.data_path).exists()
    assert Path(unprotected.receipt.data_path).exists()


def test_results_shape_is_bounded_and_searchable(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    artifact = write_result(
        [{f"dynamic_{index}": index for index in range(150)}],
        command="hunt run",
    )
    bounded = runner.invoke(app, ["results", "shape", artifact.receipt.run_id])
    parsed = json.loads(bounded.output)
    assert len(parsed["data"]) == 100
    assert parsed["metadata"]["has_more"] is True
    assert parsed["metadata"]["total"] == 150
    assert parsed["metadata"]["full_shape_meta_path"] == artifact.receipt.meta_path

    searched = runner.invoke(
        app,
        ["results", "shape", artifact.receipt.run_id, "--search", "dynamic_149"],
    )
    selected = json.loads(searched.output)
    assert [row["path"] for row in selected["data"]] == ["dynamic_149"]


def test_results_discovery_exposes_copyable_physical_correlation_input(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    artifact = write_result(
        [{"AccountUpn": "user@example.invalid"}],
        command="hunt run",
        physical_lineage_table="EntraIdSignInEvents",
    )

    listed = json.loads(runner.invoke(app, ["results", "list"]).stdout)["data"][0]
    shown = json.loads(
        runner.invoke(app, ["results", "show", artifact.receipt.run_id]).stdout
    )["data"]

    expected = f"EntraIdSignInEvents={artifact.receipt.run_id}"
    assert listed["physical_lineage_table"] == "EntraIdSignInEvents"
    assert listed["correlate_input"] == expected
    assert shown["correlate_input"] == expected
    assert f"--input {expected}" in shown["correlate_command_template"]


def test_results_prune_preserves_referenced_schema_evidence_until_overlay_pruned(
    tmp_path, monkeypatch
):
    old = datetime.now(UTC) - timedelta(days=40)
    artifact = _seed(tmp_path, monkeypatch, now=old)
    observation = ObservationRecord(
        observation_id="probe:retained-evidence",
        source_interpretation="interp:Source.Value:namespace:role",
        target_interpretation="interp:Target.Value:namespace:role",
        transform="identity",
        distinct_seeds=3,
        matched_seeds=2,
        matched_rows=2,
        source_artifact_run_id=artifact.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:retained-evidence",),
        outcome="matched",
        observed_at=old.isoformat().replace("+00:00", "Z"),
        lookback="30d",
    )
    publish_tenant_overlay("", observations=(observation,))

    protected = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert protected.exit_code == 0, protected.output
    protected_data = json.loads(protected.output)["data"]
    assert protected_data["protected_schema_evidence_bundles"] == 1
    assert Path(artifact.receipt.data_path).exists()

    overlay_prune = runner.invoke(
        app,
        [
            "--no-interactive",
            "schema",
            "prune-evidence",
            "--older-than",
            "30",
            "--yes",
        ],
    )
    assert overlay_prune.exit_code == 0, overlay_prune.output
    pruned = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert pruned.exit_code == 0, pruned.output
    assert not Path(artifact.receipt.data_path).exists()


def test_results_prune_fails_closed_when_current_overlay_is_corrupt(
    tmp_path, monkeypatch
):
    old = datetime.now(UTC) - timedelta(days=40)
    artifact = _seed(tmp_path, monkeypatch, now=old)
    observation = ObservationRecord(
        observation_id="probe:retained-corrupt-overlay",
        source_interpretation="interp:Source.Value:namespace:role",
        target_interpretation="interp:Target.Value:namespace:role",
        transform="identity",
        distinct_seeds=3,
        matched_seeds=2,
        source_artifact_run_id=artifact.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:retained-corrupt-overlay",),
        outcome="matched",
    )
    publish_tenant_overlay("", observations=(observation,))
    manifest = next((tmp_path / ".xdr-cli" / "schema").glob("*/semantic.current.json"))
    manifest.write_text("not-json")

    pruned = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )

    assert pruned.exit_code == 12
    assert Path(artifact.receipt.data_path).exists()
    status = runner.invoke(app, ["schema", "status"])
    status_lines = [json.loads(line) for line in status.stdout.splitlines()]
    assert status_lines[1]["semantic_overlay"]["state"] == "invalid"
    assert status_lines[1]["next_command"] == "xdr schema repair-overlay --yes"

    repaired = runner.invoke(app, ["schema", "repair-overlay", "--yes"])
    assert repaired.exit_code == 0, repaired.output
    protected = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )
    assert protected.exit_code == 0, protected.output
    assert Path(artifact.receipt.data_path).exists()


def test_results_prune_fails_closed_when_overlay_manifest_is_missing(
    tmp_path, monkeypatch
):
    old = datetime.now(UTC) - timedelta(days=40)
    artifact = _seed(tmp_path, monkeypatch, now=old)
    observation = ObservationRecord(
        observation_id="probe:orphaned-overlay",
        source_interpretation="interp:Source.Value:namespace:role",
        target_interpretation="interp:Target.Value:namespace:role",
        transform="identity",
        distinct_seeds=3,
        matched_seeds=2,
        source_artifact_run_id=artifact.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:orphaned-overlay",),
        outcome="matched",
    )
    publish_tenant_overlay("", observations=(observation,))
    manifest = next((tmp_path / ".xdr-cli" / "schema").glob("*/semantic.current.json"))
    manifest.unlink()

    pruned = runner.invoke(
        app,
        ["--no-interactive", "results", "prune", "--older-than", "30", "--yes"],
    )

    assert pruned.exit_code == 12
    error = json.loads(pruned.stdout)["error"]
    assert error["help_command"] == "xdr schema repair-overlay --all-local --yes"
    assert Path(artifact.receipt.data_path).exists()
