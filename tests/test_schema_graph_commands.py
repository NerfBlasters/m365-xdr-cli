from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import PropertyMock
from unittest.mock import patch

import pytest
from click import unstyle
from filelock import Timeout as FileLockTimeout
from typer.testing import CliRunner

from xdr_cli.api.hunting import HuntingResult
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import ArtifactError, QueryError
from xdr_cli.main import _emit_schema_maintenance_advisory, app
from xdr_cli.results import write_result
from xdr_cli.schema_graph.maintenance import maintenance_status
from xdr_cli.schema_graph.model import (
    Cardinality,
    Confidence,
    Direction,
    FieldLocator,
    FieldRecord,
    Graph,
    InterpretationRecord,
    ObservationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    empirical_relationship_from_observations,
    field_id,
    interpretation_id,
    relationship_id,
)
from xdr_cli.schema_graph.overlay import load_tenant_overlay, publish_tenant_overlay


runner = CliRunner()


def _normalized_help(output: str) -> str:
    """Return help text independent of terminal width and ANSI styling."""

    return " ".join(unstyle(output).split())


def test_schema_help_is_actionable_and_examples_are_copyable(config_dir):
    group = runner.invoke(app, ["schema", "--help"])
    collect = runner.invoke(app, ["schema", "collect", "--help"])
    observe = runner.invoke(app, ["schema", "observe", "--help"])
    pivot = runner.invoke(app, ["schema", "pivot", "--help"])
    path = runner.invoke(app, ["schema", "path", "--help"])
    correlate = runner.invoke(app, ["schema", "correlate", "--help"])
    discoveries = runner.invoke(app, ["schema", "discoveries", "--help"])
    candidates = runner.invoke(app, ["schema", "candidates", "--help"])
    review = runner.invoke(app, ["schema", "candidate-review", "--help"])
    proposal = runner.invoke(app, ["schema", "candidate-proposal", "--help"])
    prune = runner.invoke(app, ["schema", "prune-evidence", "--help"])
    repair = runner.invoke(app, ["schema", "repair-overlay", "--help"])
    validate = runner.invoke(app, ["schema", "validate-core", "--help"])
    export = runner.invoke(app, ["schema", "export-opengraph", "--help"])

    assert group.exit_code == 0
    assert "xdr schema refresh" in _normalized_help(group.stdout)
    assert "tables" in group.stdout and "show" in group.stdout
    assert "context.results_command" in _normalized_help(group.stdout)
    normalized_collect_help = _normalized_help(collect.stdout)
    assert "xdr schema tables" in normalized_collect_help
    assert "xdr schema show DeviceNetworkEvents" in normalized_collect_help
    assert (
        "xdr schema collect --source DeviceNetworkEvents.DeviceId --lookback 7d"
        in normalized_collect_help
    )
    assert (
        "xdr schema observe DeviceNetworkEvents.DeviceId --plan-only"
        in _normalized_help(observe.stdout)
    )
    assert "--from-file seeds.txt" in _normalized_help(observe.stdout)
    assert "operator-supplied origin" in _normalized_help(observe.stdout)
    assert "xdr schema discoveries" in _normalized_help(observe.stdout)
    assert "--target-table" in _normalized_help(observe.stdout)
    assert "--exclude-table" in _normalized_help(observe.stdout)
    assert "xdr schema pivot EntraIdSignInEvents.AccountUpn" in _normalized_help(pivot.stdout)
    assert "xdr schema show EntraIdSignInEvents" in _normalized_help(pivot.stdout)
    assert (
        "xdr schema path EntraIdSignInEvents CloudAppEvents" in _normalized_help(path.stdout)
    )
    assert "xdr schema tables" in _normalized_help(path.stdout)
    assert "xdr results list" in _normalized_help(correlate.stdout)
    assert "data digest" in _normalized_help(correlate.stdout)
    assert "observed investigation pivot" in _normalized_help(discoveries.stdout)
    assert "Compatibility alias" in _normalized_help(candidates.stdout)
    assert "xdr schema candidate-review" in _normalized_help(candidates.stdout)
    assert (
        "xdr schema discoveries --include-evidence-refs" in _normalized_help(review.stdout)
    )
    assert "xdr results head RUN_ID" in _normalized_help(review.stdout)
    normalized_proposal_help = _normalized_help(proposal.stdout)
    assert "xdr schema discoveries" in normalized_proposal_help
    assert "--relationship semantic-equivalent" in normalized_proposal_help
    assert "--provenance contract:microsoft-identifier" in normalized_proposal_help
    assert "never an automatic edit" in normalized_proposal_help
    assert "xdr schema prune-evidence --older-than 90 --yes" in _normalized_help(prune.stdout)
    assert "xdr schema repair-overlay --yes" in _normalized_help(repair.stdout)
    assert "--all-local" in _normalized_help(repair.stdout)
    assert "--reset-empty" in _normalized_help(repair.stdout)
    assert "xdr schema validate-core --document" in _normalized_help(validate.stdout)
    assert (
        "xdr schema export-opengraph schema-graph.opengraph.json"
        in _normalized_help(export.stdout)
    )


def test_schema_validate_core_checks_and_updates_generated_document(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    source = Path(__file__).parents[1] / "docs" / "schema_pivots.md"
    document = tmp_path / "schema_pivots.md"
    document.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    checked = runner.invoke(
        app,
        ["schema", "validate-core", "--document", str(document)],
    )
    assert checked.exit_code == 0, checked.output
    receipt = json.loads(checked.stdout.splitlines()[0])
    assert receipt["context"]["GraphState"] == "valid"
    assert receipt["context"]["DocumentState"] == "current"

    document.write_text(
        document.read_text(encoding="utf-8").replace(
            "## Generated semantic route inventory",
            "## Stale semantic route inventory",
            1,
        ),
        encoding="utf-8",
    )
    stale = runner.invoke(
        app,
        ["schema", "validate-core", "--document", str(document)],
    )
    assert stale.exit_code == 13
    updated = runner.invoke(
        app,
        [
            "schema",
            "validate-core",
            "--document",
            str(document),
            "--update-document",
        ],
    )
    assert updated.exit_code == 0, updated.output
    assert "## Generated semantic route inventory" in document.read_text()


def test_schema_validate_core_rejects_malformed_document_markers(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    cases = {
        "unmatched": "prefix\n<!-- BEGIN GENERATED SEMANTIC GRAPH -->\n",
        "reversed": (
            "<!-- END GENERATED SEMANTIC GRAPH -->\n<!-- BEGIN GENERATED SEMANTIC GRAPH -->\n"
        ),
        "duplicate": (
            "<!-- BEGIN GENERATED SEMANTIC GRAPH -->\n"
            "<!-- BEGIN GENERATED SEMANTIC GRAPH -->\n"
            "<!-- END GENERATED SEMANTIC GRAPH -->\n"
        ),
    }
    for name, content in cases.items():
        document = tmp_path / f"{name}.md"
        document.write_text(content)
        result = runner.invoke(
            app,
            [
                "schema",
                "validate-core",
                "--document",
                str(document),
                "--update-document",
            ],
        )
        assert result.exit_code == 13, result.output
        assert json.loads(result.stdout)["error"]["code"] == ("SEMANTIC_DOCUMENT_MARKERS_INVALID")
        assert document.read_text() == content


def test_schema_validate_core_requires_explicit_marker_initialization(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    document = tmp_path / "reference.md"
    document.write_text("# Reference\n")

    missing = runner.invoke(app, ["schema", "validate-core", "--document", str(document)])
    assert missing.exit_code == 13
    assert json.loads(missing.stdout)["error"]["code"] == ("SEMANTIC_DOCUMENT_MARKERS_MISSING")

    initialized = runner.invoke(
        app,
        [
            "schema",
            "validate-core",
            "--document",
            str(document),
            "--update-document",
        ],
    )
    assert initialized.exit_code == 0, initialized.output
    assert "<!-- BEGIN GENERATED SEMANTIC GRAPH -->" in document.read_text()


def test_schema_repair_overlay_has_actionable_quarantined_reset(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    published = publish_tenant_overlay("tenant")
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    data_path = root / f"semantic.{published['generation']}.jsonl"
    data_path.write_text("invalid\n")

    failed = runner.invoke(app, ["schema", "repair-overlay", "--yes"])
    assert failed.exit_code == 12
    error = json.loads(failed.stdout)["error"]
    assert error["code"] == "SCHEMA_OVERLAY_REPAIR_FAILED"
    assert error["help_command"] == ("xdr schema repair-overlay --reset-empty --yes")

    reset = runner.invoke(app, ["schema", "repair-overlay", "--reset-empty", "--yes"])
    assert reset.exit_code == 0, reset.output
    lines = [json.loads(line) for line in reset.stdout.splitlines()]
    assert lines[0]["context"]["reset_overlays"] == 1
    assert lines[1]["reset_empty"] is True
    assert Path(lines[1]["quarantine_path"]).is_dir()
    assert lines[1]["next_command"] == "xdr schema collect"


def test_schema_repair_overlay_reports_lock_contention_actionably(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))

    @contextmanager
    def contested_lock(*_args, **_kwargs):
        raise FileLockTimeout("held")
        yield

    monkeypatch.setattr("xdr_cli.schema_graph.overlay.exclusive_lock", contested_lock)

    result = runner.invoke(app, ["schema", "repair-overlay", "--yes"])

    assert result.exit_code == 13
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "STATE_CONFLICT"
    assert error["retryable"] is True
    assert error["help_command"] == "xdr schema repair-overlay --help"


def test_schema_opengraph_export_is_a_value_free_cli_command(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    destination = tmp_path / "schema.opengraph.json"

    result = runner.invoke(
        app,
        ["schema", "export-opengraph", str(destination)],
    )

    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["context"]["value_free"] is True
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["graph"]["nodes"]
    assert payload["graph"]["edges"]
    assert "user@example" not in destination.read_text(encoding="utf-8").casefold()
    conflict = runner.invoke(
        app,
        ["schema", "export-opengraph", str(destination)],
    )
    assert conflict.exit_code == 13


def test_schema_opengraph_export_ignores_stale_legacy_temp(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    destination = tmp_path / "schema.opengraph.json"
    stale = destination.with_name(f".{destination.name}.tmp")
    stale.write_text("stale")

    result = runner.invoke(app, ["schema", "export-opengraph", str(destination)])

    assert result.exit_code == 0, result.output
    assert json.loads(destination.read_text())["graph"]["nodes"]
    assert stale.read_text() == "stale"


def test_schema_opengraph_export_does_not_overwrite_concurrent_destination(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    destination = tmp_path / "schema.opengraph.json"
    original_link = os.link
    injected = False

    def inject_collision(source, target, *args, **kwargs):
        nonlocal injected
        if Path(target) == destination and not injected:
            destination.write_text("concurrent-owner")
            injected = True
        return original_link(source, target, *args, **kwargs)

    monkeypatch.setattr("xdr_cli.schema_graph.bundle.os.link", inject_collision)
    result = runner.invoke(app, ["schema", "export-opengraph", str(destination)])

    assert result.exit_code == 13
    assert destination.read_text() == "concurrent-owner"
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_schema_opengraph_force_replaces_symlink_not_its_target(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    target = tmp_path / "do-not-overwrite.txt"
    target.write_text("original")
    destination = tmp_path / "schema.opengraph.json"
    destination.symlink_to(target)

    result = runner.invoke(
        app,
        ["schema", "export-opengraph", str(destination), "--force"],
    )

    assert result.exit_code == 0, result.output
    assert not destination.is_symlink()
    assert json.loads(destination.read_text())["graph"]["nodes"]
    assert target.read_text() == "original"


def test_schema_collect_converts_child_process_timeout_to_resumable_failure(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    seen_kwargs = {}

    def timed_out(argv, **kwargs):
        seen_kwargs.update(kwargs)
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=timed_out),
    ):
        result = runner.invoke(
            app,
            ["schema", "collect", "--source", "DeviceNetworkEvents.DeviceId"],
        )

    assert result.exit_code == 14
    receipt, rows = _artifact_rows(result.stdout)
    assert receipt["context"]["pending_commands"] == 3
    assert rows[0]["ErrorCode"] == "CHILD_PROCESS_TIMEOUT"
    assert rows[0]["Retryable"] is True
    assert isinstance(seen_kwargs["timeout"], int)


def test_schema_collect_rejects_oversized_child_control_output(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))

    def oversized(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, "x" * (1024 * 1024 + 1), "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=oversized),
    ):
        result = runner.invoke(
            app,
            ["schema", "collect", "--source", "DeviceNetworkEvents.DeviceId"],
        )

    assert result.exit_code == 14
    _, rows = _artifact_rows(result.stdout)
    assert rows[0]["ErrorCode"] == "CHILD_OUTPUT_LIMIT"
    assert rows[0]["Retryable"] is False


def test_collection_process_stops_retaining_output_at_cap(tmp_path):
    from xdr_cli.commands.schema_cmd import _run_collection_process

    limit = 32 * 1024
    completed = _run_collection_process(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * (4 * 1024 * 1024))"],
        timeout=10,
        env=dict(os.environ),
        cwd=tmp_path,
        output_limit=limit,
    )

    assert completed.stdout_limited is True
    assert len(completed.stdout.encode("utf-8")) == limit + 1


def test_schema_collect_rejects_excessive_source_matrix(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    arguments = ["schema", "collect"]
    for index in range(101):
        arguments.extend(("--source", f"Table{index}.DeviceId"))

    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        result = runner.invoke(app, arguments)

    assert result.exit_code == 6
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "CLI_USAGE_ERROR"
    assert "at most 100 sources" in payload["error"]["message"]


def test_schema_collect_runs_the_default_matrix_and_marks_completion(tmp_path, monkeypatch):
    home = tmp_path / "xdr-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        receipt = {
            "status": "success",
            "run_id": f"run-{len(calls)}",
            "data_path": "/private/result.jsonl",
            "meta_path": "/private/result.meta.json",
        }
        if argv[4:] == ["schema", "refresh"]:
            receipt["context"] = {"schema_cache_generation": "generation-1"}
        elif argv[4:6] == ["schema", "observe"] and len(calls) == 2:
            receipt["context"] = {
                "outcome": "source-no-valid-identifiers",
                "targets_probed": 0,
                "targets_completed": 0,
            }
        return subprocess.CompletedProcess(argv, 0, json.dumps(receipt) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_run),
    ):
        result = runner.invoke(app, ["schema", "collect"])

    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["context"]["maintenance_complete"] is True
    assert receipt["context"]["empty_sources"] == 1
    assert receipt["context"]["next_command"] == "xdr schema discoveries"
    assert receipt["context"]["results_command"] == (
        f"xdr results rows {receipt['run_id']} --offset 0 --limit 100"
    )
    assert len(calls) == 8
    assert calls[0][0][:4] == [sys.executable, "-I", "-m", "xdr_cli"]
    assert calls[0][0][4:] == ["schema", "refresh"]
    assert sum(call[0][4:6] == ["schema", "observe"] for call in calls) == 6
    assert calls[-1][0][4:] == ["schema", "discoveries"]
    assert all(call[1]["env"]["XDR_SCHEMA_MAINTENANCE_CHILD"] == "1" for call in calls)
    assert all("PYTHONPATH" not in call[1]["env"] for call in calls)
    assert all("PYTHONHOME" not in call[1]["env"] for call in calls)
    assert all(call[1]["cwd"] == Path(sys.executable).resolve().parent for call in calls)
    status = maintenance_status(
        "tenant",
        cache_stale_seconds=86400,
        collection_stale_seconds=604800,
    )
    assert status["semantic_collection"]["state"] == "fresh"


def test_schema_collect_treats_unavailable_default_source_as_honest_skip(tmp_path, monkeypatch):
    home = tmp_path / "xdr-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    calls = 0

    def fake_run(argv, **kwargs):
        nonlocal calls
        calls += 1
        if argv[4:6] == ["schema", "observe"] and calls == 2:
            receipt = {
                "status": "error",
                "error": {"code": "SCHEMA_FIELD_UNAVAILABLE"},
            }
            return subprocess.CompletedProcess(argv, 8, json.dumps(receipt) + "\n", "")
        receipt = {
            "status": "success",
            "run_id": f"run-{calls}",
            "data_path": "/private/result.jsonl",
            "meta_path": "/private/result.meta.json",
        }
        if argv[4:] == ["schema", "refresh"]:
            receipt["context"] = {"schema_cache_generation": "generation-1"}
        return subprocess.CompletedProcess(argv, 0, json.dumps(receipt) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_run),
    ):
        result = runner.invoke(app, ["schema", "collect"])

    assert result.exit_code == 0, result.output
    receipt, rows = _artifact_rows(result.stdout)
    assert receipt["context"]["maintenance_complete"] is True
    assert receipt["context"]["skipped_unavailable_sources"] == 1
    assert [row["Outcome"] for row in rows if row.get("Outcome") is not None] == [
        "source-unavailable"
    ]


def test_schema_collect_does_not_hide_unavailable_custom_source(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    calls = 0

    def fake_run(argv, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            receipt = {
                "status": "error",
                "error": {"code": "SCHEMA_FIELD_UNAVAILABLE"},
            }
            return subprocess.CompletedProcess(argv, 8, json.dumps(receipt) + "\n", "")
        receipt = {"status": "success", "run_id": f"run-{calls}"}
        if argv[4:] == ["schema", "refresh"]:
            receipt["context"] = {"schema_cache_generation": "generation-1"}
        return subprocess.CompletedProcess(argv, 0, json.dumps(receipt) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_run),
    ):
        result = runner.invoke(
            app,
            ["schema", "collect", "--source", "DeviceNetworkEvents.DeviceId"],
        )

    assert result.exit_code == 14
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["context"]["maintenance_complete"] is False
    assert receipt["context"]["failed"] == 1


def test_schema_collect_pauses_when_refresh_receipt_omits_generation(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv[4:])
        receipt = {"status": "success", "run_id": "refresh-without-generation"}
        return subprocess.CompletedProcess(argv, 0, json.dumps(receipt) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_run),
    ):
        result = runner.invoke(
            app,
            ["schema", "collect", "--source", "DeviceNetworkEvents.DeviceId"],
        )

    assert result.exit_code == 14
    receipt, rows = _artifact_rows(result.stdout)
    assert calls == [["schema", "refresh"]]
    assert rows[0]["ErrorCode"] == "SCHEMA_REFRESH_RECEIPT_INVALID"
    assert receipt["context"]["maintenance_complete"] is False
    assert receipt["context"]["pending_commands"] == 3


def test_schema_collect_quarantines_partial_observe_and_finishes_other_steps(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    calls = 0

    def fake_run(argv, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            success = {
                "status": "success",
                "run_id": "partial-observe-run",
                "context": {
                    "targets_probed": 40,
                    "targets_completed": 20,
                    "page_complete": True,
                    "quarantined_tables": ["CloudAppEvents"],
                },
            }
            error = {
                "status": "error",
                "error": {
                    "code": "PARTIAL_SUCCESS",
                    "retryable": False,
                    "original": {
                        "type": "PartialSchemaObservation",
                        "failed_batch": 2,
                        "completed_targets": 20,
                        "private_value": "must-not-be-copied",
                    },
                },
            }
            return subprocess.CompletedProcess(
                argv, 14, f"{json.dumps(success)}\n{json.dumps(error)}\n", ""
            )
        success = {"status": "success", "run_id": f"run-{calls}"}
        if argv[4:] == ["schema", "refresh"]:
            success["context"] = {"schema_cache_generation": "generation-1"}
        return subprocess.CompletedProcess(argv, 0, json.dumps(success) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_run),
    ):
        result = runner.invoke(
            app,
            ["schema", "collect", "--source", "DeviceNetworkEvents.DeviceId"],
        )

    assert result.exit_code == 0, result.output
    receipt, rows = _artifact_rows(result.stdout)
    failed = next(row for row in rows if row["ExitCode"] == 14)
    assert failed["RunId"] == "partial-observe-run"
    assert failed["ErrorCode"] == "PARTIAL_SUCCESS"
    assert failed["TargetsCompleted"] == 20
    assert failed["ErrorDetails"] == {
        "type": "PartialSchemaObservation",
        "failed_batch": 2,
        "completed_targets": 20,
    }
    assert "private_value" not in json.dumps(failed)
    assert failed["Outcome"] == "completed-with-quarantined-targets"
    assert receipt["context"]["maintenance_complete"] is True
    assert receipt["context"]["quarantined_tables"] == ["CloudAppEvents"]
    assert receipt["context"]["collection_outcome"] == "complete-with-gaps"
    assert receipt["context"]["next_command"] == "xdr schema discoveries"


def test_schema_collect_automatically_continues_checkpointed_observe_pages(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv[4:])
        command = argv[4:]
        receipt = {"status": "success", "run_id": f"run-{len(calls)}"}
        if command == ["schema", "refresh"]:
            receipt["context"] = {"schema_cache_generation": "generation-1"}
        elif command[:2] == ["schema", "observe"] and "--from-run" not in command:
            receipt["context"] = {
                "page_complete": False,
                "plan_fingerprint": "plan-1",
                "next_command": (
                    "xdr schema observe DeviceNetworkEvents.DeviceId --from-run source-1 "
                    "--start-query 20 --schema-generation generation-1 --lookback 30d "
                    "--samples 5 --batch-size 20 --max-queries 20 --max-targets 40"
                ),
            }
        elif command[:2] == ["schema", "observe"]:
            receipt["context"] = {
                "page_complete": True,
                "plan_fingerprint": "plan-1",
            }
        return subprocess.CompletedProcess(argv, 0, json.dumps(receipt) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_run),
    ):
        result = runner.invoke(
            app,
            ["schema", "collect", "--source", "DeviceNetworkEvents.DeviceId"],
        )

    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["context"]["maintenance_complete"] is True
    assert receipt["context"]["commands"] == 4
    assert calls[0] == ["schema", "refresh"]
    assert calls[1][:3] == ["schema", "observe", "DeviceNetworkEvents.DeviceId"]
    assert calls[1][-2:] == ["--schema-generation", "generation-1"]
    assert "--from-run" in calls[2]
    assert calls[3] == ["schema", "discoveries"]


def test_schema_collect_resume_retries_only_the_checkpointed_command(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    calls = []
    failed_once = False

    def fake_run(argv, **kwargs):
        nonlocal failed_once
        command = argv[4:]
        calls.append(command)
        if command[:2] == ["schema", "observe"] and not failed_once:
            failed_once = True
            error = {"status": "error", "error": {"code": "API_ERROR", "retryable": True}}
            return subprocess.CompletedProcess(argv, 3, json.dumps(error) + "\n", "")
        receipt = {"status": "success", "run_id": f"run-{len(calls)}"}
        if command == ["schema", "refresh"]:
            receipt["context"] = {"schema_cache_generation": "generation-1"}
        elif command[:2] == ["schema", "observe"]:
            receipt["context"] = {"page_complete": True}
        return subprocess.CompletedProcess(argv, 0, json.dumps(receipt) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_run),
    ):
        first = runner.invoke(
            app,
            ["schema", "collect", "--source", "DeviceNetworkEvents.DeviceId"],
        )
        first_receipt = json.loads(first.stdout.splitlines()[0])
        resume_id = first_receipt["context"]["resume_id"]
        resumed = runner.invoke(app, ["schema", "collect", "--resume", resume_id])

    assert first.exit_code == 14
    assert first_receipt["context"]["pending_commands"] == 2
    assert resumed.exit_code == 0, resumed.output
    resumed_receipt = json.loads(resumed.stdout.splitlines()[0])
    assert resumed_receipt["context"]["maintenance_complete"] is True
    assert calls.count(["schema", "refresh"]) == 1
    assert calls[-1] == ["schema", "discoveries"]


def test_schema_collect_plan_only_preflights_once_and_returns_execution_command(
    tmp_path, monkeypatch
):
    home = tmp_path / "xdr-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process") as child,
    ):
        missing = runner.invoke(app, ["schema", "collect", "--plan-only"])
    assert missing.exit_code == 8
    assert json.loads(missing.stdout)["error"]["code"] == "SCHEMA_CACHE_MISSING"
    child.assert_not_called()

    _schema_cache(tmp_path, monkeypatch, [("DeviceNetworkEvents", "DeviceId")])

    def fake_plan(argv, **kwargs):
        success = {"status": "success", "run_id": "plan-run"}
        return subprocess.CompletedProcess(argv, 0, json.dumps(success) + "\n", "")

    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._run_collection_process", side_effect=fake_plan),
    ):
        planned = runner.invoke(
            app,
            [
                "schema",
                "collect",
                "--plan-only",
                "--source",
                "DeviceNetworkEvents.DeviceId",
                "--lookback",
                "7d",
                "--samples",
                "3",
            ],
        )
    assert planned.exit_code == 0, planned.output
    next_command = json.loads(planned.stdout.splitlines()[0])["context"]["next_command"]
    assert next_command.startswith("xdr schema collect --lookback 7d --samples 3")
    assert "--source DeviceNetworkEvents.DeviceId" in next_command
    assert "--plan-only" not in next_command
    assert next_command != "xdr schema candidates"


def test_schema_maintenance_advisory_is_nonblocking_stderr(config_dir):
    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        result = runner.invoke(app, ["--no-quiet", "results", "list"])
        automatic = runner.invoke(app, ["results", "list"])
        quiet = runner.invoke(app, ["--quiet", "results", "list"])

    assert result.exit_code == automatic.exit_code == quiet.exit_code == 0
    assert "Schema maintenance due" in result.stderr
    assert "xdr schema collect" in result.stderr
    assert "Schema maintenance due" not in automatic.stderr
    assert "Schema maintenance due" not in quiet.stderr
    assert json.loads(result.stdout)["status"] == "success"


def test_schema_maintenance_advisory_honors_effective_auto_quiet():
    app_ctx = AppContext(config=Config(tenant_id="tenant"))
    with (
        patch.object(AppContext, "effective_quiet", new_callable=PropertyMock, return_value=True),
        patch("xdr_cli.schema_graph.maintenance.maintenance_advisory_status") as status,
    ):
        _emit_schema_maintenance_advisory(app_ctx, "results list")
    status.assert_not_called()


def test_schema_maintenance_advisory_skips_growing_passive_history_scan(capsys):
    app_ctx = AppContext(config=Config(tenant_id="tenant"), quiet=False)
    with patch(
        "xdr_cli.schema_graph.maintenance.maintenance_advisory_status",
        return_value={"due": False},
    ) as status:
        _emit_schema_maintenance_advisory(app_ctx, "results list")
    assert capsys.readouterr().err == ""
    status.assert_called_once()


def _schema_cache(tmp_path, monkeypatch, fields, *, include_timestamps=True):
    home = tmp_path / "xdr-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    tenant_key = hashlib.sha256(b"default").hexdigest()[:12]
    cache = home / "schema" / tenant_key
    cache.mkdir(parents=True)
    expanded_fields = [(table, column, "String") for table, column in fields]
    if include_timestamps:
        for table in dict.fromkeys(table for table, _column in fields):
            if (table, "Timestamp") not in fields:
                expanded_fields.append((table, "Timestamp", "DateTime"))
    serialized = "".join(
        json.dumps(
            {
                "TableName": table,
                "ColumnName": column,
                "ColumnType": column_type,
                "ColumnOrdinal": ordinal,
            }
        )
        + "\n"
        for ordinal, (table, column, column_type) in enumerate(expanded_fields)
    )
    (cache / "schema.jsonl").write_bytes(serialized.encode("utf-8"))
    (cache / "schema.meta.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "refreshed_at": datetime.now(UTC).isoformat(),
                "row_count": len(expanded_fields),
                "data_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
                "data_bytes": len(serialized.encode()),
                "server_truncation_state": "unknown",
            }
        )
    )
    return home


def _artifact_rows(stdout: str):
    receipt = json.loads(stdout.splitlines()[0])
    return receipt, [
        json.loads(line) for line in Path(receipt["data_path"]).read_text().splitlines() if line
    ]


def test_schema_artifact_receipt_exposes_complete_local_continuation(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("CloudAppEvents", "AccountObjectId"),
            ("DeviceInfo", "DeviceId"),
            ("DeviceNetworkEvents", "DeviceId"),
            ("IdentityInfo", "AccountUpn"),
        ],
    )
    result = runner.invoke(app, ["schema", "tables"])

    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    receipt = json.loads(lines[0])
    assert receipt["rows"] == 4
    assert len(lines) == 3
    assert receipt["context"]["shown"] == 2
    assert receipt["context"]["total"] == 4
    assert receipt["context"]["has_more"] is True
    assert receipt["context"]["next_command"] == (
        f"xdr results rows {receipt['run_id']} --offset 0 --limit 100"
    )
    assert receipt["context"]["results_command"] == (
        f"xdr results rows {receipt['run_id']} --offset 0 --limit 100"
    )

    complete = runner.invoke(
        app,
        ["results", "rows", receipt["run_id"], "--offset", "0", "--limit", "100"],
    )
    assert complete.exit_code == 0, complete.output
    complete_value = json.loads(complete.stdout)
    assert complete_value["metadata"]["shown"] == 4
    assert complete_value["metadata"]["has_more"] is False
    assert [row["TableName"] for row in complete_value["data"]] == [
        "CloudAppEvents",
        "DeviceInfo",
        "DeviceNetworkEvents",
        "IdentityInfo",
    ]


def test_schema_refresh_content_binds_cache_and_tampering_is_actionable(tmp_path, monkeypatch):
    home = tmp_path / "xdr-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    client = AsyncMock()
    client.close = AsyncMock()
    hunting_result = HuntingResult(
        schema=[],
        results=[
            {
                "TableName": "DeviceInfo",
                "ColumnName": "DeviceId",
                "ColumnType": "String",
                "ColumnOrdinal": 0,
            }
        ],
        stats={},
    )
    original_open = Path.open
    cache_temp_newlines = []

    def track_cache_temp_newline(path, *args, **kwargs):
        if path.name.endswith(".jsonl.tmp") and path.parent.parent.name == "schema":
            cache_temp_newlines.append(kwargs.get("newline"))
        return original_open(path, *args, **kwargs)

    with (
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch.object(Path, "open", track_cache_temp_newline),
        patch(
            "xdr_cli.commands.schema_cmd.run_query",
            new=AsyncMock(return_value=hunting_result),
        ),
    ):
        refreshed = runner.invoke(app, ["schema", "refresh"])
    assert refreshed.exit_code == 0, refreshed.output
    manifest = next((home / "schema").glob("*/current.json"))
    generation = json.loads(manifest.read_text())["generation"]
    data_path = manifest.parent / f"schema.{generation}.jsonl"
    meta_path = manifest.parent / f"schema.{generation}.meta.json"
    metadata = json.loads(meta_path.read_text())
    raw = data_path.read_bytes()
    assert metadata["data_sha256"] == hashlib.sha256(raw).hexdigest()
    assert metadata["data_bytes"] == len(raw)
    assert metadata["row_count"] == 1
    assert cache_temp_newlines == ["\n"]

    data_path.write_text("")
    tables = runner.invoke(app, ["schema", "tables"])
    assert tables.exit_code == 12
    error = json.loads(tables.stdout)["error"]
    assert error["code"] == "SCHEMA_CACHE_INVALID"
    assert error["help_command"] == "xdr schema refresh"


def test_schema_pivot_is_cache_only_and_explains_join_safety(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("DeviceInfo", "DeviceId"),
            ("DeviceNetworkEvents", "DeviceId"),
        ],
    )
    with (
        patch("xdr_cli.commands.schema_cmd.AuthManager", side_effect=AssertionError("auth used")),
        patch("xdr_cli.commands.schema_cmd.XDRClient", side_effect=AssertionError("network used")),
    ):
        result = runner.invoke(app, ["schema", "pivot", "DeviceInfo.DeviceId"])
    assert result.exit_code == 0, result.output
    receipt, rows = _artifact_rows(result.stdout)
    assert receipt["context"]["outcome"] == "routes-found"
    assert "does not automatically mean raw join safety" in receipt["context"]["warning"]
    assert rows[0]["Target"] == "DeviceNetworkEvents.DeviceId"
    assert rows[0]["Relationship"] == "join-compatible"
    assert rows[0]["Workflow"] == "direct-join"
    assert rows[0]["SourceNamespace"] == "mde-device-id"
    assert rows[0]["TargetNamespace"] == "mde-device-id"
    assert rows[0]["TraversalDirection"] in {"forward", "reverse"}
    assert rows[0]["Provenance"] == ["curated:mde-device-id-contract"]


def test_schema_pivot_canonicalizes_documented_nested_dotted_shorthand(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("CloudAppEvents", "RawEventData"),
            ("IdentityInfo", "AccountUpn"),
        ],
    )
    pointer = runner.invoke(
        app,
        ["schema", "pivot", "CloudAppEvents.RawEventData#/UserId"],
    )
    dotted = runner.invoke(
        app,
        ["schema", "pivot", "CloudAppEvents.RawEventData.UserId"],
    )

    assert pointer.exit_code == dotted.exit_code == 0
    pointer_receipt, pointer_rows = _artifact_rows(pointer.stdout)
    dotted_receipt, dotted_rows = _artifact_rows(dotted.stdout)
    assert dotted_rows == pointer_rows
    assert dotted_receipt["context"]["locator"] == ("CloudAppEvents.RawEventData#/UserId")
    assert dotted_receipt["context"]["outcome"] == pointer_receipt["context"]["outcome"]


def test_schema_path_is_cache_only_and_symmetric(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("DeviceInfo", "DeviceId"),
            ("DeviceNetworkEvents", "DeviceId"),
        ],
    )
    forward = runner.invoke(
        app,
        ["schema", "path", "DeviceInfo", "DeviceNetworkEvents"],
    )
    reverse = runner.invoke(
        app,
        ["schema", "path", "DeviceNetworkEvents", "DeviceInfo"],
    )
    assert forward.exit_code == reverse.exit_code == 0
    _, forward_rows = _artifact_rows(forward.stdout)
    _, reverse_rows = _artifact_rows(reverse.stdout)
    assert forward_rows[0]["DirectJoin"] is True
    assert forward_rows[0]["RouteKind"] == "direct-join"
    assert forward_rows[0]["HopCount"] == 1
    assert forward_rows[0]["AllStepsJoinCompatible"] is True
    assert reverse_rows[0]["DirectJoin"] is True
    assert forward_rows[0]["Source"] == reverse_rows[0]["Target"]


def test_schema_path_labels_reviewed_multi_hop_join_route(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("EntraIdSignInEvents", "AccountObjectId"),
            ("IdentityInfo", "AccountObjectId"),
            ("CloudAppEvents", "AccountObjectId"),
        ],
    )

    result = runner.invoke(
        app,
        ["schema", "path", "EntraIdSignInEvents", "CloudAppEvents"],
    )

    assert result.exit_code == 0, result.output
    _, rows = _artifact_rows(result.stdout)
    first_path = [row for row in rows if row["Path"] == 1]
    assert len(first_path) == 2
    assert all(row["DirectJoin"] is False for row in first_path)
    assert all(row["RouteKind"] == "multi-hop-join" for row in first_path)
    assert all(row["HopCount"] == 2 for row in first_path)
    assert all(row["AllStepsJoinCompatible"] is True for row in first_path)


def test_unknown_semantic_locator_has_corrective_error(tmp_path, monkeypatch):
    _schema_cache(tmp_path, monkeypatch, [("DeviceInfo", "DeviceId")])
    result = runner.invoke(app, ["schema", "pivot", "DeviceInfo.DoesNotExist"])
    assert result.exit_code == 8
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "SCHEMA_UNKNOWN_SEMANTIC_FIELD"
    assert error["help_command"] == "xdr schema show DeviceInfo"


def test_effective_graph_conflict_is_actionable_domain_error(tmp_path, monkeypatch):
    _schema_cache(tmp_path, monkeypatch, [("DeviceInfo", "DeviceId")])
    locator = FieldLocator.parse("DeviceInfo.DeviceId")
    conflicting = Graph()
    conflicting.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="long"))
    publish_tenant_overlay("default", graph=conflicting)

    result = runner.invoke(app, ["schema", "pivot", "DeviceInfo.DeviceId"])

    assert result.exit_code == 13
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "SCHEMA_EFFECTIVE_GRAPH_CONFLICT"
    assert error["help_command"] == "xdr schema repair-overlay --help"
    assert "packaged=" in error["message"]
    assert "tenant=" in error["message"]
    assert [item["message"] for item in error["suggestions"]] == [
        "xdr schema status",
        "xdr schema repair-overlay --help",
    ]


def test_path_empty_result_is_honest_success(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [("DeviceInfo", "DeviceId"), ("EmailEvents", "NetworkMessageId")],
    )
    result = runner.invoke(app, ["schema", "path", "DeviceInfo", "EmailEvents"])
    assert result.exit_code == 0, result.output
    receipt, rows = _artifact_rows(result.stdout)
    assert rows == []
    assert receipt["context"]["outcome"] == "disconnected"


def test_schema_path_rejects_unknown_table_with_discovery_command(tmp_path, monkeypatch):
    _schema_cache(tmp_path, monkeypatch, [("DeviceInfo", "DeviceId")])

    result = runner.invoke(app, ["schema", "path", "TypoTable", "DeviceInfo"])

    assert result.exit_code == 8
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "SCHEMA_UNKNOWN_TABLE"
    assert error["help_command"] == "xdr schema tables --search TypoTable"


def _probe_graph():
    graph = Graph()
    for table in ("SourceTable", "TargetTable"):
        locator = FieldLocator.parse(f"{table}.DeviceId")
        graph.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="string"))
        graph.add(
            InterpretationRecord(
                id=interpretation_id(locator, "mde-device-id", "subject"),
                field_id=field_id(locator),
                entity_kind="device",
                namespace="mde-device-id",
                role="subject",
                normalizer="hex40-lower",
            )
        )
    graph.validate_references()
    return graph


def test_schema_observe_invalid_lookback_is_actionable_usage_error(tmp_path, monkeypatch):
    _schema_cache(tmp_path, monkeypatch, [("SourceTable", "DeviceId")])
    result = runner.invoke(
        app,
        ["schema", "observe", "SourceTable.DeviceId", "--lookback", "30days"],
    )

    assert result.exit_code == 6
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "CLI_USAGE_ERROR"
    assert error["help_command"] == "xdr schema observe --help"
    assert "30d" in error["message"]


def test_schema_observe_rejects_unbounded_source_and_excludes_unbounded_targets(
    tmp_path, monkeypatch
):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [("SourceTable", "DeviceId")],
        include_timestamps=False,
    )
    graph = _probe_graph()
    with patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph):
        rejected = runner.invoke(
            app,
            ["schema", "observe", "SourceTable.DeviceId", "--plan-only"],
        )
    assert rejected.exit_code == 13
    error = json.loads(rejected.stdout)["error"]
    assert error["code"] == "SCHEMA_PROBE_TEMPORAL_COLUMN_MISSING"
    assert error["help_command"] == "xdr schema show SourceTable --search Time"
    assert "free space" not in str(error["suggestions"]).lower()

    _schema_cache(
        tmp_path / "bounded",
        monkeypatch,
        [
            ("SourceTable", "DeviceId"),
            ("SourceTable", "Timestamp"),
            ("TargetTable", "DeviceId"),
        ],
        include_timestamps=False,
    )
    with patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph):
        planned = runner.invoke(
            app,
            ["schema", "observe", "SourceTable.DeviceId", "--plan-only"],
        )
    assert planned.exit_code == 0, planned.output
    receipt, rows = _artifact_rows(planned.stdout)
    assert receipt["context"]["excluded_unbounded_targets"] >= 1
    assert all(not row["TargetLocator"].startswith("TargetTable.") for row in rows)

    _schema_cache(
        tmp_path / "timegenerated",
        monkeypatch,
        [
            ("SourceTable", "DeviceId"),
            ("SourceTable", "Timestamp"),
            ("TargetTable", "DeviceId"),
            ("TargetTable", "TimeGenerated"),
        ],
        include_timestamps=False,
    )
    with patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph):
        alternate_time = runner.invoke(
            app,
            ["schema", "observe", "SourceTable.DeviceId", "--plan-only"],
        )
    assert alternate_time.exit_code == 0, alternate_time.output
    alternate_receipt, alternate_rows = _artifact_rows(alternate_time.stdout)
    assert alternate_receipt["context"]["excluded_unbounded_targets"] == 0
    assert any(row["TargetLocator"] == "TargetTable.DeviceId" for row in alternate_rows)


def test_schema_observe_uses_file_seeds_but_persists_only_counts(tmp_path, monkeypatch):
    home = _schema_cache(
        tmp_path,
        monkeypatch,
        [("SourceTable", "DeviceId"), ("TargetTable", "DeviceId")],
    )
    secret = "A" * 40
    seed_file = tmp_path / "seeds.txt"
    seed_file.write_text(secret + "\n")
    client = AsyncMock()
    client.close = AsyncMock()
    hunting_result = HuntingResult(
        schema=[
            {"name": "TargetLocator", "type": "String"},
            {"name": "MatchedSeeds", "type": "Int64"},
            {"name": "MatchRows", "type": "Int64"},
        ],
        results=[
            {
                "TargetLocator": "TargetTable.DeviceId",
                "TargetInterpretation": ("interp:TargetTable.DeviceId:mde-device-id:subject"),
                "MatchedSeeds": 1,
                "MatchRows": 2,
            }
        ],
        stats={},
    )
    with (
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=_probe_graph()),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.schema_cmd.run_query",
            new=AsyncMock(return_value=hunting_result),
        ) as run,
    ):
        result = runner.invoke(
            app,
            ["schema", "observe", "SourceTable.DeviceId", "--from-file", str(seed_file)],
        )
    assert result.exit_code == 0, result.output
    assert run.await_count == 1
    receipt, rows = _artifact_rows(result.stdout)
    assert receipt["context"]["targets_probed"] == 1
    assert rows[0]["matched_seeds"] == 1
    assert rows[0]["outcome"] == "matched"
    assert rows[0]["source_artifact_run_id"]
    assert rows[0]["target_artifact_run_id"]
    assert rows[0]["source_evidence_kind"] == "operator-supplied"
    report_metadata = json.loads(Path(receipt["meta_path"]).read_text())
    source_run_id = report_metadata["stage_run_ids"][0]
    source_meta_path = next((home / "results").glob(f"*/{source_run_id}.meta.json"))
    source_metadata = json.loads(source_meta_path.read_text())
    assert source_metadata["probe_stage"] == "source-explicit"
    assert source_metadata["seed_source"] == "file"
    assert source_metadata["lookback"] == "30d"
    assert Path(source_metadata["data_path"]).read_text().strip() == json.dumps(
        {"Value": secret.lower()}, separators=(",", ":")
    )
    semantic_files = list((home / "schema").rglob("semantic.*.jsonl"))
    assert semantic_files
    assert secret not in semantic_files[-1].read_text()
    assert secret.lower() not in semantic_files[-1].read_text()
    with patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=_probe_graph()):
        candidates = runner.invoke(app, ["schema", "candidates"])
    assert candidates.exit_code == 0, candidates.output
    _, candidate_rows = _artifact_rows(candidates.stdout)
    assert candidate_rows[0]["ValidatedPositiveRuns"] == 0
    assert candidate_rows[0]["MissingEvidenceReferenceCount"] == 0
    assert candidate_rows[0]["MismatchedEvidenceArtifactCount"] == 0
    assert (
        "operator-supplied-source-values-require-origin-review"
        in (candidate_rows[0]["AutomatedConcerns"])
    )


def test_schema_observe_empty_sample_is_successful_noop_for_automation(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [("SourceTable", "DeviceId"), ("TargetTable", "DeviceId")],
    )
    client = AsyncMock()
    client.close = AsyncMock()
    empty = HuntingResult(schema=[], results=[], stats={})
    with (
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=_probe_graph()),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.schema_cmd.run_query",
            new=AsyncMock(return_value=empty),
        ) as run,
    ):
        result = runner.invoke(app, ["schema", "observe", "SourceTable.DeviceId"])

    assert result.exit_code == 0, result.output
    assert run.await_count == 1
    receipt, rows = _artifact_rows(result.stdout)
    assert rows == []
    assert receipt["context"]["outcome"] == "source-no-valid-identifiers"
    assert receipt["context"]["targets_probed"] == 0


def test_schema_discoveries_ignores_relationships_with_only_negative_evidence(
    tmp_path, monkeypatch
):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [("SourceTable", "DeviceId"), ("TargetTable", "DeviceId")],
    )
    graph = _probe_graph()
    source = next(
        item.id
        for item in graph.interpretations.values()
        if str(graph.fields[item.field_id].locator) == "SourceTable.DeviceId"
    )
    target = next(
        item.id
        for item in graph.interpretations.values()
        if str(graph.fields[item.field_id].locator) == "TargetTable.DeviceId"
    )
    observation = ObservationRecord(
        observation_id="probe:negative-only",
        source_interpretation=source,
        target_interpretation=target,
        transform="hex40-lower",
        distinct_seeds=5,
        matched_seeds=0,
        matched_rows=0,
        probe_runs=1,
        provenance=("tenant-observation:negative-only",),
        outcome="no-match",
    )
    publish_tenant_overlay("default", graph=Graph(), observations=(observation,))

    with patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph):
        result = runner.invoke(app, ["schema", "discoveries"])

    assert result.exit_code == 0, result.output
    _receipt, rows = _artifact_rows(result.stdout)
    assert rows == []


def test_schema_observe_discovers_unmodeled_cross_name_target(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [("SourceTable", "DeviceId"), ("OddTable", "Initiator")],
    )
    graph = Graph()
    locator = FieldLocator.parse("SourceTable.DeviceId")
    graph.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="string"))
    graph.add(
        InterpretationRecord(
            id=interpretation_id(locator, "mde-device-id", "subject"),
            field_id=field_id(locator),
            entity_kind="device",
            namespace="mde-device-id",
            role="subject",
            normalizer="hex40-lower",
        )
    )
    seed_file = tmp_path / "seeds.txt"
    seed_file.write_text("A" * 40 + "\n")
    client = AsyncMock()
    client.close = AsyncMock()
    result_row = {
        "TargetLocator": "OddTable.Initiator",
        "TargetInterpretation": "interp:OddTable.Initiator:mde-device-id:neutral",
        "MatchedSeeds": 1,
        "MatchRows": 3,
    }
    hunting_result = HuntingResult(schema=[], results=[result_row], stats={})
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.schema_cmd.run_query",
            new=AsyncMock(return_value=hunting_result),
        ),
    ):
        observed = runner.invoke(
            app,
            ["schema", "observe", "SourceTable.DeviceId", "--from-file", str(seed_file)],
        )
        pivoted = runner.invoke(
            app,
            ["schema", "pivot", "SourceTable.DeviceId"],
        )
        candidates = runner.invoke(app, ["schema", "discoveries"])
        recursive = runner.invoke(
            app,
            ["schema", "observe", "OddTable.Initiator", "--plan-only"],
        )
    assert observed.exit_code == 0, observed.output
    assert pivoted.exit_code == 0, pivoted.output
    _, rows = _artifact_rows(pivoted.stdout)
    assert rows[0]["Target"] == "OddTable.Initiator"
    assert rows[0]["Candidate"] is False
    assert rows[0]["EvidenceLevel"] == "observed"
    assert rows[0]["Observed"] is True
    assert rows[0]["JoinSafe"] is False
    assert candidates.exit_code == 0, candidates.output
    candidate_receipt, candidate_rows = _artifact_rows(candidates.stdout)
    assert candidate_receipt["context"]["value_free"] is True
    assert candidate_rows[0]["MatchedRows"] == 3
    assert candidate_rows[0]["JoinSafe"] is False
    assert candidate_rows[0]["EvidenceGate"] == "insufficient"
    assert (
        "needs-at-least-two-verified-sampled-positive-runs"
        in candidate_rows[0]["BlockingReasons"]
    )
    assert candidate_rows[0]["ReviewDecision"] == "programmatic"
    assert candidate_rows[0]["EvidenceLevel"] == "observed"
    assert recursive.exit_code == 12
    assert json.loads(recursive.stdout)["error"]["code"] == ("SCHEMA_PROVISIONAL_SOURCE_REJECTED")


def test_schema_observe_plan_only_is_cache_only_and_exhaustive(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("SourceTable", "DeviceId"),
            ("TargetTable", "DeviceId"),
            ("OddTable", "Initiator"),
            ("OddTable", "OtherValue"),
        ],
    )
    with (
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=_probe_graph()),
        patch("xdr_cli.commands.schema_cmd.AuthManager", side_effect=AssertionError("auth used")),
        patch("xdr_cli.commands.schema_cmd.XDRClient", side_effect=AssertionError("network used")),
    ):
        result = runner.invoke(
            app,
            ["schema", "observe", "SourceTable.DeviceId", "--plan-only"],
        )
        limited = runner.invoke(
            app,
            [
                "schema",
                "observe",
                "SourceTable.DeviceId",
                "--plan-only",
                "--max-targets",
                "1",
            ],
        )
    assert result.exit_code == 0, result.output
    receipt, rows = _artifact_rows(result.stdout)
    assert receipt["context"]["networked"] is False
    assert {row["TargetLocator"] for row in rows} == {
        "TargetTable.DeviceId",
        "OddTable.Initiator",
        "OddTable.OtherValue",
    }
    limited_receipt, limited_rows = _artifact_rows(limited.stdout)
    assert len(limited_rows) == 1
    assert limited_receipt["context"]["coverage"] == "bounded-validation"
    assert limited_rows[0]["TargetLocator"] == "TargetTable.DeviceId"
    assert limited_rows[0]["Provisional"] is False
    assert limited_receipt["context"]["eligible_targets"] == 3


def test_schema_observe_discards_bad_sampled_seeds_and_honors_timeout(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("SourceTable", "AccountUpn"),
            ("TargetTable", "AccountUpn"),
        ],
    )
    graph = Graph()
    for table in ("SourceTable", "TargetTable"):
        locator = FieldLocator.parse(f"{table}.AccountUpn")
        graph.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="string"))
        graph.add(
            InterpretationRecord(
                id=interpretation_id(locator, "entra-upn", "subject"),
                field_id=field_id(locator),
                entity_kind="user",
                namespace="entra-upn",
                role="subject",
                normalizer="upn-lower",
            )
        )
    sampled = HuntingResult(
        schema=[],
        results=[
            {"Value": "not-a-upn", "Occurrences": 1},
            {"Value": "z-rare@example.com", "Occurrences": 1},
            {"Value": "a-common@example.com", "Occurrences": 100},
        ],
        stats={},
    )
    matched = HuntingResult(
        schema=[],
        results=[
            {
                "TargetLocator": "TargetTable.AccountUpn",
                "TargetInterpretation": ("interp:TargetTable.AccountUpn:entra-upn:subject"),
                "MatchedSeeds": 1,
                "MatchRows": 1,
            }
        ],
        stats={},
    )
    client = AsyncMock()
    client.close = AsyncMock()
    run_query_mock = AsyncMock(side_effect=[sampled, matched])
    private_debug = tmp_path / "private-probe-debug.jsonl"
    with (
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client) as client_factory,
        patch("xdr_cli.commands.schema_cmd.run_query", new=run_query_mock),
    ):
        result = runner.invoke(
            app,
            [
                "schema",
                "observe",
                "SourceTable.AccountUpn",
                "--timeout",
                "120",
                "--samples",
                "1",
                "--private-debug-output",
                str(private_debug),
            ],
        )

    assert result.exit_code == 0, result.output
    receipt, rows = _artifact_rows(result.stdout)
    assert receipt["context"]["seed_count"] == 1
    assert receipt["context"]["rejected_seed_count"] == 1
    assert rows[0]["matched_seeds"] == 1
    assert client_factory.call_args.kwargs["timeout"] == 120
    target_kql = run_query_mock.await_args_list[1].args[1]
    assert 'let _xdr_seeds = dynamic(["z-rare@example.com"]);' in target_kql
    assert "set_has_element(_xdr_seeds, __xdr_value_0)" in target_kql
    assert "let __" not in target_kql
    assert "a-common@example.com" not in target_kql
    debug_text = private_debug.read_text(encoding="utf-8")
    assert '"event":"source-result"' in debug_text
    assert "not-a-upn" in debug_text
    assert "z-rare@example.com" in debug_text
    assert '"event":"target-plan"' in debug_text


def test_schema_observe_publishes_completed_batches_before_exit_14(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("SourceTable", "DeviceId"),
            ("ATable", "FirstValue"),
            ("BTable", "SecondValue"),
        ],
    )
    graph = Graph()
    locator = FieldLocator.parse("SourceTable.DeviceId")
    graph.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="string"))
    graph.add(
        InterpretationRecord(
            id=interpretation_id(locator, "mde-device-id", "subject"),
            field_id=field_id(locator),
            entity_kind="device",
            namespace="mde-device-id",
            role="subject",
            normalizer="hex40-lower",
        )
    )
    seed_file = tmp_path / "seeds.txt"
    seed_file.write_text("A" * 40 + "\n")
    first = HuntingResult(
        schema=[],
        results=[
            {
                "TargetLocator": "ATable.FirstValue",
                "TargetInterpretation": "interp:ATable.FirstValue:mde-device-id:neutral",
                "MatchedSeeds": 1,
                "MatchRows": 1,
            }
        ],
        stats={},
    )
    client = AsyncMock()
    client.close = AsyncMock()
    with (
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.schema_cmd.run_query",
            new=AsyncMock(side_effect=[first, QueryError("second batch failed")]),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "schema",
                "observe",
                "SourceTable.DeviceId",
                "--from-file",
                str(seed_file),
                "--batch-size",
                "1",
            ],
        )
    assert result.exit_code == 14, result.output
    receipt, rows = _artifact_rows(result.stdout)
    assert receipt["context"]["targets_completed"] == 1
    assert rows[0]["outcome"] == "matched"
    assert receipt["context"]["targets_failed"] == 1
    assert receipt["context"]["quarantined_tables"] == ["BTable"]
    assert "--target-table BTable" in receipt["context"]["next_command"]
    error = json.loads(result.stdout.splitlines()[-1])["error"]
    failed_task = error["original"]["failed_tasks"][0]
    assert failed_task["table"] == "BTable"
    assert failed_task["target_locators"] == ["BTable.SecondValue"]
    overlay = load_tenant_overlay("default")
    assert len(overlay.observations) == 1


def test_schema_observe_pages_reuse_source_artifact_and_pinned_plan(tmp_path, monkeypatch):
    _schema_cache(
        tmp_path,
        monkeypatch,
        [
            ("SourceTable", "DeviceId"),
            ("ATable", "FirstValue"),
            ("BTable", "SecondValue"),
        ],
    )
    graph = Graph()
    source_locator = FieldLocator.parse("SourceTable.DeviceId")
    graph.add(FieldRecord(id=field_id(source_locator), locator=source_locator, kql_type="string"))
    graph.add(
        InterpretationRecord(
            id=interpretation_id(source_locator, "mde-device-id", "subject"),
            field_id=field_id(source_locator),
            entity_kind="device",
            namespace="mde-device-id",
            role="subject",
            normalizer="hex40-lower",
        )
    )
    sampled = HuntingResult(
        schema=[], results=[{"Value": "a" * 40, "Occurrences": 1}], stats={}
    )

    def target_result(table: str, column: str) -> HuntingResult:
        return HuntingResult(
            schema=[],
            results=[
                {
                    "TargetLocator": f"{table}.{column}",
                    "TargetInterpretation": f"interp:{table}.{column}:mde-device-id:neutral",
                    "MatchedSeeds": 1,
                    "MatchRows": 1,
                }
            ],
            stats={},
        )

    client = AsyncMock()
    client.close = AsyncMock()
    query_mock = AsyncMock(
        side_effect=[
            sampled,
            target_result("ATable", "FirstValue"),
            target_result("BTable", "SecondValue"),
        ]
    )
    with (
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch("xdr_cli.commands.schema_cmd.run_query", new=query_mock),
    ):
        first = runner.invoke(
            app,
            [
                "schema",
                "observe",
                "SourceTable.DeviceId",
                "--max-queries",
                "1",
                "--batch-size",
                "1",
            ],
        )
        first_receipt, first_rows = _artifact_rows(first.stdout)
        continuation = shlex.split(first_receipt["context"]["next_command"])
        assert continuation[:3] == ["xdr", "schema", "observe"]
        changed_generation = list(continuation)
        generation_index = changed_generation.index("--schema-generation") + 1
        changed_generation[generation_index] = "different-generation"
        conflict = runner.invoke(app, changed_generation[1:])
        second = runner.invoke(app, continuation[1:])

    assert first.exit_code == 0, first.output
    assert first_receipt["context"]["page_complete"] is False
    assert first_receipt["context"]["query_stop"] == 1
    assert first_receipt["context"]["targets_probed"] == 1
    assert len(first_rows) == 1
    assert "--from-run" in continuation
    assert "--schema-generation" in continuation
    assert conflict.exit_code == 13
    assert json.loads(conflict.stdout)["error"]["original"]["type"] == (
        "SchemaProbeGenerationChanged"
    )
    assert second.exit_code == 0, second.output
    second_receipt, second_rows = _artifact_rows(second.stdout)
    assert second_receipt["context"]["page_complete"] is True
    assert second_receipt["context"]["targets_probed"] == 1
    assert len(second_rows) == 1
    assert query_mock.await_count == 3


def test_schema_candidate_review_collects_private_context_and_updates_gate(
    tmp_path, monkeypatch
):
    home = _schema_cache(
        tmp_path,
        monkeypatch,
        [("SourceTable", "DeviceId"), ("TargetTable", "DeviceId")],
    )
    graph = _probe_graph()
    source_artifact = write_result(
        [{"Value": f"{value:040x}", "Occurrences": 2} for value in range(1, 6)],
        command="schema observe source-sample",
        query=("SourceTable\n| where Timestamp > ago(30d)\n| project Value=tostring(DeviceId)"),
        extra_metadata={
            "probe_stage": "source-sample",
            "locator": "SourceTable.DeviceId",
            "source_interpretation": ("interp:SourceTable.DeviceId:mde-device-id:subject"),
            "source_normalizer": "hex40-lower",
        },
        tenant_id="default",
        physical_lineage_table="SourceTable",
    )
    target_artifact = write_result(
        [
            {
                "TargetLocator": "TargetTable.DeviceId",
                "TargetInterpretation": ("interp:TargetTable.DeviceId:mde-device-id:subject"),
                "MatchedSeeds": 4,
                "MatchRows": 4,
            }
        ],
        command="schema observe target-batch",
        query="TargetTable\n| where Timestamp > ago(30d)\n| take 5",
        extra_metadata={
            "probe_stage": "target-batch",
            "source_locator": "SourceTable.DeviceId",
            "source_artifact_run_id": source_artifact.receipt.run_id,
            "selected_seed_count": 5,
            "probe_run": "probe-run-one",
            "batch": 1,
            "target_locators": ["TargetTable.DeviceId"],
        },
        tenant_id="default",
    )
    second_source_artifact = write_result(
        [
            {"Value": "not-a-device-id", "Occurrences": 1},
            *[{"Value": f"{value:040x}", "Occurrences": 2} for value in range(6, 11)],
            {"Value": "0" * 40, "Occurrences": 1000},
        ],
        command="schema observe source-sample",
        query=(
            "SourceTable\n| where TimeGenerated > ago(30d)\n"
            "| project Value=tostring(DeviceId)"
        ),
        extra_metadata={
            "probe_stage": "source-sample",
            "locator": "SourceTable.DeviceId",
            "source_interpretation": ("interp:SourceTable.DeviceId:mde-device-id:subject"),
            "source_normalizer": "hex40-lower",
        },
        tenant_id="default",
        physical_lineage_table="SourceTable",
    )
    second_target_artifact = write_result(
        [
            {
                "TargetLocator": "TargetTable.DeviceId",
                "TargetInterpretation": ("interp:TargetTable.DeviceId:mde-device-id:subject"),
                "MatchedSeeds": 4,
                "MatchRows": 4,
            }
        ],
        command="schema observe target-batch",
        query="TargetTable\n| where TimeGenerated > ago(30d)\n| take 5",
        extra_metadata={
            "probe_stage": "target-batch",
            "source_locator": "SourceTable.DeviceId",
            "source_artifact_run_id": second_source_artifact.receipt.run_id,
            "selected_seed_count": 5,
            "probe_run": "probe-run-two",
            "batch": 1,
            "target_locators": ["TargetTable.DeviceId"],
        },
        tenant_id="default",
    )
    newest_source_artifact = write_result(
        [{"Value": f"{value:040x}", "Occurrences": 2} for value in range(11, 16)],
        command="schema observe source-sample",
        query=("SourceTable\n| where Timestamp > ago(30d)\n| project Value=tostring(DeviceId)"),
        extra_metadata={
            "probe_stage": "source-sample",
            "locator": "SourceTable.DeviceId",
            "source_interpretation": ("interp:SourceTable.DeviceId:mde-device-id:subject"),
            "source_normalizer": "hex40-lower",
        },
        tenant_id="default",
        physical_lineage_table="SourceTable",
    )
    newest_target_artifact = write_result(
        [
            {
                "TargetLocator": "TargetTable.DeviceId",
                "TargetInterpretation": ("interp:TargetTable.DeviceId:mde-device-id:subject"),
                "MatchedSeeds": 4,
                "MatchRows": 4,
            }
        ],
        command="schema observe target-batch",
        query="TargetTable\n| where Timestamp > ago(30d)\n| take 5",
        extra_metadata={
            "probe_stage": "target-batch",
            "source_locator": "SourceTable.DeviceId",
            "source_artifact_run_id": newest_source_artifact.receipt.run_id,
            "selected_seed_count": 5,
            "probe_run": "probe-run-newest",
            "batch": 1,
            "target_locators": ["TargetTable.DeviceId"],
        },
        tenant_id="default",
    )
    observation = ObservationRecord(
        observation_id="probe:candidate-review-test",
        source_interpretation="interp:SourceTable.DeviceId:mde-device-id:subject",
        target_interpretation="interp:TargetTable.DeviceId:mde-device-id:subject",
        transform="hex40-lower",
        distinct_seeds=5,
        matched_seeds=4,
        matched_rows=4,
        source_artifact_run_id=source_artifact.receipt.run_id,
        target_artifact_run_id=target_artifact.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:candidate-review-test",),
        outcome="matched",
        schema_generation="generation-1",
        observed_at=(datetime.now(UTC) - timedelta(days=2)).isoformat().replace("+00:00", "Z"),
        lookback="30d",
    )
    second_observation = ObservationRecord(
        observation_id="probe:candidate-review-test-second-day",
        source_interpretation=observation.source_interpretation,
        target_interpretation=observation.target_interpretation,
        transform=observation.transform,
        distinct_seeds=5,
        matched_seeds=4,
        matched_rows=4,
        source_artifact_run_id=source_artifact.receipt.run_id,
        target_artifact_run_id=target_artifact.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:candidate-review-test-second-day",),
        outcome="matched",
        schema_generation="generation-2",
        observed_at=(datetime.now(UTC) - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        lookback="30d",
    )
    third_observation = ObservationRecord(
        observation_id="probe:candidate-review-test-third-day",
        source_interpretation=observation.source_interpretation,
        target_interpretation=observation.target_interpretation,
        transform=observation.transform,
        distinct_seeds=5,
        matched_seeds=4,
        matched_rows=4,
        source_artifact_run_id=second_source_artifact.receipt.run_id,
        target_artifact_run_id=second_target_artifact.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:candidate-review-test-third-day",),
        outcome="matched",
        schema_generation="generation-3",
        observed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        lookback="30d",
    )
    incomplete_observation = replace(
        third_observation,
        observation_id="probe:candidate-review-test-incomplete",
        outcome="partial",
        provenance=("tenant-observation:candidate-review-test-incomplete",),
    )
    newest_invalid_observation = replace(
        third_observation,
        observation_id="probe:candidate-review-test-newest-invalid",
        source_artifact_run_id=newest_source_artifact.receipt.run_id,
        target_artifact_run_id=newest_target_artifact.receipt.run_id,
        observed_at=(datetime.now(UTC) + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        provenance=("tenant-observation:candidate-review-test-newest-invalid",),
    )
    mismatched_evidence_observation = replace(
        third_observation,
        observation_id="probe:candidate-review-test-mismatched-evidence",
        source_artifact_run_id=source_artifact.receipt.run_id,
        target_artifact_run_id=second_target_artifact.receipt.run_id,
        provenance=("tenant-observation:candidate-review-test-mismatched-evidence",),
    )
    publish_tenant_overlay("default", observations=(observation, second_observation))
    relationship_id = empirical_relationship_from_observations((observation,)).id
    cache_rows = [
        json.loads(line)
        for line in next((home / "schema").glob("*/schema.jsonl")).read_text().splitlines()
    ]
    unbounded_review_rows = [
        row
        for row in cache_rows
        if not (row["TableName"] == "TargetTable" and row["ColumnName"] == "Timestamp")
    ]
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
        patch(
            "xdr_cli.commands.schema_cmd._load_cache",
            return_value=(unbounded_review_rows, {"generation": "test"}),
        ),
    ):
        unbounded_review = runner.invoke(app, ["schema", "candidate-review", relationship_id])
    assert unbounded_review.exit_code == 13
    unbounded_error = json.loads(unbounded_review.stdout)["error"]
    assert unbounded_error["code"] == "SCHEMA_PROBE_TEMPORAL_COLUMN_MISSING"
    assert unbounded_error["help_command"] == "xdr schema show TargetTable --search Time"
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
    ):
        reused_candidates = runner.invoke(app, ["schema", "candidates"])
    _, reused_rows = _artifact_rows(reused_candidates.stdout)
    assert "needs-at-least-two-independent-evidence-bundles" in reused_rows[0]["BlockingReasons"]
    assert (
        "needs-at-least-two-distinct-sampled-seed-cohorts"
        in reused_rows[0]["BlockingReasons"]
    )
    publish_tenant_overlay(
        "default",
        observations=(
            third_observation,
            incomplete_observation,
            newest_invalid_observation,
        ),
    )
    newest_source_path = Path(newest_source_artifact.receipt.data_path)
    newest_source_path.write_text("tampered\n")
    client = AsyncMock()
    client.close = AsyncMock()
    context_result = HuntingResult(
        schema=[],
        results=[{"DeviceId": "A" * 40, "ActionType": "ConnectionSuccess"}],
        stats={},
    )
    empty_context_result = HuntingResult(schema=[], results=[], stats={})
    review_run_query = AsyncMock(side_effect=[empty_context_result, context_result])
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=client),
        patch(
            "xdr_cli.commands.schema_cmd.run_query",
            new=review_run_query,
        ),
    ):
        empty_review = runner.invoke(app, ["schema", "candidate-review", relationship_id])
        blocked_candidates = runner.invoke(app, ["schema", "candidates"])
        reviewed = runner.invoke(app, ["schema", "candidate-review", relationship_id])

    publish_tenant_overlay("default", observations=(mismatched_evidence_observation,))
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
    ):
        candidates = runner.invoke(app, ["schema", "candidates"])

    assert empty_review.exit_code == 14, empty_review.output
    _, blocked_rows = _artifact_rows(blocked_candidates.stdout)
    assert blocked_rows[0]["EvidenceGate"] == "passed"
    assert blocked_rows[0]["ContextReviewArtifactsAvailable"] is False
    assert reviewed.exit_code == 0, reviewed.output
    assert "0" * 40 not in review_run_query.await_args_list[1].args[1]
    review_receipt = json.loads(reviewed.stdout)
    assert review_receipt["rows"] == 1
    assert "xdr results head" in review_receipt["context"]["next_command"]
    assert (len(reviewed.stdout.splitlines())) == 1
    review_meta = json.loads(Path(review_receipt["meta_path"]).read_text())
    assert review_meta["candidate_review"]["relationship_id"] == relationship_id
    assert review_meta["candidate_review"]["observation_id"] == (third_observation.observation_id)
    assert review_meta["candidate_review"]["source_artifact_run_id"] == (
        second_source_artifact.receipt.run_id
    )
    assert review_meta["candidate_review"]["seed_count"] == 5
    assert review_meta["candidate_review"]["rejected_retained_seed_count"] == 1
    _, candidate_rows = _artifact_rows(candidates.stdout)
    assert candidate_rows[0]["ContextReviewArtifactsAvailable"] is True
    assert candidate_rows[0]["EvidenceGate"] == "passed"
    assert candidate_rows[0]["IndependentObservationDays"] == 3
    assert candidate_rows[0]["IndependentSeedCohorts"] == 2
    assert candidate_rows[0]["DistinctValidatedSourceIdentifiers"] == 10
    assert candidate_rows[0]["LifecycleState"] == "validated-investigation-pivot"
    assert (
        "incomplete-observations-excluded-from-readiness" in candidate_rows[0]["AutomatedConcerns"]
    )
    assert "positive-runs-provenance-mismatch-excluded" in candidate_rows[0]["AutomatedConcerns"]
    assert candidate_rows[0]["ValidatedPositiveRuns"] == 3
    assert candidate_rows[0]["ExcludedInvalidPositiveRuns"] == 2

    proposal_path = tmp_path / "candidate-proposal.jsonl"
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
    ):
        proposal = runner.invoke(
            app,
            [
                "schema",
                "candidate-proposal",
                relationship_id,
                "--output",
                str(proposal_path),
                "--relationship",
                "semantic-equivalent",
                "--direction",
                "both",
                "--cardinality",
                "unknown",
                "--temporal",
                "same-retention-window",
                "--confidence",
                "medium",
                "--provenance",
                "reviewed:test-contract",
            ],
        )
    assert proposal.exit_code == 0, proposal.output
    proposal_receipt = json.loads(proposal.stdout.splitlines()[0])
    assert proposal_receipt["context"]["automatic_promotion"] is False
    proposed_records = [json.loads(line) for line in proposal_path.read_text().splitlines()]
    assert [record["record_type"] for record in proposed_records] == ["relationship"]
    assert proposed_records[0]["status"] == "reviewed"

    retained = load_tenant_overlay("default").observations
    publish_tenant_overlay(
        "default",
        observations=tuple(
            replace(
                item,
                observed_at=(datetime.now(UTC) - timedelta(days=100)).isoformat().replace(
                    "+00:00", "Z"
                ),
            )
            if item.observation_id == third_observation.observation_id
            else item
            for item in retained
            if item.observation_id != newest_invalid_observation.observation_id
        ),
        replace_observations=True,
    )
    with (
        patch("xdr_cli.main.load_config", return_value=Config(tenant_id="default")),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=graph),
    ):
        downgraded = runner.invoke(app, ["schema", "pivot", "SourceTable.DeviceId"])
    assert downgraded.exit_code == 0, downgraded.output
    _, downgraded_rows = _artifact_rows(downgraded.stdout)
    assert downgraded_rows[0]["EvidenceLevel"] == "observed"


def test_candidate_evidence_binding_rejects_impossible_counts_and_wrong_interpretation(
    tmp_path, monkeypatch
):
    from xdr_cli.commands.schema_cmd import _observation_artifacts_match

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    source_id = "interp:SourceTable.DeviceId:mde-device-id:subject"
    target_id = "interp:TargetTable.DeviceId:mde-device-id:subject"

    def source_artifact(values):
        return write_result(
            [{"Value": value} for value in values],
            command="schema observe source-sample",
            extra_metadata={
                "probe_stage": "source-sample",
                "locator": "SourceTable.DeviceId",
                "source_interpretation": source_id,
                "source_normalizer": "hex40-lower",
            },
            tenant_id="tenant",
        )

    def target_artifact(source_run_id, interpretation):
        return write_result(
            [
                {
                    "TargetLocator": "TargetTable.DeviceId",
                    "TargetInterpretation": interpretation,
                    "MatchedSeeds": 3,
                    "MatchRows": 4,
                }
            ],
            command="schema observe target-batch",
            extra_metadata={
                "probe_stage": "target-batch",
                "probe_run": "probe-binding-test",
                "batch": 1,
                "source_locator": "SourceTable.DeviceId",
                "source_artifact_run_id": source_run_id,
                "selected_seed_count": 5,
                "target_locators": ["TargetTable.DeviceId"],
            },
            tenant_id="tenant",
        )

    too_small = source_artifact(["1".zfill(40)])
    target = target_artifact(too_small.receipt.run_id, target_id)
    impossible = ObservationRecord(
        observation_id="probe:impossible-binding",
        source_interpretation=source_id,
        target_interpretation=target_id,
        transform="hex40-lower",
        distinct_seeds=5,
        matched_seeds=3,
        matched_rows=4,
        source_artifact_run_id=too_small.receipt.run_id,
        target_artifact_run_id=target.receipt.run_id,
        probe_runs=1,
        provenance=("tenant-observation:impossible-binding",),
        outcome="matched",
    )
    assert not _observation_artifacts_match(
        impossible,
        source_locator=FieldLocator.parse("SourceTable.DeviceId"),
        source_normalizer="hex40-lower",
        target_locator=FieldLocator.parse("TargetTable.DeviceId"),
        tenant_id="tenant",
    )

    enough = source_artifact([f"{value:040x}" for value in range(1, 6)])
    wrong_target = target_artifact(enough.receipt.run_id, source_id)
    misbound = replace(
        impossible,
        observation_id="probe:wrong-interpretation-binding",
        source_artifact_run_id=enough.receipt.run_id,
        target_artifact_run_id=wrong_target.receipt.run_id,
        provenance=("tenant-observation:wrong-interpretation-binding",),
    )
    assert not _observation_artifacts_match(
        misbound,
        source_locator=FieldLocator.parse("SourceTable.DeviceId"),
        source_normalizer="hex40-lower",
        target_locator=FieldLocator.parse("TargetTable.DeviceId"),
        tenant_id="tenant",
    )


def test_candidate_proposal_requires_confirmation_and_includes_missing_dependencies(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    source_locator = FieldLocator.parse("SourceTable.DeviceId")
    target_locator = FieldLocator.parse("NovelTable.ActorDevice")
    source_id = interpretation_id(source_locator, "mde-device-id", "subject")
    target_id = interpretation_id(target_locator, "mde-device-id", "neutral")
    core = Graph()
    core.add(FieldRecord(id=field_id(source_locator), locator=source_locator, kql_type="string"))
    core.add(
        InterpretationRecord(
            id=source_id,
            field_id=field_id(source_locator),
            entity_kind="device",
            namespace="mde-device-id",
            role="subject",
            normalizer="hex40-lower",
        )
    )
    effective_graph = Graph()
    for record in core.records():
        effective_graph.add(record)
    effective_graph.add(
        FieldRecord(id=field_id(target_locator), locator=target_locator, kql_type="string")
    )
    effective_graph.add(
        InterpretationRecord(
            id=target_id,
            field_id=field_id(target_locator),
            entity_kind="device",
            namespace="mde-device-id",
            role="neutral",
            normalizer="hex40-lower",
            extra={"provisional": True, "private": True},
        )
    )
    observation = ObservationRecord(
        observation_id="probe:proposal-dependency",
        source_interpretation=source_id,
        target_interpretation=target_id,
        transform="hex40-lower",
        distinct_seeds=5,
        matched_seeds=3,
        probe_runs=1,
        provenance=("tenant-observation:proposal-dependency",),
        outcome="matched",
    )
    candidate = empirical_relationship_from_observations((observation,))
    effective_graph.add(candidate)
    row = {
        "RelationshipId": candidate.id,
        "Source": str(core.fields[core.interpretations[source_id].field_id].locator),
        "EvidenceGate": "passed",
        "BlockingReasons": [],
        "ReviewCommand": f"xdr schema candidate-review {candidate.id}",
        "ValidatedObservationIds": ["probe:proposal-dependency"],
        "ValidatedSourceArtifactRunIds": ["source-run"],
        "ValidatedTargetArtifactRunIds": ["target-run"],
        "ContextReviewArtifactRunIds": ["review-run"],
    }
    proposal_args = [
        "schema",
        "candidate-proposal",
        candidate.id,
        "--output",
        str(tmp_path / "proposal.jsonl"),
        "--relationship",
        "semantic-equivalent",
        "--direction",
        "both",
        "--cardinality",
        "unknown",
        "--temporal",
        "same-retention-window",
        "--confidence",
        "medium",
        "--provenance",
        "reviewed:test-contract",
    ]
    with (
        patch(
            "xdr_cli.commands.schema_cmd._candidate_report",
            return_value=(
                [row],
                {},
                SimpleNamespace(metadata={"generation": "generation-A"}),
                SimpleNamespace(graph=effective_graph),
            ),
        ),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=core),
        patch(
            "xdr_cli.commands.schema_cmd.load_tenant_overlay",
            return_value=SimpleNamespace(metadata={"generation": "generation-A"}),
        ),
    ):
        missing_confirmation = runner.invoke(app, proposal_args)
        proposed = runner.invoke(
            app,
            [*proposal_args, "--confirm-interpretation", target_id],
        )

    assert missing_confirmation.exit_code == 6
    assert target_id in json.loads(missing_confirmation.stdout)["error"]["message"]
    assert proposed.exit_code == 0, proposed.output
    proposal_receipt = json.loads(proposed.stdout.splitlines()[0])
    proposal_meta = json.loads(Path(proposal_receipt["meta_path"]).read_text())
    proposal_binding = proposal_meta["candidate_proposal"]
    snapshot = proposal_binding["evidence_snapshot"]
    assert snapshot["overlay_generation"] == "generation-A"
    assert snapshot["validated_observation_ids"] == ["probe:proposal-dependency"]
    assert snapshot["source_artifact_run_ids"] == ["source-run"]
    assert snapshot["target_artifact_run_ids"] == ["target-run"]
    assert snapshot["review_artifact_run_ids"] == ["review-run"]
    assert len(snapshot["sha256"]) == 64
    proposal_raw = (tmp_path / "proposal.jsonl").read_bytes()
    assert proposal_binding["proposal_bytes"] == len(proposal_raw)
    assert proposal_binding["proposal_sha256"] == hashlib.sha256(proposal_raw).hexdigest()
    unsigned_binding = {
        key: value for key, value in proposal_binding.items() if key != "binding_sha256"
    }
    assert (
        proposal_binding["binding_sha256"]
        == hashlib.sha256(
            json.dumps(unsigned_binding, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    )
    records = [json.loads(line) for line in (tmp_path / "proposal.jsonl").read_text().splitlines()]
    assert [record["record_type"] for record in records] == [
        "field",
        "interpretation",
        "relationship",
    ]
    assert "private" not in records[1]
    assert "provisional" not in records[1]

    changed_path = tmp_path / "changed-evidence-proposal.jsonl"
    changed_args = [*proposal_args]
    changed_args[4] = str(changed_path)
    changed_args.extend(["--confirm-interpretation", target_id])
    with (
        patch(
            "xdr_cli.commands.schema_cmd._candidate_report",
            return_value=(
                [row],
                {},
                SimpleNamespace(metadata={"generation": "generation-A"}),
                SimpleNamespace(graph=effective_graph),
            ),
        ),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=core),
        patch(
            "xdr_cli.commands.schema_cmd.load_tenant_overlay",
            return_value=SimpleNamespace(metadata={"generation": "generation-B"}),
        ),
    ):
        changed = runner.invoke(app, changed_args)
    assert changed.exit_code == 13
    assert json.loads(changed.stdout)["error"]["code"] == ("SCHEMA_PROPOSAL_EVIDENCE_CHANGED")
    assert not changed_path.exists()

    failed_path = tmp_path / "failed-proposal.jsonl"
    failed_args = [*proposal_args]
    failed_args[4] = str(failed_path)
    failed_args.extend(["--confirm-interpretation", target_id])
    orphaned_path = tmp_path / "orphaned-proposal.jsonl"
    orphaned_args = [*failed_args]
    orphaned_args[4] = str(orphaned_path)
    candidate_report = (
        [row],
        {},
        SimpleNamespace(metadata={"generation": "generation-A"}),
        SimpleNamespace(graph=effective_graph),
    )
    with (
        patch(
            "xdr_cli.commands.schema_cmd._candidate_report",
            return_value=candidate_report,
        ),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=core),
        patch(
            "xdr_cli.commands.schema_cmd.load_tenant_overlay",
            return_value=SimpleNamespace(metadata={"generation": "generation-A"}),
        ),
        patch(
            "xdr_cli.commands.schema_cmd.write_result",
            side_effect=ArtifactError("forced artifact failure"),
        ),
    ):
        failed = runner.invoke(app, failed_args)
    assert failed.exit_code == 12
    assert not failed_path.exists()

    with (
        patch(
            "xdr_cli.commands.schema_cmd._candidate_report",
            return_value=candidate_report,
        ),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=core),
        patch(
            "xdr_cli.commands.schema_cmd.load_tenant_overlay",
            return_value=SimpleNamespace(metadata={"generation": "generation-A"}),
        ),
        patch(
            "xdr_cli.commands.schema_cmd.write_result",
            side_effect=ArtifactError("forced artifact failure"),
        ),
        patch.object(Path, "unlink", side_effect=OSError("proposal is locked")),
    ):
        orphaned = runner.invoke(app, orphaned_args)
    assert orphaned.exit_code == 14
    orphaned_error = json.loads(orphaned.stdout)["error"]
    assert orphaned_error["code"] == "SCHEMA_PROPOSAL_PARTIAL_PUBLICATION"
    assert orphaned_error["original"]["proposal_path"] == str(orphaned_path.resolve())
    assert orphaned_path.exists()


def test_candidate_proposal_requires_contract_and_never_replaces_reviewed_core(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    core = _probe_graph()
    source_id = interpretation_id(
        FieldLocator.parse("SourceTable.DeviceId"), "mde-device-id", "subject"
    )
    target_id = interpretation_id(
        FieldLocator.parse("TargetTable.DeviceId"), "mde-device-id", "subject"
    )
    reviewed = RelationshipRecord(
        id=relationship_id(
            source_id,
            target_id,
            RelationshipKind.JOIN_COMPATIBLE,
            Direction.BOTH,
            "hex40-lower",
        ),
        source=min(source_id, target_id),
        target=max(source_id, target_id),
        relationship=RelationshipKind.JOIN_COMPATIBLE,
        direction=Direction.BOTH,
        transform="hex40-lower",
        cardinality=Cardinality.ONE_TO_MANY,
        temporal="reviewed-contract",
        status=RelationshipStatus.REVIEWED,
        confidence=Confidence.HIGH,
        provenance=("curated:test-contract",),
    )
    core.add(reviewed)
    effective_graph = Graph()
    for record in core.records():
        effective_graph.add(record)
    observation = ObservationRecord(
        observation_id="probe:reviewed-collision",
        source_interpretation=source_id,
        target_interpretation=target_id,
        transform="hex40-lower",
        distinct_seeds=5,
        matched_seeds=3,
        probe_runs=2,
        provenance=("tenant-observation:reviewed-collision",),
        outcome="matched",
    )
    candidate = empirical_relationship_from_observations((observation,))
    effective_graph.add(candidate)
    row = {
        "RelationshipId": candidate.id,
        "Source": "SourceTable.DeviceId",
        "EvidenceGate": "passed",
        "BlockingReasons": [],
        "ReviewCommand": f"xdr schema candidate-review {candidate.id}",
        "ValidatedObservationIds": [observation.observation_id],
        "ValidatedSourceArtifactRunIds": ["source-run"],
        "ValidatedTargetArtifactRunIds": ["target-run"],
        "ContextReviewArtifactRunIds": ["review-run"],
    }
    base_args = [
        "schema",
        "candidate-proposal",
        candidate.id,
        "--output",
        str(tmp_path / "collision.jsonl"),
        "--relationship",
        "join-compatible",
        "--direction",
        "both",
        "--cardinality",
        "one-to-one",
        "--temporal",
        "reviewed-contract",
        "--confidence",
        "low",
        "--acknowledge-independent-contract",
    ]
    candidate_report = (
        [row],
        {},
        SimpleNamespace(metadata={"generation": "generation-A"}),
        SimpleNamespace(graph=effective_graph),
    )
    with (
        patch(
            "xdr_cli.commands.schema_cmd._candidate_report",
            return_value=candidate_report,
        ),
        patch("xdr_cli.commands.schema_cmd._semantic_graph", return_value=core),
        patch(
            "xdr_cli.commands.schema_cmd.load_tenant_overlay",
            return_value=SimpleNamespace(metadata={"generation": "generation-A"}),
        ),
    ):
        missing_contract = runner.invoke(app, [*base_args, "--provenance", "reviewed:looks-good"])
        collision = runner.invoke(app, [*base_args, "--provenance", "contract:microsoft-test"])

    assert missing_contract.exit_code == 6
    assert "contract:" in json.loads(missing_contract.stdout)["error"]["message"]
    assert collision.exit_code == 13
    collision_error = json.loads(collision.stdout)["error"]
    assert collision_error["code"] == "SCHEMA_PROPOSAL_CORE_RELATIONSHIP_EXISTS"
    assert collision_error["original"]["relationship_id"] == reviewed.id
    assert not (tmp_path / "collision.jsonl").exists()


def test_candidate_evidence_coordinates_preserve_reversed_observation_direction():
    from xdr_cli.commands.schema_cmd import _observation_evidence_coordinates

    graph = Graph()
    for table, role in (("ATable", "neutral"), ("ZTable", "subject")):
        locator = FieldLocator.parse(f"{table}.Value")
        graph.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="string"))
        graph.add(
            InterpretationRecord(
                id=interpretation_id(locator, "test-namespace", role),
                field_id=field_id(locator),
                entity_kind="user",
                namespace="test-namespace",
                role=role,
                normalizer="upn-lower",
            )
        )
    observation = ObservationRecord(
        observation_id="probe:reverse-order",
        source_interpretation="interp:ZTable.Value:test-namespace:subject",
        target_interpretation="interp:ATable.Value:test-namespace:neutral",
        transform="upn-lower",
        distinct_seeds=3,
        matched_seeds=2,
        probe_runs=1,
        provenance=("tenant-observation:reverse-order",),
        outcome="matched",
    )
    relationship = empirical_relationship_from_observations((observation,))
    assert relationship.source == observation.target_interpretation

    source, normalizer, target = _observation_evidence_coordinates(graph, observation)
    assert str(source) == "ZTable.Value"
    assert normalizer == "upn-lower"
    assert str(target) == "ATable.Value"


def test_schema_correlate_uses_metadata_sidecars_and_hides_private_values(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = write_result(
        [{"AccountUpn": "User@Example.invalid"}],
        command="hunt run",
        query="EntraIdSignInEvents | where Timestamp > ago(1d)",
        physical_lineage_table="EntraIdSignInEvents",
        tenant_id="tenant",
    )
    second = write_result(
        [{"RawEventData": {"UserId": "user@example.invalid"}}],
        command="hunt run",
        query="CloudAppEvents | where Timestamp > ago(1d)",
        physical_lineage_table="CloudAppEvents",
        tenant_id="tenant",
    )
    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        result = runner.invoke(
            app,
            [
                "schema",
                "correlate",
                "--input",
                f"EntraIdSignInEvents={first.receipt.run_id}",
                "--input",
                f"CloudAppEvents={second.receipt.run_id}",
                "--include-contextual",
            ],
        )
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout)
    assert receipt["context"]["shared_entities"] == 0
    assert receipt["context"]["contextual_matches"] == 1
    assert receipt["context"]["next_command"] == (
        f"xdr results rows {receipt['run_id']} --type relationship-path-match --limit 100"
    )
    assert "user@example.invalid" not in result.stdout.casefold()
    inspected = runner.invoke(
        app,
        [
            "results",
            "rows",
            receipt["run_id"],
            "--type",
            "relationship-path-match",
        ],
    )
    assert inspected.exit_code == 0, inspected.output
    assert json.loads(inspected.stdout)["data"][0]["match_strength"] == "contextual"
    rows = [
        json.loads(line) for line in Path(receipt["data_path"]).read_text().splitlines() if line
    ]
    entities = [row for row in rows if row["record_type"] == "entity"]
    assert [row["value"] for row in entities] == [
        "user@example.invalid",
        "user@example.invalid",
    ]
    assert sum(row["record_type"] == "event-entity-edge" for row in rows) == 2
    matches = [row for row in rows if row["record_type"] == "relationship-path-match"]
    assert matches[0]["match_strength"] == "contextual"
    assert matches[0]["temporal_evaluation"] == "required-not-evaluated"
    assert sum(row["record_type"] == "declared-input" for row in rows) == 2
    assert any(row["record_type"] == "structural-route" for row in rows)


def test_schema_correlate_rejects_cross_tenant_inputs(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = write_result(
        [{"AccountUpn": "user@example.invalid"}],
        command="hunt run",
        physical_lineage_table="EntraIdSignInEvents",
        tenant_id="tenant-a",
    )
    second = write_result(
        [{"AccountUpn": "user@example.invalid"}],
        command="hunt run",
        physical_lineage_table="IdentityInfo",
        tenant_id="tenant-b",
    )
    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant-a")):
        result = runner.invoke(
            app,
            [
                "schema",
                "correlate",
                "--input",
                f"EntraIdSignInEvents={first.receipt.run_id}",
                "--input",
                f"IdentityInfo={second.receipt.run_id}",
            ],
        )

    assert result.exit_code == 13
    assert json.loads(result.stdout)["error"]["code"] == ("SCHEMA_CORRELATION_TENANT_MISMATCH")


def test_schema_correlate_rejects_sidecar_data_substitution(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = write_result(
        [{"AccountUpn": "first@example.invalid"}],
        command="hunt run",
        physical_lineage_table="EntraIdSignInEvents",
        tenant_id="tenant",
    )
    second = write_result(
        [{"AccountUpn": "second@example.invalid"}],
        command="hunt run",
        physical_lineage_table="EntraIdSignInEvents",
        tenant_id="tenant",
    )
    metadata = json.loads(Path(first.receipt.meta_path).read_text())
    metadata["run_id"] = second.receipt.run_id
    metadata["data_path"] = second.receipt.data_path
    metadata["meta_path"] = first.receipt.meta_path
    Path(first.receipt.meta_path).write_text(json.dumps(metadata))

    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        result = runner.invoke(
            app,
            [
                "schema",
                "correlate",
                "--input",
                f"EntraIdSignInEvents={first.receipt.run_id}",
                "--input",
                f"IdentityInfo={second.receipt.run_id}",
            ],
        )

    assert result.exit_code == 12
    assert "inconsistent" in json.loads(result.stdout)["error"]["message"]


def test_schema_correlate_rejects_unproven_declared_lineage(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = write_result(
        [{"AccountUpn": "user@example.invalid"}],
        command="hunt run",
        query="OtherTable | project AccountUpn",
    )
    second = write_result(
        [{"AccountUpn": "user@example.invalid"}],
        command="hunt run",
        query="IdentityInfo | where Timestamp > ago(1d)",
        physical_lineage_table="IdentityInfo",
    )

    result = runner.invoke(
        app,
        [
            "schema",
            "correlate",
            "--input",
            f"EntraIdSignInEvents={first.receipt.run_id}",
            "--input",
            f"IdentityInfo={second.receipt.run_id}",
        ],
    )

    assert result.exit_code == 12
    error = json.loads(result.stdout)["error"]
    assert "physical lineage" in error["message"]


def test_schema_correlate_rejects_project_rename_lineage_spoof(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    spoofed = write_result(
        [{"AccountObjectId": "00000000-0000-0000-0000-000000000001"}],
        command="hunt run",
        query="CloudAppEvents | project-rename AccountObjectId=ApplicationId",
        tenant_id="tenant",
    )
    genuine = write_result(
        [{"AccountObjectId": "00000000-0000-0000-0000-000000000001"}],
        command="hunt run",
        query="IdentityInfo | where Timestamp > ago(1d)",
        physical_lineage_table="IdentityInfo",
        tenant_id="tenant",
    )

    with patch("xdr_cli.main.load_config", return_value=Config(tenant_id="tenant")):
        result = runner.invoke(
            app,
            [
                "schema",
                "correlate",
                "--input",
                f"CloudAppEvents={spoofed.receipt.run_id}",
                "--input",
                f"IdentityInfo={genuine.receipt.run_id}",
            ],
        )

    assert result.exit_code == 12
    assert "physical lineage" in json.loads(result.stdout)["error"]["message"]
