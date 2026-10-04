from __future__ import annotations

import hashlib
import json
from pathlib import Path

from click import unstyle
from typer.testing import CliRunner

from xdr_cli.commands.schema_cmd import bundle_app, schema_app
from xdr_cli.main import app
from xdr_cli.schema_graph.diagnostics import SCHEMA_CAPABILITIES, build_diagnostics
from xdr_cli.schema_graph.maintenance import maintenance_status


def _command_names(application):
    return {
        item.name or item.callback.__name__.replace("_", "-")
        for item in application.registered_commands
        if item.callback is not None
    }


def test_schema_capability_registry_matches_cli_and_documentation():
    schema_commands = _command_names(schema_app)
    bundle_commands = _command_names(bundle_app)
    readme = (Path(__file__).parent.parent / "README.md").read_text()
    guide = (Path(__file__).parent.parent / "docs" / "schema_graph.md").read_text()

    for capability in SCHEMA_CAPABILITIES:
        parts = capability["command"].split()
        assert parts[0] == "schema"
        if parts[1] == "bundle":
            assert parts[2] in bundle_commands
        else:
            assert parts[1] in schema_commands
        assert f"xdr {capability['command']}" in readme
        assert f"xdr {capability['command']}" in guide
    assert "guide](docs/schema_graph.md)" in readme
    assert "## Roadmap: graph exchange" not in guide
    assert "A follow-up will define export/import" not in guide


def test_new_schema_command_help_has_real_examples_and_references(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    runner = CliRunner()
    cases = (
        (["schema", "status", "--help"], "xdr schema status"),
        (["schema", "diagnostics", "--help"], "xdr schema diagnostics"),
        (["schema", "repair-overlay", "--help"], "xdr schema repair-overlay --yes"),
        (["schema", "migrate-cache", "--help"], "xdr schema migrate-cache --yes"),
        (["schema", "collect", "--help"], "xdr schema collect --plan-only"),
        (
            ["schema", "bundle", "inspect", "--help"],
            "xdr schema bundle inspect /mnt/transfer/schema-state.tar.gz",
        ),
        (
            ["schema", "bundle", "export", "--help"],
            "xdr schema bundle export /mnt/transfer/schema-state.tar.gz",
        ),
        (
            ["schema", "bundle", "import", "--help"],
            "xdr schema bundle import /mnt/transfer/schema-state.tar.gz --yes",
        ),
    )
    for arguments, reference in cases:
        result = runner.invoke(app, arguments)
        assert result.exit_code == 0, result.output
        assert reference in " ".join(unstyle(result.output).split())


def test_diagnostics_report_build_and_passive_automation_counts(tmp_path, monkeypatch):
    home = tmp_path / "xdr-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    result_dir = home / "results" / "2026-08-01"
    result_dir.mkdir(parents=True)
    (result_dir / "one.meta.json").write_text(
        json.dumps({"schema_catalog_ingestion": {"status": "published"}})
    )
    (result_dir / "two.meta.json").write_text(
        json.dumps({"schema_catalog_ingestion": {"status": "no-eligible-paths"}})
    )
    maintenance = maintenance_status(
        "tenant", cache_stale_seconds=86400, collection_stale_seconds=604800
    )
    diagnostics = build_diagnostics(maintenance)

    assert diagnostics["package_version"]
    assert len(diagnostics["schema_capabilities"]) == len(SCHEMA_CAPABILITIES)
    assert maintenance["passive_ingestion"] == {
        "attempts": 2,
        "outcomes": {"no-eligible-paths": 1, "published": 1},
        "invalid_sidecars_skipped": 0,
    }
    assert maintenance["semantic_evidence"] == {
        "total": 0,
        "readiness_eligible": 0,
        "legacy_or_stale": 0,
        "eligibility_scope": "timestamp-horizon-only",
    }




def test_status_ignores_retired_collection_checkpoints(tmp_path, monkeypatch):

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    tenant_key = hashlib.sha256(b"tenant").hexdigest()[:12]
    root = tmp_path / "schema" / tenant_key / "collection-checkpoints"
    root.mkdir(parents=True)
    checkpoint = root / "collect-0123456789abcdef01234567.json"
    checkpoint.write_text(json.dumps({"state": "paused", "updated_at": "2099-01-01T00:00:00Z"}))
    status = maintenance_status(
        "tenant", cache_stale_seconds=86400, collection_stale_seconds=604800
    )
    assert "crawl_checkpoints" not in status
    assert status["next_command"] == "xdr schema refresh"
    assert "semantic-collection-incomplete" not in status["reasons"]
    assert checkpoint.is_file()
