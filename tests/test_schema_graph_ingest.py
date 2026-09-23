from __future__ import annotations

from xdr_cli.results import write_result
from xdr_cli.schema_graph.effective import FieldAvailability, compose_effective_graph
from xdr_cli.schema_graph.ingest import infer_direct_table_lineage
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.overlay import load_tenant_overlay


def test_lineage_inference_accepts_only_simple_single_table_queries():
    assert (
        infer_direct_table_lineage("CloudAppEvents | where Timestamp > ago(1d) | take 5")
        == "CloudAppEvents"
    )
    assert infer_direct_table_lineage("CloudAppEvents | project RawEventData") is None
    assert (
        infer_direct_table_lineage(
            "CloudAppEvents | project-rename AccountObjectId=ApplicationId"
        )
        is None
    )
    assert infer_direct_table_lineage("CloudAppEvents | project-away ApplicationId") is None
    assert (
        infer_direct_table_lineage(
            "CloudAppEvents | join kind=inner DeviceEvents on AccountObjectId"
        )
        is None
    )


def test_result_publication_automatically_ingests_only_reviewed_nested_shape(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    artifact = write_result(
        [
            {
                "RawEventData": {
                    "UserId": "user@example.invalid",
                    "contoso.com": "secret",
                    "ProdServer": "secret",
                }
            }
        ],
        command="hunt run",
        tenant_id="tenant",
        physical_lineage_table="CloudAppEvents",
    )
    assert artifact.metadata["schema_catalog_ingestion"]["status"] == "published"
    overlay = load_tenant_overlay("tenant")
    assert set(overlay.graph.fields) == {"field:CloudAppEvents.RawEventData#/UserId"}
    canonical = load_packaged_graph()
    nested_id = "field:CloudAppEvents.RawEventData#/UserId"
    assert overlay.graph.fields[nested_id] == canonical.fields[nested_id]
    effective = compose_effective_graph(
        [{"TableName": "CloudAppEvents", "ColumnName": "RawEventData"}],
        canonical=canonical,
        overlays=(overlay.graph,),
    )
    assert effective.field_availability[nested_id] is FieldAvailability.AVAILABLE


def test_passive_ingestion_failure_does_not_lose_result_artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    artifact = write_result(
        [{"RawEventData": {"UserId": "user@example.invalid"}}],
        command="hunt run",
        tenant_id="tenant",
        physical_lineage_table="not a table",
    )
    assert artifact.receipt.rows == 1
    assert artifact.metadata["schema_catalog_ingestion"]["status"] == "failed"


def test_long_nested_key_cannot_publish_an_unreadable_overlay(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    artifact = write_result(
        [{"RawEventData": {"x" * 1100: "user@example.invalid"}}],
        command="hunt run",
        tenant_id="tenant",
        physical_lineage_table="CloudAppEvents",
    )

    assert artifact.metadata["schema_catalog_ingestion"]["status"] == "no-eligible-paths"
    assert not load_tenant_overlay("tenant").graph.fields
