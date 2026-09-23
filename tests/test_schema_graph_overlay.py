from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from xdr_cli.exceptions import ArtifactError, ConflictError
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.catalog import exhaustive_probe_targets
from xdr_cli.schema_graph.model import (
    FieldLocator,
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    ObservationRecord,
    field_id,
    interpretation_id,
)
from xdr_cli.schema_graph.overlay import (
    load_tenant_observations,
    load_tenant_overlay,
    publish_tenant_observations,
    publish_tenant_overlay,
    repair_all_local_overlays,
    repair_tenant_overlay,
    tenant_overlay_status,
)


def _observation(observation_id="probe:test", matched=2):
    return ObservationRecord(
        observation_id=observation_id,
        source_interpretation="interp:source",
        target_interpretation="interp:target",
        transform="identity",
        distinct_seeds=3,
        matched_seeds=matched,
        probe_runs=1,
        provenance=("tenant-observation:test",),
        outcome="matched" if matched else "no-match",
        schema_generation="schema-test",
    )


def test_private_overlay_is_atomic_deduplicated_and_value_free(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = publish_tenant_observations("tenant", (_observation(),))
    second = publish_tenant_observations("tenant", (_observation(),))
    observations, metadata = load_tenant_observations("tenant")
    assert first["generation"] != second["generation"]
    assert metadata["observation_count"] == len(observations) == 1
    assert metadata["integrity_state"] == "verified"
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    current = json.loads((root / "semantic.current.json").read_text())["generation"]
    assert current == second["generation"]
    serialized = (root / f"semantic.{current}.jsonl").read_text()
    assert "Value" not in serialized
    if os.name == "posix":
        assert (root / f"semantic.{current}.jsonl").stat().st_mode & 0o777 == 0o600


def test_overlay_republish_preserves_observation_extensions(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    extended = replace(
        _observation(),
        extra={"future_evidence_contract": {"batch_digest": "abc"}},
    )
    publish_tenant_overlay("tenant", observations=(extended,))

    publish_tenant_overlay(
        "tenant",
        observations=(_observation(observation_id="probe:new"),),
    )
    loaded = load_tenant_overlay("tenant")

    retained = next(
        item for item in loaded.observations if item.observation_id == extended.observation_id
    )
    assert retained.extra == extended.extra
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    generation = loaded.metadata["generation"]
    assert "future_evidence_contract" in (
        root / f"semantic.{generation}.jsonl"
    ).read_text()


def test_conflicting_observation_id_fails_without_replacing_generation(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    prior = publish_tenant_observations("tenant", (_observation(),))
    with pytest.raises(GraphValidationError, match="conflicting"):
        publish_tenant_observations("tenant", (_observation(matched=1),))
    _, metadata = load_tenant_observations("tenant")
    assert metadata["generation"] == prior["generation"]


def test_overlay_persists_private_field_and_provisional_interpretation(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    locator = FieldLocator.parse("OddTable.Initiator")
    graph = Graph()
    graph.add(FieldRecord(id=field_id(locator), locator=locator, kql_type="string"))
    graph.add(
        InterpretationRecord(
            id=interpretation_id(locator, "entra-upn", "neutral"),
            field_id=field_id(locator),
            entity_kind="user",
            namespace="entra-upn",
            role="neutral",
            normalizer="upn-lower",
            extra={"status": "candidate", "private": True},
        )
    )
    metadata = publish_tenant_overlay("tenant", graph=graph)
    loaded = load_tenant_overlay("tenant")
    assert metadata["field_count"] == len(loaded.graph.fields) == 1
    assert metadata["interpretation_count"] == len(loaded.graph.interpretations) == 1


def test_overlay_publication_reconciles_promoted_field_dependency(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    locator = FieldLocator.parse("FutureTable.FutureId")
    identifier = field_id(locator)
    discovered = Graph()
    discovered.add(
        FieldRecord(
            id=identifier,
            locator=locator,
            kql_type="string",
            extra={"provenance": ["tenant-schema"], "private": True},
        )
    )
    publish_tenant_overlay("tenant", graph=discovered)

    post_upgrade_probe = Graph()
    post_upgrade_probe.add(
        FieldRecord(id=identifier, locator=locator, kql_type="string")
    )
    new_interpretation_id = interpretation_id(locator, "future-id", "neutral")
    post_upgrade_probe.add(
        InterpretationRecord(
            id=new_interpretation_id,
            field_id=identifier,
            entity_kind="future-entity",
            namespace="future-id",
            role="neutral",
            normalizer="identity",
            extra={"status": "candidate", "provisional": True, "private": True},
        )
    )
    published = publish_tenant_overlay("tenant", graph=post_upgrade_probe)
    loaded = load_tenant_overlay("tenant")

    assert published["field_count"] == 1
    assert loaded.graph.fields[identifier].extra["private"] is True
    assert new_interpretation_id in loaded.graph.interpretations

    conflicting = Graph()
    conflicting.add(FieldRecord(id=identifier, locator=locator, kql_type="long"))
    with pytest.raises(GraphValidationError, match="conflicting graph record"):
        publish_tenant_overlay("tenant", graph=conflicting)


def test_overlay_retains_a_bounded_generation_rollback_window(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    for ordinal in range(5):
        publish_tenant_observations(
            "tenant",
            (_observation(observation_id=f"probe:test-{ordinal}"),),
        )

    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    assert len(list(root.glob("semantic.*.jsonl"))) == 3
    assert len(list(root.glob("semantic.*.meta.json"))) == 3


def test_overlay_retention_failure_does_not_misreport_committed_publication(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = publish_tenant_observations(
        "tenant", (_observation(observation_id="probe:first"),)
    )
    publish_tenant_observations(
        "tenant", (_observation(observation_id="probe:second"),)
    )
    publish_tenant_observations(
        "tenant", (_observation(observation_id="probe:third"),)
    )
    original_unlink = Path.unlink

    def locked_old_generation(path, *args, **kwargs):
        if path.name == f"semantic.{first['generation']}.jsonl":
            raise PermissionError("simulated Windows file lock")
        return original_unlink(path, *args, **kwargs)

    with patch.object(Path, "unlink", locked_old_generation):
        published = publish_tenant_observations(
            "tenant", (_observation(observation_id="probe:fourth"),)
        )

    loaded = load_tenant_overlay("tenant")
    assert loaded.metadata["generation"] == published["generation"]
    assert published["retention_cleanup_state"] == "incomplete"
    assert published["retention_cleanup_failure_count"] == 1


def test_overlay_round_trips_relationship_records(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    graph = load_packaged_graph()

    published = publish_tenant_overlay("tenant", graph=graph)
    loaded = load_tenant_overlay("tenant")

    assert published["relationship_count"] == len(graph.relationships)
    assert loaded.graph.relationships == graph.relationships


def test_overlay_digest_detects_valid_json_tampering_and_repairs_to_prior_generation(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = publish_tenant_observations("tenant", (_observation("probe:first"),))
    second = publish_tenant_observations("tenant", (_observation("probe:second"),))
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    data_path = root / f"semantic.{second['generation']}.jsonl"
    records = [json.loads(line) for line in data_path.read_text().splitlines()]
    for record in records:
        if record.get("record_type") == "observation":
            record["source_artifact_run_id"] = "run-tampered"
            break
    data_path.write_text("".join(json.dumps(row) + "\n" for row in records))

    assert tenant_overlay_status("tenant")["state"] == "invalid"
    repaired = repair_tenant_overlay("tenant")

    assert repaired["generation"] == first["generation"]
    assert repaired["integrity_state"] == "verified"
    assert load_tenant_overlay("tenant").metadata["generation"] == first["generation"]


def test_overlay_repair_migrates_legacy_generation_to_digest(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    published = publish_tenant_observations("tenant", (_observation(),))
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    meta_path = root / f"semantic.{published['generation']}.meta.json"
    metadata = json.loads(meta_path.read_text())
    metadata.pop("data_sha256")
    metadata.pop("data_bytes")
    meta_path.write_text(json.dumps(metadata))

    assert tenant_overlay_status("tenant")["state"] == "legacy-unbound"
    repaired = repair_tenant_overlay("tenant")

    assert repaired["integrity_state"] == "verified"
    assert tenant_overlay_status("tenant")["state"] == "valid"


def test_overlay_repair_inactivates_old_sha_contract_and_unsafe_passive_field(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    canonical = load_packaged_graph()
    source_id = "interp:DeviceFileEvents.SHA256:sha256:subject"
    source_field = canonical.fields["field:DeviceFileEvents.SHA256"]
    old_source = replace(
        canonical.interpretations[source_id],
        normalizer="sha-lower",
        extra={"status": "candidate", "provisional": True, "private": True},
    )
    target_locator = FieldLocator.parse("DeviceProcessEvents.SHA256")
    target_id = interpretation_id(target_locator, "sha256", "neutral")
    passive_locator = FieldLocator.parse(
        "DeviceEvents.AdditionalFields#/UnreviewedTenantKey"
    )
    passive_id = field_id(passive_locator)
    legacy = Graph()
    legacy.add(source_field)
    legacy.add(old_source)
    legacy.add(canonical.fields[field_id(target_locator)])
    legacy.add(
        InterpretationRecord(
            id=target_id,
            field_id=field_id(target_locator),
            entity_kind="hash",
            namespace="sha256",
            role="neutral",
            normalizer="sha-lower",
            extra={"status": "candidate", "provisional": True, "private": True},
        )
    )
    legacy.add(
        FieldRecord(
            id=passive_id,
            locator=passive_locator,
            kql_type="string",
            extra={"provenance": ["artifact-shape"], "private": True},
        )
    )
    observation = ObservationRecord(
        observation_id="probe:legacy-sha",
        source_interpretation=source_id,
        target_interpretation=target_id,
        transform="sha-lower",
        distinct_seeds=3,
        matched_seeds=2,
        probe_runs=1,
        provenance=("tenant-observation:test",),
        outcome="matched",
        schema_generation="schema-test",
    )
    published = publish_tenant_overlay(
        "tenant", graph=legacy, observations=(observation,)
    )
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    original_data = (
        root / f"semantic.{published['generation']}.jsonl"
    ).read_bytes()

    status = tenant_overlay_status("tenant")
    assert status["state"] == "needs-migration"
    assert status["compatibility"]["obsolete_interpretation_count"] == 2
    assert status["compatibility"]["unsafe_passive_field_count"] == 1
    assert status["compatibility"]["ineligible_observation_count"] == 1

    repaired = repair_tenant_overlay("tenant")
    migrated = load_tenant_overlay("tenant")
    quarantine = Path(repaired["quarantine_path"])
    assert repaired["generation"] != published["generation"]
    assert repaired["compatibility_state"] == "compatible"
    assert repaired["migration"]["inactivated_field_count"] == 1
    assert repaired["migration"]["inactivated_interpretation_count"] == 2
    assert repaired["migration"]["inactivated_observation_count"] == 1
    assert (quarantine / f"semantic.{published['generation']}.jsonl").read_bytes() == (
        original_data
    )
    assert source_id not in migrated.graph.interpretations
    assert target_id not in migrated.graph.interpretations
    assert passive_id not in migrated.graph.fields
    assert migrated.observations == ()

    targets, _additions = exhaustive_probe_targets(
        [
            {
                "TableName": "DeviceFileEvents",
                "ColumnName": "SHA256",
                "ColumnType": "string",
            },
            {
                "TableName": "DeviceProcessEvents",
                "ColumnName": "SHA256",
                "ColumnType": "string",
            },
            {
                "TableName": "DeviceEvents",
                "ColumnName": "AdditionalFields",
                "ColumnType": "string",
            },
        ],
        canonical,
        canonical.interpretations[source_id],
    )
    assert any(
        target.interpretation.normalizer == "sha256-lower" for target in targets
    )
    assert all(str(target.field.locator) != str(passive_locator) for target in targets)

    second = repair_tenant_overlay("tenant")
    assert second["generation"] == repaired["generation"]
    assert second["migration"] is None


def test_overlay_repair_selects_newest_structurally_valid_legacy_generation(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    publish_tenant_observations("tenant", (_observation("probe:older"),))
    newer = publish_tenant_observations("tenant", (_observation("probe:newer"),))
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    meta_path = root / f"semantic.{newer['generation']}.meta.json"
    metadata = json.loads(meta_path.read_text())
    metadata.pop("data_sha256")
    metadata.pop("data_bytes")
    meta_path.write_text(json.dumps(metadata))

    repaired = repair_tenant_overlay("tenant")

    assert repaired["generation"] == newer["generation"]
    assert repaired["observation_count"] == 2
    assert repaired["integrity_state"] == "verified"


def test_missing_manifest_is_repairable_and_blocks_new_publication(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    published = publish_tenant_observations("tenant", (_observation(),))
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    (root / "semantic.current.json").unlink()

    status = tenant_overlay_status("tenant")
    assert status["state"] == "invalid"
    assert status["integrity_state"] == "orphaned-generations"
    with pytest.raises(ArtifactError, match="no current manifest"):
        publish_tenant_observations("tenant", (_observation("probe:new"),))

    repaired = repair_tenant_overlay("tenant")
    assert repaired["generation"] == published["generation"]
    assert load_tenant_overlay("tenant").metadata["integrity_state"] == "verified"


def test_overlay_reset_preserves_invalid_files_in_quarantine(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    published = publish_tenant_observations("tenant", (_observation(),))
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    data_path = root / f"semantic.{published['generation']}.jsonl"
    data_path.write_text("invalid\n")

    with pytest.raises(ArtifactError) as failure:
        repair_tenant_overlay("tenant")
    assert failure.value.help_command == (
        "xdr schema repair-overlay --reset-empty --yes"
    )

    repaired = repair_tenant_overlay("tenant", reset_empty=True)
    quarantine = Path(repaired["quarantine_path"])
    assert repaired["reset_empty"] is True
    assert repaired["observation_count"] == 0
    assert repaired["next_command"] == "xdr schema collect"
    assert (quarantine / data_path.name).read_text() == "invalid\n"
    assert tenant_overlay_status("tenant")["state"] == "valid"


def test_overlay_refuses_to_publish_a_missing_result_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    observation = replace(
        _observation(), source_artifact_run_id="20260801T000000000000Z-deadbeef0000"
    )

    with pytest.raises(ArtifactError, match="unavailable or invalid") as failure:
        publish_tenant_observations("tenant", (observation,))

    assert failure.value.help_command == (
        "xdr results show 20260801T000000000000Z-deadbeef0000"
    )
    assert tenant_overlay_status("tenant")["state"] == "missing"


def test_overlay_expected_generation_prevents_stale_evidence_replacement(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    first = publish_tenant_observations("tenant", (_observation("probe:first"),))
    publish_tenant_observations("tenant", (_observation("probe:concurrent"),))

    with pytest.raises(ConflictError, match="changed after it was inspected"):
        publish_tenant_overlay(
            "tenant",
            observations=(_observation("probe:first"),),
            replace_observations=True,
            expected_generation=first["generation"],
        )

    assert {item.observation_id for item in load_tenant_overlay("tenant").observations} == {
        "probe:first",
        "probe:concurrent",
    }


def test_all_local_repair_preserves_all_local_reset_guidance(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    published = publish_tenant_overlay("other-tenant")
    root = next((tmp_path / "xdr-home" / "schema").iterdir())
    (root / f"semantic.{published['generation']}.jsonl").write_text("invalid\n")

    with pytest.raises(ArtifactError) as failure:
        repair_all_local_overlays()

    assert failure.value.help_command == (
        "xdr schema repair-overlay --all-local --reset-empty --yes"
    )
