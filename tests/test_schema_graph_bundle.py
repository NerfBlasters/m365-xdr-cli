from __future__ import annotations

import hashlib
import io
import json
import os
import errno
import stat
import tarfile
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from click.testing import CliRunner

from xdr_cli._lock import exclusive_lock
from xdr_cli.main import app
from xdr_cli.results import write_result
from xdr_cli.schema_graph import bundle as bundle_module
from xdr_cli.schema_graph.bundle import (
    export_bundle,
    import_bundle,
    inspect_bundle,
)
from xdr_cli.schema_graph.model import (
    Cardinality,
    Confidence,
    Direction,
    Graph,
    ObservationRecord,
    RelationshipKind,
    RelationshipRecord,
    RelationshipStatus,
    relationship_id,
)
from xdr_cli.schema_graph.overlay import (
    load_tenant_overlay,
    publish_tenant_observations,
)


def _portable_state(tmp_path, monkeypatch):
    tenant = "00000000-0000-4000-8000-000000000001"
    source_home = tmp_path / "source-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(source_home))
    result = write_result(
        [{"SyntheticId": "fabricated-value"}],
        command="test synthetic",
        server_truncation_state="known-complete",
        tenant_id=tenant,
    )
    observation = ObservationRecord(
        observation_id="probe:portable-test",
        source_interpretation="interp:source",
        target_interpretation="interp:target",
        transform="identity",
        distinct_seeds=1,
        matched_seeds=1,
        probe_runs=1,
        provenance=("tenant-observation:synthetic",),
        source_artifact_run_id=result.receipt.run_id,
        outcome="matched",
        schema_generation="schema-test",
    )
    publish_tenant_observations(tenant, (observation,))
    archive = tmp_path / "portable-state.tar.gz"
    export_bundle(source_home, tenant, archive)
    return tenant, source_home, archive, result.receipt.run_id


def _write_tar(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for info, value in members:
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))


def _extend_bundle(
    source: Path,
    destination: Path,
    *,
    name: str,
    value: bytes,
    sensitivity: str,
) -> None:
    inspected = inspect_bundle(source)
    manifest = dict(inspected.manifest)
    manifest["files"] = [
        *manifest["files"],
        {
            "path": name,
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "sensitivity": sensitivity,
        },
    ]
    manifest_raw = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    members = [(tarfile.TarInfo("manifest.json"), manifest_raw)]
    members.extend(
        (tarfile.TarInfo(member_name), member_value)
        for member_name, member_value in sorted(inspected.files.items())
    )
    members.append((tarfile.TarInfo(name), value))
    _write_tar(destination, members)


def test_bundle_relocates_result_sidecars_and_preserves_evidence_bindings(
    tmp_path, monkeypatch
):
    tenant, _source_home, archive, run_id = _portable_state(tmp_path, monkeypatch)
    inspected = inspect_bundle(archive)
    assert inspected.summary()["activation_eligible"] is False
    assert inspected.summary()["includes_results"] is True

    destination = tmp_path / "destination-home"
    destination.mkdir()
    imported = import_bundle(destination, tenant, archive)
    monkeypatch.setenv("XDR_CLI_HOME", str(destination))
    overlay = load_tenant_overlay(tenant)
    assert imported["results"] == 1
    assert overlay.observations[0].source_artifact_run_id == run_id


def test_bundle_export_omits_retired_collection_checkpoints_and_their_only_evidence(
    tmp_path, monkeypatch
):
    tenant, source_home, _archive, active_run = _portable_state(tmp_path, monkeypatch)
    tenant_key = hashlib.sha256(tenant.encode()).hexdigest()[:12]
    retired_result = write_result(
        [{"SyntheticId": "retired-checkpoint-only"}],
        command="test synthetic",
        tenant_id=tenant,
    )
    checkpoints = source_home / "schema" / tenant_key / "collection-checkpoints"
    checkpoints.mkdir()
    checkpoint = checkpoints / "collect-0123456789abcdef01234567.json"
    checkpoint.write_text(json.dumps({"source_artifact_run_id": retired_result.receipt.run_id}))
    original = checkpoint.read_bytes()
    archive = tmp_path / "current-state.tar.gz"

    export_bundle(source_home, tenant, archive)
    inspected = inspect_bundle(archive)

    assert inspected.manifest["referenced_result_ids"] == [active_run]
    assert all("collection-checkpoints" not in name for name in inspected.member_names)
    assert all(retired_result.receipt.run_id not in name for name in inspected.member_names)
    assert checkpoint.read_bytes() == original
    # Retired files are not opened or parsed, including malformed JSON.
    checkpoint.write_text("not JSON")
    export_bundle(source_home, tenant, tmp_path / "with-invalid-retired-checkpoint.tar.gz")


def test_bundle_rejects_retired_collection_members_before_activation(tmp_path, monkeypatch):
    tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    tenant_key = hashlib.sha256(tenant.encode()).hexdigest()[:12]
    legacy = tmp_path / "retired-checkpoint.tar.gz"
    _extend_bundle(
        archive,
        legacy,
        name=f"schema/{tenant_key}/collection-checkpoints/collect-0123456789abcdef01234567.json",
        value=b"{}\n",
        sensitivity="value-free-schema",
    )
    destination = tmp_path / "destination"
    destination.mkdir()

    with pytest.raises(ValueError, match="portable namespace"):
        inspect_bundle(legacy)
    with pytest.raises(ValueError, match="portable namespace"):
        import_bundle(destination, tenant, legacy)
    assert list(destination.iterdir()) == []


def test_bundle_rejects_foreign_tenant_activation(tmp_path, monkeypatch):
    _tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    destination = tmp_path / "foreign-home"
    destination.mkdir()

    with pytest.raises(ValueError, match="inspection-only"):
        import_bundle(destination, "different-tenant", archive)
    assert list(destination.iterdir()) == []


def test_bundle_collision_leaves_existing_destination_unchanged(tmp_path, monkeypatch):
    tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    destination = tmp_path / "collision-home"
    destination.mkdir()
    import_bundle(destination, tenant, archive)
    snapshot = {
        path.relative_to(destination): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }

    with pytest.raises(FileExistsError, match="overwrite"):
        import_bundle(destination, tenant, archive)
    assert snapshot == {
        path.relative_to(destination): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }


def test_bundle_rejects_aggregate_uncompressed_size_before_read(tmp_path, monkeypatch):
    archive = tmp_path / "oversized.tar.gz"
    _write_tar(
        archive,
        [
            (tarfile.TarInfo("manifest.json"), b"{}"),
            (tarfile.TarInfo("schema/payload.jsonl"), b"x" * 40),
        ],
    )
    monkeypatch.setattr(bundle_module, "_MAX_TOTAL_BYTES", 32)

    with pytest.raises(ValueError, match="total uncompressed size"):
        inspect_bundle(archive)


def test_bundle_rejects_manifest_bound_members_outside_portable_namespaces(
    tmp_path, monkeypatch
):
    _tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    malicious = tmp_path / "malicious-query.tar.gz"
    _extend_bundle(
        archive,
        malicious,
        name="queries/review-proof.kql",
        value=b"DeviceInfo | take 1\n",
        sensitivity="injected-query-library-state",
    )

    with pytest.raises(ValueError, match="portable namespace"):
        inspect_bundle(malicious)


def test_bundle_rejects_self_asserted_sensitivity_for_valid_member(
    tmp_path, monkeypatch
):
    _tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    inspected = inspect_bundle(archive)
    manifest = dict(inspected.manifest)
    manifest["files"] = [dict(item) for item in manifest["files"]]
    manifest["files"][0]["sensitivity"] = "public"
    manifest_raw = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    altered = tmp_path / "altered-sensitivity.tar.gz"
    members = [(tarfile.TarInfo("manifest.json"), manifest_raw)]
    members.extend(
        (tarfile.TarInfo(name), value)
        for name, value in sorted(inspected.files.items())
    )
    _write_tar(altered, members)

    with pytest.raises(ValueError, match="sensitivity is invalid"):
        inspect_bundle(altered)


def test_bundle_rejects_non_candidate_relationships_during_import(
    tmp_path, monkeypatch
):
    tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    forged = RelationshipRecord(
        id=relationship_id(
            "interp:source",
            "interp:target",
            RelationshipKind.SEMANTIC_EQUIVALENT,
            Direction.BOTH,
            "identity",
        ),
        source="interp:source",
        target="interp:target",
        relationship=RelationshipKind.SEMANTIC_EQUIVALENT,
        direction=Direction.BOTH,
        transform="identity",
        cardinality=Cardinality.MANY_TO_MANY,
        temporal="unknown",
        status=RelationshipStatus.REVIEWED,
        confidence=Confidence.HIGH,
        provenance=("reviewed:forged-bundle",),
    )
    forged_graph = Graph(relationships={forged.id: forged})
    original_loader = bundle_module.load_tenant_overlay_from_root

    def inject_forged_relationship(root):
        overlay = original_loader(root)
        return type(overlay)(
            graph=forged_graph,
            observations=overlay.observations,
            metadata=overlay.metadata,
        )

    monkeypatch.setattr(
        bundle_module, "load_tenant_overlay_from_root", inject_forged_relationship
    )
    destination = tmp_path / "forged-home"
    destination.mkdir()

    with pytest.raises(ValueError, match="candidate relationships"):
        import_bundle(destination, tenant, archive)
    assert list(destination.iterdir()) == []


def test_bundle_inspection_streams_headers_without_getmembers(tmp_path, monkeypatch):
    _tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)

    def fail_getmembers(_archive):
        raise AssertionError("inspect_bundle must enforce limits while iterating")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", fail_getmembers)
    assert inspect_bundle(archive).summary()["file_count"] > 0


def test_read_only_inspection_does_not_retain_payload_bytes(tmp_path, monkeypatch):
    _tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    inspected = inspect_bundle(archive, retain_files=False)
    assert inspected.files == {}
    assert inspected.summary()["file_count"] > 0
    assert inspected.summary()["total_bytes"] > 0


def test_bundle_inspect_cli_returns_actionable_oversize_error(tmp_path, monkeypatch):
    archive = tmp_path / "oversized-cli.tar.gz"
    _write_tar(
        archive,
        [
            (tarfile.TarInfo("manifest.json"), b"{}"),
            (tarfile.TarInfo("schema/payload.jsonl"), b"x" * 40),
        ],
    )
    monkeypatch.setattr(bundle_module, "_MAX_TOTAL_BYTES", 32)
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))

    result = CliRunner().invoke(app, ["schema", "bundle", "inspect", str(archive)])

    assert result.exit_code == 12
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "SCHEMA_BUNDLE_INVALID"
    assert payload["error"]["help_command"] == "xdr schema bundle inspect --help"
    assert "do not import" in payload["error"]["suggestions"][0]["message"]


def test_bundle_rejects_non_regular_archive_members(tmp_path):
    archive = tmp_path / "symlink.tar.gz"
    manifest = tarfile.TarInfo("manifest.json")
    link = tarfile.TarInfo("schema/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "../outside"
    with tarfile.open(archive, "w:gz") as bundle:
        manifest_raw = b"{}"
        manifest.size = len(manifest_raw)
        bundle.addfile(manifest, io.BytesIO(manifest_raw))
        bundle.addfile(link)

    with pytest.raises(ValueError, match="not a regular file"):
        inspect_bundle(archive)


def test_bundle_concurrent_collision_is_not_overwritten(tmp_path, monkeypatch):
    tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    destination = tmp_path / "concurrent-home"
    destination.mkdir()
    original_link = os.link
    injected: list[Path] = []

    def inject_collision(source, target, *args, **kwargs):
        target_path = Path(target)
        if ".bundle-import-" in str(source) and not injected:
            target_path.write_bytes(b"concurrent-owner")
            injected.append(target_path)
        return original_link(source, target, *args, **kwargs)

    monkeypatch.setattr(bundle_module.os, "link", inject_collision)
    with pytest.raises(FileExistsError):
        import_bundle(destination, tenant, archive)

    assert len(injected) == 1
    assert injected[0].read_bytes() == b"concurrent-owner"


def test_bundle_export_concurrent_collision_is_not_overwritten(tmp_path, monkeypatch):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    output = tmp_path / "concurrent-export.tar.gz"
    original_link = os.link
    injected = False

    def inject_collision(source, target, *args, **kwargs):
        nonlocal injected
        if Path(target) == output and not injected:
            output.write_bytes(b"concurrent-owner")
            injected = True
        return original_link(source, target, *args, **kwargs)

    monkeypatch.setattr(bundle_module.os, "link", inject_collision)
    with pytest.raises(FileExistsError):
        export_bundle(source_home, tenant, output)

    assert injected is True
    assert output.read_bytes() == b"concurrent-owner"
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))


def test_bundle_export_validates_before_publication_and_leaves_no_rejected_output(
    tmp_path, monkeypatch
):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    output = tmp_path / "rejected-export.tar.gz"
    monkeypatch.setattr(bundle_module, "_MAX_TOTAL_BYTES", 1)

    with pytest.raises(ValueError, match="total uncompressed size"):
        export_bundle(source_home, tenant, output)

    assert not output.exists()
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))


def test_bundle_export_rejects_oversized_source_before_reading_it(tmp_path, monkeypatch):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    schema_root = next((source_home / "schema").iterdir())
    oversized = schema_root / "semantic.oversized.jsonl"
    with oversized.open("wb") as handle:
        handle.truncate(64)
    monkeypatch.setattr(bundle_module, "_MAX_FILE_BYTES", 32)
    original_read_bytes = Path.read_bytes

    def reject_oversized_read(path):
        if path == oversized:
            raise AssertionError("oversized source must be rejected before read_bytes")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", reject_oversized_read)
    output = tmp_path / "oversized-source.tar.gz"
    with pytest.raises(ValueError, match="unsafe size"):
        export_bundle(source_home, tenant, output)
    assert not output.exists()


def test_bundle_export_is_owner_only_under_permissive_umask(tmp_path, monkeypatch):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    output = tmp_path / "private-export.tar.gz"
    prior = os.umask(0o022)
    try:
        export_bundle(source_home, tenant, output)
    finally:
        os.umask(prior)

    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_bundle_publication_falls_back_when_hard_links_are_unsupported(
    tmp_path, monkeypatch
):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    output = tmp_path / "portable-export.tar.gz"

    def unsupported_link(*_args, **_kwargs):
        raise OSError(errno.EPERM, "hard links unsupported")

    monkeypatch.setattr(bundle_module.os, "link", unsupported_link)
    export_bundle(source_home, tenant, output)
    assert inspect_bundle(output).summary()["file_count"] > 0

    destination = tmp_path / "portable-import-home"
    destination.mkdir()
    import_bundle(destination, tenant, output)
    assert next((destination / "schema").rglob("semantic.current.json")).is_file()


def test_bundle_copy_fallback_removes_partial_destination(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"complete")

    def unsupported_link(*_args, **_kwargs):
        raise OSError(errno.EPERM, "hard links unsupported")

    def interrupted_copy(_source, target, **_kwargs):
        target.write(b"partial")
        raise OSError("synthetic copy interruption")

    monkeypatch.setattr(bundle_module.os, "link", unsupported_link)
    monkeypatch.setattr(bundle_module.shutil, "copyfileobj", interrupted_copy)

    with pytest.raises(OSError, match="synthetic copy interruption"):
        bundle_module._link_no_replace(source, destination)
    assert not destination.exists()


def test_bundle_refuses_to_omit_referenced_evidence(tmp_path, monkeypatch):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    missing_archive = tmp_path / "missing.tar.gz"
    with pytest.raises(ValueError, match="include evidence"):
        export_bundle(
            source_home, tenant, missing_archive, include_evidence=False
        )
    assert not missing_archive.exists()


def test_bundle_imports_inactive_sessions_and_advances_operator_counter(
    tmp_path, monkeypatch
):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    sessions = source_home / "sessions"
    sessions.mkdir()
    (sessions / "ap-86.jsonl").write_text(
        '{"kind":"session_started","session_id":"ap-86"}\n'
    )
    (sessions / ".seq-ap-86").write_text("0")
    archive = tmp_path / "with-sessions.tar.gz"
    export_bundle(source_home, tenant, archive, include_sessions=True)
    destination = tmp_path / "session-home"
    destination.mkdir()

    imported = import_bundle(destination, tenant, archive)
    assert imported["sessions"] == 2
    assert (destination / "sessions" / "ap-86.jsonl").is_file()
    assert not (destination / "active_sessions").exists()
    assert (destination / "sessions" / ".counter-ap").read_text() == "86"


def test_bundle_rejects_malformed_session_history_before_publication(
    tmp_path, monkeypatch
):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    sessions = source_home / "sessions"
    sessions.mkdir()
    (sessions / "ap-86.jsonl").write_text(
        '{"kind":"session_started","session_id":"wrong-1"}\n'
    )
    archive = tmp_path / "malformed-session.tar.gz"
    export_bundle(source_home, tenant, archive, include_sessions=True)
    destination = tmp_path / "malformed-session-home"
    destination.mkdir()

    with pytest.raises(ValueError, match="session history"):
        import_bundle(destination, tenant, archive)
    assert list(destination.iterdir()) == []


def test_bundle_session_import_coordinates_with_live_counter_allocation(
    tmp_path, monkeypatch
):
    tenant, source_home, _archive, _run_id = _portable_state(tmp_path, monkeypatch)
    sessions = source_home / "sessions"
    sessions.mkdir()
    (sessions / "ap-86.jsonl").write_text(
        '{"kind":"session_started","session_id":"ap-86"}\n'
    )
    archive = tmp_path / "counter-race.tar.gz"
    export_bundle(source_home, tenant, archive, include_sessions=True)
    destination = tmp_path / "counter-race-home"
    counter = destination / "sessions" / ".counter-ap"
    counter.parent.mkdir(parents=True)
    counter.write_text("80")
    attempted = threading.Event()
    failures: list[BaseException] = []
    original_lock = bundle_module.exclusive_lock

    @contextmanager
    def observed_lock(path, *args, **kwargs):
        if path == counter:
            attempted.set()
        with original_lock(path, *args, **kwargs):
            yield

    monkeypatch.setattr(bundle_module, "exclusive_lock", observed_lock)

    def run_import():
        try:
            import_bundle(destination, tenant, archive)
        except BaseException as exc:  # captured for assertion in the test thread
            failures.append(exc)

    with exclusive_lock(counter):
        worker = threading.Thread(target=run_import)
        worker.start()
        assert attempted.wait(timeout=1)
        assert worker.is_alive()
        counter.write_text("90")
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], FileExistsError)
    assert counter.read_text() == "90"
    assert not (destination / "sessions" / "ap-86.jsonl").exists()


def test_bundle_interrupted_publication_rolls_back_created_files(
    tmp_path, monkeypatch
):
    tenant, _source_home, archive, _run_id = _portable_state(tmp_path, monkeypatch)
    destination = tmp_path / "interrupted-home"
    destination.mkdir()
    original_link = os.link
    publications = 0

    def interrupt_second_publication(source, target, *args, **kwargs):
        nonlocal publications
        if ".bundle-import-" in str(source):
            publications += 1
            if publications == 2:
                raise OSError("synthetic interruption")
        return original_link(source, target, *args, **kwargs)

    monkeypatch.setattr(
        "xdr_cli.schema_graph.bundle.os.link", interrupt_second_publication
    )
    with pytest.raises(OSError, match="synthetic interruption"):
        import_bundle(destination, tenant, archive)
    assert list(destination.iterdir()) == []


def test_bundle_relocates_candidate_proposal_and_rebinds_its_path(
    tmp_path, monkeypatch
):
    tenant, source_home, _archive, evidence_run = _portable_state(
        tmp_path, monkeypatch
    )
    proposal_path = source_home / "drafts" / "candidate.jsonl"
    proposal_path.parent.mkdir()
    rows = [{"record_type": "synthetic-proposal", "id": "proposal:test"}]
    proposal_raw = (
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)
    ).encode()
    proposal_path.write_bytes(proposal_raw)
    snapshot = {
        "overlay_generation": load_tenant_overlay(tenant).metadata["generation"],
        "validated_observation_ids": ["probe:portable-test"],
        "source_artifact_run_ids": [evidence_run],
        "target_artifact_run_ids": [evidence_run],
        "review_artifact_run_ids": [evidence_run],
    }
    snapshot["sha256"] = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    binding = {
        "proposal_path": str(proposal_path.resolve()),
        "source_candidate_relationship_id": "rel:synthetic-source",
        "proposed_relationship_id": "rel:synthetic-proposed",
        "proposal_sha256": hashlib.sha256(proposal_raw).hexdigest(),
        "proposal_bytes": len(proposal_raw),
        "evidence_snapshot": snapshot,
    }
    binding["binding_sha256"] = hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    proposal_result = write_result(
        rows,
        command="schema candidate-proposal",
        server_truncation_state="known-complete",
        tenant_id=tenant,
        extra_metadata={
            "candidate_proposal": binding,
            "proposal_path": str(proposal_path.resolve()),
        },
    )
    archive = tmp_path / "proposal-state.tar.gz"
    export_bundle(source_home, tenant, archive)
    destination = tmp_path / "proposal-home"
    destination.mkdir()

    import_bundle(destination, tenant, archive)
    imported_proposal = (
        destination / "proposals" / f"{proposal_result.receipt.run_id}.jsonl"
    )
    imported_meta = next(
        (destination / "results").glob(
            f"*/{proposal_result.receipt.run_id}.meta.json"
        )
    )
    metadata = json.loads(imported_meta.read_text())
    relocated = metadata["candidate_proposal"]
    unsigned = {
        key: value for key, value in relocated.items() if key != "binding_sha256"
    }
    assert imported_proposal.read_bytes() == proposal_raw
    assert relocated["proposal_path"] == str(imported_proposal.resolve())
    assert relocated["binding_sha256"] == hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
