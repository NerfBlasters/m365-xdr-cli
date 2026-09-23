from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from xdr_cli.schema_graph.cache import (
    load_schema_cache_pair,
    migrate_legacy_schema_cache,
    schema_cache_status,
)


def _legacy_cache(tmp_path: Path) -> tuple[Path, str, Path, Path, bytes]:
    tenant_key = hashlib.sha256(b"tenant").hexdigest()[:12]
    root = tmp_path / tenant_key
    root.mkdir()
    generation = "20260801T000000000000Z-legacy"
    raw = b'{"TableName":"DeviceInfo","ColumnName":"DeviceId"}\n'
    data_path = root / f"schema.{generation}.jsonl"
    meta_path = root / f"schema.{generation}.meta.json"
    data_path.write_bytes(raw)
    meta_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generation": generation,
                "tenant_key": tenant_key,
                "refreshed_at": "2026-08-01T00:00:00Z",
                "row_count": 1,
            }
        )
    )
    (root / "current.json").write_text(json.dumps({"generation": generation}))
    return root, tenant_key, data_path, meta_path, raw


def test_legacy_cache_migration_is_content_bound_and_preserves_metadata(tmp_path):
    root, tenant_key, data_path, meta_path, raw = _legacy_cache(tmp_path)
    original_metadata = meta_path.read_bytes()

    status = schema_cache_status(root, expected_tenant_key=tenant_key)
    assert status["state"] == "legacy-unbound"
    assert status["migration_command"] == "xdr schema migrate-cache --yes"

    migrated = migrate_legacy_schema_cache(root, expected_tenant_key=tenant_key)
    metadata = json.loads(meta_path.read_text())
    rows, verified = load_schema_cache_pair(
        data_path, meta_path, expected_generation=migrated["generation"]
    )
    assert migrated["state"] == "migrated"
    assert data_path.read_bytes() == raw
    assert rows == [{"TableName": "DeviceInfo", "ColumnName": "DeviceId"}]
    assert verified["binding_origin"] == "local-legacy-migration"
    assert metadata["data_sha256"] == hashlib.sha256(raw).hexdigest()
    assert metadata["data_bytes"] == len(raw)
    quarantine = Path(migrated["quarantine_path"])
    assert (quarantine / meta_path.name).read_bytes() == original_metadata

    repeated = migrate_legacy_schema_cache(root, expected_tenant_key=tenant_key)
    assert repeated["state"] == "already-verified"
    assert repeated["quarantine_path"] is None


@pytest.mark.parametrize("fault", ["generation", "tenant", "directory", "count"])
def test_legacy_cache_migration_rejects_identity_and_count_mismatches(
    tmp_path, fault
):
    root, tenant_key, _data_path, meta_path, _raw = _legacy_cache(tmp_path)
    metadata = json.loads(meta_path.read_text())
    expected = tenant_key
    if fault == "generation":
        metadata["generation"] = "different"
    elif fault == "tenant":
        metadata["tenant_key"] = "000000000000"
    elif fault == "directory":
        expected = "111111111111"
    else:
        metadata["row_count"] = 2
    meta_path.write_text(json.dumps(metadata))

    before = meta_path.read_bytes()
    with pytest.raises(ValueError):
        migrate_legacy_schema_cache(root, expected_tenant_key=expected)
    assert meta_path.read_bytes() == before
    assert not (root / "quarantine").exists()


def test_partial_legacy_digest_is_corrupt_not_migratable(tmp_path):
    root, tenant_key, _data_path, meta_path, _raw = _legacy_cache(tmp_path)
    metadata = json.loads(meta_path.read_text())
    metadata["data_sha256"] = "0" * 64
    meta_path.write_text(json.dumps(metadata))

    status = schema_cache_status(root, expected_tenant_key=tenant_key)
    assert status["state"] == "invalid"
    with pytest.raises(ValueError):
        migrate_legacy_schema_cache(root, expected_tenant_key=tenant_key)
