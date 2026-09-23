from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from xdr_cli.schema_graph.maintenance import maintenance_status, mark_collection_complete


def test_maintenance_status_is_fail_soft_and_collection_marker_is_value_free(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    missing = maintenance_status(
        "tenant",
        cache_stale_seconds=86400,
        collection_stale_seconds=604800,
    )
    assert missing["due"] is True
    assert "physical-cache-missing" in missing["reasons"]
    assert "semantic-collection-never-run" in missing["reasons"]
    assert not (tmp_path / "xdr-home" / "schema").exists()

    marker = mark_collection_complete(
        "tenant",
        {"sources": ["DeviceNetworkEvents.DeviceId"], "exhaustive": False},
    )
    marked = maintenance_status(
        "tenant",
        cache_stale_seconds=86400,
        collection_stale_seconds=604800,
    )
    assert marked["semantic_collection"]["state"] == "fresh"
    assert "semantic-collection-never-run" not in marked["reasons"]
    assert "DeviceNetworkEvents.DeviceId" in marker.read_text(encoding="utf-8")
    assert "value" not in marker.read_text(encoding="utf-8").casefold()


def test_unconfigured_cli_does_not_emit_maintenance_advisory(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    status = maintenance_status(
        "",
        cache_stale_seconds=1,
        collection_stale_seconds=1,
    )
    assert status == {
        "configured": False,
        "due": False,
        "reasons": [],
        "next_command": "xdr auth login",
    }


def test_maintenance_status_detects_content_corrupt_physical_cache(
    tmp_path, monkeypatch
):
    home = tmp_path / "xdr-home"
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    root = home / "schema" / hashlib.sha256(b"tenant").hexdigest()[:12]
    root.mkdir(parents=True)
    generation = "20260801T000000000000Z-test"
    raw = b'{"TableName":"DeviceInfo","ColumnName":"DeviceId"}\n'
    data_path = root / f"schema.{generation}.jsonl"
    data_path.write_bytes(raw)
    (root / f"schema.{generation}.meta.json").write_text(
        json.dumps(
            {
                "generation": generation,
                "tenant_key": root.name,
                "refreshed_at": datetime.now(UTC).isoformat(),
                "row_count": 1,
                "data_sha256": hashlib.sha256(raw).hexdigest(),
                "data_bytes": len(raw),
            }
        )
    )
    (root / "current.json").write_text(json.dumps({"generation": generation}))

    assert maintenance_status(
        "tenant", cache_stale_seconds=86400, collection_stale_seconds=604800
    )["physical_cache"]["state"] == "fresh"

    data_path.write_bytes(b"")
    corrupt = maintenance_status(
        "tenant", cache_stale_seconds=86400, collection_stale_seconds=604800
    )
    assert corrupt["physical_cache"]["state"] == "invalid"
    assert "physical-cache-invalid" in corrupt["reasons"]
    assert corrupt["next_command"] == "xdr schema refresh"
