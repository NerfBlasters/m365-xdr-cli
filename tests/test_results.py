"""Tests for artifact-first result storage."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from xdr_cli.artifact_records import incident_records
from xdr_cli.exceptions import ArtifactError
from xdr_cli.results import ResultStreamWriter, write_result


def _write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rows, **kwargs):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    return write_result(
        rows,
        command="hunt run",
        now=datetime(2026, 7, 31, 12, 34, 56, tzinfo=UTC),
        **kwargs,
    )


def test_write_result_creates_data_only_jsonl_and_metadata(tmp_path, monkeypatch):
    rows = [
        {"Timestamp": "t1", "Device": {"Name": "host1"}},
        {"Timestamp": "t2", "Device": {"Name": None}, "Optional": 7},
    ]
    artifact = _write(
        tmp_path,
        monkeypatch,
        rows,
        query="DeviceEvents | take 2",
        session_id="ap-12",
        incident_id="155278",
        execution_time_ms=42,
    )

    data_path = Path(artifact.receipt.data_path)
    meta_path = Path(artifact.receipt.meta_path)
    assert data_path.read_text().splitlines() == [
        '{"Timestamp":"t1","Device":{"Name":"host1"}}',
        '{"Timestamp":"t2","Device":{"Name":null},"Optional":7}',
    ]
    metadata = json.loads(meta_path.read_text())
    assert metadata["query"] == "DeviceEvents | take 2"
    assert len(metadata["query_sha256"]) == 64
    assert metadata["row_count"] == 2
    assert metadata["data_sha256"]
    assert metadata["tenant_binding"] == {"state": "unbound", "sha256": None}
    assert metadata["server_truncation_state"] == "unknown"
    assert metadata["session"] == {
        "id": "ap-12",
        "label": None,
        "attachment": "unattached",
    }
    assert metadata["anchors"]["incident_id"] == "155278"
    assert artifact.receipt.rows == 2
    assert len(artifact.stdout_lines()) == 3


def test_observed_shape_unions_sparse_nested_paths(tmp_path, monkeypatch):
    artifact = _write(
        tmp_path,
        monkeypatch,
        [
            {"A": 1, "Nested": {"Value": "x"}, "Items": [{"Id": "one"}]},
            {"A": None, "Items": [{"Id": "two"}, {"Id": "three"}]},
        ],
    )
    shape = {entry["path"]: entry for entry in artifact.metadata["observed_shape"]}
    assert shape["A"] == {
        "path": "A",
        "path_tokens": [{"kind": "property", "value": "A"}],
        "json_pointer": "/A",
        "types": ["integer", "null"],
        "present_count": 2,
        "non_null_count": 1,
    }
    assert shape["Nested.Value"]["present_count"] == 1
    assert shape["Items[].Id"]["present_count"] == 2
    assert shape["Items[].Id"]["json_pointer"] == "/Items/*/Id"


def test_observed_shape_tokens_are_lossless_for_ambiguous_json_keys(tmp_path, monkeypatch):
    artifact = _write(
        tmp_path,
        monkeypatch,
        [{"Raw.Event": {"Items[]": [{"slash/key": 1}]}}],
    )
    leaf = artifact.metadata["observed_shape"][-1]
    assert leaf["path"] == "Raw.Event.Items[][].slash/key"
    assert leaf["json_pointer"] == "/Raw.Event/Items[]/*/slash~1key"
    assert leaf["path_tokens"] == [
        {"kind": "property", "value": "Raw.Event"},
        {"kind": "property", "value": "Items[]"},
        {"kind": "array"},
        {"kind": "property", "value": "slash/key"},
    ]


@pytest.mark.parametrize("rows,expected_lines", [([], 1), ([{"a": 1}], 2)])
def test_stdout_line_count_is_bounded(tmp_path, monkeypatch, rows, expected_lines):
    artifact = _write(tmp_path, monkeypatch, rows)
    assert len(artifact.stdout_lines()) == expected_lines
    assert all("\n" not in line for line in artifact.stdout_lines())
    assert all(isinstance(json.loads(line), dict) for line in artifact.stdout_lines())


def test_oversized_preview_is_omitted_but_full_row_is_saved(tmp_path, monkeypatch):
    row = {"Raw": "x" * 100}
    artifact = _write(
        tmp_path,
        monkeypatch,
        [row],
        preview_byte_cap=20,
    )
    assert json.loads(Path(artifact.receipt.data_path).read_text()) == row
    assert artifact.preview_records == (
        {
            "record_type": "preview_omitted",
            "row_number": 1,
            "size_bytes": 110,
            "reason": "row_exceeds_preview_byte_cap",
        },
    )


def test_json_string_newline_stays_on_one_physical_line(tmp_path, monkeypatch):
    artifact = _write(tmp_path, monkeypatch, [{"message": "first\nsecond"}])
    lines = Path(artifact.receipt.data_path).read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "first\nsecond"


def test_private_modes_on_posix(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX modes only")
    artifact = _write(tmp_path, monkeypatch, [{"a": 1}])
    data_path = Path(artifact.receipt.data_path)
    config_home = tmp_path / ".xdr-cli"
    results_root = config_home / "results"
    assert config_home.stat().st_mode & 0o777 == 0o700
    assert results_root.stat().st_mode & 0o777 == 0o700
    assert data_path.parent.stat().st_mode & 0o777 == 0o700
    assert data_path.stat().st_mode & 0o777 == 0o600
    assert Path(artifact.receipt.meta_path).stat().st_mode & 0o777 == 0o600


def test_non_object_row_fails_without_final_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    with pytest.raises(ArtifactError, match="JSON objects"):
        write_result([{"ok": True}, "not-an-object"], command="hunt run")
    result_dir = tmp_path / ".xdr-cli" / "results"
    assert not list(result_dir.rglob("*.jsonl"))
    assert not list(result_dir.rglob("*.meta.json"))
    assert not list(result_dir.rglob("*.tmp"))


def test_metadata_failure_removes_promoted_data(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    real_replace = os.replace

    def fail_metadata_replace(src, dst):
        if str(dst).endswith(".meta.json"):
            raise OSError("disk failure")
        return real_replace(src, dst)

    with (
        patch("xdr_cli.results.os.replace", side_effect=fail_metadata_replace),
        pytest.raises(ArtifactError, match="disk failure"),
    ):
        write_result([{"ok": True}], command="hunt run")

    result_dir = tmp_path / ".xdr-cli" / "results"
    assert not list(result_dir.rglob("*.jsonl"))
    assert not list(result_dir.rglob("*.meta.json"))
    assert not list(result_dir.rglob("*.tmp"))


def test_stream_writer_does_not_require_buffering_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    with ResultStreamWriter(command="device timeline") as stream:
        stream.write_row({"Id": "one"})
        stream.write_row({"Id": "two"})
        artifact = stream.finish(execution_time_ms=12)
    assert Path(artifact.receipt.data_path).read_text().splitlines() == [
        '{"Id":"one"}',
        '{"Id":"two"}',
    ]
    assert artifact.receipt.execution_time_ms == 12
    shape = {entry["path"]: entry for entry in artifact.metadata["observed_shape"]}
    assert shape["Id"]["present_count"] == 2


def test_expanded_incident_is_split_into_grep_friendly_records(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    incident = {
        "id": "123",
        "displayName": "large expanded incident",
        "alerts": [
            {
                "id": "alert-1",
                "title": "test",
                "evidence": [
                    {"entity": f"entity-{index}", "payload": "x" * 256}
                    for index in range(50)
                ],
            }
        ],
    }
    artifact = write_result(
        incident_records(incident),
        command="incidents show",
    )
    lines = Path(artifact.receipt.data_path).read_text().splitlines()
    assert len(lines) == 52
    matches = [line for line in lines if "entity-49" in line]
    assert len(matches) == 1
    assert len(matches[0].encode()) < 1024
    assert json.loads(matches[0])["record_type"] == "evidence"
