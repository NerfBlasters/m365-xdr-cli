from __future__ import annotations

import json

from xdr_cli.results import write_result
from xdr_cli.schema_graph.artifact_metadata import nested_fields_from_artifact_metadata


def test_lossless_artifact_shape_becomes_nested_locator_without_values(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    secret = "user@example.invalid"
    artifact = write_result(
        [{"RawEventData": {"User.Id": secret, "Targets": [{"ObjectId": secret}]}}],
        command="hunt run",
    )
    fields = nested_fields_from_artifact_metadata("CloudAppEvents", artifact.metadata)
    locators = {str(item.locator): item for item in fields}
    assert "CloudAppEvents.RawEventData#/User.Id" in locators
    assert "CloudAppEvents.RawEventData#/Targets/*/ObjectId" in locators
    assert locators["CloudAppEvents.RawEventData#/User.Id"].lineage == "physical-shape"
    assert secret not in json.dumps(
        [
            {
                "locator": str(item.locator),
                "types": item.observed_types,
                "present": item.present_count,
            }
            for item in fields
        ]
    )


def test_passive_shape_rejects_keys_that_can_be_tenant_values(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / "xdr-home"))
    artifact = write_result(
        [
            {
                "RawEventData": {
                    "user@example.invalid": "value",
                    "abcdefab-cdef-abcd-efab-cdefabcdefab": "value",
                    "A" * 40: "value",
                    "opaque_token_value_that_is_long_enough_123": "value",
                    "contoso.com": "value",
                    "ProdServer": "value",
                    "a" * 1100: "value",
                    "UserId": "value",
                }
            }
        ],
        command="hunt run",
    )

    fields = nested_fields_from_artifact_metadata("CloudAppEvents", artifact.metadata)

    assert [str(item.locator) for item in fields] == [
        "CloudAppEvents.RawEventData#/UserId"
    ]


def test_legacy_dotted_shape_is_marked_ambiguous_and_unknown_columns_are_ignored():
    metadata = {
        "observed_shape": [
            {
                "path": "RawEventData.Targets[].Id",
                "types": ["string"],
                "present_count": 2,
                "non_null_count": 1,
            },
            {
                "path": "ProjectedAlias.UserId",
                "types": ["string"],
                "present_count": 1,
                "non_null_count": 1,
            },
        ]
    }
    fields = nested_fields_from_artifact_metadata("CloudAppEvents", metadata)
    assert [str(item.locator) for item in fields] == [
        "CloudAppEvents.RawEventData#/Targets/*/Id"
    ]
    assert fields[0].lineage == "legacy-shape-ambiguous"
