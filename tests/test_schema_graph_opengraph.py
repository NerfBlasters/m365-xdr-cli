from __future__ import annotations

import re

from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.opengraph import _safe_id, export_opengraph


def _assert_flat_properties(properties):
    assert all(key == key.lower() for key in properties)
    assert all(
        isinstance(value, (str, int, float, bool))
        or (
            isinstance(value, list)
            and all(isinstance(item, (str, int, float, bool)) for item in value)
        )
        for value in properties.values()
    )


def test_public_opengraph_export_is_deterministic_and_ingest_safe():
    graph = load_packaged_graph()
    first = export_opengraph(graph)
    second = export_opengraph(graph)
    assert first == second
    assert first["metadata"] == {"source_kind": "XDR_CLI"}
    assert first["graph"]["nodes"]
    assert first["graph"]["edges"]
    node_ids = {node["id"] for node in first["graph"]["nodes"]}
    assert len(node_ids) == len(first["graph"]["nodes"])
    for node in first["graph"]["nodes"]:
        assert ":" not in node["id"]
        assert re.fullmatch(r"[A-Za-z0-9._-]+", node["id"])
        assert 1 <= len(node["kinds"]) <= 3
        assert all(kind.startswith("XDR_") for kind in node["kinds"])
        _assert_flat_properties(node["properties"])
    for edge in first["graph"]["edges"]:
        assert re.fullmatch(r"[A-Za-z0-9_]+", edge["kind"])
        assert edge["start"]["match_by"] == edge["end"]["match_by"] == "id"
        assert edge["start"]["value"] in node_ids
        assert edge["end"]["value"] in node_ids
        _assert_flat_properties(edge["properties"])
    assert not any(
        edge["properties"].get("status") == "candidate"
        for edge in first["graph"]["edges"]
    )

    nodes_by_xdrid = {
        node["properties"]["xdrid"]: node for node in first["graph"]["nodes"]
    }
    assert (
        nodes_by_xdrid["table:DeviceInfo"]["id"]
        == "DeviceInfo_XDR_CLI_Table"
    )
    assert (
        nodes_by_xdrid["field:DeviceProcessEvents.DeviceId"]["id"]
        == "DeviceProcessEvents.DeviceId_XDR_CLI_Field"
    )
    assert (
        nodes_by_xdrid["entity-kind:device"]["id"]
        == "device_XDR_CLI_EntityKind"
    )
    assert (
        nodes_by_xdrid["namespace:mde-device-id"]["id"]
        == "mde-device-id_XDR_CLI_IdentifierNamespace"
    )


def test_opengraph_id_adds_collision_suffix_only_when_sanitization_is_needed():
    ordinary = _safe_id("field:DeviceEvents.DeviceId")
    nested = _safe_id("field:DeviceEvents.AdditionalFields#/Process/Id")

    assert ordinary == "DeviceEvents.DeviceId_XDR_CLI_Field"
    assert nested.startswith(
        "DeviceEvents.AdditionalFields_Process_Id_XDR_CLI_Field_"
    )
    assert re.fullmatch(r"[A-Za-z0-9._-]+", nested)
    assert len(nested.rsplit("_", 1)[1]) == 16


def test_candidates_are_explicitly_opt_in():
    payload = export_opengraph(load_packaged_graph(), include_candidates=True)
    assert any(
        edge["properties"].get("status") == "candidate"
        for edge in payload["graph"]["edges"]
    )
