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


TABLE_EDGE_KINDS = {"Join", "NormalizeJoin", "SameEntity", "Correlate", "Bridge"}


def _table_edges(payload):
    return [edge for edge in payload["graph"]["edges"] if edge["kind"] in TABLE_EDGE_KINDS]


def _table_of(node_id):
    assert node_id.endswith("_XDR_CLI_Table")
    return node_id.removesuffix("_XDR_CLI_Table")


def _edges_between(payload, start, end, kind):
    return [
        edge
        for edge in _table_edges(payload)
        if edge["kind"] == kind
        and _table_of(edge["start"]["value"]) == start
        and _table_of(edge["end"]["value"]) == end
    ]


def test_table_edge_kinds_cover_every_relationship_kind_with_plain_words():
    from xdr_cli.schema_graph.model import RelationshipKind
    from xdr_cli.schema_graph.opengraph import _TABLE_EDGE_KINDS

    assert set(_TABLE_EDGE_KINDS) == set(RelationshipKind)
    assert set(_TABLE_EDGE_KINDS.values()) == TABLE_EDGE_KINDS


def test_table_edges_summarize_field_relationships_between_tables():
    payload = export_opengraph(load_packaged_graph())
    table_ids = {
        node["id"] for node in payload["graph"]["nodes"] if node["kinds"] == ["XDR_Table"]
    }

    join = _edges_between(payload, "DeviceInfo", "DeviceProcessEvents", "Join")
    assert len(join) == 1
    assert join[0]["properties"]["keys"] == [
        "DeviceInfo.DeviceId=DeviceProcessEvents.DeviceId"
    ]
    assert join[0]["properties"]["count"] == 1
    assert join[0]["properties"]["join_safe"] is True
    assert join[0]["properties"]["status"] == "reviewed"
    assert join[0]["properties"]["evidencelevel"] == "reviewed"
    assert join[0]["properties"]["direction"] == "both"
    assert join[0]["properties"]["traversable"] is True
    assert len(join[0]["properties"]["relationshipids"]) == 1

    same = _edges_between(payload, "DeviceInfo", "DeviceProcessEvents", "SameEntity")
    assert len(same) == 1
    assert same[0]["properties"]["keys"] == [
        "DeviceInfo.DeviceName=DeviceProcessEvents.DeviceName"
    ]
    assert same[0]["properties"]["join_safe"] is False

    merged = _edges_between(payload, "CloudAppEvents", "EntraIdSignInEvents", "Correlate")
    assert len(merged) == 1
    assert merged[0]["properties"]["count"] == 2
    assert merged[0]["properties"]["keys"] == sorted(merged[0]["properties"]["keys"])

    seen = set()
    for edge in _table_edges(payload):
        assert edge["start"]["value"] in table_ids
        assert edge["end"]["value"] in table_ids
        assert edge["start"]["value"] != edge["end"]["value"]
        key = (edge["start"]["value"], edge["end"]["value"], edge["kind"])
        assert key not in seen
        seen.add(key)
    assert len(seen) == 25


def test_table_edges_match_exported_field_relationships():
    graph = load_packaged_graph()
    payload = export_opengraph(graph)
    expected = set()
    for relationship in graph.relationships.values():
        if relationship.status.value in {"candidate", "deprecated"}:
            continue
        tables = sorted(
            graph.fields[graph.interpretations[endpoint].field_id].locator.table
            for endpoint in (relationship.source, relationship.target)
        )
        expected.add((tables[0], tables[1], relationship.relationship.value))
    kinds = {
        "join-compatible": "Join",
        "transform-required": "NormalizeJoin",
        "semantic-equivalent": "SameEntity",
        "correlation-only": "Correlate",
        "bridge": "Bridge",
    }
    actual = {
        (_table_of(edge["start"]["value"]), _table_of(edge["end"]["value"]), edge["kind"])
        for edge in _table_edges(payload)
    }
    assert actual == {(a, b, kinds[kind]) for a, b, kind in expected}


def test_candidate_table_edges_are_opt_in():
    default = export_opengraph(load_packaged_graph())
    assert not any(
        edge["properties"]["status"] == "candidate" for edge in _table_edges(default)
    )
    assert not _edges_between(default, "CloudAppEvents", "IdentityInfo", "SameEntity")

    with_candidates = export_opengraph(load_packaged_graph(), include_candidates=True)
    candidate = _edges_between(with_candidates, "CloudAppEvents", "IdentityInfo", "SameEntity")
    assert len(candidate) == 1
    assert candidate[0]["properties"]["status"] == "candidate"
    assert candidate[0]["properties"]["traversable"] is False


def test_directed_relationships_orient_table_edges():
    from dataclasses import replace

    from xdr_cli.schema_graph.model import Direction, Graph, relationship_id

    graph = load_packaged_graph()

    def table(interpretation_id):
        return graph.fields[graph.interpretations[interpretation_id].field_id].locator.table

    def find(left, right, kind):
        for relationship in graph.relationships.values():
            if (
                {table(relationship.source), table(relationship.target)} == {left, right}
                and relationship.relationship.value == kind
            ):
                return relationship
        raise AssertionError(f"missing {left}/{right}/{kind}")

    def redirect(relationship, source, target, direction):
        return replace(
            relationship,
            source=source,
            target=target,
            direction=direction,
            id=relationship_id(
                source, target, relationship.relationship, direction, relationship.transform
            ),
        )

    to_forward = find("DeviceInfo", "DeviceProcessEvents", "join-compatible")
    to_reverse = find("DeviceInfo", "DeviceNetworkEvents", "join-compatible")
    process_side = next(
        endpoint
        for endpoint in (to_forward.source, to_forward.target)
        if table(endpoint) == "DeviceProcessEvents"
    )
    info_side = next(
        endpoint
        for endpoint in (to_forward.source, to_forward.target)
        if table(endpoint) == "DeviceInfo"
    )
    forward = redirect(to_forward, process_side, info_side, Direction.FORWARD)
    reverse = redirect(to_reverse, to_reverse.source, to_reverse.target, Direction.REVERSE)
    reverse_start = table(reverse.target)
    reverse_end = table(reverse.source)

    relationships = {
        key: value
        for key, value in graph.relationships.items()
        if key not in {to_forward.id, to_reverse.id}
    }
    relationships[forward.id] = forward
    relationships[reverse.id] = reverse
    directed = Graph(
        fields=dict(graph.fields),
        interpretations=dict(graph.interpretations),
        relationships=relationships,
    )
    payload = export_opengraph(directed)

    forward_edges = _edges_between(payload, "DeviceProcessEvents", "DeviceInfo", "Join")
    assert len(forward_edges) == 1
    assert forward_edges[0]["properties"]["direction"] == "forward"
    assert not _edges_between(payload, "DeviceInfo", "DeviceProcessEvents", "Join")

    reverse_edges = _edges_between(payload, reverse_start, reverse_end, "Join")
    assert len(reverse_edges) == 1
    assert reverse_edges[0]["properties"]["direction"] == "forward"


def test_nodes_carry_short_names_for_bloodhound_labels():
    payload = export_opengraph(load_packaged_graph())
    by_xdrid = {node["properties"]["xdrid"]: node for node in payload["graph"]["nodes"]}

    assert by_xdrid["table:DeviceInfo"]["properties"]["name"] == "DeviceInfo"
    assert by_xdrid["field:DeviceProcessEvents.DeviceId"]["properties"]["name"] == "DeviceId"
    assert by_xdrid["entity-kind:device"]["properties"]["name"] == "device"
    assert by_xdrid["namespace:mde-device-id"]["properties"]["name"] == "mde-device-id"
    assert (
        by_xdrid["field:CloudAppEvents.RawEventData#/ClientIP"]["properties"]["name"]
        == "RawEventData.ClientIP"
    )
    assert (
        by_xdrid["field:DeviceProcessEvents.DeviceId"]["properties"]["displayname"]
        == "DeviceProcessEvents.DeviceId"
    )
    assert by_xdrid["table:DeviceInfo"]["properties"]["displayname"] == "DeviceInfo"


def test_table_summary_does_not_promote_candidate_evidence():
    from dataclasses import replace

    from xdr_cli.schema_graph.model import Confidence, RelationshipStatus

    graph = load_packaged_graph()
    routes = [
        record for record in graph.relationships.values()
        if record.relationship.value == "correlation-only"
        and {
            graph.fields[graph.interpretations[endpoint].field_id].locator.table
            for endpoint in (record.source, record.target)
        } == {"CloudAppEvents", "EntraIdSignInEvents"}
    ]
    assert len(routes) == 2
    graph.relationships[routes[0].id] = replace(
        routes[0], status=RelationshipStatus.REVIEWED, confidence=Confidence.LOW
    )
    graph.relationships[routes[1].id] = replace(
        routes[1], status=RelationshipStatus.CANDIDATE, confidence=Confidence.MEDIUM
    )
    edge = _edges_between(
        export_opengraph(graph, include_candidates=True),
        "CloudAppEvents", "EntraIdSignInEvents", "Correlate",
    )[0]["properties"]
    assert edge["status"] == edge["evidencelevel"] == "candidate"
    assert edge["confidence"] == "low"
    assert edge["statuses"] == ["candidate", "reviewed"]
    assert edge["confidences"] == ["low", "medium"]
    assert edge["candidatecount"] == 1
    assert edge["traversable"] is False
    assert edge["count"] == 2
    default = _edges_between(
        export_opengraph(graph), "CloudAppEvents", "EntraIdSignInEvents", "Correlate"
    )[0]["properties"]
    assert default["status"] == "reviewed"
    assert default["confidence"] == "low"
    assert default["candidatecount"] == 0
    assert default["traversable"] is True
    assert default["count"] == 1


def test_overlapping_directions_have_one_table_edge_without_losing_members():
    from dataclasses import replace

    from xdr_cli.schema_graph.model import Direction, relationship_id

    graph = load_packaged_graph()
    original = next(
        record for record in graph.relationships.values()
        if record.relationship.value == "join-compatible"
        and {
            graph.fields[graph.interpretations[endpoint].field_id].locator.table
            for endpoint in (record.source, record.target)
        } == {"DeviceInfo", "DeviceProcessEvents"}
    )
    source, target = sorted(
        (original.source, original.target),
        key=lambda endpoint: graph.fields[graph.interpretations[endpoint].field_id].locator.table,
    )
    directed = replace(
        original, source=source, target=target, direction=Direction.FORWARD,
        id=relationship_id(
            source, target, original.relationship, Direction.FORWARD, original.transform
        ),
    )
    graph.add(directed)
    graph.validate_references()
    edges = _edges_between(export_opengraph(graph), "DeviceInfo", "DeviceProcessEvents", "Join")
    assert len(edges) == 1
    props = edges[0]["properties"]
    assert props["direction"] == "mixed"
    assert props["directions"] == ["both", "forward"]
    assert props["relationshipids"] == sorted([original.id, directed.id])
    assert props["count"] == 2
    first = export_opengraph(graph)
    graph.relationships = dict(reversed(list(graph.relationships.items())))
    assert export_opengraph(graph) == first


def test_bloodhound_custom_nodes_style_every_exported_node_kind():
    from xdr_cli.schema_graph.opengraph import bloodhound_custom_nodes

    payload = export_opengraph(load_packaged_graph(), include_candidates=True)
    exported_kinds = {kind for node in payload["graph"]["nodes"] for kind in node["kinds"]}
    styles = bloodhound_custom_nodes()

    assert styles == bloodhound_custom_nodes()
    assert set(styles) == {"custom_types"}
    assert set(styles["custom_types"]) == exported_kinds
    colors = set()
    for config in styles["custom_types"].values():
        icon = config["icon"]
        assert icon["type"] == "font-awesome"
        assert icon["name"] in {"table", "table-columns", "fingerprint", "key"}
        assert re.fullmatch(r"#[0-9A-Fa-f]{6}", icon["color"])
        colors.add(icon["color"].lower())
    assert len(colors) == len(styles["custom_types"])
