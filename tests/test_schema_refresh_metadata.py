"""Schema refresh merges the portal table listing without trusting it as queryable."""

import asyncio
import json
import re
from unittest.mock import patch

import pytest
import respx

from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import APIError, NotAuthenticatedError, PartialSuccessError
from xdr_cli.hunting_result import HuntingResult
from xdr_cli.hunting_tables import PROBE_TABLES, probe_table_names, render_schema_probe
from xdr_cli.schema_graph.physical import (
    merge_portal_rows,
    portal_schema_tables,
    probe_coverage,
)

PORTAL_TABLES = [
    {
        "Name": "DeviceInfo",
        "Description": "Machine information",
        "HasData": True,
        "Schema": [
            {"Name": "Timestamp", "Type": "DateTime", "Entity": None},
            {"Name": "DeviceId", "Type": "String", "Entity": "Machine"},
            {"Name": "PortalOnlyColumn", "Type": "Int64", "Entity": None},
        ],
    },
    {
        "Name": "BrandNewDefenderTable",
        "Description": "Shipped after the registry",
        "HasData": True,
        "Schema": [{"Name": "DeviceId", "Type": "String", "Entity": "Machine"}],
    },
    {"Name": "Bad Name; drop", "Schema": [{"Name": "x", "Type": "String"}]},
]


def test_render_rejects_unsafe_table_names():
    with pytest.raises(ValueError):
        render_schema_probe(["DeviceInfo", 'X") | evil'])
    assert probe_table_names(["Ok_Table", "not ok", 7]) == tuple(
        sorted({*PROBE_TABLES, "Ok_Table"})
    )


def test_dynamic_probe_keeps_the_recognized_coverage_grammar():
    names = probe_table_names(["BrandNewDefenderTable"])
    coverage = probe_coverage(render_schema_probe(names), [], "graph")
    assert coverage["scope_known"] is True
    assert "BrandNewDefenderTable" in coverage["probe_tables"]


def test_portal_listing_normalizes_types_and_drops_unsafe_names():
    tables = portal_schema_tables(PORTAL_TABLES)
    assert set(tables) == {"DeviceInfo", "BrandNewDefenderTable"}
    columns = {c["ColumnName"]: c for c in tables["DeviceInfo"]["Columns"]}
    assert columns["Timestamp"]["ColumnType"] == "datetime"
    assert columns["PortalOnlyColumn"]["ColumnType"] == "long"
    assert columns["DeviceId"]["Entity"] == "Machine"


def test_merge_never_caches_a_listed_but_unresolved_table():
    probed = [
        {"TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime"},
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": "long"},
        {"TableName": "AADSignInEventsBeta", "ColumnName": "Timestamp",
         "ColumnType": "datetime"},
    ]
    rows, facts = merge_portal_rows(probed, portal_schema_tables(PORTAL_TABLES))
    keys = {(row["TableName"], row["ColumnName"]): row for row in rows}
    assert ("BrandNewDefenderTable", "DeviceId") not in keys
    # A listed column getschema did not return is reported, never cached as queryable.
    assert ("DeviceInfo", "PortalOnlyColumn") not in keys
    assert facts["portal_only_columns"] == 1
    assert facts["portal_only_column_examples"] == ["DeviceInfo.PortalOnlyColumn"]
    assert keys[("DeviceInfo", "Timestamp")]["Sources"] == ["getschema", "portal-schema"]
    # getschema wins on type conflicts; the disagreement is recorded, value-free.
    assert keys[("DeviceInfo", "DeviceId")]["ColumnType"] == "long"
    assert facts["type_disagreements"] == 1
    assert facts["portal_only_tables"] == ["BrandNewDefenderTable"]
    assert facts["unlisted_getschema_tables"] == ["AADSignInEventsBeta"]


def test_merge_without_listing_returns_rows_unchanged():
    probed = [{"TableName": "DeviceInfo", "ColumnName": "Timestamp"}]
    assert merge_portal_rows(probed, {}) == (probed, {})


class _FakeClient:
    async def close(self):
        return None


class _FakePortal:
    def __init__(self, tables=None, error=None):
        self.tables, self.error = tables, error

    async def list_hunting_schema(self):
        if self.error:
            raise self.error
        return self.tables

    async def close(self):
        return None


def _refresh(config_dir, portal, *, metadata_source="auto", extra_tables=()):
    from xdr_cli.commands.schema_cmd import _active_cache_paths, _schema_refresh

    seen = {}

    async def fake_run_query(client, query):
        seen["query"] = query
        return HuntingResult(
            schema=[],
            results=[
                {"TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime"},
                {"TableName": "BrandNewDefenderTable", "ColumnName": "DeviceId",
                 "ColumnType": "string"},
            ],
            stats={},
            metadata={"execution_surface": "graph"},
        )

    emitted = []
    portal_factory = (
        portal if callable(portal) else (lambda *_args: portal)
    )
    with (
        patch("xdr_cli.commands.schema_cmd.AuthManager"),
        patch("xdr_cli.commands.schema_cmd.XDRClient", return_value=_FakeClient()),
        patch("xdr_cli.commands.schema_cmd.run_query", side_effect=fake_run_query),
        patch("xdr_cli.commands.schema_cmd.PortalBackend", side_effect=portal_factory),
    ):
        error = None
        try:
            asyncio.run(_schema_refresh(
                AppContext(config=Config(tenant_id="t1")),
                on_result=emitted.append,
                metadata_source=metadata_source,
                extra_tables=extra_tables,
            ))
        except PartialSuccessError as exc:
            error = exc
    data_path, meta_path = _active_cache_paths("t1")
    meta = json.loads(meta_path.read_text())
    return seen["query"], meta, data_path, emitted, error


def test_refresh_probes_portal_listed_tables_and_reports_new_ones(config_dir):
    query, meta, data_path, emitted, error = _refresh(
        config_dir, _FakePortal(PORTAL_TABLES)
    )
    assert error is None
    assert "(BrandNewDefenderTable | getschema" in query
    # Front-matter is `--` text, which is not KQL; the sent query must start at the union.
    assert query.startswith("union isfuzzy=true")
    coverage = meta["coverage"]
    assert coverage["metadata"]["status"] == "ok"
    assert coverage["new_tables"] == ["BrandNewDefenderTable"]
    assert coverage["probe_tables"] == list(probe_table_names(["BrandNewDefenderTable",
                                                               "DeviceInfo"]))
    sidecar = data_path.parent / meta["portal_schema"]["path"]
    assert json.loads(sidecar.read_text())["Tables"]["DeviceInfo"]["Description"]
    receipt_context = emitted[0].receipt.to_dict()["context"]["schema_coverage"]
    assert receipt_context["new_tables"] == 1
    assert receipt_context["listed_tables"] == 2


def test_reference_tables_are_not_reported_as_new(config_dir):
    _query, meta, *_ = _refresh(
        config_dir, _FakePortal(PORTAL_TABLES), extra_tables=("BrandNewDefenderTable",)
    )
    assert meta["coverage"]["new_tables"] == []


def test_auto_records_missing_cookies_without_failing(config_dir):
    def no_cookies(*_args):
        raise NotAuthenticatedError("no portal cookies")

    _query, meta, _data, _emitted, error = _refresh(config_dir, no_cookies)
    assert error is None
    assert meta["coverage"]["metadata"]["status"] == "unavailable"
    assert "portal_schema" not in meta


def test_probe_mode_never_constructs_the_portal(config_dir):
    def forbidden(*_args):
        raise AssertionError("portal constructed")

    query, meta, *_ = _refresh(config_dir, forbidden, metadata_source="probe")
    assert meta["coverage"]["metadata"]["status"] == "skipped"
    assert "BrandNewDefenderTable" not in query


def test_explicit_portal_failure_keeps_durable_cache_and_is_partial(config_dir):
    _query, meta, data_path, emitted, error = _refresh(
        config_dir, _FakePortal(error=APIError("boom")), metadata_source="portal"
    )
    assert isinstance(error, PartialSuccessError)
    assert error.exit_code == 14
    assert data_path.exists() and emitted
    assert meta["coverage"]["metadata"]["status"] == "failed"


@respx.mock
async def test_portal_backend_lists_hunting_schema():
    from xdr_cli.backends import PortalBackend

    origin = "https://security.microsoft.com"
    respx.get(origin + "/apiproxy/mtp/sccManagement/mgmt/TenantContext").respond(
        200, json={"AuthInfo": {"TenantId": "t1"}}
    )
    respx.get(origin + "/apiproxy/mtp/huntingService/schema").respond(
        200, json={"Tables": PORTAL_TABLES[:1]}
    )
    with patch(
        "xdr_cli.backends.load_portal_cookies",
        return_value={"sccauth": "a", "xsrf_token": "b"},
    ):
        backend = PortalBackend(Config(tenant_id="t1"), 5)
    try:
        assert (await backend.list_hunting_schema())[0]["Name"] == "DeviceInfo"
    finally:
        await backend.close()


@respx.mock
async def test_portal_backend_rejects_malformed_listing():
    from xdr_cli.backends import PortalBackend

    origin = "https://security.microsoft.com"
    respx.get(origin + "/apiproxy/mtp/sccManagement/mgmt/TenantContext").respond(
        200, json={"AuthInfo": {"TenantId": "t1"}}
    )
    respx.get(origin + "/apiproxy/mtp/huntingService/schema").respond(200, json={"x": 1})
    with patch(
        "xdr_cli.backends.load_portal_cookies",
        return_value={"sccauth": "a", "xsrf_token": "b"},
    ):
        backend = PortalBackend(Config(tenant_id="t1"), 5)
    try:
        with pytest.raises(APIError):
            await backend.list_hunting_schema()
    finally:
        await backend.close()


async def test_official_backend_has_no_schema_listing():
    from xdr_cli.official_backend import OfficialBackend

    with pytest.raises(UnsupportedBackendCapability):
        await OfficialBackend(transport=None).list_hunting_schema()


def test_portal_sidecar_requires_matching_digest(tmp_path):
    import hashlib

    from xdr_cli.schema_graph.physical import load_portal_sidecar

    raw = json.dumps({"Tables": {"DeviceInfo": {"Columns": []}}}).encode()
    (tmp_path / "schema.g1.portal.json").write_bytes(raw)
    meta = {"portal_schema": {"path": "schema.g1.portal.json",
                              "sha256": hashlib.sha256(raw).hexdigest()}}
    assert load_portal_sidecar(meta, tmp_path) == ({"DeviceInfo": {"Columns": []}}, None)
    (tmp_path / "schema.g1.portal.json").write_bytes(raw + b" ")
    assert load_portal_sidecar(meta, tmp_path) == (None, "digest-mismatch")
    assert load_portal_sidecar({}, tmp_path) == (None, "not-recorded")
    bad = {"portal_schema": {"path": "../escape.json", "sha256": "0" * 64}}
    assert load_portal_sidecar(bad, tmp_path) == (None, "invalid-binding")
    gone = {"portal_schema": {"path": "schema.g2.portal.json", "sha256": "0" * 64}}
    assert load_portal_sidecar(gone, tmp_path) == (None, "missing")


def test_identifier_candidates_are_name_hints_only():
    from xdr_cli.schema_graph.physical import identifier_column_candidates

    rows = [
        {"TableName": "BrandNew", "ColumnName": "DeviceId", "ColumnType": "string"},
        {"TableName": "BrandNew", "ColumnName": "Timestamp", "ColumnType": "datetime"},
        {"TableName": "BrandNew", "ColumnName": "AccountObjectId", "ColumnType": "datetime"},
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": "string"},
    ]
    families = {
        "defender-device": {("DeviceInfo", "DeviceId"), ("DeviceEvents", "DeviceId")},
        "entra-user": {("IdentityInfo", "AccountObjectId")},
    }
    found = identifier_column_candidates(rows, families, tables={"BrandNew"})
    assert [(c["table"], c["column"], c["family"]) for c in found] == [
        ("BrandNew", "DeviceId", "defender-device")
    ]
    assert found[0]["status"] == "candidate"
    assert found[0]["peer_endpoints"] == ["DeviceEvents.DeviceId", "DeviceInfo.DeviceId"]


def test_new_table_candidate_routes_target_present_reference_hubs():
    from types import SimpleNamespace

    from xdr_cli.schema_graph.physical import new_table_candidate_routes
    from xdr_cli.schema_graph.reference import ReferenceEndpoint, ReferenceRoute
    from xdr_cli.schema_graph.reference_query import compile_reference_query

    def endpoint(table, column, path=()):
        return ReferenceEndpoint(table, column, path, "Timestamp")

    def route(rid, family, source, target):
        return ReferenceRoute(rid, rid, family, source, target, "", {})

    snapshot = SimpleNamespace(routes=(
        route("a", "defender-device", endpoint("DeviceInfo", "DeviceId"),
              endpoint("DeviceEvents", "DeviceId")),
        route("b", "defender-device", endpoint("DeviceInfo", "DeviceId"),
              endpoint("AlertEvidence", "DeviceId")),
        route("c", "entra-user", endpoint("CloudAppEvents", "RawEventData", ("UserId",)),
              endpoint("IdentityInfo", "AccountObjectId")),
    ))
    rows = [
        {"TableName": t, "ColumnName": c, "ColumnType": k}
        for t, c, k in [
            ("DeviceInfo", "DeviceId", "string"), ("DeviceInfo", "Timestamp", "datetime"),
            ("DeviceEvents", "DeviceId", "string"), ("DeviceEvents", "Timestamp", "datetime"),
            ("NewTable", "DeviceId", "string"), ("NewTable", "Timestamp", "datetime"),
            ("NewTable", "UserId", "string"),
        ]
    ]
    routes = new_table_candidate_routes(rows, snapshot, ["NewTable"])
    # AlertEvidence is absent, nested endpoints never qualify, DeviceInfo is the busiest hub.
    assert {r.target.table for r in routes} == {"DeviceInfo", "DeviceEvents"}
    assert all(re.fullmatch(r"tenant-discovery-[0-9a-f]{16}", r.id) for r in routes)
    assert routes == new_table_candidate_routes(rows, snapshot, ["NewTable"])
    assert len(new_table_candidate_routes(rows, snapshot, ["NewTable"], max_routes=1)) == 1
    routes = sorted(routes, key=lambda r: r.target.table != "DeviceInfo")
    assert routes[0].record["origin"] == "tenant-new-table"
    assert routes[0].source.time_column == "Timestamp"
    compiled = compile_reference_query(routes[0], rows)
    assert "NewTable" in compiled.query and "DeviceInfo" in compiled.query


def test_portal_entity_tag_suggests_family_for_unfamiliar_column_name():
    from types import SimpleNamespace

    from xdr_cli.schema_graph.physical import new_table_candidate_routes
    from xdr_cli.schema_graph.reference import ReferenceEndpoint, ReferenceRoute

    hub = ReferenceEndpoint("DeviceInfo", "DeviceId", (), "Timestamp")
    spoke = ReferenceEndpoint("DeviceEvents", "DeviceId", (), "Timestamp")
    snapshot = SimpleNamespace(routes=(
        ReferenceRoute("a", "a", "defender-device", hub, spoke, "", {}),
    ))
    rows = [
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": "string"},
        {"TableName": "DeviceEvents", "ColumnName": "DeviceId", "ColumnType": "string"},
        {"TableName": "NewTable", "ColumnName": "HostKey", "ColumnType": "string"},
        {"TableName": "NewTable", "ColumnName": "Note", "ColumnType": "string"},
    ]
    portal = {"NewTable": {"Columns": [
        {"ColumnName": "HostKey", "Entity": "Machine"},
        {"ColumnName": "Note", "Entity": "Url"},
    ]}}
    routes = new_table_candidate_routes(rows, snapshot, ["NewTable"], portal_tables=portal)
    assert {(r.source.column, r.target.table) for r in routes} == {
        ("HostKey", "DeviceInfo"), ("HostKey", "DeviceEvents"),
    }
    assert all(r.record["evidence"] == "portal-entity-tag" for r in routes)
    assert new_table_candidate_routes(rows, snapshot, ["NewTable"]) == []


def test_legacy_metadata_only_rows_never_authorize_fields():
    from xdr_cli.schema_graph.physical import physical_field_rows, queryable_rows

    rows = [
        {"TableName": "DeviceInfo", "ColumnName": "DeviceId", "ColumnType": "string"},
        {"TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime",
         "Sources": ["getschema", "portal-schema"]},
        {"TableName": "DeviceInfo", "ColumnName": "Ghost", "ColumnType": "string",
         "Sources": ["portal-schema"]},
    ]
    assert [r["ColumnName"] for r in queryable_rows(rows)] == ["DeviceId", "Timestamp"]
    assert ("DeviceInfo", "Ghost") not in physical_field_rows(rows)


def test_load_cache_filters_metadata_only_rows_from_earlier_caches(config_dir):
    from xdr_cli.commands.schema_cmd import _active_cache_paths, _load_cache

    _refresh(config_dir, _FakePortal(PORTAL_TABLES))
    data_path, _meta_path = _active_cache_paths("t1")
    # Simulate a cache written by c6e44c1, which stored portal-only rows.
    ghost = {"TableName": "DeviceInfo", "ColumnName": "Ghost", "ColumnType": "string",
             "Sources": ["portal-schema"]}
    raw = data_path.read_text() + json.dumps(ghost, separators=(",", ":")) + "\n"
    _rewrite_cache(data_path, raw)
    rows, _cache = _load_cache(AppContext(config=Config(tenant_id="t1")))
    assert "Ghost" not in {row["ColumnName"] for row in rows}


def _rewrite_cache(data_path, raw: str) -> None:
    """Replace cache rows and rebind their digest, as an older writer would have."""

    import hashlib

    meta_path = data_path.with_name(data_path.name.replace(".jsonl", ".meta.json"))
    meta = json.loads(meta_path.read_text())
    data_path.write_text(raw, newline="\n")
    meta["data_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    meta["data_bytes"] = len(raw.encode())
    meta["row_count"] = len(raw.splitlines())
    meta_path.write_text(json.dumps(meta, separators=(",", ":")) + "\n")


def test_user_probe_override_is_honored_over_dynamic_rendering(config_dir):
    from xdr_cli.hunting_tables import render_schema_probe

    (config_dir / "queries" / "sys_schema_probe.kql").write_text(
        render_schema_probe(["DeviceInfo"]), encoding="utf-8"
    )
    query, meta, _data, emitted, _error = _refresh(config_dir, _FakePortal(PORTAL_TABLES))
    assert "(BrandNewDefenderTable | getschema" not in query
    assert meta["coverage"]["probe_tables"] == ["DeviceInfo"]


def test_dynamic_probe_does_not_claim_the_catalog_entry(config_dir):
    _query, _meta, _data, emitted, _error = _refresh(config_dir, _FakePortal(PORTAL_TABLES))
    metadata = emitted[0].metadata
    assert "library_entry" in metadata and metadata["library_entry"] is None
    assert "source_hash" in metadata and metadata["source_hash"] is None


def test_plain_refresh_uses_local_reference_names_for_new_tables(config_dir):
    from types import SimpleNamespace

    snapshot = SimpleNamespace(table_names=("BrandNewDefenderTable",))
    with patch("xdr_cli.schema_graph.reference.load_snapshot", return_value=snapshot):
        _query, meta, *_ = _refresh(config_dir, _FakePortal(PORTAL_TABLES))
    assert meta["coverage"]["new_tables"] == []


def test_leading_underscore_names_are_not_probe_names():
    assert "_Hidden" not in probe_table_names(["_Hidden"])
