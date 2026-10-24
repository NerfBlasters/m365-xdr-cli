"""Provider input, immutable snapshot and content-provenance boundaries."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from xdr_cli.schema_graph.reference import (
    REFERENCE_URLS,
    ReferenceEndpoint,
    ReferenceError,
    load_snapshot,
    parse_snapshot,
    publish_snapshot,
    reference_root,
    sync_reference,
)


@pytest.fixture
def reference_documents():
    data = {
        "schema": [
            {"Name": name, "Schema": [
                {"Name": "Id", "Type": "String"},
                {"Name": "Data", "Type": "Object"},
                {"Name": "Timestamp", "Type": "DateTime"},
            ]} for name in ("Events", "Profiles")
        ],
        "relations": {"version": 1, "relations": [{
            "id": "event-actor", "title": "Actor profile", "family": "entra-user",
            "from": {"table": "Events", "column": "Id", "timeColumn": "Timestamp"},
            "to": {"table": "Profiles", "column": "Data", "path": "[].id",
                   "timeColumn": "Timestamp"},
            "guidance": "Preserve actor and tenant context.",
        }]},
        "structured": {"version": 1, "entries": []},
        "actions": [],
    }
    return {name: json.dumps(value).encode() for name, value in data.items()}


def test_reference_parser_keeps_case_and_arrays_without_executing_example_kql(reference_documents):
    snapshot = parse_snapshot(reference_documents)
    assert snapshot.table_names == ("Events", "Profiles")
    route = snapshot.routes[0]
    assert str(route.target.locator) == "Profiles.Data#/*/id"
    assert route.source.time_column == "Timestamp"
    assert route.guidance == "Preserve actor and tenant context."


@pytest.mark.parametrize("endpoint", [
    {"table": "T | take 1", "column": "Id"},
    {"table": "T", "column": "Id", "path": "X; print p=1"},
    {"table": "T", "column": "Id", "path": "[][key=Token]"},
    {"table": "T", "column": "Id", "timeColumn": "Timestamp | take 1"},
])
def test_endpoint_identifiers_and_path_grammar_are_closed(endpoint):
    with pytest.raises(ReferenceError):
        ReferenceEndpoint.parse(endpoint)


def test_duplicate_routes_and_unknown_format_do_not_replace_valid_snapshot(
    tmp_path, reference_documents,
):
    first = publish_snapshot(tmp_path, reference_documents)
    broken = dict(reference_documents)
    relations = json.loads(broken["relations"])
    relations["relations"] *= 2
    broken["relations"] = json.dumps(relations).encode()
    with pytest.raises(ReferenceError, match="unique"):
        publish_snapshot(tmp_path, broken)
    assert load_snapshot(tmp_path).generation == first.generation
    relations["version"] = 2
    broken["relations"] = json.dumps(relations).encode()
    with pytest.raises(ReferenceError, match="format"):
        parse_snapshot(broken)


def test_saved_snapshot_pins_exact_bytes_and_metadata_cannot_override_hash(
    tmp_path, reference_documents,
):
    first = publish_snapshot(tmp_path, reference_documents, origins={
        "schema": {"sha256": "forged", "url": "https://elsewhere.invalid"},
    })
    loaded = load_snapshot(tmp_path)
    assert loaded.digest == first.digest
    assert loaded.metadata["documents"]["schema"]["url"] == REFERENCE_URLS["schema"]
    directory = reference_root(tmp_path) / first.generation
    (directory / "schema.json").write_text("[]")
    with pytest.raises(ReferenceError, match="verification"):
        load_snapshot(tmp_path)


def test_reference_manifest_cannot_escape_its_root(tmp_path, reference_documents):
    publish_snapshot(tmp_path, reference_documents)
    (reference_root(tmp_path) / "current.json").write_text('{"generation":"../other"}')
    with pytest.raises(ReferenceError, match="generation"):
        load_snapshot(tmp_path)


@respx.mock
def test_sync_uses_only_public_urls_and_publishes_complete_snapshot(tmp_path, reference_documents):
    for name, url in REFERENCE_URLS.items():
        respx.get(url).respond(200, content=reference_documents[name], headers={"etag": name})
    with httpx.Client() as client:
        snapshot = sync_reference(tmp_path, client=client)
    assert len(snapshot.routes) == 1
    assert load_snapshot(tmp_path).digest == snapshot.digest
    assert all("authorization" not in call.request.headers for call in respx.calls)


@respx.mock
def test_partial_provider_download_keeps_previous_generation(tmp_path, reference_documents):
    original = publish_snapshot(tmp_path, reference_documents)
    for name, url in REFERENCE_URLS.items():
        respx.get(url).respond(503 if name == "actions" else 200,
                              content=reference_documents[name])
    with httpx.Client() as client, pytest.raises(httpx.HTTPStatusError):
        sync_reference(tmp_path, client=client)
    assert load_snapshot(tmp_path).generation == original.generation


def _reference_schema_rows():
    return [{"TableName": t, "ColumnName": c, "ColumnType": k, "ColumnOrdinal": n}
            for t in ("Events", "Profiles")
            for n, (c, k) in enumerate((("Id", "string"), ("Data", "dynamic"),
                                        ("Timestamp", "datetime")))]


def test_trusted_reference_is_not_reviewed_and_missing_tenant_tables_are_reported(
    reference_documents,
):
    from xdr_cli.schema_graph.effective import compose_effective_graph
    from xdr_cli.schema_graph.model import Graph, RelationshipStatus
    from xdr_cli.schema_graph.reference_routes import compose_reference_routes, reference_catalog

    snapshot = parse_snapshot(reference_documents)
    rows = _reference_schema_rows()
    effective = compose_effective_graph(rows, canonical=Graph())
    combined = compose_reference_routes(effective, snapshot, rows)
    assert len(combined.graph.relationships) == 1
    relation = next(iter(combined.graph.relationships.values()))
    assert relation.status is RelationshipStatus.REFERENCE_TRUSTED
    assert relation.extra["reference_routes"][0]["validation"] == "pending"
    assert reference_catalog(snapshot, [])[0]["TenantUsable"] is False
    states = {"event-actor": {"status": "no-overlap"}}
    assert reference_catalog(snapshot, rows, states)[0]["TenantUsable"] is True
    states["event-actor"]["status"] = "query-failed"
    assert reference_catalog(snapshot, rows, states)[0]["TenantUsable"] is False


@pytest.mark.asyncio
async def test_reference_validation_resumes_and_verifies_private_count_evidence(
    tmp_path, monkeypatch, reference_documents,
):
    from xdr_cli.hunting_result import HuntingResult
    from xdr_cli.schema_graph.reference_state import verify_validation_record
    from xdr_cli.schema_graph.reference_validation import validate_reference

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    snapshot = parse_snapshot(reference_documents)

    class Client:
        calls = 0

        async def execute_hunting(self, query):
            self.calls += 1
            assert "take 1000" in query
            return HuntingResult([], [{"RouteId": "event-actor", "SourceValues": 2,
                                       "TargetValues": 3, "MatchedSourceValues": 1,
                                       "MatchRows": 1}], {})

    client = Client()
    options = dict(home=tmp_path, tenant_id="tenant-test")
    first = await validate_reference(client, snapshot, _reference_schema_rows(), **options)
    record = first["routes"]["event-actor"]
    assert record["status"] == "matched"
    assert verify_validation_record(tmp_path, "tenant-test", "event-actor", record)
    assert not verify_validation_record(tmp_path, "other-tenant", "event-actor", record)
    second = await validate_reference(client, snapshot, _reference_schema_rows(), **options)
    assert second["reused"] == 1 and client.calls == 1
    path = next((tmp_path / "results").glob("*/*.jsonl"))
    path.write_text('{"RouteId":"event-actor"}\n')
    third = await validate_reference(client, snapshot, _reference_schema_rows(), **options)
    assert third["queries"] == 1 and client.calls == 2


@pytest.mark.parametrize("source,target,matched,status", [
    (0, 1, 0, "no-source-data"), (1, 0, 0, "no-target-data"),
    (1, 1, 0, "no-overlap"), (1, 1, 1, "matched"),
])
def test_no_data_is_inconclusive(source, target, matched, status):
    from xdr_cli.schema_graph.reference_validation import classify_counts

    assert classify_counts({"RouteId": "x", "SourceValues": source, "TargetValues": target,
                            "MatchedSourceValues": matched, "MatchRows": matched}, "x") == status


@pytest.mark.asyncio
async def test_reference_budget_resume_preserves_completed_scope_and_pacing(
    tmp_path, monkeypatch, reference_documents,
):
    from dataclasses import replace

    from xdr_cli.hunting_result import HuntingResult
    from xdr_cli.schema_graph.reference_validation import validate_reference

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    snapshot = parse_snapshot(reference_documents)
    route = replace(snapshot.routes[0], id="second-route")
    snapshot = replace(snapshot, routes=(*snapshot.routes, route))

    class Client:
        calls = []

        async def execute_hunting(self, query):
            name = "second-route" if "second-route" in query else "event-actor"
            self.calls.append(name)
            return HuntingResult([], [{"RouteId": name, "SourceValues": 0, "TargetValues": 0,
                                       "MatchedSourceValues": 0, "MatchRows": 0,
                                       "ScanCapped": False}], {})

    client = Client()
    options = dict(home=tmp_path, tenant_id="test", max_queries=1, min_interval_seconds=0)
    first = await validate_reference(client, snapshot, _reference_schema_rows(), **options)
    assert first["pending"] == 1 and first["queries"] == 1
    second = await validate_reference(client, snapshot, _reference_schema_rows(), **options)
    assert second["pending"] == 0 and second["reused"] == 1
    assert client.calls == ["event-actor", "second-route"]


@pytest.mark.asyncio
async def test_rate_limit_stops_new_queries_and_keeps_saved_progress(
    tmp_path, monkeypatch, reference_documents,
):
    from xdr_cli.exceptions import RateLimitError
    from xdr_cli.schema_graph.reference_validation import validate_reference

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))

    class Client:
        async def execute_hunting(self, query):
            raise RateLimitError(19)

    report = await validate_reference(
        Client(), parse_snapshot(reference_documents), _reference_schema_rows(),
        home=tmp_path, tenant_id="test",
    )
    assert report["pending"] == 1
    assert report["stopped"]["retry_after_seconds"] == 19
    assert report["queries"] == 1


@pytest.mark.asyncio
async def test_plan_only_initialization_has_no_network_or_ledger_publication(
    tmp_path, monkeypatch, reference_documents, capsys,
):
    from types import SimpleNamespace

    from xdr_cli.commands import schema_cmd, schema_init_cmd

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    publish_snapshot(tmp_path, reference_documents)
    monkeypatch.setattr(schema_cmd, "_load_cache", lambda ctx: (_reference_schema_rows(), {}))
    monkeypatch.setattr(schema_init_cmd, "create_client", lambda *a, **kw: pytest.fail("network"))
    ctx = SimpleNamespace(config=SimpleNamespace(tenant_id="test"), effective_quiet=True)
    await schema_init_cmd._initialize(ctx, plan_only=True)
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert output[0]["status"] == "success"
    assert output[0]["context"]["validation_states"] == {"planned": 1}
    assert not list((tmp_path / "schema").glob("*/reference-validation/current.json"))


@pytest.mark.asyncio
async def test_initializer_matches_reach_normal_graph_and_pruned_evidence_is_scoped(
    tmp_path, monkeypatch, reference_documents, capsys,
):
    from types import SimpleNamespace

    from xdr_cli.commands import schema_cmd, schema_init_cmd
    from xdr_cli.hunting_result import HuntingResult
    from xdr_cli.schema_graph.model import Graph

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    publish_snapshot(tmp_path, reference_documents)
    rows = _reference_schema_rows()
    monkeypatch.setattr(schema_cmd, "_load_cache", lambda ctx: (rows, {}))

    class Client:
        closed = False

        async def execute_hunting(self, query):
            return HuntingResult([], [{"RouteId": "event-actor", "SourceValues": 5,
                                       "TargetValues": 10, "MatchedSourceValues": 3,
                                       "MatchRows": 3, "ScanCapped": 0}], {})

        async def close(self):
            self.closed = True

    client = Client()
    monkeypatch.setattr(schema_init_cmd, "create_client", lambda *a, **kw: client)
    ctx = SimpleNamespace(config=SimpleNamespace(tenant_id="test", api_timeout=30),
                          effective_quiet=True)
    await schema_init_cmd._initialize(ctx, skip_refresh=True)
    assert client.closed
    assert json.loads(capsys.readouterr().out.splitlines()[0])["context"]["queries"] == 1
    options = dict(tenant_id="test", canonical=Graph(), overlays=(), observations=())
    effective = schema_cmd._compose_effective(rows, **options)
    relation = next(iter(effective.graph.relationships.values()))
    assert relation.extra["reference_routes"][0]["validation"] == "matched"
    from xdr_cli.schema_graph.traversal import pivot

    steps = pivot(effective.graph, "Events.Id")
    row = schema_cmd._semantic_step_row(steps[0], 1)
    assert row["TenantMatched"] is True
    assert row["EmpiricallyValidated"] is False
    assert row["SemanticallyReviewed"] is False
    for meta in (tmp_path / "results").glob("*/*.meta.json"):
        if json.loads(meta.read_text())["command"] == "schema init validation":
            meta.unlink()
    # Pruning one result does not break all semantic commands or retain its match claim.
    assert not schema_cmd._compose_effective(rows, **options).graph.relationships


@pytest.mark.asyncio
async def test_init_invalid_lookback_fails_before_loading_or_changing_reference(monkeypatch):
    from types import SimpleNamespace

    from xdr_cli.commands import schema_init_cmd
    from xdr_cli.exceptions import UsageError

    monkeypatch.setattr(schema_init_cmd, "load_snapshot", lambda *a: pytest.fail("loaded cache"))
    with pytest.raises(UsageError):
        await schema_init_cmd._initialize(SimpleNamespace(), lookback="bad")


@pytest.mark.parametrize("matches,expected", [(0, "candidate"), (1, "candidate"), (3, "observed")])
def test_new_table_routes_need_empirical_overlap_and_never_inherit_reference_trust(
    reference_documents, matches, expected,
):
    from dataclasses import replace

    from xdr_cli.schema_graph.effective import compose_effective_graph
    from xdr_cli.schema_graph.model import Graph
    from xdr_cli.schema_graph.reference_routes import (
        compose_reference_routes,
        reference_catalog,
        tenant_candidate_routes,
    )

    snapshot = parse_snapshot(reference_documents)
    rows = [*_reference_schema_rows(),
            {"TableName": "BrandNewEvents", "ColumnName": "Id", "ColumnType": "string"},
            {"TableName": "BrandNewEvents", "ColumnName": "Timestamp", "ColumnType": "datetime"}]
    candidates, gaps = tenant_candidate_routes(snapshot, rows)
    assert len(candidates) == 1 and gaps["new_tables"] == ["BrandNewEvents"]
    assert not gaps["unmapped_new_tables"]
    candidate_snapshot = replace(snapshot, routes=candidates)
    state = {candidates[0].id: {"status": "matched" if matches else "no-overlap",
                              "counts": {"MatchedSourceValues": matches}}}
    catalog = reference_catalog(candidate_snapshot, rows, state)
    assert catalog[0]["ReferenceTrusted"] is False
    effective = compose_reference_routes(
        compose_effective_graph(rows, canonical=Graph()), candidate_snapshot, rows, states=state,
    )
    relation = next(iter(effective.graph.relationships.values()))
    assert relation.status.value == expected
    assert "reference_routes" not in relation.extra
    assert relation.extra["tenant_discoveries"][0]["counts"]["MatchedSourceValues"] == matches
    assert relation.relationship.value == "correlation-only"


def test_physical_comparison_uses_tenant_types_and_preserves_unseen_tables(reference_documents):
    from xdr_cli.schema_graph.reference_routes import compare_physical_schema

    rows = [{"TableName": "Events", "ColumnName": "Id", "ColumnType": "guid"},
            {"TableName": "Events", "ColumnName": "NewColumn", "ColumnType": "string"}]
    comparison = compare_physical_schema(parse_snapshot(reference_documents), rows)
    events = next(row for row in comparison if row["TableName"] == "Events")
    assert events["TenantOnlyColumns"] == ["NewColumn"]
    assert events["TypeDisagreements"] == [
        {"Column": "Id", "TenantType": "guid", "ReferenceType": "string"}
    ]
    profiles = next(row for row in comparison if row["TableName"] == "Profiles")
    assert profiles["TenantObserved"] is False
    assert profiles["AbsenceIsConclusive"] is False


@pytest.mark.asyncio
async def test_validation_evidence_binds_outcome_and_conditions(
    tmp_path, monkeypatch, reference_documents,
):
    from xdr_cli.hunting_result import HuntingResult
    from xdr_cli.schema_graph.reference_state import verify_validation_record
    from xdr_cli.schema_graph.reference_validation import validate_reference

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))

    class Client:
        async def execute_hunting(self, query):
            return HuntingResult([], [{"RouteId": "event-actor", "SourceValues": 1,
                                       "TargetValues": 1, "MatchedSourceValues": 0,
                                       "MatchRows": 0}], {})

    report = await validate_reference(
        Client(), parse_snapshot(reference_documents), _reference_schema_rows(),
        home=tmp_path, tenant_id="test",
    )
    record = report["routes"]["event-actor"]
    assert verify_validation_record(tmp_path, "test", "event-actor", record)
    assert not verify_validation_record(
        tmp_path, "test", "event-actor", {**record, "status": "matched"},
    )
    assert not verify_validation_record(
        tmp_path, "test", "event-actor", {**record, "validation_scope": {}},
    )


@pytest.mark.parametrize("manifest", [[], None, 1])
def test_invalid_manifest_shape_reports_reference_error(tmp_path, reference_documents, manifest):
    snapshot = publish_snapshot(tmp_path, reference_documents)
    path = reference_root(tmp_path) / snapshot.generation / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ReferenceError):
        load_snapshot(tmp_path)


def test_email_reference_reuses_existing_reviewed_meaning_without_duplicate_namespace(
    reference_documents,
):
    from xdr_cli.schema_graph.effective import compose_effective_graph
    from xdr_cli.schema_graph.loader import load_packaged_graph
    from xdr_cli.schema_graph.reference_routes import compose_reference_routes

    documents = dict(reference_documents)
    schema = json.loads(documents["schema"])
    for table, name in zip(schema, ("EmailEvents", "EmailUrlInfo"), strict=True):
        table["Name"] = name
        table["Schema"][0]["Name"] = "NetworkMessageId"
    documents["schema"] = json.dumps(schema).encode()
    relations = json.loads(documents["relations"])
    route = relations["relations"][0]
    route["family"] = "email-message"
    route["from"].update(table="EmailEvents", column="NetworkMessageId")
    route["to"].update(table="EmailUrlInfo", column="NetworkMessageId")
    route["to"].pop("path")
    documents["relations"] = json.dumps(relations).encode()
    snapshot = parse_snapshot(documents)
    rows = [{"TableName": t, "ColumnName": "NetworkMessageId", "ColumnType": "string"}
            for t in ("EmailEvents", "EmailUrlInfo")]
    core = load_packaged_graph()
    effective = compose_reference_routes(compose_effective_graph(rows, canonical=core),
                                         snapshot, rows)
    assert len(effective.graph.relationships) == len(core.relationships)
    for table in ("EmailEvents", "EmailUrlInfo"):
        locator = table + ".NetworkMessageId"
        meanings = [i for i in effective.graph.interpretations.values()
                    if str(effective.graph.fields[i.field_id].locator) == locator]
        assert len(meanings) == 1
        assert meanings[0].namespace == "network-message-id"
        assert meanings[0].normalizer == "identity"
    assert any(info["id"] == "event-actor" for r in effective.graph.relationships.values()
               for info in r.extra.get("reference_routes", []))


@pytest.mark.asyncio
async def test_failed_compiled_check_retries_without_revalidating_successful_routes(
    tmp_path, monkeypatch, reference_documents,
):
    from xdr_cli.exceptions import QueryError
    from xdr_cli.hunting_result import HuntingResult
    from xdr_cli.schema_graph.reference_validation import validate_reference

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))

    class Client:
        calls = 0

        async def execute_hunting(self, query):
            self.calls += 1
            if self.calls == 1:
                raise QueryError("compiled check failed")
            return HuntingResult([], [{"RouteId": "event-actor", "SourceValues": 0,
                                       "TargetValues": 0, "MatchedSourceValues": 0,
                                       "MatchRows": 0}], {})

    client = Client()
    kwargs = dict(home=tmp_path, tenant_id="test")
    snapshot = parse_snapshot(reference_documents)
    first = await validate_reference(client, snapshot, _reference_schema_rows(), **kwargs)
    assert first["routes"]["event-actor"]["status"] == "query-failed"
    second = await validate_reference(client, snapshot, _reference_schema_rows(), **kwargs)
    assert second["queries"] == 1 and second["routes"]["event-actor"]["status"] == "no-source-data"


@pytest.mark.asyncio
async def test_reference_http_failure_is_typed_before_tenant_activity(monkeypatch):
    from types import SimpleNamespace

    from xdr_cli.commands import schema_init_cmd
    from xdr_cli.exceptions import APIError
    from xdr_cli.schema_graph import reference

    def fail(home):
        response = httpx.Response(503, request=httpx.Request("GET", REFERENCE_URLS["schema"]))
        response.raise_for_status()

    monkeypatch.setattr(reference, "sync_reference", fail)
    with pytest.raises(APIError) as caught:
        await schema_init_cmd._initialize(SimpleNamespace(), sync_reference=True)
    assert caught.value.status_code == 503


@pytest.mark.asyncio
async def test_explicit_revalidation_recovers_invalid_ledger_without_deleting_evidence(
    tmp_path, monkeypatch, reference_documents,
):
    from xdr_cli.hunting_result import HuntingResult
    from xdr_cli.schema_graph.reference_state import validation_root
    from xdr_cli.schema_graph.reference_validation import validate_reference

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    root = validation_root(tmp_path, "test")
    root.mkdir(parents=True)
    (root / "current.json").write_text('not-json')

    class Client:
        async def execute_hunting(self, query):
            return HuntingResult([], [{"RouteId": "event-actor", "SourceValues": 0,
                                       "TargetValues": 0, "MatchedSourceValues": 0,
                                       "MatchRows": 0}], {})

    report = await validate_reference(
        Client(), parse_snapshot(reference_documents), _reference_schema_rows(),
        home=tmp_path, tenant_id="test", revalidate=True,
    )
    assert report["queries"] == 1 and report["pending"] == 0
    assert json.loads((root / "current.json").read_text())["file"].startswith("validation.")
