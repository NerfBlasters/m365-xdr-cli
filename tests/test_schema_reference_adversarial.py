"""Reproductions from the independent adversarial review of tenant initialization."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from xdr_cli.commands import schema_cmd, schema_init_cmd
from xdr_cli.hunting_result import HuntingResult
from xdr_cli.schema_graph import reference_query
from xdr_cli.schema_graph.effective import compose_effective_graph
from xdr_cli.schema_graph.model import Graph
from xdr_cli.schema_graph.reference import publish_snapshot
from xdr_cli.schema_graph.reference_routes import compose_reference_routes, reference_catalog
from xdr_cli.schema_graph.reference_state import (
    physical_schema_digest,
    reference_status,
    save_validation_state,
)
from xdr_cli.schema_graph.reference_validation import validate_reference
from xdr_cli.schema_graph.traversal import pivot


@pytest.fixture
def reference_case(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    documents = {
        "schema": [{"Name": table, "Schema": [{"Name": "Id", "Type": "String"},
                    {"Name": "Timestamp", "Type": "DateTime"}]}
                   for table in ("Events", "Profiles")],
        "relations": {"version": 1, "relations": [{
            "id": "actor-proof", "title": "Actor proof", "family": "entra-user",
            "from": {"table": "Events", "column": "Id", "timeColumn": "Timestamp"},
            "to": {"table": "Profiles", "column": "Id", "timeColumn": "Timestamp"},
            "guidance": "Keep actor and tenant context.",
        }]},
        "structured": {"version": 1, "entries": []}, "actions": [],
    }
    snapshot = publish_snapshot(tmp_path, {k: json.dumps(v).encode() for k, v in documents.items()})
    rows = [{"TableName": table, "ColumnName": column, "ColumnType": kind}
            for table in ("Events", "Profiles")
            for column, kind in (("Id", "string"), ("Timestamp", "datetime"))]
    return snapshot, rows


class MatchingClient:
    async def execute_hunting(self, query):
        return HuntingResult([], [{"RouteId": "actor-proof", "SourceValues": 1,
                                   "TargetValues": 1, "MatchedSourceValues": 1,
                                   "MatchRows": 1, "ScanCapped": 0}], {})


def runtime_step(rows):
    effective = schema_cmd._compose_effective(
        rows, tenant_id="synthetic", canonical=Graph(), overlays=(), observations=(),
    )
    return schema_cmd._semantic_step_row(pivot(effective.graph, "Events.Id")[0], 1)


@pytest.mark.asyncio
async def test_saved_match_is_retired_when_current_compiler_contract_changes(
    reference_case, tmp_path, monkeypatch,
):
    snapshot, rows = reference_case
    await validate_reference(MatchingClient(), snapshot, rows, home=tmp_path, tenant_id="synthetic")
    assert runtime_step(rows)["TenantMatched"]
    original = reference_query.compile_reference_query

    def revised(*args, **kwargs):
        result = original(*args, **kwargs)
        return replace(result, query=result.query + "\n// updated validation contract",
                       constraints_applied=(*result.constraints_applied, "new-required-condition"))

    monkeypatch.setattr(reference_query, "compile_reference_query", revised)
    step = runtime_step(rows)
    assert step["TenantMatched"] is False
    assert step["ReferenceTrusted"] is True
    assert "new-required-condition" in step["ReferenceConditions"]
    assert reference_status(tmp_path, "synthetic", rows)["state"] == "needs-validation"


@pytest.mark.asyncio
async def test_saved_record_cannot_cross_ledger_physical_schema_binding(reference_case, tmp_path):
    snapshot, rows = reference_case
    report = await validate_reference(
        MatchingClient(), snapshot, rows, home=tmp_path, tenant_id="synthetic",
    )
    changed = [*rows, {"TableName": "Events", "ColumnName": "NewField", "ColumnType": "string"}]
    # A structurally valid new ledger cannot rebind intact old execution evidence.
    save_validation_state(tmp_path, "synthetic", reference_digest=snapshot.digest,
                          schema_digest=physical_schema_digest(changed),
                          options=report["options"], routes=report["routes"])
    assert runtime_step(changed)["TenantMatched"] is False


@pytest.mark.asyncio
async def test_missing_required_scope_never_produces_a_tenant_usable_route(
    reference_case, tmp_path,
):
    snapshot, rows = reference_case
    route = replace(snapshot.routes[0], guidance="Match AccountObjectId as well.")
    snapshot = replace(snapshot, routes=(route,))
    report = await validate_reference(None, snapshot, rows, home=tmp_path, tenant_id="synthetic")
    assert report["queries"] == 0
    assert reference_catalog(snapshot, rows, report["routes"])[0]["TenantUsable"] is False
    effective = compose_reference_routes(compose_effective_graph(rows, canonical=Graph()),
                                         snapshot, rows, states=report["routes"])
    assert not effective.graph.relationships


def test_reversed_reference_conditions_keep_original_endpoint_binding(reference_case):
    snapshot, rows = reference_case
    effective = compose_reference_routes(compose_effective_graph(rows, canonical=Graph()),
                                         snapshot, rows)
    step = pivot(effective.graph, "Profiles.Id")[0]
    info = step.reference_routes[0]
    assert info["source"] == "Events.Id"
    assert info["target"] == "Profiles.Id"
    assert step.source_locator == "Profiles.Id"


@pytest.mark.asyncio
async def test_failed_new_table_checks_return_partial_and_status_reports_them(
    reference_case, tmp_path, monkeypatch, capsys,
):
    from xdr_cli.exceptions import PartialSuccessError, QueryError

    _snapshot, rows = reference_case
    rows = [*rows, {"TableName": "NovelEvents", "ColumnName": "Id", "ColumnType": "string"},
            {"TableName": "NovelEvents", "ColumnName": "Timestamp", "ColumnType": "datetime"}]
    monkeypatch.setattr(schema_cmd, "_load_cache", lambda ctx: (rows, {}))

    class Client(MatchingClient):
        async def execute_hunting(self, query):
            if "tenant-discovery-" in query:
                raise QueryError("Derived check failed")
            return await super().execute_hunting(query)

        async def close(self):
            pass

    monkeypatch.setattr(schema_init_cmd, "create_client", lambda *a, **kw: Client())
    # The test exercises bookkeeping, not real pacing.
    async def unpaced(*args, **kwargs):
        return await validate_reference(*args, **kwargs, min_interval_seconds=0)
    monkeypatch.setattr(schema_init_cmd, "validate_reference", unpaced)
    ctx = SimpleNamespace(config=SimpleNamespace(tenant_id="synthetic", api_timeout=30),
                          effective_quiet=True)
    with pytest.raises(PartialSuccessError):
        await schema_init_cmd._initialize(ctx, skip_refresh=True)
    receipt = json.loads(capsys.readouterr().out.splitlines()[0])
    assert receipt["context"]["new_table_discovery"]["validation_states"]["query-failed"] == 2
    status = reference_status(tmp_path, "synthetic", rows)
    assert status["state"] == "needs-validation"
    assert status["discovery_validation_states"]["query-failed"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["auth", "permission", "config", "artifact"])
async def test_fatal_validation_errors_preserve_their_exit_class(
    reference_case, tmp_path, kind,
):
    from xdr_cli.exceptions import ArtifactError, AuthError, ConfigError, PermissionError
    from xdr_cli.schema_graph.reference_state import load_validation_state

    snapshot, rows = reference_case
    error = {"auth": AuthError, "permission": PermissionError,
             "config": ConfigError, "artifact": ArtifactError}[kind]("fatal setup failure")

    class Client:
        calls = 0

        async def execute_hunting(self, query):
            self.calls += 1
            raise error

    client = Client()
    with pytest.raises(type(error)) as caught:
        await validate_reference(client, snapshot, rows, home=tmp_path, tenant_id="synthetic")
    assert caught.value.exit_code == error.exit_code
    assert client.calls == 1
    ledger = load_validation_state(tmp_path, "synthetic", reference_digest=snapshot.digest,
                                   schema_digest=physical_schema_digest(rows))
    assert ledger["routes"]["actor-proof"]["failure"]["exit_code"] == error.exit_code


@pytest.mark.asyncio
async def test_ledger_write_failure_is_an_artifact_error_after_query_success(
    reference_case, tmp_path, monkeypatch,
):
    from xdr_cli.exceptions import ArtifactError
    from xdr_cli.schema_graph import reference_state

    snapshot, rows = reference_case

    def denied(*args):
        raise PermissionError("synthetic ledger permission failure")

    monkeypatch.setattr(reference_state, "_atomic_json", denied)
    with pytest.raises(ArtifactError):
        await validate_reference(MatchingClient(), snapshot, rows,
                                 home=tmp_path, tenant_id="synthetic")
    assert list((tmp_path / "results").glob("*/*.jsonl"))


@pytest.mark.asyncio
async def test_failed_check_stays_suppressed_across_refresh_and_budget_pause(
    reference_case, tmp_path,
):
    from xdr_cli.exceptions import QueryError

    snapshot, rows = reference_case

    class Client:
        async def execute_hunting(self, query):
            raise QueryError("Field cannot currently be queried")

    await validate_reference(Client(), snapshot, rows, home=tmp_path, tenant_id="synthetic")
    changed = [*rows, {"TableName": "Unrelated", "ColumnName": "Other", "ColumnType": "string"}]
    effective = schema_cmd._compose_effective(
        changed, tenant_id="synthetic", canonical=Graph(), overlays=(), observations=(),
    )
    assert not effective.graph.relationships
    paused = await validate_reference(None, snapshot, changed, home=tmp_path,
                                      tenant_id="synthetic", max_queries=0)
    assert paused["pending"] == 1
    assert paused["routes"]["actor-proof"]["status"] == "query-failed"
    status = reference_status(tmp_path, "synthetic", changed)
    assert status["validation_states"]["query-failed"] == 1


def test_token_padding_is_an_edge_transform_without_a_duplicate_source_meaning(reference_case):
    from xdr_cli.schema_graph.reference import ReferenceEndpoint

    snapshot, rows = reference_case
    route = replace(snapshot.routes[0], family="entra-token")
    padded = replace(route, id="padded-token",
                     target=ReferenceEndpoint("AADGraphActivityLogs", "SignInActivityId"))
    rows = [*rows, {"TableName": "AADGraphActivityLogs", "ColumnName": "SignInActivityId",
                   "ColumnType": "string"}]
    effective = compose_reference_routes(compose_effective_graph(rows, canonical=Graph()),
                                         replace(snapshot, routes=(route, padded)), rows)
    meanings = [item for item in effective.graph.interpretations.values()
                if str(effective.graph.fields[item.field_id].locator) == "Events.Id"]
    assert len(meanings) == 1
    assert meanings[0].namespace == "entra-token-id"
    assert meanings[0].normalizer == "identity"
    transforms = {r.transform for r in effective.graph.relationships.values()}
    assert transforms == {"identity", "token-unpad"}


def test_reference_prose_is_private_artifact_data_not_automatic_preview(reference_case):
    from pathlib import Path

    from xdr_cli.results import write_result
    from xdr_cli.schema_graph.reference_routes import safe_reference_previews

    artifact = write_result([{"ReferenceId": "safe-id", "Title": "INJECT-TITLE",
                              "ReferenceRoutes": [{"id": "safe-id",
                                                   "guidance": "INJECT-GUIDANCE"}]}],
                            command="schema init", tenant_id="synthetic")
    safe = safe_reference_previews(artifact)
    assert "INJECT-" not in "\n".join(safe.stdout_lines())
    assert "safe-id" in "\n".join(safe.stdout_lines())
    raw = Path(artifact.receipt.data_path).read_text()
    assert "INJECT-TITLE" in raw and "INJECT-GUIDANCE" in raw


def test_ledger_gc_is_bounded_and_keeps_every_live_pointer(reference_case, tmp_path):
    from xdr_cli.schema_graph.reference_state import validation_root

    snapshot, rows = reference_case
    root = validation_root(tmp_path, "synthetic")
    root.mkdir(parents=True)
    for number in range(70):
        (root / f"validation.{number:024x}.json").write_text("obsolete")
    (root / "unrelated.json").write_text("keep")
    save_validation_state(tmp_path, "synthetic", reference_digest=snapshot.digest,
                          schema_digest=physical_schema_digest(rows),
                          options={"lookback": "7d", "samples": 50, "row_limit": 1000},
                          routes={})
    assert len(list(root.glob("validation.*.json"))) == 7  # new live + six pending GC
    first = json.loads((root / "current.json").read_text())["file"]
    save_validation_state(tmp_path, "synthetic", reference_digest=snapshot.digest,
                          schema_digest=physical_schema_digest(rows),
                          options={"lookback": "1d", "samples": 50, "row_limit": 1000},
                          routes={})
    assert (root / first).exists()
    assert len(list(root.glob("validation.*.json"))) == 2
    assert (root / "unrelated.json").read_text() == "keep"


@pytest.mark.asyncio
async def test_unverifiable_user_type_is_not_queried_or_materialized(reference_case, tmp_path):
    snapshot, rows = reference_case
    route = replace(snapshot.routes[0], id="cloudapp-raw-event-target-account-object-id")
    snapshot = replace(snapshot, routes=(route,))
    report = await validate_reference(None, snapshot, rows, home=tmp_path, tenant_id="synthetic")
    assert report["queries"] == 0
    state = report["routes"][route.id]
    assert state["status"] == "unsupported"
    assert "condition-unverifiable:target-is-user" in state["constraints_applied"]
    catalog = reference_catalog(snapshot, rows, report["routes"])
    assert catalog[0]["ReferenceTrusted"] is True
    assert catalog[0]["TenantUsable"] is False
    effective = compose_reference_routes(compose_effective_graph(rows, canonical=Graph()),
                                         snapshot, rows, states=report["routes"])
    assert not effective.graph.interpretations


def test_unqualified_three_key_overlap_stays_a_candidate(reference_case):
    from xdr_cli.schema_graph.reference_routes import tenant_candidate_routes

    snapshot, rows = reference_case
    rows = [*rows, {"TableName": "NovelEvents", "ColumnName": "Id", "ColumnType": "string"}]
    candidates, _ = tenant_candidate_routes(snapshot, rows)
    state = {route.id: {"status": "matched", "counts": {"MatchedSourceValues": 3}}
             for route in candidates}
    effective = compose_reference_routes(compose_effective_graph(rows, canonical=Graph()),
                                         replace(snapshot, routes=candidates), rows, states=state)
    assert all(r.status.value == "candidate" for r in effective.graph.relationships.values())
