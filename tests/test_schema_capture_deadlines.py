"""Local work honors exploration deadlines without publishing incomplete evidence."""

import sqlite3
from types import SimpleNamespace

import pytest

from xdr_cli.config import Config
from xdr_cli.context import AppContext
from xdr_cli.exceptions import PartialSuccessError
from xdr_cli.results import write_result
from xdr_cli.schema_graph import local_discovery
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.local_collection import collect_local
from xdr_cli.schema_graph.overlay import publish_tenant_overlay


def test_parse_deadline_rolls_back_current_artifact_and_resumes(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    artifact = write_result(
        [{"User": "one@example.com"}, {"User": "two@example.com"}],
        command="hunt run",
        query="First | project User",
        tenant_id="synthetic",
    )
    timer = {"now": 0}
    monkeypatch.setattr(local_discovery, "time", SimpleNamespace(monotonic=lambda: timer["now"]))
    original = local_discovery.row_identifiers

    def expire(*args, **kwargs):
        yield from original(*args, **kwargs)
        timer["now"] = 11

    with monkeypatch.context() as patch:
        patch.setattr(local_discovery, "row_identifiers", expire)
        pairs, coverage = local_discovery.discover_local(
            tmp_path / "results",
            tmp_path / "index",
            "synthetic",
            deadline=10,
            required_runs=(artifact.receipt.run_id,),
        )
    assert pairs == [] and coverage["complete"] is False
    assert coverage["required_sources_complete"] is False
    with sqlite3.connect(tmp_path / "index" / "local-discovery.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM identifiers").fetchone()[0] == 0
    timer["now"] = 0
    _, resumed = local_discovery.discover_local(
        tmp_path / "results",
        tmp_path / "index",
        "synthetic",
        deadline=10,
        required_runs=(artifact.receipt.run_id,),
    )
    assert resumed["complete"] and resumed["required_sources_complete"]
    assert resumed["indexed_rows"] == 2


def test_sql_deadline_checkpoints_after_indexing_instead_of_returning_partial_pairs(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    for table in ("First", "Second"):
        write_result(
            [{"User": f"user{i}@example.com", "Tag": table} for i in range(1000)],
            command="hunt run",
            query=f"{table} | project User,Tag",
            tenant_id="synthetic",
        )
    timer = {"now": 0, "callbacks": 0}
    monkeypatch.setattr(local_discovery, "time", SimpleNamespace(monotonic=lambda: timer["now"]))
    real_connect = sqlite3.connect

    class Connection:
        def __init__(self, *args, **kwargs):
            self.db = real_connect(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.db, name)

        def __enter__(self):
            self.db.__enter__()
            return self

        def __exit__(self, *args):
            return self.db.__exit__(*args)

        def set_progress_handler(self, callback, steps):
            if callback is None:
                self.db.set_progress_handler(None, 0)
                return

            def interrupt():
                timer["callbacks"] += 1
                timer["now"] = 11
                return callback()

            self.db.set_progress_handler(interrupt, steps)

    with monkeypatch.context() as patch:
        patch.setattr(local_discovery.sqlite3, "connect", Connection)
        pairs, coverage = local_discovery.discover_local(
            tmp_path / "results",
            tmp_path / "index",
            "synthetic",
            deadline=10,
        )
    assert timer["callbacks"] >= 1
    assert pairs == [] and coverage["complete"] is False
    timer["now"] = 0
    pairs, coverage = local_discovery.discover_local(
        tmp_path / "results",
        tmp_path / "index",
        "synthetic",
        deadline=10,
    )
    assert coverage["cached_artifacts"] == 2
    assert coverage["complete"] and len(pairs) == 1


@pytest.mark.asyncio
async def test_incomplete_index_never_changes_overlay_or_releases_handoff(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    publish_tenant_overlay("synthetic")
    manifest = next((tmp_path / "schema").glob("*/semantic.current.json"))
    before = manifest.read_bytes()
    receipts = []
    with pytest.raises(PartialSuccessError):
        await collect_local(
            AppContext(Config(tenant_id="synthetic")),
            plan_only=False,
            local_only=True,
            lookback="24h",
            samples=5,
            max_queries=0,
            timeout=120,
            schema_rows=[],
            canonical=load_packaged_graph(),
            on_result=receipts.append,
            index_deadline=-1,
        )
    assert manifest.read_bytes() == before
    assert len(receipts) == 1
    assert receipts[0].receipt.context["scope_complete"] is False
    assert receipts[0].receipt.context["local_publication_complete"] is False
    assert receipts[0].receipt.context["local_coverage"]["required_sources_complete"] is False


@pytest.mark.asyncio
async def test_planning_evidence_stream_stops_mid_bundle_without_retiring_evidence(
    tmp_path, monkeypatch
):
    from xdr_cli.schema_graph import evidence_cache

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    for table in ("First", "Second"):
        write_result(
            [{"User": f"user{i}@example.com", "Tag": table} for i in range(2005)],
            command="hunt run",
            query=f"{table} | project User,Tag",
            tenant_id="synthetic",
        )
    pairs, coverage = local_discovery.discover_local(
        tmp_path / "results",
        tmp_path / "index-unused",
        "synthetic",
    )
    assert coverage["complete"] and pairs
    # Use the actual collection index directory, then ensure the next scan uses
    # its verified cache instead of triggering the expiry while first indexing.
    import hashlib

    index = tmp_path / "schema" / hashlib.sha256(b"synthetic").hexdigest()[:12]
    local_discovery.discover_local(tmp_path / "results", index, "synthetic")
    publish_tenant_overlay("synthetic")
    manifest = index / "semantic.current.json"
    before = manifest.read_bytes()
    timer = {"now": 0, "parsed": 0}
    original = local_discovery.row_identifiers

    def expire_during_evidence(*args, **kwargs):
        timer["parsed"] += 1
        yield from original(*args, **kwargs)
        timer["now"] = 1e12 + 1

    monkeypatch.setattr(evidence_cache, "time", SimpleNamespace(monotonic=lambda: timer["now"]))
    monkeypatch.setattr(local_discovery, "row_identifiers", expire_during_evidence)
    receipts = []
    with pytest.raises(PartialSuccessError):
        await collect_local(
            AppContext(Config(tenant_id="synthetic")),
            plan_only=False,
            local_only=True,
            lookback="24h",
            samples=5,
            max_queries=0,
            timeout=120,
            schema_rows=[],
            canonical=load_packaged_graph(),
            on_result=receipts.append,
            index_deadline=1e12,
        )
    assert 0 < timer["parsed"] <= 1000
    assert manifest.read_bytes() == before
    assert receipts[0].receipt.context["local_publication_complete"] is False
    assert "retired_invalid_validations" not in receipts[0].receipt.context["local_coverage"]


@pytest.mark.asyncio
async def test_deadline_paused_pipeline_never_consumes_capture_pins(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock, patch

    from xdr_cli.backend_contract import OFFICIAL_PROFILE
    from xdr_cli.schema_graph.capture_orchestration import explore_recent_data

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    report = {
        "job_id": "cap-20261024T000000Z-12345678",
        "status": "complete",
        "interval": {},
        "stop": None,
        "counters": {"queries": 0},
        "captured_run_ids": [],
        "tables": [],
    }

    async def paused_index(ctx, **options):
        options["index_deadline"] = -1
        await collect_local(ctx, **options)

    receipts = []
    with (
        patch("xdr_cli.commands.schema_cmd._load_cache", return_value=([], {})),
        patch(
            "xdr_cli.schema_graph.capture_orchestration.create_client",
            return_value=SimpleNamespace(profile=OFFICIAL_PROFILE, close=AsyncMock()),
        ),
        patch(
            "xdr_cli.schema_graph.capture_engine.capture_recent",
            new_callable=AsyncMock,
            return_value=report,
        ),
        patch("xdr_cli.schema_graph.local_collection.collect_local", side_effect=paused_index),
        patch("xdr_cli.schema_graph.capture_engine.mark_capture_consumed") as consume,
        pytest.raises(PartialSuccessError),
    ):
        await explore_recent_data(
            AppContext(Config(tenant_id="synthetic")),
            canonical=load_packaged_graph(),
            on_result=receipts.append,
        )
    consume.assert_not_called()
    assert not receipts[0].receipt.context.get("capture_handoff_ready")
    assert not receipts[0].receipt.context["scope_complete"]
