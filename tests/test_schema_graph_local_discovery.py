import hashlib
import json
from datetime import UTC, datetime

from xdr_cli.schema_graph.local_discovery import discover_local, pair_values

TENANT = "synthetic-tenant"


def artifact(root, run, query, rows, tenant=TENANT):
    folder = root / "2026-10-03"
    folder.mkdir(parents=True, exist_ok=True)
    data = folder / f"{run}.jsonl"
    meta = folder / f"{run}.meta.json"
    raw = "".join(json.dumps(row) + "\n" for row in rows).encode()
    data.write_bytes(raw)
    meta.write_text(
        json.dumps(
            {
                "run_id": run,
                "command": "hunt run",
                "query": query,
                "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
                "data_sha256": hashlib.sha256(raw).hexdigest(),
                "data_path": str(data.resolve()),
                "meta_path": str(meta.resolve()),
                "tenant_binding": {
                    "state": "bound",
                    "sha256": hashlib.sha256(tenant.encode()).hexdigest(),
                },
                "row_count": len(rows),
                "created_at": datetime.now(UTC).isoformat(),
            }
        )
    )
    return data, meta


def test_local_overlap_is_incremental_private_and_retracts_deleted_evidence(tmp_path):
    root, index = tmp_path / "results", tmp_path / "index"
    artifact(root, "a", "First | project Alias=Principal", [{"Alias": "User@Example.com"}])
    data, meta = artifact(root, "b", "Second | project Who", [{"Who": "user@example.com"}])
    pairs, coverage = discover_local(root, index, TENANT)
    assert coverage["processed_artifacts"] == 2
    assert len(pairs) == 1
    assert (pairs[0].source, pairs[0].target) == ("First.Principal", "Second.Who")
    assert pair_values(pairs[0], root, TENANT) == ["user@example.com"]
    assert b"user@example.com" not in (index / "local-discovery.sqlite3").read_bytes()
    repeated, coverage = discover_local(root, index, TENANT)
    assert repeated == pairs
    assert coverage["cached_artifacts"] == 2
    assert coverage.get("bytes_read", 0) == 0
    meta.unlink()
    data.unlink()
    assert discover_local(root, index, TENANT)[0] == []


def test_wrong_tenant_tampering_and_calculated_columns_are_not_evidence(tmp_path):
    root, index = tmp_path / "results", tmp_path / "index"
    artifact(root, "a", "First | project Principal", [{"Principal": "user@example.com"}])
    data, _ = artifact(root, "b", "Second | project Who", [{"Who": "user@example.com"}])
    artifact(root, "c", "Third | project Who", [{"Who": "user@example.com"}], "another")
    artifact(root, "d", "Fourth | extend Who='user@example.com'", [{"Who": "user@example.com"}])
    assert len(discover_local(root, index, TENANT)[0]) == 1
    data.write_text('{"Who":"other@example.com"}\n')
    assert discover_local(root, index, TENANT)[0] == []


def test_budget_resumes_and_low_information_values_are_ignored(tmp_path):
    root, index = tmp_path / "results", tmp_path / "index"
    artifact(root, "a", "First | project User", [{"User": "user@example.com", "Flag": True}])
    artifact(root, "b", "Second | project Who", [{"Who": "user@example.com", "Count": 1}])
    pairs, coverage = discover_local(root, index, TENANT, max_artifacts=1)
    assert not pairs
    assert coverage["complete"] is False
    pairs, coverage = discover_local(root, index, TENANT, max_artifacts=1)
    assert len(pairs) == 1
    assert coverage["complete"] is True
    assert coverage["cached_artifacts"] == 1


def test_duplicate_content_and_same_table_do_not_create_independent_pairs(tmp_path):
    root, index = tmp_path / "results", tmp_path / "index"
    rows = [{"User": "user@example.com"}]
    artifact(root, "a", "First | project User", rows)
    artifact(root, "b", "Second | project User", rows)
    artifact(root, "c", "First | project Other", [{"Other": "user@example.com"}])
    pairs, _ = discover_local(root, index, TENANT)
    assert all(pair.source != "First.Other" or pair.target != "First.User" for pair in pairs)
    assert all({pair.source_run, pair.target_run} != {"a", "b"} for pair in pairs)


def test_generic_vocabulary_and_malformed_values_are_not_identifiers():
    from xdr_cli.schema_graph.local_discovery import identifier

    for value in ('svchost.exe', 'Microsoft', 'ProcessCreated', '224.0.0.251',
                  'bad\x7fvalue123', 'bad\ud800value123', 'a\\' * 1000):
        assert identifier(value) is None
    # Private addresses remain useful investigation pivots, not global identities.
    assert identifier('10.0.0.1') == ('identity', '10.0.0.1')
    assert identifier('user@example.com') == ('upn-lower', 'user@example.com')


def test_value_shaped_dictionary_keys_stay_private():
    from xdr_cli.schema_graph.local_discovery import discoverable_path

    for key in ('contoso.com', 'host-123.contoso.com', 'S-1-5-21-123456-789012-345678-1001'):
        assert not discoverable_path(('Raw', key))
    assert discoverable_path(('Actor', '*', 'UserId'))
