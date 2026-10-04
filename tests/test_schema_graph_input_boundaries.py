from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest

from xdr_cli.schema_graph.lineage import UnsupportedLineage, recover_field_origins
from xdr_cli.schema_graph.local_discovery import identifier, row_identifiers


def test_free_text_json_is_not_a_dynamic_field():
    origins = recover_field_origins('DeviceProcessEvents | project ProcessCommandLine')
    rows = list(row_identifiers(
        {'ProcessCommandLine': '{"AccountObjectId":"user@example.com"}'}, origins, Counter()
    ))
    assert rows == []


def test_known_json_column_still_discovers_nested_identifiers():
    origins = recover_field_origins('CloudAppEvents | project RawEventData')
    rows = list(row_identifiers(
        {'RawEventData': '{"UserId":"user@example.com"}'}, origins, Counter()
    ))
    assert rows == [('CloudAppEvents.RawEventData#/UserId', 'upn-lower', 'user@example.com')]


def test_cell_decoder_failure_does_not_lose_other_columns():
    origins = recover_field_origins('Events | project RawEventData, AccountUpn')
    coverage = Counter()
    with patch('xdr_cli.schema_graph.local_discovery.json.loads', side_effect=RecursionError):
        rows = list(row_identifiers(
            {'RawEventData': '{}', 'AccountUpn': 'user@example.com'}, origins, coverage
        ))
    assert rows == [('Events.AccountUpn', 'upn-lower', 'user@example.com')]
    assert coverage['unparseable_json_cells'] == 1


def test_lineage_complexity_is_bounded_before_recursive_expression_parsing():
    query = 'Events | project X=' + 'tostring(' * 80 + 'Name' + ')' * 80
    with pytest.raises(UnsupportedLineage, match='complexity'):
        recover_field_origins(query)


@pytest.mark.parametrize('constant', ['S-1-5-32-544', 'S-1-5-18', 'S-1-1-0'])
def test_well_known_principals_are_not_discovery_identifiers(constant):
    assert identifier(constant) is None


def test_lineage_complexity_never_discards_saved_hunt_results(tmp_path, monkeypatch):
    from xdr_cli.results import write_result

    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    query = 'Events | project X=' + 'tostring(' * 80 + 'Name' + ')' * 80
    result = write_result([{'X': 'preserved'}], command='hunt run', query=query)
    assert result.receipt.rows == 1
    assert 'preserved' in Path(result.receipt.data_path).read_text()


def test_live_json_expansion_preserves_raw_cell_on_decoder_failure():
    from xdr_cli.json_expansion import expand_json_string_columns

    rows = [{'RawEventData': '{}', 'AccountUpn': 'user@example.com'}]
    with patch('xdr_cli.json_expansion.json.loads', side_effect=RecursionError):
        assert expand_json_string_columns(rows) == rows


def test_tenant_guid_is_excluded_but_other_guid_is_preserved():
    import hashlib

    tenant = '12345678-1234-1234-1234-123456789abc'
    other = 'abcdef12-1234-1234-1234-123456789abc'
    origins = recover_field_origins('Events | project TenantId, AccountObjectId')
    coverage = Counter()
    rows = list(row_identifiers({'TenantId': tenant, 'AccountObjectId': other}, origins,
                                coverage, hashlib.sha256(tenant.encode()).hexdigest()))
    assert [row[2] for row in rows] == [other]
    assert coverage['tenant_constant_cells_excluded'] == 1


def test_non_ascii_addresses_are_explicitly_excluded_from_kql_normalization_scope():
    origins = recover_field_origins('Events | project AccountUpn')
    coverage = Counter()
    assert not list(row_identifiers({'AccountUpn': 'straße@bücher.example'}, origins, coverage))
    assert coverage['unsupported_normalization_cells'] == 1


def test_host_shaped_dynamic_key_is_not_a_public_locator():
    from xdr_cli.schema_graph.local_discovery import discoverable_path

    assert not discoverable_path(('jdoe_hostWKS042',))
    assert discoverable_path(('UserId',))
    assert discoverable_path(('IPv4',))


def test_future_artifact_does_not_supply_discovery_seeds(tmp_path):
    import hashlib
    import json
    from datetime import UTC, datetime, timedelta
    from xdr_cli.schema_graph.local_discovery import artifact_metadata

    root = tmp_path / 'results'
    folder = root / '2026-01-01'
    folder.mkdir(parents=True)
    meta = folder / 'future.meta.json'
    meta.write_text(json.dumps({'row_count': 0,
                               'created_at': (datetime.now(UTC) + timedelta(days=1)).isoformat()}))
    with pytest.raises(ValueError, match='future-evidence-time'):
        artifact_metadata(meta, root, hashlib.sha256(b'tenant').hexdigest())


def test_uppercase_configured_tenant_guid_is_still_a_constant(tmp_path, monkeypatch):
    from xdr_cli.results import write_result
    from xdr_cli.schema_graph.discovery import saved_seeds

    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    tenant = 'ABCDEF12-1234-5678-90AB-123456789ABC'
    write_result([{'TenantId': tenant.lower()}], command='hunt run',
                 query='Events | project TenantId', tenant_id=tenant)
    assert saved_seeds(tenant)[0] == {}
