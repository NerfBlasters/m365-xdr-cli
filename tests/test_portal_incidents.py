"""Graph portal contracts retain evidence, filters and credential boundaries."""
import json
from unittest.mock import Mock

import httpx
import pytest
import respx
from typer.testing import CliRunner

from xdr_cli.api.incidents import get_incident, list_incidents
from xdr_cli.backends import create_client
from xdr_cli.commands.investigate_cmd import _extract_entities
from xdr_cli.config import Config
from xdr_cli.exceptions import APIError
from xdr_cli.main import app
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

ORIGIN = 'https://security.microsoft.com/apiproxy/'
GRAPH = ORIGIN + 'msgraph/v1.0/'


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    save_portal_cookies({
        'tenant_fingerprint': tenant_fingerprint('test-tenant'),
        'cookie_header': 'sccauth=synthetic', 'xsrf_token': 'synthetic',
    })
    return Config(api_backend='portal-cookie', tenant_id='test-tenant')


def alert():
    return {
        'id': 'alert-1', 'incidentId': '42', 'severity': 'high', 'status': 'new',
        'evidence': [
            {'@odata.type': '#microsoft.graph.security.deviceEvidence',
             'deviceDnsName': 'sample.invalid', 'mdeDeviceId': 'a' * 40},
            {'@odata.type': '#microsoft.graph.security.userEvidence',
             'userAccount': {'userPrincipalName': 'sample@example.invalid'}},
            {'@odata.type': '#microsoft.graph.security.processEvidence',
             'processId': 12, 'processCommandLine': 'synthetic-command'},
            {'@odata.type': '#microsoft.graph.security.futureEvidence', 'opaque': 'retained'},
        ],
    }


def mock_contract():
    respx.get(ORIGIN + 'mtp/sccManagement/mgmt/TenantContext').respond(
        200, json={'AuthInfo': {'TenantId': 'test-tenant'}},
    )
    incident = respx.get(GRAPH + 'security/incidents/42').respond(200, json={
        'id': '42', 'displayName': 'Synthetic incident', 'severity': 'high',
        'status': 'active', 'classification': 'unknown', 'alerts': [alert()],
    })
    respx.get(GRAPH + 'security/alerts_v2/alert-1').respond(200, json=alert())
    return incident


@pytest.mark.asyncio
@respx.mock
async def test_expansion_preserves_full_official_evidence(config):
    route = mock_contract()
    client = create_client(config, auth_factory=Mock(side_effect=AssertionError('MSAL')))
    try:
        result = await get_incident(client, '42', expand=['alerts'])
    finally:
        await client.close()
    assert result['alerts'] == [alert()]
    assert route.calls[0].request.url.params['$expand'] == 'alerts'
    assert 'authorization' not in route.calls[0].request.headers
    entities = _extract_entities(result)
    assert entities['devices'] == {'sample.invalid'}
    assert entities['users'] == {'sample@example.invalid'}


@pytest.mark.parametrize('malformed', [
    {'id': '42'}, {'id': '42', 'alerts': None},
    {'id': '42', 'alerts': [{'id': 'alert-1'}]},
    {'id': 'other', 'alerts': [alert()]},
])
@pytest.mark.asyncio
@respx.mock
async def test_missing_expansion_is_not_empty_success(config, malformed):
    route = mock_contract()
    route.respond(200, json=malformed)
    client = create_client(config)
    try:
        with pytest.raises(APIError):
            await get_incident(client, '42', expand=['alerts'])
    finally:
        await client.close()


@pytest.mark.parametrize('command', [
    ['incidents', 'show', '42', '--expand', 'alerts'],
    ['alerts', 'show', 'alert-1'],
])
@respx.mock
def test_cli_preserves_evidence_and_portal_provenance(config, monkeypatch, command):
    from pathlib import Path

    mock_contract()
    monkeypatch.setattr('xdr_cli.main.load_config', lambda: config)
    output = CliRunner().invoke(app, command)
    assert output.exit_code == 0, output.output
    receipt = json.loads(output.stdout.splitlines()[0])
    rows = [json.loads(line) for line in Path(receipt['data_path']).read_text().splitlines()]
    assert len([row for row in rows if row['record_type'] == 'evidence']) == 4
    assert any(row.get('processCommandLine') == 'synthetic-command' for row in rows)
    assert any(row.get('opaque') == 'retained' for row in rows)
    metadata = json.loads(Path(receipt['meta_path']).read_text())
    assert metadata['api_backend'] == 'portal-cookie'
    if command[0] == 'alerts':
        assert metadata['anchors']['provenance']['incident_id'] == 'portal-response'


@pytest.mark.asyncio
@respx.mock
async def test_pagination_transfers_query_only_and_preserves_filters(config):
    mock_contract()
    route = respx.get(GRAPH + 'security/incidents').mock(side_effect=[
        httpx.Response(200, json={
            'value': [{'id': '42'}],
            '@odata.nextLink': 'https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=a%2Bb',
        }),
        httpx.Response(200, json={'value': [{'id': '43'}]}),
    ])
    client = create_client(config)
    try:
        rows = [row async for row in list_incidents(
            client, odata_filter="status eq 'active'", top=1,
        )]
    finally:
        await client.close()
    assert rows == [{'id': '42'}, {'id': '43'}]
    assert route.calls[0].request.url.params['$filter'] == "status eq 'active'"
    assert route.calls[1].request.url.query == b'$skiptoken=a%2Bb'
    assert all(call.request.url.host == 'security.microsoft.com' for call in route.calls)


@pytest.mark.parametrize('next_link', [
    'https://example.invalid/v1.0/domains?$skiptoken=a',
    'https://graph.microsoft.com/v1.0/users?$skiptoken=a',
    'http://graph.microsoft.com/v1.0/domains?$skiptoken=a',
    'https://graph.microsoft.com:444/v1.0/domains?$skiptoken=a',
])
@pytest.mark.asyncio
@respx.mock
async def test_domains_continuation_cannot_redirect_credentials(config, next_link):
    mock_contract()
    route = respx.get(GRAPH + 'domains').respond(200, json={
        'value': [{'id': 'example.invalid', 'isVerified': True}], '@odata.nextLink': next_link,
    })
    client = create_client(config)
    try:
        with pytest.raises(APIError, match='outside the named operation'):
            await client.list_domains()
    finally:
        await client.close()
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_domains_preserve_unverified_domain_and_authentication_type(config):
    from xdr_cli.api.domains import list_domains

    mock_contract()
    domains = [{'id': 'example.invalid', 'isVerified': False,
                'isDefault': False, 'authenticationType': 'Federated'}]
    respx.get(GRAPH + 'domains').respond(200, json={'value': domains})
    client = create_client(config)
    try:
        assert await list_domains(client) == domains
    finally:
        await client.close()


@respx.mock
def test_guided_investigation_uses_portal_graph_and_hunting(config, monkeypatch):
    mock_contract()
    monkeypatch.setattr('xdr_cli.main.load_config', lambda: config)
    monkeypatch.setattr('xdr_cli.auth.AuthManager.__init__', Mock(
        side_effect=AssertionError('MSAL must not initialize'),
    ))
    hunt = respx.post(
        ORIGIN + 'hunting/huntingQueryExecutorService/queryExecutor/v1/external',
    ).respond(200, json={'Schema': [], 'Results': []})
    result = CliRunner().invoke(app, ['investigate', '42'])
    assert result.exit_code == 0, result.output
    assert hunt.called
    assert all('authorization' not in call.request.headers for call in respx.calls)


@pytest.mark.asyncio
@respx.mock
async def test_hostname_lookup_filters_prefix_candidates_and_uses_exact_id(config):
    from xdr_cli.api.devices import find_device_by_hostname

    mock_contract()
    route = respx.get(ORIGIN + 'mtp/ndr/machines').respond(200, json=[
        {'SenseMachineId': 'b' * 40, 'ComputerDnsName': 'sample.invalid.extra'},
        {'SenseMachineId': 'a' * 40, 'ComputerDnsName': 'sample.invalid'},
    ])
    detail = respx.get(ORIGIN + 'mtp/getMachine/machines').respond(200, json={
        'SenseMachineId': 'a' * 40, 'ComputerDnsName': 'sample.invalid',
    })
    client = create_client(config)
    try:
        result = await find_device_by_hostname(client, 'sample.invalid')
    finally:
        await client.close()
    assert result['id'] == 'a' * 40
    assert route.calls[0].request.url.params['machineSearchPrefix'] == 'sample.invalid'
    assert detail.calls[0].request.url.params['machineId'] == 'a' * 40


@pytest.mark.asyncio
@respx.mock
async def test_hostname_ambiguity_does_not_choose_a_device(config):
    from xdr_cli.api.devices import find_device_by_hostname
    from xdr_cli.exceptions import ConflictError

    mock_contract()
    respx.get(ORIGIN + 'mtp/ndr/machines').respond(200, json=[
        {'SenseMachineId': 'b' * 40, 'ComputerDnsName': 'sample.invalid'},
        {'SenseMachineId': 'a' * 40, 'ComputerDnsName': 'sample.invalid'},
    ])
    client = create_client(config)
    try:
        with pytest.raises(ConflictError):
            await find_device_by_hostname(client, 'sample.invalid')
    finally:
        await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_incident_write_adapters_preserve_graph_contract_without_live_mutation(config):
    from xdr_cli.api.incidents import add_incident_comment, update_incident

    mock_contract()
    update = respx.patch(GRAPH + 'security/incidents/42').respond(204)
    comment = respx.post(GRAPH + 'security/incidents/42/comments').respond(
        201, json={'comment': 'synthetic review'},
    )
    client = create_client(config)
    try:
        assert await update_incident(client, '42', {'status': 'resolved'}) == {}
        assert await add_incident_comment(client, '42', 'synthetic review') == {
            'comment': 'synthetic review',
        }
    finally:
        await client.close()
    assert json.loads(update.calls[0].request.content) == {'status': 'resolved'}
    assert json.loads(comment.calls[0].request.content) == {'comment': 'synthetic review'}
    assert update.call_count == comment.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_write_transport_failure_is_not_retried(config):
    from xdr_cli.exceptions import NetworkError

    mock_contract()
    route = respx.patch(GRAPH + 'security/incidents/42').mock(
        side_effect=httpx.ReadError('synthetic failure'),
    )
    client = create_client(config)
    try:
        with pytest.raises(NetworkError) as error:
            await client.update_incident('42', {'status': 'resolved'})
    finally:
        await client.close()
    assert route.call_count == 1
    assert error.value.retryable is False
    assert 'Outcome unknown' in str(error.value)
