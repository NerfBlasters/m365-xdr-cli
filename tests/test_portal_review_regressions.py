"""Review regressions against synthetic changing collections and local auth state."""
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
import respx
from typer.testing import CliRunner

from xdr_cli.backends import create_client
from xdr_cli.commands.device_cmd import _resolve_machine_id
from xdr_cli.config import Config, load_config, save_config
from xdr_cli.exceptions import APIError, ConfigError, NotAuthenticatedError, RateLimitError
from xdr_cli.main import app
from xdr_cli.portal_auth import load_portal_cookies, save_portal_cookies
from xdr_cli.results import tenant_fingerprint
from xdr_cli.sessions import current_session, resolve_session_for_invocation

BASE = 'https://security.microsoft.com/apiproxy/'
TENANT = BASE + 'mtp/sccManagement/mgmt/TenantContext'
DEVICE = 'a' * 40
DETAIL = BASE + 'mtp/getMachine/machines'
INVENTORY = BASE + 'mtp/ndr/machines'
IPS = BASE + 'mtp/getLatestMachineIpsByIds/LatestMachineIpsByIds'
EXCLUSION = INVENTORY + '/' + DEVICE + '/exclusionDetails'


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    monkeypatch.delenv('XDR_SESSION', raising=False)
    config = Config(api_backend='portal-cookie', tenant_id='test-tenant', client_id='test-app')
    save_config(config)
    save_portal_cookies({
        'tenant_fingerprint': tenant_fingerprint(config.tenant_id),
        'cookie_header': 'sccauth=synthetic-secret', 'xsrf_token': 'synthetic-xsrf',
    })
    return config, tmp_path


@pytest.fixture(autouse=True)
def network():
    with respx.mock(assert_all_called=False) as router:
        router.get(TENANT).respond(json={'AuthInfo': {'TenantId': 'test-tenant'}})
        yield router


def official_identity(monkeypatch):
    auth = Mock()
    auth.get_auth_status.return_value = {
        'authenticated': True, 'account': 'analyst@example.invalid',
    }
    monkeypatch.setattr('xdr_cli.auth.AuthManager', Mock(return_value=auth))
    monkeypatch.setattr('xdr_cli.commands.auth_cmd.AuthManager', Mock(return_value=auth))


@pytest.mark.parametrize('command,collection', [
    ('incidents', 'incidents'), ('alerts', 'alerts_v2'),
])
def test_overlapping_pages_keep_unique_rows_and_reach_limit(local, network, command, collection):
    endpoint = BASE + 'msgraph/v1.0/security/' + collection
    route = network.get(endpoint).mock(side_effect=[
        httpx.Response(200, json={
            'value': [{'id': '1'}, {'id': '2', 'title': 'first observation'}],
            '@odata.nextLink': f'https://graph.microsoft.com/v1.0/security/{collection}?$skip=2',
        }),
        httpx.Response(200, json={'value': [{'id': '2', 'title': 'changed'}, {'id': '3'}]}),
    ])
    result = CliRunner().invoke(app, [command, 'list', '--limit', '3'])
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    rows = [json.loads(line) for line in Path(receipt['data_path']).read_text().splitlines()]
    assert [r['id'] for r in rows] == ['1', '2', '3']
    assert rows[1]['title'] == 'first observation'
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_duplicate_rows_do_not_disable_continuation_loop_guard(local, network):
    route = network.get(BASE + 'msgraph/v1.0/security/incidents').respond(json={
        'value': [{'id': '1'}],
        '@odata.nextLink': 'https://graph.microsoft.com/v1.0/security/incidents?$skip=1',
    })
    client = create_client(local[0])
    try:
        with pytest.raises(APIError, match='invalid continuation'):
            _ = [row async for row in client.list_incidents(params={})]
    finally:
        await client.close()
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_overlapping_graph_pages_still_have_a_page_bound(local, monkeypatch):
    client = create_client(local[0])
    client._verified = True
    calls = 0

    async def page(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {
            'value': [{'id': '1'}],
            '@odata.nextLink':
                f'https://graph.microsoft.com/v1.0/security/incidents?$skip={calls}',
        }

    monkeypatch.setattr(client, '_request', page)
    try:
        with pytest.raises(APIError, match='page bound'):
            _ = [row async for row in client.list_incidents(params={})]
    finally:
        await client.close()
    assert calls == 1000


@pytest.mark.asyncio
async def test_hostname_pages_can_overlap_without_losing_exact_match(local, network):
    detail, _ = device_routes(network)
    exact = {'SenseMachineId': DEVICE, 'ComputerDnsName': 'synthetic.invalid'}
    rows = [{'SenseMachineId': f'{i:040x}', 'ComputerDnsName': 'prefix.synthetic.invalid'}
            for i in range(99)] + [exact]
    search = network.get(INVENTORY).mock(side_effect=[
        httpx.Response(200, json=rows), httpx.Response(200, json=[exact]),
    ])
    client = create_client(local[0])
    try:
        found = await client.find_device_by_hostname('synthetic.invalid', enrich=False)
    finally:
        await client.close()
    assert found['id'] == DEVICE
    assert search.call_count == 2 and detail.call_count == 1


@pytest.mark.parametrize('override', [[], ['--backend', 'official']])
@pytest.mark.parametrize('bad_schema', ['', 'schema_explore_max_queries = 0\n'])
def test_backend_typo_keeps_auth_status_available(local, monkeypatch, override, bad_schema):
    _, home = local
    (home / 'config.toml').write_text(
        'tenant_id = "test-tenant"\nclient_id = "test-app"\n'
        'api_backend = "portal_cookie"\n' + bad_schema,
    )
    official_identity(monkeypatch)
    result = CliRunner().invoke(app, override + ['auth', 'status'])
    assert result.exit_code == 0, result.output
    assert 'invalid api_backend' in result.stderr
    assert 'Warning' not in result.stdout
    data = json.loads(result.stdout)['data']
    if override:
        assert data['main']['backend'] == 'official'
    else:
        assert data['backend'] == 'portal-cookie'
    assert load_config().api_backend == 'auto'
    assert 'portal_cookie' in (home / 'config.toml').read_text()  # no implicit rewrite


def test_official_session_override_uses_cached_identity(local, monkeypatch):
    official_identity(monkeypatch)
    result = CliRunner().invoke(app, ['--backend', 'official', 'session', 'start'])
    assert result.exit_code == 0, result.output
    assert current_session().upn == 'analyst@example.invalid'
    assert load_config().api_backend == 'portal-cookie'


def test_official_automatic_sessions_and_rotation_honor_selected_backend(local, monkeypatch):
    official_identity(monkeypatch)
    for anchor in (1, 2):
        session, reason = resolve_session_for_invocation(
            'incidents show', anchor_incident=anchor, api_backend='official',
        )
        assert session.upn == 'analyst@example.invalid'
        assert reason == ('automatic-created' if anchor == 1 else 'automatic-rotated')


def device_routes(network):
    detail = network.get(DETAIL).respond(json={
        'SenseMachineId': DEVICE, 'ComputerDnsName': 'synthetic.invalid',
        'LastSeen': '2026-01-01T00:00:00Z', 'IsExcluded': True,
    })
    inventory = network.get(INVENTORY).respond(json=[{
        'SenseMachineId': DEVICE, 'ComputerDnsName': 'synthetic.invalid',
    }])
    ips = network.get(IPS).respond(json={'IpAdapters': []})
    exclusion = network.get(EXCLUSION).respond(json={
        'SenseMachineId': DEVICE, 'ExclusionState': 'Excluded', 'Justification': 'Other',
    })
    return detail, {'inventory': inventory, 'ip_adapters': ips, 'exclusion': exclusion}


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['inventory', 'ip_adapters', 'exclusion'])
@pytest.mark.parametrize('failure,code', [
    (httpx.ReadTimeout, 'API_TIMEOUT'), (httpx.ConnectError, 'API_NETWORK_ERROR'),
])
async def test_optional_transport_failures_preserve_device(local, network, source, failure, code):
    detail, extras = device_routes(network)
    extras[source].mock(side_effect=failure('synthetic failure'))
    client = create_client(local[0])
    try:
        device = await client.get_device(DEVICE)
    finally:
        await client.close()
    assert device['id'] == DEVICE
    assert device['portal_source']['enrichment_errors'] == {source: code}
    assert detail.call_count == 1
    assert all(route.call_count == 1 for route in extras.values())


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['inventory', 'ip_adapters', 'exclusion'])
@pytest.mark.parametrize('status,error', [(401, NotAuthenticatedError), (429, RateLimitError)])
async def test_optional_auth_and_throttle_errors_still_stop(local, network, source, status, error):
    _, extras = device_routes(network)
    extras[source].respond(status, headers={'Retry-After': '30'})
    client = create_client(local[0])
    try:
        with pytest.raises(error):
            await client.get_device(DEVICE)
    finally:
        await client.close()
    order = list(extras)
    assert all(not extras[name].called for name in order[order.index(source) + 1:])


@pytest.mark.parametrize('target', [DEVICE, 'synthetic.invalid'])
def test_device_show_reads_detail_and_enrichments_once(local, network, target):
    detail, extras = device_routes(network)
    result = CliRunner().invoke(app, ['device', 'show', target])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)['data']['id'] == DEVICE
    assert detail.call_count == 1
    assert extras['inventory'].call_count == (1 if target == DEVICE else 2)
    assert extras['ip_adapters'].call_count == extras['exclusion'].call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('target', [DEVICE, 'synthetic.invalid'])
async def test_timeline_resolution_omits_optional_enrichments(local, network, target):
    detail, extras = device_routes(network)
    client = create_client(local[0])
    try:
        assert await _resolve_machine_id(client, target, verify_exact=True) == DEVICE
    finally:
        await client.close()
    assert detail.call_count == 1
    assert extras['inventory'].call_count == (0 if target == DEVICE else 1)
    assert not extras['ip_adapters'].called and not extras['exclusion'].called


@pytest.mark.parametrize('backend', ['official', 'portal-cookie'])
@pytest.mark.parametrize('binding', [None, 'another-tenant-fingerprint'])
def test_status_diagnoses_rejected_cookie_binding(local, monkeypatch, backend, binding):
    _, home = local
    path = home / 'portal_cookies.json'
    stored = json.loads(path.read_text())
    stored.pop('tenant_fingerprint')
    if binding is not None:
        stored['tenant_fingerprint'] = binding
    path.write_text(json.dumps(stored))
    official_identity(monkeypatch)
    result = CliRunner().invoke(app, ['--backend', backend, 'auth', 'status'])
    assert result.exit_code == 0, result.output
    portal = json.loads(result.stdout)['data']['portal']
    assert portal['cookie_stored'] is False
    assert portal['cookie_error']['code'] == 'PORTAL_COOKIE_TENANT_MISMATCH'
    assert 'synthetic-secret' not in result.output and 'synthetic-xsrf' not in result.output
    with pytest.raises(ConfigError):  # operational use remains fail closed
        load_portal_cookies('test-tenant')


@pytest.mark.parametrize('command,flag', [('scan', '--scan-type'), ('isolate', '--type')])
def test_invalid_action_mode_fails_before_confirmation_or_network(
    local, monkeypatch, command, flag,
):
    confirm = Mock(side_effect=AssertionError('Must reject before confirmation'))
    client = Mock(side_effect=AssertionError('No API allowed'))
    monkeypatch.setattr('xdr_cli.commands.device_cmd._confirm_action', confirm)
    monkeypatch.setattr('xdr_cli.commands.device_cmd._get_client', client)
    result = CliRunner().invoke(app, [
        'device', command, DEVICE, flag, 'wrong', '--comment', 'test',
    ])
    assert result.exit_code == 6, result.output
    assert '--backend official' not in result.output
    confirm.assert_not_called()
    client.assert_not_called()


@pytest.mark.parametrize('command,flag,key,value,canonical', [
    ('scan', '--scan-type', 'scan_type', 'full', 'Full'),
    ('scan', '--scan-type', 'scan_type', 'qUiCk', 'Quick'),
    ('isolate', '--type', 'isolation_type', 'full', 'Full'),
    ('isolate', '--type', 'isolation_type', 'sElEcTiVe', 'Selective'),
])
def test_action_modes_are_canonical_before_dispatch(
    local, monkeypatch, command, flag, key, value, canonical,
):
    action = AsyncMock()
    monkeypatch.setattr('xdr_cli.commands.device_cmd._device_action', action)
    result = CliRunner().invoke(app, [
        'device', command, DEVICE, flag, value, '--comment', 'test', '--yes',
    ])
    assert result.exit_code == 0, result.output
    assert action.await_args.kwargs[key] == canonical


@pytest.mark.parametrize('command', ['logout', 'portal-logout'])
def test_portal_logout_clears_cookies_but_preserves_official(local, command):
    _, home = local
    (home / 'token_cache.json').write_text('{"synthetic": "official"}')
    for first in (True, False):
        result = CliRunner().invoke(app, ['--backend', 'portal-cookie', 'auth', command])
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)['data']
        assert data['cookie_cleared'] is first
        assert 'token_cache_cleared' not in data
        assert not (home / 'portal_cookies.json').exists()
        assert (home / 'token_cache.json').read_text() == '{"synthetic": "official"}'


def invalid_backend_with_both_credentials(home):
    (home / 'config.toml').write_text(
        'tenant_id = "test-tenant"\nclient_id = "test-app"\n'
        'auth_mode = "client_credentials"\nclient_secret = "synthetic-only"\n'
        'api_backend = "portal_cookie"\n'
    )


@pytest.mark.parametrize('argv', [
    ['device', action, DEVICE, '--comment', 'test', '--yes']
    for action in ('isolate', 'unisolate', 'scan', 'collect-package', 'restrict', 'unrestrict')
] + [['incidents', 'update', '1', '--status', 'active', '--yes'],
     ['incidents', 'update', '1', '--comment', 'test', '--yes']])
def test_recovered_backend_cannot_authorize_tenant_writes(local, monkeypatch, network, argv):
    invalid_backend_with_both_credentials(local[1])
    device = AsyncMock()
    incident = AsyncMock()
    confirmation = Mock(side_effect=AssertionError('Must reject before confirmation'))
    monkeypatch.setattr('xdr_cli.commands.device_cmd._device_action', device)
    monkeypatch.setattr('xdr_cli.commands.incidents_cmd._update', incident)
    monkeypatch.setattr('xdr_cli.commands.device_cmd._confirm_action', confirmation)
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == 4, result.output
    error = json.loads(result.stdout)['error']
    assert 'explicit --backend' in error['message']
    assert error['retryable'] is False
    device.assert_not_awaited()
    incident.assert_not_awaited()
    confirmation.assert_not_called()
    assert not network.calls


@pytest.mark.parametrize('override,expected', [
    ('official', 'official'), ('portal-cookie', 'portal-cookie'), ('auto', 'official'),
])
def test_explicit_backend_allows_write_despite_invalid_saved_preference(
    local, monkeypatch, override, expected,
):
    invalid_backend_with_both_credentials(local[1])
    action = AsyncMock()
    monkeypatch.setattr('xdr_cli.commands.device_cmd._device_action', action)
    result = CliRunner().invoke(app, [
        '--backend', override, 'device', 'isolate', DEVICE, '--comment', 'test', '--yes',
    ])
    assert result.exit_code == 0, result.output
    assert action.await_args.args[0].config.api_backend == expected
    assert 'portal_cookie' in (local[1] / 'config.toml').read_text()


@pytest.mark.parametrize('argv', [
    ['device', 'isolate', DEVICE, '--comment', 'test', '--dry-run'],
    ['incidents', 'update', '1', '--status', 'active', '--dry-run'],
])
def test_recovered_backend_allows_local_dry_run(local, network, argv):
    invalid_backend_with_both_credentials(local[1])
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)['data']['dry_run'] is True
    assert not network.calls


def test_config_save_during_auth_recovery_does_not_enable_future_writes(local, monkeypatch):
    invalid_backend_with_both_credentials(local[1])
    official_identity(monkeypatch)
    result = CliRunner().invoke(app, ['auth', 'login'])
    assert result.exit_code == 0, result.output
    config = load_config()
    assert config.api_backend == 'auto'
    with pytest.raises(ConfigError, match='Tenant writes'):
        config.check_mutation_backend()
    assert 'portal_cookie' in (local[1] / 'config.toml').read_text()
    # Editing the actual preference restores ordinary write dispatch.
    config = Config(tenant_id='test-tenant', api_backend='portal-cookie')
    save_config(config)
    load_config().check_mutation_backend()


@pytest.mark.parametrize('operation,exit_code,retryable', [
    ('incident', 10, False), ('comment', 14, False), ('device', 10, False),
    ('read', 10, True), ('hunt', 10, True),
])
def test_portal_timeout_retryability_at_cli_boundary(
    local, network, operation, exit_code, retryable,
):
    endpoint = BASE + 'msgraph/v1.0/security/incidents/1'
    if operation == 'incident':
        route = network.patch(endpoint)
        argv = ['incidents', 'update', '1', '--status', 'active', '--yes']
    elif operation == 'comment':
        network.get(endpoint).respond(json={'id': '1'})
        route = network.post(endpoint + '/comments')
        argv = ['incidents', 'update', '1', '--comment', 'test', '--yes']
    elif operation == 'device':
        network.get(DETAIL).respond(json={
            'SenseMachineId': DEVICE, 'OsPlatform': 'Windows11', 'SenseClientVersion': '1.2.3',
        })
        route = network.post(BASE + 'mtp/responseApiPortal/requests/create')
        argv = ['device', 'isolate', DEVICE, '--comment', 'test', '--yes']
    elif operation == 'hunt':
        route = network.post(BASE + 'hunting/huntingQueryExecutorService/queryExecutor/v1/external')
        argv = ['hunt', 'run', 'print value=1']
    else:
        route = network.get(endpoint)
        argv = ['incidents', 'show', '1']
    route.mock(side_effect=httpx.ReadTimeout('synthetic timeout'))
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == exit_code, result.output
    error = json.loads(result.stdout.splitlines()[-1])['error']
    assert error['retryable'] is retryable
    if operation in ('incident', 'device'):
        assert 'Outcome unknown' in error['message']
    assert route.call_count == 1
