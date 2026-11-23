"""Cloud boundaries must hold before any credentials leave the client."""
from unittest.mock import Mock, patch

import httpx
import pytest
import respx
from click.testing import CliRunner

from xdr_cli.auth import AuthManager
from xdr_cli.backend_selection import select_backend
from xdr_cli.backends import PortalBackend, create_client
from xdr_cli.client import APISurface, XDRClient
from xdr_cli.cloud import PROFILES
from xdr_cli.config import Config, load_config, save_config
from xdr_cli.exceptions import APIError, ConfigError
from xdr_cli.main import app
from xdr_cli.portal_auth import load_portal_cookies, save_portal_cookies
from xdr_cli.portal_client import CookieAuth, PortalClient, RefreshTokenAuth
from xdr_cli.results import tenant_fingerprint


@pytest.fixture(autouse=True)
def private_home(tmp_path, monkeypatch):
    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))


def test_cloud_config_and_cli():
    save_config(Config(cloud='gcc-high'))
    assert load_config().cloud == 'gcc-high'
    with pytest.raises(ConfigError):
        Config(cloud='unknown')
    assert CliRunner().invoke(app, ['--cloud', 'unknown', 'auth', 'status']).exit_code == 6


@pytest.mark.parametrize('cloud', PROFILES)
def test_authority_and_login_scopes(cloud):
    config = Config(cloud=cloud, tenant_id='test-tenant', client_id='test-client')
    manager = AuthManager(config)
    with patch('xdr_cli.auth.msal.PublicClientApplication') as factory:
        manager._get_app()
        assert factory.call_args.kwargs['authority'] == (
            config.cloud_profile.authority + '/test-tenant')
    fake = Mock()
    fake.acquire_token_interactive.side_effect = RuntimeError('headless')
    fake.initiate_device_flow.return_value = {'user_code': 'test-code', 'verification_uri': 'test'}
    fake.acquire_token_by_device_flow.return_value = {'access_token': 'synthetic'}
    manager._app = fake
    with patch.object(manager, "_get_app", return_value=fake):
        manager.login()
    assert fake.initiate_device_flow.call_args.kwargs['scopes'] == config.cloud_profile.graph_scopes


@pytest.mark.parametrize('cloud', PROFILES)
@respx.mock
async def test_official_surfaces_and_pagination(cloud):
    profile = PROFILES[cloud]
    tokens = Mock(return_value='synthetic')
    transport = XDRClient(tokens, cloud=cloud)
    for surface, path in [(APISurface.GRAPH, 'incidents'), (APISurface.GRAPH, 'alerts_v2'),
                          (APISurface.GRAPH_CORE, 'domains'), (APISurface.MDE, 'machines')]:
        url = transport.base_url(surface) + path
        respx.get(url).respond(json={'value': [{'id': '1'}], '@odata.nextLink': url + '?$skip=1'})
        respx.get(url + '?$skip=1').respond(json={'value': [{'id': '2'}]})
        assert len([v async for v in transport.paginate(surface, path)]) == 2
        assert tokens.call_args.args[0] == (
            profile.mde_scopes if surface == APISurface.MDE else profile.graph_scopes)
    await transport.close()


@pytest.mark.parametrize('link', [
    'https://graph.microsoft.com/v1.0/security/incidents?$skip=1',
    'http://graph.microsoft.us/v1.0/security/incidents?$skip=1',
    'https://graph.microsoft.us:444/v1.0/security/incidents?$skip=1',
    'https://example.invalid/v1.0/security/incidents?$skip=1',
    'https://graph.microsoft.us/v1.0/users?$skip=1',
])
@respx.mock
async def test_reject_unsafe_continuation(link):
    client = XDRClient(lambda _: 'synthetic', cloud='gcc-high')
    respx.get('https://graph.microsoft.us/v1.0/security/incidents').respond(
        json={'value': [], '@odata.nextLink': link})
    with pytest.raises(APIError):
        [v async for v in client.paginate(APISurface.GRAPH, 'incidents')]
    assert len(respx.calls) == 1
    await client.close()


def test_cloud_cache_and_cookie_isolation(tmp_path):
    gov = Config(cloud='gcc-high', tenant_id='test-tenant', client_id='test-client')
    commercial = Config(tenant_id='test-tenant', client_id='test-client')
    assert AuthManager(gov)._cache_path() != AuthManager(commercial)._cache_path()
    data = {'tenant_fingerprint': tenant_fingerprint(gov.tenant_id),
            'cookie_header': 'sccauth=synthetic', 'xsrf_token': 'synthetic'}
    save_portal_cookies(data)
    assert select_backend(commercial) == 'portal-cookie'
    assert select_backend(gov) == 'official'
    with pytest.raises(ConfigError):
        load_portal_cookies(gov.tenant_id, gov.cloud)
    save_portal_cookies({**data, 'cloud': 'gcc-high'})
    assert select_backend(gov) == 'portal-cookie'
    assert select_backend(commercial) == 'official'


@respx.mock
async def test_gov_hunting_fallback():
    config = Config(cloud='gcc-high', tenant_id='test-tenant', client_id='test-client')
    backend = create_client(config, auth_factory=lambda _: Mock(get_token=lambda _: 'synthetic'))
    respx.post('https://graph.microsoft.us/v1.0/security/runHuntingQuery').respond(status_code=404)
    respx.post('https://api-gov.securitycenter.microsoft.us/api/advancedqueries/run').respond(
        json={'Results': [], 'Schema': []})
    result = await backend.execute_hunting('synthetic query')
    assert result.metadata['execution_surface'] == 'mde'
    await backend.close()


@respx.mock
async def test_gov_portal_origin_and_refresh():
    auth = RefreshTokenAuth('test-tenant', 'synthetic', cloud='gcc-high')
    token = respx.post('https://login.microsoftonline.us/test-tenant/oauth2/v2.0/token').respond(
        json={'access_token': 'synthetic'})
    client = PortalClient(auth, cloud='gcc-high')
    route = respx.get('https://security.microsoft.us/apiproxy/mtp/ndr/machines').respond(json={})
    await client.probe('ndr/machines')
    assert token.called
    assert route.calls[0].request.headers['Origin'] == 'https://security.microsoft.us'
    with pytest.raises(APIError):
        await client.probe('https://security.microsoft.com/apiproxy/mtp/ndr/machines')
    await client.close()


@pytest.mark.parametrize('cloud', PROFILES)
@respx.mock
async def test_portal_backend_cloud_pagination(cloud):
    profile = PROFILES[cloud]
    config = Config(cloud=cloud, tenant_id='test-tenant')
    save_portal_cookies({'tenant_fingerprint': tenant_fingerprint(config.tenant_id),
                         'cloud': cloud, 'cookie_header': 'sccauth=synthetic',
                         'xsrf_token': 'synthetic'})
    backend = PortalBackend(config, 30)
    # The verification call is independently covered by backend tests.
    backend._verified = True
    url = profile.portal + '/apiproxy/msgraph/v1.0/domains'
    respx.get(url).respond(json={'value': [{'id': 'first'}],
                                '@odata.nextLink': profile.graph + '/v1.0/domains?$skip=1'})
    route = respx.get(url + '?$skip=1').respond(json={'value': [{'id': 'second'}]})
    assert len([v async for v in backend.iter_domains()]) == 2
    assert route.calls[0].request.headers['Origin'] == profile.portal
    await backend.close()


def test_login_saves_cloud():
    with patch('xdr_cli.commands.auth_cmd.AuthManager') as manager:
        manager.return_value.get_auth_status.return_value = {'authenticated': True}
        result = CliRunner().invoke(app, ['--cloud', 'gcc-high', '--backend', 'official',
                                         'auth', 'login', '--tenant-id', 'test-tenant',
                                         '--client-id', 'test-client'])
    assert result.exit_code == 0, result.output
    assert load_config().cloud == 'gcc-high'
