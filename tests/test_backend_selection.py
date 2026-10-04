"""Automatic selection is local, tenant/app bound, and never an error retry."""
import json
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from xdr_cli.backend_selection import select_backend
from xdr_cli.backends import PortalBackend, create_client
from xdr_cli.client import APISurface, XDRClient
from xdr_cli.config import Config, load_config, save_config
from xdr_cli.exceptions import NotAuthenticatedError
from xdr_cli.main import app
from xdr_cli.portal_auth import save_portal_cookies, tenant_fingerprint


@pytest.fixture
def selection(tmp_path, monkeypatch):
    monkeypatch.setenv('XDR_CLI_HOME', str(tmp_path))
    config = Config(tenant_id='tenant-one', client_id='app-one')
    save_config(config)
    save_portal_cookies({
        'tenant_fingerprint': tenant_fingerprint(config.tenant_id),
        'cookie_header': 'sccauth=synthetic; XSRF-TOKEN=synthetic', 'xsrf_token': 'synthetic',
    })
    return config, tmp_path


def write_cache(home, **entries):
    (home / 'token_cache.json').write_text(json.dumps(entries))


def test_cookie_only_default_never_constructs_msal(selection, monkeypatch):
    config, _ = selection
    assert config.api_backend == 'auto'
    assert select_backend(config) == 'portal-cookie'
    auth = Mock(side_effect=AssertionError('No MSAL'))
    monkeypatch.setattr('xdr_cli.commands.auth_cmd.AuthManager', auth)
    monkeypatch.setattr('xdr_cli.commands.auth_cmd.PortalAuth', auth)
    result = CliRunner().invoke(app, ['auth', 'status'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)['data']['backend'] == 'portal-cookie'
    auth.assert_not_called()
    assert load_config().api_backend == 'auto'


@pytest.mark.parametrize('kind,extra', [
    ('AccessToken', {'realm': 'TENANT-ONE', 'expires_on': '1'}),
    ('RefreshToken', {'realm': 'tenant-one'}),
    ('RefreshToken', {'home_account_id': 'account-one'}),
])
def test_expired_access_and_refresh_tokens_keep_official_precedence(selection, kind, extra):
    config, home = selection
    write_cache(home, **{
        'Account': {'one': {'realm': 'tenant-one', 'home_account_id': 'account-one'}},
        kind: {'one': {'client_id': 'APP-ONE', 'secret': 'synthetic', **extra}},
    })
    assert select_backend(config) == 'official'


@pytest.mark.parametrize('entry', [
    {'client_id': 'other-app', 'realm': 'tenant-one', 'secret': 'synthetic'},
    {'client_id': 'app-one', 'realm': 'other-tenant', 'secret': 'synthetic'},
    {'client_id': 'app-one', 'realm': 'tenant-one', 'secret': ''},
])
def test_unrelated_or_empty_msal_token_does_not_block_cookie(selection, entry):
    config, home = selection
    write_cache(home, AccessToken={'one': entry})
    assert select_backend(config) == 'portal-cookie'


def test_refresh_token_cannot_borrow_another_tenants_account(selection):
    config, home = selection
    write_cache(home, Account={'one': {'realm': 'other', 'home_account_id': 'account-one'}},
                RefreshToken={'one': {'client_id': 'app-one', 'secret': 'synthetic',
                                      'home_account_id': 'account-one'}})
    assert select_backend(config) == 'portal-cookie'


def test_app_secret_without_cache_prefers_official(selection):
    config, _ = selection
    config.auth_mode = 'client_credentials'
    config.client_secret = 'synthetic'
    assert select_backend(config) == 'official'


@pytest.mark.parametrize('cache', ['bad-json', '[]', '{"AccessToken": []}'])
def test_broken_msal_cache_is_not_absence(selection, cache):
    config, home = selection
    (home / 'token_cache.json').write_text(cache)
    assert select_backend(config) == 'official'


def test_empty_cache_is_absence(selection):
    config, home = selection
    write_cache(home)
    assert select_backend(config) == 'portal-cookie'


@pytest.mark.parametrize('backend', ['official', 'portal-cookie'])
def test_explicit_backend_wins(selection, backend):
    config, _ = selection
    config.api_backend = backend
    assert select_backend(config) == backend
    assert select_backend(config, 'official') == 'official'
    assert select_backend(config, 'portal-cookie') == 'portal-cookie'


@pytest.mark.parametrize('update', [
    {'tenant_fingerprint': tenant_fingerprint('other-tenant')}, {'xsrf_token': ''},
    {'cookie_header': 'sccauth=chunks:2; sccauthC1=one'},
    {'cookie_header': 'sccauth=chunks:not-an-int'}, {'cookie_header': 'other=value'},
])
def test_unusable_or_cross_tenant_cookie_does_not_select_portal(selection, update):
    config, home = selection
    path = home / 'portal_cookies.json'
    data = json.loads(path.read_text())
    data.update(update)
    path.write_text(json.dumps(data))
    assert select_backend(config) == 'official'


def test_chunked_cookie_is_selected(selection):
    config, home = selection
    path = home / 'portal_cookies.json'
    data = json.loads(path.read_text())
    data['cookie_header'] = 'sccauth=chunks:2; sccauthC1=one; sccauthC2=two'
    path.write_text(json.dumps(data))
    assert select_backend(config) == 'portal-cookie'


@pytest.mark.asyncio
async def test_factory_auto_cookie_skips_msal(selection):
    config, _ = selection
    client = create_client(config, auth_factory=Mock(side_effect=AssertionError('No MSAL')))
    try:
        assert isinstance(client, PortalBackend)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_auth_failure_does_not_switch_backends(selection, monkeypatch):
    config, home = selection
    write_cache(home, AccessToken={'one': {
        'client_id': 'app-one', 'realm': 'tenant-one', 'secret': 'synthetic',
    }})
    portal = Mock(side_effect=AssertionError('No fallback after failure'))
    monkeypatch.setattr('xdr_cli.backends.PortalBackend', portal)
    auth = Mock(return_value=Mock(get_token=Mock(side_effect=NotAuthenticatedError())))
    client = create_client(config, auth_factory=auth)
    try:
        assert isinstance(client, XDRClient)
        with pytest.raises(NotAuthenticatedError):
            await client.get(APISurface.GRAPH_CORE, 'domains')
    finally:
        await client.close()
    portal.assert_not_called()


def test_auto_cookie_does_not_prevent_official_login_or_persist_resolution(selection, monkeypatch):
    _, _home = selection
    manager = Mock()
    manager.get_auth_status.return_value = {'authenticated': True, 'configured': True}
    monkeypatch.setattr('xdr_cli.commands.auth_cmd.AuthManager', Mock(return_value=manager))
    result = CliRunner().invoke(app, ['auth', 'login'])
    assert result.exit_code == 0, result.output
    manager.login.assert_called_once()
    assert load_config().api_backend == 'auto'


def test_explicit_official_login_override_does_not_rewrite_cookie_preference(
    selection, monkeypatch,
):
    config, _ = selection
    config.api_backend = 'portal-cookie'
    save_config(config)
    manager = Mock()
    manager.get_auth_status.return_value = {'authenticated': True, 'configured': True}
    monkeypatch.setattr('xdr_cli.commands.auth_cmd.AuthManager', Mock(return_value=manager))
    result = CliRunner().invoke(app, ['--backend', 'official', 'auth', 'login'])
    assert result.exit_code == 0, result.output
    assert load_config().api_backend == 'portal-cookie'


def test_cookie_only_session_uses_no_msal_identity(selection, monkeypatch):
    from xdr_cli.sessions import current_session

    forbidden = Mock(side_effect=AssertionError('No MSAL identity'))
    monkeypatch.setattr('xdr_cli.commands.session_cmd.resolve_operator_upn', forbidden)
    result = CliRunner().invoke(app, ['session', 'start'])
    assert result.exit_code == 0, result.output
    assert current_session().upn == 'automatic'
    forbidden.assert_not_called()


def test_cookie_only_logout_removes_cookie_without_persisting_selection(selection):
    _, home = selection
    result = CliRunner().invoke(app, ['auth', 'logout'])
    assert result.exit_code == 0, result.output
    assert not (home / 'portal_cookies.json').exists()
    assert load_config().api_backend == 'auto'
