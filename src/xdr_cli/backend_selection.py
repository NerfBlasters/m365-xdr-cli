"""Local credential selection; never retry an operation under another identity."""
from __future__ import annotations

import json
from pathlib import Path

from xdr_cli.config import Config, get_config_home
from xdr_cli.portal_auth import PORTAL_COOKIE_FILENAME, tenant_fingerprint


def _read_object(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('Expected a credential object')
    return value


def _same(left: object, right: str) -> bool:
    return isinstance(left, str) and left.casefold() == right.casefold()


def _has_official_credentials(config: Config) -> bool:
    if not config.tenant_id or not config.client_id:
        return False
    if config.auth_mode == 'client_credentials' and config.client_secret:
        return True
    try:
        cache = _read_object(get_config_home() / 'token_cache.json')
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        # A damaged/unreadable cache is not permission to change auth methods.
        return True
    accounts = cache.get('Account', {})
    if not isinstance(accounts, dict):
        return True
    account_ids = {
        row['home_account_id'] for row in accounts.values()
        if isinstance(row, dict) and _same(row.get('realm'), config.tenant_id)
        and isinstance(row.get('home_account_id'), str)
    }
    for kind in ('AccessToken', 'RefreshToken'):
        entries = cache.get(kind, {})
        if not isinstance(entries, dict):
            return True
        for entry in entries.values():
            if not isinstance(entry, dict):
                return True
            if (not _same(entry.get('client_id'), config.client_id)
                    or not isinstance(entry.get('secret'), str) or not entry['secret']):
                continue
            if _same(entry.get('realm'), config.tenant_id):
                return True
            # MSAL refresh records may omit realm; bind through their account.
            if (kind == 'RefreshToken' and not entry.get('realm')
                    and isinstance(entry.get('home_account_id'), str)
                    and entry['home_account_id'] in account_ids):
                return True
    return False


def _has_portal_credentials(config: Config) -> bool:
    if not config.tenant_id:
        return False
    try:
        cookies = _read_object(get_config_home() / PORTAL_COOKIE_FILENAME)
    except (OSError, ValueError):
        return False
    if cookies.get('tenant_fingerprint') != tenant_fingerprint(config.tenant_id):
        return False
    xsrf = cookies.get('xsrf_token')
    header = cookies.get('cookie_header')
    if not isinstance(xsrf, str) or not xsrf.strip():
        return False
    if not isinstance(header, str):
        return False
    values = {}
    for pair in header.split(';'):
        name, separator, value = pair.strip().partition('=')
        if separator:
            values[name.lower()] = value
    auth = values.get('sccauth', '')
    if not auth:
        return False
    if auth.startswith('chunks:'):
        try:
            count = int(auth.removeprefix('chunks:'))
        except ValueError:
            return False
        return 1 <= count <= 100 and all(values.get(f'sccauthc{i}') for i in range(1, count + 1))
    return True


def select_backend(config: Config, preference: str | None = None) -> str:
    """Select from local presence, without checking remote token/cookie validity."""
    preference = config.api_backend if preference is None else preference
    if preference in ('official', 'portal-cookie'):
        return preference
    if preference != 'auto':
        from xdr_cli.exceptions import ConfigError

        raise ConfigError('api_backend must be auto, official, or portal-cookie.')
    if _has_official_credentials(config):
        return 'official'
    return 'portal-cookie' if _has_portal_credentials(config) else 'official'
