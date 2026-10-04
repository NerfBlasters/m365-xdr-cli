"""Backend-neutral dispatch and shared continuation trust boundaries."""
import inspect
from unittest.mock import AsyncMock, create_autospec

import pytest

from xdr_cli.api import alerts, devices, domains, hunting, incidents
from xdr_cli.backend_contract import Backend, UnsupportedBackendCapability
from xdr_cli.backends import PortalBackend
from xdr_cli.continuation import validate_continuation
from xdr_cli.exceptions import APIError, UsageError
from xdr_cli.hunting_result import HuntingResult
from xdr_cli.official_backend import OfficialBackend


@pytest.mark.asyncio
@pytest.mark.parametrize('helper,method,args,kwargs,backend_args,backend_kwargs', [
    (alerts.get_alert, 'get_alert', ('alert-1',), {}, ('alert-1',), {}),
    (incidents.get_incident, 'get_incident', ('1',), {'expand': ['alerts']},
     ('1',), {'expand': ['alerts']}),
    (incidents.update_incident, 'update_incident', ('1', {'status': 'active'}), {},
     ('1', {'status': 'active'}), {}),
    (incidents.add_incident_comment, 'add_incident_comment', ('1', 'comment'), {},
     ('1', 'comment'), {}),
    (devices.get_device, 'get_device', ('device',), {'enrich': False},
     ('device',), {'enrich': False}),
    (devices.find_device_by_hostname, 'find_device_by_hostname', ('host.invalid',), {},
     ('host.invalid',), {'enrich': True}),
    (devices.get_action_status, 'get_action_status', ('action',), {'device_id': 'device'},
     ('action', 'device'), {}),
    (devices.isolate_device, 'submit_device_action', ('device',),
     {'isolation_type': 'Selective', 'comment': 'test'},
     ('device', 'isolate'), {'mode': 'Selective', 'comment': 'test'}),
    (devices.unisolate_device, 'submit_device_action', ('device',), {'comment': 'test'},
     ('device', 'unisolate'), {'comment': 'test'}),
    (devices.run_av_scan, 'submit_device_action', ('device',),
     {'scan_type': 'Full', 'comment': 'test'},
     ('device', 'scan'), {'mode': 'Full', 'comment': 'test'}),
    (devices.collect_investigation_package, 'submit_device_action', ('device',),
     {'comment': 'test'}, ('device', 'collect-package'), {'comment': 'test'}),
    (devices.restrict_code_execution, 'submit_device_action', ('device',), {'comment': 'test'},
     ('device', 'restrict'), {'comment': 'test'}),
    (devices.unrestrict_code_execution, 'submit_device_action', ('device',), {'comment': 'test'},
     ('device', 'unrestrict'), {'comment': 'test'}),
    (hunting.run_query, 'execute_hunting', ('print value=1',), {}, ('print value=1',), {}),
])
async def test_helpers_use_named_contract_without_concrete_backend_or_transport(
    helper, method, args, kwargs, backend_args, backend_kwargs,
):
    backend = create_autospec(Backend, instance=True, spec_set=True)
    assert not isinstance(backend, (PortalBackend, OfficialBackend))
    assert not hasattr(backend, 'get') and not hasattr(backend, 'post')
    result = (HuntingResult([], [], {}) if helper is hunting.run_query
              else {'id': 'synthetic', 'native': {'preserved': True}})
    getattr(backend, method).return_value = result
    assert await helper(backend, *args, **kwargs) is result
    getattr(backend, method).assert_awaited_once_with(*backend_args, **backend_kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize('helper,method', [
    (alerts.list_alerts, 'list_alerts'), (incidents.list_incidents, 'list_incidents'),
    (domains.iter_domains, 'iter_domains'), (domains.list_domains, 'iter_domains'),
])
async def test_collection_helpers_use_only_named_contract(helper, method):
    backend = create_autospec(Backend, instance=True, spec_set=True)
    rows = [{'id': 'first'}, {'id': 'second'}]

    async def collection():
        for row in rows:
            yield row

    getattr(backend, method).return_value = collection()
    kwargs = ({'odata_filter': "severity eq 'high'", 'top': 3, 'limit': 5}
              if method != 'iter_domains' else {})
    if helper is domains.list_domains:
        actual = await helper(backend, **kwargs)
    else:
        actual = [row async for row in helper(backend, **kwargs)]
    assert actual == rows
    if kwargs:
        getattr(backend, method).assert_called_once_with(params={
            '$top': 3, '$orderby': 'createdDateTime desc', '$filter': "severity eq 'high'",
        }, limit=5)
    else:
        getattr(backend, method).assert_called_once_with()


@pytest.mark.parametrize('concrete', [OfficialBackend, PortalBackend])
def test_concrete_backends_must_implement_every_required_operation(concrete):
    assert issubclass(concrete, Backend)
    assert not inspect.isabstract(concrete)
    # A missing implementation fails before auth/transport construction.
    incomplete = type('IncompleteBackend', (concrete,), {'get_alert': Backend.get_alert})
    with pytest.raises(TypeError, match='abstract'):
        incomplete(None, None)


@pytest.mark.asyncio
async def test_official_optional_capabilities_are_explicit_and_local():
    transport = AsyncMock()
    backend = OfficialBackend(transport)
    assert not backend.profile.ad_domains and not backend.profile.package_download
    for operation in (backend.read_ad_domains, backend.count_ad_domains):
        with pytest.raises(UnsupportedBackendCapability) as error:
            await operation()
        assert error.value.error_code == 'BACKEND_CAPABILITY_UNAVAILABLE'
    with pytest.raises(UsageError, match='portal-cookie'):
        await backend.get_package_download_url('action', 'device')
    assert transport.mock_calls == []


@pytest.mark.parametrize('link', [
    'https://example.invalid/v1.0/domains?$skiptoken=a',
    'https://graph.microsoft.com/v1.0/users?$skiptoken=a',
    'http://graph.microsoft.com/v1.0/domains?$skiptoken=a',
    'https://graph.microsoft.com:444/v1.0/domains?$skiptoken=a',
    'https://user:password@graph.microsoft.com/v1.0/domains?$skiptoken=a',
    'https://graph.microsoft.com/v1.0/domains?$skiptoken=a#fragment',
    'https://graph.microsoft.com/v1.0/domains',
    '/v1.0/domains?$skiptoken=a',
    'https://[invalid',
    123,
])
def test_continuation_rejects_foreign_or_malformed_urls(link):
    seen = set()
    with pytest.raises(APIError):
        validate_continuation(
            link, routes=frozenset({('graph.microsoft.com', '/v1.0/domains')}), seen=seen,
        )
    assert not seen


@pytest.mark.parametrize('host,path', [
    ('graph.microsoft.com', '/v1.0/domains'),
    ('security.microsoft.com', '/apiproxy/msgraph/v1.0/domains'),
])
def test_continuation_preserves_raw_query_and_rejects_repeats(host, path):
    link = f'https://{host}{path}?$skiptoken=aB+cD/eF==&$filter=a%20eq%20b'
    seen = set()
    result = validate_continuation(link, routes=frozenset({(host, path)}), seen=seen)
    assert result.query == b'$skiptoken=aB+cD/eF==&$filter=a%20eq%20b'
    with pytest.raises(APIError, match='invalid continuation'):
        validate_continuation(link, routes=frozenset({(host, path)}), seen=seen)


def test_continuation_does_not_mix_allowed_hosts_and_paths():
    with pytest.raises(APIError):
        validate_continuation(
            'https://security.microsoft.com/v1.0/domains?$skip=1',
            routes=frozenset({('graph.microsoft.com', '/v1.0/domains'),
                              ('security.microsoft.com', '/apiproxy/msgraph/v1.0/domains')}),
            seen=set(),
        )
