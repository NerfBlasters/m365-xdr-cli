"""Backend isolation and synthetic portal contracts; no tenant fixtures."""
import json
from unittest.mock import Mock

import httpx
import pytest
import respx
from typer.testing import CliRunner

from xdr_cli.api.hunting import run_query
from xdr_cli.backends import PortalBackend, create_client
from xdr_cli.config import Config
from xdr_cli.exceptions import (
    APIError, ConfigError, ForbiddenError, NotAuthenticatedError, QueryError, RateLimitError,
)
from xdr_cli.main import app
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

ORIGIN = "https://security.microsoft.com"
TENANT = ORIGIN + "/apiproxy/mtp/sccManagement/mgmt/TenantContext"
HUNT = ORIGIN + "/apiproxy/hunting/huntingQueryExecutorService/queryExecutor/v1/external"


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    save_portal_cookies({
        "tenant_fingerprint": tenant_fingerprint("test-tenant"),
        "cookie_header": "sccauth=synthetic; xsrf-token=synthetic",
        "xsrf_token": "synthetic",
    })
    return Config(tenant_id="test-tenant", api_backend="portal-cookie")


def success():
    return {
        "Schema": [{"Name": "value", "Type": "Int64"}], "Results": [{"value": 1}],
        "Quota": {"ExecutionTime": "00:00:00.001"},
        "EnhancedQueryStats": {"Statistics": {}},
    }


@pytest.mark.asyncio
@respx.mock
async def test_cookie_hunting_verifies_tenant_and_never_constructs_msal(config):
    auth = Mock(side_effect=AssertionError("MSAL must not be constructed"))
    client = create_client(config, auth_factory=auth)
    tenant = respx.get(TENANT).respond(200, json={"AuthInfo": {"TenantId": "TEST-TENANT"}})
    hunting = respx.post(HUNT).respond(200, json=success())
    try:
        result = await run_query(client, "print value=1")
        await run_query(client, "print value=1")
    finally:
        await client.close()
    assert result.results == [{"value": 1}]
    assert result.schema == [{"name": "value", "type": "Int64"}]
    assert result.stats["Quota"]["ExecutionTime"] == "00:00:00.001"
    assert tenant.call_count == 1
    assert hunting.call_count == 2
    auth.assert_not_called()
    request = hunting.calls[0].request
    assert "authorization" not in request.headers
    assert request.headers["x-xsrf-token"] == "synthetic"
    body = json.loads(request.content)
    assert body["QueryText"] == body["EncodedQueryText"] == "print value=1"
    assert body["StartTime"] is body["EndTime"] is None


@pytest.mark.asyncio
@respx.mock
async def test_remote_tenant_mismatch_stops_before_query(config):
    client = create_client(config)
    respx.get(TENANT).respond(200, json={"AuthInfo": {"TenantId": "other"}})
    query = respx.post(HUNT).respond(200, json=success())
    try:
        with pytest.raises(ConfigError):
            await run_query(client, "print value=1")
    finally:
        await client.close()
    assert not query.called


@pytest.mark.parametrize("status,error", [
    (401, NotAuthenticatedError), (440, NotAuthenticatedError),
    (302, NotAuthenticatedError), (403, ForbiddenError), (429, RateLimitError),
    (500, APIError),
])
@pytest.mark.asyncio
@respx.mock
async def test_error_classification_and_no_retries(config, status, error):
    client = create_client(config)
    route = respx.get(TENANT).respond(status, headers={
        "Location": "https://example.invalid/login", "Retry-After": "17",
    })
    try:
        with pytest.raises(error) as exc:
            await run_query(client, "print value=1")
        if status == 429:
            assert exc.value.retry_after_seconds == 17
    finally:
        await client.close()
    assert route.call_count == 1
    assert len(respx.calls) == 1


@pytest.mark.parametrize("response,error", [
    (httpx.Response(200, text="<html>Login</html>", headers={"Content-Type": "text/html"}),
     NotAuthenticatedError),
    (httpx.Response(200, text="invalid JSON"), APIError),
    (httpx.Response(200, json={"Results": []}), APIError),
    (httpx.Response(200, json={"error": {"message": "private data"}}), APIError),
    (httpx.Response(400, json={"message": "private data"}), QueryError),
])
@pytest.mark.asyncio
@respx.mock
async def test_bad_hunting_response_is_not_empty_success(config, response, error):
    client = create_client(config)
    respx.get(TENANT).respond(200, json={"AuthInfo": {"TenantId": config.tenant_id}})
    respx.post(HUNT).mock(return_value=response)
    try:
        with pytest.raises(error) as exc:
            await run_query(client, "print value=1")
        assert "private data" not in str(exc.value)
    finally:
        await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_unimplemented_operation_never_uses_official_api(config):
    client = create_client(config)
    try:
        # A portal backend exposes named operations, never a generic proxy.
        for verb in ("get", "post", "patch", "paginate"):
            assert not hasattr(client, verb)
    finally:
        await client.close()
    assert len(respx.calls) == 0


def test_official_factory_retains_token_provider():
    auth, client = Mock(), Mock()
    config = Config(tenant_id="test-tenant", client_id="test-client")
    backend = create_client(config, timeout=17, auth_factory=auth, client_factory=client)
    assert backend.transport is client.return_value
    auth.assert_called_once_with(config)
    client.assert_called_once_with(get_token=auth.return_value.get_token, timeout=17)


@respx.mock
def test_cli_cookie_backend_without_app_registration(config, tmp_path, monkeypatch):
    from pathlib import Path

    (tmp_path / "config.toml").write_text('tenant_id = "test-tenant"\n')
    monkeypatch.setattr("xdr_cli.commands.hunt_cmd.AuthManager", Mock(
        side_effect=AssertionError("MSAL must not be constructed"),
    ))
    respx.get(TENANT).respond(200, json={"AuthInfo": {"TenantId": "test-tenant"}})
    respx.post(HUNT).respond(200, json=success())
    result = CliRunner().invoke(app, ["--backend", "portal-cookie", "hunt", "run", "print value=1"])
    assert result.exit_code == 0, result.output
    receipt = json.loads(result.stdout.splitlines()[0])
    assert receipt["server_truncation_state"] == "unknown"
    assert Path(receipt["data_path"]).read_text().strip() == '{"value":1}'
    metadata = json.loads(Path(receipt["meta_path"]).read_text())
    assert metadata["api_backend"] == "portal-cookie"
    assert metadata["portal_query_stats"]["Quota"] == success()["Quota"]


def test_invalid_backend_rejected():
    with pytest.raises(ConfigError):
        Config(api_backend="typo")


def test_local_catalog_does_not_construct_backend(config, monkeypatch):
    monkeypatch.setattr("xdr_cli.backends.PortalBackend", Mock(
        side_effect=AssertionError("No client for local catalog"),
    ))
    result = CliRunner().invoke(app, ["--backend", "portal-cookie", "library", "show",
                                    "sys_schema_probe"])
    assert result.exit_code == 0, result.output


@pytest.mark.asyncio
@respx.mock
async def test_device_detail_verifies_exact_id_and_retains_source(config):
    from xdr_cli.api.devices import get_device

    client = create_client(config)
    respx.get(TENANT).respond(200, json={"AuthInfo": {"TenantId": config.tenant_id}})
    route = respx.get(ORIGIN + "/apiproxy/mtp/getMachine/machines").respond(200, json={
        "SenseMachineId": "a" * 40, "ComputerDnsName": "synthetic.invalid",
        "SenseClientVersion": "10.1.2.3", "ReleaseVersion": "test-release",
        "IsExcluded": False, "OsProcessor": "unmapped-portal-representation",
    })
    respx.get(ORIGIN + "/apiproxy/mtp/ndr/machines").respond(json=[])
    try:
        result = await get_device(client, "a" * 40)
        assert result["id"] == "a" * 40
        assert result["computerDnsName"] == "synthetic.invalid"
        assert result["agentVersion"] == "10.1.2.3"
        assert result["version"] == "test-release"
        assert result["isExcluded"] is False
        assert "osProcessor" not in result
        assert "osProcessor" not in result["portal_source"]
        assert result["portal_source"]["raw"]["OsProcessor"] == "unmapped-portal-representation"
        assert result["portal_source"]["field_parity"] == "partial"
        route.respond(200, json={"SenseMachineId": "b" * 40})
        with pytest.raises(APIError):
            await get_device(client, "a" * 40)
    finally:
        await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_timeline_id_resolution_needs_no_official_credentials(config):
    from xdr_cli.commands.device_cmd import _resolve_machine_id

    client = create_client(config, auth_factory=Mock(side_effect=AssertionError("MSAL")))
    respx.get(TENANT).respond(200, json={"AuthInfo": {"TenantId": config.tenant_id}})
    respx.get(ORIGIN + "/apiproxy/mtp/getMachine/machines").respond(200, json={
        "SenseMachineId": "a" * 40,
    })
    try:
        assert await _resolve_machine_id(client, "a" * 40, verify_exact=True) == "a" * 40
    finally:
        await client.close()


@pytest.mark.parametrize("path", [
    "https://example.invalid/path", "http://security.microsoft.com/apiproxy/mtp/path",
    "https://security.microsoft.com:444/apiproxy/mtp/path", "../../../outside",
])
@pytest.mark.asyncio
@respx.mock
async def test_legacy_timeline_never_forwards_cookies_outside_service(path):
    from xdr_cli.portal_client import CookieAuth, PortalClient

    client = PortalClient(CookieAuth(cookie_header="sccauth=synthetic"))
    try:
        with pytest.raises(APIError):
            await client.get(path)
    finally:
        await client.close()
    assert len(respx.calls) == 0


@respx.mock
def test_portal_auth_status_does_not_initialize_msal(config, monkeypatch):
    monkeypatch.setattr("xdr_cli.commands.auth_cmd.AuthManager", Mock(
        side_effect=AssertionError("MSAL"),
    ))
    monkeypatch.setattr("xdr_cli.main.load_config", lambda: config)
    result = CliRunner().invoke(app, ["auth", "status"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["data"]["portal"]["session_validity"] == "not_checked"
    assert len(respx.calls) == 0


@pytest.mark.asyncio
@respx.mock
async def test_portal_hunting_preserves_values_and_separates_schema_hints(config):
    # Source contract confirmed with table-free live comparisons. Both Graph
    # and portal represent KQL booleans as SByte integers; do not coerce them.
    columns = [
        {'Name': 'Large', 'Type': 'Int64', 'Entity': None},
        {'Name': 'Flag', 'Type': 'SByte', 'Entity': None},
        {'Name': 'Missing', 'Type': 'Object', 'Entity': None},
        {'Name': 'Nested', 'Type': 'Object', 'Entity': 'synthetic-hint'},
    ]
    row = {
        'Large': 9007199254740993, 'Flag': 1, 'Missing': None,
        'Nested': {'items': [1, None, 'text'], 'flag': True},
    }
    respx.get(TENANT).respond(200, json={'AuthInfo': {'TenantId': config.tenant_id}})
    respx.post(HUNT).respond(200, json={'Schema': columns, 'Results': [row]})
    client = create_client(config)
    try:
        result = await run_query(client, 'print synthetic=1')
    finally:
        await client.close()
    assert result.results == [row]
    assert type(result.results[0]['Large']) is int
    assert type(result.results[0]['Flag']) is int
    assert result.results[0]['Nested']['flag'] is True
    assert result.schema == [{'name': c['Name'], 'type': c['Type']} for c in columns]
    assert result.stats['PortalSchema'] == columns


@pytest.mark.parametrize("saved_backend", ["official", "portal-cookie"])
def test_cookie_session_start_avoids_official_identity(config, monkeypatch, saved_backend):
    from xdr_cli.sessions import current_session

    config.api_backend = saved_backend
    monkeypatch.setattr("xdr_cli.main.load_config", lambda: config)
    official_identity = Mock(side_effect=AssertionError("must not use MSAL identity"))
    monkeypatch.setattr("xdr_cli.commands.session_cmd.resolve_operator_upn", official_identity)
    monkeypatch.setattr("xdr_cli.sessions.resolve_operator_upn", official_identity)
    result = CliRunner().invoke(app, ["--backend", "portal-cookie", "session", "start"])
    assert result.exit_code == 0, result.output
    assert current_session().upn == "automatic"
    official_identity.assert_not_called()


def test_cookie_automatic_session_and_rotation_avoid_msal_identity(config, monkeypatch):
    from xdr_cli.sessions import resolve_session_for_invocation

    official_identity = Mock(side_effect=AssertionError("must not use MSAL identity"))
    monkeypatch.setattr("xdr_cli.sessions.resolve_operator_upn", official_identity)
    first, first_reason = resolve_session_for_invocation(
        "incidents show", anchor_incident=1, api_backend="portal-cookie",
    )
    second, second_reason = resolve_session_for_invocation(
        "incidents show", anchor_incident=2, api_backend="portal-cookie",
    )
    assert first_reason == "automatic-created"
    assert second_reason == "automatic-rotated"
    assert first.id != second.id
    assert first.upn == second.upn == "automatic"
    official_identity.assert_not_called()


def test_cookie_manual_session_requires_stored_cookie(config, monkeypatch):
    monkeypatch.setattr("xdr_cli.main.load_config", lambda: config)
    monkeypatch.setattr("xdr_cli.portal_auth.load_portal_cookies", lambda tenant: None)
    result = CliRunner().invoke(app, ["session", "start"])
    assert result.exit_code == 2
    assert "portal-cookie" in result.stdout


def test_cookie_operator_resolution_never_uses_cached_official_account(config, monkeypatch):
    from xdr_cli.sessions import resolve_operator_upn

    monkeypatch.setattr("xdr_cli.config.load_config", lambda: config)
    auth = Mock(return_value=Mock(get_auth_status=Mock(return_value={
        "authenticated": True, "account": "unrelated@example.com",
    })))
    monkeypatch.setattr("xdr_cli.auth.AuthManager", auth)
    assert resolve_operator_upn() is None
    auth.assert_not_called()


def test_cookie_logout_clears_only_cookie_store_without_msal(config, monkeypatch):
    from xdr_cli.config import get_config_home
    from xdr_cli.portal_auth import PORTAL_COOKIE_FILENAME

    monkeypatch.setattr("xdr_cli.main.load_config", lambda: config)
    auth = Mock(side_effect=AssertionError("MSAL must not be constructed"))
    monkeypatch.setattr("xdr_cli.commands.auth_cmd.AuthManager", auth)
    home = get_config_home()
    official_cache = home / "token_cache.json"
    official_cache.write_text("synthetic official cache")
    for expected in (True, False):
        result = CliRunner().invoke(app, ["auth", "logout"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["data"]["cleared"] is expected
        assert not (home / PORTAL_COOKIE_FILENAME).exists()
        assert official_cache.read_text() == "synthetic official cache"
    auth.assert_not_called()


def test_cookie_login_guides_import_without_initializing_msal(config, monkeypatch):
    monkeypatch.setattr("xdr_cli.main.load_config", lambda: config)
    auth = Mock(side_effect=AssertionError("MSAL must not be constructed"))
    monkeypatch.setattr("xdr_cli.commands.auth_cmd.AuthManager", auth)
    result = CliRunner().invoke(app, ["auth", "login"])
    assert result.exit_code == 6
    assert "portal-cookie <cookie-source>" in result.stdout
    assert config.client_id == ""
    auth.assert_not_called()


@respx.mock
def test_cookie_session_end_refreshes_schema_without_official_auth(config, monkeypatch):
    from xdr_cli.sessions import current_session

    # Persisted official defaults must not defeat the invocation override.
    config.api_backend = "official"
    monkeypatch.setattr("xdr_cli.main.load_config", lambda: config)
    forbidden = Mock(side_effect=AssertionError("official auth must not be constructed"))
    for target in (
        "xdr_cli.auth.AuthManager", "xdr_cli.commands.schema_cmd.AuthManager",
        "xdr_cli.schema_graph.local_collection.AuthManager",
        "xdr_cli.schema_graph.discovery.AuthManager",
    ):
        monkeypatch.setattr(target, forbidden)
    respx.get(TENANT).respond(200, json={"AuthInfo": {"TenantId": "test-tenant"}})
    schema = success()
    schema["Schema"] = [
        {"Name": name, "Type": "String"}
        for name in ("TableName", "ColumnName", "ColumnType")
    ]
    schema["Results"] = [{
        "TableName": "DeviceInfo", "ColumnName": "Timestamp", "ColumnType": "datetime",
    }]
    hunting = respx.post(HUNT).respond(200, json=schema)
    runner = CliRunner()
    start = runner.invoke(app, ["--backend", "portal-cookie", "session", "start"])
    assert start.exit_code == 0, start.output
    config.api_backend = "official"
    end = runner.invoke(app, ["--backend", "portal-cookie", "session", "end"])
    assert end.exit_code == 0, end.output
    records = [json.loads(line) for line in end.stdout.splitlines()]
    assert [record["record_type"] for record in records] == [
        "session-end", "session-maintenance",
    ]
    assert records[-1]["status"] == "success"
    stages = records[-1]["maintenance"]["result"]["context"]["stages"]
    assert stages["refresh"]["status"] == "success"
    assert current_session() is None
    assert hunting.call_count == 1  # No evidence: no broad discovery queries.
    forbidden.assert_not_called()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("native,expected", [("64-bit", "64-bit"), ("32-bit", "32-bit"),
                                             ("x64", None), (None, None)])
async def test_device_architecture_uses_bitness_not_processor(config, native, expected):
    device = "a" * 40
    respx.get(TENANT).respond(json={"AuthInfo": {"TenantId": "test-tenant"}})
    respx.get(ORIGIN + "/apiproxy/mtp/getMachine/machines").respond(json={
        "SenseMachineId": device, "OsProcessor": native,
    })
    client = create_client(config)
    try:
        value = await client.get_device(device)
    finally:
        await client.close()
    if expected is None:
        assert "osArchitecture" not in value
    else:
        assert value["osArchitecture"] == expected
    assert "osProcessor" not in value
    assert "lastSeen" in value["portal_source"]["field_notes"]


@pytest.mark.asyncio
@respx.mock
async def test_device_enrichment_correlates_inventory_and_preserves_partial_ips(config):
    device = 'a' * 40
    respx.get(TENANT).respond(json={'AuthInfo': {'TenantId': config.tenant_id}})
    respx.get(ORIGIN + '/apiproxy/mtp/getMachine/machines').respond(json={
        'SenseMachineId': device, 'ComputerDnsName': 'synthetic.invalid',
        'LastSeen': '2026-01-01T00:00:00Z', 'MemEnrollmentStatus': 3, 'RbacGroupId': 7,
        'IsExcluded': True,
    })
    inventory = respx.get(ORIGIN + '/apiproxy/mtp/ndr/machines').respond(json=[
        {'SenseMachineId': 'b' * 40, 'AssetValue': 'Low', 'DynamicAssetValue': None},
        {'SenseMachineId': device, 'AssetValue': 'High', 'DynamicAssetValue': None,
         'RbacGroupId': 7, 'MachineGroup': 'group', 'ManagedBy': 'Other'},
    ])
    ips = respx.get(
        ORIGIN + '/apiproxy/mtp/getLatestMachineIpsByIds/LatestMachineIpsByIds',
    ).respond(
        json={'IpAdapters': [{'IpAddresses': [{'Address': '192.0.2.2'}],
                              'PhysicalAddress': None, 'InterfaceType': 'Ethernet',
                              'OperationalStatus': 'Up'}]},
    )
    respx.get(ORIGIN + f'/apiproxy/mtp/ndr/machines/{device}/exclusionDetails').respond(json={
        'SenseMachineId': device, 'ExclusionState': 'Excluded', 'Justification': 'DuplicateMachine',
    })
    client = create_client(config, auth_factory=Mock(side_effect=AssertionError('No MSAL')))
    try:
        value = await client.get_device(device)
    finally:
        await client.close()
    assert value['deviceValue'] == 'High'
    assert value['rbacGroupName'] == 'group'
    assert value['managedBy'] == 'Intune'
    assert value['exclusionReason'] == 'DuplicateDevice'
    assert 'isPotentialDuplication' not in value
    assert len(value['ipAddresses']) == 1
    assert 'loopback' in value['portal_source']['field_notes']['ipAddresses']
    assert value['portal_source']['supplementary']['inventory']['ManagedBy'] == 'Other'
    assert not value['portal_source']['enrichment_errors']
    assert inventory.calls[0].request.url.params['machineSearchPrefix'] == 'synthetic.invalid'
    assert ips.calls[0].request.url.params['senseMachineId'] == device
    assert ips.calls[0].request.url.params['machineId'] == device


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize('status,payload', [
    (200, [{'SenseMachineId': 'b' * 40, 'AssetValue': 'High', 'DynamicAssetValue': None}]),
    (403, {}), (200, {'unexpected': []}),
])
async def test_inventory_enrichment_failure_is_explicit_not_wrong_device_data(
    config, status, payload,
):
    respx.get(TENANT).respond(json={'AuthInfo': {'TenantId': config.tenant_id}})
    respx.get(ORIGIN + '/apiproxy/mtp/getMachine/machines').respond(json={
        'SenseMachineId': 'a' * 40, 'ComputerDnsName': 'synthetic.invalid',
    })
    respx.get(ORIGIN + '/apiproxy/mtp/ndr/machines').respond(status, json=payload)
    client = create_client(config)
    try:
        value = await client.get_device('a' * 40)
    finally:
        await client.close()
    assert 'deviceValue' not in value
    assert 'inventory' in value['portal_source']['enrichment_errors']
    assert value['portal_source']['supplementary'] == {}


@pytest.mark.asyncio
@respx.mock
async def test_enrichment_rate_limit_stops_without_adapter_request(config):
    from xdr_cli.exceptions import RateLimitError

    respx.get(TENANT).respond(json={'AuthInfo': {'TenantId': config.tenant_id}})
    respx.get(ORIGIN + '/apiproxy/mtp/getMachine/machines').respond(json={
        'SenseMachineId': 'a' * 40, 'ComputerDnsName': 'synthetic.invalid',
        'LastSeen': '2026-01-01T00:00:00Z',
    })
    route = respx.get(ORIGIN + '/apiproxy/mtp/ndr/machines').respond(
        429, headers={'Retry-After': '42'},
    )
    client = create_client(config)
    try:
        with pytest.raises(RateLimitError):
            await client.get_device('a' * 40)
    finally:
        await client.close()
    assert route.call_count == 1
