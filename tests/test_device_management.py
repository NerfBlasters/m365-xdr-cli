"""Synthetic trust-boundary and concurrency checks for device metadata adapters."""

from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.device_management import OfficialDeviceManagement, PortalDeviceManagement
from xdr_cli.exceptions import APIError, ConflictError, NetworkError, UsageError
from xdr_cli.portal_client import CookieAuth

BASE = "https://security.microsoft.com/apiproxy/mtp"
DEVICE = "a" * 40
ACTION = "00000000-0000-0000-0000-000000000001"


class PortalHarness(PortalDeviceManagement):
    pass


class OfficialHarness(OfficialDeviceManagement):
    pass


@pytest.fixture
async def portal():
    client = PortalHarness()
    client._client = httpx.AsyncClient(base_url="https://security.microsoft.com")
    client._auth = CookieAuth(cookie_header="sccauth=synthetic", xsrf_token="synthetic")
    client._tenant_id = "synthetic-tenant"
    client.verify_tenant = AsyncMock()
    client.get_device = AsyncMock(
        return_value={
            "id": DEVICE,
            "portal_source": {"raw": {"InternalMachineId": 123}},
        }
    )
    client.get_action_status = AsyncMock()
    yield client
    await client._client.aclose()


def tags(manual=None, system=None):
    return {"UserDefinedTags": manual or [], "BuiltInTags": system or []}


def action(status="Pending", kind="IsolationResponse"):
    return {
        "id": ACTION,
        "machineId": DEVICE,
        "status": status,
        "portal_source": {"raw": {"Type": kind}},
    }


@pytest.mark.asyncio
@respx.mock
async def test_reads_manual_and_system_tags_without_conflating_sources(portal):
    route = respx.get(BASE + "/ndr/machines/machineTags").respond(
        json=tags(
            ["manual", {"name": "modeled-manual"}],
            ["system"],
        )
    )
    result = await portal.get_device_tags(DEVICE)
    assert result == {
        "manual": ["manual", "modeled-manual"],
        "system": ["system"],
        "source": "portal-response",
    }
    assert route.calls[0].request.url.params["senseMachineId"] == DEVICE
    assert route.calls[0].request.headers["x-xsrf-token"] == "synthetic"
    assert "authorization" not in route.calls[0].request.headers
    portal.verify_tenant.assert_awaited_once()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        {},
        {"UserDefinedTags": [], "BuiltInTags": None},
        {"UserDefinedTags": ["duplicate", "duplicate"], "BuiltInTags": []},
        {"UserDefinedTags": [{"unknown": "shape"}], "BuiltInTags": []},
    ],
)
async def test_malformed_tags_do_not_become_empty_success(portal, response):
    respx.get(BASE + "/ndr/machines/machineTags").respond(json=response)
    with pytest.raises(APIError):
        await portal.get_device_tags(DEVICE)


@pytest.mark.asyncio
@respx.mock
async def test_set_preserves_manual_snapshot_and_verifies_replacement(portal):
    respx.get(BASE + "/ndr/machines/machineTags").mock(
        side_effect=[
            httpx.Response(200, json=tags(["keep"], ["system"])),
            httpx.Response(200, json=tags(["keep", "new"], ["system"])),
        ]
    )
    route = respx.post(BASE + "/ndr/machines/editMachineTags").respond(json="OK")
    result = await portal.set_device_tags(DEVICE, ["keep", "new"], expected_current=["keep"])
    import json

    body = json.loads(route.calls[0].request.content)
    assert body == {
        "SenseMachineIds": [DEVICE],
        "InternalMachineIds": [123],
        "MachineTags": '["keep", "new"]',
    }
    assert "system" not in body["MachineTags"]
    assert result["manual"] == ["keep", "new"] and result["system"] == ["system"]
    assert result["verified"] is True
    assert result["atomic_compare_and_swap"] is False


@pytest.mark.asyncio
@respx.mock
async def test_missing_internal_id_is_not_invented(portal):
    portal.get_device.return_value = {"id": DEVICE, "portal_source": {"raw": {}}}
    respx.get(BASE + "/ndr/machines/machineTags").mock(
        side_effect=[
            httpx.Response(200, json=tags()),
            httpx.Response(200, json=tags(["new"])),
        ]
    )
    route = respx.post(BASE + "/ndr/machines/editMachineTags").respond(json={})
    await portal.set_device_tags(DEVICE, ["new"], expected_current=[])
    assert b"InternalMachineIds" not in route.calls[0].request.content


@pytest.mark.asyncio
@respx.mock
async def test_stale_expected_set_prevents_write(portal):
    respx.get(BASE + "/ndr/machines/machineTags").respond(json=tags(["concurrent"]))
    write = respx.post(BASE + "/ndr/machines/editMachineTags").respond(json={})
    with pytest.raises(ConflictError, match="changed"):
        await portal.set_device_tags(DEVICE, ["new"], expected_current=[])
    assert not write.called


@pytest.mark.asyncio
@respx.mock
async def test_post_write_concurrent_change_reports_conflict_not_success(portal):
    respx.get(BASE + "/ndr/machines/machineTags").mock(
        side_effect=[
            httpx.Response(200, json=tags()),
            httpx.Response(200, json=tags(["concurrent"])),
        ]
    )
    write = respx.post(BASE + "/ndr/machines/editMachineTags").respond(json={})
    with pytest.raises(ConflictError, match="after replacement"):
        await portal.set_device_tags(DEVICE, ["new"], expected_current=[])
    assert write.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_mutation_transport_loss_is_never_replayed_or_echoed(portal):
    respx.get(BASE + "/ndr/machines/machineTags").respond(json=tags())
    write = respx.post(BASE + "/ndr/machines/editMachineTags").mock(
        side_effect=httpx.ReadError("sensitive-upstream-detail"),
    )
    with pytest.raises(NetworkError) as caught:
        await portal.set_device_tags(DEVICE, ["private-tag"], expected_current=[])
    assert caught.value.error_code == "OUTCOME_UNKNOWN" and not caught.value.retryable
    assert write.call_count == 1
    assert "private-tag" not in str(caught.value)
    assert "sensitive-upstream-detail" not in str(caught.value)


@pytest.mark.asyncio
@respx.mock
async def test_add_helper_preserves_unrelated_tags_and_rechecks_snapshot(portal):
    respx.get(BASE + "/ndr/machines/machineTags").mock(
        side_effect=[
            httpx.Response(200, json=tags(["keep"])),
            httpx.Response(200, json=tags(["keep"])),
            httpx.Response(200, json=tags(["keep", "new"])),
        ]
    )
    write = respx.post(BASE + "/ndr/machines/editMachineTags").respond(json={})
    result = await portal.update_device_tag(DEVICE, "new", remove=False)
    assert write.call_count == 1 and result["manual"] == ["keep", "new"]
    assert result["atomic_compare_and_swap"] is False


@pytest.mark.asyncio
@respx.mock
async def test_noop_tag_set_does_not_mutate(portal):
    respx.get(BASE + "/ndr/machines/machineTags").respond(json=tags(["keep"]))
    write = respx.post(BASE + "/ndr/machines/editMachineTags").respond(json={})
    result = await portal.set_device_tags(DEVICE, ["keep"], expected_current=["keep"])
    assert result["changed"] is False and not write.called


@pytest.mark.asyncio
async def test_invalid_identity_fails_before_auth_or_transport(portal):
    with pytest.raises(UsageError):
        await portal.get_device_tags("../wrong")
    portal.verify_tenant.assert_not_awaited()


@pytest.mark.asyncio
@respx.mock
async def test_permissions_keep_native_unknown_values_without_granting_auth(portal):
    respx.get(BASE + "/responseApiPortal/requests/permissions").respond(
        json={
            "Permissions": [
                {"Type": "ScanRequest", "Result": 0, "ReasonDescription": "supported"},
                {"Type": "FutureRequest", "Result": 100},
            ],
        }
    )
    result = await portal.get_device_action_permissions(DEVICE)
    assert result["permissions"][0]["status"] == "allowed"
    assert result["permissions"][1] == {
        "type": "FutureRequest",
        "native_result": 100,
        "status": "unmapped",
        "reason": None,
    }
    assert result["authorization_granted"] is False


@pytest.mark.asyncio
@respx.mock
async def test_cancel_uses_query_parameters_and_fresh_actual_status(portal):
    portal.get_action_status.side_effect = [action(), action("InProgress")]
    route = respx.post(BASE + "/responseApiPortal/requests/cancelbyid").respond(json="OK")
    result = await portal.cancel_device_action(ACTION, device_id=DEVICE, comment="test reason")
    request = route.calls[0].request
    assert request.url.params["requestGuid"] == ACTION
    assert request.url.params["comment"] == "test reason"
    assert request.content == b""
    assert result["status"] == "InProgress"
    assert result["cancellation_requested"] and not result["device_rollback_confirmed"]
    assert portal.get_action_status.await_count == 2


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("before", [action("Succeeded"), action(kind="FutureRequest")])
async def test_cancel_rejects_terminal_or_unknown_type_before_submission(portal, before):
    portal.get_action_status.return_value = before
    route = respx.post(BASE + "/responseApiPortal/requests/cancelbyid").respond(json={})
    with pytest.raises(ConflictError):
        await portal.cancel_device_action(ACTION, device_id=DEVICE, comment="test reason")
    assert not route.called


@pytest.mark.asyncio
@respx.mock
async def test_cancel_rejects_mismatched_device_before_submission(portal):
    before = action()
    before["machineId"] = "b" * 40
    portal.get_action_status.return_value = before
    route = respx.post(BASE + "/responseApiPortal/requests/cancelbyid").respond(json={})
    with pytest.raises(APIError, match="identity mismatch"):
        await portal.cancel_device_action(ACTION, device_id=DEVICE, comment="test reason")
    assert not route.called


@pytest.mark.asyncio
async def test_official_read_uses_native_machine_tags_and_marks_no_system_coverage():
    client = OfficialHarness()
    client.get_device = AsyncMock(return_value={"id": DEVICE, "machineTags": ["manual"]})
    result = await client.get_device_tags(DEVICE)
    assert result["manual"] == ["manual"] and result["system_tags_available"] is False


@pytest.mark.asyncio
async def test_official_replacement_explicitly_unsupported_without_request():
    client = OfficialHarness()
    client.transport = AsyncMock()
    with pytest.raises(UnsupportedBackendCapability):
        await client.set_device_tags(DEVICE, [], expected_current=[])
    client.transport.post.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("remove,expected", [(False, "Add"), (True, "Remove")])
async def test_official_native_add_remove_request(remove, expected):
    client = OfficialHarness()
    client.transport = AsyncMock()
    client.transport.post.return_value = {"id": DEVICE, "machineTags": [] if remove else ["tag"]}
    result = await client.update_device_tag(DEVICE, "tag", remove=remove)
    assert client.transport.post.call_args.args[1] == f"machines/{DEVICE}/tags"
    assert client.transport.post.call_args.kwargs["json"] == {"Value": "tag", "Action": expected}
    assert result["verified"]


@pytest.mark.asyncio
async def test_official_transport_loss_cannot_echo_tag_or_enable_retry():
    client = OfficialHarness()
    client.transport = AsyncMock()
    client.transport.post.side_effect = NetworkError("private-tag", retryable=True)
    with pytest.raises(NetworkError) as caught:
        await client.update_device_tag(DEVICE, "private-tag", remove=False)
    assert "private-tag" not in str(caught.value)
    assert caught.value.error_code == "OUTCOME_UNKNOWN" and not caught.value.retryable
    assert client.transport.post.await_count == 1


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "context,expected_suffix,expected_body",
    [
        (
            {"Features": {"UseDotnetAirsUiInvestigations": True}},
            "/autoIr/ui/investigations/",
            {"machine": DEVICE},
        ),
        (
            {"EnabledFeatures": ["UseDotnetAirsUiInvestigations"]},
            "/autoIr/ui/investigations/",
            {"machine": DEVICE},
        ),
        (
            {"EnabledFeatures": [], "Features": {"UseDotnetAirsUiInvestigations": True}},
            "/autoIr/investigations/",
            {"machine_id": DEVICE},
        ),
        ({"Features": {}}, "/autoIr/investigations/", {"machine_id": DEVICE}),
    ],
)
async def test_autoir_selects_one_native_protocol_from_fresh_features(
    portal,
    context,
    expected_suffix,
    expected_body,
):
    import json

    respx.get(BASE + "/sccManagement/mgmt/TenantContext").respond(
        json={
            "AuthInfo": {"TenantId": "synthetic-tenant"},
            **context,
        }
    )
    selected = respx.post(BASE + expected_suffix).respond(
        json={"investigation_id": 123, "state": 0}
    )
    result = await portal.start_device_investigation(DEVICE, comment="local-only reason")
    request = selected.calls[0].request
    assert json.loads(request.content) == expected_body
    assert "local-only reason" not in request.content.decode()
    assert request.url.params["useDotnetAutoIrUi"] == str("/ui/" in expected_suffix).lower()
    assert result["request_accepted"] and not result["comment_upstream_recorded"]
    assert result["investigation_status"] == "not_interpreted"


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("inventory", [
    {},
    {"Features": {"UseDotnetAirsUiInvestigations": 0}},
    {"Features": {"UseDotnetAirsUiInvestigations": 1}},
    {"EnabledFeatures": [1]},
])
async def test_autoir_invalid_feature_inventory_never_sends_a_mutation(portal, inventory):
    respx.get(BASE + "/sccManagement/mgmt/TenantContext").respond(
        json={
            "AuthInfo": {"TenantId": "synthetic-tenant"},
            **inventory,
        }
    )
    legacy = respx.post(BASE + "/autoIr/investigations/").respond(json={"id": 1})
    dotnet = respx.post(BASE + "/autoIr/ui/investigations/").respond(json={"id": 1})
    with pytest.raises(APIError):
        await portal.start_device_investigation(DEVICE, comment="reason")
    assert not legacy.called and not dotnet.called


@pytest.mark.asyncio
@respx.mock
async def test_autoir_feature_tenant_mismatch_cannot_select_a_protocol(portal):
    from xdr_cli.exceptions import ConfigError

    respx.get(BASE + "/sccManagement/mgmt/TenantContext").respond(
        json={
            "AuthInfo": {"TenantId": "foreign-tenant"},
            "Features": {},
        }
    )
    with pytest.raises(ConfigError, match="configured tenant"):
        await portal.start_device_investigation(DEVICE, comment="reason")


@pytest.mark.asyncio
@respx.mock
async def test_autoir_transport_loss_never_probes_the_other_mutation_protocol(portal):
    respx.get(BASE + "/sccManagement/mgmt/TenantContext").respond(
        json={
            "AuthInfo": {"TenantId": "synthetic-tenant"},
            "Features": {"UseDotnetAirsUiInvestigations": True},
        }
    )
    dotnet = respx.post(BASE + "/autoIr/ui/investigations/").mock(
        side_effect=httpx.ReadError("secret")
    )
    legacy = respx.post(BASE + "/autoIr/investigations/").respond(json={"id": 1})
    with pytest.raises(NetworkError) as caught:
        await portal.start_device_investigation(DEVICE, comment="reason")
    assert dotnet.call_count == 1 and not legacy.called
    assert caught.value.error_code == "OUTCOME_UNKNOWN"
    assert not caught.value.retryable


@pytest.mark.asyncio
@respx.mock
async def test_portal_history_uses_exact_device_filter_and_no_widget_action_subset(portal):
    native = {"ActionId": "one", "MachineId": DEVICE, "ActionType": "IsolateResponse"}
    route = respx.get(BASE + "/actionCenter/actioncenterui/history-actions").respond(
        json={
            "Results": [native],
            "Count": 1,
        }
    )
    rows = [row async for row in portal.iter_device_action_history(DEVICE)]
    params = route.calls[0].request.url.params
    assert params["machineId"] == DEVICE and params["useMtpApi"] == "true"
    assert "ActionType" not in params and params["pageIndex"] == "1"
    assert "fromDate" in params and "toDate" in params
    assert rows[0]["native"] == native
    assert rows[-1]["record_type"] == "device-action-history-coverage"
    assert rows[-1]["complete"] and rows[-1]["lookback_days"] == 7


@pytest.mark.asyncio
@respx.mock
async def test_portal_history_cap_is_explicit_partial_not_global_completeness(portal):
    route = respx.get(BASE + "/actionCenter/actioncenterui/history-actions").respond(
        json={
            "Results": [{"ActionId": "one", "MachineId": DEVICE}],
            "Count": 20,
        }
    )
    rows = [row async for row in portal.iter_device_action_history(DEVICE, limit=1)]
    assert not rows[-1]["complete"] and rows[-1]["native_count"] == 20
    assert rows[-1]["stop_reason"] == "limit-reached"
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_portal_history_rejects_ignored_device_filter(portal):
    respx.get(BASE + "/actionCenter/actioncenterui/history-actions").respond(
        json={
            "Results": [{"ActionId": "one", "MachineId": "b" * 40}],
            "Count": 1,
        }
    )
    with pytest.raises(APIError, match="unexpected identity"):
        _ = [row async for row in portal.iter_device_action_history(DEVICE)]


@pytest.mark.asyncio
@respx.mock
async def test_portal_history_uses_one_based_pages_with_stable_page_size(portal):
    first = [{"ActionId": str(index), "MachineId": DEVICE} for index in range(100)]
    route = respx.get(BASE + "/actionCenter/actioncenterui/history-actions").mock(
        side_effect=[
            httpx.Response(200, json={"Results": first, "Count": 101}),
            httpx.Response(
                200, json={"Results": [{"ActionId": "100", "MachineId": DEVICE}], "Count": 101}
            ),
        ]
    )
    rows = [row async for row in portal.iter_device_action_history(DEVICE, limit=101)]
    assert len(rows) == 102 and rows[-1]["returned"] == 101 and rows[-1]["complete"]
    assert [call.request.url.params["pageIndex"] for call in route.calls] == ["1", "2"]
    assert [call.request.url.params["pageSize"] for call in route.calls] == ["100", "100"]
    assert len({call.request.url.params["fromDate"] for call in route.calls}) == 1


@pytest.mark.asyncio
@respx.mock
async def test_portal_history_deduplicates_and_marks_concurrent_page_overlap(portal):
    first = [{"ActionId": str(index), "MachineId": DEVICE} for index in range(100)]
    second = [{"ActionId": str(index), "MachineId": DEVICE} for index in (99, 100, 101)]
    respx.get(BASE + "/actionCenter/actioncenterui/history-actions").mock(
        side_effect=[
            httpx.Response(200, json={"Results": first, "Count": 102}),
            httpx.Response(200, json={"Results": second, "Count": 102}),
        ]
    )
    rows = [row async for row in portal.iter_device_action_history(DEVICE, limit=200)]
    assert len(rows) == 103 and rows[-1]["returned"] == 102
    assert not rows[-1]["complete"] and rows[-1]["duplicate_actions"] == 1


@pytest.mark.asyncio
@respx.mock
async def test_portal_history_count_drift_never_claims_complete(portal):
    first = [{"ActionId": str(index), "MachineId": DEVICE} for index in range(100)]
    second = [{"ActionId": str(index), "MachineId": DEVICE} for index in (100, 101)]
    respx.get(BASE + "/actionCenter/actioncenterui/history-actions").mock(
        side_effect=[
            httpx.Response(200, json={"Results": first, "Count": 101}),
            httpx.Response(200, json={"Results": second, "Count": 102}),
        ]
    )
    rows = [row async for row in portal.iter_device_action_history(DEVICE, limit=200)]
    assert not rows[-1]["complete"]
    assert rows[-1]["native_counts_observed"] == [101, 102]
    assert rows[-1]["stop_reason"] == "native-count-changed-during-pagination"


@pytest.mark.asyncio
async def test_official_start_investigation_preserves_comment_and_native_result():
    client = OfficialHarness()
    client.transport = AsyncMock()
    client.transport.post.return_value = {"id": "123", "machineId": DEVICE, "state": "Running"}
    result = await client.start_device_investigation(DEVICE, comment="upstream reason")
    assert client.transport.post.call_args.args[1] == f"machines/{DEVICE}/startInvestigation"
    assert client.transport.post.call_args.kwargs["json"] == {"Comment": "upstream reason"}
    assert result["comment_upstream_recorded"] and result["native"]["state"] == "Running"
    assert result["investigation_status"] == "not_interpreted"


@pytest.mark.asyncio
async def test_official_start_investigation_does_not_accept_an_error_object():
    client = OfficialHarness()
    client.transport = AsyncMock()
    client.transport.post.return_value = {"error": {"message": "private upstream text"}}
    with pytest.raises(APIError) as caught:
        await client.start_device_investigation(DEVICE, comment="upstream reason")
    assert "private upstream text" not in str(caught.value)


@pytest.mark.asyncio
async def test_official_history_filter_and_native_continuation_gap():
    client = OfficialHarness()
    client.transport = AsyncMock()
    client.transport.get.return_value = {
        "value": [{"id": ACTION, "machineId": DEVICE}],
        "@odata.nextLink": "https://attacker.invalid/collect?secret=value",
    }
    rows = [row async for row in client.iter_device_action_history(DEVICE)]
    params = client.transport.get.call_args.kwargs["params"]
    assert params["$filter"] == f"machineId eq '{DEVICE}'"
    assert client.transport.get.call_args.args[1] == "machineactions"
    assert not rows[-1]["complete"]
    assert rows[-1]["stop_reason"] == "native-continuation-unfollowed"
    assert client.transport.get.call_count == 1
    assert not rows[-1]["portal_live_response_included"]
