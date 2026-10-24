"""Reference routes compile to bounded, aggregate-only, condition-preserving KQL."""

import re

import pytest

from xdr_cli.schema_graph.reference import ReferenceEndpoint, ReferenceRoute
from xdr_cli.schema_graph.reference_query import (
    MAX_SCAN_ROW_LIMIT,
    ReferenceQueryUnsupported,
    compile_reference_query,
)


def _rows(spec: dict[str, dict[str, str]]) -> list[dict]:
    return [
        {"TableName": table, "ColumnName": column, "ColumnType": kind}
        for table, columns in spec.items()
        for column, kind in columns.items()
    ]


def _route(route_id, family, source, target, guidance=""):
    return ReferenceRoute(
        route_id, route_id, family,
        ReferenceEndpoint.parse(source), ReferenceEndpoint.parse(target), guidance, {},
    )


DEVICE = _rows({
    "DeviceInfo": {"Timestamp": "datetime", "DeviceId": "string"},
    "DeviceEvents": {"Timestamp": "datetime", "DeviceId": "string"},
})
DEVICE_ROUTE = _route(
    "device-info-device-events", "defender-device",
    {"table": "DeviceInfo", "column": "DeviceId", "timeColumn": "Timestamp"},
    {"table": "DeviceEvents", "column": "DeviceId", "timeColumn": "Timestamp"},
)


def test_top_level_route_is_aggregate_only_and_every_read_is_capped():
    compiled = compile_reference_query(DEVICE_ROUTE, DEVICE)
    query = compiled.query
    assert query.rstrip().endswith(
        "project RouteId, SourceValues, TargetValues, MatchedSourceValues, MatchRows, "
        "ScanCapped"
    )
    # Four table reads (source, target sample, window count, membership), each bounded.
    reads = re.findall(r"^\s*(?:let \w+ = (?:materialize\()?\s*)?(DeviceInfo|DeviceEvents)\s*$",
                       query, re.M)
    assert len(reads) == 4
    assert query.count("top 1000 by Timestamp desc") == 2
    assert "top 100000 by Timestamp desc" in query
    assert "take 100001" in query
    assert "top 50 by hash(__k) asc" in query
    assert "tolower(trim(@'\\s', tostring(DeviceId)))" in query
    assert compiled.normalizer == "lower"
    assert compiled.time_policy == {"lookback": "7d", "source": "Timestamp",
                                    "target": "Timestamp"}


@pytest.mark.parametrize("rows, reason", [
    (_rows({"DeviceEvents": {"DeviceId": "string"}}), "source-table-unavailable"),
    (_rows({"DeviceInfo": {"DeviceId": "string"}}), "target-table-unavailable"),
    (_rows({"DeviceInfo": {"Timestamp": "datetime"},
            "DeviceEvents": {"DeviceId": "string"}}), "source-column-unavailable"),
    (_rows({"DeviceInfo": {"DeviceId": "datetime", "Timestamp": "datetime"},
            "DeviceEvents": {"DeviceId": "string", "Timestamp": "datetime"}}),
     "source-column-type-unsupported"),
    (_rows({"DeviceInfo": {"DeviceId": "string"},
            "DeviceEvents": {"DeviceId": "string", "Timestamp": "datetime"}}),
     "time-column-unavailable"),
])
def test_unrepresentable_routes_fail_with_stable_reasons(rows, reason):
    with pytest.raises(ReferenceQueryUnsupported) as caught:
        compile_reference_query(DEVICE_ROUTE, rows)
    assert caught.value.reason == reason


@pytest.mark.parametrize("kwargs", [
    {"samples": 0}, {"row_limit": 20000}, {"scan_row_limit": 10},
    {"scan_row_limit": MAX_SCAN_ROW_LIMIT + 1},
])
def test_budgets_are_bounded(kwargs):
    with pytest.raises(ReferenceQueryUnsupported) as caught:
        compile_reference_query(DEVICE_ROUTE, DEVICE, **kwargs)
    assert caught.value.reason == "invalid-budget"


SIGNIN_CLOUDAPP = _rows({
    "EntraIdSignInEvents": {"Timestamp": "datetime", "SessionId": "string",
                            "UniqueTokenId": "string", "AccountObjectId": "string"},
    "CloudAppEvents": {"Timestamp": "datetime", "RawEventData": "dynamic",
                       "AccountObjectId": "string", "ActionType": "string"},
})
ACCOUNT_GUIDANCE = "Exclude empty identifiers and matches AccountObjectId as well."


def test_nested_path_reparses_each_hop_and_keeps_case_for_tokens():
    route = _route(
        "entra-signin-cloudapp-m365-token", "entra-token",
        {"table": "EntraIdSignInEvents", "column": "UniqueTokenId", "timeColumn": "Timestamp"},
        {"table": "CloudAppEvents", "column": "RawEventData",
         "path": "AppAccessContext.UniqueTokenId", "timeColumn": "Timestamp"},
        ACCOUNT_GUIDANCE,
    )
    compiled = compile_reference_query(route, SIGNIN_CLOUDAPP)
    query = compiled.query
    assert "parse_json(tostring(RawEventData))" in query
    assert "parse_json(tostring(__t0))['AppAccessContext']" in query
    assert "parse_json(tostring(__t1))['UniqueTokenId']" in query
    # Token values are never lowercased; only the scope key is.
    assert "extend __v = trim(@'\\s', tostring(UniqueTokenId))" in query
    assert "tolower(tostring(AccountObjectId)), '|', __v" in query
    assert compiled.constraints_applied == ("composite-key:AccountObjectId",)


def test_account_scope_from_guidance_is_required():
    rows = [r for r in SIGNIN_CLOUDAPP
            if not (r["TableName"] == "CloudAppEvents" and r["ColumnName"] == "AccountObjectId")]
    route = _route(
        "entra-signin-cloudapp-m365-session", "entra-session",
        {"table": "EntraIdSignInEvents", "column": "SessionId", "timeColumn": "Timestamp"},
        {"table": "CloudAppEvents", "column": "RawEventData",
         "path": "AppAccessContext.AADSessionId", "timeColumn": "Timestamp"},
        ACCOUNT_GUIDANCE,
    )
    with pytest.raises(ReferenceQueryUnsupported) as caught:
        compile_reference_query(route, rows)
    assert caught.value.reason == "scope-column-unavailable"


def test_exchange_session_keeps_workload_predicate():
    route = _route(
        "entra-signin-cloudapp-exchange-session", "entra-session",
        {"table": "EntraIdSignInEvents", "column": "SessionId", "timeColumn": "Timestamp"},
        {"table": "CloudAppEvents", "column": "RawEventData", "path": "SessionId",
         "timeColumn": "Timestamp"},
        ACCOUNT_GUIDANCE,
    )
    compiled = compile_reference_query(route, SIGNIN_CLOUDAPP)
    assert "where ActionType == 'MailItemsAccessed'" in compiled.query
    assert "target-predicate:ActionType==MailItemsAccessed" in compiled.constraints_applied


PROCESS = _rows({
    "DeviceProcessEvents": {"Timestamp": "datetime", "DeviceId": "string",
                            "ProcessUniqueId": "long", "ProcessCreationTime": "datetime"},
    "DeviceNetworkEvents": {"Timestamp": "datetime", "DeviceId": "string",
                            "InitiatingProcessUniqueId": "long"},
})


def test_process_start_key_is_device_scoped_and_ordered():
    route = _route(
        "process-start-key-device-network-events", "process-start-key",
        {"table": "DeviceProcessEvents", "column": "ProcessUniqueId", "timeColumn": "Timestamp"},
        {"table": "DeviceNetworkEvents", "column": "InitiatingProcessUniqueId",
         "timeColumn": "Timestamp"},
    )
    compiled = compile_reference_query(route, PROCESS)
    assert "summarize __o = min(ProcessCreationTime) by __k" in compiled.query
    assert "join kind=inner (SourceKeys) on __k" in compiled.query
    assert "where Timestamp >= __o" in compiled.query
    assert "composite-key:DeviceId" in compiled.constraints_applied
    assert any("TenantId" in warning for warning in compiled.warnings)


def test_audit_target_resources_expand_and_filter_user_elements():
    rows = _rows({
        "AuditLogs": {"ActivityDateTime": "datetime", "TargetResources": "dynamic"},
        "IdentityInfo": {"Timestamp": "datetime", "AccountObjectId": "string"},
    })
    route = _route(
        "audit-target-resource-id-account-object-id", "entra-user",
        {"table": "AuditLogs", "column": "TargetResources", "path": "[].id",
         "timeColumn": "ActivityDateTime"},
        {"table": "IdentityInfo", "column": "AccountObjectId", "timeColumn": "Timestamp"},
    )
    query = compile_reference_query(route, rows).query
    expand = query.index("mv-expand __s0 to typeof(dynamic) limit 1000")
    user_filter = query.index("where tostring(__s0['type']) =~ 'User'")
    assert expand < user_filter < query.index("['id']")


def test_padded_graph_token_trims_both_sides():
    rows = _rows({
        "EntraIdSignInEvents": {"Timestamp": "datetime", "UniqueTokenId": "string"},
        "AADGraphActivityLogs": {"TimeRequested": "datetime", "SignInActivityId": "string"},
    })
    route = _route(
        "entra-signin-aad-graph-activity-token", "entra-token",
        {"table": "EntraIdSignInEvents", "column": "UniqueTokenId", "timeColumn": "Timestamp"},
        {"table": "AADGraphActivityLogs", "column": "SignInActivityId",
         "timeColumn": "TimeRequested"},
    )
    compiled = compile_reference_query(route, rows)
    # Source keys, target presence sample and target membership scan.
    assert compiled.query.count("trim_end(@'=+',") == 3
    assert "where TimeRequested > ago(7d)" in compiled.query


def test_timeless_target_is_a_capped_snapshot():
    rows = _rows({
        "DeviceTvmSoftwareVulnerabilities": {"CveId": "string"},
        "DeviceTvmSoftwareVulnerabilitiesKB": {"CveId": "string"},
    })
    route = _route(
        "device-vulnerability-to-knowledge-base", "cve",
        {"table": "DeviceTvmSoftwareVulnerabilities", "column": "CveId"},
        {"table": "DeviceTvmSoftwareVulnerabilitiesKB", "column": "CveId"},
    )
    compiled = compile_reference_query(route, rows, scan_row_limit=5000)
    assert "ago(" not in compiled.query
    assert "take 5000" in compiled.query and "take 5001" in compiled.query
    assert compiled.time_policy["target"] == "snapshot-capped"
    assert "toupper(" in compiled.query
    assert any("snapshot" in warning for warning in compiled.warnings)


def test_missing_declared_time_column_falls_back_with_warning():
    rows = _rows({
        "DeviceInfo": {"TimeGenerated": "datetime", "DeviceId": "string"},
        "DeviceEvents": {"Timestamp": "datetime", "DeviceId": "string"},
    })
    compiled = compile_reference_query(DEVICE_ROUTE, rows)
    assert compiled.time_policy["source"] == "TimeGenerated"
    assert any("used TimeGenerated" in warning for warning in compiled.warnings)
