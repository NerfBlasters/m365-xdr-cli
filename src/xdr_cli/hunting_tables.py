"""Packaged registry of advanced-hunting table names.

Single source for the tables ``sys_schema_probe`` enumerates and the names
``kql_parse`` accepts as table references. ``tests/test_hunting_tables.py``
fails if the probe query drifts from ``PROBE_TABLES``; regenerate it with
``python scripts/build_schema_probe.py``.

Membership is a naming fact only. It does not claim a tenant has the table,
that a caller may query it, or that two similarly named tables are aliases
(``AIAgentsInfo`` and ``AgentsInfo`` stay separate entries). Additions should
be listed in Microsoft's advanced-hunting or Log Analytics table reference.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Defender XDR tables listed in Microsoft Learn's advanced-hunting schema
# reference, plus legacy/preview spellings already in the probe.
_DEFENDER_TABLES = (
    "AADSignInEventsBeta", "AADSpnSignInEventsBeta",
    "AgentsInfo", "AIAgentsInfo",
    "AlertEvidence", "AlertInfo", "BehaviorEntities", "BehaviorInfo",
    "CallActivityEvents", "CampaignInfo",
    "CloudAppEvents", "CloudAuditEvents", "CloudDnsEvents",
    "CloudPolicyEnforcementEvents", "CloudProcessEvents",
    "CloudStorageAggregatedEvents", "ConnectorStatusInfo",
    "DataSecurityBehaviors", "DataSecurityEvents",
    "DeviceBaselineComplianceAssessment", "DeviceBaselineComplianceAssessmentKB",
    "DeviceBaselineComplianceProfiles",
    "DeviceEvents", "DeviceFileCertificateInfo", "DeviceFileEvents",
    "DeviceImageLoadEvents", "DeviceInfo", "DeviceLogonEvents",
    "DeviceNetworkEvents", "DeviceNetworkInfo", "DeviceProcessEvents",
    "DeviceRegistryEvents",
    "DeviceTvmBrowserExtensions", "DeviceTvmBrowserExtensionsKB",
    "DeviceTvmCertificateInfo", "DeviceTvmHardwareFirmware",
    "DeviceTvmInfoGathering", "DeviceTvmInfoGatheringKB",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmSoftwareEvidenceBeta", "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities", "DeviceTvmSoftwareVulnerabilitiesKB",
    "DisruptionAndResponseEvents",
    "EmailAttachmentInfo", "EmailEvents", "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "EntraIdSignInEvents", "EntraIdSpnSignInEvents",
    "ExposureGraphEdges", "ExposureGraphNodes",
    "FileMaliciousContentInfo", "GraphAPIAuditEvents",
    "IdentityAccountInfo", "IdentityDirectoryEvents", "IdentityEvents",
    "IdentityInfo", "IdentityLogonEvents", "IdentityQueryEvents",
    "MessageContents", "MessageEvents", "MessagePostDeliveryEvents",
    "MessageUrlInfo",
    "OAuthAppInfo", "UrlClickEvents",
)

# Sentinel / Log Analytics workspace tables visible through unified hunting.
_WORKSPACE_TABLES = (
    "AADGraphActivityLogs", "AADManagedIdentitySignInLogs",
    "AADProvisioningLogs", "AADRiskyUsers", "AADServicePrincipalSignInLogs",
    "AADUserRiskEvents",
    "Alert", "Anomalies", "AuditLogs",
    "GraphNotificationsActivityLogs", "Heartbeat",
    "MicrosoftGraphActivityLogs", "Operation",
    "SecurityAlert", "SecurityIncident", "SigninLogs",
    "ThreatIntelligenceIndicator", "Usage",
)

PROBE_TABLES: tuple[str, ...] = tuple(sorted(set(_DEFENDER_TABLES + _WORKSPACE_TABLES)))
"""Exact table set queried by ``sys_schema_probe``, sorted."""

KNOWN_TABLES: frozenset[str] = frozenset(PROBE_TABLES)
"""Names the KQL tokenizer accepts as table references."""

_PROBE_HEADER = """\
-- name: sys_schema_probe
-- description: Enumerate tables/columns available in this tenant (run first in a new environment)
-- tier: utility
-- params:
-- Generated from xdr_cli.hunting_tables by scripts/build_schema_probe.py; do not edit by hand.
"""


TABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}")
"""Names safe to interpolate into a probe arm; anything else is rejected."""


def probe_table_names(extra: Iterable[str] = ()) -> tuple[str, ...]:
    """Return the sorted registry plus safe extra names (portal, reference, cache)."""

    names = set(PROBE_TABLES)
    for name in extra:
        if isinstance(name, str) and TABLE_NAME.fullmatch(name):
            names.add(name)
    return tuple(sorted(names))


def render_schema_probe(names: Iterable[str] | None = None) -> str:
    """Return ``sys_schema_probe`` KQL for ``names`` (default: ``PROBE_TABLES``)."""

    tables = PROBE_TABLES if names is None else tuple(names)
    for name in tables:
        if not TABLE_NAME.fullmatch(name):
            raise ValueError(f"unsafe hunting table name: {name!r}")
    arms = ",\n".join(
        f'  ({name} | getschema | extend TableName = "{name}")' for name in tables
    )
    return (
        f"{_PROBE_HEADER}union isfuzzy=true\n{arms}\n"
        "| project TableName, ColumnName, ColumnType, ColumnOrdinal\n"
        "| sort by TableName asc, ColumnOrdinal asc\n"
    )
