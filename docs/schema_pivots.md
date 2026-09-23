# Schema Pivot Reference

Cross-table field intersections for pivoting and hunting across Microsoft 365
Defender Advanced Hunting tables. Every field lists every table that
contains it — grep for a table name to find every pivot it supports, or
grep for a field name to find every table it reaches.

> **Physical reference only:** a shared column name does not prove shared
> semantics, matching values, uniqueness, cardinality, or join safety. Use
> `xdr schema pivot <Table.Column>` and `xdr schema path <Source> <Target>` for
> reviewed semantic routes. See `docs/schema_graph.md`.

<!-- BEGIN GENERATED SEMANTIC GRAPH -->
## Generated semantic route inventory

This table is generated from the packaged graph. Tenant availability is
reported at runtime by `xdr schema pivot` and `xdr schema path`.

| Source | Target | Relationship | Workflow | Cardinality | Confidence | Status |
|---|---|---|---|---|---|---|
| DeviceFileEvents.DeviceName | DeviceInfo.DeviceName | semantic-equivalent | query → extract → query | many-to-one | medium | reviewed |
| CloudAppEvents.RawEventData#/ClientIP | EntraIdSignInEvents.IPAddress | correlation-only | query → extract → query | many-to-many | medium | reviewed |
| CloudAppEvents.IPAddress | EntraIdSignInEvents.IPAddress | correlation-only | query → extract → query | many-to-many | high | reviewed |
| DeviceFileEvents.DeviceId | DeviceInfo.DeviceId | join-compatible | direct join | many-to-one | high | reviewed |
| DeviceEvents.DeviceId | DeviceInfo.DeviceId | join-compatible | direct join | many-to-one | high | reviewed |
| DeviceProcessEvents.SHA256 | EmailAttachmentInfo.SHA256 | correlation-only | query → extract → query | many-to-many | high | reviewed |
| EntraIdSignInEvents.AccountObjectId | IdentityInfo.AccountObjectId | join-compatible | direct join | many-to-one | high | reviewed |
| DeviceInfo.DeviceId | DeviceRegistryEvents.DeviceId | join-compatible | direct join | one-to-many | high | reviewed |
| DeviceInfo.DeviceId | DeviceLogonEvents.DeviceId | join-compatible | direct join | one-to-many | high | reviewed |
| DeviceInfo.DeviceId | DeviceNetworkEvents.DeviceId | join-compatible | direct join | one-to-many | high | reviewed |
| CloudAppEvents.AccountObjectId | IdentityInfo.AccountObjectId | join-compatible | direct join | many-to-one | high | reviewed |
| GraphAPIAuditEvents.AccountObjectId | IdentityInfo.AccountObjectId | join-compatible | direct join | many-to-one | high | reviewed |
| CloudAppEvents.RawEventData#/UserId | IdentityInfo.AccountUpn | transform-required | query → extract → query | many-to-one | medium | reviewed |
| EntraIdSignInEvents.AccountUpn | IdentityInfo.AccountUpn | transform-required | query → extract → query | many-to-one | high | reviewed |
| CloudAppEvents.RawEventData#/TargetResources/*/id | IdentityInfo.AccountObjectId | semantic-equivalent | query → extract → query | unknown | low | candidate |
| AADSignInEventsBeta.AccountUpn | IdentityInfo.AccountUpn | transform-required | query → extract → query | many-to-one | high | reviewed |
| DeviceInfo.DeviceId | DeviceProcessEvents.DeviceId | join-compatible | direct join | one-to-many | high | reviewed |
| DeviceFileEvents.SHA256 | EmailAttachmentInfo.SHA256 | correlation-only | query → extract → query | many-to-many | high | reviewed |
| DeviceInfo.DeviceName | DeviceNetworkEvents.DeviceName | semantic-equivalent | query → extract → query | one-to-many | medium | reviewed |
| EmailAttachmentInfo.NetworkMessageId | EmailEvents.NetworkMessageId | join-compatible | direct join | many-to-one | high | reviewed |
| DeviceProcessEvents.AccountUpn | IdentityInfo.AccountUpn | transform-required | query → extract → query | many-to-one | high | reviewed |
| DeviceImageLoadEvents.DeviceId | DeviceInfo.DeviceId | join-compatible | direct join | many-to-one | high | reviewed |
| DeviceProcessEvents.AccountObjectId | IdentityInfo.AccountObjectId | join-compatible | direct join | many-to-one | high | reviewed |
| EmailEvents.NetworkMessageId | UrlClickEvents.NetworkMessageId | join-compatible | direct join | one-to-many | high | reviewed |
| EmailEvents.NetworkMessageId | EmailUrlInfo.NetworkMessageId | join-compatible | direct join | one-to-many | high | reviewed |
| IdentityInfo.AccountUpn | UrlClickEvents.AccountUpn | transform-required | query → extract → query | one-to-many | high | reviewed |
| DeviceInfo.DeviceName | DeviceProcessEvents.DeviceName | semantic-equivalent | query → extract → query | one-to-many | medium | reviewed |

Do not infer a route from the physical same-name appendix below. Use the
generated inventory or the runtime commands, which also return transforms,
roles, namespaces, provenance, temporal guidance, and tenant availability.
<!-- END GENERATED SEMANTIC GRAPH -->

> Refresh in any tenant with `xdr schema refresh`, then convert the receipt's
> complete `data_path` JSONL to CSV before running the renderer. See
> `docs/schema_probe.md` for exact POSIX commands and the portal-export path.
>
> The probe covers **80 curated Defender XDR, Sentinel, and Entra workspace
> tables**; which schemas resolve can vary by license, permission, region,
> connected-workspace context, and connector. `sys_schema_probe` uses
> `union isfuzzy=true`, so absent tables are silently skipped. Schema presence
> does not prove recent row population or a licensed SKU. Custom logs and future
> workspace tables must be added to the probe explicitly. Re-run after a
> relevant tenant or schema change.

> Rebuilding this doc: the build script consumes **CSV**, so convert the
> probe's artifact JSONL to `schema.csv` first (see `docs/schema_probe.md`),
> then
> `python scripts/build_schema_pivots.py schema.csv docs/schema_pivots.md`.

---

## Casing gotchas — read first

Column names are case-sensitive in KQL joins. A few near-duplicates trip up
cross-table queries:

- `IPAddress` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, CloudAppEvents, CloudAuditEvents, CloudStorageAggregatedEvents, DataSecurityEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityDirectoryEvents, IdentityEvents, IdentityLogonEvents, IdentityQueryEvents, MicrosoftGraphActivityLogs, SigninLogs, UrlClickEvents — all-caps — the dominant form.
- `IpAddress` → AADUserRiskEvents, DisruptionAndResponseEvents, GraphAPIAuditEvents — camelCase `p` — `DisruptionAndResponseEvents` and `GraphAPIAuditEvents` use this spelling instead of `IPAddress`. `DisruptionAndResponseEvents` also has `SourceIpAddress` and plain `Port`/`SourcePort`.
- `Categories` → AlertEvidence, BehaviorEntities, BehaviorInfo, DataSecurityBehaviors, DeviceTvmInfoGatheringKB, ExposureGraphNodes — dynamic array in most tables, but `AlertInfo` uses scalar `Category` (singular) instead.

When unioning across these boundaries, normalize: `extend IpAddr = coalesce(IPAddress, IpAddress)`.

---

## Tenant variance - columns that may be absent

Some columns appear in Microsoft's public schema documentation but are not
consistently populated or even present across all tenants. License tier,
region, and table version determine availability. Columns to sanity-check
before using:

- `IsAnonymousProxy`, `IsExternalDevice` are documented for
  `AADSignInEventsBeta` but are absent on some tenants. Projecting them
  causes `Failed to resolve scalar expression` (API 400).
- `RawEventData.CountryCode` is populated for some `CloudAppEvents` sources
  (for example, Entra sign-in-derived rows) and null for others.
- `DetectionMethods` is documented for `EmailEvents`, but the table itself
  may be empty in tenants without Defender for Office licenses.

Before referencing an unfamiliar column, run `xdr schema refresh` followed by
`xdr schema show <table> --search <column>`, or test with `getschema`:

```kql
AADSignInEventsBeta | getschema | where ColumnName in ('IsAnonymousProxy', 'IsExternalDevice')
```

An empty result means the column is not in this tenant's schema - pick an
available alternative (`IsCompliant`, `AuthenticationRequirement`,
`ConditionalAccessStatus`) or drop the projection.

---

## Row identity (uniqueness contracts)

Uniqueness contracts come from Microsoft's Advanced Hunting docs, not from
the probe — `getschema` only reports columns, not keys.

- `ReportId` → AADSignInEventsBeta, AADSpnSignInEventsBeta, CampaignInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, ConnectorStatusInfo, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DisruptionAndResponseEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, EntraIdSignInEvents, EntraIdSpnSignInEvents, FileMaliciousContentInfo, GraphAPIAuditEvents, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, OAuthAppInfo, UrlClickEvents — **not unique alone**; MDE event identity is `(DeviceId, ReportId, Timestamp)`. Many other tables have their own ReportId semantics.
- `Timestamp` → AADSignInEventsBeta, AADSpnSignInEventsBeta, AlertEvidence, AlertInfo, BehaviorEntities, BehaviorInfo, CampaignInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, ConnectorStatusInfo, DataSecurityBehaviors, DataSecurityEvents, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmInfoGathering, DeviceTvmSecureConfigurationAssessment, DisruptionAndResponseEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, EntraIdSignInEvents, EntraIdSpnSignInEvents, FileMaliciousContentInfo, GraphAPIAuditEvents, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, OAuthAppInfo, UrlClickEvents — always narrow by time window before joins.
- `AlertId` → Alert, AlertEvidence, AlertInfo — one `AlertInfo` row per alert, many `AlertEvidence` rows.
- `BehaviorId` → BehaviorEntities, BehaviorInfo, DataSecurityBehaviors — do not assume this key is unique in either `BehaviorInfo` or `BehaviorEntities`; aggregate or deduplicate it to match the investigation question. Also used by `DataSecurityBehaviors`.
- `NetworkMessageId` → AlertEvidence, BehaviorEntities, CampaignInfo, DataSecurityEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, UrlClickEvents — spine of the email chain; `CampaignInfo` and `DataSecurityEvents` ride it too.
- `InternetMessageId` → DataSecurityEvents, EmailEvents, EmailPostDeliveryEvents — RFC-5322 `Message-ID`.
- `TeamsMessageId` → MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo — spine of the Teams chain.
- `CampaignId` → CampaignInfo
- `RequestId` → AADGraphActivityLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, AADUserRiskEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, GraphAPIAuditEvents, MicrosoftGraphActivityLogs — Entra sign-in request ID; joins Entra twins + Graph audit.
- `CorrelationId` → AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, AADUserRiskEvents, AuditLogs, EntraIdSignInEvents, EntraIdSpnSignInEvents, GraphNotificationsActivityLogs, Operation, SigninLogs — Entra sign-in correlation ID across user + SPN + new/legacy Entra tables.
- `SessionId` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, DisruptionAndResponseEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, MicrosoftGraphActivityLogs, SigninLogs
- `OperationId` → GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `ActivityId` → DataSecurityEvents
- `UniqueTokenId` → EntraIdSignInEvents, EntraIdSpnSignInEvents, MicrosoftGraphActivityLogs

---

## Ingestion and tenancy metadata

These fields describe the hunting data pipeline rather than an entity pivot.
Use them for ingestion and billing analysis, not event correlation:

- `MachineGroup` → AlertEvidence, AlertInfo, BehaviorEntities, BehaviorInfo, DeviceBaselineComplianceAssessment, DeviceBaselineComplianceProfiles, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmBrowserExtensions, DeviceTvmCertificateInfo, DeviceTvmHardwareFirmware, DeviceTvmInfoGathering, DeviceTvmSecureConfigurationAssessment, DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, DisruptionAndResponseEvents
- `SourceSystem` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, AADUserRiskEvents, Alert, AlertEvidence, AlertInfo, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, CampaignInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, ConnectorStatusInfo, DataSecurityBehaviors, DataSecurityEvents, DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB, DeviceBaselineComplianceProfiles, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmBrowserExtensions, DeviceTvmCertificateInfo, DeviceTvmHardwareFirmware, DeviceTvmInfoGathering, DeviceTvmInfoGatheringKB, DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB, DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareVulnerabilitiesKB, DisruptionAndResponseEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, EntraIdSignInEvents, EntraIdSpnSignInEvents, ExposureGraphEdges, ExposureGraphNodes, FileMaliciousContentInfo, GraphAPIAuditEvents, GraphNotificationsActivityLogs, Heartbeat, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, MicrosoftGraphActivityLogs, OAuthAppInfo, Operation, SecurityAlert, SecurityIncident, SigninLogs, UrlClickEvents, Usage
- `TenantId` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, AADUserRiskEvents, Alert, AlertEvidence, AlertInfo, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, CampaignInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, ConnectorStatusInfo, DataSecurityBehaviors, DataSecurityEvents, DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB, DeviceBaselineComplianceProfiles, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmBrowserExtensions, DeviceTvmCertificateInfo, DeviceTvmHardwareFirmware, DeviceTvmInfoGathering, DeviceTvmInfoGatheringKB, DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB, DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareVulnerabilitiesKB, DisruptionAndResponseEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, EntraIdSignInEvents, EntraIdSpnSignInEvents, ExposureGraphEdges, ExposureGraphNodes, FileMaliciousContentInfo, GraphAPIAuditEvents, GraphNotificationsActivityLogs, Heartbeat, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, MicrosoftGraphActivityLogs, OAuthAppInfo, Operation, SecurityAlert, SecurityIncident, SigninLogs, UrlClickEvents, Usage
- `TenantMembershipType` → IdentityAccountInfo, IdentityInfo
- `TimeGenerated` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, AADUserRiskEvents, Alert, AlertEvidence, AlertInfo, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, CampaignInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, ConnectorStatusInfo, DataSecurityBehaviors, DataSecurityEvents, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmSecureConfigurationAssessment, DisruptionAndResponseEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, EntraIdSignInEvents, EntraIdSpnSignInEvents, FileMaliciousContentInfo, GraphAPIAuditEvents, GraphNotificationsActivityLogs, Heartbeat, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, MicrosoftGraphActivityLogs, OAuthAppInfo, Operation, SecurityAlert, SecurityIncident, SigninLogs, UrlClickEvents, Usage
- `_BilledSize` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADUserRiskEvents, Alert, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, GraphNotificationsActivityLogs, Heartbeat, MicrosoftGraphActivityLogs, Operation, SecurityAlert, SecurityIncident, SigninLogs, Usage
- `_IsBillable` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADUserRiskEvents, Alert, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, GraphNotificationsActivityLogs, Heartbeat, MicrosoftGraphActivityLogs, Operation, SecurityAlert, SecurityIncident, SigninLogs, Usage
- `_ItemId` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADUserRiskEvents, Alert, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, GraphNotificationsActivityLogs, Heartbeat, MicrosoftGraphActivityLogs, Operation, SecurityAlert, SecurityIncident, SigninLogs, Usage
- `_ResourceId` → AADGraphActivityLogs, Alert, BehaviorEntities, BehaviorInfo, Heartbeat, Operation
- `_SubscriptionId` → AADGraphActivityLogs, Alert, BehaviorEntities, BehaviorInfo, Heartbeat, Operation
- `_TimeReceived` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADUserRiskEvents, Alert, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, GraphNotificationsActivityLogs, Heartbeat, MicrosoftGraphActivityLogs, Operation, SecurityAlert, SecurityIncident, SigninLogs, Usage

---

## Device identity

- `DeviceId` → AADGraphActivityLogs, AlertEvidence, BehaviorEntities, BehaviorInfo, DeviceBaselineComplianceAssessment, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmBrowserExtensions, DeviceTvmCertificateInfo, DeviceTvmHardwareFirmware, DeviceTvmInfoGathering, DeviceTvmSecureConfigurationAssessment, DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, DisruptionAndResponseEvents, MicrosoftGraphActivityLogs — prefer as MDE join key.
- `DeviceName` → AADSignInEventsBeta, AlertEvidence, BehaviorEntities, DeviceBaselineComplianceAssessment, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmHardwareFirmware, DeviceTvmInfoGathering, DeviceTvmSecureConfigurationAssessment, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, DisruptionAndResponseEvents, EntraIdSignInEvents, IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents — human-readable, rename-unsafe; filter/display only.
- `AadDeviceId` → AADSignInEventsBeta, DeviceInfo, DeviceTvmSoftwareVulnerabilities — Entra join key — device ↔ Azure AD object.
- `EntraIdDeviceId` → AADSignInEventsBeta, EntraIdSignInEvents — new Entra device ID (equivalent to `AadDeviceId` in Entra sign-in tables).

## OS / device facets

- `OSPlatform` → AADSignInEventsBeta, CloudAppEvents, DeviceBaselineComplianceAssessment, DeviceBaselineComplianceProfiles, DeviceInfo, DeviceTvmInfoGathering, DeviceTvmSecureConfigurationAssessment, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, EntraIdSignInEvents, IdentityLogonEvents
- `OSArchitecture` → DeviceInfo, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities
- `OSVersion` → DeviceBaselineComplianceAssessment, DeviceBaselineComplianceProfiles, DeviceInfo, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities
- `DeviceType` → CloudAppEvents, DeviceInfo, IdentityLogonEvents
- `Platform` → **(not present in probe)**

---

## Cloud resource identity (Defender for Cloud — multi-cloud)

MDC tables (`CloudAuditEvents`, `CloudDnsEvents`, `CloudProcessEvents`,
`CloudStorageAggregatedEvents`) don't carry `DeviceId`. They identify the
workload by cloud-native resource ID:

- `AzureResourceId` → CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, DeviceInfo — also present in `DeviceInfo` — the Azure VM join bridge.
- `AwsResourceName` → CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, DeviceInfo
- `GcpFullResourceName` → CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, DeviceInfo

`CloudProcessEvents` mirrors MDE process telemetry with a workload
identifier — bridge MDE ↔ cloud via `AzureResourceId` (from `DeviceInfo`
to `CloudProcessEvents`), then pivot on `ProcessCommandLine` / `FileName` /
`AccountName`.

Container / Kubernetes context (MDC `CloudDnsEvents` ↔ `CloudProcessEvents`):

- `ContainerId` → CloudDnsEvents, CloudProcessEvents
- `ContainerName` → CloudDnsEvents, CloudProcessEvents
- `KubernetesNamespace` → CloudDnsEvents, CloudProcessEvents
- `KubernetesPodName` → CloudDnsEvents, CloudProcessEvents
- `KubernetesResource` → CloudDnsEvents, CloudProcessEvents
- `ProcessName` → CloudDnsEvents, CloudProcessEvents

MDC cloud-audit plumbing:

- `AuditSource` → CloudAppEvents, CloudAuditEvents
- `DataSource` → CloudAuditEvents, CloudStorageAggregatedEvents, DisruptionAndResponseEvents
- `IsAnonymousProxy` → CloudAppEvents, CloudAuditEvents

---

## User / account identity

- `AccountObjectId` → AADSignInEventsBeta, AlertEvidence, BehaviorEntities, BehaviorInfo, CloudAppEvents, CloudStorageAggregatedEvents, DataSecurityEvents, DeviceProcessEvents, EntraIdSignInEvents, GraphAPIAuditEvents, IdentityDirectoryEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents — Entra OID — strongest cross-surface pivot (Entra sign-ins ↔ MDI ↔ MDCA ↔ DLP ↔ Graph audit ↔ alerts ↔ device processes).
- `AccountUpn` → AADSignInEventsBeta, AlertEvidence, BehaviorEntities, BehaviorInfo, CloudStorageAggregatedEvents, DataSecurityBehaviors, DataSecurityEvents, DeviceProcessEvents, EntraIdSignInEvents, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents, UrlClickEvents — human-readable UPN; reaches click telemetry, MDI, MDCA, DLP, Entra sign-ins.
- `AccountSid` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceLogonEvents, DeviceProcessEvents, IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents — Windows SID, device-side + MDI.
- `AccountName` → AlertEvidence, BehaviorEntities, CloudProcessEvents, DeviceEvents, DeviceLogonEvents, DeviceProcessEvents, IdentityDirectoryEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents — pair with `AccountDomain`.
- `AccountDomain` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceLogonEvents, DeviceProcessEvents, IdentityDirectoryEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents — pair with `AccountName`.
- `AccountDisplayName` → AADSignInEventsBeta, CloudAppEvents, EntraIdSignInEvents, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents — display name; filter/display only.
- `AccountId` → CloudAppEvents, IdentityAccountInfo, IdentityEvents — MDI/Cloud account identifier (different from `AccountObjectId`).
- `AccountType` → CloudAppEvents, CloudStorageAggregatedEvents, GraphNotificationsActivityLogs, IdentityEvents
- `IdentityId` → IdentityAccountInfo, IdentityInfo — `IdentityInfo` + `IdentityAccountInfo` identity key.
- `AlternateSignInName` → AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `IsExternalUser` → AADSignInEventsBeta, CloudAppEvents, EntraIdSignInEvents
- `IsGuestUser` → AADSignInEventsBeta, EntraIdSignInEvents

MDI target-entity fields (actor + target shape):

- `TargetAccountUpn` → IdentityDirectoryEvents, IdentityQueryEvents
- `TargetAccountDisplayName` → IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents
- `TargetDeviceName` → DisruptionAndResponseEvents, IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents
- `TargetDomainName` → DisruptionAndResponseEvents
- `DestinationDeviceName` → IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents
- `DestinationIPAddress` → IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents
- `DestinationPort` → IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents

`DisruptionAndResponseEvents` has its own Source/Target shape:

- `SourceDeviceId` → DisruptionAndResponseEvents
- `TargetDeviceId` → DisruptionAndResponseEvents
- `SourceDeviceName` → DisruptionAndResponseEvents
- `SourceDomainName` → DisruptionAndResponseEvents
- `SourceUserSid` → DisruptionAndResponseEvents
- `SourceUserName` → DisruptionAndResponseEvents
- `SourceUserDomainName` → DisruptionAndResponseEvents
- `SourceIpAddress` → Anomalies, DisruptionAndResponseEvents — camelCase `p` — not `IPAddress`.
- `SourcePort` → DisruptionAndResponseEvents

---

## Service principals / OAuth apps

- `ApplicationId` → AADSignInEventsBeta, AADSpnSignInEventsBeta, AlertEvidence, BehaviorEntities, CloudAppEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, GraphAPIAuditEvents, GraphNotificationsActivityLogs
- `Application` → AADSignInEventsBeta, AADSpnSignInEventsBeta, AlertEvidence, BehaviorEntities, CloudAppEvents, DataSecurityBehaviors, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityDirectoryEvents, IdentityEvents, IdentityLogonEvents, IdentityQueryEvents
- `AppName` → OAuthAppInfo, UrlClickEvents
- `OAuthAppId` → CloudAppEvents, OAuthAppInfo — join to Entra SPN sign-ins via `ServicePrincipalId`.
- `OAuthApplicationId` → AlertEvidence, BehaviorEntities
- `ServicePrincipalId` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSpnSignInEventsBeta, EntraIdSpnSignInEvents, GraphAPIAuditEvents, MicrosoftGraphActivityLogs, OAuthAppInfo, SigninLogs
- `ServicePrincipalName` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSpnSignInEventsBeta, EntraIdSpnSignInEvents, SigninLogs
- `ApplicationInstanceId` → IdentityEvents
- `ApplicationEventId` → IdentityEvents
- `ApplicationSessionId` → IdentityEvents
- `ResourceDisplayName` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, EntraIdSignInEvents, EntraIdSpnSignInEvents, SigninLogs
- `ResourceId` → AADSignInEventsBeta, AADSpnSignInEventsBeta, Alert, AuditLogs, EntraIdSignInEvents, EntraIdSpnSignInEvents, Heartbeat, SecurityAlert, SigninLogs
- `ResourceTenantId` → AADSignInEventsBeta, AADSpnSignInEventsBeta, EntraIdSignInEvents, EntraIdSpnSignInEvents, SigninLogs — tenant of the resource the token was issued for.
- `AppOwnerTenantId` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, OAuthAppInfo, SigninLogs

---

## Initiating process bundle (27 fields across the same 7 device tables)

Every field below is present in exactly these 7 tables: **DeviceEvents,
DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents,
DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents**.

- `InitiatingProcessAccountDomain` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessAccountName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessAccountObjectId` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessAccountSid` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessAccountUpn` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessCommandLine` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessCreationTime` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessFileSize` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessFolderPath` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessMD5` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessParentCreationTime` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessParentFileName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessParentId` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessRemoteSessionDeviceName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessRemoteSessionIP` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessSHA1` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessSHA256` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessSessionId` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessUniqueId` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessVersionInfoCompanyName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessVersionInfoFileDescription` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessVersionInfoInternalFileName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessVersionInfoOriginalFileName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessVersionInfoProductName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessVersionInfoProductVersion` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `IsInitiatingProcessRemoteSession` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `AppGuardContainerId` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents

Extended (8–9 tables — also in `CloudProcessEvents` + `DisruptionAndResponseEvents`):

- `InitiatingProcessFileName` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents, DisruptionAndResponseEvents
- `InitiatingProcessId` → CloudProcessEvents, DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents, DisruptionAndResponseEvents

Subset (6 of 7 — missing from `DeviceEvents`):

- `InitiatingProcessIntegrityLevel` → DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents
- `InitiatingProcessTokenElevation` → DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents

Canonical unique process identity on a device:
`(DeviceId, InitiatingProcessId, InitiatingProcessCreationTime)`.

## Created-process bundle

- `CreatedProcessSessionId` → DeviceEvents, DeviceProcessEvents
- `ProcessCreationTime` → CloudProcessEvents, DeviceEvents, DeviceProcessEvents
- `ProcessId` → CloudDnsEvents, CloudProcessEvents, DeviceEvents, DeviceProcessEvents — also in `CloudProcessEvents` + `CloudDnsEvents` — cloud workload process id, not DeviceId-scoped.
- `ProcessRemoteSessionDeviceName` → DeviceEvents, DeviceProcessEvents
- `ProcessRemoteSessionIP` → DeviceEvents, DeviceProcessEvents
- `ProcessTokenElevation` → DeviceEvents, DeviceProcessEvents
- `IsProcessRemoteSession` → DeviceEvents, DeviceProcessEvents
- `InitiatingProcessLogonId` → DeviceEvents, DeviceProcessEvents
- `ProcessCommandLine` → AlertEvidence, BehaviorEntities, CloudProcessEvents, DeviceEvents, DeviceProcessEvents — also in `CloudProcessEvents`.
- `LogonId` → CloudProcessEvents, DeviceEvents, DeviceLogonEvents, DeviceProcessEvents, DisruptionAndResponseEvents — `DisruptionAndResponseEvents` and `CloudProcessEvents` extend the MDE logon trio.

---

## File identity

- `SHA256` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents, EmailAttachmentInfo, FileMaliciousContentInfo — canonical file pivot; reaches `FileMaliciousContentInfo` too.
- `SHA1` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents — only hash that joins `DeviceFileCertificateInfo` (code signing).
- `MD5` → DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents — legacy.
- `FileName` → AlertEvidence, BehaviorEntities, CloudProcessEvents, DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents, DisruptionAndResponseEvents, EmailAttachmentInfo, FileMaliciousContentInfo
- `FolderPath` → AlertEvidence, BehaviorEntities, CloudProcessEvents, DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents, FileMaliciousContentInfo
- `FileSize` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceProcessEvents, EmailAttachmentInfo, FileMaliciousContentInfo
- `FileOriginIP` → DeviceEvents, DeviceFileEvents
- `FileOriginUrl` → DeviceEvents, DeviceFileEvents
- `FileOwnerUpn` → FileMaliciousContentInfo
- `DocumentID` → FileMaliciousContentInfo

---

## Network — device-side (MDE)

- `RemoteIP` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceLogonEvents, DeviceNetworkEvents
- `LocalIP` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceNetworkEvents
- `RemoteUrl` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceNetworkEvents
- `RemotePort` → DeviceEvents, DeviceLogonEvents, DeviceNetworkEvents
- `LocalPort` → DeviceEvents, DeviceNetworkEvents
- `Protocol` → DeviceLogonEvents, DeviceNetworkEvents, IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents
- `RemoteIPType` → DeviceLogonEvents, DeviceNetworkEvents
- `RemoteDeviceName` → DeviceEvents, DeviceLogonEvents
- `ShareName` → DeviceFileEvents, DisruptionAndResponseEvents — device file-share activity, also surfaces in `DisruptionAndResponseEvents`.

## Network — identity / sign-in / cloud-apps

Distinct shape from device-side `Remote*`/`Local*` — actor-centric source
IP + port, `Destination*` / `Target*` for the target.

- `IPAddress` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, CloudAppEvents, CloudAuditEvents, CloudStorageAggregatedEvents, DataSecurityEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityDirectoryEvents, IdentityEvents, IdentityLogonEvents, IdentityQueryEvents, MicrosoftGraphActivityLogs, SigninLogs, UrlClickEvents — see casing gotchas above.
- `IpAddress` → AADUserRiskEvents, DisruptionAndResponseEvents, GraphAPIAuditEvents — camelCase `p` variant.
- `Port` → DisruptionAndResponseEvents, IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents
- `UserAgent` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, CloudAppEvents, CloudAuditEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityEvents, MicrosoftGraphActivityLogs, SigninLogs
- `GatewayJA4` → EntraIdSignInEvents, EntraIdSpnSignInEvents

---

## Logon correlation (device ↔ identity ↔ Entra sign-in)

- `LogonType` → AADSignInEventsBeta, DeviceLogonEvents, DisruptionAndResponseEvents, EntraIdSignInEvents, IdentityLogonEvents — MDE `DeviceLogonEvents` ↔ MDI `IdentityLogonEvents` ↔ Entra `AADSignInEventsBeta`/`EntraIdSignInEvents` ↔ `DisruptionAndResponseEvents`.
- `LogonId` → CloudProcessEvents, DeviceEvents, DeviceLogonEvents, DeviceProcessEvents, DisruptionAndResponseEvents
- `FailureReason` → DeviceLogonEvents, IdentityLogonEvents
- `ActionFailureReason` → IdentityEvents
- `ErrorCode` → AADSignInEventsBeta, AADSpnSignInEventsBeta, EntraIdSignInEvents, EntraIdSpnSignInEvents — Entra sign-in failure code (user + SPN, legacy + new).

## Sign-in events — Entra twins (user)

`AADSignInEventsBeta` and `EntraIdSignInEvents` are schema-compatible twins
(legacy vs new). Prefer `EntraIdSignInEvents` when available.

- `RiskLevelAggregated` → AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `RiskLevelDuringSignIn` → AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `RiskEventTypes` → AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `RiskState` → AADRiskyUsers, AADSignInEventsBeta, AADUserRiskEvents, EntraIdSignInEvents, SigninLogs
- `ConditionalAccessPolicies` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `ConditionalAccessStatus` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `AuthenticationProcessingDetails` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `AuthenticationRequirement` → AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `TokenIssuerType` → AADSignInEventsBeta, AADUserRiskEvents, EntraIdSignInEvents, SigninLogs
- `ClientAppUsed` → AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `Browser` → AADSignInEventsBeta, EntraIdSignInEvents
- `DeviceTrustType` → AADSignInEventsBeta, EntraIdSignInEvents
- `IsManaged` → AADSignInEventsBeta, EntraIdSignInEvents
- `IsCompliant` → AADSignInEventsBeta, DeviceBaselineComplianceAssessment, DeviceTvmSecureConfigurationAssessment, EntraIdSignInEvents
- `EndpointCall` → AADSignInEventsBeta, EntraIdSignInEvents
- `EntraIdDeviceId` → AADSignInEventsBeta, EntraIdSignInEvents
- `NetworkLocationDetails` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `LastPasswordChangeTimestamp` → AADSignInEventsBeta, EntraIdSignInEvents

## Sign-in events — Entra twins (service principal)

`AADSpnSignInEventsBeta` and `EntraIdSpnSignInEvents` — workload identity sign-ins.

- `IsManagedIdentity` → AADSpnSignInEventsBeta, EntraIdSpnSignInEvents
- `IsConfidentialClient` → AADSpnSignInEventsBeta, EntraIdSpnSignInEvents

---

## Geo enrichment

- `Country` → AADSignInEventsBeta, AADSpnSignInEventsBeta, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityAccountInfo, IdentityInfo
- `CountryCode` → CloudAppEvents, CloudAuditEvents
- `State` → AADSignInEventsBeta, AADSpnSignInEventsBeta, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityInfo
- `City` → AADSignInEventsBeta, AADSpnSignInEventsBeta, CloudAppEvents, CloudAuditEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityAccountInfo, IdentityInfo
- `Latitude` → AADSignInEventsBeta, AADSpnSignInEventsBeta, EntraIdSignInEvents, EntraIdSpnSignInEvents
- `Longitude` → AADSignInEventsBeta, AADSpnSignInEventsBeta, EntraIdSignInEvents, EntraIdSpnSignInEvents
- `Location` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADUserRiskEvents, AuditLogs, CloudStorageAggregatedEvents, GraphAPIAuditEvents, GraphNotificationsActivityLogs, IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents, MicrosoftGraphActivityLogs, SigninLogs
- `ISP` → CloudAppEvents, CloudAuditEvents, IdentityDirectoryEvents, IdentityLogonEvents

---

## Email chain

`NetworkMessageId` is the spine — `EmailEvents` → `EmailAttachmentInfo` →
`EmailUrlInfo` → `EmailPostDeliveryEvents` → `UrlClickEvents` →
`CampaignInfo` → `DataSecurityEvents` (+ `AlertEvidence` / `BehaviorEntities`
for XDR fusion).

- `NetworkMessageId` → AlertEvidence, BehaviorEntities, CampaignInfo, DataSecurityEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, UrlClickEvents
- `InternetMessageId` → DataSecurityEvents, EmailEvents, EmailPostDeliveryEvents
- `RecipientEmailAddress` → CampaignInfo, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents
- `SenderFromAddress` → EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents
- `RecipientObjectId` → EmailAttachmentInfo, EmailEvents
- `SenderObjectId` → EmailAttachmentInfo, EmailEvents, MessageEvents
- `SenderDisplayName` → EmailAttachmentInfo, EmailEvents, MessageEvents
- `Url` → Alert, EmailUrlInfo, MessageUrlInfo, UrlClickEvents
- `UrlDomain` → EmailUrlInfo, MessageUrlInfo
- `EmailDirection` → EmailEvents, EmailPostDeliveryEvents
- `DeliveryLocation` → EmailEvents, EmailPostDeliveryEvents, MessageEvents
- `DeliveryAction` → EmailEvents, MessageEvents
- `LatestDeliveryLocation` → EmailEvents, MessagePostDeliveryEvents
- `LatestDeliveryAction` → EmailEvents
- `EmailClusterId` → BehaviorEntities, EmailEvents
- `EmailSubject` → AlertEvidence, BehaviorEntities, DataSecurityEvents
- `Subject` → EmailEvents, MessageEvents

## Campaigns (MDO)

- `CampaignId` → CampaignInfo
- `CampaignName` → CampaignInfo
- `CampaignType` → CampaignInfo
- `CampaignSubType` → CampaignInfo

Join `CampaignInfo` to the email chain on `NetworkMessageId`.

---

## Teams chain

`TeamsMessageId` is the spine for `MessageEvents` / `MessagePostDeliveryEvents`
/ `MessageUrlInfo`. These do **not** share `NetworkMessageId` — pivot only
on `TeamsMessageId` within the Teams set.

- `TeamsMessageId` → MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo
- `SenderEmailAddress` → MessageEvents, MessagePostDeliveryEvents
- `RecipientDetails` → MessageEvents, MessagePostDeliveryEvents — dynamic — `parse_json` or `mv-expand`.
- `IsExternalThread` → MessageEvents, MessagePostDeliveryEvents
- `SafetyTip` → MessageEvents, MessagePostDeliveryEvents
- `ConfidenceLevel` → EmailEvents, MessageEvents, MessagePostDeliveryEvents, SecurityAlert
- `MessageType` → ConnectorStatusInfo, MessageEvents — also used by `ConnectorStatusInfo` (unrelated semantic — connector message type).

Cross-link to users/accounts via `SenderObjectId` (shared with email chain).

---

## Registry

- `RegistryKey` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceRegistryEvents
- `RegistryValueName` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceRegistryEvents
- `RegistryValueData` → AlertEvidence, BehaviorEntities, DeviceEvents, DeviceRegistryEvents

---

## TVM — software inventory

- `SoftwareName` → DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities
- `SoftwareVendor` → DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities
- `SoftwareVersion` → DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities

## TVM — vulnerabilities (device data ↔ CVE KB)

- `CveId` → DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareVulnerabilitiesKB
- `VulnerabilitySeverityLevel` → DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareVulnerabilitiesKB

## TVM — secure-config assessment (data ↔ KB)

- `ConfigurationId` → DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB, DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB — also in `DeviceBaselineCompliance*` — same field name, different semantic.
- `ConfigurationCategory` → DeviceBaselineComplianceAssessmentKB, DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB
- `ConfigurationSubcategory` → DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB
- `ConfigurationImpact` → DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB

## TVM — info-gathering

- `LastSeenTime` → DeviceTvmInfoGathering, DeviceTvmSoftwareEvidenceBeta

## TVM — browser extensions (device evidence ↔ KB)

- `BrowserName` → DeviceTvmBrowserExtensions, DeviceTvmBrowserExtensionsKB
- `ExtensionId` → DeviceTvmBrowserExtensions, DeviceTvmBrowserExtensionsKB
- `ExtensionName` → DeviceTvmBrowserExtensions, DeviceTvmBrowserExtensionsKB
- `ExtensionDescription` → DeviceTvmBrowserExtensions, DeviceTvmBrowserExtensionsKB
- `ExtensionVersion` → DeviceTvmBrowserExtensions, DeviceTvmBrowserExtensionsKB
- `ExtensionRisk` → DeviceTvmBrowserExtensions, DeviceTvmBrowserExtensionsKB

## Device baseline compliance (new)

- `ProfileId` → DeviceBaselineComplianceAssessment, DeviceBaselineComplianceProfiles
- `IsCompliant` → AADSignInEventsBeta, DeviceBaselineComplianceAssessment, DeviceTvmSecureConfigurationAssessment, EntraIdSignInEvents — shared with TVM secure-config + Entra sign-ins.
- `IsApplicable` → DeviceBaselineComplianceAssessment, DeviceTvmSecureConfigurationAssessment
- `AssessmentMethod` → DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB
- `RecommendedValue` → DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB
- `Source` → AADUserRiskEvents, DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB

Baseline KB ↔ TVM secure-config KB share control metadata:

- `ConfigurationName` → DeviceBaselineComplianceAssessmentKB, DeviceTvmSecureConfigurationAssessmentKB
- `ConfigurationDescription` → DeviceBaselineComplianceAssessmentKB, DeviceTvmSecureConfigurationAssessmentKB
- `RemediationOptions` → DeviceBaselineComplianceAssessmentKB, DeviceTvmSecureConfigurationAssessmentKB

---

## Cloud apps (MDCA)

- `Application` → AADSignInEventsBeta, AADSpnSignInEventsBeta, AlertEvidence, BehaviorEntities, CloudAppEvents, DataSecurityBehaviors, EntraIdSignInEvents, EntraIdSpnSignInEvents, IdentityDirectoryEvents, IdentityEvents, IdentityLogonEvents, IdentityQueryEvents
- `ApplicationId` → AADSignInEventsBeta, AADSpnSignInEventsBeta, AlertEvidence, BehaviorEntities, CloudAppEvents, EntraIdSignInEvents, EntraIdSpnSignInEvents, GraphAPIAuditEvents, GraphNotificationsActivityLogs
- `OAuthApplicationId` → AlertEvidence, BehaviorEntities

---

## Alerts & behaviors fan-out

- `AlertId` → Alert, AlertEvidence, AlertInfo
- `Title` → AlertEvidence, AlertInfo, BehaviorInfo, SecurityIncident
- `Severity` → AlertEvidence, AlertInfo, SecurityIncident
- `SentinelWorkspaceIds` → AlertEvidence, AlertInfo
- `ServiceSource` → AlertEvidence, AlertInfo, BehaviorEntities, BehaviorInfo, DataSecurityBehaviors
- `DetectionSource` → AlertEvidence, AlertInfo, BehaviorEntities, BehaviorInfo, DataSecurityBehaviors
- `AttackTechniques` → AlertEvidence, AlertInfo, BehaviorInfo, DataSecurityBehaviors
- `BehaviorId` → BehaviorEntities, BehaviorInfo, DataSecurityBehaviors
- `DataSources` → BehaviorEntities, BehaviorInfo
- `Categories` → AlertEvidence, BehaviorEntities, BehaviorInfo, DataSecurityBehaviors, DeviceTvmInfoGatheringKB, ExposureGraphNodes — `AlertInfo` uses scalar `Category` (singular), not the `Categories` array.
- `ActionType` → BehaviorEntities, BehaviorInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, DataSecurityBehaviors, DataSecurityEvents, DeviceEvents, DeviceFileEvents, DeviceImageLoadEvents, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents, DisruptionAndResponseEvents, EmailPostDeliveryEvents, IdentityDirectoryEvents, IdentityEvents, IdentityLogonEvents, IdentityQueryEvents, MessagePostDeliveryEvents, UrlClickEvents
- `Action` → AADProvisioningLogs, EmailPostDeliveryEvents, MessagePostDeliveryEvents
- `ActionCategory` → DataSecurityBehaviors
- `ActionResult` → EmailPostDeliveryEvents, IdentityEvents, MessagePostDeliveryEvents
- `ActionTrigger` → EmailPostDeliveryEvents, MessagePostDeliveryEvents
- `EntityType` → AlertEvidence, BehaviorEntities, GraphAPIAuditEvents
- `EntityRole` → BehaviorEntities
- `DetailedEntityRole` → BehaviorEntities
- `EvidenceRole` → AlertEvidence
- `EvidenceDirection` → AlertEvidence
- `ThreatFamily` → AlertEvidence, BehaviorEntities
- `CloudResource` → AlertEvidence, BehaviorEntities
- `CloudPlatform` → AlertEvidence, BehaviorEntities
- `ResourceType` → Alert, AlertEvidence, Heartbeat
- `ResourceID` → AlertEvidence
- `SubscriptionId` → AlertEvidence, CloudStorageAggregatedEvents, Heartbeat
- `StartTime` → Anomalies, BehaviorInfo, DataSecurityBehaviors, SecurityAlert, Usage
- `EndTime` → Anomalies, BehaviorInfo, DataSecurityBehaviors, SecurityAlert, Usage

---

## Email / file / message threat metadata

- `DetectionMethods` → EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, FileMaliciousContentInfo, MessageEvents, MessagePostDeliveryEvents, UrlClickEvents
- `ThreatTypes` → EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, FileMaliciousContentInfo, MessageEvents, MessagePostDeliveryEvents, UrlClickEvents
- `ThreatNames` → EmailAttachmentInfo, EmailEvents, FileMaliciousContentInfo
- `ThreatClassification` → EmailEvents

---

## Data security (Purview DLP / insider risk)

`DataSecurityEvents` and `DataSecurityBehaviors` cross-link to alerts via
`AttackTechniques` / `ServiceSource` / `DetectionSource` / `Categories`,
to email via `NetworkMessageId` / `InternetMessageId`, to users via
`AccountObjectId` / `AccountUpn`.

- `SensitivityLabelId` → DataSecurityEvents
- `SensitivityLabel` → DeviceFileEvents
- `SensitivitySubLabel` → DeviceFileEvents
- `ObjectId` → CloudAppEvents, DataSecurityEvents — DLP-scoped content id; also used by `CloudAppEvents`.
- `PrinterName` → DataSecurityBehaviors, DataSecurityEvents

---

## Attack disruption

`DisruptionAndResponseEvents` logs automatic attack-disruption actions
(user disable, device contain). Pivots on its Source/Target shape (see
*User / account identity* above) and on `PolicyId` / `PolicyName` /
`CompromisedAccountCount` (per-table).

---

## File threat intel

`FileMaliciousContentInfo` joins endpoint + email file events via
`SHA256`, `FileName`, `FileSize`, `FolderPath`. See *File identity*.

---

## Risk signals

- `IsAnomalous` → DataSecurityBehaviors
- `IsPolicyOn` → DisruptionAndResponseEvents
- `CompromisedAccountCount` → DisruptionAndResponseEvents

---

## Anomaly flags (dynamic)

- `UncommonForUser` → CloudAppEvents, IdentityLogonEvents — MDCA/MDI per-event anomaly signal; `parse_json` before filtering.
- `LastSeenForUser` → CloudAppEvents, IdentityLogonEvents — complements `UncommonForUser`; last-observed baseline.

---

## Multi-valued / JSON fields (require `mv-expand` or `parse_json`)

Filtering these with `==` or `contains` silently misses matches. Normalize
first.

- `AdditionalFields` → AlertEvidence, BehaviorEntities, BehaviorInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, ConnectorStatusInfo, DeviceEvents, DeviceFileEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceTvmHardwareFirmware, DeviceTvmInfoGathering, EmailEvents, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityLogonEvents, IdentityQueryEvents
- `RawEventData` → CloudAppEvents, CloudAuditEvents, IdentityEvents
- `Categories` → AlertEvidence, BehaviorEntities, BehaviorInfo, DataSecurityBehaviors, DeviceTvmInfoGatheringKB, ExposureGraphNodes
- `AttackTechniques` → AlertEvidence, AlertInfo, BehaviorInfo, DataSecurityBehaviors
- `ThreatTypes` → EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, FileMaliciousContentInfo, MessageEvents, MessagePostDeliveryEvents, UrlClickEvents
- `DetectionMethods` → EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, FileMaliciousContentInfo, MessageEvents, MessagePostDeliveryEvents, UrlClickEvents
- `DataSources` → BehaviorEntities, BehaviorInfo
- `SentinelWorkspaceIds` → AlertEvidence, AlertInfo
- `Tags` → DeviceTvmSecureConfigurationAssessmentKB, IdentityAccountInfo, IdentityInfo
- `ThreatNames` → EmailAttachmentInfo, EmailEvents, FileMaliciousContentInfo
- `UncommonForUser` → CloudAppEvents, IdentityLogonEvents
- `LastSeenForUser` → CloudAppEvents, IdentityLogonEvents
- `IPTags` → CloudAppEvents
- `UserAgentTags` → CloudAppEvents
- `ActivityObjects` → CloudAppEvents
- `SessionData` → CloudAppEvents
- `ConditionalAccessPolicies` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AADSignInEventsBeta, EntraIdSignInEvents, SigninLogs
- `Permissions` → OAuthAppInfo
- `GroupMembership` → IdentityAccountInfo, IdentityInfo
- `AssignedRoles` → IdentityAccountInfo, IdentityInfo, OAuthAppInfo
- `KnowledgeDetails` → **(not present in probe)**
- `AgentTopicsDetails` → **(not present in probe)**
- `AgentToolsDetails` → **(not present in probe)**
- `ConnectedAgentsSchemaNames` → **(not present in probe)**
- `ChildAgentsSchemaNames` → **(not present in probe)**
- `AccessCapabilities` → **(not present in probe)**
- `PolicyMatchInfo` → DataSecurityBehaviors
- `DlpPolicyMatchInfo` → DataSecurityEvents
- `DlpPolicyRuleMatchInfo` → DataSecurityEvents
- `SensitivityLabelInfo` → DataSecurityBehaviors
- `SensitiveInfoTypesInfo` → DataSecurityBehaviors
- `SharepointSiteInfo` → DataSecurityBehaviors
- `RemovableMediaInfo` → DataSecurityBehaviors, DataSecurityEvents
- `UrlDomainInfo` → DataSecurityBehaviors, DataSecurityEvents
- `DeviceInfo` → DataSecurityBehaviors, DataSecurityEvents
- `RecipientDetails` → MessageEvents, MessagePostDeliveryEvents
- `EnrolledMfas` → IdentityAccountInfo
- `EligibleRoles` → IdentityAccountInfo
- `TargetObjects` → IdentityEvents

---

## Misc shared fields

- `Description` → Anomalies, BehaviorInfo, ConnectorStatusInfo, DataSecurityBehaviors, DeviceTvmInfoGatheringKB, SecurityAlert, SecurityIncident
- `Context` → DeviceTvmSecureConfigurationAssessment, EmailEvents
- `LastModifiedTime` → DeviceTvmSoftwareVulnerabilitiesKB, FileMaliciousContentInfo, OAuthAppInfo, SecurityIncident
- `Workload` → DataSecurityEvents, FileMaliciousContentInfo, UrlClickEvents
- `Manager` → IdentityAccountInfo, IdentityInfo
- `Department` → DataSecurityEvents, IdentityAccountInfo, IdentityInfo
- `CreatedDateTime` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, IdentityAccountInfo, IdentityInfo, SigninLogs
- `DeletedDateTime` → IdentityAccountInfo, IdentityInfo
- `EmployeeId` → IdentityAccountInfo, IdentityInfo
- `GivenName` → IdentityAccountInfo, IdentityInfo
- `Surname` → IdentityAccountInfo, IdentityInfo
- `JobTitle` → IdentityAccountInfo, IdentityInfo
- `Address` → IdentityAccountInfo, IdentityInfo
- `Phone` → IdentityAccountInfo, IdentityInfo
- `EmailAddress` → IdentityAccountInfo, IdentityInfo
- `DisplayName` → IdentityAccountInfo, SecurityAlert
- `CriticalityLevel` → IdentityAccountInfo, IdentityInfo
- `SourceProvider` → IdentityAccountInfo, IdentityInfo
- `Type` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADSignInEventsBeta, AADSpnSignInEventsBeta, AADUserRiskEvents, Alert, AlertEvidence, AlertInfo, Anomalies, AuditLogs, BehaviorEntities, BehaviorInfo, CampaignInfo, CloudAppEvents, CloudAuditEvents, CloudDnsEvents, CloudProcessEvents, CloudStorageAggregatedEvents, ConnectorStatusInfo, DataSecurityBehaviors, DataSecurityEvents, DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB, DeviceBaselineComplianceProfiles, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, DeviceTvmBrowserExtensions, DeviceTvmCertificateInfo, DeviceTvmHardwareFirmware, DeviceTvmInfoGathering, DeviceTvmInfoGatheringKB, DeviceTvmSecureConfigurationAssessment, DeviceTvmSecureConfigurationAssessmentKB, DeviceTvmSoftwareEvidenceBeta, DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareVulnerabilitiesKB, DisruptionAndResponseEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, EntraIdSignInEvents, EntraIdSpnSignInEvents, ExposureGraphEdges, ExposureGraphNodes, FileMaliciousContentInfo, GraphAPIAuditEvents, GraphNotificationsActivityLogs, Heartbeat, IdentityAccountInfo, IdentityDirectoryEvents, IdentityEvents, IdentityInfo, IdentityLogonEvents, IdentityQueryEvents, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, MicrosoftGraphActivityLogs, OAuthAppInfo, Operation, SecurityAlert, SecurityIncident, SigninLogs, UrlClickEvents, Usage
- `BlastRadius` → IdentityInfo
- `RiskLevel` → AADRiskyUsers, AADUserRiskEvents, IdentityInfo, SigninLogs
- `RiskScore` → IdentityInfo, OAuthAppInfo
- `RiskLevelDetails` → IdentityInfo
- `RiskScoreUpdateTime` → IdentityInfo
- `IdentityEnvironment` → IdentityInfo
- `SourceProviders` → IdentityInfo

---

## Additional shared fields

Shared fields outside the curated pivot categories above. These are
generated directly from the tenant schema so connected workspace tables
and custom logs remain represented without manual renderer changes.

- `AADTenantId` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AuditLogs, SigninLogs
- `ActivityDateTime` → AADUserRiskEvents, AuditLogs
- `Agent` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `AlertName` → Alert, SecurityAlert
- `AlertSeverity` → Alert, SecurityAlert
- `ApiVersion` → AADGraphActivityLogs, GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `AppId` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, MicrosoftGraphActivityLogs, SigninLogs
- `AuthenticationContextClassReferences` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `AuthenticationDetails` → EmailEvents, SigninLogs
- `AuthenticationProtocol` → DisruptionAndResponseEvents, SigninLogs
- `AutonomousSystemNumber` → AADServicePrincipalSignInLogs, SigninLogs
- `Category` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AlertInfo, AuditLogs, Heartbeat, SigninLogs
- `ClientAuthMethod` → AADGraphActivityLogs, MicrosoftGraphActivityLogs
- `ClientCredentialType` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `ClientRequestId` → GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `Comments` → Alert, SecurityIncident
- `Computer` → Alert, Heartbeat, Operation, Usage
- `ConditionalAccessAudiences` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `ConditionalAccessPoliciesV2` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs
- `DurationMs` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AuditLogs, GraphNotificationsActivityLogs, MicrosoftGraphActivityLogs, SigninLogs
- `Entities` → Anomalies, SecurityAlert
- `ExtendedLinks` → Anomalies, SecurityAlert
- `ExtendedProperties` → Anomalies, SecurityAlert
- `FederatedCredentialId` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `HostName` → Alert, CloudProcessEvents
- `Id` → AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADUserRiskEvents, Anomalies, AuditLogs, SigninLogs
- `Identity` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AuditLogs, SigninLogs
- `IdentityProvider` → AADGraphActivityLogs, GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `InitiatedBy` → AADProvisioningLogs, AuditLogs
- `Level` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AuditLogs, SigninLogs
- `LocationDetails` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `MG` → Alert, Heartbeat, Operation
- `ManagementGroupName` → Alert, Heartbeat, Operation
- `OperationName` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADRiskyUsers, AADServicePrincipalSignInLogs, AADUserRiskEvents, AuditLogs, CloudAuditEvents, SigninLogs
- `OperationVersion` → AADManagedIdentitySignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AuditLogs, SigninLogs
- `ProviderName` → SecurityAlert, SecurityIncident
- `Query` → Alert, IdentityQueryEvents
- `RequestMethod` → AADGraphActivityLogs, GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `RequestUri` → AADGraphActivityLogs, GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `Resource` → AuditLogs, Heartbeat, SigninLogs
- `ResourceGroup` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AuditLogs, CloudStorageAggregatedEvents, Heartbeat, SigninLogs
- `ResourceIdentity` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, GraphNotificationsActivityLogs, SigninLogs
- `ResourceOwnerTenantId` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `ResourceProvider` → AuditLogs, Heartbeat, SigninLogs
- `ResourceServicePrincipalId` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, SigninLogs
- `ResponseSizeBytes` → AADGraphActivityLogs, MicrosoftGraphActivityLogs
- `ResponseStatusCode` → AADGraphActivityLogs, GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `ResultDescription` → AADManagedIdentitySignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AuditLogs, GraphNotificationsActivityLogs, SigninLogs
- `ResultSignature` → AADGraphActivityLogs, AADManagedIdentitySignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AuditLogs, SigninLogs
- `ResultType` → AADManagedIdentitySignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AuditLogs, SigninLogs
- `RiskDetail` → AADRiskyUsers, AADUserRiskEvents, SigninLogs
- `Roles` → AADGraphActivityLogs, MicrosoftGraphActivityLogs
- `Scopes` → AADGraphActivityLogs, GraphAPIAuditEvents, MicrosoftGraphActivityLogs
- `ServicePrincipalCredentialKeyId` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs
- `ServicePrincipalCredentialThumbprint` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs
- `SignInActivityId` → AADGraphActivityLogs, MicrosoftGraphActivityLogs
- `Solution` → Operation, Usage
- `SourceAppClientId` → AADManagedIdentitySignInLogs, SigninLogs
- `SourceComputerId` → Heartbeat, Operation, SecurityAlert
- `SourceLocation` → Anomalies, EmailPostDeliveryEvents
- `Status` → DeviceBaselineComplianceProfiles, SecurityAlert, SecurityIncident, SigninLogs
- `Tactics` → Anomalies, SecurityAlert
- `Techniques` → Anomalies, SecurityAlert
- `TokenIssuedAt` → AADGraphActivityLogs, MicrosoftGraphActivityLogs
- `UniqueTokenIdentifier` → AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, GraphAPIAuditEvents, SigninLogs
- `UserDisplayName` → AADRiskyUsers, AADUserRiskEvents, SigninLogs
- `UserId` → AADGraphActivityLogs, AADUserRiskEvents, MicrosoftGraphActivityLogs, SigninLogs
- `UserPrincipalName` → AADRiskyUsers, AADUserRiskEvents, Anomalies, SigninLogs
- `VendorName` → Anomalies, SecurityAlert
- `Wids` → AADGraphActivityLogs, MicrosoftGraphActivityLogs

---

## Worked pivot recipes

**1) Hash → everywhere it ran (endpoint + email + TI):**
```kql
let h = "SHA256_HERE";
union
  (DeviceProcessEvents      | where SHA256 == h | project Timestamp, Table="DeviceProcessEvents",      DeviceName, AccountUpn=InitiatingProcessAccountUpn, FileName, FolderPath),
  (DeviceFileEvents         | where SHA256 == h | project Timestamp, Table="DeviceFileEvents",         DeviceName, AccountUpn=InitiatingProcessAccountUpn, FileName, FolderPath),
  (DeviceImageLoadEvents    | where SHA256 == h | project Timestamp, Table="DeviceImageLoadEvents",    DeviceName, AccountUpn=InitiatingProcessAccountUpn, FileName, FolderPath),
  (EmailAttachmentInfo      | where SHA256 == h | project Timestamp, Table="EmailAttachmentInfo",      DeviceName=tostring(dynamic(null)), AccountUpn=RecipientEmailAddress, FileName, FolderPath=tostring(dynamic(null))),
  (FileMaliciousContentInfo | where SHA256 == h | project Timestamp, Table="FileMaliciousContentInfo", DeviceName=tostring(dynamic(null)), AccountUpn=FileOwnerUpn, FileName, FolderPath)
| order by Timestamp asc
```

**2) Entra sign-in ↔ MDE logon correlation (same UPN, same window):**
```kql
EntraIdSignInEvents
| where Timestamp > ago(1h) and ErrorCode == 0
| project EntraTime=Timestamp, AccountUpn, EntraIP=IPAddress, EntraCity=City, DeviceTrustType, IsCompliant
| join kind=inner (
  DeviceLogonEvents | where Timestamp > ago(1h) and ActionType == "LogonSuccess"
  | extend AccountUpn = strcat(AccountName, "@", AccountDomain)
  | project DeviceTime=Timestamp, DeviceName, AccountUpn, DeviceLogonType=LogonType, DeviceRemoteIP=RemoteIP
  ) on AccountUpn
| where abs(datetime_diff('second', EntraTime, DeviceTime)) < 300
```

**3) OAuth app compromise triangulation (app ↔ SPN sign-ins ↔ Graph calls):**
```kql
OAuthAppInfo
| where AppName has "SuspectApp"
| project OAuthAppId, ServicePrincipalId, Permissions, IsAdminConsented, ConsentedUsersCount
| join kind=inner (
  EntraIdSpnSignInEvents | project SpnTime=Timestamp, ServicePrincipalId, ApplicationId, IPAddress, Country, ErrorCode
  ) on ServicePrincipalId
| join kind=leftouter (
  GraphAPIAuditEvents | project GraphTime=Timestamp, ServicePrincipalId, RequestUri, ResponseStatusCode, RequestMethod, Scopes
  ) on ServicePrincipalId
| order by SpnTime asc
```

**4) Cloud workload → process activity (MDC ↔ MDE by Azure resource):**
```kql
DeviceInfo
| where isnotempty(AzureResourceId)
| project DeviceId, DeviceName, AzureResourceId
| join kind=inner (
  CloudProcessEvents | project CloudTime=Timestamp, AzureResourceId, ProcessCommandLine, FileName, AccountName, LogonId
  ) on AzureResourceId
| project CloudTime, DeviceName, AccountName, FileName, ProcessCommandLine
```

**5) Email campaign → users who clicked a link:**
```kql
EmailEvents
| where NetworkMessageId in ("MSG_ID1","MSG_ID2")
| join kind=inner UrlClickEvents on NetworkMessageId
| project ClickTime=Timestamp1, AccountUpn, Url, NetworkMessageId, Subject
```

**6) Entra user → every surface they touched:**
```kql
let oid = toscalar(IdentityInfo | where AccountUpn == "user@domain.com" | take 1 | project AccountObjectId);
union
  (DeviceProcessEvents     | where AccountObjectId == oid | project Timestamp, Table="DeviceProcessEvents",     Detail=ProcessCommandLine),
  (IdentityLogonEvents     | where AccountObjectId == oid | project Timestamp, Table="IdentityLogonEvents",     Detail=strcat(LogonType, " from ", IPAddress)),
  (IdentityDirectoryEvents | where AccountObjectId == oid | project Timestamp, Table="IdentityDirectoryEvents", Detail=ActionType),
  (EntraIdSignInEvents     | where AccountObjectId == oid | project Timestamp, Table="EntraIdSignInEvents",     Detail=strcat(Application, " @ ", IPAddress, " err=", tostring(ErrorCode))),
  (CloudAppEvents          | where AccountObjectId == oid | project Timestamp, Table="CloudAppEvents",          Detail=strcat(Application, " / ", ActionType)),
  (GraphAPIAuditEvents     | where AccountObjectId == oid | project Timestamp, Table="GraphAPIAuditEvents",     Detail=strcat(RequestMethod, " ", RequestUri)),
  (AlertEvidence           | where AccountObjectId == oid | project Timestamp, Table="AlertEvidence",           Detail=strcat(Title, " [", Severity, "]"))
| order by Timestamp asc
```

**7) Alert → all evidence → device activity around the event:**
```kql
AlertInfo
| where AlertId == "ALERT_ID"
| join kind=inner AlertEvidence on AlertId
| where isnotempty(DeviceId) and isnotempty(Timestamp)
| project AlertId, DeviceId, PivotFrom=Timestamp
| join kind=inner (
    DeviceEvents | project DeviceId, Timestamp, ActionType, FileName, ProcessCommandLine
  ) on DeviceId
| where Timestamp between (PivotFrom - 10m .. PivotFrom + 10m)
```

**8) CVE → vulnerable devices with CVSS / exploit context:**
```kql
DeviceTvmSoftwareVulnerabilitiesKB
| where CveId == "CVE-YYYY-NNNNN"
| project CveId, CvssScore, IsExploitAvailable, VulnerabilityDescription
| join kind=inner DeviceTvmSoftwareVulnerabilities on CveId
| project DeviceName, SoftwareName, SoftwareVersion, CveId, CvssScore, IsExploitAvailable
```
