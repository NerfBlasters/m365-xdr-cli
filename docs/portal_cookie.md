# Portal-cookie backend: support and limits

The default `auto` preference selects official authentication when a configured
app secret or a matching MSAL access/refresh token is present. If those are absent
and a structurally usable cookie store matches the configured tenant, commands
select `portal-cookie` automatically. Importing a cookie is sufficient; no backend
flag or configuration change is needed. Client ID/secret and MSAL are optional
for a cookie-only setup; the tenant ID remains required.

Explicit `--backend official|portal-cookie` wins over configuration. A configured
`api_backend = "official"` or `"portal-cookie"` pins that choice; `"auto"` restores
automatic selection. CLI flags and the resolved choice do not rewrite the saved
preference. `auth status` reports `backend` and `backend_preference`.

Selection reads local stores without contacting Microsoft. It does not establish
remote validity. Expired MSAL access tokens still count as present; refresh-token
recovery belongs to MSAL. A corrupt/unreadable MSAL cache preserves official auth
and its recovery path. Cookie stores from another tenant or with missing required
material are not selected automatically. If neither credential method is present,
the normal official configuration/login guidance applies.

A command selects once, before session attribution and API work. Authentication,
permission, network, or service errors never trigger a backend change or replay a
request. With both credentials present, use an explicit override when you want to
exercise cookie mode. In auto mode, `auth login` can establish MSAL credentials;
`auth logout` removes credentials only for the backend selected for that invocation.

## Supported operations

Cookie authentication supports hunting, library and schema hunting workflows,
incident/alert reads and evidence, guided investigations, domain discovery,
exact device lookup, and device timelines. Incident updates support status,
classification, determination, and comments.

Device actions include Quick/Full antivirus scans, Selective/Full isolation,
unisolation, execution restriction, investigation-package collection/download,
and action status reads. `device unrestrict DEVICE_ID --comment "Recovery reason"`
removes the execution restriction, with confirmation or `--yes`. Official auth
uses Microsoft's [unrestrict API](https://learn.microsoft.com/en-us/defender-endpoint/api/unrestrict-code-execution);
cookie auth submits the captured native `Unrestrict` policy action.
Submission acceptance does not mean an action succeeded; use `device action-status`
to check its outcome. Action completion does not independently prove an antivirus
scan has finished.

## Domain sources

`xdr domains list` saves source-labelled records from Entra and MDI-observed
Active Directory domains. `--source entra` and `--source active-directory` select
one source. Each record preserves its provider's identifier and native fields,
plus `name` and `source`; same-named records are not merged. Only Entra records
supply tenant verification semantics. AD records include `isDeleted` and must
not be treated as exhaustive forest discovery.

Official auth supports Entra only. Default combined listing then returns a
private artifact plus exit 14 for unavailable AD coverage. Explicit
`--source entra` returns normal success. AD reads are bounded to 100 rows;
`context.sources` reports the native `has_more`, returned count, reported total,
and errors. Missing sources, truncation, or count discrepancies preserve usable
records and report partial success. A valid empty response is distinguishable
from unavailable data. No undocumented continuation parameter is guessed.

## Device fields

Device responses preserve the portal record in `portal_source.raw`, identify
unavailable fields, and mark field parity partial. `OsProcessor` values `32-bit`
and `64-bit` map to official `osArchitecture`; they do not establish the deprecated
`osProcessor` value (`x64`, for example). Other bitness values stay unmapped.

The portal's `lastSeen` follows its observation view; the official property is
the last full device report. This semantic difference is also recorded in
`portal_source.field_notes`. See Microsoft's
[Machine resource reference](https://learn.microsoft.com/en-us/defender-endpoint/api/machine).

Additional mappings use device details and bounded, exact-ID supplementary reads:

| Field | Portal source and conversion |
|---|---|
| `deviceValue` | Inventory `DynamicAssetValue`, then `AssetValue`; explicit null values use the portal's `Normal` default. Criticality is a separate property. |
| `machineTags` | Detail `ExtendedMachineTags.UserDefinedTags` plus `DynamicRulesTags`, deduplicated. Cloud-app labels and group/system labels stay in raw data. |
| `managedBy` | Detail `MemEnrollmentStatus` mapped to official provider enum names. |
| `managedByStatus` | Enrollment outcome normalized to official `Unknown`, `Success`, or `Error`; detailed native codes remain in raw data. |
| `rbacGroupName` | Inventory `MachineGroup`, only when its RBAC group ID matches device detail. AD `ParentGroups` is not used. |
| `ipAddresses` | Reported IP adapters, with address/MAC/interface/status fields. Portal data can omit loopbacks; this collection is not a complete official-API equivalent. |
| `exclusionReason` | Null for explicitly included devices; excluded-device justification converted to the official exclusion enum after exact-device correlation. |
| `vmMetadata` | Explicit null cloud-resource data, or Azure `VmId`, `ResourceId`, and `SubscriptionId` with an explicit Azure environment. Other cloud shapes remain unmapped. |
| `mergedIntoMachineId` | Direct `MergedIntoMachineId` when supplied; absence does not imply null. |

The official provider, management-status, exclusion, and cloud enums are defined
by the [MDE service metadata](https://api.security.microsoft.com/api/$metadata).
The native enrollment code is retained because its detailed error information
is more specific than the official status enum. Unknown codes are left unmapped.

Inventory enrichment searches the exact hostname with a 100-row bound and uses
only a unique matching MachineId. `portal_source.supplementary` retains the
selected inventory record and adapter/exclusion responses; `field_sources` records
the conversions. Optional-source permission or response-shape failures are listed
in `enrichment_errors` and leave affected fields unavailable. Authentication,
rate-limit, network, and timeout errors stop the command. Action submission
prerequisite reads do not fetch these supplementary views.

These views can disagree in time and meaning. In particular, the device-detail
enrollment state can differ from inventory `ManagedBy` and the official API's
last full report. Cloud-resource data describes the portal's discovered resource;
null does not establish that the host is physically non-virtual. No inferred
loopbacks, processor families, or duplicate flags are added.

`isPotentialDuplication` has no established source in these portal contracts.
The deprecated `osProcessor` cannot be recovered from 32/64-bit architecture.
A merge target remains unavailable when the portal omits it. Missing fields,
unknown enum values, and unsupported cloud shapes remain explicit in
`portal_source.unavailable_fields`; they are not replaced with synthetic defaults.

## Action history

The device's overflow-menu Action Center displays real success/failure for the
latest retained action in each category. The CLI reads that same source and
correlates exact action/device IDs. An older action may disappear after another
action of the same category replaces it. Global Action Center history can label
both failed and successful actions `Completed`; it cannot supply a trustworthy
outcome for a superseded action. This is a documented portal limitation, not a
reason to infer success. Keep official auth available when such history is needed.

## Credentials and operation

Cookies remain user-session credentials: expiry, Conditional Access and portal
RBAC still apply. Manual import works. Automatic browser export/renewal and
unattended reauthentication are not shipped. `auth status` checks local storage,
not remote session validity. Explicit cookie-mode `auth login` directs import;
`auth logout` deletes local cookies without revoking Microsoft's browser session
or deleting official credentials.

New cookie-mode sessions use the existing `automatic` identity placeholder;
it is not an authenticated operator UPN. They do not borrow the MSAL account.
Schema maintenance honors the selected backend. Investigation-package transfers
use a separate client without portal credentials, publish private ZIP files
atomically, and do not extract files.

Browser-assisted renewal is scoped separately in the
[browser cookie renewal follow-up proposal](browser_cookie_renewal.md), including
manual renewal, profile ownership, tenant verification, failure recovery, optional
dependencies, and acceptance checks.
