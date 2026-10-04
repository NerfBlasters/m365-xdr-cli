"""Backend selection and explicit, cookie-authenticated portal operations.

The portal backend is deliberately capability based. Unsupported official API
operations fail locally; they never fall back to an MSAL token or generic proxy.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from enum import Enum

import httpx

from xdr_cli.action_associations import load_action_device, remember_action_device
from xdr_cli.auth import AuthManager
from xdr_cli.backend_contract import (
    PORTAL_PROFILE,
    APIBackend,
    Backend,
    UnsupportedBackendCapability,
)
from xdr_cli.backend_selection import select_backend
from xdr_cli.client import XDRClient
from xdr_cli.config import Config
from xdr_cli.continuation import validate_continuation
from xdr_cli.device_fields import adapter_addresses, additional_device_fields, exclusion_reason
from xdr_cli.exceptions import (
    APIError,
    ConfigError,
    ConflictError,
    ForbiddenError,
    NetworkError,
    NotAuthenticatedError,
    NotFoundError,
    QueryError,
    RateLimitError,
    TimeoutError,
    UsageError,
    parse_retry_after,
)
from xdr_cli.hunting_result import HuntingResult, _normalize_response
from xdr_cli.official_backend import OfficialBackend
from xdr_cli.output import err_console
from xdr_cli.portal_auth import load_portal_cookies
from xdr_cli.portal_client import CookieAuth


class _Operation(Enum):
    PACKAGE_LINK = (
        "GET", "/apiproxy/mtp/responseApiPortal/requests/forensics/downloaduribyguid/V2",
    )
    ACTION_CREATE = ("POST", "/apiproxy/mtp/responseApiPortal/requests/create")
    ACTION_STATUS = ("GET", "/apiproxy/mtp/responseApiPortal/requests/latest")
    TENANT = ("GET", "/apiproxy/mtp/sccManagement/mgmt/TenantContext")
    DOMAINS = ("GET", "/apiproxy/msgraph/v1.0/domains")
    AD_DOMAINS = ("GET", "/apiproxy/aatp/api/domains/search")
    AD_DOMAIN_COUNT = ("GET", "/apiproxy/aatp/api/domains/totalCount")
    INCIDENTS = ("GET", "/apiproxy/msgraph/v1.0/security/incidents")
    INCIDENT = ("GET", "/apiproxy/msgraph/v1.0/security/incidents/{identifier}")
    INCIDENT_UPDATE = ("PATCH", "/apiproxy/msgraph/v1.0/security/incidents/{identifier}")
    INCIDENT_COMMENT = ("POST", "/apiproxy/msgraph/v1.0/security/incidents/{identifier}/comments")
    ALERTS = ("GET", "/apiproxy/msgraph/v1.0/security/alerts_v2")
    ALERT = ("GET", "/apiproxy/msgraph/v1.0/security/alerts_v2/{identifier}")
    DEVICES = ("GET", "/apiproxy/mtp/ndr/machines")
    DEVICE = ("GET", "/apiproxy/mtp/getMachine/machines")
    DEVICE_IPS = ("GET", "/apiproxy/mtp/getLatestMachineIpsByIds/LatestMachineIpsByIds")
    DEVICE_EXCLUSION = ("GET", "/apiproxy/mtp/ndr/machines/{identifier}/exclusionDetails")
    HUNT = ("POST", "/apiproxy/hunting/huntingQueryExecutorService/queryExecutor/v1/external")


class PortalBackend(Backend):
    """Named portal operations with authenticated tenant binding per client."""

    profile = PORTAL_PROFILE

    def __init__(self, config: Config, timeout: float) -> None:
        if not config.tenant_id:
            raise ConfigError("portal-cookie requires a configured tenant_id.")
        cookies = load_portal_cookies(config.tenant_id)
        if not cookies:
            raise self._auth_error()
        self._auth = CookieAuth(
            sccauth=cookies.get("sccauth"),
            xsrf_token=cookies.get("xsrf_token", ""),
            sccauth_chunks=cookies.get("sccauth_chunks"),
            cookie_header=cookies.get("cookie_header"),
        )
        self._tenant_id = config.tenant_id
        self._verified = False
        self._client = httpx.AsyncClient(
            base_url="https://security.microsoft.com", timeout=timeout,
            follow_redirects=False,
            headers={"Accept": "application/json", "Origin": "https://security.microsoft.com"},
        )

    @staticmethod
    def _auth_error() -> NotAuthenticatedError:
        return NotAuthenticatedError(
            "Portal credentials are missing, expired, or require interactive sign-in.",
            suggested_fix="Refresh credentials with xdr auth portal-cookie <cookie-source>.",
        )

    async def _request(
        self, operation: _Operation, *, body: dict | None = None, params: dict | None = None,
        identifier: str | None = None, raw_query: bytes | None = None,
    ) -> dict:
        method, path = operation.value
        if "{identifier}" in path:
            pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,511}" if operation in (
                _Operation.ALERT,
            ) else r"[0-9]+"
            if operation is _Operation.DEVICE_EXCLUSION:
                pattern = r"[0-9a-fA-F]{40}"
            if not isinstance(identifier, str) or not re.fullmatch(pattern, identifier):
                raise UsageError("Invalid identifier for the selected portal operation.")
            path = path.format(identifier=identifier)
        request = self._client.build_request(method, path, json=body, params=params)
        if raw_query is not None:
            request.url = request.url.copy_with(query=raw_query)
        await self._auth.apply(request)
        request.headers["tenant-id"] = self._tenant_id
        request.headers["x-tid"] = self._tenant_id
        if operation is _Operation.HUNT:
            request.headers["X-Hunting-Execution-Context"] = '{"SelectedWorkspaces":{}}'
        mutating = operation in (
            _Operation.INCIDENT_UPDATE, _Operation.INCIDENT_COMMENT, _Operation.ACTION_CREATE,
        )
        try:
            response = await self._client.send(request)
        except httpx.TimeoutException as exc:
            message = "Portal request timed out."
            if mutating:
                target = "device" if operation is _Operation.ACTION_CREATE else "incident"
                message += f" Outcome unknown; inspect the {target} before retrying."
            raise TimeoutError(message, retryable=not mutating) from exc
        except httpx.TransportError as exc:
            message = "Portal transport failed."
            if mutating:
                target = "device" if operation is _Operation.ACTION_CREATE else "incident"
                message += f" Outcome unknown; inspect the {target} before retrying."
            raise NetworkError(message, retryable=not mutating) from exc
        status = response.status_code
        # Never follow a login redirect with session credentials.
        if status in (401, 440) or response.is_redirect:
            raise self._auth_error()
        if status == 403:
            error = ForbiddenError()
            error.suggested_fix = (
                "Check the signed-in user's Defender portal roles and permissions."
            )
            raise error
        if status == 404:
            raise NotFoundError("portal object")
        if status == 429:
            raise RateLimitError(retry_after=parse_retry_after(response.headers.get("Retry-After")))
        if "text/html" in response.headers.get("content-type", "").lower():
            raise self._auth_error()
        if status == 400 and operation is _Operation.HUNT:
            raise QueryError("Portal hunting rejected the query or its request parameters.")
        if not response.is_success:
            raise APIError("Portal request failed.", status_code=status)
        if status == 204 and mutating:
            return {}
        if operation is _Operation.PACKAGE_LINK:
            try:
                value = response.json() if "json" in response.headers.get(
                    "content-type", ""
                ).lower() else response.text.strip()
            except ValueError:
                raise APIError("Portal package link was malformed.") from None
            if not isinstance(value, str):
                raise APIError("Portal package link was not a URL string.")
            from xdr_cli.package_download import validate_package_url

            validate_package_url(value)
            return {"url": value}
        try:
            result = response.json()
        except ValueError as exc:
            raise APIError("Portal returned malformed JSON.", status_code=status) from exc
        if operation in (_Operation.DEVICES, _Operation.ACTION_STATUS) and isinstance(result, list):
            return result
        if not isinstance(result, dict):
            raise APIError("Portal returned an unexpected response shape.", status_code=status)
        if operation is _Operation.AD_DOMAINS:
            return result  # Preserve useful records alongside native partial errors.
        if any(result.get(key) for key in ("error", "errors", "Error", "Errors")):
            raise APIError("Portal returned an application error.", status_code=status)
        return result

    async def verify_tenant(self) -> None:
        if self._verified:
            return
        result = await self._request(_Operation.TENANT)
        info = result.get("AuthInfo")
        actual = info.get("TenantId") if isinstance(info, dict) else None
        if not isinstance(actual, str) or actual.casefold() != self._tenant_id.casefold():
            raise ConfigError(
                "Authenticated portal tenant does not match configured tenant_id. "
                "Import cookies for the configured tenant."
            )
        self._verified = True

    async def execute_hunting(self, query: str) -> HuntingResult:
        await self.verify_tenant()
        result = await self._request(_Operation.HUNT, body={
            "QueryText": query, "EncodedQueryText": query,
            "StartTime": None, "EndTime": None, "MaxRecordCount": 100000,
            "TenantIds": None, "tenantIds": None, "selectedWorkspaces": None,
            "QueryOrigin": "User",
        })
        schema, rows = result.get("Schema"), result.get("Results")
        if (
            not isinstance(schema, list) or not isinstance(rows, list)
            or any(not isinstance(row, dict) for row in rows)
            or any(not isinstance(col, dict) or not isinstance(col.get("Name"), str)
                   or not isinstance(col.get("Type"), str) for col in schema)
        ):
            raise APIError("Portal hunting returned an unexpected result shape.")
        normalized = _normalize_response(result)
        normalized.schema = [{"name": col["name"], "type": col["type"]}
                             for col in normalized.schema]
        normalized.stats = {
            "PortalSchema": result["Schema"],
            **{key: result[key] for key in ("Quota", "EnhancedQueryStats") if key in result},
        }
        normalized.metadata = {"portal_query_stats": normalized.stats}
        return normalized

    async def _graph_pages(
        self, operation: _Operation, *, params: dict | None = None, limit: int = 0,
    ) -> AsyncIterator[dict]:
        if operation not in (_Operation.DOMAINS, _Operation.INCIDENTS, _Operation.ALERTS):
            raise UnsupportedBackendCapability()
        await self.verify_tenant()
        seen_links: set[str] = set()
        seen_ids: set[str] = set()
        query = None
        count = 0
        for _ in range(1000):
            result = await self._request(operation, params=params, raw_query=query)
            rows = result.get("value")
            if not isinstance(rows, list):
                raise APIError("Portal Graph collection returned an unexpected shape.")
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                    raise APIError("Portal Graph collection returned an invalid object.")
                if row["id"] in seen_ids:
                    # Offset pages can overlap when the live collection changes.
                    continue
                seen_ids.add(row["id"])
                yield row
                count += 1
                if limit and count >= limit:
                    return
            next_link = result.get("@odata.nextLink")
            if not next_link:
                return
            path = operation.value[1]
            url = validate_continuation(
                next_link, seen=seen_links, routes=frozenset({
                    ("graph.microsoft.com", path.removeprefix("/apiproxy/msgraph")),
                    ("security.microsoft.com", path),
                }),
            )
            # Transfer only query bytes onto the fixed portal route. Cookies
            # are never sent to Graph or to a continuation-supplied origin.
            query = url.query
            params = None
        raise APIError("Portal Graph pagination exceeded its page bound.")

    async def list_domains(self) -> list[dict]:
        return [row async for row in self.iter_domains()]

    async def iter_domains(self) -> AsyncIterator[dict]:
        async for row in self._graph_pages(_Operation.DOMAINS):
            yield row

    async def read_ad_domains(self) -> dict:
        await self.verify_tenant()
        result = await self._request(_Operation.AD_DOMAINS, params={"limit": 100})
        rows = result.get("results")
        if (not isinstance(rows, list) or type(result.get("hasMore")) is not bool
                or len(rows) > 100):
            raise APIError("Portal AD domain search returned an invalid envelope.")
        seen = set()
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                    or not row["id"] or not isinstance(row.get("dnsName"), str)
                    or not row["dnsName"] or row["id"] in seen):
                raise APIError("Portal AD domain search returned invalid or duplicate records.")
            seen.add(row["id"])
        return result

    async def count_ad_domains(self) -> int:
        await self.verify_tenant()
        result = await self._request(_Operation.AD_DOMAIN_COUNT)
        count = result.get("totalCount")
        if type(count) is not int or count < 0:
            raise APIError("Portal AD domain count returned an invalid value.")
        return count

    async def list_incidents(self, *, params: dict, limit: int = 0) -> AsyncIterator[dict]:
        async for row in self._graph_pages(_Operation.INCIDENTS, params=params, limit=limit):
            yield row

    async def list_alerts(self, *, params: dict, limit: int = 0) -> AsyncIterator[dict]:
        async for row in self._graph_pages(_Operation.ALERTS, params=params, limit=limit):
            yield row

    async def get_incident(self, incident_id: str, *, expand: list[str] | None = None) -> dict:
        if not re.fullmatch(r"[0-9]+", incident_id):
            raise UsageError("Portal incident reads require a numeric incident ID.")
        if expand and set(expand) != {"alerts"}:
            raise UnsupportedBackendCapability()
        await self.verify_tenant()
        result = await self._request(
            _Operation.INCIDENT, identifier=incident_id,
            params={"$expand": "alerts"} if expand else None,
        )
        if result.get("id") != incident_id:
            raise APIError("Portal Graph returned a different incident ID.")
        if expand:
            alerts = result.get("alerts")
            if not isinstance(alerts, list):
                raise APIError("Portal Graph did not return expanded alerts.")
            for alert in alerts:
                self._validate_alert(alert)
        return result

    @staticmethod
    def _validate_alert(result: dict) -> None:
        if not isinstance(result, dict) or not isinstance(result.get("id"), str):
            raise APIError("Portal Graph returned an invalid alert.")
        evidence = result.get("evidence")
        if not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence):
            raise APIError("Portal Graph alert evidence has an unexpected shape.")

    async def get_alert(self, alert_id: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,511}", alert_id):
            raise UsageError("Invalid portal alert ID.")
        await self.verify_tenant()
        result = await self._request(_Operation.ALERT, identifier=alert_id)
        self._validate_alert(result)
        if result["id"] != alert_id:
            raise APIError("Portal Graph returned a different alert ID.")
        return result

    async def update_incident(self, incident_id: str, payload: dict) -> dict:
        if not re.fullmatch(r"[0-9]+", incident_id):
            raise UsageError("Portal incident updates require a numeric incident ID.")
        allowed = {"status", "classification", "determination"}
        if not payload or not set(payload).issubset(allowed):
            raise UsageError("Unsupported portal incident update fields.")
        await self.verify_tenant()
        return await self._request(_Operation.INCIDENT_UPDATE, identifier=incident_id, body=payload)

    async def add_incident_comment(self, incident_id: str, comment: str) -> dict:
        if not re.fullmatch(r"[0-9]+", incident_id):
            raise UsageError("Portal incident comments require a numeric incident ID.")
        await self.verify_tenant()
        return await self._request(
            _Operation.INCIDENT_COMMENT, identifier=incident_id, body={"comment": comment},
        )

    async def find_device_by_hostname(self, hostname: str, *, enrich: bool = True) -> dict | None:
        if not hostname or len(hostname) > 253:
            raise UsageError("Device hostname must contain between 1 and 253 characters.")
        await self.verify_tenant()
        matches: set[str] = set()
        seen: set[str] = set()
        for page in range(1, 101):
            rows = await self._request(_Operation.DEVICES, params={
                "machineSearchPrefix": hostname, "hideLowFidelityDevices": "false",
                "lookingBackIndays": 180, "pageIndex": page, "pageSize": 100,
                "sortByField": "riskscore", "sortOrder": "Descending",
            })
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise APIError("Portal device search returned an unexpected response shape.")
            for row in rows:
                machine_id = row.get("SenseMachineId")
                # Inventory includes assets that do not have an MDE identity.
                if (not isinstance(machine_id, str)
                        or not re.fullmatch(r"[0-9a-fA-F]{40}", machine_id)):
                    continue
                if machine_id in seen:
                    continue
                seen.add(machine_id)
                name = row.get("ComputerDnsName")
                if isinstance(name, str) and name.casefold() == hostname.casefold():
                    matches.add(machine_id)
            if len(rows) < 100:
                break
        else:
            raise APIError("Portal device search exceeded its page bound.")
        if len(matches) > 1:
            raise ConflictError("Multiple MDE devices match this hostname; supply a MachineId.")
        if not matches:
            return None
        return await self.get_device(next(iter(matches)), enrich=enrich)

    async def get_device(self, device_id: str, *, enrich: bool = True) -> dict:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", device_id):
            raise UsageError("Portal device reads currently require a 40-character MachineId.")
        await self.verify_tenant()
        result = await self._request(_Operation.DEVICE, params={
            "machineId": device_id, "idType": "SenseMachineId",
            "readFromCache": "false", "lookingBackIndays": 180,
        })
        actual = result.get("SenseMachineId")
        if not isinstance(actual, str) or actual.casefold() != device_id.casefold():
            raise APIError("Portal did not return the requested MachineId.")
        # Map only directly corresponding observed fields; retain the source
        # so missing official fields are not replaced with invented values.
        fields = {
            "SenseMachineId": "id", "ComputerDnsName": "computerDnsName",
            "FirstSeen": "firstSeen", "LastSeen": "lastSeen", "OsPlatform": "osPlatform",
            "OsVersion": "osVersion", "OsBuild": "osBuild", "HealthStatus": "healthStatus",
            "RiskScore": "riskScore", "ExposureScore": "exposureLevel",
            "AadDeviceId": "aadDeviceId", "IsAadJoined": "isAadJoined",
            "RbacGroupId": "rbacGroupId", "LastIpAddress": "lastIpAddress",
            "LastExternalIpAddress": "lastExternalIpAddress",
            "OnboardingStatus": "onboardingStatus",
            "SenseClientVersion": "agentVersion", "ReleaseVersion": "version",
            "IsExcluded": "isExcluded",
        }
        mapped = {target: result[source] for source, target in fields.items() if source in result}
        # The portal calls this OsProcessor, but its observed bitness values
        # match the documented official osArchitecture contract (not x64/ARM64).
        if result.get("OsProcessor") in ("32-bit", "64-bit"):
            mapped["osArchitecture"] = result["OsProcessor"]
        supplementary = {}
        enrichment_errors = {}
        inventory = None
        if enrich:
            hostname = result.get("ComputerDnsName")
            if isinstance(hostname, str) and hostname:
                try:
                    rows = await self._request(_Operation.DEVICES, params={
                        "machineSearchPrefix": hostname, "hideLowFidelityDevices": "false",
                        "lookingBackIndays": 180, "pageIndex": 1, "pageSize": 100,
                        "sortByField": "riskscore", "sortOrder": "Descending",
                    })
                    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
                        raise APIError("Unexpected device inventory shape.")
                    matches = [r for r in rows if isinstance(r.get("SenseMachineId"), str)
                               and r["SenseMachineId"].casefold() == device_id.casefold()]
                    if len(matches) != 1:
                        raise APIError("No unique exact device in bounded inventory response.")
                    inventory = matches[0]
                    supplementary["inventory"] = inventory
                except RateLimitError:
                    raise
                except (APIError, TimeoutError, NetworkError) as exc:
                    enrichment_errors["inventory"] = exc.error_code
            if (isinstance(result.get("LastSeen"), str) and result["LastSeen"]
                    and isinstance(hostname, str) and hostname):
                try:
                    ips = await self._request(_Operation.DEVICE_IPS, params={
                        "senseMachineId": device_id, "lastSeen": result["LastSeen"],
                        "machineId": device_id, "idType": "SenseMachineId",
                        "isUnifiedDevicePage": "true", "computerDnsName": hostname,
                    })
                    supplementary["ip_adapters"] = ips
                    addresses = adapter_addresses(ips)
                    if addresses is None:
                        raise APIError("Unexpected device adapter shape.")
                    mapped["ipAddresses"] = addresses
                except RateLimitError:
                    raise
                except (APIError, TimeoutError, NetworkError) as exc:
                    enrichment_errors["ip_adapters"] = exc.error_code
            if result.get("IsExcluded") is True:
                try:
                    exclusion = await self._request(
                        _Operation.DEVICE_EXCLUSION, identifier=device_id,
                    )
                    actual_id = exclusion.get("SenseMachineId")
                    if (not isinstance(actual_id, str)
                            or actual_id.casefold() != device_id.casefold()):
                        raise APIError("Exclusion details did not match the requested device.")
                    supplementary["exclusion"] = exclusion
                    reason = exclusion_reason(exclusion)
                    if exclusion.get("ExclusionState") == "Excluded" and reason is not None:
                        mapped["exclusionReason"] = reason
                except RateLimitError:
                    raise
                except (APIError, TimeoutError, NetworkError) as exc:
                    enrichment_errors["exclusion"] = exc.error_code
        additional, sources = additional_device_fields(result, inventory)
        mapped.update(additional)
        if "ipAddresses" in mapped:
            sources["ipAddresses"] = "ip_adapters.IpAdapters"
        if "exclusionReason" in mapped and "exclusionReason" not in sources:
            sources["exclusionReason"] = "exclusion.Justification"
        return {
            **mapped,
            "portal_source": {
                "backend": "portal-cookie", "field_parity": "partial", "raw": result,
                "supplementary": supplementary, "field_sources": sources,
                "enrichment_errors": enrichment_errors,
                "field_notes": {
                    "lastSeen": (
                        "Portal observation time; official lastSeen is the last full report."
                    ),
                    "ipAddresses": (
                        "Reported portal adapters only; loopback addresses can be omitted."
                    ),
                    "managedBy": (
                        "Derived from device enrollment; inventory ManagedBy can disagree."
                    ),
                },
                "unavailable_fields": [
                    name for name in (
                        "deviceValue", "exclusionReason", "ipAddresses",
                        "isPotentialDuplication", "machineTags", "managedBy",
                        "managedByStatus", "mergedIntoMachineId", "osArchitecture",
                        "osProcessor", "rbacGroupName", "vmMetadata",
                    ) if name not in mapped
                ],
            },
        }

    async def submit_device_action(
        self, device_id: str, action: str, *, comment: str, mode: str | None = None,
    ) -> dict:
        """Submit a named response action; transport failures are never retried."""
        contracts = {
            "scan": ("ScanRequest", "RunAntiVirusScan"),
            "collect-package": ("ForensicsRequest", "CollectInvestigationPackage"),
            "restrict": ("RestrictExecutionRequest", "RestrictCodeExecution"),
            "unrestrict": ("RestrictExecutionRequest", "UnrestrictCodeExecution"),
            "isolate": ("IsolationRequest", "Isolate"),
            "unisolate": ("IsolationRequest", "Unisolate"),
        }
        if action not in contracts:
            raise UnsupportedBackendCapability()
        # Invalid mode values are usage errors, not missing backend capabilities.
        if (action == "scan" and mode not in ("Full", "Quick")) or (
            action == "isolate" and mode not in ("Selective", "Full")
        ):
            raise UsageError(
                "Invalid device action mode. Scan: Quick or Full; isolate: Full or Selective."
            )
        device = await self.get_device(device_id, enrich=False)
        raw = device["portal_source"]["raw"]
        if any(not isinstance(raw.get(k), str) or not raw[k]
               for k in ("OsPlatform", "SenseClientVersion")):
            raise APIError("Portal device lacks action prerequisite fields; no action was sent.")
        request_type, public_type = contracts[action]
        body = {
            "MachineId": device_id, "RequestorComment": comment, "Type": request_type,
            "OsPlatform": raw["OsPlatform"], "SenseClientVersion": raw["SenseClientVersion"],
        }
        if action == "scan":
            body["Params"] = {"ScanType": mode}
        elif action == "isolate":
            body.update(Action="Isolate", IsolationType=mode)
        elif action == "unisolate":
            body.update(Action="Unisolate")
        elif action in ("restrict", "unrestrict"):
            body.update(
                PolicyType="Restrict" if action == "restrict" else "Unrestrict",
                ClientVersion=raw["SenseClientVersion"],
            )
        result = await self._request(_Operation.ACTION_CREATE, body=body)
        action_id = result.get("Id")
        if (not isinstance(action_id, str) or not self._valid_action_id(action_id)
                or (not isinstance(result.get("MachineId"), str)
                    or result["MachineId"].casefold() != device_id.casefold())
                or not isinstance(result.get("Status"), str)):
            raise APIError(
                "Portal action response could not be correlated. Outcome unknown; "
                "inspect the device in the portal before retrying."
            )
        remembered = self._remember_action(action_id, device_id)
        return {
            "id": action_id, "machineId": device_id, "type": public_type,
            "status": result["Status"],
            "portal_source": {
                "backend": "portal-cookie", "field_parity": "partial", "raw": result,
                "device_association_saved": remembered,
                "status_command": (
                    f"xdr --backend portal-cookie device action-status {action_id} "
                    f"--device {device_id}"
                ),
            },
        }

    @staticmethod
    def _valid_action_id(value: str) -> bool:
        return re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value,
        ) is not None

    async def get_action_status(self, action_id: str, device_id: str | None = None) -> dict:
        """Match the exact device/request pair; latest can return unrelated requests."""
        if not isinstance(action_id, str) or not self._valid_action_id(action_id):
            raise UsageError("Portal action status requires a GUID action ID.")
        if device_id is None:
            device_id = load_action_device(self._tenant_id, action_id)
        if not device_id or not re.fullmatch(r"[0-9a-fA-F]{40}", device_id):
            raise UsageError(
                "Portal action status requires --device with a 40-character MachineId."
            )
        await self.verify_tenant()
        rows = await self._request(_Operation.ACTION_STATUS, params={
            "machineId": device_id, "requestGuid": action_id, "tenantIds": "",
        })
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise APIError("Portal action status returned an unexpected response shape.")
        matches = [row for row in rows if isinstance(row.get("RequestGuid"), str)
                   and row["RequestGuid"].casefold() == action_id.casefold()]
        if not matches:
            raise NotFoundError("action in portal latest response (history may be limited)")
        if len(matches) != 1:
            raise APIError("Portal returned duplicate records for the requested action.")
        row = matches[0]
        if (not isinstance(row.get("MachineId"), str)
                or row["MachineId"].casefold() != device_id.casefold()
                or not isinstance(row.get("RequestStatus"), str)):
            raise APIError("Portal action identity or status did not match the requested device.")
        remembered = self._remember_action(action_id, device_id)
        fields = {
            "CreationDateTimeUtc": "creationDateTimeUtc",
            "LastUpdateTimeUtc": "lastUpdateDateTimeUtc",
            "Requestor": "requestor", "RequestorComment": "requestorComment",
            "ErrorHResult": "errorHResult", "CancellationRequestor": "cancellationRequestor",
            "CancellationComment": "cancellationComment",
            "CancellationDateTimeUtc": "cancellationDateTimeUtc",
        }
        # These response types identify one operation without numeric subtype inference.
        action_types = {
            "ScanResponse": "RunAntiVirusScan",
            "ForensicsResponse": "CollectInvestigationPackage",
        }
        public_type = action_types.get(row.get("Type"))
        # Correlated portal/official outcomes from supervised action pairs
        # establish these numeric subtypes. Unknown values stay unmapped.
        subtypes = {
            "IsolationResponse": ("Action", {0: "Isolate", 1: "Unisolate"}),
            "RestrictExecutionResponse": (
                "PolicyType", {0: "RestrictCodeExecution", 1: "UnrestrictCodeExecution"},
            ),
        }
        subtype = subtypes.get(row.get("Type"))
        if subtype is not None:
            field, mapping = subtype
            value = row.get(field)
            if type(value) is int:
                public_type = mapping.get(value)
        return {
            "id": row["RequestGuid"], "machineId": row["MachineId"],
            "status": row["RequestStatus"],
            **{target: row[source] for source, target in fields.items() if source in row},
            **({"type": public_type} if public_type else {}),
            "portal_source": {
                "backend": "portal-cookie", "field_parity": "partial",
                "status_contract": "portal-native", "raw": row,
                "device_association_saved": remembered,
            },
        }

    def _remember_action(self, action_id: str, device_id: str) -> bool:
        saved = remember_action_device(self._tenant_id, action_id, device_id)
        if not saved:
            err_console.print(
                "Warning: could not save the action's device association. "
                "Use --device for future status reads; do not resubmit the action.",
                markup=False,
            )
        return saved

    async def get_package_download_url(self, action_id: str, device_id: str) -> str:
        """Resolve a completed collection action; never expose its signed URL in output."""
        action = await self.get_action_status(action_id, device_id)
        raw = action["portal_source"]["raw"]
        if raw.get("Type") != "ForensicsResponse":
            raise UsageError("Package download requires a collection action ID.")
        if action["status"] != "Succeeded":
            raise ConflictError(
                "Package collection has not succeeded; inspect action-status first."
            )
        result = await self._request(_Operation.PACKAGE_LINK, params={
            "requestGuid": action_id, "packageIdentity": "null",
        })
        return result["url"]

    async def close(self) -> None:
        await self._client.aclose()


def create_client(
    config: Config, *, timeout: float | None = None,
    auth_factory=AuthManager, client_factory=XDRClient,
) -> Backend:
    """Select before constructing auth; portal mode never initializes MSAL."""
    effective_timeout = config.api_timeout if timeout is None else timeout
    backend = select_backend(config)
    if backend == APIBackend.PORTAL_COOKIE:
        return PortalBackend(config, effective_timeout)
    return OfficialBackend(
        client_factory(get_token=auth_factory(config).get_token, timeout=effective_timeout),
    )
