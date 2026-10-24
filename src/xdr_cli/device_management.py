"""Named device metadata operations and source-verified portal action cancellation.

The portal's tag endpoint replaces a whole editable tag set. Its preflight and
read-back checks detect some concurrent edits, but cannot provide atomic CAS.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from enum import Enum

import httpx

from xdr_cli._bounded_http import read_bounded_response
from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.client import APISurface
from xdr_cli.exceptions import (
    APIError,
    ConfigError,
    ConflictError,
    ForbiddenError,
    NetworkError,
    NotAuthenticatedError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    UsageError,
    XDRError,
    parse_retry_after,
)

_DEVICE = re.compile(r"[0-9a-fA-F]{40}")
_ACTION = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_CANCELLABLE_TYPES = frozenset(
    {
        "IsolationResponse",
        "ForensicsResponse",
        "ScanResponse",
        "RestrictExecutionResponse",
        "LogsCollectionResponse",
        "ForensicArtifactsRequest",
    }
)
_CANCELLABLE_STATES = frozenset({"Pending", "InProgress", "Submitted"})
_PERMISSION_STATES = {-2: "unknown", -1: "disallowed", 0: "allowed", 1: "allowed-with-warning"}


class _Route(Enum):
    TAGS = ("GET", "/apiproxy/mtp/ndr/machines/machineTags")
    SET_TAGS = ("POST", "/apiproxy/mtp/ndr/machines/editMachineTags")
    PERMISSIONS = ("GET", "/apiproxy/mtp/responseApiPortal/requests/permissions")
    CANCEL = ("POST", "/apiproxy/mtp/responseApiPortal/requests/cancelbyid")
    TENANT_CONTEXT = ("GET", "/apiproxy/mtp/sccManagement/mgmt/TenantContext")
    START_INVESTIGATION = ("POST", "/apiproxy/mtp/autoIr/investigations/")
    START_INVESTIGATION_DOTNET = ("POST", "/apiproxy/mtp/autoIr/ui/investigations/")
    ACTION_HISTORY = ("GET", "/apiproxy/mtp/actionCenter/actioncenterui/history-actions")


def _machine_id(value: str) -> str:
    if not isinstance(value, str) or not _DEVICE.fullmatch(value):
        raise UsageError("Device management requires a 40-character MachineId.")
    return value


def _action_id(value: str) -> str:
    if not isinstance(value, str) or not _ACTION.fullmatch(value):
        raise UsageError("Device action cancellation requires a GUID action ID.")
    return value


def _comment(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise UsageError("Device action requires a nonempty bounded comment.")
    return value


def _history_limit(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 10000:
        raise UsageError("Device action history limit must be between 1 and 10000.")
    return value


def _autoir_feature(context: dict) -> bool:
    """Match the frontend's EnabledFeatures-over-Features precedence, including []."""
    enabled = context.get("EnabledFeatures")
    if enabled is not None:
        if not isinstance(enabled, list) or any(not isinstance(item, str) for item in enabled):
            raise APIError("Tenant feature inventory has an invalid EnabledFeatures collection.")
        return "UseDotnetAirsUiInvestigations" in enabled
    features = context.get("Features")
    if not isinstance(features, dict):
        raise APIError(
            "Tenant context lacks a usable feature inventory for automated investigation."
        )
    value = features.get("UseDotnetAirsUiInvestigations", False)
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    raise APIError("Automated-investigation feature state has an unsupported native value.")


def _tag(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 1024
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise UsageError("Device tags require nonempty names without control characters.")
    return value


def _requested_tags(values: object) -> list[str]:
    if not isinstance(values, list) or len(values) > 1024:
        raise UsageError("Device tag replacement requires a bounded list of tag names.")
    result = [_tag(value) for value in values]
    if len(set(result)) != len(result):
        raise UsageError("Device tag lists must not contain duplicate names.")
    return result


def _observed_tags(values: object) -> list[str]:
    """Decode known string tags and their portal-model name objects, fail closed."""
    if not isinstance(values, list) or len(values) > 1024:
        raise APIError("Device tag response is not a bounded tag collection.")
    result = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("name")
        try:
            result.append(_tag(value))
        except UsageError:
            raise APIError("Device tag response contains an invalid tag name.") from None
    if len(set(result)) != len(result):
        raise APIError("Device tag response contains duplicate tag names.")
    return result


def _portal_tags(value: object) -> dict:
    if not isinstance(value, dict) or not {"BuiltInTags", "UserDefinedTags"} <= value.keys():
        raise APIError("Portal device tags lack their manual/system distinction.")
    return {
        "manual": _observed_tags(value["UserDefinedTags"]),
        "system": _observed_tags(value["BuiltInTags"]),
        "source": "portal-response",
    }


def _official_tags(value: object, machine_id: str) -> dict:
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("id"), str)
        or value["id"].lower() != machine_id.lower()
    ):
        raise APIError("Official device tag response identity mismatch.")
    return {
        "manual": _observed_tags(value.get("machineTags")),
        "system": [],
        "source": "official-machine-response",
        "system_tags_available": False,
    }


def _portal_raw(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    source = value.get("portal_source")
    if not isinstance(source, dict) or not isinstance(source.get("raw"), dict):
        return None
    return source["raw"]


def _action_matches(value: object, action_id: str, device_id: str) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("id"), str)
        and value["id"].lower() == action_id.lower()
        and isinstance(value.get("machineId"), str)
        and value["machineId"].lower() == device_id.lower()
    )


def _sanitize(error: XDRError, message: str, *, mutation: bool = False) -> XDRError:
    """Preserve typed recovery classes without echoing upstream request values."""
    error.message = message
    error.args = (message,)
    error.original = None
    if hasattr(error, "detail"):
        error.detail = None
    error.suggestions = []
    if mutation and isinstance(error, (TimeoutError, NetworkError)):
        error.retryable = False
        error.error_code = "OUTCOME_UNKNOWN"
    return error


class PortalDeviceManagement:
    async def _dm_request(
        self, route: _Route, *, params: dict | None = None, body: dict | None = None
    ):
        """Call only a fixed source-verified route; never replay a mutation."""
        await self.verify_tenant()
        method, path = route.value
        request = self._client.build_request(method, path, params=params, json=body)
        await self._auth.apply(request)
        request.headers["tenant-id"] = self._tenant_id
        request.headers["x-tid"] = self._tenant_id
        mutating = method != "GET"
        try:
            response = await read_bounded_response(self._client, request, max_bytes=2 * 1024**2)
        except (httpx.TimeoutException, httpx.TransportError) as cause:
            cls = TimeoutError if isinstance(cause, httpx.TimeoutException) else NetworkError
            error = cls(
                "Device management request failed."
                + (" Outcome unknown; inspect the device before retrying." if mutating else ""),
                retryable=not mutating,
            )
            if mutating:
                error.error_code = "OUTCOME_UNKNOWN"
            raise error from None
        status = response.status_code
        if status in (401, 440) or response.is_redirect:
            raise NotAuthenticatedError("Device management requires a renewed portal session.")
        if status == 403:
            raise ForbiddenError("Defender device-management role/permissions")
        if status == 404:
            raise NotFoundError("portal device-management object")
        if status == 409:
            raise ConflictError("Device management operation conflicts with current server state.")
        if status == 429:
            raise RateLimitError(parse_retry_after(response.headers.get("Retry-After")))
        if "text/html" in response.headers.get("content-type", "").lower():
            raise NotAuthenticatedError("Device management returned a sign-in page.")
        if not response.is_success:
            error = APIError("Device management request was rejected.", status_code=status)
            if mutating and status >= 500:
                error.error_code = "OUTCOME_UNKNOWN"
            raise error
        if not response.content:
            return None
        if len(response.content) > 2 * 1024**2:
            raise APIError("Device management response exceeds its metadata size bound.")
        try:
            value = response.json()
        except ValueError:
            raise APIError("Device management returned malformed JSON.") from None
        if isinstance(value, dict) and any(value.get(key) for key in ("error", "errors", "Error")):
            raise APIError("Device management returned an application error.")
        return value

    async def get_device_tags(self, machine_id: str) -> dict:
        _machine_id(machine_id)
        value = await self._dm_request(_Route.TAGS, params={"senseMachineId": machine_id})
        return _portal_tags(value)

    async def set_device_tags(
        self, machine_id: str, tags: list[str], *, expected_current: list[str]
    ) -> dict:
        _machine_id(machine_id)
        requested = _requested_tags(tags)
        expected = _requested_tags(expected_current)
        device = await self.get_device(machine_id, enrich=False)
        if (
            not isinstance(device, dict)
            or not isinstance(device.get("id"), str)
            or device["id"].lower() != machine_id.lower()
        ):
            raise APIError("Device metadata response identity mismatch.")
        fresh = await self.get_device_tags(machine_id)
        if set(fresh["manual"]) != set(expected):
            raise ConflictError(
                "Device manual tags changed; refresh them before replacing the set."
            )
        metadata = {
            "atomic_compare_and_swap": False,
            "concurrency": "best-effort-read-check-replace-read",
        }
        if set(requested) == set(fresh["manual"]):
            return {**fresh, **metadata, "changed": False, "verified": True}
        body = {"SenseMachineIds": [machine_id], "MachineTags": json.dumps(requested)}
        raw = _portal_raw(device)
        if isinstance(raw, dict):
            internal_id = raw.get("InternalMachineId")
            if type(internal_id) is int and internal_id >= 0:
                body["InternalMachineIds"] = [internal_id]
        await self._dm_request(_Route.SET_TAGS, body=body)
        try:
            after = await self.get_device_tags(machine_id)
        except XDRError as error:
            raise _sanitize(
                error,
                "Tag replacement was accepted but verification failed; "
                "inspect current device tags before retrying.",
            ) from None
        if set(after["manual"]) != set(requested):
            raise ConflictError(
                "Device tags differ from the submitted set after replacement; "
                "another writer or server-side change may have intervened."
            )
        return {**after, **metadata, "changed": True, "verified": True}

    async def update_device_tag(self, machine_id: str, tag: str, *, remove: bool) -> dict:
        _machine_id(machine_id)
        _tag(tag)
        if type(remove) is not bool:
            raise UsageError("Device tag update requires a boolean remove selector.")
        current = await self.get_device_tags(machine_id)
        desired = [value for value in current["manual"] if value != tag]
        if not remove:
            desired.append(tag)
        return await self.set_device_tags(machine_id, desired, expected_current=current["manual"])

    async def get_device_action_permissions(self, machine_id: str) -> dict:
        _machine_id(machine_id)
        value = await self._dm_request(
            _Route.PERMISSIONS, params={"machineId": machine_id, "tenantIds": ""}
        )
        if not isinstance(value, dict) or not isinstance(value.get("Permissions"), list):
            raise APIError("Device action permissions response has an invalid shape.")
        permissions = []
        seen = set()
        for row in value["Permissions"]:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("Type"), str)
                or not row["Type"]
                or type(row.get("Result")) is not int
                or row["Type"] in seen
                or (
                    row.get("ReasonDescription") is not None
                    and not isinstance(row["ReasonDescription"], str)
                )
            ):
                raise APIError("Device action permissions contain an invalid native entry.")
            seen.add(row["Type"])
            permissions.append(
                {
                    "type": row["Type"],
                    "native_result": row["Result"],
                    "status": _PERMISSION_STATES.get(row["Result"], "unmapped"),
                    "reason": row.get("ReasonDescription"),
                }
            )
        return {
            "machine_id": machine_id,
            "permissions": permissions,
            "source": "portal-response",
            "authorization_granted": False,
            "interpretation": "server-reported-action-availability",
        }

    async def cancel_device_action(self, action_id: str, *, device_id: str, comment: str) -> dict:
        _action_id(action_id)
        _machine_id(device_id)
        if not isinstance(comment, str) or not comment.strip() or len(comment) > 4096:
            raise UsageError("Device action cancellation requires a nonempty bounded comment.")
        before = await self.get_action_status(action_id, device_id)
        if not _action_matches(before, action_id, device_id):
            raise APIError("Device cancellation preflight identity mismatch.")
        raw = _portal_raw(before)
        if (
            not isinstance(raw, dict)
            or raw.get("Type") not in _CANCELLABLE_TYPES
            or before.get("status") not in _CANCELLABLE_STATES
        ):
            raise ConflictError(
                "Device action type or current state is not eligible for cancellation."
            )
        await self._dm_request(
            _Route.CANCEL, params={"requestGuid": action_id, "comment": comment, "tenantIds": ""}
        )
        after = await self.get_action_status(action_id, device_id)
        if not _action_matches(after, action_id, device_id):
            raise APIError("Device cancellation verification identity mismatch.")
        return {**after, "cancellation_requested": True, "device_rollback_confirmed": False}

    async def start_device_investigation(self, machine_id: str, *, comment: str) -> dict:
        """Choose one source-defined protocol from fresh tenant features; never probe writes."""
        _machine_id(machine_id)
        _comment(comment)
        context = await self._dm_request(_Route.TENANT_CONTEXT)
        auth = context.get("AuthInfo") if isinstance(context, dict) else None
        if (
            not isinstance(auth, dict)
            or not isinstance(auth.get("TenantId"), str)
            or auth["TenantId"].casefold() != self._tenant_id.casefold()
        ):
            raise ConfigError(
                "Automated-investigation tenant context does not match the configured tenant."
            )
        dotnet = _autoir_feature(context)
        route = _Route.START_INVESTIGATION_DOTNET if dotnet else _Route.START_INVESTIGATION
        field = "machine" if dotnet else "machine_id"
        value = await self._dm_request(
            route, params={"useDotnetAutoIrUi": str(dotnet).lower()}, body={field: machine_id}
        )
        if not isinstance(value, dict) or not value:
            raise APIError(
                "Automated-investigation response is not an interpretable native object."
            )
        return {
            "machine_id": machine_id,
            "source": "portal-response",
            "request_accepted": True,
            "protocol": "dotnet-ui" if dotnet else "legacy",
            "comment_upstream_recorded": False,
            "comment_handling": "not_upstream_recorded",
            "investigation_status": "not_interpreted",
            "native": value,
        }

    async def iter_device_action_history(
        self,
        machine_id: str,
        *,
        limit: int = 100,
    ) -> AsyncIterator[dict]:
        """Read the source-defined seven-day window with live-verified 1-based pages.

        Native counts, duplicates, local limits and count drift stay explicit;
        multiple requests do not establish a transactional tenant snapshot.
        """
        _machine_id(machine_id)
        _history_limit(limit)
        now = datetime.now(UTC)
        since = now - timedelta(days=7)
        page_size = min(limit, 100)
        params = {
            "machineId": machine_id,
            "useMtpApi": "true",
            "pageSize": page_size,
            "fromDate": since.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "toDate": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "sortByField": "eventTime",
            "sortOrder": "Descending",
        }
        seen = set()
        counts = set()
        unknown_count = False
        duplicates = 0
        pages = 0
        reason = "page-bound-reached"
        first_count = None
        for page in range(1, 101):
            value = await self._dm_request(
                _Route.ACTION_HISTORY, params={**params, "pageIndex": page}
            )
            pages += 1
            if not isinstance(value, dict):
                raise APIError("Portal device action history is not a native collection object.")
            count = value.get("Count")
            if count is not None and (type(count) is not int or count < 0):
                raise APIError("Portal device action history returned an invalid native count.")
            if page == 1:
                first_count = count
            if count is None:
                unknown_count = True
            else:
                counts.add(count)
            rows = value.get("Results")
            if isinstance(rows, dict):
                rows = [rows]
            if rows is None and count == 0:
                rows = []
            if not isinstance(rows, list) or len(rows) > page_size:
                raise APIError(
                    "Portal device action history returned an unsupported results shape."
                )
            if count is not None and count < len(rows):
                raise APIError(
                    "Portal device action history count is smaller than its returned page."
                )
            previous_size = len(seen)
            for row in rows:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("MachineId"), str)
                    or row["MachineId"].lower() != machine_id.lower()
                    or type(row.get("ActionId")) not in (str, int)
                    or (isinstance(row["ActionId"], str) and not row["ActionId"])
                ):
                    raise APIError("Portal device action history contains an unexpected identity.")
                identity = str(row["ActionId"]).lower()
                if identity in seen:
                    duplicates += 1
                    continue
                if len(seen) >= limit:
                    reason = "limit-reached"
                    break
                seen.add(identity)
                yield {
                    "record_type": "device-action-history",
                    "source": "portal-response",
                    "native": row,
                }
            if count is not None and len(seen) >= count:
                reason = "native-count-satisfied" if len(seen) == count else "native-count-shrank"
                break
            if len(seen) >= limit:
                reason = "limit-reached"
                break
            if len(rows) < page_size:
                reason = (
                    "native-count-unavailable" if count is None else "native-count-not-reconciled"
                )
                break
            if len(seen) == previous_size:
                reason = "repeated-page-or-concurrent-change"
                break
        complete = (
            not unknown_count and len(counts) == 1 and duplicates == 0 and first_count == len(seen)
        )
        if len(counts) > 1:
            reason = "native-count-changed-during-pagination"
        elif duplicates and reason == "native-count-satisfied":
            reason = "duplicate-actions-during-pagination"
        yield {
            "record_type": "device-action-history-coverage",
            "machine_id": machine_id,
            "source": "portal-response",
            "lookback_days": 7,
            "from": since.isoformat(),
            "to": now.isoformat(),
            "native_count": first_count,
            "native_counts_observed": sorted(counts),
            "returned": len(seen),
            "duplicate_actions": duplicates,
            "limit": limit,
            "pages": pages,
            "complete": complete,
            "stop_reason": reason,
            "scope": "requested-device-and-time-window",
            "snapshot_consistency": "multiple-requests-not-transactional",
        }


class OfficialDeviceManagement:
    async def get_device_tags(self, machine_id: str) -> dict:
        _machine_id(machine_id)
        return _official_tags(await self.get_device(machine_id, enrich=False), machine_id)

    async def set_device_tags(
        self, machine_id: str, tags: list[str], *, expected_current: list[str]
    ) -> dict:
        raise UnsupportedBackendCapability(
            "Whole-set tag replacement is not available on the official backend.",
            suggested_fix="Use the named add/remove tag operation, or portal-cookie replacement.",
        )

    async def update_device_tag(self, machine_id: str, tag: str, *, remove: bool) -> dict:
        _machine_id(machine_id)
        _tag(tag)
        if type(remove) is not bool:
            raise UsageError("Device tag update requires a boolean remove selector.")
        try:
            value = await self.transport.post(
                APISurface.MDE,
                f"machines/{machine_id}/tags",
                json={"Value": tag, "Action": "Remove" if remove else "Add"},
            )
        except XDRError as error:
            raise _sanitize(
                error,
                "Device tag update failed; inspect device tags before retrying.",
                mutation=True,
            ) from None
        result = _official_tags(value, machine_id)
        if (tag in result["manual"]) == remove:
            raise ConflictError("Device tag update response does not reflect the requested change.")
        return {**result, "verified": True, "operation": "remove" if remove else "add"}

    async def get_device_action_permissions(self, machine_id: str) -> dict:
        raise UnsupportedBackendCapability(
            "Device-page action-availability metadata requires the portal-cookie backend.",
            suggested_fix=(
                "Use portal-cookie to read the portal's native action-availability response."
            ),
        )

    async def cancel_device_action(self, action_id: str, *, device_id: str, comment: str) -> dict:
        raise UnsupportedBackendCapability(
            "This source-verified device action cancellation adapter requires portal-cookie.",
            suggested_fix="Use portal-cookie with an explicit device ID, or cancel in Defender.",
        )

    async def start_device_investigation(self, machine_id: str, *, comment: str) -> dict:
        _machine_id(machine_id)
        _comment(comment)
        try:
            value = await self.transport.post(
                APISurface.MDE,
                f"machines/{machine_id}/startInvestigation",
                json={"Comment": comment},
            )
        except XDRError as error:
            raise _sanitize(
                error,
                "Automated-investigation request failed; inspect device "
                "investigations before retrying.",
                mutation=True,
            ) from None
        if not isinstance(value, dict) or not value:
            raise APIError("Official automated-investigation response has an invalid native shape.")
        if any(value.get(key) for key in ("error", "errors", "Error")):
            raise APIError(
                "Official automated-investigation response contains an application error."
            )
        reported_machine = value.get("machineId")
        if reported_machine is not None and (
            not isinstance(reported_machine, str) or reported_machine.lower() != machine_id.lower()
        ):
            raise APIError("Official automated-investigation response device identity mismatch.")
        return {
            "machine_id": machine_id,
            "source": "official-investigation-response",
            "request_accepted": True,
            "comment_upstream_recorded": True,
            "investigation_status": "not_interpreted",
            "native": value,
        }

    async def iter_device_action_history(
        self, machine_id: str, *, limit: int = 100
    ) -> AsyncIterator[dict]:
        """Page a fixed documented machineActions filter; never follow arbitrary links."""
        _machine_id(machine_id)
        _history_limit(limit)
        returned = 0
        page_size = min(limit, 100)
        seen = set()
        complete = False
        reason = "limit-reached"
        pages = 0
        for _ in range(100):
            take = min(page_size, limit - returned)
            if take <= 0:
                break
            value = await self.transport.get(
                APISurface.MDE,
                "machineactions",
                params={
                    "$filter": f"machineId eq '{machine_id}'",
                    "$top": take,
                    "$skip": returned,
                },
            )
            pages += 1
            rows = value.get("value") if isinstance(value, dict) else None
            if not isinstance(rows, list) or len(rows) > take:
                raise APIError("Official device action history has an invalid collection shape.")
            for row in rows:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("machineId"), str)
                    or row["machineId"].lower() != machine_id.lower()
                    or not isinstance(row.get("id"), str)
                    or not row["id"]
                ):
                    raise APIError("Official device action history contains an invalid identity.")
                identity = row["id"].lower()
                if identity in seen:
                    reason = "repeated-action-or-concurrent-page-change"
                    break
                seen.add(identity)
                returned += 1
                yield {
                    "record_type": "device-action-history",
                    "source": "official-machineactions",
                    "native": row,
                }
            else:
                if value.get("@odata.nextLink"):
                    reason = "native-continuation-unfollowed"
                    break
                if len(rows) < take:
                    complete = True
                    reason = "short-native-page"
                    break
                if returned >= limit:
                    break
                continue
            break
        else:
            reason = "page-bound-reached"
        yield {
            "record_type": "device-action-history-coverage",
            "machine_id": machine_id,
            "source": "official-machineactions",
            "returned": returned,
            "limit": limit,
            "pages": pages,
            "complete": complete,
            "stop_reason": reason,
            "scope": "official-machineactions-only",
            "portal_live_response_included": False,
            "snapshot_consistency": "multiple-requests-not-transactional",
        }
