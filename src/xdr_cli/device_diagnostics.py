"""Source-verified portal support logs and the four-hour troubleshooting window.

These operations submit asynchronous device actions. Acceptance does not prove
that an endpoint completed a collection or changed its troubleshooting state.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from enum import Enum

from xdr_cli.backend_contract import UnsupportedBackendCapability
from xdr_cli.device_management import _comment, _machine_id, _portal_raw, _tenant_feature
from xdr_cli.exceptions import APIError, ConflictError, UsageError

_ACTION = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_PENDING = frozenset({"Pending", "InProgress", "Submitted"})
_WINDOW_MINUTES = 240


class _DiagnosticsRoute(Enum):
    CREATE = ("POST", "/apiproxy/mtp/responseApiPortal/requests/create")
    LATEST = ("GET", "/apiproxy/mtp/responseApiPortal/requests/latest")


def _now() -> datetime:
    return datetime.now(UTC)


def _time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 80:
        raise APIError("Troubleshooting state contains an invalid expiration timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC)
    except ValueError:
        raise APIError("Troubleshooting state contains an invalid expiration timestamp.") from None


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _unsupported(operation: str) -> UnsupportedBackendCapability:
    return UnsupportedBackendCapability(
        f"{operation} requires a source-verified portal-cookie adapter.",
        suggested_fix="Use --backend portal-cookie for device diagnostics actions.",
    )


class PortalDeviceDiagnostics:
    """Mixin using PortalDeviceManagement's fixed-route, non-replaying transport."""

    async def _dd_device(self, machine_id: str) -> dict:
        _machine_id(machine_id)
        device = await self.get_device(machine_id, enrich=False)
        if (
            not isinstance(device, dict)
            or not isinstance(device.get("id"), str)
            or device["id"].lower() != machine_id.lower()
        ):
            raise APIError("Device diagnostics preflight identity mismatch.")
        raw = _portal_raw(device)
        if not isinstance(raw, dict):
            raise APIError("Device diagnostics requires native portal device metadata.")
        for key in ("MachineId", "SenseMachineId"):
            observed = raw.get(key)
            if observed is not None and (
                not isinstance(observed, str) or observed.lower() != machine_id.lower()
            ):
                raise APIError("Native diagnostics device metadata has conflicting identities.")
        return {
            key: raw[key]
            for key in ("OsPlatform", "SenseClientVersion")
            if isinstance(raw.get(key), str) and raw[key]
        }

    def _dd_accepted(self, value: object, machine_id: str, public_type: str) -> dict:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("Id"), str)
            or not _ACTION.fullmatch(value["Id"])
            or not isinstance(value.get("MachineId"), str)
            or value["MachineId"].lower() != machine_id.lower()
            or not isinstance(value.get("Status"), str)
            or not value["Status"]
        ):
            error = APIError(
                "Diagnostics response could not be correlated. Outcome unknown; "
                "inspect the device before resubmitting."
            )
            error.error_code = "OUTCOME_UNKNOWN"
            raise error
        action_id = value["Id"]
        saved = self._remember_action(action_id, machine_id)
        return {
            "id": action_id,
            "machineId": machine_id,
            "type": public_type,
            "status": value["Status"],
            "portal_source": {
                "backend": "portal-cookie",
                "field_parity": "partial",
                "raw": value,
                "device_association_saved": saved,
                "status_command": (
                    f"xdr --backend portal-cookie device action-status {action_id} "
                    f"--device {machine_id}"
                ),
            },
        }

    async def collect_device_support_logs(self, machine_id: str, *, comment: str) -> dict:
        """Submit one support-log collection request, retaining its native status."""
        _machine_id(machine_id)
        _comment(comment)
        context = await self._dm_tenant_context()
        if not _tenant_feature(context, "LogsCollection"):
            error = APIError("Support-log collection is not enabled for this tenant.")
            error.error_code = "TENANT_FEATURE_UNAVAILABLE"
            error.suggested_fix = (
                "Check support-log availability with your Defender administrator "
                "or Microsoft support."
            )
            raise error
        if _tenant_feature(context, "EnableCollectDiagnosticPackage"):
            raise UnsupportedBackendCapability(
                "This tenant uses the modern diagnostic-package collection protocol, "
                "which the CLI does not implement yet.",
                suggested_fix="Use the Defender portal's diagnostic-package collection workflow.",
            )
        metadata = await self._dd_device(machine_id)
        value = await self._dm_request(
            _DiagnosticsRoute.CREATE,
            body={
                "MachineId": machine_id,
                "RequestorComment": comment,
                "Type": "LogsCollectionRequest",
                **metadata,
            },
        )
        return self._dd_accepted(value, machine_id, "CollectSupportLogs")

    async def _dd_troubleshooting_requests(self, machine_id: str) -> list[dict]:
        values = await self._dm_request(
            _DiagnosticsRoute.LATEST,
            params={"machineId": machine_id, "tenantIds": ""},
        )
        if not isinstance(values, list) or any(not isinstance(row, dict) for row in values):
            raise APIError("Device diagnostics state is not a native request list.")
        requests = [row for row in values if row.get("Type") == "TroubleshootResponse"]
        for row in requests:
            if (
                not isinstance(row.get("MachineId"), str)
                or row["MachineId"].lower() != machine_id.lower()
            ):
                raise APIError("Troubleshooting state contains a different device identity.")
            if (
                type(row.get("TroubleshootState")) is not int
                or row["TroubleshootState"] not in (0, 1)
                or not isinstance(row.get("RequestStatus"), str)
            ):
                raise APIError("Troubleshooting response lacks a known native state.")
        return requests

    async def set_device_troubleshooting(
        self,
        machine_id: str,
        *,
        enabled: bool,
        duration_minutes: int | None,
        comment: str,
    ) -> dict:
        """Start the GUI's four-hour window, or stop a verified active window."""
        _machine_id(machine_id)
        _comment(comment)
        if type(enabled) is not bool:
            raise UsageError("Troubleshooting enabled must be a boolean.")
        if (
            enabled
            and duration_minutes is not None
            and (type(duration_minutes) is not int or duration_minutes != _WINDOW_MINUTES)
        ):
            raise UsageError("The verified portal troubleshooting window is exactly 240 minutes.")
        if not enabled and duration_minutes is not None:
            raise UsageError("Stopping troubleshooting does not accept a duration.")
        metadata = await self._dd_device(machine_id)
        requests = await self._dd_troubleshooting_requests(machine_id)
        if any(row["RequestStatus"] in _PENDING for row in requests):
            raise ConflictError("A troubleshooting change is already pending for this device.")
        now = _now()
        active = []
        for row in requests:
            if row["RequestStatus"] == "Succeeded" and row["TroubleshootState"] == 1:
                expiration = _time(row.get("TroubleshootExpirationDateTimeUtc"))
                if expiration > now:
                    active.append(row)
        body = {
            "MachineId": machine_id,
            "RequestorComment": comment,
            "Type": "TroubleshootRequest",
            "TroubleshootState": 1 if enabled else 0,
            "ParamsJsonFormatVersion": 1,
            "RequestSource": 2,
            **metadata,
        }
        if enabled:
            if active:
                raise ConflictError("Troubleshooting is already active; no new window was started.")
            start = now + timedelta(seconds=2)
            body["TroubleshootStartDateTimeUtc"] = _iso(start)
            body["TroubleshootExpirationDateTimeUtc"] = _iso(
                start + timedelta(minutes=_WINDOW_MINUTES),
            )
        else:
            if len(active) != 1:
                raise ConflictError(
                    "No unambiguous active troubleshooting window is available to stop."
                )
            # The GUI carries forward this exact expiration and omits start_date.
            body["TroubleshootExpirationDateTimeUtc"] = active[0][
                "TroubleshootExpirationDateTimeUtc"
            ]
        value = await self._dm_request(_DiagnosticsRoute.CREATE, body=body)
        result = self._dd_accepted(
            value, machine_id, "TroubleshootingOn" if enabled else "TroubleshootingOff"
        )
        result["requested_state"] = "on" if enabled else "off"
        result["state_change_confirmed"] = False
        return result

    async def get_support_logs_transfer(self, action_id: str, *, device_id: str):
        """Fail locally until authenticated log-download host/response rules are verified."""
        raise UnsupportedBackendCapability(
            "Support-log download has no validated transfer adapter yet.",
            suggested_fix=(
                "Download the completed support logs from the Defender device action center."
            ),
        )


class OfficialDeviceDiagnostics:
    async def collect_device_support_logs(self, machine_id: str, *, comment: str) -> dict:
        raise _unsupported("Support-log collection")

    async def set_device_troubleshooting(
        self,
        machine_id: str,
        *,
        enabled: bool,
        duration_minutes: int | None,
        comment: str,
    ) -> dict:
        raise _unsupported("Troubleshooting mode")

    async def get_support_logs_transfer(self, action_id: str, *, device_id: str):
        raise _unsupported("Support-log download")
