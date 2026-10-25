"""Named operations shared by official and portal authentication backends.

Transport verbs are intentionally absent: adding an operation requires an
implementation in each concrete backend, including an explicit unsupported result.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from xdr_cli.exceptions import NotFoundError, XDRError
from xdr_cli.hunting_result import HuntingResult
from xdr_cli.live_response.models import LRCommandState, LRLibraryFile, LRSession, ParsedCommand
from xdr_cli.live_response.transfer import SignedTransfer


class APIBackend(StrEnum):
    AUTO = "auto"
    OFFICIAL = "official"
    PORTAL_COOKIE = "portal-cookie"


@dataclass(frozen=True)
class BackendProfile:
    name: APIBackend
    cookie_auth: bool
    ad_domains: bool
    package_download: bool
    detail_truncation_state: str
    response_provenance: str
    lr_sessions: bool = False
    lr_batch: bool = False
    lr_library: bool = False


OFFICIAL_PROFILE = BackendProfile(
    name=APIBackend.OFFICIAL, cookie_auth=False, ad_domains=False, package_download=False,
    detail_truncation_state="known-complete", response_provenance="graph-response",
    lr_batch=True, lr_library=True,
)
PORTAL_PROFILE = BackendProfile(
    name=APIBackend.PORTAL_COOKIE, cookie_auth=True, ad_domains=True, package_download=True,
    detail_truncation_state="unknown", response_provenance="portal-response",
    lr_sessions=True, lr_library=True,
)
_PROFILES = {profile.name: profile for profile in (OFFICIAL_PROFILE, PORTAL_PROFILE)}


def backend_profile(selected: str) -> BackendProfile:
    """Look up an already-resolved backend, without loading credentials."""
    return _PROFILES[APIBackend(selected)]


class UnsupportedBackendCapability(XDRError):
    exit_code = 3
    error_code = "BACKEND_CAPABILITY_UNAVAILABLE"
    suggested_fix = "Select --backend official for this operation."

    def __init__(self, message: str | None = None, *, suggested_fix: str | None = None) -> None:
        super().__init__(message or (
            "This operation does not yet have a validated portal-cookie adapter. "
            "No request was sent and no official authentication fallback was attempted."
        ))
        if suggested_fix is not None:
            self.suggested_fix = suggested_fix


def ad_unavailable() -> UnsupportedBackendCapability:
    return UnsupportedBackendCapability(
        "Active Directory domain inventory requires the portal-cookie backend.",
        suggested_fix=(
            "Use --backend portal-cookie, or domains list --source entra for Entra domains only."
        ),
    )


class Backend(ABC):
    @property
    @abstractmethod
    def profile(self) -> BackendProfile: ...

    @abstractmethod
    async def execute_hunting(self, query: str) -> HuntingResult: ...

    @abstractmethod
    def list_incidents(self, *, params: dict, limit: int = 0) -> AsyncIterator[dict]: ...

    @abstractmethod
    async def get_incident(self, incident_id: str, *, expand: list[str] | None = None) -> dict: ...

    @abstractmethod
    async def update_incident(self, incident_id: str, payload: dict) -> dict: ...

    @abstractmethod
    async def add_incident_comment(self, incident_id: str, comment: str) -> dict: ...

    @abstractmethod
    def list_alerts(self, *, params: dict, limit: int = 0) -> AsyncIterator[dict]: ...

    @abstractmethod
    async def get_alert(self, alert_id: str) -> dict: ...

    @abstractmethod
    def iter_domains(self) -> AsyncIterator[dict]: ...

    @abstractmethod
    async def read_ad_domains(self) -> dict: ...

    @abstractmethod
    async def count_ad_domains(self) -> int: ...

    @abstractmethod
    async def get_device(self, device_id: str, *, enrich: bool = True) -> dict: ...

    @abstractmethod
    async def find_device_by_hostname(
        self, hostname: str, *, enrich: bool = True,
    ) -> dict | None: ...

    async def show_device(self, device: str) -> dict:
        if re.fullmatch(r"[a-fA-F0-9]{40}", device):
            return await self.get_device(device)
        found = await self.find_device_by_hostname(device)
        if found is None:
            raise NotFoundError("device hostname", device)
        return found

    @abstractmethod
    async def submit_device_action(
        self, device_id: str, action: str, *, comment: str, mode: str | None = None,
    ) -> dict: ...

    @abstractmethod
    async def get_action_status(self, action_id: str, device_id: str | None = None) -> dict: ...

    @abstractmethod
    async def get_package_download_url(self, action_id: str, device_id: str) -> str: ...

    @abstractmethod
    async def get_device_tags(self, machine_id: str) -> dict: ...

    @abstractmethod
    async def set_device_tags(
        self, machine_id: str, tags: list[str], *, expected_current: list[str],
    ) -> dict: ...

    @abstractmethod
    async def update_device_tag(self, machine_id: str, tag: str, *, remove: bool) -> dict: ...

    @abstractmethod
    async def get_device_action_permissions(self, machine_id: str) -> dict: ...

    @abstractmethod
    async def cancel_device_action(
        self, action_id: str, *, device_id: str, comment: str,
    ) -> dict: ...

    @abstractmethod
    async def start_device_investigation(self, machine_id: str, *, comment: str) -> dict: ...

    @abstractmethod
    def iter_device_action_history(
        self, machine_id: str, *, limit: int = 100,
    ) -> AsyncIterator[dict]: ...

    @abstractmethod
    async def collect_device_support_logs(self, machine_id: str, *, comment: str) -> dict: ...

    @abstractmethod
    async def set_device_troubleshooting(
        self, machine_id: str, *, enabled: bool, duration_minutes: int | None, comment: str,
    ) -> dict: ...

    @abstractmethod
    async def get_support_logs_transfer(
        self, action_id: str, *, device_id: str,
    ) -> SignedTransfer: ...

    @abstractmethod
    async def lr_capabilities(self, machine_id: str) -> dict: ...

    @abstractmethod
    async def lr_command_definitions(self, session_id: str) -> list[dict]: ...

    @abstractmethod
    async def lr_open_session(self, machine_id: str, *, comment: str | None) -> LRSession: ...

    @abstractmethod
    async def lr_get_session(self, session_id: str) -> LRSession: ...

    @abstractmethod
    def lr_iter_sessions(self, *, machine_id: str | None) -> AsyncIterator[LRSession]: ...

    @abstractmethod
    async def lr_close_session(self, session_id: str) -> LRSession: ...

    @abstractmethod
    async def lr_submit(self, session_id: str, command: ParsedCommand) -> LRCommandState: ...

    @abstractmethod
    async def lr_submit_batch(
        self, machine_id: str, commands: Sequence[ParsedCommand], *, comment: str,
    ) -> LRCommandState: ...

    @abstractmethod
    async def lr_get_command(self, session_id: str | None, command_id: str) -> LRCommandState: ...

    @abstractmethod
    def lr_iter_commands(self, session_id: str) -> AsyncIterator[LRCommandState]: ...

    @abstractmethod
    async def lr_cancel(self, session_id: str | None, command_id: str) -> LRCommandState: ...

    @abstractmethod
    def lr_iter_output(self, session_id: str | None, command_id: str) -> AsyncIterator[dict]: ...

    @abstractmethod
    async def lr_result_transfer(
        self, session_id: str | None, command_id: str, *, index: int = 0,
    ) -> SignedTransfer: ...

    @abstractmethod
    def lr_iter_library(self) -> AsyncIterator[LRLibraryFile]: ...

    @abstractmethod
    async def lr_library_transfer(self, name: str) -> SignedTransfer: ...

    @abstractmethod
    async def lr_upload_library(
        self, path: Path, *, description: str | None, parameters_description: str | None,
        has_parameters: bool, overwrite: bool,
    ) -> LRLibraryFile: ...

    @abstractmethod
    async def lr_delete_library(self, name: str) -> None: ...

    async def list_hunting_schema(self) -> list[dict]:
        """Return the tenant's advanced-hunting table metadata listing."""

        raise UnsupportedBackendCapability(
            "Hunting schema metadata is available only through the portal-cookie backend.",
            suggested_fix="Use the getschema probe, or import portal cookies for this tenant.",
        )

    @abstractmethod
    async def close(self) -> None: ...
