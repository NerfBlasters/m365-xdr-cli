"""Devices API — Defender for Endpoint machines and actions."""

from __future__ import annotations

from xdr_cli.backend_contract import Backend


async def get_device(client: Backend, device_id: str, *, enrich: bool = True) -> dict:
    """Get device details by ID."""
    return await client.get_device(device_id, enrich=enrich)


async def find_device_by_hostname(
    client: Backend, hostname: str, *, enrich: bool = True,
) -> dict | None:
    """Find a device by hostname. Returns the first match or None."""
    return await client.find_device_by_hostname(hostname, enrich=enrich)


async def isolate_device(
    client: Backend,
    device_id: str,
    *,
    isolation_type: str = "Full",
    comment: str = "",
) -> dict:
    """Isolate a device from the network."""
    return await client.submit_device_action(
        device_id, "isolate", comment=comment, mode=isolation_type,
    )


async def unisolate_device(
    client: Backend, device_id: str, *, comment: str = "",
) -> dict:
    """Release a device from network isolation."""
    return await client.submit_device_action(device_id, "unisolate", comment=comment)


async def run_av_scan(
    client: Backend,
    device_id: str,
    *,
    scan_type: str = "Quick",
    comment: str = "",
) -> dict:
    """Trigger an antivirus scan on a device."""
    return await client.submit_device_action(
        device_id, "scan", comment=comment, mode=scan_type,
    )


async def collect_investigation_package(
    client: Backend, device_id: str, *, comment: str = "",
) -> dict:
    """Request a forensic investigation package."""
    return await client.submit_device_action(device_id, "collect-package", comment=comment)


async def restrict_code_execution(
    client: Backend, device_id: str, *, comment: str = "",
) -> dict:
    """Restrict app execution to Microsoft-signed binaries."""
    return await client.submit_device_action(device_id, "restrict", comment=comment)


async def unrestrict_code_execution(
    client: Backend, device_id: str, *, comment: str = "",
) -> dict:
    """Remove the Defender app-execution restriction."""
    return await client.submit_device_action(device_id, "unrestrict", comment=comment)


async def get_action_status(
    client: Backend, action_id: str, *, device_id: str | None = None,
) -> dict:
    """Check the status of a submitted machine action."""
    return await client.get_action_status(action_id, device_id)
