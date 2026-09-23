"""Devices API — Defender for Endpoint machines and actions."""

from __future__ import annotations

from xdr_cli.client import APISurface, XDRClient


async def get_device(client: XDRClient, device_id: str) -> dict:
    """Get device details by ID."""
    return await client.get(APISurface.MDE, f"machines/{device_id}")


async def find_device_by_hostname(
    client: XDRClient, hostname: str,
) -> dict | None:
    """Find a device by hostname. Returns the first match or None."""
    result = await client.get(
        APISurface.MDE,
        "machines",
        params={
            "$filter": f"computerDnsName eq '{hostname}'",
            "$top": 1,
        },
    )
    machines = result.get("value", [])
    return machines[0] if machines else None


async def isolate_device(
    client: XDRClient,
    device_id: str,
    *,
    isolation_type: str = "Full",
    comment: str = "",
) -> dict:
    """Isolate a device from the network."""
    return await client.post(
        APISurface.MDE,
        f"machines/{device_id}/isolate",
        json={"Comment": comment, "IsolationType": isolation_type},
    )


async def unisolate_device(
    client: XDRClient, device_id: str, *, comment: str = "",
) -> dict:
    """Release a device from network isolation."""
    return await client.post(
        APISurface.MDE,
        f"machines/{device_id}/unisolate",
        json={"Comment": comment},
    )


async def run_av_scan(
    client: XDRClient,
    device_id: str,
    *,
    scan_type: str = "Quick",
    comment: str = "",
) -> dict:
    """Trigger an antivirus scan on a device."""
    return await client.post(
        APISurface.MDE,
        f"machines/{device_id}/runAntiVirusScan",
        json={"Comment": comment, "ScanType": scan_type},
    )


async def collect_investigation_package(
    client: XDRClient, device_id: str, *, comment: str = "",
) -> dict:
    """Request a forensic investigation package."""
    return await client.post(
        APISurface.MDE,
        f"machines/{device_id}/collectInvestigationPackage",
        json={"Comment": comment},
    )


async def restrict_code_execution(
    client: XDRClient, device_id: str, *, comment: str = "",
) -> dict:
    """Restrict app execution to Microsoft-signed binaries."""
    return await client.post(
        APISurface.MDE,
        f"machines/{device_id}/restrictCodeExecution",
        json={"Comment": comment},
    )


async def get_action_status(
    client: XDRClient, action_id: str,
) -> dict:
    """Check the status of a submitted machine action."""
    return await client.get(
        APISurface.MDE, f"machineactions/{action_id}",
    )
