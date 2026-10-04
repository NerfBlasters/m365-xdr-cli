"""Official named operations over the MSAL-backed Graph/MDE transport."""
from __future__ import annotations

from collections.abc import AsyncIterator

from xdr_cli.backend_contract import OFFICIAL_PROFILE, Backend, ad_unavailable
from xdr_cli.client import APISurface, XDRClient
from xdr_cli.continuation import validate_continuation
from xdr_cli.exceptions import APIError, ForbiddenError, NotFoundError, UsageError
from xdr_cli.hunting_result import HuntingResult, _normalize_response
from xdr_cli.output import err_console


class OfficialBackend(Backend):
    profile = OFFICIAL_PROFILE

    def __init__(self, transport: XDRClient) -> None:
        self.transport = transport

    async def execute_hunting(self, query: str) -> HuntingResult:
        try:
            response = await self.transport.post(
                APISurface.GRAPH, "runHuntingQuery", json={"query": query},
            )
        except (NotFoundError, ForbiddenError):
            err_console.print(
                "[dim]Graph hunting unavailable on this tenant; "
                "falling back to MDE-only tables...[/dim]"
            )
            response = await self.transport.post(
                APISurface.MDE, "advancedqueries/run", json={"Query": query},
            )
        return _normalize_response(response)

    async def list_incidents(self, *, params: dict, limit: int = 0) -> AsyncIterator[dict]:
        async for row in self.transport.paginate(
            APISurface.GRAPH, "incidents", params=params, limit=limit,
        ):
            yield row

    async def get_incident(self, incident_id: str, *, expand: list[str] | None = None) -> dict:
        return await self.transport.get(
            APISurface.GRAPH, f"incidents/{incident_id}",
            params={"$expand": ",".join(expand)} if expand else None,
        )

    async def update_incident(self, incident_id: str, payload: dict) -> dict:
        return await self.transport.patch(
            APISurface.GRAPH, f"incidents/{incident_id}", json=payload,
        )

    async def add_incident_comment(self, incident_id: str, comment: str) -> dict:
        return await self.transport.post(
            APISurface.GRAPH, f"incidents/{incident_id}/comments", json={"comment": comment},
        )

    async def list_alerts(self, *, params: dict, limit: int = 0) -> AsyncIterator[dict]:
        async for row in self.transport.paginate(
            APISurface.GRAPH, "alerts_v2", params=params, limit=limit,
        ):
            yield row

    async def get_alert(self, alert_id: str) -> dict:
        return await self.transport.get(APISurface.GRAPH, f"alerts_v2/{alert_id}")

    async def iter_domains(self) -> AsyncIterator[dict]:
        path = "domains"
        seen_links: set[str] = set()
        seen_ids: set[str] = set()
        for _ in range(100):
            result = await self.transport.get(APISurface.GRAPH_CORE, path)
            rows = result.get("value")
            if not isinstance(rows, list):
                raise APIError("Graph domains returned an invalid collection.")
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                        or not row["id"] or row["id"] in seen_ids):
                    raise APIError("Graph domains returned invalid or duplicate records.")
                seen_ids.add(row["id"])
                yield row
            link = result.get("@odata.nextLink")
            if not link:
                return
            path = str(validate_continuation(
                link, routes=frozenset({("graph.microsoft.com", "/v1.0/domains")}),
                seen=seen_links,
            ))
        raise APIError("Graph domain pagination exceeded its page bound.")

    async def read_ad_domains(self) -> dict:
        raise ad_unavailable()

    async def count_ad_domains(self) -> int:
        raise ad_unavailable()

    async def get_device(self, device_id: str, *, enrich: bool = True) -> dict:
        return await self.transport.get(APISurface.MDE, f"machines/{device_id}")

    async def find_device_by_hostname(self, hostname: str, *, enrich: bool = True) -> dict | None:
        result = await self.transport.get(
            APISurface.MDE, "machines",
            params={"$filter": f"computerDnsName eq '{hostname}'", "$top": 1},
        )
        machines = result.get("value", [])
        return machines[0] if machines else None

    async def show_device(self, device: str) -> dict:
        # Preserve the official command's existing hostname/ID resolution.
        if "-" not in device or len(device) < 30:
            found = await self.find_device_by_hostname(device)
            if found:
                return found
        return await self.get_device(device)

    async def submit_device_action(
        self, device_id: str, action: str, *, comment: str, mode: str | None = None,
    ) -> dict:
        paths = {
            "isolate": "isolate", "unisolate": "unisolate", "scan": "runAntiVirusScan",
            "collect-package": "collectInvestigationPackage", "restrict": "restrictCodeExecution",
            "unrestrict": "unrestrictCodeExecution",
        }
        if action not in paths:
            raise UsageError("Unknown device action; no request was sent.")
        body = {"Comment": comment}
        if action == "isolate":
            body["IsolationType"] = mode
        elif action == "scan":
            body["ScanType"] = mode
        return await self.transport.post(APISurface.MDE, f"machines/{device_id}/{paths[action]}",
                                         json=body)

    async def get_action_status(self, action_id: str, device_id: str | None = None) -> dict:
        return await self.transport.get(APISurface.MDE, f"machineactions/{action_id}")

    async def get_package_download_url(self, action_id: str, device_id: str) -> str:
        raise UsageError("Package download requires --backend portal-cookie.")

    async def close(self) -> None:
        await self.transport.close()
