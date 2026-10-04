"""Domain discovery across Entra and Defender for Identity."""
from __future__ import annotations

import asyncio
from enum import StrEnum

import typer

from xdr_cli.api.domains import iter_domains
from xdr_cli.auth import AuthManager
from xdr_cli.backends import PortalBackend, UnsupportedBackendCapability, create_client
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import APIError, PartialSuccessError, XDRError
from xdr_cli.results import emit_result, write_result

domains_app = typer.Typer(
    name="domains", help="Entra tenant and observed Active Directory domains.",
    no_args_is_help=True,
)


class DomainSource(StrEnum):
    ALL = "all"
    ENTRA = "entra"
    AD = "active-directory"


def _ad_unavailable() -> UnsupportedBackendCapability:
    error = UnsupportedBackendCapability()
    error.message = "Active Directory domain inventory requires the portal-cookie backend."
    error.suggested_fix = (
        "Use --backend portal-cookie, or domains list --source entra for Entra domains only."
    )
    return error


@domains_app.command("list")
def domains_list(
    ctx: typer.Context,
    source: DomainSource = typer.Option(
        DomainSource.ALL, "--source", help="Domain inventory source (default: both).",
    ),
) -> None:
    """Save domain records with source labels as private JSONL.

    Active Directory reads require portal-cookie and are capped at 100 records.
    Unavailable sources or incomplete results return durable data plus exit 14.
    Entra and AD records retain distinct identifiers even when DNS names match.
    """
    app_ctx: AppContext = ctx.obj
    if source == DomainSource.AD and app_ctx.config.api_backend != "portal-cookie":
        raise _ad_unavailable()
    asyncio.run(_domains_list(app_ctx, source))


async def _domains_list(ctx: AppContext, source: DomainSource) -> None:
    client = create_client(ctx.config, auth_factory=AuthManager, client_factory=XDRClient)
    rows: list[dict] = []
    coverage: dict[str, dict] = {}
    failures: list[XDRError] = []
    completed_source = False

    def failed(name: str, error: XDRError) -> None:
        retained = sum(row["source"] == name for row in rows)
        coverage[name] = {**coverage.get(name, {}), "rows": retained,
                          "status": "partial" if retained else "unavailable",
                          "error_code": error.error_code}
        failures.append(error)

    try:
        if source != DomainSource.AD:
            try:
                async for row in iter_domains(client):
                    rows.append({**row, "name": row["id"], "source": "entra"})
                coverage["entra"] = {"status": "complete", "rows": len(rows)}
                completed_source = True
            except XDRError as exc:
                failed("entra", exc)
        if source != DomainSource.ENTRA:
            if not isinstance(client, PortalBackend):
                failed("active-directory", _ad_unavailable())
            elif failures and int(failures[-1].exit_code) in (2, 4, 9, 10, 11):
                coverage["active-directory"] = {"status": "not_attempted",
                                                 "reason": "previous_request_failed"}
            else:
                try:
                    result = await client.read_ad_domains()
                    ad_rows = result["results"]
                    rows.extend({**row, "name": row["dnsName"], "source": "active-directory"}
                                for row in ad_rows)
                    native_errors = any(
                        result.get(key) for key in ("error", "errors", "Error", "Errors")
                    )
                    coverage["active-directory"] = {
                        "status": "partial" if result["hasMore"] or native_errors else "complete",
                        "rows": len(ad_rows), "has_more": result["hasMore"],
                        "upstream_errors": native_errors, "requested_limit": 100,
                        "scope": "mdi-observed-domains",
                    }
                    if result["hasMore"] or native_errors:
                        failures.append(APIError("AD domain search returned incomplete results."))
                    if not native_errors:
                        completed_source = True
                        total = await client.count_ad_domains()
                        coverage["active-directory"]["reported_total"] = total
                        if total != len(ad_rows):
                            coverage["active-directory"]["status"] = "partial"
                            failures.append(APIError(
                                "AD domain search and count snapshots differ."
                            ))
                except XDRError as exc:
                    failed("active-directory", exc)
                    if "rows" in coverage["active-directory"]:
                        coverage["active-directory"]["status"] = "partial"
        if failures and not rows and not completed_source:
            raise failures[0]
        context = {"sources": coverage, "requested_source": source.value}
        artifact = write_result(
            rows, command=ctx.invoked_command or "domains list",
            tenant_id=ctx.config.tenant_id, session_id=ctx.session_id,
            session_label=ctx.session_label, session_attachment=ctx.session_attachment,
            extra_metadata={"api_backend": ctx.config.api_backend, **context},
            receipt_context=context,
        )
        emit_result(artifact)
        if failures:
            partial = PartialSuccessError(
                "Domain inventory is incomplete; inspect the receipt's sources coverage.",
                help_command="xdr domains list --help",
            )
            partial.retry_after_seconds = next(
                (e.retry_after_seconds for e in failures if e.retry_after_seconds is not None),
                None,
            )
            raise partial from failures[0]
    finally:
        await client.close()
