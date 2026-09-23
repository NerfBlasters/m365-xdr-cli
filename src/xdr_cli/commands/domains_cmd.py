"""Domain commands: list."""

from __future__ import annotations

import asyncio

import typer

from xdr_cli.api.domains import list_domains
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.output import OutputFormatter

domains_app = typer.Typer(
    name="domains",
    help="Entra ID / M365 tenant domains.",
    no_args_is_help=True,
)

_DOMAIN_COLUMNS = [
    {"key": "id", "header": "Domain", "style": "cyan"},
    {"key": "isDefault", "header": "Default"},
    {"key": "isVerified", "header": "Verified"},
    {"key": "authenticationType", "header": "Auth Type"},
]


@domains_app.command("list")
def domains_list(
    ctx: typer.Context,
) -> None:
    """List all domains registered in the tenant."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(_domains_list(app_ctx))


async def _domains_list(ctx: AppContext) -> None:
    auth = AuthManager(ctx.config)
    client = XDRClient(
        get_token=auth.get_token, timeout=ctx.config.api_timeout,
    )
    try:
        domains = await list_domains(client)
        fmt = OutputFormatter(
            session_id=ctx.session_id,
            session_label=ctx.session_label,
        )
        typer.echo(fmt.format_output(
            domains,
            columns=_DOMAIN_COLUMNS,
            title="Tenant Domains",
        ))
    finally:
        await client.close()
