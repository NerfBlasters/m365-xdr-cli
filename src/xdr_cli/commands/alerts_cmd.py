"""Alerts commands: list, show."""

from __future__ import annotations

import asyncio
from time import monotonic

import click

from xdr_cli.api.alerts import get_alert, list_alerts
from xdr_cli.artifact_records import alert_records
from xdr_cli.auth import AuthManager
from xdr_cli.backends import create_client
from xdr_cli.cli_params import optional_multiple
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.helpers import build_odata_filter, split_csv, validate_filter_choices
from xdr_cli.results import emit_result, write_result
from xdr_cli.sessions import resolve_session_for_invocation, set_session_anchor_incident

alerts_app = click.Group(
    name="alerts",
    help="View security alerts.",
    no_args_is_help=True,
)

_VALID_SEVERITY = frozenset({"high", "medium", "low", "informational", "unknown"})

@alerts_app.command("list")
@click.option(
    "--severity",
    "-s",
    default=None,
    multiple=True,
    callback=optional_multiple,
    help=("Filter by severity. Repeatable, or comma-separated: --severity medium,high."),
)
@click.option("--service", default=None, help="Filter by service source.")
@click.option("--since", default=None, help="Show alerts since (e.g., 24h, 7d).")
@click.option(
    "--limit",
    "-l",
    type=int,
    default=None,
    help="Max results [default: default_limit in config.toml, 25].",
)
@click.pass_context
def alerts_list(
    ctx: click.Context,
    severity: list[str] | None,
    service: str | None,
    since: str | None,
    limit: int | None,
) -> None:
    """List security alerts."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(
        _alerts_list(
            app_ctx,
            severity=severity,
            service=service,
            since=since,
            limit=app_ctx.config.list_limit(limit),
        )
    )


async def _alerts_list(
    ctx: AppContext, severity, service, since, limit,
) -> None:
    severity = split_csv(severity)
    severity = validate_filter_choices(
        severity,
        _VALID_SEVERITY,
        option="--severity",
        help_command="xdr alerts list --help",
    )
    odata_filter = build_odata_filter(
        severity=severity, since=since, service_source=service,
    )
    client = create_client(
        ctx.config, timeout=ctx.config.api_timeout,
        auth_factory=AuthManager, client_factory=XDRClient,
    )
    try:
        started = monotonic()
        items = []
        async for item in list_alerts(
            client, odata_filter=odata_filter, limit=limit,
        ):
            items.append(item)
        artifact = write_result(
            items,
            command=ctx.invoked_command or "alerts list",
            execution_time_ms=int((monotonic() - started) * 1000),
            server_truncation_state="unknown",
            session_id=ctx.session_id,
            session_label=ctx.session_label,
            session_attachment=ctx.session_attachment,
            incident_id=ctx.anchor_incident,
            alert_id=ctx.anchor_alert,
            anchor_provenance=ctx.anchor_provenance,
            extra_metadata={
                "api_backend": ctx.config.api_backend,
                "filters_applied": {
                    "severity": severity,
                    "service": service,
                    "since": since,
                },
                "requested_limit": limit,
            },
            tenant_id=ctx.config.tenant_id,
        )
        emit_result(artifact)
    finally:
        await client.close()


@alerts_app.command("show")
@click.argument("alert_id", type=str, required=True, help="Alert ID.")
@click.pass_context
def alerts_show(
    ctx: click.Context,
    alert_id: str,
) -> None:
    """Show alert details with evidence."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(_alerts_show(app_ctx, alert_id))


async def _alerts_show(ctx: AppContext, alert_id: str) -> None:
    client = create_client(
        ctx.config, timeout=ctx.config.api_timeout,
        auth_factory=AuthManager, client_factory=XDRClient,
    )
    try:
        started = monotonic()
        result = await get_alert(client, alert_id)
        response_provenance = client.profile.response_provenance
        incident_anchor: int | None = None
        if result.get("incidentId") is not None:
            try:
                incident_anchor = int(result["incidentId"])
            except (TypeError, ValueError):
                incident_anchor = None

        # Alert identity is authoritative only after the selected backend returns incidentId.
        # Resolve here, not in the pre-dispatch leaf hook, so a new unrelated
        # alert cannot inherit and then overwrite the previous automatic session.
        session, attachment = resolve_session_for_invocation(
            ctx.invoked_command or "alerts show",
            api_backend=ctx.config.api_backend,
            timeout_seconds=ctx.config.session_timeout_seconds,
            anchor_incident=incident_anchor,
            anchor_alert=alert_id,
            response_provenance=response_provenance,
        )
        if session is not None and incident_anchor is not None:
            session = set_session_anchor_incident(
                session.id,
                incident_anchor,
                provenance=response_provenance,
            ) or session
        ctx.session_attachment = attachment
        if ctx.recorder is not None:
            ctx.recorder.session = session
            ctx.recorder.annotate("session_attachment", attachment)
            if incident_anchor is not None:
                ctx.recorder.annotate("anchor_incident", incident_anchor)
        if result.get("incidentId") is not None:
            ctx.anchor_incident = str(result["incidentId"])
            ctx.anchor_provenance["incident_id"] = response_provenance
        ctx.anchor_alert = alert_id
        ctx.anchor_provenance["alert_id"] = "argv"
        if ctx.recorder is not None:
            ctx.recorder.annotate("anchor_alert", alert_id)
            ctx.recorder.annotate(
                "anchor_provenance",
                dict(ctx.anchor_provenance),
            )
        artifact = write_result(
            alert_records(result, incident_id=result.get("incidentId")),
            command=ctx.invoked_command or "alerts show",
            execution_time_ms=int((monotonic() - started) * 1000),
            server_truncation_state=client.profile.detail_truncation_state,
            session_id=ctx.session_id,
            session_label=ctx.session_label,
            session_attachment=ctx.session_attachment,
            incident_id=(
                str(result["incidentId"])
                if result.get("incidentId") is not None
                else None
            ),
            alert_id=alert_id,
            anchor_provenance=ctx.anchor_provenance,
            tenant_id=ctx.config.tenant_id,
            extra_metadata={
                "api_backend": ctx.config.api_backend,
                "source_contract": "microsoft-graph",
            },
        )
        emit_result(artifact)
    finally:
        await client.close()
