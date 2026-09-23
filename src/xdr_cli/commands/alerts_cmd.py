"""Alerts commands: list, show."""

from __future__ import annotations

import asyncio
from time import monotonic

import typer

from xdr_cli.api.alerts import get_alert, list_alerts
from xdr_cli.artifact_records import alert_records
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.helpers import build_odata_filter, split_csv, validate_filter_choices
from xdr_cli.results import emit_result, write_result
from xdr_cli.sessions import resolve_session_for_invocation, set_session_anchor_incident

alerts_app = typer.Typer(
    name="alerts",
    help="View security alerts.",
    no_args_is_help=True,
)

_VALID_SEVERITY = frozenset({"high", "medium", "low", "informational", "unknown"})

@alerts_app.command("list")
def alerts_list(
    ctx: typer.Context,
    severity: list[str] | None = typer.Option(
        None, "--severity", "-s",
        help="Filter by severity. Repeatable, or comma-separated: --severity medium,high.",
    ),
    service: str | None = typer.Option(
        None, "--service", help="Filter by service source.",
    ),
    since: str | None = typer.Option(
        None, "--since", help="Show alerts since (e.g., 24h, 7d).",
    ),
    limit: int = typer.Option(
        25, "--limit", "-l", help="Max results.",
    ),
) -> None:
    """List security alerts."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(
        _alerts_list(
            app_ctx,
            severity=severity,
            service=service,
            since=since,
            limit=limit,
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
    auth = AuthManager(ctx.config)
    client = XDRClient(
        get_token=auth.get_token, timeout=ctx.config.api_timeout,
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
def alerts_show(
    ctx: typer.Context,
    alert_id: str = typer.Argument(help="Alert ID."),
) -> None:
    """Show alert details with evidence."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(_alerts_show(app_ctx, alert_id))


async def _alerts_show(ctx: AppContext, alert_id: str) -> None:
    auth = AuthManager(ctx.config)
    client = XDRClient(
        get_token=auth.get_token, timeout=ctx.config.api_timeout,
    )
    try:
        started = monotonic()
        result = await get_alert(client, alert_id)
        incident_anchor: int | None = None
        if result.get("incidentId") is not None:
            try:
                incident_anchor = int(result["incidentId"])
            except (TypeError, ValueError):
                incident_anchor = None

        # Alert identity is authoritative only after Graph returns incidentId.
        # Resolve here, not in the pre-dispatch leaf hook, so a new unrelated
        # alert cannot inherit and then overwrite the previous automatic session.
        session, attachment = resolve_session_for_invocation(
            ctx.invoked_command or "alerts show",
            timeout_seconds=ctx.config.session_timeout_seconds,
            anchor_incident=incident_anchor,
            anchor_alert=alert_id,
        )
        if session is not None and incident_anchor is not None:
            session = set_session_anchor_incident(
                session.id,
                incident_anchor,
                provenance="graph-response",
            ) or session
        ctx.session_attachment = attachment
        if ctx.recorder is not None:
            ctx.recorder.session = session
            ctx.recorder.annotate("session_attachment", attachment)
            if incident_anchor is not None:
                ctx.recorder.annotate("anchor_incident", incident_anchor)
        if result.get("incidentId") is not None:
            ctx.anchor_incident = str(result["incidentId"])
            ctx.anchor_provenance["incident_id"] = "graph-response"
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
            server_truncation_state="known-complete",
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
        )
        emit_result(artifact)
    finally:
        await client.close()
