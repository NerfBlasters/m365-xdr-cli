"""Incidents commands: list, show, update."""

from __future__ import annotations

import asyncio
import contextlib
from time import monotonic

import typer

from xdr_cli.api.incidents import (
    add_incident_comment,
    get_incident,
    list_incidents,
    update_incident,
)
from xdr_cli.artifact_records import incident_records
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import ConflictError, PartialSuccessError, UsageError, XDRError
from xdr_cli.helpers import build_odata_filter, split_csv, validate_filter_choices
from xdr_cli.output import OutputFormatter, err_console
from xdr_cli.results import emit_result, write_result
from xdr_cli.sessions import set_session_anchor_incident


def _validate_choice(
    value: str | None,
    valid: frozenset[str] | tuple[str, ...],
    flag: str,
) -> str | None:
    """Validate that ``value`` is in ``valid`` for the option named ``flag``.

    Returns ``None`` unchanged so callers can pass through the not-supplied
    case. Invalid input raises a structured usage error with the allowed set.
    """
    if value is None:
        return None
    if value not in valid:
        error = UsageError(
            f"Invalid {flag}: {value!r}.",
            invalid={"kind": "enum", "value": value, "option": flag},
            allowed=sorted(valid),
            help_command="xdr incidents update --help",
        )
        error.error_code = "CLI_INVALID_ENUM"
        raise error
    return value

incidents_app = typer.Typer(
    name="incidents",
    help="Manage security incidents.",
    no_args_is_help=True,
)

_VALID_SEVERITY = frozenset({"high", "medium", "low", "informational"})
_VALID_INCIDENT_STATUS = frozenset({"active", "resolved", "redirected", "inProgress"})

@incidents_app.command("list")
def incidents_list(
    ctx: typer.Context,
    severity: list[str] | None = typer.Option(
        None, "--severity", "-s",
        help=(
            "Filter by severity (high, medium, low, informational). "
            "Repeatable, or comma-separated: --severity medium,high."
        ),
    ),
    status: list[str] | None = typer.Option(
        None, "--status",
        help=(
            "Filter by status (active, resolved, inProgress, redirected). "
            "Repeatable, or comma-separated: --status active,inProgress."
        ),
    ),
    assigned_to: str | None = typer.Option(
        None, "--assigned-to", help="Filter by assignee.",
    ),
    since: str | None = typer.Option(
        None, "--since",
        help="Show incidents since (e.g., 7d, 24h, 30m).",
    ),
    limit: int = typer.Option(
        25, "--limit", "-l", help="Max results to return.",
    ),
) -> None:
    """List incidents in the tenant (use --status to filter, e.g. --status active).

    Output schema (envelope at .data[]):
      id (str)               — Microsoft Graph incident id, e.g. "155278"
      displayName (str)      — analyst-facing title
      severity (str)         — informational | low | medium | high
      status (str)           — active | resolved | inProgress | redirected
      classification (str)   — unknown | falsePositive | truePositive |
                              informationalExpectedActivity
      determination (str)    — unknown | apt | malware | securityPersonnel |
                              other | unknownFutureValue | ...
      createdDateTime (str)  — ISO-8601 UTC timestamp
      lastUpdateDateTime (str) — ISO-8601 UTC timestamp
      assignedTo (str|null)  — UPN of assignee, null when unassigned
      alertCount (int)       — number of alerts in the incident

    Full rows are saved as JSONL; use the receipt's data_path with rg/jq."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(
        _list(
            app_ctx,
            severity=severity,
            status=status,
            assigned_to=assigned_to,
            since=since,
            limit=limit,
        )
    )


async def _list(
    ctx: AppContext,
    severity: list[str] | None,
    status: list[str] | None,
    assigned_to: str | None,
    since: str | None,
    limit: int,
) -> None:
    severity = split_csv(severity)
    status = split_csv(status)
    severity = validate_filter_choices(
        severity,
        _VALID_SEVERITY,
        option="--severity",
        help_command="xdr incidents list --help",
    )
    status = validate_filter_choices(
        status,
        _VALID_INCIDENT_STATUS,
        option="--status",
        help_command="xdr incidents list --help",
    )
    odata_filter = build_odata_filter(
        severity=severity,
        status=status,
        assigned_to=assigned_to,
        since=since,
    )
    auth = AuthManager(ctx.config)
    client = XDRClient(
        get_token=auth.get_token, timeout=ctx.config.api_timeout,
    )
    try:
        started = monotonic()
        items = []
        async for item in list_incidents(
            client, odata_filter=odata_filter, limit=limit,
        ):
            items.append(item)

        artifact = write_result(
            items,
            command=ctx.invoked_command or "incidents list",
            execution_time_ms=int((monotonic() - started) * 1000),
            server_truncation_state="unknown",
            session_id=ctx.session_id,
            session_label=ctx.session_label,
            session_attachment=ctx.session_attachment,
            incident_id=ctx.anchor_incident,
            alert_id=ctx.anchor_alert,
            anchor_provenance=ctx.anchor_provenance,
            extra_metadata={
                "returned_count": len(items),
                "filters_applied": {
                    "severity": severity,
                    "status": status,
                    "since": since,
                },
                "requested_limit": limit,
            },
            tenant_id=ctx.config.tenant_id,
        )
        emit_result(artifact)
    finally:
        await client.close()


@incidents_app.command("show")
def incidents_show(
    ctx: typer.Context,
    incident_id: str = typer.Argument(help="Incident ID."),
    expand: list[str] | None = typer.Option(
        None, "--expand", "-e",
        help="Expand: alerts, evidence. Repeatable.",
    ),
) -> None:
    """Show incident details."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(_show(app_ctx, incident_id, expand=expand))
    # Auto-set the session's anchor_incident so subsequent recorded invocations
    # inherit it as their default. No-op if no active session.
    session = app_ctx.recorder.session if app_ctx.recorder else None
    if session is not None:
        with contextlib.suppress(TypeError, ValueError):
            set_session_anchor_incident(session.id, int(incident_id))


async def _show(
    ctx: AppContext, incident_id: str, expand: list[str] | None,
) -> None:
    auth = AuthManager(ctx.config)
    client = XDRClient(
        get_token=auth.get_token, timeout=ctx.config.api_timeout,
    )
    try:
        started = monotonic()
        result = await get_incident(
            client, incident_id, expand=expand,
        )
        artifact = write_result(
            incident_records(result),
            command=ctx.invoked_command or "incidents show",
            execution_time_ms=int((monotonic() - started) * 1000),
            server_truncation_state="known-complete",
            session_id=ctx.session_id,
            session_label=ctx.session_label,
            session_attachment=ctx.session_attachment,
            incident_id=incident_id,
            alert_id=ctx.anchor_alert,
            anchor_provenance=ctx.anchor_provenance,
            extra_metadata={"expand": expand or []},
            tenant_id=ctx.config.tenant_id,
        )
        emit_result(artifact)
    finally:
        await client.close()


_VALID_STATUS = _VALID_INCIDENT_STATUS
_VALID_CLASSIFICATION = frozenset(
    {
        "unknown",
        "falsePositive",
        "truePositive",
        "informationalExpectedActivity",
    }
)
# Graph API-accepted determinations. The Defender portal UI also shows
# "confirmedUserActivity" but it's not in the API enum — agents that copy
# from the UI hit an opaque 400. Validate up front.
_VALID_DETERMINATION = frozenset(
    {
        "unknown",
        "apt",
        "malware",
        "securityPersonnel",
        "securityTesting",
        "unwantedSoftware",
        "other",
        "multiStagedAttack",
        "compromisedUser",
        "phishing",
        "maliciousUserActivity",
        "notMalicious",
        "notEnoughDataToValidate",
        "lineOfBusinessApplication",
    }
)


@incidents_app.command("update")
def incidents_update(
    ctx: typer.Context,
    incident_id: str = typer.Argument(help="Incident ID."),
    status: str | None = typer.Option(
        None, "--status",
        help=f"New status. One of: {', '.join(sorted(_VALID_STATUS))}.",
    ),
    classification: str | None = typer.Option(
        None, "--classification",
        help=f"One of: {', '.join(sorted(_VALID_CLASSIFICATION))}.",
    ),
    determination: str | None = typer.Option(
        None, "--determination",
        help=f"One of: {', '.join(sorted(_VALID_DETERMINATION))}.",
    ),
    comment: str | None = typer.Option(
        None, "--comment",
        help=(
            "Add a comment. Supports \\r\\n line breaks: the Defender portal "
            "squashes them in the Activity log list view but renders them "
            "correctly in the comment fly-out when clicked."
        ),
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Show what would be updated without making changes.",
    ),
) -> None:
    """Update an incident's status, classification, or determination."""
    app_ctx: AppContext = ctx.obj
    with contextlib.suppress(TypeError, ValueError):
        anchor = int(incident_id)
        if app_ctx.recorder is not None:
            app_ctx.recorder.annotate("anchor_incident", anchor)
        if app_ctx.session_id:
            set_session_anchor_incident(app_ctx.session_id, anchor)

    # Validate enum values at the CLI surface so bad values fail loud
    # with the valid-set listed (vs. silent API rejection).
    status = _validate_choice(status, _VALID_STATUS, "--status")
    classification = _validate_choice(classification, _VALID_CLASSIFICATION, "--classification")
    determination = _validate_choice(determination, _VALID_DETERMINATION, "--determination")

    payload: dict = {}
    if status:
        payload["status"] = status
    if classification:
        payload["classification"] = classification
    if determination:
        payload["determination"] = determination
    # Comments live on a separate endpoint — they are NOT part of the PATCH body.
    # We POST the comment in a second call after the PATCH succeeds (see _update).

    if not payload and not comment:
        typer.echo(
            '{"status":"success","data":{"updated":false,'
            '"reason":"no-updates-specified"}}'
        )
        return

    if dry_run:
        fmt = OutputFormatter(
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
        )
        dry_info: dict = {
            "dry_run": True,
            "incident_id": incident_id,
            "changes": payload,
        }
        if comment:
            dry_info["comment"] = comment
        output = fmt.format_output(dry_info)
        typer.echo(output)
        return

    if not yes and app_ctx.is_interactive:
        err_console.print(
            f"[bold]Updating incident {incident_id}:[/bold]",
        )
        for k, v in payload.items():
            err_console.print(f"  {k}: {v}")
        if not typer.confirm("Proceed?"):
            raise ConflictError("Incident update was cancelled by the operator.")

    if not yes and not app_ctx.is_interactive:
        raise UsageError(
            "Non-interactive incident updates require --yes.",
            invalid={"kind": "missing_option", "value": "--yes"},
            suggestions=[
                {
                    "reason": "confirmation_required",
                    "message": "Re-run the same incident update command with --yes.",
                    "confidence": "exact",
                }
            ],
            help_command="xdr incidents update --help",
        )

    asyncio.run(_update(app_ctx, incident_id, payload, comment=comment))


async def _update(
    ctx: AppContext,
    incident_id: str,
    payload: dict,
    *,
    comment: str | None = None,
) -> None:
    auth = AuthManager(ctx.config)
    client = XDRClient(
        get_token=auth.get_token, timeout=ctx.config.api_timeout,
    )
    try:
        if payload:
            result = await update_incident(client, incident_id, payload)
        else:
            # Comment-only update: fetch the current incident so the operator
            # sees its state back in the envelope rather than an empty dict.
            result = await get_incident(client, incident_id)
        if comment:
            try:
                await add_incident_comment(client, incident_id, comment)
            except XDRError as exc:
                message = (
                    "The incident field update completed, but the comment request "
                    "did not complete successfully. Do not repeat the full update; "
                    "inspect the incident, then retry only --comment if needed."
                    if payload
                    else "The comment request failed and its server-side outcome is "
                    "unknown. Inspect the incident before retrying the comment."
                )
                raise PartialSuccessError(
                    message,
                    retryable=False,
                    suggestions=[
                        {
                            "reason": "avoid_duplicate_update",
                            "message": (
                                f"xdr incidents show {incident_id}, then use a "
                                "comment-only incidents update if the comment is absent."
                            ),
                            "confidence": "exact",
                        }
                    ],
                    original={
                        "type": "PartialIncidentUpdate",
                        "incident_id": incident_id,
                        "fields_updated": bool(payload),
                        "comment_outcome": "unknown",
                        "comment_error_code": exc.error_code,
                    },
                ) from exc
        fmt = OutputFormatter(
            session_id=ctx.session_id,
            session_label=ctx.session_label,
        )
        output = fmt.format_output(
            result,
            metadata={
                "action": "updated",
                "incident_id": incident_id,
                "comment_added": comment is not None,
            },
        )
        typer.echo(output)
    finally:
        await client.close()
