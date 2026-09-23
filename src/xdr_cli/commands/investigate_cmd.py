"""Guided investigation workflow combining incidents, hunting, and containment recommendations."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
from time import monotonic
from typing import Any

import typer

from xdr_cli._recording import run_kql_with_recording
from xdr_cli.api.hunting import run_query
from xdr_cli.api.incidents import get_incident
from xdr_cli.artifact_records import investigation_records
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import PartialSuccessError
from xdr_cli.output import err_console
from xdr_cli.queries import load_query
from xdr_cli.results import emit_result, write_result

# Patterns for validating entity values from API responses before use in KQL queries.
# Rejects values containing characters that could alter query structure (' | ; //).
_SAFE_HOSTNAME = re.compile(r"^[a-zA-Z0-9._-]+$")
_SAFE_UPN = re.compile(r"^[a-zA-Z0-9._%+@-]+$")
_SAFE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_SAFE_IP = re.compile(r"^[0-9a-fA-F.:]+$")
_SAFE_MDE_ID = re.compile(r"^[a-fA-F0-9]{32,64}$")

# Matches PowerShell -EncodedCommand / -enc / -e argument with base64 payload.
_ENCODED_PS = re.compile(
    r"-(?:e|en|enc|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)


def _decode_encoded_powershell(cmdline: str) -> str | None:
    """Decode a PowerShell -EncodedCommand payload (UTF-16LE) if present."""
    m = _ENCODED_PS.search(cmdline)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1), validate=True)
        return raw.decode("utf-16-le", errors="replace")
    except Exception:
        return None


def _extract_entities(incident: dict) -> dict[str, Any]:
    """Extract unique entities from incident alerts/evidence.

    Values are validated against expected patterns to prevent query injection
    when they're later substituted into KQL templates by the auto-enrich flow.
    """
    entities: dict[str, Any] = {
        "devices": set(),
        "device_ids": {},  # dns_name -> mdeDeviceId for copy-paste-ready commands
        "users": set(),
        "file_hashes": set(),
        "ips": set(),
        "decoded_commands": [],  # [{command_line, decoded}]
    }
    seen_cmds: set[str] = set()
    for alert in incident.get("alerts", []):
        for ev in alert.get("evidence", []):
            ev_type = ev.get("@odata.type", "").lower()
            if "device" in ev_type:
                name = ev.get("deviceDnsName", "")
                mde_id = ev.get("mdeDeviceId", "")
                if name and _SAFE_HOSTNAME.match(name):
                    entities["devices"].add(name)
                    if mde_id and _SAFE_MDE_ID.match(mde_id):
                        entities["device_ids"][name] = mde_id
                elif name:
                    err_console.print(
                        f"[yellow]Skipping suspicious device name: {name!r}[/yellow]"
                    )
            elif "user" in ev_type:
                upn = ev.get("userAccount", {}).get("userPrincipalName", "")
                if upn and _SAFE_UPN.match(upn):
                    entities["users"].add(upn)
                elif upn:
                    err_console.print(
                        f"[yellow]Skipping suspicious UPN: {upn!r}[/yellow]"
                    )
            elif "file" in ev_type:
                sha = ev.get("fileDetails", {}).get("sha256", "")
                if sha and _SAFE_SHA256.match(sha):
                    entities["file_hashes"].add(sha)
                elif sha:
                    err_console.print(
                        f"[yellow]Skipping suspicious SHA256: {sha!r}[/yellow]"
                    )
            elif "ip" in ev_type:
                addr = ev.get("ipAddress", "")
                if addr and _SAFE_IP.match(addr):
                    entities["ips"].add(addr)
                elif addr:
                    err_console.print(
                        f"[yellow]Skipping suspicious IP: {addr!r}[/yellow]"
                    )
            elif "process" in ev_type:
                cmdline = ev.get("processCommandLine") or ev.get("commandLine", "")
                if cmdline and cmdline not in seen_cmds:
                    decoded = _decode_encoded_powershell(cmdline)
                    if decoded:
                        seen_cmds.add(cmdline)
                        entities["decoded_commands"].append({
                            "command_line": cmdline[:500],
                            "decoded": decoded[:500],
                        })
    return entities


def _suggest_queries(entities: dict[str, Any]) -> list[tuple[str, dict[str, str]]]:
    """Suggest library queries based on extracted entities."""
    suggestions: list[tuple[str, dict[str, str]]] = []

    for device in entities["devices"]:
        suggestions.append(("qry_process_tree", {"device_name": device}))
    for sha in entities["file_hashes"]:
        suggestions.append(("qry_file_hash_scope", {"sha256": sha}))
    if entities["users"]:
        suggestions.append(("ttp_impossible_travel", {}))
        suggestions.append(("ttp_token_theft_replay", {}))
    if entities["devices"]:
        suggestions.append(("ttp_lateral_movement_rdp", {}))
        suggestions.append(("ttp_encoded_powershell", {}))

    return suggestions


def _build_recommended_actions(
    incident: dict, entities: dict[str, Any]
) -> dict[str, Any]:
    """Build a triage-ladder recommendation: investigate first, contain only when warranted.

    Containment is gated on severity=high AND classification not in
    {falsePositive, informationalExpectedActivity}.
    Surfaces Microsoft's own recommendedActions verbatim so the analyst/agent
    sees the graduated "Validate -> Scope -> Contain -> Escalate" guidance
    instead of jumping to isolation on every signal.
    """
    incident_id = str(incident.get("id", ""))
    severity = (incident.get("severity") or "").lower()
    classification = (incident.get("classification") or "").lower()

    investigate_first: list[dict] = []
    contain: list[dict] = []

    for device in sorted(entities["devices"]):
        investigate_first.append({
            "step": "inspect_process_tree",
            "device": device,
            "command": (
                f"xdr library run qry_process_tree "
                f"--param device_name={device}"
            ),
        })
    for sha in sorted(entities["file_hashes"]):
        investigate_first.append({
            "step": "check_file_prevalence",
            "sha256": sha,
            "command": (
                f"xdr library run qry_file_hash_scope "
                f"--param sha256={sha}"
            ),
        })
    for ip in sorted(entities["ips"]):
        try:
            parsed = ipaddress.ip_address(ip)
            is_private = parsed.is_private or parsed.is_loopback or parsed.is_link_local
        except ValueError:
            is_private = False
        if is_private:
            continue  # RFC1918/loopback/link-local — no external-rep lookup needed
        investigate_first.append({
            "step": "check_ip_reputation",
            "ip": ip,
            "note": "External IP — check reputation via threat intel before escalating.",
        })
    for enc in entities.get("decoded_commands", []):
        investigate_first.append({
            "step": "review_decoded_commandline",
            "command_line": enc["command_line"],
            "decoded": enc["decoded"],
            "note": (
                "Decoded Base64 PowerShell — inspect intent before containment. "
                "Benign administrative scripts routinely use -EncodedCommand."
            ),
        })

    # Skip containment for confirmed-benign classifications:
    # - falsePositive: detection was wrong
    # - informationalExpectedActivity: detection was right, but activity is benign
    #   (e.g. security testing, admin scripts — containment would be harmful)
    benign_classifications = {"falsepositive", "informationalexpectedactivity"}
    should_contain = (
        severity == "high" and classification not in benign_classifications
    )
    gating_reason = None
    if not should_contain:
        if classification in benign_classifications:
            gating_reason = (
                f"Classification is '{classification}' — containment not warranted."
            )
        elif severity != "high":
            gating_reason = (
                f"Severity is '{severity or 'unknown'}' (not 'high'); "
                "complete investigation before containment."
            )

    if should_contain:
        for device in sorted(entities["devices"]):
            mde_id = entities["device_ids"].get(device)
            target = mde_id or "<device-id>"
            contain.append({
                "step": "isolate",
                "device": device,
                "mde_device_id": mde_id,
                "command": (
                    f"xdr device isolate {target} --type Full "
                    f"--comment 'Incident {incident_id}' --yes"
                ),
                "rationale": (
                    f"Severity={severity}, classification={classification or 'unknown'}"
                ),
            })

    ms_recommended = None
    for alert in incident.get("alerts", []):
        ra = alert.get("recommendedActions")
        if ra:
            ms_recommended = ra
            break

    return {
        "investigate_first": investigate_first,
        "contain": contain,
        "containment_gated": not should_contain,
        "gating_reason": gating_reason,
        "ms_recommended_actions": ms_recommended,
    }


def investigate(
    ctx: typer.Context,
    incident_id: str = typer.Argument(help="Incident ID to investigate."),
    auto_enrich: bool = typer.Option(
        False, "--auto-enrich", help="Auto-run all relevant enrichment queries."
    ),
) -> None:
    """Guided incident investigation."""
    app_ctx: AppContext = ctx.obj
    asyncio.run(_investigate(app_ctx, incident_id, auto_enrich))


async def _investigate(ctx: AppContext, incident_id: str, auto_enrich: bool) -> None:
    auth = AuthManager(ctx.config)
    client = XDRClient(get_token=auth.get_token, timeout=ctx.config.api_timeout)
    started = monotonic()

    try:
        # Step 1: Fetch incident
        if not ctx.effective_quiet:
            err_console.print(f"[bold]Fetching incident {incident_id}...[/bold]")
        incident = await get_incident(client, incident_id, expand=["alerts"])

        # Anchor the outer ``investigate`` invocation record to this incident
        # so ``xdr history --incident <id>`` (Task 8 surface) can group
        # the outer record with all internal ``investigate.hunt`` fan-outs.
        if ctx.recorder is not None:
            ctx.recorder.annotate("anchor_incident", incident_id)

        # Step 2: Extract entities
        entities = _extract_entities(incident)

        # Step 3: Suggest and run enrichment queries
        suggestions = _suggest_queries(entities)
        enrichment_results: dict[str, list[dict]] = {}
        failed_queries: list[str] = []

        async def _dispatch(query_name: str, params: dict[str, str]) -> None:
            """Run one library query under a child Recorder, capture results.

            Each internal query writes its OWN invocation record to the
            session JSONL (``command="investigate.hunt"`` with
            ``library_query`` and ``anchor_incident`` populated). The child
            Recorder shares the parent's session + monotonic seq axis but
            flushes immediately so the call graph is preserved in temporal
            order even when the outer ``investigate`` call is still running.

            Per-query failures are caught and written into
            ``enrichment_results[name] = [{"error": ...}]`` so the response
            envelope shows which queries failed without aborting the rest of
            the fan-out — same contract as before Task 4.5; the new contract
            is that the JSONL also captures the failure on the corresponding
            child invocation record (via the helper's failure-path
            ``error`` annotation).
            """
            try:
                kql = load_query(query_name, **params)
            except Exception as e:
                enrichment_results[query_name] = [{"error": str(e)}]
                failed_queries.append(query_name)
                return
            if not ctx.effective_quiet:
                err_console.print(f"[dim]Running: {query_name}...[/dim]")
            try:
                recorded = await run_kql_with_recording(
                    ctx,
                    kql=kql,
                    invoked_command="investigate.hunt",
                    library_query=query_name,
                    params=params,
                    anchor_incident=incident_id,
                    expand_json=True,
                    display_limit=None,  # aggregate full results, no truncation
                    child_recorder=True,
                    # Closure captures `kql` by reference but is awaited immediately below,
                    # before the next iteration rebinds — no late-binding hazard.
                    runner=lambda: run_query(client, kql),
                )
                enrichment_results[query_name] = recorded.api_result.results
            except Exception as e:
                # Helper already wrote a child record with `error` populated;
                # mirror the failure into the response envelope so the
                # operator/agent sees it without inspecting the JSONL.
                enrichment_results[query_name] = [{"error": str(e)}]
                failed_queries.append(query_name)

        if suggestions:
            if auto_enrich or not ctx.is_interactive:
                # Run all suggested queries
                for query_name, params in suggestions:
                    await _dispatch(query_name, params)
            elif ctx.is_interactive:
                # Interactive: let user pick
                err_console.print("\n[bold]Suggested enrichment queries:[/bold]")
                for i, (name, params) in enumerate(suggestions):
                    param_str = ", ".join(f"{k}={v}" for k, v in params.items())
                    err_console.print(
                        f"  [{i + 1}] {name}"
                        + (f" ({param_str})" if param_str else "")
                    )
                err_console.print("  [a] All")
                err_console.print("  [n] None")

                choice = typer.prompt("Run which queries?", default="a")

                if choice.lower() == "n":
                    pass
                elif choice.lower() == "a":
                    for query_name, params in suggestions:
                        await _dispatch(query_name, params)
                else:
                    indices = [
                        int(c.strip()) - 1
                        for c in choice.split(",")
                        if c.strip().isdigit()
                    ]
                    for i in indices:
                        if 0 <= i < len(suggestions):
                            query_name, params = suggestions[i]
                            await _dispatch(query_name, params)

        # Step 4: Build investigate-first triage ladder (containment gated on severity)
        recommended = _build_recommended_actions(incident, entities)

        # Aggregate row count across the internal hunts so the outer
        # ``investigate`` record's ``result.row_count`` reflects the total
        # evidence pulled in. Error markers are excluded from the sum.
        if ctx.recorder is not None:
            total_rows = sum(
                len([r for r in rows if "error" not in r])
                for rows in enrichment_results.values()
            )
            ctx.recorder.annotate(
                "result",
                {
                    "row_count": total_rows,
                    "execution_time_ms": None,
                    "cpu_usage": None,
                    "has_more": None,
                    "sample_rows": None,
                    "partial": bool(failed_queries),
                },
            )

        # Step 5: Output
        # entities has mixed value types (sets, dicts, lists) — normalize for JSON.
        entities_out: dict[str, Any] = {}
        for k, v in entities.items():
            if isinstance(v, set):
                entities_out[k] = sorted(v)
            else:
                entities_out[k] = v

        artifact = write_result(
            investigation_records(
                incident,
                entities_out,
                enrichment_results,
                recommended,
            ),
            command=ctx.invoked_command or "investigate",
            execution_time_ms=int((monotonic() - started) * 1000),
            # Advanced Hunting does not provide a completeness guarantee, and
            # failed enrichment makes the bundle explicitly partial.
            server_truncation_state="unknown",
            session_id=ctx.session_id,
            session_label=ctx.session_label,
            session_attachment=ctx.session_attachment,
            incident_id=incident_id,
            alert_id=ctx.anchor_alert,
            anchor_provenance=ctx.anchor_provenance,
            extra_metadata={
                "incident_id": incident_id,
                "queries_run": len(enrichment_results),
                "failed_queries": sorted(set(failed_queries)),
                "partial": bool(failed_queries),
            },
            tenant_id=ctx.config.tenant_id,
        )
        emit_result(artifact)

        if failed_queries:
            raise PartialSuccessError(
                "Investigation artifact was saved, but one or more enrichment "
                "queries failed.",
                original={
                    "type": "PartialInvestigation",
                    "run_id": artifact.receipt.run_id,
                    "data_path": artifact.receipt.data_path,
                    "failed_queries": sorted(set(failed_queries)),
                },
            )

        # Step 6: Interactive prompt (only for human users, never in JSON mode)
        if ctx.is_interactive and not ctx.effective_quiet:
            if recommended["investigate_first"]:
                err_console.print(
                    "\n[bold]Investigate first (run these before any containment):[/bold]"
                )
                for step in recommended["investigate_first"]:
                    cmd = step.get("command") or step.get("note", "")
                    err_console.print(f"  [cyan]{step['step']}[/cyan]: {cmd}")
            if recommended["contain"]:
                err_console.print(
                    "\n[bold red]Containment recommended:[/bold red]"
                )
                for step in recommended["contain"]:
                    err_console.print(f"  {step['command']}")
                    err_console.print(f"    [dim]({step['rationale']})[/dim]")
            elif recommended["gating_reason"]:
                err_console.print(
                    f"\n[bold yellow]No containment suggested:[/bold yellow] "
                    f"{recommended['gating_reason']}"
                )

    finally:
        await client.close()
