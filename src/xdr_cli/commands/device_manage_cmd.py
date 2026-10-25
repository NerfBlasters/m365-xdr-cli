"""Device metadata and action-management commands: tags, action availability, cancel.

Tag replacement on the portal replaces the whole manual tag set and has no
server-side compare-and-swap, so ``tags set`` requires the caller to state the
manual tags they expect to replace. Add and remove read the current set and
replace it; a concurrent portal edit can still race them.
"""
from __future__ import annotations

import asyncio
import re
import shlex
from collections.abc import Awaitable, Callable

import click

from xdr_cli.auth import AuthManager
from xdr_cli.backend_contract import Backend
from xdr_cli.backends import create_client
from xdr_cli.client import XDRClient
from xdr_cli.context import AppContext
from xdr_cli.exceptions import ConflictError, UsageError
from xdr_cli.output import OutputFormatter, err_console
from xdr_cli.results import emit_result, write_result

tags_app = click.Group(
    name="tags", help="Read and change a device's manual tags.", no_args_is_help=True,
)

_yes_option = click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
_dry_run_option = click.option("--dry-run", is_flag=True, help="Show what would happen.")
_machine_argument = click.argument("machine_id", type=str, required=True)


def _get_client(ctx: AppContext) -> Backend:
    return create_client(
        ctx.config, timeout=ctx.config.api_timeout,
        auth_factory=AuthManager, client_factory=XDRClient,
    )


# Identifier shapes checked before a dry-run reports success.
_DRY_RUN_IDS = {
    "machine_id": (re.compile(r"[0-9a-fA-F]{40}"), "a 40-character MachineId"),
    "device_id": (re.compile(r"[0-9a-fA-F]{40}"), "a 40-character MachineId"),
    "action_id": (re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"),
                  "an action GUID"),
}


def _check_dry_run_ids(data: dict) -> None:
    for key, (pattern, description) in _DRY_RUN_IDS.items():
        if key in data and not pattern.fullmatch(str(data[key])):
            raise UsageError(f"{key} must be {description}.",
                             invalid={"kind": "identifier", "param": key})


def _emit(ctx: AppContext, data: dict) -> None:
    if data.get("dry_run") is True:
        _check_dry_run_ids(data)
    fmt = OutputFormatter(session_id=ctx.session_id, session_label=ctx.session_label)
    click.echo(fmt.format_output(data))


def _with_client(ctx: AppContext, work: Callable[[Backend], Awaitable[dict]]) -> None:
    async def run() -> None:
        client = _get_client(ctx)
        try:
            _emit(ctx, await work(client))
        finally:
            await client.close()

    asyncio.run(run())


def _confirm(ctx: AppContext, action: str, target: str, yes: bool) -> None:
    if yes:
        return
    if not ctx.is_interactive:
        raise UsageError(
            f"Non-interactive mode requires --yes to {action}.",
            invalid={"kind": "missing_option", "value": "--yes"},
            help_command="xdr device --help",
        )
    err_console.print(f"[bold yellow]About to {action} on {target}.[/bold yellow]")
    if not click.confirm("Proceed?"):
        raise ConflictError("Device operation was cancelled by the operator.")


def _mutate(ctx: AppContext, action: str, target: str, yes: bool,
            work: Callable[[Backend], Awaitable[dict]]) -> None:
    _confirm(ctx, action, target, yes)
    ctx.config.check_mutation_backend()
    _with_client(ctx, work)


@tags_app.command("list")
@_machine_argument
@click.pass_obj
def tags_list(ctx: AppContext, machine_id: str) -> None:
    """Show a device's manual and system tags (read-only)."""

    async def work(client: Backend) -> dict:
        tags = await client.get_device_tags(machine_id)
        expect = " ".join(f"--expect {shlex.quote(tag)}" for tag in tags["manual"])
        return {
            **tags, "machine_id": machine_id,
            "set_command": f"xdr device tags set {machine_id} "
                           f"{expect or '--expect-none'} --tag TAG ... --yes",
        }

    _with_client(ctx, work)


@tags_app.command("set")
@_machine_argument
@click.option("--tag", "tags", multiple=True, default=(),
              help="Desired manual tag; repeatable. Omit all to clear manual tags.")
@click.option("--expect", "expected", multiple=True, default=(),
              help="A manual tag you expect the device to have now; repeatable.")
@click.option("--expect-none", is_flag=True, help="Expect the device to have no manual tags.")
@_yes_option
@_dry_run_option
@click.pass_obj
def tags_set(ctx: AppContext, machine_id: str, tags: tuple[str, ...],
             expected: tuple[str, ...], expect_none: bool, yes: bool, dry_run: bool) -> None:
    """Replace a device's whole manual tag set (portal-cookie).

    The current manual tags must match --expect (or --expect-none); otherwise
    nothing is sent. System tags are never sent. The service offers no atomic
    compare-and-swap, so a concurrent portal edit can still be overwritten.
    Whole-set replacement is tested with synthetic responses only.
    """
    if bool(expected) == expect_none:
        raise UsageError(
            "State the current manual tags with --expect TAG ... or --expect-none.",
            invalid={"kind": "missing_option", "value": "--expect"},
            help_command="xdr device tags list --help",
        )
    if dry_run:
        _emit(ctx, {"dry_run": True, "action": "tags set", "machine_id": machine_id,
                    "tags": list(tags), "expected_current": list(expected)})
        return

    async def work(client: Backend) -> dict:
        return {**await client.set_device_tags(
            machine_id, list(tags), expected_current=list(expected)), "machine_id": machine_id}

    _mutate(ctx, "replace manual tags", f"device {machine_id}", yes, work)


def _tag_update(name: str, remove: bool):
    summary = (
        f"{'Remove' if remove else 'Add'} one manual tag. On portal-cookie this re-reads "
        "and replaces the whole manual set, so a concurrent edit can race it."
    )

    @tags_app.command(name, help=summary)
    @_machine_argument
    @click.argument("tag", type=str)
    @_yes_option
    @_dry_run_option
    @click.pass_obj
    def command(ctx: AppContext, machine_id: str, tag: str, yes: bool, dry_run: bool) -> None:
        if dry_run:
            _emit(ctx, {"dry_run": True, "action": f"tags {name}", "machine_id": machine_id,
                        "tag": tag})
            return

        async def work(client: Backend) -> dict:
            result = await client.update_device_tag(machine_id, tag, remove=remove)
            return {**result, "machine_id": machine_id}

        _mutate(ctx, f"{name} tag '{tag}'", f"device {machine_id}", yes, work)

    return command


tags_add = _tag_update("add", remove=False)
tags_remove = _tag_update("remove", remove=True)


@click.command("action-permissions")
@_machine_argument
@click.pass_obj
def action_permissions(ctx: AppContext, machine_id: str) -> None:
    """Show which response actions the portal reports as available (portal-cookie).

    This is the portal's native availability response, not a grant of
    authorization; the service still enforces RBAC when an action is sent.
    """

    async def work(client: Backend) -> dict:
        return await client.get_device_action_permissions(machine_id)

    _with_client(ctx, work)


@click.command("cancel-action")
@click.argument("action_id", type=str, required=True)
@click.option("--device", "device_id", required=True, help="MachineId the action targets.")
@click.option("--comment", "-c", required=True, help="Reason for cancellation.")
@_yes_option
@_dry_run_option
@click.pass_obj
def cancel_action(ctx: AppContext, action_id: str, device_id: str, comment: str, yes: bool,
                  dry_run: bool) -> None:
    """Cancel a pending device response action (portal-cookie).

    Only pending or in-progress isolation, package collection, scan,
    app-restriction and log-collection requests are eligible. Cancellation
    does not confirm any rollback on the device; check action-status afterwards.
    A device that already picked the action up may still complete it.
    """
    if dry_run:
        _emit(ctx, {"dry_run": True, "action": "cancel-action", "action_id": action_id,
                    "device_id": device_id})
        return

    async def work(client: Backend) -> dict:
        return await client.cancel_device_action(action_id, device_id=device_id, comment=comment)

    _mutate(ctx, f"cancel action {action_id}", f"device {device_id}", yes, work)


def _containment(name: str, summary: str) -> click.Command:
    @click.command(name, help=summary)
    @_machine_argument
    @click.option("--comment", "-c", required=True, help="Reason recorded with the action.")
    @_yes_option
    @_dry_run_option
    @click.pass_obj
    def command(ctx: AppContext, machine_id: str, comment: str, yes: bool,
                dry_run: bool) -> None:
        if dry_run:
            _emit(ctx, {"dry_run": True, "action": name, "machine_id": machine_id})
            return

        async def work(client: Backend) -> dict:
            return await client.submit_device_action(machine_id, name, comment=comment)

        _mutate(ctx, name, f"device {machine_id}", yes, work)

    return command


contain = _containment(
    "contain",
    "Contain an unmanaged device so Defender-onboarded devices stop talking to it "
    "(portal-cookie). Refused for onboarded or unknown-state devices; use isolate for those. "
    "Not yet verified against a live tenant; see docs/live_response_coverage.md.",
)
uncontain = _containment(
    "uncontain",
    "Release containment of an unmanaged device (portal-cookie). Requires exactly one "
    "matching containment action on record; anything ambiguous is refused. "
    "Not yet verified against a live tenant; see docs/live_response_coverage.md.",
)


@click.command("start-investigation")
@_machine_argument
@click.option("--comment", "-c", required=True,
              help="Reason. The official API records it; the portal protocol does not.")
@_yes_option
@_dry_run_option
@click.pass_obj
def start_investigation(ctx: AppContext, machine_id: str, comment: str, yes: bool,
                        dry_run: bool) -> None:
    """Start an automated investigation on a device.

    The portal-cookie backend selects the tenant's investigation protocol from
    fresh tenant features and sends exactly one request. The result reports
    request acceptance only; follow the investigation in Defender. Tenants
    where Microsoft has withdrawn manual investigations report
    TENANT_FEATURE_UNAVAILABLE; see docs/live_response_coverage.md.
    """
    if dry_run:
        _emit(ctx, {"dry_run": True, "action": "start-investigation", "machine_id": machine_id})
        return

    async def work(client: Backend) -> dict:
        return await client.start_device_investigation(machine_id, comment=comment)

    _mutate(ctx, "start an automated investigation", f"device {machine_id}", yes, work)


@click.command("action-history")
@_machine_argument
@click.option("--limit", type=click.IntRange(min=1, max=10000), default=100, show_default=True,
              help="Maximum number of actions to read.")
@click.pass_obj
def action_history(ctx: AppContext, machine_id: str, limit: int) -> None:
    """Save a device's response-action history as a private artifact (read-only).

    Portal-cookie reads the Action center history for the last seven days.
    The official backend reads machine actions, which exclude portal-initiated
    Live Response activity. The final row (record_type
    device-action-history-coverage) states the window, native count and
    whether the read was complete; the receipt context repeats it.
    """

    async def run() -> None:
        client = _get_client(ctx)
        try:
            rows = [row async for row in client.iter_device_action_history(
                machine_id, limit=limit)]
        finally:
            await client.close()
        coverage = next((row for row in reversed(rows)
                         if row.get("record_type") == "device-action-history-coverage"), None)
        complete = bool(coverage and coverage.get("complete") is True)
        artifact = write_result(
            rows, command=ctx.invoked_command or "device action-history",
            tenant_id=ctx.config.tenant_id, session_id=ctx.session_id,
            session_label=ctx.session_label, session_attachment=ctx.session_attachment,
            server_truncation_state="known-complete" if complete else "unknown",
            extra_metadata={"api_backend": ctx.config.api_backend, "machine_id": machine_id},
            receipt_context={"coverage": coverage},
        )
        emit_result(artifact)

    asyncio.run(run())


@click.command("collect-support-logs")
@_machine_argument
@click.option("--comment", "-c", required=True, help="Reason recorded with the request.")
@_yes_option
@_dry_run_option
@click.pass_obj
def collect_support_logs(ctx: AppContext, machine_id: str, comment: str, yes: bool,
                         dry_run: bool) -> None:
    """Request a Defender support-log collection from a device (portal-cookie).

    Follow the request with action-status. Downloading the collected logs is
    not available from the CLI yet; use Defender for that. No collection has
    completed against a live tenant; see docs/live_response_coverage.md.
    """
    if dry_run:
        _emit(ctx, {"dry_run": True, "action": "collect-support-logs", "machine_id": machine_id})
        return

    async def work(client: Backend) -> dict:
        return await client.collect_device_support_logs(machine_id, comment=comment)

    _mutate(ctx, "collect support logs", f"device {machine_id}", yes, work)


@click.command("troubleshoot")
@_machine_argument
@click.option("--on/--off", "enabled", required=True,
              help="Turn troubleshooting mode on (a fixed four-hour window) or off.")
@click.option("--comment", "-c", required=True, help="Reason recorded with the request.")
@_yes_option
@_dry_run_option
@click.pass_obj
def troubleshoot(ctx: AppContext, machine_id: str, enabled: bool, comment: str, yes: bool,
                 dry_run: bool) -> None:
    """Turn Defender troubleshooting mode on or off for a device (portal-cookie).

    On starts the portal's fixed four-hour window; off ends the one active
    window. Acceptance does not confirm the device changed state; check
    action-status.
    """
    action = "troubleshoot --on" if enabled else "troubleshoot --off"
    if dry_run:
        _emit(ctx, {"dry_run": True, "action": action, "machine_id": machine_id,
                    "duration_minutes": 240 if enabled else None})
        return

    async def work(client: Backend) -> dict:
        return await client.set_device_troubleshooting(
            machine_id, enabled=enabled, duration_minutes=None, comment=comment)

    _mutate(ctx, f"turn troubleshooting mode {'on' if enabled else 'off'}",
            f"device {machine_id}", yes, work)


def register(group: click.Group) -> None:
    group.add_command(tags_app)
    group.add_command(action_permissions)
    group.add_command(cancel_action)
    group.add_command(contain)
    group.add_command(uncontain)
    group.add_command(start_investigation)
    group.add_command(action_history)
    group.add_command(collect_support_logs)
    group.add_command(troubleshoot)
