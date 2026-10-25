"""``collect-event-logs``: fetch Windows event logs over Live Response in one command.

One read-only ``dir`` of the fixed event-log folder, then one ordinary
``getfile`` per selected log, downloaded privately and never opened. This is a
forensic collection, not Defender's support-log package. Every step is recorded
in a private manifest; a job left incomplete keeps its accepted command ID and
exact read-only recovery commands, and is never resubmitted.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from time import monotonic

import click
from filelock import Timeout as LockTimeout

from xdr_cli._lock import exclusive_lock
from xdr_cli.backend_contract import Backend
from xdr_cli.commands.live_response_cmd import (
    _POLL_SECONDS,
    _PORTAL_PREFIX,
    _accepted,
    _audit_submission,
    _emit,
    _poll,
    _require_sessions,
    _with_client,
)
from xdr_cli.context import AppContext
from xdr_cli.exceptions import (
    ArtifactError,
    ConfigError,
    ConflictError,
    ForbiddenError,
    LiveResponseSizeLimitError,
    NetworkError,
    NotAuthenticatedError,
    PartialSuccessError,
    RateLimitError,
    TimeoutError,
    UsageError,
    XDRError,
)
from xdr_cli.live_response import event_logs as evtx
from xdr_cli.live_response.catalog import merge_definitions
from xdr_cli.live_response.handles import session_activity
from xdr_cli.live_response.models import LRCommandState, LRPlatform, LRSession, ParsedCommand
from xdr_cli.live_response.parser import build_command, parse_console_line
from xdr_cli.live_response.session_aliases import is_alias
from xdr_cli.live_response.transfer import DEFAULT_MAX_BYTES, download_transfer
from xdr_cli.output import err_console
from xdr_cli.results import emit_result, tenant_fingerprint, write_result

_MACHINE = re.compile(r"[0-9a-fA-F]{40}")
_SESSION = re.compile(r"CLR[A-Za-z0-9_-]{1,125}")
# Failures that say nothing about one log (or break the manifest): stop the run.
_SYSTEMIC = (NotAuthenticatedError, ForbiddenError, RateLimitError, NetworkError, TimeoutError,
             ConfigError, ArtifactError)
_DEFAULT_TOTAL = 4 * 1024**3


def _target_kind(target: str) -> str:
    if _MACHINE.fullmatch(target):
        return "device"
    if _SESSION.fullmatch(target) or is_alias(target):
        return "session"
    raise UsageError("TARGET must be a session (lr-N or CLR…) or a 40-character MachineId.",
                     invalid={"kind": "identifier", "param": "target"})


def _quote_path(path: Path | str) -> str:
    """Quote one recovery-command argument for the host's usual shell."""
    value = str(path)
    if os.name == "nt":
        return "'" + value.replace("'", "''") + "'"
    return shlex.quote(value)


def _prepare_output_dir(path: Path) -> Path:
    """A new, or existing but empty, private directory."""
    directory = path.expanduser()
    try:
        if not directory.exists():
            directory.mkdir(mode=0o700)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ArtifactError("--output-dir must be a directory.")
        if os.name == "posix" and info.st_mode & 0o077:
            raise ArtifactError(
                "--output-dir must be private (mode 0700); event logs are sensitive.",
                suggestions=[{"reason": "recovery", "confidence": "exact",
                              "message": "chmod 700 the directory, or give a new path."}],
            )
        if any(p.name != evtx.MANIFEST + ".lock" for p in directory.iterdir()):
            raise ConflictError("--output-dir is not empty; give a new directory.")
    except OSError:
        raise ArtifactError("Could not prepare the event-log output directory.") from None
    return directory.resolve()


@dataclass(frozen=True)
class _Plan:
    stems: tuple[str, ...]
    include_all: bool
    min_bytes: int
    max_bytes: int
    max_total_bytes: int
    wait_seconds: int


@click.command("collect-event-logs")
@click.argument("target", type=str)
@click.option("--output-dir", type=click.Path(path_type=Path, file_okay=False), required=True,
              help="New or empty private directory for the logs and manifest.json.")
@click.option("--log", "logs", multiple=True, default=(),
              help="Event log to fetch (repeatable), e.g. Security or "
                   "Microsoft-Windows-PowerShell/Operational. Default: a curated triage set.")
@click.option("--all", "include_all", is_flag=True, help="Fetch every .evtx in the folder.")
@click.option("--min-bytes", type=click.IntRange(min=0), default=0, show_default=True,
              help="Skip logs listed smaller than this. A size filter only: a small log "
                   "can still hold events.")
@click.option("--max-bytes", type=click.IntRange(min=1), default=DEFAULT_MAX_BYTES,
              show_default=True, help="Skip, or stop downloading, any single larger log.")
@click.option("--max-total-bytes", type=click.IntRange(min=1), default=_DEFAULT_TOTAL,
              show_default=True,
              help="Maximum total saved file bytes; bounds each transfer by the remaining "
                   "budget. Failed transfers stop collection.")
@click.option("--wait", "wait_seconds", type=click.IntRange(min=1, max=3600), default=300,
              show_default=True, help="Seconds to wait for each job.")
@click.option("--comment", "-c", default=None,
              help="Reason recorded locally when this command opens the session.")
@click.option("--dry-run", is_flag=True, help="Show the plan; no network, nothing written.")
@click.pass_obj
def collect_event_logs(ctx: AppContext, target: str, output_dir: Path, logs: tuple[str, ...],
                       include_all: bool, min_bytes: int, max_bytes: int,
                       max_total_bytes: int, wait_seconds: int, comment: str | None,
                       dry_run: bool) -> None:
    """Fetch Windows event logs (.evtx) from a device over Live Response (collect).

    TARGET is a session (lr-N or CLR…) or a MachineId; for a MachineId this
    command opens a session and closes it afterwards. It lists the event-log
    folder once, then fetches each selected log with getfile. Files are saved
    privately with SHA-256s and are never opened. This is not Defender's
    support-log collection.
    """
    kind = _target_kind(target)
    if include_all and logs:
        raise UsageError("Use either --log or --all, not both.",
                         invalid={"kind": "conflicting_options"})
    stems = tuple(dict.fromkeys(evtx.canonical_stem(name) for name in logs)) or evtx.DEFAULT_LOGS
    plan = _Plan(stems=stems, include_all=include_all, min_bytes=min_bytes,
                 max_bytes=max_bytes, max_total_bytes=max_total_bytes,
                 wait_seconds=wait_seconds)
    if dry_run:
        _emit(ctx, {
            "dry_run": True, "action": "collect-event-logs", "target_kind": kind,
            "logs_dir": evtx.LOGS_DIR,
            "selection": "all" if include_all else ("explicit" if logs else "default"),
            "logs": None if include_all else list(stems), "min_bytes": min_bytes,
            "max_bytes": max_bytes, "max_total_bytes": max_total_bytes,
            "opens_session": kind == "device",
        })
        return
    _require_sessions(ctx)
    ctx.config.check_mutation_backend()
    directory = _prepare_output_dir(output_dir)

    async def work(client: Backend) -> None:
        await _Collector(ctx, client, directory, plan).run(target, kind, comment)

    try:
        # Reserve the output before creating a client or opening any session.
        # The persistent, content-free lock sidecar is not collection evidence.
        with exclusive_lock(directory / evtx.MANIFEST, timeout=0):
            if any(p.name != evtx.MANIFEST + ".lock" for p in directory.iterdir()):
                raise ConflictError("The output directory was claimed by another collection.")
            _with_client(ctx, work)
    except LockTimeout:
        raise ConflictError(
            "Another event-log collection is using this output directory."
        ) from None


class _Collector:
    def __init__(self, ctx: AppContext, client: Backend, directory: Path, plan: _Plan) -> None:
        self.ctx, self.client, self.directory, self.plan = ctx, client, directory, plan
        self.failures: list[XDRError] = []
        self.stopped: str | None = None
        self.owned: LRSession | None = None
        self.manifest: evtx.Manifest | None = None
        self.remaining = plan.max_total_bytes

    async def run(self, target: str, kind: str, comment: str | None) -> None:
        primary: BaseException | None = None
        closed: bool | None = None
        try:
            if kind == "device":
                session = await self._open(target, comment)
            else:
                session = await self.client.lr_get_session(target)
            await self._collect(session)
        except BaseException as error:
            primary = error
            raise
        finally:
            if self.owned is not None:
                try:
                    closed = await self._close(self.owned)
                except BaseException:
                    if primary is None:
                        raise
                    # Cleanup must not hide the original error or cancellation.
                    closed = False
                    err_console.print(
                        "Session cleanup could not be confirmed; inspect it with: "
                        f"{_PORTAL_PREFIX} show {self._ref(self.owned)}"
                    )
                if not closed and isinstance(primary, XDRError):
                    primary.suggestions = [*primary.suggestions,
                                           self._disconnect_hint(self.owned)]
        self._report(session, closed)

    async def _open(self, machine_id: str, comment: str | None) -> LRSession:
        session = await self.client.lr_open_session(machine_id, comment=comment)
        # Owned from acceptance on, so any later failure still closes it.
        self.owned = session
        with _accepted("session", session.session_id,
                       [f"{_PORTAL_PREFIX} show {self._ref(session)}"]):
            deadline = monotonic() + 120
            while session.state == "pending" and monotonic() < deadline:
                await asyncio.sleep(_POLL_SECONDS)
                session = await self.client.lr_get_session(session.session_id)
                self.owned = session
        return session

    @staticmethod
    def _ref(session: LRSession) -> str:
        return session.alias or session.session_id

    def _disconnect_hint(self, session: LRSession) -> dict:
        return {"reason": "owned_session_not_closed", "confidence": "exact",
                "message": "Closure of the session this command opened is unconfirmed; "
                           "inspect its state before another close request.",
                "commands": [f"{_PORTAL_PREFIX} show {self._ref(session)}"]}

    async def _close(self, session: LRSession) -> bool:
        recovery = f"{_PORTAL_PREFIX} show {self._ref(session)}"
        try:
            current = await self.client.lr_close_session(session.session_id)
            if session_activity(current) == "inactive":
                return True
            failure = ConflictError(
                "A session close was requested, but closure is not yet confirmed.",
                help_command=recovery,
            )
            failure.error_code = "LIVE_RESPONSE_SESSION_CLOSE_UNCONFIRMED"
            self.failures.append(failure)
        except XDRError as error:
            self.failures.append(error)
        err_console.print(
            "Session closure is unconfirmed; do not repeat the close request. "
            f"Inspect it with: {recovery}"
        )
        return False

    async def _collect(self, session: LRSession) -> None:
        if session.state != "running":
            raise ConflictError(f"The Live Response session is {session.state}, not running.")
        if session.platform is not LRPlatform.WINDOWS:
            raise UsageError("Event-log collection needs a Windows device session.",
                             invalid={"kind": "platform"})
        self.session = session
        self.commands, _ = merge_definitions(
            await self.client.lr_command_definitions(session.session_id))
        listed = evtx.parse_listing(await self._listing())
        rows = evtx.select(listed, logs=self.plan.stems, include_all=self.plan.include_all,
                           min_bytes=self.plan.min_bytes, max_bytes=self.plan.max_bytes)
        total = sum(row.listed_bytes or 0 for row in rows if row.status == evtx.PLANNED)
        if total > self.plan.max_total_bytes:
            raise UsageError(
                f"The selected logs are listed at {total} bytes, over --max-total-bytes; "
                "narrow the selection with --log or --min-bytes, or raise the limit.",
                invalid={"kind": "too_large"})
        self.manifest = evtx.Manifest(
            self.directory / evtx.MANIFEST, tenant_fingerprint(self.ctx.config.tenant_id) or "",
            "portal-cookie", session.session_id, session.alias, session.machine_id,
            self.owned is not None, rows)
        self.manifest.save()
        for row in rows:
            if self.stopped is not None:
                break
            if row.status == evtx.PLANNED:
                try:
                    await self._fetch(row)
                except ArtifactError as error:
                    # A receipt in the separate results store can still preserve
                    # completed evidence and accepted IDs when this manifest fails.
                    self._fail(row, error, stop=True)
                    self.stopped = "manifest-unwritable"
                except Exception:
                    failure = XDRError(
                        "Collection stopped after an unexpected failure; progress is retained "
                        f"at {self.manifest.path}. Do not resubmit accepted commands.",
                    )
                    failure.error_code = "COLLECTION_INTERNAL_FAILURE"
                    self._fail(row, failure, stop=True)

    def _audit(self, parsed: ParsedCommand) -> None:
        _audit_submission(self.ctx, self.session.session_id, parsed)
        logging.getLogger("xdr.audit").info(
            "LR_IDENTITY: session_id=%s machine_id=%s alias=%s",
            self.session.session_id, self.session.machine_id, self.session.alias or "-",
        )

    async def _listing(self) -> list[dict]:
        # The console form verified live; the listing must be JSON to parse it.
        parsed = parse_console_line(f"dir {evtx.LOGS_DIR} -output json",
                                    platform=self.session.platform, commands=self.commands)
        self._audit(parsed)
        state = await self.client.lr_submit(self.session.session_id, parsed)
        with _accepted("command", state.command_id, self._recovery(state.command_id)):
            state = await _poll(self.client, self.session.session_id, state,
                                self.plan.wait_seconds)
            if not state.succeeded:
                raise ConflictError("Listing the event-log folder did not complete without "
                                    f"errors (state {state.state}); nothing was fetched.")
            return [row async for row in
                    self.client.lr_iter_output(self.session.session_id, state.command_id)]

    def _recovery(self, command_id: str, local_file: str | None = None,
                  *, max_bytes: int | None = None) -> list[str]:
        reference = self._ref(self.session)
        commands = [f"{_PORTAL_PREFIX} status {reference} {command_id} --wait 60"]
        if local_file is not None:
            cap = max_bytes if max_bytes is not None else self.plan.max_bytes
            commands.append(f"{_PORTAL_PREFIX} download {reference} {command_id} "
                            f"--output {_quote_path(self.directory / local_file)} "
                            f"--max-bytes {cap}")
        return commands

    def _save(self) -> None:
        assert self.manifest is not None
        self.manifest.save()

    def _fail(self, row: evtx.LogRow, error: XDRError, *, stop: bool = False) -> None:
        row.error = error.error_code
        self.failures.append(error)
        if stop or isinstance(error, _SYSTEMIC):
            self.stopped = error.error_code

    async def _fetch(self, row: evtx.LogRow) -> None:
        if self.remaining <= 0 or (
            row.listed_bytes is not None and row.listed_bytes > self.remaining
        ):
            row.error = "total-budget-exhausted"
            self.stopped = row.error
            self._save()
            return
        parsed = build_command("getfile", params={"path": row.remote_path}, flags=frozenset(),
                               platform=self.session.platform, background=False,
                               commands=self.commands)
        # Recorded before sending: a crash from here on leaves the outcome unknown.
        row.status = evtx.OUTCOME_UNKNOWN
        self._save()
        self._audit(parsed)
        try:
            state = await self.client.lr_submit(self.session.session_id, parsed)
        except XDRError as error:
            if error.error_code != "OUTCOME_UNKNOWN":
                row.status = evtx.FAILED
            self._fail(row, error)
            self._save()
            return
        row.status, row.command_id = evtx.ACCEPTED, state.command_id
        cap = self._cap()
        row.recovery = self._recovery(state.command_id, row.local_file, max_bytes=cap)
        try:
            with _accepted("command", state.command_id, row.recovery):
                self._save()
                await self._follow(row, state, cap)
        except XDRError as error:
            # Already decorated by _accepted: non-retryable, with the command ID and recovery.
            budget_bound = (isinstance(error, LiveResponseSizeLimitError)
                            and cap < self.plan.max_bytes)
            self._fail(row, error, stop=budget_bound)
            if budget_bound:
                row.error = self.stopped = "total-budget-exhausted"
            try:
                self._save()
            except ArtifactError:
                self.stopped = "manifest-unwritable"

    def _cap(self) -> int:
        return min(self.plan.max_bytes, self.remaining)

    async def _follow(self, row: evtx.LogRow, state: LRCommandState, cap: int) -> None:
        state = await _poll(self.client, self.session.session_id, state, self.plan.wait_seconds)
        row.state, row.error_count = state.state, state.error_count
        if state.terminal is not True:
            row.error = "not_terminal" if state.terminal is False else "state_unknown"
            self.failures.append(ConflictError("A getfile job did not reach a terminal state."))
            self._save()
            return
        if not state.succeeded:
            row.status = evtx.FAILED
            row.error = "completed_with_errors" if state.state == "completed" else "failed"
            self.failures.append(ConflictError("A getfile job did not complete cleanly."))
            self._save()
            return
        try:
            transfer = await self.client.lr_result_transfer(self.session.session_id,
                                                            state.command_id)
            receipt = await download_transfer(
                transfer, self.directory / row.local_file, force=False, max_bytes=cap,
                timeout=self.ctx.config.api_timeout)
        except XDRError as error:
            # Failed streams have no durable byte receipt. Stop rather than
            # repeatedly spending an unknown portion of the remaining budget.
            self.stopped = error.error_code
            raise
        self.remaining -= receipt["bytes"]
        row.status, row.bytes, row.sha256 = evtx.COMPLETED, receipt["bytes"], receipt["sha256"]
        row.error, row.recovery = None, None
        self._save()

    def _report(self, session: LRSession, closed: bool | None) -> None:
        rows = self.manifest.rows if self.manifest else []
        counts: dict[str, int] = {}
        for row in rows:
            counts[row.status] = counts.get(row.status, 0) + 1
        context = {
            "output_dir": str(self.directory),
            "manifest": str(self.directory / evtx.MANIFEST),
            "session_id": session.session_id, "session_alias": session.alias,
            "session_opened_here": self.owned is not None, "session_closed": closed,
            "cleanup_recovery_command": (
                f"{_PORTAL_PREFIX} show {self._ref(session)}"
                if self.owned is not None and closed is not True else None
            ),
            "counts": counts, "stopped": self.stopped,
            "downloaded_bytes": sum(row.bytes or 0 for row in rows),
        }
        artifact = write_result(
            [asdict(row) for row in rows],
            command=self.ctx.invoked_command or "device live-response collect-event-logs",
            tenant_id=self.ctx.config.tenant_id, session_id=self.ctx.session_id,
            session_label=self.ctx.session_label,
            session_attachment=self.ctx.session_attachment,
            server_truncation_state="known-complete",
            extra_metadata={"api_backend": self.ctx.config.api_backend, **context},
            receipt_context=context,
        )
        emit_result(artifact)
        incomplete = [row for row in rows if row.status not in evtx.DELIBERATE]
        if incomplete or self.failures:
            issues = []
            if incomplete:
                issues.append(f"{len(incomplete)} event log(s) were not collected")
            if self.owned is not None and closed is not True:
                issues.append("owned session closure is unconfirmed")
            if self.stopped == "manifest-unwritable":
                issues.append("the progress manifest could not be saved")
            partial = PartialSuccessError(
                "; ".join(issues or ["Collection encountered an error"]) + ". Completed "
                "files are saved. Rows with a command_id are accepted jobs: follow their recovery "
                "commands instead of resubmitting.",
            )
            partial.retry_after_seconds = next(
                (e.retry_after_seconds for e in self.failures
                 if e.retry_after_seconds is not None), None)
            raise partial from (self.failures[0] if self.failures else None)
