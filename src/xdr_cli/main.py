"""XDR CLI entry point with global options."""

from __future__ import annotations

import contextlib
import contextvars
import functools
import inspect
import logging
import os
import sys
import time

import click
import typer

from xdr_cli import __version__
from xdr_cli.commands.alerts_cmd import alerts_app
from xdr_cli.commands.annotate_cmd import annotate
from xdr_cli.commands.auth_cmd import auth_app
from xdr_cli.commands.device_cmd import device_app
from xdr_cli.commands.domains_cmd import domains_app
from xdr_cli.commands.history_cmd import history_app
from xdr_cli.commands.hunt_cmd import hunt_app
from xdr_cli.commands.incidents_cmd import incidents_app
from xdr_cli.commands.investigate_cmd import investigate
from xdr_cli.commands.library_cmd import library_app
from xdr_cli.commands.lists_cmd import lists_app
from xdr_cli.commands.results_cmd import results_app
from xdr_cli.commands.schema_cmd import schema_app
from xdr_cli.commands.session_cmd import session_app
from xdr_cli.config import ensure_config_dir, get_config_home, load_config
from xdr_cli.context import AppContext
from xdr_cli.error_boundary import StructuredTyperGroup
from xdr_cli.exceptions import ConflictError, XDRError, format_error_json
from xdr_cli.sessions import (
    Recorder,
    actor_needs_annotation,
    current_session,
    resolve_session_for_invocation,
)

app = typer.Typer(
    name="xdr",
    cls=StructuredTyperGroup,
    help="Microsoft 365 Defender XDR investigation CLI.",
    no_args_is_help=True,
)

# Register sub-apps
app.add_typer(alerts_app)
app.add_typer(auth_app)
app.add_typer(device_app)
app.add_typer(domains_app)
app.add_typer(history_app)
app.add_typer(hunt_app)
app.add_typer(incidents_app)
app.add_typer(lists_app)
app.add_typer(library_app)
app.add_typer(results_app)
app.add_typer(schema_app)
app.add_typer(session_app)
app.command("investigate")(investigate)
app.command("annotate")(annotate)


# Commands that modify state — logged to audit log
_WRITE_COMMANDS = {
    "isolate", "unisolate", "scan", "collect-package",
    "restrict", "update", "login", "logout", "investigate",
    "lists init",
    "portal-login", "portal-cookie", "portal-logout",
    "schema repair-overlay", "schema migrate-cache", "schema bundle import",
}


def _matches_write_command(cmd: str, argv: list[str]) -> bool:
    """Check whether ``cmd`` (possibly multi-token) appears as a contiguous
    subsequence of ``argv``.

    Multi-token entries like ``"lists init"`` need a contiguous-subsequence
    match — plain ``cmd in argv`` only matches single argv tokens, so a
    space-containing string would never match.
    """
    parts = cmd.split()
    if len(parts) == 1:
        return cmd in argv
    return any(
        argv[i:i + len(parts)] == parts
        for i in range(len(argv) - len(parts) + 1)
    )


# Flags whose value is a secret and must never reach the session Recorder
# (which snapshots argv verbatim into ~/.xdr-cli/sessions/<id>.jsonl). Today
# just the `device timeline --refresh-token` FOCI token; add future
# secret-bearing flags here. `MDE_REFRESH_TOKEN` (the env-var form) never
# enters argv, so it needs no handling.
_SECRET_ARGV_FLAGS: frozenset[str] = frozenset({"--refresh-token"})

_REDACTED_PLACEHOLDER = "***REDACTED***"


def _redact_argv(argv: list[str]) -> list[str]:
    """Return a copy of ``argv`` with known secret flag values replaced.

    Handles both the space-separated form (``--refresh-token SECRET``) and
    the inline ``--refresh-token=SECRET`` form. Everything else — including
    unrecognized flags and positional args — passes through unchanged.
    """
    redacted: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            redacted.append(_REDACTED_PLACEHOLDER)
            redact_next = False
            continue
        name, sep, _value = arg.partition("=")
        if sep and name in _SECRET_ARGV_FLAGS:
            redacted.append(f"{name}={_REDACTED_PLACEHOLDER}")
            continue
        redacted.append(arg)
        if arg in _SECRET_ARGV_FLAGS:
            redact_next = True
    return redacted


# Commands EXEMPT from the learning-mode gate. Annotate clears the gate;
# session/history are control-plane and shouldn't be blocked by it. Matched
# against the TOP-LEVEL group only (first space-separated token of the chain).
_LEARNING_GATE_BYPASS: frozenset[str] = frozenset({
    "annotate", "session", "history",
})


def _is_help_invocation(argv: list[str]) -> bool:
    """Help invocations bypass both gates — help is metadata, not a hunt."""
    return any(t in ("--help", "-h") for t in argv)


def _check_learning_mode_gate(invoked: str | None, argv: list[str]) -> None:
    """Block non-bypass commands when the actor has unannotated invocations
    in a learning-mode session.

    Per-actor isolation: actor A's unannotated invocation does not block
    actor B. The bypass set is matched against the TOP-LEVEL group only.
    """
    if _is_help_invocation(argv):
        return
    if invoked is None:
        return
    session = current_session()
    if session is None or not session.learning_mode:
        return

    top = invoked.split(" ", 1)[0]
    if top in _LEARNING_GATE_BYPASS:
        return

    actor = os.environ.get("XDR_ACTOR", "operator")
    pending = actor_needs_annotation(session, actor)
    if pending is None:
        return

    raise ConflictError(
        f"Learning mode requires annotation of invocation {pending} for actor {actor!r}.",
        suggestions=[
            {
                "reason": "learning_annotation",
                "message": "xdr annotate <text>",
                "confidence": "exact",
            },
            {
                "reason": "learning_skip",
                "message": "xdr annotate --skip <reason>",
                "confidence": "exact",
            },
        ],
        help_command="xdr annotate --help",
    )


def _emit_schema_maintenance_advisory(app_ctx: AppContext, chain: str | None) -> None:
    """Surface due maintenance on stderr without blocking the requested command."""

    if (
        chain is None
        or chain
        in {
            "schema status",
            "schema diagnostics",
            "schema collect",
            "schema repair-overlay",
            "schema migrate-cache",
            "schema bundle inspect",
            "schema bundle export",
            "schema bundle import",
        }
        or app_ctx.effective_quiet
        or os.environ.get("XDR_SCHEMA_MAINTENANCE_CHILD") == "1"
    ):
        return
    try:
        from xdr_cli.schema_graph.maintenance import maintenance_advisory_status

        status = maintenance_advisory_status(
            app_ctx.config.tenant_id,
            cache_stale_seconds=app_ctx.config.schema_stale_seconds,
            collection_stale_seconds=app_ctx.config.schema_collection_stale_seconds,
        )
    except Exception:
        return
    if status.get("due"):
        reasons = ", ".join(status.get("reasons", ()))
        print(
            "Schema maintenance due "
            f"({reasons}). Run: {status['next_command']} "
            "or inspect: xdr schema status",
            file=sys.stderr,
        )



def _setup_audit_log() -> logging.Logger:
    """Set up audit logging to ``$XDR_CLI_HOME/audit.log``.

    Path-aware: if a handler is attached but points at a stale path (e.g.,
    a different ``XDR_CLI_HOME`` from a previous test invocation), rebind
    to the current target path. Production has a single stable path; this
    rebind is the test-isolation seam.
    """
    logger = logging.getLogger("xdr.audit")
    log_path = get_config_home() / "audit.log"
    target = str(log_path)
    # Reuse only if the existing handler points to the same file.
    keep = [
        h for h in logger.handlers
        if isinstance(h, logging.FileHandler) and h.baseFilename == target
    ]
    if keep and len(keep) == len(logger.handlers):
        return logger
    # Otherwise rebuild: close stale handlers, install one targeting log_path.
    for h in list(logger.handlers):
        logger.removeHandler(h)
        with contextlib.suppress(Exception):
            h.close()
    log_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    handler = logging.FileHandler(log_path)
    # The audit log holds the user's command history — keep it private (0600),
    # matching the cookie/token stores, not the FileHandler default (~0644).
    os.chmod(log_path, 0o600)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def _setup_debug_logging() -> None:
    """Configure httpx and msal loggers to DEBUG level on stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    )
    for name in ("httpx", "msal", "xdr_cli"):
        log = logging.getLogger(name)
        log.setLevel(logging.DEBUG)
        log.addHandler(handler)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"xdr-cli {__version__}")
        raise typer.Exit()


# "Active" AppContext pointer used by run()'s finally block. The Typer
# callback stores ctx.obj here so the recorder can be flushed even when the
# click context has already exited (KeyboardInterrupt mid-command, uncaught
# BaseException, etc.).
#
# A ContextVar — not a module-level scalar — so concurrent invocations from
# threads or asyncio tasks each see their own value, and so the test harness
# gets clean isolation across `runner.invoke` calls without a manual reset of
# a shared global. ``run()`` explicitly resets to None at the top of every
# invocation for serial-test cleanliness.
_active_app_ctx: contextvars.ContextVar[AppContext | None] = contextvars.ContextVar(
    "_xdr_active_app_ctx", default=None
)


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
    no_interactive: bool = typer.Option(
        False, "--no-interactive",
        help="Disable all interactive prompts.",
    ),
    debug: bool = typer.Option(
        False, "--debug",
        help="Enable debug output to stderr.",
    ),
    quiet: bool | None = typer.Option(
        None, "--quiet/--no-quiet", "-q",
        help=(
            "Suppress progress output. Auto-enabled when stdout is piped. "
            "Use --no-quiet to force progress on."
        ),
    ),
    rationale: str = typer.Option(
        "", "--rationale",
        help=(
            "Pre-run intent. Captured on any invocation record when a "
            "session is active."
        ),
    ),
) -> None:
    """Microsoft 365 Defender XDR investigation CLI."""
    config = load_config()
    app_ctx = AppContext(
        config=config,
        no_interactive=no_interactive,
        debug=debug,
        quiet=quiet,
        rationale=rationale,
    )
    # Construct the Recorder in the callback so every command path has access
    # to it via ctx.obj.recorder. invoked_command is filled in later by the
    # leaf-callback hook once Typer has resolved the subcommand chain.
    #
    # The hunt-requires-session and learning-mode gates fire from inside the
    # leaf-callback hook (where the resolved subcommand chain is known).
    # ``--help`` short-circuits Typer before the leaf runs, so help paths
    # naturally bypass both gates without a special case.
    app_ctx.recorder = Recorder(
        session=current_session(),
        # Redacted at capture time so the Recorder never holds (and thus
        # never persists to the session JSONL) a raw secret flag value.
        argv=_redact_argv(list(sys.argv[1:])),
        invoked_command=None,
    )
    ctx.obj = app_ctx
    _active_app_ctx.set(app_ctx)


def _capture_chain_from_leaf() -> None:
    """Hook fired from inside every leaf subcommand to capture the resolved
    subcommand chain on AppContext / Recorder.

    Why a leaf hook instead of a Typer ``result_callback``: Click's
    ``result_callback`` runs at the root level after invocation completes,
    where the subcommand chain has already unwound. From inside the leaf
    callback we walk the click context's parent chain bottom-up, collect each
    context's ``info_name``, drop the root (which is the program name —
    ``"xdr"`` in production, ``"python -m pytest.xdr"`` under pytest, ``"xdr-foo"``
    for installs renamed by the packager — none of which belong in the chain),
    then join. Walking parents is robust against arbitrary prog_name values
    in a way that ``command_path``-string-stripping is not.

    Implementation detail: we install this hook by wrapping every leaf
    command's callback once at import time (see ``_install_leaf_hook``).
    """
    try:
        click_ctx = click.get_current_context(silent=True)
    except RuntimeError:
        click_ctx = None
    if click_ctx is None:
        return
    app_ctx = click_ctx.find_object(AppContext)
    if app_ctx is None:
        return
    # Walk parents bottom-up, collect info_names, then drop the root (prog name).
    names: list[str] = []
    node: click.Context | None = click_ctx
    while node is not None:
        if node.info_name:
            names.append(node.info_name)
        node = node.parent
    # names is leaf->root; reverse to root->leaf, drop root.
    names.reverse()
    if names:
        names = names[1:]
    chain = " ".join(names) or None
    app_ctx.invoked_command = chain
    if app_ctx.recorder is not None:
        app_ctx.recorder.invoked_command = chain
        # Annotate --rationale unconditionally on every recorded invocation.
        # Recorder.flush is a no-op when session is None, so annotations on
        # no-session paths never reach disk. Whitespace-only rationale is
        # coerced to None so accidental spaces don't poison training data.
        rationale_text = (app_ctx.rationale or "").strip() or None
        if rationale_text:
            app_ctx.recorder.annotate("rationale", rationale_text)

    argv = app_ctx.recorder.argv if app_ctx.recorder else []
    anchor_incident: int | None = None
    anchor_alert: str | None = None
    try:
        if chain == "investigate":
            pos = argv.index("investigate")
            anchor_incident = int(argv[pos + 1])
        elif chain == "incidents show":
            pos = argv.index("show", argv.index("incidents") + 1)
            anchor_incident = int(argv[pos + 1])
        elif chain == "alerts show":
            pos = argv.index("show", argv.index("alerts") + 1)
            anchor_alert = argv[pos + 1]
    except (ValueError, IndexError):
        pass

    # Alert -> incident identity is learned only from Graph. Defer automatic
    # attachment until alerts_cmd has the authoritative incidentId. Explicit
    # XDR_SESSION remains authoritative and is resolved immediately.
    defer_alert_identity = chain == "alerts show" and not os.environ.get(
        "XDR_SESSION", ""
    ).strip()
    if defer_alert_identity:
        session, attachment = None, "deferred-alert-identity"
    else:
        session, attachment = resolve_session_for_invocation(
            chain,
            timeout_seconds=app_ctx.config.session_timeout_seconds,
            anchor_incident=anchor_incident,
            anchor_alert=anchor_alert,
        )
    app_ctx.session_attachment = attachment
    app_ctx.anchor_provenance = {}
    if anchor_incident is not None:
        app_ctx.anchor_incident = str(anchor_incident)
        app_ctx.anchor_provenance["incident_id"] = "argv"
    elif session is not None and session.anchor_incident is not None:
        app_ctx.anchor_incident = str(session.anchor_incident)
        app_ctx.anchor_provenance["incident_id"] = "session-inherited"
    else:
        app_ctx.anchor_incident = None
    if anchor_alert is not None:
        app_ctx.anchor_alert = anchor_alert
        app_ctx.anchor_provenance["alert_id"] = "argv"
    elif session is not None and session.anchor_alert is not None:
        app_ctx.anchor_alert = session.anchor_alert
        app_ctx.anchor_provenance["alert_id"] = "session-inherited"
    else:
        app_ctx.anchor_alert = None
    if app_ctx.recorder is not None:
        app_ctx.recorder.session = session
        app_ctx.recorder.annotate("session_attachment", attachment)
        app_ctx.recorder.annotate(
            "anchor_provenance",
            dict(app_ctx.anchor_provenance),
        )
        if anchor_incident is not None:
            app_ctx.recorder.annotate("anchor_incident", anchor_incident)
    if attachment == "ambiguous-unattached":
        print(
            "Multiple live sessions; command is running unattached. "
            "POSIX: XDR_SESSION=<id> xdr ... | "
            "PowerShell: $env:XDR_SESSION = \"<id>\"",
            file=sys.stderr,
        )
    _emit_schema_maintenance_advisory(app_ctx, chain)
    _check_learning_mode_gate(chain, argv)


def _install_leaf_hook(typer_app: typer.Typer, *, _seen: set[int] | None = None) -> None:
    """Wrap every leaf callback registered on ``typer_app`` (and its sub-apps)
    so the full subcommand chain is captured into AppContext.invoked_command.

    We mutate Typer's ``CommandInfo`` registry rather than the realized Click
    command tree because ``typer.Typer.__call__`` re-builds the Click tree on
    every invocation (via ``get_command``), so any wrapping applied to the
    Click tree is discarded. The Typer registry is the source of truth.

    Idempotent: callbacks tagged with ``_xdr_chain_wrapped`` are skipped, and
    sub-apps already visited in this walk are skipped via ``_seen`` to prevent
    infinite recursion if a sub-app is registered into multiple parents.

    IMPLEMENTATION NOTE: This walks Typer's internal registry attributes
    (``registered_commands``, ``registered_groups``, ``CommandInfo.callback``).
    These are NOT documented as public API. Verified working against
    Typer 0.24.x (see the ``>=0.24.0,<0.25.0`` range in pyproject.toml). On a
    Typer minor-version bump, re-verify that the registry shape hasn't changed
    by running the chain-capture smoke test (``test_chain_capture_smoke`` in
    test_main.py).
    """
    if _seen is None:
        _seen = set()
    if id(typer_app) in _seen:
        return
    _seen.add(id(typer_app))

    def make_wrapper(orig):
        @functools.wraps(orig)
        def wrapper(*args, **kwargs):
            _capture_chain_from_leaf()
            return orig(*args, **kwargs)

        # functools.wraps preserves __name__/__doc__/__wrapped__/__annotations__;
        # __signature__ is NOT copied by wraps and is what Typer's parameter
        # parsing reads, so set it explicitly.
        wrapper.__signature__ = inspect.signature(orig)  # type: ignore[attr-defined]
        wrapper._xdr_chain_wrapped = True  # type: ignore[attr-defined]
        return wrapper

    for cmd_info in typer_app.registered_commands:
        original = cmd_info.callback
        if original is None or getattr(original, "_xdr_chain_wrapped", False):
            continue
        cmd_info.callback = make_wrapper(original)

    # Sub-apps with ``invoke_without_command=True`` use their *callback* as the
    # leaf when no subcommand is given (e.g., ``xdr history`` defaulting to
    # browse). The Typer registry stores that callback on
    # ``registered_callback.callback``; wrap it so the chain hook fires for
    # bare-group invocations too. Skip when the field is a Typer
    # DefaultPlaceholder (no callback registered) or when already wrapped.
    if typer_app.info.invoke_without_command is True and typer_app.registered_callback is not None:
        cb_info = typer_app.registered_callback
        cb_original = cb_info.callback
        if (
            callable(cb_original)
            and not getattr(cb_original, "_xdr_chain_wrapped", False)
        ):
            cb_info.callback = make_wrapper(cb_original)

    for group_info in typer_app.registered_groups:
        if group_info.typer_instance is not None:
            _install_leaf_hook(group_info.typer_instance, _seen=_seen)


def _ensure_chain_hook_installed() -> None:
    """Install the leaf-callback hook on the live Typer app.

    Idempotent at the callback level — :func:`_install_leaf_hook` skips
    callbacks already tagged with ``_xdr_chain_wrapped``. We deliberately do
    NOT short-circuit at the module level so that test harnesses which patch
    ``xdr_cli.main.app`` (or rebuild the app) re-install the hook on each
    ``run()`` invocation.
    """
    if not isinstance(app, typer.Typer):
        # Test harness may patch app to a Mock; nothing to wrap.
        return
    _install_leaf_hook(app)


def run() -> None:
    """Entry point for the CLI.

    Wraps the Typer dispatcher in a ``try/finally`` so the recorder always
    flushes on every exit path. Without this, the most interesting failures
    (Ctrl-C mid-hunt, unexpected crash in an async path) would leave no
    training record.

    Exit-code semantics:

    - ``0`` on normal completion.
    - ``XDRError.exit_code`` on XDR-shaped errors (envelope already emitted
      to stdout; we convert to ``sys.exit`` so the JSON is preserved).
    - ``typer.Exit``'s ``exit_code`` on typer-driven exits (re-raised).
    - ``130`` on ``KeyboardInterrupt`` — matches POSIX convention; converted
      via ``sys.exit`` rather than re-raising so wrapper scripts and
      pytest's ``SystemExit``-catching pattern see uniform exit semantics.
      (Re-raising ``KeyboardInterrupt`` would bubble through callers'
      ``pytest.raises(SystemExit)`` differently and break the ``xdr`` shell
      wrappers that expect a real process exit.)
    - ``SystemExit``'s exit code on raw ``sys.exit`` calls (re-raised).
    - ``1`` on uncaught ``BaseException``, then re-raised so the original
      traceback is preserved for the user.

    The recorder is flushed on every exit path via ``try/finally`` before
    any of the above conversions or re-raises occur.
    """
    _active_app_ctx.set(None)  # reset between invocations (test-harness safety)

    # Set up debug logging early if --debug is present
    if "--debug" in sys.argv:
        _setup_debug_logging()

    # Ensure config dir exists before audit log setup
    ensure_config_dir()

    # Audit log write/action commands
    audit = _setup_audit_log()
    argv_str = " ".join(sys.argv[1:])
    if any(_matches_write_command(cmd, sys.argv) for cmd in _WRITE_COMMANDS):
        audit.info("CMD: %s", argv_str)

    # Install the leaf-callback hook that captures the resolved subcommand
    # chain on AppContext.invoked_command. Idempotent across run() calls.
    _ensure_chain_hook_installed()

    start = time.monotonic()
    exit_code = 0
    suppressed_xdr_error = False
    try:
        try:
            app()
            # Normal completion. exit_code stays 0.
        except XDRError as e:
            # JSON envelope to stdout on both success and error — stderr is
            # for progress/warnings only. Mirrors the success-path contract.
            sys.stdout.write(format_error_json(e) + "\n")
            exit_code = e.exit_code
            suppressed_xdr_error = True
        except typer.Exit as e:
            exit_code = e.exit_code or 0
            raise
        except KeyboardInterrupt:
            exit_code = 130  # POSIX convention for SIGINT
        except SystemExit as e:
            exit_code = e.code if isinstance(e.code, int) else 1
            raise
        except BaseException:
            exit_code = 1
            raise
    finally:
        # Flush is fail-soft — never raises. Safe in finally.
        active_ctx = _active_app_ctx.get()
        if active_ctx is not None and active_ctx.recorder is not None:
            duration_ms = int((time.monotonic() - start) * 1000)
            active_ctx.recorder.flush(exit_code=exit_code, duration_ms=duration_ms)

    # XDRError path swallowed the exception; convert exit code to sys.exit
    # so callers see the right non-zero return without losing the JSON envelope.
    if suppressed_xdr_error:
        sys.exit(exit_code)
    # KeyboardInterrupt path — see run() docstring "Exit-code semantics" for
    # rationale. Convert to sys.exit(130).
    if exit_code == 130:
        sys.exit(130)


# Install the leaf-callback hook at import time so the chain capture and
# the hunt-requires-session / learning-mode gates fire on the very first
# ``app()`` invocation — including under ``CliRunner.invoke(app, ...)``,
# which doesn't go through :func:`run`. ``_ensure_chain_hook_installed`` is
# idempotent: if ``run()`` later calls it again, the wrappers are already
# tagged ``_xdr_chain_wrapped`` and skipped.
_ensure_chain_hook_installed()
