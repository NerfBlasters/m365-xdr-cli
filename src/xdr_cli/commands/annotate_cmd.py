"""`xdr annotate` — append an annotation record clearing the learning-mode gate.

On success, a single ``xdr annotate`` invocation produces TWO JSONL lines:

* the standard ``kind: "invocation"`` record (from :meth:`Recorder.flush`,
  per Task 3 universal-recording wiring), and
* a separate ``kind: "annotation"`` record (from
  :func:`xdr_cli.sessions.write_annotation`).

The annotation record is what clears the per-actor learning-mode gate; the
invocation record is the audit trail for the annotate call itself.
"""

from __future__ import annotations

import os

import typer

from xdr_cli.context import AppContext
from xdr_cli.exceptions import ConflictError, QueryError, UsageError
from xdr_cli.sessions import current_session, write_annotation


def annotate(
    ctx: typer.Context,
    text: str = typer.Argument(
        "",
        help="Annotation text. Required unless --skip is supplied.",
    ),
    skip: str = typer.Option(
        "",
        "--skip",
        help="Skip the annotation with a reason. Mutually exclusive with text.",
    ),
    refers_to: int | None = typer.Option(
        None,
        "--refers-to",
        help=(
            "Seq of the invocation to annotate. "
            "Defaults to the calling actor's most-recent unannotated invocation."
        ),
    ),
) -> None:
    """Annotate the calling actor's most-recent unannotated invocation.

    Or a specific seq via ``--refers-to``.
    """
    text_value = (text or "").strip()
    skip_value = (skip or "").strip()

    if text_value and skip_value:
        raise UsageError(
            "--skip is mutually exclusive with annotation text.",
            invalid={"kind": "mutually_exclusive", "value": ["text", "--skip"]},
            help_command="xdr annotate --help",
        )
    if not text_value and not skip_value:
        raise UsageError(
            "Provide annotation text or --skip <reason>.",
            invalid={"kind": "missing_value", "value": "text|--skip"},
            help_command="xdr annotate --help",
        )

    session = current_session()
    if session is None:
        raise ConflictError(
            "No active session is unambiguously available to annotate.",
            help_command="xdr session list",
        )

    actor = os.environ.get("XDR_ACTOR", "operator")

    try:
        seq = write_annotation(
            session=session,
            actor=actor,
            text=text_value or None,
            skip_reason=skip_value or None,
            refers_to=refers_to,
        )
    except QueryError:
        app_ctx: AppContext = ctx.obj
        if app_ctx is not None and app_ctx.recorder is not None:
            app_ctx.recorder.skip_record()
        raise

    typer.echo(f"annotated seq={seq}")
