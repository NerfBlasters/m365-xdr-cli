"""Manage tenant-local investigation questions and their source evidence."""

import json

import click

from xdr_cli.exceptions import ExitCode, UsageError
from xdr_cli.inquiries import (
    SIGNALS,
    add_note,
    add_question,
    answer_question,
    attach_run,
    delete_inquiry,
    finish_inquiry,
    index_incident,
    inquiry_view,
    list_inquiries,
    open_inquiry,
    settle_check,
)
from xdr_cli.results import emit_result

inquiry_app = click.Group("inquiry", help="Track a local investigation and its evidence.")


@inquiry_app.command("open")
@click.argument("objective", required=True)
@click.option("--source", default=None, help="Verified evidence run to attach to the root.")
@click.pass_obj
def inquiry_open(ctx, objective: str, source: str | None) -> None:
    """Open an inquiry with a root question and impact check."""
    if not objective.strip():
        raise UsageError("Supply a nonempty investigation objective.")
    record = open_inquiry(ctx.config.tenant_id, objective, source, ctx.rationale)
    click.echo(json.dumps(record, separators=(",", ":")))


@inquiry_app.command("attach")
@click.argument("inquiry_id", required=True)
@click.argument("run_id", required=True)
@click.option("--question", required=True, help="Question in this inquiry.")
@click.pass_obj
def inquiry_attach(ctx, inquiry_id: str, run_id: str, question: str) -> None:
    """Attach an existing verified tenant read without running it again."""
    record = attach_run(ctx.config.tenant_id, inquiry_id, question, run_id, ctx.rationale)
    click.echo(json.dumps(record, separators=(",", ":")))


@inquiry_app.command("view")
@click.argument("inquiry_id", required=True)
@click.option("--question", default=None, help="Focus on one question.")
@click.option("--entity", default=None, help="Namespace-qualified entity value.")
@click.option("--prior", is_flag=True, help="Include verified earlier same-tenant sightings.")
@click.pass_obj
def view(ctx, inquiry_id: str, question: str | None, entity: str | None, prior: bool) -> None:
    """Inspect the inquiry objective, pending checks and attached evidence."""
    if prior and not entity:
        raise UsageError("--prior requires --entity.")
    emit_result(inquiry_view(ctx, inquiry_id, question, entity, prior))


@inquiry_app.command("question")
@click.argument("inquiry_id")
@click.argument("text")
@click.option("--parent", required=True)
@click.option("--from", "trigger", default=None, help="Originating observation ID.")
@click.option("--entity", default=None, help="Inquiry-local entity key.")
@click.pass_obj
def question_cmd(ctx, inquiry_id, text, parent, trigger, entity):
    """Open a material child question."""
    _emit(add_question(ctx, inquiry_id, parent, text, trigger, entity))


@inquiry_app.command("note")
@click.argument("inquiry_id")
@click.argument("text")
@click.option("--question", required=True)
@click.option("--cite", multiple=True, required=True)
@click.option("--entity", multiple=True, default=())
@click.option("--scope", default="", help="Agent-declared search scope and limitations.")
@click.option("--signal", type=click.Choice(list(SIGNALS)), default=None)
@click.pass_obj
def note_cmd(ctx, inquiry_id, text, question, cite, signal, entity, scope):
    """Record a cited observation and surface downstream impact checks."""
    _emit(add_note(ctx, inquiry_id, question, text, cite, signal, entity, scope))


@inquiry_app.command("check")
@click.argument("inquiry_id")
@click.argument("check_id")
@click.option("--basis", default=None)
@click.option("--skip-reason", default=None)
@click.pass_obj
def check_cmd(ctx, inquiry_id, check_id, basis, skip_reason):
    """Record the disposition of an impact check."""
    _emit(settle_check(ctx, inquiry_id, check_id, basis, skip_reason))


@inquiry_app.command("answer")
@click.argument("inquiry_id")
@click.argument("text")
@click.option("--question", required=True)
@click.option(
    "--state",
    type=click.Choice(["open", "answered", "inconclusive", "set-aside", "needs-analyst"]),
    required=True,
)
@click.option("--basis", multiple=True, default=())
@click.option("--revision", type=int, required=True)
@click.pass_obj
def answer_cmd(ctx, inquiry_id, text, question, state, basis, revision):
    """Save an assessment at the indicated inquiry revision."""
    _emit(answer_question(ctx, inquiry_id, question, state, text, basis, revision))


@inquiry_app.command("finish")
@click.argument("inquiry_id")
@click.pass_obj
def finish_cmd(ctx, inquiry_id):
    """Verify disposition and evidence for the current conclusion."""
    record = finish_inquiry(ctx, inquiry_id)
    _emit(record)
    if record["status"] == "analyst-required":
        raise click.exceptions.Exit(ExitCode.ANALYST_REQUIRED)


def _emit(value):
    click.echo(json.dumps(value, separators=(",", ":")))


@inquiry_app.command("index")
@click.argument("run_id")
@click.pass_obj
def index_cmd(ctx, run_id):
    """Index typed evidence from a saved expanded incident."""
    _emit(index_incident(ctx, run_id))


@inquiry_app.command("list")
@click.pass_obj
def list_cmd(ctx):
    """List current-tenant inquiries and their assessment states."""
    emit_result(list_inquiries(ctx))


@inquiry_app.command("delete")
@click.argument("inquiry_id")
@click.option("--yes", is_flag=True, help="Delete the inquiry and its derived views.")
@click.pass_obj
def delete_cmd(ctx, inquiry_id, yes):
    """Preview or delete an inquiry and its private rendered copies."""
    _emit(delete_inquiry(ctx, inquiry_id, yes))
