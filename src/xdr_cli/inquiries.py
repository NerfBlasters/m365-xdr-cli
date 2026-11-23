"""Local inquiry ownership and durable evidence attachments."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from contextlib import closing, contextmanager
from functools import cache
from importlib.resources import files
from uuid import uuid4

from xdr_cli.commands.results_cmd import _find_meta, _verified_result_rows
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import (
    ArtifactError,
    ConfigError,
    ConflictError,
    LocalNotFoundError,
    PartialSuccessError,
    UsageError,
    XDRError,
)
from xdr_cli.inquiry_entities import index_row
from xdr_cli.queries import load_query, query_source_hash
from xdr_cli.results import results_page_command, tenant_fingerprint, write_result
from xdr_cli.schema_graph.overlay import schema_evidence_lock

_EVIDENCE = {"incidents show", "alerts show", "hunt run", "library run"}
_SCHEMA = (
    """CREATE TABLE sighting (
        run_id TEXT NOT NULL, ref TEXT NOT NULL, field TEXT NOT NULL, entity TEXT NOT NULL,
        seen TEXT, PRIMARY KEY(ref,field))""",
    "CREATE INDEX sighting_entity ON sighting(entity)",
    """CREATE TABLE derived_result (inquiry_id TEXT NOT NULL REFERENCES inquiry(id)
        ON DELETE CASCADE, run_id TEXT NOT NULL, PRIMARY KEY(inquiry_id,run_id))""",
    """CREATE TABLE indexed_source (
        run_id TEXT PRIMARY KEY, digest TEXT NOT NULL, passive INTEGER NOT NULL DEFAULT 0,
        unattributed INTEGER NOT NULL, incident TEXT)""",
    "CREATE TABLE inquiry (id TEXT PRIMARY KEY, revision INTEGER NOT NULL)",
    """CREATE TABLE question (
        id TEXT PRIMARY KEY, inquiry_id TEXT NOT NULL REFERENCES inquiry(id) ON DELETE CASCADE,
        parent_id TEXT REFERENCES question(id) ON DELETE CASCADE, objective TEXT NOT NULL,
        trigger_note TEXT, entity TEXT,
        state TEXT NOT NULL DEFAULT 'open')""",
    """CREATE TABLE impact_check (
        id TEXT PRIMARY KEY, question_id TEXT NOT NULL REFERENCES question(id) ON DELETE CASCADE,
        description TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open', trigger_ref TEXT,
        UNIQUE(question_id,description,trigger_ref))""",
    """CREATE TABLE note (
        id TEXT PRIMARY KEY, question_id TEXT NOT NULL REFERENCES question(id) ON DELETE CASCADE,
        statement TEXT NOT NULL, citations TEXT NOT NULL, signal TEXT NOT NULL,
        entities TEXT NOT NULL, scope TEXT NOT NULL,
        UNIQUE(question_id, statement, citations, signal, entities, scope))""",
    """CREATE TABLE assessment (
        question_id TEXT NOT NULL REFERENCES question(id) ON DELETE CASCADE,
        revision INTEGER NOT NULL,
        state TEXT NOT NULL, explanation TEXT NOT NULL, basis TEXT NOT NULL,
        verified_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(question_id, revision))""",
    """CREATE TABLE disposition (
        check_id TEXT PRIMARY KEY REFERENCES impact_check(id) ON DELETE CASCADE,
        reason TEXT, basis TEXT)""",
    """CREATE TABLE attachment (
        question_id TEXT NOT NULL REFERENCES question(id) ON DELETE CASCADE, run_id TEXT NOT NULL,
        data_sha256 TEXT NOT NULL, metadata_sha256 TEXT NOT NULL, rationale TEXT NOT NULL,
        PRIMARY KEY(question_id, run_id))""",
)


@contextmanager
def inquiry_transaction(tenant_id: str | None):
    fingerprint = tenant_fingerprint(tenant_id)
    if not fingerprint:
        raise ConfigError("Configure a tenant ID before opening an inquiry.")
    directory = get_config_home() / "inquiries" / fingerprint
    try:
        with schema_evidence_lock(help_command="xdr inquiry --help"):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = directory / "inquiries.sqlite"
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            os.close(fd)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("BEGIN IMMEDIATE")
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version == 0:
                    for statement in _SCHEMA:
                        db.execute(statement)
                if version in (0, 1):
                    db.execute(
                        "CREATE TABLE read_failure (question_id TEXT NOT NULL REFERENCES "
                        "question(id) ON DELETE CASCADE, command TEXT NOT NULL, "
                        "error_code TEXT NOT NULL, recorded_at TEXT DEFAULT CURRENT_TIMESTAMP)"
                    )
                    db.execute("PRAGMA user_version=2")
                elif version != 2:
                    raise ConflictError("Unsupported inquiry database version.")
                yield db, fingerprint
    except (sqlite3.Error, OSError) as exc:
        raise ArtifactError("Could not access the private inquiry store.") from exc


def validate_question(db: sqlite3.Connection, inquiry: str, question: str) -> None:
    if not db.execute(
        "SELECT 1 FROM question WHERE inquiry_id=? AND id=?", (inquiry, question)
    ).fetchone():
        raise LocalNotFoundError("inquiry question", question)


@cache
def playbook_catalog():
    return json.loads(files("xdr_cli").joinpath("inquiry_playbooks.json").read_text("utf-8"))


def _playbook_checks(db, question, row, reference):
    title = row.get("title")
    if row.get("record_type") != "alert" or not isinstance(title, str):
        return
    for playbook in playbook_catalog().values():
        if any(keyword.casefold() in title.casefold() for keyword in playbook["titles"]):
            for check in playbook["checks"]:
                db.execute(
                    "INSERT OR IGNORE INTO impact_check"
                    "(id,question_id,description,trigger_ref) VALUES (?,?,?,?)",
                    (uuid4().hex, question, check["description"], reference),
                )


def _attach(db, tenant, inquiry, question, run, rationale):
    validate_question(db, inquiry, question)
    # The visitor writes only within the enclosing transaction. A later byte,
    # binding or row-count failure rolls every derived check back.
    gaps = 0
    click_source = None

    def observe(meta, row, index, line):
        nonlocal gaps, click_source
        if meta.get("tenant_binding", {}).get("sha256") != tenant:
            return
        digest = hashlib.sha256(line.removesuffix(b"\n").removesuffix(b"\r")).hexdigest()
        reference = f"{meta['run_id']}:{index}:{digest}"
        if not index_row(db, meta, row, reference):
            gaps += 1
        if meta.get("command") in {"incidents show", "alerts show"}:
            _playbook_checks(db, question, row, reference)
            return
        if meta.get("command") not in {"hunt run", "library run"}:
            return
        if click_source is None:
            click_source = meta.get("physical_lineage") == {
                "kind": "physical", "table": "UrlClickEvents",
            }
            if meta.get("library_entry") == "qry_url_clicks":
                params = meta.get("resolved_parameters") or {}
                click_source = (
                    params.get("mode", "detail") == "detail"
                    and meta.get("source_hash") == query_source_hash("qry_url_clicks")
                    and meta.get("query") == load_query("qry_url_clicks", **params)
                )
        if not click_source:
            return
        action = row.get("ActionType")
        if row.get("IsClickedThrough") in (True, 1, "1") or action == "ClickAllowed":
            signal = "permitted-click"
        elif action == "ClickBlocked":
            return
        else:
            signal = "ambiguous-click"
        for description in SIGNALS[signal]:
            db.execute(
                "INSERT OR IGNORE INTO impact_check"
                "(id,question_id,description,trigger_ref) VALUES (?,?,?,?)",
                (uuid4().hex, question, description, reference),
            )

    meta, _, _ = _verified_result_rows(_find_meta(run), limit=0, visit=observe)
    if meta.get("tenant_binding") != {"state": "bound", "sha256": tenant}:
        raise ConflictError("Evidence must be bound to the inquiry tenant.")
    if meta.get("command") not in _EVIDENCE:
        raise ConflictError("This result is not an eligible source of inquiry evidence.")
    run = meta["run_id"]
    _remember(db, meta, gaps)
    hashes = (meta["data_sha256"], _metadata_hash(meta))
    prior = db.execute(
        "SELECT data_sha256,metadata_sha256 FROM attachment WHERE question_id=? AND run_id=?",
        (question, run),
    ).fetchone()
    if prior and prior != hashes:
        raise ArtifactError("Attached evidence has changed since it was first verified.")
    if prior is None:
        db.execute("INSERT INTO attachment VALUES (?,?,?,?,?)", (question, run, *hashes, rationale))
        _reopen(db, inquiry, question)
    return {
        "run_id": run,
        "rows": meta["row_count"],
        "server_truncation_state": meta["server_truncation_state"],
    }


def _receipt(db, inquiry, question):
    (revision,) = db.execute("SELECT revision FROM inquiry WHERE id=?", (inquiry,)).fetchone()
    return {
        "status": "success",
        "inquiry_id": inquiry,
        "question_id": question,
        "revision": revision,
        "inquiry_command": f"xdr inquiry view {inquiry} --question {question}",
    }


def open_inquiry(tenant_id, objective, source, rationale):
    with inquiry_transaction(tenant_id) as (db, tenant):
        inquiry, question, check = (uuid4().hex for _ in range(3))
        db.execute("INSERT INTO inquiry VALUES (?,1)", (inquiry,))
        db.execute(
            "INSERT INTO question(id,inquiry_id,objective) VALUES (?,?,?)",
            (question, inquiry, objective),
        )
        db.execute(
            "INSERT INTO impact_check(id,question_id,description) VALUES (?,?,?)",
            (check, question, "Assess observed impact and affected entities."),
        )
        evidence = _attach(db, tenant, inquiry, question, source, rationale) if source else {}
        return {**_receipt(db, inquiry, question), "impact_check_id": check, **evidence}


def attach_run(tenant_id, inquiry, question, run, rationale):
    with inquiry_transaction(tenant_id) as (db, tenant):
        evidence = _attach(db, tenant, inquiry, question, run, rationale)
        return {**_receipt(db, inquiry, question), **evidence}


@contextmanager
def bound_read(ctx, inquiry, question, ask):
    if inquiry is None and question is None and ask is None:
        yield
        return
    if not inquiry or not question:
        raise UsageError("Supply --inquiry and --question together, including with --ask.")
    if ask is not None:
        if not ask.strip():
            raise UsageError("Supply a material question with --ask.")
        question = add_question(ctx, inquiry, question, ask.strip())["question_id"]
    else:
        with inquiry_transaction(ctx.config.tenant_id) as (db, _):
            validate_question(db, inquiry, question)
    ctx.inquiry_binding = (inquiry, question)
    try:
        yield
    except PartialSuccessError:
        # The durable result has its own recovery command.
        raise
    except Exception as exc:
        code = exc.error_code if isinstance(exc, XDRError) else "READ_FAILED"
        try:
            with inquiry_transaction(ctx.config.tenant_id) as (db, _):
                validate_question(db, inquiry, question)
                db.execute(
                    "INSERT INTO read_failure(question_id,command,error_code) VALUES (?,?,?)",
                    (question, ctx.invoked_command, code),
                )
                _reopen(db, inquiry, question)
        except XDRError as record_error:
            # Preserve the read's exit code, retry delay and original recovery instructions.
            print(f"Could not record failed read ({record_error.error_code}).", file=sys.stderr)
        print(f"Review the question: xdr inquiry view {inquiry} --question {question}",
              file=sys.stderr)
        raise


def inquiry_view(ctx, inquiry, question, entity=None, prior=False):
    with inquiry_transaction(ctx.config.tenant_id) as (db, tenant):
        root = db.execute(
            "SELECT id,objective FROM question WHERE inquiry_id=? AND parent_id IS NULL",
            (inquiry,),
        ).fetchone()
        if not root:
            raise LocalNotFoundError("inquiry", inquiry)
        question = question or root[0]
        validate_question(db, inquiry, question)
        summary = {
            **_receipt(db, inquiry, question),
            "record_type": "inquiry-summary",
            "objective": root[1],
            "root_id": root[0],
        }
        rows = [summary]
        for command, code, recorded_at in db.execute(
            "SELECT command,error_code,recorded_at FROM read_failure "
            "WHERE question_id=? ORDER BY rowid", (question,),
        ):
            rows.append({"record_type": "failed-read", "question_id": question,
                         "command": command, "error_code": code, "recorded_at": recorded_at})
        for ident, description, state, trigger in db.execute(
            "SELECT id,description,state,trigger_ref FROM impact_check "
            "WHERE question_id=? ORDER BY rowid",
            (question,),
        ):
            rows.append(
                {
                    "record_type": "impact-check",
                    "id": ident,
                    "description": description,
                    "trigger": trigger,
                    "state": state,
                }
            )
        for run, rationale, pinned in db.execute(
            "SELECT run_id,rationale,metadata_sha256 FROM attachment "
            "WHERE question_id=? ORDER BY rowid",
            (question,),
        ):
            try:
                source, _, _ = _verified_result_rows(_find_meta(run), limit=0)
            except LocalNotFoundError:
                rows.append({"record_type": "expired-source", "run_id": run})
                continue
            if _metadata_hash(source) != pinned:
                raise ArtifactError("Attached evidence provenance changed.")
            rows.append(
                {
                    "record_type": "attached-check",
                    "run_id": run,
                    "results_command": results_page_command(run, citations=True),
                    "rationale": rationale,
                    "anchors": source.get("anchors"),
                    "row_count": source["row_count"],
                    "server_truncation_state": source["server_truncation_state"],
                    "window": "not recorded",
                }
            )
            summary["latest_attached_run"] = run
        for note, statement, references, entities, scope in db.execute(
            "SELECT id,statement,citations,entities,scope FROM note "
            "WHERE question_id=? ORDER BY rowid",
            (question,),
        ):
            rows.append(
                {
                    "record_type": "observation",
                    "id": note,
                    "statement": statement,
                    "entities": json.loads(entities),
                    "agent_declared_scope": scope or None,
                    "citations": json.loads(references),
                }
            )
        for child, title, state, parent, trigger, subject in db.execute(
            "SELECT id,objective,state,parent_id,trigger_note,entity FROM question "
            "WHERE inquiry_id=? ORDER BY state!='open',rowid", (inquiry,)
        ):
            rows.append(
                {"record_type": "question", "id": child, "objective": title, "state": state,
                 "parent_id": parent, "trigger_observation": trigger, "entity": subject}
            )
        for q, revision, state, explanation, basis, timestamp in db.execute(
            "SELECT a.question_id,a.revision,a.state,a.explanation,a.basis,a.verified_at "
            "FROM assessment a JOIN question q ON q.id=a.question_id "
            "WHERE q.inquiry_id=? ORDER BY a.revision DESC",
            (inquiry,),
        ):
            rows.append(
                {
                    "record_type": "assessment",
                    "question_id": q,
                    "revision": revision,
                    "state": state,
                    "explanation": explanation,
                    "basis": json.loads(basis),
                    "checked_at": timestamp,
                }
            )
        summary["revision"] = _receipt(db, inquiry, question)["revision"]
        summary["question_id"] = question
        summary["open_checks"] = db.execute(
            "SELECT count(*) FROM impact_check c JOIN question q ON q.id=c.question_id "
            "WHERE q.inquiry_id=? AND c.state='open'",
            (inquiry,),
        ).fetchone()[0]
        summary["commands"] = {
            "note": f'xdr inquiry note {inquiry} "OBSERVATION" --question {question} --cite REF',
            "question": f'xdr inquiry question {inquiry} "QUESTION" --parent {question}',
            "answer": (
                f'xdr inquiry answer {inquiry} "ASSESSMENT" --question {question} '
                f"--state answered --basis NOTE --revision {summary['revision']}"
            ),
            "finish": f"xdr inquiry finish {inquiry}",
        }
        current_runs = {
            run
            for (run,) in db.execute(
                "SELECT a.run_id FROM attachment a JOIN question q ON q.id=a.question_id "
                "WHERE q.inquiry_id=?",
                (inquiry,),
            )
        }
        summary["unattributed_rows"] = 0
        for run, digest, gaps, incident in db.execute(
            "SELECT run_id,digest,unattributed,incident FROM indexed_source"
        ):
            current = run in current_runs
            if not current and not (entity and prior and ctx.config.entity_memory):
                continue
            selection = db.execute(
                "SELECT entity,ref,field,seen FROM sighting WHERE run_id=? "
                "AND (? IS NULL OR entity=?) ORDER BY rowid",
                (run, entity, entity),
            ).fetchall()
            if not current and not selection:
                continue
            try:
                source, _, _ = _verified_result_rows(_find_meta(run), limit=0)
            except LocalNotFoundError:
                rows.append({"record_type": "expired-source", "run_id": run})
                continue
            if (source["data_sha256"] != digest or
                    source.get("tenant_binding") != {"state": "bound", "sha256": tenant}):
                raise ArtifactError("Entity source digest changed.")
            summary["unattributed_rows"] += gaps
            # Only typed mailMessageEvidence contributes these two provider field paths.
            # Preserve the direction asserted by the recipient field on that message.
            for message, recipient, ref, seen in db.execute(
                "SELECT m.entity,r.entity,m.ref,m.seen FROM sighting m JOIN sighting r "
                "ON m.ref=r.ref WHERE m.run_id=? AND m.field='networkMessageId' "
                "AND r.field='recipientEmailAddress' "
                "AND (? IS NULL OR m.entity=? OR r.entity=?) ORDER BY m.rowid",
                (run, entity, entity, entity),
            ):
                rows.append({
                    "record_type": "entity-relation", "relation": "message-recipient",
                    "message": message, "recipient": recipient, "citation": ref, "seen": seen,
                    "scope": "current" if current else "prior",
                })
            for key, ref, field, seen in selection:
                rows.append(
                    {
                        "record_type": "sighting",
                        "entity": key,
                        "citation": ref,
                        "field": field,
                        "seen": seen,
                        "incident_id": incident,
                        "scope": "current" if current else "prior",
                    }
                )
        artifact = write_result(
            rows,
            command="inquiry view",
            tenant_id=ctx.config.tenant_id,
            extra_metadata={"inquiry_owners": [inquiry]},
        )
        db.execute("INSERT INTO derived_result VALUES (?,?)", (inquiry, artifact.receipt.run_id))
        return artifact


SIGNALS = {
    "permitted-click": (
        "Assess subsequent account and session activity for the recipient.",
        "Attribute the visit to a device and assess downloads and process execution.",
    ),
    "ambiguous-click": ("Resolve navigation outcome and possible downstream impact.",),
    "linked-download": ("Establish whether the downloaded file executed or was prevented.",),
    "suspicious-execution": (
        "Establish process ancestry and observable effects.",
        "Scope matching evidence to other devices.",
    ),
    "unauthorized-account-use": (
        "Identify subsequent session actions and affected resources.",
        "Assess whether other identities were affected.",
    ),
}


def _reopen(db, inquiry, question):
    db.execute(
        """WITH RECURSIVE ancestors(id) AS (
        SELECT ? UNION ALL SELECT q.parent_id FROM question q JOIN ancestors a
        ON q.id=a.id WHERE q.parent_id IS NOT NULL)
        UPDATE question SET state='open' WHERE id IN (SELECT id FROM ancestors)""",
        (question,),
    )
    db.execute("UPDATE inquiry SET revision=revision+1 WHERE id=?", (inquiry,))


def _check_entities(db, inquiry, entities):
    for entity in entities:
        found = db.execute(
            "SELECT 1 FROM sighting s JOIN attachment a ON s.run_id=a.run_id "
            "JOIN question q ON q.id=a.question_id WHERE q.inquiry_id=? AND s.entity=? LIMIT 1",
            (inquiry, entity),
        ).fetchone()
        if not found:
            raise LocalNotFoundError("inquiry entity", entity)


def add_question(ctx, inquiry, parent, text, trigger=None, entity=None):
    with inquiry_transaction(ctx.config.tenant_id) as (db, _):
        validate_question(db, inquiry, parent)
        _check_entities(db, inquiry, [entity] if entity else [])
        if trigger:
            _validate_basis(db, tenant_fingerprint(ctx.config.tenant_id), inquiry, [trigger])
        found = db.execute(
            "SELECT id FROM question WHERE parent_id=? AND objective=? AND trigger_note IS ? "
            "AND entity IS ?",
            (parent, text, trigger, entity),
        ).fetchone()
        if found:
            return _receipt(db, inquiry, found[0])
        ident = uuid4().hex
        db.execute(
            "INSERT INTO question(id,inquiry_id,parent_id,objective,trigger_note,entity) "
            "VALUES (?,?,?,?,?,?)",
            (ident, inquiry, parent, text, trigger, entity),
        )
        _reopen(db, inquiry, parent)
        return _receipt(db, inquiry, ident)


def _metadata_hash(meta):
    encoded = json.dumps(meta, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _verify_references(db, tenant, inquiry, refs):
    """Verify each distinct bundle once and acknowledge references in caller order."""
    by_run: dict[str, set[int]] = {}
    for ref in refs:
        parts = ref.split(":")
        if len(parts) not in {1, 3}:
            raise UsageError("Supply a whole run ID or a reader-issued row citation.")
        indices = by_run.setdefault(parts[0], set())
        if len(parts) == 3:
            index = parts[1]
            if not index.isascii() or not index.isdecimal() or len(index) > 18:
                raise UsageError("Invalid citation row index.")
            indices.add(int(index))

    verified = {}
    for run, indices in by_run.items():
        verified.update(_verified_run_references(db, tenant, inquiry, run, indices))
    if any(ref not in verified for ref in refs):
        raise ArtifactError("Citation does not match the indicated row.")
    return [verified[ref] for ref in refs]


def _verified_run_references(db, tenant, inquiry, run, indices):
    attached = db.execute(
        """SELECT a.data_sha256,a.metadata_sha256 FROM attachment a JOIN question q
           ON a.question_id=q.id WHERE q.inquiry_id=? AND a.run_id=? LIMIT 1""",
        (inquiry, run),
    ).fetchone()
    if not attached:
        raise ConflictError("The cited run is not attached to this inquiry.")
    try:
        path = _find_meta(run)
    except LocalNotFoundError as exc:
        raise ConflictError("Cited evidence has expired. Reassess the question.") from exc
    meta, rows, _ = _verified_result_rows(
        path, row_indices=indices, citations=True
    )
    if (meta["data_sha256"], _metadata_hash(meta)) != attached:
        raise ArtifactError("Attached evidence or its provenance has changed.")
    if meta.get("tenant_binding") != {"state": "bound", "sha256": tenant}:
        raise ConflictError("Cited evidence tenant mismatch.")
    verified = {
        run: {"run_id": run, "rows": meta["row_count"],
              "server_truncation_state": meta["server_truncation_state"]}
    }
    for entry in rows:
        row = entry["row"]
        fields = {k: row[k][:128] for k in ("record_type", "Timestamp", "id")
                  if isinstance(row.get(k), str)}
        token = entry["citation"]
        verified[token] = {"citation": token, "identifying_fields": fields}
    return verified


def add_note(ctx, inquiry, question, text, refs, signal, entities=(), scope=""):
    with inquiry_transaction(ctx.config.tenant_id) as (db, tenant):
        validate_question(db, inquiry, question)
        references = sorted(set(refs))
        echoes = _verify_references(db, tenant, inquiry, references)
        citations = json.dumps(references)
        _check_entities(db, inquiry, entities)
        arguments = (
            question,
            text,
            citations,
            signal or "",
            json.dumps(sorted(set(entities))),
            scope,
        )
        found = db.execute(
            "SELECT id FROM note WHERE question_id=? AND statement=? AND citations=? "
            "AND signal=? AND entities=? AND scope=?",
            arguments,
        ).fetchone()
        if found:
            ident = found[0]
        else:
            ident = uuid4().hex
            db.execute("INSERT INTO note VALUES (?,?,?,?,?,?,?)", (ident, *arguments))
            for description in SIGNALS.get(signal, ()):
                for ref in references:
                    db.execute(
                        "INSERT OR IGNORE INTO impact_check"
                        "(id,question_id,description,trigger_ref) VALUES (?,?,?,?)",
                        (uuid4().hex, question, description, ref),
                    )
            _reopen(db, inquiry, question)
        return {**_receipt(db, inquiry, question), "note_id": ident, "citations": echoes}


def _validate_basis(db, tenant, inquiry, notes):
    references = set()
    for ident in sorted(set(notes)):
        found = db.execute(
            """SELECT citations FROM note n JOIN question q ON q.id=n.question_id
            WHERE n.id=? AND q.inquiry_id=?""",
            (ident, inquiry),
        ).fetchone()
        if not found:
            raise LocalNotFoundError("inquiry observation", ident)
        references.update(json.loads(found[0]))
    _verify_references(db, tenant, inquiry, references)


def settle_check(ctx, inquiry, check, basis, reason):
    if bool(basis) == bool(reason):
        raise UsageError("Supply a basis observation or a specific skip reason.")
    with inquiry_transaction(ctx.config.tenant_id) as (db, tenant):
        row = db.execute(
            """SELECT c.question_id FROM impact_check c JOIN question q ON q.id=c.question_id
               WHERE c.id=? AND q.inquiry_id=?""",
            (check, inquiry),
        ).fetchone()
        if not row:
            raise LocalNotFoundError("inquiry check", check)
        question = row[0]
        if basis:
            _validate_basis(db, tenant, inquiry, [basis])
        if db.execute(
            "SELECT reason,basis FROM disposition WHERE check_id=?", (check,)
        ).fetchone() != (reason, basis):
            db.execute("INSERT OR REPLACE INTO disposition VALUES (?,?,?)", (check, reason, basis))
            db.execute(
                "UPDATE impact_check SET state=? WHERE id=?",
                ("supported" if basis else "set-aside", check),
            )
            _reopen(db, inquiry, question)
        return _receipt(db, inquiry, question)


def answer_question(ctx, inquiry, question, state, text, basis, revision):
    if not text.strip():
        raise UsageError("Explain the assessment or the remaining limit.")
    with inquiry_transaction(ctx.config.tenant_id) as (db, tenant):
        validate_question(db, inquiry, question)
        if _receipt(db, inquiry, question)["revision"] != revision:
            raise ConflictError("Inquiry changed. Inspect its latest revision.")
        if state == "answered" and not basis:
            raise UsageError("An answered question requires a basis observation.")
        _validate_basis(db, tenant, inquiry, basis)
        if (
            state == "set-aside"
            and db.execute("SELECT parent_id FROM question WHERE id=?", (question,)).fetchone()[0]
            is None
        ):
            raise UsageError("The root question cannot be set aside.")
        _reopen(db, inquiry, question)
        db.execute("UPDATE question SET state=? WHERE id=?", (state, question))
        db.execute(
            "INSERT INTO assessment(question_id,revision,state,explanation,basis) "
            "VALUES (?,?,?,?,?)",
            (question, revision + 1, state, text, json.dumps(basis)),
        )
        return _receipt(db, inquiry, question)


def finish_inquiry(ctx, inquiry):
    with inquiry_transaction(ctx.config.tenant_id) as (db, tenant):
        questions = db.execute(
            "SELECT id,state,parent_id FROM question WHERE inquiry_id=? ORDER BY rowid", (inquiry,)
        ).fetchall()
        if not questions:
            raise LocalNotFoundError("inquiry", inquiry)
        root = next(q for q in questions if q[2] is None)
        pending = db.execute(
            """SELECT c.id,c.question_id FROM impact_check c JOIN question q ON c.question_id=q.id
               WHERE q.inquiry_id=? AND c.state='open'""",
            (inquiry,),
        ).fetchall()
        blocked = {question for question, state, _ in questions if state == "needs-analyst"}
        parents = {question: parent for question, _, parent in questions}
        waiting = set(blocked)
        for question in blocked:
            while parents[question] is not None:
                question = parents[question]
                waiting.add(question)
        actionable = {q for q, state, _ in questions if state == "open"} - waiting
        pending_owners = {owner for _, owner in pending}
        if blocked and not actionable and not pending_owners - waiting:
            requests = []
            for q in sorted(blocked):
                (reason,) = db.execute(
                    "SELECT explanation FROM assessment WHERE question_id=? "
                    "ORDER BY revision DESC LIMIT 1",
                    (q,),
                ).fetchone()
                requests.append(
                    {
                        "question_id": q,
                        "request": reason,
                        "review_command": f"xdr inquiry view {inquiry} --question {q}",
                    }
                )
            return {
                **_receipt(db, inquiry, root[0]),
                "status": "analyst-required",
                "requests": requests,
            }
        basis_notes = set()
        for question, state, _ in questions:
            if state in {"open", "needs-analyst"} or pending:
                raise ConflictError(
                    "Inquiry has outstanding work.", help_command=f"xdr inquiry view {inquiry}"
                )
            (basis,) = db.execute(
                "SELECT basis FROM assessment WHERE question_id=? ORDER BY revision DESC LIMIT 1",
                (question,),
            ).fetchone()
            basis_notes.update(json.loads(basis))
        for (basis,) in db.execute(
            """SELECT d.basis FROM disposition d JOIN impact_check c ON d.check_id=c.id
               JOIN question q ON c.question_id=q.id
               WHERE q.inquiry_id=? AND d.basis IS NOT NULL""",
            (inquiry,),
        ):
            basis_notes.add(basis)
        _validate_basis(db, tenant, inquiry, basis_notes)
        explanation, basis = db.execute(
            "SELECT explanation,basis FROM assessment WHERE question_id=? "
            "ORDER BY revision DESC LIMIT 1", (root[0],)
        ).fetchone()
        return {
            **_receipt(db, inquiry, root[0]), "root_state": root[1], "outstanding": 0,
            "assessment": explanation, "basis": json.loads(basis),
            "limitations": [
                {"question_id": q, "question": objective, "reason": reason}
                for q, objective, reason in db.execute(
                    "SELECT q.id,q.objective,a.explanation FROM question q JOIN assessment a "
                    "ON a.question_id=q.id WHERE q.inquiry_id=? AND q.state='inconclusive' "
                    "AND a.revision=(SELECT MAX(revision) FROM assessment WHERE question_id=q.id) "
                    "ORDER BY q.rowid", (inquiry,),
                )
            ],
        }


def _remember(db, meta, gaps, passive=False):
    prior = db.execute(
        "SELECT digest FROM indexed_source WHERE run_id=?", (meta["run_id"],)
    ).fetchone()
    if prior and prior[0] != meta["data_sha256"]:
        raise ArtifactError("Indexed evidence has changed.")
    db.execute(
        "INSERT INTO indexed_source VALUES (?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET "
        "passive=max(passive,excluded.passive)",
        (
            meta["run_id"],
            meta["data_sha256"],
            int(passive),
            gaps,
            meta.get("anchors", {}).get("incident_id"),
        ),
    )


def index_incident(ctx, run):
    if ctx.config.entity_memory is not True:
        raise ConflictError("Passive entity memory is disabled.")
    with inquiry_transaction(ctx.config.tenant_id) as (db, tenant):
        gaps = 0

        def observe(meta, row, index, line):
            nonlocal gaps
            digest = hashlib.sha256(line.removesuffix(b"\n").removesuffix(b"\r")).hexdigest()
            if not index_row(db, meta, row, f"{meta['run_id']}:{index}:{digest}"):
                gaps += 1

        meta, _, _ = _verified_result_rows(_find_meta(run), limit=0, visit=observe)
        if (
            meta.get("tenant_binding") != {"state": "bound", "sha256": tenant}
            or meta.get("command") != "incidents show"
            or "alerts" not in meta.get("expand", [])
        ):
            raise ConflictError("Indexing requires a same-tenant expanded incident result.")
        _remember(db, meta, gaps, passive=True)
        return {"status": "success", "run_id": meta["run_id"], "unattributed_rows": gaps}


def list_inquiries(ctx):
    with inquiry_transaction(ctx.config.tenant_id) as (db, _):
        rows = [
            {"inquiry_id": ident, "objective": objective, "root_state": state, "revision": revision}
            for ident, objective, state, revision in db.execute(
                "SELECT i.id,q.objective,q.state,i.revision FROM inquiry i JOIN question q "
                "ON q.inquiry_id=i.id WHERE q.parent_id IS NULL ORDER BY i.rowid DESC"
            )
        ]
        owners = [row["inquiry_id"] for row in rows]
        artifact = write_result(
            rows,
            command="inquiry list",
            tenant_id=ctx.config.tenant_id,
            extra_metadata={"inquiry_owners": owners},
        )
        db.executemany(
            "INSERT INTO derived_result VALUES (?,?)",
            ((owner, artifact.receipt.run_id) for owner in owners),
        )
        return artifact


def delete_inquiry(ctx, inquiry, yes):
    from xdr_cli.commands.results_cmd import _load_meta, _metadata_paths

    with inquiry_transaction(ctx.config.tenant_id) as (db, tenant):
        if not db.execute("SELECT 1 FROM inquiry WHERE id=?", (inquiry,)).fetchone():
            raise LocalNotFoundError("inquiry", inquiry)
        # Include published artifacts even if an interruption preceded their DB registration.
        registered = {
            r
            for (r,) in db.execute(
                "SELECT run_id FROM derived_result WHERE inquiry_id=?", (inquiry,)
            )
        }
        artifacts = []
        for path in _metadata_paths():
            meta = _load_meta(path)
            if meta.get("run_id") not in registered and inquiry not in meta.get(
                "inquiry_owners", []
            ):
                continue
            run = meta.get("run_id")
            if (
                meta.get("command") not in {"inquiry list", "inquiry view"}
                or meta.get("tenant_binding") != {"state": "bound", "sha256": tenant}
                or path.name != f"{run}.meta.json"
                or inquiry not in meta["inquiry_owners"]
            ):
                raise ArtifactError(
                    "Inquiry-owned result metadata does not match its registration."
                )
            data = path.with_name(f"{run}.jsonl")
            if data.exists():
                _verified_result_rows(path, limit=0)
            artifacts.append((data, path))
        if yes:
            for data, meta_path in artifacts:
                data.unlink(missing_ok=True)
                meta_path.unlink()
            db.execute("DELETE FROM inquiry WHERE id=?", (inquiry,))
            db.execute(
                "DELETE FROM indexed_source WHERE passive=0 AND run_id NOT IN "
                "(SELECT run_id FROM attachment)"
            )
            db.execute(
                "DELETE FROM sighting WHERE run_id NOT IN (SELECT run_id FROM indexed_source)"
            )
        return {
            "status": "success",
            "inquiry_id": inquiry,
            "deleted": yes,
            "owned_bundles": len(artifacts),
        }


def retire_sources_locked(run_ids):
    """Called by prune with the evidence lock held, before deleting the source bytes."""
    if not run_ids:
        return
    for path in (get_config_home() / "inquiries").glob("*/inquiries.sqlite"):
        try:
            with closing(sqlite3.connect(path)) as db, db:
                for table in ("sighting", "indexed_source"):
                    db.executemany(f"DELETE FROM {table} WHERE run_id=?", ((r,) for r in run_ids))
        except sqlite3.Error as exc:
            raise ArtifactError("Could not retire inquiry sightings before pruning.") from exc
