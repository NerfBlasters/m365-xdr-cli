"""Question-led investigation checks through Click's normal command entry points."""

import json
from pathlib import Path

from click.testing import CliRunner

from xdr_cli.main import _redact_argv, app
from xdr_cli.results import write_result


def test_inquiry_loop_verifies_evidence_and_tracks_downstream_impact(monkeypatch, tmp_path):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('tenant_id="tenant-a"\n')
    runner = CliRunner()

    def call(*args, code=0):
        result = runner.invoke(app, list(args))
        assert result.exit_code == code, (result.stdout, result.stderr, result.exception)
        return json.loads(result.stdout.splitlines()[0])

    source = write_result([{"id": "click-1"}], command="hunt run", tenant_id="tenant-a")
    run = source.receipt.run_id
    opened = call("inquiry", "open", "Assess downstream impact", "--source", run)
    inquiry, q = opened["inquiry_id"], opened["question_id"]
    again = call("inquiry", "attach", inquiry, run, "--question", q)
    assert again["revision"] == opened["revision"]
    ref = call("results", "cite", run, "--line", "1")["data"]["citation"]
    note = call(
        "inquiry",
        "note",
        inquiry,
        "Message click",
        "--question",
        q,
        "--cite",
        ref,
        "--signal",
        "permitted-click",
    )
    assert note["citations"][0]["identifying_fields"] == {"id": "click-1"}
    view = call("inquiry", "view", inquiry)
    rows = [json.loads(line) for line in Path(view["data_path"]).read_text().splitlines()]
    checks = [row for row in rows if row["record_type"] == "impact-check"]
    assert len(checks) == 3
    call("inquiry", "finish", inquiry, code=13)
    for check in checks:
        # Analyst explicitly restricted the fixture to message tracing.
        updated = call("inquiry", "check", inquiry, check["id"], "--skip-reason", "Trace only")
    call(
        "inquiry",
        "answer",
        inquiry,
        "Click confirmed; investigation limited to message trace.",
        "--question",
        q,
        "--state",
        "answered",
        "--basis",
        note["note_id"],
        "--revision",
        str(updated["revision"]),
    )
    assert call("inquiry", "finish", inquiry)["root_state"] == "answered"
    Path(source.receipt.data_path).write_text("{}\n")
    call("inquiry", "finish", inquiry, code=12)


def test_wrong_tenant_source_rolls_back_open(monkeypatch, tmp_path):
    import sqlite3

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('tenant_id="tenant-a"\n')
    run = write_result([], command="alerts show", tenant_id="tenant-b").receipt.run_id
    runner = CliRunner()
    assert runner.invoke(app, ["inquiry", "open", "Initial"]).exit_code == 0
    result = runner.invoke(app, ["inquiry", "open", "Private hypothesis", "--source", run])
    assert result.exit_code == 13, result.output
    db = sqlite3.connect(next(tmp_path.glob("inquiries/*/*.sqlite")))
    try:
        assert db.execute("SELECT objective FROM question").fetchall() == [("Initial",)]
    finally:
        db.close()
    assert _redact_argv(["inquiry", "open", "Private hypothesis"]) == ["inquiry", "open"]


def test_permitted_navigation_opens_two_checks_without_agent_interpretation(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('tenant_id="example"\n')
    source = write_result(
        [{"ActionType": "ClickAllowed"}],
        command="hunt run",
        tenant_id="example",
        physical_lineage_table="UrlClickEvents",
    )
    runner = CliRunner()
    root = json.loads(
        runner.invoke(
            app, ["inquiry", "open", "Investigate this alert", "--source", source.receipt.run_id]
        ).stdout
    )
    view = runner.invoke(app, ["inquiry", "view", root["inquiry_id"]])
    artifact = json.loads(view.stdout.splitlines()[0])
    rows = [json.loads(line) for line in Path(artifact["data_path"]).read_text().splitlines()]
    triggers = [r for r in rows if r.get("trigger")]
    assert len(triggers) == 2
    assert all(r["trigger"].startswith(f"{source.receipt.run_id}:0:") for r in triggers)
    blocked = runner.invoke(
        app,
        [
            "inquiry",
            "answer",
            root["inquiry_id"],
            "Identify the user",
            "--state",
            "needs-analyst",
            "--question",
            root["question_id"],
            "--revision",
            str(root["revision"]),
        ],
    )
    assert blocked.exit_code == 0, blocked.output
    finish = runner.invoke(app, ["inquiry", "finish", root["inquiry_id"]])
    assert finish.exit_code == 15
    assert json.loads(finish.stdout)["requests"][0]["request"] == "Identify the user"


def test_packaged_checks_match_playbook_front_matter():
    from xdr_cli.inquiries import playbook_catalog

    root = Path(__file__).resolve().parents[1] / "playbooks"
    expected = {}
    for path in root.glob("*.md"):
        if path.name in {"README.md", "index.md"}:
            continue
        header = path.read_text().splitlines()
        assert header[0] == "---" and header[2] == "---"
        expected[path.stem] = json.loads(header[1].removeprefix("inquiry: "))
    assert playbook_catalog() == expected


def test_bound_hunt_uses_receipt_and_recovers_locally(monkeypatch, tmp_path):
    from unittest.mock import AsyncMock, patch

    from xdr_cli.exceptions import ArtifactError
    from xdr_cli.hunting_result import HuntingResult

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('tenant_id="test"\n')
    runner = CliRunner()
    opened = json.loads(runner.invoke(app, ["inquiry", "open", "Assess a click"]).stdout)
    inquiry, q = opened["inquiry_id"], opened["question_id"]
    args = ["hunt", "run", "UrlClickEvents | take 1", "--inquiry", inquiry]
    fake = HuntingResult([], [{"ActionType": "ClickAllowed"}], {})
    query = AsyncMock(return_value=fake)
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.run_query", new=query),
    ):
        assert runner.invoke(app, args).exit_code == 6
        query.assert_not_called()
        bound = runner.invoke(app, [*args, "--question", q])
        assert bound.exit_code == 0, bound.output
        receipt = json.loads(bound.stdout.splitlines()[0])
        assert receipt["context"]["inquiry_command"] == opened["inquiry_command"]
        assert receipt["context"]["preview_citations"][0].startswith(receipt["run_id"] + ":0:")
        with patch("xdr_cli.commands.hunt_cmd.attach_run", side_effect=ArtifactError("disk full")):
            partial = runner.invoke(app, [*args, "--question", q])
        assert partial.exit_code == 14
        recovery = json.loads(partial.stdout.splitlines()[-1])["error"]["help_command"]
        assert runner.invoke(app, recovery.split()[1:]).exit_code == 0
        assert query.await_count == 2


def test_private_views_removed_without_deleting_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('tenant_id="test"\n')
    source = write_result([], command="hunt run", tenant_id="test")
    runner = CliRunner()
    opened = runner.invoke(
        app, ["inquiry", "open", "Private text", "--source", source.receipt.run_id]
    )
    inquiry = json.loads(opened.stdout)["inquiry_id"]
    view = runner.invoke(app, ["inquiry", "view", inquiry])
    receipt = json.loads(view.stdout.splitlines()[0])
    result = runner.invoke(app, ["inquiry", "delete", inquiry, "--yes"])
    assert result.exit_code == 0, result.output
    assert not Path(receipt["data_path"]).exists()
    assert Path(source.receipt.data_path).exists()


def test_click_library_checks_require_detail_and_exact_query(tmp_path, monkeypatch):
    from xdr_cli.queries import load_query, query_source_hash

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('tenant_id="example"\n')
    runner = CliRunner()
    for mode, modified, expected in [
        ("detail", False, 2),
        ("summary", False, 0),
        ("detail", True, 0),
    ]:
        params = {
            "mode": mode,
            "account_upn": "test@example.org",
            "start": "2026-01-01",
            "end": "2026-01-02",
        }
        name = "qry_url_clicks"
        query = load_query(name, **params)
        source = write_result(
            [{"ActionType": "ClickAllowed"}],
            command="library run",
            tenant_id="example",
            library_entry=name,
            resolved_parameters=params,
            source_hash=query_source_hash(name),
            query=query + " | take 1" if modified else query,
        )
        result = runner.invoke(
            app, ["inquiry", "open", "Investigate", "--source", source.receipt.run_id]
        )
        assert result.exit_code == 0, result.output
        view = runner.invoke(app, ["inquiry", "view", json.loads(result.stdout)["inquiry_id"]])
        assert view.exit_code == 0, view.output
        path = Path(json.loads(view.stdout.splitlines()[0])["data_path"])
        assert (
            sum(bool(json.loads(row).get("trigger")) for row in path.read_text().splitlines())
            == expected
        )


def test_passive_memory_reports_provider_relation_and_respects_opt_out(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    config = tmp_path / "config.toml"
    config.write_text('tenant_id="example"\n')
    source = write_result(
        [
            {
                "record_type": "evidence",
                "@odata.type": "#microsoft.graph.security.mailMessageEvidence",
                "networkMessageId": "11111111-2222-3333-4444-555555555555",
                "recipientEmailAddress": "analyst@example.org",
            }
        ],
        command="incidents show",
        tenant_id="example",
        extra_metadata={"expand": ["alerts"]},
    )
    runner = CliRunner()
    result = runner.invoke(app, ["inquiry", "index", source.receipt.run_id])
    assert result.exit_code == 0, result.output
    inquiry = json.loads(runner.invoke(app, ["inquiry", "open", "Assess activity"]).stdout)
    args = [
        "inquiry",
        "view",
        inquiry["inquiry_id"],
        "--entity",
        "smtp:analyst@example.org",
        "--prior",
    ]

    def relations():
        view = runner.invoke(app, args)
        assert view.exit_code == 0, view.output
        path = Path(json.loads(view.stdout.splitlines()[0])["data_path"])
        rows = map(json.loads, path.read_text().splitlines())
        return [row for row in rows if row["record_type"] == "entity-relation"]

    (relation,) = relations()
    assert relation["scope"] == "prior" and relation["recipient"] == args[-2]
    assert relation["citation"].startswith(source.receipt.run_id + ":0:")
    config.write_text('tenant_id="example"\nentity_memory=false\n')
    assert not relations()
    assert runner.invoke(app, ["inquiry", "index", source.receipt.run_id]).exit_code == 13


def test_failed_and_empty_reads_keep_material_question_and_finish_shows_limit(
    monkeypatch, tmp_path
):
    from unittest.mock import AsyncMock, patch
    from xdr_cli.hunting_result import HuntingResult

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text('tenant_id="test"\n')
    runner = CliRunner()

    def run(*args, code=0):
        result = runner.invoke(app, list(args))
        assert result.exit_code == code, result.output
        return json.loads(result.stdout.splitlines()[0])

    def view(*args):
        receipt = run("inquiry", "view", inquiry, *args)
        return list(map(json.loads, Path(receipt["data_path"]).read_text().splitlines()))

    source = write_result([{"id": "event"}], command="alerts show", tenant_id="test")
    opened = run(
        "inquiry", "open", "Determine observed activity", "--source", source.receipt.run_id
    )
    inquiry, root = opened["inquiry_id"], opened["question_id"]
    child_args = ["--inquiry", inquiry, "--question", root, "--ask", "Who else was affected?"]
    failure = run("library", "run", "missing_query", *child_args, code=5)
    questions = [row for row in view() if row.get("parent_id") == root]
    (child,) = questions
    assert child["state"] == "open"
    failures = [r for r in view("--question", child["id"]) if r["record_type"] == "failed-read"]
    assert failures[0]["error_code"] == failure["error"]["code"]
    fake = AsyncMock(return_value=HuntingResult([], [], {}))
    with (
        patch("xdr_cli.commands.hunt_cmd.AuthManager"),
        patch("xdr_cli.commands.hunt_cmd.run_query", new=fake),
    ):
        empty = run("hunt", "run", "DeviceEvents | take 1", *child_args)
    assert empty["rows"] == 0 and empty["context"]["question_id"] == child["id"]
    assert empty["context"]["investigation_hint"]
    run("inquiry", "finish", inquiry, code=13)
    ref = run("results", "cite", source.receipt.run_id, "--line", "1")["data"]["citation"]
    note = run(
        "inquiry",
        "note",
        inquiry,
        "One device reported activity",
        "--question",
        root,
        "--cite",
        ref,
    )
    checked = run(
        "inquiry", "check", inquiry, opened["impact_check_id"], "--basis", note["note_id"]
    )
    limit = "Alternate endpoint source was empty. Other devices lack telemetry in this window."
    assessed = run(
        "inquiry",
        "answer",
        inquiry,
        limit,
        "--question",
        child["id"],
        "--state",
        "inconclusive",
        "--revision",
        str(checked["revision"]),
    )
    run(
        "inquiry",
        "answer",
        inquiry,
        "Activity confirmed on the reporting device.",
        "--question",
        root,
        "--state",
        "answered",
        "--basis",
        note["note_id"],
        "--revision",
        str(assessed["revision"]),
    )
    done = run("inquiry", "finish", inquiry)
    assert done["limitations"] == [
        {"question": child["objective"], "question_id": child["id"], "reason": limit}
    ]
    for args in (["--ask", "private question"], ["--ask=private question"]):
        assert "private question" not in str(_redact_argv(["hunt", "run", *args], "hunt run"))


def test_existing_inquiry_survives_read_failure_schema_upgrade(tmp_path, monkeypatch):
    import sqlite3
    from xdr_cli.inquiries import _SCHEMA, inquiry_transaction
    from xdr_cli.results import tenant_fingerprint

    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    directory = tmp_path / "inquiries" / tenant_fingerprint("example")
    directory.mkdir(parents=True)
    db = sqlite3.connect(directory / "inquiries.sqlite")
    try:
        with db:
            for sql in _SCHEMA:
                db.execute(sql)
            db.execute("INSERT INTO inquiry VALUES ('existing',17)")
            db.execute("PRAGMA user_version=1")
    finally:
        db.close()
    for _ in range(2):
        with inquiry_transaction("example") as (db, _tenant):
            assert db.execute("PRAGMA user_version").fetchone() == (2,)
            assert db.execute("SELECT * FROM inquiry").fetchall() == [("existing", 17)]
            assert db.execute("SELECT count(*) FROM read_failure").fetchone() == (0,)
