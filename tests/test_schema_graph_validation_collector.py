from __future__ import annotations

import json
import subprocess
import sys

from scripts import collect_schema_graph_validation as collector


def test_run_reports_progress_and_writes_sanitized_debug(tmp_path, monkeypatch, capsys):
    error = {
        "status": "error",
        "error": {
            "type": "QueryError",
            "code": "QUERY_UNKNOWN_COLUMN",
            "exit_code": 5,
            "retryable": False,
            "message": "unknown probe column",
            "invalid": {"value": "user@example.invalid"},
            "request_ids": {"request-id": "private-request"},
            "original": {
                "type": "BadRequest",
                "message": "unknown probe column",
                "detail": {
                    "request-id": "private-request",
                    "client-request-id": "private-client-request",
                },
            },
        },
    }

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            ["xdr", "schema", "observe", "Table.Column"],
            5,
            stdout=json.dumps(error) + "\n",
            stderr="target user@example.invalid failed\n",
        )

    monkeypatch.setattr(collector.subprocess, "run", fake_run)
    destination = tmp_path / "observe"
    debug_path = tmp_path / "collector.debug.jsonl"

    result = collector._run(
        [
            "xdr",
            "schema",
            "observe",
            "Table.Column",
            "--private-debug-output",
            "/private/path/debug.jsonl",
        ],
        destination=destination,
        environment={},
        debug_path=debug_path,
        progress_index=3,
        progress_total=8,
    )

    assert result["exit_code"] == 5
    assert result["error"]["code"] == "QUERY_UNKNOWN_COLUMN"
    assert result["argv"][-1] == "<private-debug-path>"
    progress = capsys.readouterr().err
    assert "[03/08] RUN" in progress
    assert "[03/08] FAIL" in progress
    assert "QUERY_UNKNOWN_COLUMN" in progress
    captured = destination.with_suffix(".stdout.jsonl").read_text(encoding="utf-8")
    debug = debug_path.read_text(encoding="utf-8")
    assert "private-request" not in captured
    assert "private-client-request" not in captured
    assert "unknown probe column" not in captured
    assert "user@example.invalid" not in captured
    assert "unknown probe column" not in destination.with_suffix(
        ".stderr.txt"
    ).read_text()
    assert "user@example.invalid" not in destination.with_suffix(
        ".stderr.txt"
    ).read_text()
    assert "/private/path" not in debug
    assert '"duration_ms"' in debug


def test_main_wires_progress_and_explicit_private_debug(tmp_path, monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return {
            "argv": collector._public_argv(argv),
            "exit_code": 0,
            "receipt_run_id": None,
            "duration_ms": 1,
            "error": None,
        }

    output = tmp_path / "bundle"
    monkeypatch.setattr(collector, "_run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "collect_schema_graph_validation.py",
            "--output-dir",
            str(output),
            "--include-private-debug",
        ],
    )

    assert collector.main() == 0
    expected = 2 + (2 * len(collector.DEFAULT_SOURCES))
    assert len(calls) == expected
    assert [item[1]["progress_index"] for item in calls] == list(range(1, expected + 1))
    observe_calls = [
        argv for argv, _kwargs in calls if "--private-debug-output" in argv
    ]
    assert len(observe_calls) == len(collector.DEFAULT_SOURCES)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["contains_seed_values"] is True
    assert manifest["private_debug"] is True
