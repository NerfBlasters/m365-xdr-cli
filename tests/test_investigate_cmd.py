"""Tests for investigate command."""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from xdr_cli.commands.investigate_cmd import (
    _build_recommended_actions,
    _decode_encoded_powershell,
    _extract_entities,
)
from xdr_cli.main import app, run

runner = CliRunner()

# Valid 64-char hex SHA256
_VALID_SHA256 = "a" * 64

MOCK_INCIDENT = {
    "id": "4421",
    "displayName": "Multi-stage attack",
    "severity": "high",
    "status": "active",
    "alerts": [
        {
            "id": "al-1",
            "title": "Suspicious PowerShell",
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.deviceEvidence",
                    "deviceDnsName": "WS-01",
                },
                {
                    "@odata.type": "#microsoft.graph.security.fileEvidence",
                    "fileDetails": {"sha256": _VALID_SHA256},
                },
            ],
        }
    ],
}


@patch("xdr_cli.commands.investigate_cmd.run_query")
@patch("xdr_cli.commands.investigate_cmd.AuthManager")
@patch("xdr_cli.commands.investigate_cmd.XDRClient")
def test_investigate_auto_enrich_json(
    mock_client_cls, mock_auth_cls, mock_run_query, tmp_path, monkeypatch
):
    # `investigate` is gated on session presence (Task 8). Set up a session.
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    (home / "queries").mkdir()
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    started = {
        "kind": "session_started", "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z", "session_id": "jd-1",
        "upn": "jane.doe@corp.com", "label": None, "learning_mode": False,
    }
    (home / "sessions" / "jd-1.jsonl").write_text(json.dumps(started) + "\n")
    monkeypatch.setenv("XDR_SESSION", "jd-1")

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=MOCK_INCIDENT)
    mock_client.close = AsyncMock()
    mock_client_cls.return_value = mock_client

    from xdr_cli.api.hunting import HuntingResult

    mock_run_query.return_value = HuntingResult(
        schema=[], results=[{"DeviceName": "WS-01"}], stats={}
    )

    result = runner.invoke(app, ["--quiet", "investigate", "--auto-enrich", "4421"])
    assert result.exit_code == 0
    receipt = json.loads(result.output.splitlines()[0])
    parsed = [
        json.loads(line)
        for line in Path(receipt["data_path"]).read_text().splitlines()
    ]
    assert any(
        row["record_type"] == "entity"
        and row["entity_type"] == "devices"
        and row["value"] == "WS-01"
        for row in parsed
    )
    assert any(row["record_type"] == "enrichment" for row in parsed)
    # High-severity incident with no falsePositive classification -> containment emitted.
    assert any(
        row["record_type"] == "recommended_action"
        and row["action_group"] == "contain"
        and row["step"] == "isolate"
        for row in parsed
    )
    # Investigation steps always emitted.
    assert any(
        row["record_type"] == "recommended_action"
        and row["action_group"] == "investigate_first"
        and row["step"] == "inspect_process_tree"
        for row in parsed
    )


def test_extract_entities_rejects_kql_injection_in_hostname():
    """Device names with KQL injection characters are rejected."""
    incident = {
        "alerts": [
            {
                "evidence": [
                    {
                        "@odata.type": "#microsoft.graph.security.deviceEvidence",
                        "deviceDnsName": "evil' | union DeviceLogonEvents //",
                    },
                    {
                        "@odata.type": "#microsoft.graph.security.deviceEvidence",
                        "deviceDnsName": "LEGIT-WS-01",
                    },
                ]
            }
        ]
    }
    entities = _extract_entities(incident)
    assert "LEGIT-WS-01" in entities["devices"]
    assert "evil' | union DeviceLogonEvents //" not in entities["devices"]


def test_extract_entities_rejects_bad_sha256():
    """SHA256 values that aren't 64 hex chars are rejected."""
    incident = {
        "alerts": [
            {
                "evidence": [
                    {
                        "@odata.type": "#microsoft.graph.security.fileEvidence",
                        "fileDetails": {"sha256": "not-a-hash"},
                    },
                    {
                        "@odata.type": "#microsoft.graph.security.fileEvidence",
                        "fileDetails": {"sha256": _VALID_SHA256},
                    },
                ]
            }
        ]
    }
    entities = _extract_entities(incident)
    assert _VALID_SHA256 in entities["file_hashes"]
    assert "not-a-hash" not in entities["file_hashes"]


def test_containment_gated_on_medium_severity():
    """Medium-severity incidents should NOT emit containment actions."""
    incident = {
        "id": "1",
        "severity": "medium",
        "classification": "unknown",
        "alerts": [],
    }
    entities = {
        "devices": {"WS-01"},
        "device_ids": {"WS-01": "a" * 40},
        "users": set(),
        "file_hashes": set(),
        "ips": set(),
        "decoded_commands": [],
    }
    rec = _build_recommended_actions(incident, entities)
    assert rec["contain"] == []
    assert rec["containment_gated"] is True
    assert "medium" in rec["gating_reason"].lower()
    # Investigation steps still emitted.
    assert any(s["step"] == "inspect_process_tree" for s in rec["investigate_first"])


def test_containment_skipped_on_informational_expected_activity():
    """informationalExpectedActivity skips containment even at high severity.

    The detection fires correctly but the activity is benign — containment
    would be harmful. Covers classifications like securityTesting and
    legitimate admin scripts.
    """
    incident = {
        "id": "3",
        "severity": "high",
        "classification": "informationalExpectedActivity",
        "alerts": [],
    }
    entities = {
        "devices": {"WS-01"},
        "device_ids": {},
        "users": set(),
        "file_hashes": set(),
        "ips": set(),
        "decoded_commands": [],
    }
    rec = _build_recommended_actions(incident, entities)
    assert rec["contain"] == []
    assert "informationalexpectedactivity" in rec["gating_reason"].lower()


def test_containment_skipped_when_false_positive():
    """Confirmed false positives skip containment even at high severity."""
    incident = {
        "id": "2",
        "severity": "high",
        "classification": "falsePositive",
        "alerts": [],
    }
    entities = {
        "devices": {"WS-01"},
        "device_ids": {},
        "users": set(),
        "file_hashes": set(),
        "ips": set(),
        "decoded_commands": [],
    }
    rec = _build_recommended_actions(incident, entities)
    assert rec["contain"] == []
    assert "falsepositive" in rec["gating_reason"].lower().replace(" ", "")


def test_decode_encoded_powershell():
    """Base64 -EncodedCommand payloads are decoded to readable UTF-16LE text."""
    # Write-Host 'hi' in UTF-16LE then base64
    cmdline = "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAaABpACcA"
    decoded = _decode_encoded_powershell(cmdline)
    assert decoded == "Write-Host 'hi'"


def test_decode_encoded_powershell_ignores_plain_commands():
    """Plain command lines with no -EncodedCommand flag return None."""
    assert _decode_encoded_powershell("powershell.exe Get-Process") is None


def test_extract_entities_accepts_valid_values():
    """Normal entity values pass validation."""
    incident = {
        "alerts": [
            {
                "evidence": [
                    {
                        "@odata.type": "#microsoft.graph.security.deviceEvidence",
                        "deviceDnsName": "DC-01.corp.contoso.com",
                    },
                    {
                        "@odata.type": "#microsoft.graph.security.userEvidence",
                        "userAccount": {"userPrincipalName": "admin@contoso.com"},
                    },
                    {
                        "@odata.type": "#microsoft.graph.security.ipEvidence",
                        "ipAddress": "10.1.4.87",
                    },
                    {
                        "@odata.type": "#microsoft.graph.security.ipEvidence",
                        "ipAddress": "fe80::1",
                    },
                ]
            }
        ]
    }
    entities = _extract_entities(incident)
    assert "DC-01.corp.contoso.com" in entities["devices"]
    assert "admin@contoso.com" in entities["users"]
    assert "10.1.4.87" in entities["ips"]
    assert "fe80::1" in entities["ips"]


# ---------------------------------------------------------------------------
# Recorder integration (Task 4.5): each internal library query writes its own
# invocation record to the session JSONL.
# ---------------------------------------------------------------------------


def _seed_session(home_dir, session_id="jd-1"):
    """Write a session_started header so the recorder lands invocations onto a
    well-formed JSONL. Mirrors the helper in test_main.py / test_hunt_cmd.py."""
    started = {
        "kind": "session_started",
        "schema_version": 1,
        "timestamp": "2026-04-24T00:00:00Z",
        "session_id": session_id,
        "upn": "jane.doe@corp.com",
        "label": None,
        "learning_mode": False,
    }
    (home_dir / "sessions" / f"{session_id}.jsonl").write_text(
        json.dumps(started) + "\n"
    )


@pytest.fixture
def session_home(tmp_path, monkeypatch):
    """tmp XDR_CLI_HOME plus a seeded jd-1 session targeted by XDR_SESSION."""
    home = tmp_path / ".xdr-cli"
    (home / "sessions").mkdir(parents=True, mode=0o700)
    (home / "queries").mkdir()
    monkeypatch.setenv("XDR_CLI_HOME", str(home))
    _seed_session(home)
    monkeypatch.setenv("XDR_SESSION", "jd-1")
    return home


def _read_invocations(home_dir, session_id="jd-1"):
    """Return all invocation records from the session JSONL."""
    records = (
        home_dir / "sessions" / f"{session_id}.jsonl"
    ).read_text().splitlines()
    return [
        json.loads(r) for r in records if json.loads(r).get("kind") == "invocation"
    ]


# A high-severity multi-entity incident: 1 device + 1 file_hash + 1 user.
# Per `_suggest_queries`, this fans out into 4 distinct library queries:
#   qry_process_tree (device), qry_file_hash_scope (sha), ttp_impossible_travel (user),
#   ttp_token_theft_replay (user), ttp_lateral_movement_rdp (device),
#   ttp_encoded_powershell (device). Six in total.
_INCIDENT_FANOUT = {
    "id": "12345",
    "displayName": "Multi-stage attack",
    "severity": "high",
    "status": "active",
    "alerts": [
        {
            "id": "al-1",
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.deviceEvidence",
                    "deviceDnsName": "WS-01",
                },
                {
                    "@odata.type": "#microsoft.graph.security.fileEvidence",
                    "fileDetails": {"sha256": _VALID_SHA256},
                },
                {
                    "@odata.type": "#microsoft.graph.security.userEvidence",
                    "userAccount": {"userPrincipalName": "admin@contoso.com"},
                },
            ],
        }
    ],
}


def test_investigate_records_each_internal_hunt(session_home, monkeypatch):
    """`xdr investigate <id>` produces 1 outer + N inner invocation records.

    The outer record carries `command="investigate"` with `anchor_incident=<id>`.
    Each inner record carries `command="investigate.hunt"`, `library_query`
    populated, and `anchor_incident` matching the outer.
    """
    from xdr_cli.api.hunting import HuntingResult
    from xdr_cli.api.incidents import get_incident as _gi  # noqa: F401

    # Each library query returns a row count we can sum / verify on the outer.
    fake_result = HuntingResult(
        schema=[{"name": "DeviceName", "type": "String"}],
        results=[{"DeviceName": "WS-01"}, {"DeviceName": "WS-02"}],
        stats={"ExecutionTime": "00:00:00.100"},
    )
    monkeypatch.setattr(
        sys, "argv", ["xdr", "investigate", "--auto-enrich", "12345"]
    )
    with (
        patch("xdr_cli.commands.investigate_cmd.AuthManager"),
        patch("xdr_cli.commands.investigate_cmd.XDRClient") as mock_client_cls,
        patch(
            "xdr_cli.commands.investigate_cmd.get_incident",
            new=AsyncMock(return_value=_INCIDENT_FANOUT),
        ),
        patch(
            "xdr_cli.commands.investigate_cmd.run_query",
            new=AsyncMock(return_value=fake_result),
        ),
        pytest.raises(SystemExit),
    ):
        mock_client = AsyncMock()
        mock_client.close = AsyncMock()
        mock_client_cls.return_value = mock_client
        run()

    invocations = _read_invocations(session_home)
    # 1 outer + 6 internal = 7 (qry_process_tree, qry_file_hash_scope,
    # ttp_impossible_travel, ttp_token_theft_replay, ttp_lateral_movement_rdp,
    # ttp_encoded_powershell — see _suggest_queries).
    assert len(invocations) == 7, (
        f"expected 1 outer + 6 internal, got {len(invocations)}"
    )

    # Children flush in temporal order during the run; the outer record is
    # flushed last by ``run()``'s try/finally. So the outer is the LAST
    # invocation in JSONL order, and the children are at positions 0..N-1.
    outer = next(r for r in invocations if r["command"] == "investigate")
    inner = [r for r in invocations if r["command"] != "investigate"]
    assert outer["command"] == "investigate"
    assert outer["anchor_incident"] == "12345"
    # Outer carries the aggregate row_count across all internal queries.
    assert outer["result"]["row_count"] == 12  # 6 queries × 2 rows each

    assert len(inner) == 6
    inner_commands = [r["command"] for r in inner]
    assert all(c == "investigate.hunt" for c in inner_commands), inner_commands
    assert all(r["library_query"] is not None for r in inner)
    assert all(r["anchor_incident"] == "12345" for r in inner)
    # Each inner record has its own kql + tables_referenced.
    assert all(r["kql"] for r in inner)
    # Inner records carry their own result.row_count (the API returned 2 rows).
    assert all(r["result"]["row_count"] == 2 for r in inner)

    # Seq monotonicity: children flush in order seq=1..6, outer at seq=7.
    # Same monotonic axis (sidecar counter), no gaps, no duplicates.
    seqs = [r["seq"] for r in invocations]
    assert seqs == [1, 2, 3, 4, 5, 6, 7], seqs
    # Outer is the LAST seq (flushed by run()'s try/finally after children).
    assert outer["seq"] == 7


def test_investigate_records_failure_mid_fan_out(session_home, monkeypatch):
    """If internal hunt 2 of N raises, hunt 1 is recorded, the outer
    `investigate` reflects failure, and subsequent hunts are NOT attempted.

    The current implementation catches per-query exceptions and writes them
    into ``enrichment_results[query_name] = [{"error": ...}]`` — so the run
    completes successfully (exit 0) and ALL hunts are attempted. This test
    asserts that behavior is preserved end-to-end with the new recorder
    integration: each hunt that raised STILL produces a child invocation
    record (the kql annotation lands pre-API, the result block reflects the
    failure), and the outer investigate exits cleanly.
    """
    from xdr_cli.api.hunting import HuntingResult

    success_result = HuntingResult(
        schema=[{"name": "DeviceName"}],
        results=[{"DeviceName": "WS-01"}],
        stats={"ExecutionTime": "00:00:00.050"},
    )
    call_count = {"n": 0}

    async def _flaky_run_query(client, kql):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("API blew up on the second query")
        return success_result

    # Use a smaller incident: only device → 3 fan-out queries
    # (qry_process_tree, ttp_lateral_movement_rdp, ttp_encoded_powershell).
    incident_device_only = {
        "id": "9999",
        "severity": "high",
        "alerts": [
            {
                "evidence": [
                    {
                        "@odata.type": "#microsoft.graph.security.deviceEvidence",
                        "deviceDnsName": "WS-01",
                    }
                ]
            }
        ],
    }

    monkeypatch.setattr(
        sys, "argv", ["xdr", "investigate", "--auto-enrich", "9999"]
    )
    with (
        patch("xdr_cli.commands.investigate_cmd.AuthManager"),
        patch("xdr_cli.commands.investigate_cmd.XDRClient") as mock_client_cls,
        patch(
            "xdr_cli.commands.investigate_cmd.get_incident",
            new=AsyncMock(return_value=incident_device_only),
        ),
        patch(
            "xdr_cli.commands.investigate_cmd.run_query",
            new=AsyncMock(side_effect=_flaky_run_query),
        ),
        pytest.raises(SystemExit),
    ):
        mock_client = AsyncMock()
        mock_client.close = AsyncMock()
        mock_client_cls.return_value = mock_client
        run()

    invocations = _read_invocations(session_home)
    # 1 outer + 3 internal: each internal is recorded even when the API
    # raised. The failed query lands its error into the `error` field on the
    # invocation record; the kql/library_query/anchor_incident annotations
    # still land because they're written before the API call.
    assert len(invocations) == 4, (
        f"expected 1 outer + 3 internal records (recorder must be fail-soft "
        f"per query), got {len(invocations)}"
    )
    outer = next(r for r in invocations if r["command"] == "investigate")
    inner = [r for r in invocations if r["command"] != "investigate"]
    assert outer["anchor_incident"] == "9999"
    # The durable artifact remains available, but the outer invocation signals
    # partial success so automation cannot mistake failed enrichment for complete.
    assert outer["exit_code"] == 14

    assert all(r["command"] == "investigate.hunt" for r in inner)
    assert all(r["anchor_incident"] == "9999" for r in inner)
    # Failed-query record has error annotation populated; successful ones don't.
    failed = [r for r in inner if r["error"] is not None]
    succeeded = [r for r in inner if r["error"] is None]
    assert len(failed) == 1, (
        f"expected exactly one failed inner, got {len(failed)}: "
        f"{[r['error'] for r in inner]}"
    )
    assert "API blew up" in failed[0]["error"]
    # The two successful queries got their full result block.
    assert len(succeeded) == 2
    assert all(r["result"]["row_count"] == 1 for r in succeeded)
    # Failed inner has exit_code != 0 (set by the helper's fail path).
    assert failed[0]["exit_code"] != 0
    metadata_files = list((session_home / "results").rglob("*.meta.json"))
    assert len(metadata_files) == 1
    metadata = json.loads(metadata_files[0].read_text())
    assert metadata["partial"] is True
    assert metadata["failed_queries"] == ["ttp_lateral_movement_rdp"]
    assert metadata["server_truncation_state"] == "unknown"


def test_investigate_seq_monotonicity_across_nested_invocations(
    session_home, monkeypatch
):
    """Nested invocations share the seq axis with subsequent top-level commands.

    investigate at seq=1, internals at 2/3/4, then a follow-up `session list`
    at seq=5. No gaps, no duplicates.
    """
    from xdr_cli.api.hunting import HuntingResult

    fake_result = HuntingResult(
        schema=[{"name": "DeviceName"}],
        results=[{"DeviceName": "WS-01"}],
        stats={},
    )
    incident_device_only = {
        "id": "5555",
        "severity": "high",
        "alerts": [
            {
                "evidence": [
                    {
                        "@odata.type": "#microsoft.graph.security.deviceEvidence",
                        "deviceDnsName": "WS-01",
                    }
                ]
            }
        ],
    }

    # 1) Run investigate (writes 1 outer + 3 inner = seq 1..4).
    monkeypatch.setattr(
        sys, "argv", ["xdr", "investigate", "--auto-enrich", "5555"]
    )
    with (
        patch("xdr_cli.commands.investigate_cmd.AuthManager"),
        patch("xdr_cli.commands.investigate_cmd.XDRClient") as mock_client_cls,
        patch(
            "xdr_cli.commands.investigate_cmd.get_incident",
            new=AsyncMock(return_value=incident_device_only),
        ),
        patch(
            "xdr_cli.commands.investigate_cmd.run_query",
            new=AsyncMock(return_value=fake_result),
        ),
        pytest.raises(SystemExit),
    ):
        mock_client = AsyncMock()
        mock_client.close = AsyncMock()
        mock_client_cls.return_value = mock_client
        run()

    # 2) Run a follow-up top-level command (browse-only, no network).
    monkeypatch.setattr(sys, "argv", ["xdr", "session", "list"])
    with pytest.raises(SystemExit):
        run()

    invocations = _read_invocations(session_home)
    seqs = [r["seq"] for r in invocations]
    assert seqs == [1, 2, 3, 4, 5], (
        f"seq must be monotonic across nested + subsequent invocations; "
        f"got {seqs}"
    )
    # Final follow-up is the seq=5 record.
    assert invocations[-1]["command"] == "session list"
    assert invocations[-1]["seq"] == 5
