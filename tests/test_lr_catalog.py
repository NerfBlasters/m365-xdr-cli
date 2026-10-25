"""Pinned Live Response command catalog invariants."""
from __future__ import annotations

import pytest

from xdr_cli.live_response.catalog import (
    DOCS,
    FRONTEND,
    LIBRARY_NAME_PATTERN,
    PINNED,
    PORTAL,
    build_alias_index,
    catalog,
)
from xdr_cli.live_response.models import MUTATION_POLICY_RISKS, LRCommandSpec, LRRisk

# Every command in Microsoft's documented basic and advanced tables.
DOCUMENTED = {
    "cd", "cls", "connect", "connections", "dir", "drivers", "fg", "fileinfo", "findfile",
    "getfile", "help", "jobs", "persistence", "processes", "registry", "scheduledtasks",
    "services", "startupfolders", "status", "trace", "analyze", "collect", "isolate",
    "release", "run", "library", "putfile", "remediate", "scan", "undo",
}
# Known to the shipped portal console behind a feature gate.
FRONTEND_ONLY = {"processdump"}


def test_catalog_covers_every_documented_command_once():
    names = [spec.name for spec in catalog()]
    assert len(names) == len(set(names))
    assert set(names) == DOCUMENTED | FRONTEND_ONLY


def test_each_entry_has_evidence_platforms_and_honest_local_notes():
    for spec in catalog():
        assert spec.platforms, spec.name
        assert spec.evidence in {DOCS, PORTAL, FRONTEND}, spec.name
        assert (spec.risk is LRRisk.LOCAL) == (spec.local_note is not None), spec.name
        assert all(alias == alias.lower() for alias in spec.aliases), spec.name


def test_only_reads_and_local_commands_skip_confirmation():
    for spec in catalog():
        risks = {spec.risk, *(risk for _, _, risk in spec.risk_by_value)}
        for risk in risks:
            assert (risk in MUTATION_POLICY_RISKS) == (risk not in {LRRisk.LOCAL, LRRisk.READ})
    state_changing = {s.name for s in catalog() if s.risk in MUTATION_POLICY_RISKS}
    assert state_changing == {
        "getfile", "analyze", "collect", "processdump", "putfile", "run", "remediate", "undo",
        "isolate", "release", "scan",
    }


def test_official_api_types_are_limited_to_the_three_documented_commands():
    assert {s.name: s.official_type for s in catalog() if s.official_type} == {
        "getfile": "GetFile", "putfile": "PutFile", "run": "RunScript",
    }


def test_alias_collisions_are_rejected():
    first = LRCommandSpec("a", LRRisk.READ, frozenset(), DOCS, "", aliases=("x",))
    second = LRCommandSpec("b", LRRisk.EXECUTE, frozenset(), DOCS, "", aliases=("X",))
    with pytest.raises(ValueError):
        build_alias_index([first, second])
    assert PINNED["get"].name == "getfile"


@pytest.mark.parametrize("name,ok", [
    ("get proc.ps1", True), ("collect-logs_v2.sh", True), ("a", False), ("x.ps1 ", False),
    ("../x.ps1", False), ("a/b.sh", False), ("a\\b.ps1", False), (".hidden", False),
])
def test_library_name_policy(name, ok):
    assert bool(LIBRARY_NAME_PATTERN.match(name)) is ok
