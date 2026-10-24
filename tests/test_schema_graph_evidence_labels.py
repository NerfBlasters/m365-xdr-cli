"""Reviewed semantics and empirical validation are different evidence claims."""

from dataclasses import replace

import pytest

from xdr_cli.commands.schema_cmd import _semantic_step_row
from xdr_cli.schema_graph.loader import load_packaged_graph
from xdr_cli.schema_graph.traversal import pivot


@pytest.mark.parametrize("level,reviewed,empirical,legacy", [
    ("candidate", False, False, False),
    ("observed", False, False, False),
    ("validated", False, True, True),
    ("reviewed", True, False, True),
])
def test_semantic_review_does_not_claim_empirical_validation(level, reviewed, empirical, legacy):
    original = pivot(load_packaged_graph(), "DeviceInfo.DeviceId")[0]
    step = replace(original, evidence_level=level, candidate=level == "candidate")
    row = _semantic_step_row(step, 1)
    assert row["EvidenceLevel"] == level
    assert row["SemanticallyReviewed"] is reviewed
    assert row["EmpiricallyValidated"] is empirical
    assert row["Validated"] is legacy
    assert "Confirmed" not in row


def test_physical_availability_cannot_create_an_empirical_evidence_claim():
    graph = load_packaged_graph()
    source = "field:DeviceInfo.DeviceId"
    available = pivot(graph, "DeviceInfo.DeviceId")[0]
    missing = pivot(graph, "DeviceInfo.DeviceId", available_fields={source})[0]
    for step in (available, missing):
        row = _semantic_step_row(step, 1)
        assert row["SemanticallyReviewed"] is True
        assert row["EmpiricallyValidated"] is False
    assert available.target_available is True
    assert missing.target_available is False
