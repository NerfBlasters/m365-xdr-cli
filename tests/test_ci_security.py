"""Negative cases for the CI gates that prevent incomplete scans passing."""
import copy
import importlib.util
from pathlib import Path

import pytest


def load_script(name):
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guarddog = load_script("guarddog_scan")
dist = load_script("check_dist")
EXPECTED = {("example-package", "1.0")}
CLEAN = [{"dependency": "example_package", "version": "1.0", "result": {
    "issues": 0, "errors": {}, "results": {"rule": {}},
    "risk_score": {"label": "no_risks_detected"},
}}]


def test_guarddog_requires_exact_version_coverage():
    assert guarddog.validate_scan(CLEAN, EXPECTED) == []
    with pytest.raises(ValueError, match="Unexpected"):
        guarddog.validate_scan(CLEAN, {("example-package", "2.0")})
    with pytest.raises(ValueError, match="not scanned"):
        guarddog.validate_scan(CLEAN, EXPECTED | {("missing", "1.0")})
    with pytest.raises(ValueError, match="duplicate"):
        guarddog.validate_scan(CLEAN * 2, EXPECTED)


@pytest.mark.parametrize("rows", [[], {}, None, [None]])
def test_guarddog_never_accepts_empty_or_malformed_output(rows):
    with pytest.raises((ValueError, TypeError, KeyError)):
        guarddog.validate_scan(rows, EXPECTED)


@pytest.mark.parametrize("key,value", [
    ("errors", {"download": "timeout"}), ("errors", None),
    ("results", {}), ("results", {"rule": None}), ("results", []),
    ("risk_score", {}), ("risk_score", {"label": "unknown"}),
    ("issues", -1), ("issues", False),
])
def test_guarddog_blocks_incomplete_scan_records(key, value):
    rows = copy.deepcopy(CLEAN)
    rows[0]["result"][key] = value
    with pytest.raises((ValueError, TypeError, KeyError)):
        guarddog.validate_scan(rows, EXPECTED)


@pytest.mark.parametrize("label", ["suspicious", "high_risk"])
def test_guarddog_blocks_native_correlated_risks(label):
    rows = copy.deepcopy(CLEAN)
    rows[0]["result"]["risk_score"]["label"] = label
    assert guarddog.validate_scan(rows, EXPECTED) == [f"example-package==1.0: {label}"]


@pytest.mark.parametrize("text", ["", "example>=1", "example @ https://example.com/x.whl"])
def test_guarddog_rejects_unpinned_or_direct_url_scan_inputs(text):
    with pytest.raises(ValueError):
        guarddog.expected_packages(text)


@pytest.mark.parametrize("name", [
    "project/docs/superpowers/private.md", "project/.env", "project/token_cache.json",
    "project/.claude/notes.md", "../escape", "/absolute", "project/certificate.pfx",
])
def test_distribution_rejects_private_or_unsafe_members(name):
    with pytest.raises(ValueError):
        dist.check_names([name])


def exception_policy():
    return {"scanner_version": "3.2.0", "exceptions": [{
        "package": "example-package", "version": "1.0",
        "findings_sha256": guarddog.fingerprint(CLEAN[0]["result"]),
        "reviewed_on": "2026-09-23", "expires": "2026-10-23",
        "reason": "Reviewed test fixture", "evidence": ["https://example.com/review"],
    }]}


def test_exceptions_require_exact_version_and_findings():
    from datetime import date

    rows = copy.deepcopy(CLEAN)
    rows[0]["result"]["risk_score"]["label"] = "high_risk"
    policy = exception_policy()
    policy["exceptions"][0]["findings_sha256"] = guarddog.fingerprint(rows[0]["result"])
    blocked = guarddog.validate_scan(rows, EXPECTED)
    today = date(2026, 9, 24)
    assert guarddog.apply_exceptions(rows, blocked, policy, today) == []
    rows[0]["version"] = "2.0"
    newer = guarddog.validate_scan(rows, {("example-package", "2.0")})
    assert guarddog.apply_exceptions(rows, newer, policy, today) == newer
    rows[0]["version"] = "1.0"
    rows[0]["result"]["results"]["new-threat"] = [{"code": "new suspicious code"}]
    assert guarddog.apply_exceptions(rows, blocked, policy, today) == blocked


@pytest.mark.parametrize("change", ["expired", "future", "long", "duplicate", "reason", "hash"])
def test_exception_policy_fails_closed(change):
    from datetime import date

    policy = exception_policy()
    entry = policy["exceptions"][0]
    if change == "expired":
        entry["expires"] = "2026-09-24"
    elif change == "future":
        entry["reviewed_on"] = "2026-10-01"
    elif change == "long":
        entry["expires"] = "2027-12-31"
    elif change == "duplicate":
        policy["exceptions"].append(copy.deepcopy(entry))
    elif change == "reason":
        entry["reason"] = " "
    else:
        entry["findings_sha256"] = "invalid"
    with pytest.raises(ValueError):
        guarddog.apply_exceptions(CLEAN, [], policy, date(2026, 9, 24))
