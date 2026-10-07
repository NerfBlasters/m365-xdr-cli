"""Run pinned GuardDog, retain native reports, and fail closed on incomplete scans.

GuardDog 3.2.0's native exit flag counts capabilities as findings but does not
reject missing packages or rule errors. Gate on its correlated risk labels;
keep all lower-risk observations in the unmodified JSON/SARIF reports.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from copy import deepcopy
from datetime import date
from pathlib import Path
from unittest.mock import patch


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def expected_packages(text: str) -> set[tuple[str, str]]:
    pins = set()
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.+!-]+)", line.strip())
        if not match:
            raise ValueError(f"Expected an exact registry package pin: {line!r}")
        pins.add((canonical(match[1]), match[2]))
    if not pins:
        raise ValueError("No dependencies to scan")
    return pins


def validate_scan(rows: list, expected: set[tuple[str, str]]) -> list[str]:
    """Reject incomplete/schema-drifted output; return native blocking risks."""
    if not isinstance(rows, list) or not rows:
        raise ValueError("Empty or malformed scan output")
    seen, blocked = set(), []
    for row in rows:
        key = (canonical(row["dependency"]), row["version"])
        result = row["result"]
        if key in seen or key not in expected:
            raise ValueError(f"Unexpected or duplicate scanned package: {key}")
        seen.add(key)
        if result["errors"] != {} or not isinstance(result["results"], dict):
            raise ValueError(f"Incomplete scan for {key}: {result.get('errors')}")
        if not result["results"] or not any(v is not None for v in result["results"].values()):
            raise ValueError(f"No rule results for {key}")
        if type(result["issues"]) is not int or result["issues"] < 0:
            raise ValueError(f"Invalid issue count for {key}")
        label = result["risk_score"]["label"]
        if label not in {"no_risks_detected", "low", "suspicious", "high_risk"}:
            raise ValueError(f"Unknown risk label for {key}: {label}")
        if label in {"suspicious", "high_risk"}:
            blocked.append(f"{key[0]}=={key[1]}: {label}")
    if seen != expected:
        raise ValueError(f"Packages not scanned: {sorted(expected - seen)}")
    return blocked



def fingerprint(result: dict) -> str:
    results = dict(result["results"])
    # GuardDog's filesystem traversal order varies between runners. Preserve
    # every binary hash and filename, including duplicates; normalize only order.
    binaries = results.get("bundled_binary")
    header = "Binary file/s detected in package:\n"
    if isinstance(binaries, str) and binaries.startswith(header):
        lines = binaries[len(header):].splitlines()
        matches = [re.fullmatch(r"([a-f0-9]{64}): (.+)", line) for line in lines]
        if lines and all(matches):
            results["bundled_binary"] = header + "\n".join(sorted(
                f"{match[1]}: {', '.join(sorted(match[2].split(', ')))}"
                for match in matches
            ))
    evidence = {"results": results, "risk_score": result["risk_score"]}
    return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()


def apply_exceptions(rows: list, blocked: list[str], policy: dict, today: date) -> list[str]:
    """Waive only exact reviewed observations; never call before validate_scan."""
    if policy["scanner_version"] != "3.2.0":
        raise ValueError("Exception policy must be reviewed for this scanner version")
    exceptions = {}
    for entry in policy["exceptions"]:
        key = (canonical(entry["package"]), entry["version"])
        if key in exceptions or not entry["reason"].strip() or not entry["evidence"]:
            raise ValueError(f"Duplicate or undocumented exception: {key}")
        reviewed = date.fromisoformat(entry["reviewed_on"])
        expires = date.fromisoformat(entry["expires"])
        if not reviewed <= today < expires or (expires - reviewed).days > 90:
            raise ValueError(f"Expired or invalid exception review window: {key}")
        if not re.fullmatch(r"[a-f0-9]{64}", entry["findings_sha256"]):
            raise ValueError(f"Invalid findings fingerprint: {key}")
        exceptions[key] = entry
    remaining = list(blocked)
    for row in rows:
        key = (canonical(row["dependency"]), row["version"])
        result = row["result"]
        marker = f"{key[0]}=={key[1]}: {result['risk_score']['label']}"
        entry = exceptions.get(key)
        if marker in remaining and entry and fingerprint(result) == entry["findings_sha256"]:
            remaining.remove(marker)
            print(f"Reviewed exception: {marker}; expires {entry['expires']}")
    return remaining


def review_reports(
    rows: list, requirements: str, policy: dict, today: date, native_sarif: dict
) -> tuple[dict, dict, list[str]]:
    """Publish the gate's review decisions, retaining native evidence separately.

    Validate completeness and exception policy before producing even an empty
    public report. A changed fingerprint becomes a new review alert; ordinary
    capabilities remain in the native audit reports rather than open alerts.
    """
    blocked = validate_scan(rows, expected_packages(requirements))
    remaining = apply_exceptions(rows, blocked, policy, today)
    if native_sarif.get("version") != "2.1.0" or len(native_sarif.get("runs", [])) != 1:
        raise ValueError("Unexpected native SARIF format")
    public = deepcopy(native_sarif)
    run = public["runs"][0]
    if run["tool"]["driver"]["name"] != "GuardDog-pypi":
        raise ValueError("Unexpected native SARIF tool")
    rule_id = "dependency-review-required"
    run["tool"]["driver"]["rules"] = [{
        "id": rule_id,
        "shortDescription": {"text": "Dependency findings require review"},
        "fullDescription": {"text": (
            "GuardDog classified this exact package/version as suspicious or high risk, "
            "and no current fingerprint-matched review exception accepts it. "
            "This heuristic requires investigation; it is not a confirmed vulnerability."
        )},
        "defaultConfiguration": {"level": "warning"},
        "help": {"text": (
            "Inspect guarddog.json and guarddog.raw.sarif in the dependency-security "
            "workflow artifact. guarddog.review.json records the disposition and "
            "any matching review reason. Scanner errors and incomplete coverage "
            "fail CI and never publish a clean report."
        )},
    }]
    run["results"] = []
    locations = {}
    for line_number, pin in enumerate(requirements.splitlines(), 1):
        name, version = pin.strip().split("==")
        locations.setdefault((canonical(name), version), (line_number, len(name)))
    exceptions = {(canonical(e["package"]), e["version"]): e for e in policy["exceptions"]}
    inventory = []
    for row in sorted(rows, key=lambda r: (canonical(r["dependency"]), r["version"])):
        key = (canonical(row["dependency"]), row["version"])
        result = row["result"]
        marker = f"{key[0]}=={key[1]}: {result['risk_score']['label']}"
        needs_review = marker in remaining
        reviewed = marker in blocked and not needs_review
        observation = {
            "package": key[0], "version": key[1],
            "risk_label": result["risk_score"]["label"],
            "findings_sha256": fingerprint(result),
            "disposition": (
                "needs-review" if needs_review else
                "reviewed-exception" if reviewed else "nonblocking-observation"
            ),
        }
        if reviewed:
            observation["review"] = deepcopy(exceptions[key])
        inventory.append(observation)
        if not needs_review:
            continue
        line_number, name_length = locations[key]
        identity = hashlib.sha256(json.dumps(
            [*key, observation["findings_sha256"]], separators=(",", ":")
        ).encode()).hexdigest()
        run["results"].append({
            "ruleId": rule_id, "ruleIndex": 0, "level": "warning",
            "message": {"text": (
                f"Review required: {marker}. Findings SHA256: "
                f"{observation['findings_sha256']}. See the dependency-security "
                "artifact for complete native observations and review decisions."
            )},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "reports/dependencies.txt"},
                "region": {"startLine": line_number, "endLine": line_number,
                           "startColumn": 1, "endColumn": name_length + 1},
            }}],
            "partialFingerprints": {"guarddog/review-v1": identity},
        })
    return public, {"scanner_version": "3.2.0", "packages": inventory}, remaining


def main(requirements: Path, reports: Path) -> int:
    reports.mkdir(parents=True, exist_ok=True)
    # Never let a failed/incomplete rerun upload a previous clean report.
    for name in ("guarddog.sarif", "guarddog.review.json"):
        (reports / name).unlink(missing_ok=True)
    # Imports stay inside main so fail-closed behavior can be tested without
    # installing scanner dependencies into the application environment.
    from importlib.metadata import version

    import whois
    from guarddog.cli import _get_all_rules
    from guarddog.ecosystems import ECOSYSTEM
    from guarddog.reporters.sarif import SarifReporter
    from guarddog.scanners.pypi_project_scanner import PypiRequirementsScanner
    from guarddog_rdap import RDAPLookup
    from whois.exceptions import PywhoisError

    if version("guarddog") != "3.2.0":
        raise ValueError("Review the adapter and exception policy before updating GuardDog")
    requirements_text = requirements.read_text()
    expected_packages(requirements_text)
    reports.mkdir(parents=True, exist_ok=True)
    rdap = RDAPLookup(whois.extract_domain, whois.whois, PywhoisError)
    try:
        with patch.object(whois, "whois", rdap):
            dependencies, rows = PypiRequirementsScanner().scan_local(str(requirements))
    finally:
        (reports / "rdap-lookups.json").write_text(json.dumps(rdap.evidence, indent=2))
    (reports / "guarddog.json").write_text(json.dumps(rows, indent=2))
    sarif, errors = SarifReporter.render_verify(
        dependencies, sorted(_get_all_rules(ECOSYSTEM.PYPI)), rows, ECOSYSTEM.PYPI
    )
    (reports / "guarddog.raw.sarif").write_text(sarif)
    if errors.strip():
        print(errors, file=sys.stderr)
        return 1
    policy = json.loads(Path(".github/guarddog-exceptions.json").read_text())
    public, review, blocked = review_reports(
        rows, requirements_text, policy, date.today(), json.loads(sarif)
    )
    (reports / "guarddog.review.json").write_text(json.dumps(review, indent=2))
    (reports / "guarddog.sarif").write_text(json.dumps(public, indent=2))
    print(f"GuardDog completed {len(rows)} package-version scans.")
    if blocked:
        print("Review required:\n" + "\n".join(blocked), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
