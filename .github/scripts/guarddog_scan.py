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
from datetime import date
from pathlib import Path


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

def main(requirements: Path, reports: Path) -> int:
    # Imports stay inside main so fail-closed behavior can be tested without
    # installing scanner dependencies into the application environment.
    from importlib.metadata import version

    from guarddog.cli import _get_all_rules
    from guarddog.ecosystems import ECOSYSTEM
    from guarddog.reporters.sarif import SarifReporter
    from guarddog.scanners.pypi_project_scanner import PypiRequirementsScanner

    if version("guarddog") != "3.2.0":
        raise ValueError("Review the adapter and exception policy before updating GuardDog")
    expected = expected_packages(requirements.read_text())
    reports.mkdir(parents=True, exist_ok=True)
    dependencies, rows = PypiRequirementsScanner().scan_local(str(requirements))
    (reports / "guarddog.json").write_text(json.dumps(rows, indent=2))
    sarif, errors = SarifReporter.render_verify(
        dependencies, sorted(_get_all_rules(ECOSYSTEM.PYPI)), rows, ECOSYSTEM.PYPI
    )
    (reports / "guarddog.sarif").write_text(sarif)
    if errors.strip():
        print(errors, file=sys.stderr)
        return 1
    blocked = validate_scan(rows, expected)
    policy = json.loads(Path(".github/guarddog-exceptions.json").read_text())
    blocked = apply_exceptions(rows, blocked, policy, date.today())
    print(f"GuardDog completed {len(rows)} package-version scans.")
    if blocked:
        print("Review required:\n" + "\n".join(blocked), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
