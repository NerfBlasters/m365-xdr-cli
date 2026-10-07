"""Security regressions for order-independent binary-finding fingerprints."""

import copy

# RDAP uses the same registration/date contract as the native WHOIS helper.
import io
from datetime import UTC, date, datetime
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import URLError

import pytest
from guarddog_rdap import BOOTSTRAP, HTTPSRedirects, RDAPLookup
from guarddog_scan import fingerprint, main, review_reports


def report(binary_text):
    return {"results": {"bundled_binary": binary_text}, "risk_score": {"label": "high_risk"}}


def test_binary_inventory_order_does_not_change_exception_identity():
    header = "Binary file/s detected in package:\n"
    a, b = "a" * 64, "b" * 64
    original = report(f"{header}{a}: cli.exe (exe), cli-32.exe (exe)\n{b}: gui.exe (exe)")
    reordered = report(f"{header}{b}: gui.exe (exe)\n{a}: cli-32.exe (exe), cli.exe (exe)")
    assert fingerprint(original) == fingerprint(reordered)
    assert original["results"]["bundled_binary"].endswith("gui.exe (exe)")


def test_changed_hash_filename_or_added_binary_never_matches_exception():
    header = "Binary file/s detected in package:\n"
    original = report(f"{header}{'a' * 64}: cli.exe (exe)")
    for text in (
        f"{header}{'b' * 64}: cli.exe (exe)",
        f"{header}{'a' * 64}: payload.exe (exe)",
        f"{header}{'a' * 64}: cli.exe (exe), payload.exe (exe)",
        f"{header}{'a' * 64}: cli.exe (exe), cli.exe (exe)",
        f"{header}{'a' * 64}: cli.exe (exe)\nunknown format",
    ):
        assert fingerprint(original) != fingerprint(report(text))
    changed = copy.deepcopy(original)
    changed["results"]["new-threat"] = [{"code": "new suspicious code"}]
    assert fingerprint(original) != fingerprint(changed)


def scan_row(label="suspicious"):
    return {
        "dependency": "example-package", "version": "1.0",
        "result": {
            "issues": 1, "errors": {},
            "results": {
                "bundled_binary": f"Binary file/s detected in package:\n{'a' * 64}: tool (elf)"
            },
            "risk_score": {"label": label},
        },
    }


def review_policy(row=None):
    policy = {"scanner_version": "3.2.0", "exceptions": []}
    if row:
        policy["exceptions"].append({
            "package": "example-package", "version": "1.0",
            "findings_sha256": fingerprint(row["result"]),
            "reviewed_on": "2026-10-07", "expires": "2027-01-05",
            "reason": "Verified upstream executable", "evidence": ["https://example.org/release"],
        })
    return policy


def native_sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "GuardDog-pypi", "rules": [{"id": "bundled_binary"}]}},
        "results": [{"ruleId": "bundled_binary", "message": {"text": "native observation"}}],
    }]}


def test_unreviewed_package_alerts_even_when_observation_is_only_a_capability():
    row = scan_row()
    row["result"]["results"] = {"capability-process-spawn": [{"code": "run()"}]}
    public, review, blocked = review_reports(
        [row], "example-package==1.0\n", review_policy(), date(2026, 10, 7), native_sarif()
    )
    assert blocked == ["example-package==1.0: suspicious"]
    assert len(public["runs"][0]["results"]) == 1
    alert = public["runs"][0]["results"][0]
    assert alert["ruleId"] == "dependency-review-required"
    assert review["packages"][0]["disposition"] == "needs-review"


@pytest.mark.parametrize("label", ["low", "no_risks_detected"])
def test_nonblocking_observations_retained_without_open_alerts(label):
    public, review, blocked = review_reports(
        [scan_row(label)], "example-package==1.0", review_policy(),
        date(2026, 10, 7), native_sarif(),
    )
    assert not blocked and not public["runs"][0]["results"]
    assert review["packages"][0]["disposition"] == "nonblocking-observation"
    assert "review" not in review["packages"][0]


def test_exact_review_retains_rationale_and_native_report_is_unchanged():
    row, native = scan_row(), native_sarif()
    before = copy.deepcopy(native)
    policy = review_policy(row)
    public, review, blocked = review_reports(
        [row], "example-package==1.0", policy, date(2026, 10, 7), native
    )
    assert not blocked and not public["runs"][0]["results"]
    assert native == before
    accepted = review["packages"][0]
    assert accepted["disposition"] == "reviewed-exception"
    assert accepted["review"] == policy["exceptions"][0]


def test_changed_findings_reappear_with_new_identity_and_are_not_reviewed():
    row = scan_row()
    policy = review_policy(row)
    public1, _, _ = review_reports(
        [row], "example-package==1.0", review_policy(), date(2026, 10, 7), native_sarif()
    )
    row["result"]["results"]["bundled_binary"] = "new unreviewed binary"
    public2, review, blocked = review_reports(
        [row], "example-package==1.0", policy, date(2026, 10, 7), native_sarif()
    )
    assert blocked and review["packages"][0]["disposition"] == "needs-review"
    assert "review" not in review["packages"][0]
    assert public1["runs"][0]["results"][0]["partialFingerprints"] != (
        public2["runs"][0]["results"][0]["partialFingerprints"]
    )


@pytest.mark.parametrize("failure", ["missing", "error", "label", "empty-results", "duplicate"])
def test_incomplete_or_unknown_scans_cannot_publish_clean_report(failure):
    rows = [scan_row()]
    if failure == "missing":
        rows = []
    elif failure == "error":
        rows[0]["result"]["errors"] = {"rule": "scanner failed"}
    elif failure == "label":
        rows[0]["result"]["risk_score"]["label"] = "unknown"
    elif failure == "empty-results":
        rows[0]["result"]["results"] = {}
    else:
        rows.append(copy.deepcopy(rows[0]))
    with pytest.raises(ValueError):
        review_reports(
            rows, "example-package==1.0", review_policy(), date(2026, 10, 7), native_sarif()
        )


@pytest.mark.parametrize("failure", ["expired", "scanner-version"])
def test_invalid_review_policy_cannot_publish_clean_report(failure):
    row = scan_row()
    policy = review_policy(row)
    if failure == "expired":
        policy["exceptions"][0]["expires"] = "2026-10-07"
    else:
        policy["scanner_version"] = "3.3.0"
    with pytest.raises(ValueError):
        review_reports([row], "example-package==1.0", policy, date(2026, 10, 7), native_sarif())


def test_failed_rerun_removes_stale_public_report_before_scanner_import(tmp_path, monkeypatch):
    import builtins

    reports = tmp_path / "reports"
    reports.mkdir()
    for name in ("guarddog.sarif", "guarddog.review.json"):
        (reports / name).write_text("stale clean report")
    original_import = builtins.__import__

    def fail_import(name, *args, **kwargs):
        if name == "whois":
            raise ImportError("scanner environment unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_import)
    with pytest.raises(ImportError, match="scanner environment unavailable"):
        main(tmp_path / "dependencies.txt", reports)
    assert not (reports / "guarddog.sarif").exists()
    assert not (reports / "guarddog.review.json").exists()


class NotFound(Exception):
    pass


@pytest.fixture
def rdap():
    lookup = RDAPLookup(lambda name: name, Mock(), NotFound)
    lookup.services = {"org": ["https://registry.example/rdap/"]}
    return lookup


def domain_response(**overrides):
    return {
        "rdapConformance": ["rdap_level_0"],
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.ORG",
        "events": [{"eventAction": "registration", "eventDate": "2000-01-01T02:00:00+02:00"}],
        **overrides,
    }


def test_rdap_registration_normalization_and_cache(rdap):
    rdap.normalize = Mock(return_value="example.org")
    rdap.request = Mock(return_value=(200, domain_response()))
    result = rdap("MAIL.Example.ORG.")
    assert result.creation_date == datetime(2000, 1, 1, tzinfo=UTC)
    assert rdap("example.org").creation_date == result.creation_date
    rdap.request.assert_called_once_with("https://registry.example/rdap/domain/example.org")
    rdap.legacy_lookup.assert_not_called()


def test_rdap_missing_date_preserves_native_registered_semantics(rdap):
    rdap.request = Mock(return_value=(200, domain_response(events=[])))
    assert rdap("example.org").creation_date is None


def test_rdap_uses_earliest_registration_not_last_change(rdap):
    rdap.request = Mock(
        return_value=(
            200,
            domain_response(
                events=[
                    {"eventAction": "last changed", "eventDate": "1990-01-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                ]
            ),
        )
    )
    assert rdap("example.org").creation_date.year == 2000


def test_authoritative_rdap_absence_uses_native_not_found_error(rdap):
    rdap.request = Mock(return_value=(404, {"rdapConformance": ["rdap_level_0"], "errorCode": 404}))
    for _ in range(2):
        with pytest.raises(NotFound, match="No match for example.org"):
            rdap("example.org")
    rdap.request.assert_called_once()


@pytest.mark.parametrize(
    "status,data",
    [
        (404, {"errorCode": 404}),
        (404, {"rdapConformance": ["rdap_level_0"], "errorCode": "404"}),
        (200, domain_response(ldhName="unrelated.org")),
        (200, domain_response(objectClassName="entity")),
        (200, domain_response(events="invalid")),
        (200, domain_response(events=[None])),
        (200, domain_response(events=[{"eventAction": "registration", "eventDate": "invalid"}])),
        (200, domain_response(events=[{"eventAction": "registration", "eventDate": "2000-01-01"}])),
    ],
)
def test_invalid_rdap_cannot_become_a_clean_lookup(rdap, status, data):
    rdap.request = Mock(return_value=(status, data))
    with pytest.raises(ValueError):
        rdap("example.org")
    assert not rdap.cache


@pytest.mark.parametrize(
    "domain", ["https://example.org", "example.org/path", "x@example.org", "a..org"]
)
def test_invalid_domain_never_reaches_network(rdap, domain):
    rdap.request = Mock()
    with pytest.raises(ValueError):
        rdap(domain)
    rdap.request.assert_not_called()
    rdap.legacy_lookup.assert_not_called()


def test_unsupported_registry_uses_strict_whois(rdap):
    rdap.legacy_lookup.return_value = SimpleNamespace(creation_date=None)
    assert rdap("example.uk").creation_date is None
    rdap.legacy_lookup.assert_called_once_with("example.uk", ignore_socket_errors=False)
    assert rdap.evidence[-1]["transport"] == "whois"


def test_unsupported_registry_connection_error_remains_failure(rdap):
    rdap.legacy_lookup.side_effect = ConnectionRefusedError("refused")
    with pytest.raises(ConnectionRefusedError):
        rdap("example.uk")
    assert not rdap.cache


def test_iana_bootstrap_chooses_longest_https_service(rdap):
    rdap.services = None
    rdap.request = Mock(
        return_value=(
            200,
            {
                "services": [
                    [["org"], ["http://insecure.example/", "https://registry.example/"]],
                    [["special.org"], ["https://special.example/"]],
                ]
            },
        )
    )
    assert (
        rdap.endpoint("example.special.org") == "https://special.example/domain/example.special.org"
    )
    assert rdap.endpoint("example.org") == "https://registry.example/domain/example.org"
    rdap.request.assert_called_once_with(BOOTSTRAP)


def test_missing_bootstrap_is_not_an_unregistered_domain(rdap):
    rdap.services = None
    rdap.request = Mock(return_value=(404, {"errorCode": 404}))
    with pytest.raises(ValueError, match="bootstrap"):
        rdap("example.org")
    rdap.legacy_lookup.assert_not_called()


class Response(io.BytesIO):
    def __init__(self, status, body=b"{}", headers=None, url="https://registry.example/"):
        super().__init__(body)
        self.code = status
        self.headers = headers or {}
        self.url = url

    def geturl(self):
        return self.url


@pytest.mark.parametrize("failure", [URLError("refused"), TimeoutError("timeout")])
def test_rdap_transport_retries_are_bounded_and_fail_closed(rdap, monkeypatch, failure):
    sleep = Mock()
    monkeypatch.setattr("guarddog_rdap.time.sleep", sleep)
    rdap.opener = Mock()
    rdap.opener.open.side_effect = failure
    with pytest.raises(type(failure)):
        rdap("example.org")
    assert rdap.opener.open.call_count == 3
    assert [call.args[0] for call in sleep.call_args_list] == [2, 5]
    assert not rdap.cache


def test_rdap_retry_after_is_honored(rdap, monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("guarddog_rdap.time.sleep", sleep)
    rdap.opener = Mock()
    rdap.opener.open.side_effect = [Response(429, headers={"Retry-After": "7"}), Response(200)]
    assert rdap.request("https://registry.example/") == (200, {})
    sleep.assert_called_once_with(7)


def test_excessive_retry_after_fails_without_early_retry(rdap, monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("guarddog_rdap.time.sleep", sleep)
    rdap.opener = Mock()
    rdap.opener.open.return_value = Response(429, headers={"Retry-After": "120"})
    with pytest.raises(ValueError, match="retry budget"):
        rdap.request("https://registry.example/")
    rdap.opener.open.assert_called_once()
    sleep.assert_not_called()


@pytest.mark.parametrize("status,body", [(200, b"not json"), (200, b"[]"), (403, b"{}")])
def test_http_or_json_errors_propagate(rdap, status, body):
    rdap.opener = Mock()
    rdap.opener.open.return_value = Response(status, body)
    with pytest.raises(ValueError):
        rdap.request("https://registry.example/")
    rdap.opener.open.assert_called_once()


def test_rdap_redirect_cannot_downgrade_transport():
    with pytest.raises(ValueError, match="HTTPS"):
        HTTPSRedirects().redirect_request(None, None, 302, "", {}, "http://registry.example/")


@pytest.mark.parametrize(
    "fields",
    [
        {"rdapConformance": "rdap_level_0"},
        {"rdapConformance": {"rdap_level_0": True}},
        {"rdapConformance": ["rdap_level_0", None]},
        {"events": [{}]},
        {"events": [{"eventAction": "last changed"}]},
        {"events": [{"eventDate": "2000-01-01T00:00:00Z"}]},
        {"events": [{"eventAction": "last changed", "eventDate": 123}]},
    ],
)
def test_malformed_optional_metadata_does_not_hide_registration_date(rdap, fields):
    rdap.request = Mock(return_value=(200, domain_response(**fields)))
    with pytest.raises(ValueError):
        rdap("example.org")
    assert not rdap.cache


@pytest.mark.parametrize("fraction", ["6", "66", "666", "6666", "666666", "6666666"])
def test_fractional_dates_work_in_pinned_python310_image(rdap, fraction):
    rdap.request = Mock(
        return_value=(
            200,
            domain_response(
                events=[
                    {
                        "eventAction": "registration",
                        "eventDate": f"2015-07-24T15:13:23.{fraction}Z",
                    }
                ]
            ),
        )
    )
    assert rdap("example.org").creation_date.microsecond == int(fraction[:6].ljust(6, "0"))


def test_empty_authoritative_404_preserves_native_absence(rdap):
    rdap.opener = Mock()
    url = "https://registry.example/rdap/domain/example.org"
    rdap.opener.open.return_value = Response(404, b"", url=url)
    with pytest.raises(NotFound):
        rdap("example.org")


def test_empty_redirected_404_is_not_authoritative_absence(rdap):
    rdap.opener = Mock()
    rdap.opener.open.return_value = Response(404, b"", url="https://other.example/")
    with pytest.raises(ValueError):
        rdap("example.org")
    assert not rdap.cache


def test_io_supplement_is_used_only_without_iana_service(rdap):
    assert rdap.endpoint("example.io") == (
        "https://rdap.identitydigital.services/rdap/domain/example.io"
    )
    rdap.services["io"] = ["https://iana-selected.example/"]
    assert rdap.endpoint("example.io") == "https://iana-selected.example/domain/example.io"
