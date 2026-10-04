"""Domain source boundaries, partial artifacts and captured AD envelopes."""
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import respx
from typer.testing import CliRunner

from xdr_cli.config import Config
from xdr_cli.main import app
from xdr_cli.portal_auth import save_portal_cookies
from xdr_cli.results import tenant_fingerprint

BASE = "https://security.microsoft.com"
TENANT = BASE + "/apiproxy/mtp/sccManagement/mgmt/TenantContext"
ENTRA = BASE + "/apiproxy/msgraph/v1.0/domains"
AD = BASE + "/apiproxy/aatp/api/domains/search"
COUNT = BASE + "/apiproxy/aatp/api/domains/totalCount"
AD_ROW = {"id": "ad-id", "dnsName": "contoso.com", "sid": "synthetic-sid", "isDeleted": False}


@pytest.fixture(autouse=True)
def mocked_network():
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def cookie_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path))
    monkeypatch.delenv("XDR_SESSION", raising=False)
    c = Config(tenant_id="test-tenant", api_backend="portal-cookie")
    save_portal_cookies({"tenant_fingerprint": tenant_fingerprint(c.tenant_id),
                        "cookie_header": "sccauth=synthetic", "xsrf_token": "synthetic"})
    monkeypatch.setattr("xdr_cli.main.load_config", lambda: c)
    monkeypatch.setattr("xdr_cli.commands.domains_cmd.AuthManager", Mock(
        side_effect=AssertionError("MSAL prohibited"),
    ))
    return c


def routes(router, *, more=False, errors=None, rows=None, total=1):
    router.get(TENANT).respond(json={"AuthInfo": {"TenantId": "test-tenant"}})
    router.get(ENTRA).respond(json={"value": [{"id": "contoso.com", "isVerified": True}]})
    router.get(AD).respond(json={"results": [AD_ROW] if rows is None else rows,
                                "hasMore": more, "errors": errors})
    router.get(COUNT).respond(json={"totalCount": total})


def artifact(result):
    receipt = json.loads(result.stdout.splitlines()[0])
    rows = [json.loads(line) for line in Path(receipt["data_path"]).read_text().splitlines()]
    return receipt, rows


def test_combined_domains_preserves_same_name_distinct_sources(cookie_config, mocked_network):
    routes(mocked_network)
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 0, result.output
    receipt, rows = artifact(result)
    assert [r["source"] for r in rows] == ["entra", "active-directory"]
    assert [r["name"] for r in rows] == ["contoso.com", "contoso.com"]
    assert "isVerified" not in rows[1]
    assert rows[1]["sid"] == "synthetic-sid"
    assert receipt["context"]["sources"]["active-directory"]["has_more"] is False
    assert mocked_network.calls[-2].request.url.params["limit"] == "100"


@pytest.mark.parametrize("more,errors,total", [(True, None, 101), (False, ["private"], 1),
                                                (False, None, 2)])
def test_domain_partial_preserves_records(cookie_config, mocked_network, more, errors, total):
    routes(mocked_network, more=more, errors=errors, total=total)
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 14, result.output
    receipt, rows = artifact(result)
    assert len(rows) == 2
    assert receipt["context"]["sources"]["active-directory"]["status"] == "partial"
    assert "private" not in result.stdout
    assert json.loads(result.stdout.splitlines()[-1])["status"] == "error"


@pytest.mark.parametrize("bad_rows", [[AD_ROW, AD_ROW], [{"id": "a"}], ["bad"]])
def test_malformed_ad_keeps_entra(cookie_config, mocked_network, bad_rows):
    routes(mocked_network, rows=bad_rows)
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 14
    _, rows = artifact(result)
    assert len(rows) == 1 and rows[0]["source"] == "entra"


def test_count_failure_preserves_ad_records(cookie_config, mocked_network):
    routes(mocked_network)
    mocked_network.get(COUNT).respond(403)
    result = CliRunner().invoke(app, ["domains", "list", "--source", "active-directory"])
    assert result.exit_code == 14
    receipt, rows = artifact(result)
    assert len(rows) == 1 and rows[0]["source"] == "active-directory"
    assert receipt["context"]["sources"]["active-directory"]["error_code"]
    assert not any(str(c.request.url) == ENTRA for c in mocked_network.calls)


def test_auth_failure_does_not_try_more_sources(cookie_config, mocked_network):
    routes(mocked_network)
    mocked_network.get(ENTRA).respond(401)
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 2
    assert not any(str(c.request.url).startswith(AD) for c in mocked_network.calls)


def test_official_ad_only_fails_without_msal(cookie_config, mocked_network):
    cookie_config.api_backend = "official"
    result = CliRunner().invoke(app, ["domains", "list", "--source", "active-directory"])
    assert result.exit_code == 3
    assert "portal-cookie" in result.stdout
    assert len(mocked_network.calls) == 0


def test_official_combined_reports_ad_gap(cookie_config, mocked_network, monkeypatch):
    from unittest.mock import AsyncMock

    cookie_config.api_backend = "official"
    client = AsyncMock()
    client.get.return_value = {"value": [{"id": "contoso.com"}]}
    monkeypatch.setattr("xdr_cli.commands.domains_cmd.create_client", lambda *a, **kw: client)
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 14
    receipt, rows = artifact(result)
    assert rows[0]["source"] == "entra"
    assert receipt["context"]["sources"]["active-directory"]["status"] == "unavailable"


def test_entra_page_failure_preserves_first_page(cookie_config, mocked_network):
    routes(mocked_network)
    mocked_network.get(ENTRA).respond(json={
        "value": [{"id": "contoso.com"}],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/domains?$skiptoken=opaque",
    })
    mocked_network.get(ENTRA, params={"$skiptoken": "opaque"}).respond(429, headers={
        "Retry-After": "30",
    })
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 14
    receipt, rows = artifact(result)
    assert len(rows) == 1
    assert receipt["context"]["sources"]["active-directory"]["status"] == "not_attempted"
    assert json.loads(result.stdout.splitlines()[-1])["error"]["retry_after_seconds"] == 30


@pytest.mark.parametrize("count", [True, -1, "2", None])
def test_invalid_ad_count_is_partial(cookie_config, mocked_network, count):
    routes(mocked_network, total=count)
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 14
    _, rows = artifact(result)
    assert len(rows) == 2


def test_empty_sources_are_not_an_error(cookie_config, mocked_network):
    routes(mocked_network, rows=[], total=0)
    mocked_network.get(ENTRA).respond(json={"value": []})
    result = CliRunner().invoke(app, ["domains", "list"])
    assert result.exit_code == 0, result.output
    receipt, rows = artifact(result)
    assert receipt["rows"] == 0 and rows == []
