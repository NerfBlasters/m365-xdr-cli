"""Tests for the lists loader and frontmatter handling."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from xdr_cli.exceptions import QueryError
from xdr_cli.queries import _build_query_info, load_query, parse_frontmatter


def test_library_string_parameters_are_escaped_as_kql_data():
    payload = "host' | take 1 | extend Injected='yes\\tail"

    rendered = load_query(
        "qry_process_tree",
        device_name=payload,
        hours="1",
        mode="summary",
    )

    assert (
        "| where DeviceName == "
        "'host\\' | take 1 | extend Injected=\\'yes\\\\tail'"
    ) in rendered


def test_library_double_quoted_string_parameters_are_escaped():
    rendered = load_query(
        "ttp_ldap_process_attribution",
        start="2026-08-01T00:00:00Z",
        end="2026-08-02T00:00:00Z",
        lookback="30m",
        device_name='host" | take 1',
        mode="summary",
    )

    assert 'let deviceNameToInvestigate = "host\\" | take 1";' in rendered


@pytest.mark.parametrize(
    ("name", "params"),
    [
        (
            "qry_process_tree",
            {"device_name": "host", "hours": "1 | take 1", "mode": "summary"},
        ),
        (
            "qry_url_clicks",
            {
                "account_upn": "user@example.com",
                "start": "2026-08-01) | take 1 //",
                "end": "2026-08-02",
                "mode": "summary",
            },
        ),
        (
            "ttp_ldap_process_attribution",
            {
                "device_name": "host",
                "start": "2026-08-01",
                "end": "2026-08-02",
                "lookback": "30m); take 1",
                "mode": "summary",
            },
        ),
    ],
)
def test_library_rejects_injected_typed_parameters(name, params):
    with pytest.raises(QueryError, match="Invalid value"):
        load_query(name, **params)


def test_library_rejects_unquoted_string_placeholder_context(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    query_dir = tmp_path / ".xdr-cli" / "queries"
    query_dir.mkdir(parents=True)
    (query_dir / "unsafe_context.kql").write_text(
        "-- description: unsafe synthetic context\n"
        "-- tier: utility\n"
        "-- params: subject\n"
        "print value={subject}\n"
    )

    with pytest.raises(QueryError, match="must appear inside a quoted KQL"):
        load_query("unsafe_context", subject="safe text")


@pytest.mark.parametrize(
    ("literal", "message"),
    [
        ("@'{subject}'", "ordinary quoted KQL"),
        ('@"{subject}"', "ordinary quoted KQL"),
        ("```{subject}```", "multiline KQL"),
    ],
)
def test_library_rejects_placeholder_in_unsupported_string_literal(
    tmp_path, monkeypatch, literal, message
):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    query_dir = tmp_path / ".xdr-cli" / "queries"
    query_dir.mkdir(parents=True)
    (query_dir / "unsafe_literal.kql").write_text(
        "-- description: unsafe synthetic literal context\n"
        "-- tier: utility\n"
        "-- params: subject\n"
        f"print value={literal}\n"
    )

    with pytest.raises(QueryError, match=message):
        load_query("unsafe_literal", subject="safe text")


def test_library_parameter_values_are_not_rescanned_as_placeholders(tmp_path, monkeypatch):
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    query_dir = tmp_path / ".xdr-cli" / "queries"
    query_dir.mkdir(parents=True)
    (query_dir / "single_pass.kql").write_text(
        "-- description: single-pass synthetic rendering\n"
        "-- tier: utility\n"
        "-- params: first, second\n"
        "print first='{first}', second='{second}'\n"
    )

    rendered = load_query("single_pass", first="{second}", second="replacement")

    assert "first='{second}'" in rendered
    assert "second='replacement'" in rendered


def test_parse_frontmatter_extracts_lists_field():
    text = (
        "-- name: example\n"
        "-- description: Example\n"
        "-- params: hours=24, account_upn=, mode=summary\n"
        "-- lists: TenantDomains, KnownGoodSigners, InternalSubnets\n"
        "EntraIdSignInEvents\n"
        "| where Timestamp > ago({hours}h)\n"
    )
    meta, _ = parse_frontmatter(text)
    assert meta["lists"] == "TenantDomains, KnownGoodSigners, InternalSubnets"


def test_query_info_lists_field_default_empty():
    text = (
        "-- name: example\n"
        "-- description: Example\n"
        "-- tier: r1\n"
        "-- params: hours=24\n"
        "EntraIdSignInEvents\n"
    )
    info = _build_query_info("example", text, "builtin")
    assert info.lists == []


def test_query_info_lists_field_parsed():
    text = (
        "-- name: example\n"
        "-- description: Example\n"
        "-- tier: r1\n"
        "-- params: hours=24\n"
        "-- lists: TenantDomains , KnownGoodSigners,  InternalSubnets\n"
        "EntraIdSignInEvents\n"
    )
    info = _build_query_info("example", text, "builtin")
    assert info.lists == ["TenantDomains", "KnownGoodSigners", "InternalSubnets"]


def test_parse_frontmatter_continuation_lines():
    """Multi-line agent_hint blocks must reach meta['agent_hint'] intact."""
    from xdr_cli.queries import parse_frontmatter
    text = (
        "-- name: example\n"
        "-- description: Example\n"
        "-- tier: r1\n"
        "-- agent_hint: first line of the hint\n"
        "--   second line continues\n"
        "--   third line still continues\n"
        "-- params: hours=24\n"
        "EntraIdSignInEvents\n"
    )
    meta, _ = parse_frontmatter(text)
    assert meta["agent_hint"] == (
        "first line of the hint\n"
        "second line continues\n"
        "third line still continues"
    )
    # Subsequent key is parsed independently — the continuation block does
    # not bleed into params.
    assert meta["params"] == "hours=24"


def test_parse_frontmatter_continuation_resets_on_bare_comment():
    """A bare `-- comment` line (no colon) breaks the continuation chain
    so the next non-key `--   text` line is not silently appended."""
    from xdr_cli.queries import parse_frontmatter
    text = (
        "-- name: example\n"
        "-- tier: r1\n"
        "-- agent_hint: hint line one\n"
        "--   hint line two\n"
        "-- a bare comment that resets continuation\n"
        "--   this is not appended to agent_hint\n"
        "EntraIdSignInEvents\n"
    )
    meta, _ = parse_frontmatter(text)
    assert meta["agent_hint"] == "hint line one\nhint line two"


def test_build_query_info_rejects_missing_tier():
    """Every .kql file must declare `-- tier: <value>`; the loader rejects
    files that omit it so the methodology test can rely on q.tier."""
    from xdr_cli.queries import _build_query_info, QueryError
    text = (
        "-- name: example\n"
        "-- description: missing tier\n"
        "-- params: hours=24\n"
        "EntraIdSignInEvents\n"
    )
    with pytest.raises(QueryError, match="missing required '-- tier:'"):
        _build_query_info("example", text, "builtin")


def test_build_query_info_rejects_unknown_tier():
    from xdr_cli.queries import _build_query_info, QueryError
    text = (
        "-- name: example\n"
        "-- description: bad tier\n"
        "-- tier: not-a-real-tier\n"
        "-- params: hours=24\n"
        "EntraIdSignInEvents\n"
    )
    with pytest.raises(QueryError, match="unknown tier"):
        _build_query_info("example", text, "builtin")


def test_build_query_info_deprecated_requires_alias_of():
    """A `-- tier: deprecated` shim must declare `-- alias_of: <target>` —
    otherwise load_query has nowhere to forward to."""
    from xdr_cli.queries import _build_query_info, QueryError
    text = (
        "-- name: legacy_thing\n"
        "-- description: legacy alias missing alias_of\n"
        "-- tier: deprecated\n"
        "-- params: hours=24\n"
        "EntraIdSignInEvents\n"
    )
    with pytest.raises(QueryError, match="alias_of"):
        _build_query_info("legacy_thing", text, "builtin")


# --- Task 2: _resolve_lists ---


def test_resolve_lists_empty_input_returns_empty_string(tmp_path, monkeypatch):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    block, health = _resolve_lists([])
    assert block == ""
    assert health == {}


def test_resolve_lists_missing_file_synthesises_empty_dynamic(tmp_path, monkeypatch):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    block, health = _resolve_lists(["TenantDomains"])
    assert "let _xdr_TenantDomains = dynamic([]);" in block
    assert health["_xdr_TenantDomains"]["is_empty"] is True


def test_resolve_lists_reads_values_quotes_and_joins(tmp_path, monkeypatch):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_text(
        "example.com\nexample.net\n# comment line\n\nexample.org\n"
    )
    block, health = _resolve_lists(["TenantDomains"])
    assert (
        'let _xdr_TenantDomains = dynamic(["example.com", "example.net", "example.org"]);'
        in block
    )
    assert health["_xdr_TenantDomains"]["value_count"] == 3


def test_resolve_lists_multi_block_concat(tmp_path, monkeypatch):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "InternalSubnets.txt").write_text("10.0.0.0/8\n")
    (lists_dir / "KnownGoodSigners.txt").write_text("Microsoft Corporation\n")
    block, _ = _resolve_lists(["InternalSubnets", "KnownGoodSigners"])
    assert 'let _xdr_InternalSubnets = dynamic(["10.0.0.0/8"]);' in block
    assert 'let _xdr_KnownGoodSigners = dynamic(["Microsoft Corporation"]);' in block


def test_resolve_lists_skips_comments_and_blanks(tmp_path, monkeypatch):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_text(
        "# top-level header comment\n"
        "  \n"
        "corp.example.com\n"
        "# inline comment between values\n"
        "internal.example.com\n"
    )
    block, _ = _resolve_lists(["TenantDomains"])
    assert (
        'let _xdr_TenantDomains = dynamic(["corp.example.com", "internal.example.com"]);'
        in block
    )


# --- Task 3: load_query integration ---


def test_load_query_strips_inline_dynamic_default(tmp_path, monkeypatch):
    """The inline `let _xdr_<Name> = dynamic([]);` placeholder in the query
    body must be stripped before prepending the resolved-lists block; otherwise
    the inline default shadows the loaded values."""
    from xdr_cli.queries import _strip_inline_list_defaults
    body = (
        "let _xdr_TenantDomains = dynamic([]);\n"
        "let _xdr_KnownGoodSigners = dynamic([]);\n"
        "let Window = 24h;\n"
        "EntraIdSignInEvents | where Timestamp > ago(Window)\n"
    )
    stripped = _strip_inline_list_defaults(body, ["TenantDomains", "KnownGoodSigners"])
    assert "let _xdr_TenantDomains = dynamic([]);" not in stripped
    assert "let _xdr_KnownGoodSigners = dynamic([]);" not in stripped
    assert "let Window = 24h;" in stripped


def test_strip_inline_list_defaults_removes_nonempty_arrays():
    """Authored placeholders like `dynamic([""])` must also be stripped, plus
    duplicate declarations of the same block (not just a single `count=1` match)."""
    from xdr_cli.queries import _strip_inline_list_defaults
    body = (
        'let _xdr_TenantDomains = dynamic([""]);\n'
        'let _xdr_TenantDomains = dynamic(["placeholder.example"]);\n'
        "EntraIdSignInEvents | take 10\n"
    )
    stripped = _strip_inline_list_defaults(body, ["TenantDomains"])
    assert "_xdr_TenantDomains" not in stripped
    assert "EntraIdSignInEvents | take 10" in stripped


def test_load_query_rejects_unknown_param():
    """A typo'd --param key must raise, not silently downgrade scope."""
    from xdr_cli.queries import load_query, QueryError
    with pytest.raises(QueryError, match="Unknown param"):
        # `qry_app_data_access` declares: app_name, start, end.
        load_query(
            "qry_app_data_access",
            app_name="Microsoft",
            start="2026-04-01",
            end="2026-04-02",
            accont_upn="alice@x.com",  # typo
        )


def test_load_query_resolves_deprecated_alias(capsys):
    """qry_inbox_rule_audit is a -- tier: deprecated shim -> qry_inbox_rule_activity."""
    from xdr_cli.queries import load_query
    kql = load_query("qry_inbox_rule_audit", account_upn="", hours="24", mode="summary")
    # Alias resolution forwards to qry_inbox_rule_activity whose body references
    # CloudAppEvents and EntraIdSignInEvents.
    assert "CloudAppEvents" in kql or "EntraIdSignInEvents" in kql
    # Deprecation warning emitted via err_console (stderr).
    captured = capsys.readouterr()
    assert "deprecated" in captured.err.lower()


@pytest.mark.skip(
    reason="Depends on Phase 7 R1 rewrite of ttp_token_theft_replay to declare "
           "params: hours, account_upn=, session_id=, mode=summary. The mode='' "
           "coercion logic itself is tested by test_load_query_coerces_empty_mode_synthetic "
           "below using a stubbed user-dir query."
)
def test_load_query_coerces_empty_mode_to_declared_default():
    """`--param mode=` (empty) must coerce to the declared default ('summary'
    in the canonical contract)."""
    from xdr_cli.queries import load_query
    kql = load_query(
        "ttp_token_theft_replay",
        hours="24",
        account_upn="",
        session_id="",
        mode="",
    )
    assert "'summary' == 'summary'" in kql or "where 'summary'" in kql
    assert "'' == ''" in kql or "or AccountUpn =~ ''" in kql


def test_load_query_coerces_empty_mode_synthetic(tmp_path, monkeypatch):
    """Synthetic-query equivalent of the Phase-7-dependent test above.

    Drops a user-dir .kql with the canonical `mode=summary, account_upn=`
    contract and verifies the loader's empty-coercion guard applies to mode
    (declared default 'summary') but NOT to account_upn (declared default '').
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    user_queries = tmp_path / ".xdr-cli" / "queries"
    user_queries.mkdir(parents=True)
    (user_queries / "synth_mode_coercion.kql").write_text(
        "-- name: synth_mode_coercion\n"
        "-- description: synthetic query exercising mode='' coercion\n"
        "-- tier: r1\n"
        "-- params: hours=24, account_upn=, mode=summary\n"
        "let SummaryRow = print mode='{mode}', account_upn='{account_upn}';\n"
        "SummaryRow\n"
    )
    from xdr_cli.queries import load_query
    kql = load_query(
        "synth_mode_coercion",
        hours="24",
        account_upn="",
        mode="",
    )
    # mode coerced to declared default 'summary'
    assert "mode='summary'" in kql
    # account_upn declared default '' → kept empty (scope-pass-through idiom)
    assert "account_upn=''" in kql


def test_load_query_prepends_resolved_lists_block_synthetic(tmp_path, monkeypatch):
    """End-to-end: a query declaring `-- lists: TenantDomains` must have
    the inline placeholder stripped and the resolved values prepended."""
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    user_dir = tmp_path / ".xdr-cli"
    user_queries = user_dir / "queries"
    user_queries.mkdir(parents=True)
    lists_dir = user_dir / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_text("example.com\nexample.net\n")
    (user_queries / "synth_lists_load.kql").write_text(
        "-- name: synth_lists_load\n"
        "-- description: synthetic query exercising lists prepend\n"
        "-- tier: r1\n"
        "-- params: hours=24\n"
        "-- lists: TenantDomains\n"
        "let _xdr_TenantDomains = dynamic([]);\n"
        "EntraIdSignInEvents\n"
        "| where Timestamp > ago({hours}h)\n"
    )
    from xdr_cli.queries import load_query
    kql = load_query("synth_lists_load", hours="24")
    # Inline placeholder stripped; resolved block prepended with values.
    assert 'let _xdr_TenantDomains = dynamic(["example.com", "example.net"]);' in kql
    # Inline `dynamic([])` placeholder removed.
    assert "let _xdr_TenantDomains = dynamic([]);" not in kql


# --- Task 4: # fetched: / # ttl: / # source: header parsing ---


def test_resolve_lists_parses_metadata_headers(tmp_path, monkeypatch):
    """The Task 2 _resolve_lists implementation already parses # fetched: /
    # ttl: / # source: header lines into the per-block ListHealth dict.
    No separate _read_list_file helper exists — the value/metadata split
    happens inline during the value-collection loop. Verify via the
    structured health dict returned alongside the rendered KQL.
    """
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "MaliciousDomains.txt").write_text(
        "# fetched: 2026-04-30T12:00:00Z\n"
        "# ttl: 7d\n"
        "# source: https://bazaar.abuse.ch/export/csv/recent/\n"
        + "deadbeef" * 8 + "\n"
        + "feedface" * 8 + "\n"
    )
    block, health = _resolve_lists(["MaliciousDomains"])
    # Values land in the rendered KQL string-literal-by-string-literal.
    assert ("deadbeef" * 8) in block
    assert ("feedface" * 8) in block
    # Header parse exposed in ListHealth.
    h = health["_xdr_MaliciousDomains"]
    assert h["fetched"] == "2026-04-30T12:00:00Z"
    assert h["ttl_hours"] == "7d"
    assert h["source"] == "https://bazaar.abuse.ch/export/csv/recent/"
    assert h["value_count"] == 2


def test_resolve_lists_ignores_unrecognised_headers(tmp_path, monkeypatch):
    """Unknown header keys (e.g., `# author:`) do not crash the loader; the
    value-set is still collected. Only fetched/ttl/source flow into ListHealth.
    """
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_text(
        "# fetched: 2026-04-30T12:00:00Z\n"
        "# author: nobody\n"
        "# random-key: random-value\n"
        "example.com\n"
    )
    block, health = _resolve_lists(["TenantDomains"])
    assert "example.com" in block
    assert health["_xdr_TenantDomains"]["fetched"] == "2026-04-30T12:00:00Z"
    assert health["_xdr_TenantDomains"]["value_count"] == 1


# --- Task 5: staleness warning emission ---


def test_parse_ttl_seconds_minutes_hours_days():
    from xdr_cli.queries import _parse_ttl
    assert _parse_ttl("30s") == dt.timedelta(seconds=30)
    assert _parse_ttl("15m") == dt.timedelta(minutes=15)
    assert _parse_ttl("6h") == dt.timedelta(hours=6)
    assert _parse_ttl("7d") == dt.timedelta(days=7)
    assert _parse_ttl("garbage") is None
    assert _parse_ttl("") is None


def test_parse_ttl_weeks():
    """`w` (week) accepted in addition to `s`/`m`/`h`/`d` so operators can
    write `1w`/`2w` for monthly/fortnightly TTLs without the regex silently
    treating those as never-stale."""
    from xdr_cli.queries import _parse_ttl
    assert _parse_ttl("1w") == dt.timedelta(weeks=1)
    assert _parse_ttl("2w") == dt.timedelta(weeks=2)


def test_resolve_lists_warns_when_stale(tmp_path, monkeypatch, capsys):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    # fetched 30 days ago, TTL 1d -> stale
    (lists_dir / "MaliciousDomains.txt").write_text(
        "# fetched: 2025-01-01T00:00:00Z\n"
        "# ttl: 1d\n"
        "deadbeef\n"
    )
    _resolve_lists(["MaliciousDomains"])
    captured = capsys.readouterr()
    assert "MaliciousDomains" in captured.err
    assert "stale" in captured.err.lower() or "ttl" in captured.err.lower()


def test_resolve_lists_no_warning_when_fresh(tmp_path, monkeypatch, capsys):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    fetched = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)).isoformat()
    (lists_dir / "MaliciousDomains.txt").write_text(
        f"# fetched: {fetched}\n# ttl: 7d\ndeadbeef\n"
    )
    _resolve_lists(["MaliciousDomains"])
    captured = capsys.readouterr()
    assert "MaliciousDomains" not in captured.err


def test_resolve_lists_no_warning_when_headers_missing(tmp_path, monkeypatch, capsys):
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_text("example.com\n")
    _resolve_lists(["TenantDomains"])
    captured = capsys.readouterr()
    # no headers -> no staleness check -> no warning
    assert captured.err == ""


# ---------------------------------------------------------------------------
# Fix 1: naive ISO timestamp in _is_stale must not raise TypeError
# ---------------------------------------------------------------------------


def test_is_stale_naive_timestamp_treated_as_utc():
    """A `# fetched:` header without timezone info (no 'Z', no '+00:00') returns
    a naive datetime from fromisoformat(). Comparing a naive datetime to
    datetime.now(UTC) raises TypeError. The fix must treat naive as UTC and
    return the correct staleness result without raising.
    """
    from xdr_cli.queries import _is_stale

    # Naive timestamp that is very old — must be detected as stale, not crash.
    meta = {"fetched": "2026-01-01T00:00:00", "ttl": "1d"}
    result = _is_stale(meta)  # must not raise TypeError
    assert result is True


def test_is_stale_naive_timestamp_fresh():
    """A naive timestamp from one hour ago with a 7d TTL is not stale."""
    from xdr_cli.queries import _is_stale

    recent = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S"  # no timezone suffix — deliberately naive
    )
    meta = {"fetched": recent, "ttl": "7d"}
    result = _is_stale(meta)  # must not raise TypeError
    assert result is False


# ---------------------------------------------------------------------------
# Fix 2: single-quote in source header must produce well-formed KQL
# ---------------------------------------------------------------------------


def test_resolve_lists_single_quote_in_source_escaped(tmp_path, monkeypatch):
    """A `# source:` header value containing an apostrophe (e.g. "O'Reilly")
    must have ' → '' doubled in the KQL output, so the parse_json(...)
    literal remains syntactically valid.
    """
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_text(
        "# fetched: 2026-01-01T00:00:00Z\n"
        "# ttl: 7d\n"
        "# source: O'Reilly Security Feed\n"
        "example.com\n"
    )
    block, health = _resolve_lists(["TenantDomains"])
    # The raw apostrophe must not appear unescaped inside the single-quoted KQL literal.
    assert "O'Reilly" not in block or "O''Reilly" in block
    # More precisely: the KQL-escaped form must be present.
    assert "O''Reilly" in block
    # And the health dict retains the raw (un-doubled) source value.
    assert health["_xdr_TenantDomains"]["source"] == "O'Reilly Security Feed"


# ---------------------------------------------------------------------------
# Fix 3: deprecated-alias resolution — synthetic test coverage
# ---------------------------------------------------------------------------


def test_load_query_resolves_deprecated_alias_synthetic(tmp_path, monkeypatch, capsys):
    """Synthetic equivalent of the skipped live-query test.

    Writes two .kql files into a tmp user dir:
      - synth_old_name: tier=deprecated, alias_of=synth_new_name
      - synth_new_name: tier=r1, real KQL body

    Asserts load_query("synth_old_name") returns the TARGET's KQL and that a
    deprecation warning appears on stderr.
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    user_queries = tmp_path / ".xdr-cli" / "queries"
    user_queries.mkdir(parents=True)

    # Deprecated shim.
    (user_queries / "synth_old_name.kql").write_text(
        "-- name: synth_old_name\n"
        "-- description: legacy alias for synth_new_name\n"
        "-- tier: deprecated\n"
        "-- alias_of: synth_new_name\n"
        "-- params: hours=24\n"
        "THIS BODY MUST NOT APPEAR IN OUTPUT\n"
    )
    # Live target.
    (user_queries / "synth_new_name.kql").write_text(
        "-- name: synth_new_name\n"
        "-- description: new canonical query\n"
        "-- tier: r1\n"
        "-- params: hours=24\n"
        "EntraIdSignInEvents | where Timestamp > ago({hours}h)\n"
    )

    from xdr_cli.queries import load_query

    kql = load_query("synth_old_name", hours="24")

    # Result is the TARGET's KQL, not the shim body.
    assert "EntraIdSignInEvents" in kql
    assert "THIS BODY MUST NOT APPEAR IN OUTPUT" not in kql

    # Deprecation warning on stderr.
    captured = capsys.readouterr()
    assert "deprecated" in captured.err.lower()
    assert "synth_old_name" in captured.err
    assert "synth_new_name" in captured.err


# ---------------------------------------------------------------------------
# Fix 6: _kql_escape edge cases
# ---------------------------------------------------------------------------


def test_kql_escape_double_quote_only():
    """A value consisting only of a double-quote must be escaped to \\\"."""
    from xdr_cli.queries import _kql_escape
    assert _kql_escape('"') == '\\"'


def test_kql_escape_backslash_only():
    """A value consisting only of a backslash must be escaped to \\\\."""
    from xdr_cli.queries import _kql_escape
    assert _kql_escape("\\") == "\\\\"


def test_kql_escape_backslash_then_double_quote():
    r"""A value `\"` (backslash + double-quote) must become `\\\"` with both
    characters escaped — backslash first produces `\\`, then the double-quote
    produces `\"`, yielding `\\\"` (4 chars).  Wrong escape order would turn
    `\"` into `\\"` (only 3 chars), which is incorrect KQL.
    """
    from xdr_cli.queries import _kql_escape
    # Input: backslash followed by double-quote (2 chars: \ ")
    # Expected: escaped backslash then escaped double-quote (4 chars: \ \ \ ")
    assert _kql_escape('\\"') == '\\\\\\"'


def test_kql_escape_double_backslash():
    r"""A value `\\` must become `\\\\` — both backslashes escaped."""
    from xdr_cli.queries import _kql_escape
    assert _kql_escape("\\\\") == "\\\\\\\\"


# ---------------------------------------------------------------------------
# Fix 7: zero-byte and comments-only file → dynamic([]) without crash
# ---------------------------------------------------------------------------


def test_resolve_lists_zero_byte_file_produces_empty_dynamic(tmp_path, monkeypatch):
    """A zero-byte list file (empty) must produce `dynamic([])` without crashing
    or emitting a warning.
    """
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_bytes(b"")  # zero bytes
    block, health = _resolve_lists(["TenantDomains"])
    assert "let _xdr_TenantDomains = dynamic([]);" in block
    assert health["_xdr_TenantDomains"]["is_empty"] is True
    assert health["_xdr_TenantDomains"]["value_count"] == 0


def test_resolve_lists_comments_only_file_produces_empty_dynamic(tmp_path, monkeypatch, capsys):
    """A file with only comments and blank lines must produce `dynamic([])` and
    emit no staleness warning (no `# fetched:` header means no staleness check).
    """
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "TenantDomains.txt").write_text(
        "# this is a comment\n"
        "# another comment\n"
        "\n"
        "   \n"
    )
    block, health = _resolve_lists(["TenantDomains"])
    assert "let _xdr_TenantDomains = dynamic([]);" in block
    assert health["_xdr_TenantDomains"]["is_empty"] is True
    # No warning expected — no values but also no stale headers.
    captured = capsys.readouterr()
    assert "stale" not in captured.err.lower()


# ---------------------------------------------------------------------------
# Task 6: _known_list_blocks() now resolves to the seeded set
# ---------------------------------------------------------------------------


def test_known_list_blocks_is_nonempty():
    """After Task 6 ships lists_seed/, the loader's known-block set is the
    enumeration of those seed files. The unknown-block typo guard in
    _resolve_lists is then active in production.
    """
    from xdr_cli.queries import _known_list_blocks
    blocks = _known_list_blocks()
    assert blocks, "lists_seed/ enumeration returned empty — packaging regression?"
    # A few canonical names must be present so spec drift is caught early.
    assert "TenantDomains" in blocks
    assert "InternalSubnets" in blocks
    assert "KnownGoodSigners" in blocks
    assert "KnownGoodParentDomains" in blocks


def test_known_list_blocks_excludes_dunder_init():
    """The package-data scan must filter to *.txt — `__init__.py` is not a block."""
    from xdr_cli.queries import _known_list_blocks
    blocks = _known_list_blocks()
    assert "__init__" not in blocks
    assert all(not b.startswith("_") for b in blocks)


def test_resolve_lists_unknown_name_emits_typo_warning(tmp_path, monkeypatch, capsys):
    """With the seed set populated, an unknown block name in `-- lists:` is
    rejected with a warning naming the known set; the resolved block is empty.
    """
    from xdr_cli.queries import _resolve_lists
    monkeypatch.setattr("xdr_cli.queries.get_config_home", lambda: tmp_path)
    block, health = _resolve_lists(["TenanetDomains"])  # typo: extra 'e'
    assert "let _xdr_TenanetDomains = dynamic([]);" in block
    assert health["_xdr_TenanetDomains"]["is_empty"] is True
    captured = capsys.readouterr()
    assert "TenanetDomains" in captured.err
    assert "unknown list block" in captured.err.lower()


# ---------------------------------------------------------------------------
# Task 9: scripts/extract_tenant_domains.py round-trip
# ---------------------------------------------------------------------------


def test_extract_tenant_domains_round_trip(tmp_path, monkeypatch, config_dir):
    """Round-trip: write legacy-shape queries, run extract, verify TenantDomains.txt.

    Patching order is load-bearing:
      1. Set XDR_CLI_HOME via the ``config_dir`` fixture (existing tests/conftest.py).
         This is the only patch that affects every ``get_config_home()`` callsite
         reliably — including the script's module-level ``from xdr_cli.config
         import get_config_home`` binding which other patches cannot reach.
      2. ``exec_module`` first, so the script's ``QUERIES_DIR`` global is
         set from the script's ``__file__``. Only THEN ``monkeypatch.setattr(
         mod, "QUERIES_DIR", qdir, raising=False)`` to override it for this
         test. Patching ``mod.QUERIES_DIR`` BEFORE ``exec_module`` is wrong:
         the script's top-level assignment ``QUERIES_DIR = Path(__file__)...``
         would overwrite the patch during execution.
    """
    import importlib.util
    spec_path = Path(__file__).parent.parent / "scripts" / "extract_tenant_domains.py"
    spec = importlib.util.spec_from_file_location("extract_tenant_domains", spec_path)
    mod = importlib.util.module_from_spec(spec)

    # Write fake legacy queries to a tmp queries dir
    qdir = tmp_path / "queries"
    qdir.mkdir()
    (qdir / "ttp_dns_beaconing.kql").write_text(
        '-- name: ttp_dns_beaconing\n'
        '| where ParentDomain !in ("example.com", "example.net", "example.org")\n'
    )
    (qdir / "dns_subdomain_diversity.kql").write_text(
        '-- name: dns_subdomain_diversity\n'
        'let approved = dynamic(["example.com", "casalemedia.com"]);\n'
    )

    # Order matters: exec_module BEFORE patching mod.QUERIES_DIR.
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "QUERIES_DIR", qdir, raising=False)

    rc = mod.main([])  # empty argv — defaults: not --dry-run
    assert rc == 0
    out = (Path(config_dir) / "lists" / "TenantDomains.txt").read_text()
    assert "example.com" in out
    assert "example.net" in out
    assert "example.org" in out
    # casalemedia.com is in KnownGoodParentDomains.txt → CDN-filtered, not written.
    assert "casalemedia.com" not in out
    assert "# fetched:" in out

    # Determinism check: re-running yields the same on-disk content.
    first = out
    rc = mod.main([])
    assert rc == 0
    assert (Path(config_dir) / "lists" / "TenantDomains.txt").read_text() == first


def test_extract_tenant_domains_dry_run_does_not_write(tmp_path, monkeypatch, config_dir):
    """--dry-run prints the merged file to stdout and leaves the target absent."""
    import importlib.util
    spec_path = Path(__file__).parent.parent / "scripts" / "extract_tenant_domains.py"
    spec = importlib.util.spec_from_file_location("extract_tenant_domains", spec_path)
    mod = importlib.util.module_from_spec(spec)

    qdir = tmp_path / "queries"
    qdir.mkdir()
    (qdir / "ttp_dns_beaconing.kql").write_text(
        '-- name: ttp_dns_beaconing\n'
        '| where ParentDomain !in ("example.com")\n'
    )
    (qdir / "dns_subdomain_diversity.kql").write_text(
        '-- name: dns_subdomain_diversity\n'
        'let approved = dynamic([]);\n'
    )

    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "QUERIES_DIR", qdir, raising=False)

    rc = mod.main(["--dry-run"])
    assert rc == 0
    assert not (Path(config_dir) / "lists" / "TenantDomains.txt").exists()


# ---------------------------------------------------------------------------
# CDN-filtering: extract_tenant_domains.py must not write public CDN domains
# ---------------------------------------------------------------------------


def test_extract_cdn_filter_excludes_public_domains_keeps_tenant(
    tmp_path, monkeypatch, config_dir, capsys
):
    """CDN filter: domains from KnownGoodParentDomains.txt are excluded;
    genuine tenant domains survive.

    Fixture uses a small inline slice of dns_subdomain_diversity.kql content
    that mirrors the real file structure (mixed CDN + tenant entries in a
    single !in (...) block), so the test is independent of the live file
    growing or shrinking.
    """
    import importlib.util

    spec_path = Path(__file__).parent.parent / "scripts" / "extract_tenant_domains.py"
    spec = importlib.util.spec_from_file_location("extract_tenant_domains", spec_path)
    mod = importlib.util.module_from_spec(spec)

    # Write a fixture that mirrors a slice of the real dns_subdomain_diversity.kql.
    # It contains CDN domains (microsoft.com, google.com, cloudflare.com) alongside
    # the genuine tenant domains that appear in the current file.
    qdir = tmp_path / "queries"
    qdir.mkdir()
    (qdir / "dns_subdomain_diversity.kql").write_text(
        '-- name: dns_subdomain_diversity\n'
        '| where ParentDomain !in (\n'
        '    "microsoft.com", "microsoftonline.com", "office.com",\n'
        '    "google.com", "googleapis.com",\n'
        '    "cloudflare.com", "cloudfront.net",\n'
        '    "example.com", "example.net", "example.org"\n'
        '    )\n'
    )

    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "QUERIES_DIR", qdir, raising=False)

    rc = mod.main([])
    assert rc == 0

    out_path = Path(config_dir) / "lists" / "TenantDomains.txt"
    assert out_path.exists()
    written = out_path.read_text()

    # Public CDN / Microsoft domains must NOT appear in TenantDomains.txt.
    assert "microsoft.com" not in written
    assert "google.com" not in written
    assert "cloudflare.com" not in written

    # Genuine tenant domains MUST appear.
    assert "example.com" in written

    # The stderr skip summary must name the filtered count.
    captured = capsys.readouterr()
    assert "Skipped" in captured.err
    assert "CDN" in captured.err


# --- Soft-fail on malformed user queries ---


def test_list_queries_skips_malformed_user_query_with_warning(
    tmp_path, monkeypatch, capsys
):
    """A user-installed .kql missing required frontmatter must not break the
    library: list_queries() skips it with a stderr warning and returns the
    rest. Reason: a single bad user file (e.g. left over from a pre-rename
    install) was hard-failing the entire library command.
    """
    monkeypatch.setenv("XDR_CLI_HOME", str(tmp_path / ".xdr-cli"))
    user_queries = tmp_path / ".xdr-cli" / "queries"
    user_queries.mkdir(parents=True)
    # Bad: no `-- tier:` line.
    (user_queries / "broken.kql").write_text(
        "-- name: broken\n"
        "-- description: missing tier frontmatter\n"
        "-- params: hours=24\n"
        "DeviceInfo | take 1\n"
    )
    # Good: complete frontmatter.
    (user_queries / "good_user.kql").write_text(
        "-- name: good_user\n"
        "-- description: properly formed user query\n"
        "-- tier: r3\n"
        "-- params: hours=24\n"
        "DeviceInfo | take 1\n"
    )

    from xdr_cli.queries import list_queries

    queries = list_queries()
    names = {q.name for q in queries}
    assert "good_user" in names
    assert "broken" not in names

    captured = capsys.readouterr()
    assert "broken.kql" in captured.err
    assert "tier" in captured.err.lower()
