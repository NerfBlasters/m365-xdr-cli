"""Tests for the fail-soft KQL table-name tokenizer.

The tokenizer is intentionally NOT a real parser — it strips comments and
``let`` bindings, then scans for capitalized identifiers at pipeline entry
points. Anything that surprises it returns ``[]`` instead of raising; the
recorder annotation must never crash a hunt.
"""

from xdr_cli.kql_parse import extract_tables


def test_single_table():
    assert extract_tables("CloudAppEvents | take 10") == ["CloudAppEvents"]


def test_table_with_where():
    assert extract_tables(
        "DeviceProcessEvents | where Timestamp > ago(1h)"
    ) == ["DeviceProcessEvents"]


def test_union_of_tables():
    kql = "union DeviceEvents, DeviceFileEvents | take 1"
    assert sorted(extract_tables(kql)) == ["DeviceEvents", "DeviceFileEvents"]


def test_join_tables():
    kql = (
        "AADSignInEventsBeta | join kind=inner "
        "(IdentityLogonEvents) on AccountObjectId"
    )
    assert sorted(extract_tables(kql)) == [
        "AADSignInEventsBeta", "IdentityLogonEvents",
    ]


def test_comments_ignored():
    kql = "// CloudAppEvents in a comment\nDeviceProcessEvents | take 1"
    assert extract_tables(kql) == ["DeviceProcessEvents"]


def test_malformed_returns_empty_not_raises():
    # Fail-soft — junk input must not propagate.
    assert extract_tables("this is not kql at all {}{}{}") == []


def test_empty_string():
    assert extract_tables("") == []


def test_let_binding_not_confused_as_table():
    kql = "let horizon = ago(1d); CloudAppEvents | where Timestamp > horizon"
    assert extract_tables(kql) == ["CloudAppEvents"]


def test_block_comment_ignored():
    kql = "/* DeviceFileEvents\n   DeviceInfo */ CloudAppEvents | take 1"
    assert extract_tables(kql) == ["CloudAppEvents"]


def test_extract_tables_filters_out_column_names():
    # Synthetic query — Application, IsManaged, RiskLevelDuringSignIn
    # are columns, not tables, but they start with capitals and match the _IDENT pattern.
    kql = """AADSignInEventsBeta
| where Timestamp between(datetime(2026-01-01T00:00:00Z) .. datetime(2026-01-01T06:00:00Z))
| where AccountUpn =~ "analyst@example.com"
| project Timestamp, AccountUpn, IPAddress, Country, City, State,
          Application, LogonType, ErrorCode, ConditionalAccessStatus,
          IsManaged, IsCompliant, AuthenticationRequirement,
          RiskLevelDuringSignIn, RiskLevelAggregated
| order by Timestamp asc"""
    tables = extract_tables(kql)
    assert tables == ["AADSignInEventsBeta"]
    # Column names that previously leaked must be gone.
    for col in ("Application", "IsManaged", "RiskLevelDuringSignIn"):
        assert col not in tables


def test_extract_tables_returns_empty_for_unparseable_kql():
    assert extract_tables("not even close to KQL syntax {{{}}}") == []
    assert extract_tables("") == []
