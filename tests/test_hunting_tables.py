"""The table registry is the single source for the probe and the tokenizer."""

import re
from pathlib import Path

from xdr_cli.hunting_tables import KNOWN_TABLES, PROBE_TABLES, render_schema_probe
from xdr_cli.kql_parse import extract_tables
from xdr_cli.queries import parse_frontmatter
from xdr_cli.schema_graph.ingest import infer_direct_table_lineage

PROBE_PATH = Path(__file__).parent.parent / "src/xdr_cli/queries/sys_schema_probe.kql"


def test_packaged_probe_matches_registry():
    assert PROBE_PATH.read_text(encoding="utf-8") == render_schema_probe(), (
        "sys_schema_probe.kql is stale; run scripts/build_schema_probe.py"
    )


def test_probe_queries_exactly_the_registry_tables():
    # Read the packaged file, not load_query(), so a user override cannot mask drift.
    _meta, kql = parse_frontmatter(PROBE_PATH.read_text(encoding="utf-8"))
    arms = re.findall(r'\((\w+) \| getschema \| extend TableName = "(\w+)"\)', kql)
    assert [source for source, _label in arms] == list(PROBE_TABLES)
    assert all(source == label for source, label in arms)


def test_registry_is_sorted_and_unique():
    assert list(PROBE_TABLES) == sorted(set(PROBE_TABLES))


def test_probe_frontmatter_survives_generation():
    meta, _kql = parse_frontmatter(render_schema_probe())
    assert meta["name"] == "sys_schema_probe"
    assert meta["tier"] == "utility"


def test_tokenizer_accepts_every_probe_table():
    assert set(PROBE_TABLES) <= KNOWN_TABLES
    for table in PROBE_TABLES:
        assert extract_tables(f"{table} | take 1") == [table]


def test_workspace_tables_previously_missing_from_tokenizer():
    assert extract_tables("SigninLogs | join (AuditLogs) on CorrelationId") == [
        "SigninLogs", "AuditLogs",
    ]


def test_legacy_and_current_agent_tables_stay_distinct():
    assert {"AIAgentsInfo", "AgentsInfo"} <= set(PROBE_TABLES)
    assert extract_tables("union AIAgentsInfo, AgentsInfo") == ["AIAgentsInfo", "AgentsInfo"]


def test_tokenizer_only_legacy_name_is_now_probed():
    assert "ThreatIntelligenceIndicator" in PROBE_TABLES


def test_passive_lineage_accepts_workspace_tables():
    assert infer_direct_table_lineage("SigninLogs | where TimeGenerated > ago(1h)") == "SigninLogs"
