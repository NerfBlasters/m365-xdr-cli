"""Fail-soft KQL table-name tokenizer.

Used by the session recorder to populate ``tables_referenced`` on hunt
invocation records. Intentionally NOT a real KQL parser — Microsoft's KQL
grammar is complex enough that a faithful implementation would be a
multi-hundred-line job for marginal value. This tokenizer recognises the
common shapes (``Table | ...``, ``union A, B``, ``join (Other) on ...``,
``let`` bindings, ``//`` and ``/* */`` comments) and returns ``[]`` on
anything else.

The whole entry point is wrapped in ``try/except Exception: return []`` so a
recorder annotation can never crash the hunt — recording is best-effort, the
operator's command output is the contract.

Known false-negatives:
  * ``union (A | take 1), (B | take 1)`` may capture only the first table.
    Paren-balanced KQL parsing is a real parser's job; this tokenizer stops
    at the first ``|`` or ``;`` after ``union`` for Pattern C.
"""

from __future__ import annotations

import re

# KQL operators / functions / keywords that follow a ``|`` and must NOT be
# treated as table names. The list is closed: false positives here mean we
# silently drop a real table; false negatives mean we tag an operator as a
# table. Both are recoverable downstream (training-map noise, not crashes),
# but this list is the conservative cut.
_KQL_KEYWORDS: frozenset[str] = frozenset(
    {
        "summarize", "where", "extend", "project", "take", "top",
        "order", "sort", "join", "union", "lookup",
        "mv-apply", "mv-expand", "render", "evaluate", "count",
        "distinct", "externaldata", "print", "search", "find",
        "make-series", "parse", "parse-where", "parse-kv",
        "range", "datatable", "let", "as", "on",
        "by", "asc", "desc", "kind", "inner", "outer", "left",
        "right", "anti", "semi", "fullouter", "leftouter",
        "rightouter", "leftanti", "rightanti", "leftsemi",
        "rightsemi", "invoke", "getschema", "fork", "facet",
        "limit", "sample", "sample-distinct", "tag", "consume",
        "materialize", "pack", "pack_all", "unpack",
    }
)

# Table identifiers in KQL conventionally start with an uppercase letter
# (CloudAppEvents, DeviceProcessEvents, AADSignInEventsBeta). Lowercase
# identifiers in pipeline position are operators or column refs.
_IDENT = r"[A-Z][A-Za-z0-9_]+"

# Strip ``//``-style line comments.
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# Strip ``/* ... */`` block comments. Non-greedy + DOTALL so multi-line
# block comments are removed wholesale before the line-comment pass —
# otherwise capitalised identifiers buried inside a block comment would
# be tagged as live tables.
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

# ``let name =`` head only. Replaced with a newline so the RHS expression
# (which often begins with a table identifier) is recognised by Pattern A
# as a statement-start.
_LET_HEAD_RE = re.compile(r"\blet\s+\w+\s*=\s*", re.IGNORECASE)

# Known Defender XDR / Microsoft Graph hunting table names. Used to filter
# extract_tables() output so column names with PascalCase don't leak into
# tables_referenced. List sourced from schema_probe.kql and docs/schema_pivots.md —
# keep in sync when new tables ship.
_KNOWN_TABLES: frozenset[str] = frozenset({
    # Defender for Endpoint
    "AlertEvidence", "AlertInfo", "BehaviorEntities", "BehaviorInfo",
    "DeviceEvents", "DeviceFileCertificateInfo", "DeviceFileEvents",
    "DeviceImageLoadEvents", "DeviceInfo", "DeviceLogonEvents",
    "DeviceNetworkEvents", "DeviceNetworkInfo", "DeviceProcessEvents",
    "DeviceRegistryEvents", "DeviceBaselineComplianceAssessment",
    "DeviceBaselineComplianceAssessmentKB", "DeviceBaselineComplianceProfiles",
    "DeviceTvmBrowserExtensions", "DeviceTvmBrowserExtensionsKB",
    "DeviceTvmCertificateInfo", "DeviceTvmHardwareFirmware",
    "DeviceTvmInfoGathering", "DeviceTvmInfoGatheringKB",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmSoftwareEvidenceBeta", "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities", "DeviceTvmSoftwareVulnerabilitiesKB",
    # Defender for Office 365
    "EmailAttachmentInfo", "EmailEvents", "EmailPostDeliveryEvents",
    "EmailUrlInfo", "UrlClickEvents",
    # Defender for Identity / Cloud Apps / Entra
    "AADSignInEventsBeta", "AADSpnSignInEventsBeta",
    "CloudAppEvents", "CloudAuditEvents", "CloudDnsEvents", "CloudProcessEvents",
    "CloudStorageAggregatedEvents",
    "IdentityAccountInfo", "IdentityDirectoryEvents", "IdentityEvents",
    "IdentityInfo", "IdentityLogonEvents", "IdentityQueryEvents",
    "EntraIdSignInEvents", "EntraIdSpnSignInEvents",
    # Campaign / Threat Intelligence
    "CampaignInfo", "DataSecurityBehaviors", "DataSecurityEvents",
    "ThreatIntelligenceIndicator",
    # Exposure / Malware / Auxiliary
    "DisruptionAndResponseEvents", "ExposureGraphEdges", "ExposureGraphNodes",
    "FileMaliciousContentInfo", "GraphAPIAuditEvents",
    "ConnectorStatusInfo", "AIAgentsInfo",
    "MessageEvents", "MessagePostDeliveryEvents", "MessageUrlInfo",
    "OAuthAppInfo",
})

# Pattern A: identifier at the start of a statement / pipeline. Anchored to
# either the start of input or a newline / semicolon to avoid matching mid-
# expression identifiers (column refs, function args).
_STATEMENT_START_RE = re.compile(rf"(?:^|[\n;])\s*({_IDENT})\b")

# Pattern B: identifier following ``union`` / ``join`` / ``lookup``. We use
# inline case-insensitive ``(?i:...)`` for the keyword only — the identifier
# itself MUST start with a real capital so case-insensitive matching does not
# tag operator words like ``kind`` as a table.
_AFTER_KEYWORD_RE = re.compile(
    rf"\b(?i:union|join|lookup)\b[^|;]*?(?:\(\s*)?({_IDENT})\b",
)

# Pattern C: comma-continuation after ``union A, B, C``. Once we've matched
# the first table after ``union``, additional table names follow comma
# separators until the next pipe or semicolon.
_UNION_LIST_RE = re.compile(
    r"\b(?i:union)\b([^|;]*)",
)
_UNION_TABLES_RE = re.compile(rf"\b({_IDENT})\b")


def extract_tables(kql: str) -> list[str]:
    """Return a deduplicated list of KQL table names referenced by ``kql``.

    Recognises:
      * single-table queries (``Table | take 10``)
      * ``union A, B, C``
      * ``X | join (Y) on ...`` and ``X | lookup (Y) on ...``
      * ``//`` line comments and ``/* ... */`` block comments (stripped
        before scanning)
      * ``let name = expr;`` bindings (stripped before scanning)

    Returns ``[]`` on empty input, junk input, or anything that raises
    internally — by design. The recorder annotation must never crash a hunt.
    Order is preservation-of-first-occurrence; callers wanting deterministic
    ordering should ``sorted()`` the result.
    """
    try:
        if not kql or not kql.strip():
            return []

        # 1. Strip block comments first — their content (including
        #    embedded ``//`` sequences) must not survive into the line-
        #    comment pass.
        cleaned = _BLOCK_COMMENT_RE.sub(" ", kql)
        # 2. Strip line comments.
        cleaned = _LINE_COMMENT_RE.sub("", cleaned)
        # 3. Replace each ``let name =`` prefix with a synthetic newline
        #    so the RHS body becomes a "statement-start" for Pattern A.
        #    The R1/R2/R3 library pattern routinely binds
        #    ``let DetailRows = TableName | ...;`` so the table reference
        #    lives inside the let RHS — we must surface it. The
        #    ``_KNOWN_TABLES`` filter at the tail rejects column names
        #    that happen to match the identifier pattern.
        cleaned = _LET_HEAD_RE.sub("\n", cleaned)

        found: list[str] = []
        seen: set[str] = set()

        def _record(name: str) -> None:
            if name in _KQL_KEYWORDS:
                return
            # Lowercase keyword check (defence in depth — _IDENT requires a
            # capital, but normalise anyway in case the keyword set grows).
            if name.lower() in _KQL_KEYWORDS:
                return
            if name in seen:
                return
            seen.add(name)
            found.append(name)

        # Pattern A: statement-start identifiers.
        for m in _STATEMENT_START_RE.finditer(cleaned):
            _record(m.group(1))

        # Pattern B: identifiers immediately after union/join/lookup. This
        # picks up ``union A`` (first table), ``join (Y)``, ``lookup (Z)``.
        for m in _AFTER_KEYWORD_RE.finditer(cleaned):
            _record(m.group(1))

        # Pattern C: union's comma-separated tail (``union A, B, C``).
        for chunk_match in _UNION_LIST_RE.finditer(cleaned):
            chunk = chunk_match.group(1)
            for m in _UNION_TABLES_RE.finditer(chunk):
                _record(m.group(1))

        # Filter to known tables only — this prevents column names with PascalCase
        # from leaking as tables, which was a real issue in production training
        # queries (covered by tests/test_kql_parse.py).
        return [t for t in found if t in _KNOWN_TABLES]
    except Exception:
        # Fail-soft. Any regex / unicode / unexpected surprise lands us here
        # — a recorder annotation must never crash the hunt.
        return []
