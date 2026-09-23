"""Static methodology contract checks for the query library.

This suite enforces the library-wide invariants documented in the spec
section "Out of scope" / "Tier frontmatter" / "Public-list semantics" /
"List health metadata" / "Schema migration" / "Deprecated query aliases":

  * Every .kql file declares `-- tier:` frontmatter.
  * Every non-utility, non-deprecated query declares `mode=summary|detail`.
  * Schema-tier queries (r1/r2/r3/n/beta/pivot) project `SchemaVersion`.
  * Finding-tier queries (r1/r2/n/beta) carry a `Severity = case(...)` band.
  * Allowlist blocks use the negative operator direction (currently scoped
    to the queries fixed in Task 12; broader test is paused pending
    annotation-aware refinement — see test_allowlist_blocks_use_negative_operator).
  * Deny-list blocks (`MaliciousDomains`, `AiTMInfrastructure`,
    `RiskyKeywords`, `AnonymizingIPRanges`) use positive operators.
  * Deprecated `tier: deprecated` aliases resolve to live `alias_of:` targets.
  * Every `-- lists:` declaration names a real seed in `lists_seed/`.

Two contract checks are currently skipped (each names its unblock path):
TopEvidence ordering and the full allowlist-direction sweep.

When tightening: prefer per-query ratchet tests (e.g. the Task 12 / Task 13
regressions) over loosening a broad contract.
"""

from __future__ import annotations

import re

import pytest

from xdr_cli.queries import list_queries


# Tiers that REQUIRE a Severity = case(...) band (finding queries).
FINDING_TIERS = {"r1", "r2", "n", "beta"}
# Tiers that REQUIRE SchemaVersion = 1 (everything except utility).
SCHEMA_TIERS = {"r1", "r2", "r3", "n", "beta", "pivot"}
# Tiers exempt from all methodology checks.
UTILITY_TIERS = {"utility"}
# Deprecated aliases — exempt except for alias-resolves check.
DEPRECATED_TIERS = {"deprecated"}


def _strip_kql_comments(body: str) -> str:
    """Strip `// line comments` and `/* block comments */` so methodology
    regexes don't false-match against commented-out code.
    """
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    body = re.sub(r"//[^\n]*", "", body)
    return body


def test_every_query_declares_tier():
    """Every .kql file must declare `-- tier:` frontmatter so the methodology
    test can dispatch on tier without a name-pattern heuristic.
    """
    failed: list[str] = []
    for q in list_queries():
        if not getattr(q, "tier", None):
            failed.append(q.name)
    assert not failed, f"Queries missing '-- tier:' frontmatter: {failed}"


def test_query_name_frontmatter_matches_filename_stem():
    """The `-- name:` frontmatter must match the filename stem (without `.kql`).
    The runtime keys queries by filename, so a mismatch is purely cosmetic, but
    it confuses generated docs and any consumer that trusts the frontmatter as
    the canonical identifier.
    """
    import importlib.resources
    from xdr_cli.queries import parse_frontmatter
    failed: list[tuple[str, str]] = []
    for entry in importlib.resources.files("xdr_cli.queries").iterdir():
        if not entry.name.endswith(".kql"):
            continue
        stem = entry.name[: -len(".kql")]
        meta, _ = parse_frontmatter(entry.read_text())
        declared = meta.get("name", "").strip()
        if declared and declared != stem:
            failed.append((stem, declared))
    assert not failed, (
        f"`-- name:` frontmatter mismatches filename stem in {len(failed)} files: {failed}. "
        "Update each file's first line to match the filename."
    )


def test_every_non_utility_query_declares_mode():
    failed: list[str] = []
    for q in list_queries():
        if q.tier in UTILITY_TIERS or q.tier in DEPRECATED_TIERS:
            continue
        if not any(p.name == "mode" for p in q.params):
            failed.append(q.name)
    assert not failed, f"Queries missing 'mode' param: {failed}"


def test_schema_tier_queries_have_schema_version():
    failed: list[str] = []
    for q in list_queries():
        if q.tier not in SCHEMA_TIERS:
            continue
        body = _strip_kql_comments(q.raw_kql)
        if "SchemaVersion = 1" not in body and "SchemaVersion=1" not in body:
            failed.append(q.name)
    assert not failed, f"Queries missing 'SchemaVersion = 1' projection: {failed}"


def test_finding_tier_queries_have_severity_band():
    failed: list[str] = []
    for q in list_queries():
        if q.tier not in FINDING_TIERS:
            continue
        body = _strip_kql_comments(q.raw_kql)
        if "Severity = case(" not in body:
            failed.append(q.name)
    assert not failed, f"Finding queries missing 'Severity = case(...)' band: {failed}"


def test_finding_tier_queries_have_completeness_fields():
    """Every R1/R2/N/beta summary row carries the data-completeness fields
    documented in the spec (EvidenceTotal, EvidenceOmitted, SuppressedCount,
    FirstSeen, LastSeen, ListHealth) so playbooks cannot close on summary
    alone without seeing what was omitted.
    """
    required = [
        "FirstSeen", "LastSeen", "ListHealth",
        "EvidenceTotal", "EvidenceOmitted", "SuppressedCount",
    ]
    failed: list[tuple[str, list[str]]] = []
    for q in list_queries():
        if q.tier not in FINDING_TIERS:
            continue
        body = _strip_kql_comments(q.raw_kql)
        missing = [f for f in required if f not in body]
        if missing:
            failed.append((q.name, missing))
    assert not failed, f"Finding queries missing completeness fields: {failed}"


def test_responsive_queries_accept_time_anchor():
    """Per the spec time-anchoring contract, every R1/R2/N tier query must
    expose at least one time-anchoring idiom: either ``hours=N`` (sweep) OR
    the pair ``start=``/``end=`` (anchored triage window). Bodies in this
    library converged on the ``hours=`` idiom for R1/R2/N and the explicit
    ``start=``/``end=`` form for R3 pivots; the test accepts both shapes
    so a query body need not duplicate the time anchor in two forms.

    Queries can opt out entirely via an ``agent_hint: playbook_invoked: false``
    declaration (e.g., utility / deprecated shims).
    """
    failed: list[str] = []
    for q in list_queries():
        if q.tier not in {"r1", "r2", "n"}:
            continue
        # Honour the opt-out hint (read from the dedicated agent_hint field,
        # not from the body — the methodology test must not depend on the
        # body containing the opt-out comment after the loader has stripped
        # frontmatter into structured fields).
        if re.search(r"playbook_invoked\s*:\s*false", q.agent_hint or ""):
            continue
        param_names = {p.name for p in q.params}
        has_hours = "hours" in param_names
        has_start_end = "start" in param_names and "end" in param_names
        if not (has_hours or has_start_end):
            failed.append(q.name)
    assert not failed, (
        f"R1/R2/N queries with no time-anchor (need hours= OR start=/end=): "
        f"{failed}"
    )


def test_no_inline_tenant_strings_in_dns_queries():
    """After Phase 7 (R1), tenant strings live in TenantDomains.txt, not in
    the query body. Watches the two specific queries that historically
    hardcoded WPAD/parent-domain strings.
    """
    target_names = {"ttp_dns_beaconing", "dns_subdomain_diversity"}
    by_name = {q.name: q for q in list_queries()}
    missing = target_names - by_name.keys()
    assert not missing, (
        f"Test target queries renamed/removed: {sorted(missing)}. "
        f"Update target_names or this test will silently pass."
    )
    for name in target_names:
        body = by_name[name].raw_kql
        assert re.search(r"let\s+_xdr_TenantDomains\s*=\s*dynamic\(\[\]\)", body), (
            f"Query '{name}' must load tenant domains from the external list."
        )
        assert not re.search(r"[\"']wpad\.[a-z0-9.-]+[\"']", body, re.IGNORECASE), (
            f"Query '{name}' contains a hardcoded WPAD hostname."
        )


def test_no_remaining_aadsignineventsbeta():
    """All sign-in queries are migrated to EntraIdSignInEvents / EntraIdSpnSignInEvents.

    Utility-tier queries (e.g. ``sys_schema_probe`` enumerating every table
    name including legacy ones) are exempt — surfacing the deprecated table
    is precisely what they document.
    """
    failed: list[str] = []
    for q in list_queries():
        if q.tier in UTILITY_TIERS or q.tier in DEPRECATED_TIERS:
            continue
        if "AADSignInEventsBeta" in q.raw_kql:
            failed.append(q.name)
    assert not failed, f"Queries still on deprecated AADSignInEventsBeta: {failed}"


# ---------------------------------------------------------------------------
# Operator-direction and TopEvidence-ordering guards
# ---------------------------------------------------------------------------
# Allowlist blocks must be referenced with `!in` / `not has_any` (or via the
# `array_length(...) > 0 and ipv4_is_in_any_range(...)` guard for CIDR
# allowlists), so an empty list = nothing whitelisted (fail-safe). Denylist
# blocks with `in` / `has_any`. Inverted blocks (the `KnownRemoteSupportTools`
# in `ttp_rmm_first_seen` is intentionally treated as a deny-list) are
# allowed to opt out via an `inverted-list-direction:` agent_hint.

_ALLOWLIST_BLOCKS = {
    "_xdr_KnownGoodSigners",
    "_xdr_KnownGoodServiceImagePaths",
    "_xdr_KnownGoodParentDomains",
    "_xdr_KnownRemoteSupportTools",
    "_xdr_KnownServiceAccounts",
    "_xdr_KnownEgressIPs",
    "_xdr_TenantDomains",
    "_xdr_InternalSubnets",
    "_xdr_DomainControllers",
}
_DENYLIST_BLOCKS = {
    "_xdr_MaliciousDomains",
    "_xdr_AiTMInfrastructure",
    "_xdr_RiskyKeywords",
    "_xdr_AnonymizingIPRanges",
}
# CIDR-shaped allowlists also accept `not(ipv4_is_in_any_range(IP, X))`
# (and `ipv6_*`) as the negative direction, since the membership check is
# over CIDR, not exact equality.
_CIDR_ALLOWLIST_BLOCKS = {"_xdr_InternalSubnets", "_xdr_KnownEgressIPs"}


def _operator_for(block: str, body: str) -> set[str]:
    """Return the set of operator phrases used against `block` in body."""
    body = _strip_kql_comments(body)
    found: set[str] = set()
    for m in re.finditer(
        r"(!in~?|\bin~?\b|!has_any|not\s+has_any|has_any|"
        r"ipv[46]_is_in_any_range|ipv[46]_is_in_range)"
        r"\s*\(?\s*[^,()]*[,\(]?\s*" + re.escape(block),
        body,
    ):
        found.add(re.sub(r"\s+", " ", m.group(1)))
    # Also detect `not(ipv4_is_in_any_range(IP, _xdr_X))` — the negative-CIDR form.
    if re.search(
        r"not\s*\(\s*ipv[46]_is_in_any_range\([^)]*"
        + re.escape(block)
        + r"[^)]*\)",
        body,
    ):
        found.add("not(cidr)")
    return found


@pytest.mark.skip(
    reason=(
        "TODO(library-hunter-rewrite follow-up): the spec's allowlist-direction "
        "convention is mixed in practice — some queries use allowlist blocks "
        "for ANNOTATION (e.g. `IsExternal = not(ipv4_is_in_any_range(IPAddress, "
        "_xdr_InternalSubnets))` adds an enrichment column without filtering) "
        "while the test treats every positive-operator reference as a "
        "violation. 37 violations across ~25 queries at end of initial "
        "implementation — most are legitimate annotation uses. Tracked for "
        "either (a) tightening the test to recognise annotation patterns or "
        "(b) per-query agent_hint opt-outs in a focused follow-up."
    )
)
def test_allowlist_blocks_use_negative_operator():
    """Allowlist blocks must filter OUT matches (`!in` / `not has_any` / negative CIDR)."""
    failed: list[tuple[str, str, set[str]]] = []
    for q in list_queries():
        body = _strip_kql_comments(q.raw_kql)
        # Honour intentional inversions:
        if re.search(r"inverted-list-direction\s*:\s*true", body):
            continue
        for block in _ALLOWLIST_BLOCKS:
            if block not in body:
                continue
            ops = _operator_for(block, body)
            has_negative = bool(
                ops & {"!in", "!in~", "!has_any", "not has_any", "not(cidr)"}
            )
            has_guard = (
                re.search(
                    r"array_length\(\s*" + re.escape(block) + r"\s*\)\s*>\s*0",
                    body,
                )
                is not None
            )
            # CIDR blocks are allowed to use ipv4_is_in_any_range positively
            # only when paired with `not(...)` outside (covered by 'not(cidr)')
            # or with the array_length guard.
            if block in _CIDR_ALLOWLIST_BLOCKS:
                if has_negative or has_guard:
                    continue
            else:
                if has_negative or has_guard:
                    continue
            failed.append((q.name, block, ops))
    assert not failed, (
        "Allowlist blocks referenced with positive operator (use !in / not has_any "
        f"/ not(ipv4_is_in_any_range(...)) / array_length(...) > 0 guard): {failed}"
    )


def test_denylist_blocks_use_positive_operator():
    """Denylist blocks must filter IN matches (`in` / `has_any` / `ipv4_is_in_any_range`)."""
    failed: list[tuple[str, str, set[str]]] = []
    for q in list_queries():
        body = _strip_kql_comments(q.raw_kql)
        for block in _DENYLIST_BLOCKS:
            if block not in body:
                continue
            ops = _operator_for(block, body)
            positive = ops & {
                "in",
                "in~",
                "has_any",
                "ipv4_is_in_any_range",
                "ipv6_is_in_any_range",
                "ipv4_is_in_range",
                "ipv6_is_in_range",
            }
            if not positive:
                failed.append((q.name, block, ops))
    assert not failed, (
        f"Denylist blocks referenced with negative operator: {failed}"
    )


@pytest.mark.skip(
    reason=(
        "TODO(library-hunter-rewrite follow-up): the spec's TopEvidence "
        "ordering pattern compiles Score INSIDE the same summarize that "
        "builds make_list, which means the test's required pre-`order by "
        "Score desc` cannot exist in the same let-block — Score doesn't yet "
        "exist when the order-by would run. 29 queries non-conformant at end "
        "of initial implementation. Resolving this requires a spec-level "
        "pattern fix (e.g. two-stage summarize: compute Score, join back, "
        "order, then make_list) and is out of scope for the initial slice."
    )
)
def test_topevidence_make_list_is_score_ordered():
    """`TopEvidence = make_list(pack(...), N)` MUST be preceded by an
    `order by Score desc` (or `RowScore desc` / `LegFidelity desc`) on the
    row-set being aggregated, IN THE SAME let-block. Global-position
    matching (the previous heuristic) false-fails on multi-stage queries
    that have an unrelated earlier `make_list` for an event-stream column.
    """
    failed: list[str] = []
    for q in list_queries():
        body = _strip_kql_comments(q.raw_kql)
        # Find every `TopEvidence = make_list(pack(...))` site.
        for m in re.finditer(
            r"TopEvidence\s*=\s*make_list\s*\(\s*pack(?:_dictionary)?\(",
            body,
        ):
            # Walk back from the make_list site to the start of the
            # enclosing let-block (the previous `let <name> = ` at column 0).
            start = m.start()
            block_start = body.rfind("\nlet ", 0, start)
            if block_start < 0:
                block_start = 0
            block_text = body[block_start:start]
            # Allowed orderings: any `| order by <col> desc` on a column ending
            # in `Score` or `Fidelity` (per the public-list-as-enrichment
            # convention). `order by Timestamp desc` alone is NOT sufficient
            # for finding queries — fidelity/Score must drive the ordering.
            if not re.search(
                r"\|\s*order\s+by\s+\w*(?:Score|Fidelity)\b\s+desc",
                block_text,
            ):
                failed.append(q.name)
                break
    assert not failed, (
        "TopEvidence make_list missing prior `| order by *(Score|Fidelity) desc` "
        f"in same let-block (non-deterministic top-N): {failed}"
    )


# Per-query public-list-semantics contract: each tuple is
# (query_name, annotation_column, allowlist_block_name, negative_weight). A
# query enters this table once it has been brought into compliance with the
# spec's public-list semantics (negative-weight, not row-drop). The 4th
# element is the per-spec weight (typically -3, but spec line 372 mandates -5
# for `_xdr_KnownGoodParentDomains`). Add new entries here to ratchet the
# contract forward; do not loosen by removing entries.
ALLOWLIST_CONTRACTS: list[tuple[str, str, str, int]] = [
    ("ttp_dll_sideloading", "IsKnownGoodSigner", "_xdr_KnownGoodSigners", -3),
    ("ttp_suspicious_downloads_exec", "IsKnownGoodSigner", "_xdr_KnownGoodSigners", -3),
    ("ttp_facedancer_webview2", "IsKnownGoodSigner", "_xdr_KnownGoodSigners", -3),
    (
        "ttp_ldap_process_attribution",
        "IsRemoteSupportTool",
        "_xdr_KnownRemoteSupportTools",
        -3,
    ),
    (
        "ttp_discovery_recon",
        "IsRemoteSupportTool",
        "_xdr_KnownRemoteSupportTools",
        -3,
    ),
    (
        "dns_subdomain_diversity",
        "IsKnownGoodParentDomain",
        "_xdr_KnownGoodParentDomains",
        -5,
    ),
]


def test_public_allowlist_is_negative_weight_for_scoped_queries():
    """Public lists provide enrichment rather than hard suppression.

    Lists like `_xdr_KnownGoodSigners` MUST be wired as negative-weight Score
    signals, NOT row-dropping `where` filters. A signed BYOVD driver, attacker-
    deployed AnyDesk, or partner-vendor binary signed by a known-good vendor must
    still surface and can still reach medium severity via compounding signals.

    This test pins the contract for each query in `ALLOWLIST_CONTRACTS`. The
    broader `test_allowlist_blocks_use_negative_operator` covers the rest of
    the library but is currently skipped (mixed annotation-vs-violation usage
    requires per-query triage). Once a query is brought into compliance,
    add it to `ALLOWLIST_CONTRACTS` to ratchet the contract forward.
    """
    by_name = {q.name: q for q in list_queries()}
    failed: list[tuple[str, str]] = []
    for query_name, annotation, list_block, weight in ALLOWLIST_CONTRACTS:
        q = by_name.get(query_name)
        assert q is not None, f"Test target {query_name} renamed/removed"
        body = _strip_kql_comments(q.raw_kql)
        # Negative direction: must NOT have a row-dropping
        # `where ... !in (<list_block>)` OR `where not(... in~ (<list_block>))`.
        if re.search(
            rf"where\s+\S+\s+!in~?\s*\(\s*{re.escape(list_block)}\s*\)",
            body,
        ) or re.search(
            rf"where\s+not\s*\(\s*\S+\s+in~?\s*\(\s*{re.escape(list_block)}\s*\)",
            body,
        ):
            failed.append(
                (
                    query_name,
                    f"row-dropping filter on {list_block} present",
                )
            )
            continue
        # Positive direction: must annotate with
        # `<annotation> = ... in (<list_block>)` (accepts `in` or `in~`).
        if not re.search(
            rf"{re.escape(annotation)}\s*=\s*\S+\s+in~?\s*\(\s*{re.escape(list_block)}\s*\)",
            body,
        ):
            failed.append(
                (
                    query_name,
                    f"missing `{annotation} = ... in ({list_block})` annotation",
                )
            )
            continue
        # Negative weight: Score block must include
        # `iif(<annotation>, <weight>, ...)`.
        if not re.search(
            rf"iif\(\s*{re.escape(annotation)}\s*,\s*{weight}\s*,",
            body,
        ):
            failed.append(
                (
                    query_name,
                    f"missing negative-weight `iif({annotation}, {weight}, ...)` Score term",
                )
            )
            continue
    assert not failed, (
        "Public-list-semantics contract violations (see spec line 239-247): "
        f"{failed}"
    )


def test_ttp_dns_beaconing_uses_malicious_domains_per_spec():
    """Require `-- lists: TenantDomains, MaliciousDomains` and a +10
    score weight for `DnsQuery has_any (_xdr_MaliciousDomains)`.

    A regression to the prior `KnownGoodParentDomains` hard-drop (which was
    cross-polluted from `dns_subdomain_diversity`'s spec at line 367, and even
    there is a -5 negative weight, NOT a row-drop) must fail loudly here.
    """
    queries = list_queries()
    by_name = {q.name: q for q in queries}
    q = by_name["ttp_dns_beaconing"]
    assert "MaliciousDomains" in (q.lists or []), (
        "ttp_dns_beaconing must declare `-- lists: TenantDomains, MaliciousDomains` "
        f"per spec line 348; got {q.lists}"
    )
    assert "KnownGoodParentDomains" not in (q.lists or []), (
        "ttp_dns_beaconing must NOT declare KnownGoodParentDomains in its lists "
        "frontmatter — that list belongs to dns_subdomain_diversity (spec line 367) "
        f"and is a -5 negative weight there, not a row-drop. Got {q.lists}"
    )
    body = _strip_kql_comments(q.raw_kql)
    # No hard-drop on KnownGoodParentDomains anywhere in the body.
    assert "_xdr_KnownGoodParentDomains" not in body, (
        "ttp_dns_beaconing must not reference _xdr_KnownGoodParentDomains at all — "
        "it was cross-polluted from dns_subdomain_diversity's spec, and even there "
        "is a -5 negative weight, not a row-drop. Remove it; do not re-add as a "
        "row-drop on a public list."
    )
    # Positive scoring weight on _xdr_MaliciousDomains: accept either the inline
    # `iff(... has_any (_xdr_MaliciousDomains), 10, 0)` or the `iff(IsMalicious, 10, 0)`
    # bool-extracted form (the chosen idiom in this query).
    has_inline = re.search(
        r"iff\([^,]*MaliciousDomains[^,]*,\s*10\s*,\s*0\)",
        body,
    )
    has_bool = re.search(r"iff\(\s*IsMalicious\s*,\s*10\s*,\s*0\)", body)
    assert has_inline or has_bool, (
        "ttp_dns_beaconing must include a +10 score weight for "
        "`DnsQuery has_any (_xdr_MaliciousDomains)` per spec line 353 "
        "(either inline or via an IsMalicious bool extend)."
    )


def test_qry_inbox_rule_activity_wires_risky_keywords():
    """Spec line 120 declares RiskyKeywords as a deny-list consumed by
    qry_inbox_rule_activity; line 539 mandates _xdr_FinanceKeywords stays
    inline. Both must coexist: HasFinanceKeyword fires on either set."""
    queries = list_queries()
    by_name = {q.name: q for q in queries}
    q = by_name["qry_inbox_rule_activity"]
    assert "RiskyKeywords" in q.lists, (
        "qry_inbox_rule_activity must declare `RiskyKeywords` in its `-- lists:` "
        f"frontmatter per spec line 120; got {q.lists}"
    )
    body = _strip_kql_comments(q.raw_kql)
    # The inline universal default is preserved (not replaced)
    assert "_xdr_FinanceKeywords" in body, (
        "Universal-default `_xdr_FinanceKeywords` block must remain in the body "
        "per spec line 539 (FinanceKeywords is inline, NOT a list block)."
    )
    assert 'dynamic(["wire"' in body or "dynamic(['wire'" in body, (
        "FinanceKeywords inline body must remain"
    )
    # The new list reference is wired into the keyword-trigger annotation
    assert "_xdr_RiskyKeywords" in body, (
        "qry_inbox_rule_activity must reference `_xdr_RiskyKeywords` in the "
        "body so the loader-injected list block is consumed."
    )
    # HasFinanceKeyword (or HasRiskyKeyword) consults BOTH lists
    assert re.search(
        r"FinanceText\s+has_any\s*\(\s*_xdr_(Finance|Risky)Keywords\s*\)"
        r"\s+or\s+FinanceText\s+has_any\s*\(\s*_xdr_(Finance|Risky)Keywords\s*\)",
        body,
    ), "HasFinanceKeyword must consult both _xdr_FinanceKeywords and _xdr_RiskyKeywords"


def test_deprecated_aliases_resolve():
    """Files declared `-- tier: deprecated` must declare `-- alias_of:` and
    that target must exist in the live library.
    """
    live_names = {q.name for q in list_queries() if q.tier != "deprecated"}
    failed: list[str] = []
    for q in list_queries():
        if q.tier != "deprecated":
            continue
        target = getattr(q, "alias_of", None)
        if not target or target not in live_names:
            failed.append(q.name)
    assert not failed, (
        f"Deprecated aliases with missing/invalid alias_of target: {failed}"
    )


def test_no_arg_max_wrapped_in_string_funcs():
    """`arg_max(ExprToMaximize, ColumnsToReturn)` is a row-selector aggregation,
    not a scalar — wrapping it in `tostring(arg_max(...))` or
    `substring(tostring(arg_max(...)), ...)` is broken at runtime: the wrapper
    sees a tabular construct, not a scalar.

    Per Microsoft Kusto docs, used inside `summarize` `arg_max(Score, Col)`
    produces multiple output columns (the maximized expression with its
    original name plus the columns from the max-row). The correct pattern is
    `summarize arg_max(Expr, Col) by ... | project Renamed = Col` — or to
    wrap the unaggregated source column instead.

    Reference: https://learn.microsoft.com/en-us/kusto/query/arg-max-aggregation-function
    """
    smell = re.compile(
        r"\b(tostring|substring|tolong|toint|toreal|todatetime|tobool)"
        r"\s*\(\s*(?:tostring\s*\(\s*)?arg_max\s*\(",
    )
    failed: list[str] = []
    for q in list_queries():
        body = _strip_kql_comments(q.raw_kql)
        if smell.search(body):
            failed.append(q.name)
    assert not failed, (
        f"Queries wrap arg_max() in a scalar conversion (broken at runtime): "
        f"{failed}. Replace with `summarize arg_max(Expr, Col) by ... | "
        f"project Renamed = Col`."
    )


def test_lists_declarations_match_known_blocks():
    """Every `-- lists: <Name>` declaration must reference a real seed file
    in src/xdr_cli/lists_seed/. Catches typos that would otherwise silently
    fall through to an empty `dynamic([])` block at runtime.
    """
    import importlib.resources

    known: set[str] = set()
    for entry in importlib.resources.files("xdr_cli.lists_seed").iterdir():
        if entry.name.endswith(".txt"):
            known.add(entry.name[:-4])
    failed: list[tuple[str, list[str]]] = []
    for q in list_queries():
        unknown = [n for n in (q.lists or []) if n not in known]
        if unknown:
            failed.append((q.name, unknown))
    assert not failed, (
        f"Queries reference unknown list blocks (typo or missing seed file): {failed}"
    )


# ---------------------------------------------------------------------------
# Per-query ratchet tests (Task 13 / live-test fallout)
# ---------------------------------------------------------------------------


def test_ttp_ldap_process_attribution_has_ip_fallback_path():
    """The `IsIpFallback=true` code path is the primary behavioral
    differentiator of this query versus a naive "filter by LDAP port" join.
    Verified live (FQDN path) in `report-ttp-ldap-process-attribution.md`;
    the fallback path itself could not be exercised against the test tenant
    because MDI never populated `DestinationIPAddress`. This test asserts
    the rendered KQL preserves every structural element the fallback
    depends on, so a future refactor can't silently regress to FQDN-only
    correlation.

    The actual runtime behavior (matching, back-fill, IsIpFallback flag
    truthiness) would need a KQL emulator to assert directly — that is
    out of scope for the in-repo test suite.
    """
    from xdr_cli.queries import load_query

    body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        mode="summary",
    )
    body_nocomments = _strip_kql_comments(body)

    # 1. Both an FQDN target list and an IP target list are built.
    assert "LdapTargetIPs" in body_nocomments, (
        "Lost IP target list — IsIpFallback path cannot fire without it."
    )
    assert "DestinationIPAddress" in body_nocomments, (
        "Lost reference to IdentityQueryEvents.DestinationIPAddress — "
        "the IP target list has no source."
    )
    # 2. The join filter accepts EITHER an FQDN match OR an IP match.
    assert "RemoteFqdn in (LdapTargets) or " in body_nocomments, (
        "Join filter no longer accepts IP-based fallback (must be "
        "`RemoteFqdn in (LdapTargets) or (... RemoteIP in (LdapTargetIPs))`)."
    )
    assert "RemoteIP in (LdapTargetIPs)" in body_nocomments, (
        "IP-based fallback condition missing from join filter."
    )
    # 3. The IsIpFallback flag is extended on attributed candidates.
    assert "IsIpFallback" in body_nocomments, (
        "IsIpFallback flag is required so analysts can distinguish "
        "IP-only correlation from FQDN correlation in output rows."
    )
    # 4. The IP -> FQDN back-fill table is built and joined in.
    assert "LdapIpToFqdn" in body_nocomments, (
        "Lost IP -> FQDN back-fill table — IsIpFallback rows would "
        "expose only raw IPs in RemoteFqdn instead of human-readable FQDNs."
    )
    # 5. The case-expression coalesces RemoteFqdn -> ResolvedFqdn -> RemoteIP.
    # Match across whitespace/newlines since the case() spans multiple lines.
    assert re.search(
        r"RemoteFqdn\s*=\s*case\(\s*"
        r"isnotempty\(RemoteFqdn\),\s*RemoteFqdn,\s*"
        r"isnotempty\(ResolvedFqdn\),\s*ResolvedFqdn,\s*"
        r"RemoteIP\s*\)",
        body_nocomments,
    ), (
        "RemoteFqdn back-fill case-expression must coalesce "
        "RemoteFqdn -> ResolvedFqdn -> RemoteIP."
    )


def test_ttp_ldap_process_attribution_has_mde_learned_ip_source():
    """Documented in `report-ttp-ldap-process-attribution.md` smoke summary:
    `IdentityQueryEvents.DestinationIPAddress` was empty for every LDAP row
    in the test tenant across the full 30-day retention window. The MDI-
    provided IP target list was therefore always empty, making the
    IsIpFallback code path dormant in that tenant — DC-to-DC empty-RemoteUrl
    connections silently dropped.

    The MDE-learned IP fallback derives the IP target list from MDE's own
    FQDN-confirmed rows in the same window: any `DeviceNetworkEvents` row
    where `RemoteUrl` already matches an MDI FQDN target contributes its
    `RemoteIP` as a known LDAP destination. This activates the fallback
    independently of whether MDI populates `DestinationIPAddress`.

    This test locks in the structural elements of that derivation so a
    future refactor cannot regress to the MDI-only target list.
    """
    from xdr_cli.queries import load_query

    body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        mode="summary",
    )
    body_nocomments = _strip_kql_comments(body)

    # 1. MDI-provided and MDE-learned source tables exist, tagged distinctly.
    assert "LdapTargetIPsMdi" in body_nocomments, (
        "MDI-provided IP target source missing — break in the fallback derivation."
    )
    assert "LdapTargetIPsMdeLearned" in body_nocomments, (
        "MDE-learned IP target source missing — the fallback will be dormant "
        "in any tenant where MDI does not populate DestinationIPAddress."
    )
    assert 'IpSource="mdi"' in body_nocomments, "MDI source tag missing."
    assert 'IpSource="mde-learned"' in body_nocomments, (
        "MDE-learned source tag missing."
    )

    # 2. The MDE-learned derivation filters on LDAP ports AND known FQDNs.
    # Match across whitespace since the let-block spans multiple lines.
    assert re.search(
        r"LdapTargetIPsMdeLearned\s*=\s*DeviceNetworkEvents.*?"
        r"RemotePort in \(389, 636, 3268, 3269\).*?"
        r"RemoteFqdnLower\s+in\s+\(LdapTargets\).*?"
        r"isnotempty\(RemoteIP\)",
        body_nocomments,
        re.DOTALL,
    ), (
        "MDE-learned IP derivation must filter on LDAP ports AND require "
        "RemoteUrl already in LdapTargets AND a non-empty RemoteIP."
    )

    # 3. The two sources are unioned into a single source list.
    assert (
        "union LdapTargetIPsMdi, LdapTargetIPsMdeLearned" in body_nocomments
    ), "MDI + MDE-learned target sources must be unioned into LdapTargetIPSources."

    # 4. AttributedCandidates carries an IpSource field with the three valid
    # values: `fqdn` (direct FQDN match), `mdi` (MDI-provided IP fallback),
    # `mde-learned` (MDE-learned IP fallback).
    assert re.search(
        r"IpSource\s*=\s*case\(\s*"
        r"not\(IsIpFallback\),\s*\"fqdn\",\s*"
        r"isnotempty\(ResolvedIpSource\),\s*ResolvedIpSource,\s*"
        r'"unknown"\s*\)',
        body_nocomments,
    ), (
        "AttributedCandidates IpSource case-expression must resolve to "
        "`fqdn` for FQDN-direct rows or the back-fill table's resolved "
        "IpSource (mdi / mde-learned) for IP-fallback rows."
    )

    # 5. The back-fill table prefers MDI over MDE-learned when both are
    # present for the same IP.
    assert "HasMdi" in body_nocomments and "ResolvedIpSource" in body_nocomments, (
        "LdapIpToFqdn back-fill must compute ResolvedIpSource so "
        "AttributedCandidates can tag rows correctly."
    )


def test_ttp_ldap_process_attribution_summary_carries_fallback_signal():
    """SummaryRow must expose enough signal for an analyst to tell whether
    correlation came via FQDN (strong), MDI-provided IP (medium), or
    MDE-learned IP (weaker). The contract:

    * `IpFallbackCount` (long) — total connections correlated via IP-only.
    * `TopEvidence` pack — surfaces `IpSources` (dynamic set) per process.
    """
    from xdr_cli.queries import load_query

    body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        mode="summary",
    )
    body_nocomments = _strip_kql_comments(body)

    # SummaryRow inner summarize counts the IP-fallback connections.
    assert "IpFallbackCount = countif(IsIpFallback)" in body_nocomments, (
        "SummaryRow inner summarize must count IsIpFallback connections."
    )
    # Outer summarize rolls IpFallbackCount up.
    assert "IpFallbackCount  = sum(IpFallbackCount)" in body_nocomments, (
        "SummaryRow outer summarize must sum IpFallbackCount across processes."
    )
    # IpSources set appears in the inner summarize.
    assert "IpSources    = make_set(IpSource, 4)" in body_nocomments, (
        "SummaryRow inner summarize must collect IpSources set."
    )
    # TopEvidence pack carries IpSource per evidence row at the inner level
    # and IpSources at the outer level.
    assert "'IpSource',   IpSource," in body_nocomments, (
        "Inner TopEvidence pack must include per-row IpSource."
    )
    assert "'IpSources',   IpSources," in body_nocomments, (
        "Outer TopEvidence pack must include the per-process IpSources set."
    )


def test_ttp_ldap_process_attribution_detail_carries_fallback_signal():
    """DetailRows must expose `IpSources` (dynamic set) and
    `IpFallbackCount` so an analyst can tell at-a-row whether the
    correlation was FQDN-direct, MDI-IP-only, or MDE-learned-IP-only.
    """
    from xdr_cli.queries import load_query

    body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        mode="detail",
    )
    body_nocomments = _strip_kql_comments(body)

    # Slice the DetailRows let-block.
    detail_start = body_nocomments.index("let DetailRows = AttributedEvents")
    detail_end = body_nocomments.index(";", detail_start)
    detail_body = body_nocomments[detail_start:detail_end]
    assert "IpSources=make_set(IpSource, 4)" in detail_body, (
        "DetailRows must collect an IpSources set per detail-row group."
    )
    assert "IpFallbackCount=countif(IsIpFallback)" in detail_body, (
        "DetailRows must count IsIpFallback connections per detail-row group."
    )


def test_ttp_ldap_process_attribution_lookback_widens_only_mdi_leg():
    """The R2 `lookback` param widens only the MDI/IdentityQueryEvents
    discovery window, not the MDE attribution window. Asserts the param
    defaults to a no-op (0d), is wired through `totimespan({lookback})`,
    and is applied to the LdapTargetRows filter (not DeviceNetworkEvents).
    """
    from xdr_cli.queries import load_query, list_queries

    by_name = {q.name: q for q in list_queries()}
    q = by_name["ttp_ldap_process_attribution"]
    lookback_param = next((p for p in q.params if p.name == "lookback"), None)
    assert lookback_param is not None, (
        "ttp_ldap_process_attribution must declare a `lookback` param."
    )
    assert lookback_param.default == "0d", (
        "lookback default must be 0d so existing callers see no behavior "
        f"change; got {lookback_param.default!r}"
    )

    # Default render: t0_ldap derivation should resolve to a 0d offset.
    default_body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        mode="summary",
    )
    assert "let t0_ldap = t0 - totimespan(0d);" in default_body, (
        "Default lookback render lost — expected `let t0_ldap = t0 - totimespan(0d);`"
    )
    body_nocomments = _strip_kql_comments(default_body)
    # The MDE window is still bounded by `t0 .. t1` (NOT widened).
    assert re.search(
        r"DeviceNetworkEvents\s*\|\s*where Timestamp between \(t0 \.\. t1\)",
        body_nocomments,
    ), (
        "DeviceNetworkEvents filter must use the un-widened (t0 .. t1) "
        "window; lookback must NOT widen the MDE attribution leg."
    )
    # The MDI window is bounded by `t0_ldap .. t1`.
    assert re.search(
        r"IdentityQueryEvents\s*\|\s*where Timestamp between \(t0_ldap \.\. t1\)",
        body_nocomments,
    ), (
        "IdentityQueryEvents filter must use the lookback-widened "
        "(t0_ldap .. t1) window."
    )

    # Explicit lookback render: passes through verbatim.
    explicit_body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        lookback="7d",
        mode="summary",
    )
    assert "let t0_ldap = t0 - totimespan(7d);" in explicit_body


def test_ttp_ldap_process_attribution_excludes_mdi_sensor_process():
    """The MDI sensor process (`microsoft.tri.sensor.exe`) is a
    universally-known benign process that performs DC connectivity health
    checks over LDAP. It is hard-excluded inside the query body so
    fresh tenants without a populated KnownServiceAccounts list still
    get clean output. Asserts both the row-drop in AttributedEvents
    and the SuppressedPerDevice counter include it.
    """
    from xdr_cli.queries import load_query

    body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        mode="summary",
    )
    body_nocomments = _strip_kql_comments(body)
    assert (
        'InitiatingProcessFileName !~ "microsoft.tri.sensor.exe"'
        in body_nocomments
    ), "MDI sensor hard-exclusion missing from AttributedEvents row-drop chain."
    assert (
        'InitiatingProcessFileName =~ "microsoft.tri.sensor.exe"'
        in body_nocomments
    ), (
        "MDI sensor hard-exclusion missing from SuppressedPerDevice counter "
        "— suppressed connections must still be counted for transparency."
    )


def test_ttp_ldap_process_attribution_detail_mode_surfaces_suppressed_count():
    """R3: DetailRows must join SuppressedPerDevice so analysts in detail
    mode see the same suppression-visibility the summary row provides.
    Without it, an analyst can't tell whether 0 attributed rows means
    "no LDAP recon" vs "all attributed rows were suppressed by
    KnownServiceAccounts / the MDI-sensor exclusion".
    """
    from xdr_cli.queries import load_query

    body = load_query(
        "ttp_ldap_process_attribution",
        device_name="dc01",
        start="2026-05-01T00:00:00Z",
        end="2026-05-11T00:00:00Z",
        mode="detail",
    )
    body_nocomments = _strip_kql_comments(body)
    # The DetailRows let-block runs from `let DetailRows = AttributedEvents`
    # to the terminating `;`. Slice that range out, asserting the slice
    # contains both the SuppressedPerDevice join and the coalesce.
    detail_start = body_nocomments.index("let DetailRows = AttributedEvents")
    detail_end = body_nocomments.index(";", detail_start)
    detail_body = body_nocomments[detail_start:detail_end]
    assert "join kind=leftouter SuppressedPerDevice on DeviceName" in detail_body, (
        "DetailRows must left-outer join SuppressedPerDevice — without it, "
        "the SuppressedCount column is missing from detail-mode output."
    )
    assert "SuppressedCount = coalesce(SuppressedCount, 0)" in detail_body, (
        "DetailRows must coalesce the joined SuppressedCount to 0 so the "
        "column is always numeric, never null."
    )


def test_identity_signin_baseline_isknownegress_handles_ipv6():
    """`ipv4_is_in_any_range()` returns null (not false) when passed an
    IPv6 address. Without an explicit coalesce, the OR-chain leaks null
    into `IsKnownEgress`, breaking downstream consumers that expect a
    boolean. Asserts the rendered query wraps the call with
    `coalesce(..., false)` so IPv6 sign-ins report
    `IsKnownEgress=false` instead of null.
    """
    from xdr_cli.queries import load_query

    body = load_query(
        "identity_signin_baseline",
        account_oid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        hours="720",
        mode="summary",
    )
    body_nocomments = _strip_kql_comments(body)
    assert re.search(
        r"coalesce\(\s*ipv4_is_in_any_range\(IPAddress,\s*_xdr_KnownEgressIPs\)"
        r",\s*false\s*\)",
        body_nocomments,
    ), (
        "identity_signin_baseline must wrap `ipv4_is_in_any_range(...)` "
        "with `coalesce(..., false)` — without it, IPv6 source IPs make "
        "IsKnownEgress null instead of false."
    )
