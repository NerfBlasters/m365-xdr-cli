"""Compile one bounded, aggregate-only validation query per reference route.

XDRInternals relations are trusted as conditional claims: the compiler keeps
their stated conditions (scope keys, workload predicates, element filters,
ordering, snapshot selection) and refuses routes it cannot represent safely.
Queries return counts only; identifier values never leave the service.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from xdr_cli.schema_graph.physical import canonical_storage_type, physical_field_rows
from xdr_cli.schema_graph.probe import validate_lookback
from xdr_cli.schema_graph.reference import ReferenceEndpoint, ReferenceRoute

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ROUTE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
_NESTED_OUTER_TYPES = {"string", "dynamic"}
_SCALAR_TYPES = {"string", "guid", "long", "int"}

# Case policy per identifier family. GUID-like and hash identifiers compare
# case-insensitively; token, session-token and cloud-native names keep case.
FAMILY_NORMALIZERS = {
    "aws-resource": "identity",
    "azure-resource": "lower",
    "bookmark": "lower",
    "configuration": "identity",
    "crowdstrike-agent": "lower",
    "cve": "upper",
    "defender-alert": "identity",
    "defender-behavior": "identity",
    "defender-device": "lower",
    # Matches the packaged network-message-id contract (identity), avoiding a parallel namespace.
    "email-message": "identity",
    "entra-device": "lower",
    "entra-session": "lower",
    "entra-token": "identity",
    "entra-user": "lower",
    "exposure-node": "identity",
    "file-sha1": "lower",
    "file-sha256": "lower",
    "gcp-resource": "identity",
    "identity-account": "lower",
    "oauth-client": "lower",
    "process-start-key": "identity",
    "sentinel-alert": "lower",
    "sentinel-behavior": "identity",
    "sentinel-intel": "identity",
    "service-principal": "lower",
    "stix-object": "identity",
    "teams-message": "identity",
    "unified-identity": "lower",
}

_PADDED_TOKEN_FIELDS = {("AADGraphActivityLogs", "SignInActivityId")}

DEFAULT_SCAN_ROW_LIMIT = 100_000
MAX_SCAN_ROW_LIMIT = 1_000_000


class ReferenceQueryUnsupported(ValueError):
    """The route cannot be compiled safely for this tenant; ``reason`` is stable."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class CompiledReferenceQuery:
    route_id: str
    query: str
    normalizer: str
    time_policy: dict
    constraints_applied: tuple[str, ...]
    warnings: tuple[str, ...]
    scope: dict = field(default_factory=dict)


@dataclass
class _Side:
    """Per-endpoint compilation state.

    Pipeline order: time filter, ``pre`` row filters, row cap, ``snapshot``
    aggregation, ``post`` filters, extraction, scoped key. Aggregation therefore
    never runs over more rows than the cap.
    """

    endpoint: ReferenceEndpoint
    role: str
    pre: list[str] = field(default_factory=list)
    snapshot: list[str] = field(default_factory=list)
    post: list[str] = field(default_factory=list)
    element_filter: str | None = None
    key_parts: list[tuple[str, str, bool]] = field(default_factory=list)
    value_filters: list[str] = field(default_factory=list)
    order_column: str | None = None

    def scope(self, label: str, expression: str | None = None, *,
              preserve_case: bool = False) -> None:
        """Add a scope value; GUID-like scopes fold case, provenance labels keep it."""

        self.key_parts.append((label, expression or f"tostring({label})", preserve_case))


def _columns(schema_rows: list[dict]) -> dict[str, dict[str, set[str | None]]]:
    tables: dict[str, dict[str, set[str | None]]] = {}
    for (table, column), rows in physical_field_rows(schema_rows).items():
        tables.setdefault(table, {})[column] = {
            canonical_storage_type(row.get("ColumnType")) for row in rows
        }
    return tables


def _value_expression(normalizer: str, value: str) -> str:
    text = f"trim(@'\\s', tostring({value}))"
    if normalizer == "lower":
        return f"tolower({text})"
    if normalizer == "upper":
        return f"toupper({text})"
    if normalizer == "trim-base64-padding":
        return f"trim_end(@'=+', {text})"
    return text


def _extraction(side: _Side, prefix: str) -> tuple[list[str], str]:
    """Return pipeline steps and the final raw value column for an endpoint."""

    endpoint = side.endpoint
    if not endpoint.path:
        return [], endpoint.column
    steps = [f"extend {prefix}0 = parse_json(tostring({endpoint.column}))"]
    current = f"{prefix}0"
    for index, segment in enumerate(endpoint.path, start=1):
        name = f"{prefix}{index}"
        if segment == "*":
            steps.append(f"mv-expand {current} to typeof(dynamic) limit 1000")
            if side.element_filter and index == 1:
                steps.append(side.element_filter.format(element=current))
            steps.append(f"extend {name} = {current}")
        else:
            if not _IDENTIFIER.fullmatch(segment):
                raise ReferenceQueryUnsupported("unsupported-path", "path segment is not a name")
            # Re-parse at each hop: claims and similar members can be JSON-encoded strings.
            steps.append(f"extend {name} = parse_json(tostring({current}))['{segment}']")
        current = name
    return steps, current


def _require(tables, table: str, column: str, reason: str) -> set[str | None]:
    if table not in tables:
        raise ReferenceQueryUnsupported(f"{reason.split('-')[0]}-table-unavailable", table)
    if column not in tables[table]:
        raise ReferenceQueryUnsupported(reason, f"{table}.{column}")
    return tables[table][column]


def _time_column(tables, endpoint: ReferenceEndpoint, role: str, warnings: list[str]) -> str | None:
    columns = tables[endpoint.table]
    declared = endpoint.time_column
    if declared:
        if declared in columns and columns[declared] <= {"datetime", None}:
            return declared
        for fallback in ("Timestamp", "TimeGenerated"):
            if fallback in columns and columns[fallback] <= {"datetime", None}:
                warnings.append(f"{role} time column {declared} unavailable; used {fallback}")
                return fallback
        raise ReferenceQueryUnsupported(
            "time-column-unavailable", f"{endpoint.table}.{declared}"
        )
    return None


_WORKSPACE_FAMILIES = {"sentinel-behavior", "sentinel-intel", "stix-object",
                       "sentinel-alert", "bookmark"}
_STIX_SNAPSHOT_TABLES = {"ThreatIntelIndicators", "ThreatIntelObjects"}
_FEED_KEY = "iff(indexof(Id, '---') > 0, substring(Id, 0, indexof(Id, '---')), '')"


def _apply_conditions(route: ReferenceRoute, source: _Side, target: _Side, tables,
                      times: dict[str, str | None], constraints: list[str],
                      warnings: list[str]) -> None:
    """Translate the reference's stated conditions into machine predicates.

    A condition the reference states as required either compiles or makes the
    route unsupported; it is never silently downgraded to a warning.
    """

    guidance = route.guidance or ""

    def both_have(column: str) -> bool:
        return column in tables[source.endpoint.table] and column in tables[target.endpoint.table]

    def require(side: _Side, column: str) -> None:
        if column not in tables[side.endpoint.table]:
            raise ReferenceQueryUnsupported(
                "scope-column-unavailable", f"{side.endpoint.table}.{column}"
            )

    def scope_both(column: str) -> None:
        for side in (source, target):
            require(side, column)
            side.scope(column)
        constraints.append(f"composite-key:{column}")

    def latest_snapshot(side: _Side, *keys: str) -> None:
        time_column = times[side.role]
        if time_column is None:
            raise ReferenceQueryUnsupported(
                "time-column-unavailable", f"{side.endpoint.table} latest snapshot"
            )
        for column in keys:
            require(side, column)
        side.snapshot.append(f"summarize arg_max({time_column}, *) by {', '.join(keys)}")
        constraints.append(f"{side.role}-latest-snapshot:{'+'.join(keys)}")

    if route.family == "process-start-key":
        scope_both("DeviceId")
        if both_have("TenantId"):
            scope_both("TenantId")
        else:
            # Defender device tables lack TenantId; one selected tenant is implicit.
            constraints.append("tenant-scope:implicit-single-tenant")
        require(source, "ProcessCreationTime")
        source.order_column = "ProcessCreationTime"
        constraints.append("target-activity-at-or-after:ProcessCreationTime")
    if re.search(r"AccountObjectId as well", guidance):
        scope_both("AccountObjectId")
    if route.family == "crowdstrike-agent":
        scope_both("Cid")
        scope_both("TenantId")
    if route.family in _WORKSPACE_FAMILIES:
        scope_both("TenantId")
    if route.id == "entra-signin-cloudapp-exchange-session":
        require(target, "ActionType")
        target.pre.append("where ActionType == 'MailItemsAccessed'")
        constraints.append("target-predicate:ActionType==MailItemsAccessed")
    if route.id.startswith("stix-relationship-"):
        for side in (source, target):
            latest_snapshot(side, "TenantId", "Id")
            if "IsDeleted" in tables[side.endpoint.table]:
                side.post.append("where not(tobool(IsDeleted))")
                constraints.append(f"{side.role}-predicate:not-deleted-after-latest")
            # The reference joins feed prefixes exactly; case is provenance.
            side.scope("FeedKey", _FEED_KEY, preserve_case=True)
        constraints.append("composite-key:FeedKey")
        if "StixType" in tables[source.endpoint.table]:
            source.post.append("where tostring(StixType) == 'relationship'")
        else:
            source.post.append(
                "where tostring(parse_json(tostring(Data))['type']) == 'relationship'"
            )
        constraints.append("source-predicate:relationship-object")
    elif route.family in {"stix-object", "sentinel-intel"}:
        for side in (source, target):
            if side.endpoint.table in _STIX_SNAPSHOT_TABLES:
                latest_snapshot(side, "TenantId", "Id")
    incident_source = source.endpoint.table == "SecurityIncident"
    if route.family in {"sentinel-alert", "bookmark"} and incident_source:
        latest_snapshot(source, "TenantId", "IncidentName")
    if route.id == "cloudapp-raw-event-target-account-object-id":
        # Target may name any resource type; only GUID shape is machine-checkable.
        source.value_filters.append("isnotempty(toguid(__v))")
        constraints.extend(["source-value-shape:guid", "condition-unverifiable:target-is-user"])
    if route.record.get("origin") == "tenant-new-table":
        _candidate_quality(route.family, (source, target))
        constraints.append("candidate-identifier-quality:v1")
    if route.id == "audit-target-resource-id-account-object-id":
        source.element_filter = "where tostring({element}['type']) =~ 'User'"
        constraints.append("source-element-predicate:type==User")
    if "latest" in guidance and not any("latest-snapshot" in item for item in constraints):
        warnings.append("reference recommends latest-snapshot selection; not enforced")


_PLACEHOLDERS = "('0', '-', 'null', 'none', 'unknown', 'n/a', " \
    "'00000000-0000-0000-0000-000000000000')"
_FAMILY_SHAPES = {
    "defender-device": "__v matches regex @'^[0-9a-fA-F]{40}$'",
    "file-sha1": "__v matches regex @'^[0-9a-fA-F]{40}$'",
    "file-sha256": "__v matches regex @'^[0-9a-fA-F]{64}$'",
}
_GUID_FAMILIES = {"entra-user", "entra-device", "entra-session", "oauth-client",
                  "service-principal", "email-message"}


def _candidate_quality(family: str, sides: tuple[_Side, ...]) -> None:
    """Derived new-table routes count only informative, family-shaped identifiers."""

    shape = _FAMILY_SHAPES.get(family) or (
        "isnotempty(toguid(__v))" if family in _GUID_FAMILIES else None
    )
    for side in sides:
        side.value_filters.append(f"tolower(__v) !in {_PLACEHOLDERS}")
        if shape:
            side.value_filters.append(shape)


def _key_expression(side: _Side, value: str) -> list[str]:
    """Scoped keys count only when the identifier and every scope value are non-empty."""

    steps = [f"extend __v = {value}"]
    steps.extend(f"where {condition}" for condition in side.value_filters)
    if not side.key_parts:
        return [*steps, "extend __k = __v"]
    names = []
    for index, (_label, expression, preserve_case) in enumerate(side.key_parts):
        value = f"trim(@'\\s', {expression})"
        steps.append(f"extend __p{index} = {value if preserve_case else f'tolower({value})'}")
        names.append(f"__p{index}")
    empty = " or ".join(f"isempty({name})" for name in ["__v", *names])
    joined = ", '|', ".join([*names, "__v"])
    steps.append(f"extend __k = iff({empty}, '', strcat({joined}))")
    return steps


def _side_pipeline(side: _Side, normalizer: str, time_column: str | None,
                   lookback: str, cap: int) -> list[str]:
    """Build one endpoint pipeline; rows are capped before any aggregation."""

    steps = [side.endpoint.table]
    if time_column:
        steps.append(f"where {time_column} > ago({lookback})")
    steps.extend(side.pre)
    # Most-recent rows keep repeated validations comparable; `take` is arbitrary.
    steps.append(f"top {cap} by {time_column} desc" if time_column else f"take {cap}")
    steps.extend(side.snapshot)
    steps.extend(side.post)
    prefix = "__s" if side.role == "source" else "__t"
    extraction, raw = _extraction(side, prefix)
    steps.extend(extraction)
    steps.extend(_key_expression(side, _value_expression(normalizer, raw)))
    steps.append("where isnotempty(__k)")
    return steps


def compile_reference_query(
    route: ReferenceRoute,
    schema_rows: list[dict],
    *,
    lookback: str = "7d",
    samples: int = 50,
    row_limit: int = 1000,
    scan_row_limit: int = DEFAULT_SCAN_ROW_LIMIT,
) -> CompiledReferenceQuery:
    """Compile one aggregate overlap check, or raise ``ReferenceQueryUnsupported``.

    Every table read is row-capped before any aggregation: ``row_limit`` for
    source sampling, ``scan_row_limit`` for the single materialized target read
    that serves both the presence count and membership.
    The result reports ``ScanCapped`` so a no-overlap under the cap stays
    inconclusive instead of reading as a contradiction.
    """

    validate_lookback(lookback)
    if not _ROUTE_ID.fullmatch(route.id):
        raise ReferenceQueryUnsupported("invalid-route-id", route.id)
    if (
        not 1 <= samples <= 1000
        or not 1 <= row_limit <= 10000
        or not row_limit <= scan_row_limit <= MAX_SCAN_ROW_LIMIT
    ):
        raise ReferenceQueryUnsupported(
            "invalid-budget",
            f"samples={samples} rows={row_limit} scan_rows={scan_row_limit}",
        )
    tables = _columns(schema_rows)
    warnings: list[str] = []
    constraints: list[str] = []
    for role, endpoint in (("source", route.source), ("target", route.target)):
        types = _require(tables, endpoint.table, endpoint.column, f"{role}-column-unavailable")
        allowed = _NESTED_OUTER_TYPES if endpoint.path else _SCALAR_TYPES | _NESTED_OUTER_TYPES
        if not types <= allowed | {None}:
            raise ReferenceQueryUnsupported(
                f"{role}-column-type-unsupported", f"{endpoint.table}.{endpoint.column}"
            )
    source, target = _Side(route.source, "source"), _Side(route.target, "target")
    normalizer = FAMILY_NORMALIZERS.get(route.family)
    if normalizer is None:
        raise ReferenceQueryUnsupported("unknown-family", route.family)
    if any(
        (endpoint.table, endpoint.column) in _PADDED_TOKEN_FIELDS
        for endpoint in (route.source, route.target)
    ):
        normalizer = "trim-base64-padding"
        constraints.append("both-sides:trim-trailing-base64-padding")
    source_time = _time_column(tables, route.source, "source", warnings)
    target_time = _time_column(tables, route.target, "target", warnings)
    _apply_conditions(route, source, target, tables,
                      {"source": source_time, "target": target_time}, constraints, warnings)
    if source.order_column and target_time is None:
        raise ReferenceQueryUnsupported("time-column-unavailable", "ordering needs target time")
    time_policy = {
        "lookback": lookback,
        "source": source_time or "snapshot-capped",
        "target": target_time or "snapshot-capped",
    }
    source_steps = _side_pipeline(source, normalizer, source_time, lookback, row_limit)
    order = source.order_column
    source_steps.append(
        f"summarize __o = min({order}) by __k" if order else "summarize by __k"
    )
    source_steps.append(f"top {samples} by hash(__k) asc")
    # One capped, sorted target read serves both the presence count and membership.
    target_rows = _side_pipeline(target, normalizer, target_time, lookback, scan_row_limit)
    target_rows.append(f"project __k{', __tt = ' + target_time if order else ''}")
    target_scan = ["TargetRows", "where __k in ((SourceKeys | project __k))"]
    if order:
        target_scan.append("join kind=inner (SourceKeys) on __k")
        target_scan.append("where __tt >= __o")
    # Raw window rows up to cap+1 (before snapshot aggregation) reveal truncation cheaply.
    window = [route.target.table]
    if target_time:
        window.append(f"where {target_time} > ago({lookback})")
    window.extend(target.pre)
    window.extend([f"take {scan_row_limit + 1}", "count"])
    target_scan.extend([
        "summarize MatchRows = count(), MatchedSourceValues = count_distinct(__k)",
        f"extend RouteId = '{route.id}'",
        "extend SourceValues = toscalar(SourceKeys | count)",
        f"extend TargetValues = toscalar(TargetRows | take {row_limit} | count)",
        # Graph hunting serializes KQL bool as SByte 0/1, so emit an explicit int.
        f"extend ScanCapped = toint(toscalar(TargetWindow) > {scan_row_limit})",
        "project RouteId, SourceValues, TargetValues, MatchedSourceValues, MatchRows, "
        "ScanCapped",
    ])

    def block(steps: list[str]) -> str:
        return "\n    | ".join(steps)

    query = (
        f"let SourceKeys = materialize(\n    {block(source_steps)});\n"
        f"let TargetRows = materialize(\n    {block(target_rows)});\n"
        f"let TargetWindow = \n    {block(window)};\n"
        f"{block(target_scan).replace(chr(10) + '    ', chr(10))}"
    )
    if not target_time:
        warnings.append("target has no time column; membership scans a capped snapshot")
    return CompiledReferenceQuery(
        route_id=route.id,
        query=query,
        normalizer=normalizer,
        time_policy=time_policy,
        constraints_applied=tuple(constraints),
        warnings=tuple(warnings),
        scope={
            "source_key_columns": [label for label, *_ in source.key_parts],
            "target_key_columns": [label for label, *_ in target.key_parts],
            "samples": samples,
            "row_limit": row_limit,
            "scan_row_limit": scan_row_limit,
        },
    )
