"""Deterministic KQL compilation and value-free observation aggregation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from xdr_cli.queries import _kql_escape
from xdr_cli.schema_graph.model import (
    FieldLocator,
    GraphValidationError,
    InterpretationRecord,
    ObservationRecord,
)
from xdr_cli.schema_graph.normalize import normalize_value

_DURATION = re.compile(r"^[1-9][0-9]{0,4}[smhd]$")
_LOWER_NORMALIZERS = {
    "domain-lower",
    "guid-lower",
    "hex40-lower",
    "hostname-lower",
    "sha1-lower",
    "sha256-lower",
    "smtp-lower",
    "upn-lower",
}
_PREFILTER_NORMALIZERS = _LOWER_NORMALIZERS | {"identity"}
_SOURCE_OVERSAMPLE_FACTOR = 10
PROBE_QUERY_BYTE_LIMIT = 256 * 1024
MAX_PROBE_SEED_BYTES = 2048
_BOUNDED_TIME_COLUMNS = ("Timestamp", "TimeGenerated")


@dataclass(frozen=True, slots=True)
class CompiledProbeQuery:
    table: str
    locator: str
    interpretation_id: str
    kql: str
    nested: bool
    wildcard: bool


@dataclass(frozen=True, slots=True)
class CompiledProbeBatch:
    table: str
    task_id: str
    kql: str
    target_locators: tuple[str, ...]
    interpretation_ids: tuple[str, ...]
    query_bytes: int


def _property_access(expression: str, segments: tuple[str, ...]) -> str:
    for segment in segments:
        expression += f'["{_kql_escape(segment)}"]'
    return expression


def _projection_lines(locator: FieldLocator, output: str = "__xdr_value") -> list[str]:
    if not locator.json_path:
        return [f"| extend {output} = tostring({locator.column})"]
    wildcard_indexes = [index for index, segment in enumerate(locator.json_path) if segment == "*"]
    if len(wildcard_indexes) > 1:
        raise GraphValidationError("probe compiler supports at most one nested array wildcard")
    root = f"parse_json(tostring({locator.column}))"
    if not wildcard_indexes:
        return [f"| extend {output} = tostring({_property_access(root, locator.json_path)})"]
    wildcard_index = wildcard_indexes[0]
    prefix = _property_access(root, locator.json_path[:wildcard_index])
    suffix = _property_access("__xdr_item", locator.json_path[wildcard_index + 1 :])
    return [
        f"| extend __xdr_array = {prefix}",
        "| mv-apply __xdr_item = __xdr_array on (",
        f"    extend {output} = tostring({suffix})",
        ")",
    ]


def _scalar_projection_expression(locator: FieldLocator) -> str:
    """Return one scalar KQL expression, rejecting array-expanding locators."""

    if "*" in locator.json_path:
        raise GraphValidationError("array-wildcard probe targets require an isolated query")
    if not locator.json_path:
        return f"tostring({locator.column})"
    root = f"parse_json(tostring({locator.column}))"
    return f"tostring({_property_access(root, locator.json_path)})"


def _normalized_expression(normalizer: str, source: str = "__xdr_value") -> str:
    stripped = rf'trim(@"\s+", tostring({source}))'
    if normalizer == "guid-lower":
        return f"tostring(toguid({stripped}))"
    if normalizer in {"domain-lower", "hostname-lower"}:
        return rf'trim_end(@"[.]+", tolower({stripped}))'
    if normalizer in _LOWER_NORMALIZERS:
        return f"tolower({stripped})"
    if normalizer == "identity":
        return stripped
    raise GraphValidationError(f"normalizer {normalizer!r} has no deterministic KQL prefilter")


def validate_lookback(lookback: str) -> str:
    """Validate and return the bounded KQL duration accepted by probes."""

    if not isinstance(lookback, str) or not _DURATION.fullmatch(lookback):
        raise GraphValidationError("lookback must be a positive KQL duration such as 30d")
    return lookback


def bounded_time_column(
    table: str,
    available_columns: dict[str, set[str]] | None,
) -> str | None:
    """Return the preferred cached event-time column for a bounded probe.

    Defender-native tables normally expose ``Timestamp`` while Sentinel and
    connected-workspace tables normally expose ``TimeGenerated``. This column
    bounds each table scan independently; it is never a correlation key.
    """

    if available_columns is None:
        return "Timestamp"
    columns = available_columns.get(table, set())
    return next((column for column in _BOUNDED_TIME_COLUMNS if column in columns), None)


def _time_filter(
    table: str,
    lookback: str,
    available_columns: dict[str, set[str]] | None,
) -> list[str]:
    validate_lookback(lookback)
    time_column = bounded_time_column(table, available_columns)
    if time_column is not None:
        return [f"| where {time_column} > ago({lookback})"]
    raise GraphValidationError(
        f"{table} has no cached Timestamp or TimeGenerated column; "
        "a bounded probe cannot be compiled"
    )


def compile_source_sampling_query(
    interpretation: InterpretationRecord,
    locator: FieldLocator,
    *,
    lookback: str = "30d",
    samples: int = 5,
    available_columns: dict[str, set[str]] | None = None,
) -> CompiledProbeQuery:
    if interpretation.constraints:
        raise GraphValidationError(
            "probe compiler cannot yet enforce this interpretation's constraints"
        )
    if samples < 1 or samples > 100:
        raise GraphValidationError("samples must be between 1 and 100")
    lines = [locator.table, *_time_filter(locator.table, lookback, available_columns)]
    lines.extend(_projection_lines(locator))
    lines.extend(
        [
            f"| extend __xdr_normalized = {_normalized_expression(interpretation.normalizer)}",
            "| where isnotempty(__xdr_normalized)",
        ]
    )
    if interpretation.normalizer in {"smtp-lower", "upn-lower"}:
        lines.append('| where __xdr_normalized contains "@"')
    candidate_count = min(samples * _SOURCE_OVERSAMPLE_FACTOR, 1000)
    lines.extend(
        [
            "| summarize Occurrences=count() by Value=__xdr_normalized",
            "| sort by Occurrences asc, Value asc",
            f"| take {candidate_count}",
            "| project Value, Occurrences",
        ]
    )
    return CompiledProbeQuery(
        table=locator.table,
        locator=str(locator),
        interpretation_id=interpretation.id,
        kql="\n".join(lines),
        nested=bool(locator.json_path),
        wildcard="*" in locator.json_path,
    )


def compile_target_probe_query(
    interpretation: InterpretationRecord,
    locator: FieldLocator,
    seeds: list[str],
    *,
    lookback: str = "30d",
    available_columns: dict[str, set[str]] | None = None,
) -> CompiledProbeQuery:
    if interpretation.constraints:
        raise GraphValidationError(
            "probe compiler cannot yet enforce this interpretation's constraints"
        )
    if not seeds or len(seeds) > 100:
        raise GraphValidationError("probe requires between 1 and 100 seeds")
    normalized = _normalized_seeds(interpretation.normalizer, seeds)
    rendered = ",".join(f'"{_kql_escape(value)}"' for value in normalized)
    lines = _target_probe_leg(
        interpretation,
        locator,
        seed_expression=f"dynamic([{rendered}])",
        lookback=lookback,
        available_columns=available_columns,
    )
    return CompiledProbeQuery(
        table=locator.table,
        locator=str(locator),
        interpretation_id=interpretation.id,
        kql="\n".join(lines),
        nested=bool(locator.json_path),
        wildcard="*" in locator.json_path,
    )


def compile_target_context_query(
    interpretation: InterpretationRecord,
    locator: FieldLocator,
    seeds: list[str],
    *,
    lookback: str = "30d",
    limit: int = 20,
    available_columns: dict[str, set[str]] | None = None,
) -> CompiledProbeQuery:
    """Compile a bounded private row-context query for one candidate review."""

    if interpretation.constraints:
        raise GraphValidationError(
            "probe compiler cannot yet enforce this interpretation's constraints"
        )
    if limit < 1 or limit > 100:
        raise GraphValidationError("candidate review limit must be between 1 and 100")
    normalized = _normalized_seeds(interpretation.normalizer, seeds)
    rendered = ",".join(f'"{_kql_escape(value)}"' for value in normalized)
    lines = [locator.table, *_time_filter(locator.table, lookback, available_columns)]
    lines.extend(_projection_lines(locator))
    lines.extend(
        [
            f"| extend __xdr_normalized = {_normalized_expression(interpretation.normalizer)}",
            "| where isnotempty(__xdr_normalized)",
            f"| where set_has_element(dynamic([{rendered}]), __xdr_normalized)",
            f"| take {limit}",
        ]
    )
    kql = "\n".join(lines)
    if len(kql.encode("utf-8")) > PROBE_QUERY_BYTE_LIMIT:
        raise GraphValidationError(
            "candidate review query exceeds 256 KiB; recollect with fewer samples"
        )
    return CompiledProbeQuery(
        table=locator.table,
        locator=str(locator),
        interpretation_id=interpretation.id,
        kql=kql,
        nested=bool(locator.json_path),
        wildcard="*" in locator.json_path,
    )


def _normalized_seeds(normalizer: str, seeds: list[str]) -> list[str]:
    if not seeds or len(seeds) > 100:
        raise GraphValidationError("probe requires between 1 and 100 seeds")
    normalized = []
    for seed in seeds:
        if not isinstance(seed, str) or len(seed.encode("utf-8")) > MAX_PROBE_SEED_BYTES:
            raise GraphValidationError("probe seed is not a bounded string")
        value = normalize_value(normalizer, seed)
        if any(ord(character) < 32 for character in value):
            raise GraphValidationError("probe seed contains a control character")
        normalized.append(value)
    return sorted(set(normalized))


def _target_probe_leg(
    interpretation: InterpretationRecord,
    locator: FieldLocator,
    *,
    seed_expression: str,
    lookback: str,
    available_columns: dict[str, set[str]] | None,
) -> list[str]:
    if interpretation.constraints:
        raise GraphValidationError(
            "probe compiler cannot yet enforce this interpretation's constraints"
        )
    lines = [locator.table, *_time_filter(locator.table, lookback, available_columns)]
    lines.extend(_projection_lines(locator))
    lines.extend(
        [
            f"| extend __xdr_normalized = {_normalized_expression(interpretation.normalizer)}",
            "| where isnotempty(__xdr_normalized)",
            f"| where set_has_element({seed_expression}, __xdr_normalized)",
            "| summarize MatchRows=count(), MatchedSeeds=dcount(__xdr_normalized)",
            f'| extend TargetLocator="{_kql_escape(str(locator))}"',
            f'| extend TargetInterpretation="{_kql_escape(interpretation.id)}"',
            "| project TargetLocator, TargetInterpretation, MatchRows, MatchedSeeds",
        ]
    )
    return lines


def compile_target_probe_batches(
    targets: list[tuple[InterpretationRecord, FieldLocator]],
    seeds: list[str],
    *,
    lookback: str = "30d",
    batch_size: int = 20,
    available_columns: dict[str, set[str]] | None = None,
) -> tuple[CompiledProbeBatch, ...]:
    """Compile table-aware target tasks below a strict request byte budget.

    Compatible scalar fields from one table share a single bounded scan. Array
    wildcard locators remain isolated because they expand rows before
    aggregation. Every result is labelled and contains counts only.
    """

    if batch_size < 1 or batch_size > 50:
        raise GraphValidationError("probe batch size must be between 1 and 50")
    if not targets:
        return ()
    ordered = sorted(
        targets,
        key=lambda item: (
            item[0].extra.get("provisional") is True,
            str(item[1]),
            item[0].id,
        ),
    )
    normalizers = {item.normalizer for item, _locator in ordered}
    if len(normalizers) != 1:
        raise GraphValidationError("all targets in a probe plan must share one normalizer")
    normalized = _normalized_seeds(next(iter(normalizers)), seeds)
    rendered = ",".join(f'"{_kql_escape(value)}"' for value in normalized)
    batches: list[CompiledProbeBatch] = []

    def make_batch(
        table: str,
        chunk: list[tuple[InterpretationRecord, FieldLocator]],
        kql: str,
    ) -> CompiledProbeBatch:
        encoded = kql.encode("utf-8")
        task_digest = hashlib.sha256(b"table-probe-v1\0" + encoded).hexdigest()[:24]
        return CompiledProbeBatch(
            table=table,
            task_id=f"probe-task:{task_digest}",
            kql=kql,
            target_locators=tuple(str(locator) for _item, locator in chunk),
            interpretation_ids=tuple(item.id for item, _locator in chunk),
            query_bytes=len(encoded),
        )

    def compile_scalar_chunk(
        table: str,
        chunk: list[tuple[InterpretationRecord, FieldLocator]],
    ) -> CompiledProbeBatch:
        lines = [
            f"let _xdr_seeds = dynamic([{rendered}]);",
            table,
            *_time_filter(table, lookback, available_columns),
        ]
        aliases: list[tuple[str, str, str]] = []
        for index, (interpretation, locator) in enumerate(chunk):
            raw_expression = _scalar_projection_expression(locator)
            normalized_expression = _normalized_expression(
                interpretation.normalizer, raw_expression
            )
            alias = f"__xdr_value_{index}"
            predicate = f"isnotempty({alias}) and set_has_element(_xdr_seeds, {alias})"
            lines.append(f"| extend {alias} = {normalized_expression}")
            aliases.append((alias, predicate, str(locator)))
        aggregates: list[str] = []
        for index, (alias, predicate, _locator) in enumerate(aliases):
            aggregates.extend(
                (
                    f"__xdr_rows_{index}=countif({predicate})",
                    f"__xdr_seeds_{index}=dcountif({alias}, {predicate})",
                )
            )
        lines.append("| summarize " + ", ".join(aggregates))
        packed = []
        for index, ((interpretation, locator), _alias) in enumerate(
            zip(chunk, aliases, strict=True)
        ):
            packed.append(
                "pack("
                f'"TargetLocator","{_kql_escape(str(locator))}",'
                f'"TargetInterpretation","{_kql_escape(interpretation.id)}",'
                f'"MatchRows",__xdr_rows_{index},'
                f'"MatchedSeeds",__xdr_seeds_{index}'
                ")"
            )
        lines.extend(
            (
                "| project __xdr_results = pack_array(" + ",".join(packed) + ")",
                "| mv-expand __xdr_result = __xdr_results",
                "| project "
                "TargetLocator=tostring(__xdr_result.TargetLocator), "
                "TargetInterpretation=tostring(__xdr_result.TargetInterpretation), "
                "MatchRows=toint(__xdr_result.MatchRows), "
                "MatchedSeeds=toint(__xdr_result.MatchedSeeds)",
            )
        )
        return make_batch(table, chunk, "\n".join(lines))

    def compile_wildcard(
        target: tuple[InterpretationRecord, FieldLocator],
    ) -> CompiledProbeBatch:
        interpretation, locator = target
        leg = _target_probe_leg(
            interpretation,
            locator,
            seed_expression="_xdr_seeds",
            lookback=lookback,
            available_columns=available_columns,
        )
        kql = f"let _xdr_seeds = dynamic([{rendered}]);\n" + "\n".join(leg)
        return make_batch(locator.table, [target], kql)

    # Preserve reviewed-first target selection, then keep every table's fields
    # adjacent so a table is scanned once per bounded chunk.
    grouped: dict[str, list[tuple[InterpretationRecord, FieldLocator]]] = {}
    table_order: list[str] = []
    for target in ordered:
        table = target[1].table
        if table not in grouped:
            grouped[table] = []
            table_order.append(table)
        grouped[table].append(target)

    for table in table_order:
        chunk: list[tuple[InterpretationRecord, FieldLocator]] = []
        for target in grouped[table]:
            if "*" in target[1].json_path:
                if chunk:
                    batches.append(compile_scalar_chunk(table, chunk))
                    chunk = []
                wildcard = compile_wildcard(target)
                if wildcard.query_bytes > PROBE_QUERY_BYTE_LIMIT:
                    raise GraphValidationError(
                        "one probe target exceeds the 256 KiB compiled-query limit; "
                        "reduce --samples or use shorter seed values"
                    )
                batches.append(wildcard)
                continue
            proposed = [*chunk, target]
            compiled = compile_scalar_chunk(table, proposed)
            if compiled.query_bytes > PROBE_QUERY_BYTE_LIMIT and chunk:
                batches.append(compile_scalar_chunk(table, chunk))
                chunk = [target]
                compiled = compile_scalar_chunk(table, chunk)
            else:
                chunk = proposed
            if compiled.query_bytes > PROBE_QUERY_BYTE_LIMIT:
                raise GraphValidationError(
                    "one probe target exceeds the 256 KiB compiled-query limit; "
                    "reduce --samples or use shorter seed values"
                )
            if len(chunk) == batch_size:
                batches.append(compiled)
                chunk = []
        if chunk:
            batches.append(compile_scalar_chunk(table, chunk))
    return tuple(batches)


def worst_case_seed_payload_bytes(samples: int) -> int:
    """Return the bounded seed-array contribution used for plan diagnostics."""

    if samples < 1 or samples > 100:
        raise GraphValidationError("samples must be between 1 and 100")
    return samples * (MAX_PROBE_SEED_BYTES + 3)


def aggregate_observation(
    *,
    observation_id: str,
    source_interpretation: str,
    target_interpretation: str,
    transform: str,
    distinct_seeds: int,
    matched_seeds: int,
    matched_rows: int = 0,
    source_artifact_run_id: str | None = None,
    target_artifact_run_id: str | None = None,
    probe_runs: int,
    provenance: tuple[str, ...],
    outcome: str = "observed",
    schema_generation: str | None = None,
    observed_at: str | None = None,
    lookback: str | None = None,
) -> ObservationRecord:
    """Build a value-free observation; no seed/result value is accepted."""

    return ObservationRecord(
        observation_id=observation_id,
        source_interpretation=source_interpretation,
        target_interpretation=target_interpretation,
        transform=transform,
        distinct_seeds=distinct_seeds,
        matched_seeds=matched_seeds,
        probe_runs=probe_runs,
        provenance=provenance,
        matched_rows=matched_rows,
        source_artifact_run_id=source_artifact_run_id,
        target_artifact_run_id=target_artifact_run_id,
        outcome=outcome,
        schema_generation=schema_generation,
        observed_at=observed_at,
        lookback=lookback,
    )


def supports_probe_prefilter(normalizer: str) -> bool:
    return normalizer in _PREFILTER_NORMALIZERS
