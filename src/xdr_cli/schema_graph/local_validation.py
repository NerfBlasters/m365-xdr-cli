"""Per-table validation with independently bound identifier cohorts for each route."""

from __future__ import annotations

from dataclasses import dataclass

from xdr_cli.queries import _kql_escape
from xdr_cli.schema_graph.model import FieldLocator, GraphValidationError, InterpretationRecord
from xdr_cli.schema_graph.probe import (
    PROBE_QUERY_BYTE_LIMIT,
    _normalized_expression,
    _normalized_seeds,
    _projection_lines,
    _scalar_projection_expression,
    validate_lookback,
)

COMPILER_VERSION = "local-table/v2"


@dataclass(frozen=True)
class ValidationTarget:
    pair_key: str
    interpretation: InterpretationRecord
    locator: FieldLocator
    seeds: tuple[str, ...]


@dataclass(frozen=True)
class ValidationBatch:
    targets: tuple[ValidationTarget, ...]
    kql: str


def compile_query(targets, *, lookback, time_column):
    """One scalar table scan, or one isolated array-expansion path scan."""
    validate_lookback(lookback)
    if not targets or time_column not in {"Timestamp", "TimeGenerated"}:
        raise GraphValidationError("validation requires targets and a bounded time column")
    tables = {target.locator.table for target in targets}
    paths = {str(t.locator) for t in targets if "*" in t.locator.json_path}
    if len(tables) != 1 or (
        paths and (len(paths) != 1 or any(str(t.locator) not in paths for t in targets))
    ):
        raise GraphValidationError("incompatible table or array expansion in validation batch")
    if len({t.pair_key for t in targets}) != len(targets):
        raise GraphValidationError("duplicate pair in validation batch")
    lines = []
    for index, target in enumerate(targets):
        if target.interpretation.constraints:
            raise GraphValidationError("local validation cannot enforce interpretation constraints")
        seeds = _normalized_seeds(target.interpretation.normalizer, list(target.seeds))
        if not 1 <= len(seeds) <= 100:
            raise GraphValidationError("validation cohort must have 1 to 100 identifiers")
        rendered = ",".join('"' + _kql_escape(seed) + '"' for seed in seeds)
        lines.append(f"let _xdr_seeds_{index} = dynamic([{rendered}]);")
    lines.extend((next(iter(tables)), f"| where {time_column} > ago({lookback})"))
    if paths:
        lines.extend(_projection_lines(targets[0].locator, "__xdr_raw", expanded_paths=True))
        # Drop native columns before introducing helper names.
        lines.append("| project __xdr_raw")
        raw = ["__xdr_raw"] * len(targets)
    else:
        raw = [f"__xdr_raw_{index}" for index in range(len(targets))]
        lines.append(
            "| project "
            + ", ".join(
                f"{alias} = {_scalar_projection_expression(target.locator, expanded_paths=True)}"
                for alias, target in zip(raw, targets, strict=True)
            )
        )
    lines.append(
        "| project "
        + ", ".join(
            f"__xdr_value_{index} = "
            f"{_normalized_expression(target.interpretation.normalizer, alias)}"
            for index, (target, alias) in enumerate(zip(targets, raw, strict=True))
        )
    )
    aggregates = []
    for index in range(len(targets)):
        value = f"__xdr_value_{index}"
        predicate = f"isnotempty({value}) and set_has_element(_xdr_seeds_{index}, {value})"
        aggregates.extend(
            (
                f"__xdr_rows_{index}=countif({predicate})",
                f"__xdr_seeds_{index}=count_distinctif({value}, {predicate})",
            )
        )
    lines.append("| summarize " + ", ".join(aggregates))
    packed = []
    for index, target in enumerate(targets):
        packed.append(
            "pack("
            + ",".join(
                (
                    f'"PairKey","{_kql_escape(target.pair_key)}"',
                    f'"TargetLocator","{_kql_escape(str(target.locator))}"',
                    f'"TargetInterpretation","{_kql_escape(target.interpretation.id)}"',
                    f'"MatchRows",__xdr_rows_{index}',
                    f'"MatchedSeeds",__xdr_seeds_{index}',
                )
            )
            + ")"
        )
    lines.extend(
        (
            "| project __xdr_results = pack_array(" + ",".join(packed) + ")",
            "| mv-expand __xdr_result = __xdr_results",
            "| project PairKey=tostring(__xdr_result.PairKey), "
            "TargetLocator=tostring(__xdr_result.TargetLocator), "
            "TargetInterpretation=tostring(__xdr_result.TargetInterpretation), "
            "MatchRows=tolong(__xdr_result.MatchRows), "
            "MatchedSeeds=toint(__xdr_result.MatchedSeeds)",
        )
    )
    return "\n".join(lines)


def compile_batches(targets, *, lookback, time_column, batch_size=20):
    """Bound distinct locators and request bytes, without splitting by source cohort."""
    if not 1 <= batch_size <= 50:
        raise GraphValidationError("validation batch size must be 1 to 50")
    groups = {}
    for target in sorted(targets, key=lambda t: (str(t.locator), t.pair_key)):
        path = str(target.locator) if "*" in target.locator.json_path else None
        groups.setdefault((target.locator.table, path), []).append(target)
    batches = []
    for group in groups.values():
        chunk = []
        for target in group:
            proposed = [*chunk, target]
            query = compile_query(proposed, lookback=lookback, time_column=time_column)
            if chunk and (
                len(query.encode()) > PROBE_QUERY_BYTE_LIMIT
                or len({str(t.locator) for t in proposed}) > batch_size
            ):
                batches.append(
                    ValidationBatch(
                        tuple(chunk),
                        compile_query(chunk, lookback=lookback, time_column=time_column),
                    )
                )
                proposed = [target]
                query = compile_query(proposed, lookback=lookback, time_column=time_column)
            if len(query.encode()) > PROBE_QUERY_BYTE_LIMIT:
                raise GraphValidationError("one validation cohort exceeds the 256 KiB query limit")
            chunk = proposed
        if chunk:
            batches.append(
                ValidationBatch(
                    tuple(chunk), compile_query(chunk, lookback=lookback, time_column=time_column)
                )
            )
    return tuple(batches)
