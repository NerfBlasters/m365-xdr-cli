"""Publish local overlap evidence and selectively validate it against the tenant."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

from filelock import Timeout as FileLockTimeout

from xdr_cli._lock import exclusive_lock
from xdr_cli.api.hunting import run_query
from xdr_cli.auth import AuthManager
from xdr_cli.backends import create_client
from xdr_cli.client import XDRClient
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import (
    ArtifactError,
    AuthError,
    ConflictError,
    PartialSuccessError,
    XDRError,
)
from xdr_cli.results import emit_result, write_result
from xdr_cli.schema_graph.evidence_cache import cached_evidence, with_evidence_snapshot
from xdr_cli.schema_graph.lineage import UnsupportedLineage
from xdr_cli.schema_graph.local_discovery import LocalPair, discover_local, pair_values
from xdr_cli.schema_graph.model import (
    FieldLocator,
    FieldRecord,
    Graph,
    GraphValidationError,
    InterpretationRecord,
    ObservationRecord,
    field_id,
    interpretation_id,
)
from xdr_cli.schema_graph.overlay import load_tenant_overlay, publish_tenant_overlay
from xdr_cli.schema_graph.probe import bounded_time_column, compile_target_probe_batches


def pair_key(pair: LocalPair) -> str:
    return hashlib.sha256(json.dumps(asdict(pair), sort_keys=True).encode()).hexdigest()[:24]


def pair_graph(pair: LocalPair, known: Graph) -> tuple[Graph, tuple[InterpretationRecord, ...]]:
    additions = Graph()
    interpretations = []
    for text in (pair.source, pair.target):
        locator = FieldLocator.parse(text)
        field = known.fields.get(field_id(locator)) or FieldRecord(
            field_id(locator),
            locator,
            "string",
            extra={"private": True, "provenance": ["local-overlap"]},
        )
        additions.add(field)
        namespace = f"local-{pair.normalizer}"
        interp = InterpretationRecord(
            interpretation_id(locator, namespace, "occurrence"),
            field.id,
            "identifier",
            namespace,
            "occurrence",
            pair.normalizer,
            extra={"private": True, "provisional": True, "provenance": ["local-overlap"]},
        )
        additions.add(interp)
        interpretations.append(interp)
    return additions, tuple(interpretations)


def eligible_shared_values(seeds):
    """Private addresses are not independent identifiers across table namespaces."""
    count = 0
    for seed in seeds:
        try:
            if ipaddress.ip_address(seed).is_private:
                continue
        except ValueError:
            pass
        count += 1
    return count


def local_observation(pair: LocalPair, interpretations, seeds=None) -> ObservationRecord:
    return ObservationRecord(
        observation_id=f"local:{pair_key(pair)}",
        source_interpretation=interpretations[0].id,
        target_interpretation=interpretations[1].id,
        transform=pair.normalizer,
        distinct_seeds=pair.shared_values,
        matched_seeds=pair.shared_values,
        matched_rows=pair.shared_values,
        probe_runs=1,
        provenance=("local-overlap",),
        outcome="matched",
        source_artifact_run_id=pair.source_run,
        target_artifact_run_id=pair.target_run,
        observed_at=pair.observed_at,
        extra={
            "evidence_stage": "local-overlap",
            "local_pair": asdict(pair),
            "eligible_shared_values": (
                eligible_shared_values(seeds)
                if seeds is not None
                else pair.shared_values
                if pair.normalizer != "identity"
                else 0
            ),
        },
    )


def verify_local_observation(graph, observation, tenant_id, *, require_fresh=True):
    # Retain the graph for this snapshot so object IDs cannot be recycled.
    cached_evidence("graph", id(graph), lambda: graph)
    return cached_evidence(
        "local-observation",
        (id(graph), tenant_id, repr(observation), require_fresh),
        lambda: _verify_local_observation(
            graph, observation, tenant_id, require_fresh=require_fresh
        ),
    )


def _verify_local_observation(graph, observation, tenant_id, *, require_fresh=True):
    """Reconstruct original evidence and live query bytes before trusting counts."""
    from xdr_cli.commands.schema_cmd import _verified_schema_artifact

    try:
        pair = LocalPair(**observation.extra["local_pair"])
        if not all(
            isinstance(v, str)
            for v in (
                pair.source,
                pair.target,
                pair.normalizer,
                pair.source_run,
                pair.target_run,
            )
        ):
            return None
        if observation.source_artifact_run_id != pair.source_run:
            return None
        for interp_id, locator in (
            (observation.source_interpretation, pair.source),
            (observation.target_interpretation, pair.target),
        ):
            interp = graph.interpretations[interp_id]
            if (
                str(graph.fields[interp.field_id].locator) != locator
                or interp.normalizer != pair.normalizer
            ):
                return None
        seeds = pair_values(pair, get_config_home() / "results", tenant_id)
        observed = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
        now = datetime.now(UTC)
        if observed > now:
            return None
        originals = [
            _verified_schema_artifact(run, tenant_id=tenant_id)
            for run in (pair.source_run, pair.target_run)
        ]
        if any(bundle is None for bundle in originals):
            return None
        original_times = [
            datetime.fromisoformat(bundle[0]["created_at"].replace("Z", "+00:00"))
            for bundle in originals
        ]
        if any(when > now for when in original_times):
            return None
        if datetime.fromisoformat(pair.observed_at.replace("Z", "+00:00")) != min(original_times):
            return None
        if observation.extra["evidence_stage"] == "local-overlap":
            if (
                observation.target_artifact_run_id != pair.target_run
                or observed != min(original_times)
                or observation.distinct_seeds != len(seeds)
                or observation.matched_seeds != len(seeds)
                or observation.extra.get("eligible_shared_values") != eligible_shared_values(seeds)
            ):
                return None
            return {"sampled_cohort": None}
        observed = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
        if require_fresh and observed < datetime.now(UTC) - timedelta(days=30):
            return None
        target = _verified_schema_artifact(observation.target_artifact_run_id, tenant_id=tenant_id)
        if target is None:
            return None
        meta, rows = target
        stage = meta.get("local_validation", {})
        if observed != datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00")):
            return None
        if (
            asdict(pair) not in stage.get("pairs", [])
            or stage.get("samples") != observation.distinct_seeds
        ):
            return None
        seeds = seeds[: observation.distinct_seeds]
        locator = FieldLocator.parse(pair.target)
        time_column = stage.get("time_column")
        if time_column not in {"Timestamp", "TimeGenerated"}:
            return None
        query = compile_target_probe_batches(
            [
                (
                    graph.interpretations[
                        interpretation_id(
                            FieldLocator.parse(item["target"]),
                            f"local-{pair.normalizer}",
                            "occurrence",
                        )
                    ],
                    FieldLocator.parse(item["target"]),
                )
                for item in stage["pairs"]
            ],
            seeds,
            batch_size=50,
            lookback=observation.lookback,
            available_columns={locator.table: {time_column}},
            expanded_paths=stage.get("expanded_paths", False),
        )[0].kql
        matching_rows = [row for row in rows if row.get("TargetLocator") == pair.target]
        if meta.get("query") != query or len(matching_rows) != 1:
            return None
        row = matching_rows[0]
        if (
            row.get("TargetLocator") != pair.target
            or row.get("TargetInterpretation") != observation.target_interpretation
            or row.get("MatchedSeeds") != observation.matched_seeds
            or row.get("MatchRows") != observation.matched_rows
            or observation.extra.get("eligible_shared_values")
            != max(0, observation.matched_seeds - (len(seeds) - eligible_shared_values(seeds)))
        ):
            return None
        # Existing independent-cohort requirements still apply; arbitrary local
        # string matches cannot assert semantic join safety.
        source_bundle = _verified_schema_artifact(pair.source_run, tenant_id=tenant_id)
        if source_bundle is None:
            return None
        return {
            "sampled_cohort": frozenset(seeds),
            "source_content_digest": source_bundle[0]["data_sha256"],
        }
    except (OSError, KeyError, TypeError, ValueError, GraphValidationError, UnsupportedLineage):
        return None


@contextmanager
def collection_claim(tenant_id):
    """Serialize planning and execution across local and active collection."""
    root = get_config_home() / "schema" / hashlib.sha256(tenant_id.encode()).hexdigest()[:12]
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with ExitStack() as stack:
        try:
            stack.enter_context(exclusive_lock(root / ".local-collection", timeout=0))
        except FileLockTimeout as exc:
            raise ConflictError(
                "Schema collection is already running for this tenant; retry after it finishes.",
                help_command="xdr schema collect",
            ) from exc
        yield


async def collect_local(
    ctx,
    *,
    plan_only: bool,
    local_only: bool,
    lookback: str,
    samples: int,
    max_queries: int,
    batch_size: int = 20,
    timeout: int,
    schema_rows: list[dict],
    canonical: Graph,
    on_result=None,
    mark_complete=True,
) -> None:
    with collection_claim(ctx.config.tenant_id):
        await _collect_local(
            ctx,
            plan_only=plan_only,
            local_only=local_only,
            lookback=lookback,
            samples=samples,
            max_queries=max_queries,
            batch_size=batch_size,
            timeout=timeout,
            schema_rows=schema_rows,
            canonical=canonical,
            on_result=on_result,
            mark_complete=mark_complete,
        )


@with_evidence_snapshot
async def _collect_local(
    ctx,
    *,
    plan_only: bool,
    local_only: bool,
    lookback: str,
    samples: int,
    max_queries: int,
    batch_size: int = 20,
    timeout: int,
    schema_rows: list[dict],
    canonical: Graph,
    on_result=None,
    mark_complete=True,
) -> None:
    tenant = ctx.config.tenant_id
    root = get_config_home()
    index_root = root / "schema" / hashlib.sha256(tenant.encode()).hexdigest()[:12]
    pairs, coverage = discover_local(root / "results", index_root, tenant)
    overlay = load_tenant_overlay(tenant)
    from xdr_cli.schema_graph.effective import merge_graphs

    known = merge_graphs(canonical, overlay.graph)
    additions = Graph()
    observations = []
    tasks = []
    planned_routes = {}
    available: dict[str, set[str]] = {}
    for row in schema_rows:
        available.setdefault(str(row.get("TableName")), set()).add(str(row.get("ColumnName")))
    retained = []
    fresh_routes = {}
    tested_routes = {}
    for observation in overlay.observations:
        stage = observation.extra.get("evidence_stage")
        if stage == "local-overlap":
            continue
        if stage == "identifier-search":
            from xdr_cli.schema_graph.discovery import verify_search_observation

            evidence = verify_search_observation(known, observation, tenant, require_fresh=False)
            if evidence is not None:
                retained.append(observation)
                when = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
                source = known.interpretations[observation.source_interpretation]
                target = known.interpretations[observation.target_interpretation]
                route = (
                    str(known.fields[source.field_id].locator),
                    str(known.fields[target.field_id].locator),
                    observation.transform,
                )
                if observation.lookback == lookback:
                    tested_routes.setdefault(route, []).append(
                        (evidence["sampled_cohort"], when.timestamp())
                    )
                if (
                    datetime.now(UTC) - timedelta(days=1) < when <= datetime.now(UTC)
                    and observation.lookback == lookback
                ):
                    source = known.interpretations[observation.source_interpretation]
                    target = known.interpretations[observation.target_interpretation]
                    route = (
                        str(known.fields[source.field_id].locator),
                        str(known.fields[target.field_id].locator),
                        observation.transform,
                    )
                    fresh_routes.setdefault(route, []).append(evidence["sampled_cohort"])
            else:
                coverage["retired_invalid_validations"] = (
                    coverage.get("retired_invalid_validations", 0) + 1
                )
            continue
        if stage != "local-validation":
            retained.append(observation)
            continue
        evidence = verify_local_observation(known, observation, tenant, require_fresh=False)
        if evidence is None:
            coverage["retired_invalid_validations"] = (
                coverage.get("retired_invalid_validations", 0) + 1
            )
            continue
        retained.append(observation)
        when = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
        pair = observation.extra["local_pair"]
        route = (pair["source"], pair["target"], observation.transform)
        if observation.lookback == lookback:
            tested_routes.setdefault(route, []).append(
                (evidence["sampled_cohort"], when.timestamp())
            )
        if (
            datetime.now(UTC) - timedelta(days=1) < when <= datetime.now(UTC)
            and observation.lookback == lookback
        ):
            pair = observation.extra["local_pair"]
            route = (pair["source"], pair["target"], observation.transform)
            fresh_routes.setdefault(route, []).append(evidence["sampled_cohort"])
    for pair in pairs:
        try:
            graph, interpretations = pair_graph(pair, known)
            values = pair_values(pair, root / "results", tenant)
            observation = local_observation(pair, interpretations, values)
            additions = merge_graphs(additions, graph)
        except (GraphValidationError, ValueError, UnsupportedLineage):
            coverage["invalid_local_pairs"] = coverage.get("invalid_local_pairs", 0) + 1
            continue
        observations.append(observation)
        locator = FieldLocator.parse(pair.target)
        time_column = bounded_time_column(locator.table, available)
        if time_column is None or locator.column not in available.get(locator.table, set()):
            reverse = FieldLocator.parse(pair.source)
            reverse_time = bounded_time_column(reverse.table, available)
            if reverse_time and reverse.column in available.get(reverse.table, set()):
                pair = replace(
                    pair,
                    source=pair.target,
                    target=pair.source,
                    source_run=pair.target_run,
                    target_run=pair.source_run,
                )
                interpretations = tuple(reversed(interpretations))
                time_column = reverse_time
            else:
                reason = (
                    "unavailable_validation_targets"
                    if locator.column not in available.get(locator.table, set())
                    else "tables_without_time_column"
                )
                coverage[reason] = coverage.get(reason, 0) + 1
                continue
        route = (pair.source, pair.target, pair.normalizer)
        seeds = frozenset(pair_values(pair, root / "results", tenant)[:samples])
        if not eligible_shared_values(seeds):
            coverage["non_discriminative_seed_routes"] = (
                coverage.get("non_discriminative_seed_routes", 0) + 1
            )
            continue
        if any(seeds <= cohort for cohort in fresh_routes.get(route, [])):
            coverage["fresh_validations_reused"] = coverage.get("fresh_validations_reused", 0) + 1
            continue
        if any(seeds <= cohort for cohort in planned_routes.get(route, [])):
            continue
        planned_routes.setdefault(route, []).append(seeds)
        tasks.append((pair, interpretations, time_column))
    grouped = {}
    for pair, interpretations, time_column in tasks:
        seeds = tuple(pair_values(pair, root / "results", tenant)[:samples])
        key = (
            pair.source_run,
            pair.source,
            pair.normalizer,
            FieldLocator.parse(pair.target).table,
            seeds,
            time_column,
        )
        grouped.setdefault(key, []).append((pair, interpretations))
    batches = []
    for key, items in grouped.items():
        seeds, time_column = key[-2:]
        compiled_batches = compile_target_probe_batches(
            [(interps[1], FieldLocator.parse(pair.target)) for pair, interps in items],
            list(seeds),
            lookback=lookback,
            batch_size=batch_size,
            available_columns={key[3]: {time_column}},
            expanded_paths=True,
        )
        for compiled in compiled_batches:
            selected = [
                (pair, interps)
                for pair, interps in items
                if pair.target in compiled.target_locators
            ]
            batches.append((compiled, selected, seeds, time_column))
    # Freshness controls reuse; completion history controls fairness. Unseen
    # cohorts run before stale ones, then refresh the oldest verified work.
    batches.sort(
        key=lambda batch: min(
            max(
                (
                    when
                    for cohort, when in tested_routes.get(
                        (pair.source, pair.target, pair.normalizer), []
                    )
                    if set(batch[2]) <= cohort
                ),
                default=0,
            )
            for pair, _ in batch[1]
        )
    )
    if not plan_only:
        published = publish_tenant_overlay(
            tenant,
            graph=additions,
            observations=(*retained, *observations),
            replace_observations=True,
            expected_generation=overlay.metadata.get("generation"),
        )
    else:
        published = {}
    executed = 0
    attempted = 0
    failure = None
    if not plan_only and not local_only and batches:
        client = create_client(
            ctx.config, timeout=timeout,
            auth_factory=AuthManager, client_factory=XDRClient,
        )
        try:
            for compiled, items, seeds, time_column in batches[:max_queries]:
                attempted += 1
                result = await run_query(client, compiled.kql)
                artifact = write_result(
                    result.results,
                    command="schema collect local-validation",
                    query=compiled.kql,
                    tenant_id=tenant,
                    preview_rows=0,
                    extra_metadata={
                        "local_validation": {
                            "pairs": [asdict(pair) for pair, _ in items],
                            "samples": len(seeds),
                            "time_column": time_column,
                            "expanded_paths": True,
                        }
                    },
                )
                for pair, interpretations in items:
                    matching = [
                        row for row in result.results if row.get("TargetLocator") == pair.target
                    ]
                    if len(matching) != 1:
                        raise ArtifactError("Local validation returned an unexpected result shape.")
                    row = matching[0]
                    matched, count = row.get("MatchedSeeds"), row.get("MatchRows")
                    if (
                        row.get("TargetLocator") != pair.target
                        or row.get("TargetInterpretation") != interpretations[1].id
                        or type(matched) is not int
                        or type(count) is not int
                        or not 0 <= matched <= len(seeds)
                        or count < matched
                    ):
                        raise ArtifactError("Local validation returned invalid match counts.")
                    observation = ObservationRecord(
                        observation_id=f"local-live:{artifact.receipt.run_id}-{pair_key(pair)[:12]}",
                        source_interpretation=interpretations[0].id,
                        target_interpretation=interpretations[1].id,
                        transform=pair.normalizer,
                        distinct_seeds=len(seeds),
                        matched_seeds=matched,
                        matched_rows=count,
                        probe_runs=1,
                        provenance=("local-overlap-validation",),
                        source_artifact_run_id=pair.source_run,
                        target_artifact_run_id=artifact.receipt.run_id,
                        outcome="matched" if matched else "no-match",
                        observed_at=artifact.metadata["created_at"],
                        lookback=lookback,
                        extra={
                            "evidence_stage": "local-validation",
                            "local_pair": asdict(pair),
                            "pair_key": pair_key(pair),
                            "eligible_shared_values": max(
                                0, matched - (len(seeds) - eligible_shared_values(seeds))
                            ),
                        },
                    )
                    publish_tenant_overlay(tenant, observations=(observation,))
                executed += 1
        except XDRError as exc:
            failure = exc
        finally:
            await client.close()
    remaining = len(batches) - executed
    excluded = {
        key: coverage[key]
        for key in (
            "unavailable_validation_targets",
            "tables_without_time_column",
            "invalid_local_pairs",
            "non_discriminative_seed_routes",
        )
        if coverage.get(key)
    }
    gaps = {}
    if (
        mark_complete
        and not plan_only
        and not local_only
        and not remaining
        and not gaps
        and failure is None
    ):
        from xdr_cli.schema_graph.maintenance import mark_collection_complete

        mark_collection_complete(tenant, {"mode": "local-first", "local_coverage": coverage})
    context = {
        "local_coverage": coverage,
        "coverage_gaps": gaps,
        "excluded_scope": excluded,
        "scope_complete": not remaining and not gaps and failure is None,
        "candidate_pairs": len(pairs),
        "validation_queries_planned": len(batches),
        "queries_executed": executed,
        "remaining_queries": remaining,
        "networked": attempted > 0,
        "mode": "plan" if plan_only else "local-only" if local_only else "local-first",
        "semantic_generation": published.get("generation"),
        "next_command": "xdr schema collect" if remaining else "xdr schema discoveries",
    }
    (on_result or emit_result)(
        write_result(
            [pair.to_dict() for pair in pairs],
            command="schema collect",
            tenant_id=tenant,
            receipt_context=context,
            extra_metadata=context,
            server_truncation_state="known-complete",
        )
    )
    if failure:
        recovery = failure.help_command or (
            "xdr auth status" if isinstance(failure, AuthError) else "xdr schema collect"
        )
        raise PartialSuccessError(
            "Local evidence was saved; tenant validation stopped after an upstream failure.",
            help_command=recovery,
            retryable=failure.retryable,
            retry_after_seconds=failure.retry_after_seconds,
            original={
                "code": int(failure.exit_code),
                "type": type(failure).__name__,
                "error_code": failure.error_code,
                "help_command": recovery,
                "suggested_fix": failure.suggested_fix,
            },
        ) from failure
    if (remaining or gaps) and not plan_only and not local_only:
        raise PartialSuccessError(
            "Local evidence and completed validations were saved. "
            "Inspect remaining tasks and unavailable validation targets.",
            help_command="xdr schema collect" if remaining else "xdr schema refresh",
        )
