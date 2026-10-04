"""Identifier-led discovery with a typed, privately retained query result contract."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from xdr_cli.api.hunting import run_query
from xdr_cli.auth import AuthManager
from xdr_cli.client import XDRClient
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import ArtifactError, AuthError, PartialSuccessError
from xdr_cli.results import write_result
from xdr_cli.schema_graph.evidence_cache import cached_evidence
from xdr_cli.schema_graph.local_discovery import (
    LocalPair,
    artifact_metadata,
    discoverable_path,
    verified_values,
)
from xdr_cli.schema_graph.model import FieldLocator, Graph, GraphValidationError, ObservationRecord
from xdr_cli.schema_graph.overlay import load_tenant_overlay, publish_tenant_overlay
from xdr_cli.schema_graph.probe import bounded_time_column

SEARCH_STAGE = "identifier-search"
SEARCH_COMMAND = "schema collect discovery"
EXPECTED_EXCLUSIONS = frozenset({
    "unsupported_paths", "excluded_non_schema_paths", "unsupported_normalization_cells",
    "uncompilable_seed_scopes",
})


def saved_seeds(tenant_id, sources=()):
    """Read identifiers even when only one saved physical table contains them."""
    root = get_config_home() / "results"
    tenant = hashlib.sha256(tenant_id.strip().encode()).hexdigest()
    seeds = defaultdict(list)
    coverage = defaultdict(int)
    from xdr_cli.schema_graph.local_collection import eligible_shared_values
    for path in sorted(root.glob("*/*.meta.json")):
        try:
            header = json.loads(path.read_text())
            if header.get("command") not in {"hunt run", "library run"}:
                continue
            meta, _ = artifact_metadata(path, root, tenant)
            values = original_values(meta["run_id"], tenant_id)
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            coverage["skipped_seed_artifacts"] += 1
            continue
        coverage["seed_artifacts"] += 1
        for locator, normalizer, value in sorted(values):
            if sources and locator not in sources:
                continue
            if not eligible_shared_values((value,)):
                coverage["non_discriminative_seed_cells"] += 1
                continue
            seeds[normalizer, value].append({"run_id": meta["run_id"], "locator": locator})
    coverage["seed_identifiers"] = len(seeds)
    coverage["seed_fields"] = len(
        {origin["locator"] for origins in seeds.values() for origin in origins}
    )
    return seeds, dict(coverage)


def original_values(run, tenant_id):
    root = get_config_home() / "results"
    tenant = hashlib.sha256(tenant_id.strip().encode()).hexdigest()
    if not isinstance(run, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", run):
        raise ValueError("invalid-discovery-source-id")

    def load():
        paths = list(root.glob(f"*/{run}.meta.json"))
        if len(paths) != 1:
            raise ValueError("missing-seed-origin")
        meta, _ = artifact_metadata(paths[0], root, tenant)
        if datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00")) > datetime.now(UTC):
            raise ValueError("future-seed-evidence")
        if meta["command"] not in {"hunt run", "library run"}:
            raise ValueError("invalid-seed-origin-command")
        return set(verified_values(paths[0], root, tenant, tenant_id=tenant_id))

    return cached_evidence("discovery-source", (str(root), tenant, run), load)


def _search_artifact(run_id, tenant_id):
    from xdr_cli.commands.schema_cmd import _verified_schema_artifact
    from xdr_cli.schema_graph.discovery_query import compile_discovery_query

    bundle = _verified_schema_artifact(run_id, tenant_id=tenant_id)
    if bundle is None:
        raise ValueError("missing-discovery-evidence")
    meta, rows = bundle
    if meta.get("tenant_binding", {}).get("state") != "bound":
        raise ValueError("unbound-discovery-evidence")
    spec = meta.get("identifier_search")
    if meta.get("command") != SEARCH_COMMAND or not isinstance(spec, dict):
        raise ValueError("not-discovery-evidence")
    if meta.get("query_sha256") != hashlib.sha256(meta["query"].encode()).hexdigest():
        raise ValueError("discovery-query-digest-mismatch")
    if compile_discovery_query(**spec["query_args"]) != meta["query"]:
        raise ValueError("discovery-query-provenance-mismatch")
    args = spec["query_args"]
    values = set(args["seeds"])
    origins = spec["origins"]
    if not isinstance(origins, list) or not origins:
        raise ValueError("missing-discovery-seed-origins")
    backed = set()
    for origin in origins:
        locator = str(FieldLocator.parse(origin["locator"]))
        run = origin["run_id"]
        if not isinstance(run, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", run):
            raise ValueError("invalid-discovery-source-id")

        original = original_values(run, tenant_id)
        if (locator, args["normalizer"], origin["value"]) not in original:
            raise ValueError("discovery-seed-not-in-original")
        backed.add(origin["value"])
    if backed != values:
        raise ValueError("unbacked-discovery-seeds")
    hits, gaps = read_search_rows(rows, args)
    return meta, hits, gaps


def search_artifact(run_id, tenant_id):
    return cached_evidence(
        "discovery-artifact",
        (str(get_config_home()), tenant_id, run_id),
        lambda: _search_artifact(run_id, tenant_id),
    )


def _query_boolean(value):
    # Graph hunting serializes KQL bool columns as 0/1 on some tenants.
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    raise ValueError("invalid-discovery-boolean")


def read_search_rows(rows, args):
    """Interpret explicitly typed query output, never infer its fields from KQL."""
    from xdr_cli.schema_graph.normalize import normalize_value

    receipts = [row for row in rows if row.get("RowKind") == "receipt"]
    matches = [row for row in rows if row.get("RowKind") == "match"]
    if (
        len(receipts) != 1
        or len(rows) != len(matches) + 1
        or type(receipts[0].get("ReturnedRows")) is not int
        or receipts[0]["ReturnedRows"] != len(matches)
    ):
        raise ValueError("missing-or-incomplete-discovery-receipt")
    rows = matches
    hits, gaps, seen = [], defaultdict(int), set()
    if len(rows) > args["row_limit"]:
        gaps["row_limit_reached"] += 1
    for row in rows:
        path = row.get("PathTokens")
        if isinstance(path, str):
            path = json.loads(path)
        if not isinstance(path, list) or not all(isinstance(p, str) for p in path):
            raise ValueError("invalid-discovery-path")
        unsupported = _query_boolean(row.get("UnsupportedPath"))
        count = row.get("MatchingRows")
        limited = _query_boolean(row.get("DepthLimitReached"))
        if type(count) is not int or count < 1:
            raise ValueError("invalid-discovery-count-or-depth")
        if (
            row.get("TableName") not in args["tables"]
            or not isinstance(row.get("ColumnName"), str)
            or not isinstance(row.get("MatchedValue"), str)
            or len(path) > args["max_depth"]
        ):
            raise ValueError("discovery-location-outside-query")
        if unsupported:
            gaps["unsupported_paths"] += 1
            continue
        try:
            locator = FieldLocator(row["TableName"], row["ColumnName"], tuple(path))
        except GraphValidationError:
            gaps["unsupported_paths"] += 1
            continue
        if len(str(locator)) > 768:
            gaps["unsupported_paths"] += 1
            continue
        if path and not discoverable_path(tuple(path)):
            gaps["excluded_non_schema_paths"] += 1
            continue
        if limited:
            gaps["depth_limit_reached"] += 1
            continue
        if args["normalizer"] == "upn-lower" and not row["MatchedValue"].isascii():
            gaps["unsupported_normalization_cells"] += 1
            continue
        value = normalize_value(args["normalizer"], row["MatchedValue"])
        if value not in args["seeds"]:
            raise ValueError("discovery-result-not-an-exact-seed")
        key = (str(locator), value)
        if key in seen:
            raise ValueError("duplicate-discovery-result")
        seen.add(key)
        hits.append((str(locator), value, count))
    return hits, dict(gaps)


def verify_search_observation(graph, observation, tenant_id, *, require_fresh=True):
    from xdr_cli.commands.schema_cmd import _verified_schema_artifact
    from xdr_cli.schema_graph.local_collection import eligible_shared_values

    try:
        meta, hits, _ = search_artifact(observation.target_artifact_run_id, tenant_id)
        spec = meta["identifier_search"]
        source = graph.interpretations[observation.source_interpretation]
        target = graph.interpretations[observation.target_interpretation]
        source_locator = str(graph.fields[source.field_id].locator)
        target_locator = str(graph.fields[target.field_id].locator)
        if not (
            source.normalizer
            == target.normalizer
            == observation.transform
            == spec["query_args"]["normalizer"]
        ):
            return None
        refs = sorted({origin["run_id"] for origin in spec["origins"]})
        if observation.extra.get("discovery_source_runs") != refs:
            return None
        seeds = frozenset(
            value
            for locator, normalizer, value in original_values(
                observation.source_artifact_run_id, tenant_id
            )
            if locator == source_locator
            and normalizer == observation.transform
            and value in spec["query_args"]["seeds"]
        )
        matches = [
            (value, count) for loc, value, count in hits if loc == target_locator and value in seeds
        ]
        if (
            not seeds
            or not matches
            or observation.distinct_seeds != len(seeds)
            or observation.matched_seeds != len(matches)
            or observation.matched_rows != sum(count for _, count in matches)
            or observation.lookback != spec["query_args"]["lookback"]
            or observation.observed_at != meta["created_at"]
            or observation.extra.get("eligible_shared_values")
            != eligible_shared_values(value for value, _ in matches)
        ):
            return None
        when = datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00"))
        if when > datetime.now(UTC) or (
            require_fresh and when < datetime.now(UTC) - timedelta(days=30)
        ):
            return None
        original = _verified_schema_artifact(
            observation.source_artifact_run_id, tenant_id=tenant_id
        )
        if original is None:
            return None
        return {"sampled_cohort": seeds, "source_content_digest": original[0]["data_sha256"]}
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def publish_search(run_id, tenant_id, canonical, seed_origins=None):
    from xdr_cli.schema_graph.effective import merge_graphs
    from xdr_cli.schema_graph.local_collection import eligible_shared_values, pair_graph

    meta, hits, gaps = search_artifact(run_id, tenant_id)
    spec = meta["identifier_search"]
    overlay = load_tenant_overlay(tenant_id)
    known = merge_graphs(canonical, overlay.graph)
    additions, observations = Graph(), []
    sources = defaultdict(set)
    targets = defaultdict(dict)
    for origin in spec["origins"]:
        sources[origin["run_id"], origin["locator"]].add(origin["value"])
    if seed_origins is not None:
        for value in spec["query_args"]["seeds"]:
            for origin in seed_origins.get((spec["query_args"]["normalizer"], value), []):
                sources[origin["run_id"], origin["locator"]].add(value)
    for locator, value, count in hits:
        targets[locator][value] = count
    refs = sorted({origin["run_id"] for origin in spec["origins"]})
    existing = {item.observation_id for item in overlay.observations}
    for (source_run, source), seeds in sources.items():
        for target, values in targets.items():
            matched = seeds & values.keys()
            if not matched or FieldLocator.parse(source).table == FieldLocator.parse(target).table:
                continue
            identifier = hashlib.sha256(
                f"{run_id}:{source_run}:{source}:{target}".encode()
            ).hexdigest()[:24]
            if f"search:{identifier}" in existing:
                continue
            pair = LocalPair(
                source,
                target,
                spec["query_args"]["normalizer"],
                source_run,
                run_id,
                len(matched),
                meta["created_at"],
            )
            try:
                graph, interpretations = pair_graph(pair, known)
                additions = merge_graphs(additions, graph)
            except GraphValidationError:
                gaps["invalid_local_pairs"] = gaps.get("invalid_local_pairs", 0) + 1
                continue
            observations.append(
                ObservationRecord(
                    observation_id=f"search:{identifier}",
                    source_interpretation=interpretations[0].id,
                    target_interpretation=interpretations[1].id,
                    transform=pair.normalizer,
                    distinct_seeds=len(seeds),
                    matched_seeds=len(matched),
                    matched_rows=sum(values[value] for value in matched),
                    probe_runs=1,
                    provenance=("identifier-search",),
                    outcome="matched",
                    source_artifact_run_id=source_run,
                    target_artifact_run_id=run_id,
                    observed_at=meta["created_at"],
                    lookback=spec["query_args"]["lookback"],
                    extra={
                        "evidence_stage": SEARCH_STAGE,
                        "discovery_source_runs": refs,
                        "eligible_shared_values": eligible_shared_values(matched),
                    },
                )
            )
    existing = {item.observation_id for item in overlay.observations}
    new = tuple(item for item in observations if item.observation_id not in existing)
    if new:
        publish_tenant_overlay(tenant_id, graph=additions, observations=new)
    return len(new), gaps


async def explore_saved_identifiers(
    ctx,
    *,
    schema_rows,
    canonical,
    plan_only=False,
    lookback="30d",
    max_queries=20,
    seed_batch_size=20,
    max_depth=6,
    row_limit=2000,
    timeout=120,
    sources=(),
    on_result=None,
    mark_complete=True,
):
    """Search every saved identifier; budgets pause work rather than cap its scope."""
    from xdr_cli.exceptions import LocalNotFoundError, UsageError, XDRError
    from xdr_cli.results import emit_result
    from xdr_cli.schema_graph.discovery_query import compile_discovery_query
    from xdr_cli.schema_graph.evidence_cache import evidence_snapshot
    from xdr_cli.schema_graph.local_collection import collection_claim

    try:
        sources = tuple(str(FieldLocator.parse(source)) for source in sources)
    except GraphValidationError as exc:
        raise UsageError("Discovery sources must be physical Table.Column locators.") from exc
    with collection_claim(ctx.config.tenant_id), evidence_snapshot():
        from xdr_cli.schema_graph.local_collection import _collect_local

        local_receipts = []
        await _collect_local(
            ctx,
            plan_only=plan_only,
            local_only=True,
            lookback=lookback,
            samples=5,
            max_queries=0,
            timeout=timeout,
            schema_rows=schema_rows,
            canonical=canonical,
            on_result=local_receipts.append,
        )
        seeds, coverage = saved_seeds(ctx.config.tenant_id, sources)
        seeded_sources = {origin["locator"] for origins in seeds.values() for origin in origins}
        if set(sources) - seeded_sources:
            raise LocalNotFoundError("saved identifiers for requested source", "xdr results list")
        columns = defaultdict(set)
        for row in schema_rows:
            columns[row["TableName"]].add(row["ColumnName"])
        tables = defaultdict(list)
        for table in sorted(columns):
            time_column = bounded_time_column(table, columns)
            if time_column is None:
                coverage["tables_without_time_column"] = (
                    coverage.get("tables_without_time_column", 0) + 1
                )
            else:
                tables[time_column].append(table)
        from xdr_cli.schema_graph.discovery_query import MAX_DISCOVERY_TABLES

        table_groups = [
            (time_column, names[offset : offset + MAX_DISCOVERY_TABLES])
            for time_column, names in tables.items()
            for offset in range(0, len(names), MAX_DISCOVERY_TABLES)
        ]
        completed, prior_gaps = set(), defaultdict(int)
        excluded = dict(local_receipts[0].receipt.context.get("excluded_scope", {}))

        def record_coverage(counts):
            for key, count in counts.items():
                if key in EXPECTED_EXCLUSIONS:
                    excluded[key] = excluded.get(key, 0) + count
                else:
                    prior_gaps[key] += count
        if coverage.get("tables_without_time_column"):
            excluded["tables_without_time_column"] = coverage["tables_without_time_column"]
        for key, value in local_receipts[0].receipt.context.get("coverage_gaps", {}).items():
            prior_gaps[key] += value
        last_completed = {}
        # Query output is the durable checkpoint. Verify it, including original
        # seed provenance, before suppressing any work on a subsequent run.
        for path in sorted((get_config_home() / "results").glob("*/*.meta.json")):
            try:
                header = json.loads(path.read_text())
                if header.get("command") != SEARCH_COMMAND:
                    continue
                meta, _, gaps = search_artifact(header["run_id"], ctx.config.tenant_id)
                when = datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00"))
                if when > datetime.now(UTC):
                    raise ValueError("future-discovery-evidence")
                fresh = when >= datetime.now(UTC) - timedelta(days=1)
                args = meta["identifier_search"]["query_args"]
                scope = {k: v for k, v in args.items() if k not in {"seeds", "normalizer"}}
                # A smaller batch can recover rows hidden by an earlier cap.
                refining = bool(gaps.get("row_limit_reached")) and (
                    seed_batch_size < len(args["seeds"])
                )
                if not refining:
                    for value in args["seeds"]:
                        key = (args["normalizer"], value, json.dumps(scope, sort_keys=True))
                        last_completed[key] = max(when.timestamp(), last_completed.get(key, 0))
                        if fresh:
                            completed.add(key)
                            if not (set(gaps) - EXPECTED_EXCLUSIONS):
                                for table in args["tables"]:
                                    single_scope = dict(scope, tables=[table])
                                    completed.add(
                                        (
                                            args["normalizer"],
                                            value,
                                            json.dumps(single_scope, sort_keys=True),
                                        )
                                    )
                relevant = (
                    args["lookback"] == lookback
                    and args["max_depth"] == max_depth
                    and args["row_limit"] == row_limit
                    and (args["time_column"], args["tables"]) in table_groups
                    and any((args["normalizer"], value) in seeds for value in args["seeds"])
                )
                if relevant and not refining and fresh:
                    record_coverage(gaps)
                if not plan_only:
                    publish_search(meta["run_id"], ctx.config.tenant_id, canonical, seeds)
            except (OSError, ValueError, KeyError, TypeError, RecursionError):
                coverage["invalid_search_artifacts"] = (
                    coverage.get("invalid_search_artifacts", 0) + 1
                )
        grouped = defaultdict(list)
        for normalizer, value in sorted(seeds, key=lambda item: (len(seeds[item]), item)):
            for time_column, selected_tables in table_groups:
                scope = dict(
                    tables=selected_tables,
                    time_column=time_column,
                    lookback=lookback,
                    max_depth=max_depth,
                    row_limit=row_limit,
                )
                key = (normalizer, value, json.dumps(scope, sort_keys=True))
                if key not in completed:
                    pending_tables = [
                        table
                        for table in selected_tables
                        if (
                            normalizer,
                            value,
                            json.dumps(dict(scope, tables=[table]), sort_keys=True),
                        )
                        not in completed
                    ]
                    if pending_tables:
                        pending_scope = json.dumps(
                            dict(scope, tables=pending_tables), sort_keys=True
                        )
                        grouped[normalizer, pending_scope].append(value)
        tasks = []

        def add_batch(normalizer, raw_scope, batch):
            args = dict(json.loads(raw_scope), normalizer=normalizer, seeds=batch)
            try:
                compile_discovery_query(**args)
            except GraphValidationError:
                if len(batch) > 1:
                    midpoint = len(batch) // 2
                    add_batch(normalizer, raw_scope, batch[:midpoint])
                    add_batch(normalizer, raw_scope, batch[midpoint:])
                else:
                    coverage["uncompilable_seed_scopes"] = (
                        coverage.get("uncompilable_seed_scopes", 0) + 1
                    )
                    excluded["uncompilable_seed_scopes"] = (
                        excluded.get("uncompilable_seed_scopes", 0) + 1
                    )
                return
            origins = [
                dict(origin, value=value) for value in batch for origin in seeds[normalizer, value]
            ]
            tasks.append((args, origins))

        for (normalizer, raw_scope), values in grouped.items():
            values.sort(key=lambda value: last_completed.get((normalizer, value, raw_scope), 0))
            for offset in range(0, len(values), seed_batch_size):
                batch = values[offset : offset + seed_batch_size]
                add_batch(normalizer, raw_scope, batch)
        tasks.sort(
            key=lambda task: min(
                last_completed.get(
                    (
                        task[0]["normalizer"],
                        value,
                        json.dumps(
                            {k: v for k, v in task[0].items() if k not in {"seeds", "normalizer"}},
                            sort_keys=True,
                        ),
                    ),
                    0,
                )
                for value in task[0]["seeds"]
            )
        )
        executed, added, failure, failure_run_id, attempted = 0, 0, None, None, 0
        if not plan_only and tasks:
            client = XDRClient(get_token=AuthManager(ctx.config).get_token, timeout=timeout)
            try:
                for args, origins in tasks[:max_queries]:
                    query = compile_discovery_query(**args)
                    attempted += 1
                    result = await run_query(client, query)
                    read_search_rows(result.results, args)
                    artifact = write_result(
                        result.results,
                        command=SEARCH_COMMAND,
                        query=query,
                        tenant_id=ctx.config.tenant_id,
                        preview_rows=0,
                        extra_metadata={
                            "identifier_search": {"query_args": args, "origins": origins}
                        },
                        server_truncation_state="unknown",
                    )
                    count, gaps = publish_search(
                        artifact.receipt.run_id, ctx.config.tenant_id, canonical
                    )
                    added += count
                    record_coverage(gaps)
                    executed += 1
            except XDRError as exc:
                failure = exc
                diagnostic = write_result(
                    [{"error_code": exc.error_code, "message": exc.message}],
                    command="schema collect discovery-failure",
                    query=query,
                    tenant_id=ctx.config.tenant_id,
                    preview_rows=0,
                )
                failure_run_id = diagnostic.receipt.run_id
            except ValueError as exc:
                failure = ArtifactError("Discovery returned invalid structured evidence.")
                failure.__cause__ = exc
            finally:
                await client.close()
        remaining = len(tasks) - executed
        import shlex

        continuation = [
            "xdr",
            "schema",
            "collect",
            "--explore",
            "--lookback",
            lookback,
            "--seed-batch-size",
            str(seed_batch_size),
            "--max-json-depth",
            str(max_depth),
            "--discovery-row-limit",
            str(row_limit),
            "--timeout",
            str(timeout),
            "--max-queries-per-page",
            str(max_queries),
        ]
        for source in sources:
            continuation.extend(["--source", source])
        resume_command = shlex.join(continuation)
        if prior_gaps:
            gap_command = resume_command
            if prior_gaps.get("row_limit_reached") and row_limit < 10000:
                gap_command = gap_command.replace(
                    f"--discovery-row-limit {row_limit}",
                    f"--discovery-row-limit {min(row_limit * 2, 10000)}",
                )
            elif prior_gaps.get("row_limit_reached") and seed_batch_size > 1:
                gap_command = gap_command.replace(
                    f"--seed-batch-size {seed_batch_size}",
                    f"--seed-batch-size {max(seed_batch_size // 2, 1)}",
                )
            if prior_gaps.get("depth_limit_reached") and max_depth < 12:
                gap_command = gap_command.replace(
                    f"--max-json-depth {max_depth}", "--max-json-depth 12"
                )
            if gap_command == resume_command:
                gap_command = None
        else:
            gap_command = None
        if mark_complete and not plan_only and not remaining and not prior_gaps and not failure:
            from xdr_cli.schema_graph.maintenance import mark_collection_complete

            mark_collection_complete(ctx.config.tenant_id, {"mode": "identifier-discovery"})
        local_receipts[0].receipt.context["shown"] = 0
        local_receipts[0].receipt.context["has_more"] = local_receipts[0].receipt.rows > 0
        context = dict(
            mode="identifier-discovery",
            networked=attempted > 0,
            failure_run_id=failure_run_id,
            queries_planned=len(tasks),
            queries_executed=executed,
            remaining_queries=remaining,
            observations_added=added,
            coverage=coverage,
            coverage_gaps=dict(prior_gaps),
            excluded_scope=excluded,
            normalization_scope={"addresses": "ASCII-only"},
            scope_complete=not remaining and not prior_gaps,
            next_command=resume_command if remaining else gap_command or "xdr schema discoveries",
            local_result=local_receipts[0].receipt.to_dict(),
        )
        (on_result or emit_result)(
            write_result(
                [],
                command="schema collect",
                tenant_id=ctx.config.tenant_id,
                receipt_context=context,
                extra_metadata=context,
                preview_rows=0,
            )
        )
        if failure:
            raise PartialSuccessError(
                "Discovery saved progress before an upstream failure.",
                help_command=failure.help_command
                or ("xdr auth status" if isinstance(failure, AuthError) else resume_command),
                retry_after_seconds=failure.retry_after_seconds,
                retryable=failure.retryable,
                original={"type": type(failure).__name__, "code": int(failure.exit_code)},
            ) from failure
        if not plan_only and (remaining or prior_gaps):
            raise PartialSuccessError(
                "Discovery saved progress; inspect remaining queries and coverage gaps.",
                help_command=(resume_command if remaining else gap_command)
                or "xdr schema discoveries",
            )
