"""Initialize a tenant from the public reference and bounded live validation."""

from __future__ import annotations

import asyncio
import shlex
from collections import Counter
from pathlib import Path

import click
import httpx

from xdr_cli.auth import AuthManager
from xdr_cli.backends import create_client
from xdr_cli.client import XDRClient
from xdr_cli.config import get_config_home
from xdr_cli.exceptions import (
    APIError,
    ArtifactError,
    NetworkError,
    PartialSuccessError,
    UsageError,
)
from xdr_cli.results import emit_result, write_result
from xdr_cli.schema_graph.reference import (
    ReferenceError,
    import_reference_directory,
    load_snapshot,
)
from xdr_cli.schema_graph.reference_routes import (
    compare_physical_schema,
    reference_catalog,
    tenant_candidate_routes,
)
from xdr_cli.schema_graph.reference_validation import validate_reference


def register_schema_init(schema_app):
    @schema_app.command("init")
    @click.option("--reference-dir", default=None,
                  type=click.Path(exists=True, file_okay=False, path_type=Path),
                  help="Import a complete saved reference snapshot instead of downloading.")
    @click.option("--sync-reference", is_flag=True, help="Download a fresh public snapshot.")
    @click.option("--skip-refresh", is_flag=True, help="Use the existing physical schema cache.")
    @click.option("--plan-only", is_flag=True,
                  help="Plan using local caches; no network or cache changes.")
    @click.option("--metadata-source", type=click.Choice(["auto", "portal", "probe"]),
                  default="auto")
    @click.option("--lookback", default="7d", show_default=True)
    @click.option("--samples", type=click.IntRange(1, 100), default=50, show_default=True)
    @click.option("--row-limit", type=click.IntRange(1, 10000), default=1000, show_default=True)
    @click.option("--max-queries", type=click.IntRange(0, 1000), default=200, show_default=True)
    @click.option("--revalidate", is_flag=True, help="Rerun fresh saved validations.")
    @click.pass_context
    def schema_init(ctx, **options):
        """Compare this tenant to XDRInternals and validate all applicable mappings.

        Reference mappings start trusted. No-data results preserve that trust;
        empirical matches are explicitly labeled and retain bounded query scope.
        Rerun after a budget pause to reuse verified results and continue.
        """
        asyncio.run(_initialize(ctx.obj, **options))


async def _initialize(
    ctx, *, reference_dir=None, sync_reference=False, skip_refresh=False, plan_only=False,
    metadata_source="auto", lookback="7d", samples=50, row_limit=1000, max_queries=200,
    revalidate=False,
):
    from xdr_cli.commands.schema_cmd import _load_cache, _schema_refresh
    from xdr_cli.schema_graph.probe import validate_lookback
    from xdr_cli.schema_graph.reference import sync_reference as download_reference

    try:
        validate_lookback(lookback)
    except ValueError as exc:
        raise UsageError(str(exc)) from exc
    if plan_only and (reference_dir or sync_reference):
        raise UsageError("--plan-only uses local caches; omit --reference-dir and --sync-reference")

    home = get_config_home()
    try:
        if plan_only:
            snapshot = load_snapshot(home)
        elif reference_dir:
            snapshot = import_reference_directory(home, reference_dir)
        elif sync_reference or load_snapshot(home) is None:
            snapshot = download_reference(home)
        else:
            snapshot = load_snapshot(home)
        if snapshot is None:
            raise ReferenceError("No local reference snapshot; run xdr schema init first")
    except (ReferenceError, OSError) as exc:
        raise ArtifactError(str(exc), help_command="xdr schema init --sync-reference") from exc
    except httpx.HTTPStatusError as exc:
        raise APIError("Public schema reference download failed",
                       status_code=exc.response.status_code) from exc
    except httpx.RequestError as exc:
        raise NetworkError("Could not download public schema reference") from exc
    refresh_failure = None
    if not skip_refresh and not plan_only:
        try:
            await _schema_refresh(ctx, on_result=lambda artifact: None,
                                  metadata_source=metadata_source,
                                  extra_tables=snapshot.table_names)
        except PartialSuccessError as exc:
            refresh_failure = exc.error_code
    rows, cache = _load_cache(ctx)
    from dataclasses import replace

    from xdr_cli.schema_graph.reference_state import validation_root

    candidates, discovery = tenant_candidate_routes(
        snapshot, rows, cache_meta=cache,
        cache_root=validation_root(home, ctx.config.tenant_id).parent,
    )
    client = None
    try:
        if not plan_only:
            client = create_client(ctx.config, timeout=ctx.config.api_timeout,
                                   auth_factory=AuthManager, client_factory=XDRClient)
        report = await validate_reference(
            client, snapshot, rows, home=home, tenant_id=ctx.config.tenant_id,
            lookback=lookback, samples=samples, row_limit=row_limit, max_queries=max_queries,
            revalidate=revalidate, plan_only=plan_only,
            extra_routes=candidates,
            on_progress=lambda route, number: click.echo(
                f"Validating reference route {number}: {route}", err=True
            ) if not ctx.effective_quiet else None,
        )
    except ReferenceError as exc:
        raise ArtifactError(str(exc), help_command="xdr schema init --revalidate") from exc
    finally:
        if client is not None:
            await client.close()
    catalog = reference_catalog(snapshot, rows, report["routes"])
    discoveries = reference_catalog(replace(snapshot, routes=candidates), rows, report["routes"])
    comparison = compare_physical_schema(snapshot, rows)
    summary = dict(Counter(row["ReferenceValidationState"] for row in catalog))
    continuation = (f"xdr schema init --skip-refresh --lookback {shlex.quote(lookback)}"
                    f" --samples {samples} --row-limit {row_limit} --max-queries {max_queries}")
    context = {"reference_digest": snapshot.digest, "reference_routes": len(catalog),
               "validation_states": summary, "queries": report["queries"],
               "reused": report["reused"], "pending": report["pending"],
               "stopped": report["stopped"], "plan_only": plan_only,
               "new_table_discovery": {
                   "candidate_routes": len(candidates),
                   "unmapped_tables": len(discovery["unmapped_new_tables"]),
                   "candidate_route_cap_reached": discovery["candidate_route_cap_reached"],
                   "next_command": "xdr schema collect --explore"
                   if discovery["unmapped_new_tables"] else None,
               },
               "new_tables_count": len(cache.get("coverage", {}).get("new_tables", [])),
               "new_tables_preview": cache.get("coverage", {}).get("new_tables", [])[:20],
               "schema_comparison": {
                   "tables": len(comparison),
                   "tenant_observed": sum(row["TenantObserved"] for row in comparison),
                   "tenant_only": sum(not row["ReferenceKnown"] for row in comparison),
                   "type_disagreements": sum(len(row["TypeDisagreements"]) for row in comparison),
               },
               "next_command": continuation if report["pending"]
               else "xdr schema pivot DeviceInfo.DeviceId"}
    emit_result(write_result(
        [*catalog, *discoveries, *comparison], command="schema init",
        tenant_id=ctx.config.tenant_id,
        extra_metadata={"reference_initialization": context,
                        "new_tables": cache.get("coverage", {}).get("new_tables", []),
                        "new_table_discovery": discovery},
        receipt_context=context,
    ))
    if not plan_only and (report["pending"] or refresh_failure or any(
        count for state, count in summary.items() if state in {"query-failed", "invalid-shape"}
    )):
        raise PartialSuccessError(
            "Schema initialization saved its results with incomplete validation.",
            help_command=continuation,
            retry_after_seconds=(report["stopped"] or {}).get("retry_after_seconds"),
            original={"validation": context, "refresh_failure": refresh_failure},
        )
