"""Native, queryable KQL library discovery and execution."""

from __future__ import annotations

import asyncio
import difflib
import ipaddress
import json
import re

import typer

from xdr_cli.commands.hunt_cmd import _hunt_run
from xdr_cli.context import AppContext
from xdr_cli.exceptions import QueryError, UsageError
from xdr_cli.kql_parse import extract_tables
from xdr_cli.queries import list_queries, load_query
from xdr_cli.results import emit_result, write_result

library_app = typer.Typer(
    name="library",
    help="Discover and run the built-in KQL library.",
    no_args_is_help=True,
)


def _declared_output_fields(kql: str) -> list[str]:
    """Extract conservative projection/alias hints without claiming live schema."""

    fields: set[str] = set()
    collecting_project = False
    for raw_line in kql.splitlines():
        line = raw_line.strip()
        if line.startswith("| project "):
            collecting_project = True
            line = line.removeprefix("| project ")
        elif collecting_project and line.startswith("|"):
            collecting_project = False
        if collecting_project:
            for item in line.rstrip(";").split(","):
                match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", item.strip())
                if match:
                    fields.add(match.group(1))
            if line.endswith(";"):
                collecting_project = False
    for match in re.finditer(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", kql):
        fields.add(match.group(1))
    return sorted(fields)


def _cost_hint(query) -> dict[str, str]:
    cpu = re.search(r"\bcpu_class=(low|medium|high)\b", query.agent_hint)
    volume = re.search(r"\brow_volume=(low|medium|high)\b", query.agent_hint)
    tier_default = {
        "r1": "medium",
        "r2": "medium",
        "r3": "low",
        "pivot": "low",
        "utility": "low",
        "n": "medium",
        "beta": "medium",
        "deprecated": "unknown",
    }
    return {
        "cpu_class": cpu.group(1) if cpu else tier_default.get(query.tier, "unknown"),
        "row_volume": volume.group(1) if volume else "unknown",
        "basis": "frontmatter" if cpu or volume else "tier-default",
    }


def _descriptor(query) -> dict:
    return {
        "name": query.name,
        "description": query.description,
        "tier": query.tier,
        "source": query.source,
        "alias_of": query.alias_of,
        "parameters": [
            {
                "name": param.name,
                "type": param.value_type,
                "format": param.value_format,
                "allowed": list(param.allowed),
                "required": param.default is None,
                "default": param.default,
            }
            for param in query.params
        ],
        "required_permissions": {
            "any_of": [
                {
                    "resource": "Microsoft Graph",
                    "permission": "ThreatHunting.Read.All",
                    "path": "primary",
                },
                {
                    "resource": "WindowsDefenderATP",
                    "permission": "AdvancedQuery.Read.All",
                    "path": "fallback",
                },
            ]
        },
        "schema_hint": {
            "tables": extract_tables(query.raw_kql),
            "declared_output_fields": _declared_output_fields(query.raw_kql),
            "mode_dependent": any(p.name == "mode" for p in query.params),
            "tenant_observed_schema": False,
            "lists": list(query.lists),
            "notes": query.agent_hint or None,
        },
        "cost_hint": _cost_hint(query),
        "examples": [
            f"xdr library run {query.name}"
            + "".join(
                f" --param {p.name}=<value>" for p in query.params if p.default is None
            )
        ],
    }


def _find(name: str):
    queries = list_queries()
    by_name = {query.name: query for query in queries}
    if name in by_name:
        return by_name[name]
    matches = difflib.get_close_matches(name, sorted(by_name), n=5, cutoff=0.45)
    error = QueryError(
        f"Unknown KQL library entry {name!r}.",
        invalid={"kind": "library_entry", "value": name},
        allowed=sorted(by_name),
        suggestions=[
            {
                "reason": "nearest_entry",
                "message": match,
                "confidence": "heuristic",
            }
            for match in matches
        ],
        help_command=f"xdr library list --search {name}",
    )
    error.error_code = "LIBRARY_UNKNOWN_ENTRY"
    raise error


def _parse_params(name: str, values: list[str] | None) -> dict[str, str]:
    query = _find(name)
    allowed = [p.name for p in query.params]
    params: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            error = QueryError(
                f"Invalid parameter {item!r}; expected key=value.",
                invalid={"kind": "library_parameter", "value": item},
                allowed=allowed,
                help_command=f"xdr library show {name}",
            )
            error.error_code = "LIBRARY_UNKNOWN_PARAM"
            raise error
        key, value = item.split("=", 1)
        key = key.strip()
        if key not in allowed:
            error = QueryError(
                f"Unknown parameter {key!r} for {name}.",
                invalid={"kind": "library_parameter", "value": key},
                allowed=allowed,
                help_command=f"xdr library show {name}",
            )
            error.error_code = "LIBRARY_UNKNOWN_PARAM"
            raise error
        params[key] = value.strip()
    missing = [p.name for p in query.params if p.default is None and p.name not in params]
    if missing:
        error = QueryError(
            f"Missing required parameter(s): {', '.join(missing)}.",
            invalid={"kind": "missing_library_parameter", "value": missing},
            allowed=allowed,
            help_command=f"xdr library show {name}",
        )
        error.error_code = "LIBRARY_MISSING_PARAM"
        raise error
    by_name = {p.name: p for p in query.params}
    for key, value in params.items():
        contract = by_name[key]
        invalid_reason: str | None = None
        if contract.allowed and value not in contract.allowed:
            invalid_reason = f"expected one of {', '.join(contract.allowed)}"
        elif contract.value_type == "integer":
            try:
                if int(value) < 1:
                    raise ValueError
            except ValueError:
                invalid_reason = "expected a positive integer"
        elif contract.value_format == "64-character SHA-256 hex" and not re.fullmatch(
            r"[A-Fa-f0-9]{64}", value
        ):
            invalid_reason = "expected exactly 64 hexadecimal characters"
        elif contract.value_format == "IPv4 or IPv6 address":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                invalid_reason = "expected an IPv4 or IPv6 address"
        if invalid_reason:
            error = QueryError(
                f"Invalid value for {key!r}: {invalid_reason}.",
                invalid={"kind": "library_parameter", "value": {key: value}},
                allowed=list(contract.allowed),
                help_command=f"xdr library show {name}",
            )
            error.error_code = "LIBRARY_INVALID_PARAM"
            raise error
    return params


@library_app.command("list")
def library_list(
    ctx: typer.Context,
    search: str | None = typer.Option(None, "--search"),
    tier: str | None = typer.Option(None, "--tier"),
) -> None:
    """List library descriptors without dumping KQL source."""
    catalog = [_descriptor(query) for query in list_queries()]
    rows = list(catalog)
    if search:
        needle = search.casefold()
        rows = [
            row
            for row in rows
            if needle in row["name"].casefold()
            or needle in row["description"].casefold()
        ]
    if tier:
        allowed = sorted({row["tier"] for row in catalog})
        if tier not in allowed:
            raise UsageError(
                f"Unknown tier {tier!r}.",
                invalid={"kind": "tier", "value": tier},
                allowed=allowed,
                help_command="xdr library list --help",
            )
        rows = [row for row in rows if row["tier"] == tier]
    app_ctx: AppContext = ctx.obj
    emit_result(
        write_result(
            rows,
            command=app_ctx.invoked_command or "library list",
            server_truncation_state="known-complete",
            session_id=app_ctx.session_id,
            session_label=app_ctx.session_label,
            session_attachment=app_ctx.session_attachment,
            incident_id=app_ctx.anchor_incident,
            alert_id=app_ctx.anchor_alert,
            anchor_provenance=app_ctx.anchor_provenance,
            extra_metadata={"search": search, "tier": tier},
            tenant_id=app_ctx.config.tenant_id,
        )
    )


@library_app.command("show")
def library_show(
    name: str = typer.Argument(help="Exact library entry name."),
) -> None:
    """Show one typed library descriptor."""
    typer.echo(
        json.dumps(
            {"status": "success", "data": _descriptor(_find(name))},
            separators=(",", ":"),
        )
    )


@library_app.command("run")
def library_run(
    ctx: typer.Context,
    name: str = typer.Argument(help="Exact library entry name."),
    param: list[str] | None = typer.Option(None, "--param", "-p"),
    raw: bool = typer.Option(False, "--raw"),
    timeout: int | None = typer.Option(None, "--timeout"),
) -> None:
    """Run a named KQL query through the artifact-first execution path."""
    app_ctx: AppContext = ctx.obj
    params = _parse_params(name, param)
    kql = load_query(name, **params)
    asyncio.run(
        _hunt_run(
            app_ctx,
            kql,
            raw=raw,
            library_query=name,
            params=params,
            timeout=timeout,
        )
    )
