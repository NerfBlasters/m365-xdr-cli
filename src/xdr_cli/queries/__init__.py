"""KQL query library: load, list, and parameterize built-in and user queries."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.resources
import json
import re
from dataclasses import dataclass, field

from xdr_cli.config import get_config_home
from xdr_cli.exceptions import QueryError


@dataclass
class QueryParam:
    name: str
    # str | None — None means "no declared default; required at load_query time".
    # "" means "declared empty default" (the scope-param idiom — empty string
    # bypasses the `'{x}' == ''` guard). "<value>" means "declared default".
    # The three-state distinction lets load_query distinguish missing-default
    # from declared-empty when applying _strip_inline_list_defaults / mode='' coercion.
    default: str | None = None
    value_type: str = "string"
    value_format: str | None = None
    allowed: tuple[str, ...] = ()


@dataclass
class QueryInfo:
    name: str
    description: str
    params: list[QueryParam] = field(default_factory=list)
    source: str = "builtin"  # "builtin" or "user"
    raw_kql: str = ""
    lists: list[str] = field(default_factory=list)
    tier: str = ""                       # r1 | r2 | r3 | n | beta | pivot | utility | deprecated
    alias_of: str | None = None          # set on `-- tier: deprecated` shims
    agent_hint: str = ""                 # multi-line block; opt-out flags read by methodology test


def query_source_hash(name: str) -> str | None:
    """SHA-256 of one catalog entry's unrendered KQL source."""

    for query in list_queries():
        if query.name == name:
            return hashlib.sha256(query.raw_kql.encode("utf-8")).hexdigest()
    return None


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Parse '-- key: value' front-matter from a .kql file.

    Multi-line values use a 2+-space-indent continuation convention:

        -- agent_hint: first line of the hint
        --   second line continues
        --   third line still continues
        -- next_key: ...

    Continuation lines (those starting `--` + 2+ whitespace chars) are
    appended to the prior key's value, separated by a single newline.
    """
    meta: dict = {}
    lines = text.strip().splitlines()
    kql_lines: list[str] = []
    in_frontmatter = True
    last_key: str | None = None

    for line in lines:
        if not in_frontmatter:
            kql_lines.append(line)
            continue

        if not line.startswith("--"):
            in_frontmatter = False
            kql_lines.append(line)
            last_key = None
            continue

        # Strip leading `--` and inspect what follows. `-- key: value` has
        # exactly one space after `--`; continuation lines have 2+ spaces.
        rest = line[2:]
        is_continuation = rest.startswith("  ") and last_key is not None

        if is_continuation:
            meta[last_key] = (meta[last_key] + "\n" + rest.strip()).strip()
            continue

        # Normal key line: `-- key: value`. Tolerate a missing colon
        # (treat as a tagged comment — empty value).
        body = rest.strip()
        if ":" in body:
            key, _, value = body.partition(":")
            key = key.strip()
            meta[key] = value.strip()
            last_key = key
        else:
            last_key = None  # bare comment line; resets continuation context

    return meta, "\n".join(kql_lines).strip()


_VALID_TIERS = {"r1", "r2", "r3", "n", "beta", "pivot", "utility", "deprecated"}


def _parameter_contract(name: str) -> tuple[str, str | None, tuple[str, ...]]:
    """Return the catalog-wide type contract for a conventional parameter."""

    if name == "mode":
        return "enum", None, ("summary", "detail")
    if name in {"hours", "threshold"}:
        return "integer", "positive integer", ()
    if name in {"start", "end"}:
        return "datetime", "ISO-8601 date or timestamp", ()
    if name == "lookback":
        return "duration", "KQL duration such as 30m, 6h, or 7d", ()
    if name == "sha256":
        return "string", "64-character SHA-256 hex", ()
    if name in {"ip", "source_ip"}:
        return "string", "IPv4 or IPv6 address", ()
    if name in {"account_upn", "actor_upn", "target_upn", "sender"}:
        return "string", "user principal name or email address", ()
    if name == "device_name" or name == "target_device":
        return "string", "Defender DeviceName hostname", ()
    if name.endswith("_id") or name.endswith("_oid"):
        return "string", "tenant identifier", ()
    if name == "remote":
        return "string", "IP address or DNS name", ()
    return "string", None, ()


_PARAM_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_DURATION_LITERAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:ms|s|m|h|d|w)$")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")


def _valid_iso_datetime(value: str) -> bool:
    """Return whether ``value`` is one ISO date or timestamp literal."""

    if not value or value != value.strip():
        return False
    try:
        if "T" in value or "t" in value or " " in value:
            dt.datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
        else:
            dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _validate_parameter_value(param: QueryParam, value: str) -> None:
    """Validate the non-contextual part of one library parameter contract."""

    valid = True
    if param.allowed:
        valid = value in param.allowed
    elif param.value_type == "integer":
        valid = bool(_POSITIVE_INTEGER.fullmatch(value))
    elif param.value_type == "datetime":
        valid = _valid_iso_datetime(value)
    elif param.value_type == "duration":
        valid = bool(_DURATION_LITERAL.fullmatch(value))
    elif param.value_type == "string":
        valid = _PARAM_CONTROL_CHARS.search(value) is None
    if valid:
        return
    expected = (
        f"one of {', '.join(param.allowed)}"
        if param.allowed
        else param.value_format or param.value_type
    )
    raise QueryError(
        f"Invalid value for parameter '{param.name}': expected {expected}.",
        invalid={"kind": "library_parameter", "value": {param.name: value}},
    )


def _escape_kql_literal_content(value: str, quote: str) -> str:
    """Escape content for an ordinary single- or double-quoted KQL literal."""

    escaped = value.replace("\\", "\\\\")
    return escaped.replace(quote, f"\\{quote}")


def _render_parameters(
    kql: str, parameters: dict[str, tuple[QueryParam, str]]
) -> str:
    """Render typed placeholders in one pass without changing KQL syntax."""

    for param, value in parameters.values():
        _validate_parameter_value(param, value)
    placeholders = {
        f"{{{name}}}": (param, value)
        for name, (param, value) in parameters.items()
    }
    ordered_placeholders = sorted(placeholders, key=len, reverse=True)

    def match_at(position: int) -> tuple[str, QueryParam, str] | None:
        for candidate in ordered_placeholders:
            if kql.startswith(candidate, position):
                param, value = placeholders[candidate]
                return candidate, param, value
        return None

    output: list[str] = []
    quote: str | None = None
    verbatim = False
    multiline = False
    comment: str | None = None
    index = 0
    replaced = {name: 0 for name in parameters}
    while index < len(kql):
        if comment == "line":
            char = kql[index]
            output.append(char)
            index += 1
            if char == "\n":
                comment = None
            continue
        if comment == "block":
            if kql.startswith("*/", index):
                output.append("*/")
                index += 2
                comment = None
            else:
                output.append(kql[index])
                index += 1
            continue
        if multiline:
            if kql.startswith("```", index):
                output.append("```")
                index += 3
                multiline = False
            elif (matched := match_at(index)) is not None:
                _placeholder, param, _value = matched
                raise QueryError(
                    f"Parameter '{param.name}' must not appear inside a multiline "
                    "KQL string literal."
                )
            else:
                output.append(kql[index])
                index += 1
            continue
        if quote is None and kql.startswith("//", index):
            output.append("//")
            index += 2
            comment = "line"
            continue
        if quote is None and kql.startswith("/*", index):
            output.append("/*")
            index += 2
            comment = "block"
            continue
        if quote is None and kql.startswith("```", index):
            output.append("```")
            index += 3
            multiline = True
            continue
        matched = match_at(index)
        if matched is not None:
            placeholder, param, value = matched
            string_value = param.value_type in {"string", "enum"}
            if string_value and quote is None:
                raise QueryError(
                    f"String parameter '{param.name}' must appear inside a quoted "
                    "KQL string literal."
                )
            if not string_value and quote is not None:
                raise QueryError(
                    f"Typed parameter '{param.name}' must not appear inside a KQL "
                    "string literal."
                )
            if quote is not None and verbatim:
                raise QueryError(
                    f"Parameter '{param.name}' must appear inside an ordinary quoted "
                    "KQL string literal, not a verbatim literal."
                )
            output.append(
                _escape_kql_literal_content(value, quote) if quote is not None else value
            )
            index += len(placeholder)
            replaced[param.name] += 1
            continue

        char = kql[index]
        output.append(char)
        if quote is not None and not verbatim and char == "\\" and index + 1 < len(kql):
            index += 1
            output.append(kql[index])
        elif quote is not None and char == quote and kql[index + 1 : index + 2] == quote:
            # KQL also accepts doubled enclosing quotes inside a regular
            # literal. Keep both characters without ending the literal.
            index += 1
            output.append(kql[index])
        elif char in {"'", '"'}:
            if quote == char:
                quote = None
                verbatim = False
            elif quote is None:
                quote = char
                verbatim = index > 0 and kql[index - 1] == "@"
        index += 1

    for placeholder, (param, _value) in placeholders.items():
        if placeholder in kql and replaced[param.name] == 0:
            raise QueryError(f"Parameter '{param.name}' was not substituted.")
    return "".join(output)


def _substitute_parameter(kql: str, param: QueryParam, value: str) -> str:
    """Compatibility wrapper for rendering one typed library parameter."""

    return _render_parameters(kql, {param.name: (param, value)})


def _build_query_info(name: str, text: str, source: str) -> QueryInfo:
    meta, kql = parse_frontmatter(text)

    # Param parsing: distinguish "no `=`" (None — required) from "`=` with empty
    # value" ("" — declared empty default) from "`=value`" ("value" — declared).
    params_str = meta.get("params", "")
    params: list[QueryParam] = []
    for p in params_str.split(","):
        p = p.strip()
        if not p:
            continue
        if "=" in p:
            pname, default = p.split("=", 1)
            pname = pname.strip()
            value_type, value_format, allowed = _parameter_contract(pname)
            params.append(
                QueryParam(
                    name=pname,
                    default=default.strip(),
                    value_type=value_type,
                    value_format=value_format,
                    allowed=allowed,
                )
            )
        else:
            value_type, value_format, allowed = _parameter_contract(p)
            params.append(
                QueryParam(
                    name=p,
                    default=None,
                    value_type=value_type,
                    value_format=value_format,
                    allowed=allowed,
                )
            )

    lists = [n.strip() for n in meta.get("lists", "").split(",") if n.strip()]

    tier = meta.get("tier", "").strip()
    alias_of = meta.get("alias_of", "").strip() or None
    agent_hint = meta.get("agent_hint", "")  # parse_frontmatter joins continuation lines

    # Required-tier validation. Every .kql file must declare `-- tier:`;
    # the methodology test reads q.tier as the single source of truth for
    # FINDING_TIERS / SCHEMA_TIERS / pivot exemption (replacing the
    # prefix-based heuristic that mis-classified
    # qry_post_compromise_activity, qry_email_outbound_spike,
    # qry_spn_activity as pivots).
    if not tier:
        raise QueryError(
            f"{name}.kql is missing required '-- tier:' frontmatter "
            f"(expected one of {sorted(_VALID_TIERS)})."
        )
    if tier not in _VALID_TIERS:
        raise QueryError(
            f"{name}.kql declares unknown tier '{tier}' "
            f"(expected one of {sorted(_VALID_TIERS)})."
        )
    # Deprecated-alias shims must declare `-- alias_of: <target>`.
    if tier == "deprecated" and not alias_of:
        raise QueryError(
            f"{name}.kql declares '-- tier: deprecated' but no '-- alias_of:' "
            f"target. Deprecated shims must name the live query they forward to."
        )

    return QueryInfo(
        name=name,
        description=meta.get("description", ""),
        params=params,
        source=source,
        raw_kql=kql,
        lists=lists,
        tier=tier,
        alias_of=alias_of,
        agent_hint=agent_hint,
    )


# Hard caps on a list-file's footprint. A poisoned upstream feed must not
# become KQL injection, an OOM, or a parse error. Values must escape `"` and
# `\` before quoting; lines exceeding the per-line cap or containing control
# characters / newlines are rejected with a stderr warning and skipped (the
# rest of the file still loads).
_LIST_VALUE_MAX_BYTES = 512
_LIST_FILE_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB total
_LIST_VALUE_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _kql_escape(value: str) -> str:
    """Escape a list-file value for safe interpolation into ``dynamic([...])``."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _known_list_blocks() -> set[str]:
    """The set of known list-block names — sourced from lists_seed/ enumeration.

    Used by :func:`_resolve_lists` to reject typos in ``-- lists:`` declarations
    and by :mod:`tests.test_queries_methodology` to validate every query
    references a real block.
    """
    blocks: set[str] = set()
    try:
        for entry in importlib.resources.files("xdr_cli.lists_seed").iterdir():
            name = entry.name
            if name.endswith(".txt"):
                blocks.add(name[: -len(".txt")])
    except (ModuleNotFoundError, FileNotFoundError):
        pass
    return blocks


# `w` (week) accepted in addition to `s`/`m`/`h`/`d` — operators write `1w`
# / `2w` for monthly / fortnightly TTLs and the original `^(\d+)([smhd])$`
# pattern silently returned None on those (treating the file as never-stale).
_TTL_PATTERN = re.compile(r"^(\d+)([smhdw])$")
_TTL_UNITS = {
    "s": lambda n: dt.timedelta(seconds=n),
    "m": lambda n: dt.timedelta(minutes=n),
    "h": lambda n: dt.timedelta(hours=n),
    "d": lambda n: dt.timedelta(days=n),
    "w": lambda n: dt.timedelta(weeks=n),
}


def _parse_ttl(s: str) -> dt.timedelta | None:
    """Parse `<N>{s|m|h|d|w}` TTL strings to a timedelta.

    Returns None for empty/malformed input — callers treat that as "never stale"
    (advisory feature, fail-open).
    """
    m = _TTL_PATTERN.match(s.strip()) if s else None
    if not m:
        return None
    return _TTL_UNITS[m.group(2)](int(m.group(1)))


def _is_stale(meta: dict[str, str]) -> bool:
    """Return True if ``fetched + ttl < now`` (UTC). Missing/malformed → False."""
    fetched_s, ttl_s = meta.get("fetched"), meta.get("ttl")
    if not fetched_s or not ttl_s:
        return False
    try:
        fetched = dt.datetime.fromisoformat(fetched_s.replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=dt.UTC)
    except ValueError:
        return False
    ttl = _parse_ttl(ttl_s)
    if ttl is None:
        return False
    return dt.datetime.now(dt.UTC) > fetched + ttl


def _resolve_lists(names: list[str]) -> tuple[str, dict]:
    """Synthesise ``let _xdr_<Name> = dynamic([...]);`` blocks for the given names.

    Reads ``<config_home>/lists/<Name>.txt`` for each declared name. Non-comment,
    non-empty lines become string-literal entries (escaped via
    :func:`_kql_escape`). Returns a tuple ``(rendered_block, list_health)`` where
    ``list_health`` is the per-block health summary surfaced in summary rows
    via ``_xdr_ListHealth``.

    Safety:
    * Each value is escaped (``\\`` → ``\\\\``, ``"`` → ``\\"``) before quoting.
    * Values containing control characters or newlines are rejected.
    * Per-value byte cap (``_LIST_VALUE_MAX_BYTES``); over-cap values are skipped.
    * Per-file byte cap (``_LIST_FILE_MAX_BYTES``); over-cap files are treated
      as empty (fail-safe) with a stderr warning.
    * Block names not in the known set (``_known_list_blocks()``) are loaded
      empty with a typo warning naming the closest known name.

    All warnings route through :data:`xdr_cli.output.err_console`.

    .. TODO: wire quiet-flag suppression once the quiet-flag forwarding
       mechanism is threaded through the loader call chain.
    """
    if not names:
        return "", {}

    from xdr_cli.output import err_console

    known = _known_list_blocks()
    lists_dir = get_config_home() / "lists"
    out_lets: list[str] = []
    health: dict = {}

    for n in names:
        # Validate block-name against known set; typo → empty fallback.
        # Only enforce when the seed module is present (skipped in tests
        # before Phase 2 ships lists_seed/).
        if known and n not in known:
            err_console.print(
                f"[yellow]warning:[/yellow] unknown list block '{n}' (not a "
                f"seeded block name); loading empty. Known: {sorted(known)}"
            )
            out_lets.append(f"let _xdr_{n} = dynamic([]);")
            health[f"_xdr_{n}"] = {
                "value_count": 0,
                "is_empty": True,
                "is_stale": False,
                "fetched": None,
                "ttl_hours": None,
                "source": None,
            }
            continue

        path = lists_dir / f"{n}.txt"
        values: list[str] = []
        meta: dict = {}

        if path.exists():
            try:
                stat = path.stat()
                if stat.st_size > _LIST_FILE_MAX_BYTES:
                    err_console.print(
                        f"[yellow]warning:[/yellow] list file {path} exceeds "
                        f"{_LIST_FILE_MAX_BYTES} bytes; treating as empty (fail-safe)."
                    )
                else:
                    for raw in path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines():
                        stripped = raw.strip()
                        if not stripped:
                            continue
                        if stripped.startswith("#"):
                            # Header parse: `# fetched: <iso>`, `# ttl: 720h`, `# source: ...`
                            if ":" in stripped:
                                k, _, v = stripped[1:].partition(":")
                                meta[k.strip()] = v.strip()
                            continue
                        if len(stripped.encode("utf-8")) > _LIST_VALUE_MAX_BYTES:
                            err_console.print(
                                f"[yellow]warning:[/yellow] list value in {path} "
                                f"exceeds {_LIST_VALUE_MAX_BYTES} bytes; skipping."
                            )
                            continue
                        if _LIST_VALUE_BAD_CHARS.search(stripped):
                            err_console.print(
                                f"[yellow]warning:[/yellow] list value in {path} "
                                f"contains control characters; skipping."
                            )
                            continue
                        values.append(stripped)
            except OSError as exc:
                err_console.print(
                    f"[yellow]warning:[/yellow] reading {path} failed ({exc}); "
                    f"treating as empty (fail-safe)."
                )

        is_empty = len(values) == 0
        is_stale = _is_stale(meta)
        rendered = ", ".join(f'"{_kql_escape(v)}"' for v in values)
        out_lets.append(f"let _xdr_{n} = dynamic([{rendered}]);")
        health[f"_xdr_{n}"] = {
            "value_count": len(values),
            "is_empty":    is_empty,
            "is_stale":    is_stale,
            "fetched":     meta.get("fetched"),
            "ttl_hours":   meta.get("ttl"),
            "source":      meta.get("source"),
        }
        if is_stale:
            err_console.print(
                f"[yellow]warning:[/yellow] list {n}.txt is stale "
                f"(fetched {meta.get('fetched')} + ttl {meta.get('ttl')} < now)"
            )

    # Synthesise the _xdr_ListHealth declaration consumed by every summary row.
    # Escape single-quotes via KQL doubling — a source URL like "O'Reilly"
    # inside a single-quoted KQL literal requires ' → '' to remain well-formed.
    health_json = json.dumps(health).replace("'", "''")
    out_lets.append(f"let _xdr_ListHealth = parse_json('{health_json}');")
    return "\n".join(out_lets) + "\n", health


# Match `let _xdr_<Name> = dynamic([<anything>]);` regardless of array contents.
# A naive regex matching only literal `dynamic([])` (empty) misses author-written
# placeholders like `dynamic([""])` and misses duplicate declarations of the same
# block (the `count=1` cap also masks duplicates). Use a non-greedy `[^)]*` to
# match any contents inside the array.
def _strip_inline_list_defaults(body: str, names: list[str]) -> str:
    """Remove inline ``let _xdr_<Name> = dynamic([...]);`` lines from a body.

    Matches any placeholder whose array content does not contain a literal
    ``)`` character (the regex uses ``[^)]*`` inside the ``dynamic(...)``
    group). An authored placeholder of ``dynamic([""])`` (some Defender-portal
    authors use this to keep the inline form syntactically valid) is therefore
    stripped. ``count=1`` is intentionally NOT used — duplicate declarations
    would shadow the loader's prepended block and must all be removed.
    """
    out = body
    for n in names:
        pattern = re.compile(
            r"^[ \t]*let[ \t]+_xdr_" + re.escape(n)
            + r"[ \t]*=[ \t]*dynamic\([^)]*\)[ \t]*;[ \t]*\n?",
            re.MULTILINE,
        )
        out = pattern.sub("", out)
    return out


def list_queries() -> list[QueryInfo]:
    """List all available queries (builtin + user).

    A malformed .kql (missing/invalid frontmatter) is skipped with a stderr
    warning rather than raising — a single bad file from a stale install or
    a hand-edited user query must not brick the entire library command. The
    methodology test (test_queries_methodology) is the strict gate for shipped
    builtins; this runtime path is fail-open by design.
    """
    from xdr_cli.output import err_console

    queries: dict[str, QueryInfo] = {}

    # Load built-in queries
    pkg = importlib.resources.files("xdr_cli.queries")
    for item in pkg.iterdir():
        if hasattr(item, "name") and item.name.endswith(".kql"):
            name = item.name.removesuffix(".kql")
            try:
                text = item.read_text(encoding="utf-8")
                queries[name] = _build_query_info(name, text, "builtin")
            except QueryError as exc:
                err_console.print(
                    f"[yellow]warning:[/yellow] skipping builtin query "
                    f"{item.name}: {exc}"
                )

    # Load user queries (override builtins)
    user_dir = get_config_home() / "queries"
    if user_dir.exists():
        for path in user_dir.glob("*.kql"):
            name = path.stem
            try:
                text = path.read_text(encoding="utf-8")
                queries[name] = _build_query_info(name, text, "user")
            except QueryError as exc:
                err_console.print(
                    f"[yellow]warning:[/yellow] skipping user query "
                    f"{path.name}: {exc}"
                )

    return sorted(queries.values(), key=lambda q: q.name)


def load_query(name: str, **params: str) -> str:
    """Load a query by name and substitute parameters.

    Raises ``QueryError`` if ``name`` is unknown or if ``params`` contains
    a key that is not in the resolved query's declared params (a typo in
    ``--param accont_upn=...`` must not silently turn a scoped hunt into a
    tenant-wide sweep).
    """
    from xdr_cli.output import err_console

    queries = list_queries()
    by_name = {q.name: q for q in queries}

    if name not in by_name:
        raise QueryError(
            f"Query '{name}' not found. "
            "Run 'xdr hunt library' to see available queries."
        )
    q = by_name[name]

    # Deprecated-alias resolution: a `-- tier: deprecated` shim transparently
    # forwards to its alias_of target with a one-release stderr deprecation
    # warning. The shim's own body is ignored — the target's body is loaded
    # and substituted. This keeps `xdr hunt library-run qry_inbox_rule_audit`
    # working for one release after the merge into qry_inbox_rule_activity.
    if q.tier == "deprecated" and q.alias_of:
        target = by_name.get(q.alias_of)
        if target is None:
            raise QueryError(
                f"Deprecated alias '{name}' points at missing target "
                f"'{q.alias_of}'."
            )
        err_console.print(
            f"[yellow]warning:[/yellow] '{name}' is a deprecated alias for "
            f"'{q.alias_of}'; will be removed in a future release."
        )
        q = target

    # Unknown-param rejection. A typo'd --param accont_upn=alice@x.com would
    # otherwise be silently dropped, leaving account_upn='' and turning a
    # scoped hunt into a tenant-wide sweep.
    declared = {p.name for p in q.params}
    unknown = [k for k in params if k not in declared]
    if unknown:
        raise QueryError(
            f"Unknown param(s) {sorted(unknown)} for query '{q.name}'. "
            f"Known params: {sorted(declared)}"
        )

    kql = q.raw_kql

    # Apply defaults for missing params. p.default is None means "required".
    for p in q.params:
        if p.name not in params:
            if p.default is None:
                raise QueryError(
                    f"Missing required parameter '{p.name}' for query '{q.name}'."
                )
            params[p.name] = p.default

    # Empty-string-to-default coercion. An explicit `--param mode=` (empty
    # string) substituted into the body produces zero rows from the union
    # `(SummaryRow | where '{mode}' == 'summary'), (DetailRows | where '{mode}'
    # == 'detail')` because neither '' == 'summary' nor '' == 'detail' is
    # true. The loader coerces an empty resolved value to the declared default
    # WHEN the declared default is itself non-empty — this preserves the
    # scope-param idiom (account_upn=, session_id=, etc.) where an empty
    # resolved value is the intended "match all" semantics.
    for p in q.params:
        if p.default and params.get(p.name, "") == "":
            params[p.name] = p.default

    # Strip inline list-default placeholders, then prepend resolved blocks.
    # _resolve_lists returns (rendered_kql_block, list_health); the health
    # dict is also surfaced in summary rows via _xdr_ListHealth but is
    # discarded here — load_query only returns substituted KQL.
    if q.lists:
        kql = _strip_inline_list_defaults(kql, q.lists)
        resolved_kql, _list_health = _resolve_lists(q.lists)
        kql = resolved_kql + kql
    elif "_xdr_ListHealth" in kql:
        # Methodology contract: every finding-tier summary row carries
        # `extend ListHealth = _xdr_ListHealth`. Queries that consume no
        # tenant lists still need the symbol declared so the KQL parses;
        # otherwise the API rejects the request with a 400 (e.g.
        # qry_email_outbound_spike, qry_post_compromise_activity,
        # ttp_oauth_consent_anomaly). Synthesise an empty health record.
        kql = "let _xdr_ListHealth = parse_json('{}');\n" + kql

    # Substitute declared placeholders using their catalog-wide type and KQL
    # literal context. Raw text replacement is unsafe here: entity values come
    # from tenant evidence and may contain quotes or operator characters.
    by_param_name = {param.name: param for param in q.params}
    kql = _render_parameters(
        kql,
        {
            key: (by_param_name[key], value)
            for key, value in params.items()
        },
    )

    return kql
