"""Recover physical field origins from a deliberately bounded KQL grammar.

This parser never executes KQL. Unsupported table operators invalidate lineage;
unsupported scalar expressions invalidate only their output columns. Quoted
strings and comments are tokenized before splitting pipelines or assignments.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from xdr_cli.schema_graph.model import FieldLocator

_TOKEN = re.compile(
    r"\s+|//[^\n]*|/\*[\s\S]*?\*/|"
    r"""@"(?:""|[^"])*"|@'(?:''|[^'])*'|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|"""
    r"[A-Za-z_][A-Za-z_0-9-]*|\d+(?:\.\d+)?|[^\s]"
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


class UnsupportedLineage(ValueError):
    """A query cannot be attributed by this parser version."""


def _tokens(query: str) -> list[str]:
    if len(query) > 262144:
        raise UnsupportedLineage("query-complexity-limit")
    tokens = []
    position = 0
    while position < len(query):
        match = _TOKEN.match(query, position)
        if match is None:
            raise UnsupportedLineage("unsupported-token")
        token = match.group()
        # Never fall back to punctuation for an unterminated literal/comment.
        # Multiline backtick strings are outside this parser's supported grammar.
        if token in {'"', "'", "@", "`"} or (
            query.startswith("/*", position) and not token.endswith("*/")
        ):
            raise UnsupportedLineage("unsupported-literal-or-comment")
        if not token.isspace() and not token.startswith(("//", "/*")):
            tokens.append(token)
        position = match.end()
    return tokens


def _split(tokens: list[str], separator: str) -> list[list[str]]:
    chunks: list[list[str]] = [[]]
    stack: list[str] = []
    closes = {"(": ")", "[": "]", "{": "}"}
    for token in tokens:
        if token == separator and not stack:
            chunks.append([])
            continue
        if token in closes:
            stack.append(closes[token])
            if len(stack) > 64:
                raise UnsupportedLineage("expression-complexity-limit")
        elif token in closes.values() and (not stack or stack.pop() != token):
            raise UnsupportedLineage("unbalanced-expression")
        chunks[-1].append(token)
    if stack:
        raise UnsupportedLineage("unbalanced-expression")
    return chunks


def _string(token: str) -> str:
    if token.startswith('@"'):
        return token[2:-1].replace('""', '"')
    if token.startswith("@'"):
        return token[2:-1].replace("''", "'")
    try:
        value = ast.literal_eval(token)
    except (SyntaxError, ValueError) as exc:
        raise UnsupportedLineage("unsupported-quoted-name") from exc
    if not isinstance(value, str):
        raise UnsupportedLineage("unsupported-quoted-name")
    return value


def _name(tokens: list[str]) -> str | None:
    if len(tokens) == 1 and _IDENT.fullmatch(tokens[0]):
        return tokens[0]
    if len(tokens) == 3 and tokens[0] == "[" and tokens[2] == "]":
        return _string(tokens[1])
    return None


@dataclass(frozen=True)
class _ExpressionOrigin:
    locator: FieldLocator
    root_decoded: bool = False
    stringified: bool = False

    @property
    def reproducible(self) -> FieldLocator | None:
        # A root JSON scalar can lose its quoting when decoded. The probe
        # decodes only nested locators, so scalar root outputs are excluded.
        if self.root_decoded and not self.locator.json_path:
            return None
        return self.locator


@dataclass(frozen=True)
class FieldOrigins:
    table: str
    columns: dict[str, FieldLocator | None]
    passthrough: bool = True
    expressions: dict[str, _ExpressionOrigin] = field(default_factory=dict, repr=False)

    def origin(self, column: str) -> FieldLocator | None:
        if column in self.columns:
            return self.columns[column]
        if self.passthrough and _IDENT.fullmatch(column):
            return FieldLocator(self.table, column)
        return None

    def expression(self, column: str) -> _ExpressionOrigin | None:
        # Preserve decoded dynamic aliases for later property access without
        # exposing the alias itself as a reproducible scalar origin.
        if column in self.expressions:
            return self.expressions[column]
        locator = self.origin(column)
        return _ExpressionOrigin(locator) if locator is not None else None

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "table": self.table,
            "passthrough": self.passthrough,
            "columns": {k: str(v) if v else None for k, v in self.columns.items()},
        }


def _expression(tokens: list[str], origins: FieldOrigins) -> _ExpressionOrigin | None:
    direct = _name(tokens)
    if direct is not None:
        return origins.expression(direct)
    if not tokens:
        return None
    # Track casts and decoding until property access establishes a locator the
    # probe's single root parse_json(tostring(Column)) can reproduce.
    start = 1
    if tokens[0] in {"tostring", "parse_json", "todynamic"} and tokens[1:2] == ["("]:
        depth = 1
        end = 2
        while end < len(tokens) and depth:
            depth += (tokens[end] == "(") - (tokens[end] == ")")
            end += 1
        if depth:
            return None
        base = _expression(tokens[2 : end - 1], origins)
        if base is None:
            return None
        if tokens[0] == "tostring":
            base = _ExpressionOrigin(base.locator, base.root_decoded, True)
        else:
            if base.stringified and (base.root_decoded or base.locator.json_path):
                # Decoding a stringified decoded root or nested leaf can add
                # another JSON layer that a FieldLocator cannot represent.
                return None
            base = _ExpressionOrigin(base.locator, True)
        start = end
    elif tokens[0] == "[" and len(tokens) >= 3 and tokens[2] == "]":
        base = origins.expression(_string(tokens[1]))
        start = 3
    else:
        base = origins.expression(tokens[0]) if _IDENT.fullmatch(tokens[0]) else None
    if base is None:
        return None
    if start < len(tokens) and base.stringified:
        return None
    path = list(base.locator.json_path)
    while start < len(tokens):
        if tokens[start] == "." and start + 1 < len(tokens) and _IDENT.fullmatch(tokens[start + 1]):
            path.append(tokens[start + 1])
            start += 2
        elif start + 2 < len(tokens) and tokens[start] == "[" and tokens[start + 2] == "]":
            if not tokens[start + 1].startswith(('"', "'", '@"', "@'")):
                return None
            path.append(_string(tokens[start + 1]))
            start += 3
        else:
            return None
    return _ExpressionOrigin(
        FieldLocator(base.locator.table, base.locator.column, tuple(path)),
        base.root_decoded,
        base.stringified,
    )


def recover_field_origins(query: str) -> FieldOrigins:
    """Attribute one-table projections/aliases and direct summary grouping keys.

    Scalar let bindings may be used by filters. Tabular let bindings, unions,
    joins, expansion, invocation and aggregate outputs remain unsupported.
    """
    statements = [part for part in _split(_tokens(query), ";") if part]
    if not statements:
        raise UnsupportedLineage("empty-query")
    bindings: set[str] = set()
    for statement in statements[:-1]:
        if len(statement) < 4 or statement[0] != "let" or statement[2] != "=":
            raise UnsupportedLineage("unsupported-statement")
        # Restrict scalar bindings to literals and scalar constructors; this
        # prevents a let binding from shadowing a physical table or column.
        rhs = statement[3:]
        if len(_split(rhs, "|")) != 1 or not (
            rhs[0].startswith(('"', "'", '@"', "@'"))
            or rhs[0] in {"datetime", "timespan", "dynamic", "ago", "now"}
            or rhs[0][0].isdigit()
        ):
            raise UnsupportedLineage("unsupported-let-binding")
        bindings.add(statement[1])
    pipeline = _split(statements[-1], "|")
    table = _name(pipeline[0])
    if table is None or table in bindings:
        raise UnsupportedLineage("unsupported-table-source")
    origins = FieldOrigins(table, {name: None for name in bindings})
    for part in pipeline[1:]:
        if not part:
            raise UnsupportedLineage("empty-operator")
        op, body = part[0], part[1:]
        if op in {"where", "take", "limit", "top", "sort", "order", "sample"}:
            continue
        if op in {"project", "extend", "project-rename"}:
            columns = dict(origins.columns) if op != "project" else {}
            expressions = dict(origins.expressions) if op != "project" else {}
            written: set[str] = set()
            for expression in _split(body, ","):
                assignment = _split(expression, "=")
                output = _name(assignment[0])
                if output is None or len(assignment) > 2:
                    raise UnsupportedLineage("unsupported-projection")
                rhs = assignment[-1]
                expression_origins = FieldOrigins(
                    table, {**origins.columns, **dict.fromkeys(written)}, origins.passthrough,
                    {name: value for name, value in origins.expressions.items()
                     if name not in written},
                )
                value = _expression(rhs, expression_origins)
                columns[output] = value.reproducible if value is not None else None
                expressions.pop(output, None)
                if value is not None:
                    expressions[output] = value
                written.add(output)
                if op == "project-rename":
                    old = _name(rhs)
                    if old is None or len(assignment) != 2:
                        raise UnsupportedLineage("unsupported-rename")
                    columns[old] = None
                    expressions.pop(old, None)
            origins = FieldOrigins(
                table, columns, origins.passthrough and op != "project", expressions
            )
        elif op == "project-away":
            columns = dict(origins.columns)
            expressions = dict(origins.expressions)
            for expression in _split(body, ","):
                name = _name(expression)
                if name is None:
                    raise UnsupportedLineage("unsupported-project-away")
                columns[name] = None
                expressions.pop(name, None)
            origins = FieldOrigins(table, columns, origins.passthrough, expressions)
        elif op in {"summarize", "distinct"}:
            groups = _split(body, "by") if op == "summarize" else [[], body]
            if len(groups) != 2:
                raise UnsupportedLineage("summary-without-direct-grouping")
            columns = {}
            expressions = {}
            for expression in _split(groups[1], ","):
                assignment = _split(expression, "=")
                name = _name(assignment[0])
                if name is not None and len(assignment) <= 2:
                    value = _expression(assignment[-1], origins)
                    columns[name] = value.reproducible if value is not None else None
                    if value is not None:
                        expressions[name] = value
            origins = FieldOrigins(table, columns, False, expressions)
        else:
            raise UnsupportedLineage(
                f"unsupported-operator:{op}" if _IDENT.fullmatch(op) else "unsupported-operator"
            )
    return origins
