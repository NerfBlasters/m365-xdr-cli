"""Value-free semantic hints from private result metadata sidecars."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from xdr_cli.json_expansion import JSON_STRING_COLUMNS
from xdr_cli.schema_graph.model import FieldLocator, GraphValidationError

# JSON object keys are not necessarily schema: Microsoft payloads also use
# tenant domains, hostnames, user names, IDs, and arbitrary resource names as
# dictionary keys. Passive learning is therefore fail-closed. Additions to
# this set are code-reviewed schema changes; arbitrary observed keys never
# become supposedly value-free graph data.
_REVIEWED_PASSIVE_SEGMENTS = frozenset(
    {
        "Actors",
        "ClientIP",
        "ConsentContext",
        "CountryCode",
        "DetectionMethods",
        "ExtendedProperties",
        "ForwardingSMTPAddress",
        "Id",
        "ModifiedProperties",
        "ObjectId",
        "Parameters",
        "ResourceData",
        "Role",
        "ScriptContent",
        "Signals",
        "TargetResources",
        "TargetUserOrGroupName",
        "Targets",
        "User",
        "User.Id",
        "UserId",
        "Value",
        "displayName",
        "id",
        "key",
        "name",
        "type",
        "userPrincipalName",
        "value",
    }
)


@dataclass(frozen=True, slots=True)
class ArtifactShapeField:
    locator: FieldLocator
    observed_types: tuple[str, ...]
    present_count: int
    non_null_count: int
    lineage: str


def _segments_from_tokens(tokens: object) -> tuple[str, ...]:
    if not isinstance(tokens, list) or not tokens:
        raise GraphValidationError("artifact shape path_tokens must be a non-empty list")
    segments: list[str] = []
    for token in tokens:
        if not isinstance(token, dict):
            raise GraphValidationError("artifact shape path token must be an object")
        kind = token.get("kind")
        if kind == "array" and set(token) == {"kind"}:
            segments.append("*")
        elif kind == "property" and isinstance(token.get("value"), str):
            segments.append(token["value"])
        else:
            raise GraphValidationError("artifact shape path token is invalid")
    return tuple(segments)


def _safe_passive_segment(segment: str) -> bool:
    """Accept only reviewed Microsoft payload property names and wildcards."""

    return segment == "*" or segment in _REVIEWED_PASSIVE_SEGMENTS


def _safe_passive_path(segments: tuple[str, ...]) -> bool:
    """Return whether shape keys are schema-like rather than possible values.

    JSON object keys are not inherently metadata: tenant values, tokens, or
    opaque identifiers can appear as keys. Passive ingestion therefore accepts
    only explicitly reviewed property names plus the array wildcard. Explicit
    reviewed graph records may still use the full JSON Pointer grammar.
    """

    return bool(segments) and all(_safe_passive_segment(segment) for segment in segments)


def passive_locator_is_reviewed(locator: FieldLocator) -> bool:
    """Return whether a nested locator satisfies today's passive-key policy.

    This public compatibility hook deliberately exposes only a boolean.  Upgrade
    and status workflows can therefore quarantine legacy arbitrary object keys
    without rendering those potentially tenant-controlled keys to stdout.
    """

    return bool(locator.json_path) and _safe_passive_path(locator.json_path)


def _legacy_segments(path: object) -> tuple[str, ...]:
    """Best-effort compatibility parser; dotted v1 paths are inherently ambiguous."""

    if not isinstance(path, str) or not path:
        raise GraphValidationError("artifact shape path is invalid")
    segments: list[str] = []
    for dotted in path.split("."):
        if not dotted:
            raise GraphValidationError("artifact shape path has an empty segment")
        array_depth = 0
        while dotted.endswith("[]"):
            dotted = dotted[:-2]
            array_depth += 1
        if dotted:
            segments.append(dotted)
        segments.extend("*" for _ in range(array_depth))
    return tuple(segments)


def nested_fields_from_artifact_metadata(
    table: str,
    metadata: dict[str, Any],
) -> tuple[ArtifactShapeField, ...]:
    """Convert only known expanded JSON columns into value-free graph locators.

    The caller remains responsible for table lineage. Arbitrary projected
    columns are ignored, and no query text, parameters, or leaf values enter
    the returned records.
    """

    shape = metadata.get("observed_shape")
    if not isinstance(shape, list):
        raise GraphValidationError("artifact metadata observed_shape must be a list")
    discovered: list[ArtifactShapeField] = []
    for entry in shape:
        if not isinstance(entry, dict):
            raise GraphValidationError("artifact observed_shape entries must be objects")
        if "path_tokens" in entry:
            segments = _segments_from_tokens(entry["path_tokens"])
            lineage = "physical-shape"
        else:
            segments = _legacy_segments(entry.get("path"))
            lineage = "legacy-shape-ambiguous"
        if len(segments) < 2 or segments[0] not in JSON_STRING_COLUMNS:
            continue
        if not _safe_passive_path(segments[1:]):
            continue
        types = entry.get("types", [])
        present = entry.get("present_count", 0)
        non_null = entry.get("non_null_count", 0)
        if (
            not isinstance(types, list)
            or any(not isinstance(item, str) for item in types)
            or not isinstance(present, int)
            or not isinstance(non_null, int)
            or present < 0
            or non_null < 0
            or non_null > present
        ):
            raise GraphValidationError("artifact observed_shape counts/types are invalid")
        locator = FieldLocator(table=table, column=segments[0], json_path=segments[1:])
        if len(f"field:{locator}") > 1024:
            continue
        discovered.append(
            ArtifactShapeField(
                locator=locator,
                observed_types=tuple(sorted(set(types))),
                present_count=present,
                non_null_count=non_null,
                lineage=lineage,
            )
        )
    return tuple(sorted(discovered, key=lambda item: str(item.locator)))
