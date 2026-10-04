"""Backend-independent hunting result and response normalization."""
from dataclasses import dataclass, field


@dataclass
class HuntingResult:
    """Result from an advanced hunting query."""

    schema: list[dict]
    results: list[dict]
    stats: dict
    metadata: dict = field(default_factory=dict)


def _strip_odata(obj):
    """Recursively drop ``@odata.type`` keys from any nested dict / list.

    Graph's runHuntingQuery emits ``@odata.type`` annotations not just on
    top-level row columns but also inside ``dynamic`` column values (e.g.
    a row's ``ListHealth`` is a nested object whose fields each carry an
    ``@odata.type`` sibling for int64 hints). The original strip only
    visited top-level row keys; nested annotations leaked through into
    JSON output. Walk the structure so the envelope is uniformly clean.
    """
    if isinstance(obj, dict):
        return {
            k: _strip_odata(v)
            for k, v in obj.items()
            if not k.endswith("@odata.type")
        }
    if isinstance(obj, list):
        return [_strip_odata(item) for item in obj]
    return obj


def _normalize_response(response: dict) -> HuntingResult:
    """Normalise the two endpoint shapes into one ``HuntingResult``.

    Differences flattened here:

    * **Casing.** Graph returns lowercase keys (``schema`` / ``results`` /
      ``stats``); MDE returns PascalCase (``Schema`` / ``Results`` /
      ``Stats``). Schema entries' inner keys are lowercased so callers see
      ``{name, type}`` regardless of source.
    * **OData annotations.** Graph emits ``<Field>@odata.type: "#Int64"``
      next to int64 columns — the OData convention for hinting precision
      that JSON's single ``number`` type can't carry. They are pure
      protocol noise for our consumers (the precision info is already in
      ``schema``), and they double the column count for AI agents reading
      rows. Stripped recursively from each row so nested ``dynamic``
      columns (e.g. ``ListHealth``) are also clean.
    * **Stats availability.** Neither endpoint reliably returns execution
      time / CPU usage in the documented response — Graph's
      ``runHuntingQuery`` documents only ``schema`` + ``results``. We
      preserve whatever ``stats`` does come back, but consumers should not
      depend on any specific keys being present (use wall-clock timing for
      execution duration instead).
    """
    schema_raw = response.get("schema", response.get("Schema", []))
    schema = [{k.lower(): v for k, v in col.items()} for col in schema_raw]
    raw_results = response.get("results", response.get("Results", []))
    results = [_strip_odata(row) for row in raw_results]
    return HuntingResult(
        schema=schema,
        results=results,
        stats=response.get("stats", response.get("Stats", {})),
    )
