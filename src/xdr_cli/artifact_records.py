"""Normalize nested investigation API objects into grep-friendly JSONL rows."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def _record(record_type: str, value: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Return one flat-enough typed row while preserving the API payload fields."""

    return {**value, **context, "record_type": record_type}


def alert_records(
    alert: dict[str, Any],
    *,
    incident_id: str | int | None = None,
) -> list[dict[str, Any]]:
    """Split an alert and its evidence into independently searchable rows."""

    summary = dict(alert)
    evidence = summary.pop("evidence", None)
    alert_id = summary.get("id")
    parent_incident = incident_id if incident_id is not None else summary.get("incidentId")
    rows = [
        _record(
            "alert",
            summary,
            parent_incident_id=parent_incident,
            parent_alert_id=alert_id,
        )
    ]
    if isinstance(evidence, list):
        for index, item in enumerate(evidence):
            value = item if isinstance(item, dict) else {"value": item}
            rows.append(
                _record(
                    "evidence",
                    value,
                    parent_incident_id=parent_incident,
                    parent_alert_id=alert_id,
                    evidence_index=index,
                )
            )
    return rows


def incident_records(incident: dict[str, Any]) -> list[dict[str, Any]]:
    """Split an expanded incident into incident, alert, and evidence rows."""

    summary = dict(incident)
    alerts = summary.pop("alerts", None)
    incident_id = summary.get("id")
    rows = [_record("incident", summary, parent_incident_id=incident_id)]
    if isinstance(alerts, list):
        for alert in alerts:
            if isinstance(alert, dict):
                rows.extend(alert_records(alert, incident_id=incident_id))
            else:
                rows.append(
                    _record(
                        "alert",
                        {"value": alert},
                        parent_incident_id=incident_id,
                    )
                )
    return rows


def investigation_records(
    incident: dict[str, Any],
    entities: dict[str, Any],
    enrichment: dict[str, list[dict[str, Any]]],
    recommended_actions: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Yield granular rows for a complete guided-investigation bundle."""

    yield from incident_records(incident)

    device_ids = entities.get("device_ids", {})
    for entity_type, values in entities.items():
        if entity_type == "device_ids" and isinstance(values, dict):
            for device_name, device_id in sorted(values.items()):
                yield _record(
                    "entity",
                    {
                        "entity_type": "device_id",
                        "device_name": device_name,
                        "value": device_id,
                    },
                )
            continue
        if isinstance(values, dict):
            for key, value in sorted(values.items()):
                yield _record(
                    "entity",
                    {"entity_type": entity_type, "name": key, "value": value},
                )
            continue
        iterable = values if isinstance(values, (list, set, tuple)) else [values]
        for value in sorted(iterable, key=str):
            payload = value if isinstance(value, dict) else {"value": value}
            yield _record("entity", payload, entity_type=entity_type)

    for query_name, rows in enrichment.items():
        for index, row in enumerate(rows):
            value = row if isinstance(row, dict) else {"value": row}
            yield _record(
                "enrichment",
                value,
                query_name=query_name,
                result_index=index,
            )

    for action_group in ("investigate_first", "contain"):
        actions = recommended_actions.get(action_group, [])
        if isinstance(actions, list):
            for index, action in enumerate(actions):
                value = action if isinstance(action, dict) else {"value": action}
                yield _record(
                    "recommended_action",
                    value,
                    action_group=action_group,
                    action_index=index,
                )

    yield _record(
        "recommendation_summary",
        {
            "containment_gated": recommended_actions.get("containment_gated"),
            "gating_reason": recommended_actions.get("gating_reason"),
            "ms_recommended_actions": recommended_actions.get(
                "ms_recommended_actions"
            ),
            "device_id_count": len(device_ids) if isinstance(device_ids, dict) else 0,
        },
    )
