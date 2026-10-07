"""Normalize nested investigation API objects into grep-friendly JSONL rows."""

from __future__ import annotations

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
