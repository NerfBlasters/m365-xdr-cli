"""Typed entity sightings for local investigation evidence."""

from xdr_cli.schema_graph.normalize import NormalizationError, normalize_value

# Paths are scoped to the provider evidence type so equal field names elsewhere
# cannot establish an identity.
_EVIDENCE_FIELDS = {
    "userEvidence": (
        ("userAccount.userPrincipalName", "upn", "upn-lower"),
        ("userAccount.azureAdUserId", "entra-user-id", "guid-lower"),
        ("userAccount.userSid", "sid", "text-upper"),
    ),
    "deviceEvidence": (
        ("mdeDeviceId", "device-id", "hex40-lower"),
        ("deviceDnsName", "hostname", "hostname-lower"),
    ),
    "fileEvidence": (
        ("fileDetails.sha1", "sha1", "sha1-lower"),
        ("fileDetails.sha256", "sha256", "sha256-lower"),
    ),
    "ipEvidence": (("ipAddress", "ip", "ip-canonical"),),
    "urlEvidence": (("url", "url", "url-canonical"),),
    "mailMessageEvidence": (
        ("networkMessageId", "network-message-id", "guid-lower"),
        ("recipientEmailAddress", "smtp", "smtp-lower"),
    ),
}
_PHYSICAL_FIELDS = {
    "UrlClickEvents": (
        ("AccountUpn", "upn", "upn-lower"),
        ("IPAddress", "ip", "ip-canonical"),
        ("NetworkMessageId", "network-message-id", "guid-lower"),
    ),
    "DeviceProcessEvents": (
        ("DeviceId", "device-id", "hex40-lower"),
        ("SHA256", "sha256", "sha256-lower"),
    ),
    "DeviceFileEvents": (
        ("DeviceId", "device-id", "hex40-lower"),
        ("SHA256", "sha256", "sha256-lower"),
    ),
}


def index_row(db, meta, row, reference):
    command = meta["command"]
    fields = ()
    if command in {"incidents show", "alerts show"} and row.get("record_type") == "evidence":
        kind = row.get("@odata.type", "")
        if isinstance(kind, str) and kind.startswith("#microsoft.graph.security."):
            fields = _EVIDENCE_FIELDS.get(kind.rsplit(".", 1)[-1], ())
    elif command in {"hunt run", "library run"}:
        lineage = meta.get("physical_lineage", {})
        if lineage.get("kind") == "physical":
            fields = _PHYSICAL_FIELDS.get(lineage["table"], ())
        origins = meta.get("column_lineage") or {}
        if origins.get("version") == 1:
            table = origins["table"]
            known = {f"{table}.{name}": (namespace, normalizer)
                     for name, namespace, normalizer in _PHYSICAL_FIELDS.get(table, ())}
            attributed = []
            for name in row:
                origin = origins["columns"].get(
                    name, f"{table}.{name}" if origins.get("passthrough") else None
                )
                if origin in known:
                    attributed.append((name, *known[origin]))
            fields = attributed
    indexed = 0
    for field, namespace, normalizer in fields:
        value = row
        for component in field.split("."):
            value = value.get(component) if isinstance(value, dict) else None
        try:
            value = normalize_value(normalizer, value)
        except NormalizationError:
            continue
        db.execute(
            "INSERT OR IGNORE INTO sighting(run_id,ref,field,entity,seen) VALUES (?,?,?,?,?)",
            (
                meta["run_id"],
                reference,
                field,
                f"{namespace}:{value}",
                row.get("Timestamp") or row.get("createdDateTime"),
            ),
        )
        indexed += 1
    return indexed
