"""Windows event-log collection over Live Response: selection, paths and the manifest.

The collector lists the fixed event-log folder once, then fetches each selected
``.evtx`` with an ordinary ``getfile``. Listing entries are basenames; each is
validated and anchored beneath the fixed folder, so a listing can never steer a
fetch elsewhere. The manifest is a provenance record written after every step:
it binds the collection to its tenant, backend, session and device and keeps
each accepted command ID, so any job left incomplete can be followed by ID
instead of being resubmitted.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from xdr_cli.exceptions import APIError, ArtifactError, UsageError
from xdr_cli.secret_files import atomic_write_secret

LOGS_DIR = "C:\\Windows\\System32\\winevt\\Logs"
MANIFEST = "manifest.json"

# Curated triage set (file stems; '%4' is the on-disk spelling of '/').
DEFAULT_LOGS = (
    "Security", "System", "Application", "Windows PowerShell",
    "Microsoft-Windows-PowerShell%4Operational",
    "Microsoft-Windows-Sysmon%4Operational",
    "Microsoft-Windows-TaskScheduler%4Operational",
    "Microsoft-Windows-Windows Defender%4Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational",
    "Microsoft-Windows-WMI-Activity%4Operational",
    "Microsoft-Windows-WinRM%4Operational",
    "Microsoft-Windows-Bits-Client%4Operational",
    "Microsoft-Windows-NTLM%4Operational",
    "Microsoft-Windows-CodeIntegrity%4Operational",
)

# Channel names use letters, digits, spaces and a few punctuation marks only.
_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _%()+,.-]{0,250}\.evtx", re.IGNORECASE)

# Row states. Only "completed" means the file is saved locally.
PLANNED = "planned"
OUTCOME_UNKNOWN = "outcome-unknown"  # the submission may or may not have reached the service
ACCEPTED = "accepted"                # follow its command ID; never resubmit
COMPLETED = "completed"
FAILED = "failed"
ABSENT = "absent"
SKIPPED_MIN_BYTES = "skipped-min-bytes"
SKIPPED_MAX_BYTES = "skipped-max-bytes"
NOT_ATTEMPTED = (PLANNED,)
DELIBERATE = frozenset({COMPLETED, ABSENT, SKIPPED_MIN_BYTES, SKIPPED_MAX_BYTES})


def canonical_stem(name: str) -> str:
    """Accept 'Security', 'Security.evtx' or 'Microsoft-Windows-X/Operational'."""
    stem = name.strip()
    if stem.lower().endswith(".evtx"):
        stem = stem[:-5]
    stem = stem.replace("/", "%4")
    if not stem or not _BASENAME.fullmatch(stem + ".evtx"):
        raise UsageError("--log must name an event log, e.g. Security or "
                         "Microsoft-Windows-PowerShell/Operational.",
                         invalid={"kind": "invalid_log_name"})
    return stem


def remote_path(basename: str) -> str:
    """Anchor a validated listing basename beneath the fixed event-log folder."""
    if not _BASENAME.fullmatch(basename) or ".." in basename:
        raise APIError("Event-log listing contained an unexpected file name; nothing was fetched.")
    return f"{LOGS_DIR}\\{basename}"


def parse_listing(rows: list[dict]) -> dict[str, int]:
    """Map each listed ``.evtx`` basename to its size; fail closed on any surprise."""
    entries = [entry for row in rows if isinstance(row, dict)
               for entry in (row.get("data") if isinstance(row.get("data"), list) else [])]
    if not entries:
        raise APIError("Event-log listing returned no parseable entries; nothing was fetched.")
    listed: dict[str, int] = {}
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise APIError("Event-log listing has an unexpected shape; nothing was fetched.")
        name, size, is_dir = entry.get("path"), entry.get("size"), entry.get("isDirectory")
        if not isinstance(name, str) or type(is_dir) is not bool:
            raise APIError("Event-log listing has an unexpected shape; nothing was fetched.")
        if is_dir or not name.lower().endswith(".evtx"):
            continue
        if type(size) is not int or size < 0:
            raise APIError("Event-log listing has an invalid file size; nothing was fetched.")
        remote_path(name)
        if name.lower() in seen:
            raise APIError("Event-log listing repeats a file name; nothing was fetched.")
        seen.add(name.lower())
        listed[name] = size
    return listed


@dataclass
class LogRow:
    log: str
    remote_path: str | None
    listed_bytes: int | None
    status: str = PLANNED
    command_id: str | None = None
    state: str | None = None
    error_count: int | None = None
    bytes: int | None = None
    sha256: str | None = None
    local_file: str | None = None
    error: str | None = None
    # Exact read-only commands that follow an accepted job; never a resubmission.
    recovery: list[str] | None = None


def select(listed: dict[str, int], *, logs: tuple[str, ...], include_all: bool,
           min_bytes: int, max_bytes: int) -> list[LogRow]:
    """Rows for every requested log, including ones absent or skipped by a size filter."""
    by_stem = {name[:-5].lower(): name for name in listed}
    rows: list[LogRow] = []
    if include_all:
        wanted = sorted(listed, key=str.lower)
    else:
        wanted = []
        for stem in logs:
            name = by_stem.get(stem.lower())
            if name is None:
                rows.append(LogRow(stem, None, None, status=ABSENT))
            elif name not in wanted:
                wanted.append(name)
    for name in wanted:
        size = listed[name]
        row = LogRow(name[:-5], remote_path(name), size, local_file=name)
        if size < min_bytes:
            row.status, row.error = SKIPPED_MIN_BYTES, "listed size below --min-bytes"
        elif size > max_bytes:
            row.status, row.error = SKIPPED_MAX_BYTES, "listed size above --max-bytes"
        rows.append(row)
    return rows


@dataclass
class Manifest:
    """Private provenance record: names, sizes, IDs and hashes, never content."""

    path: Path
    tenant_fingerprint: str
    backend: str
    session_id: str
    session_alias: str | None
    machine_id: str
    session_opened_here: bool
    rows: list[LogRow] = field(default_factory=list)
    version: int = 1

    def save(self) -> None:
        document = {key: value for key, value in asdict(self).items() if key != "path"}
        try:
            atomic_write_secret(self.path, json.dumps(document, indent=1))
        except OSError:
            raise ArtifactError("Could not save the event-log collection manifest.") from None
