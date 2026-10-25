# Live Response

`xdr device live-response` drives Microsoft Defender for Endpoint Live
Response from the CLI. You can open a session on a device, inspect it, search
for files, fetch files, place library files on it, run library scripts, follow
command jobs and manage the tenant file library.

Interactive sessions use the portal's Live Response service and need the
**portal-cookie** backend (`--backend portal-cookie`, or a stored cookie with
no official credentials). The official API offers only one-shot machine
actions limited to PutFile, RunScript and GetFile. Those are available as
`batch` on the **official** backend. Neither backend falls back to the other.

Availability still depends on the tenant (Live Response must be enabled in
Advanced features), your RBAC role (basic or advanced commands), and the
device's OS and sensor version. The command set a session accepts comes from
that session's own server definitions.

## Sessions

```bash
xdr --backend portal-cookie device live-response connect <machine-id> --wait 120
xdr device live-response show lr-1
xdr device live-response sessions [list] [--device <machine-id>] [--all]
xdr device live-response sessions refresh [--device <machine-id>]
xdr device live-response disconnect lr-1
```

`connect` takes the 40-hex MachineId (`xdr device show HOST` prints it).
`--wait` polls while the session is `pending`. The record it prints includes
the session's `alias`, its native `session_id`, `next_command` and
`disconnect_command`. The service limits a device to one session and a user
to five, and ends idle sessions after 30 minutes.

### Session aliases

Each session this CLI opens or remembers gets a short alias: `lr-1`, `lr-2`,
and so on. Use the alias anywhere a session is expected; the native `CLR…`
ID still works too. Aliases are resolved locally and only the native ID is
sent to the service. An alias is bound to one tenant, backend, session and
device, and is never reused, even after the session ends. An unknown alias is
an error; it never opens a new session. Sessions remembered from earlier
versions get aliases the first time they are listed, without any request.
Recovery and follow-up commands in CLI output use the alias.

### Remembered sessions

`sessions` (or `sessions list`) shows the sessions this CLI remembers for the
current tenant, from local state only: no authentication or network. It shows
active sessions by default; `--all` adds those remembered as closed, failed or
not found. Each row has the alias, native IDs, the last seen `state`, an
`activity` of `active`, `inactive` or `unknown` (for native states the CLI
cannot map), and `last_verified_at`. The receipt says
`context.coverage: "locally-known-sessions"` and `verification: "cached"`. It
is not a tenant-wide inventory, which the service does not offer.

`sessions refresh` looks up each remembered active or unknown session once and
updates the local state. It never closes, reconnects or retries anything.
Rows report `previous_state`, the current `state` and `verification`:

- `remote`: looked up; `state` is current.
- `not-found`: the service no longer knows the session; it is remembered as
  `not-found` from now on.
- `error`: the lookup failed; the remembered state is unchanged and
  `refresh_error` names the error code.
- `not-checked`: not looked up, because an earlier sign-in, permission,
  throttling, timeout or network failure stopped the refresh.

A failed lookup never marks a session closed. Any `error` or `not-checked`
row returns exit 14 after the receipt (with `retry_after_seconds` when the
service set one). If the very first lookup fails that way, the error is
returned directly with no receipt. `--all` applies to `list` only.

## Console commands

```bash
xdr device live-response exec lr-1 --command 'processes -name notepad.exe'
xdr device live-response exec lr-1 --command-file cmd.txt --wait 60
echo 'dir C:\Users\Public -output json' | xdr device live-response exec lr-1 --command-stdin
```

Each submission is **one** console command. A trailing `&` requests the
service's background mode. A final `> FILE` saves the command's rendered output
to a private local file (0600, never replaces an existing file without
`--force`) once the command completes without reported errors. `FILE` is not
sent to the device.
`;`, `|`, `&&`, `||`, `<`, backticks and newlines outside double quotes are
rejected before anything is sent. Inside double quotes, text is literal, and
backslashes are never escape characters, so Windows paths and registry keys
pass unchanged.

Aliases, parameter names (`-param_id value` or the server's display name) and
flags (`-flag`, short or long form) follow the session's definitions.
`xdr device live-response catalog [--os windows|macos|linux] [--risk CLASS]`
lists the pinned catalog locally, without authentication.

`help`, `cls`, `trace`, `jobs`, `fg`, `status`, `connect` and `library` are
console behaviours, so they are not sent. `help COMMAND` is answered from the
catalog. For the others, the error names the CLI equivalent (`history`,
`status --wait`, `library ...`).

### Risk classes

Every command is classified locally after command-name alias resolution. The
server never supplies the class:

| Class | Commands | Changes or takes from the device |
|---|---|---|
| `read` | cd, connections, dir, drivers, fileinfo, findfile, persistence, processes, registry, scheduledtasks, services, startupfolders, `remediate list` | no |
| `collect` | getfile, analyze, collect, processdump | data leaves the device |
| `place` | putfile | yes |
| `execute` | run, remediate, undo | yes |
| `device-action` | isolate, release, scan (macOS/Linux console) | yes |
| `library-write` | library upload, library delete | tenant library |

There is no confirmation prompt and no `--yes`: running the command is the
intent. Everything beyond `read` is still classified, recorded in the audit
log, and refused when the backend preference in `config.toml` is invalid and
no explicit `--backend` was given. Command files and stdin are read as UTF-8, and a leading byte-order mark is
ignored. `--dry-run` validates against the pinned catalog and prints the verb, class and
parameter names without authentication or network activity. Commands that a
session's definitions do not offer, and server commands without a pinned class,
are refused.

### Shortcuts

```bash
xdr device live-response findfile lr-1 invoice.pdf.exe --wait 120
xdr device live-response fileinfo lr-1 'C:\Temp\a.exe'
xdr device live-response dir lr-1 'C:\Users\Public' --full-path
xdr device live-response getfile lr-1 'C:\Temp\a.exe' --output a.bin
xdr device live-response putfile lr-1 collect.ps1 --overwrite
xdr device live-response run lr-1 collect.ps1 --parameters-file args.txt
```

Shortcuts build the same console command and go through the same validation
and classification. `getfile --output` waits (`--wait`, default 300 seconds) and
downloads only after the command reports `completed` with no errors. A
completed command can still carry errors (for example `fileinfo` on an empty
placeholder file); records show the count as `error_count`. Otherwise it
leaves the command running and you use `download` later. `run` reads script parameters
only from `--parameters-file` or `--parameters-stdin`, so they stay out of
argv. The service forbids `; & | ! $` in script parameters.

## Command jobs

```bash
xdr device live-response status lr-1 <command-id> --wait 60
xdr device live-response history lr-1
xdr device live-response output lr-1 <command-id>
xdr device live-response download lr-1 <command-id> --output sample.bin
xdr device live-response cancel lr-1 <command-id>
```

`status` reports the native state and polls with `--wait` while the state is
non-terminal. `history` (the console's command log and jobs) and `output` save
private artifacts. `download` streams a completed command's file privately and
atomically, and reports its size and SHA-256. It never opens or extracts the
file, and treats downloaded content as hostile. `cancel` cancels in the portal
only. The device may still finish the command (`device_outcome: "unknown"`).

`output` and `batch output` print a receipt with zero preview rows, so script
transcripts, native error text and potentially large command output stay in
the private artifact. Follow the receipt's results command, or inspect its
JSONL locally, to read the content.

A submission that times out or loses its connection is **not** retried. The
error carries a recovery command. Check `history` before resubmitting.

Once the service has accepted a command, session or batch action, a failure in
a later step (polling with `--wait`, saving `> FILE`, or the `getfile
--output` download) keeps its own exit code but is reported with
`retryable: false`. The message names the accepted ID. `help_command` and the
first suggestion (`reason: "submission_accepted"`) give the read-only status,
output or download commands that follow the existing job. Do not resubmit: the
job is already running or finished on the device.

`getfile --output` emits one result: command state plus the transfer receipt
when downloaded, or `downloaded: false` with `download_skipped_reason` when
the job is pending, failed, or completed with errors. A download failure
emits only its error record and points to the existing command's status; it
never reports an intermediate download success. `--upload-only` and
`--output` cannot be combined.

If local directory upkeep fails on a status read, the native result stays
readable and reports `directory_tracking: "unavailable"`. Use absolute
paths until the local directory state can be updated.

Downloads and `> FILE` saves publish with a hard link so they never replace a
file that appears concurrently. File systems without hard links (FAT32, exFAT,
some network shares) therefore need `--force`, or a destination on a file
system that supports them.

## Event-log collection

```bash
xdr --backend portal-cookie device live-response collect-event-logs <machine-id> --output-dir ./ir-42-logs
xdr device live-response collect-event-logs lr-1 --output-dir ./ir-42-ps --log Security --log Microsoft-Windows-PowerShell/Operational
xdr device live-response collect-event-logs lr-1 --output-dir ./ir-42-all --all
```

`collect-event-logs` fetches Windows event logs (`.evtx`) in one command. It
lists `C:\Windows\System32\winevt\Logs` once, then runs an ordinary `getfile`
for each selected log. Logs that Windows holds open download normally. This is
a forensic collection of event logs. It is **not** Defender's support-log
package (`device collect-support-logs`), which holds sensor diagnostics.

- **Target:** an `lr-N` alias or session ID reuses that session and leaves it
  open. A MachineId opens a session, collects, and makes one attempt to close
  that session afterwards, also after a failure, Ctrl-C or an unexpected error.
  The original error always wins. The session counts as closed
  (`context.session_closed: true`) only when the service reports it inactive.
  Otherwise closure is unconfirmed: do **not** repeat the close; inspect the
  session with the `show` command in `context.cleanup_recovery_command` (or
  the error's `owned_session_not_closed` suggestion). Windows sessions only.
- **Selection:** by default a curated triage set: Security, System,
  Application, Windows PowerShell, PowerShell/Operational, Sysmon, Task
  Scheduler, Defender, Terminal Services (local session and remote connection
  managers), WMI-Activity, WinRM, BITS, NTLM and CodeIntegrity. Logs the device
  doesn't have are listed as `absent`. `--log NAME` (repeatable) picks specific
  logs; `/` in a channel name is accepted. `--all` takes every `.evtx` in the
  folder, typically about 180 on Windows 11.
- **`--min-bytes`** skips logs listed below a size and reports them as
  `skipped-min-bytes`. It is only a size filter. Channel files are
  pre-allocated, so a 68 KiB (69,632-byte) file can still contain events (a
  4 KiB header plus a 64 KiB chunk of records; see the
  [EVTX format notes](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc)).
  The default is 0, so nothing is skipped.
- **Limits:** `--max-bytes` skips any log listed above it (`skipped-max-bytes`)
  and caps each download. `--max-total-bytes` (default 4 GiB) limits the bytes
  saved locally. The selection's listed sizes are checked before any
  `getfile`. Because logs keep growing after the listing, each download is also
  capped at the budget that remains after the files already saved. A download
  that would exceed it is abandoned and the run stops
  (`context.stopped: "total-budget-exhausted"`). This bounds what is saved,
  not the exact network traffic of an abandoned transfer. Each `getfile` is a
  separate job, typically 15–30 s.
- **Output:** `--output-dir` must be new or empty and private (0700), because
  event logs, Security especially, are sensitive. Each log is saved under its
  on-disk name with its SHA-256, never replaces an existing file, and is never
  opened. Each file is a copy of a live log taken at the moment it was
  fetched, not an atomic snapshot of all logs together.
- **Manifest:** `manifest.json` records the tenant fingerprint, backend,
  session, alias, MachineId and whether this command opened the session, then
  each log's name, listed size, status, command ID, bytes and hash, never
  content. It is rewritten after every step. The receipt rows are the manifest
  rows.

Nothing is ever resubmitted. A `getfile` the service accepted keeps its
command ID. If it hasn't finished, or its download failed, its row is
`accepted` with exact `recovery` commands (`status` and `download` by that ID)
to follow it in its session. Any failure while downloading a completed job's
file stops the run, so one bad transfer never repeats across many logs; a
job that merely fails on the device does not stop it. A submission whose
outcome is unknown (for example a timeout while sending) is
`outcome-unknown`; check `history` before fetching that log again. A session
this command opened is closed at the end, so follow incomplete jobs promptly,
or collect through a session you opened yourself (`lr-N`) when you expect to
follow up. Sign-in, permission,
throttling, timeout, network, configuration and local manifest failures stop
the run. Anything not collected returns exit 14 after the receipt.

`--dry-run` shows the plan (target kind, folder, selection and limits) without
authentication, network or writing anything. The listing and every `getfile`
are recorded in the audit log with the native session and device IDs.

## Library

```bash
xdr device live-response library list
xdr device live-response library show collect.ps1
xdr device live-response library upload --from-file ./collect.ps1 --description 'IR collection'
xdr device live-response library download collect.ps1 --output collect.ps1.copy
xdr device live-response library delete collect.ps1
```

Library names allow letters, digits, `_`, `.`, `-` and inner spaces. Uploading
from the portal console requires the **Manage Security Settings** permission.
`--parameters-description` marks a script as taking parameters, and
`--overwrite` replaces a file with the same name.

## Official batch actions

The official batch path has been run live for GetFile; PutFile, RunScript and
cancel are tested with synthetic responses only. See
[the coverage matrix](live_response_coverage.md).

```bash
xdr --backend official device live-response batch submit <machine-id> \
    --command-file batch.txt --comment 'IR-42'
xdr --backend official device live-response batch status <action-id> --wait 120
xdr --backend official device live-response batch output <action-id>
xdr --backend official device live-response batch download <action-id> --index 2 --output result.zip
xdr --backend official device live-response batch cancel <action-id>
```

`batch.txt` holds one command per line, in the order putfile, run, getfile.
Other console commands are rejected locally.

The official service delivers GetFile results gzip-compressed. Downloads are
saved byte-for-byte and never decompressed; the receipt reports `kind: "gzip"`
when the saved bytes are gzip and `"raw"` otherwise. `--output` must be in a
directory only you can write to (or a sticky one such as `/tmp`).

## Privacy and audit

Every remote Live Response command is written to `~/.xdr-cli/audit.log` at
dispatch, including `--dry-run`. For these commands, the recorded argv keeps
only MachineIds, session IDs and `lr-N` aliases, command IDs, numbers, option
names and fixed words. Console text, paths, comments, script parameters and local file names
are replaced with `***REDACTED***` in both the audit log and the session log.
Each submission also records one `LR:` line with the session or MachineId,
verb, class and parameter names. Signed download URLs and raw service payloads
are never printed.

## Coverage

[Live Response coverage](live_response_coverage.md) records, for each GUI
operation, which CLI command covers it and whether it has been validated
synthetically, against a development tenant, or only from source.
