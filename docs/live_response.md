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
xdr --backend portal-cookie device live-response connect <machine-id> --wait 120 --yes
xdr device live-response show <session-id>
xdr device live-response sessions [--device <machine-id>]
xdr device live-response disconnect <session-id> --yes
```

`connect` takes the 40-hex MachineId (`xdr device show HOST` prints it).
`--wait` polls while the session is `pending`. The record it prints includes
`next_command` and `disconnect_command`. The service limits a device to one
session and a user to five, and ends idle sessions after 30 minutes.

`sessions` lists sessions this CLI opened for the current tenant and backend
(`context.coverage: "locally-known-sessions"`). It is not a tenant-wide
session inventory.

## Console commands

```bash
xdr device live-response exec <session-id> --command 'processes -name notepad.exe'
xdr device live-response exec <session-id> --command-file cmd.txt --wait 60
echo 'dir C:\Users\Public -output json' | xdr device live-response exec <session-id> --command-stdin
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

### Risk classes and confirmation

Every command is classified locally after alias resolution. The server never
supplies the class:

| Class | Commands | Confirmation |
|---|---|---|
| `read` | cd, connections, dir, drivers, fileinfo, findfile, persistence, processes, registry, scheduledtasks, services, startupfolders, `remediate list` | no |
| `collect` | getfile, analyze, collect, processdump | yes |
| `place` | putfile | yes |
| `execute` | run, remediate, undo | yes |
| `device-action` | isolate, release, scan (macOS/Linux console) | yes |
| `library-write` | library upload, library delete | yes |

Confirmation-class commands prompt, or need `--yes` when non-interactive.
`--dry-run` validates against the pinned catalog and prints the verb, class and
parameter names without authentication or network activity. Commands that a
session's definitions do not offer, and server commands without a pinned class,
are refused.

### Shortcuts

```bash
xdr device live-response findfile <session-id> invoice.pdf.exe --wait 120
xdr device live-response fileinfo <session-id> 'C:\Temp\a.exe'
xdr device live-response dir <session-id> 'C:\Users\Public' --full-path
xdr device live-response getfile <session-id> 'C:\Temp\a.exe' --output a.bin --yes
xdr device live-response putfile <session-id> collect.ps1 --overwrite --yes
xdr device live-response run <session-id> collect.ps1 --parameters-file args.txt --yes
```

Shortcuts build the same console command and go through the same validation
and confirmation. `getfile --output` waits (`--wait`, default 300 seconds) and
downloads only after the command reports `completed` with no errors. A
completed command can still carry errors (for example `fileinfo` on an empty
placeholder file); records show the count as `error_count`. Otherwise it
leaves the command running and you use `download` later. `run` reads script parameters
only from `--parameters-file` or `--parameters-stdin`, so they stay out of
argv. The service forbids `; & | ! $` in script parameters.

## Command jobs

```bash
xdr device live-response status <session-id> <command-id> --wait 60
xdr device live-response history <session-id>
xdr device live-response output <session-id> <command-id>
xdr device live-response download <session-id> <command-id> --output sample.bin
xdr device live-response cancel <session-id> <command-id> --yes
```

`status` reports the native state and polls with `--wait` while the state is
non-terminal. `history` (the console's command log and jobs) and `output` save
private artifacts. `download` streams a completed command's file privately and
atomically, and reports its size and SHA-256. It never opens or extracts the
file, and treats downloaded content as hostile. `cancel` cancels in the portal
only. The device may still finish the command (`device_outcome: "unknown"`).

`output` prints a receipt with zero preview rows so script transcripts and
potentially large command output stay in the private artifact. Follow the
receipt's results command or inspect its JSONL locally to read the content.

A submission that times out or loses its connection is **not** retried. The
error carries a recovery command. Check `history` before resubmitting.

## Library

```bash
xdr device live-response library list
xdr device live-response library show collect.ps1
xdr device live-response library upload --from-file ./collect.ps1 --description 'IR collection' --yes
xdr device live-response library download collect.ps1 --output collect.ps1.copy
xdr device live-response library delete collect.ps1 --yes
```

Library names allow letters, digits, `_`, `.`, `-` and inner spaces. Uploading
from the portal console requires the **Manage Security Settings** permission.
`--parameters-description` marks a script as taking parameters, and
`--overwrite` replaces a file with the same name.

## Official batch actions

```bash
xdr --backend official device live-response batch submit <machine-id> \
    --command-file batch.txt --comment 'IR-42' --yes
xdr device live-response batch status <action-id> --wait 120
xdr device live-response batch output <action-id>
xdr device live-response batch download <action-id> --index 2 --output result.zip
xdr device live-response batch cancel <action-id> --yes
```

`batch.txt` holds one command per line, in the order putfile, run, getfile.
Other console commands are rejected locally.

## Privacy and audit

Every remote Live Response command is written to `~/.xdr-cli/audit.log` at
dispatch, including `--dry-run`. For these commands, the recorded argv keeps
only MachineIds, session and command IDs, numbers, option names and fixed
words. Console text, paths, comments, script parameters and local file names
are replaced with `***REDACTED***` in both the audit log and the session log.
Each submission also records one `LR:` line with the session or MachineId,
verb, class and parameter names. Signed download URLs and raw service payloads
are never printed.

## Coverage

[Live Response coverage](live_response_coverage.md) records, for each GUI
operation, which CLI command covers it and whether it has been validated
synthetically, against a development tenant, or only from source.
