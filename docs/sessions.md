# Session Mechanics

Sessions are optional local telemetry. They capture invocation history under
`~/.xdr-cli/sessions/<session-id>.jsonl`, but session state never blocks an
investigation or changes its result.

## Automatic attachment

Each live session has a private marker under
`~/.xdr-cli/active_sessions/<session-id>`. Markers record activity time,
timeout, automatic/manual origin, and incident/alert anchors. The default
inactivity timeout is 1,800 seconds (30 minutes).

Resolution order is:

1. a valid explicit `XDR_SESSION`;
2. a matching incident/alert anchor;
3. exactly one unexpired marker;
4. automatic creation for `hunt run`, `library run`,
   `schema observe`, `schema candidate-review`, `investigate`,
   `incidents show`, and `alerts show`;
5. unattached execution when multiple unmatched sessions remain.

Ambiguity is deliberately nonblocking. stderr provides both forms:

```bash
XDR_SESSION=<id> xdr ...
```

```powershell
$env:XDR_SESSION = "<id>"
```

Help, lists, auth, result browsing, and `library list`/`library show` do not
create sessions; of the `schema` commands only `observe` and `candidate-review`
do. Expired markers are retired with `end_reason: "idle-timeout"`; their JSONL
history remains.

## Manual and concurrent sessions

Normal `session start` rotates the selected current session. If multiple
markers exist and `XDR_SESSION` does not explicitly select one, it rotates all
of them before creating one new sequential session. With the official backend,
it requires a cached authenticated account so the session has an operator identity:

```bash
xdr session start --label incident-12345 --timeout 1800
```

`--timeout` is the inactivity timeout in seconds (minimum 1; default 1,800).
`--quiet` is accepted for caller compatibility only: there is no banner to
suppress, and the bare session ID on stdout already suits
`$(xdr session start --quiet)` capture.

With `--backend portal-cookie`, manual start requires locally stored cookies
bound to the configured tenant; it does not check their remote validity. New
manual and automatic cookie-mode sessions use the existing `automatic` identity
placeholder (`aut-...` session IDs). This is not an authenticated operator UPN:
the cookie backend never borrows an account from the official MSAL cache.
Existing session attachment and rotation rules still apply.

Preserve existing sessions only when parallel work is intentional:

```bash
xdr session start --concurrent --label incident-67890
```

The `--concurrent` command prints exact POSIX and PowerShell attachment syntax.
Parallel actors sharing one session should set distinct `XDR_ACTOR` values.
JSONL and sequence allocation remain cross-process locked.

With multiple concurrent markers, set `XDR_SESSION=<id>` (POSIX) or
`$env:XDR_SESSION = "<id>"` (PowerShell) before `session end`; without an
explicit attachment there is deliberately no unambiguous current session to
end.

## Ending and append-only feedback

`session end` is actor-restricted: when `XDR_ACTOR` is set to anything other
than `operator` it refuses unless `--force` is passed, so a sub-agent cannot
cut off its siblings' ability to write records and clear gates. Ending an
already ended session is a conflict error.

Explicit `xdr session end` closes the session first, then runs three foreground
maintenance stages: refresh a missing or stale physical cache, mine saved results
and validate their overlaps, and explore new identifier locations. All are enabled
by default. `schema_collect_on_session_end = false` in `~/.xdr-cli/config.toml`
disables the entire workflow. Set `schema_refresh_on_session_end = false` or
`schema_explore_on_session_end = false` to disable just that stage.

`schema_explore_max_queries = 5` controls the exploration query budget per explicit
session end (integer 1–1000). Focused validation retains its separate 20-query
budget; a needed refresh adds one schema query. A validation budget pause still
allows exploration its budget. Upstream failures, including authentication and
rate limits, stop subsequent stages. Completed work is reused at later explicit
session ends. Refresh uses the existing `schema_stale_seconds` threshold, which
defaults to one day. Ordinary commands and startup do not run this workflow.
Idle expiry, automatic rotation, and ending an already closed or missing session
never trigger maintenance. No scheduler or new session is created.

The first JSON line is a `record_type: "session-end"` receipt, flushed immediately
after durable closure with feedback `next_action`. The second is a
`record_type: "session-maintenance"` completion record containing `maintenance`
and, when available, an artifact receipt with the individual stage receipts.
Maintenance has an overall deadline of `schema_maintenance_timeout_seconds = 90`
seconds (maximum 3,600 seconds). Local synchronous parsing can finish its current
operation before the deadline is checked. Use `session end --no-maintenance`
to skip upkeep once.
Failure or partial completion leaves the session ended and returns exit 14 with
the cause classification in the terminal record. Cancellation returns exit 130.
Do not retry session
end; inspect `maintenance.status`, honor any
`retry_after_seconds`, and follow the reported recovery command. Use
`xdr schema collect` for focused validation or `xdr schema collect --explore`
for exploration; both reuse completed work. The feedback
`next_action` remains available. An unconfigured tenant skips collection.
Underlying API/authentication errors retain their classification in
`maintenance.cause`; follow `maintenance.next_command` for recovery (for example,
`xdr auth status`). Concurrent collection reports a conflict; retry once the
other collection finishes.

Unknown configuration keys produce a warning. Invalid schema-maintenance
settings prevent automatic upkeep from running, but do not block core commands
or `session end --no-maintenance`. Correct the reported setting before retrying
collection; saving authentication settings preserves the invalid entry rather
than silently replacing it with a default that enables tenant queries.


`xdr session end` first appends a deterministic `session_summary`, then a
terminal `session_ended` record, and durably removes the marker. It does not
prompt by default—even on a TTY. Its structured `next_action` asks the agent
to append an assessment:

```bash
xdr session feedback <id> \
  --source agent \
  --outcome completed-with-friction \
  --category output-handling \
  --comment "large output required extra handling"
```

If the analyst later supplies feedback, append it separately:

```bash
xdr session feedback <id> \
  --source analyst \
  --outcome completed-smoothly \
  --comment "the artifact workflow was much better"
```

Feedback never overwrites, deduplicates, reopens, or changes older records.
Each entry has a unique ID and monotonic feedback sequence. `--source analyst`
means the analyst supplied the substance; an agent must never infer or invent
it. Feedback may be added after explicit end, inactivity timeout, or automatic
rotation.

Session end never prompts for feedback. Follow its first record's `next_action`
and append feedback with `xdr session feedback`.

Supported outcomes:

- `completed-smoothly`
- `completed-with-friction`
- `incomplete-blocked`

Supported categories:

- `session-state`
- `output-handling`
- `parsing`
- `query-or-schema`
- `library-discovery`
- `auth-or-permission`
- `latency-or-timeout`
- `tenant-context`
- `other`

## Learning mode and rationale

`xdr --rationale "<prediction>" ...` records pre-run intent when attachment
succeeds. `xdr session start --learning-mode` requires `xdr annotate` after
each attached, non-housekeeping invocation. A command the gate refuses is
still recorded (with `learning_gate_refused: true`) but is never itself
waiting for annotation, so the next `xdr annotate` clears the command that
was actually pending. An unattached command cannot be learning-gated. Use `xdr annotate --skip "<reason>"` rather than inventing a
successful lesson.

## Security and compatibility

- Known secret argv values such as `device timeline --refresh-token` are
  replaced with `***REDACTED***`; do not pass other secrets on argv.
- `XDR_SESSION` must name an existing session (a live, real session JSONL).
  An arbitrary synthetic ID does not create a session, and a terminal
  `session_ended` record is never reopened implicitly; append feedback or
  explicitly start/resume a live session instead.
- Locking uses `filelock` and supports PowerShell/bash on local filesystems.
- Copilot transcripts remain the canonical corpus for agentic efficacy;
  sessions are optional enrichment.
