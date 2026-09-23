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
4. automatic creation for `hunt run`, `library run`, the deprecated
   `hunt library-run` alias, `investigate`, and alert/incident `show`;
5. unattached execution when multiple unmatched sessions remain.

Ambiguity is deliberately nonblocking. stderr provides both forms:

```bash
XDR_SESSION=<id> xdr ...
```

```powershell
$env:XDR_SESSION = "<id>"
```

Help, lists, auth, result browsing, and library/schema discovery do not create
sessions. Expired markers are retired with `end_reason: "idle-timeout"`; their
JSONL history remains.

## Manual and concurrent sessions

Normal `session start` rotates the selected current session. If multiple
markers exist and `XDR_SESSION` does not explicitly select one, it rotates all
of them before creating one new sequential session. It requires a cached
authenticated account so the session has an operator identity:

```bash
xdr session start --label incident-12345 --timeout 1800
```

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

`xdr session end --prompt-feedback` is the only interactive path. The session
is already closed before prompting, so interruption cannot leave it active.

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
each attached, non-housekeeping invocation. An unattached command cannot be
learning-gated. Use `xdr annotate --skip "<reason>"` rather than inventing a
successful lesson.

## Security and compatibility

- Known secret argv values such as `device timeline --refresh-token` are
  replaced with `***REDACTED***`; do not pass other secrets on argv.
- `XDR_SESSION` must name a live, real session JSONL. Arbitrary synthetic IDs
  no longer create sessions, and a terminal `session_ended` record cannot be
  reopened implicitly; append feedback or explicitly start/resume a live
  session instead.
- Locking uses `filelock` and supports PowerShell/bash on local filesystems.
- Copilot transcripts remain the canonical corpus for agentic efficacy;
  sessions are optional enrichment.
