# Troubleshooting

This is the long-form troubleshooting reference for `xdr`. Every symptom
has its own `###` heading; where the CLI emits a stable error `code`, that
code appears in the heading so you can search for it directly.

Contents:

- [How errors are reported](#how-errors-are-reported)
- [Exit codes and error codes](#exit-codes-and-error-codes)
- [Output streams, piping, and non-interactive mode](#output-streams-piping-and-non-interactive-mode)
- [Authentication and consent](#authentication-and-consent)
- [Portal-cookie backend](#portal-cookie-backend)
- [Command-line usage errors](#command-line-usage-errors)
- [Query library](#query-library)
- [Installation](#installation)
- [Lookups, debugging, and multiple tenants](#lookups-debugging-and-multiple-tenants)
- [Schema maintenance advisory](#schema-maintenance-advisory)
- [Audit log](#audit-log)

## How errors are reported

When a command fails before it has produced durable output, `xdr` prints
exactly one compact JSON line on **stdout** and exits with a non-zero
class-specific code. The record always has the same shape:

```json
{"status":"error","error":{"schema_version":1,"type":"ForbiddenError",
"message":"Insufficient permissions. Required scope: ...",
"code":"PERMISSION_MISSING_SCOPE","exit_code":7,"retryable":false,
"invalid":null,"allowed":[],"suggestions":[{"reason":"recovery",
"message":"Check your Entra ID app permissions and RBAC roles.",
"confidence":"exact"}],"corrected_argv":null,"help_command":null,
"retry_after_seconds":null,"request_ids":{"request-id":"..."},
"original":{"type":"Forbidden","status":403,"message":"...","detail":{...}}}}
```

`original` carries the upstream error's type, HTTP status, message and
detail when the failure came from an API; it is `null` for local errors.

Fields worth scripting against:

| Field                 | Meaning                                                |
| --------------------- | ------------------------------------------------------ |
| `code`                | Stable string identifier (see table below)             |
| `exit_code`           | The process exit code, duplicated for convenience      |
| `retryable`           | `true` for timeouts and rate limits                    |
| `retry_after_seconds` | Set on `API_RATE_LIMITED`                              |
| `invalid`             | `{kind, value}` naming the offending option/argument   |
| `allowed`             | Valid choices when `invalid` is an enum or option name |
| `suggestions`         | Recovery hints; `confidence` is `exact` or `heuristic` |
| `corrected_argv`      | A full replacement command line, when one is known     |
| `help_command`        | The `--help` invocation that documents the fix         |

## Exit codes and error codes

Exit codes are grouped by the recovery action they require. Every `code`
string the CLI emits is listed under its exit code; the schema-cache codes
are grouped separately below the table because they only come from
`xdr schema ...` and `xdr results` proposal commands.

| Exit | Class                | `code` values                                                           | What to do                                                        |
| ---- | -------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 0    | `SUCCESS`            | --                                                                      | --                                                                |
| 1    | `INTERNAL_ERROR`     | `INTERNAL_ERROR`                                                        | Re-run with `--debug`; report a bug                               |
| 2    | `AUTH_ERROR`         | `AUTH_LOGIN_REQUIRED`, `NOT_AUTHENTICATED`, `TOKEN_EXPIRED`             | `xdr auth status`, then `xdr auth login` (official) or `xdr auth portal-cookie <source>` (cookie mode) |
| 3    | `UPSTREAM_API_ERROR` | `API_ERROR`, `API_MALFORMED_RESPONSE`, `API_INVALID_RESPONSE_SHAPE`, `BACKEND_CAPABILITY_UNAVAILABLE` | Inspect `original.status` / `original.detail`; for the capability code, no request was sent -- pick the other `--backend` |
| 4    | `CONFIG_ERROR`       | `CONFIG_ERROR`, `PORTAL_COOKIE_INVALID`, `PORTAL_XSRF_TOKEN_MISSING`, `PORTAL_COOKIE_TENANT_MISMATCH`, `PACKAGE_DATA_MISSING` | Check `~/.xdr-cli/config.toml`; re-import cookies; reinstall for the package code |
| 5    | `QUERY_ERROR`        | `QUERY_ERROR`, `QUERY_UNKNOWN_TABLE`, `QUERY_UNKNOWN_COLUMN`, `QUERY_SEMANTIC_ERROR`, `LIBRARY_UNKNOWN_ENTRY`, `LIBRARY_UNKNOWN_PARAM`, `LIBRARY_MISSING_PARAM`, `LIBRARY_INVALID_PARAM` | Fix KQL (`xdr schema tables --search <name>`) or the library call (`xdr library show <name>`) |
| 6    | `USAGE_ERROR`        | `CLI_USAGE_ERROR`, `CLI_UNKNOWN_COMMAND`, `CLI_UNKNOWN_OPTION`, `CLI_INVALID_VALUE`, `CLI_INVALID_ENUM`, `CLI_MISSING_VALUE` | Follow `help_command` / `corrected_argv` |
| 7    | `PERMISSION_ERROR`   | `PERMISSION_MISSING_SCOPE`, `PERMISSION_DENIED`                         | Grant the missing API permission and admin consent (see below)    |
| 8    | `NOT_FOUND`          | `API_NOT_FOUND`, `LOCAL_NOT_FOUND`, `RESULT_NOT_FOUND`, `RESULT_QUERY_NOT_FOUND` | Verify the ID or run-id (`xdr results list`)              |
| 9    | `RATE_LIMIT`         | `API_RATE_LIMITED`                                                      | Wait `retry_after_seconds`, then retry                            |
| 10   | `TIMEOUT`            | `API_TIMEOUT`, `AUTH_CACHE_LOCK_TIMEOUT`, `SESSION_SCHEMA_MAINTENANCE_TIMEOUT` | Raise `--timeout` / `api_timeout`; narrow the query; retry after the other `xdr` login finishes |
| 11   | `NETWORK_ERROR`      | `API_NETWORK_ERROR`                                                     | Check connectivity / proxy                                        |
| 12   | `ARTIFACT_ERROR`     | `ARTIFACT_WRITE_FAILED`, `RESULT_INTEGRITY_FAILED`                      | Check free space and permissions under `~/.xdr-cli/results`; `xdr results show <run-id>` for integrity failures |
| 13   | `CONFLICT`           | `STATE_CONFLICT`                                                        | Resolve the conflicting local state, then retry; also returned when you answer no to a confirmation prompt |
| 14   | `PARTIAL_SUCCESS`    | `PARTIAL_SUCCESS`                                                       | Receipt was written; inspect the trailing error for failed parts  |
| 130  | (SIGINT)             | `SESSION_SCHEMA_MAINTENANCE_CANCELLED` (from `session end` only), otherwise none | Command was interrupted with Ctrl-C; POSIX convention   |

Schema-cache codes, by exit code:

- 8 (`NOT_FOUND`): `SCHEMA_CACHE_MISSING`, `SCHEMA_UNKNOWN_TABLE`,
  `SCHEMA_UNKNOWN_SEMANTIC_FIELD`, `SCHEMA_FIELD_UNAVAILABLE`,
  `SCHEMA_CANDIDATE_NOT_FOUND`, `SCHEMA_CANDIDATE_SOURCE_EVIDENCE_MISSING`
- 12 (`ARTIFACT_ERROR`): `SCHEMA_CACHE_INVALID`, `SEMANTIC_GRAPH_INVALID`,
  `SEMANTIC_PROFILE_INVALID`, `SCHEMA_OVERLAY_INVALID`,
  `SCHEMA_OVERLAY_REPAIR_FAILED`, `SCHEMA_PROVISIONAL_SOURCE_REJECTED`,
  `SCHEMA_PROPOSAL_INTEGRITY_FAILED`, `SCHEMA_BUNDLE_INVALID`,
  `SCHEMA_BUNDLE_EXPORT_FAILED`, `SCHEMA_BUNDLE_IMPORT_FAILED`
- 13 (`CONFLICT`): `SCHEMA_OVERLAY_COMPATIBILITY_REQUIRED`,
  `SCHEMA_EFFECTIVE_GRAPH_CONFLICT`, `SEMANTIC_DOCUMENT_MARKERS_MISSING`,
  `SEMANTIC_DOCUMENT_STALE`, `SCHEMA_PROBE_TEMPORAL_COLUMN_MISSING`,
  `SCHEMA_BUNDLE_COLLISION`, `SCHEMA_CANDIDATE_EVIDENCE_INSUFFICIENT`,
  `SCHEMA_PROPOSAL_CORE_RELATIONSHIP_EXISTS`,
  `SCHEMA_PROPOSAL_EVIDENCE_CHANGED`, `SCHEMA_CORRELATION_TENANT_MISMATCH`
- 14 (`PARTIAL_SUCCESS`): `SCHEMA_PROPOSAL_PARTIAL_PUBLICATION`

Recovery for these is covered in the
[semantic schema graph guide](schema_graph.md).

Note that there is no `FORBIDDEN` code. An HTTP 403 from either API, or
from the Defender portal in cookie mode, is reported as
`PERMISSION_MISSING_SCOPE` with exit code 7.

`BACKEND_CAPABILITY_UNAVAILABLE` is the one exit-3 code that is raised
locally: the selected backend has no adapter for the operation, so no
request is sent and no fallback to the other backend is attempted. See
[Portal-cookie backend](#portal-cookie-backend).

`CLI_COMMAND_FAILED` is not tied to one class: it wraps a command that exited
without a structured error and keeps that command's own exit code.

## Output streams, piping, and non-interactive mode

### Progress and warnings appear mixed into JSON output

They should not, and will not unless you merge the streams yourself.
`xdr` keeps a strict contract:

- **stdout** carries data: artifact receipts, previews, and (on failure)
  structured errors. Lifecycle and raw-render commands have the exceptions
  documented in [AGENTS.md](../AGENTS.md#3-artifact-and-compact-output-shapes).
- **stderr** carries progress messages, warnings, deprecation notices,
  and the schema maintenance advisory.

Do not use `2>&1`. Doing so interleaves human-oriented text with the
machine-readable stream and breaks `jq`-based consumers. Redirect stderr
separately if you need to keep it:

```bash
xdr incidents list --since 24h 2>progress.log | jq .
```

### No progress output when piping

This is expected. Stderr progress is auto-silenced whenever stdout is not
a TTY (for example, when piped into `jq` or redirected to a file). The
flag is tri-state:

| Invocation       | Behaviour                                              |
| ---------------- | ------------------------------------------------------ |
| (default)        | Progress shown on a TTY, silenced when stdout is piped |
| `--quiet` / `-q` | Always silenced (useful when stderr is also captured)  |
| `--no-quiet`     | Always shown, even when stdout is piped                |

```bash
xdr --no-quiet hunt run 'DeviceEvents | where Timestamp > ago(1h) | take 10' | jq -c .
```

### Command exited 14 (`PARTIAL_SUCCESS`) but a receipt was written

Exit 14 means the durable part of the operation succeeded and one or more
sub-operations did not. The CLI emits the receipt and previews on stdout
first, then a final `PARTIAL_SUCCESS` JSON line naming the failed
sub-operations. Treat the artifact as valid and inspect the trailing error
for what to retry. When consuming with `jq`, read all lines (`jq -c .`
or `jq -s .`) rather than assuming a single document.

Explicit `session end` has a lifecycle-specific shape: a `session-end` record
with feedback instructions, followed by a `session-maintenance` record. Upkeep
failure or incomplete work returns 14; cancellation returns 130. The session
is already closed, so do not retry `session end`. Run the maintenance record's
`next_command`; when the failure had an underlying cause, `maintenance.cause`
names it. Use `session end --no-maintenance` to skip
upkeep for an end that has not yet run. See [sessions](sessions.md).

Configuration warnings can still appear on stderr in quiet mode. Invalid
schema-maintenance settings prevent upkeep but leave core recovery commands
and `session end --no-maintenance` available.

### A prompt was skipped, or a destructive action refused to run

`xdr` prompts only when **both** stdin and stdout are TTYs and
`--no-interactive` is not given. If either stream is redirected or piped,
the CLI never prompts. Commands that would normally ask for confirmation
(the device actions `isolate`, `unisolate`, `restrict`, `unrestrict`,
`scan`, `collect-package`, plus `incidents update` and `results prune`)
then refuse with `CLI_USAGE_ERROR` (exit 6) unless `--yes` is passed.

Answering no at the prompt is reported as `STATE_CONFLICT` (exit 13) with a
message such as *Device action 'isolate' was cancelled by the operator.*
Nothing was sent.

`auth login` is a separate interactive flow and is not made unattended by
`--no-interactive`. Agents should surface authentication failures to a human
rather than retrying login in a subprocess.

```bash
xdr --no-interactive device isolate <machine-id> --yes --comment "IR-1234"
```

### `investigate` asks "Run which queries?" or runs every enrichment query

When an incident yields suggested enrichment queries, `xdr investigate`
without `--auto-enrich` prints the numbered list on stderr and prompts
`Run which queries?` (default `a` for all; `n` for none; or a
comma-separated list of numbers) -- but only on a TTY. When stdin or
stdout is not a TTY, or `--no-interactive` is set, there is no prompt and
every suggested query runs. Pass `--auto-enrich` to get that behaviour on
a TTY too, or answer `n` to skip enrichment.

## Authentication and consent

### `xdr auth status` shows `"configured": false`

This field appears only when the official backend is selected (it sits
under `main`). No `tenant_id` / `client_id` is present in
`~/.xdr-cli/config.toml`. Run the login once with both IDs; they are saved
to the config file:

```bash
xdr auth login --tenant-id <TENANT-ID> --client-id <CLIENT-ID>
```

Any later command that needs a token before configuration exists raises
`CONFIG_ERROR` (exit 4) with the same hint.

If you intend to use cookies only, ignore the `auth login` hint: the
official backend was selected because no cookies are stored for the
configured tenant, so there is nothing for `auto` to fall back to. Set
`tenant_id` in `config.toml` and import a cookie instead (see
[Portal-cookie backend](#portal-cookie-backend)).

### `NOT_AUTHENTICATED` or `AUTH_LOGIN_REQUIRED`

`NOT_AUTHENTICATED` means the token cache holds no signed-in account.
`AUTH_LOGIN_REQUIRED` means an account is cached but a token could not be
refreshed silently. `TOKEN_EXPIRED` (same class, exit 2) means the cached
token has expired and could not be renewed. Re-run `xdr auth login`. The
token cache lives at `~/.xdr-cli/token_cache.json`; `xdr auth logout`
deletes it if you want a clean start.

In cookie mode the same exit code means the stored portal cookies are
missing or rejected; the fix is `xdr auth portal-cookie <source>`, not
`auth login`. See [Portal-cookie backend](#portal-cookie-backend).

If the message says *Interactive authentication required for scope ...*
(code `AUTH_LOGIN_REQUIRED`), the cache holds an account but that API
audience, usually Defender for Endpoint, has never been consented
interactively. Run `xdr auth logout && xdr auth login`; if that still fails,
see the `AADSTS65001` entry below.

### Sign-in hangs, never opens a browser, or rejects the device code

`xdr auth login` is interactive. On Windows it uses the WAM broker (so the
device's Primary Refresh Token satisfies Conditional Access device
policies); elsewhere it opens a browser on this machine. If no display or
broker is available (headless host, SSH session, CI), it prints
*Interactive auth unavailable ... falling back to device code* on stderr
and shows a URL plus a one-time code to enter from another device.

After the primary Graph token is acquired, the login pre-warms the other
API audiences. A warning such as *could not pre-warm scope ...* is
non-fatal: the Graph token is already saved, and the first command that
needs the other audience will prompt for it.

If the flow stalls or the code is rejected:

- Make sure **Allow public client flows** is enabled in the app
  registration's **Authentication** blade.
- Confirm redirect URI `http://localhost` is registered as a **Public
  client/native** redirect (see `AADSTS50011` below). On Windows, the WAM
  broker also needs `ms-appx-web://Microsoft.AAD.BrokerPlugin/<client-id>`.
- An interactive sign-in that opens but then fails (cancelled, blocked by
  Conditional Access, redirect mismatch) is reported as an error; it does
  not fall back to a device code. The fallback is only for hosts where no
  browser or broker can start.
- If a browser did open but you dismissed it, re-run the command; the
  cancelled dialog is reported as an `AUTH_LOGIN_REQUIRED` error, not a
  hang.
- In a headless environment, make sure stdin and stderr are attached so
  you can see the device code.

### `PERMISSION_MISSING_SCOPE` / HTTP 403 on API calls

The token lacks a required scope, or the permission exists on the app
registration but has not been consented. Re-check the API permissions
table in the README and click **Grant admin consent for [tenant]**.
Permissions take effect only after consent, and the cached access token
does not pick up a newly consented scope: silent sign-in keeps returning the
token issued before the change until it expires (up to about 90 minutes).
Run `xdr auth logout && xdr auth login` to start using the new permission
immediately. This is the usual cause when the error persists right after
you have added and consented the permission.

The error's `message` names the required permission when the CLI knows the
endpoint (for example `ThreatHunting.Read.All` or `Machine.Isolate`). Where
the delegated and application names differ, both are given, e.g.
`Machine.Read (delegated) or Machine.Read.All (application)`. A 403 can also
come from a missing Defender role for the signed-in user; that is reported
the same way.

`PERMISSION_DENIED` (also exit 7) is local: `xdr session end` refuses to end
a session for a non-`operator` `XDR_ACTOR` unless `--force` is given.

### `AADSTS65001` ("user or administrator has not consented")

The app registration is missing admin consent for one of the **two token
audiences** the CLI needs:

- **Microsoft Graph** (incidents, alerts, Graph hunting) -- consent for
  Microsoft Graph permissions.
- **Defender for Endpoint** (device actions, fallback hunting) -- consent
  for **WindowsDefenderATP** permissions.

In **API permissions**, verify every required permission shows *Granted
for [tenant]* in the Status column. If any are missing, click **Grant
admin consent for [tenant]** again, then `xdr auth logout && xdr auth
login` so the cache is rebuilt with the new consent.

When a silent token request (delegated or `client_credentials`) returns this
AADSTS code, it is surfaced as a `PERMISSION_MISSING_SCOPE` error naming the
scope.

### Why WindowsDefenderATP audience vs. api.security.microsoft.com endpoint?

Defender for Endpoint endpoints live at
`api.security.microsoft.com/api/...`, but their tokens must be issued for
the **`api.securitycenter.microsoft.com` audience**. This is
Microsoft's current guidance (see the
[Defender for Endpoint APIs docs](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-nativeapp)).
That is why the permissions you add in the portal are listed under
**WindowsDefenderATP** -- the audience has not migrated even though the
endpoint URLs have.

### `AADSTS50011` / redirect URI mismatch during login

The app registration is missing the `http://localhost` redirect URI under
**Authentication** > **Platform configurations** > **Mobile and desktop
applications** (shown as *Public client/native*). Add it and retry.

### `auth_mode = "client_credentials"`: `xdr auth status` says `authenticated: false`

This can be expected. In `client_credentials` mode the CLI uses a
confidential client and acquires an application token with the client
secret on demand. `xdr auth status` derives `main.authenticated` from the
presence of a cached delegated user account. With no such account the
`data` block of the envelope reports (trimmed):

```json
{"main": {"authenticated": false, "configured": true, "account": null,
          "tenant": "...", "backend": "official",
          "backend_preference": "auto"},
 "portal": {"authenticated": false, "method": null, "account": null,
            "tenant": "...", "cookie_stored": false, ...}}
```

If a delegated account remains from an earlier login, `main.authenticated`
can instead be `true`. Neither value validates the client secret. Commands
attempt to obtain application tokens on demand when configured. `xdr auth
login` is **not applicable** in this mode -- it drives the interactive user
flow, which a confidential client does not support. If token acquisition
itself fails you will see `AUTH_LOGIN_REQUIRED` with *Client credentials
auth failed: ...*, or `PERMISSION_MISSING_SCOPE` when the description
mentions consent. Check that `client_secret` is set, has not expired, and
that the app has **application** (not delegated) permissions with admin
consent.

## Portal-cookie backend

The portal-cookie backend talks to `security.microsoft.com` with a browser
session you import; the official backend uses MSAL tokens against the
Graph and Defender for Endpoint APIs. Both expose the same named
operations, but the error you see for "not signed in" and the fix differ.

### Which backend is in use, and why

`xdr auth status` reports two fields: `backend` is the backend actually
selected for this invocation and `backend_preference` is what was asked
for (`--backend` if given, otherwise `api_backend` from `config.toml`,
default `auto`). In the official shape both sit under `main`; in cookie
mode they are top-level:

```json
{"backend": "portal-cookie", "backend_preference": "auto",
 "portal": {"cookie_stored": true, "session_validity": "not_checked"},
 "capabilities": ["hunting", "incidents-list", ...],
 "full_parity": false}
```

Selection is local and never checks whether a token or cookie still works.
Under `auto`, the official backend wins when `tenant_id` and `client_id`
are configured and either a `client_secret` is set in `client_credentials`
mode or `token_cache.json` holds a token or refresh token for that tenant
and client. Otherwise cookie mode is chosen if `portal_cookies.json` holds
a usable cookie bound to the configured tenant; with neither present the
official backend is selected and `auth status` reports
`"configured": false`. `--backend official` or `--backend portal-cookie`
pins the choice.

### Exit 2 (`NOT_AUTHENTICATED`) in cookie mode

The message is *Portal credentials are missing, expired, or require
interactive sign-in.* and the suggestion is `xdr auth portal-cookie
<cookie-source>`. The same error is raised when the portal answers 401 or
440, redirects to a sign-in page, or returns HTML instead of JSON. Import
a fresh cookie; `auth login` does not help here.

Running `xdr auth login` while the cookie backend is pinned (`--backend
portal-cookie` or `api_backend = "portal-cookie"`) is a `CLI_USAGE_ERROR`
(exit 6) pointing at `xdr auth portal-cookie --help`. Under `auto` the
login proceeds and, once a token is cached, the next command selects the
official backend.

### Cookies stopped working

Portal cookies have no fixed lifetime; the session ends when the portal
decides, typically after sign-out, a password or Conditional Access
re-evaluation, or an idle period. `auth status` never probes them
(`session_validity` is always `not_checked`). The import itself does probe
by default: `xdr auth portal-cookie <source>` reports `verified: true` or
`false` plus `verify_error`; use `--no-verify` to skip the call. Re-import
when a command returns exit 2.

### `PORTAL_COOKIE_INVALID` / `PORTAL_XSRF_TOKEN_MISSING` at import

Both are `CONFIG_ERROR` (exit 4) from `xdr auth portal-cookie`.
`PORTAL_COOKIE_INVALID` means the source carries no `sccauth` cookie, so
it is not a Defender portal session; nothing is stored and the source file
is not deleted. Copy the whole request as cURL (bash) from DevTools, not a
single cookie value. `PORTAL_XSRF_TOKEN_MISSING` means the header had no
`XSRF-TOKEN` cookie and the manual prompt was left empty.

### Tenant mismatch: `PORTAL_COOKIE_TENANT_MISMATCH` or exit 4 on the first call

Stored cookies are bound to a fingerprint of the `tenant_id` configured at
import time. If `tenant_id` later changes, loading the store raises
`PORTAL_COOKIE_TENANT_MISMATCH` (exit 4); `auth status` surfaces the same
condition as `portal.cookie_error` instead of failing. Re-run
`xdr auth portal-cookie <source>` for the current tenant.

A cookie whose fingerprint matches but that was captured while signed in
to a different tenant fails on the first API call: the backend reads the
portal's tenant context before any operation and raises `CONFIG_ERROR`
(exit 4) with *Authenticated portal tenant does not match configured
tenant_id.* No operation was sent. Sign in to the right tenant in the
browser and import again.

### Stderr warning: "invalid api_backend in config.toml"

`api_backend` accepts `auto`, `official`, or `portal-cookie`. Any other
value prints *Warning: invalid api_backend in config.toml; using auto for
reads and diagnostics* on stderr and the command continues under `auto`.
Tenant writes (`device isolate`, `unisolate`, `scan`, `collect-package`,
`restrict`, `unrestrict`, `incidents update`) are blocked with
`CONFIG_ERROR` (exit 4) until the value is corrected or `--backend` is
passed explicitly; `--dry-run` runs are not blocked. Passing `--backend`
with an unknown value is a `CLI_INVALID_ENUM` usage error.

### `BACKEND_CAPABILITY_UNAVAILABLE` (exit 3)

The selected backend has no validated adapter for the operation. The
error is raised locally: no request was sent and no fallback to the other
backend was attempted, so the exit-3 class is misleading if you read it as
an upstream failure. The two cases:

- `xdr domains list --source active-directory` on the official backend: Active Directory
  domain inventory exists only in cookie mode. Use `--backend
  portal-cookie`, or `--source entra`. With the default `--source all` the
  Entra rows are still written and the AD failure is reported as
  `PARTIAL_SUCCESS` (exit 14).
- A cookie-mode operation without a portal adapter; the suggestion is
  `--backend official`. `xdr auth status` lists the cookie backend's
  `capabilities`.

`xdr device download-package` is the reverse case and is reported as a
plain `CLI_USAGE_ERROR` (exit 6): it requires `--backend portal-cookie`.

### `auth logout` switched me to cookies

`xdr auth logout` clears the credentials of the backend that is selected
when it runs. Under `auto` with both a token cache and a cookie store, the
official backend is selected, so `logout` deletes `token_cache.json`; the
next command then finds only cookies and runs in cookie mode. Use
`xdr auth portal-logout` to clear cookies only, and run `auth logout`
again under `--backend portal-cookie` to clear both.

## Command-line usage errors

### `CLI_UNKNOWN_OPTION` for `--jq`, `--fields`, or hunt `--limit`

These flags do not exist. `xdr` does not project or filter results
locally, and hunts save every row the API returns; you shape the JSONL
artifact with shell tools. (`incidents list`, `alerts list` and
`results list` do take `--limit`, which bounds how many items are fetched.)
`schema collect` likewise takes no `--resume` or `--exhaustive`: plain
`xdr schema collect` continues pending validation and `--explore` drives
identifier-led discovery.

| Flag                 | Instead                                                            |
| -------------------- | ------------------------------------------------------------------ |
| `--fields`           | `xdr results shape <run-id>` to see columns; filter with `rg`/`jq -s` |
| `--jq`               | Run `jq` on the saved JSONL artifact                                |
| hunt `--limit`       | Limit at the source in KQL (`\| take 100`) or filter the artifact    |

```bash
xdr incidents list
xdr results shape <run-id>
jq -s 'map(.id)' <data_path>
```

### `CLI_UNKNOWN_COMMAND` / `CLI_UNKNOWN_OPTION`

The command or option was not recognised. `allowed` lists the valid names
at that level and `suggestions` carries up to three nearest matches with
`confidence: "heuristic"`. Run the `help_command` from the error to see
the full option list for that subcommand.

### `CLI_INVALID_ENUM`, `CLI_INVALID_VALUE`, `CLI_MISSING_VALUE`

A value was rejected. For enums, `allowed` contains every accepted choice.
For a missing value, `invalid.value` names the option or argument that
still needs one.

## Query library

### `xdr library list` reports a query is missing `-- tier:` frontmatter

Every `.kql` file must declare `-- tier:` in its frontmatter. The loader
does not abort the whole library when it meets a bad file; it skips that
file and prints `warning: skipping builtin query ...` or `warning:
skipping user query ...` on stderr, so the listing simply omits the
query. Two common causes:

1. **A user-installed `.kql` in `~/.xdr-cli/queries/` is missing
   `-- tier:`** or has another malformed-frontmatter problem (unknown
   tier, or `-- tier: deprecated` without `-- alias_of:`). Either delete
   the file or add the required header:

   ```
   -- name: my_query
   -- description: ...
   -- tier: r3
   -- params: hours=24
   ```

   Choose a supported tier (`r1`, `r2`, `r3`, `n`, `beta`, `pivot`, `utility`,
   or `deprecated`). Keep explanations outside the header value; inline
   comments become part of the parsed tier and make it invalid.

2. **Stale build artifacts in a source install.** See
   [Installation](#installation) below.

### `API_TIMEOUT`: `xdr library run` times out when the same query completes in the portal

Library queries with joins or aggregations can exceed the configured HTTP
timeout even though they eventually finish in the Defender portal. The CLI
reports this as a one-line `API_TIMEOUT` error with exit code 10 and
`retryable: true`; because the failure precedes durable output, no result
artifact is created. Either raise the per-call timeout:

```bash
xdr library run qry_inbox_rule_activity -p account_upn=alice@corp.com --timeout 240
```

or raise the default in `~/.xdr-cli/config.toml`:

```toml
api_timeout = 240
```

To compare what the CLI is about to send against the portal, render the
fully resolved KQL without executing it:

```bash
xdr hunt library-show qry_inbox_rule_activity -p account_upn=alice@corp.com
```

`xdr library show NAME` prints the entry's descriptor instead (parameters
with types and defaults, referenced tables, declared output fields, cost
hint, and example invocations).

After a successful artifact-producing run, `xdr results query <run-id>`
prints the exact KQL stored with that result, which is what was sent to
the API.

### `--param` only captured the first argument

`--param` / `-p` is a **repeatable** flag, not a comma-separated list.
Pass each parameter as its own `-p`:

```bash
# Wrong -- sets account_upn to the literal "alice@corp.com,mode=detail"
xdr library run qry_inbox_rule_activity -p account_upn=alice@corp.com,mode=detail

# Right
xdr library run qry_inbox_rule_activity \
  -p account_upn=alice@corp.com \
  -p mode=detail
```

### `RESULT_QUERY_NOT_FOUND` from `xdr results query`

The result exists but its metadata has no stored `query` field (for
example, a non-hunt artifact). Use `xdr results show <run-id>` to inspect
what the artifact does contain.

## Installation

### Stale build artifacts after `pipx install` / `pipx upgrade` from source

Leftover `build/`, `dist/`, or `*.egg-info/` directories in a source
clone can confuse setuptools' `package-data` glob, so the installed
package ships the wrong set of bundled `.kql` files or other data. A
typical symptom is `xdr library list` warning about a built-in query that
looks fine on disk. Clean them out and reinstall:

```powershell
# from your xdr-cli source clone (PowerShell)
Remove-Item -Recurse -Force build, dist, src\xdr_cli.egg-info -ErrorAction SilentlyContinue
pip cache remove "xdr*"
pipx uninstall xdr-cli
pipx install .
```

```bash
# Linux / macOS
rm -rf build dist src/xdr_cli.egg-info
pip cache remove "xdr*"
pipx uninstall xdr-cli
pipx install .
```

## Lookups, debugging, and multiple tenants

### Incident or device not found (`API_NOT_FOUND`)

Incident IDs come from `xdr incidents list` or from the Defender portal
URL. Device IDs are 40-character hex MachineIds, not hostnames -- get them
from the evidence rows of `xdr incidents show <id> --expand alerts`
(`mdeDeviceId`), from `xdr device show <hostname>`, or from a hunting query
(`DeviceInfo | project DeviceId, DeviceName`). A `RESULT_NOT_FOUND` with
the same exit code (8) means no saved result matches the run-id (or
run-id prefix) you gave; check it with `xdr results list`. An ambiguous
prefix that matches several results is `STATE_CONFLICT` (exit 13) instead.
`LOCAL_NOT_FOUND` is the generic form for other local artifacts, sessions,
and cache entries.

### Inspecting HTTP traffic

Add the global `--debug` flag to emit MSAL and httpx debug logs on
stderr. Keep stderr separate from stdout so the JSON output stays clean:

```bash
xdr --debug incidents list --since 24h 2>debug.log
```

The debug log can contain request URLs and headers; review it before
sharing.

### Multiple tenants

Set `XDR_CLI_HOME` to isolate config, token cache, results, schema cache,
sessions, and the audit log per tenant:

```bash
XDR_CLI_HOME=~/.xdr-cli-prod  xdr auth login --tenant-id <PROD>  --client-id <ID>
XDR_CLI_HOME=~/.xdr-cli-dev   xdr auth login --tenant-id <DEV>   --client-id <ID>
```

Export the variable in a shell profile or wrapper script so every
subsequent command uses the same home.

## Schema maintenance advisory

### Stderr says "Schema maintenance due (...). Run: ... or inspect: xdr schema status"

When running in a TTY, the CLI checks the local semantic schema cache
before executing your command. If the cache is stale, or a periodic
collection is overdue, it prints a one-line advisory on **stderr** that
names the reason and the exact next command. The advisory is informational
only:

- It never blocks or alters the command you asked for.
- It is suppressed when stdout is piped (auto-quiet) or `--quiet` is set,
  so it cannot contaminate scripted output.
- It is not shown while you are already running a `schema status`,
  `schema diagnostics`, `schema collect`, `schema repair-overlay`,
  `schema migrate-cache`, or `schema bundle ...` command.

Run `xdr schema status` to see the full maintenance state and the
recommended action, then run the suggested command when convenient. State
definitions, staleness thresholds (`schema_stale_seconds`,
`schema_collection_stale_seconds` in `config.toml`), and recovery
procedures are documented in the
[semantic schema graph guide](schema_graph.md).

## Audit log

### Where the audit log is and what it records

`xdr` appends a line to `~/.xdr-cli/audit.log` (or
`$XDR_CLI_HOME/audit.log`) each time it is invoked with a command that
modifies state. The file is created with mode `0600` inside a `0700`
directory, matching the token and cookie stores, because it is effectively
your command history. Each line is a timestamp followed by `CMD:` and the
argument vector as typed, with secret-bearing values (`--refresh-token`)
redacted:

```
2026-10-03 09:14:22,118 CMD: device isolate 1a2b3c... --yes --comment IR-1234
```

Commands that are logged (matched against the command Click actually
dispatches, so every accepted syntax is covered and an argument that
happens to equal a command name does not count):

- Device actions: `device isolate`, `device unisolate`, `device scan`,
  `device collect-package`, `device restrict`, `device unrestrict`
- Incident updates: `incidents update`
- Authentication: `auth login`, `auth logout`, `auth portal-cookie`,
  `auth portal-logout`
- Guided investigation: `investigate`
- Lists: `lists init`
- Schema cache writes: `schema repair-overlay`, `schema migrate-cache`,
  `schema bundle import`

Commands that are **not** logged include, among others: all `session`
commands, `results prune`, `schema refresh`, `schema collect`,
`schema observe`, `device timeline`, and every read-only command
(`incidents list`, `hunt run`, `library run`, and so on). If you need a
complete per-invocation record, use sessions (`docs/sessions.md`), which
capture every command while active.

Two cautions:

- Apart from `--refresh-token`, any value you pass on the command line
  (comments, UPNs, IDs) lands in the file as typed.
- This is a local convenience log, not a tamper-evident audit trail. It
  can be edited or deleted by anyone with access to the home directory.
  The line is written when the command is dispatched, before it runs, so
  it records that a command was *attempted* (including `--dry-run` runs and
  ones refused for a missing `--yes` or declined at the prompt), not whether
  it succeeded. `--help` and argument errors never dispatch a command and
  are not logged. For authoritative records of device actions and incident
  changes, use the Defender portal's action center and Microsoft Entra
  sign-in / audit logs.
