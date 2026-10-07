# Portal-cookie backend

The portal-cookie backend reuses your logged-in security.microsoft.com
browser session: `xdr` forwards the browser's Cookie header to the portal's
undocumented `apiproxy` interface, the same one the Defender web UI calls.
You would choose it because it takes minutes to set up and needs no Entra
app registration and no admin consent; the official Graph/MDE backend
(`xdr auth login`) remains the supported alternative. Everything below
applies to a user session, not a service identity.

> **Caveats, read before importing anything**
>
> - The `apiproxy` interface is undocumented and unsupported by Microsoft.
>   It can change or break without notice; the CLI validates response shapes
>   and fails closed rather than guessing.
> - The imported cookie is a bearer credential for your user session. Anyone
>   who reads `~/.xdr-cli/portal_cookies.json` can act as you in the portal.
> - The session expires on Microsoft's schedule and is subject to your
>   tenant's Conditional Access and sign-in-frequency policies. When it
>   stops working, renewal is manual: capture and import again.
> - `xdr auth logout` deletes the local copy only. It does not revoke the
>   browser session at Microsoft; sign out in the browser for that.
> - Your Defender RBAC still applies. The CLI can do exactly what your user
>   can do in the portal, no more.
> - Attribution in sign-in and activity logs is that of your browser
>   session, not of a named application. Verify what your tenant records.

## Capture and import a cookie

Tested path: **Microsoft Edge** with the **Copy as cURL (bash)** menu item.
Chrome, Firefox, and the cmd/PowerShell cURL variants are unverified; they
may work if the result contains the full Cookie header, but nobody has
checked.

1. Configure the tenant. Cookie authentication needs `tenant_id` and
   nothing else from the official setup; `client_id` and `client_secret`
   can be absent.

   ```toml
   # ~/.xdr-cli/config.toml
   tenant_id = "00000000-0000-0000-0000-000000000000"
   ```

   Importing without `tenant_id` fails with exit 4 before anything is
   stored.

2. In Edge, sign in to <https://security.microsoft.com> and open any page
   that loads live data, for example a device page's timeline. Open
   DevTools (F12), select the **Network** tab, and filter on `apiproxy`.

3. Right-click any `apiproxy` request, choose **Copy**, then **Copy as cURL
   (bash)**. Save the clipboard to a file, for example `mde-curl.txt`, or
   keep it on the clipboard and pipe it in.

4. Import it. The argument is a file path or `-` for stdin; there is no
   paste prompt because the header is far longer than a terminal line
   accepts.

   ```bash
   xdr auth portal-cookie mde-curl.txt
   pbpaste | xdr auth portal-cookie -        # macOS clipboard via stdin
   ```

5. Confirm with `xdr auth status` (output shape below).

The whole header matters. `apiproxy` requires the routing cookie
`X-PortalEndpoint-RouteKey` and the session cookie `s.SessID` in addition to
`sccauth`; with only `sccauth` it answers an opaque HTTP 500. A large
`sccauth` is split by the portal into `sccauth=chunks:N` plus
`sccauthC1..N`; all of these are forwarded verbatim.

### What the import accepts

The source text is parsed in this order: the `-b '...'`/`--cookie '...'`
value of a bash cURL blob; otherwise a line beginning `Cookie:`; otherwise
the whole text as a bare cookie string. The result must contain an
`sccauth` cookie, or the import stops with `PORTAL_COOKIE_INVALID` and
neither stores nor deletes anything.

The XSRF token is taken from the `XSRF-TOKEN` cookie in the header and
URL-decoded. Only when the header has no such cookie does the command
prompt, with hidden input, for an `xsrf-token` value; an empty answer fails
with `PORTAL_XSRF_TOKEN_MISSING`. That is the only interactive prompt.

Cookies are written to `~/.xdr-cli/portal_cookies.json` with mode `0600`
(user-profile ACL on Windows), together with the XSRF token, a timestamp,
and a non-reversible fingerprint of the configured tenant. Cookie values
never appear on the command line.

### Options

`--verify` / `--no-verify` (default: verify). After storing, the command
issues one GET to `apiproxy/mtp/ndr/machines` with the imported cookies and
reports `verified: true` or `verified: false` plus a `verify_error` string.
This is a "do the cookies work at all" probe. It does **not** check which
tenant the session belongs to; that check runs on your first API command
(see [Errors you may see](#errors-you-may-see)). Network and HTTP failures
are reported, not raised, so the command exits 0 either way.

`--keep-source`. By default, once the cookies are stored, the source file
is overwritten with random bytes, fsynced, and unlinked, because it holds a
live session credential. Two honest qualifications: the cookies are stored
*before* the verify probe, and the source file is shredded even when verify
reports `false`; and the shred is best-effort, since SSD wear levelling and
copy-on-write or journaling filesystems can retain copies. Symlinks are
rejected as a source, and the file's identity (device and inode) is
rechecked before overwrite; on a mismatch the import succeeds but warns you
to remove the capture yourself. stdin (`-`) is never shredded. Pass
`--keep-source` to skip the shred; the command then reminds you on stderr
to delete the file.

### `auth status` afterwards

When the resolved backend is `portal-cookie`, `xdr auth status` prints a
cookie-mode record (trimmed here):

```json
{
  "backend": "portal-cookie",
  "backend_preference": "auto",
  "portal": {
    "cookie_stored": true,
    "session_validity": "not_checked"
  },
  "capabilities": [
    "hunting", "incidents-list", "incidents-show", "alerts-list",
    "alerts-show", "domains-list", "device-show",
    "device-timeline", "device-action-status-with-device",
    "device-download-package", "incident-comments", "incidents-update",
    "device-scan-quick", "device-scan-full", "device-isolate-selective",
    "device-isolate-full", "device-unisolate", "device-collect-package",
    "device-restrict", "device-unrestrict"
  ],
  "unverified_capabilities": [],
  "validation_caveats": ["..."],
  "full_parity": false
}
```

`session_validity` is always `not_checked`: status reads local files and
never contacts Microsoft. A store that parses but is bound to a different
tenant shows `cookie_stored: false` and a `cookie_error` object with code
`PORTAL_COOKIE_TENANT_MISMATCH`. When the resolved backend is `official`,
the same `cookie_stored`/`cookie_error` fields appear under `portal`, next
to the MSAL account details.

## What works in cookie mode

Supported operations, as reported by `auth status`:

| Area | Commands |
|---|---|
| Hunting | `hunt`, plus `library run` and schema workflows that execute KQL |
| Incidents | `incidents list`, `incidents show` (with `--expand alerts`), `incidents update` (status, classification, determination, `--comment`) |
| Alerts | `alerts list`, `alerts show` |
| Domains | `domains list` (Entra and MDI-observed Active Directory) |
| Devices | `device show`, `device timeline`, `device action-status` |
| Device actions | `device scan` (Quick/Full), `device isolate` (Selective/Full), `device unisolate`, `device restrict`, `device unrestrict`, `device collect-package`, `device download-package` |

Input limits specific to the portal adapters:

- Incident IDs must be numeric. Alert IDs may be up to 512 characters of
  letters, digits, `_`, `.` and `-`.
- `incidents show --expand` accepts only `alerts`; any other value is
  `BACKEND_CAPABILITY_UNAVAILABLE`.
- `incidents update` accepts only `--status`, `--classification`,
  `--determination`, and `--comment`. Fields are sent in one PATCH; the
  comment is a second POST issued only after the PATCH succeeds.
- Device reads take a 40-hex-character MachineId. A hostname is resolved by
  an exact, case-insensitive `ComputerDnsName` match among MDE devices in
  the portal's 180-day inventory view (up to 100 pages of 100 rows). Zero
  matches is `API_NOT_FOUND` (exit 8); more than one is `STATE_CONFLICT`
  (exit 13) asking for a MachineId.
- Action IDs must be GUIDs. `device action-status` also needs the device:
  pass `--device <MachineId>` unless a local association exists (see below).
- Scan and isolation modes are case-insensitive but must be one of the
  listed values; anything else is a usage error (exit 6) before any request.
- Incident and alert listing skips IDs already returned when live pages
  overlap; it is a live read, not a point-in-time snapshot.

Anything not listed is refused locally with `BACKEND_CAPABILITY_UNAVAILABLE`
(exit 3). No request is sent and the CLI never falls back to MSAL or to the
official API for that call.

Acceptance of a device action is not success. Check outcome with
`device action-status`. A portal mutation that times out is reported with
`retryable: false` because the action may already have been accepted;
inspect the incident or device before submitting again.

Sessions started in cookie mode (`xdr session start`) record the identity
placeholder `automatic` rather than an operator UPN, and refuse to start
without stored cookies.

## Backend selection

The `--backend` global option takes `auto`, `official`, or `portal-cookie`;
the `api_backend` key in `config.toml` takes the same values and defaults to
`auto`. An explicit `--backend` wins over the configured value. Neither the
flag nor the resolved choice rewrites the saved preference. `auth status`
reports both `backend` (resolved) and `backend_preference` (requested).

In `auto` mode, a command selects once, before any API work:

1. If official credentials are present, use `official`.
2. Otherwise, if a structurally usable cookie store matches the configured
   tenant, use `portal-cookie`.
3. Otherwise use `official`, so the normal configuration and login guidance
   applies.

Selection reads local files only. It does not establish that any credential
is still valid remotely, and authentication, permission, network, or
service errors never trigger a backend change or a replayed request.

"Official credentials present" means precisely: `tenant_id` and
`client_id` are both set, and either `auth_mode = "client_credentials"`
with a non-empty `client_secret` (a secret under any other `auth_mode` does
not count), or `~/.xdr-cli/token_cache.json` holds an access or refresh
token for that client ID and tenant. Expired access tokens still count. A
corrupt or unreadable token cache also counts as present, so official auth
and its recovery path are preserved rather than silently switching methods.

"Usable cookie store" means `portal_cookies.json` parses, its tenant
fingerprint matches the configured `tenant_id`, it has a non-empty XSRF
token, and the cookie header contains `sccauth` (or `sccauth=chunks:N` with
every `sccauthC1..N` cookie present, 1 ≤ N ≤ 100). Stores from another
tenant or with missing material are never selected automatically.

With both credential kinds present, `auto` picks official; pass
`--backend portal-cookie` to exercise cookie mode.

### Invalid `api_backend`

If `config.toml` holds any other value, `xdr` prints a warning on stderr and
behaves as `auto` for reads and diagnostics. Tenant writes (`incidents
update`, `device isolate|unisolate|scan|collect-package|restrict|unrestrict`)
stop with exit 4 before confirmation or dispatch unless `--backend` is given
explicitly or the command is a `--dry-run`. `auth login` and `auth
portal-cookie` still work during recovery but preserve the invalid value
when they save configuration; correct it by hand to clear the warning.

### `auth login` and `auth logout`

`auth login` refuses with a usage error (exit 6) whenever the resolved
backend is `portal-cookie` and the request was not `auto`, that is, under
an explicit `--backend portal-cookie` or a pinned `api_backend =
"portal-cookie"`. It directs you to `auth portal-cookie` instead. In `auto`
mode with only cookies present, `auth login` proceeds with the official MSAL
flow (which needs `client_id`).

`auth logout` clears credentials for the backend selected for that
invocation only. In cookie mode it deletes `portal_cookies.json` and
reports `cookie_cleared`; official `token_cache.json` is untouched. In official mode it clears `token_cache.json` and leaves the
cookies in place. Consequence in `auto` mode: with both present, `auth
logout` clears MSAL, and the next command silently selects cookies. Run
`auth portal-logout`, which always clears the portal files regardless of
backend, if you intend to remove cookies too. None of these revoke the
browser session at Microsoft.

## Known gaps and differences

### Device detail is partial

`device show` maps the portal fields that correspond directly to official
`Machine` properties and carries the rest under `portal_source`:
`raw` (the portal record), `supplementary` (inventory, IP-adapter and
exclusion reads), `field_sources` (where each derived field came from),
`enrichment_errors` (optional reads that failed, by error code),
`field_notes`, and `unavailable_fields`. `field_parity` is always
`partial`. Nothing is backfilled with synthetic defaults.

- `lastSeen` is the portal's observation time; the official property is the
  time of the last full device report. Recorded in `field_notes`.
- `osArchitecture` is set only when the portal's `OsProcessor` is `32-bit`
  or `64-bit`. The official `osProcessor` value (such as `x64`) cannot be
  recovered and stays in `unavailable_fields`.
- `deviceValue`, `machineTags`, `managedBy`, `managedByStatus`,
  `rbacGroupName`, `ipAddresses`, `exclusionReason`, `vmMetadata`, and
  `mergedIntoMachineId` come from a bounded exact-hostname inventory read
  and per-device supplementary reads; each is listed in `unavailable_fields`
  when its source did not supply it. `ipAddresses` can omit loopbacks.
  `isPotentialDuplication` has no portal source.
- Enrichment failures (permission, shape, network, timeout) are recorded
  and leave fields unavailable; authentication and rate-limit errors stop
  the command. Action submission and timeline device verification skip
  enrichment entirely.

### Action status needs the device

The portal's "latest actions" endpoint is queried per device, so
`device action-status` needs a MachineId. When an action is submitted or
first read through this backend, the CLI stores the pairing under
`~/.xdr-cli/action_associations/<tenant-fingerprint>/<action-id>.json`
(mode `0700`/`0600`) and later reads can omit `--device`. Pass
`--device <MachineId>` on first sight of an action created elsewhere or
when the association could not be saved (a stderr warning says so).

The endpoint keeps the latest retained action per category. A superseded
action can disappear and then reads as `API_NOT_FOUND`; this is a portal
limitation, not evidence of success or failure. Keep official credentials
available when you need durable action history. Response fields follow the
portal contract (`portal_source.status_contract: "portal-native"`).

### `domains list` has an Active Directory source

On this backend `domains list` combines Entra domains with MDI-observed
Active Directory domains, each record labelled with `source` and keeping its
provider identifier; same-named records are not merged. `--source entra`
and `--source active-directory` select one. The AD read is capped at 100
rows; `context.sources.active-directory` reports `has_more`, the returned
count, the portal's `reported_total`, and upstream errors. Truncation, a
count mismatch, or one failed source still writes the usable rows and exits
14 (`PARTIAL_SUCCESS`). AD records are not an exhaustive forest inventory. On the official backend the default `all`
listing writes Entra rows and exits 14 for the unavailable AD source;
`--source active-directory` there is `BACKEND_CAPABILITY_UNAVAILABLE`.

### `download-package`

`device download-package ACTION_ID --device MACHINE_ID --output PATH`
fetches an investigation package already collected by a succeeded
`collect-package` action. Both `--device` and `--output` are required. The
action must be a package-collection action (`Type: ForensicsResponse`) with
status `Succeeded`; otherwise exit 6 or exit 13 respectively. `--force`
replaces an existing output path atomically; `--max-bytes` (default 1 GiB)
caps the transfer. The parent directory must be a directory that is not
group- or world-writable unless it carries the sticky bit (exit 12). The
download goes to the signed Azure Blob URL with a separate client that
carries no portal cookies or tenant headers; the URL never appears in
output. The ZIP container is checked but not extracted. The receipt's
output key is `data_path`, with `bytes`, `sha256`, `action_id`,
`device_id`, and `api_backend`. On the official backend this command is a
usage error (exit 6).

### `device timeline`

With `--backend portal-cookie`, timeline reads use the stored cookies and
`--refresh-token` is rejected (exit 4). On the official backend the timeline
keeps its own credential order: explicit refresh token, then stored cookies.
See [device_timeline.md](device_timeline.md).

## Errors you may see

| Code | Exit | Meaning and fix |
|---|---|---|
| `PORTAL_COOKIE_INVALID` | 4 | The import source has no `sccauth` cookie. Nothing was stored or deleted. Re-copy as cURL (bash) from an `apiproxy` request. |
| `PORTAL_XSRF_TOKEN_MISSING` | 4 | The header had no `XSRF-TOKEN` cookie and the prompt was answered empty. Re-copy, or supply the token at the prompt. |
| `PORTAL_COOKIE_TENANT_MISMATCH` | 4 | `portal_cookies.json` is bound to a different tenant than `tenant_id`, or has no binding. Also shown as `cookie_error` by `auth status`. Re-import for the configured tenant. |
| `CONFIG_ERROR` "Authenticated portal tenant does not match configured tenant_id" | 4 | Raised on the first API call of a command: the portal reports a different tenant for your session than `tenant_id`. Sign in to the right tenant in the browser and re-import. |
| `NOT_AUTHENTICATED` | 2 | The portal answered 401/440, redirected to sign-in, or returned HTML. The session has expired or was revoked. Re-import with `xdr auth portal-cookie`. |
| `BACKEND_CAPABILITY_UNAVAILABLE` | 3 | The operation has no portal adapter (or used an unsupported option such as `--expand` other than `alerts`). No request was sent; use `--backend official`. |
| `PERMISSION_MISSING_SCOPE` | 7 | The portal answered 403. Check the signed-in user's Defender roles. |
| `STATE_CONFLICT` | 13 | A hostname matched several devices (supply a MachineId), or a package download targeted an action that has not succeeded. |

The import command itself exits 0 even when `--verify` reports
`verified: false`; read the `verify_error` and re-import if the cookies are
stale.

## Related

- [device_timeline.md](device_timeline.md): the timeline command, including
  the original capture walkthrough and secret-handling notes.
- [troubleshooting.md](troubleshooting.md): exit codes, error record shape,
  and output streams.
- [../README.md](../README.md): installation and the official backend.
- [Browser cookie renewal](proposals/browser_cookie_renewal.md):
  proposal, not implemented.
