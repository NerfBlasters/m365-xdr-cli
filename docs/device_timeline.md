# Device timeline (unofficial API)

`xdr device timeline` downloads a device's Defender for Endpoint timeline, the
same event stream shown on a device's page in the Defender portal, by talking
to the unofficial `security.microsoft.com/apiproxy/mtp/mdeTimelineExperience`
endpoint the portal UI itself uses. It is not part of the documented Microsoft
Defender for Endpoint API, has no SLA, and can break without notice.

## When to use this

Advanced Hunting (`xdr hunt run`) only retains roughly 30 days of raw event
data, while the portal's device timeline retains roughly **180 days**. Reach
for `device timeline` when an investigation needs to establish first-seen or
earliest-activity evidence beyond what `hunt run` can see. Use `--hours` for a
narrow window on busy devices or `--days` for longer lookbacks; the resolved
window may be at most 180 days, and anything larger is rejected before any
request is made.

## Commands

| Command | Description |
|---|---|
| `xdr auth portal-login` | Returns a usage error directing callers to `portal-cookie` |
| `xdr auth portal-cookie` | Authenticate to the unofficial Defender portal API via browser cookies |
| `xdr auth portal-logout` | Clear portal cookies and the portal token cache; official tokens are preserved |
| `xdr device timeline DEVICE` | Download device timeline (unofficial API) |

## Quick start

```bash
xdr auth portal-cookie mde-curl.txt
xdr device timeline my-workstation --hours 3
xdr device timeline my-workstation --days 30 --output timeline.jsonl
```

## Audit attribution by auth method

Use `xdr auth portal-cookie` to import an existing browser session. Activity
uses that signed-in user's portal permissions. Audit attribution must be
verified in your tenant; a local auth-status label is not evidence of the
actual sign-in or activity-log attribution.

`xdr auth portal-login` does not sign in; it returns a usage error pointing
at `portal-cookie`. The `--refresh-token` path redeems the token as the
"Microsoft Azure CLI" client, so sign-in logs attribute that activity to
Azure CLI.

## Portal credentials

With `--backend portal-cookie`, timeline requires stored cookies;
`--refresh-token` (and `MDE_REFRESH_TOKEN`) is rejected, and the portal token
cache is never consulted. The default official backend selects a credential
in this order: an explicit refresh token, stored cookies, then an account in
`~/.xdr-cli/portal_token_cache.json` (a token cache left by a sign-in flow
this release does not offer; `auth portal-logout` deletes it). Neither token
path is available under the cookie backend.

### 1. `xdr auth portal-cookie COOKIE_SOURCE` (recommended, validated)

The canonical capture walkthrough and backend limits live in
[portal_cookie.md](portal_cookie.md); this section is the short form.

Reuses your existing logged-in security.microsoft.com browser session. It
takes the **whole** browser Cookie header from a file (or `-` for stdin) and
stores it in `~/.xdr-cli/portal_cookies.json` (mode `0600` on POSIX;
protected by the user-profile ACL on Windows). The store is bound to a
non-reversible fingerprint of the configured tenant, so a configured tenant is
required before importing. Unbound or different-tenant stores are rejected;
re-run `portal-cookie` after selecting the intended tenant to re-import.

The apiproxy backend needs more than `sccauth`/`xsrf-token`: it also relies
on the routing cookie `X-PortalEndpoint-RouteKey` (pins the request to your
tenant's regional backend) and the session cookie `s.SessID`. Omit those and
the backend answers with an **opaque HTTP 500**, which is why the whole header
is required, not just a couple of cookies. To capture it, in **Microsoft
Edge** (logged in to security.microsoft.com) open DevTools, go to
**Network**, right-click the timeline **apiproxy** request, then **Copy** and
**Copy as cURL (bash)**, save it, and run (only Edge plus the *bash* cURL
variant is tested; Chrome/Firefox and the cmd/PowerShell variants are
unverified):

```bash
xdr auth portal-cookie mde-curl.txt          # a saved "Copy as cURL (bash)" or Cookie header
pbpaste | xdr auth portal-cookie -            # or pipe it in via stdin
```

xdr extracts the full `Cookie` header, forwards it verbatim (chunked
`sccauth`, `chunks:N` plus `sccauthC1…N`, included), and auto-extracts the
XSRF token. The only interactive prompt is a hidden `xsrf-token` fallback,
shown only when the header carries no `XSRF-TOKEN` cookie; an empty answer is
rejected. A file or stdin is required rather than a paste prompt because the
header runs past the ~4 KB a terminal will accept on one line.

Options:

- `--verify/--no-verify` (default: verify). After storing, make one
  lightweight apiproxy call to confirm the cookies work. The result reports
  `verified` and, on failure, a `verify_error`.
- `--keep-source`. By default, on a successful import xdr makes a best-effort
  overwrite and deletion of the regular source file it validated (it holds a
  live session bearer credential). Pass `--keep-source` to keep it. Symlinks
  are rejected and file identity is rechecked before overwrite; a detected
  mismatch stops cleanup and warns you to remove the original capture
  manually. stdin (`-`) is not a file and is never shredded. A source
  containing no `sccauth` cookie is rejected and left untouched (nothing is
  stored).

### 2. `xdr auth portal-login`

Returns a usage error directing callers to `portal-cookie`, without
contacting Microsoft or changing the configured tenant.

### 3. `--refresh-token` (env `MDE_REFRESH_TOKEN`)

For CI/non-interactive use on the official backend: redeems a pre-obtained
FOCI refresh token instead of stored portal auth. It wins over any stored
cookie or MSAL state. Under `--backend portal-cookie` it is rejected as a
configuration error.

### Clearing portal credentials

`xdr auth portal-logout` removes both `~/.xdr-cli/portal_cookies.json` and
the portal token cache `~/.xdr-cli/portal_token_cache.json`. It does not
touch the main `~/.xdr-cli/token_cache.json` used by `xdr auth login`/`xdr
auth logout`.
Missing files are a no-op.

## Secret handling

**Cookie secrets are never passed as `device timeline` flags.** The Cookie
header is accepted by `portal-cookie` only from a file or stdin (`-`), the
XSRF token is auto-extracted from it (or entered at a hidden prompt only when
the header has no `XSRF-TOKEN` cookie), and the result is stored in
`~/.xdr-cli/portal_cookies.json`. Cookie values never reach argv.

**`--refresh-token` *can* be passed as a flag**, but prefer the
`MDE_REFRESH_TOKEN` environment variable instead. A value passed as
`--refresh-token` lands in shell history and is visible to anyone who can run
`ps` while the command is executing; the environment variable avoids both.
The flag form is also captured by session recording: its value is replaced
with `***REDACTED***` before being written to the session JSONL (both
`--refresh-token SECRET` and `--refresh-token=SECRET` forms), but the flag
itself is still best avoided. The environment variable never enters argv.

## `xdr device timeline` options

| Option | Behaviour |
|---|---|
| `DEVICE` | Hostname or 40-hex MachineId (required). |
| `--from` | Window start; defaults to the lookback window. |
| `--to` | Window end; defaults to now. |
| `--days N` | Lookback days when `--from` is not given (min 1; default 7). |
| `--hours N` | Lookback hours when `--from` is not given (min 1). Mutually exclusive with `--days`. |
| `--output PATH`, `-o` | Atomically write owner-only JSONL here; refuses existing paths and unsafe shared directories. |
| `--gzip`, `-z` | Gzip the output file (`.jsonl.gz`). Requires `--output`. |
| `--force` | Replace an existing `--output` path; replaces a symlink entry, never its target. Requires `--output`. |
| `--page-size N` | Events per request (min 1; default 1000; max 1000). |
| `--refresh-token` | CI/non-interactive FOCI refresh token (env `MDE_REFRESH_TOKEN`). Official backend only; rejected under `--backend portal-cookie`. |

### Time window

`--hours` and `--days` are mutually exclusive; supplying both is a usage
error. When neither `--from`, `--hours`, nor `--days` is supplied, the default
lookback is seven days ending now.

`--from` and `--to` accept RFC3339-style values (for example
`2026-07-24T21:00:00Z`). The accepted formats are
`YYYY-MM-DDTHH:MM:SS<offset>`, `YYYY-MM-DDTHH:MM:SS.ffffff<offset>`,
`YYYY-MM-DDTHH:MM:SS`, `YYYY-MM-DD HH:MM:SS`, and `YYYY-MM-DD`. A value with
no UTC offset is treated as UTC. `--from` must be at or before `--to`.

The 180-day cap is enforced on the *resolved* window, not just on `--days`:
an explicit `--from`/`--to` span or an hours-based window over the limit is
rejected before any request is made, rather than being silently truncated
server-side.

### Resolution and output

Device resolution runs through the selected backend's inventory. The official
backend resolves a hostname through the MDE `machines` API and, when stored
cookies supply the credential, also verifies a supplied MachineId there. With
`xdr --backend portal-cookie device timeline DEVICE`, tenant verification,
MachineId verification, and hostname lookup all use portal requests (an exact,
unique match in the portal inventory's 180-day view); no app registration or
MSAL credentials are required. On either backend an ambiguous hostname is
rejected with the candidate MachineIds. Timeline events stream through the
same portal adapter.

With no `--output`, the complete stream is atomically registered under
`~/.xdr-cli/results/` and stdout is a receipt plus at most two preview rows.
Explicit `--output PATH` (optionally `--gzip`) writes a plain raw-JSONL
file instead. It writes through an owner-only temporary file and publishes
atomically while keeping the original staging descriptor open, refusing an
existing path by default. Non-sticky group/world-writable output directories
are rejected; owner-only directories and sticky temporary directories are
supported. Add `--force` to replace an existing path; a symlink entry is
replaced rather than followed. A failed download leaves no partial
destination. A one-line event-count summary is printed to stderr.

This is a read-only command: it does not modify device state.

## Identifiers & Advanced Hunting cross-reference

The `device` argument is either a **`DeviceName`** (hostname) or a 40-hex
**`DeviceId`** (MachineId). A hostname is resolved to its MachineId by an
exact, unambiguous match in the selected backend's inventory: the MDE
`machines` API on the official backend, the portal inventory (180-day view)
under `--backend portal-cookie`. A 40-hex value is normally used directly;
when stored cookies supply the credential, the selected backend confirms it
first, and a mismatch is a conflict error.

**The portal timeline's `MachineId` is the same identifier as Advanced
Hunting's `DeviceId`** (verified against live tenant data), and the hostname
is Advanced Hunting's `DeviceName`. So a `device timeline` run pivots cleanly
into Advanced Hunting on `DeviceId`. Each streamed event also carries this
pair under `Machine`:

| Timeline field | Advanced Hunting column | Meaning |
|---|---|---|
| `Machine.MachineId` (and the `device` you pass, once resolved) | `DeviceId` | 40-hex device identifier |
| `Machine.Name` | `DeviceName` | FQDN / hostname (case-insensitive) |
| `Machine.Domain` | (host domain suffix) | AD domain of the host |

The same `DeviceId` + `DeviceName` pair keys every `Device*` Advanced Hunting
table, so you can cross-reference a timeline against structured hunt data:
`DeviceInfo`, `DeviceEvents`, `DeviceFileCertificateInfo`, `DeviceFileEvents`,
`DeviceImageLoadEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`,
`DeviceNetworkInfo`, `DeviceProcessEvents`, `DeviceRegistryEvents`,
`DeviceTvmInfoGathering`, and `DeviceTvmSecureConfigurationAssessment`.

Pivot predicate (swap in any `Device*` table, e.g. via `xdr hunt run`):

```kusto
let hostname  = 'workstation-01.contoso.com';
let device_id = '0000000000000000000000000000000000000000';  // the timeline MachineId
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceId == device_id and DeviceName =~ hostname
| summarize Records = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
```

## Operational caveats

- **Unofficial and unstable.** This endpoint is not documented by Microsoft
  and is not covered by any support agreement. It can change shape or
  disappear without warning.
- **Rate limits apply.** Large windows against busy devices can hit portal-side
  throttling; use `--hours` where practical. Page size is tunable via
  `--page-size` (default 1000, max 1000) if you need to retune request cadence.
- **Coordinate with your SOC before relying on the refresh-token path in
  production.** `--refresh-token`/`MDE_REFRESH_TOKEN` redeems the token as
  the "Microsoft Azure CLI" client, and that client plus a non-browser
  (Python) user agent is a pattern some detection content specifically flags
  as suspicious. Loop in whoever tunes your Entra/Defender detections before
  running it against a real tenant, especially at scale.
- **Check your organization's policy on first-party-app impersonation.**
  This applies only to the `--refresh-token`/`MDE_REFRESH_TOKEN` path; there
  is no interactive portal OAuth sign-in, and `portal-cookie` reuses your own
  browser session. Authenticating as the Azure CLI's own client ID to reach an
  API it wasn't built for is exactly what "impersonating a first-party
  Microsoft app", a practice some organizations explicitly forbid, means. If
  in doubt, use `portal-cookie` instead, or don't use the refresh-token path.

## Related

- [README](../README.md): command reference and the project overview.
- [Session mechanics](sessions.md): how session recording redacts the
  `device timeline --refresh-token` value.
