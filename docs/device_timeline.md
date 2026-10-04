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
| `xdr auth portal-login` | Authenticate to the unofficial Defender portal API (MSAL) |
| `xdr auth portal-cookie` | Authenticate to the unofficial Defender portal API via browser cookies |
| `xdr auth portal-logout` | Clear cached portal credentials (MSAL cache + cookie store) |
| `xdr device timeline DEVICE` | Download device timeline (unofficial API) |

## Quick start

```bash
xdr auth portal-cookie mde-curl.txt
xdr device timeline my-workstation --hours 3
xdr device timeline my-workstation --days 30 --output timeline.jsonl
```

## Audit attribution by auth method

The timeline endpoint requires portal session credentials, which xdr-cli can
obtain two ways. They differ in what they *should* produce in your Entra
sign-in logs, but this attribution has **not been independently verified**,
so confirm it in your own tenant before relying on it:

- **`xdr auth portal-cookie` (cookie), the validated method.** Reuses your
  *existing* logged-in security.microsoft.com browser session (the
  `sccauth`/`xsrf-token` `Cookie` header captured via **Microsoft Edge**'s
  DevTools "Copy as cURL (bash)" of the timeline apiproxy request). Because it
  rides a session you already established in a browser, it should not mint a
  new token or create new sign-in events.
- **`xdr auth portal-login` (MSAL/FOCI), experimental and unverified.**
  Attempts an interactive sign-in with the Microsoft Azure CLI FOCI client ID
  (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) via a *separate* MSAL instance,
  isolated from xdr-cli's own app registration. It may not succeed in every
  tenant. If it does, the sign-in is *expected* to be attributed to
  **"Microsoft Azure CLI"** (the FOCI client), not "xdr-cli", by design, but
  this has not been confirmed.

`xdr auth status` reports which method is active and its `audit_app_name`
label: `Microsoft Azure CLI` for the MSAL/FOCI path and
`Microsoft Defender portal (browser session)` for the cookie path. Treat that
label as the *intended* attribution, not a verified fact about how the
activity appears in your logs.

## Three auth paths

`device timeline` picks its credential by first-match-wins precedence:
`--refresh-token`/`MDE_REFRESH_TOKEN`, then a stored cookie store, then a
cached portal MSAL account. With none of those present it exits non-zero and
names both portal auth commands.

### 1. `xdr auth portal-cookie COOKIE_SOURCE` (recommended, validated)

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

### 2. `xdr auth portal-login` (experimental, unverified)

An interactive MSAL sign-in (browser or device code) using the Microsoft Azure
CLI FOCI client. Takes `--tenant-id` to override the configured tenant. It may
not complete in every tenant, and its Entra sign-in-log attribution is
unconfirmed; prefer cookie auth (above). Tokens are cached in
`~/.xdr-cli/portal_token_cache.json`.

### 3. `--refresh-token` (env `MDE_REFRESH_TOKEN`)

For CI/non-interactive use: redeems a pre-obtained FOCI refresh token instead
of stored portal auth. It wins over any stored cookie or MSAL state.

### Clearing portal credentials

`xdr auth portal-logout` removes both `~/.xdr-cli/portal_token_cache.json` and
`~/.xdr-cli/portal_cookies.json`. It does not touch the main
`~/.xdr-cli/token_cache.json` used by `xdr auth login`/`xdr auth logout`.
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
| `--refresh-token` | CI/non-interactive FOCI refresh token (env `MDE_REFRESH_TOKEN`). |

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

`device timeline` resolves `DEVICE` to a MachineId using the *official* MDE
`machines` API (your normal `xdr auth login` credentials) before switching to
the portal apiproxy client for the timeline events themselves; only the
timeline fetch touches the unofficial API. With stored cookie auth, even a
supplied 40-hex MachineId is verified through the configured official tenant
before portal data is accepted.

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
**`DeviceId`** (MachineId). A hostname is resolved to its MachineId via the
official MDE `machines` API. A 40-hex value is normally used directly; stored
cookie auth verifies it through the configured official tenant first.

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
- **Coordinate with your SOC before relying on this in production.** The
  combination of "Microsoft Azure CLI" client + a non-browser (Python)
  user agent is a pattern some detection content specifically flags as
  suspicious. Loop in whoever tunes your Entra/Defender detections before
  running this against a real tenant, especially at scale.
- **Check your organization's policy on first-party-app impersonation.**
  Authenticating as the Azure CLI's own client ID to reach an API it wasn't
  built for is exactly what "impersonating a first-party Microsoft app", a
  practice some organizations explicitly forbid, means. If in doubt, use
  `portal-cookie` instead, or don't use this feature.

## Related

- [README](../README.md): command reference and the project overview.
- [Session mechanics](sessions.md): how session recording redacts the
  `device timeline --refresh-token` value.
