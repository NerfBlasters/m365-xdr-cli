# Browser cookie renewal — follow-up PR proposal

Status: planned, not implemented in this release. Cookie-only commands currently
use an imported browser session. Auto backend selection already chooses cookies
when official credentials are absent. This proposal adds an explicit browser-assisted
renewal command while keeping the backend independent of Playwright and MSAL.

## Current operation

Sign in to `https://security.microsoft.com` in a browser. In DevTools > Network,
select a successful portal API request and copy it as cURL (bash). Save it to a
private file and run:

```bash
xdr auth portal-cookie /path/to/private-cookie-source.txt
```

The importer extracts the complete Cookie header, including routing/session
cookies and chunked `sccauth`, plus the XSRF token. It binds the stored credentials
to the configured tenant. Source cleanup is best effort after successful import;
`--keep-source` preserves the file. `--verify` is on by default. See
`xdr auth portal-cookie --help` for the complete current behavior.

`auth status` reports local storage, not remote validity. A command returning
exit 2 requires a refreshed session. There is no fixed cookie lifetime the CLI
can promise: server-side expiry, revocation, Conditional Access, and sign-in
frequency can invalidate cookies before their browser expiry timestamps.

## Proposed command and scope

Proposed interface, **not available yet**:

```text
xdr auth portal-cookie --browser
```

Make COOKIE_SOURCE optional only when `--browser` is selected. Reject a source
and `--browser` together. Browser mode must validate credentials before saving;
reject `--no-verify` and file-only options such as `--keep-source` in browser mode.
Preserve existing file/stdin imports and their outputs.

The follow-up should contain one visible Chromium workflow and optional browser
dependencies. It should not change the portal API adapters, introduce a daemon,
read a user's normal browser profile, or add credential-vault integration.
Microsoft's normal sign-in and MFA UI remains interactive. Automated password,
TOTP, proof-up, or Conditional Access handling is outside this PR.

## Browser lifecycle

1. Check the configured tenant and browser dependency before opening a browser.
   Missing dependencies produce explicit installation guidance; no automatic
   package or browser download on an ordinary command invocation.
2. Acquire a lock for a CLI-owned, tenant-specific persistent browser profile.
   Use a private directory beneath the CLI config home, keyed by the existing
   tenant fingerprint. Treat the entire profile as credential material.
3. Open a visible browser at the fixed Defender HTTPS origin. Reuse its session
   when possible; otherwise let the operator complete normal Microsoft sign-in,
   account selection, MFA, or proof-up. Provide a bounded overall timeout and
   cancellation. Do not interpret a loaded portal shell as authenticated success.
4. Obtain the cookies that the browser would send to the exact tenant-context
   API URL, accounting for domain, path, Secure, expiry, duplicate names, and
   partitioning. Preserve the complete routing/session header and all `sccauth`
   chunks. If Playwright's cookie API cannot faithfully reproduce the applicable
   header, fail with manual-import guidance rather than broadening cookie scope.
5. Extract XSRF using the existing parser. Validate the candidate credentials in
   memory with the fixed-origin, no-redirect tenant-context request. Require exact
   `AuthInfo.TenantId` equality with configured tenant; a successful page load or
   matching email domain is insufficient. Never forward portal cookies to a
   redirect destination or copy identity-provider cookies into the CLI store.
6. Atomically replace `portal_cookies.json` only after verification succeeds,
   using `save_portal_cookies` and its existing private-write guarantees. Record
   the storage time, tenant fingerprint, and non-secret acquisition method.
7. Close the CLI-owned browser and release the profile lock in all exit paths.
   Preserve the profile for later explicit renewal. Do not terminate unrelated
   browsers. A future attach-to-browser mode would need its own ownership rules.

The current manually imported credentials must remain intact after cancellation,
timeout, wrong-tenant login, verification failure, or a failed replacement write.
Do not temporarily replace the active cookie file just to test a candidate.

## Observed browser integration issue

During development, attaching Playwright over CDP to the existing visible browser
returned an empty list from `BrowserContext.cookies()` while page-scoped CDP
`Network.getCookies` returned the applicable portal cookies. A tenant-context
request using the latter's XSRF token succeeded. An empty context cookie list
therefore did not establish that the browser session had expired.

Test cookie acquisition against the specific page/context that made the successful
portal request. For the proposed owned Chromium profile, verify this binding in
integration tests; if page-scoped CDP is needed, query only the fixed portal API
URL and validate the resulting candidate before storage. Never compensate by
exporting every browser context or identity-provider cookie. CDP attachment is
development tooling here, not a shipped renewal interface.

## Expiry, recovery, and concurrency

Renewal is explicit. API operations continue to return the existing authentication
error when their session expires. Do not silently open a browser inside a hunt,
device action, incident update, or background process. Do not automatically retry
writes after renewal: their outcome may be unknown. An operator should inspect
the original action before deciding whether to submit it again.

Two renewal commands for the same profile must not run concurrently. Coordinate
cookie replacement with logout so a browser command cannot silently restore
credentials after logout. Recheck the configured tenant before publication if
configuration can change while the browser is open. Existing API clients may
retain the old in-memory cookies until the operator reruns the command.

A persistent browser profile can still have a valid Microsoft session after CLI
cookie logout. Preserve today's documented `auth logout` semantics unless the
follow-up explicitly adds an opt-in profile removal option. Explain that local
file/profile deletion is not Microsoft-side session revocation. Profile cleanup
must target only the owned tenant directory and refuse symlink substitution.

## Packaging and integration

- Put Playwright in an optional dependency group; lazy-import it inside the
  explicit browser path. Normal imports and cookie API calls must work without it.
- Add a small browser-session module that returns candidate cookie material in
  memory. Reuse the current parser, tenant fingerprint, and atomic secret storage.
- Factor tenant verification to accept candidate credentials without writing the
  store or initializing MSAL. Keep verification requests fixed-origin and bounded.
- Keep stdout to one compact success/error record; progress and interactive
  guidance go to stderr. Never print cookie values, tokens, complete headers,
  browser storage state, passwords, or signed URLs. Disable traces/HARs/screenshots
  by default, including on exceptions.
- Close resources on Ctrl-C and report exit 130. Use established authentication,
  configuration, conflict, network, and rate-limit errors; honor Retry-After.
- Audit initiation/result without secret material or a guessed operator identity.
  Define platform support explicitly and exercise profile permissions on Windows
  as well as POSIX; don't assume chmod alone supplies Windows access control.

## Verification and acceptance

Unit/integration coverage must include source/browser argument conflicts; missing
optional dependencies; chunked cookies; XSRF encoding; domain/path/partition
selection; wrong tenant; expired/revoked credentials; HTTP redirects; 429; network
errors; cancellation; atomic replacement failure; profile-lock contention; logout
races; and absence of credentials in stdout, stderr, audit records, and exceptions.
A failed renewal must leave the previous cookie store byte-for-byte unchanged.

Use a local browser fixture for most automation. In the development tenant,
perform these explicit acceptance checks:

- A signed-in persistent profile exports a session; a cookie-only named read
  succeeds with MSAL construction prohibited.
- An expired CLI store is replaced from a still-valid browser session.
- An expired browser session shows the normal interactive login/MFA flow and
  publishes credentials only after exact-tenant verification.
- Cancelling login, selecting another tenant, and rejecting MFA preserve the old
  store and release the browser/profile lock.
- With a refreshed cookie, an existing read command succeeds. Renewal itself
  submits no incident/device changes and replays no previous mutation.

The release review should include observed lifecycle results, dependency/browser
installation instructions, supported platforms, and profile cleanup behavior.
Browser renewal remains a separate PR so these lifecycle changes can be reviewed
independently of the API backend and device-field mappings.
