# API backend development

`backend_contract.Backend` defines the named operations used by API helpers and
commands. `OfficialBackend` implements them over the MSAL-backed `XDRClient`
transport; `PortalBackend` implements them with fixed, tenant-verified portal
routes. `backends.create_client()` selects and constructs one implementation.
There is no generic HTTP verb or arbitrary URL operation on the shared interface.

When adding an operation:

1. Add its typed abstract method to `Backend`. Both concrete backends must
   implement it before they can be instantiated. An unsupported operation needs
   an explicit local error; it must not change authentication backends or replay
   a request.
2. Put endpoint paths, request bodies, response validation and native response
   conversion in the concrete backend. Keep `api/*` helpers dependent only on
   `Backend`; do not add backend type checks or transport calls there.
3. Use `BackendProfile` for availability and provenance differences. Commands
   can inspect the selected configuration's profile before constructing auth
   when an unavailable operation should fail locally. Once constructed, the
   backend's profile supplies the same metadata. Profiles do not attest remote
   session validity or grant permissions.
4. Extend the contract tests and each backend's synthetic request/response tests.
   `test_backend_contract.py` exercises API helpers with an interface-only mock
   that cannot call Graph/MDE transport methods. A missing concrete method fails
   at construction rather than during a tenant request.

Hunting returns the shared `HuntingResult`. Normalization preserves the public
schema and rows; backend-specific diagnostics use its `metadata` field. Official
Graph-to-MDE hunting fallback remains internal to the official backend and only
handles the existing permission/not-found cases. Cookie authentication never
falls back to MSAL.

`continuation.validate_continuation()` is shared by official domain pagination
and portal Graph collections. Callers supply exact permitted **host/path pairs**
and a seen-link set. It requires HTTPS, the default port, a nonempty query, and
no user information or fragment. Portal callers copy only the returned raw query
onto their fixed route; official domains follow the validated URL. Keep page
bounds and row handling in the collection implementation. Do not decode and
re-encode opaque cursor query strings.

Timeline streaming retains its existing `PortalClient` and `PortalAuthStrategy`
interface for stored cookies and an existing `portal_token_cache.json`. Device
resolution before streaming uses `Backend` with enrichment disabled. Browser
renewal is a separate proposal and is not part of this interface change.
