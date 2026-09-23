# Lists: tenant data and IOC feeds for library queries

Library queries reference shared reference data — tenant-owned domains, internal
subnets, known-good publishers, RMM tools, IOC feeds — through "list blocks".
Each block is a plain-text file under `~/.xdr-cli/lists/<BlockName>.txt`. The
loader reads them, synthesises `let _xdr_<BlockName> = dynamic([...])` blocks,
and prepends them to the query body before parameter substitution.

## Initialisation

Run once after install:

```bash
xdr lists init
```

This copies the in-repo seed files (`src/xdr_cli/lists_seed/`) into
`~/.xdr-cli/lists/`. Public seeds (`InternalSubnets.txt`, `KnownGoodSigners.txt`,
`KnownRemoteSupportTools.txt`, `KnownGoodParentDomains.txt`) ship populated.
Most tenant-specific lists (`TenantDomains.txt`, `KnownEgressIPs.txt`, etc.)
ship empty — populate by hand or wait for the future `xdr enumerate` spec.
`KnownServiceAccounts.txt` is an exception: the seed ships pre-populated with
universal Windows service principals (`NT AUTHORITY\*`, `MSOL_*`, `AAD_*`,
`Sync_*`); add tenant-specific accounts to the user copy.

## File format

Plain text, one value per line. Comment lines starting with `#` are ignored
unless they match a recognised metadata header:

- `# fetched: <ISO timestamp>` — when the file was last refreshed.
- `# ttl: <Ns|Nm|Nh|Nd|Nw>` — staleness threshold (seconds, minutes, hours, days, weeks).
- `# source: <URL or note>` — provenance.

When `fetched + ttl < now()`, the loader emits a stderr warning. Values are
still loaded; staleness is advisory.

## List blocks

| Block | Purpose | How to populate |
|---|---|---|
| `TenantDomains` | Tenant-owned host/domain strings. Used by inbox-rule, mailbox-delegation, and DNS queries for internal/external classification. | Run `python scripts/extract_tenant_domains.py` once to migrate inline strings from legacy queries. Add new domains by hand. |
| `InternalSubnets` | Tenant-internal IPv4 CIDRs. | Public seed ships RFC1918 + CGNAT. Add tenant-specific ranges. |
| `KnownServiceAccounts` | IT-managed service accounts (UPN / sAMAccountName). | Pre-populated seed ships with universal Windows service principals (`NT AUTHORITY\*`, `MSOL_*`, `AAD_*`, `Sync_*`). Add tenant-specific accounts (e.g. `svc_*`, `MSSQL$*`) to the user copy. |
| `KnownGoodSigners` | Widely-trusted Authenticode publishers. | Public seed ships ~40. Add tenant-specific signers. |
| `KnownGoodServiceImagePaths` | Canonical Windows service ImagePath values. | By hand or via future `xdr enumerate`. |
| `KnownRemoteSupportTools` | RMM binary names. | Public seed ships common tools. Add tenant-specific. |
| `KnownEgressIPs` | Corp VPN egress, CGNAT, Starlink, iOS Private Relay. | By hand. |
| `KnownGoodParentDomains` | Universal CDN/ad-tech/SaaS allowlist. | Public seed ships. |
| `DomainControllers` | Tenant Domain Controller hostnames / FQDNs. | By hand or via future `xdr enumerate`. |
| `AiTMInfrastructure` / `MaliciousDomains` / `AnonymizingIPRanges` | Deny-lists. | Future `xdr lists refresh` will pull from feeds; populate by hand for now. |
| `RiskyKeywords` | Inbox-rule BEC content flags. | By hand. Suggested seeds in placeholder file. |

## Empty-list semantics

Each query is written so an empty list block is the safe direction:

- Allowlists are consumed via `Field !in (X)` or `not(...)` — empty list admits all rows.
- Denylists are consumed via `Field in (X)` or `has_any (X)` — empty list rejects all rows.
- CIDR membership uses `ipv4_is_in_any_range(IP, X)`, not `IP in (X)` (which is string equality).

If you populate a list, the corresponding queries get tighter. If you don't, queries still run — they just produce noisier output.
