# Changelog

All notable changes to xdr-cli are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This repository begins with a fresh source snapshot of `0.9.0`. Earlier
changelog entries are retained as release notes; their commits and referenced
issues or pull requests are not part of this repository. Historical CI entries
may describe tooling that has since been replaced; see [CI security](docs/ci.md)
for the current checks.

## [0.14.0] - 2026-10-04

Second documentation pass for a reader arriving fresh at the public
repository, and removal of the compatibility aliases, stubs and
removed-option hints carried over from before 0.9.0.

### Removed

- `xdr hunt library` and `xdr hunt library-run`, the aliases for
  `xdr library list` and `xdr library run`. `xdr hunt library-show` stays as
  the resolved-KQL renderer.
- `xdr schema candidates`, the alias for `xdr schema discoveries`.
- `xdr auth portal-login` and the portal OAuth token cache
  (`portal_token_cache.json`) behind it. Portal access is cookie-based and
  `auth status` no longer reports `msal_cached`. `auth portal-logout` (and
  cookie-mode `auth logout`) still delete a `portal_token_cache.json` left by
  an earlier release, so one logout cleans up an upgraded installation.
- The `CLI_REMOVED_OPTION` shims for `--fields`, `--jq`, hunt `--limit`, and
  `schema collect --resume`/`--exhaustive`. These are ordinary unknown
  options now.
- The hidden, always-rejected `schema collect --max-targets`.
- The deprecated query aliases `qry_inbox_rule_audit` and
  `qry_inbox_rule_triggers`; use `qry_inbox_rule_activity`. The `deprecated`
  tier and `alias_of` mechanism remain for future deprecations.

### Changed

- `xdr history stats` counts only `library run` records in its
  `hunt_library_run` ratio; the output key name is unchanged.
- README leads with the two sign-in paths and presents the portal cookie as
  the quick start (no app registration or admin consent); the Entra app
  registration follows as the supported path. The cookie backend's
  undocumented-interface and credential caveats now precede its setup steps.
- README states that the schema graph and sessions are optional, what an
  explicit `session end` costs, and how to keep it offline.
- `docs/portal_cookie.md` rewritten newcomer-first: capture and import steps,
  what works in cookie mode and its input limits, backend selection, known
  gaps, and error codes.
- Corrected against source: `unrestrict` requires `--comment`; exit 2 in
  cookie mode is fixed by re-importing a cookie, not `auth login`; the
  `auth status` shape differs by backend; `results prune` retires automatic
  graph evidence; `observe` accepts `TimeGenerated`; the auto-session command
  set; the audit-log scope; missing run IDs report `RESULT_NOT_FOUND`;
  unknown `--tier` is a usage error; declined confirmations exit 13.
- Documented every `xdr schema` flag that had no mention, `--backend`,
  `api_backend`, `action_associations/`, and the
  cookie-backend error codes in the troubleshooting reference.
- `docs/schema_probe.md` folded into `docs/schema_pivots.md`; the browser
  cookie renewal proposal moved to `docs/proposals/`.

## [0.13.0] - 2026-10-04

Experimental portal-cookie authentication, a shared API backend interface, and
the reliability fixes identified during implementation and adversarial review.

### Added

- Experimental `portal-cookie` backend using the undocumented Defender portal
  `apiproxy` interface. This is not an officially supported public integration
  path. Tenant-bound browser cookies support hunting, incident/alert workflows,
  domains, device reads/actions, and timelines without an app registration.
- Automatic backend selection: prefer matching MSAL credentials or configured
  app credentials; select cookies when they are the only usable local credentials.
  Explicit `--backend` and configured preferences override automatic selection.
- Combined Entra and MDI-observed Active Directory domain inventory through
  `domains list`, with source labels, source selection, and coverage metadata.
- `device unrestrict` for official and cookie authentication; cookie-based
  investigation-package archive downloads with private atomic output and no
  extraction or disclosure of signed download URLs.
- Tenant-bound local action/device associations and device enrichment with
  native source provenance and explicit unavailable-field reporting.

### Changed

- Both API backends implement a shared named-operation interface. API helpers
  delegate through that contract; capability profiles supply backend differences.
  Official domain and portal Graph reads share continuation URL validation.
- `domains list` saves artifact receipts and reports partial success when a
  requested source is unavailable. Use `--source entra` for Entra-only reads.
- `auth portal-login` is retired and directs users to cookie import. Browser
  renewal is documented as a separate follow-up, not included in this release.

### Fixed

- Overlapping portal pages no longer discard incident/alert listings or hostname
  searches; duplicate IDs are skipped while continuation and page bounds remain.
- Invalid backend configuration preserves diagnostics and reads, but blocks
  tenant writes without an explicit backend choice. Auth recovery does not
  silently change the invalid preference into a valid automatic selection.
- Session attribution honors an explicit official-backend override. Auth status
  diagnoses rejected cookie stores, and portal logout clears legacy portal tokens.
- Optional device lookup timeouts/network failures preserve the primary response;
  device detail is fetched once, and timeline verification skips enrichment.
- AD source failures distinguish unavailable data from retained partial results.
- Scan/isolation modes accept any letter case and reject invalid values before
  confirmation. Unknown-outcome portal mutation timeouts are nonretryable.

Full device-field and historical action parity remains limited by observed portal
contracts. See [portal-cookie support and limits](docs/portal_cookie.md).

## [0.12.0] - 2026-10-04

Documentation rewrite for the public launch, plus the fixes found while
verifying it against the code and a live tenant.

### Changed

- README rewritten as a landing page: what the tool is, who it is for, a
  recorded demo, install, Entra app registration, a six-command quick start,
  and a complete command reference. Long-form material moved to `docs/`.
- Entra permissions table verified against a live tenant: `Domain.Read.All`
  added for `xdr domains list`; `SecurityAlert.Read.All` instead of
  `ReadWrite.All` (`xdr` never modifies alerts); delegated `Machine.Read`
  (sufficient for `device show`, hostname lookups and `device action-status`)
  instead of `Machine.Read.All`/`Machine.ReadWrite`; `AdvancedQuery.Read` for
  the hunting fallback. Service-principal setup names the differing
  application permissions.
- 403 errors and the `library show` descriptor name the delegated Defender
  for Endpoint permission and its application equivalent (`Machine.Read
  (delegated) or Machine.Read.All (application)`), name
  `SecurityAlert.Read.All` for alerts, and name `Domain.Read.All` for
  `domains list`. The descriptor's `required_permissions` entries gain an
  `application_permission` field.
- `incidents show --expand` accepts only `alerts` and rejects anything else
  with `CLI_INVALID_ENUM` (exit 6) before calling Graph. Graph incidents have
  no `evidence` expansion; `--expand evidence` previously returned HTTP 400.
  Evidence is already included in each alert.
- `hunt library-show` and the deprecated `hunt library-run` validate
  parameters exactly as `library run` does. Unknown names, missing required
  parameters, and invalid values now fail with the `LIBRARY_*` codes (exit 5)
  instead of being silently dropped or coerced. Unknown entries report
  `LIBRARY_UNKNOWN_ENTRY` instead of `QUERY_ERROR`.
- Deprecated library aliases accept and validate their target's parameters.
- The audit log is written from the command Click actually dispatches,
  instead of a token search over raw argv. Every accepted syntax (`--`,
  clustered short flags, `--opt=value`) is covered; an argument equal to a
  command name (`xdr hunt run update`) is no longer logged; `--help` and
  argument errors, which dispatch nothing, are no longer logged; and
  `--refresh-token` values are redacted as in the session recorder.
- The hunting fallback calls Defender for Endpoint's documented
  `api/advancedqueries/run`, whose delegated permission is the
  `AdvancedQuery.Read` the README asks for, instead of the Defender XDR
  `api/advancedhunting/run`, which Microsoft documents with
  `AdvancedHunting.Read` under a different API. The request and response are
  unchanged.
- Library parameter validation reuses the renderer's type checks, so invalid
  dates, durations, and integers fail with `LIBRARY_INVALID_PARAM` and a
  `help_command` instead of a generic `QUERY_ERROR`.
- `library show` and `library list` describe a deprecated alias with its
  target's parameters, tables, and cost hint, matching what it runs.
- README gains a "Built to improve with use" section describing the local
  improvement loop that already exists: automatic session recording,
  `--rationale`, learning mode with `xdr annotate`, append-only agent and
  analyst feedback at session end, and `xdr history stats` failure and
  library-coverage metrics.
- README now describes `xdr auth login` accurately (WAM on Windows, browser
  elsewhere, device code only when neither can start), adds the Windows
  broker redirect URI to setup, documents `xdr lists init`, the `--rationale`
  global flag, and the real scope of `~/.xdr-cli/audit.log`, and lists every
  exit code.
- Troubleshooting references the error codes the CLI actually emits
  (`PERMISSION_MISSING_SCOPE`, not `FORBIDDEN`; `AUTH_LOGIN_REQUIRED`, not
  `TOKEN_EXPIRED`) and describes `PERMISSION_DENIED`, `CLI_COMMAND_FAILED`,
  and non-interactive confirmation behaviour correctly.
- `docs/schema_graph.md` gained the bundle guarantees, `repair-overlay` /
  `migrate-cache` behaviour, and the `validate-core` command-map row that
  previously lived only in the README.
- Help text and comments that pointed at removed README sections now point
  at `docs/device_timeline.md` (`xdr auth portal-login --help`,
  `xdr device timeline --help`, AGENTS.md).
- Launch documentation reconciled with 0.11.0: local-first discovery,
  automatic session-end upkeep, output contracts, and evidence retention.

### Fixed

- `investigate` no longer treats an IP address reported as a device name
  (Defender for Identity does this for hosts it cannot resolve) as a device:
  the address is recorded as an IP, and no process-tree hunt or isolation
  command is suggested for it.
- Isolation suggestions for a device without an MDE ID carry a
  `resolve_command` (`xdr device show <host>`) and print it, instead of a
  bare `<device-id>` placeholder.
- In learning mode, a command refused by the gate is no longer the target of
  the next `xdr annotate`. It was recorded as a new unannotated invocation,
  so annotating cleared the refusal and left the gate closed. Refused
  attempts are now recorded with `learning_gate_refused: true` and are never
  pending.
- The README's admin-consent step named Security Administrator, which cannot
  grant tenant-wide consent. It now names Cloud Application Administrator,
  Application Administrator, or Privileged Role Administrator.
- `default_limit` in `config.toml` is now the default for `incidents list`
  and `alerts list --limit`; it was previously ignored.

### Added

- `docs/device_timeline.md`: the unofficial device-timeline feature and portal
  authentication, moved out of the README and corrected.
- `docs/library.md`: every packaged KQL query with tier and parameters, the
  parameter contract and its error codes, and custom-query format.
- `docs/troubleshooting.md`: long-form troubleshooting and the exit-code table.
- `docs/media/investigate.gif` (with its asciinema source) recorded against a
  demo tenant, with tenant, object, and local-path identifiers replaced for
  publication.

### Removed

- References in the documentation and library descriptions to releases that
  predate this repository.

## [0.11.0] - 2026-10-04

### Added

- Explicit session end refreshes missing/stale physical schema, validates saved
  overlaps, and explores new locations in the foreground. Exploration defaults
  to `schema_explore_max_queries = 5` per end; refresh and exploration have
  individual switches. `schema_collect_on_session_end = false` disables all
  stages. Automatic retirement never collects, and maintenance failures leave
  the session safely closed.
- Local-first schema discovery recovers field origins from saved KQL and indexes
  identifier overlap across differently named fields in private tenant artifacts.
- `schema collect --local-only` publishes local evidence without tenant queries;
  focused validation reuses saved identifiers and recent results.
- Saved result metadata includes recoverable per-column lineage.
- Identifier-led exploration discovers new fields and nested JSON paths using
  typed query results, exact value matches, and reusable private evidence.

### Changed

- Removed `session end --prompt-feedback`; use the closure receipt's feedback
  command. `schema collect --source` now requires `--explore`, and
  `--max-queries-per-page` is a total per-invocation query budget.
- Session-end cancellation returns 130 after durable closure. Expected scope
  exclusions are reported separately from incomplete or failed eligible work.
- Session end flushes closure and feedback instructions before maintenance, then
  emits a separate terminal maintenance record; incomplete upkeep returns exit
  14. Added `--no-maintenance` and a configurable 90-second overall deadline
  capped at 3,600 seconds. Progress respects automatic quiet mode for pipes.
- Automatic evidence retirement now follows explicit result-pruning cutoffs and
  cannot be recreated by mining the same old artifacts. Explicit observation and
  proposal evidence remains protected.
- Untested local overlaps have low confidence. Generic vocabulary and malformed
  seeds are excluded, while strong empirical evidence retains ranking priority.
- Pending discovery work runs before stale refreshes across daily budget windows;
  KQL verbatim strings preserve projection lineage and malformed literals fail
  closed. Oversized seed batches split instead of aborting all discovery.
- `schema collect` now mines local artifacts before querying the tenant. Broad
  identifier-led exploration requires `--explore`. Local validation saves progress
  after each bounded query batch.
- Removed `schema collect --exhaustive`; use `--explore` for identifier-led
  discovery, replacing the six-field starter matrix and target-field sweep.
  Query budgets pause remaining work; result caps and depth limits are explicit
  coverage gaps.
- Removed `schema collect --resume`, the legacy collection executor, checkpoint
  status, and checkpoint bundle support. Rerunning current collection commands
  continues remaining work using their saved query evidence.
- Navigation prioritizes empirically validated and observed pivots over authored
  catalog status. Overlap remains correlation evidence, not a join assertion.

### Fixed

- Expected timeless tables and unsupported paths no longer force every session
  end to return partial success. Validation can reverse a pair when only its
  other endpoint supports a time bound.
- Single coincidental overlaps remain candidates; tenant-wide and built-in
  constants are excluded from discovery. Overlapping cohorts cannot count twice
  toward validation, and future-dated artifacts cannot establish freshness.
- Bounded JSON and KQL lineage handling preserve useful hunt results when
  optional discovery parsing cannot process a cell or expression. Free-text JSON
  no longer manufactures dynamic fields.
- Retention indexes metadata once per publication and contains malformed
  automatic references without weakening explicit observation/proposal pins.
- Opposite-direction observations now aggregate into a single bidirectional pivot
  rather than preventing tenant graph composition.
- Preserve reproducible column lineage through JSON expressions and skip malformed
  identifiers without aborting local discovery.
- Revalidate changed time windows or seed cohorts, retire invalid local evidence,
  and support projected evidence in candidate review.
- Reuse verified evidence within each discovery report and serialize tenant
  collection to avoid redundant reads and concurrent duplicate queries.
- Preserve underlying authentication recovery details in session-end receipts.


## [0.10.0] - 2026-09-30

BloodHound readability update for the OpenGraph schema export.

### Added

- `schema export-opengraph` now links tables directly with `Join`,
  `NormalizeJoin`, `SameEntity`, `Correlate`, and `Bridge` edges, one per table
  pair and pivot kind, so
  ``MATCH p=(:XDR_Table)-[:`Join`|NormalizeJoin|SameEntity|Correlate|Bridge]->(:XDR_Table) RETURN p``
  draws a table-level pivot map. Each edge lists the field pairs and
  relationship IDs it summarizes. Queries that match every relationship from a
  table, such as `MATCH (:XDR_Table)-[r]->()`, now also return these edges.
- `schema export-opengraph --custom-nodes PATH` writes the request body for
  BloodHound's `POST /api/v2/custom-nodes`, giving tables, fields, entity kinds,
  and namespaces their own icon and color. xdr-cli does not contact BloodHound.
- Every exported node has a short `name` property (table name, column, entity
  kind, or namespace), which BloodHound uses as the canvas label ahead of the
  long `displayname`.

### Fixed

- Updated locked PyJWT from 2.14.0 to 2.15.0 to address
  GHSA-42vr-xj54-vc7v, an unhandled exception when parsing certain JWT payloads.
- Both OpenGraph output files are staged before either is published. A later
  styling-publication failure reports the saved graph and failed path with
  partial-success exit 14.
- Table summaries use the weakest member evidence and expose mixed statuses,
  confidence levels, candidate counts, and directions. Candidate keys cannot
  inherit reviewed status or traversability from another member.
- Overlapping direction groups merge into one edge per start/end/kind instead
  of emitting duplicate table edges.
- Table-map examples quote `Join`, a reserved word in BloodHound CE's Cypher
  parser.

## [0.9.0] - 2026-09-03

Autonomous semantic-crawl and empirical-pivot update following live-tenant
validation of the initial graph workflow.

### Added

- `schema discoveries` reports automatically usable `observed` and
  machine-`validated` investigation pivots; `schema candidates` remains a
  compatibility alias.
- `schema collect --resume` persists a tenant-bound crawl checkpoint, while
  `schema observe` exposes pinned `--from-run`, `--start-query`,
  `--max-queries`, and `--schema-generation` continuation controls.
- Repeatable `--target-table` and `--exclude-table` filters support narrow
  retries and explicit coverage exclusions.
- Pivot, path, and OpenGraph output expose evidence level and join safety, with
  BloodHound examples for direct and multi-hop schema traversal.

### Changed

- Compatible scalar targets on the same table share one bounded table scan,
  eliminating the prior field-by-field rescans that made exhaustive crawls
  impractical on wide tables.
- Target-local API, query, and timeout failures are quarantined with exact task,
  table, locator, and retry details while collection continues across the
  remaining tables and source locators. Authentication and rate-limit failures
  still stop globally.
- A completed positive observation is immediately available as a
  correlation-only investigation pivot. Two independently sampled,
  artifact-verified positive runs can advance it to `validated` under the
  versioned tenant search-pivot policy.
- Automatic empirical evidence never claims raw equality-join safety,
  cardinality, a bridge, or repository-reviewed semantics. Optional private
  context review and contributor proposals remain available for ambiguous
  investigations or independently contracted core changes.
- Schema help, README guidance, and the detailed graph guide now distinguish
  routine target caps from exhaustive all-table coverage and document paging,
  resume, quarantine, evidence levels, and current BloodHound behavior.
- Deprecated `hunt library` and `hunt library-run` aliases remain available
  through the 0.x line for compatibility and now advertise removal in 1.0.
- Release CI now validates the latest three stable Python feature releases
  (3.12–3.14), with Windows state-portability coverage running on Python 3.14.
  The declared Python 3.11 minimum remains unchanged.

### Fixed

- Generated semantic-probe KQL now uses Defender-compatible `let` identifiers,
  preventing live crawls from quarantining otherwise valid target-table pages.
- Library parameters are now rendered through typed, quote-aware KQL literal
  encoding, preventing tenant-controlled entity values from changing a built-in
  or user-library query's syntax.
- `config.toml`, token caches, and stored portal cookies use private atomic
  persistence; MSAL cache acquisition is serialized across processes so
  concurrent commands cannot lose refresh-token or audience-cache updates.
- Portal cookies are bound to the configured tenant, and cookie-authenticated
  MachineIds are verified through that tenant's official MDE API before portal
  events are accepted. Cookie-source cleanup refuses symlinks and rechecks the
  validated file identity before overwrite.
- Schema collection children now run with isolated module search paths, finite
  process deadlines, and concurrently drained 1 MiB control-output caps;
  timeouts remain resumable from the existing checkpoint.
- Explicit device-timeline exports publish atomically with owner-only
  descriptor-backed staging, reject unsafe shared directories, refuse existing
  paths by default, and replace symlink entries rather than following them when
  `--force` is intentional.
- Incident update/comment split failures report non-retryable partial success
  with an inspection-and-comment-only recovery path, preventing accidental
  replay of an already-applied field update.
- OData list filters encode apostrophes and validate closed severity/status
  vocabularies before sending requests.
- OpenGraph exports use unique owner-only temporary files, avoiding stale-file
  and concurrent-export collisions.
- Removed the nonexistent Typer `all` extra from package metadata while keeping
  the tested Typer 0.24 compatibility range.
- Completed observations retain their actual matched/no-match outcomes when a
  different target table fails instead of being downgraded wholesale to
  partial evidence.
- Observe continuations reuse the exact sampled or explicit source artifact and
  every post-refresh page is pinned to one physical-schema generation,
  preventing resampling drift and mixed-generation evidence.
- Resumed and imported collection checkpoints enforce their complete plan
  contract and may invoke only the expected read-only schema child commands.
- Effective graph composition reopens tenant-bound source and target artifacts
  before granting `validated`; imported or edited metadata cannot self-assert
  machine validation.
- Corrected stale command references and examples throughout schema docstrings,
  `--help`, diagnostics capabilities, README, and the detailed graph guide.

## [0.8.1] - 2026-08-12

Semantic schema graph release-hardening update following live-state and
adversarial bundle validation of `0.8.0`.

### Changed

- Semantic probes match normalized identifier values across tables while using
  Defender `Timestamp` or Sentinel/workspace `TimeGenerated` only as independent
  lookback bounds. Tables without either remain excluded rather than producing
  unbounded or misleading evidence.
- Schema collection and OpenGraph documentation now distinguish the six default
  reviewed source locators from the full eligible target catalog, and document
  BloodHound Quick Upload, source replacement, and Cypher visualization for
  public, tenant, and candidate layers.
- Bundle help and documentation now describe SHA-256 and tenant fingerprints as
  integrity/routing checks rather than archive-authenticity proof.

### Fixed

- Portable bundle inspection/import now enforce exact schema, result, proposal,
  and inactive-session namespaces plus sensitivity bindings; unsigned archives
  cannot inject configuration, query-library, auth-adjacent, or other live
  xdr-cli state.
- Tenant overlays cannot self-assert repository-reviewed relationships through
  import or effective graph composition; tenant-only relationships remain
  candidates until code review.
- Bundle export validates size and content before publication, leaves no
  rejected output, creates owner-only POSIX archives, and preserves collision
  refusal and rollback on filesystems without hard-link support.
- Read-only bundle inspection streams bounded headers and payloads without
  retaining archive contents, and imported session history must satisfy exact
  filename, JSONL, and counter-sidecar contracts.
- Maintenance advisories honor automatic pipe quieting and use fixed-cost
  current markers instead of scanning growing result/observation history on
  every unrelated command.
- Corrected attachment-to-message and image-load-event-to-device-inventory
  cardinalities to `many-to-one` in their stored direction.
- OpenGraph node IDs now preserve readable table, field, entity-kind, and
  namespace names because BloodHound uses the root ID as the graph's visible
  object label; sanitization-only collision suffixes replace always-opaque
  SHA-256 IDs.
- Added a dedicated Windows CI job for bundle, cache, overlay, command, and
  session portability contracts.

## [0.8.0] - 2026-08-11

Semantic schema graph and correlation release.

### Added

- `schema diagnostics` exposes package/source identity, registered schema
  capabilities, passive-ingestion outcomes, evidence eligibility, and
  maintenance state without tenant access.
- `schema migrate-cache --yes` content-binds a structurally valid pre-digest
  physical cache while preserving its original metadata in quarantine.
- `schema bundle export`, `schema bundle inspect`, and `schema bundle import`
  provide content-bound schema-state relocation with same-tenant activation,
  evidence/proposal path rewriting, optional inactive session history,
  collision refusal, and rollback on interrupted publication.
- Packaged semantic graph and an explicitly scoped Microsoft E5-oriented
  reviewed starter profile with typed pivots, direct joins, transforms,
  bridge-table paths, correlation-only relationships, deterministic path
  traversal, and OpenGraph export.
- `schema observe` with explicit exhaustive tenant-locator planning, safe
  default bounds, counts-only batched
  probes, private provisional interpretations, partial-success publication,
  and candidate-only learning.
- Cache-only `schema candidates` evidence triage with automated sufficiency
  gates, explicit human-context requirements, and no bulk promotion path.
- `schema status` plus bounded `schema collect` maintenance, with a nonblocking
  periodic stderr advisory and explicit exhaustive mode.
- Native `schema export-opengraph` for public or value-free tenant overlays;
  repository Python scripts remain contributor/UAT tooling.
- Bounded `schema candidate-review`, private `results head`, and
  reference-aware schema/result pruning complete the candidate evidence
  lifecycle without adding a bulk approval path.
- Lineage-validated offline artifact correlation with relationship-path safety
  metadata, lossless reviewed nested JSON locators, privacy-filtered passive
  paths, private tenant overlays, and purpose-built live-validation tooling.

### Changed

- `schema status` now reports physical integrity, semantic-overlay integrity,
  packaged-contract compatibility, collection state, passive ingestion, and
  observations inside versus outside the 90-day readiness horizon separately.
- `schema repair-overlay --yes` now quarantines exact prior artifacts and
  publishes a loss-aware compatible generation when packaged contracts change;
  obsolete provisional interpretations and dependent observations are
  inactivated rather than silently reinterpreted.
- Result sidecars can passively register nested string paths when physical
  lineage is deterministic; ambiguous projections, joins, and legacy paths
  fail closed.
- Result sidecars now carry tenant fingerprints and data digests; offline
  correlation verifies both plus exact registered paths and row counts.
- Physical schema availability, semantic pivot compatibility, and reviewed
  join safety are now represented and documented as separate claims.

### Fixed

- Legacy `sha-lower` provisional interpretations no longer conflict with the
  current `sha256-lower` packaged source during collection planning.
- Legacy passive nested fields that fail the current reviewed key policy are
  excluded from availability, probing, traversal, and correlation.
- Result and candidate-proposal registrations are safely relocated during
  portable import instead of requiring manual absolute-path edits.
- Bundle inspection now bounds aggregate uncompressed bytes before extraction,
  bundle publication refuses concurrent destination creation atomically, and
  optional session-history imports coordinate with live session counters.
- Semantic source sampling uses Advanced Hunting-compatible deterministic
  ordering; batched probes avoid cross-union scalar scope assumptions, malformed
  sampled identifiers fail soft, and the live-validation collector bounds
  validation fan-out while prioritizing reviewed mappings. Collection progress,
  sanitized diagnostics, and an explicit sensitive-debug mode make live probe
  failures attributable without weakening the default value-free bundle.
- Observation publication accepts the numeric-leading generation IDs emitted by
  `schema refresh`, and source sampling over-fetches candidates so malformed
  rare UPN placeholders do not crowd out valid identifiers.
- Schema path rows now distinguish direct joins, multi-hop join chains, and
  sequential pivots with explicit route kind, hop count, and join-compatibility
  fields while retaining the existing `DirectJoin` contract.
- Passive nested-field learning now uses a reviewed property allowlist and
  rejects every projection variant, preventing tenant values or renamed fields
  from entering value-free lineage. Tenant overlays round-trip relationship
  records instead of publishing generations their loader cannot read.
- Candidate readiness now requires distinct evidence bundles and non-empty
  context, mixed-invalid retained samples fail soft, and a failed later batch
  marks the whole observation run partial. Empty or unavailable routine sources
  no longer prevent otherwise complete maintenance.
- Private result previews verify bundle identity, digest, row type, and count;
  result pruning aborts before deletion when any current schema overlay cannot
  be validated.
- Candidate readiness now rebinds each claim to the exact source artifact,
  selected-seed count, target interpretation, probe batch, and independently
  distinct source/target bundles. Collection preserves empty-source outcomes
  and relaunches portably under both console-script and `python -m` invocation.
- Tenant overlays now bind generations to content digests. `schema status`
  diagnoses integrity state and `schema repair-overlay --yes` atomically selects
  the newest valid retained generation or migrates legacy metadata.
- `schema validate-core` gives the human-reviewed core-graph update lifecycle a
  native graph/profile and generated-document validation command; it can update
  only the generated reference block when explicitly requested.
- Overlay recovery now detects missing manifests, repairs all local tenant
  overlays, and offers an explicit quarantined empty reset when no generation
  is usable. Result pruning and overlay publication share an evidence lock.
- Core-document validation rejects unmatched, duplicate, or reversed generated
  markers with a structured corrective error instead of mutating the file.
- Probe plans now carry canonical field dependencies for provisional
  interpretations, and passive nested learning reuses exact packaged records
  while correctly marking tenant-observed paths available.
- Result pruning validates exact bundle identity, evidence pruning rejects stale
  generation replacement, and normal evidence-lock contention is retryable and
  actionable.
- Physical schema cache generations now validate exact bytes, digest, identity,
  and row count in both consumers and maintenance status. Result discovery
  exposes copyable physical `Table=RUN_ID` correlation inputs.
- Candidate evidence validation preserves each observation's source/target
  direction, and persisted provisional interpretations can no longer masquerade
  as reviewed probe targets.
- Windows schema refreshes now write the exact LF bytes recorded by cache
  integrity metadata, and a best-effort old-generation cleanup cannot turn an
  already committed tenant overlay into a reported publication failure.
- Collection planning preflights its cache once and returns the exact bounded
  collection command to run. Aggregate collection artifacts retain both a
  partial child's saved run ID and sanitized actionable failure details.
- Candidate readiness is computed from independently verified evidence only;
  incomplete, missing, or provenance-mismatched historical observations remain
  explicit concerns without poisoning later sufficient evidence.
- Source sampling and candidate review preserve the KQL's rare-first ordering
  when normalizing identifiers. Probes reject or exclude tables without
  `Timestamp`, so an unbounded query cannot claim a bounded evidence window.
- `results rows --type ... --offset ...` makes late correlation match records
  inspectable through the CLI, and correlation receipts link to that view.
- Evidence-ready candidates can produce a deterministic, value-free
  `candidate-proposal` packet only after the analyst supplies explicit
  relationship semantics and provenance; it never edits the core graph. The
  proposal cannot shadow reviewed/deprecated core semantics, requires an actual
  contract/documentation citation for join or bridge claims, and atomically
  binds its exact evidence-generation snapshot and proposal-file bytes. Extant
  proposal drafts protect their verified receipt and referenced evidence from
  result pruning; digest, snapshot, path, row, or binding mismatches stop
  pruning instead of trusting altered references.
- Core-graph upgrades reconcile retained tenant fields/interpretations when
  their stable semantic contracts are identical and only private/provisional
  annotations differ, both during effective composition and subsequent overlay
  publication. Real type, locator, namespace, role, normalizer, constraint, or
  relationship conflicts still fail closed.
- Artifact receipts now state preview `shown`, `total`, and `has_more` and
  provide an exact `results rows` reader whenever the two stdout previews are
  incomplete. Nested `schema pivot` inputs canonicalize documented dotted
  shorthand before traversal.
- The immediately preceding four-key candidate-proposal sidecar remains
  upgrade-safe: intact live drafts are row-verified and conservatively retain
  evidence, while deleting a retired draft releases it without a permanent
  prune integrity error.
- Live proposals now cause result pruning to open and fully validate every
  referenced source, target, and review bundle, including tenant, stage, and
  cross-reference bindings. Missing or corrupt evidence stops deletion.
- Explicit file/stdin seeds now receive zero-preview private source artifacts,
  participate in deterministic readiness validation, and remain clearly marked
  for origin review. Candidate review falls back past invalid newer evidence.
- Effective graph conflicts now return an actionable schema conflict instead of
  a generic internal error, and tenant observation extensions survive overlay
  rewrites for forward compatibility.
- Incomplete receipts expose `results_command` separately from workflow
  `next_command`, so collection guidance cannot hide the complete local result.
- Missing `Timestamp` preconditions now use one actionable conflict exit/code
  across source sampling and candidate review instead of masquerading as an
  artifact-write or invalid-argument failure.

## [0.7.4] - 2026-07-31

### Changed

- Operational, contributor, security, schema, and foundation-design Markdown
  now matches the shipped artifact/session/discovery contracts and avoids
  treating schema availability as proof of table population or licensing.
- Examples now consume complete compact output safely, distinguish pre-artifact
  timeouts from successful result provenance, and use the validated portal
  cookie path for device-timeline quick starts.

## [0.7.3] - 2026-07-31

Windows session-concurrency remediation release.

### Fixed

- File-backed locks now combine the existing cross-process sidecar lock with
  a per-path in-process mutex, preventing concurrent Windows threads from
  entering the same marker-update critical section.
- Atomic session-marker publication now retries brief Windows sharing
  violations with a bounded backoff while continuing to surface persistent
  access failures.
## [0.7.2] - 2026-07-31

Windows UAT remediation release for the artifact-first foundation.

### Fixed

- Built-in and user KQL files now decode explicitly as UTF-8, preventing
  Windows ANSI code pages from corrupting query descriptions and content
  before they reach library artifacts or execution.
- Cross-platform credential and audit-log tests retain their functional
  coverage on Windows while limiting Unix mode-bit assertions to POSIX,
  where the `0600` contract is meaningful.

## [0.7.1] - 2026-07-31

Focused live-tenant remediation release for the artifact-first foundation.

### Added

- `xdr device timeline --hours N` for narrow pulls on high-volume devices;
  `--hours` and `--days` are mutually exclusive and the default remains seven
  days when neither is specified.

### Fixed

- Result storage now enforces private POSIX modes on the config home and every
  results directory (`0700`) as well as generated and explicit timeline files
  (`0600`).
- Portal-cookie verification now checks HTTP success without requiring a
  dict-shaped response, and portal login-timeout responses (HTTP 440) map to
  the authentication recovery path (exit 2) with valid `xdr auth ...` commands.
- Main authentication errors no longer suggest the nonexistent `xdr login`
  command.

## [0.7.0] - 2026-07-31

Breaking pre-1.0 foundation release based on sanitized Copilot-workflow
analysis.

### Added

- Private artifact-first result bundles under
  `~/.xdr-cli/results/YYYY-MM-DD/`: data-only JSONL, provenance/observed-shape
  sidecars, compact receipts, bounded previews, atomic writes, and explicit
  `results list/show/query/shape/prune` lifecycle commands.
- One-line versioned corrective errors with stable codes and distinct recovery
  exits for usage, permission, not-found, throttling, timeout, network,
  artifact, conflict, and partial-success failures.
- Automatic 30-minute session attachment, incident/alert anchors,
  nonblocking ambiguity, explicit concurrent sessions, deterministic end
  summaries, and immutable append-only agent/analyst feedback.
- Native `library list/show/run` and cached `schema
  refresh/tables/show` discovery backed by the existing KQL catalog and
  `sys_schema_probe`.
- Typed library parameter, table, output-field, permission, and cost hints;
  bounded/searchable result-shape discovery; and visibly stale schema receipts.

### Changed

- Hunt and library execution, library listing, schema refresh/browsing,
  alert/incident list/show, investigate, and default device timeline output now
  save the complete returned dataset and write at most one receipt plus two
  previews to stdout.
- Expanded incidents, alerts, and investigations are normalized into granular
  JSONL records; partial enrichment exits 14 while retaining its artifact.
- Automatic alert sessions attach only after Graph supplies authoritative
  incident identity, and schema cache generations publish atomically.
- Sessions are optional telemetry and never gate read-only investigation work.
  The old `hunt library` and `hunt library-run` paths remain deprecated aliases
  for one release; `hunt library-show` remains the compatibility executable-KQL
  renderer while native `library show` returns a typed descriptor.
- Versioned exit taxonomy preserves codes 0–5 where accurate and adds 6–14;
  403, 404, 429, timeouts, and network failures no longer collapse into code 3.

### Removed

- Global `--fields` and native `--jq`/JMESPath projection.
- Hunt display `--limit`, which discarded locally displayed rows without
  controlling Defender API execution.
- The arbitrary synthetic `XDR_SESSION=adhoc-N` escape hatch; explicit
  attachment must name an existing session.

## [0.6.1] - 2026-07-25
Documentation-correctness release. The instructional docs (`README.md`,
`AGENTS.md`, `CONTRIBUTING.md`, `docs/`, `playbooks/`) are read directly by AI
agents and treated as contract, so each drift from the implemented CLI, query
library, and Defender schema is tracked below. Corrections were verified
against the code, and — where marked *(tenant-verified)* — against a live
Defender XDR tenant (read-only, 30 recorded invocations, 2026-07-25).

### Changed
- `--rationale` help text (`src/xdr_cli/main.py`) now reads "Captured on any
  invocation record when a session is active." The prior "silently ignored on
  session/history/annotate paths" was wrong — the flag is recorded onto any
  command's invocation record whenever a session is active.

### Fixed
**AI-agent output contract (`AGENTS.md`, `README.md`):**
- Corrected "all output is JSON": `session start`/`end`/`resume` and `annotate`
  print a plain-text line; `device timeline`/`session show` emit raw JSONL, not
  the `{status,data,metadata}` envelope. Agents branching on the envelope were
  told a contract the CLI does not emit for those commands.
- Removed the nonexistent `metadata.cpu_usage` field (quota surfaces only as
  HTTP 429); renamed `execution_time` → `execution_time_ms`; `metadata.session_id`/
  `session_label` are present only on **success** envelopes (error envelopes
  carry no `metadata`) — was documented as "always present."
- `xdr auth login` documented as interactive-first (WAM/browser) with device-code
  fallback, matching `auth.py` (was "device code flow").
- `investigate` clarified as read-only (audit-logged for traceability, mutates
  nothing) — it was listed among "state-changing commands," contradicting the
  read-only-command list two sections away.

**Device-timeline auth accuracy (`README.md`, `AGENTS.md`, `auth_cmd.py` help, and the `[0.6.0]` entry above):**
- Reframed the portal-auth story to match what is actually validated: cookie
  auth (`xdr auth portal-cookie`, a Microsoft Edge DevTools "Copy as cURL (bash)") is the
  validated, recommended method; the MSAL/FOCI `xdr auth portal-login` path is
  now marked **experimental and unverified** (it had been documented as the
  default in "Three auth paths"). Sign-in-log attribution ("Microsoft Azure
  CLI") is stated as *intended*, not verified fact, with a "confirm in your own
  tenant" caveat.

**CLI command/flag examples (`README.md`, `playbooks/`):**
- `xdr hunt run` takes a **positional** KQL argument; removed the nonexistent
  `--kql` flag.
- `xdr device isolate`/`unisolate`/`restrict` require `--comment`; added to every
  runnable playbook example and the README reference table (`scan`/`collect-package`
  do not require it). The bare form exits 2 before running.
- `api_timeout` default corrected to 120s (was documented as 30).
- Removed the nonexistent `xdr threats list` command from examples.
- README custom-query example now includes the required `-- tier:` frontmatter —
  the prior example raised `QueryError` on load.

**KQL authoring & schema (`docs/schema_pivots.md`, `docs/schema_probe.md`, `docs/investigation.md`, `playbooks/`):**
- `--` lines are repo frontmatter, not KQL comments (KQL line comments are `//`).
- `RiskLevelDuringSignIn` is an **integer**, not a nullable string — the `!in`
  guidance was wrong; the failure is a type mismatch, not nullability. *(tenant-verified)*
- `CloudAppEvents` acting user is `RawEventData.UserId` (no `AccountUpn` column);
  `GraphAPIAuditEvents` uses `IpAddress` (camelCase); removed nonexistent columns
  (`AlertEvidence.Url`→`RemoteUrl`, `EmailPostDeliveryEvents.DeliveryAction`, others).
- Exchange `Send` audit records carry no `Subject`/`Recipients` in `RawEventData`;
  the email-forwarding sent-mail check now uses `qry_email_outbound_detail`
  (EmailEvents-based) and the custom rule query gains the missing `RedirectTo`
  forwarding vector. *(tenant-verified)*
- `BehaviorId` is not unique across `BehaviorInfo`/`BehaviorEntities`. *(tenant-verified)*
- Corrected the curated-table count (63 → 80), initiating-process bundle count
  (25 → 27), and probe row-count/runtime figures; `schema_probe.md` Quick Start now
  documents the required `xdr session start` prerequisite and the JSON→CSV step.

**Library query references (`playbooks/`):**
- `qry_inbox_rule_audit` → `qry_inbox_rule_activity` (former is a deprecated alias).
- `ttp_oauth_app_signin_anomaly` / `ttp_oauth_consent_anomaly` descriptions aligned
  to the queries' actual scoring signals.
- Sign-in baseline window is 30 days (`hours=720` default), not 7; corrected param
  names and the password-spray `FailCount`/`UniqueAccounts` description.

**Contributor & security docs (`CONTRIBUTING.md`, `docs/contributing-walkthrough.md`, `SECURITY.md`):**
- Branch-protection description corrected against the live rulesets: `main` has
  two rulesets; the review-requiring one exempts the repository Admin role via a
  bypass actor (was "no bypass actors" / "self-merge not possible"), and required
  status checks (lint-and-test 3.11/3.12/3.13, version-bump/CHANGELOG, GuardDog)
  are enforced. *(verified via `gh api`)*
- A new flag is a MINOR bump, not PATCH (walkthrough examples 0.4.1 → 0.5.0).
- Fixed `SECURITY.md` source path (`src/xdr_cli/commands/auth_cmd.py`) and the
  private-vulnerability-reporting steps; corrected a nonexistent test path
  (`tests/test_domains_cmd.py`) and the Keep-a-Changelog category list.

**CLI help strings & docstrings (`src/xdr_cli/`):**
- Audited every `--help` string and command docstring against the code and fixed
  15 drifts (the review had only covered the markdown docs, not the CLI's own
  self-description). Examples: the `incidents` output-schema status enum was
  missing `inProgress` and "list active" actually lists all incidents;
  `--determination` help now enumerates the accepted values (was a circular "see
  `--help`"); `investigate`'s containment-gate docstring omitted the
  `informationalExpectedActivity` exclusion; `hunt --timeout` referenced a
  nonexistent "summary tier" (`summary` is a mode); a stale
  `xdr history --anchor-incident` reference (the real flag is `--incident`); and
  `history --by-actor` help now matches the actual JSON shape (the
  `cpu_usage_total_by_actor` sibling key).

**Cross-file consistency & housekeeping:**
- Removed a dead cross-reference to a nonexistent `usb-worm-malware.md` playbook;
  fixed ordered-list numbering (`playbooks/README.md`, `email-malicious-delivery.md`);
  standardized "Microsoft Entra" branding; documented the `--ttl` weeks unit.

## [0.6.0] - 2026-07-24
### Added
- `xdr device timeline <hostname-or-id>`: paginated download of Defender for
  Endpoint device timeline events via the unofficial
  `security.microsoft.com/apiproxy/mtp/mdeTimelineExperience` endpoint. Extends
  visibility to ~180 days, beyond Advanced Hunting's 30-day retention.
  `<device>` is resolved to a MachineId via the official MDE `machines` API
  first; only the timeline fetch itself uses the unofficial portal apiproxy.
  The validated auth path is cookie auth (`xdr auth portal-cookie`): paste the
  browser `Cookie` header from a logged-in Defender portal session — a Microsoft
  Edge DevTools "Copy as cURL (bash)" of the timeline apiproxy request — which
  reuses your
  existing portal session. A separate MSAL/FOCI path (`xdr auth portal-login`,
  Azure CLI public client, isolated from xdr-cli's main app registration) also
  exists but is **experimental and unverified**: it may not succeed in every
  tenant, and its Entra sign-in-log attribution has not been confirmed.
  `--refresh-token` (env `MDE_REFRESH_TOKEN`) is supported for CI. Output is
  raw JSONL — one event per line, NOT the standard `{status, data, metadata}`
  envelope other commands use — to stdout or `--output PATH` (optional
  `--gzip`); a one-line event-count summary prints to stderr.
- `xdr auth portal-login` / `xdr auth portal-cookie` / `xdr auth portal-logout`:
  manage the separate portal auth. `portal-cookie COOKIE_SOURCE` — **the
  validated method** — takes the whole browser `Cookie`
  header from a file (or `-` for stdin) — a saved Microsoft Edge DevTools "Copy
  as cURL (bash)" of the timeline apiproxy request, or a raw Cookie header — and
  stores it in
  `~/.xdr-cli/portal_cookies.json` (0600), with an optional
  `--verify`/`--no-verify` live apiproxy check; cookie values never reach argv.
  It forwards every cookie verbatim — including the routing
  (`X-PortalEndpoint-RouteKey`) and session (`s.SessID`) cookies the apiproxy
  backend requires (whose absence the backend answers with an opaque HTTP 500)
  and a chunked `sccauth` (`chunks:N` + `sccauthC1`…`sccauthCN`) — and
  auto-extracts the XSRF token (prompting only if the header carries no
  `XSRF-TOKEN` cookie). A file/stdin source is required rather than a hidden
  prompt because the full header runs past the ~4 KB a terminal accepts on one
  line. On a successful import the source **file is securely shredded by
  default** (it holds a live bearer credential); `--keep-source` opts out. A
  source with no `sccauth` cookie is rejected and never shredded, so a mistyped
  path can't be turned into a file wipe. The portal client
  now sends browser-parity `Accept`/`Accept-Language` headers and an `xdr-cli`
  User-Agent (not the default `python-httpx`), and surfaces the failing
  request path (with its `fromDate`/`toDate`/`skipToken` query) plus the
  apiproxy error response body — or routing/correlation headers on an
  empty-body 5xx — in `APIError.detail` so failures are diagnosable.
  `portal-login` attempts an interactive FOCI/MSAL sign-in (Azure CLI public
  client) as an **experimental, unverified** alternative to cookie auth.
  `portal-logout` clears both the portal MSAL token cache and the cookie store,
  independent of `xdr auth logout`.
- `xdr auth status`: now reports both main and portal auth state, including
  the active portal `method` (`msal` or `cookie`) and its `audit_app_name`
  label ("Microsoft Azure CLI" for MSAL, "Microsoft Defender portal (browser
  session)" for cookie). The label reflects the client each method
  authenticates as; how portal activity actually surfaces in Entra sign-in
  logs has not been independently verified.

### Fixed
- `xdr device timeline`: pagination silently truncated to the first page
  (~1000 events) on any device with more history, ending with a spurious 404.
  The apiproxy's `Next` link is a path **relative to the `mdeTimelineExperience`
  endpoint** (e.g. `/machines/<id>/events?…&ReportIdForScrolling=…`) and does
  not repeat that segment; the follow-up request merged it against the base URL
  alone, hitting `/apiproxy/mtp/machines/<id>/events` (segment dropped) → 404.
  The endpoint segment is now re-added when following `Next`, mirroring the
  reference downloader, so the full requested range is retrieved. `Next` is
  also now followed with its query string preserved byte-for-byte (a decode/
  re-encode round-trip would have corrupted a base64 `skipToken`'s literal
  `+`). The initial request now also sends `IsScrollingForward=true` so the
  apiproxy pages forward from `fromDate` through the whole window; without it
  the apiproxy returned only the newest page and a forward-to-now cursor that
  terminated immediately, truncating history to the first ~1000 events.
- `xdr device timeline --from`/`--to`: now accept the RFC3339 forms the help
  documents — a trailing `Z` (UTC) or a numeric offset (e.g.
  `2026-07-24T21:00:00Z`, `…-05:00`). Previously only naive forms parsed, so
  the documented `Z` suffix was rejected client-side.
- `xdr device timeline --to`: is now an exact upper bound. Forward-scroll
  pagination overshoots `toDate` within the final fetched page (the apiproxy
  bounds pagination, not individual events), so events after `--to` are now
  filtered out; previously the last page could return events well past the
  requested cutoff. (No effect on the common `--days` case, where `--to` is
  now.)
- The audit log (`~/.xdr-cli/audit.log`) is now created mode `0600` instead of
  the `FileHandler` default (~`0644`); it records command history and should
  not be world-readable, matching the cookie/token stores.

### Documentation
- `device timeline` help + README now document the identifier mapping: the
  `device` argument is a `DeviceName` (hostname) or a 40-hex `DeviceId`, the
  portal timeline's `MachineId` **is** Advanced Hunting's `DeviceId` (and the
  hostname is `DeviceName`, verified against live data), and each event carries
  the pair under `Machine.MachineId` / `Machine.Name` — so a timeline pivots
  into the `Device*` Advanced Hunting tables on `DeviceId`, with the full table
  list and a KQL pivot predicate in README §"Device Timeline".

### Notes
- The portal API surface used by `device timeline` and the `portal-*` auth
  commands is undocumented and unstable. Microsoft may break this at any
  time. See `README.md` §"Device Timeline" for the trade-offs, including
  audit-attribution and compliance considerations.

## [0.5.2] - 2026-07-23
### Fixed
- **Silent supply-chain coverage hole:** `scripts/filter_guarddog.py` read only
  GuardDog's `results` and ignored per-package `errors`, so a scan whose rules
  failed to run (e.g. semgrep missing) reported "clean" and exited 0 while
  having scanned nothing. The filter now fails closed on any rule-run error.
- **"Clean" now requires proof that a scan happened.** `filter_guarddog.py`
  additionally fails closed on an empty payload (what GuardDog emits, exit 0,
  for an empty requirements file), on a package whose `result`/`results`/
  `errors` is missing or not a mapping, on a package whose `results` mapping is
  empty, and — via the new `--closure` argument, passed by both workflows — on
  any package listed in the scanned closure that never appears in the output.
  GuardDog silently drops requirements it cannot resolve and still exits 0, so
  a partial scan previously read as clean.
- **Allowlist matching could bless more than it was given.** One entry now
  forgives exactly one finding (matching consumes it), so a second identical
  finding injected at a new line is no longer accepted; metadata findings
  (`bundled_binary`, `single_python_file`, …) key on their message, so one
  entry no longer blesses any future set of bundled binaries; duplicate YAML
  keys are rejected instead of silently discarding the entries under the first;
  a leftover `TODO` reason is rejected; `file`/`code`/`reason` are type-checked
  (YAML coerces `code: 12345` to an int) instead of raising `AttributeError`;
  and snippet normalization keeps line boundaries, so a multi-line span
  re-flowed onto fewer lines is no longer the same key.
### Changed
- GuardDog now scans a pinned closure (`.github/guarddog-scan-closure.txt`)
  instead of a live `pip freeze`, so the required check only moves when a PR
  moves it — not when PyPI drifts. Same 35-package population as before
  (audited: zero added, zero removed); `pyproject.toml` keeps its `>=` ranges,
  so end-user resolution is unchanged.
- The GuardDog allowlist is now structured `(package, rule, file, code)`
  entries instead of `file:line` strings: line-agnostic, so upstream line
  moves no longer break CI, but still file-anchored, so a blessed line
  relocated into a new path is re-reviewed. Entries are emitted/parsed via
  `yaml.safe_dump`, making snippets with quotes, backslashes and unicode safe.
  Several justifications were corrected against the code actually flagged.
- The GuardDog scan output is no longer cached at all. A required security gate
  must not be satisfiable by a stored artifact: a cache hit skipped the scan, so
  a planted JSON blob could pass the check, and with the closure hash now
  deliberately stable the scan could have gone unrun for months while
  GuardDog's live-state rules (typosquatting, maintainer domains) never
  re-evaluated.
- `uv` in the supply-chain watch workflow is now hash-pinned
  (`.github/uv-requirements.txt`); pinning the resolver does not stale the
  resolution, since `uv pip compile` still queries the live index. Both GuardDog
  jobs carry `timeout-minutes: 20`, and `ci.yml` declares a top-level
  `permissions: contents: read`.
### Added
- `.github/workflows/supply-chain-watch.yml` — a weekly, off-gate scan that
  compiles the closure fresh from `pyproject.toml` and scans that live
  resolution. The pinned scan cannot see newer versions developers actually
  install, so this restores that zero-day coverage as early warning without
  blocking merges.

## [0.5.1] - 2026-07-23
### Changed
- `version-and-changelog` CI job skips the version-bump and CHANGELOG checks
  for PRs whose entire diff is under `.github/` — unblocks dependabot PRs.
  Nothing under `.github/` ships; a diff touching any file outside it still
  gets the full policy. Detection fails closed (bad base SHA fails the job;
  renames out of the shipped tree still count as shipped).
- CONTRIBUTING §1/§4/§5 updated to match; `.github/` workflows and guarddog
  config added to §4's higher-risk always-wait-for-review list as the
  compensating audit control.
- Aligned the PR template, `docs/contributing-walkthrough.md`, and
  CONTRIBUTING §4/§7 with the `.github/`-only exemption; corrected the
  branch-protection description to reflect the active `main` ruleset.

## [0.5.0] - 2026-07-20
### Added
- `sys_schema_probe` now covers 17 confirmed Microsoft Sentinel and Entra
  workspace tables, including Entra sign-in/audit logs, Sentinel incidents and
  alerts, and workspace health data.

### Changed
- The schema pivot renderer now automatically includes every shared field from
  the probe, keeping connected-workspace tables represented without adding
  manual field categories.
- Schema-probe documentation now describes its 80-table curated catalog and the
  explicit limitation for custom or future workspace tables.

### Fixed
- Generated schema-pivot refresh guidance now uses the supported CLI command
  and conversion workflow.

## [0.4.4] - 2026-05-11
### Fixed
- `identity_signin_baseline` (#20): query returned `API 400 — Operator source
  expression should be table or column` because `make_list(pack(... 'LastSeen',
  max(Timestamp)), 10)` is a nested aggregate. Pre-aggregate per
  `(IPAddress, Country)` in a `let`, then build `TopIPs` from the materialized
  rows via a left-outer join.
- `identity_signin_baseline`: `IsKnownEgress` returned `null` for IPv6 source
  IPs because `ipv4_is_in_any_range()` returns `null` for IPv6 inputs and
  null bubbled through the OR-chain. Wrapped the call with
  `coalesce(..., false)` so IPv6 sign-ins now report `IsKnownEgress=false`
  (matching the literal `in (_xdr_KnownEgressIPs)` path) instead of leaking
  null into downstream consumers. Surfaced during the live test of
  `identity_signin_baseline`.
- `ttp_ldap_process_attribution` (#19): DC-to-DC LDAP and many client-to-DC
  connections record only `RemoteIP` in `DeviceNetworkEvents` (`RemoteUrl` is
  empty), so joining on `RemoteUrl` alone dropped real telemetry. Build both
  an FQDN target list and an IP target list from `IdentityQueryEvents`, allow
  the join to match either, and back-fill `RemoteFqdn` via an IP->FQDN map so
  downstream groupings still key on a meaningful value. New `IsIpFallback`
  flag surfaces when correlation was IP-only.
- `playbooks/email-forwarding-rule.md` (#24): the `Send`-activity confirmation
  snippet referenced `ClientIP=ClientIP` (no-op alias). `CloudAppEvents`
  exposes the column as `IPAddress`; aligned with the library queries'
  `ClientIP = IPAddress` convention.

### Added
- `ttp_ldap_process_attribution` `lookback` param (default `0d`): widens
  only the MDI/IdentityQueryEvents discovery window backward from `start`;
  the MDE attribution window stays bounded by `start`/`end`. Useful when
  MDI LDAP events are sparse and a tight start/end leaves `LdapTargetRows`
  empty even though MDE has plenty of LDAP-port traffic. Example:
  `--param start=<incident T-1h> --param end=<incident T+1h> --param lookback=7d`.
- `ttp_ldap_process_attribution`: detail mode now joins `SuppressedPerDevice`
  and surfaces `SuppressedCount` alongside attributed rows (previously only
  the summary row exposed it). Analysts in detail mode can now see how many
  connections were dropped by `KnownServiceAccounts` / the MDI-sensor
  hard-exclusion without re-running in summary mode.
- `ttp_ldap_process_attribution`: hard-excludes `microsoft.tri.sensor.exe`
  (the MDI sensor's own LDAP health-check process, running as
  `NT AUTHORITY\Local Service`) inside the query body. Suppressed
  connections are still counted in `SuppressedPerDevice` for transparency.
  Fresh tenants without a populated `KnownServiceAccounts` list now get
  clean output instead of seeing the sensor itself surfaced as low-severity
  LDAP attribution.

### Changed
- `ttp_ldap_process_attribution`: the IP-fallback target list now unions
  TWO sources — MDI-provided (`IdentityQueryEvents.DestinationIPAddress`)
  AND MDE-learned (RemoteIPs observed in DeviceNetworkEvents rows whose
  RemoteUrl already matched a known FQDN target in the same window).
  Surfaced by the post-fix live test: the tenant's MDI never populated
  `DestinationIPAddress` across the full 30-day retention window, so the
  MDI-only target list was always empty and the IsIpFallback code path
  was dormant — DC-to-DC empty-`RemoteUrl` connections (8 in the tester's
  synthetic validation) silently dropped. The MDE-learned source closes
  that gap independently of whether MDI ever records the IP.

  New `IpSource` field on each attributed row (and rolled up as
  `IpSources` sets + `IpFallbackCount` totals on SummaryRow and
  DetailRows) makes the correlation provenance explicit:
  - `fqdn` — RemoteUrl matched a known FQDN target directly (strongest).
  - `mdi` — RemoteUrl empty; RemoteIP matched an MDI-provided IP.
  - `mde-learned` — RemoteUrl empty; RemoteIP matched an IP we learned
    from another MDE row whose RemoteUrl was populated and matched an
    MDI FQDN target in the same window (weakest of the three; still
    sound).

  `LdapIpToFqdn` back-fill prefers MDI source when both are present for
  the same IP; the resolved FQDN is the same either way.

### Notes
- `ttp_ldap_process_attribution`: the `IsIpFallback=true` code path is the
  primary behavioral differentiator versus a naive port-389 filter. Four
  structural ratchet tests
  (`test_ttp_ldap_process_attribution_has_ip_fallback_path`,
  `..._has_mde_learned_ip_source`,
  `..._summary_carries_fallback_signal`,
  `..._detail_carries_fallback_signal`) assert every element of the
  fallback derivation (MDI + MDE-learned source tables, union, three-value
  IpSource case, `IpFallbackCount` / `IpSources` propagation through
  summary and detail) stays in the rendered KQL so future refactors
  cannot silently regress. End-to-end runtime behavior of the fallback
  would require a KQL emulator and is tracked separately; live testing
  in the report confirmed the MDE-learned path captures the 8 empty-
  `RemoteUrl` connections it was designed for.

## [0.4.3] - 2026-05-08
### Changed
- Restructured `AGENTS.md` into mission briefing + CLI reference (~170 lines,
  down from ~352). Expanded `docs/investigation.md` to be self-contained for
  investigations (absorbed KQL authoring rules, `xdr investigate` guidance,
  `--rationale`/`--learning-mode`). Extracted session mechanics to
  `docs/sessions.md`. Moved CloudAppEvents inbox-rule KQL recipe to the
  email-forwarding playbook.
- Fixed seven doc-accuracy defects found during code review (obsolete
  session-pointer description, phantom command name, mission overclaim, no-op
  flag promotion, redundant text, orphaned term, imprecise bypass description).
  Added code-fidelity verification rule to `CONTRIBUTING.md` §7.

## [0.4.2] - 2026-05-05
### Changed
- `.github/guarddog-requirements.txt` : CI - bumped python-multipart from 0.26 to 0.27.

## [0.4.1] - 2026-05-05
### Changed
- `endpoint-malware-generic` playbook: added archive-extraction delivery vector
  guidance (container pivot, broad/narrow hunt patterns, `FileOriginReferrerUrl`
  interpretation).

## [0.4.0] - 2026-05-03

### Added
- `xdr lists init` command — seeds `~/.xdr-cli/lists/` from in-repo public
  defaults (`KnownGoodSigners`, `InternalSubnets`, `KnownRemoteSupportTools`,
  etc.) with atomic writes and idempotent re-runs. Audit-logged.
- Lists infrastructure: queries declare `-- lists: <Name>, <Name>` in
  frontmatter; loader prepends `let _xdr_<Name> = dynamic([...])` blocks from
  per-tenant text files at `~/.xdr-cli/lists/<Name>.txt`. List files support
  `# fetched:`, `# ttl:`, `# source:` headers; loader emits stderr staleness
  warnings when `now() > fetched + ttl`.
- 12 new library queries: `qry_mailbox_delegation`,
  `ttp_oauth_app_signin_anomaly`, `ttp_oauth_consent_anomaly`,
  `ttp_discovery_recon`, `ttp_defender_av_tampering`,
  `ttp_ransomware_precursors`, `ttp_conditional_access_tamper`,
  `ttp_credential_dumping`, `ttp_rmm_first_seen` (production tier);
  `ttp_adcs_abuse`, `ttp_kerberos_delegation_abuse`,
  `ttp_device_code_flow_abuse` (beta tier).
- `qry_inbox_rule_activity` — replaces `qry_inbox_rule_audit` and
  `qry_inbox_rule_triggers` (which remain as deprecated aliases for one
  release; removal planned for `0.5.0`).
- Methodology surface across the library: every non-utility query now
  declares `mode=summary|detail`, projects `SchemaVersion`, and (for
  finding-tier queries) carries a `Severity = case(...)` band.
- Spec-mandated JSON envelope completeness fields on every R1/R2/N/beta
  summary row: `EvidenceTotal`, `EvidenceOmitted`, `SuppressedCount`,
  `FirstSeen`, `LastSeen`, `ListHealth`. Playbooks consuming summary rows
  can now see what was omitted before closing on summary alone.
- `tier:` and `alias_of:` frontmatter, validated at load time.
  Deprecated-alias resolution: invoking a `tier: deprecated` query
  forwards to its `alias_of:` target with a one-release stderr warning.
- Static methodology contract test (`tests/test_queries_methodology.py`)
  enforcing: tier frontmatter, `mode` parameter, `SchemaVersion`,
  Severity bands, public-list negative-weight contract,
  deny-list positive operators, deprecated-alias resolution, lists
  reference real seed files, completeness-field projections,
  no inline tenant strings in DNS queries, no remaining
  `AADSignInEventsBeta` references, `arg_max()` not wrapped in scalar
  conversions, `-- name:` matches filename stem.
- `scripts/extract_tenant_domains.py` — one-shot migration from inline
  hardcoded tenant FQDNs to `~/.xdr-cli/lists/TenantDomains.txt` (with
  CDN allowlist filtering and atomic write).
- `docs/lists.md` analyst documentation for the lists model.

### Changed
- 12 R1 full rewrites: `ttp_token_theft_replay` (multi-signal session/token
  scoring + AiTM + refresh-token replay), `ttp_impossible_travel`
  (geo_distance + velocity scoring), `ttp_dns_beaconing`
  (jitter scoring with TenantDomains list extraction; +10 weight on
  `_xdr_MaliciousDomains`), `dns_subdomain_diversity`
  (burstiness scoring with split lists), `ttp_ransomware_mass-rename`
  (multi-signal late-stage correlation), `ttp_lateral_movement_rdp`
  (DeviceLogonEvents anchor + novelty/fan-out/tunnel detection),
  `ttp_new_service_creation` (3-leg union + parent attribution),
  `ttp_encoded_powershell` (decode pipeline + AMSI/ETW + obfuscation
  heuristics), `qry_entra_role_changes`, `qry_exchange_role_changes`,
  `qry_privilege_grant_revoke`, `ttp_lateral_psexec_wmi`.
- 12 R2 methodology-only retrofits and 29 R3 mode-only retrofits across
  the existing pivot/finding queries.
- Schema migration: `AADSignInEventsBeta` and `AADSpnSignInEventsBeta`
  references in `ttp_impossible_travel` and `ttp_token_theft_replay`
  migrated to `EntraIdSignInEvents` / `EntraIdSpnSignInEvents`. Only
  `sys_schema_probe` (utility tier, intentionally documents the legacy
  table) still references the deprecated names.
- `playbooks/email-forwarding-rule.md` — full rewrite to consume the
  merged `qry_inbox_rule_activity` end-to-end.
- 10 other playbooks — param-name corrections and orphan-query reference
  sweep after the merge of `qry_inbox_rule_audit`/`qry_inbox_rule_triggers`.
- Public allowlists (`KnownGoodSigners`, `KnownRemoteSupportTools`,
  `KnownGoodParentDomains`) wired as **negative-weight scoring signals**
  (`-3` or `-5`), not row-dropping `where` filters, in the queries that
  consume them — per the spec's "Public-list semantics: enrichment vs
  hard-suppression" contract. Tenant-curated allowlists
  (`KnownServiceAccounts`, `TenantDomains`, etc.) retain row-drop
  semantics where the operator opts in.
- Loader: `parse_frontmatter` recognizes `lists:`, `tier:`, `alias_of:`,
  multi-line `agent_hint:` (continuation via 2-space-indent `--   ...`).
  Unknown query parameters now raise `QueryError` (a typo'd
  `--param accont_upn=...` no longer silently widens a scoped hunt to a
  tenant-wide sweep). An empty resolved value coerces to the declared
  default when the default is non-empty (preserves the
  `account_upn=` scope-pass-through idiom).
- `_WRITE_COMMANDS` matcher in `main.py` now handles multi-token entries
  (so `xdr lists init` is correctly audit-logged).
- `xdr hunt library` renders empty-default params (`account_upn=()`)
  distinctly from required params (`account_upn=required`) and
  valued-default params (`hours=(168)`).
- `kql_parse.extract_tables` now scans the RHS of `let` bindings for
  table references — previously the loader's table-introspection pass
  underreported tables on R1/R2/R3-shaped queries that bind their
  detail rows to a `let` variable.

### Fixed
- `arg_max()` row-selector aggregation no longer wrapped in `tostring()`
  / `substring()` in three queries (`ttp_dns_beaconing`,
  `dns_subdomain_diversity`, `ttp_encoded_powershell`) — the wrapping
  was broken at runtime per the Kusto docs.
- 8 new query files had `-- name:` frontmatter stripped of the
  `qry_`/`ttp_` prefix; aligned to filename stem.
- `xdr hunt library` no longer hard-fails on a single malformed `.kql`.
  Builtin and user-installed queries with missing/invalid frontmatter
  are skipped with a stderr warning; the rest of the library still loads.
  This previously bricked the entire library command when a stale
  pre-rename file lingered in `~/.xdr-cli/queries/` or in a stale
  pipx package install.
- Query timeouts now surface as `error: query timed out (...)` on stderr
  with exit code 3 instead of exiting silently with no rows on stdout —
  previously a 30s timeout looked indistinguishable from "empty results"
  to the operator.

### Added (post-bump, slated for 0.4.0 retag)
- `xdr hunt library-show <name> [-p key=value]` — render a library query
  with substitutions applied without executing it. Useful for diffing
  CLI behaviour against a query pasted into the Defender Advanced
  Hunting GUI.
- `--timeout <seconds>` flag on `hunt run` and `hunt library-run` —
  per-call override of `config.api_timeout`. Summary-tier hunts with
  joins / aggregations may need 180-300s on busy tenants.

### Changed (post-bump, slated for 0.4.0 retag)
- Default `api_timeout` raised from 30s to 120s. Library queries with
  joins / aggregations routinely run 30-90s+ against Defender; the prior
  default reflected single-event lookups.
- Hunt response envelope cleanup. `metadata.execution_time` renamed to
  `metadata.execution_time_ms` and now always populated — falls back to
  client-measured wall-clock when the API doesn't return execution time
  (Graph's `runHuntingQuery` documents only `schema` + `results`, no
  stats). `metadata.cpu_usage` removed: it's a tenant-wide quota concept
  ("10 min/hour, 3 hours/day"), not a per-call value, and Defender's
  successful responses don't expose it. Quota exhaustion still surfaces
  as a 429 via the existing HTTPStatusError handler.
- Hunt rows now strip Microsoft Graph's `@odata.type` annotations
  (`Score@odata.type: "#Int64"`, `IsExternal@odata.type: "#Int64"`,
  etc.). Graph emits these next to int64 columns to hint precision
  back to clients — pure protocol noise that doubled column count
  for AI-agent consumers when the same precision info is already in
  `result.schema`.
- List-block consolidation. `InternalDomains` collapsed into
  `TenantDomains` — same data ("domains owned by my tenant"),
  different name with no operational distinction. `qry_inbox_rule_activity`
  and `qry_mailbox_delegation` now reference `TenantDomains`. Operators
  who hand-populated `~/.xdr-cli/lists/InternalDomains.txt` should
  rename it to `TenantDomains.txt` (or copy the contents over;
  `xdr hunt library-show qry_inbox_rule_activity` will render the
  values into `_xdr_TenantDomains` once moved).
- Dropped four zero-reference seed blocks from the lists catalog:
  `InternalSubnetsIPv6`, `KnownGoodDllSha1`, `KnownGoodSoftwareSha1`,
  `MaliciousHashes`. None were consumed by any query; they appeared
  in `xdr lists init` output and `_known_list_blocks()` validation
  without doing anything. Re-add when a real consumer ships.

## [0.3.0] - 2026-04-27

### Added
- Missing playbooks and library queries from prior PR.

### Changed
- Playbooks moved to `playbooks/` top-level directory.

## [0.2.0] - 2026-04-26

### Added
- `CONTRIBUTING.md` at repo root — reference doc covering branching, commits,
  pull requests, versioning, syncing main, AI-agent rules, the don't-commit
  list, recipes for common git mishaps, open-source readiness, and security
  disclosure.
- `docs/contributing-walkthrough.md` — three narrative walkthroughs (first
  human-only contribution, first AI-assisted contribution, rebase walkthrough).
- `CHANGELOG.md` — this file.
- `SECURITY.md` — private vulnerability disclosure policy.
- `.github/pull_request_template.md` — auto-populated PR description with
  Bump, Test plan (automated + live smoke), Risk areas, References, and
  pre-merge checklist.
- Per-PR versioning policy (SemVer with pre-1.0 stance, project-specific
  bump table treating the JSON envelope, AGENTS.md contract, and session
  JSONL schema as public API).
- Test that catches version drift between `pyproject.toml` and
  `xdr_cli.__version__` (`tests/test_version.py`).
- CI enforcement of the per-PR policy: a `version-and-changelog` job in
  `.github/workflows/ci.yml` fails the PR check if `pyproject.toml` version
  is unchanged or `CHANGELOG.md` is unmodified vs the base branch.
- GuardDog supply-chain scan in CI: `guarddog pypi verify` scans the resolved
  dependency closure (from `pip freeze --exclude-editable`) for known-malicious
  PyPI packages, and `guarddog github_action verify` scans the workflow file
  for malicious GitHub Actions patterns. GuardDog and its full transitive
  dependency closure are pinned with SHA-256 hashes in
  `.github/guarddog-requirements.txt` (generated by `pip-compile
  --generate-hashes`); CI installs via `pip install --require-hashes -r ...`
  so any tampered artifact in the closure fails the install.

### Changed
- `src/xdr_cli/__init__.py` reads `__version__` dynamically from package
  metadata via `importlib.metadata.version("xdr-cli")`, with a
  `PackageNotFoundError` fallback to `"0.0.0+unknown"` for source-tree-only
  execution. `pyproject.toml` is now the single source of truth.
- `README.md` gained a "Contributing" section linking to the new docs and
  to `SECURITY.md`.
- `AGENTS.md` §13 (Links) gained a cross-link to `CONTRIBUTING.md` §7
  (the AI-agent contribution rules).
- `.gitignore` extended to cover `.claude/`, `.cursor/`, `.windsurf/`
  alongside the existing `.codex` entry.
