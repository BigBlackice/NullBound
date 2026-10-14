# NullBound

## Product statement

Build a local-first workspace for authorized web reconnaissance and OSINT work. The
application should let an operator launch compatible tools from a consistent
interface, optionally organize work into scoped projects, preserve evidence, and
turn tool output into traceable assets and findings.

NullBound is intended to provide a free and open-source web-testing workflow built
around ZAP and other FOSS tools, without requiring Burp or another proprietary
platform. Over time, NullBound should become the primary operator interface and use
ZAP as a headless interception and scanning engine wherever practical.

The first goal is not to replace every security tool. It is to make the common
recon workflow calmer, faster, and easier to audit.

Public name: **NullBound**. Render the primary application header and browser title
as **NULL//BOUND**.

## Product principles

- **Execution context is always visible.** Operators should know whether a run is
  attached to a project, uses project scope, or uses direct targets. Projects and
  scope improve organization; they are not prerequisites for launching a tool.
- **Evidence comes first.** Preserve raw output and execution metadata before
  attempting to normalize or enrich it.
- **Progressive disclosure.** Keep the launchpad compact; reveal advanced tool
  options in a contextual configuration panel.
- **Operational, not decorative.** Status, counts, and visualizations must help
  answer a workflow question.
- **Local and safe by default.** Bind to localhost, construct commands without
  unsafe shell interpolation, and require explicit configuration for remote use.
- **Linux-first, portable core.** Treat Linux as the reference runtime and initial
  packaging target, while keeping the UI, project format, data model, and adapter
  contracts operating-system agnostic unless a platform difference is unavoidable.
- **Adapters over special cases.** Tool behavior should eventually be described by
  a common adapter contract instead of being embedded throughout the UI.
- **Single tools and workflows are distinct.** A single-tool launcher exposes one
  adapter directly; a chained workflow composes launchers through typed artifacts
  without hiding stage commands, scope decisions, or provenance.
- **FOSS-first integrations.** Core workflows must not depend on proprietary tools
  or services. Optional integrations must be clearly identified and replaceable.
- **Original visual identity.** Use an industrial/cyber command-center aesthetic,
  but do not copy proprietary game fonts, icons, logos, or interface assets.

## Core information architecture

- **Launchpad:** distinct single-tool launcher and chained-workflow collections,
  with shared search, favorites, recent use, and tool health.
- **Single-tool launchers:** direct access to one executable adapter and its
  profiles, parameters, exact command preview, output, and artifacts.
- **Chained workflows:** ordered launchers joined by typed normalized handoffs,
  with every stage still visible and independently auditable.
- **Runs:** queued, active, completed, failed, and cancelled executions.
- **Project workspaces:** open projects appear as switchable tabs in the command
  bar; findings, assets, evidence, and scope remain project-aware rail views.
- **Evidence:** raw artifacts, normalized records, hashes, provenance, and
  relationships between project objects.
- **Settings > Proxy:** application-level HTTP/SOCKS proxy configuration,
  connection status, and per-adapter routing capability.
- **Settings:** projects, tool availability, adapter configuration, and appearance.

The persistent shell should include:

- A compact top command bar with project-workspace tabs, proxy/scope execution
  toggles, and command palette access.
- A compact left navigation rail for launchpad, findings, assets, evidence, scope,
  runs, and settings.
- A contextual right panel for module configuration and selected-object details.
- A collapsible bottom console with one tab per run.
- A fullscreen/focus mode for a selected workflow.

## v0.1 — Operator console

### v0.1a — UI prototype

**Status: complete (2026-09-08).**

- [x] Archive the original Tkinter experiment and unstructured notes.
- [x] Create the NiceGUI application shell and interactive Launchpad.
- [x] Give every initial module a selectable, module-specific configuration view.
- [x] Route unfinished navigation destinations to a shared placeholder view.
- [x] Add live Launchpad module search.
- [x] Replace illustrative console content with a real, empty NiceGUI log view.
- [x] Add minimize and fullscreen controls to the run output panel.
- [x] Move project views into the rail and add switchable project-workspace tabs.
- [x] Add persistent UI state for proxy-enabled and scope-enforced toggles.
- [x] Move proxy configuration into Settings while retaining the top-bar runtime
  toggle; prototype HTTP/SOCKS, intercept-proxy, authentication, and routing policy
  controls.
- [x] Allow open project-workspace tabs to be closed without unloading the shell.
- [x] Make the configuration inspector collapsible and prioritize it over module
  selection at narrow viewport widths.
- [x] Constrain the application shell to the viewport so an overflowing contextual
  right rail scrolls independently to the bottom without stretching the navigation
  rail, workspace, or run console.
- [x] Preserve the labeled navigation rail until the icon-only narrow breakpoint.
- [x] Move modules and scan profiles into a validated, data-driven catalog with
  automatic numeric ID allocation and a default-icon fallback.
- [x] Prototype project-aware Findings, Assets, Evidence, Scope, and Runs list/detail
  views using the shared workspace and contextual inspector.
- [x] Prototype a modal Settings workspace with General, Projects, Modules, and
  Appearance sections, including the planned module/profile editor fields.
- [x] Review the prototype at common desktop widths.
- [x] Agree on navigation, information density, vocabulary, and visual direction.
- [x] Extract reusable design tokens and components after the direction is agreed.
- [x] Keep theme tokens semantic and limited: near-black backgrounds, a structural
  accent for borders/separators, and an interactive accent for controls/text.
- [x] Default theme: red structure on near-black surfaces with blue interactive
  controls. Avoid per-component background shades and decorative color gradients.
- [x] Define empty, unavailable, running, failed, and completed states.
- [x] Confirm keyboard navigation and readable contrast; never communicate status
  using color alone. Tab navigation works, and Escape releases writable fields or
  closes dialogs.

### v0.1b — Optional project and scope foundation

- [x] Create, open, and validate portable project directories. Default new projects
  to `~/.nullbound/projects`, but allow the operator to choose any parent path.
- [x] Add a local directory browser, starting in `~/.nullbound`, for opening any
  folder containing a valid `project.json` as a workspace tab.
- [x] Persist the open project-tab set in local application state and restore it on
  restart; tabs explicitly closed with their close control remain closed.
- [x] Model direct-target execution when no project is open. Tool process launch is
  implemented separately in v0.1c.
- [x] Allow a project execution context to use direct targets without first adding
  them to scope.
- [x] Store project metadata in a versioned, platform-neutral `project.json` file.
- [x] Add portable saved target sets containing domains, IPv4/IPv6 addresses,
  CIDRs, and URLs.
- [x] Support explicit includes, exclusions, and review-required targets through a
  versioned, independently editable `scope.json` document.
- [x] Keep authorization status separate from ownership confidence:
  - `scope_status`: `allowed`, `denied`
  - `ownership_confidence`: `confirmed`, `likely`, or `unknown`
- [x] Make the active project and target set visible throughout the UI.
- [x] Tag each run with a nullable project ID and a captured project display name.
- [x] Determine project association from the active workspace. Module configuration
  must not contain a separate project selector: runs launched inside a project are
  filed into it automatically, while launchpad runs outside a project remain
  unattached.
- [x] Make run history follow the active project workspace without a duplicate
  project dropdown; when no project is active, show session-only unattached runs.

### v0.1c — One complete execution path

- [x] Define an argv-based, data-driven tool-adapter schema which runtime-added
  modules and profiles can use without changing the process runner.
- [x] Build **Settings > Modules** to list, add, edit, and delete modules. The editor must
  show an automatically allocated, read-only numeric ID after the module type,
  plus `eyebrow`, optional `icon`, `description`, `bin`, and executable `path`.
- [x] Validate module executable paths, show availability/version state, and use
  the catalog's default icon whenever no icon is selected.
- [x] Support named scan profiles and provide per-module profile creation and
  editing in **Settings > Modules**.
- [x] Integrate ProjectDiscovery `httpx` as the first end-to-end adapter: availability
  check, version capture, direct/project targets, JSONL output, cancellation, and a
  completed run manifest. Keep it distinct from the Python HTTPX package.
- [x] Add initial runnable profiles and raw artifacts for every Launchpad module:
  Subfinder, dnsx, Nmap, httpx, gau, and tlsx. Normalization into project evidence
  remains a separate v0.2 concern.
- [x] Preview the exact executable and arguments before launch.
- [x] Launch processes without interpolating user input into a shell string.
- [x] Stream stdout and stderr to the run console and persistent log files.
- [x] Add a deliberate starting/loading state to the run console for the period
  between launch and the first process output.
- [x] Prototype managed Amass v5 execution and OAM indexing, then place the
  integration on indefinite hold. Preserve the disconnected implementation under
  `recon_modules/amass_hold` without registering it in NullBound.
- [x] Support queueing, concurrency limits, timeouts, and process-group cancellation.
- [x] Preserve run state if the browser disconnects or refreshes.
- [x] Record executable path, version, arguments, inputs, timestamps, duration,
  exit code, and artifact hashes in a run manifest.
- [x] Add project-filtered run history and safe artifact preview/download actions.
- [x] Keep no-project runs session-only. When creating a project, require an explicit
  choice to attach completed session runs or delete them permanently; active runs
  must finish or be cancelled first.

### v0.1 acceptance criteria

- An operator can enter a direct target, configure the first adapter, review its
  command, run it without a project, watch its output, cancel it, and reopen its
  evidence from run history.
- When the operator is inside a project, the run is attached to that project
  automatically and may use project assets as targets. Outside a project, the run
  remains unattached.
- A denied target cannot be launched accidentally.
- Project-attached raw artifacts and complete manifests remain available after
  restarting the app; intentionally transient no-project runs do not.
- The main workflow is usable without an interactive terminal.

## v0.2 — Evidence and asset workspace

- [x] Prototype an in-scope Evidence browser where assets, vulnerabilities, and
  identities act as relationship nodes and the inspector lists their artifacts.
- [x] Use SQLite as the searchable project index while keeping raw artifacts on
  disk.
- [x] Add schema versions, transactional migrations, SQLite write locking,
  rollback, and interrupted-ingestion recovery. This release is explicitly
  single-process per project; a cross-process project lock is deferred until
  multi-instance use is supported.
- [x] Define normalized record envelopes with stable IDs and source provenance.
- [x] Implement `parse -> normalize -> deduplicate -> scope review` as explicit,
  independently testable stages.
- [x] Define extensible correlation-rule contracts and persist typed, evidenced
  relationships; start with explicit parser links and conservative URL-to-host
  correlation without guessing registrable-domain boundaries.
- [x] Automatically parse project-attached terminal runs into the evidence index.
  Native parsers cover Subfinder/dnsx/httpx/gau/tlsx JSONL and Nmap XML;
  no-project runs remain session-only and never create a project database.
- [x] Drive Assets from normalized project records with live filtering through the
  global top-bar search, multi-row selection/actions, and per-row context actions
  for adding supported assets to scope.
- [x] Add the shared tri-state scope filter to Assets, Findings, and Runs: all
  records, in-scope only, or out-of-scope only. Findings inherit their linked
  asset's status; Runs evaluate all recorded targets against the active project's
  current scope rules.
- [x] Keep Scope limited to explicit portable scope rules and allow operators to
  add domains, wildcard domains, IPs, CIDRs, exact URLs, and conservative wildcard
  URL patterns manually.
- [x] Refresh open Assets, Findings, and Evidence result tables when any concurrent
  project run finishes evidence indexing, and update Runs on lifecycle changes.
  Replace only the affected table rows and inspector data so searches, filters, and
  other workspace controls are not disrupted by a full workspace rebuild.
- [x] Keep large Subfinder result sets responsive: batch asset provenance reads,
  render Assets in bounded 50-row pages, and represent the run-log tail with one
  text surface instead of thousands of per-line UI components.
- [x] Apply the same scale discipline across active surfaces: use set-based Evidence
  counts with lazy inspector detail; bound Findings, Evidence, Scope, and Runs to
  50 mounted rows; cache unchanged project adapters and run manifests; update row
  selection without rebuilding workspaces; batch live console browser updates;
  stream JSONL input; hash artifacts off the event loop; and commit each normalized
  ingestion batch atomically instead of opening transactions per record.
- [x] Replace active Amass support with Subfinder JSONL discovery, retain provider
  provenance, and index submitted root domains as seed assets even when no
  subdomains are returned.
- Amass is on indefinite hold. Its engine adapter, OAM SQLite parser, and catalog
  profiles are disconnected backups under `recon_modules/amass_hold`; they must
  not be imported or installed by NullBound. The standalone Windows Mullvad DNS
  helper remains under `scripts/` for manual testing of DNS discovery tools only.
- [x] Preserve every raw value alongside its normalized comparison key.
- [x] Treat URL canonicalization conservatively and record the normalization
  version and transformations.
- [x] Retain denied, review, and unmatched discoveries. The operator-requested
  tri-state filters expose all, in-scope-only, or out-of-scope-only records rather
  than silently hiding retained discoveries.
- [x] Provide asset, run, artifact, and finding details through the shared
  inspector and artifact viewer without introducing separate duplicate screens.
- [x] Add finding lifecycle states `candidate`, `validated`, `false_positive`, and
  `accepted_risk`, including operator lifecycle controls in the Findings and
  Evidence inspectors.
- [x] Provide live global search plus scope/status filters on the active record
  workspaces.

Tags, editable notes, JSON/CSV export, and an in-app project-backup command are
post-release conveniences. For the first release, project directories remain
self-contained and the README documents safe whole-directory backup and cleanup.

The database framework includes schema migrations, SQLite write locking,
transaction rollback, and explicit recovery of interrupted ingestion batches.
Do not open one project in multiple NullBound processes until a portable
cross-process project lock exists.

### Preserved UI classification vocabulary

The prototype records were removed when the project database became the source for
Assets, Findings, Evidence, and Scope. Preserve these semantic classifications and
their established colors when real records populate those views:

- Finding severity: `critical` uses structural red, `high` orange, `medium` amber,
  `low` interactive blue, and `info` green.
- Finding lifecycle: `candidate`, `validated`, `false_positive`, and
  `accepted_risk`; lifecycle must remain distinct from severity and confidence.
- Scope/record tones: `allowed`, `completed`, `verified`, `confirmed`, and
  `in-scope` use interactive blue; `running`, `review`, `review-required`, and
  `queued` use amber; `denied` and `failed` use structural red; `cancelled` uses
  faint neutral text.
- Ownership confidence remains `confirmed`, `likely`, or `unknown`, independently
  of authorization. Scope decisions remain `allowed` or `denied`, with review as a
  separate flag; unmatched discoveries enter deliberate review rather than being
  silently treated as authorized.

Suggested run layout:

```text
project/
  project.json
  project.db
  runs/
    2026-09-06T192251Z_<run-id>/
      manifest.json
      stdout.log
      stderr.log
      raw/
      staging/
      exports/
```

Run directories are append-only by application policy. SHA-256 hashes in the
manifest provide integrity checks; an ordinary folder should not be described as
physically immutable.

## Long-term performance and scale

These changes are deferred until profiling shows the current bounded, cached views
or atomic ingestion pipeline approaching their practical limits. Preserve current
behavior and evidence guarantees while implementing them.

- Move Assets, Findings, and Evidence to SQL-backed keyset pagination and add
  SQLite FTS search. This has the highest payoff for projects with hundreds of
  thousands or millions of records, but requires schema migrations and careful
  handling of filters, stable ordering, multi-selection, and search semantics.
- Evaluate a client-side virtualized data grid or a deliberately small custom
  virtual list before raising the current 50-row page size. Preserve keyboard
  navigation, context actions, multi-selection, non-disruptive live updates, the
  Cyberpunk visual language, and NiceGUI lifecycle stability. Prototype this
  separately because it carries medium-to-high UI regression risk.
- Let parsers yield normalized records incrementally and commit very large
  imports in recoverable chunks, so multi-million-line artifacts do not require a
  complete tuple in memory. Define resume, rollback, visibility, and crash-recovery
  semantics before replacing the current atomic ingestion transaction.
- Page observations and relationships inside the Evidence inspector for nodes
  with unusually high degree or extensive repeated observations. This is a
  low-to-medium-risk safeguard even though top-level Evidence paging is already
  bounded.
- Compile or index scope matchers and reevaluate very large asset inventories
  in a background job with visible progress. Define how temporarily stale scope
  labels and enforcement decisions are represented before making reevaluation
  asynchronous.
- Add a reconciled persistent run index if projects commonly reach thousands
  of run directories. Preserve portable self-contained run manifests as the source
  of truth; the index must remain rebuildable and must not introduce stale history.

## Web-centric discovery, enumeration, and attack modules

Make this the next capability focus before the generic saved-workflow system.
Provide three task-oriented module groups: **Discovery modules** populate the
project inventory from scope seeds, **Enumeration modules** perform deeper work
against the discovered inventory, and **Attack modules** validate server-side
weaknesses that can provide an initial foothold. Every handoff is operator-reviewed;
no stage silently launches the next one.

- [x] Keep one Launchpad page, but divide it into four clearly separated groups:
  **Single-tool launchers**, **Discovery modules**, **Enumeration modules**, and
  **Attack modules**. Do not hide or replace the underlying single-tool launchers.
- [x] Add an initial **Web discovery** module that accepts one or more project
  scope items as seeds and reuses the existing Subfinder, dnsx, and httpx
  capabilities to discover subdomains, resolve them, identify IPs, and confirm
  live web services. Each underlying tool remains directly launchable.
- [x] Add selectable Standard, Broad, and Recursive Web Discovery profiles while
  preserving the fixed Subfinder -> dnsx -> httpx stage order.
- [x] Add an initial **Web enumeration** module for the resulting live web assets.
  The first chains provide quick httpx/tlsx enumeration and GAU -> httpx -> tlsx
  archive/deep enumeration. Chain and stage definitions are data-driven so more
  built-in chains can reuse the same runner and inspector.
- [x] Add a Web Enumeration chain for `ffuf` directory discovery with an
  operator-selected wordlist, conservative recursion, and a bounded depth.
- [x] Keep separate configurable project fallbacks for web-content and password
  wordlists, while continuing to offer the corresponding Kali SecLists trees
  whenever they are installed.
- Add HTTP/S screenshot capture with Playwright as a later Web Enumeration
  chain. Define screenshot retention controls first. Do not inherit Cygor's RDP,
  VNC, or X11 scope.
- Make **Discovery -> Enumeration** a first-class reviewed handoff. When a
  discovery module finishes, offer the matching enumeration module with the scope
  item and discovered target count already selected, but require the operator to
  inspect the targets and explicitly launch it.
- [x] Keep this first pair as fixed built-in, task-oriented modules; do not require
  a generic workflow editor, arbitrary workflow definitions, or automatic chaining.
  Preserve each underlying stage as an ordinary run with its own command, state,
  logs, artifacts, and provenance.
- [x] Let an enumeration module target one explicit project **scope rule** from
  its configuration. Exact domain rules exclude subdomains; wildcard rules such
  as `*.google.com` include directly matched subdomains and their infrastructure
  descendants. Do not merge exact and wildcard rules for launches.
- [x] Reuse the Evidence workspace's existing scope-anchor and relationship
  resolution for standard, wildcard, and regex scope entries. Do not build a
  second asset hierarchy or infer registrable-domain ownership beyond recorded
  scope matches and evidenced relationships.
- [x] Before launch, show the number of compatible targets plus a bounded sample,
  deduplicate normalized values, and clearly report assets omitted because their
  type is incompatible. A scope item with no compatible indexed assets must fail
  with an actionable message.
- [x] Apply the normal launch-time scope evaluation to the expanded target set so
  explicit exclusions and the operator's enforcement choice retain their current
  meaning. Capture the final target snapshot in the run manifest so later scope or
  asset changes cannot alter what the enumeration run actually covered.
- [x] Keep large scope anchors responsive: resolve complete target sets with
  paged or streamed SQL reads, bound only the on-screen preview, never mount every
  descendant as a UI element, and use the existing target-file execution path
  where supported.
- [x] Preserve the ordinary run contract for enumeration modules: exact command or
  operation preview, health state, timeout and cancellation, live output, raw
  artifacts, normalization, evidence provenance, and project-filtered history.
- [x] Require an active project only for scope-driven Discovery, Enumeration, and
  Attack modules. Preserve direct, no-project execution for every compatible
  single-tool launcher.

### Server-side attack validation

Keep the initial Attack module focused on web penetration testing and proving
server-side footholds. Defer browser/user-targeted bug-bounty coverage such as XSS,
DOM analysis, CORS, clickjacking, and client-side OAuth abuse to a later release.

- [x] Add separate single-tool Attack launchers for safe-profile Nuclei checks,
  low-impact sqlmap detection, and capped CSRF-aware Brutepyweb password testing.
  Keep unconfirmed results as candidate findings; allow Brutepyweb's repeated
  fresh-session differential plus invalid control to mark a result validated.
  Preserve matched passwords in the local run and evidence record; mask them by
  default in the finding inspector with explicit reveal and copy controls.

- Make **Enumeration -> Attack** a reviewed handoff. Resolve only compatible
  assets, services, endpoints, and parameters under the selected scope item; show
  the target count and a bounded sample, then require an explicit launch.
- Add an **Exposure validation** profile for databases, caches, queues,
  management panels, debug services, storage, backups, configuration files, and
  secrets. Enumeration reports exposure; Attack confirms anonymous or known-default
  access with the least invasive read-only operation available.
- Add an **Injection validation** profile covering SQL, NoSQL, command,
  server-side template, LDAP, and XPath injection. Use ZAP for broad targeted
  checks and sqlmap in detection-only mode for SQL injection confirmation; disable
  data dumping, filesystem access, shells, takeover, and other side-effecting
  capabilities.
- Add an **SSRF and parser validation** profile covering SSRF, blind SSRF,
  XXE, and remote-file inclusion. Use Interactsh or a replaceable self-hosted OAST
  provider for callback evidence; do not probe cloud metadata or pivot through
  unrestricted internal address ranges by default.
- Add a **Known vulnerability validation** profile using Nuclei templates
  selected from evidenced products and versions. Pin and record the template set,
  template IDs, versions or hashes, and matching evidence; exclude destructive,
  denial-of-service, file-write, and unreviewed fuzzing templates by default.
- Add authentication and server-side authorization validation after NullBound
  can safely model credentials, redacted sessions, attempt limits, account-lockout
  risk, and two-identity request comparison. Cover authentication bypass, limited
  credential testing, IDOR/BOLA, privilege boundaries, cross-tenant access, and
  unsafe administrative API operations without exposing secrets in commands,
  logs, manifests, or evidence.
- [x] Classify Attack profiles as **safe**, **stateful**, or **intrusive** and show
  the classification, request/concurrency limits, authentication context, scope
  decision, and immutable target snapshot before launch. Stateful or intrusive
  profiles require explicit confirmation even when scope enforcement is advisory.
- [x] Promote a candidate to a validated finding only when the run preserves a
  reproducible proof such as a redacted request/response, read-only service result,
  tool match, or correlated OAST callback. Preserve raw artifacts and complete
  provenance alongside normalized findings.
- [x] Keep shell creation, bulk data extraction, persistent writes, destructive
  queries, denial of service, unrestricted internal SSRF pivoting, request
  smuggling, cache poisoning, race conditions, and complex business-logic abuse
  outside the initial automated Attack module.

## Post-release workflows and integrations

Deferred until the fixed Discovery and Enumeration modules have real operator
usage. These are roadmap notes, not first-release requirements.

- [x] Split the Launchpad catalog into distinct **Single tools** and **Workflows**
  collections. Every executable adapter remains directly launchable; workflows
  reference existing launchers instead of duplicating module/profile definitions.
- [x] Prove cross-tool interoperability with the first built-in chain:
  **Subfinder -> dnsx**. Pass normalized domain assets from Subfinder into dnsx for
  DNS validation and record enrichment while preserving each stage's raw artifacts,
  exact command, scope decision, and provenance.
- Add **Manual chaining** to Runs: a run-row right-click menu plus `Send to...`
  in the visible selection/action menu, including bulk handoff from multiple
  selected runs. Filter destinations to adapters that can consume the selected
  runs' normalized output. Let the operator review/select the records, target
  profile, parameters, and scope policy before launching linked runs. Runs created
  by a manual handoff must expose the same `Send to...` actions so operators can
  continue chaining recursively while retaining the complete provenance chain.
- Add a workflow-run manifest that links ordered child runs and exposes stage
  status, output, cancellation, failure, and retry without flattening them into one
  opaque process.
- Add saved multi-tool workflows with explicit inputs and outputs.
- Store relationships between assets, findings, artifacts, and runs as part of
  the Evidence model.
- Add a useful relationship view inside Evidence only after real project data
  can drive it.
- [x] Add per-tool proxy capability declarations and configuration.
- [x] Connect **Settings > Proxy** to application-level HTTP/SOCKS configuration
  and show which adapters support the selected protocol.
- Keep proxy routing implementation-agnostic: support ZAP, Burp, generic
  HTTP(S) proxies, and SOCKS jumphosts through the same host, port,
  authentication, bypass, and CA-trust controls. Burp compatibility is optional
  interoperability and must never become a dependency or required paid workflow.
- [x] Clearly identify tools whose traffic cannot be routed through the configured
  HTTP or SOCKS proxy.
- Connect to the ZAP API and treat ZAP as NullBound's headless interception and
  scanning engine rather than as the primary operator interface.
- Manage ZAP availability, API authentication, sessions, contexts, scope,
  authentication, users, and scan policies from NullBound.
- Import proxied HTTP history, request/response bodies, passive-scan alerts,
  active-scan results, spider results, and AJAX-spider results with provenance.
- Add NullBound-native request/response inspection, editing, resend/replay, and
  comparison so common manual proxy work no longer requires opening the ZAP UI.
- Keep a temporary route to the complete ZAP UI for capabilities NullBound has
  not exposed yet; record those fallbacks to prioritize later replacement.

### Deferred bug-bounty tool integrations

Treat this list as an integration portfolio, not as a requirement that every item
becomes a Launchpad card. Prefer adapters for executables, service integrations for
stateful systems, and internal libraries for reusable behavior.

#### Launchpad adapters

- [x] Add `subfinder` for passive subdomain discovery and normalize discovered
  names into candidate assets with source provenance.
- [x] Keep `dnsx` available as a standalone DNS resolution and record-enrichment
  launcher with JSONL normalization, executable health/version checks, and setup
  support; also use it as the second stage of the planned Subfinder -> dnsx workflow.
- [x] Add ProjectDiscovery `httpx` for reachability checks, HTTP metadata, and
  validation of output from `subfinder` and other discovery adapters.
- [x] Place Amass on indefinite hold and keep its disconnected implementation in
  `recon_modules/amass_hold` for possible future reassessment.
- Add Katana for scoped crawling and normalize URLs, forms, parameters, and
  JavaScript references without silently expanding beyond scope.
- [x] Add `ffuf` for bounded recursive content discovery with visible wordlist,
  recursion depth, and execution controls. Virtual-host and parameter fuzzing are
  deferred until operator usage justifies additional profiles.
- Add Arjun as a focused hidden-parameter discovery adapter. Keep it separate
  from `ffuf` because its request model and output semantics differ.
- [x] Add Nuclei with safe HTTP-only profiles, tool-version capture, severity and
  confidence mapping, and raw JSONL retained beside normalized findings. Pinning
  and hashing template sets remains post-release hardening.

#### Stateful and UI-backed integrations

- Configure ZAP routing in **Settings > Proxy**, control supported operations
  through its API, and expose the resulting traffic and evidence through
  NullBound-native views.
- Add Playwright as a managed browser-automation integration for authenticated
  navigation, screenshots, traces, and operator-authored workflows. Keep browser
  profiles, cookies, and credentials out of ordinary logs and manifests.
- Add Interactsh as an OAST provider integration rather than a one-shot scanner:
  create or register sessions, protect correlation tokens, poll interactions, and
  link callbacks to the originating run, request, asset, and finding.
- Evaluate GraphQL Voyager as an optional schema visualization inside Evidence
  after NullBound can import or introspect a GraphQL schema. It is not a scanner or
  a general-purpose Launchpad module.

#### Internal capabilities and external interoperability

- [x] Use Python `asyncio` for bounded orchestration and `requests` as the selected
  controlled HTTP client. JWT mutation and reusable response-diff tooling remain
  deferred until their actual workflows exist.
- Add reusable request-diff evidence for authorization/IDOR and race-condition
  workflows only after request redaction, deterministic replay, concurrency limits,
  and scope checks are in place.
- Replace the useful Param Miner workflow with native hidden-input discovery
  over requests selected from ZAP history or created in NullBound. Support query,
  body, header, and cookie insertion points, configurable wordlists, safe batching,
  and differential response scoring with reproducible evidence.
- [x] Do not require `jq` as NullBound's JSON database or parser. Preserve JSON and
  JSONL artifacts, parse them natively, and optionally offer copy/export recipes
  for operators who use `jq` outside NullBound.

Adapter workflows should compose typed outputs where practical, for example
`subfinder -> dnsx -> httpx -> Katana or Nuclei`, while retaining the same tools as
independent single-tool launchers plus the raw output and provenance from every
individual workflow stage.

The application must not claim that all traffic is proxied. Environment proxy
variables do not affect every scanner, DNS client, or raw-socket tool.

The retired Amass prototype exposed a v5.1.1 bootstrap dependency on hard-coded
public DNS resolvers that VPN DNS-leak protection can block. The standalone
`scripts/amass-mullvad-dns.ps1` helper can temporarily enable that broader resolver
pool for manual testing of Amass or other DNS discovery tools, then restore the
known Mullvad defaults. NullBound never invokes it or changes operator VPN/DNS settings.

## Post-release extensibility

Customization and third-party tool packs are intentionally outside the first
release. The current built-in adapter foundation remains internal until its
contract is stable through real use.

- [x] Use a validated declarative catalog for common CLI profiles and dedicated
  Python adapters for behavior the catalog cannot express.
- [x] Detect missing executables, capture versions, and provide optional Windows
  and Linux setup scripts separate from normal application startup.
- Stabilize and document a public adapter API only when external adapters are in
  scope.
- Add importable tool packs with explicit version compatibility only after that API.
- Evaluate isolated/containerized adapters when a concrete unsafe dependency
  requires the additional boundary.

## Deferred ideas

These are not part of the core roadmap unless later workflow testing demonstrates
a clear need:

- A general-purpose interactive terminal or custom shell.
- System-wide transparent proxying.
- A one-for-one recreation of the complete ZAP interface. Replace common manual
  workflows with NullBound-native views based on actual operator needs instead.
- Automatic `apt`, `pacman`, or other privileged package-manager calls.
- Decorative globes, ambient animations, or metrics without operator value.
- Multiple finished visual themes before the primary design system is stable.

## Cross-cutting engineering requirements

- [x] Use Linux as the reference environment and first packaging target while
  continuing to run and test the application on Windows during development.
- [x] Keep shared code platform-neutral: use `pathlib`, argument arrays, portable
  project-relative paths, and Python APIs instead of shell-specific commands or
  hard-coded drive paths.
- [x] Isolate unavoidable differences—executable discovery, process groups,
  cancellation signals, certificate stores, permissions, and browser launching—
  behind small platform services with explicit capability checks.
- [x] Add automated unit/integration smoke tests on Linux and Windows; do not let support for either
  platform distort the persisted project format or adapter schema.
- [x] Bind the local application to `127.0.0.1` by default, with validated
  `--host`/`--port` overrides and a warning for explicit non-loopback access.
- Treat authenticated or untrusted remote access as post-release work. The current
  application binds to loopback by default, warns on non-loopback binding, and is
  documented for trusted networks only.
- [x] Render tool output and artifacts through text components rather than raw HTML.
- [x] Treat Brutepyweb matches as operator evidence: preserve plaintext passwords
  in local logs, artifacts, and finding metadata while masking them by default in
  the UI. Keep proxy credentials and unrelated secret fields out of commands and
  manifests unless a future workflow explicitly requires and protects them.
- [x] Prevent artifact and evidence paths from traversing outside their run or
  project roots.
- [x] Test scope enforcement, command construction, cancellation, parsers,
  migrations, and provenance.
- [x] Document data retention, whole-project backup, session-run cleanup, and the
  absence of silent project evidence deletion.
- [x] Document that scanner binaries are installed from upstream on operator
  request and must not be redistributed from `.nullbound-tools` without a fresh
  upstream license review.

## Release-owner decision

- [ ] Choose and add NullBound's own source-code license. The repository calls
  itself FOSS but cannot grant reuse or redistribution rights until its owner makes
  this legal choice; it must not be guessed by an implementation change.

## Post-release product decisions

- Initial Linux packaging format beyond the documented source/virtualenv release.
- Whether multi-process project access or collaboration is ever supported. The
  first release is single-user, local-first, and single-process per project.
- Retention controls for projects large enough to require managed archival.
