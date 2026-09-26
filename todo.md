# Recon Dashboard

## Product statement

Build a local-first workspace for authorized web reconnaissance and OSINT work. The
application should let an operator launch compatible tools from a consistent
interface, optionally organize work into scoped projects, preserve evidence, and
turn tool output into traceable assets and findings.

Blackwall is intended to provide a free and open-source web-testing workflow built
around ZAP and other FOSS tools, without requiring Burp or another proprietary
platform. Over time, Blackwall should become the primary operator interface and use
ZAP as a headless interception and scanning engine wherever practical.

The first goal is not to replace every security tool. It is to make the common
recon workflow calmer, faster, and easier to audit.

Working title: **Blackwall**. Treat this as an internal codename until a public
name and trademark check are completed.

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
- **FOSS-first integrations.** Core workflows must not depend on proprietary tools
  or services. Optional integrations must be clearly identified and replaceable.
- **Original visual identity.** Use an industrial/cyber command-center aesthetic,
  but do not copy proprietary game fonts, icons, logos, or interface assets.

## Core information architecture

- **Launchpad:** searchable module grid, favorites, recent tools, and tool health.
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
  to `~/.blackwall/projects`, but allow the operator to choose any parent path.
- [x] Add a local directory browser, starting in `~/.blackwall`, for opening any
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
- [x] Add run-history filtering by project ID/name, including a `No project`
  filter. This can follow the first polished UI implementation.

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
  `recon_modules/amass_hold` without registering it in Blackwall.
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
- [ ] Add schema versions, migrations, workspace locking, and crash recovery.
- [x] Define normalized record envelopes with stable IDs and source provenance.
- [x] Implement `parse -> normalize -> deduplicate -> scope review` as explicit,
  independently testable stages.
- [x] Define extensible correlation-rule contracts and persist typed, evidenced
  relationships; start with explicit parser links and conservative URL-to-host
  correlation without guessing registrable-domain boundaries.
- [x] Automatically parse project-attached terminal runs into the evidence index.
  Native parsers cover Subfinder/dnsx/httpx/gau/tlsx JSONL and Nmap XML;
  no-project runs remain session-only and never create a project database.
- [x] Drive Assets from normalized project records with a live search field, an
  independent in-scope-only filter, multi-row selection/actions, and per-row
  context actions for adding supported assets to scope.
- [x] Keep Scope limited to explicit portable scope rules and allow operators to
  add domains, wildcard domains, IPs, CIDRs, exact URLs, and conservative wildcard
  URL patterns manually.
- [x] Refresh an open Assets view when any concurrent project run finishes evidence
  indexing, without requiring navigation or a browser reload.
- [x] Replace active Amass support with Subfinder JSONL discovery, retain provider
  provenance, and index submitted root domains as seed assets even when no
  subdomains are returned.
- Amass is on indefinite hold. Its engine adapter, OAM SQLite parser, and catalog
  profiles are disconnected backups under `recon_modules/amass_hold`; they must
  not be imported or installed by Blackwall. The standalone Windows Mullvad DNS
  helper remains under `scripts/` for manual testing of DNS discovery tools only.
- [x] Preserve every raw value alongside its normalized comparison key.
- [x] Treat URL canonicalization conservatively and record the normalization
  version and transformations.
- [ ] Retain out-of-scope discoveries, hide them from normal workflows, and expose
  them only in a deliberate review view.
- [ ] Build asset, run, artifact, and finding detail screens.
- [ ] Add finding lifecycle states: `candidate`, `validated`, `false_positive`, and
  `accepted_risk`.
- [ ] Add search, filters, tags, notes, JSON/CSV export, and project backup.

The initial database framework includes schema migrations, SQLite write locking,
transaction rollback, and explicit recovery of interrupted ingestion batches. A
separate multi-process workspace lock and backup/rebuild workflow are still needed
before the combined locking/recovery item above can be marked complete.

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

## v0.3 — Workflows and integrations

- [ ] Prove cross-tool interoperability by using normalized output from one adapter
  as typed input to a second adapter.
- [ ] Add saved multi-tool workflows with explicit inputs and outputs.
- [ ] Store relationships between assets, findings, artifacts, and runs as part of
  the Evidence model.
- [ ] Add a useful relationship view inside Evidence only after real project data
  can drive it.
- [ ] Add per-tool proxy capability declarations and configuration.
- [ ] Connect **Settings > Proxy** to application-level HTTP/SOCKS configuration
  and show which adapters support the selected protocol.
- [ ] Keep proxy routing implementation-agnostic: support ZAP, Burp, generic
  HTTP(S) proxies, and SOCKS jumphosts through the same host, port,
  authentication, bypass, and CA-trust controls. Burp compatibility is optional
  interoperability and must never become a dependency or required paid workflow.
- [ ] Clearly identify tools whose traffic cannot be routed through the configured
  HTTP or SOCKS proxy.
- [ ] Connect to the ZAP API and treat ZAP as Blackwall's headless interception and
  scanning engine rather than as the primary operator interface.
- [ ] Manage ZAP availability, API authentication, sessions, contexts, scope,
  authentication, users, and scan policies from Blackwall.
- [ ] Import proxied HTTP history, request/response bodies, passive-scan alerts,
  active-scan results, spider results, and AJAX-spider results with provenance.
- [ ] Add Blackwall-native request/response inspection, editing, resend/replay, and
  comparison so common manual proxy work no longer requires opening the ZAP UI.
- [ ] Keep a temporary route to the complete ZAP UI for capabilities Blackwall has
  not exposed yet; record those fallbacks to prioritize later replacement.

### Planned bug-bounty tool integrations

Treat this list as an integration portfolio, not as a requirement that every item
becomes a Launchpad card. Prefer adapters for executables, service integrations for
stateful systems, and internal libraries for reusable behavior.

#### Launchpad adapters

- [x] Add `subfinder` for passive subdomain discovery and normalize discovered
  names into candidate assets with source provenance.
- [ ] Add ProjectDiscovery `httpx` for reachability checks, HTTP metadata, and
  validation of output from `subfinder` and other discovery adapters.
- [x] Place Amass on indefinite hold and keep its disconnected implementation in
  `recon_modules/amass_hold` for possible future reassessment.
- [ ] Add Katana for scoped crawling and normalize URLs, forms, parameters, and
  JavaScript references without silently expanding beyond scope.
- [ ] Add `ffuf` for content, virtual-host, and parameter fuzzing with rate,
  concurrency, recursion, matcher, and filter controls visible in its profiles.
- [ ] Add Arjun as a focused hidden-parameter discovery adapter. Keep it separate
  from `ffuf` because its request model and output semantics differ.
- [ ] Add Nuclei with pinned template metadata, template/version capture, severity
  and confidence mapping, and raw JSONL retained beside normalized findings.

#### Stateful and UI-backed integrations

- [ ] Configure ZAP routing in **Settings > Proxy**, control supported operations
  through its API, and expose the resulting traffic and evidence through
  Blackwall-native views.
- [ ] Add Playwright as a managed browser-automation integration for authenticated
  navigation, screenshots, traces, and operator-authored workflows. Keep browser
  profiles, cookies, and credentials out of ordinary logs and manifests.
- [ ] Add Interactsh as an OAST provider integration rather than a one-shot scanner:
  create or register sessions, protect correlation tokens, poll interactions, and
  link callbacks to the originating run, request, asset, and finding.
- [ ] Evaluate GraphQL Voyager as an optional schema visualization inside Evidence
  after Blackwall can import or introspect a GraphQL schema. It is not a scanner or
  a general-purpose Launchpad module.

#### Internal capabilities and external interoperability

- [ ] Use Python `asyncio` for bounded orchestration and concurrency, `requests`
  (or one deliberately selected HTTP client) for controlled HTTP operations,
  PyJWT for explicit JWT inspection/mutation workflows, and `difflib` for response
  comparison. These are implementation capabilities, not user-facing modules.
- [ ] Add reusable request-diff evidence for authorization/IDOR and race-condition
  workflows only after request redaction, deterministic replay, concurrency limits,
  and scope checks are in place.
- [ ] Replace the useful Param Miner workflow with native hidden-input discovery
  over requests selected from ZAP history or created in Blackwall. Support query,
  body, header, and cookie insertion points, configurable wordlists, safe batching,
  and differential response scoring with reproducible evidence.
- [ ] Do not require `jq` as Blackwall's JSON database or parser. Preserve JSON and
  JSONL artifacts, parse them natively, and optionally offer copy/export recipes
  for operators who use `jq` outside Blackwall.

Adapter workflows should compose typed outputs where practical, for example
`subfinder -> httpx -> Katana or Nuclei`, while retaining the raw output
and provenance from every individual stage.

The application must not claim that all traffic is proxied. Environment proxy
variables do not affect every scanner, DNS client, or raw-socket tool.

The retired Amass prototype exposed a v5.1.1 bootstrap dependency on hard-coded
public DNS resolvers that VPN DNS-leak protection can block. The standalone
`scripts/amass-mullvad-dns.ps1` helper can temporarily enable that broader resolver
pool for manual testing of Amass or other DNS discovery tools, then restore the
known Mullvad defaults. Blackwall never invokes it or changes operator VPN/DNS settings.

## v1.0 — Extensibility

- [ ] Stabilize a declarative adapter manifest for common CLI tools.
- [ ] Add Python extension hooks for behavior a manifest cannot express.
- [ ] Provide an adapter validator, fixtures, documentation, and test harness.
- [ ] Support importable tool packs with explicit version compatibility.
- [ ] Detect missing executables and provide verified installation guidance.
- [ ] Evaluate isolated/containerized adapters.
- [ ] Consider guarded package-manager integration only after the Linux packaging
  and privilege model are defined; keep installation optional and separate from
  portable executable discovery.

## Deferred ideas

These are not part of the core roadmap unless later workflow testing demonstrates
a clear need:

- A general-purpose interactive terminal or custom shell.
- System-wide transparent proxying.
- A one-for-one recreation of the complete ZAP interface. Replace common manual
  workflows with Blackwall-native views based on actual operator needs instead.
- Automatic `apt`, `pacman`, or other privileged package-manager calls.
- Decorative globes, ambient animations, or metrics without operator value.
- Multiple finished visual themes before the primary design system is stable.

## Cross-cutting engineering requirements

- [ ] Use Linux as the reference environment and first packaging target while
  continuing to run and test the application on Windows during development.
- [ ] Keep shared code platform-neutral: use `pathlib`, argument arrays, portable
  project-relative paths, and Python APIs instead of shell-specific commands or
  hard-coded drive paths.
- [ ] Isolate unavoidable differences—executable discovery, process groups,
  cancellation signals, certificate stores, permissions, and browser launching—
  behind small platform services with explicit capability checks.
- [ ] Add automated smoke tests on Linux and Windows; do not let support for either
  platform distort the persisted project format or adapter schema.
- [x] Bind the local application to `127.0.0.1` by default, with validated
  `--host`/`--port` overrides and a warning for explicit non-loopback access.
- [ ] Define authentication and isolation requirements before permitting remote
  access.
- [ ] Escape or sanitize tool output before rendering it in the browser.
- [ ] Redact secrets from logs, manifests, and command previews.
- [ ] Prevent path traversal outside the active project.
- [ ] Test scope enforcement, command construction, cancellation, parsers,
  migrations, and provenance.
- [ ] Document data retention and cleanup without silently deleting evidence.
- [ ] Review the licenses and redistribution rules of integrated tools.

## Open product decisions

- Public project name and original visual identity.
- Initial Linux packaging format and the promised Windows support tier.
- Whether a project may be opened by more than one application instance.
- Expected project size and retention period.
- Whether collaboration is ever in scope or the product remains single-user and
  local-only.
