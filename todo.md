# Recon Dashboard

## Product statement

Build a local-first workspace for authorized web reconnaissance and OSINT work. The
application should let an operator launch compatible tools from a consistent
interface, optionally organize work into scoped projects, preserve evidence, and
turn tool output into traceable assets and findings.

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
- **Adapters over special cases.** Tool behavior should eventually be described by
  a common adapter contract instead of being embedded throughout the UI.
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

- [ ] Create, open, and validate a project directory.
- [ ] Add an open/browse action for reopening existing projects as workspace tabs.
- [ ] Allow tools to run with direct targets when no project is open.
- [ ] Allow a project run to use direct targets without first adding them to scope.
- [ ] Store project metadata in a versioned `project.json` file.
- [ ] Add saved target sets containing domains, IPs, CIDRs, and URLs.
- [ ] Support explicit includes, exclusions, and review-required targets.
- [ ] Keep authorization status separate from ownership confidence:
  - `scope_status`: `allowed`, `denied`
  - `ownership_confidence`: `confirmed`, `likely`, or `unknown`
- [x] Make the active project and target set visible throughout the UI.
- [ ] Tag each run with a nullable project ID and a captured project display name.
- [ ] Determine project association from the active workspace. Module configuration
  must not contain a separate project selector: runs launched inside a project are
  filed into it automatically, while launchpad runs outside a project remain
  unattached.
- [ ] Add run-history filtering by project ID/name, including a `No project`
  filter. This can follow the first polished UI implementation.

### v0.1c — One complete execution path

- [ ] Define the first tool-adapter schema.
- [ ] Build **Settings > Modules** to list, add, and edit modules. The editor must
  show an automatically allocated, read-only numeric ID after the module type,
  plus `eyebrow`, optional `icon`, `description`, `bin`, and executable `path`.
- [ ] Validate module executable paths, show availability/version state, and use
  the catalog's default icon whenever no icon is selected.
- [ ] Support named scan profiles and provide per-module profile creation and
  editing in **Settings > Modules**.
- [ ] Integrate one low-risk tool from availability check through completed run.
- [ ] Preview the exact executable and arguments before launch.
- [ ] Launch processes without interpolating user input into a shell string.
- [ ] Stream stdout and stderr to the run console.
- [ ] Add a deliberate starting/loading state to the run console for the period
  between launch and the first process output.
- [ ] Support queueing, concurrency limits, timeouts, and process-group cancellation.
- [ ] Preserve run state if the browser disconnects or refreshes.
- [ ] Record executable path, version, arguments, inputs, timestamps, duration,
  exit code, and artifact hashes in a run manifest.
- [ ] Add run history and artifact download/open actions.

### v0.1 acceptance criteria

- An operator can enter a direct target, configure the first adapter, review its
  command, run it without a project, watch its output, cancel it, and reopen its
  evidence from run history.
- When the operator is inside a project, the run is attached to that project
  automatically and may use project assets as targets. Outside a project, the run
  remains unattached.
- A denied target cannot be launched accidentally.
- Raw artifacts and a complete manifest remain available after restarting the app.
- The main workflow is usable without an interactive terminal.

## v0.2 — Evidence and asset workspace

- [x] Prototype an in-scope Evidence browser where assets, vulnerabilities, and
  identities act as relationship nodes and the inspector lists their artifacts.
- [ ] Use SQLite as the searchable project index while keeping raw artifacts on
  disk.
- [ ] Add schema versions, migrations, workspace locking, and crash recovery.
- [ ] Define normalized record envelopes with stable IDs and source provenance.
- [ ] Implement `parse -> normalize -> deduplicate -> scope review` as explicit,
  independently testable stages.
- [ ] Preserve every raw value alongside its normalized comparison key.
- [ ] Treat URL canonicalization conservatively and record the normalization
  version and transformations.
- [ ] Retain out-of-scope discoveries, hide them from normal workflows, and expose
  them only in a deliberate review view.
- [ ] Build asset, run, artifact, and finding detail screens.
- [ ] Add finding lifecycle states: `candidate`, `validated`, `false_positive`, and
  `accepted_risk`.
- [ ] Add search, filters, tags, notes, JSON/CSV export, and project backup.
- [ ] Prove interoperability by using normalized output from one adapter as input
  to a second adapter.

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

- [ ] Add saved multi-tool workflows with explicit inputs and outputs.
- [ ] Store relationships between assets, findings, artifacts, and runs as part of
  the Evidence model.
- [ ] Add a useful relationship view inside Evidence only after real project data
  can drive it.
- [ ] Add per-tool proxy capability declarations and configuration.
- [ ] Connect **Settings > Proxy** to application-level HTTP/SOCKS configuration
  and show which adapters support the selected protocol.
- [ ] Clearly identify tools whose traffic cannot be routed through the configured
  HTTP or SOCKS proxy.
- [ ] Connect to the ZAP API to manage contexts, start supported scans, monitor
  progress, and import alerts with provenance.
- [ ] Provide a direct route to the full ZAP interface for features not represented
  in the dashboard.

The application must not claim that all traffic is proxied. Environment proxy
variables do not affect every scanner, DNS client, or raw-socket tool.

## v1.0 — Extensibility

- [ ] Stabilize a declarative adapter manifest for common CLI tools.
- [ ] Add Python extension hooks for behavior a manifest cannot express.
- [ ] Provide an adapter validator, fixtures, documentation, and test harness.
- [ ] Support importable tool packs with explicit version compatibility.
- [ ] Detect missing executables and provide verified installation guidance.
- [ ] Evaluate isolated/containerized adapters.
- [ ] Consider guarded package-manager integration only after the supported
  operating systems and privilege model are defined.

## Deferred ideas

These are not part of the core roadmap unless later workflow testing demonstrates
a clear need:

- A general-purpose interactive terminal or custom shell.
- System-wide transparent proxying.
- Recreating the complete ZAP or Burp user interface.
- Automatic `apt`, `pacman`, or other privileged package-manager calls.
- Decorative globes, ambient animations, or metrics without operator value.
- Multiple finished visual themes before the primary design system is stable.

## Cross-cutting engineering requirements

- [ ] Decide whether the initial supported environment is Linux-only or
  cross-platform.
- [ ] Bind the local application to `127.0.0.1` by default.
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
- Initial operating system and packaging format.
- First real adapter used for the end-to-end execution slice.
- Whether a project may be opened by more than one application instance.
- Expected project size and retention period.
- Whether collaboration is ever in scope or the product remains single-user and
  local-only.
