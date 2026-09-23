"""Interactive NiceGUI shell for the Blackwall launchpad."""

from __future__ import annotations

from functools import partial
from pathlib import Path
import re
import shlex

from nicegui import events, ui
from app_config import AppConfig
from blackwall_execution import (
    ExecutionError, ExecutionManager, RunEvent, RunManifest, RunRequest,
    expand_argument_template,
)
from blackwall_projects import Project, ProjectStore, ProjectValidationError, ProjectWorkspace
from blackwall_projects.picker import LocalDirectoryPicker
from blackwall_scope import (
    ExecutionContext,
    ScopeStatus,
    ScopeStore,
    ScopeValidationError,
    Target,
    TargetSelection,
    evaluate_targets,
)
from recon_modules import FAVICON_DATA_URL, ModuleDefinition, load_default_catalog
from workspace_data import ASSETS, EVIDENCE, SCOPE_RULES


# Shared resources and module data loaded once when the application starts.
STYLESHEET = Path(__file__).with_name("styles.css")
ESCAPE_KEY_BEHAVIOR = """
<script>
(() => {
  if (window.__blackwallEscapeBlurInstalled) return;
  window.__blackwallEscapeBlurInstalled = true;
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    const active = document.activeElement;
    const writable = active?.matches(
      'input:not([readonly]):not([disabled]), textarea:not([readonly]):not([disabled]), [contenteditable="true"]'
    );
    if (writable) {
      active.blur();
      event.preventDefault();
      event.stopImmediatePropagation();
      return;
    }

    // Dialogs opt into Escape dismissal by marking their visible close control.
    const closeButton = [...document.querySelectorAll('[data-escape-close="true"]')]
      .filter(button => button.getClientRects().length > 0).at(-1);
    if (!closeButton) return;
    closeButton.click();
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);
})();
</script>
"""
MODULE_CATALOG = load_default_catalog()

# Temporary finding records used to shape the UI before scanner persistence exists.
FINDINGS = (
    {
        "id": "FW-1042", "severity": "critical",
        "title": "Remote code execution via template injection",
        "asset": "portal.acme.test", "source": "Nuclei", "confidence": "Confirmed", "seen": "12:42:18",
        "location": "POST /api/v2/render",
        "description": "User-controlled template input is evaluated by the server process.",
        "evidence": "{{7*7}} returned 49 in the rendered response body.",
        "recommendation": "Remove dynamic template evaluation and strictly allow-list supported fields.",
    },
    {
        "id": "FW-1038", "severity": "high", "title": "Exposed administrative interface",
        "asset": "admin.acme.test:8443", "source": "HTTPX", "confidence": "High", "seen": "12:37:04",
        "location": "https://admin.acme.test:8443/console",
        "description": "An administrative console is reachable from the public network.",
        "evidence": "HTTP 200 with the product administration login page and version banner.",
        "recommendation": "Restrict the interface to the management network and require strong authentication.",
    },
    {
        "id": "FW-1029", "severity": "medium", "title": "TLS certificate name mismatch",
        "asset": "legacy.acme.test", "source": "TLSX", "confidence": "Medium", "seen": "12:19:51",
        "location": "legacy.acme.test:443",
        "description": "The presented certificate does not contain the requested hostname.",
        "evidence": "Certificate SAN contains old-portal.acme.test but not legacy.acme.test.",
        "recommendation": "Replace the certificate with one covering the active service hostname.",
    },
    {
        "id": "FW-1016", "severity": "low",
        "title": "Server version disclosed in response header",
        "asset": "api.acme.test", "source": "HTTPX", "confidence": "Low", "seen": "11:58:23",
        "location": "GET /health",
        "description": "The Server response header exposes an exact software version.",
        "evidence": "Server: nginx/1.24.0",
        "recommendation": "Suppress version tokens in externally visible response headers.",
    },
    {
        "id": "FW-1007", "severity": "info", "title": "Additional hostname discovered",
        "asset": "status.acme.test", "source": "Amass", "confidence": "N/A", "seen": "11:44:09",
        "location": "status.acme.test",
        "description": "A previously unknown hostname was identified through passive DNS sources.",
        "evidence": "A record resolves to 203.0.113.42 and serves an HTTP status page.",
        "recommendation": "Review ownership and add the host to the project scope if appropriate.",
    },
)

# Navigation is data-driven: each entry defines its icon, label, view ID, and badge.
NAV_ITEMS = (
    ("grid_view", "Launchpad", "launchpad", ""),
    ("flag", "Findings", "findings", f"{len(FINDINGS):02d}"),
    ("language", "Assets", "assets", "24"),
    ("link", "Evidence", "evidence", f"{len(EVIDENCE):02d}"),
    ("gpp_good", "Scope", "scope", "27"),
    ("terminal", "Runs", "runs", ""),
)

VIEW_NAMES = {
    "runs": "Runs",
    "settings": "Settings",
    "findings": "Findings",
    "assets": "Assets",
    "evidence": "Evidence",
    "scope": "Scope",
}

FUNCTIONAL_VIEWS = {"launchpad", "findings", "assets", "evidence", "scope", "runs"}
SETTINGS_SECTIONS = (
    ("tune", "General", "general"),
    ("folder_open", "Projects", "projects"),
    ("swap_horiz", "Proxy", "proxy"),
    ("extension", "Modules", "modules"),
    ("palette", "Appearance", "appearance"),
)


# Small wrapper used to keep icon creation consistent throughout the UI.
def icon(name: str, classes: str = "") -> None:
    ui.icon(name).classes(classes)


class DashboardUI:
    """Owns per-page UI state and redraws the affected regions."""

    # State and application bootstrap.
    def __init__(
        self,
        project_store: ProjectStore | None = None,
        app_config: AppConfig | None = None,
        execution_manager: ExecutionManager | None = None,
    ) -> None:
        self.app_config = app_config or AppConfig()
        self.active_view = "launchpad"
        self.module_catalog = MODULE_CATALOG
        modules = self.module_catalog.modules
        self.selected_module_id = "04"
        self.selected_finding_id = FINDINGS[0]["id"]
        self.selected_asset_id = ASSETS[0]["id"]
        self.selected_evidence_id = EVIDENCE[0]["id"]
        self.selected_scope_id = SCOPE_RULES[0]["id"]
        self.selected_run_id: str | None = None
        self.target_modes = {module.id: "direct" for module in modules}
        self.direct_targets = {module.id: module.target_example for module in modules}
        self.selected_profiles = {module.id: module.default_profile.name for module in modules}
        self.selected_target_sets: dict[str, str] = {}
        self.search_query = ""
        self.console_minimized = False
        self.console_fullscreen = False
        self.inspector_collapsed = False
        self.proxy_enabled = False
        self.scope_enforced = False
        self.settings_open = False
        self.settings_section = "general"
        self.settings_module_id = modules[0].id
        self.project_workspace = ProjectWorkspace(project_store or ProjectStore())
        self.execution_manager = execution_manager or ExecutionManager()
        self.active_run_id: str | None = None
        self._run_unsubscribe = None

    # Resolve the selected ID through the module catalog instead of duplicating data.
    @property
    def selected_module(self) -> ModuleDefinition:
        return self.module_catalog.get(self.selected_module_id)

    @property
    def projects(self) -> list[Project]:
        """Currently open project tabs supplied by the project workspace layer."""
        return self.project_workspace.open_projects

    @property
    def active_project_id(self) -> str | None:
        return self.project_workspace.active_project_id

    @property
    def active_project(self) -> Project | None:
        return next(
            (project for project in self.projects if project.id == self.active_project_id), None
        )

    @property
    def selected_finding(self) -> dict[str, str]:
        return next(finding for finding in FINDINGS if finding["id"] == self.selected_finding_id)

    @staticmethod
    def _record(records: tuple[dict[str, str], ...], record_id: str) -> dict[str, str]:
        return next(record for record in records if record["id"] == record_id)

    def run_records(self) -> tuple[dict[str, str], ...]:
        """Adapt durable manifests to the existing dense Runs table component."""
        project_paths = tuple(project.path for project in self.projects)
        manifests = self.execution_manager.list_runs(project_paths)
        return tuple(self._run_record(manifest) for manifest in manifests)

    @staticmethod
    def _run_record(run: RunManifest) -> dict[str, str]:
        targets = ", ".join(item["value"] for item in run.targets) or "—"
        project = f"{run.project_name} / {run.project_id}" if run.project_id else "—"
        command = shlex.join((run.executable, *run.arguments))
        context = f"{run.target_source.replace('_', ' ').title()} / " + (
            "scope enforced" if run.scope_enforced else "scope not enforced"
        )
        duration = "—"
        if run.duration_seconds is not None:
            minutes, seconds = divmod(int(run.duration_seconds), 60)
            duration = f"{minutes:02d}:{seconds:02d}"
        return {
            "id": run.id,
            "state": run.state.value.upper(),
            "module": run.module_bin.upper(),
            "target": targets,
            "project": project,
            "duration": duration,
            "started": run.started_at or run.created_at,
            "exit_code": "—" if run.exit_code is None else str(run.exit_code),
            "artifacts": str(len(run.artifacts)),
            "profile": run.profile_name,
            "command": command,
            "context": context,
            "summary": run.error or f"Run state: {run.state.value}.",
        }

    def build(self) -> None:
        ui.add_css(STYLESHEET.read_text(encoding="utf-8"))
        ui.add_head_html(ESCAPE_KEY_BEHAVIOR)
        ui.colors(primary="#22cfff")
        ui.dark_mode(True)

        with ui.element("div").classes("app-shell") as self.shell:
            self.rail = ui.element("aside").classes("rail")
            self.topbar = ui.element("header").classes("topbar")
            self.workspace = ui.element("main").classes("workspace")
            self.inspector = ui.element("aside").classes("inspector")
            self.console = ui.element("section").classes("console")

        self.render_rail()
        self.render_topbar()
        self.render_workspace()
        self.render_inspector()
        self.render_console()
        self.render_settings_dialog()
        self.render_project_dialogs()
        self.create_location_picker = LocalDirectoryPicker(
            "Choose project parent", self.set_create_project_parent
        )
        self.open_project_picker = LocalDirectoryPicker("Open project directory", self.open_project)

    # Primary navigation and launchpad interaction handlers.
    def navigate(self, view_id: str) -> None:
        if view_id != self.active_view:
            self.search_query = ""
        self.active_view = view_id
        if view_id in FUNCTIONAL_VIEWS:
            self.shell.classes(remove="nyi-mode")
        else:
            self.shell.classes(add="nyi-mode")
        if view_id == "evidence":
            self.shell.classes(add="evidence-mode")
        else:
            self.shell.classes(remove="evidence-mode")
        self.update_rail_selection()
        self.render_topbar()
        self.render_workspace()
        self.render_inspector()

    def select_record(self, view_id: str, record_id: str) -> None:
        setattr(self, f"selected_{view_id.rstrip('s')}_id", record_id)
        if view_id == "runs":
            self.active_run_id = record_id
            self.render_console()
        if self.inspector_collapsed:
            self.inspector_collapsed = False
            self.update_inspector_layout()
        self.render_workspace()
        self.render_inspector()

    def preview_evidence_filter(self, label: str) -> None:
        ui.notify(f"{label.title()} evidence filtering is not connected yet")

    def open_settings(self) -> None:
        self.settings_open = True
        self.update_rail_selection()
        self.settings_dialog.open()

    def close_settings(self) -> None:
        self.settings_open = False
        self.update_rail_selection()
        self.settings_dialog.close()

    def sync_settings_closed(self) -> None:
        """Keep rail selection correct when Escape or the backdrop closes Settings."""
        self.settings_open = False
        self.update_rail_selection()

    def select_settings_section(self, section: str) -> None:
        self.settings_section = section
        self.render_settings_navigation()
        self.render_settings_content()

    # === START: PROJECT DIALOGS ===
    # Thin NiceGUI forms; all filesystem work remains in blackwall_projects.
    def render_project_dialogs(self) -> None:
        with ui.dialog().classes("project-dialog") as self.create_project_dialog:
            with ui.card().classes("project-modal"):
                with ui.element("header").classes("settings-header"):
                    with ui.element("div"):
                        ui.label("PROJECT / CREATE").classes("section-kicker")
                        ui.label("Create project").classes("settings-title")
                    with ui.element("button").classes("settings-close").props(
                        'type=button aria-label="Close create project" data-escape-close=true'
                    ).on("click", self.create_project_dialog.close):
                        ui.label("×")
                with ui.element("div").classes("settings-field"):
                    ui.label("PROJECT NAME").classes("field-label")
                    self.create_project_name = ui.input().props(
                        "dense outlined autofocus maxlength=120"
                    ).classes("config-control")
                with ui.element("div").classes("settings-field"):
                    ui.label("PARENT DIRECTORY").classes("field-label")
                    with ui.element("div").classes("directory-path-row"):
                        self.create_project_location = ui.input().props("dense outlined").classes(
                            "config-control directory-path-input"
                        )
                        ui.button("BROWSE", on_click=self.browse_create_location).props(
                            "flat dense no-caps"
                        ).classes("settings-action")
                with ui.element("div").classes("settings-actions"):
                    ui.button("CREATE", icon="create_new_folder", on_click=self.create_project).props(
                        "flat no-caps"
                    ).classes("settings-action primary")
    # === END: PROJECT DIALOGS ===

    def select_settings_module(self, module_id: str) -> None:
        self.settings_module_id = module_id
        self.render_settings_content()

    def new_settings_module(self) -> None:
        self.settings_module_id = "__new__"
        self.render_settings_content()

    def select_finding(self, finding_id: str) -> None:
        self.selected_finding_id = finding_id
        if self.inspector_collapsed:
            self.inspector_collapsed = False
            self.update_inspector_layout()
        self.render_workspace()
        self.render_inspector()

    def select_module(self, module_id: str) -> None:
        self.selected_module_id = module_id
        module = self.selected_module
        self.target_modes.setdefault(module.id, "direct")
        self.direct_targets.setdefault(module.id, module.target_example)
        self.selected_profiles.setdefault(module.id, module.default_profile.name)
        if self.inspector_collapsed:
            self.inspector_collapsed = False
            self.update_inspector_layout()
        self.render_workspace()
        self.render_inspector()

    def set_target_mode(self, mode: str) -> None:
        self.target_modes[self.selected_module_id] = mode
        self.render_inspector()

    def set_direct_target(self, module_id: str, event: events.ValueChangeEventArguments) -> None:
        self.direct_targets[module_id] = str(event.value or "")

    def set_profile(self, module_id: str, event: events.ValueChangeEventArguments) -> None:
        self.selected_profiles[module_id] = str(event.value)
        self.render_inspector()

    def set_target_set(self, module_id: str, event: events.ValueChangeEventArguments) -> None:
        self.selected_target_sets[module_id] = str(event.value)

    def set_search_query(self, event: events.ValueChangeEventArguments) -> None:
        self.search_query = str(event.value or "")
        if self.active_view in FUNCTIONAL_VIEWS:
            self.render_workspace()

    def set_proxy_enabled(self, event: events.ValueChangeEventArguments) -> None:
        self.proxy_enabled = bool(event.value)
        if self.settings_open and self.settings_section == "proxy":
            self.render_settings_content()

    def set_scope_enforced(self, event: events.ValueChangeEventArguments) -> None:
        self.scope_enforced = bool(event.value)

    def _selected_profile(self, module: ModuleDefinition):
        name = self.selected_profiles.get(module.id, module.default_profile.name)
        return next((profile for profile in module.profiles if profile.name == name), module.default_profile)

    def _target_selection(self, module: ModuleDefinition) -> TargetSelection:
        if self.target_modes[module.id] == "direct":
            values = tuple(
                value.strip() for value in re.split(r"[\r\n]+", self.direct_targets[module.id])
                if value.strip()
            )
            if not values:
                raise ScopeValidationError("enter at least one target")
            return TargetSelection.direct(Target.parse(value) for value in values)

        project = self.active_project
        if project is None:
            raise ScopeValidationError("open a project before selecting a saved target set")
        document = ScopeStore(project.path).load()
        target_set_id = self.selected_target_sets.get(module.id)
        if not target_set_id and document.target_sets:
            target_set_id = document.target_sets[0].id
        if not target_set_id:
            raise ScopeValidationError("this project has no saved target sets")
        return TargetSelection.saved(document.get_target_set(target_set_id))

    async def launch_selected_module(self) -> None:
        """Translate UI state into a typed request; execution remains outside the UI."""
        module = self.selected_module
        project = self.active_project
        try:
            selection = self._target_selection(module)
            rules = ScopeStore(project.path).load().rules if project else ()
            evaluations = evaluate_targets(selection.targets, rules, enforce=self.scope_enforced)
            blocked = tuple(item for item in evaluations if not item.launch_allowed)
            if blocked:
                targets = ", ".join(item.target.value for item in blocked)
                raise ScopeValidationError(f"scope enforcement blocked: {targets}")
            context = ExecutionContext(
                selection=selection,
                project_id=project.id if project else None,
                project_name=project.name if project else None,
                scope_enforced=self.scope_enforced,
            )
            request = RunRequest(module=module, profile=self._selected_profile(module), context=context)
            run = await self.execution_manager.start(request, project.path if project else None)
        except (ExecutionError, OSError, ScopeValidationError, KeyError) as error:
            ui.notify(str(error), type="negative")
            return

        if self._run_unsubscribe:
            self._run_unsubscribe()
        self.active_run_id = run.id
        self.selected_run_id = run.id
        self._run_unsubscribe = self.execution_manager.subscribe(run.id, self.handle_run_event)
        self.console_minimized = False
        self.update_console_layout()
        self.render_console()
        ui.notify(f"Started {run.id}", type="positive")

    def handle_run_event(self, event: RunEvent) -> None:
        """Update the connected console without coupling the runner to NiceGUI."""
        if event.run.id != self.active_run_id:
            return
        if event.text is not None and hasattr(self, "run_output"):
            prefix = "[stderr] " if event.stream == "stderr" else ""
            self.run_output.push(prefix + event.text)
        if hasattr(self, "console_state_label"):
            self.console_state_label.set_text(f"{event.run.id} / {event.run.state.value.upper()}")
        if hasattr(self, "cancel_run_button"):
            self.cancel_run_button.set_visibility(not event.run.state.terminal)
        if self.active_view == "runs" and event.text is None:
            self.render_workspace()
            self.render_inspector()

    async def cancel_active_run(self) -> None:
        if self.active_run_id and await self.execution_manager.cancel(self.active_run_id):
            ui.notify(f"Cancellation requested for {self.active_run_id}")

    # Project-tab actions delegate persistence and validation to blackwall_projects.
    def select_project(self, project_id: str) -> None:
        self.project_workspace.select(project_id)
        self.render_topbar()
        if self.active_view == "launchpad":
            self.render_inspector()

    def add_project_tab(self) -> None:
        self.create_project_name.value = f"UNTITLED PROJECT {len(self.projects) + 1:02d}"
        self.create_project_location.value = str(self.project_workspace.store.root)
        self.create_project_dialog.open()

    def create_project(self) -> None:
        try:
            parent = Path(str(self.create_project_location.value or "")).expanduser()
            project = self.project_workspace.create(str(self.create_project_name.value or ""), parent)
        except (OSError, ProjectValidationError) as error:
            ui.notify(str(error), type="negative")
            return
        self.create_project_dialog.close()
        self.execution_manager.recover_incomplete((project.path,))
        ui.notify(f"Created {project.id} / {project.name}", type="positive")
        self.refresh_project_surfaces()

    def browse_create_location(self) -> None:
        requested = Path(str(self.create_project_location.value or self.project_workspace.store.root))
        try:
            if requested.expanduser().resolve(strict=False) == self.project_workspace.store.root:
                requested.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            ui.notify(f"Cannot open default project location: {error}", type="negative")
            return
        self.create_location_picker.open(requested)

    def set_create_project_parent(self, path: Path) -> None:
        self.create_project_location.value = str(path)

    def browse_for_project(self) -> None:
        start = self.project_workspace.store.root.parent
        start.mkdir(parents=True, exist_ok=True)
        self.open_project_picker.open(start)

    def open_project(self, reference: str | Path) -> None:
        try:
            project = self.project_workspace.open(reference)
        except (OSError, ProjectValidationError) as error:
            ui.notify(str(error), type="negative")
            return
        ui.notify(f"Opened {project.id} / {project.name}", type="positive")
        self.execution_manager.recover_incomplete((project.path,))
        self.refresh_project_surfaces()

    def refresh_project_surfaces(self) -> None:
        self.render_topbar()
        if self.settings_open and self.settings_section == "projects":
            self.render_settings_content()

    def close_project_tab(self, project_id: str) -> None:
        self.project_workspace.close(project_id)
        self.refresh_project_surfaces()

    # Collapsible console and module-inspector state.
    def toggle_console_minimized(self) -> None:
        self.console_minimized = not self.console_minimized
        if self.console_minimized:
            self.console_fullscreen = False
        self.update_console_layout()
        self.render_console()

    def toggle_console_fullscreen(self) -> None:
        self.console_fullscreen = not self.console_fullscreen
        if self.console_fullscreen:
            self.console_minimized = False
        self.update_console_layout()
        self.render_console()

    def toggle_inspector_collapsed(self) -> None:
        self.inspector_collapsed = not self.inspector_collapsed
        self.update_inspector_layout()
        self.render_inspector()

    def update_inspector_layout(self) -> None:
        if self.inspector_collapsed:
            self.shell.classes(add="inspector-collapsed")
        else:
            self.shell.classes(remove="inspector-collapsed")

    def update_console_layout(self) -> None:
        self.shell.classes(
            remove="console-minimized console-fullscreen",
            add=(
                "console-fullscreen"
                if self.console_fullscreen
                else "console-minimized" if self.console_minimized else ""
            ),
        )

    # === START: LEFT RAIL ===
    # Left navigation rail. All standard entries are generated from NAV_ITEMS.
    def render_rail(self) -> None:
        self.rail.clear()
        self.nav_buttons = {}
        with self.rail:
            with ui.element("div").classes("brand"):
                ui.image(FAVICON_DATA_URL).classes("brand-mark").props("fit=contain")
                with ui.element("div").classes("brand-copy"):
                    ui.label("BLACKWALL").classes("brand-title")
                    ui.label("RECON WORKSPACE").classes("brand-sub")

            ui.label("WORKSPACE").classes("rail-label")
            for icon_name, label, view_id, count in NAV_ITEMS:
                classes = "nav-item active" if self.active_view == view_id else "nav-item"
                with ui.element("button").classes(classes).props(
                    f'type=button aria-label="{label}" title="{label}"'
                ).on(
                    "click", partial(self.navigate, view_id)
                ) as nav_button:
                    self.nav_buttons[view_id] = nav_button
                    icon(icon_name)
                    ui.label(label)
                    if count:
                        ui.label(count).classes("nav-count")

            ui.element("div").classes("rail-spacer")
            ui.label("SYSTEM").classes("rail-label")
            classes = "nav-item active" if self.settings_open else "nav-item"
            with ui.element("button").classes(classes).props(
                'type=button aria-label="Settings" title="Settings"'
            ).on(
                "click", self.open_settings
            ) as settings_button:
                self.nav_buttons["settings"] = settings_button
                icon("settings")
                ui.label("Settings")

    def update_rail_selection(self) -> None:
        for view_id, button in self.nav_buttons.items():
            if view_id == "settings":
                if self.settings_open:
                    button.classes(add="active")
                else:
                    button.classes(remove="active")
            elif view_id == self.active_view:
                button.classes(add="active")
            else:
                button.classes(remove="active")

    # === END: LEFT RAIL ===

    # === START: TOP BAR ===
    # Top bar containing execution toggles, project tabs, search, and utilities.
    def render_topbar(self) -> None:
        self.topbar.clear()
        with self.topbar:
            with ui.element("div").classes("project-stack"):
                with ui.element("div").classes("execution-toggles"):
                    ui.checkbox(
                        "PROXY",
                        value=self.proxy_enabled,
                        on_change=self.set_proxy_enabled,
                    ).props("dense").classes("project-toggle")
                    ui.checkbox(
                        "SCOPE",
                        value=self.scope_enforced,
                        on_change=self.set_scope_enforced,
                    ).props("dense").classes("project-toggle")
                with ui.element("nav").classes("project-tabs"):
                    for project in self.projects:
                        classes = "project-tab active" if self.active_project_id == project.id else "project-tab"
                        with ui.element("div").classes(classes):
                            with ui.element("button").classes("project-tab-select").props("type=button").on(
                                "click", partial(self.select_project, project.id)
                            ):
                                ui.label(project.name)
                                ui.label(project.id).classes("project-tab-count")
                            with ui.element("button").classes("project-tab-close").props(
                                f'type=button aria-label="Close {project.name}"'
                            ).on("click", partial(self.close_project_tab, project.id)):
                                ui.label("×")
                    with ui.element("button").classes("project-tab-add").props(
                        'type=button aria-label="Create project tab"'
                    ).on("click", self.add_project_tab):
                        ui.label("+")

            ui.element("div").classes("top-spacer")
            with ui.element("div").classes("command-search"):
                icon("search")
                search_subject = {
                    "launchpad": "MODULES", "findings": "FINDINGS", "assets": "ASSETS",
                    "evidence": "EVIDENCE", "scope": "SCOPE", "runs": "RUNS",
                }.get(self.active_view, "WORKSPACE")
                ui.input(
                    value=self.search_query,
                    placeholder=f"SEARCH {search_subject}",
                    on_change=self.set_search_query,
                ).props(f"borderless dense debounce=150 aria-label=Search-{search_subject.lower()}").classes(
                    "command-search-input"
                )
                ui.label("CTRL K").classes("keycap")
            with ui.element("button").classes("icon-button").props("type=button aria-label=Notifications"):
                icon("notifications_none")
            with ui.element("button").classes("icon-button").props("type=button aria-label=Fullscreen"):
                icon("fullscreen")

    # === END: TOP BAR ===

    # === START: WORKSPACE ROUTER ===
    # Main content region dispatches to the active workspace renderer.
    def render_workspace(self) -> None:
        self.workspace.clear()
        with self.workspace:
            if self.active_view == "launchpad":
                self.render_launchpad()
                return
            if self.active_view == "findings":
                self.render_findings_workspace()
                return
            if self.active_view == "assets":
                self.render_assets_workspace()
                return
            if self.active_view == "evidence":
                self.render_evidence_workspace()
                return
            if self.active_view == "scope":
                self.render_scope_workspace()
                return
            if self.active_view == "runs":
                self.render_runs_workspace()
                return
            self.render_nyi_view()

    # === END: WORKSPACE ROUTER ===

    # === START: LAUNCHPAD VIEW ===
    def render_launchpad(self) -> None:
        """Render the module selection workspace."""
        ui.label("OPERATIONS / LAUNCHPAD").classes("section-kicker")
        with ui.element("div").classes("title-row"):
            ui.label("Recon modules").classes("page-title")
            ui.label(f"VIEW 01 / {len(self.module_catalog):02d} MODULES").classes("view-index")

        with ui.element("div").classes("module-heading"):
            with ui.element("div").classes("filters"):
                ui.label("ALL").classes("filter-active")
                ui.label("DISCOVERY")
                ui.label("WEB")
                ui.label("NETWORK")

        query = self.search_query.strip().casefold()
        visible_modules = tuple(
            module
            for module in self.module_catalog
            if not query
            or query in " ".join((module.description, module.bin, module.eyebrow)).casefold()
        )
        with ui.element("section").classes("module-grid"):
            for module in visible_modules:
                self.render_module_card(module)
        if not visible_modules:
            ui.label("NO MODULES MATCH THE CURRENT SEARCH").classes("module-empty")

    # === END: LAUNCHPAD VIEW ===

    # === START: FINDINGS VIEW ===
    def render_findings_workspace(self) -> None:
        """Render a compact, packet-list-inspired finding table."""
        ui.label("ASSESSMENT / FINDINGS").classes("section-kicker")
        with ui.element("div").classes("title-row"):
            ui.label("Findings").classes("page-title")
            ui.label(f"VIEW 02 / {len(FINDINGS):02d} RECORDS").classes("view-index")

        with ui.element("div").classes("finding-summary"):
            ui.label("ALL").classes("filter-active")
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = sum(finding["severity"] == severity.lower() for finding in FINDINGS)
                ui.label(f"{severity} {count:02d}")

        query = self.search_query.strip().casefold()
        visible_findings = tuple(
            finding for finding in FINDINGS
            if not query or query in " ".join(finding.values()).casefold()
        )
        with ui.element("section").classes("finding-table"):
            with ui.element("div").classes("finding-row finding-header"):
                ui.label("SEVERITY").classes("finding-cell finding-severity")
                ui.label("FINDING").classes("finding-cell finding-name")
                ui.label("ASSET").classes("finding-cell finding-asset")
                ui.label("SOURCE").classes("finding-cell finding-source")
                ui.label("CONFIDENCE").classes("finding-cell finding-confidence")
                ui.label("SEEN").classes("finding-cell finding-seen")

            for finding in visible_findings:
                selected = finding["id"] == self.selected_finding_id
                classes = f"finding-row severity-{finding['severity']}"
                if selected:
                    classes += " selected"
                with ui.element("button").classes(classes).props(
                    f'type=button aria-label="Open finding {finding["id"]}: {finding["title"]}"'
                ).on("click", partial(self.select_finding, finding["id"])):
                    ui.label(finding["severity"].upper()).classes("finding-cell finding-severity")
                    with ui.element("div").classes("finding-cell finding-name"):
                        ui.label(finding["title"]).classes("finding-title")
                        ui.label(finding["id"]).classes("finding-id")
                    ui.label(finding["asset"]).classes("finding-cell finding-asset")
                    ui.label(finding["source"].upper()).classes("finding-cell finding-source")
                    ui.label(finding["confidence"].upper()).classes("finding-cell finding-confidence")
                    ui.label(finding["seen"]).classes("finding-cell finding-seen")
        if not visible_findings:
            ui.label("NO FINDINGS MATCH THE CURRENT SEARCH").classes("module-empty")

    # === END: FINDINGS VIEW ===

    # === START: PROJECT RECORD VIEWS ===
    def render_assets_workspace(self) -> None:
        self.render_record_workspace(
            view_id="assets", kicker="INVENTORY / ASSETS", title="Assets", index="SHOWING 06 / 24",
            filters=("ALL", "DOMAIN", "HOST", "IP", "URL"), records=ASSETS,
            columns=(("type", "TYPE"), ("name", "ASSET"), ("address", "ADDRESS"),
                     ("ports", "PORTS"), ("scope", "SCOPE"), ("source", "SOURCE")),
            selected_id=self.selected_asset_id, tone_key="scope",
        )

    def render_evidence_workspace(self) -> None:
        self.render_record_workspace(
            view_id="evidence", kicker="PROVENANCE / EVIDENCE", title="Evidence", index="05 IN-SCOPE NODES",
            filters=("ALL", "ASSETS", "VULNERABILITIES", "IDENTITIES", "DOMAINS", "URLS"), records=EVIDENCE,
            columns=(("kind", "TYPE"), ("identifier", "IDENTIFIER"), ("scope_anchor", "SCOPE ANCHOR"),
                     ("relations", "RELATED"), ("artifact_count", "ARTIFACTS"), ("updated", "UPDATED")),
            selected_id=self.selected_evidence_id, tone_key="scope", interactive_filters=True,
        )

    def render_scope_workspace(self) -> None:
        self.render_record_workspace(
            view_id="scope", kicker="AUTHORIZATION / SCOPE", title="Scope", index="SHOWING 06 / 27",
            filters=("ALL", "ALLOWED", "DENIED", "REVIEW REQUIRED"), records=SCOPE_RULES,
            columns=(("decision", "DECISION"), ("target", "TARGET"), ("type", "TYPE"),
                     ("ownership", "OWNERSHIP"), ("source", "SOURCE"), ("updated", "UPDATED")),
            selected_id=self.selected_scope_id, tone_key="decision",
        )

    def render_runs_workspace(self) -> None:
        records = self.run_records()
        if records and self.selected_run_id not in {record["id"] for record in records}:
            self.selected_run_id = records[0]["id"]
        self.render_record_workspace(
            view_id="runs", kicker="EXECUTION / RUNS", title="Runs", index=f"{len(records):02d} RECORDS",
            filters=("ALL", "ACTIVE", "COMPLETED", "FAILED", "QUEUED"), records=records,
            columns=(("state", "STATE"), ("module", "MODULE"), ("target", "TARGET"),
                     ("project", "PROJECT"), ("duration", "DURATION"), ("started", "STARTED")),
            selected_id=self.selected_run_id or "", tone_key="state",
        )

    def render_record_workspace(
        self,
        *,
        view_id: str,
        kicker: str,
        title: str,
        index: str,
        filters: tuple[str, ...],
        records: tuple[dict[str, str], ...],
        columns: tuple[tuple[str, str], ...],
        selected_id: str,
        tone_key: str,
        interactive_filters: bool = False,
    ) -> None:
        """Render one of the project-aware record lists with a shared dense pattern."""
        ui.label(kicker).classes("section-kicker")
        with ui.element("div").classes("title-row"):
            ui.label(title).classes("page-title")
            ui.label(index).classes("view-index")

        with ui.element("div").classes(f"record-filters {view_id}-filters"):
            for index, label in enumerate(filters):
                if interactive_filters:
                    ui.button(label, on_click=partial(self.preview_evidence_filter, label)).props(
                        "flat dense no-caps"
                    ).classes(
                        "record-filter-button active" if index == 0 else "record-filter-button"
                    )
                else:
                    ui.label(label).classes("filter-active" if index == 0 else "")

        query = self.search_query.strip().casefold()
        visible_records = tuple(
            record for record in records
            if not query or query in " ".join(str(value) for value in record.values()).casefold()
        )
        with ui.element("section").classes(f"record-table {view_id}-table"):
            with ui.element("div").classes("record-row record-header"):
                for key, label in columns:
                    ui.label(label).classes(f"record-cell record-{key}")

            for record in visible_records:
                tone = record[tone_key].lower().replace(" ", "-").replace("/", "-")
                classes = f"record-row tone-{tone}"
                if record["id"] == selected_id:
                    classes += " selected"
                with ui.element("button").classes(classes).props(
                    f'type=button aria-label="Open {view_id} record {record["id"]}"'
                ).on("click", partial(self.select_record, view_id, record["id"])):
                    for column_index, (key, _label) in enumerate(columns):
                        if column_index == 1:
                            with ui.element("div").classes(f"record-cell record-{key} record-primary"):
                                ui.label(record[key]).classes("record-primary-value")
                                ui.label(record["id"]).classes("record-id")
                        else:
                            ui.label(record[key]).classes(f"record-cell record-{key}")
        if not visible_records:
            ui.label(f"NO {view_id.upper()} RECORDS MATCH THE CURRENT SEARCH").classes("module-empty")

    # === END: PROJECT RECORD VIEWS ===

    # === START: MODULE CARD ===
    # One reusable card renderer handles every data-driven recon module.
    def render_module_card(self, module: ModuleDefinition) -> None:
        selected = module.id == self.selected_module_id
        classes = "module-card selected" if selected else "module-card"
        with ui.element("button").classes(classes).props(
            f'type=button aria-label="Configure {module.description}"'
        ).on("click", partial(self.select_module, module.id)):
            with ui.element("div").classes("card-head"):
                with ui.element("div").classes("card-copy"):
                    ui.label(module.display_eyebrow).classes("card-eyebrow")
                    ui.label(module.description).classes("module-name")
                    ui.label(module.bin.upper()).classes("module-tool")
                icon(module.icon, "module-icon")
            with ui.element("div").classes("card-footer"):
                ui.label(module.target_summary).classes("target-count")
                tone = "muted" if module.state == "MISSING" else "interactive"
                ui.label(module.state).classes(f"state {tone}")

    # === END: MODULE CARD ===

    # === START: NYI VIEW ===
    # Placeholder shared by navigation destinations that do not have a view yet.
    def render_nyi_view(self) -> None:
        view_name = VIEW_NAMES[self.active_view]
        with ui.element("section").classes("nyi-view"):
            with ui.element("div").classes("nyi-frame"):
                ui.label(f"VIEW / {self.active_view.upper()}").classes("section-kicker")
                ui.label(view_name).classes("nyi-title")
                ui.label("NOT YET IMPLEMENTED").classes("nyi-status")
                ui.label("Launchpad is the current development focus.").classes("nyi-copy")
                ui.button(
                    "RETURN TO LAUNCHPAD",
                    icon="grid_view",
                    on_click=partial(self.navigate, "launchpad"),
                ).props("flat no-caps").classes("nyi-return")

    # === END: NYI VIEW ===

    # === START: RIGHT INSPECTOR ===
    # Shared right inspector dispatches to the active view's selected object.
    def render_inspector(self) -> None:
        self.inspector.clear()
        if self.active_view == "findings":
            with self.inspector:
                self.render_finding_inspector()
            return
        if self.active_view == "assets":
            with self.inspector:
                record = self._record(ASSETS, self.selected_asset_id)
                self.render_record_inspector(
                    record, "ASSET", record["name"], f"{record['type']} / {record['scope']}",
                    (("ADDRESS", record["address"]), ("PORTS", record["ports"]),
                     ("SCOPE", record["scope"]), ("SOURCE", record["source"]),
                     ("FIRST SEEN", record["first_seen"]), ("LAST SEEN", record["last_seen"])),
                    (("TECHNOLOGY", record["technology"]), ("PROVENANCE", record["provenance"]),
                     ("NOTES", record["notes"])), record["scope"],
                )
            return
        if self.active_view == "evidence":
            with self.inspector:
                record = self._record(EVIDENCE, self.selected_evidence_id)
                self.render_evidence_inspector(record)
            return
        if self.active_view == "scope":
            with self.inspector:
                record = self._record(SCOPE_RULES, self.selected_scope_id)
                self.render_record_inspector(
                    record, "SCOPE RULE", record["target"], record["decision"],
                    (("DECISION", record["decision"]), ("OWNERSHIP", record["ownership"]),
                     ("TYPE", record["type"]), ("SOURCE", record["source"]),
                     ("UPDATED", record["updated"])),
                    (("APPLIES TO", record["applies"]), ("RATIONALE", record["reason"]),
                     ("NOTES", record["notes"])), record["decision"],
                )
            return
        if self.active_view == "runs":
            with self.inspector:
                records = self.run_records()
                if not records:
                    with ui.element("div").classes("inspector-header"):
                        with ui.element("div").classes("inspector-header-copy"):
                            ui.label("RUNS").classes("panel-number")
                            ui.label("No persisted runs yet").classes("panel-title")
                    return
                record = self._record(records, self.selected_run_id or records[0]["id"])
                self.render_record_inspector(
                    record, "RUN", record["module"], record["state"],
                    (("TARGET", record["target"]), ("PROJECT", record["project"]),
                     ("PROFILE", record["profile"]), ("DURATION", record["duration"]),
                     ("STARTED", record["started"]), ("EXIT CODE", record["exit_code"]),
                     ("ARTIFACTS", record["artifacts"])),
                    (("EXECUTION CONTEXT", record["context"]), ("COMMAND", record["command"]),
                     ("SUMMARY", record["summary"])), record["state"],
                )
            return
        if self.active_view != "launchpad":
            return

        module = self.selected_module
        profile = self._selected_profile(module)
        target_mode = self.target_modes[module.id]
        with self.inspector:
            with ui.element("div").classes("inspector-header"):
                with ui.element("button").classes("inspector-toggle").props(
                    f'type=button aria-label="{"Expand module configuration" if self.inspector_collapsed else "Collapse module configuration"}"'
                ).on("click", self.toggle_inspector_collapsed):
                    icon("chevron_left" if self.inspector_collapsed else "chevron_right")
                with ui.element("div").classes("inspector-header-copy"):
                    ui.label(f"CONFIG / {module.bin.upper()}").classes("panel-number")
                    ui.label(module.description).classes("panel-title")
                    ui.label(f"{module.bin.upper()} / {module.state}").classes("panel-tool")

            if self.inspector_collapsed:
                return

            with ui.element("div").classes("inspector-body"):
                with ui.element("div").classes("field"):
                    ui.label("TARGETS").classes("field-label")
                    with ui.element("div").classes("target-mode"):
                        for label, mode in (("DIRECT", "direct"), ("PROJECT ASSETS", "project")):
                            classes = "target-mode-item active" if target_mode == mode else "target-mode-item"
                            with ui.element("button").classes(classes).props("type=button").on(
                                "click", partial(self.set_target_mode, mode)
                            ):
                                ui.label(label)

                    if target_mode == "direct":
                        ui.textarea(
                            value=self.direct_targets[module.id],
                            on_change=partial(self.set_direct_target, module.id),
                        ).props("dense outlined autogrow").classes("config-control")
                        ui.button(
                            "+ ADD TARGET ON A NEW LINE",
                            on_click=lambda: ui.notify("Enter one target per line"),
                        ).props("flat dense no-caps").classes("text-action")
                    else:
                        project = self.active_project
                        target_sets = ScopeStore(project.path).load().target_sets if project else ()
                        options = {item.id: f"{item.name} / {len(item.targets)} targets" for item in target_sets}
                        selected_set = self.selected_target_sets.get(module.id)
                        if not selected_set and target_sets:
                            selected_set = target_sets[0].id
                            self.selected_target_sets[module.id] = selected_set
                        ui.select(
                            options, value=selected_set,
                            on_change=partial(self.set_target_set, module.id),
                        ).props("dense outlined options-dense").classes("config-control")
                        if not target_sets:
                            ui.label("NO SAVED TARGET SETS IN ACTIVE PROJECT").classes("field-help")

                with ui.element("div").classes("field"):
                    ui.label("SCAN PROFILE").classes("field-label")
                    ui.select(
                        list(module.profile_names), value=profile.name,
                        on_change=partial(self.set_profile, module.id),
                    ).props(
                        "dense outlined options-dense"
                    ).classes("config-control")
                    ui.button(
                        "EDIT / CREATE PROFILES",
                        on_click=lambda: ui.notify("Profile editing is not implemented yet"),
                    ).props("flat dense no-caps").classes("text-action")

                with ui.element("div").classes("field"):
                    ui.label("RUN OPTIONS").classes("field-label")
                    for label, value in profile.options:
                        with ui.element("div").classes("check-row"):
                            ui.label(label).classes("check-name")
                            ui.label(value).classes("check-value")

                with ui.element("div").classes("field"):
                    ui.label("COMMAND PREVIEW").classes("field-label")
                    with ui.element("div").classes("command-preview"):
                        ui.label(module.path).classes("command-tool")
                        try:
                            selection = self._target_selection(module)
                            arguments = expand_argument_template(
                                profile.arguments,
                                tuple(target.normalized for target in selection.targets),
                            )
                            for argument in arguments:
                                ui.label(f" {shlex.quote(argument)}").classes("command-argument")
                            if module.adapter == "httpx":
                                ui.label(" -o <run>/artifacts/httpx.jsonl").classes("command-argument")
                        except (ExecutionError, ScopeValidationError, KeyError):
                            for token_type, text in profile.command:
                                if token_type != "tool":
                                    ui.label(text).classes(f"command-{token_type}")

                with ui.element("div").classes("run-context"):
                    ui.label("TARGET COUNT")
                    ui.label("01 / DIRECT" if target_mode == "direct" else "24 / PROJECT").classes(
                        "run-context-value"
                    )

                ui.button(
                    "LAUNCH",
                    icon="play_arrow",
                    on_click=self.launch_selected_module,
                ).props("unelevated no-caps").classes("launch-button")

    def render_finding_inspector(self) -> None:
        """Render details for the selected finding in the shared right inspector."""
        finding = self.selected_finding
        with ui.element("div").classes("inspector-header finding-inspector-header"):
            with ui.element("button").classes("inspector-toggle").props(
                f'type=button aria-label="{"Expand finding details" if self.inspector_collapsed else "Collapse finding details"}"'
            ).on("click", self.toggle_inspector_collapsed):
                icon("chevron_left" if self.inspector_collapsed else "chevron_right")
            with ui.element("div").classes("inspector-header-copy"):
                ui.label(f"FINDING / {finding['id']}").classes("panel-number")
                ui.label(finding["title"]).classes("panel-title finding-panel-title")
                ui.label(finding["severity"].upper()).classes(
                    f"finding-detail-severity severity-{finding['severity']}"
                )

        if self.inspector_collapsed:
            return

        with ui.element("div").classes("inspector-body finding-detail"):
            for label, value in (
                ("ASSET", finding["asset"]),
                ("LOCATION", finding["location"]),
                ("SOURCE", finding["source"].upper()),
                ("CONFIDENCE", finding["confidence"].upper()),
                ("FIRST SEEN", finding["seen"]),
            ):
                with ui.element("div").classes("finding-detail-row"):
                    ui.label(label).classes("finding-detail-label")
                    ui.label(value).classes("finding-detail-value")

            for label, value in (
                ("DESCRIPTION", finding["description"]),
                ("EVIDENCE", finding["evidence"]),
                ("RECOMMENDATION", finding["recommendation"]),
            ):
                with ui.element("section").classes("finding-detail-section"):
                    ui.label(label).classes("field-label")
                    ui.label(value).classes("finding-detail-copy")

    def render_evidence_inspector(self, record: dict[str, object]) -> None:
        """Show the identifiers and artifacts connected to one in-scope evidence node."""
        with ui.element("div").classes("inspector-header evidence-inspector-header"):
            with ui.element("button").classes("inspector-toggle").props(
                f'type=button aria-label="{"Expand evidence details" if self.inspector_collapsed else "Collapse evidence details"}"'
            ).on("click", self.toggle_inspector_collapsed):
                icon("chevron_left" if self.inspector_collapsed else "chevron_right")
            with ui.element("div").classes("inspector-header-copy"):
                ui.label(f"EVIDENCE NODE / {record['id']}").classes("panel-number")
                ui.label(str(record["identifier"])).classes("panel-title evidence-panel-title")
                ui.label(f"{record['kind']} / {record['scope']}").classes("panel-tool record-tone tone-in-scope")

        if self.inspector_collapsed:
            return

        with ui.element("div").classes("inspector-body evidence-detail"):
            with ui.element("div").classes("evidence-scope-banner"):
                icon("gpp_good")
                with ui.element("div"):
                    ui.label("IN SCOPE").classes("evidence-scope-state")
                    ui.label(f"ANCHOR / {record['scope_anchor']}").classes("evidence-scope-anchor")

            ui.label(str(record["context"])).classes("evidence-context")

            ui.label("RELATED IDENTIFIERS").classes("field-label evidence-subheading")
            with ui.element("div").classes("evidence-identifiers"):
                for identifier_type, value in record["identifiers"]:
                    with ui.element("button").classes("evidence-identifier").props("type=button"):
                        ui.label(identifier_type).classes("evidence-identifier-type")
                        ui.label(value).classes("evidence-identifier-value")

            with ui.element("div").classes("evidence-artifact-heading"):
                ui.label("RELATED ARTIFACTS").classes("field-label")
                ui.label(f"{len(record['artifacts']):02d} RECORDS").classes("settings-meta")
            with ui.element("div").classes("evidence-artifacts"):
                for artifact_type, artifact_id, name, source, integrity in record["artifacts"]:
                    with ui.element("button").classes("evidence-artifact").props(
                        f'type=button aria-label="Open artifact {artifact_id}"'
                    ):
                        ui.label(artifact_type).classes("evidence-artifact-type")
                        with ui.element("div").classes("evidence-artifact-copy"):
                            ui.label(name).classes("evidence-artifact-name")
                            ui.label(f"{artifact_id} / {source}").classes("record-id")
                        ui.label(integrity).classes("evidence-artifact-integrity")

    def render_record_inspector(
        self,
        record: dict[str, str],
        kind: str,
        title: str,
        subtitle: str,
        fields: tuple[tuple[str, str], ...],
        sections: tuple[tuple[str, str], ...],
        tone: str,
    ) -> None:
        """Render consistent details for assets, evidence, scope rules, and runs."""
        tone_class = tone.lower().replace(" ", "-").replace("/", "-")
        with ui.element("div").classes("inspector-header record-inspector-header"):
            with ui.element("button").classes("inspector-toggle").props(
                f'type=button aria-label="{"Expand details" if self.inspector_collapsed else "Collapse details"}"'
            ).on("click", self.toggle_inspector_collapsed):
                icon("chevron_left" if self.inspector_collapsed else "chevron_right")
            with ui.element("div").classes("inspector-header-copy"):
                ui.label(f"{kind} / {record['id']}").classes("panel-number")
                ui.label(title).classes("panel-title record-panel-title")
                ui.label(subtitle).classes(f"panel-tool record-tone tone-{tone_class}")

        if self.inspector_collapsed:
            return

        with ui.element("div").classes("inspector-body record-detail"):
            for label, value in fields:
                with ui.element("div").classes("finding-detail-row"):
                    ui.label(label).classes("finding-detail-label")
                    ui.label(value).classes("finding-detail-value")
            for label, value in sections:
                with ui.element("section").classes("finding-detail-section"):
                    ui.label(label).classes("field-label")
                    ui.label(value).classes("finding-detail-copy")

    # === END: RIGHT INSPECTOR ===

    # === START: SETTINGS DIALOG ===
    # Modal-style settings workspace with internal section navigation.
    def render_settings_dialog(self) -> None:
        with ui.dialog().classes("settings-dialog").on("hide", self.sync_settings_closed) as self.settings_dialog:
            with ui.card().classes("settings-modal"):
                with ui.element("header").classes("settings-header"):
                    with ui.element("div"):
                        ui.label("BLACKWALL / CONTROL PLANE").classes("section-kicker")
                        ui.label("Settings").classes("settings-title")
                    with ui.element("button").classes("settings-close").props(
                        'type=button aria-label="Close settings" data-escape-close=true'
                    ).on("click", self.close_settings):
                        ui.label("×")

                with ui.element("div").classes("settings-layout"):
                    self.settings_nav = ui.element("nav").classes("settings-nav")
                    self.settings_content = ui.element("main").classes("settings-content")

        self.render_settings_navigation()
        self.render_settings_content()

    def render_settings_navigation(self) -> None:
        self.settings_nav.clear()
        with self.settings_nav:
            ui.label("CONFIGURATION").classes("settings-nav-label")
            for icon_name, label, section in SETTINGS_SECTIONS:
                classes = "settings-nav-item active" if section == self.settings_section else "settings-nav-item"
                with ui.element("button").classes(classes).props("type=button").on(
                    "click", partial(self.select_settings_section, section)
                ):
                    icon(icon_name)
                    ui.label(label)

    def render_settings_content(self) -> None:
        self.settings_content.clear()
        with self.settings_content:
            if self.settings_section == "general":
                self.render_general_settings()
            elif self.settings_section == "projects":
                self.render_project_settings()
            elif self.settings_section == "proxy":
                self.render_proxy_settings()
            elif self.settings_section == "modules":
                self.render_module_settings()
            else:
                self.render_appearance_settings()

    def render_settings_heading(self, title: str, copy: str) -> None:
        ui.label(f"SETTINGS / {title.upper()}").classes("section-kicker")
        ui.label(title).classes("settings-section-title")
        ui.label(copy).classes("settings-section-copy")

    def render_general_settings(self) -> None:
        self.render_settings_heading("General", "Local runtime, storage, and execution defaults.")
        with ui.element("section").classes("settings-group"):
            ui.label("APPLICATION").classes("settings-group-title")
            self.render_setting_field("DEFAULT PROJECT LOCATION", str(self.project_workspace.store.root), readonly=True)
            with ui.element("div").classes("settings-field-grid"):
                self.render_setting_field("NETWORK BIND", self.app_config.host, readonly=True)
                self.render_setting_field("PORT", str(self.app_config.port), readonly=True)
            if self.app_config.remote_access_warning:
                ui.label(self.app_config.remote_access_warning).classes("settings-note warning")
            else:
                ui.label("LOCALHOST ONLY / LAN ACCESS DISABLED").classes("settings-note")

        with ui.element("section").classes("settings-group"):
            ui.label("EXECUTION").classes("settings-group-title")
            self.render_setting_field("MAX CONCURRENT RUNS", "3")
            ui.checkbox("Preserve incomplete run artifacts", value=True).props("dense").classes("setting-check")
            ui.checkbox("Restore open project tabs on startup", value=True).props("dense").classes("setting-check")

    def render_project_settings(self) -> None:
        self.render_settings_heading("Projects", "Open tabs and portable local project directories.")
        with ui.element("section").classes("settings-group"):
            with ui.element("div").classes("settings-group-head"):
                ui.label("OPEN PROJECTS").classes("settings-group-title")
                ui.label(f"{len(self.projects):02d} OPEN").classes("settings-meta")
            for project in self.projects:
                with ui.element("div").classes("settings-project-row"):
                    icon("folder_open")
                    with ui.element("div").classes("settings-project-copy"):
                        ui.label(project.name).classes("settings-project-name")
                        ui.label(f"{project.id}  /  {project.path}").classes(
                            "settings-project-path"
                        )
                    ui.button("FOCUS", on_click=partial(self.select_project, project.id)).props(
                        "flat dense no-caps"
                    ).classes("settings-action project-open-action")

            if not self.projects:
                ui.label("NO PROJECT TABS ARE OPEN").classes("settings-note")

        with ui.element("section").classes("settings-group"):
            ui.label("PROJECT ACTIONS").classes("settings-group-title")
            with ui.element("div").classes("settings-actions"):
                ui.button("CREATE PROJECT", icon="create_new_folder", on_click=self.add_project_tab).props(
                    "flat no-caps"
                ).classes("settings-action primary")
                ui.button("OPEN PROJECT", icon="folder_open", on_click=self.browse_for_project).props(
                    "flat no-caps"
                ).classes("settings-action")

    def render_proxy_settings(self) -> None:
        self.render_settings_heading(
            "Proxy",
            "Route compatible launcher modules through an HTTP or SOCKS proxy.",
        )
        with ui.element("section").classes("settings-group"):
            with ui.element("div").classes("settings-group-head"):
                ui.label("CONNECTION").classes("settings-group-title")
                ui.label(f"CONFIGURED / {'ON' if self.proxy_enabled else 'OFF'}").classes(
                    "settings-state ready" if self.proxy_enabled else "settings-state missing"
                )

            ui.label("LOCAL INTERCEPT PRESETS").classes("field-label proxy-preset-label")
            with ui.element("div").classes("proxy-presets"):
                for label in (
                    "ZAP / 127.0.0.1:8080",
                    "BURP / 127.0.0.1:8080",
                    "REMOTE SOCKS / JUMPHOST",
                    "CUSTOM",
                ):
                    ui.button(label, on_click=lambda: ui.notify(
                        "Proxy presets are not connected yet"
                    )).props("flat dense no-caps").classes("proxy-preset")

            with ui.element("div").classes("settings-field-grid proxy-connection-grid"):
                with ui.element("div").classes("settings-field"):
                    ui.label("PROTOCOL").classes("field-label")
                    ui.select(["HTTP", "HTTPS", "SOCKS4", "SOCKS5"], value="HTTP").props(
                        "dense outlined options-dense"
                    ).classes("config-control settings-select-control")
                self.render_setting_field("HOST", "127.0.0.1")
                self.render_setting_field("PORT", "8080")

            with ui.element("div").classes("settings-actions"):
                ui.button("TEST CONNECTION", icon="network_check", on_click=lambda: ui.notify(
                    "Proxy connectivity testing is not connected yet"
                )).props("flat no-caps").classes("settings-action primary")

        with ui.element("section").classes("settings-group"):
            ui.label("AUTHENTICATION AND TLS").classes("settings-group-title")
            with ui.element("div").classes("settings-field-grid"):
                with ui.element("div").classes("settings-field"):
                    ui.label("AUTHENTICATION").classes("field-label")
                    ui.select(["None", "Username / password"], value="None").props(
                        "dense outlined options-dense"
                    ).classes("config-control settings-select-control")
                self.render_setting_field("USERNAME", "")
            self.render_setting_field("PASSWORD", "", password=True)
            self.render_setting_field("INTERCEPTION CA CERTIFICATE (OPTIONAL)", "")
            ui.label(
                "HTTPS interception through ZAP, Burp, or another intercepting proxy requires the launcher "
                "environment to trust that proxy's CA certificate."
            ).classes("settings-note")

        with ui.element("section").classes("settings-group"):
            ui.label("ROUTING POLICY").classes("settings-group-title")
            ui.checkbox("Proxy DNS through SOCKS5 when supported", value=True).props("dense").classes(
                "setting-check"
            )
            ui.checkbox("Block launch when an enabled proxy cannot be honored", value=True).props(
                "dense"
            ).classes("setting-check")
            self.render_setting_field("BYPASS TARGETS", "localhost, 127.0.0.1, ::1")
            ui.label(
                "Proxy capability is adapter-specific. Raw sockets, DNS clients, and some scanners may not support "
                "HTTP or SOCKS routing; Blackwall must never imply that unsupported traffic is proxied."
            ).classes("settings-note warning")

    def render_module_settings(self) -> None:
        self.render_settings_heading("Modules", "Manage executable adapters and their scan profiles.")
        with ui.element("div").classes("module-settings-layout"):
            with ui.element("aside").classes("settings-module-list"):
                with ui.element("button").classes(
                    "settings-module-add active" if self.settings_module_id == "__new__" else "settings-module-add"
                ).props("type=button").on("click", self.new_settings_module):
                    ui.label("+")
                    ui.label("ADD MODULE")
                for module in self.module_catalog:
                    classes = "settings-module-item active" if module.id == self.settings_module_id else "settings-module-item"
                    with ui.element("button").classes(classes).props("type=button").on(
                        "click", partial(self.select_settings_module, module.id)
                    ):
                        icon(module.icon)
                        with ui.element("div").classes("settings-module-copy"):
                            ui.label(module.description)
                            ui.label(f"{module.id} / {module.bin.upper()}").classes("settings-meta")
                        ui.label(module.state).classes(
                            "settings-state ready" if module.state == "READY" else "settings-state missing"
                        )

            with ui.element("section").classes("settings-module-editor"):
                if self.settings_module_id == "__new__":
                    module = None
                    module_id = self.module_catalog.next_id()
                else:
                    module = self.module_catalog.get(self.settings_module_id)
                    module_id = module.id

                with ui.element("div").classes("settings-field-grid"):
                    self.render_setting_field("TYPE / EYEBROW", module.eyebrow if module else "discovery")
                    self.render_setting_field("AUTO ID", module_id, readonly=True)
                self.render_setting_field("DESCRIPTION", module.description if module else "")
                with ui.element("div").classes("settings-field-grid"):
                    self.render_setting_field("BINARY", module.bin if module else "")
                    self.render_setting_field("ICON (OPTIONAL)", module.icon if module else "")
                self.render_setting_field("EXECUTABLE PATH", module.path if module else "")

                ui.label("SCAN PROFILES").classes("settings-group-title profile-heading")
                with ui.element("div").classes("profile-list"):
                    profile_names = module.profile_names if module else ("Default",)
                    for index, profile_name in enumerate(profile_names):
                        with ui.element("div").classes("profile-row"):
                            ui.label(f"{index + 1:02d}").classes("profile-index")
                            ui.label(profile_name).classes("profile-name")
                            ui.label("DEFAULT" if index == 0 else "PROFILE").classes("settings-meta")
                    with ui.element("button").classes("profile-add").props("type=button"):
                        ui.label("+ ADD PROFILE")

                with ui.element("div").classes("settings-actions editor-actions"):
                    ui.button("SAVE MODULE", icon="save", on_click=lambda: ui.notify(
                        "Module persistence is not connected yet"
                    )).props("flat no-caps").classes("settings-action primary")

    def render_appearance_settings(self) -> None:
        self.render_settings_heading("Appearance", "Tune density and atmosphere without changing information semantics.")
        with ui.element("section").classes("settings-group"):
            ui.label("THEME").classes("settings-group-title")
            with ui.element("div").classes("theme-option active"):
                with ui.element("div").classes("theme-swatches"):
                    ui.element("span").classes("swatch void")
                    ui.element("span").classes("swatch structure")
                    ui.element("span").classes("swatch interactive")
                with ui.element("div"):
                    ui.label("BLACKWALL DEFAULT").classes("settings-project-name")
                    ui.label("VOID / STRUCTURE RED / INTERACTIVE BLUE").classes("settings-meta")
                icon("check")

        with ui.element("section").classes("settings-group"):
            ui.label("DISPLAY").classes("settings-group-title")
            ui.select(["Compact", "Comfortable"], value="Compact").props("dense outlined").classes(
                "config-control settings-select"
            )
            ui.checkbox("CRT scanline overlay", value=True).props("dense").classes("setting-check")
            ui.checkbox("Show navigation badges", value=True).props("dense").classes("setting-check")

    def render_setting_field(
        self, label: str, value: str, *, readonly: bool = False, password: bool = False
    ) -> None:
        with ui.element("div").classes("settings-field"):
            ui.label(label).classes("field-label")
            field = ui.input(value=value).props("dense outlined").classes("config-control settings-input")
            if readonly:
                field.props("readonly")
            if password:
                field.props("type=password")

    # === END: SETTINGS DIALOG ===

    # === START: RUN OUTPUT ===
    # Bottom output region backed by persistent stdout/stderr logs.
    def render_console(self) -> None:
        self.console.clear()
        run = next(
            (
                item for item in self.execution_manager.list_runs(
                    tuple(project.path for project in self.projects)
                )
                if item.id == self.active_run_id
            ),
            None,
        )
        with self.console:
            with ui.element("div").classes("console-head"):
                with ui.element("div").classes("console-title"):
                    icon("terminal")
                    ui.label("RUN OUTPUT")
                self.console_state_label = ui.label(
                    f"{run.id} / {run.state.value.upper()}" if run else "IDLE / NO ACTIVE RUN"
                ).classes("console-tab active" + ("" if run else " empty"))
                ui.element("div").classes("console-spacer")
                with ui.element("button").classes("console-action").props(
                    'type=button aria-label="Cancel active run" title="Cancel active run"'
                ).on("click", self.cancel_active_run) as self.cancel_run_button:
                    icon("stop")
                self.cancel_run_button.set_visibility(bool(run and not run.state.terminal))
                with ui.element("button").classes("console-action").props(
                    f'type=button aria-label="{"Exit fullscreen" if self.console_fullscreen else "Fullscreen run output"}"'
                ).on("click", self.toggle_console_fullscreen):
                    icon("close_fullscreen" if self.console_fullscreen else "open_in_full")
                with ui.element("button").classes("console-action").props(
                    f'type=button aria-label="{"Restore run output" if self.console_minimized else "Minimize run output"}"'
                ).on("click", self.toggle_console_minimized):
                    icon("keyboard_arrow_up" if self.console_minimized else "keyboard_arrow_down")

            self.run_output = ui.log(max_lines=5000).classes("console-log").props(
                'aria-label="Run output" role=log aria-live=polite'
            )
            if run and run.run_path:
                for stream_name in ("stdout", "stderr"):
                    path = run.run_path / f"{stream_name}.log"
                    if not path.is_file():
                        continue
                    prefix = "[stderr] " if stream_name == "stderr" else ""
                    try:
                        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                            self.run_output.push(prefix + line)
                    except OSError:
                        self.run_output.push(f"Unable to read {path.name}")

    # === END: RUN OUTPUT ===


# NiceGUI root callable used by main.py.
def build_ui(
    app_config: AppConfig | None = None,
    execution_manager: ExecutionManager | None = None,
) -> None:
    DashboardUI(app_config=app_config, execution_manager=execution_manager).build()
