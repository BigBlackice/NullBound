"""Interactive NiceGUI shell for the Blackwall launchpad."""

from __future__ import annotations

import asyncio
from functools import partial
import json
from pathlib import Path
import re
import shlex

from nicegui import events, ui
from app_config import AppConfig
from blackwall_evidence import EvidenceStore
from blackwall_execution import (
    ExecutionError, ExecutionManager, RunEvent, RunManifest, RunRequest, ToolHealth,
)
from blackwall_projects import Project, ProjectStore, ProjectValidationError, ProjectWorkspace
from blackwall_projects.picker import LocalDirectoryPicker
from blackwall_scope import (
    ExecutionContext,
    OwnershipConfidence,
    ScopeRule,
    ScopeStatus,
    ScopeStore,
    ScopeValidationError,
    Target,
    TargetKind,
    TargetSelection,
    evaluate_targets,
)
from recon_modules import (
    FAVICON_DATA_URL, ModuleCatalog, ModuleDefinition, ScanProfile, load_default_catalog,
)


# Shared static resources. Module data is intentionally loaded per page below so
# definitions.json changes become visible on the next browser refresh.
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
# Navigation is data-driven: each entry defines its icon, label, view ID, and badge.
NAV_ITEMS = (
    ("grid_view", "Launchpad", "launchpad", ""),
    ("flag", "Findings", "findings", ""),
    ("language", "Assets", "assets", ""),
    ("link", "Evidence", "evidence", ""),
    ("gpp_good", "Scope", "scope", ""),
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
ASSET_PAGE_SIZE = 50
RECORD_PAGE_SIZE = 50
CONSOLE_MAX_LINES = 5000
CONSOLE_TAIL_BYTES = 2_000_000
SCOPE_FILTER_LABELS = {
    False: "ALL ITEMS",
    True: "IN SCOPE ONLY",
    None: "OUT OF SCOPE ONLY",
}
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
        module_catalog: ModuleCatalog | None = None,
    ) -> None:
        self.app_config = app_config or AppConfig()
        self.active_view = "launchpad"
        # NiceGUI creates this controller for each page load. Re-reading the
        # catalog here makes a normal browser refresh the explicit reload point.
        self.module_catalog = module_catalog or load_default_catalog()
        modules = self.module_catalog.modules
        if not modules:
            raise ValueError("module catalog must contain at least one module")
        self.selected_module_id = "04"
        if all(module.id != self.selected_module_id for module in modules):
            self.selected_module_id = modules[0].id
        self.selected_finding_id: str | None = None
        self.selected_asset_id: str | None = None
        self.selected_evidence_id: str | None = None
        self.selected_scope_id: str | None = None
        self.selected_run_id: str | None = None
        self.selected_asset_ids: set[str] = set()
        self._asset_selection_project_id: str | None = None
        self.asset_page_index = 0
        self.record_page_indexes = {
            "findings": 0,
            "evidence": 0,
            "scope": 0,
            "runs": 0,
        }
        self._project_record_cache: dict[
            str, tuple[object, tuple[dict[str, object], ...]]
        ] = {}
        self._visible_record_sets: dict[str, tuple[dict[str, object], ...]] = {}
        self._row_elements: dict[str, dict[str, object]] = {}
        self.record_scope_filters: dict[str, bool | None] = {
            "assets": False,
            "findings": False,
            "runs": False,
        }
        self.target_modes = {module.id: "direct" for module in modules}
        self.direct_targets = {module.id: "" for module in modules}
        self.selected_profiles = {module.id: module.default_profile.name for module in modules}
        self.module_config_values = {
            module.id: {field.id: "" for field in module.config_fields} for module in modules
        }
        self.selected_target_sets: dict[str, str] = {}
        self.search_query = ""
        self.console_minimized = False
        self.console_fullscreen = False
        self.console_wrap = True
        self.inspector_collapsed = False
        self.proxy_enabled = False
        self.scope_enforced = False
        self.settings_open = False
        self.settings_section = "general"
        self.settings_module_id = modules[0].id
        self.settings_profile_index = 0
        self.settings_profile_drafts: dict[str, list[dict[str, object]]] = {}
        self.module_health: dict[str, ToolHealth] = {}
        self.run_state_filter = "ALL"
        self.run_timeout_values = {module.id: "" for module in modules}
        self._pending_project: tuple[str, Path] | None = None
        self.execution_manager = execution_manager or ExecutionManager()
        self.project_workspace = ProjectWorkspace(project_store or ProjectStore())
        self.evidence_stores: dict[Path, EvidenceStore] = {}
        self.evidence_scope_versions: dict[Path, tuple[int, int] | None] = {}
        for project in self.project_workspace.open_projects:
            self.execution_manager.recover_incomplete((project.path,))
            evidence_store = EvidenceStore(project.path)
            evidence_store.recover_incomplete()
            scope_store = ScopeStore(project.path)
            evidence_store.sync_scope(scope_store.load())
            key = project.path.resolve()
            self.evidence_stores[key] = evidence_store
            self.evidence_scope_versions[key] = (
                (scope_store.path.stat().st_mtime_ns, scope_store.path.stat().st_size)
                if scope_store.path.exists() else None
            )
        self.active_run_id: str | None = None
        self._run_unsubscribe = None
        self._workspace_unsubscribe = None
        self._last_evidence_refresh: tuple[str, str] | None = None
        self._pending_run_output: list[str] = []
        self._client = None

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

    def active_evidence_store(self) -> EvidenceStore | None:
        project = self.active_project
        if project is None:
            return None
        key = project.path.resolve()
        store = self.evidence_stores.get(key)
        if store is None:
            store = EvidenceStore(key)
            self.evidence_stores[key] = store
        scope_store = ScopeStore(project.path)
        try:
            stat = scope_store.path.stat()
            scope_version: tuple[int, int] | None = (stat.st_mtime_ns, stat.st_size)
        except FileNotFoundError:
            scope_version = None
        if key not in self.evidence_scope_versions or self.evidence_scope_versions[key] != scope_version:
            store.sync_scope(scope_store.load())
            self.evidence_scope_versions[key] = scope_version
        return store

    def _cached_project_records(
        self,
        view_id: str,
        store: EvidenceStore,
        loader,
    ) -> tuple[dict[str, object], ...]:
        """Reuse immutable view adapters until the project database changes."""
        token = (self.active_project_id, store.change_token())
        cache = getattr(self, "_project_record_cache", {})
        cached = cache.get(view_id)
        if cached is not None and cached[0] == token:
            return cached[1]
        records = tuple(loader())
        cache[view_id] = (token, records)
        self._project_record_cache = cache
        return records

    def _invalidate_project_record_cache(self, *view_ids: str) -> None:
        cache = getattr(self, "_project_record_cache", {})
        if view_ids:
            for view_id in view_ids:
                cache.pop(view_id, None)
        else:
            cache.clear()

    @staticmethod
    def _scope_label(value: str) -> str:
        return {
            "allowed": "ALLOWED", "denied": "DENIED", "review": "REVIEW",
            "unmatched": "REVIEW",
        }.get(value, value.upper())

    def asset_records(self) -> tuple[dict[str, str], ...]:
        store = self.active_evidence_store()
        if store is None:
            return ()

        def load() -> tuple[dict[str, str], ...]:
            records: list[dict[str, str]] = []
            provenance = store.list_asset_provenance(include_denied=True)
            for asset in store.list_assets(include_denied=True):
                source_items, run_items = provenance.get(asset.id, ((), ()))
                sources = ", ".join(item.upper() for item in source_items) or "—"
                run_ids = ", ".join(run_items)
                metadata = dict(asset.metadata)
                records.append({
                    "id": asset.id, "type": asset.kind.value.upper(), "name": asset.display_name,
                    "target_kind": asset.kind.value, "normalized": asset.normalized_key,
                    "address": str(metadata.get("address", "—")),
                    "ports": str(metadata.get("ports", "—")),
                    "scope": self._scope_label(asset.scope.value), "source": sources,
                    "scope_rule": asset.matched_rule_id or "",
                    "first_seen": asset.first_seen_at, "last_seen": asset.last_seen_at,
                    "technology": str(metadata.get("technology", "—")),
                    "provenance": run_ids or sources,
                    "notes": str(metadata.get("notes", "")),
                })
            return tuple(records)

        return self._cached_project_records("assets", store, load)  # type: ignore[return-value]

    def filtered_asset_records(self) -> tuple[dict[str, str], ...]:
        records = self._filter_records_by_scope(
            self.asset_records(), self._scope_filter_state("assets")
        )
        query = self.search_query.strip().casefold()
        if query:
            records = tuple(
                record for record in records
                if query in " ".join(str(value) for value in record.values()).casefold()
            )
        return records

    def finding_records(self) -> tuple[dict[str, str], ...]:
        store = self.active_evidence_store()
        if store is None:
            return ()

        def load() -> tuple[dict[str, str], ...]:
            scopes = store.list_finding_scopes()
            return tuple({
                "id": finding.id, "severity": finding.severity.value, "title": finding.title,
                "asset": finding.asset_name or "—", "source": finding.source,
                "scope": self._scope_label(scopes.get(finding.id, "unmatched")),
                "confidence": finding.confidence, "seen": finding.last_seen_at,
                "location": finding.location, "description": finding.description,
                "evidence": finding.evidence, "recommendation": finding.recommendation,
                "state": finding.state.value,
            } for finding in store.list_findings(include_denied=True))

        return self._cached_project_records("findings", store, load)  # type: ignore[return-value]

    def filtered_finding_records(self) -> tuple[dict[str, str], ...]:
        records = self._filter_records_by_scope(
            self.finding_records(), self._scope_filter_state("findings")
        )
        query = self.search_query.strip().casefold()
        if query:
            records = tuple(
                record for record in records
                if query in " ".join(record.values()).casefold()
            )
        return records

    def _scope_filter_state(self, view_id: str) -> bool | None:
        return getattr(self, "record_scope_filters", {}).get(view_id, False)

    @staticmethod
    def _filter_records_by_scope(
        records: tuple[dict[str, object], ...],
        state: bool | None,
    ) -> tuple[dict[str, object], ...]:
        if state is False:
            return records
        in_scope = state is True
        return tuple(
            record for record in records
            if (record.get("scope") == "ALLOWED") is in_scope
        )

    def evidence_node_records(self) -> tuple[dict[str, object], ...]:
        store = self.active_evidence_store()
        if store is None:
            return ()

        def load() -> tuple[dict[str, object], ...]:
            counts = store.list_evidence_node_counts()
            return tuple({
                "id": asset.id, "kind": asset.kind.value.upper(),
                "identifier": asset.display_name,
                "scope": "IN SCOPE" if asset.scope.value == "allowed" else "REVIEW REQUIRED",
                "scope_anchor": asset.matched_rule_id or "NO MATCHED RULE",
                "relations": f"{counts.get(asset.id, (0, 0))[1]:02d}",
                "artifact_count": f"{counts.get(asset.id, (0, 0))[0]:02d}",
                "updated": asset.last_seen_at,
                "search_context": "Normalized evidence node with retained raw observations and provenance.",
            } for asset in store.list_assets())

        return self._cached_project_records("evidence", store, load)

    def evidence_node_record(self, asset_id: str) -> dict[str, object]:
        """Load heavier Evidence inspector details only for the selected node."""
        store = self.active_evidence_store()
        if store is None:
            raise KeyError(asset_id)
        asset = store.get_asset(asset_id)
        evidence = store.list_evidence(asset_id=asset.id)
        relationships = store.list_relationships(asset.id)
        identifiers = [(asset.kind.value.upper(), asset.normalized_key)]
        identifiers.extend(
            (related.kind.value.upper(), related.normalized_key)
            for related in store.list_related_assets(asset.id)
        )
        return {
            "id": asset.id, "kind": asset.kind.value.upper(),
            "identifier": asset.display_name,
            "scope": "IN SCOPE" if asset.scope.value == "allowed" else "REVIEW REQUIRED",
            "scope_anchor": asset.matched_rule_id or "NO MATCHED RULE",
            "relations": f"{len(relationships):02d}",
            "artifact_count": f"{len(evidence):02d}", "updated": asset.last_seen_at,
            "context": "Normalized evidence node with retained raw observations and provenance.",
            "identifiers": tuple(dict.fromkeys(identifiers)),
            "artifacts": tuple(
                (item.kind.value.upper(), item.id, item.raw_value, item.source.upper(),
                 item.integrity_status.upper())
                for item in evidence
            ),
        }

    def scope_records(self) -> tuple[dict[str, str], ...]:
        store = self.active_evidence_store()
        if store is None:
            return ()

        def load() -> tuple[dict[str, str], ...]:
            records = []
            for rule in store.list_scope_rules():
                decision = "REVIEW REQUIRED" if rule["review_required"] else str(rule["scope_status"]).upper()
                records.append({
                    "id": str(rule["id"]), "target": str(rule["original_target"]),
                    "type": str(rule["target_kind"]).upper(), "decision": decision,
                    "ownership": str(rule["ownership_confidence"]).upper(),
                    "source": str(rule["source"]).upper(), "updated": str(rule["synced_at"]),
                    "reason": str(rule["notes"] or "Portable scope rule mirrored from scope.json."),
                    "applies": str(rule["normalized_target"]), "notes": str(rule["notes"]),
                })
            return tuple(records)

        return self._cached_project_records("scope", store, load)  # type: ignore[return-value]

    @staticmethod
    def _record(records: tuple[dict[str, str], ...], record_id: str) -> dict[str, str]:
        return next(record for record in records if record["id"] == record_id)

    def run_records(self) -> tuple[dict[str, str], ...]:
        """Adapt manifests from the active project, or the no-project session."""
        project = self.active_project
        project_paths = (project.path,) if project is not None else ()
        manifests = self.execution_manager.list_runs(project_paths)
        project_id = project.id if project is not None else None
        manifests = tuple(run for run in manifests if run.project_id == project_id)
        rules = ScopeStore(project.path).load().rules if project is not None else ()
        return tuple(
            self._run_record(manifest, self._run_scope_label(manifest, rules))
            for manifest in manifests
        )

    def filtered_run_records(self) -> tuple[dict[str, str], ...]:
        """Apply the Runs view filters for both the table and its inspector."""
        records = self.run_records()
        if self.run_state_filter == "ACTIVE":
            records = tuple(
                record for record in records if record["state"] in {"STARTING", "RUNNING"}
            )
        elif self.run_state_filter != "ALL":
            records = tuple(
                record for record in records if record["state"] == self.run_state_filter
            )
        records = self._filter_records_by_scope(
            records, self._scope_filter_state("runs")
        )
        query = self.search_query.strip().casefold()
        if query:
            records = tuple(
                record for record in records
                if query in " ".join(record.values()).casefold()
            )
        return records

    def run_manifest(self, run_id: str) -> RunManifest:
        return next(
            run for run in self.execution_manager.list_runs(tuple(p.path for p in self.projects))
            if run.id == run_id
        )

    def download_artifact(self, run_id: str, relative_path: str) -> None:
        try:
            path = self.execution_manager.store.resolve_artifact(
                self.run_manifest(run_id), relative_path
            )
            ui.download(path)
        except (ExecutionError, OSError, StopIteration) as error:
            ui.notify(str(error), type="negative")

    def open_artifact(self, run_id: str, relative_path: str) -> None:
        try:
            path = self.execution_manager.store.resolve_artifact(
                self.run_manifest(run_id), relative_path
            )
            size = path.stat().st_size
            if size > 2_000_000:
                raise ExecutionError("artifact is too large to preview; use download")
            content = path.read_text(encoding="utf-8", errors="replace")
        except (ExecutionError, OSError, StopIteration) as error:
            ui.notify(str(error), type="negative")
            return

        artifact_preview = None

        def set_wrap(event: events.ValueChangeEventArguments) -> None:
            if artifact_preview is None:
                return
            if bool(event.value):
                artifact_preview.classes(add="wrap-text")
            else:
                artifact_preview.classes(remove="wrap-text")

        line_count = len(content.splitlines())
        with ui.dialog().classes("project-dialog") as dialog, ui.card().classes(
            "project-modal artifact-modal"
        ):
            with ui.element("header").classes("settings-header"):
                ui.label(path.name).classes("settings-title")
                ui.button("×", on_click=dialog.close).props("flat dense")
            with ui.element("div").classes("artifact-toolbar"):
                ui.label(f"{line_count:,} LINES / {size:,} BYTES").classes("artifact-stats")
                ui.checkbox("WRAP TEXT", value=True, on_change=set_wrap).props(
                    "dense"
                ).classes("artifact-wrap-toggle")
            artifact_preview = ui.element("div").classes("artifact-preview wrap-text")
            with artifact_preview:
                ui.label(content).classes("artifact-preview-content")
        dialog.open()

    @staticmethod
    def _run_scope_label(run: RunManifest, rules: tuple[ScopeRule, ...]) -> str:
        """Classify all recorded targets against the active project's current scope."""
        targets: list[Target] = []
        try:
            for item in run.targets:
                targets.append(Target(TargetKind(item["kind"]), item["value"]))
        except (KeyError, ScopeValidationError, ValueError):
            return "REVIEW"
        if not targets:
            return "REVIEW"
        evaluations = evaluate_targets(tuple(targets), rules, enforce=False)
        if all(item.scope_status is ScopeStatus.ALLOWED for item in evaluations):
            return "ALLOWED"
        if any(item.scope_status is ScopeStatus.DENIED for item in evaluations):
            return "DENIED"
        return "REVIEW"

    @staticmethod
    def _run_record(run: RunManifest, scope: str = "REVIEW") -> dict[str, str]:
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
        evidence_summary = ", ".join(
            f"{key.replace('_', ' ')}: {value}" for key, value in run.evidence_summary
        )
        return {
            "id": run.id,
            "state": run.state.value.upper(),
            "module": run.module_bin.upper(),
            "target": targets,
            "project": project,
            "project_id": run.project_id or "",
            "scope": scope,
            "duration": duration,
            "started": run.started_at or run.created_at,
            "exit_code": "—" if run.exit_code is None else str(run.exit_code),
            "artifacts": str(len(run.artifacts)),
            "profile": run.profile_name,
            "command": command,
            "context": context,
            "summary": run.error or f"Run state: {run.state.value}.",
            "evidence_state": run.evidence_state.replace("_", " ").upper(),
            "evidence_summary": run.evidence_error or evidence_summary or "No indexed records.",
        }

    def build(self) -> None:
        # Run events are emitted by background subprocess tasks. Retain the
        # page client so those callbacks can safely re-enter its UI context.
        self._client = ui.context.client
        self._workspace_unsubscribe = self.execution_manager.subscribe_all(
            self.handle_workspace_event
        )
        self._client.on_delete(self.dispose)
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
        self._run_output_timer = ui.timer(0.1, self.flush_run_output)
        self.render_settings_dialog()
        self.render_project_dialogs()
        self.render_scope_dialog()
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
        attribute = f"selected_{view_id.rstrip('s')}_id"
        previous_id = getattr(self, attribute, None)
        setattr(self, attribute, record_id)
        self._update_selected_row(view_id, previous_id, record_id)
        if view_id == "runs":
            self.active_run_id = record_id
            self.render_console()
        if self.inspector_collapsed:
            self.inspector_collapsed = False
            self.update_inspector_layout()
        self.render_inspector()

    def _update_selected_row(
        self,
        view_id: str,
        previous_id: str | None,
        selected_id: str | None,
    ) -> None:
        rows = getattr(self, "_row_elements", {}).get(view_id, {})
        previous = rows.get(previous_id or "")
        selected = rows.get(selected_id or "")
        if previous is not None and previous is not selected:
            previous.classes(remove="selected")
        if selected is not None:
            selected.classes(add="selected")

    def preview_evidence_filter(self, label: str) -> None:
        ui.notify(f"{label.title()} evidence filtering is not connected yet")

    def open_settings(self) -> None:
        self.settings_open = True
        self.update_rail_selection()
        self.settings_dialog.open()

    def open_selected_module_settings(self) -> None:
        """Open the profile editor for the module currently shown in the inspector."""
        self.settings_module_id = self.selected_module_id
        self.settings_profile_index = 0
        self.settings_section = "modules"
        self.open_settings()
        self.render_settings_navigation()
        self.render_settings_content()
        asyncio.create_task(self.refresh_module_health())

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
        if section == "modules":
            asyncio.create_task(self.refresh_module_health())

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

        with ui.dialog().classes("project-dialog") as self.unattached_runs_dialog:
            with ui.card().classes("project-modal"):
                with ui.element("header").classes("settings-header"):
                    with ui.element("div"):
                        ui.label("PROJECT / SESSION RUNS").classes("section-kicker")
                        ui.label("Unattached runs detected").classes("settings-title")
                    with ui.element("button").classes("settings-close").props(
                        'type=button aria-label="Cancel project creation" data-escape-close=true'
                    ).on("click", self.unattached_runs_dialog.close):
                        ui.label("×")
                self.unattached_runs_message = ui.label("").classes("settings-section-copy")
                with ui.element("div").classes("settings-actions"):
                    ui.button(
                        "ADD TO PROJECT", icon="drive_file_move",
                        on_click=partial(self.finish_create_project, "attach"),
                    ).props("flat no-caps").classes("settings-action primary")
                    ui.button(
                        "DELETE PERMANENTLY", icon="delete_forever",
                        on_click=partial(self.finish_create_project, "delete"),
                    ).props("flat no-caps").classes("settings-action danger")
                    ui.button("CANCEL", on_click=self.unattached_runs_dialog.close).props(
                        "flat no-caps"
                    ).classes("settings-action")
    # === END: PROJECT DIALOGS ===

    # === START: SCOPE DIALOG ===
    def render_scope_dialog(self) -> None:
        with ui.dialog().classes("project-dialog") as self.scope_add_dialog:
            with ui.card().classes("project-modal scope-modal"):
                with ui.element("header").classes("settings-header"):
                    with ui.element("div"):
                        ui.label("AUTHORIZATION / SCOPE").classes("section-kicker")
                        ui.label("Add scope items").classes("settings-title")
                    with ui.element("button").classes("settings-close").props(
                        'type=button aria-label="Close add scope items" data-escape-close=true'
                    ).on("click", self.scope_add_dialog.close):
                        ui.label("Ã—")
                ui.label(
                    "One target per line. Supports domains, IPs, CIDRs, exact URLs, "
                    "*.example.com, and https://*.example.com/* patterns."
                ).classes("settings-section-copy scope-dialog-copy")
                with ui.element("div").classes("settings-field"):
                    ui.label("TARGETS").classes("field-label")
                    self.scope_add_targets = ui.textarea(
                        placeholder="*.example.com\nhttps://*.example.com/*"
                    ).props("dense outlined autogrow").classes("config-control")
                with ui.element("div").classes("settings-field-grid scope-dialog-grid"):
                    with ui.element("div").classes("settings-field"):
                        ui.label("DECISION").classes("field-label")
                        self.scope_add_decision = ui.select(
                            {"allowed": "ALLOWED", "denied": "DENIED"}, value="allowed",
                            on_change=self.set_scope_add_decision,
                        ).props("dense outlined options-dense").classes("config-control")
                    with ui.element("div").classes("settings-field"):
                        ui.label("OWNERSHIP").classes("field-label")
                        self.scope_add_ownership = ui.select(
                            {
                                "unknown": "UNKNOWN",
                                "likely": "LIKELY",
                                "confirmed": "CONFIRMED",
                            },
                            value="unknown",
                        ).props("dense outlined options-dense").classes("config-control")
                with ui.element("div").classes("settings-field"):
                    ui.label("NOTES").classes("field-label")
                    self.scope_add_notes = ui.input(
                        placeholder="Authorization reference or operator note"
                    ).props("dense outlined").classes("config-control")
                with ui.element("div").classes("settings-field scope-review-field"):
                    self.scope_add_review = ui.checkbox(
                        "REQUIRE REVIEW", value=False
                    ).props("dense").classes("setting-check")
                with ui.element("div").classes("settings-actions"):
                    ui.button(
                        "ADD TO SCOPE", icon="add_task", on_click=self.add_manual_scope_rules
                    ).props("flat no-caps").classes("settings-action primary")
                    ui.button("CANCEL", on_click=self.scope_add_dialog.close).props(
                        "flat no-caps"
                    ).classes("settings-action")
    # === END: SCOPE DIALOG ===

    def open_scope_add_dialog(self) -> None:
        if self.active_project is None:
            ui.notify("Open a project before adding scope items", type="warning")
            return
        self.scope_add_targets.value = ""
        self.scope_add_decision.value = "allowed"
        self.scope_add_ownership.value = "unknown"
        self.scope_add_notes.value = ""
        self.scope_add_review.value = False
        self.scope_add_review.enable()
        self.scope_add_dialog.open()

    def set_scope_add_decision(self, event: events.ValueChangeEventArguments) -> None:
        if not hasattr(self, "scope_add_review"):
            return
        if str(event.value) == "denied":
            self.scope_add_review.value = False
            self.scope_add_review.disable()
        else:
            self.scope_add_review.enable()

    def add_manual_scope_rules(self) -> None:
        project = self.active_project
        if project is None:
            ui.notify("Open a project before adding scope items", type="warning")
            return
        values = tuple(
            value.strip()
            for value in re.split(r"[\r\n]+", str(self.scope_add_targets.value or ""))
            if value.strip()
        )
        try:
            if not values:
                raise ScopeValidationError("enter at least one scope target")
            created = ScopeStore(project.path).add_rules(
                tuple(Target.parse(value) for value in values),
                scope_status=ScopeStatus(str(self.scope_add_decision.value)),
                ownership_confidence=OwnershipConfidence(str(self.scope_add_ownership.value)),
                review_required=bool(self.scope_add_review.value),
                source="manual",
                notes=str(self.scope_add_notes.value or "").strip(),
            )
        except (OSError, ScopeValidationError, ValueError) as error:
            ui.notify(str(error), type="negative")
            return
        if not created:
            ui.notify("Those targets already have scope rules", type="warning")
            return
        self.selected_scope_id = created[-1].id
        self._sync_active_scope()
        self.scope_add_dialog.close()
        self._refresh_scope_surfaces()
        ui.notify(f"Added {len(created)} scope rule(s)", type="positive")

    @staticmethod
    def _target_for_asset(record: dict[str, str]) -> Target:
        kind = record.get("target_kind", "")
        supported = {
            "domain": TargetKind.DOMAIN,
            "ipv4": TargetKind.IPV4,
            "ipv6": TargetKind.IPV6,
            "cidr": TargetKind.CIDR,
            "url": TargetKind.URL,
        }
        if kind == "host":
            return Target.parse(record["normalized"])
        if kind not in supported:
            raise ScopeValidationError(
                f"{record.get('type', kind).lower()} assets cannot be used as scope targets"
            )
        return Target(supported[kind], record["normalized"])

    def add_assets_to_scope(self, asset_ids: tuple[str, ...]) -> None:
        project = self.active_project
        if project is None:
            ui.notify("Open a project before adding assets to scope", type="warning")
            return
        records = {record["id"]: record for record in self.asset_records()}
        targets: list[Target] = []
        unsupported = 0
        for asset_id in dict.fromkeys(asset_ids):
            record = records.get(asset_id)
            if record is None:
                continue
            try:
                targets.append(self._target_for_asset(record))
            except ScopeValidationError:
                unsupported += 1
        if not targets:
            ui.notify("Select a domain, host, IP, CIDR, or URL asset", type="warning")
            return
        try:
            created = ScopeStore(project.path).add_rules(
                tuple(targets), scope_status=ScopeStatus.ALLOWED,
                ownership_confidence=OwnershipConfidence.UNKNOWN,
                source="assets", notes="Added from the Assets workspace",
            )
        except (OSError, ScopeValidationError, ValueError) as error:
            ui.notify(str(error), type="negative")
            return
        self._sync_active_scope()
        self._refresh_scope_surfaces()
        if not created and not unsupported:
            ui.notify("The selected assets already have scope rules", type="warning")
            return
        skipped = len(targets) - len(created)
        details = []
        if skipped:
            details.append(f"{skipped} already scoped")
        if unsupported:
            details.append(f"{unsupported} unsupported")
        suffix = f" ({', '.join(details)})" if details else ""
        ui.notify(
            f"Added {len(created)} asset(s) to scope{suffix}",
            type="positive" if created else "warning",
        )

    def add_selected_assets_to_scope(self) -> None:
        self.add_assets_to_scope(tuple(self.selected_asset_ids))

    def _sync_active_scope(self) -> None:
        project = self.active_project
        if project is None:
            return
        scope_store = ScopeStore(project.path)
        key = project.path.resolve()
        evidence_store = self.evidence_stores.get(key)
        if evidence_store is None:
            evidence_store = EvidenceStore(key)
            self.evidence_stores[key] = evidence_store
        evidence_store.sync_scope(scope_store.load())
        self._invalidate_project_record_cache("assets", "findings", "evidence", "scope")
        stat = scope_store.path.stat()
        self.evidence_scope_versions[key] = (stat.st_mtime_ns, stat.st_size)

    def _refresh_scope_surfaces(self) -> None:
        if self.active_view == "assets" and hasattr(self, "assets_result_host"):
            self.refresh_asset_results()
            self.render_inspector()
        elif self.active_view == "scope":
            self.render_workspace()
            self.render_inspector()

    def select_settings_module(self, module_id: str) -> None:
        self.settings_module_id = module_id
        self.settings_profile_index = 0
        self.render_settings_content()

    def new_settings_module(self) -> None:
        self.settings_module_id = "__new__"
        self.settings_profile_index = 0
        self.settings_profile_drafts.pop("__new__", None)
        self.render_settings_content()

    def select_finding(self, finding_id: str) -> None:
        previous_id = self.selected_finding_id
        self.selected_finding_id = finding_id
        self._update_selected_row("findings", previous_id, finding_id)
        if self.inspector_collapsed:
            self.inspector_collapsed = False
            self.update_inspector_layout()
        self.render_inspector()

    def select_module(self, module_id: str) -> None:
        self.selected_module_id = module_id
        module = self.selected_module
        self.target_modes.setdefault(module.id, "direct")
        self.direct_targets.setdefault(module.id, "")
        self.selected_profiles.setdefault(module.id, module.default_profile.name)
        self.module_config_values.setdefault(
            module.id, {field.id: "" for field in module.config_fields}
        )
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

    def set_module_config(
        self,
        module_id: str,
        field_id: str,
        event: events.ValueChangeEventArguments,
    ) -> None:
        self.module_config_values.setdefault(module_id, {})[field_id] = str(event.value or "")

    def set_run_timeout(self, module_id: str, event: events.ValueChangeEventArguments) -> None:
        self.run_timeout_values[module_id] = str(event.value or "").strip()

    def set_search_query(self, event: events.ValueChangeEventArguments) -> None:
        self.search_query = str(event.value or "")
        if self.active_view == "assets":
            self.asset_page_index = 0
        elif self.active_view in getattr(self, "record_page_indexes", {}):
            self.record_page_indexes[self.active_view] = 0
        if self.active_view in FUNCTIONAL_VIEWS:
            self.render_workspace()

    def set_run_state_filter(self, state: str) -> None:
        self.run_state_filter = state
        self.record_page_indexes["runs"] = 0
        self.render_workspace()
        self.render_inspector()

    def set_record_scope_filter(
        self,
        view_id: str,
        event: events.ValueChangeEventArguments,
    ) -> None:
        state = event.value if event.value is None or type(event.value) is bool else False
        self.record_scope_filters[view_id] = state
        checkbox = getattr(self, f"{view_id}_scope_filter", None)
        if checkbox is not None:
            checkbox.set_text(SCOPE_FILTER_LABELS[state])
        if view_id == "assets":
            self.asset_page_index = 0
            self.refresh_asset_results()
        elif view_id == "findings":
            self.record_page_indexes["findings"] = 0
            self.refresh_finding_results()
        elif view_id == "runs":
            self.record_page_indexes["runs"] = 0
            self.refresh_run_results()
        self.render_inspector()

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
            options = tuple(
                (field.id, self.module_config_values.get(module.id, {}).get(field.id, ""))
                for field in module.config_fields
            )
            timeout_text = self.run_timeout_values.get(module.id, "").strip()
            timeout_seconds = int(timeout_text) if timeout_text else None
            if timeout_seconds is not None and timeout_seconds < 1:
                raise ValueError("run timeout must be a positive number of seconds")
            request = RunRequest(
                module=module,
                profile=self._selected_profile(module),
                context=context,
                options=options,
                timeout_seconds=timeout_seconds,
            )
            run = await self.execution_manager.start(request, project.path if project else None)
        except (ExecutionError, OSError, ScopeValidationError, KeyError, ValueError) as error:
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
        """Route a background run event through the owning page context."""
        if event.run.id != self.active_run_id:
            return
        if self._client is not None:
            self._client.safe_invoke(lambda: self._apply_run_event(event))
            return
        self._apply_run_event(event)

    def handle_workspace_event(self, event: RunEvent) -> None:
        """Apply metadata changes to visible data surfaces without rebuilding them."""
        if event.text is not None:
            return

        evidence_marker = None
        if (
            event.run.project_id == self.active_project_id
            and event.run.evidence_state in {"indexed", "failed", "no_artifact"}
        ):
            evidence_marker = (event.run.id, event.run.evidence_state)
            if evidence_marker == self._last_evidence_refresh:
                evidence_marker = None

        if self.active_view != "runs" and evidence_marker is None:
            return
        if self._client is not None:
            self._client.safe_invoke(
                lambda: self._apply_workspace_refresh(evidence_marker)
            )
            return
        self._apply_workspace_refresh(evidence_marker)

    def _apply_workspace_refresh(
        self,
        evidence_marker: tuple[str, str] | None,
    ) -> None:
        """Refresh only the active table host after a run metadata event."""
        if self.active_view == "runs" and hasattr(self, "runs_result_host"):
            self.refresh_run_results()
            self.render_inspector()

        if evidence_marker is None:
            return
        self._last_evidence_refresh = evidence_marker
        self._invalidate_project_record_cache("assets", "findings", "evidence")
        if self.active_view == "assets" and hasattr(self, "assets_result_host"):
            self.refresh_asset_results()
            self.render_inspector()
        elif self.active_view == "findings" and hasattr(self, "findings_result_host"):
            self.refresh_finding_results()
            self.render_inspector()
        elif self.active_view == "evidence" and hasattr(self, "evidence_result_host"):
            self.refresh_evidence_results()
            self.render_inspector()

    def dispose(self) -> None:
        """Detach page-owned listeners when NiceGUI discards this client."""
        if self._run_unsubscribe:
            self._run_unsubscribe()
            self._run_unsubscribe = None
        if self._workspace_unsubscribe:
            self._workspace_unsubscribe()
            self._workspace_unsubscribe = None

    def _apply_run_event(self, event: RunEvent) -> None:
        """Apply a run event after the page's NiceGUI context is active."""
        if event.text is not None and hasattr(self, "run_output"):
            self.push_run_output(event.text)
        elif event.text is None:
            self.flush_run_output()
        if hasattr(self, "console_state_label"):
            self.console_state_label.set_text(f"{event.run.id} / {event.run.state.value.upper()}")
        if hasattr(self, "cancel_run_button"):
            self.cancel_run_button.set_visibility(not event.run.state.terminal)

    async def cancel_active_run(self) -> None:
        if self.active_run_id and await self.execution_manager.cancel(self.active_run_id):
            ui.notify(f"Cancellation requested for {self.active_run_id}")

    def push_run_output(self, text: str) -> None:
        """Queue live output so bursts become one browser update per timer tick."""
        pending = getattr(self, "_pending_run_output", [])
        pending.append(text)
        self._pending_run_output = pending

    def flush_run_output(self) -> None:
        """Append one bounded output batch without server-side elements per line."""
        if not hasattr(self, "run_output_content"):
            return
        pending = getattr(self, "_pending_run_output", [])
        if not pending:
            return
        self._pending_run_output = []
        payload = json.dumps("".join(f"{line}\n" for line in pending))
        line_count = len(pending)
        ui.run_javascript(
            f'const output = document.querySelector("#c{self.run_output.id}");'
            f'const content = document.querySelector("#c{self.run_output_content.id}");'
            'if (output && content) {'
            f'content.textContent += {payload};'
            f'let count = Number(content.dataset.lineCount || "0") + {line_count};'
            f'if (count > {CONSOLE_MAX_LINES + 500}) {{'
            'const lines = content.textContent.split("\\n");'
            f'content.textContent = lines.slice(-{CONSOLE_MAX_LINES + 1}).join("\\n");'
            f'count = {CONSOLE_MAX_LINES};'
            '}'
            'content.dataset.lineCount = String(count);'
            'output.scrollTop = output.scrollHeight;'
            '}'
        )

    # Project-tab actions delegate persistence and validation to blackwall_projects.
    def select_project(self, project_id: str) -> None:
        self.project_workspace.select(project_id)
        self.refresh_project_surfaces()
        if self.active_view == "launchpad":
            self.render_inspector()

    def add_project_tab(self) -> None:
        self.create_project_name.value = f"UNTITLED PROJECT {len(self.projects) + 1:02d}"
        self.create_project_location.value = str(self.project_workspace.store.root)
        self.create_project_dialog.open()

    def create_project(self) -> None:
        name = str(self.create_project_name.value or "")
        parent = Path(str(self.create_project_location.value or "")).expanduser()
        unattached = self.execution_manager.unattached_runs()
        if any(not run.state.terminal for run in unattached):
            ui.notify("Wait for or cancel active standalone runs before creating a project", type="warning")
            return
        if unattached:
            self._pending_project = (name, parent)
            self.unattached_runs_message.set_text(
                f"{len(unattached)} session run(s) are not attached to a project. "
                "Add them to the new project or remove them permanently."
            )
            self.unattached_runs_dialog.open()
            return
        self._create_project(name, parent)

    def finish_create_project(self, policy: str) -> None:
        if self._pending_project is None:
            self.unattached_runs_dialog.close()
            return
        name, parent = self._pending_project
        self._create_project(name, parent, policy)

    def _create_project(self, name: str, parent: Path, run_policy: str | None = None) -> None:
        try:
            project = self.project_workspace.create(name, parent)
            if run_policy == "attach":
                self.execution_manager.adopt_unattached(project)
            elif run_policy == "delete":
                self.execution_manager.delete_unattached()
        except (ExecutionError, OSError, ProjectValidationError) as error:
            ui.notify(str(error), type="negative")
            return
        self._pending_project = None
        self.unattached_runs_dialog.close()
        self.create_project_dialog.close()
        self.execution_manager.recover_incomplete((project.path,))
        evidence_store = EvidenceStore(project.path)
        evidence_store.recover_incomplete()
        evidence_store.sync_scope(ScopeStore(project.path).load())
        key = project.path.resolve()
        self.evidence_stores[key] = evidence_store
        scope_path = ScopeStore(project.path).path
        self.evidence_scope_versions[key] = (
            (scope_path.stat().st_mtime_ns, scope_path.stat().st_size)
            if scope_path.exists() else None
        )
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
        evidence_store = EvidenceStore(project.path)
        evidence_store.recover_incomplete()
        evidence_store.sync_scope(ScopeStore(project.path).load())
        key = project.path.resolve()
        self.evidence_stores[key] = evidence_store
        scope_path = ScopeStore(project.path).path
        self.evidence_scope_versions[key] = (
            (scope_path.stat().st_mtime_ns, scope_path.stat().st_size)
            if scope_path.exists() else None
        )
        self.refresh_project_surfaces()

    def refresh_project_surfaces(self) -> None:
        if self._asset_selection_project_id != self.active_project_id:
            self.selected_asset_ids.clear()
            self.selected_asset_id = None
            self._asset_selection_project_id = self.active_project_id
        self.render_topbar()
        if self.active_view in {"findings", "assets", "evidence", "scope", "runs"}:
            self.render_workspace()
            self.render_inspector()
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

    def set_console_wrap(self, event: events.ValueChangeEventArguments) -> None:
        self.console_wrap = bool(event.value)
        if hasattr(self, "run_output"):
            if self.console_wrap:
                self.run_output.classes(add="wrap-output")
                ui.run_javascript(
                    f'document.querySelector("#c{self.run_output.id}")?.scrollTo({{left: 0}})'
                )
            else:
                self.run_output.classes(remove="wrap-output")

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
    def render_scope_state_filter(self, view_id: str, classes: str = "") -> None:
        state = self._scope_filter_state(view_id)
        checkbox = ui.checkbox(
            SCOPE_FILTER_LABELS[state],
            value=state,
            on_change=partial(self.set_record_scope_filter, view_id),
        ).props(
            f"dense toggle-indeterminate toggle-order=ft aria-label={view_id}-scope-filter"
        ).classes(f"scope-state-filter {classes}")
        setattr(self, f"{view_id}_scope_filter", checkbox)

    def render_record_pagination(self, view_id: str) -> None:
        with ui.element("div").classes("record-pagination"):
            previous = ui.button(
                icon="chevron_left",
                on_click=partial(self.change_record_page, view_id, -1),
            ).props(f"flat dense aria-label=Previous-{view_id}-page").classes(
                "asset-page-button"
            )
            label = ui.label("").classes("asset-page-label")
            following = ui.button(
                icon="chevron_right",
                on_click=partial(self.change_record_page, view_id, 1),
            ).props(f"flat dense aria-label=Next-{view_id}-page").classes(
                "asset-page-button"
            )
        setattr(self, f"{view_id}_prev_button", previous)
        setattr(self, f"{view_id}_page_label", label)
        setattr(self, f"{view_id}_next_button", following)

    def _update_record_pagination(
        self, view_id: str, page_index: int, page_count: int
    ) -> None:
        label = getattr(self, f"{view_id}_page_label", None)
        previous = getattr(self, f"{view_id}_prev_button", None)
        following = getattr(self, f"{view_id}_next_button", None)
        if label is None or previous is None or following is None:
            return
        label.set_text(f"PAGE {page_index + 1:02d} / {page_count:02d}")
        if page_index:
            previous.enable()
        else:
            previous.disable()
        if page_index + 1 < page_count:
            following.enable()
        else:
            following.disable()

    def change_record_page(self, view_id: str, delta: int) -> None:
        self.record_page_indexes[view_id] += delta
        if view_id == "findings":
            self.refresh_finding_results()
        elif view_id == "evidence":
            self.refresh_evidence_results()
        elif view_id == "runs":
            self.refresh_run_results()
        elif view_id == "scope":
            records = self.scope_records()
            self._refresh_record_results(
                view_id="scope", index=f"{len(records):02d} RULES", records=records,
                columns=(("decision", "DECISION"), ("target", "TARGET"), ("type", "TYPE"),
                         ("ownership", "OWNERSHIP"), ("source", "SOURCE"),
                         ("updated", "UPDATED")),
                selected_id=self.selected_scope_id or "", tone_key="decision",
            )
        self.render_inspector()

    def render_findings_workspace(self) -> None:
        """Render a compact, packet-list-inspired finding table."""
        findings = self.filtered_finding_records()
        if findings and self.selected_finding_id not in {item["id"] for item in findings}:
            self.selected_finding_id = findings[0]["id"]
        elif not findings:
            self.selected_finding_id = None
        ui.label("ASSESSMENT / FINDINGS").classes("section-kicker")
        with ui.element("div").classes("title-row"):
            ui.label("Findings").classes("page-title")
            self.findings_index_label = ui.label().classes("view-index")

        with ui.element("div").classes("finding-scope-controls"):
            self.render_scope_state_filter("findings")
            self.render_record_pagination("findings")
        self.findings_result_host = ui.element("div").classes("findings-results")
        self.refresh_finding_results(findings)

    def refresh_finding_results(
        self,
        findings: tuple[dict[str, str], ...] | None = None,
    ) -> None:
        """Refresh the Findings summary and rows without replacing the workspace."""
        if not hasattr(self, "findings_result_host"):
            return
        findings = self.filtered_finding_records() if findings is None else findings
        visible_sets = getattr(self, "_visible_record_sets", {})
        visible_sets["findings"] = findings
        self._visible_record_sets = visible_sets
        page, page_index, page_count, start = self._record_page(
            findings, self.record_page_indexes["findings"]
        )
        self.record_page_indexes["findings"] = page_index
        finding_ids = {finding["id"] for finding in page}
        if self.selected_finding_id not in finding_ids:
            self.selected_finding_id = page[0]["id"] if page else None
        if hasattr(self, "findings_index_label"):
            end = start + len(page)
            self.findings_index_label.set_text(
                f"{start + 1:,}-{end:,} / {len(findings):,} RECORDS"
                if findings else "0 / 0 RECORDS"
            )
        self._update_record_pagination("findings", page_index, page_count)
        self.findings_result_host.clear()
        row_elements: dict[str, object] = {}
        with self.findings_result_host:
            with ui.element("div").classes("finding-summary"):
                ui.label("ALL").classes("filter-active")
                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    count = sum(
                        finding["severity"] == severity.lower() for finding in findings
                    )
                    ui.label(f"{severity} {count:02d}")

            with ui.element("section").classes("finding-table"):
                with ui.element("div").classes("finding-row finding-header"):
                    ui.label("SEVERITY").classes("finding-cell finding-severity")
                    ui.label("FINDING").classes("finding-cell finding-name")
                    ui.label("ASSET").classes("finding-cell finding-asset")
                    ui.label("SOURCE").classes("finding-cell finding-source")
                    ui.label("CONFIDENCE").classes("finding-cell finding-confidence")
                    ui.label("SEEN").classes("finding-cell finding-seen")

                for finding in page:
                    selected = finding["id"] == self.selected_finding_id
                    classes = f"finding-row severity-{finding['severity']}"
                    if selected:
                        classes += " selected"
                    with ui.element("button").classes(classes).props(
                        f'type=button aria-label="Open finding {finding["id"]}: {finding["title"]}"'
                    ).on("click", partial(self.select_finding, finding["id"])) as row:
                        row_elements[finding["id"]] = row
                        ui.label(finding["severity"].upper()).classes(
                            "finding-cell finding-severity"
                        )
                        with ui.element("div").classes("finding-cell finding-name"):
                            ui.label(finding["title"]).classes("finding-title")
                            ui.label(finding["id"]).classes("finding-id")
                        ui.label(finding["asset"]).classes("finding-cell finding-asset")
                        ui.label(finding["source"].upper()).classes(
                            "finding-cell finding-source"
                        )
                        ui.label(finding["confidence"].upper()).classes(
                            "finding-cell finding-confidence"
                        )
                        ui.label(finding["seen"]).classes("finding-cell finding-seen")
            if not page:
                ui.label("NO FINDINGS MATCH THE CURRENT SEARCH").classes("module-empty")
        rows = getattr(self, "_row_elements", {})
        rows["findings"] = row_elements
        self._row_elements = rows

    # === END: FINDINGS VIEW ===

    # === START: PROJECT RECORD VIEWS ===
    def render_assets_workspace(self) -> None:
        records = self.filtered_asset_records()
        ui.label("INVENTORY / ASSETS").classes("section-kicker")
        with ui.element("div").classes("title-row"):
            ui.label("Assets").classes("page-title")
            self.assets_index_label = ui.label("").classes("view-index")

        with ui.element("div").classes("asset-controls"):
            self.render_scope_state_filter("assets", "asset-scope-filter")
            with ui.element("div").classes("asset-pagination"):
                self.asset_prev_button = ui.button(
                    icon="chevron_left", on_click=partial(self.change_asset_page, -1)
                ).props("flat dense aria-label=Previous-assets-page").classes(
                    "asset-page-button"
                )
                self.asset_page_label = ui.label("").classes("asset-page-label")
                self.asset_next_button = ui.button(
                    icon="chevron_right", on_click=partial(self.change_asset_page, 1)
                ).props("flat dense aria-label=Next-assets-page").classes(
                    "asset-page-button"
                )
            self.asset_selection_label = ui.label("").classes("asset-selection-count")
            with ui.button("ACTIONS", icon="more_horiz").props(
                "flat dense no-caps"
            ).classes("asset-action-button") as self.asset_action_button:
                with ui.menu().classes("asset-action-menu"):
                    ui.menu_item("ADD SELECTED TO SCOPE", self.add_selected_assets_to_scope)
                    ui.menu_item("CLEAR SELECTION", self.clear_asset_selection)
        self.assets_result_host = ui.element("div").classes("asset-results")
        self.refresh_asset_results(records)

    def select_asset_record(self, asset_id: str) -> None:
        previous_id = self.selected_asset_id
        self.selected_asset_id = asset_id
        self._update_selected_row("assets", previous_id, asset_id)
        if self.inspector_collapsed:
            self.inspector_collapsed = False
            self.update_inspector_layout()
        self.render_inspector()

    def toggle_asset_selection(
        self, asset_id: str, event: events.ValueChangeEventArguments
    ) -> None:
        if event.value:
            self.selected_asset_ids.add(asset_id)
        else:
            self.selected_asset_ids.discard(asset_id)
        self.refresh_asset_results()

    def toggle_visible_asset_selection(self, event: events.ValueChangeEventArguments) -> None:
        visible_ids = {
            record["id"] for record in getattr(self, "_visible_asset_records", ())
        }
        if event.value:
            self.selected_asset_ids.update(visible_ids)
        else:
            self.selected_asset_ids.difference_update(visible_ids)
        self.refresh_asset_results()

    def toggle_asset_selection_from_menu(self, asset_id: str) -> None:
        if asset_id in self.selected_asset_ids:
            self.selected_asset_ids.remove(asset_id)
        else:
            self.selected_asset_ids.add(asset_id)
        self.refresh_asset_results()

    def clear_asset_selection(self) -> None:
        self.selected_asset_ids.clear()
        self.refresh_asset_results()

    def _update_asset_action_state(self) -> None:
        count = len(self.selected_asset_ids)
        if hasattr(self, "asset_selection_label"):
            self.asset_selection_label.set_text(
                f"{count:02d} SELECTED" if count else "NO SELECTION"
            )
        if hasattr(self, "asset_action_button"):
            if count:
                self.asset_action_button.enable()
            else:
                self.asset_action_button.disable()

    @staticmethod
    def _record_page(
        records: tuple[dict[str, object], ...],
        page_index: int,
        page_size: int = RECORD_PAGE_SIZE,
    ) -> tuple[tuple[dict[str, object], ...], int, int, int]:
        """Return one bounded page plus its clamped index and starting offset."""
        page_count = max(1, (len(records) + page_size - 1) // page_size)
        page_index = min(max(page_index, 0), page_count - 1)
        start = page_index * page_size
        return records[start:start + page_size], page_index, page_count, start

    @staticmethod
    def _asset_page(
        records: tuple[dict[str, str], ...], page_index: int
    ) -> tuple[tuple[dict[str, str], ...], int, int, int]:
        page, page_index, page_count, start = DashboardUI._record_page(
            records, page_index, ASSET_PAGE_SIZE
        )
        return page, page_index, page_count, start  # type: ignore[return-value]

    def change_asset_page(self, delta: int) -> None:
        self.asset_page_index += delta
        self.refresh_asset_results()
        self.render_inspector()

    def refresh_asset_results(
        self, records: tuple[dict[str, str], ...] | None = None
    ) -> None:
        if not hasattr(self, "assets_result_host"):
            return
        filtered_records = records if records is not None else self.filtered_asset_records()
        visible_sets = getattr(self, "_visible_record_sets", {})
        visible_sets["assets"] = filtered_records
        self._visible_record_sets = visible_sets
        visible_records, self.asset_page_index, page_count, start = self._asset_page(
            filtered_records, self.asset_page_index
        )
        self._visible_asset_records = visible_records
        visible_ids = {record["id"] for record in visible_records}
        if self.selected_asset_id not in visible_ids:
            self.selected_asset_id = visible_records[0]["id"] if visible_records else None
        if hasattr(self, "assets_index_label"):
            end = start + len(visible_records)
            self.assets_index_label.set_text(
                f"{start + 1:,}-{end:,} / {len(filtered_records):,} RECORDS"
                if filtered_records else "0 / 0 RECORDS"
            )
        if hasattr(self, "asset_page_label"):
            self.asset_page_label.set_text(
                f"PAGE {self.asset_page_index + 1:02d} / {page_count:02d}"
            )
            if self.asset_page_index:
                self.asset_prev_button.enable()
            else:
                self.asset_prev_button.disable()
            if self.asset_page_index + 1 < page_count:
                self.asset_next_button.enable()
            else:
                self.asset_next_button.disable()
        self._update_asset_action_state()

        self.assets_result_host.clear()
        row_elements: dict[str, object] = {}
        with self.assets_result_host:
            with ui.element("section").classes("record-table assets-table"):
                with ui.element("div").classes("record-row record-header"):
                    ui.checkbox(
                        value=bool(visible_ids and visible_ids <= self.selected_asset_ids),
                        on_change=self.toggle_visible_asset_selection,
                    ).props("dense aria-label=Select-all-visible-assets").classes(
                        "record-cell asset-select-cell"
                    )
                    for key, label in (
                        ("type", "TYPE"), ("name", "ASSET"), ("address", "ADDRESS"),
                        ("ports", "PORTS"), ("scope", "SCOPE"), ("source", "SOURCE"),
                    ):
                        ui.label(label).classes(f"record-cell record-{key}")

                for record in visible_records:
                    tone = record["scope"].lower().replace(" ", "-")
                    classes = f"record-row tone-{tone}"
                    if record["id"] == self.selected_asset_id:
                        classes += " selected"
                    with ui.element("div").classes(classes).props(
                        f'role=button tabindex=0 aria-label="Open asset {record["id"]}"'
                    ).on(
                        "click", partial(self.select_asset_record, record["id"])
                    ).on(
                        "keydown.enter", partial(self.select_asset_record, record["id"])
                    ) as row:
                        row_elements[record["id"]] = row
                        ui.checkbox(
                            value=record["id"] in self.selected_asset_ids,
                            on_change=partial(self.toggle_asset_selection, record["id"]),
                        ).props(f'dense aria-label="Select asset {record["id"]}"').classes(
                            "record-cell asset-select-cell"
                        ).on("click", js_handler="event => event.stopPropagation()")
                        ui.label(record["type"]).classes("record-cell record-type")
                        with ui.element("div").classes("record-cell record-name record-primary"):
                            ui.label(record["name"]).classes("record-primary-value")
                            ui.label(record["id"]).classes("record-id")
                        ui.label(record["address"]).classes("record-cell record-address")
                        ui.label(record["ports"]).classes("record-cell record-ports")
                        ui.label(record["scope"]).classes("record-cell record-scope")
                        ui.label(record["source"]).classes("record-cell record-source")
                        with ui.context_menu().classes("asset-context-menu"):
                            scope_target_supported = record["target_kind"] in {
                                "domain", "host", "ipv4", "ipv6", "cidr", "url",
                            }
                            add_label = (
                                "ALREADY IN SCOPE" if record["scope_rule"]
                                else "ADD TO SCOPE" if scope_target_supported
                                else "NOT A SCOPE TARGET"
                            )
                            add_item = ui.menu_item(
                                add_label,
                                partial(self.add_assets_to_scope, (record["id"],)),
                            )
                            if record["scope_rule"] or not scope_target_supported:
                                add_item.disable()
                            ui.menu_item(
                                "DESELECT" if record["id"] in self.selected_asset_ids else "SELECT",
                                partial(self.toggle_asset_selection_from_menu, record["id"]),
                            )
        rows = getattr(self, "_row_elements", {})
        rows["assets"] = row_elements
        self._row_elements = rows
        if not visible_records:
            with self.assets_result_host:
                ui.label("NO ASSETS MATCH THE CURRENT FILTERS").classes("module-empty")

    def render_evidence_workspace(self) -> None:
        records = self.evidence_node_records()
        if records and self.selected_evidence_id not in {item["id"] for item in records}:
            self.selected_evidence_id = str(records[0]["id"])
        elif not records:
            self.selected_evidence_id = None
        self.render_record_workspace(
            view_id="evidence", kicker="PROVENANCE / EVIDENCE", title="Evidence",
            index=f"{len(records):02d} NODES",
            filters=("ALL", "ASSETS", "VULNERABILITIES", "IDENTITIES", "DOMAINS", "URLS"), records=records,
            columns=(("kind", "TYPE"), ("identifier", "IDENTIFIER"), ("scope_anchor", "SCOPE ANCHOR"),
                     ("relations", "RELATED"), ("artifact_count", "ARTIFACTS"), ("updated", "UPDATED")),
            selected_id=self.selected_evidence_id or "", tone_key="scope",
            interactive_filters=True,
        )

    def refresh_evidence_results(self) -> None:
        """Refresh indexed Evidence rows without replacing filters or other UI state."""
        if not hasattr(self, "evidence_result_host"):
            return
        records = self.evidence_node_records()
        record_ids = {str(record["id"]) for record in records}
        if self.selected_evidence_id not in record_ids:
            self.selected_evidence_id = str(records[0]["id"]) if records else None
        self._refresh_record_results(
            view_id="evidence",
            index=f"{len(records):02d} NODES",
            records=records,
            columns=(
                ("kind", "TYPE"), ("identifier", "IDENTIFIER"),
                ("scope_anchor", "SCOPE ANCHOR"), ("relations", "RELATED"),
                ("artifact_count", "ARTIFACTS"), ("updated", "UPDATED"),
            ),
            selected_id=self.selected_evidence_id or "",
            tone_key="scope",
        )

    def render_scope_workspace(self) -> None:
        records = self.scope_records()
        if records and self.selected_scope_id not in {item["id"] for item in records}:
            self.selected_scope_id = records[0]["id"]
        self.render_record_workspace(
            view_id="scope", kicker="AUTHORIZATION / SCOPE", title="Scope",
            index=f"{len(records):02d} RULES",
            filters=("ALL", "ALLOWED", "DENIED", "REVIEW REQUIRED"), records=records,
            columns=(("decision", "DECISION"), ("target", "TARGET"), ("type", "TYPE"),
                     ("ownership", "OWNERSHIP"), ("source", "SOURCE"), ("updated", "UPDATED")),
            selected_id=self.selected_scope_id, tone_key="decision",
        )

    def render_runs_workspace(self) -> None:
        records = self.filtered_run_records()
        if records and self.selected_run_id not in {record["id"] for record in records}:
            self.selected_run_id = records[0]["id"]
        elif not records:
            self.selected_run_id = None
        self.render_record_workspace(
            view_id="runs", kicker="EXECUTION / RUNS", title="Runs", index=f"{len(records):02d} RECORDS",
            filters=("ALL", "ACTIVE", "COMPLETED", "FAILED", "QUEUED", "CANCELLED"), records=records,
            columns=(("state", "STATE"), ("module", "MODULE"), ("target", "TARGET"),
                     ("scope", "SCOPE"), ("duration", "DURATION"), ("started", "STARTED")),
            selected_id=self.selected_run_id or "", tone_key="state",
        )

    def refresh_run_results(self) -> None:
        """Refresh run rows and state labels without rebuilding the Runs workspace."""
        if not hasattr(self, "runs_result_host"):
            return
        records = self.filtered_run_records()
        record_ids = {record["id"] for record in records}
        if self.selected_run_id not in record_ids:
            self.selected_run_id = records[0]["id"] if records else None
        self._refresh_record_results(
            view_id="runs",
            index=f"{len(records):02d} RECORDS",
            records=records,
            columns=(
                ("state", "STATE"), ("module", "MODULE"), ("target", "TARGET"),
                ("scope", "SCOPE"), ("duration", "DURATION"),
                ("started", "STARTED"),
            ),
            selected_id=self.selected_run_id or "",
            tone_key="state",
        )

    def render_record_workspace(
        self,
        *,
        view_id: str,
        kicker: str,
        title: str,
        index: str,
        filters: tuple[str, ...],
        records: tuple[dict[str, object], ...],
        columns: tuple[tuple[str, str], ...],
        selected_id: str,
        tone_key: str,
        interactive_filters: bool = False,
    ) -> None:
        """Render one of the project-aware record lists with a shared dense pattern."""
        ui.label(kicker).classes("section-kicker")
        with ui.element("div").classes("title-row"):
            ui.label(title).classes("page-title")
            index_label = ui.label(index).classes("view-index")
            setattr(self, f"{view_id}_index_label", index_label)

        with ui.element("div").classes(f"record-filters {view_id}-filters"):
            if view_id == "scope":
                add_scope_button = ui.button(
                    "ADD SCOPE ITEM", icon="add", on_click=self.open_scope_add_dialog
                ).props("flat dense no-caps").classes("record-filter-button scope-add-button")
                if self.active_project is None:
                    add_scope_button.disable()
            for filter_index, label in enumerate(filters):
                if view_id == "runs":
                    ui.button(label, on_click=partial(self.set_run_state_filter, label)).props(
                        "flat dense no-caps"
                    ).classes(
                        "record-filter-button active"
                        if label == self.run_state_filter else "record-filter-button"
                    )
                elif interactive_filters:
                    ui.button(label, on_click=partial(self.preview_evidence_filter, label)).props(
                        "flat dense no-caps"
                    ).classes(
                        "record-filter-button active" if filter_index == 0 else "record-filter-button"
                    )
                else:
                    ui.label(label).classes("filter-active" if filter_index == 0 else "")
            if view_id == "runs":
                self.render_scope_state_filter("runs", "run-scope-filter")
            if view_id in {"evidence", "scope", "runs"}:
                self.render_record_pagination(view_id)

        result_host = ui.element("section").classes(f"record-table {view_id}-table")
        setattr(self, f"{view_id}_result_host", result_host)
        self._refresh_record_results(
            view_id=view_id,
            index=index,
            records=records,
            columns=columns,
            selected_id=selected_id,
            tone_key=tone_key,
        )

    def _refresh_record_results(
        self,
        *,
        view_id: str,
        index: str,
        records: tuple[dict[str, object], ...],
        columns: tuple[tuple[str, str], ...],
        selected_id: str,
        tone_key: str,
    ) -> None:
        """Replace one generic record table's rows while preserving its controls."""
        result_host = getattr(self, f"{view_id}_result_host", None)
        if result_host is None:
            return
        index_label = getattr(self, f"{view_id}_index_label", None)
        if index_label is not None:
            index_label.set_text(index)
        query = self.search_query.strip().casefold()
        if query and view_id == "evidence":
            store = self.active_evidence_store()
            detailed_matches = store.search_evidence_asset_ids(query) if store else set()
            visible_records = tuple(
                record for record in records
                if str(record["id"]) in detailed_matches
                or query in " ".join(str(value) for value in record.values()).casefold()
            )
        else:
            visible_records = tuple(
                record for record in records
                if not query
                or query in " ".join(str(value) for value in record.values()).casefold()
            )
        visible_sets = getattr(self, "_visible_record_sets", {})
        visible_sets[view_id] = visible_records
        self._visible_record_sets = visible_sets
        page_index = self.record_page_indexes.get(view_id, 0)
        page, page_index, page_count, start = self._record_page(
            visible_records, page_index
        )
        self.record_page_indexes[view_id] = page_index
        page_ids = {str(record["id"]) for record in page}
        if selected_id not in page_ids:
            selected_id = str(page[0]["id"]) if page else ""
            attribute = f"selected_{view_id.rstrip('s')}_id"
            if hasattr(self, attribute):
                setattr(self, attribute, selected_id or None)

        noun = index.rsplit(" ", 1)[-1]
        if index_label is not None:
            end = start + len(page)
            index_label.set_text(
                f"{start + 1:,}-{end:,} / {len(visible_records):,} {noun}"
                if visible_records else f"0 / 0 {noun}"
            )
        self._update_record_pagination(view_id, page_index, page_count)

        result_host.clear()
        row_elements: dict[str, object] = {}
        with result_host:
            with ui.element("div").classes("record-row record-header"):
                for key, label in columns:
                    ui.label(label).classes(f"record-cell record-{key}")

            for record in page:
                tone = record[tone_key].lower().replace(" ", "-").replace("/", "-")
                classes = f"record-row tone-{tone}"
                if record["id"] == selected_id:
                    classes += " selected"
                with ui.element("button").classes(classes).props(
                    f'type=button aria-label="Open {view_id} record {record["id"]}"'
                ).on("click", partial(self.select_record, view_id, record["id"])) as row:
                    row_elements[str(record["id"])] = row
                    for column_index, (key, _label) in enumerate(columns):
                        if column_index == 1:
                            with ui.element("div").classes(f"record-cell record-{key} record-primary"):
                                ui.label(record[key]).classes("record-primary-value")
                                ui.label(record["id"]).classes("record-id")
                        else:
                            ui.label(record[key]).classes(f"record-cell record-{key}")
            if not page:
                ui.label(
                    f"NO {view_id.upper()} RECORDS MATCH THE CURRENT SEARCH"
                ).classes("module-empty")
        rows = getattr(self, "_row_elements", {})
        rows[view_id] = row_elements
        self._row_elements = rows

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
                health = self.module_health.get(module.id)
                state = health.state if health else "UNCHECKED"
                tone = "interactive" if state == "AVAILABLE" else "muted"
                ui.label(state).classes(f"state {tone}")

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
    def render_empty_inspector(self, label: str) -> None:
        with ui.element("div").classes("inspector-header"):
            with ui.element("div").classes("inspector-header-copy"):
                ui.label(label.upper()).classes("panel-number")
                ui.label(
                    "Open a project to view indexed records"
                    if self.active_project is None else "No indexed records yet"
                ).classes("panel-title")

    def render_inspector(self) -> None:
        self.inspector.clear()
        if self.active_view == "findings":
            with self.inspector:
                visible_sets = getattr(self, "_visible_record_sets", {})
                records = (
                    visible_sets["findings"]
                    if "findings" in visible_sets else self.filtered_finding_records()
                )
                if not records:
                    self.render_empty_inspector("Findings")
                    return
                record = self._record(records, self.selected_finding_id or records[0]["id"])
                self.render_finding_inspector(record)
            return
        if self.active_view == "assets":
            with self.inspector:
                visible_sets = getattr(self, "_visible_record_sets", {})
                records = (
                    visible_sets["assets"]
                    if "assets" in visible_sets else self.filtered_asset_records()
                )
                if not records:
                    self.render_empty_inspector("Assets")
                    return
                record = self._record(records, self.selected_asset_id or records[0]["id"])
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
                visible_sets = getattr(self, "_visible_record_sets", {})
                records = (
                    visible_sets["evidence"]
                    if "evidence" in visible_sets else self.evidence_node_records()
                )
                if not records:
                    self.render_empty_inspector("Evidence")
                    return
                record_id = self.selected_evidence_id or str(records[0]["id"])
                record = self.evidence_node_record(record_id)
                self.render_evidence_inspector(record)
            return
        if self.active_view == "scope":
            with self.inspector:
                visible_sets = getattr(self, "_visible_record_sets", {})
                records = (
                    visible_sets["scope"]
                    if "scope" in visible_sets else self.scope_records()
                )
                if not records:
                    self.render_empty_inspector("Scope")
                    return
                record = self._record(records, self.selected_scope_id or records[0]["id"])
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
                visible_sets = getattr(self, "_visible_record_sets", {})
                records = (
                    visible_sets["runs"]
                    if "runs" in visible_sets else self.filtered_run_records()
                )
                if not records:
                    with ui.element("div").classes("inspector-header"):
                        with ui.element("div").classes("inspector-header-copy"):
                            ui.label("RUNS").classes("panel-number")
                            ui.label("No runs match the current filters").classes("panel-title")
                    return
                record = self._record(records, self.selected_run_id or records[0]["id"])
                self.render_run_inspector(record)
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
                    health = self.module_health.get(module.id)
                    ui.label(
                        f"{module.bin.upper()} / {health.state if health else 'UNCHECKED'}"
                    ).classes("panel-tool")

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
                            placeholder=module.target_placeholder,
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
                        on_click=self.open_selected_module_settings,
                    ).props("flat dense no-caps").classes("text-action")

                with ui.element("div").classes("field"):
                    ui.label("RUN OPTIONS").classes("field-label")
                    for label, value in profile.options:
                        with ui.element("div").classes("check-row"):
                            ui.label(label).classes("check-name")
                            ui.label(value).classes("check-value")

                if module.config_fields:
                    with ui.element("div").classes("field"):
                        ui.label("MODULE OPTIONS").classes("field-label")
                        for config_field in module.config_fields:
                            ui.label(config_field.label).classes("field-label")
                            ui.input(
                                value=self.module_config_values[module.id].get(config_field.id, ""),
                                placeholder=config_field.placeholder,
                                on_change=partial(
                                    self.set_module_config, module.id, config_field.id
                                ),
                            ).props("dense outlined clearable").classes("config-control")

                with ui.element("div").classes("field"):
                    ui.label("RUN TIMEOUT / SECONDS").classes("field-label")
                    ui.input(
                        value=self.run_timeout_values.get(module.id, ""),
                        placeholder="optional / no limit",
                        on_change=partial(self.set_run_timeout, module.id),
                    ).props("dense outlined clearable type=number min=1").classes("config-control")

                with ui.element("div").classes("field"):
                    ui.label("COMMAND PREVIEW").classes("field-label")
                    with ui.element("div").classes("command-preview"):
                        try:
                            selection = self._target_selection(module)
                            project = self.active_project
                            request = RunRequest(
                                module=module, profile=profile,
                                context=ExecutionContext(
                                    selection=selection,
                                    project_id=project.id if project else None,
                                    project_name=project.name if project else None,
                                    scope_enforced=self.scope_enforced,
                                ),
                                options=tuple(
                                    (field.id, self.module_config_values[module.id].get(field.id, ""))
                                    for field in module.config_fields
                                ),
                            )
                            adapter = self.execution_manager.adapters.get(module.adapter)
                            executable = adapter.resolve_executable(request)
                            command = adapter.preview_command(request, executable)
                            ui.label(command.executable).classes("command-tool")
                            for argument in command.arguments:
                                ui.label(f" {shlex.quote(argument)}").classes("command-argument")
                        except (ExecutionError, ScopeValidationError, KeyError):
                            ui.label(module.path).classes("command-tool")
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

    def render_finding_inspector(self, finding: dict[str, str]) -> None:
        """Render details for the selected finding in the shared right inspector."""
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
                ("SCOPE", finding["scope"]),
                ("LOCATION", finding["location"]),
                ("SOURCE", finding["source"].upper()),
                ("CONFIDENCE", finding["confidence"].upper()),
                ("LIFECYCLE", finding["state"].replace("_", " ").upper()),
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

    def render_run_inspector(self, record: dict[str, str]) -> None:
        """Render run metadata plus safe artifact preview/download actions."""
        run = self.run_manifest(record["id"])
        self.render_record_inspector(
            record, "RUN", record["module"], record["state"],
            (("TARGET", record["target"]), ("SCOPE", record["scope"]),
             ("PROJECT", record["project"]),
             ("PROFILE", record["profile"]), ("DURATION", record["duration"]),
             ("STARTED", record["started"]), ("EXIT CODE", record["exit_code"]),
             ("EVIDENCE", record["evidence_state"])),
            (("EXECUTION CONTEXT", record["context"]), ("COMMAND", record["command"]),
             ("SUMMARY", record["summary"]),
             ("EVIDENCE INGESTION", record["evidence_summary"])), record["state"],
        )
        if self.inspector_collapsed:
            return
        with ui.element("section").classes("run-artifacts"):
            ui.label(f"ARTIFACTS / {len(run.artifacts):02d}").classes("field-label")
            for artifact in run.artifacts:
                with ui.element("div").classes("run-artifact-row"):
                    with ui.element("div").classes("run-artifact-copy"):
                        ui.label(artifact.path).classes("settings-project-name")
                        ui.label(f"{artifact.size} bytes / {artifact.sha256[:12]}").classes("settings-meta")
                    ui.button(
                        "VIEW", on_click=partial(self.open_artifact, run.id, artifact.path)
                    ).props("flat dense no-caps").classes("settings-action")
                    ui.button(
                        "GET", on_click=partial(self.download_artifact, run.id, artifact.path)
                    ).props("flat dense no-caps").classes("settings-action primary")

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

    # === START: MODULE SETTINGS ===
    def _profile_drafts(self, key: str, module: ModuleDefinition | None) -> list[dict[str, object]]:
        if key not in self.settings_profile_drafts:
            profiles = module.profiles if module else ()
            self.settings_profile_drafts[key] = [profile.to_mapping() for profile in profiles]
        return self.settings_profile_drafts[key]

    def select_settings_profile(self, index: int) -> None:
        self.settings_profile_index = index
        self.render_settings_content()

    def add_settings_profile(self) -> None:
        module = None if self.settings_module_id == "__new__" else self.module_catalog.get(self.settings_module_id)
        drafts = self._profile_drafts(self.settings_module_id, module)
        drafts.append({
            "name": f"Profile {len(drafts) + 1}", "options": [], "command": [],
            "arguments": ["{targets}"], "output_format": "text",
        })
        self.settings_profile_index = len(drafts) - 1
        self.render_settings_content()

    def delete_settings_profile(self, index: int) -> None:
        module = None if self.settings_module_id == "__new__" else self.module_catalog.get(self.settings_module_id)
        drafts = self._profile_drafts(self.settings_module_id, module)
        if 0 <= index < len(drafts):
            drafts.pop(index)
        self.settings_profile_index = max(0, min(self.settings_profile_index, len(drafts) - 1))
        self.render_settings_content()

    def update_settings_profile(self, index: int, field: str, event: events.ValueChangeEventArguments) -> None:
        drafts = self.settings_profile_drafts[self.settings_module_id]
        drafts[index][field] = str(event.value or "")

    async def refresh_module_health(self) -> None:
        modules = self.module_catalog.modules
        requests = tuple(
            RunRequest(
                module=module, profile=module.default_profile,
                context=ExecutionContext(selection=TargetSelection.direct((Target.parse("example.com"),))),
            )
            for module in modules
        )
        results = await asyncio.gather(
            *(self.execution_manager.check_tool(request) for request in requests)
        )
        self.module_health.update({module.id: health for module, health in zip(modules, results)})
        if self.settings_open and self.settings_section == "modules":
            self.render_settings_content()
        if self.active_view == "launchpad":
            self.render_workspace()

    @staticmethod
    def _parse_argument_template(value: str) -> tuple[str, ...]:
        """Split an argv editor value without consuming Windows path backslashes."""
        tokens = shlex.split(value, posix=False)
        return tuple(
            token[1:-1]
            if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}
            else token
            for token in tokens
        )

    def save_settings_module(self) -> None:
        try:
            drafts = self.settings_profile_drafts.get(self.settings_module_id, [])
            if not drafts:
                raise ValueError("add at least one scan profile")
            profiles: list[ScanProfile] = []
            for draft in drafts:
                arguments = draft.get("arguments", ())
                if isinstance(arguments, str):
                    arguments = self._parse_argument_template(arguments)
                if not any(token in arguments for token in ("{target}", "{targets}", "{target_file}")):
                    raise ValueError(f"profile {draft.get('name')!r} needs a target placeholder")
                payload = dict(draft)
                payload["arguments"] = arguments
                profiles.append(ScanProfile.from_mapping(payload))
            values = {
                "eyebrow": str(self.module_eyebrow.value or ""),
                "description": str(self.module_description.value or ""),
                "bin": str(self.module_binary.value or ""),
                "path": str(self.module_path.value or ""),
                "icon": str(self.module_icon.value or "").strip() or "extension",
                "target_placeholder": str(self.module_target_placeholder.value or ""),
                "profiles": profiles,
            }
            if self.settings_module_id == "__new__":
                module = self.module_catalog.create_module(**values)
            else:
                module = self.module_catalog.replace_module(self.settings_module_id, **values)
            self.module_catalog.save()
        except (OSError, ValueError) as error:
            ui.notify(str(error), type="negative")
            return
        self.settings_module_id = module.id
        self.settings_profile_drafts[module.id] = [profile.to_mapping() for profile in module.profiles]
        self.settings_profile_drafts.pop("__new__", None)
        self.target_modes.setdefault(module.id, "direct")
        self.direct_targets.setdefault(module.id, "")
        self.selected_profiles[module.id] = module.default_profile.name
        self.module_config_values.setdefault(module.id, {})
        self.run_timeout_values.setdefault(module.id, "")
        ui.notify(f"Saved module {module.id} / {module.bin}", type="positive")
        self.render_settings_content()
        if self.active_view == "launchpad":
            self.render_workspace()

    def confirm_delete_settings_module(self) -> None:
        if self.settings_module_id == "__new__":
            return
        module = self.module_catalog.get(self.settings_module_id)
        with ui.dialog().classes("project-dialog") as dialog, ui.card().classes("project-modal"):
            ui.label("DELETE MODULE").classes("section-kicker")
            ui.label(module.description).classes("settings-title")
            ui.label("This removes the module definition and all of its scan profiles.").classes(
                "settings-section-copy"
            )
            with ui.element("div").classes("settings-actions"):
                ui.button(
                    "DELETE", on_click=lambda: (dialog.close(), self.delete_settings_module(module.id))
                ).props("flat no-caps").classes("settings-action danger")
                ui.button("CANCEL", on_click=dialog.close).props("flat no-caps").classes("settings-action")
        dialog.open()

    def delete_settings_module(self, module_id: str) -> None:
        try:
            if len(self.module_catalog) <= 1:
                raise ValueError("Blackwall requires at least one module")
            self.module_catalog.remove_module(module_id)
            self.module_catalog.save()
        except (OSError, ValueError) as error:
            ui.notify(str(error), type="negative")
            return
        self.settings_profile_drafts.pop(module_id, None)
        self.module_health.pop(module_id, None)
        self.target_modes.pop(module_id, None)
        self.direct_targets.pop(module_id, None)
        self.selected_profiles.pop(module_id, None)
        self.module_config_values.pop(module_id, None)
        self.run_timeout_values.pop(module_id, None)
        self.settings_module_id = self.module_catalog.modules[0].id
        if self.selected_module_id == module_id:
            self.selected_module_id = self.settings_module_id
        self.render_settings_content()
        self.render_workspace()

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
                        health = self.module_health.get(module.id)
                        state = health.state if health else "UNCHECKED"
                        ui.label(state).classes(
                            "settings-state ready" if state == "AVAILABLE" else "settings-state missing"
                        )

            with ui.element("section").classes("settings-module-editor"):
                if self.settings_module_id == "__new__":
                    module = None
                    module_id = self.module_catalog.next_id()
                else:
                    module = self.module_catalog.get(self.settings_module_id)
                    module_id = module.id

                drafts = self._profile_drafts(self.settings_module_id, module)
                with ui.element("div").classes("settings-field-grid"):
                    self.module_eyebrow = self.render_setting_field(
                        "TYPE / EYEBROW", module.eyebrow if module else "",
                        placeholder="e.g. discovery",
                    )
                    self.render_setting_field("AUTO ID", module_id, readonly=True)
                self.module_description = self.render_setting_field(
                    "DESCRIPTION", module.description if module else "",
                    placeholder="what the module does",
                )
                with ui.element("div").classes("settings-field-grid"):
                    self.module_binary = self.render_setting_field(
                        "BINARY", module.bin if module else "", placeholder="e.g. subfinder"
                    )
                    self.module_icon = self.render_setting_field(
                        "ICON (OPTIONAL)", module.icon if module else "",
                        placeholder="default icon if empty",
                    )
                self.module_path = self.render_setting_field(
                    "EXECUTABLE PATH", module.path if module else "",
                    placeholder="binary name or full executable path",
                )
                self.module_target_placeholder = self.render_setting_field(
                    "TARGET PLACEHOLDER", module.target_placeholder if module else "",
                    placeholder="e.g. example.com or https://example.com",
                )

                if module:
                    health = self.module_health.get(module.id)
                    with ui.element("div").classes("tool-health"):
                        ui.label(f"HEALTH / {health.state if health else 'UNCHECKED'}").classes("field-label")
                        if health:
                            ui.label(health.executable or health.detail).classes("settings-note")
                            if health.version:
                                ui.label(health.version).classes("settings-meta")
                        ui.button("CHECK", icon="health_and_safety", on_click=lambda: asyncio.create_task(
                            self.refresh_module_health()
                        )).props("flat dense no-caps").classes("settings-action")

                ui.label("SCAN PROFILES").classes("settings-group-title profile-heading")
                with ui.element("div").classes("profile-list"):
                    for index, draft in enumerate(drafts):
                        classes = "profile-row active" if index == self.settings_profile_index else "profile-row"
                        with ui.element("button").classes(classes).props("type=button").on(
                            "click", partial(self.select_settings_profile, index)
                        ):
                            ui.label(f"{index + 1:02d}").classes("profile-index")
                            ui.label(str(draft["name"])).classes("profile-name")
                            ui.label("DEFAULT" if index == 0 else "PROFILE").classes("settings-meta")
                    with ui.element("button").classes("profile-add").props("type=button").on(
                        "click", self.add_settings_profile
                    ):
                        ui.label("+ ADD PROFILE")

                if drafts:
                    index = min(self.settings_profile_index, len(drafts) - 1)
                    draft = drafts[index]
                    ui.label("PROFILE NAME").classes("field-label")
                    ui.input(
                        value=str(draft["name"]),
                        on_change=partial(self.update_settings_profile, index, "name"),
                    ).props("dense outlined").classes("config-control settings-input")
                    ui.label("ARGUMENT TEMPLATE / ONE ARGUMENT STRING").classes("field-label")
                    ui.textarea(
                        value=shlex.join(tuple(draft.get("arguments", ())))
                        if not isinstance(draft.get("arguments"), str) else str(draft["arguments"]),
                        placeholder="-u {target} -json",
                        on_change=partial(self.update_settings_profile, index, "arguments"),
                    ).props("dense outlined autogrow").classes("config-control settings-input")
                    ui.label("OUTPUT FORMAT").classes("field-label")
                    ui.input(
                        value=str(draft.get("output_format", "text")),
                        on_change=partial(self.update_settings_profile, index, "output_format"),
                    ).props("dense outlined").classes("config-control settings-input")
                    ui.button(
                        "REMOVE PROFILE", on_click=partial(self.delete_settings_profile, index)
                    ).props("flat dense no-caps").classes("settings-action danger")

                with ui.element("div").classes("settings-actions editor-actions"):
                    ui.button("SAVE MODULE", icon="save", on_click=self.save_settings_module).props(
                        "flat no-caps"
                    ).classes("settings-action primary")
                    if module:
                        ui.button(
                            "DELETE MODULE", icon="delete", on_click=self.confirm_delete_settings_module
                        ).props("flat no-caps").classes("settings-action danger")

    # === END: MODULE SETTINGS ===

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
        self,
        label: str,
        value: str,
        *,
        readonly: bool = False,
        password: bool = False,
        placeholder: str = "",
    ):
        with ui.element("div").classes("settings-field"):
            ui.label(label).classes("field-label")
            field = ui.input(value=value, placeholder=placeholder).props("dense outlined").classes(
                "config-control settings-input"
            )
            if readonly:
                field.props("readonly")
            if password:
                field.props("type=password")
            return field

    # === END: SETTINGS DIALOG ===

    # === START: RUN OUTPUT ===
    # Bottom output region backed by persistent stdout/stderr logs.
    @staticmethod
    def _tail_text_lines(
        path: Path,
        max_lines: int = CONSOLE_MAX_LINES,
        max_bytes: int = CONSOLE_TAIL_BYTES,
    ) -> tuple[tuple[str, ...], bool]:
        """Read a bounded UTF-8 tail without loading an arbitrarily large log."""
        with path.open("rb") as stream:
            stream.seek(0, 2)
            size = stream.tell()
            read_size = min(size, max_bytes)
            stream.seek(-read_size, 2)
            data = stream.read(read_size)

        truncated = read_size < size
        if truncated:
            newline = data.find(b"\n")
            if newline >= 0:
                data = data[newline + 1:]
        lines = data.decode("utf-8", errors="replace").splitlines()
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
            truncated = True
        return tuple(lines), truncated

    def render_console(self) -> None:
        # The persisted log already contains pending live lines; avoid replaying them.
        self._pending_run_output = []
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
                ui.checkbox(
                    "WRAP", value=self.console_wrap, on_change=self.set_console_wrap
                ).props("dense").classes("console-wrap-toggle")
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

            log_classes = "console-log wrap-output" if self.console_wrap else "console-log"
            self.run_output = ui.element("div").classes(log_classes).props(
                'aria-label="Run output" role=log aria-live=polite'
            )
            output_lines: list[str] = []
            output_truncated = False
            if run and run.run_path:
                console_path = run.run_path / "console.log"
                paths = (console_path,) if console_path.is_file() else (
                    run.run_path / "stderr.log",
                    run.run_path / "stdout.log",
                )
                for path in paths:
                    if not path.is_file():
                        continue
                    try:
                        lines, truncated = self._tail_text_lines(path)
                        output_lines.extend(lines)
                        output_truncated = output_truncated or truncated
                    except OSError:
                        output_lines.append(f"Unable to read {path.name}")
            if len(output_lines) > CONSOLE_MAX_LINES:
                output_lines = output_lines[-CONSOLE_MAX_LINES:]
                output_truncated = True
            if output_truncated:
                output_lines.insert(
                    0,
                    f"[BLACKWALL] OUTPUT TRUNCATED — SHOWING LAST {CONSOLE_MAX_LINES:,} LINES",
                )
            with self.run_output:
                self.run_output_content = ui.label("\n".join(output_lines)).classes(
                    "console-content"
                ).props(f'data-line-count="{len(output_lines)}"')

    # === END: RUN OUTPUT ===


# NiceGUI root callable used by main.py.
def build_ui(
    app_config: AppConfig | None = None,
    execution_manager: ExecutionManager | None = None,
) -> None:
    DashboardUI(app_config=app_config, execution_manager=execution_manager).build()
