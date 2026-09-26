"""UI-independent state for currently open project workspaces."""

from __future__ import annotations

from pathlib import Path

from .models import Project, ProjectValidationError
from .session import WORKSPACE_SESSION_NAME, WorkspaceSessionStore
from .store import ProjectStore


class ProjectWorkspace:
    """Coordinate portable project directories and open tabs without NiceGUI."""

    def __init__(
        self,
        store: ProjectStore,
        session_store: WorkspaceSessionStore | None = None,
    ) -> None:
        self.store = store
        self.session_store = session_store or WorkspaceSessionStore(
            self.store.root.parent / WORKSPACE_SESSION_NAME
        )
        self.open_projects: list[Project] = []
        self.active_project_id: str | None = None
        self._restore()

    def create(self, name: str, parent: Path | None = None) -> Project:
        project_store = self.store if parent is None else ProjectStore(parent)
        project = project_store.create_project(name)
        self._open(project)
        return project

    def open(self, reference: str | Path) -> Project:
        project = self.store.open_project(reference)
        self._open(project)
        return project

    def select(self, project_id: str) -> None:
        if project_id not in {project.id for project in self.open_projects}:
            raise KeyError(project_id)
        self.active_project_id = project_id
        self._persist()

    def close(self, project_id: str) -> None:
        index = next(
            (index for index, project in enumerate(self.open_projects) if project.id == project_id),
            None,
        )
        if index is None:
            raise KeyError(project_id)

        self.open_projects.pop(index)
        if self.active_project_id == project_id:
            self.active_project_id = (
                self.open_projects[min(index, len(self.open_projects) - 1)].id
                if self.open_projects else None
            )
        self._persist()

    def _open(self, project: Project) -> None:
        existing = next((item for item in self.open_projects if item.id == project.id), None)
        if existing is not None and existing.path != project.path:
            raise ProjectValidationError(
                f"project id {project.id} is already open from a different directory"
            )
        if existing is None:
            self.open_projects.append(project)
        self.active_project_id = project.id
        self._persist()

    def _restore(self) -> None:
        paths, active_path = self.session_store.load()
        for path in paths:
            try:
                project = self.store.open_project(path)
                existing = next(
                    (item for item in self.open_projects if item.id == project.id), None
                )
                if existing is not None and existing.path != project.path:
                    continue
                if existing is None:
                    self.open_projects.append(project)
            except (OSError, ProjectValidationError):
                continue
        active = next(
            (
                project for project in self.open_projects
                if active_path is not None and project.path == active_path
            ),
            None,
        )
        self.active_project_id = (
            active.id if active is not None
            else self.open_projects[-1].id if self.open_projects else None
        )
        if paths:
            self._persist()

    def _persist(self) -> None:
        try:
            self.session_store.save(self.open_projects, self.active_project_id)
        except OSError:
            # Losing local tab convenience must not prevent opening a valid project.
            pass
