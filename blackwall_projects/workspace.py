"""UI-independent state for currently open project workspaces."""

from __future__ import annotations

from pathlib import Path

from .models import Project, ProjectValidationError
from .store import ProjectStore


class ProjectWorkspace:
    """Coordinate portable project directories and open tabs without NiceGUI."""

    def __init__(self, store: ProjectStore) -> None:
        self.store = store
        self.open_projects: list[Project] = []
        self.active_project_id: str | None = None

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

    def _open(self, project: Project) -> None:
        existing = next((item for item in self.open_projects if item.id == project.id), None)
        if existing is not None and existing.path != project.path:
            raise ProjectValidationError(
                f"project id {project.id} is already open from a different directory"
            )
        if existing is None:
            self.open_projects.append(project)
        self.active_project_id = project.id
