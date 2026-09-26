"""Local application-session persistence for open project tabs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final
from uuid import uuid4

from .models import Project


WORKSPACE_SESSION_KIND: Final = "blackwall-workspace-session"
WORKSPACE_SESSION_SCHEMA_VERSION: Final = 1
WORKSPACE_SESSION_NAME: Final = "workspace.json"


class WorkspaceSessionStore:
    """Persist local tab state without modifying portable project data."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve(strict=False)

    def load(self) -> tuple[tuple[Path, ...], Path | None]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return (), None
        if not isinstance(payload, dict):
            return (), None
        if (
            payload.get("kind") != WORKSPACE_SESSION_KIND
            or payload.get("schema_version") != WORKSPACE_SESSION_SCHEMA_VERSION
        ):
            return (), None
        raw_paths = payload.get("open_projects", ())
        if not isinstance(raw_paths, list):
            return (), None
        paths = tuple(
            Path(value).expanduser().resolve(strict=False)
            for value in raw_paths if isinstance(value, str) and value.strip()
        )
        raw_active = payload.get("active_project")
        active = (
            Path(raw_active).expanduser().resolve(strict=False)
            if isinstance(raw_active, str) and raw_active.strip() else None
        )
        return paths, active

    def save(self, projects: list[Project], active_project_id: str | None) -> None:
        active = next(
            (project for project in projects if project.id == active_project_id), None
        )
        payload = {
            "kind": WORKSPACE_SESSION_KIND,
            "schema_version": WORKSPACE_SESSION_SCHEMA_VERSION,
            "open_projects": [str(project.path.resolve()) for project in projects],
            "active_project": str(active.path.resolve()) if active is not None else None,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
