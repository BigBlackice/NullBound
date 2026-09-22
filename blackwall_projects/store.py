"""Filesystem-backed Blackwall project creation and discovery."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from typing import Final
from uuid import uuid4

from .models import (
    PROJECT_ID_PATTERN,
    Project,
    ProjectIssue,
    ProjectManifest,
    ProjectValidationError,
    validate_project_name,
)


PROJECT_MANIFEST_NAME: Final = "project.json"
PROJECT_RUNS_DIRECTORY: Final = "runs"


def default_projects_root(home: Path | None = None) -> Path:
    """Return Blackwall's managed project root below the current user's home."""
    user_home = (home or Path.home()).expanduser()
    return user_home / ".blackwall" / "projects"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ProjectStore:
    """Create, locate, and strictly validate projects inside one managed root."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or default_projects_root()).expanduser().resolve(strict=False)

    def ensure_root(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise ProjectValidationError(f"project store is not a directory: {self.root}")
        return self.root

    def list_projects(self) -> tuple[Project, ...]:
        """Return every valid managed project ordered by numeric project ID."""
        projects, issues = self.discover_projects()
        if issues:
            first = issues[0]
            raise ProjectValidationError(f"{first.path.name}: {first.message}")
        return projects

    def discover_projects(self) -> tuple[tuple[Project, ...], tuple[ProjectIssue, ...]]:
        """Return valid projects and report invalid managed directories separately."""
        root = self.ensure_root()
        candidates = (
            path for path in root.iterdir()
            if path.is_dir() and PROJECT_ID_PATTERN.fullmatch(path.name)
        )
        projects: list[Project] = []
        issues: list[ProjectIssue] = []
        for path in sorted(candidates, key=lambda item: int(item.name[2:])):
            try:
                projects.append(self.open_project(path))
            except ProjectValidationError as error:
                issues.append(ProjectIssue(path=path, message=str(error)))
        return tuple(projects), tuple(issues)

    def create_project(self, name: str) -> Project:
        """Atomically create a project manifest and its initial run directory."""
        root = self.ensure_root()
        normalized_name = validate_project_name(name)
        project_id = self._next_project_id()
        destination = root / project_id
        staging = root / f".{project_id}.{uuid4().hex}.tmp"
        now = _utc_now()
        manifest = ProjectManifest(
            id=project_id,
            name=normalized_name,
            created_at=now,
            updated_at=now,
        )

        try:
            staging.mkdir()
            (staging / PROJECT_RUNS_DIRECTORY).mkdir()
            self._write_manifest(staging / PROJECT_MANIFEST_NAME, manifest)
            staging.replace(destination)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise

        return self.open_project(destination)

    def open_project(self, reference: str | Path) -> Project:
        """Open a project ID in the default root or any explicit project directory."""
        raw_reference = Path(reference).expanduser()
        candidate = (
            self.ensure_root() / raw_reference
            if not raw_reference.is_absolute() and PROJECT_ID_PATTERN.fullmatch(str(raw_reference))
            else raw_reference
        )
        project_path = candidate.resolve(strict=False)

        if not project_path.is_dir():
            raise ProjectValidationError(f"project directory does not exist: {project_path}")

        manifest_path = project_path / PROJECT_MANIFEST_NAME
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise ProjectValidationError(f"missing {PROJECT_MANIFEST_NAME}: {project_path}") from error
        except (OSError, json.JSONDecodeError) as error:
            raise ProjectValidationError(f"cannot read project manifest: {manifest_path}") from error

        if not isinstance(payload, dict):
            raise ProjectValidationError("project manifest must contain a JSON object")
        manifest = ProjectManifest.from_mapping(payload)

        runs_path = project_path / PROJECT_RUNS_DIRECTORY
        try:
            runs_path.mkdir(exist_ok=True)
        except OSError as error:
            raise ProjectValidationError(f"cannot create runs directory: {runs_path}") from error
        if not runs_path.is_dir():
            raise ProjectValidationError(f"runs path is not a directory: {runs_path}")
        return Project(manifest=manifest, path=project_path)

    def _next_project_id(self) -> str:
        numbers = [
            int(path.name[2:])
            for path in self.root.iterdir()
            if path.is_dir() and PROJECT_ID_PATTERN.fullmatch(path.name)
        ]
        return f"P-{max(numbers, default=0) + 1:04d}"

    @staticmethod
    def _write_manifest(path: Path, manifest: ProjectManifest) -> None:
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(manifest.to_mapping(), indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
