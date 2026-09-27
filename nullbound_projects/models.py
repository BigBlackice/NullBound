"""Versioned, platform-neutral project metadata models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
from typing import Any, Mapping


PROJECT_KIND = "nullbound-project"
PROJECT_SCHEMA_VERSION = 1
PROJECT_ID_PATTERN = re.compile(r"^P-[0-9]{4,}$")
MAX_PROJECT_NAME_LENGTH = 120


class ProjectValidationError(ValueError):
    """Raised when a directory is not a valid NullBound project."""


def _validate_timestamp(value: object, field: str) -> str:
    timestamp = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProjectValidationError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ProjectValidationError(f"{field} must include a timezone")
    return timestamp


def validate_project_name(value: object) -> str:
    """Return a normalized display name or raise a validation error."""
    name = str(value or "").strip()
    if not name:
        raise ProjectValidationError("project name cannot be empty")
    if len(name) > MAX_PROJECT_NAME_LENGTH:
        raise ProjectValidationError(
            f"project name cannot exceed {MAX_PROJECT_NAME_LENGTH} characters"
        )
    if any(ord(character) < 32 for character in name):
        raise ProjectValidationError("project name cannot contain control characters")
    return name


@dataclass(frozen=True, slots=True)
class ProjectManifest:
    """Portable metadata persisted in a project's ``project.json`` file."""

    id: str
    name: str
    created_at: str
    updated_at: str
    schema_version: int = PROJECT_SCHEMA_VERSION
    kind: str = PROJECT_KIND

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ProjectManifest:
        """Validate and construct a manifest from decoded JSON data."""
        if data.get("kind") != PROJECT_KIND:
            raise ProjectValidationError(f"kind must be {PROJECT_KIND!r}")
        if data.get("schema_version") != PROJECT_SCHEMA_VERSION:
            raise ProjectValidationError(
                f"unsupported project schema version: {data.get('schema_version')!r}"
            )

        project_id = str(data.get("id", "")).strip()
        if not PROJECT_ID_PATTERN.fullmatch(project_id):
            raise ProjectValidationError("project id must match P- followed by at least four digits")

        return cls(
            id=project_id,
            name=validate_project_name(data.get("name")),
            created_at=_validate_timestamp(data.get("created_at"), "created_at"),
            updated_at=_validate_timestamp(data.get("updated_at"), "updated_at"),
        )

    def to_mapping(self) -> dict[str, object]:
        """Return the stable on-disk representation without machine-specific paths."""
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class Project:
    """A validated project manifest paired with its local directory."""

    manifest: ProjectManifest
    path: Path

    @property
    def id(self) -> str:
        return self.manifest.id

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def manifest_path(self) -> Path:
        return self.path / "project.json"

    @property
    def runs_path(self) -> Path:
        return self.path / "runs"

    @property
    def scope_path(self) -> Path:
        """Optional versioned target/scope data stored beside project metadata."""
        return self.path / "scope.json"

    @property
    def database_path(self) -> Path:
        """Searchable local index; portable raw evidence remains beside it on disk."""
        return self.path / "project.db"


@dataclass(frozen=True, slots=True)
class ProjectIssue:
    """A managed project directory which could not be opened safely."""

    path: Path
    message: str
