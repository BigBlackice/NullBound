"""Immutable requests and durable run records for tool execution."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

from nullbound_scope import ExecutionContext
from recon_modules import ModuleDefinition, ScanProfile


RUN_KIND = "nullbound-run"
RUN_SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ExecutionError(RuntimeError):
    """Raised for an invalid or unavailable execution request."""


class RunState(StrEnum):
    QUEUED = "queued"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED, self.CANCELLED}


@dataclass(frozen=True, slots=True)
class RunRequest:
    module: ModuleDefinition
    profile: ScanProfile
    context: ExecutionContext
    options: tuple[tuple[str, str], ...] = ()
    timeout_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class ToolHealth:
    """Result of resolving and identifying one configured executable."""

    state: str
    executable: str | None = None
    version: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CompanionProcessSpec:
    """A short-lived local service required while the main command runs."""

    executable: str
    arguments: tuple[str, ...]
    ready_host: str
    ready_port: int
    ready_http_path: str | None = None
    label: str = "companion process"
    startup_timeout_seconds: float = 15.0

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.executable, self.ready_host, self.ready_port)


@dataclass(frozen=True, slots=True)
class CommandSpec:
    executable: str
    arguments: tuple[str, ...]
    output_format: str = "text"
    companion: CompanionProcessSpec | None = None
    environment: tuple[tuple[str, str], ...] = ()

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.executable, *self.arguments)


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    path: str
    size: int
    sha256: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ArtifactRecord:
        return cls(path=str(data["path"]), size=int(data["size"]), sha256=str(data["sha256"]))

    def to_mapping(self) -> dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class RunManifest:
    id: str
    state: RunState
    module_id: str
    module_name: str
    module_bin: str
    module_path: str
    module_version: str | None
    profile_name: str
    targets: tuple[dict[str, str], ...]
    target_source: str
    options: tuple[tuple[str, str], ...]
    project_id: str | None
    project_name: str | None
    scope_enforced: bool
    executable: str
    arguments: tuple[str, ...]
    created_at: str
    timeout_seconds: int | None = None
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    duration_seconds: float | None = None
    error: str | None = None
    artifacts: tuple[ArtifactRecord, ...] = ()
    evidence_state: str = "pending"
    evidence_parser: str | None = None
    evidence_error: str | None = None
    evidence_summary: tuple[tuple[str, int], ...] = ()
    kind: str = RUN_KIND
    schema_version: int = RUN_SCHEMA_VERSION
    run_path: Path | None = field(default=None, compare=False, repr=False)

    def evolve(self, **changes: object) -> RunManifest:
        return replace(self, **changes)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], run_path: Path | None = None) -> RunManifest:
        if data.get("kind") != RUN_KIND or data.get("schema_version") != RUN_SCHEMA_VERSION:
            raise ExecutionError("unsupported run manifest")
        return cls(
            id=str(data["id"]), state=RunState(str(data["state"])),
            module_id=str(data["module_id"]), module_name=str(data["module_name"]),
            module_bin=str(data["module_bin"]), module_path=str(data["module_path"]),
            module_version=data.get("module_version"), profile_name=str(data["profile_name"]),
            targets=tuple(dict(item) for item in data.get("targets", ())),
            target_source=str(data["target_source"]),
            options=tuple((str(x["id"]), str(x["value"])) for x in data.get("options", ())),
            project_id=data.get("project_id"),
            project_name=data.get("project_name"), scope_enforced=bool(data["scope_enforced"]),
            executable=str(data["executable"]), arguments=tuple(str(x) for x in data["arguments"]),
            timeout_seconds=(
                int(data["timeout_seconds"]) if data.get("timeout_seconds") is not None else None
            ),
            created_at=str(data["created_at"]), started_at=data.get("started_at"),
            finished_at=data.get("finished_at"), exit_code=data.get("exit_code"),
            duration_seconds=data.get("duration_seconds"),
            error=data.get("error"),
            artifacts=tuple(ArtifactRecord.from_mapping(x) for x in data.get("artifacts", ())),
            evidence_state=str(data.get(
                "evidence_state",
                "pending" if data.get("project_id") else "not_applicable",
            )),
            evidence_parser=data.get("evidence_parser"),
            evidence_error=data.get("evidence_error"),
            evidence_summary=tuple(
                (str(key), int(value))
                for key, value in dict(data.get("evidence_summary", {})).items()
            ),
            run_path=run_path,
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "kind": self.kind, "schema_version": self.schema_version, "id": self.id,
            "state": self.state.value, "module_id": self.module_id,
            "module_name": self.module_name, "module_bin": self.module_bin,
            "module_path": self.module_path, "module_version": self.module_version,
            "profile_name": self.profile_name, "targets": list(self.targets),
            "target_source": self.target_source,
            "options": [{"id": key, "value": value} for key, value in self.options],
            "project_id": self.project_id,
            "project_name": self.project_name, "scope_enforced": self.scope_enforced,
            "executable": self.executable, "arguments": list(self.arguments),
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at, "started_at": self.started_at,
            "finished_at": self.finished_at, "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "error": self.error, "artifacts": [item.to_mapping() for item in self.artifacts],
            "evidence_state": self.evidence_state,
            "evidence_parser": self.evidence_parser,
            "evidence_error": self.evidence_error,
            "evidence_summary": dict(self.evidence_summary),
        }


@dataclass(frozen=True, slots=True)
class RunEvent:
    run: RunManifest
    stream: str | None = None
    text: str | None = None
