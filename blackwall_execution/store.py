"""Portable run directories and atomic manifest persistence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from uuid import uuid4

from .models import (
    ArtifactRecord,
    CommandSpec,
    ExecutionError,
    RunManifest,
    RunRequest,
    RunState,
    utc_now,
)


RUN_MANIFEST_NAME = "run.json"


def default_runs_root(home: Path | None = None) -> Path:
    return (home or Path.home()).expanduser() / ".blackwall" / "runs"


class RunStore:
    """Create and discover self-contained run records."""

    def __init__(self, standalone_root: Path | None = None) -> None:
        # Unattached runs intentionally live only for this Blackwall process.
        # An explicit root remains available for tests and embedding.
        self._temporary_directory = TemporaryDirectory(prefix="blackwall-runs-") if standalone_root is None else None
        root = Path(self._temporary_directory.name) if self._temporary_directory else standalone_root
        self.standalone_root = Path(root).expanduser().resolve(False)

    def reserve(self, project_path: Path | None = None) -> tuple[str, Path]:
        root = (
            Path(project_path).expanduser().resolve(False) / "runs"
            if project_path is not None else self.standalone_root
        )
        root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        run_id = f"RUN-{stamp}-{uuid4().hex[:6].upper()}"
        run_path = root / run_id
        run_path.mkdir()
        (run_path / "artifacts").mkdir()
        return run_id, run_path

    def create(
        self,
        run_id: str,
        run_path: Path,
        request: RunRequest,
        command: CommandSpec,
        version: str | None,
    ) -> RunManifest:
        context = request.context
        manifest = RunManifest(
            id=run_id,
            state=RunState.QUEUED,
            module_id=request.module.id,
            module_name=request.module.description,
            module_bin=request.module.bin,
            module_path=request.module.path,
            module_version=version,
            profile_name=request.profile.name,
            targets=tuple(
                {"kind": target.kind.value, "value": target.value, "normalized": target.normalized}
                for target in context.selection.targets
            ),
            target_source=context.selection.source.value,
            options=request.options,
            project_id=context.project_id,
            project_name=context.project_name,
            scope_enforced=context.scope_enforced,
            executable=command.executable,
            arguments=command.arguments,
            created_at=utc_now(),
            timeout_seconds=request.timeout_seconds,
            run_path=run_path,
        )
        return self.save(manifest)

    def save(self, manifest: RunManifest) -> RunManifest:
        if manifest.run_path is None:
            raise ExecutionError("run manifest has no storage path")
        path = manifest.run_path / RUN_MANIFEST_NAME
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(manifest.to_mapping(), indent=2) + "\n", encoding="utf-8"
            )
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return manifest

    def load(self, run_path: Path) -> RunManifest:
        path = Path(run_path) / RUN_MANIFEST_NAME
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ExecutionError(f"cannot read run manifest: {path}") from error
        if not isinstance(payload, dict):
            raise ExecutionError(f"run manifest must contain an object: {path}")
        return RunManifest.from_mapping(payload, Path(run_path))

    def list_runs(self, project_paths: tuple[Path, ...] = ()) -> tuple[RunManifest, ...]:
        roots = (self.standalone_root, *(Path(path) / "runs" for path in project_paths))
        records: dict[Path, RunManifest] = {}
        for root in roots:
            if not root.is_dir():
                continue
            for run_path in root.iterdir():
                if not run_path.is_dir() or not (run_path / RUN_MANIFEST_NAME).is_file():
                    continue
                try:
                    records[run_path.resolve()] = self.load(run_path)
                except ExecutionError:
                    continue
        return tuple(sorted(records.values(), key=lambda item: item.created_at, reverse=True))

    def list_unattached(self) -> tuple[RunManifest, ...]:
        """Return session-only runs which have not been assigned to a project."""
        if not self.standalone_root.is_dir():
            return ()
        return tuple(run for run in self.list_runs() if run.project_id is None)

    def adopt_unattached(self, project: object) -> tuple[RunManifest, ...]:
        """Move all terminal session runs into a newly created project."""
        runs = self.list_unattached()
        active = tuple(run for run in runs if not run.state.terminal)
        if active:
            raise ExecutionError("wait for or cancel active standalone runs before creating a project")
        project_path = Path(getattr(project, "path"))
        destination_root = project_path / "runs"
        destination_root.mkdir(parents=True, exist_ok=True)
        collisions = tuple(run.id for run in runs if (destination_root / run.id).exists())
        if collisions:
            raise ExecutionError(f"project already contains run {collisions[0]}")
        adopted: list[RunManifest] = []
        for run in runs:
            if run.run_path is None:
                continue
            destination = destination_root / run.id
            shutil.move(str(run.run_path), str(destination))
            adopted.append(self.save(run.evolve(
                project_id=str(getattr(project, "id")),
                project_name=str(getattr(project, "name")),
                run_path=destination,
            )))
        return tuple(adopted)

    def delete_unattached(self) -> tuple[str, ...]:
        """Permanently remove all terminal session-only runs."""
        runs = self.list_unattached()
        if any(not run.state.terminal for run in runs):
            raise ExecutionError("wait for or cancel active standalone runs before deleting them")
        removed: list[str] = []
        for run in runs:
            if run.run_path and run.run_path.is_dir():
                shutil.rmtree(run.run_path)
            removed.append(run.id)
        return tuple(removed)

    @staticmethod
    def resolve_artifact(manifest: RunManifest, relative_path: str) -> Path:
        if manifest.run_path is None:
            raise ExecutionError("run has no storage path")
        root = (manifest.run_path / "artifacts").resolve()
        candidate = (manifest.run_path / relative_path).resolve()
        if candidate != root and root not in candidate.parents:
            raise ExecutionError("artifact path escapes the run directory")
        if not candidate.is_file():
            raise ExecutionError("artifact no longer exists")
        return candidate

    def recover_incomplete(self, project_paths: tuple[Path, ...] = ()) -> tuple[RunManifest, ...]:
        recovered: list[RunManifest] = []
        for manifest in self.list_runs(project_paths):
            if manifest.state.terminal:
                continue
            recovered.append(self.save(manifest.evolve(
                state=RunState.FAILED,
                finished_at=utc_now(),
                error="Blackwall stopped before the run completed",
            )))
        return tuple(recovered)

    @staticmethod
    def collect_artifacts(run_path: Path) -> tuple[ArtifactRecord, ...]:
        artifact_root = run_path / "artifacts"
        records: list[ArtifactRecord] = []
        if not artifact_root.is_dir():
            return ()
        for path in sorted(item for item in artifact_root.rglob("*") if item.is_file()):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            records.append(ArtifactRecord(
                path=path.relative_to(run_path).as_posix(),
                size=path.stat().st_size,
                sha256=digest.hexdigest(),
            ))
        return tuple(records)
