"""Application integration for indexing completed project run artifacts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from blackwall_scope import ScopeStore

from .models import IngestionResult
from .parsers import ParserRegistry
from .pipeline import EvidencePipeline
from .store import EvidenceStore

if TYPE_CHECKING:
    from blackwall_execution.models import RunManifest


class ProjectRunIngestor:
    """Select a native parser and index one terminal project run."""

    _ARTIFACT_NAMES = {
        "dnsx": "dnsx.jsonl",
        "nmap": "nmap.xml",
        "httpx": "httpx.jsonl",
        "gau": "gau.jsonl",
        "tlsx": "tlsx.jsonl",
    }

    def __init__(self, parsers: ParserRegistry | None = None) -> None:
        self.parsers = parsers or ParserRegistry.native()

    def __call__(self, manifest: "RunManifest") -> dict[str, int] | None:
        if manifest.project_id is None or manifest.run_path is None:
            return None
        module_key = manifest.module_bin.casefold()
        try:
            parser = self.parsers.get(module_key)
        except KeyError:
            # Runtime-defined modules may not have an evidence parser yet. Their
            # raw artifact remains available and the scan itself is still valid.
            return None
        project_path, artifact = self._artifact_for(manifest, module_key)
        if artifact is None:
            return None
        records = parser.parse(artifact, run_id=manifest.id)
        relative_artifact = artifact.relative_to(project_path).as_posix()
        records = tuple(replace(record, artifact_path=relative_artifact) for record in records)
        pipeline = EvidencePipeline(EvidenceStore(project_path))
        result = pipeline.ingest(
            records, scope=ScopeStore(project_path).load(), parser=parser.key,
            source=f"run:{manifest.id}",
        )
        return self._summary(result)

    def _artifact_for(
        self, manifest: "RunManifest", module_key: str
    ) -> tuple[Path, Path | None]:
        run_path = manifest.run_path.resolve()
        if run_path.parent.name != "runs":
            raise ValueError("project run is not stored under a project runs directory")
        project_path = run_path.parent.parent.resolve()
        artifact_root = (run_path / "artifacts").resolve()
        candidates: list[Path] = []
        for record in manifest.artifacts:
            candidate = (run_path / record.path).resolve()
            if candidate != artifact_root and artifact_root not in candidate.parents:
                raise ValueError("run artifact path escapes the artifact directory")
            if not candidate.is_file():
                continue
            if module_key == "amass":
                if candidate.suffix.casefold() in {".db", ".sqlite", ".sqlite3"}:
                    candidates.append(candidate)
            elif candidate.name.casefold() == self._ARTIFACT_NAMES.get(module_key, ""):
                candidates.append(candidate)
        if module_key == "amass":
            candidates.sort(key=lambda path: (path.name.casefold() != "asset.db", path.as_posix()))
        return project_path, candidates[0] if candidates else None

    @staticmethod
    def _summary(result: IngestionResult) -> dict[str, int]:
        return {
            "assets_created": result.assets_created,
            "assets_matched": result.assets_matched,
            "evidence_created": result.evidence_created,
            "findings_created": result.findings_created,
            "relationships_created": result.relationships_created,
        }
