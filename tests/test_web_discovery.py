"""Focused tests for the fixed multi-step Web Discovery module."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from nullbound_execution import (
    ArtifactRecord,
    ExecutionError,
    RunManifest,
    RunRequest,
    RunState,
    ToolHealth,
)
from nullbound_modules import WebDiscoveryModule
from nullbound_scope import ScopeRule, ScopeStatus, ScopeValidationError, Target, TargetKind
from recon_modules import load_default_catalog


class FakeExecutionManager:
    def __init__(
        self,
        project_path: Path,
        unavailable: str | None = None,
        evidence_failure: str | None = None,
    ) -> None:
        self.project_path = project_path
        self.unavailable = unavailable
        self.evidence_failure = evidence_failure
        self.started: list[RunRequest] = []
        self.runs: dict[str, RunManifest] = {}

    async def check_tool(self, request: RunRequest) -> ToolHealth:
        if request.module.bin == self.unavailable:
            return ToolHealth("MISSING", detail="not installed")
        return ToolHealth("AVAILABLE", request.module.path, "test", "ready")

    async def start(self, request: RunRequest, project_path: Path | None = None) -> RunManifest:
        self.started.append(request)
        run_id = f"RUN-{len(self.started):02d}"
        run_path = (project_path or self.project_path) / "runs" / run_id
        artifact_path = run_path / "artifacts" / f"{request.module.bin}.jsonl"
        artifact_path.parent.mkdir(parents=True)
        targets = tuple(target.normalized for target in request.context.selection.targets)
        if request.module.bin == "subfinder":
            records = (
                {"host": "api.example.com", "input": "example.com"},
                {"host": "blocked.example.com", "input": "example.com"},
            )
        elif request.module.bin == "dnsx":
            records = tuple({"host": target, "a": ["192.0.2.10"]} for target in targets)
        else:
            records = tuple({"url": f"https://{target}/", "status_code": 200} for target in targets)
        artifact_path.write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
        manifest = RunManifest(
            id=run_id,
            state=RunState.QUEUED,
            module_id=request.module.id,
            module_name=request.module.description,
            module_bin=request.module.bin,
            module_path=request.module.path,
            module_version="test",
            profile_name=request.profile.name,
            targets=tuple(target.to_mapping() for target in request.context.selection.targets),
            target_source="direct",
            options=(),
            project_id=request.context.project_id,
            project_name=request.context.project_name,
            scope_enforced=request.context.scope_enforced,
            executable=request.module.path,
            arguments=(),
            created_at="2026-01-01T00:00:00Z",
            run_path=run_path,
        )
        self.runs[run_id] = manifest.evolve(
            state=RunState.COMPLETED,
            artifacts=(ArtifactRecord(
                artifact_path.relative_to(run_path).as_posix(),
                artifact_path.stat().st_size,
                "digest",
            ),),
            evidence_state=(
                "failed" if request.module.bin == self.evidence_failure else "indexed"
            ),
            evidence_error=(
                "database unavailable"
                if request.module.bin == self.evidence_failure else None
            ),
        )
        return manifest

    async def wait(self, run_id: str) -> RunManifest:
        return self.runs[run_id]


class WebDiscoveryModuleTests(unittest.IsolatedAsyncioTestCase):
    def test_discovery_profile_selects_subfinder_profile_without_changing_stages(self) -> None:
        with TemporaryDirectory() as temporary:
            manager = FakeExecutionManager(Path(temporary))
            module = WebDiscoveryModule(manager, load_default_catalog())  # type: ignore[arg-type]
            request = module._request(
                module.get_profile("broad"), "01", (Target.parse("example.com"),),
                project_id="P-0001", project_name="Example", scope_enforced=False,
                timeout_seconds=None, proxy=None,
            )

        self.assertEqual(request.profile.name, "Broad passive")
        with self.assertRaisesRegex(ScopeValidationError, "unknown Web Discovery profile"):
            module.get_profile("missing")

    def test_scope_seeds_accept_domains_and_urls_but_not_regex(self) -> None:
        rules = (
            ScopeRule(
                "SC-0001", Target(TargetKind.DOMAIN, "*.example.com"), ScopeStatus.ALLOWED
            ),
            ScopeRule(
                "SC-0002", Target(TargetKind.URL, "https://example.com/app"),
                ScopeStatus.ALLOWED,
            ),
            ScopeRule(
                "SC-0003", Target(TargetKind.REGEX, r".*\.example\.com"),
                ScopeStatus.ALLOWED,
            ),
            ScopeRule(
                "SC-0004", Target(TargetKind.URL, "https://192.0.2.10/"),
                ScopeStatus.ALLOWED,
            ),
        )

        seeds = WebDiscoveryModule.scope_seeds(rules, ("SC-0001", "SC-0002"))
        self.assertEqual(tuple(target.normalized for target in seeds), ("example.com",))
        with self.assertRaisesRegex(ScopeValidationError, "incompatible selection"):
            WebDiscoveryModule.scope_seeds(rules, ("SC-0003",))
        self.assertFalse(WebDiscoveryModule.supports_scope_rule(rules[3]))

    async def test_pipeline_runs_existing_launchers_and_enforces_exclusions(self) -> None:
        with TemporaryDirectory() as temporary:
            project_path = Path(temporary)
            manager = FakeExecutionManager(project_path)
            module = WebDiscoveryModule(manager, load_default_catalog())  # type: ignore[arg-type]
            rules = (
                ScopeRule(
                    "SC-0001", Target(TargetKind.DOMAIN, "example.com"),
                    ScopeStatus.ALLOWED,
                ),
                ScopeRule(
                    "SC-0002", Target(TargetKind.DOMAIN, "blocked.example.com"),
                    ScopeStatus.DENIED,
                ),
            )
            started: list[tuple[int, str]] = []

            result = await module.run(
                (Target.parse("example.com"),),
                project_id="P-0001",
                project_name="Example",
                project_path=project_path,
                scope_rules=rules,
                scope_enforced=True,
                on_stage_started=lambda number, _count, run: started.append(
                    (number, run.module_bin)
                ),
            )

        self.assertEqual([request.module.bin for request in manager.started], [
            "subfinder", "dnsx", "httpx",
        ])
        self.assertIn("{target_file}", manager.started[2].profile.arguments)
        self.assertEqual(
            tuple(target.normalized for target in manager.started[1].context.selection.targets),
            ("example.com", "api.example.com"),
        )
        self.assertEqual(started, [(1, "subfinder"), (2, "dnsx"), (3, "httpx")])
        self.assertEqual(len(result.runs), 3)
        self.assertEqual(result.discovered_domains, 2)
        self.assertEqual(result.resolved_hosts, 2)
        self.assertEqual(result.live_web_services, 2)
        self.assertEqual(result.excluded_targets, 1)

    async def test_preflight_fails_before_creating_any_run(self) -> None:
        with TemporaryDirectory() as temporary:
            project_path = Path(temporary)
            manager = FakeExecutionManager(project_path, unavailable="dnsx")
            module = WebDiscoveryModule(manager, load_default_catalog())  # type: ignore[arg-type]

            with self.assertRaisesRegex(ExecutionError, "dnsx: not installed"):
                await module.run(
                    (Target.parse("example.com"),),
                    project_id="P-0001",
                    project_name="Example",
                    project_path=project_path,
                    scope_rules=(),
                    scope_enforced=False,
                )

        self.assertEqual(manager.started, [])

    async def test_indexing_failure_stops_before_the_next_stage(self) -> None:
        with TemporaryDirectory() as temporary:
            project_path = Path(temporary)
            manager = FakeExecutionManager(project_path, evidence_failure="subfinder")
            module = WebDiscoveryModule(manager, load_default_catalog())  # type: ignore[arg-type]

            with self.assertRaisesRegex(ExecutionError, "evidence indexing failed"):
                await module.run(
                    (Target.parse("example.com"),),
                    project_id="P-0001",
                    project_name="Example",
                    project_path=project_path,
                    scope_rules=(),
                    scope_enforced=False,
                )

        self.assertEqual([request.module.bin for request in manager.started], ["subfinder"])


if __name__ == "__main__":
    unittest.main()
