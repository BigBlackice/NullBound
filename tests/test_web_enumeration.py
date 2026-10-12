"""Scope-to-assets tests for the built-in Web Enumeration module."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from nullbound_evidence import (
    AssetKind,
    AssetReference,
    EvidencePipeline,
    EvidenceStore,
    ParsedRecord,
)
from nullbound_execution import (
    ExecutionError,
    RunManifest,
    RunRequest,
    RunState,
    ToolHealth,
)
from nullbound_modules import WebEnumerationModule
from nullbound_scope import ScopeDocument, ScopeRule, ScopeStatus, ScopeValidationError, Target
from recon_modules import load_default_catalog


class FakeExecutionManager:
    def __init__(self, project_path: Path, unavailable: str | None = None) -> None:
        self.project_path = project_path
        self.unavailable = unavailable
        self.started: list[RunRequest] = []
        self.runs: dict[str, RunManifest] = {}

    async def check_tool(self, request: RunRequest) -> ToolHealth:
        if request.module.bin == self.unavailable:
            return ToolHealth("MISSING", detail="not installed")
        return ToolHealth("AVAILABLE", request.module.path, "test", "ready")

    async def start(self, request: RunRequest, project_path: Path | None = None) -> RunManifest:
        self.started.append(request)
        run_id = f"RUN-{len(self.started):02d}"
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
            target_source=request.context.selection.source.value,
            options=(),
            project_id=request.context.project_id,
            project_name=request.context.project_name,
            scope_enforced=request.context.scope_enforced,
            executable=request.module.path,
            arguments=(),
            created_at="2026-01-01T00:00:00Z",
            run_path=(project_path or self.project_path) / "runs" / run_id,
        )
        self.runs[run_id] = manifest.evolve(
            state=RunState.COMPLETED, evidence_state="indexed"
        )
        return manifest

    async def wait(self, run_id: str) -> RunManifest:
        return self.runs[run_id]


class WebEnumerationModuleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project_path = Path(self.temporary.name)
        self.store = EvidenceStore(self.project_path)
        self.scope = ScopeDocument(rules=(
            ScopeRule("SC-0001", Target.parse("google.com"), ScopeStatus.ALLOWED),
            ScopeRule("SC-0002", Target.parse("*.google.com"), ScopeStatus.ALLOWED),
            ScopeRule("SC-0003", Target.parse("google.co.uk"), ScopeStatus.ALLOWED),
        ))
        EvidencePipeline(self.store).ingest((
            ParsedRecord(
                AssetKind.DOMAIN,
                "mail.google.com",
                "subfinder",
                related=(AssetReference(
                    AssetKind.DOMAIN, "google.com", "discovered_from"
                ),),
            ),
            ParsedRecord(
                AssetKind.DOMAIN,
                "mail.google.com",
                "dnsx",
                related=(AssetReference(
                    AssetKind.IPV4, "192.0.2.10", "resolves_to"
                ),),
            ),
            ParsedRecord(
                AssetKind.DOMAIN,
                "mail.google.co.uk",
                "subfinder",
                related=(AssetReference(
                    AssetKind.DOMAIN, "google.co.uk", "discovered_from"
                ),),
            ),
            ParsedRecord(
                AssetKind.URL, "https://mail.google.com/admin", "httpx"
            ),
        ), scope=self.scope, source="fixture")

    def _rule_id(self, target: str) -> str:
        return next(
            str(rule["id"]) for rule in self.store.list_scope_rules()
            if rule["original_target"] == target
        )

    def test_exact_scope_rule_does_not_include_discovered_subdomains(self) -> None:
        manager = FakeExecutionManager(self.project_path)
        module = WebEnumerationModule(manager, load_default_catalog())  # type: ignore[arg-type]

        targets = module.resolve_targets(
            self.store, self._rule_id("google.com"), "quick"
        )

        values = {item.target.normalized for item in targets}
        self.assertEqual(values, {"google.com"})
        self.assertNotIn("mail.google.co.uk", values)

    def test_wildcard_scope_rule_includes_matching_subdomains_and_descendants(self) -> None:
        manager = FakeExecutionManager(self.project_path)
        module = WebEnumerationModule(manager, load_default_catalog())  # type: ignore[arg-type]

        targets = module.resolve_targets(
            self.store, self._rule_id("*.google.com"), "quick"
        )

        self.assertEqual({item.target.normalized for item in targets}, {
            "mail.google.com", "192.0.2.10", "https://mail.google.com/admin",
        })

    async def test_selected_chain_runs_archive_http_and_tls_with_scope_snapshots(self) -> None:
        manager = FakeExecutionManager(self.project_path)
        module = WebEnumerationModule(manager, load_default_catalog())  # type: ignore[arg-type]
        started: list[tuple[int, str]] = []

        result = await module.run(
            self.store,
            self._rule_id("google.com"),
            "deep",
            project_id="P-0001",
            project_name="Google",
            project_path=self.project_path,
            scope_rules=self.scope.rules,
            scope_enforced=False,
            on_stage_started=lambda number, _count, run: started.append(
                (number, run.module_bin)
            ),
        )

        self.assertEqual(
            [request.module.bin for request in manager.started], ["gau", "httpx", "tlsx"]
        )
        self.assertEqual(
            tuple(
                target.normalized
                for target in manager.started[0].context.selection.targets
            ),
            ("google.com",),
        )
        self.assertNotIn("--subs", manager.started[0].profile.arguments)
        self.assertTrue(all(
            "{target_file}" in request.profile.arguments for request in manager.started[1:]
        ))
        self.assertTrue(all(
            request.context.selection.source.value == "scope_anchor"
            for request in manager.started
        ))
        self.assertNotIn(
            "https://mail.google.com/admin",
            {
                target.normalized
                for target in manager.started[2].context.selection.targets
            },
        )
        self.assertEqual(started, [(1, "gau"), (2, "httpx"), (3, "tlsx")])
        self.assertEqual(result.target_count, 1)

    async def test_recursive_directory_chain_runs_ffuf_once_per_url(self) -> None:
        manager = FakeExecutionManager(self.project_path)
        module = WebEnumerationModule(manager, load_default_catalog())  # type: ignore[arg-type]
        wordlist = self.project_path / "directories.txt"
        wordlist.write_text("admin\n", encoding="utf-8")

        await module.run(
            self.store,
            self._rule_id("*.google.com"),
            "directories",
            project_id="P-0001",
            project_name="Google",
            project_path=self.project_path,
            scope_rules=self.scope.rules,
            scope_enforced=False,
            wordlist=str(wordlist),
            recursion_depth=3,
        )

        self.assertEqual(
            [request.module.bin for request in manager.started], ["httpx", "ffuf"]
        )
        self.assertEqual(
            tuple(target.normalized for target in manager.started[1].context.selection.targets),
            ("https://mail.google.com/admin",),
        )
        self.assertEqual(dict(manager.started[1].options), {
            "wordlist": str(wordlist), "recursion_depth": "3",
        })

    async def test_archive_chain_enables_subdomains_only_for_wildcard_scope(self) -> None:
        manager = FakeExecutionManager(self.project_path)
        module = WebEnumerationModule(manager, load_default_catalog())  # type: ignore[arg-type]

        await module.run(
            self.store,
            self._rule_id("*.google.com"),
            "deep",
            project_id="P-0001",
            project_name="Google",
            project_path=self.project_path,
            scope_rules=self.scope.rules,
            scope_enforced=False,
        )

        self.assertIn("--subs", manager.started[0].profile.arguments)

    async def test_directory_chain_rejects_missing_wordlist_before_starting(self) -> None:
        manager = FakeExecutionManager(self.project_path)
        module = WebEnumerationModule(manager, load_default_catalog())  # type: ignore[arg-type]

        with self.assertRaisesRegex(ScopeValidationError, "wordlist does not exist"):
            await module.run(
                self.store,
                self._rule_id("*.google.com"),
                "directories",
                project_id="P-0001",
                project_name="Google",
                project_path=self.project_path,
                scope_rules=self.scope.rules,
                scope_enforced=False,
                wordlist=str(self.project_path / "missing.txt"),
            )

        self.assertEqual(manager.started, [])

    async def test_preflight_fails_before_any_enumeration_run(self) -> None:
        manager = FakeExecutionManager(self.project_path, unavailable="tlsx")
        module = WebEnumerationModule(manager, load_default_catalog())  # type: ignore[arg-type]

        with self.assertRaisesRegex(ExecutionError, "tlsx: not installed"):
            await module.run(
                self.store,
                self._rule_id("google.com"),
                "quick",
                project_id="P-0001",
                project_name="Google",
                project_path=self.project_path,
                scope_rules=self.scope.rules,
                scope_enforced=False,
            )

        self.assertEqual(manager.started, [])


if __name__ == "__main__":
    unittest.main()
