"""Tests for safe command construction and persistent execution lifecycle."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from blackwall_execution import (
    AdapterRegistry,
    CommandSpec,
    ExecutionManager,
    RunRequest,
    RunState,
    RunStore,
    ToolAdapter,
    HttpxAdapter,
    expand_argument_template,
)
from blackwall_scope import ExecutionContext, Target, TargetSelection
from recon_modules import ModuleDefinition, ScanProfile, load_default_catalog


class PythonTestAdapter(ToolAdapter):
    key = "python-test"

    def resolve_executable(self, request: RunRequest) -> str:
        return sys.executable

    async def version(self, executable: str) -> str | None:
        return "test-python"

    def build_command(self, request: RunRequest, run_path: Path, executable: str) -> CommandSpec:
        return CommandSpec(executable, request.profile.arguments)


def request_for(script: str) -> RunRequest:
    module = ModuleDefinition.from_mapping({
        "id": "99", "eyebrow": "test", "description": "Test process",
        "bin": "python", "path": sys.executable, "adapter": "python-test",
        "profiles": [{"name": "Test", "arguments": ["-c", script]}],
    })
    return RunRequest(
        module=module,
        profile=module.default_profile,
        context=ExecutionContext(
            selection=TargetSelection.direct((Target.parse("example.com"),))
        ),
    )


class AdapterTests(unittest.TestCase):
    def test_httpx_catalog_has_an_executable_argv_profile(self) -> None:
        module = load_default_catalog().get("04")
        self.assertEqual(module.adapter, "httpx")
        for profile in module.profiles:
            self.assertIn("{target}", profile.arguments)
            self.assertEqual(profile.output_format, "jsonl")

    def test_target_text_remains_one_argv_element(self) -> None:
        hostile = "example.com; echo should-not-run"
        arguments = expand_argument_template(("-u", "{target}", "-json"), (hostile,))
        self.assertEqual(arguments, ("-u", hostile, "-json"))

    def test_httpx_writes_jsonl_into_the_run_artifact_directory(self) -> None:
        module = load_default_catalog().get("04")
        request = RunRequest(
            module=module,
            profile=module.default_profile,
            context=ExecutionContext(
                selection=TargetSelection.direct((Target.parse("https://example.com"),))
            ),
        )
        run_path = Path("portable-run")

        command = HttpxAdapter().build_command(request, run_path, "httpx")

        self.assertEqual(command.argv[:3], ("httpx", "-u", "https://example.com/"))
        self.assertEqual(command.arguments[-2:], ("-o", str(run_path / "artifacts" / "httpx.jsonl")))


class ExecutionManagerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addAsyncCleanup(self._cleanup)
        self.store = RunStore(Path(self.temporary_directory.name) / "runs")
        self.manager = ExecutionManager(
            store=self.store,
            adapters=AdapterRegistry((PythonTestAdapter(),)),
            max_concurrent=1,
        )

    async def _cleanup(self) -> None:
        self.temporary_directory.cleanup()

    async def test_run_streams_and_persists_output_manifest_and_artifact(self) -> None:
        script = (
            "from pathlib import Path; import sys; "
            "print('hello stdout', flush=True); "
            "print('hello stderr', file=sys.stderr, flush=True); "
            "Path('artifacts/result.jsonl').write_text('{\\\"ok\\\": true}\\n')"
        )
        run = await self.manager.start(request_for(script))
        events = []
        self.manager.subscribe(run.id, events.append)

        finished = await self.manager.wait(run.id)

        self.assertEqual(finished.state, RunState.COMPLETED)
        self.assertEqual(finished.exit_code, 0)
        self.assertEqual(finished.module_version, "test-python")
        self.assertIn("hello stdout", (finished.run_path / "stdout.log").read_text())
        self.assertIn("hello stderr", (finished.run_path / "stderr.log").read_text())
        self.assertEqual(finished.artifacts[0].path, "artifacts/result.jsonl")
        self.assertEqual(len(finished.artifacts[0].sha256), 64)
        self.assertTrue(any(event.text == "hello stdout" for event in events))
        self.assertEqual(self.store.load(finished.run_path).state, RunState.COMPLETED)

    async def test_active_process_can_be_cancelled(self) -> None:
        run = await self.manager.start(request_for("import time; print('started', flush=True); time.sleep(30)"))
        for _ in range(100):
            if self.manager.get(run.id).state is RunState.RUNNING:
                break
            await asyncio.sleep(0.01)

        self.assertTrue(await self.manager.cancel(run.id))
        finished = await asyncio.wait_for(self.manager.wait(run.id), timeout=5)
        self.assertEqual(finished.state, RunState.CANCELLED)

    async def test_direct_run_can_be_attached_to_a_project_automatically(self) -> None:
        request = request_for("print('project run')")
        request = RunRequest(
            module=request.module,
            profile=request.profile,
            context=ExecutionContext(
                selection=request.context.selection,
                project_id="P-0042",
                project_name="Engagement",
            ),
        )
        project = Path(self.temporary_directory.name) / "project"
        project.mkdir()

        run = await self.manager.start(request, project)
        finished = await self.manager.wait(run.id)

        self.assertEqual(finished.project_id, "P-0042")
        self.assertEqual(finished.run_path.parent, project / "runs")

    async def test_stale_run_is_recovered_after_restart(self) -> None:
        run_id, run_path = self.store.reserve()
        request = request_for("print('unused')")
        queued = self.store.create(
            run_id, run_path, request,
            CommandSpec(sys.executable, ("-c", "print('unused')")), "test-python",
        )
        self.assertEqual(queued.state, RunState.QUEUED)

        recovered = self.manager.recover_incomplete()

        self.assertEqual(recovered[0].state, RunState.FAILED)
        self.assertIn("stopped", recovered[0].error)


if __name__ == "__main__":
    unittest.main()
