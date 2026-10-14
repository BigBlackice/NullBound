"""Tests for safe command construction and persistent execution lifecycle."""

from __future__ import annotations

import asyncio
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from nullbound_evidence import EvidenceStore, ProjectRunIngestor
from nullbound_execution import (
    AdapterRegistry,
    CommandSpec,
    CompanionProcessSpec,
    DEFAULT_FFUF_WORDLIST,
    DeclarativeAdapter,
    ExecutionError,
    ExecutionManager,
    FfufAdapter,
    RunRequest,
    RunState,
    RunStore,
    ToolAdapter,
    HttpxAdapter,
    ProxyConfig,
    discover_ffuf_wordlists,
    expand_argument_template,
)
from nullbound_scope import ExecutionContext, Target, TargetSelection
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
    def test_seclists_discovery_prefers_raft_medium_and_includes_nested_lists(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            preferred = root / DEFAULT_FFUF_WORDLIST
            preferred.write_text("admin\n", encoding="utf-8")
            nested = root / "CMS" / "wordpress.txt"
            nested.parent.mkdir()
            nested.write_text("wp-admin\n", encoding="utf-8")
            (root / "README.md").write_text("docs", encoding="utf-8")

            wordlists = discover_ffuf_wordlists(root)

        self.assertEqual(wordlists, (preferred, nested))

    def test_ffuf_wordlist_discovery_can_include_any_project_file(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            extensionless = root / "passwords"
            extensionless.write_text("secret\n", encoding="utf-8")
            binary_named = root / "content.lst"
            binary_named.write_text("admin\n", encoding="utf-8")

            wordlists = discover_ffuf_wordlists(root, all_files=True)

        self.assertEqual(wordlists, (binary_named, extensionless))

    def test_httpx_catalog_has_an_executable_argv_profile(self) -> None:
        module = load_default_catalog().get("04")
        self.assertEqual(module.adapter, "httpx")
        self.assertEqual(module.config_fields[0].id, "resolver")
        self.assertEqual(module.config_fields[0].argument, "-r")
        for profile in module.profiles:
            self.assertIn("{target}", profile.arguments)
            self.assertEqual(profile.output_format, "jsonl")

    def test_target_text_remains_one_argv_element(self) -> None:
        hostile = "example.com; echo should-not-run"
        arguments = expand_argument_template(("-u", "{target}", "-json"), (hostile,))
        self.assertEqual(arguments, ("-u", hostile, "-json"))

    def test_positional_and_file_target_templates_preserve_boundaries(self) -> None:
        targets = ("one.example", "two.example")
        positional = expand_argument_template(("-sT", "{targets}"), targets)
        from_file = expand_argument_template(
            ("-l", "{target_file}", "-a"), targets, target_file="inputs/targets.txt"
        )
        self.assertEqual(positional, ("-sT", *targets))
        self.assertEqual(from_file, ("-l", "inputs/targets.txt", "-a"))

    def test_every_builtin_module_builds_a_safe_artifact_command(self) -> None:
        catalog = load_default_catalog()
        target_values = {
            "01": "example.com", "02": "api.example.com", "03": "192.0.2.10",
            "04": "https://example.com", "05": "example.com", "06": "example.com",
            "07": "https://example.com",
            "08": "https://example.com", "09": "https://example.com/?id=1",
            "10": "https://example.com/login",
        }
        artifact_flags = {
            "01": "-o", "02": "-o", "03": "-oX",
            "04": "-o", "05": "--o", "06": "-o", "07": "-o",
            "08": "-jle", "09": "--output-dir", "10": "--artifact",
        }
        registry = AdapterRegistry()

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            sqlmap = root / "sqlmap.py"
            brutepyweb = root / "webbruterv1.py"
            sqlmap.write_text("print('sqlmap')\n", encoding="utf-8")
            brutepyweb.write_text("print('brutepyweb')\n", encoding="utf-8")
            for module in catalog:
                for profile in module.profiles:
                    with self.subTest(module=module.bin, profile=profile.name):
                        if module.id == "07":
                            options = (("wordlist", str(root / "words.txt")),)
                        elif module.id == "10":
                            options = (("password_file", str(root / "words.txt")),)
                        else:
                            options = ()
                        if module.id in {"09", "10"}:
                            payload = module.to_mapping()
                            payload["path"] = str(sqlmap if module.id == "09" else brutepyweb)
                            module = ModuleDefinition.from_mapping(payload)
                        (root / "words.txt").write_text("admin\n", encoding="utf-8")
                        request = RunRequest(
                            module=module,
                            profile=profile,
                            context=ExecutionContext(
                                selection=TargetSelection.direct((Target.parse(target_values[module.id]),))
                            ),
                            options=options,
                        )
                        run_path = root / module.bin
                        command = registry.get(module.adapter).build_command(
                            request, run_path, module.bin
                        )
                        self.assertEqual(command.executable, module.bin)
                        self.assertIn(artifact_flags[module.id], command.arguments)
                        self.assertNotIn(";", command.arguments)
                        self.assertIn(command.output_format, {"json", "jsonl", "xml", "text"})

            dns_targets = root / "dnsx" / "inputs" / "targets.txt"
            self.assertEqual(dns_targets.read_text(encoding="utf-8"), "api.example.com\n")

    def test_projectdiscovery_version_parser_accepts_current_installed_format(self) -> None:
        adapter = AdapterRegistry().get("subfinder")
        for line, expected in (
            ("[INF] Current Version: v2.16.0", "v2.16.0"),
            ("[INF] Current version: 1.3.1", "1.3.1"),
            ("subfinder version v2.16.0", "v2.16.0"),
        ):
            with self.subTest(line=line):
                self.assertEqual(adapter.parse_version([line]), expected)

    def test_nuclei_version_parser_rejects_an_unrelated_executable(self) -> None:
        adapter = AdapterRegistry().get("nuclei")
        self.assertEqual(
            adapter.parse_version(["[INF] Current nuclei version: v3.4.10 (latest)"]),
            "v3.4.10",
        )
        self.assertIsNone(adapter.parse_version(["unrelated tool 1.0"]))

    def test_subfinder_writes_source_attributed_jsonl_without_private_state(self) -> None:
        module = load_default_catalog().get("01")
        request = RunRequest(
            module=module,
            profile=module.default_profile,
            context=ExecutionContext(
                selection=TargetSelection.direct((Target.parse("example.com"),))
            ),
        )
        with TemporaryDirectory() as directory:
            run_path = Path(directory)
            command = AdapterRegistry().get("subfinder").build_command(
                request, run_path, "subfinder"
            )

            self.assertEqual(command.arguments[:2], (
                "-dL", str(run_path / "inputs" / "targets.txt")
            ))
            self.assertIn("-json", command.arguments)
            self.assertIn("-collect-sources", command.arguments)
            self.assertIn("-silent", command.arguments)
            self.assertEqual(
                command.arguments[-2:],
                ("-o", str(run_path / "artifacts" / "subfinder.jsonl")),
            )
            self.assertEqual(command.output_format, "jsonl")
            self.assertIsNone(command.companion)
            self.assertEqual(command.environment, ())

    def test_catalog_targets_are_placeholders_not_submitted_values(self) -> None:
        for module in load_default_catalog():
            self.assertTrue(module.target_placeholder)
            self.assertNotIn("target_example", module.to_mapping())
            for profile in module.profiles:
                self.assertTrue(profile.arguments)

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
        self.assertNotIn("-silent", command.arguments)
        self.assertIn("-no-color", command.arguments)
        self.assertEqual(command.arguments[-2:], ("-o", str(run_path / "artifacts" / "httpx.jsonl")))

    def test_httpx_optional_resolver_is_passed_as_safe_argv_elements(self) -> None:
        module = load_default_catalog().get("04")
        request = RunRequest(
            module=module,
            profile=module.default_profile,
            context=ExecutionContext(
                selection=TargetSelection.direct((Target.parse("https://example.com"),))
            ),
            options=(("resolver", "udp:10.64.0.1:53"),),
        )

        command = HttpxAdapter().build_command(request, Path("run"), "httpx")

        resolver_index = command.arguments.index("-r")
        self.assertEqual(command.arguments[resolver_index + 1], "udp:10.64.0.1:53")

    def test_ffuf_builds_a_bounded_recursive_directory_command(self) -> None:
        module = load_default_catalog().get("07")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wordlist = root / "words.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            request = RunRequest(
                module=module,
                profile=module.profiles[1],
                context=ExecutionContext(
                    selection=TargetSelection.direct((Target.parse("https://example.com/app?x=1"),))
                ),
                options=(("wordlist", str(wordlist)), ("recursion_depth", "3")),
            )

            command = FfufAdapter().build_command(request, root / "run", "ffuf")

            self.assertIn("https://example.com/app/FUZZ", command.arguments)
            self.assertIn("-recursion", command.arguments)
            self.assertEqual(
                command.arguments[command.arguments.index("-recursion-depth") + 1], "3"
            )
            self.assertEqual(command.arguments[-5:], (
                "-noninteractive", "-of", "json", "-o",
                str(root / "run" / "artifacts" / "ffuf.json"),
            ))

    def test_preview_uses_real_artifact_command_with_placeholder_run_path(self) -> None:
        module = load_default_catalog().get("04")
        request = RunRequest(
            module=module,
            profile=module.default_profile,
            context=ExecutionContext(
                selection=TargetSelection.direct((Target.parse("https://example.com"),))
            ),
        )

        command = HttpxAdapter().preview_command(request, "httpx")

        self.assertEqual(command.executable, "httpx")
        self.assertIn(str(Path("<run>") / "artifacts" / "httpx.jsonl"), command.arguments)

    def test_proxy_routing_is_explicit_and_disabled_runs_ignore_inherited_proxy(self) -> None:
        module = load_default_catalog().get("04")
        context = ExecutionContext(
            selection=TargetSelection.direct((Target.parse("https://example.com"),))
        )
        with TemporaryDirectory() as directory:
            manager = ExecutionManager(store=RunStore(Path(directory)))
            enabled = manager.preview_command(RunRequest(
                module, module.default_profile, context,
                proxy=ProxyConfig("http", "127.0.0.1", 8080),
            ), "httpx")
            disabled = manager.preview_command(
                RunRequest(module, module.default_profile, context), "httpx"
            )

        self.assertEqual(enabled.arguments[-2:], ("-proxy", "http://127.0.0.1:8080"))
        self.assertIn(("HTTPS_PROXY", "http://127.0.0.1:8080"), enabled.environment)
        self.assertIn(("NO_PROXY", "*"), disabled.environment)
        self.assertIn(("HTTPS_PROXY", ""), disabled.environment)

    def test_proxy_blocks_tools_that_cannot_honor_it(self) -> None:
        module = load_default_catalog().get("02")
        request = RunRequest(
            module, module.default_profile,
            ExecutionContext(selection=TargetSelection.direct((Target.parse("example.com"),))),
            proxy=ProxyConfig("http", "127.0.0.1", 8080),
        )
        with TemporaryDirectory() as directory:
            manager = ExecutionManager(store=RunStore(Path(directory)))
            with self.assertRaisesRegex(ExecutionError, "cannot honor"):
                manager.preview_command(request, "dnsx")

    def test_run_manifest_records_the_enforced_proxy(self) -> None:
        module = load_default_catalog().get("04")
        request = RunRequest(
            module, module.default_profile,
            ExecutionContext(selection=TargetSelection.direct((Target.parse("https://example.com"),))),
            proxy=ProxyConfig("http", "127.0.0.1", 8080),
        )
        with TemporaryDirectory() as directory:
            store = RunStore(Path(directory))
            run_id, run_path = store.reserve()
            manifest = store.create(
                run_id, run_path, request, CommandSpec("httpx", ("-u", "https://example.com/")),
                "test",
            )
            loaded = store.load(run_path)

        self.assertEqual(manifest.proxy_url, "http://127.0.0.1:8080")
        self.assertEqual(loaded.proxy_url, manifest.proxy_url)

    def test_configured_executable_path_must_be_runnable(self) -> None:
        with TemporaryDirectory() as directory:
            executable = Path(directory) / "probe"
            executable.write_text("test", encoding="utf-8")
            original = request_for("print('unused')")
            module = ModuleDefinition.from_mapping({
                **original.module.to_mapping(),
                "path": str(executable),
                "adapter": "declarative",
                "profiles": [{"name": "Default", "arguments": ["{targets}"]}],
            })
            request = RunRequest(module, module.default_profile, original.context)

            with patch("nullbound_execution.adapters.os.access", return_value=False):
                with self.assertRaisesRegex(ExecutionError, "not runnable"):
                    DeclarativeAdapter().resolve_executable(request)

    def test_httpx_version_parser_skips_the_ascii_banner(self) -> None:
        version = HttpxAdapter().parse_version([
            "    __    __  __       _  __",
            "[INF] Current httpx version v1.12.0 (latest)",
        ])
        self.assertEqual(version, "v1.12.0")

    def test_amass_is_not_registered_as_an_active_adapter(self) -> None:
        with self.assertRaisesRegex(ExecutionError, "unknown module adapter"):
            AdapterRegistry().get("amass")

    def test_setup_scripts_bootstrap_external_tools_and_use_bundled_brutepyweb(self) -> None:
        setup_script = (
            Path(__file__).parents[1] / "scripts" / "setup-tools.ps1"
        ).read_text(encoding="utf-8")
        linux_setup = (
            Path(__file__).parents[1] / "scripts" / "setup-tools.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("projectdiscovery/subfinder", setup_script)
        self.assertIn("ffuf/ffuf", setup_script)
        self.assertIn("projectdiscovery/nuclei", setup_script)
        self.assertIn("recon_modules\\brutepyweb\\webbruterv1.py", setup_script)
        self.assertNotIn("BigBlackice/brutepyweb", setup_script)
        self.assertIn("sqlmapproject/sqlmap", setup_script)
        self.assertIn("github.com/ffuf/ffuf/v2@latest", linux_setup)
        self.assertIn("projectdiscovery/nuclei", linux_setup)
        self.assertIn("recon_modules/brutepyweb/webbruterv1.py", linux_setup)
        self.assertNotIn("BigBlackice/brutepyweb", linux_setup)
        self.assertNotIn("owasp-amass/amass", setup_script)

    def test_brutepyweb_baseline_is_tracked_in_the_module_tree(self) -> None:
        module = load_default_catalog().get("10")
        script = Path(__file__).parents[1] / module.path

        self.assertEqual(module.path, "recon_modules/brutepyweb/webbruterv1.py")
        self.assertTrue(script.is_file())


    def test_brutepyweb_wrapper_preserves_matches_in_output_and_artifact(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "fake_brute.py"
            artifact = root / "result.jsonl"
            wordlist = root / "passwords.txt"
            wordlist.write_text("first\nswordfish\n", encoding="utf-8")
            tool.write_text(
                "print('[+] Candidate: status=200 length=20 password=first')\n"
                "print('[+] Validated: status=302 length=12 signals=final-url,redirects password=swordfish')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                (
                    sys.executable, "scripts/brutepyweb_adapter.py",
                    "--tool", str(tool), "--artifact", str(artifact), "--identity", "alice",
                    "--", "-u", "https://example.com/login", "-p", str(wordlist),
                ),
                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
                check=True,
            )
            stored = artifact.read_text(encoding="utf-8")

        self.assertIn("password=swordfish", completed.stdout)
        self.assertIn('"password": "swordfish"', stored)
        self.assertIn('"identity": "alice"', stored)
        self.assertIn('"wordlist_name": "passwords.txt"', stored)
        self.assertIn('"wordlist_line": 2', stored)
        self.assertIn('"classification": "validated"', stored)
        self.assertIn('"classification": "candidate"', stored)
        self.assertIn('"signals": ["final-url", "redirects"]', stored)

    def test_brutepyweb_identity_is_submitted_as_the_username(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "webbruterv1.py"
            wordlist = root / "passwords.txt"
            tool.write_text("print('brutepyweb')\n", encoding="utf-8")
            wordlist.write_text("candidate\n", encoding="utf-8")
            payload = load_default_catalog().get("10").to_mapping()
            payload["path"] = str(tool)
            module = ModuleDefinition.from_mapping(payload)
            request = RunRequest(
                module, module.default_profile,
                ExecutionContext(selection=TargetSelection.direct((
                    Target.parse("https://example.com/login"),
                ))),
                options=(("password_file", str(wordlist)), ("identity", "alice")),
            )

            command = AdapterRegistry().get("brutepyweb").build_command(
                request, root / "run", sys.executable
            )

        username_index = command.arguments.index("--username")
        self.assertEqual(command.arguments[username_index + 1], "alice")


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
        combined_output = (finished.run_path / "console.log").read_text()
        self.assertIn("hello stdout", combined_output)
        self.assertIn("hello stderr", combined_output)
        self.assertEqual(finished.artifacts[0].path, "artifacts/result.jsonl")
        self.assertEqual(len(finished.artifacts[0].sha256), 64)
        self.assertTrue(any(event.text == "hello stdout" for event in events))
        self.assertEqual(self.store.load(finished.run_path).state, RunState.COMPLETED)

    async def test_long_run_emits_throttled_adapter_progress(self) -> None:
        class ProgressAdapter(PythonTestAdapter):
            key = "progress-test"

            def progress_summary(self, run_path):
                return "42 records collected"

        original = request_for("import time; time.sleep(0.2)")
        module = ModuleDefinition.from_mapping({
            **original.module.to_mapping(),
            "adapter": "progress-test",
        })
        manager = ExecutionManager(
            store=self.store,
            adapters=AdapterRegistry((ProgressAdapter(),)),
            progress_interval_seconds=0.05,
        )

        run = await manager.start(RunRequest(module, module.default_profile, original.context))
        finished = await manager.wait(run.id)
        console = (finished.run_path / "console.log").read_text(encoding="utf-8")

        self.assertEqual(finished.state, RunState.COMPLETED)
        self.assertIn("still running", console)
        self.assertIn("42 records collected", console)

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
        self.assertTrue(finished.run_path.parent.samefile(project / "runs"))

    async def test_project_run_is_post_processed_without_changing_terminal_state(self) -> None:
        processed = []

        def processor(manifest):
            processed.append(manifest.id)
            return {"assets_created": 2, "evidence_created": 2}

        manager = ExecutionManager(
            store=self.store, adapters=AdapterRegistry((PythonTestAdapter(),)),
            max_concurrent=1, post_run_processor=processor,
        )
        original = request_for("print('index me')")
        request = RunRequest(
            module=original.module, profile=original.profile,
            context=ExecutionContext(
                selection=original.context.selection,
                project_id="P-0043", project_name="Indexed",
            ),
        )
        project = Path(self.temporary_directory.name) / "indexed-project"
        project.mkdir()

        run = await manager.start(request, project)
        finished = await manager.wait(run.id)

        self.assertEqual(finished.state, RunState.COMPLETED)
        self.assertEqual(finished.evidence_state, "indexed")
        self.assertEqual(dict(finished.evidence_summary)["assets_created"], 2)
        self.assertEqual(processed, [run.id])

    async def test_post_processing_failure_is_recorded_separately_from_scan_failure(self) -> None:
        def processor(_manifest):
            raise ValueError("parser fixture failed")

        manager = ExecutionManager(
            store=self.store, adapters=AdapterRegistry((PythonTestAdapter(),)),
            max_concurrent=1, post_run_processor=processor,
        )
        original = request_for("print('scan succeeded')")
        request = RunRequest(
            module=original.module, profile=original.profile,
            context=ExecutionContext(
                selection=original.context.selection,
                project_id="P-0044", project_name="Indexed",
            ),
        )
        project = Path(self.temporary_directory.name) / "failed-index-project"
        project.mkdir()

        run = await manager.start(request, project)
        finished = await manager.wait(run.id)

        self.assertEqual(finished.state, RunState.COMPLETED)
        self.assertEqual(finished.evidence_state, "failed")
        self.assertIn("parser fixture failed", finished.evidence_error)

    async def test_scan_artifact_flows_into_project_assets_and_evidence(self) -> None:
        script = (
            "from pathlib import Path; "
            "Path('artifacts/dnsx.jsonl').write_text("
            "'{\"host\":\"api.example.com\",\"a\":[\"192.0.2.50\"]}\\n')"
        )
        module = ModuleDefinition.from_mapping({
            "id": "98", "eyebrow": "test", "description": "dnsx fixture",
            "bin": "dnsx", "path": sys.executable, "adapter": "python-test",
            "profiles": [{"name": "Test", "arguments": ["-c", script]}],
        })
        project = Path(self.temporary_directory.name) / "pipeline-project"
        project.mkdir()
        request = RunRequest(
            module=module, profile=module.default_profile,
            context=ExecutionContext(
                selection=TargetSelection.direct((Target.parse("api.example.com"),)),
                project_id="P-PIPE", project_name="Pipeline",
            ),
        )
        manager = ExecutionManager(
            store=self.store, adapters=AdapterRegistry((PythonTestAdapter(),)),
            post_run_processor=ProjectRunIngestor(),
        )

        run = await manager.start(request, project)
        finished = await manager.wait(run.id)
        assets = EvidenceStore(project).list_assets()
        evidence = EvidenceStore(project).list_evidence()

        self.assertEqual(finished.state, RunState.COMPLETED)
        self.assertEqual(finished.evidence_state, "indexed")
        self.assertEqual({asset.normalized_key for asset in assets}, {
            "api.example.com", "192.0.2.50",
        })
        self.assertEqual({item.run_id for item in evidence}, {run.id})

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

    async def test_standalone_run_can_be_adopted_by_a_project(self) -> None:
        run = await self.manager.start(request_for("print('adopt me')"))
        await self.manager.wait(run.id)
        project_path = Path(self.temporary_directory.name) / "adopted-project"
        project_path.mkdir()
        project = SimpleNamespace(id="P-0099", name="Adopted", path=project_path)

        adopted = self.manager.adopt_unattached(project)

        self.assertEqual(adopted[0].project_id, "P-0099")
        self.assertTrue(adopted[0].run_path.parent.samefile(project_path / "runs"))
        self.assertFalse((self.store.standalone_root / run.id).exists())

    async def test_standalone_runs_can_be_permanently_deleted(self) -> None:
        run = await self.manager.start(request_for("print('discard me')"))
        await self.manager.wait(run.id)

        removed = self.manager.delete_unattached()

        self.assertEqual(removed, (run.id,))
        self.assertFalse(run.run_path.exists())

    async def test_active_standalone_run_cannot_be_adopted_or_deleted(self) -> None:
        run = await self.manager.start(request_for("import time; time.sleep(30)"))
        for _ in range(100):
            if self.manager.get(run.id).state is RunState.RUNNING:
                break
            await asyncio.sleep(0.01)
        project_path = Path(self.temporary_directory.name) / "blocked-project"
        project_path.mkdir()
        project = SimpleNamespace(id="P-0100", name="Blocked", path=project_path)

        try:
            with self.assertRaisesRegex(ExecutionError, "active standalone runs"):
                self.manager.adopt_unattached(project)
            with self.assertRaisesRegex(ExecutionError, "active standalone runs"):
                self.manager.delete_unattached()
        finally:
            await self.manager.cancel(run.id)
            await asyncio.wait_for(self.manager.wait(run.id), timeout=5)

    async def test_artifact_resolution_rejects_paths_outside_artifact_directory(self) -> None:
        script = "from pathlib import Path; Path('artifacts/result.txt').write_text('safe')"
        run = await self.manager.start(request_for(script))
        finished = await self.manager.wait(run.id)
        outside = finished.run_path / "outside.txt"
        outside.write_text("unsafe", encoding="utf-8")

        resolved = self.store.resolve_artifact(finished, "artifacts/result.txt")

        self.assertEqual(resolved, (finished.run_path / "artifacts" / "result.txt").resolve())
        with self.assertRaisesRegex(ExecutionError, "escapes"):
            self.store.resolve_artifact(finished, "outside.txt")

    async def test_run_timeout_is_recorded_as_failure(self) -> None:
        request = request_for("import time; time.sleep(30)")
        request = RunRequest(
            module=request.module, profile=request.profile, context=request.context,
            timeout_seconds=1,
        )

        run = await self.manager.start(request)
        finished = await asyncio.wait_for(self.manager.wait(run.id), timeout=8)

        self.assertEqual(finished.state, RunState.FAILED)
        self.assertIn("timed out after 1 seconds", finished.error)

    async def test_companion_failure_is_streamed_and_reported_without_waiting_full_timeout(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            unused_port = probe.getsockname()[1]

        class FailedCompanionAdapter(PythonTestAdapter):
            key = "failed-companion"

            def build_command(self, request, run_path, executable):
                return CommandSpec(
                    executable,
                    ("-c", "print('main should not run')"),
                    companion=CompanionProcessSpec(
                        executable,
                        (
                            "-c",
                            "import os, sys; print(os.environ['NULLBOUND_COMPANION_TEST'], file=sys.stderr, flush=True); sys.exit(7)",
                        ),
                        "127.0.0.1",
                        unused_port,
                        ready_http_path=None,
                        label="Test engine",
                        startup_timeout_seconds=5,
                    ),
                    environment=(("NULLBOUND_COMPANION_TEST", "isolated engine startup failed"),),
                )

        original = request_for("print('unused')")
        module = ModuleDefinition.from_mapping({
            **original.module.to_mapping(),
            "adapter": "failed-companion",
        })
        request = RunRequest(module, module.default_profile, original.context)
        manager = ExecutionManager(
            store=self.store,
            adapters=AdapterRegistry((FailedCompanionAdapter(),)),
        )

        run = await manager.start(request)
        finished = await asyncio.wait_for(manager.wait(run.id), timeout=5)

        self.assertEqual(finished.state, RunState.FAILED)
        self.assertIn("Test engine exited before becoming ready", finished.error)
        self.assertIn("engine startup failed", finished.error)
        self.assertIn(
            "isolated engine startup failed",
            (finished.run_path / "console.log").read_text(encoding="utf-8"),
        )

    async def test_existing_companion_endpoint_is_not_reused(self) -> None:
        async def healthy_endpoint(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(healthy_endpoint, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        class ExistingCompanionAdapter(PythonTestAdapter):
            key = "existing-companion"

            def build_command(self, request, run_path, executable):
                return CommandSpec(
                    executable,
                    ("-c", "print('main should not run')"),
                    companion=CompanionProcessSpec(
                        executable,
                        ("-c", "import time; time.sleep(10)"),
                        "127.0.0.1",
                        port,
                        ready_http_path="/api/v1/health",
                        label="Test engine",
                    ),
                )

        original = request_for("print('unused')")
        module = ModuleDefinition.from_mapping({
            **original.module.to_mapping(),
            "adapter": "existing-companion",
        })
        manager = ExecutionManager(
            store=self.store,
            adapters=AdapterRegistry((ExistingCompanionAdapter(),)),
        )
        try:
            run = await manager.start(RunRequest(module, module.default_profile, original.context))
            finished = await manager.wait(run.id)
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(finished.state, RunState.FAILED)
        self.assertIn("already running outside this NullBound run", finished.error)
        self.assertFalse((finished.run_path / "stdout.log").exists())


if __name__ == "__main__":
    unittest.main()
