"""Focused regressions for per-page dashboard event handling."""

from __future__ import annotations

from pathlib import Path
import re
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from dashboard_ui import ASSET_PAGE_SIZE, RECORD_PAGE_SIZE, DashboardUI
from nullbound_execution import ExecutionManager, RunStore
from nullbound_scope import ScopeRule, ScopeStatus, ScopeValidationError, Target, TargetKind


class _SafeClient:
    """Minimal stand-in for NiceGUI Client.safe_invoke."""

    def safe_invoke(self, callback) -> None:
        try:
            callback()
        except Exception:
            # NiceGUI reports page callback failures without propagating them
            # into the subprocess event publisher.
            pass


class LiveRunConsoleTests(TestCase):
    def test_live_output_lines_are_batched_into_one_browser_update(self) -> None:
        dashboard = DashboardUI.__new__(DashboardUI)
        dashboard._pending_run_output = []
        dashboard.run_output = SimpleNamespace(id=10)
        dashboard.run_output_content = SimpleNamespace(id=11)

        with patch("dashboard_ui.ui.run_javascript") as run_javascript:
            dashboard.push_run_output("first")
            dashboard.push_run_output("second")
            run_javascript.assert_not_called()
            dashboard.flush_run_output()

        run_javascript.assert_called_once()
        script = run_javascript.call_args.args[0]
        self.assertIn("first\\nsecond\\n", script)
        self.assertEqual(dashboard._pending_run_output, [])

    def test_page_callback_failure_does_not_detach_live_run_listener(self) -> None:
        dashboard = DashboardUI.__new__(DashboardUI)
        dashboard.active_run_id = "RUN-LIVE"
        dashboard._client = _SafeClient()
        received: list[str] = []

        def apply_event(event) -> None:
            received.append(event.text)
            if event.text == "first line":
                raise RuntimeError("simulated missing UI context")

        dashboard._apply_run_event = apply_event
        with TemporaryDirectory() as root:
            manager = ExecutionManager(store=RunStore(Path(root)))
            manager.subscribe("RUN-LIVE", dashboard.handle_run_event)

            manager._emit(SimpleNamespace(
                run=SimpleNamespace(id="RUN-LIVE"), text="first line",
            ))
            manager._emit(SimpleNamespace(
                run=SimpleNamespace(id="RUN-LIVE"), text="second line",
            ))

        self.assertEqual(received, ["first line", "second line"])

    def test_global_listener_observes_multiple_runs_and_can_unsubscribe(self) -> None:
        received: list[str] = []
        with TemporaryDirectory() as root:
            manager = ExecutionManager(store=RunStore(Path(root)))
            unsubscribe = manager.subscribe_all(lambda event: received.append(event.run.id))

            manager._emit(SimpleNamespace(run=SimpleNamespace(id="RUN-ONE")))
            manager._emit(SimpleNamespace(run=SimpleNamespace(id="RUN-TWO")))
            unsubscribe()
            manager._emit(SimpleNamespace(run=SimpleNamespace(id="RUN-THREE")))

        self.assertEqual(received, ["RUN-ONE", "RUN-TWO"])


class AssetWorkspaceLogicTests(TestCase):
    def test_asset_page_is_bounded_and_clamps_an_out_of_range_index(self) -> None:
        records = tuple(
            {"id": f"AS-{index:04d}"}
            for index in range(ASSET_PAGE_SIZE * 2 + 3)
        )

        page, index, count, start = DashboardUI._asset_page(records, 1)
        self.assertEqual(len(page), ASSET_PAGE_SIZE)
        self.assertEqual(page[0]["id"], f"AS-{ASSET_PAGE_SIZE:04d}")
        self.assertEqual((index, count, start), (1, 3, ASSET_PAGE_SIZE))

        page, index, count, start = DashboardUI._asset_page(records, 99)
        self.assertEqual(len(page), 3)
        self.assertEqual(page[0]["id"], f"AS-{ASSET_PAGE_SIZE * 2:04d}")
        self.assertEqual((index, count, start), (2, 3, ASSET_PAGE_SIZE * 2))

    def test_generic_record_page_is_bounded(self) -> None:
        records = tuple(
            {"id": f"EV-{index:04d}"}
            for index in range(RECORD_PAGE_SIZE * 2 + 5)
        )

        page, index, count, start = DashboardUI._record_page(records, 2)

        self.assertEqual(len(page), 5)
        self.assertEqual(page[0]["id"], f"EV-{RECORD_PAGE_SIZE * 2:04d}")
        self.assertEqual((index, count, start), (2, 3, RECORD_PAGE_SIZE * 2))

    def test_selecting_asset_updates_rows_without_rebuilding_results(self) -> None:
        class Row:
            def __init__(self) -> None:
                self.changes: list[dict[str, str]] = []

            def classes(self, **change):
                self.changes.append(change)

        dashboard = DashboardUI.__new__(DashboardUI)
        previous = Row()
        selected = Row()
        dashboard.selected_asset_id = "AS-OLD"
        dashboard._row_elements = {
            "assets": {"AS-OLD": previous, "AS-NEW": selected}
        }
        dashboard.inspector_collapsed = False
        dashboard.refresh_asset_results = lambda: self.fail("results were rebuilt")
        rendered: list[str] = []
        dashboard.render_inspector = lambda: rendered.append("inspector")

        dashboard.select_asset_record("AS-NEW")

        self.assertEqual(previous.changes, [{"remove": "selected"}])
        self.assertEqual(selected.changes, [{"add": "selected"}])
        self.assertEqual(rendered, ["inspector"])

    def test_global_asset_search_and_tri_state_scope_filter_are_independent(self) -> None:
        dashboard = DashboardUI.__new__(DashboardUI)
        dashboard.search_query = "portal"
        dashboard.record_scope_filters = {"assets": False}
        dashboard.asset_records = lambda: (
            {"id": "AS-1", "name": "portal.example.com", "scope": "ALLOWED"},
            {"id": "AS-2", "name": "other.example.com", "scope": "REVIEW"},
        )

        self.assertEqual(
            [record["id"] for record in dashboard.filtered_asset_records()], ["AS-1"]
        )
        dashboard.search_query = ""
        dashboard.record_scope_filters["assets"] = True
        self.assertEqual(
            [record["id"] for record in dashboard.filtered_asset_records()], ["AS-1"]
        )
        dashboard.record_scope_filters["assets"] = None
        self.assertEqual(
            [record["id"] for record in dashboard.filtered_asset_records()], ["AS-2"]
        )

    def test_run_scope_requires_every_target_to_be_allowed(self) -> None:
        allowed = ScopeRule(
            id="SC-0001", target=Target(TargetKind.DOMAIN, "example.com"),
            scope_status=ScopeStatus.ALLOWED,
        )
        denied = ScopeRule(
            id="SC-0002", target=Target(TargetKind.DOMAIN, "blocked.example.com"),
            scope_status=ScopeStatus.DENIED,
        )
        run = SimpleNamespace(targets=({"kind": "domain", "value": "example.com"},))
        mixed = SimpleNamespace(targets=(
            {"kind": "domain", "value": "example.com"},
            {"kind": "domain", "value": "unknown.example.net"},
        ))
        blocked = SimpleNamespace(
            targets=({"kind": "domain", "value": "blocked.example.com"},)
        )

        self.assertEqual(DashboardUI._run_scope_label(run, (allowed, denied)), "ALLOWED")
        self.assertEqual(DashboardUI._run_scope_label(mixed, (allowed, denied)), "REVIEW")
        self.assertEqual(DashboardUI._run_scope_label(blocked, (allowed, denied)), "DENIED")

    def test_scope_filter_state_updates_its_label_and_active_results(self) -> None:
        dashboard = DashboardUI.__new__(DashboardUI)
        dashboard.record_scope_filters = {"assets": False}
        labels: list[str] = []
        refreshes: list[str] = []
        dashboard.assets_scope_filter = SimpleNamespace(set_text=labels.append)
        dashboard.refresh_asset_results = lambda: refreshes.append("assets")
        dashboard.render_inspector = lambda: refreshes.append("inspector")

        for state in (True, None, False):
            dashboard.set_record_scope_filter("assets", SimpleNamespace(value=state))

        self.assertEqual(
            labels, ["IN SCOPE ONLY", "OUT OF SCOPE ONLY", "ALL ITEMS"]
        )
        self.assertEqual(refreshes, ["assets", "inspector"] * 3)

    def test_run_records_follow_the_active_project(self) -> None:
        with TemporaryDirectory() as root:
            project = SimpleNamespace(id="P-0001", path=Path(root), name="Active")
            other = SimpleNamespace(id="P-0002")
            unattached = SimpleNamespace(id="RUN-NONE", project_id=None)
            active = SimpleNamespace(id="RUN-ACTIVE", project_id="P-0001")
            inactive = SimpleNamespace(id="RUN-OTHER", project_id="P-0002")
            requested_paths: list[tuple[Path, ...]] = []
            dashboard = DashboardUI.__new__(DashboardUI)
            dashboard.project_workspace = SimpleNamespace(
                active_project_id="P-0001", open_projects=[project, other],
            )
            dashboard.execution_manager = SimpleNamespace(
                list_runs=lambda paths: requested_paths.append(paths)
                or (unattached, active, inactive)
            )
            dashboard._run_scope_label = lambda _run, _rules: "ALLOWED"
            dashboard._run_record = lambda run, scope: {"id": run.id, "scope": scope}

            self.assertEqual(dashboard.run_records(), ({"id": "RUN-ACTIVE", "scope": "ALLOWED"},))
            self.assertEqual(requested_paths, [(Path(root),)])

    def test_supported_assets_convert_to_typed_scope_targets(self) -> None:
        target = DashboardUI._target_for_asset({
            "target_kind": "url", "normalized": "https://portal.example.com/",
            "type": "URL",
        })
        self.assertEqual(target.kind, TargetKind.URL)

        with self.assertRaises(ScopeValidationError):
            DashboardUI._target_for_asset({
                "target_kind": "technology", "normalized": "nginx", "type": "TECHNOLOGY",
            })

    def test_completed_indexing_refreshes_active_data_surface_once(self) -> None:
        for view, host_name, refresh_name in (
            ("assets", "assets_result_host", "refresh_asset_results"),
            ("findings", "findings_result_host", "refresh_finding_results"),
            ("evidence", "evidence_result_host", "refresh_evidence_results"),
        ):
            with self.subTest(view=view):
                dashboard = DashboardUI.__new__(DashboardUI)
                dashboard.project_workspace = SimpleNamespace(active_project_id="P-0001")
                dashboard.active_view = view
                setattr(dashboard, host_name, object())
                dashboard._client = _SafeClient()
                dashboard._last_evidence_refresh = None
                refreshes: list[str] = []
                setattr(dashboard, refresh_name, lambda: refreshes.append(view))
                dashboard.render_inspector = lambda: refreshes.append("inspector")
                event = SimpleNamespace(
                    text=None,
                    run=SimpleNamespace(
                        id="RUN-INDEXED", project_id="P-0001",
                        evidence_state="indexed",
                    ),
                )

                dashboard.handle_workspace_event(event)
                dashboard.handle_workspace_event(event)

                self.assertEqual(refreshes, [view, "inspector"])

    def test_run_state_event_refreshes_only_the_runs_results(self) -> None:
        dashboard = DashboardUI.__new__(DashboardUI)
        dashboard.project_workspace = SimpleNamespace(active_project_id="P-0001")
        dashboard.active_view = "runs"
        dashboard.runs_result_host = object()
        dashboard._client = _SafeClient()
        dashboard._last_evidence_refresh = None
        refreshes: list[str] = []
        dashboard.refresh_run_results = lambda: refreshes.append("runs")
        dashboard.render_inspector = lambda: refreshes.append("inspector")
        dashboard.render_workspace = lambda: refreshes.append("workspace")
        event = SimpleNamespace(
            text=None,
            run=SimpleNamespace(
                id="RUN-COMPLETED", project_id="P-0001", evidence_state="pending",
                state=SimpleNamespace(value="completed"),
            ),
        )

        dashboard.handle_workspace_event(event)

        self.assertEqual(refreshes, ["runs", "inspector"])


class ConsoleTailTests(TestCase):
    def test_log_tail_is_limited_by_lines(self) -> None:
        with TemporaryDirectory() as root:
            path = Path(root) / "console.log"
            path.write_text(
                "".join(f"line {index}\n" for index in range(20)), encoding="utf-8"
            )

            lines, truncated = DashboardUI._tail_text_lines(
                path, max_lines=5, max_bytes=10_000
            )

        self.assertTrue(truncated)
        self.assertEqual(lines, tuple(f"line {index}" for index in range(15, 20)))

    def test_small_log_tail_is_returned_in_full(self) -> None:
        with TemporaryDirectory() as root:
            path = Path(root) / "console.log"
            path.write_text("first\nsecond\n", encoding="utf-8")

            lines, truncated = DashboardUI._tail_text_lines(
                path, max_lines=5, max_bytes=10_000
            )

        self.assertFalse(truncated)
        self.assertEqual(lines, ("first", "second"))


class LayoutStylesTests(TestCase):
    def test_workspace_scrollbar_is_overflow_driven_and_theme_matched(self) -> None:
        stylesheet = (Path(__file__).parents[1] / "styles.css").read_text(encoding="utf-8")
        workspace = re.search(
            r"^\.workspace\s*\{(?P<body>.*?)\n\}", stylesheet,
            re.DOTALL | re.MULTILINE,
        )

        self.assertIsNotNone(workspace)
        self.assertIn("overflow: auto", workspace.group("body"))
        self.assertNotIn("overflow-y: scroll", workspace.group("body"))
        self.assertIn("scrollbar-color: var(--interactive) var(--line)", workspace.group("body"))
        self.assertIn(
            ".workspace::-webkit-scrollbar-thumb { border-radius: 0; background: var(--interactive); }",
            stylesheet,
        )

    def test_right_inspector_scrolls_inside_a_viewport_bounded_shell(self) -> None:
        stylesheet = (Path(__file__).parents[1] / "styles.css").read_text(encoding="utf-8")
        shell = re.search(
            r"^\.app-shell\s*\{(?P<body>.*?)\n\}", stylesheet, re.DOTALL | re.MULTILINE
        )
        inspector = re.search(
            r"^\.inspector\s*\{(?P<body>.*?)\n\}", stylesheet,
            re.DOTALL | re.MULTILINE,
        )

        self.assertIsNotNone(shell)
        self.assertIn("height: 100dvh", shell.group("body"))
        self.assertIn("overflow: hidden", shell.group("body"))
        self.assertIn("grid-template-rows: 86px minmax(0, 1fr) 158px", shell.group("body"))
        self.assertIsNotNone(inspector)
        self.assertIn("min-height: 0", inspector.group("body"))
        self.assertIn("overflow: auto", inspector.group("body"))

    def test_artifact_viewer_uses_full_height_scroll_surface_and_wrap_mode(self) -> None:
        stylesheet = (Path(__file__).parents[1] / "styles.css").read_text(encoding="utf-8")
        modal = re.search(
            r"^\.project-modal\.artifact-modal\s*\{(?P<body>.*?)\n\}",
            stylesheet, re.DOTALL | re.MULTILINE,
        )
        preview = re.search(
            r"^\.artifact-preview\s*\{(?P<body>.*?)\n\}",
            stylesheet, re.DOTALL | re.MULTILINE,
        )
        wrapped = re.search(
            r"^\.artifact-preview\.wrap-text \.artifact-preview-content\s*\{"
            r"(?P<body>.*?)\n\}",
            stylesheet, re.DOTALL | re.MULTILINE,
        )

        self.assertIsNotNone(modal)
        self.assertIn("grid-template-rows: 70px 38px minmax(0, 1fr)", modal.group("body"))
        self.assertIsNotNone(preview)
        self.assertIn("min-height: 0", preview.group("body"))
        self.assertIn("height: 100%", preview.group("body"))
        self.assertIn("max-height: 100%", preview.group("body"))
        self.assertIn("overflow: auto !important", preview.group("body"))
        self.assertIsNotNone(wrapped)
        self.assertIn("white-space: pre-wrap", wrapped.group("body"))


if __name__ == "__main__":
    import unittest
    unittest.main()
