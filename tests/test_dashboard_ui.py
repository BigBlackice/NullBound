"""Focused regressions for per-page dashboard event handling."""

from __future__ import annotations

from pathlib import Path
import re
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase

from dashboard_ui import DashboardUI
from blackwall_execution import ExecutionManager, RunStore
from blackwall_scope import ScopeValidationError, TargetKind


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
    def test_asset_search_and_scope_filter_are_independent(self) -> None:
        dashboard = DashboardUI.__new__(DashboardUI)
        dashboard.search_query = ""
        dashboard.asset_search_query = "portal"
        dashboard.asset_in_scope_only = False
        dashboard.asset_records = lambda: (
            {"id": "AS-1", "name": "portal.example.com", "scope": "ALLOWED"},
            {"id": "AS-2", "name": "other.example.com", "scope": "REVIEW"},
        )

        self.assertEqual(
            [record["id"] for record in dashboard.filtered_asset_records()], ["AS-1"]
        )
        dashboard.asset_search_query = ""
        dashboard.asset_in_scope_only = True
        self.assertEqual(
            [record["id"] for record in dashboard.filtered_asset_records()], ["AS-1"]
        )

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

    def test_completed_indexing_refreshes_assets_once(self) -> None:
        dashboard = DashboardUI.__new__(DashboardUI)
        dashboard.project_workspace = SimpleNamespace(active_project_id="P-0001")
        dashboard.active_view = "assets"
        dashboard.assets_result_host = object()
        dashboard._client = _SafeClient()
        dashboard._last_evidence_refresh = None
        refreshes: list[str] = []
        dashboard.refresh_asset_results = lambda: refreshes.append("assets")
        dashboard.render_inspector = lambda: refreshes.append("inspector")
        event = SimpleNamespace(
            text=None,
            run=SimpleNamespace(
                id="RUN-INDEXED", project_id="P-0001", evidence_state="indexed",
            ),
        )

        dashboard.handle_evidence_event(event)
        dashboard.handle_evidence_event(event)

        self.assertEqual(refreshes, ["assets", "inspector"])


class LayoutStylesTests(TestCase):
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


if __name__ == "__main__":
    import unittest
    unittest.main()
