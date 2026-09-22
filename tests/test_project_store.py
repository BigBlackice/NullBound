"""Tests for portable Blackwall project storage."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from blackwall_projects import (
    PROJECT_KIND,
    PROJECT_SCHEMA_VERSION,
    ProjectStore,
    ProjectValidationError,
    ProjectWorkspace,
    default_projects_root,
)


class ProjectStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.temporary_root = Path(self.temporary_directory.name)
        self.store = ProjectStore(self.temporary_root / "portable" / "projects")

    def test_default_root_is_below_user_home(self) -> None:
        fake_home = self.temporary_root / "users" / "operator"
        self.assertEqual(
            default_projects_root(fake_home),
            fake_home / ".blackwall" / "projects",
        )

    def test_create_project_writes_portable_versioned_layout(self) -> None:
        project = self.store.create_project("Nightfall / ACME")

        self.assertEqual(project.id, "P-0001")
        self.assertEqual(project.name, "Nightfall / ACME")
        self.assertTrue(project.runs_path.is_dir())
        payload = json.loads(project.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["kind"], PROJECT_KIND)
        self.assertEqual(payload["schema_version"], PROJECT_SCHEMA_VERSION)
        self.assertNotIn("path", payload)

    def test_projects_can_be_opened_by_id_or_managed_path(self) -> None:
        first = self.store.create_project("First")
        second = self.store.create_project("Second")

        self.assertEqual(self.store.open_project(first.id), first)
        self.assertEqual(self.store.open_project(second.path), second)
        self.assertEqual(self.store.list_projects(), (first, second))

    def test_project_can_be_opened_outside_default_store(self) -> None:
        external_store = ProjectStore(self.temporary_root / "engagements")
        external = external_store.create_project("External")
        renamed_directory = external.path.with_name("client-alpha")
        external.path.rename(renamed_directory)

        opened = self.store.open_project(renamed_directory)

        self.assertEqual(opened.id, external.id)
        self.assertEqual(opened.path, renamed_directory.resolve())

    def test_unsupported_schema_is_rejected(self) -> None:
        project = self.store.create_project("Schema test")
        payload = json.loads(project.manifest_path.read_text(encoding="utf-8"))
        payload["schema_version"] = 999
        project.manifest_path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(ProjectValidationError, "unsupported project schema"):
            self.store.open_project(project.id)

    def test_missing_runs_directory_is_restored_when_opened(self) -> None:
        project = self.store.create_project("Incomplete")
        project.runs_path.rmdir()

        reopened = self.store.open_project(project.id)

        self.assertTrue(reopened.runs_path.is_dir())

    def test_invalid_names_are_rejected_before_creating_a_directory(self) -> None:
        for invalid_name in ("", "   ", "bad\nname"):
            with self.subTest(invalid_name=invalid_name):
                with self.assertRaises(ProjectValidationError):
                    self.store.create_project(invalid_name)
        self.assertEqual(self.store.list_projects(), ())

    def test_workspace_opens_selects_and_closes_projects(self) -> None:
        first = self.store.create_project("First")
        second = self.store.create_project("Second")
        workspace = ProjectWorkspace(self.store)

        self.assertEqual(workspace.open_projects, [])
        workspace.open(first.id)
        workspace.open(second.id)
        workspace.select(first.id)
        workspace.close(first.id)
        self.assertEqual(workspace.active_project_id, second.id)
        self.assertEqual(workspace.open_projects, [second])

    def test_workspace_reopens_a_closed_project(self) -> None:
        project = self.store.create_project("Reopen")
        workspace = ProjectWorkspace(self.store)
        workspace.open(project.id)
        workspace.close(project.id)

        reopened = workspace.open(project.id)

        self.assertEqual(reopened, project)
        self.assertEqual(workspace.open_projects, [project])
        self.assertEqual(workspace.active_project_id, project.id)

    def test_workspace_can_create_in_an_arbitrary_parent_directory(self) -> None:
        workspace = ProjectWorkspace(self.store)
        alternate_parent = self.temporary_root / "client supplied location"

        project = workspace.create("Portable", alternate_parent)

        self.assertEqual(project.path.parent, alternate_parent.resolve())
        self.assertEqual(workspace.open_projects, [project])


if __name__ == "__main__":
    unittest.main()
