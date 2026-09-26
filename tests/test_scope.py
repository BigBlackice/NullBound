"""Tests for Blackwall's UI-independent target and scope foundation."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from blackwall_scope import (
    ExecutionContext,
    OwnershipConfidence,
    SCOPE_KIND,
    ScopeRule,
    ScopeStatus,
    ScopeStore,
    ScopeValidationError,
    Target,
    TargetKind,
    TargetSelection,
    evaluate_target,
)


class TargetTests(unittest.TestCase):
    def test_parse_and_normalize_supported_targets(self) -> None:
        cases = (
            ("EXAMPLE.com.", TargetKind.DOMAIN, "example.com"),
            ("192.0.2.7", TargetKind.IPV4, "192.0.2.7"),
            ("2001:0db8::1", TargetKind.IPV6, "2001:db8::1"),
            ("192.0.2.7/24", TargetKind.CIDR, "192.0.2.0/24"),
            ("HTTPS://Example.COM/path#fragment", TargetKind.URL, "https://example.com/path"),
        )
        for value, kind, normalized in cases:
            with self.subTest(value=value):
                target = Target.parse(value)
                self.assertEqual(target.kind, kind)
                self.assertEqual(target.normalized, normalized)
                self.assertEqual(target.value, value)

    def test_invalid_target_is_rejected(self) -> None:
        with self.assertRaises(ScopeValidationError):
            Target(TargetKind.URL, "ftp://example.com/file")


class ScopeEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = (
            ScopeRule(
                id="SC-0001",
                target=Target(TargetKind.DOMAIN, "*.example.com"),
                scope_status=ScopeStatus.ALLOWED,
                ownership_confidence=OwnershipConfidence.CONFIRMED,
            ),
            ScopeRule(
                id="SC-0002",
                target=Target(TargetKind.DOMAIN, "admin.example.com"),
                scope_status=ScopeStatus.DENIED,
                ownership_confidence=OwnershipConfidence.CONFIRMED,
            ),
            ScopeRule(
                id="SC-0003",
                target=Target(TargetKind.CIDR, "192.0.2.0/24"),
                scope_status=ScopeStatus.ALLOWED,
                ownership_confidence=OwnershipConfidence.LIKELY,
                review_required=True,
            ),
        )

    def test_domain_rule_applies_to_url_host(self) -> None:
        result = evaluate_target(Target.parse("https://portal.example.com/"), self.rules, enforce=True)
        self.assertEqual(result.scope_status, ScopeStatus.ALLOWED)
        self.assertTrue(result.launch_allowed)

    def test_explicit_exclusion_wins_and_only_blocks_when_enforced(self) -> None:
        target = Target.parse("admin.example.com")
        self.assertFalse(evaluate_target(target, self.rules, enforce=True).launch_allowed)
        self.assertTrue(evaluate_target(target, self.rules, enforce=False).launch_allowed)

    def test_unmatched_direct_target_is_not_an_implicit_block(self) -> None:
        result = evaluate_target(Target.parse("unlisted.test"), self.rules, enforce=True)
        self.assertFalse(result.matched)
        self.assertIsNone(result.scope_status)
        self.assertEqual(result.ownership_confidence, OwnershipConfidence.UNKNOWN)
        self.assertTrue(result.launch_allowed)

    def test_review_and_ownership_are_independent_of_authorization(self) -> None:
        result = evaluate_target(Target.parse("192.0.2.19"), self.rules, enforce=True)
        self.assertEqual(result.scope_status, ScopeStatus.ALLOWED)
        self.assertEqual(result.ownership_confidence, OwnershipConfidence.LIKELY)
        self.assertTrue(result.review_required)
        self.assertTrue(result.launch_allowed)

    def test_wildcard_url_rule_matches_subdomains_and_path_prefix(self) -> None:
        rule = ScopeRule(
            id="SC-0010",
            target=Target.parse("https://*.example.com/api/*"),
            scope_status=ScopeStatus.ALLOWED,
        )

        self.assertTrue(evaluate_target(
            Target.parse("https://portal.example.com/api/users"), (rule,), enforce=False
        ).matched)
        self.assertTrue(evaluate_target(
            Target.parse("https://portal.example.com/api/users?page=2"), (rule,), enforce=False
        ).matched)
        self.assertFalse(evaluate_target(
            Target.parse("https://example.com/api/users"), (rule,), enforce=False
        ).matched)
        self.assertFalse(evaluate_target(
            Target.parse("https://portal.example.com/admin/"), (rule,), enforce=False
        ).matched)


class ScopeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.project_path = Path(self.temporary_directory.name) / "P-0001"
        self.project_path.mkdir()
        self.store = ScopeStore(self.project_path)

    def test_missing_scope_document_is_an_empty_backward_compatible_scope(self) -> None:
        document = self.store.load()
        self.assertEqual(document.target_sets, ())
        self.assertEqual(document.rules, ())
        self.assertFalse(self.store.path.exists())

    def test_add_edit_and_remove_saved_target_set(self) -> None:
        target_set = self.store.add_target_set(
            "Web perimeter",
            (Target.parse("example.com"), Target.parse("192.0.2.0/24")),
        )
        self.assertEqual(target_set.id, "TS-0001")
        edited = type(target_set)(
            id=target_set.id,
            name="External web",
            description="Operator-maintained targets",
            targets=target_set.targets,
        )
        self.store.put_target_set(edited)
        self.assertEqual(self.store.load().get_target_set("TS-0001").name, "External web")
        self.store.remove_target_set("TS-0001")
        self.assertEqual(self.store.load().target_sets, ())

    def test_add_edit_and_remove_rule(self) -> None:
        rule = self.store.add_rule(
            target=Target.parse("*.example.com"),
            scope_status=ScopeStatus.ALLOWED,
            ownership_confidence=OwnershipConfidence.CONFIRMED,
        )
        self.assertEqual(rule.id, "SC-0001")
        edited = ScopeRule(
            id=rule.id,
            target=rule.target,
            scope_status=rule.scope_status,
            ownership_confidence=rule.ownership_confidence,
            review_required=True,
        )
        self.store.put_rule(edited)
        self.assertTrue(self.store.load().rules[0].review_required)
        self.store.remove_rule(rule.id)
        self.assertEqual(self.store.load().rules, ())

    def test_bulk_add_rules_is_atomic_and_skips_existing_targets(self) -> None:
        self.store.add_rule(
            target=Target.parse("existing.example.com"),
            scope_status=ScopeStatus.DENIED,
        )

        created = self.store.add_rules(
            (
                Target.parse("existing.example.com"),
                Target.parse("*.example.com"),
                Target.parse("*.EXAMPLE.COM"),
            ),
            scope_status=ScopeStatus.ALLOWED,
            ownership_confidence=OwnershipConfidence.LIKELY,
            source="assets",
        )

        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].id, "SC-0002")
        self.assertEqual(created[0].target.normalized, "*.example.com")
        rules = self.store.load().rules
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].scope_status, ScopeStatus.DENIED)

    def test_saved_document_is_versioned_and_portable(self) -> None:
        self.store.add_target_set("Direct", (Target.parse("example.com"),))
        payload = json.loads(self.store.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["kind"], SCOPE_KIND)
        self.assertEqual(payload["schema_version"], 1)
        self.assertNotIn(str(self.project_path), self.store.path.read_text(encoding="utf-8"))

    def test_duplicate_targets_are_rejected(self) -> None:
        with self.assertRaisesRegex(ScopeValidationError, "duplicate targets"):
            self.store.add_target_set(
                "Duplicates",
                (Target.parse("EXAMPLE.COM"), Target.parse("example.com")),
            )


class ExecutionContextTests(unittest.TestCase):
    def test_direct_targets_work_without_a_project(self) -> None:
        selection = TargetSelection.direct((Target.parse("example.com"),))
        context = ExecutionContext(selection=selection)
        self.assertIsNone(context.project_id)
        self.assertFalse(context.scope_enforced)

    def test_direct_targets_do_not_need_to_be_saved_in_a_project(self) -> None:
        selection = TargetSelection.direct((Target.parse("temporary.example.com"),))
        context = ExecutionContext(
            selection=selection,
            project_id="P-0001",
            project_name="Engagement",
            scope_enforced=True,
        )
        self.assertEqual(context.selection.source.value, "direct")
        self.assertEqual(context.project_id, "P-0001")

    def test_saved_target_set_requires_project_context(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            target_set = ScopeStore(Path(temporary_directory)).add_target_set(
                "Saved", (Target.parse("example.com"),)
            )
            with self.assertRaisesRegex(ScopeValidationError, "require a project"):
                ExecutionContext(selection=TargetSelection.saved(target_set))


if __name__ == "__main__":
    unittest.main()
