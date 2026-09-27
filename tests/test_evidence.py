"""Tests for the project-local evidence index and enrichment pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from blackwall_evidence import (
    AssetKind,
    AssetReference,
    DATABASE_SCHEMA_VERSION,
    DnsxJsonlParser,
    EvidencePipeline,
    EvidenceStore,
    FindingSeverity,
    GauJsonlParser,
    HttpxJsonlParser,
    JsonLinesEnvelopeParser,
    NmapXmlParser,
    ParserRegistry,
    ParsedFinding,
    ParsedRecord,
    ProjectRunIngestor,
    ScopeDisposition,
    SubfinderJsonlParser,
    TlsxJsonlParser,
    normalize_record,
)
from blackwall_execution import ArtifactRecord, ExecutionManager, RunStore
from blackwall_scope import (
    OwnershipConfidence,
    ScopeDocument,
    ScopeRule,
    ScopeStatus,
    Target,
)
from blackwall_projects import ProjectStore


class EvidenceFrameworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.project_path = Path(self.temporary_directory.name) / "P-0001"
        self.project_path.mkdir()
        self.store = EvidenceStore(self.project_path)
        self.pipeline = EvidencePipeline(self.store)
        self.scope = ScopeDocument(rules=(
            ScopeRule(
                id="SC-0001", target=Target.parse("*.example.com"),
                scope_status=ScopeStatus.ALLOWED,
                ownership_confidence=OwnershipConfidence.CONFIRMED,
            ),
            ScopeRule(
                id="SC-0002", target=Target.parse("blocked.example.com"),
                scope_status=ScopeStatus.DENIED,
                ownership_confidence=OwnershipConfidence.CONFIRMED,
            ),
        ))

    def test_database_is_versioned_and_recovers_interrupted_batches(self) -> None:
        batch_id = self.store.begin_batch("test", "fixture")
        with self.store.database.read() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, DATABASE_SCHEMA_VERSION)

        self.assertEqual(self.store.recover_incomplete(), 1)
        with self.store.database.read() as connection:
            row = connection.execute(
                "SELECT status, error FROM ingestion_batches WHERE id = ?", (batch_id,)
            ).fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertIn("stopped", row["error"])

    def test_normalization_preserves_raw_url_and_records_transformations(self) -> None:
        normalized = normalize_record(ParsedRecord(
            AssetKind.URL, "HTTPS://Portal.Example.COM#frag", "fixture"
        ))

        self.assertEqual(normalized.raw_value, "HTTPS://Portal.Example.COM#frag")
        self.assertEqual(normalized.normalized_key, "https://portal.example.com/")
        self.assertIn("removed_fragment", normalized.transformations)
        self.assertGreaterEqual(normalized.normalization_version, 1)

    def test_pipeline_deduplicates_assets_and_preserves_observation_provenance(self) -> None:
        records = (
            ParsedRecord(
                AssetKind.DOMAIN, "Portal.Example.com.", "subfinder", run_id="RUN-001",
                artifact_path="runs/RUN-001/artifacts/subfinder.jsonl",
            ),
            ParsedRecord(
                AssetKind.DOMAIN, "portal.example.com", "dnsx", run_id="RUN-002",
                artifact_path="runs/RUN-002/artifacts/dnsx.jsonl",
            ),
        )

        result = self.pipeline.ingest(records, scope=self.scope, source="fixture")
        assets = self.store.list_assets()
        evidence = self.store.list_evidence(asset_id=assets[0].id)

        self.assertEqual(result.assets_created, 1)
        self.assertEqual(result.assets_matched, 1)
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].scope, ScopeDisposition.ALLOWED)
        self.assertEqual({item.run_id for item in evidence}, {"RUN-001", "RUN-002"})
        self.assertEqual({item.raw_value for item in evidence}, {
            "Portal.Example.com.", "portal.example.com",
        })
        provenance = self.store.list_asset_provenance()
        sources, run_ids = provenance[assets[0].id]
        self.assertEqual(set(sources), {"dnsx", "subfinder"})
        self.assertEqual(set(run_ids), {"RUN-001", "RUN-002"})
        self.assertEqual(
            self.store.list_evidence_node_counts()[assets[0].id], (2, 0)
        )
        self.assertEqual(
            self.store.search_evidence_asset_ids("Portal.Example.com."),
            {assets[0].id},
        )

    def test_url_enrichment_correlates_a_host_without_guessing_a_root_domain(self) -> None:
        result = self.pipeline.ingest((ParsedRecord(
            AssetKind.URL, "https://api.example.com/v1", "gau",
        ),), scope=self.scope, source="gau")

        assets = self.store.list_assets()
        relations = self.store.list_relationships()

        self.assertEqual(result.relationships_created, 1)
        self.assertEqual({asset.kind for asset in assets}, {AssetKind.URL, AssetKind.DOMAIN})
        self.assertEqual(relations[0].relation, "hosted_by")
        related = self.store.list_related_assets(relations[0].source_id)
        self.assertEqual({item.id for item in related}, {relations[0].target_id})

    def test_denied_assets_are_retained_but_hidden_from_normal_queries(self) -> None:
        self.pipeline.ingest((ParsedRecord(
            AssetKind.DOMAIN, "blocked.example.com", "subfinder",
        ),), scope=self.scope, source="subfinder")

        self.assertEqual(self.store.list_assets(), ())
        review = self.store.list_scope_review_assets()
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0].scope, ScopeDisposition.DENIED)

    def test_findings_are_deduplicated_and_correlated_to_assets(self) -> None:
        finding = ParsedFinding(
            title="Exposed admin console", severity=FindingSeverity.HIGH,
            source="manual", asset=AssetReference(AssetKind.DOMAIN, "admin.example.com"),
            location="https://admin.example.com/", confidence="high",
        )

        first = self.pipeline.ingest((), findings=(finding,), scope=self.scope, source="manual")
        second = self.pipeline.ingest((), findings=(finding,), scope=self.scope, source="manual")

        self.assertEqual(first.findings_created, 1)
        self.assertEqual(second.findings_created, 0)
        self.assertEqual(len(self.store.list_findings()), 1)
        self.assertEqual(self.store.list_relationships()[0].relation, "affects")
        finding = self.store.list_findings()[0]
        self.assertEqual(self.store.list_finding_scopes()[finding.id], "allowed")

    def test_unchanged_scope_sync_skips_asset_reevaluation(self) -> None:
        self.store.sync_scope(self.scope)
        original = self.store._scope_for
        self.store._scope_for = lambda *_args: self.fail("scope was reevaluated")
        try:
            self.assertEqual(self.store.sync_scope(self.scope), len(self.scope.rules))
        finally:
            self.store._scope_for = original

    def test_failed_ingestion_rolls_back_partial_normalized_records(self) -> None:
        records = (
            ParsedRecord(AssetKind.DOMAIN, "valid.example.com", "fixture"),
            ParsedRecord(AssetKind.IPV4, "not-an-address", "fixture"),
        )

        with self.assertRaises(ValueError):
            self.pipeline.ingest(records, scope=self.scope, source="fixture")

        self.assertEqual(self.store.list_assets(include_denied=True), ())
        with self.store.database.read() as connection:
            batch = connection.execute(
                "SELECT status FROM ingestion_batches ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(batch["status"], "failed")

    def test_neutral_jsonl_parser_produces_typed_records(self) -> None:
        path = self.project_path / "records.jsonl"
        path.write_text(json.dumps({
            "kind": "domain", "value": "example.com",
            "related": [{"kind": "ipv4", "value": "192.0.2.10", "relation": "resolves_to"}],
        }) + "\n", encoding="utf-8")

        parser = JsonLinesEnvelopeParser("fixture")
        records = parser.parse(path, run_id="RUN-001")
        result = self.pipeline.ingest_artifact(
            parser, path, run_id="RUN-001", scope=self.scope
        )

        self.assertEqual(records[0].kind, AssetKind.DOMAIN)
        self.assertEqual(records[0].related[0].relation, "resolves_to")
        self.assertEqual(result.relationships_created, 1)
        self.assertEqual(self.store.list_relationships()[0].relation, "resolves_to")

    def test_native_jsonl_parsers_cover_projectdiscovery_and_gau_artifacts(self) -> None:
        fixtures = {
            "subfinder.jsonl": ({
                "host": "api.example.com", "input": "example.com",
                "sources": ["crtsh", "hackertarget"],
            }, SubfinderJsonlParser(), AssetKind.DOMAIN, None),
            "dnsx.jsonl": ({
                "host": "api.example.com", "a": ["192.0.2.10"],
                "cname": ["edge.example.net"],
            }, DnsxJsonlParser(), AssetKind.DOMAIN, "resolves_to"),
            "httpx.jsonl": ({
                "url": "https://api.example.com", "a": ["192.0.2.10"],
                "tech": ["nginx"], "status_code": 200,
            }, HttpxJsonlParser(), AssetKind.URL, "uses_technology"),
            "gau.jsonl": ({
                "url": "https://api.example.com/archive", "source": "wayback",
            }, GauJsonlParser(), AssetKind.URL, None),
            "tlsx.jsonl": ({
                "host": "api.example.com", "ip": "192.0.2.10", "port": "443",
                "subject_cn": "api.example.com", "tls_version": "tls13",
            }, TlsxJsonlParser(), AssetKind.DOMAIN, "exposes_service"),
        }
        for filename, (payload, parser, expected_kind, expected_relation) in fixtures.items():
            with self.subTest(parser=parser.key):
                path = self.project_path / filename
                path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                records = parser.parse(path, run_id="RUN-NATIVE")
                self.assertEqual(records[0].kind, expected_kind)
                self.assertEqual(records[0].run_id, "RUN-NATIVE")
                if expected_relation:
                    self.assertIn(expected_relation, {item.relation for item in records[0].related})

    def test_nmap_xml_parser_emits_hosts_services_and_technology_links(self) -> None:
        path = self.project_path / "nmap.xml"
        path.write_text(
            """<?xml version="1.0"?><nmaprun><host><status state="up"/>
            <address addr="192.0.2.20" addrtype="ipv4"/>
            <hostnames><hostname name="web.example.com"/></hostnames>
            <ports><port protocol="tcp" portid="443"><state state="open"/>
            <service name="https" product="nginx" version="1.25"/>
            </port></ports></host></nmaprun>""",
            encoding="utf-8",
        )

        records = NmapXmlParser().parse(path, run_id="RUN-NMAP")

        self.assertEqual({record.kind for record in records}, {AssetKind.IPV4, AssetKind.SERVICE})
        service = next(record for record in records if record.kind is AssetKind.SERVICE)
        self.assertIn("uses_technology", {item.relation for item in service.related})

    def test_subfinder_parser_preserves_provider_provenance(self) -> None:
        path = self.project_path / "subfinder.jsonl"
        path.write_text(json.dumps({
            "host": "api.example.com", "input": "example.com",
            "sources": ["crtsh", "hackertarget"],
        }) + "\n", encoding="utf-8")

        records = SubfinderJsonlParser().parse(path, run_id="RUN-SUBFINDER")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].kind, AssetKind.DOMAIN)
        self.assertEqual(records[0].value, "api.example.com")
        self.assertEqual(records[0].metadata["input"], "example.com")
        self.assertEqual(
            records[0].metadata["sources"], ("crtsh", "hackertarget")
        )

    def test_amass_parser_is_not_registered_in_the_active_pipeline(self) -> None:
        with self.assertRaisesRegex(KeyError, "unknown evidence parser"):
            ParserRegistry.native().get("amass")

    def test_project_run_ingestor_uses_native_parser_and_project_relative_provenance(self) -> None:
        run_path = self.project_path / "runs" / "RUN-INGEST"
        artifact = run_path / "artifacts" / "dnsx.jsonl"
        artifact.parent.mkdir(parents=True)
        artifact.write_text(
            json.dumps({"host": "api.example.com", "a": ["192.0.2.40"]}) + "\n",
            encoding="utf-8",
        )
        manifest = SimpleNamespace(
            id="RUN-INGEST", project_id="P-0001", module_bin="dnsx", run_path=run_path,
            artifacts=(ArtifactRecord("artifacts/dnsx.jsonl", artifact.stat().st_size, "digest"),),
        )

        summary = ProjectRunIngestor()(manifest)
        assets = EvidenceStore(self.project_path).list_assets()
        evidence = EvidenceStore(self.project_path).list_evidence()

        self.assertEqual(summary["assets_created"], 2)
        self.assertEqual({asset.kind for asset in assets}, {AssetKind.DOMAIN, AssetKind.IPV4})
        self.assertEqual(
            {item.artifact_path for item in evidence},
            {"runs/RUN-INGEST/artifacts/dnsx.jsonl"},
        )

    def test_subfinder_run_indexes_the_submitted_domain_as_a_seed_without_results(self) -> None:
        run_path = self.project_path / "runs" / "RUN-SEED"
        (run_path / "artifacts").mkdir(parents=True)
        manifest = SimpleNamespace(
            id="RUN-SEED", project_id="P-0001", module_bin="subfinder",
            run_path=run_path, artifacts=(), target_source="direct",
            targets=({
                "kind": "domain", "value": "Example.COM",
                "normalized": "example.com",
            },),
        )

        summary = ProjectRunIngestor()(manifest)
        assets = EvidenceStore(self.project_path).list_assets()
        evidence = EvidenceStore(self.project_path).list_evidence()

        self.assertEqual(summary["assets_created"], 1)
        self.assertEqual(assets[0].normalized_key, "example.com")
        self.assertEqual(evidence[0].metadata["role"], "seed")
        self.assertIsNone(evidence[0].artifact_path)

    def test_artifact_provenance_path_cannot_escape_project(self) -> None:
        with self.assertRaisesRegex(ValueError, "project-relative"):
            self.pipeline.ingest((ParsedRecord(
                AssetKind.DOMAIN, "example.com", "fixture", artifact_path="../secret",
            ),), scope=self.scope)

    def test_dashboard_reads_project_records_instead_of_placeholder_data(self) -> None:
        project_store = ProjectStore(self.project_path.parent / "projects")
        project = project_store.create_project("Indexed UI")
        EvidencePipeline(EvidenceStore(project.path)).ingest((ParsedRecord(
            AssetKind.DOMAIN, "portal.example.com", "fixture",
        ),), scope=self.scope, source="fixture")

        from dashboard_ui import DashboardUI
        dashboard = DashboardUI(
            project_store=project_store,
            execution_manager=ExecutionManager(
                store=RunStore(self.project_path.parent / "session-runs")
            ),
        )
        dashboard.project_workspace.open(project.path)

        assets = dashboard.asset_records()
        evidence = dashboard.evidence_node_records()

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["name"], "portal.example.com")
        self.assertEqual(evidence[0]["identifier"], "portal.example.com")


if __name__ == "__main__":
    unittest.main()
