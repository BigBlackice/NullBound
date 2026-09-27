"""Explicit parse-to-correlation evidence enrichment stages."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from blackwall_scope import ScopeDocument

from .models import (
    AssetKind,
    AssetReference,
    IngestionResult,
    NormalizedRecord,
    ParsedFinding,
    ParsedRecord,
)
from .normalization import normalize_record
from .parsers import EvidenceParser
from .store import EvidenceStore


@dataclass(frozen=True, slots=True)
class CorrelationCandidate:
    target: AssetReference
    relation: str
    confidence: str = "derived"


class CorrelationRule(Protocol):
    def candidates(self, record: NormalizedRecord) -> tuple[CorrelationCandidate, ...]: ...


class UrlHostCorrelation:
    """Relate a URL to its host without guessing registrable-domain boundaries."""

    def candidates(self, record: NormalizedRecord) -> tuple[CorrelationCandidate, ...]:
        if record.kind is not AssetKind.URL:
            return ()
        host = urlsplit(record.normalized_key).hostname
        if not host:
            return ()
        try:
            address = ip_address(host)
        except ValueError:
            kind = AssetKind.DOMAIN
        else:
            kind = AssetKind.IPV4 if address.version == 4 else AssetKind.IPV6
        return (CorrelationCandidate(AssetReference(kind, host), "hosted_by"),)


class EvidencePipeline:
    """Coordinate independently testable enrichment stages over one project index."""

    def __init__(
        self,
        store: EvidenceStore,
        correlation_rules: tuple[CorrelationRule, ...] | None = None,
    ) -> None:
        self.store = store
        self.correlation_rules = correlation_rules or (UrlHostCorrelation(),)

    def ingest_artifact(
        self,
        parser: EvidenceParser,
        path: Path,
        *,
        run_id: str | None = None,
        scope: ScopeDocument | None = None,
        source: str | None = None,
    ) -> IngestionResult:
        """Run the parse stage and feed its envelopes through every later stage."""
        records = parser.parse(path, run_id=run_id)
        return self.ingest(
            records, scope=scope, parser=parser.key,
            source=source or parser.key,
        )

    def ingest(
        self,
        records: tuple[ParsedRecord, ...],
        *,
        findings: tuple[ParsedFinding, ...] = (),
        scope: ScopeDocument | None = None,
        parser: str = "direct",
        source: str = "unknown",
    ) -> IngestionResult:
        scope_document = scope or ScopeDocument()
        self.store.sync_scope(scope_document)
        batch_id = self.store.begin_batch(parser, source)
        assets_created = assets_matched = evidence_created = 0
        findings_created = relationships_created = 0
        try:
            with self.store.transaction() as connection:
                for parsed in records:
                    normalized = normalize_record(parsed)
                    asset, evidence, new_asset, new_evidence = self.store.put_asset(
                        normalized, scope_document, batch_id=batch_id,
                        connection=connection,
                    )
                    assets_created += int(new_asset)
                    assets_matched += int(not new_asset)
                    evidence_created += int(new_evidence)
                    candidates = [
                        CorrelationCandidate(reference, reference.relation, reference.confidence)
                        for reference in normalized.related
                    ]
                    for rule in self.correlation_rules:
                        candidates.extend(rule.candidates(normalized))
                    for candidate in candidates:
                        related = normalize_record(ParsedRecord(
                            kind=candidate.target.kind,
                            value=candidate.target.value,
                            source=f"{normalized.source}:correlation",
                            run_id=normalized.run_id,
                            artifact_path=normalized.artifact_path,
                            observed_at=normalized.observed_at,
                            metadata={"derived_from": asset.id},
                        ))
                        related_asset, _, created, related_evidence = self.store.put_asset(
                            related, scope_document, batch_id=batch_id,
                            connection=connection,
                        )
                        assets_created += int(created)
                        assets_matched += int(not created)
                        evidence_created += int(related_evidence)
                        _, relation_created = self.store.put_relationship(
                            "asset", asset.id, "asset", related_asset.id,
                            candidate.relation, evidence_id=evidence.id,
                            confidence=candidate.confidence,
                            metadata=dict(candidate.target.metadata),
                            connection=connection,
                        )
                        relationships_created += int(relation_created)

                for parsed_finding in findings:
                    asset_id = None
                    evidence_id = None
                    if parsed_finding.asset:
                        asset_record = normalize_record(ParsedRecord(
                            kind=parsed_finding.asset.kind,
                            value=parsed_finding.asset.value,
                            source=parsed_finding.source,
                            run_id=parsed_finding.run_id,
                            observed_at=parsed_finding.observed_at,
                            metadata={"finding_title": parsed_finding.title},
                        ))
                        asset, evidence, created, created_evidence = self.store.put_asset(
                            asset_record, scope_document, batch_id=batch_id,
                            connection=connection,
                        )
                        asset_id = asset.id
                        evidence_id = evidence.id
                        assets_created += int(created)
                        assets_matched += int(not created)
                        evidence_created += int(created_evidence)
                    finding, created = self.store.put_finding(
                        parsed_finding, asset_id, batch_id, connection=connection
                    )
                    findings_created += int(created)
                    if asset_id:
                        _, relation_created = self.store.put_relationship(
                            "finding", finding.id, "asset", asset_id, "affects",
                            evidence_id=evidence_id, confidence=parsed_finding.confidence,
                            connection=connection,
                        )
                        relationships_created += int(relation_created)
            self.store.finish_batch(batch_id)
        except Exception as error:
            self.store.finish_batch(batch_id, str(error))
            raise
        return IngestionResult(
            batch_id=batch_id,
            assets_created=assets_created,
            assets_matched=assets_matched,
            evidence_created=evidence_created,
            findings_created=findings_created,
            relationships_created=relationships_created,
        )
