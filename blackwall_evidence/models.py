"""Typed records for Blackwall's project-local evidence index."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping


NORMALIZATION_VERSION = 1


class AssetKind(StrEnum):
    DOMAIN = "domain"
    HOST = "host"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    URL = "url"
    SERVICE = "service"
    EMAIL = "email"
    USERNAME = "username"
    ORGANIZATION = "organization"
    AUTONOMOUS_SYSTEM = "autonomous_system"
    TECHNOLOGY = "technology"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingState(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class ScopeDisposition(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    REVIEW = "review"
    UNMATCHED = "unmatched"


class EvidenceKind(StrEnum):
    OBSERVATION = "observation"
    ARTIFACT = "artifact"
    FINDING = "finding"
    INFERENCE = "inference"


@dataclass(frozen=True, slots=True)
class ParsedRecord:
    """One parser output before normalization or deduplication."""

    kind: AssetKind
    value: str
    source: str
    run_id: str | None = None
    artifact_path: str | None = None
    observed_at: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)
    related: tuple[AssetReference, ...] = ()


@dataclass(frozen=True, slots=True)
class AssetReference:
    kind: AssetKind
    value: str
    relation: str = "related_to"
    confidence: str = "observed"
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ParsedFinding:
    title: str
    severity: FindingSeverity
    source: str
    asset: AssetReference | None = None
    location: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    confidence: str = "unknown"
    state: FindingState = FindingState.CANDIDATE
    run_id: str | None = None
    fingerprint: str | None = None
    observed_at: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NormalizedRecord:
    kind: AssetKind
    raw_value: str
    normalized_key: str
    source: str
    normalization_version: int = NORMALIZATION_VERSION
    transformations: tuple[str, ...] = ()
    run_id: str | None = None
    artifact_path: str | None = None
    observed_at: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)
    related: tuple[AssetReference, ...] = ()


@dataclass(frozen=True, slots=True)
class AssetRecord:
    id: str
    kind: AssetKind
    original_value: str
    normalized_key: str
    display_name: str
    scope: ScopeDisposition
    ownership_confidence: str
    review_required: bool
    matched_rule_id: str | None
    first_seen_at: str
    last_seen_at: str
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    id: str
    kind: EvidenceKind
    asset_id: str | None
    finding_id: str | None
    source: str
    raw_value: str
    normalized_key: str | None
    normalization_version: int | None
    transformations: tuple[str, ...]
    run_id: str | None
    batch_id: str | None
    artifact_path: str | None
    observed_at: str
    integrity_status: str
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FindingRecord:
    id: str
    fingerprint: str
    title: str
    severity: FindingSeverity
    state: FindingState
    confidence: str
    asset_id: str | None
    asset_name: str
    location: str
    description: str
    evidence: str
    recommendation: str
    source: str
    run_id: str | None
    batch_id: str | None
    first_seen_at: str
    last_seen_at: str
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RelationshipRecord:
    id: str
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    relation: str
    evidence_id: str | None
    confidence: str
    created_at: str
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IngestionResult:
    batch_id: str
    assets_created: int
    assets_matched: int
    evidence_created: int
    findings_created: int
    relationships_created: int
