"""Project-local evidence indexing, enrichment, and correlation."""

from .database import (
    DATABASE_NAME,
    DATABASE_SCHEMA_VERSION,
    DatabaseVersionError,
    ProjectDatabase,
)
from .models import (
    AssetKind,
    AssetRecord,
    AssetReference,
    EvidenceKind,
    EvidenceRecord,
    FindingRecord,
    FindingSeverity,
    FindingState,
    IngestionResult,
    NORMALIZATION_VERSION,
    NormalizedRecord,
    ParsedFinding,
    ParsedRecord,
    RelationshipRecord,
    ScopeDisposition,
)
from .normalization import normalize_record, normalize_value
from .parsers import (
    DnsxJsonlParser,
    EvidenceParser,
    GauJsonlParser,
    HttpxJsonlParser,
    JsonLinesEnvelopeParser,
    NmapXmlParser,
    ParserRegistry,
    SubfinderJsonlParser,
    TlsxJsonlParser,
)
from .pipeline import CorrelationCandidate, CorrelationRule, EvidencePipeline, UrlHostCorrelation
from .store import EvidenceStore, stable_id
from .integration import ProjectRunIngestor

__all__ = [
    "AssetKind", "AssetRecord", "AssetReference", "CorrelationCandidate",
    "CorrelationRule", "DATABASE_NAME", "DATABASE_SCHEMA_VERSION", "DatabaseVersionError",
    "DnsxJsonlParser", "EvidenceKind", "EvidenceParser", "EvidencePipeline", "EvidenceRecord", "EvidenceStore",
    "FindingRecord", "FindingSeverity", "FindingState", "IngestionResult",
    "GauJsonlParser", "HttpxJsonlParser", "JsonLinesEnvelopeParser", "NORMALIZATION_VERSION",
    "NmapXmlParser", "NormalizedRecord", "ParsedFinding", "ParsedRecord", "ParserRegistry",
    "ProjectDatabase", "ProjectRunIngestor", "RelationshipRecord", "ScopeDisposition", "SubfinderJsonlParser",
    "TlsxJsonlParser", "UrlHostCorrelation", "normalize_record", "normalize_value", "stable_id",
]
