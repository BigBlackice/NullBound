"""Public target and scope API, independent of UI and tool adapters."""

from .evaluation import ScopeEvaluation, evaluate_target, evaluate_targets, rule_matches
from .models import (
    ExecutionContext,
    OwnershipConfidence,
    SCOPE_KIND,
    SCOPE_SCHEMA_VERSION,
    ScopeDocument,
    ScopeRule,
    ScopeStatus,
    ScopeValidationError,
    Target,
    TargetKind,
    TargetSelection,
    TargetSet,
    TargetSource,
)
from .store import SCOPE_DOCUMENT_NAME, ScopeStore


__all__ = [
    "ExecutionContext",
    "OwnershipConfidence",
    "SCOPE_DOCUMENT_NAME",
    "SCOPE_KIND",
    "SCOPE_SCHEMA_VERSION",
    "ScopeDocument",
    "ScopeEvaluation",
    "ScopeRule",
    "ScopeStatus",
    "ScopeStore",
    "ScopeValidationError",
    "Target",
    "TargetKind",
    "TargetSelection",
    "TargetSet",
    "TargetSource",
    "evaluate_target",
    "evaluate_targets",
    "rule_matches",
]
