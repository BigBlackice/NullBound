"""Public execution API used by the UI and future automation surfaces."""

from .adapters import (
    AdapterRegistry, DeclarativeAdapter, DnsxAdapter, GauAdapter, HttpxAdapter,
    NmapAdapter, SubfinderAdapter, TlsxAdapter, ToolAdapter, expand_argument_template,
)
from .manager import ExecutionManager
from .models import (
    ArtifactRecord,
    CommandSpec,
    CompanionProcessSpec,
    ExecutionError,
    RunEvent,
    RunManifest,
    RunRequest,
    RunState,
    ToolHealth,
)
from .store import RUN_MANIFEST_NAME, RunStore, default_runs_root


__all__ = [
    "AdapterRegistry", "ArtifactRecord", "CommandSpec",
    "CompanionProcessSpec",
    "DeclarativeAdapter", "DnsxAdapter", "ExecutionError", "ExecutionManager",
    "GauAdapter", "HttpxAdapter", "NmapAdapter", "RUN_MANIFEST_NAME", "SubfinderAdapter",
    "TlsxAdapter",
    "RunEvent", "RunManifest", "RunRequest", "RunState", "RunStore",
    "ToolAdapter", "ToolHealth", "default_runs_root", "expand_argument_template",
]
