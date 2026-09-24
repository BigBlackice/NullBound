"""Public execution API used by the UI and future automation surfaces."""

from .adapters import (
    AdapterRegistry, AmassAdapter, DeclarativeAdapter, DnsxAdapter, GauAdapter,
    HttpxAdapter, NmapAdapter, TlsxAdapter, ToolAdapter, expand_argument_template,
)
from .manager import ExecutionManager
from .models import (
    ArtifactRecord,
    CommandSpec,
    ExecutionError,
    RunEvent,
    RunManifest,
    RunRequest,
    RunState,
)
from .store import RUN_MANIFEST_NAME, RunStore, default_runs_root


__all__ = [
    "AdapterRegistry", "AmassAdapter", "ArtifactRecord", "CommandSpec",
    "DeclarativeAdapter", "DnsxAdapter", "ExecutionError", "ExecutionManager",
    "GauAdapter", "HttpxAdapter", "NmapAdapter", "RUN_MANIFEST_NAME", "TlsxAdapter",
    "RunEvent", "RunManifest", "RunRequest", "RunState", "RunStore",
    "ToolAdapter", "default_runs_root", "expand_argument_template",
]
