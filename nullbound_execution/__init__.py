"""Public execution API used by the UI and future automation surfaces."""

from .adapters import (
    AdapterRegistry, DEFAULT_FFUF_WORDLIST, DeclarativeAdapter, DnsxAdapter,
    FfufAdapter, GauAdapter, HttpxAdapter, NmapAdapter, SECLISTS_WEB_CONTENT_ROOT,
    SubfinderAdapter, TlsxAdapter, ToolAdapter, discover_ffuf_wordlists,
    expand_argument_template,
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
    "AdapterRegistry", "ArtifactRecord", "CommandSpec", "DEFAULT_FFUF_WORDLIST",
    "CompanionProcessSpec",
    "DeclarativeAdapter", "DnsxAdapter", "ExecutionError", "ExecutionManager",
    "FfufAdapter", "GauAdapter", "HttpxAdapter", "NmapAdapter", "RUN_MANIFEST_NAME", "SubfinderAdapter",
    "TlsxAdapter",
    "RunEvent", "RunManifest", "RunRequest", "RunState", "RunStore",
    "SECLISTS_WEB_CONTENT_ROOT", "ToolAdapter", "ToolHealth", "default_runs_root",
    "discover_ffuf_wordlists", "expand_argument_template",
]
