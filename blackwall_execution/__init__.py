"""Public execution API used by the UI and future automation surfaces."""

from .adapters import (
    AdapterRegistry, DeclarativeAdapter, HttpxAdapter, ToolAdapter, expand_argument_template,
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
    "AdapterRegistry", "ArtifactRecord", "CommandSpec", "DeclarativeAdapter",
    "ExecutionError", "ExecutionManager", "HttpxAdapter", "RUN_MANIFEST_NAME",
    "RunEvent", "RunManifest", "RunRequest", "RunState", "RunStore",
    "ToolAdapter", "default_runs_root", "expand_argument_template",
]
