"""Data-driven recon module catalog."""

from base64 import b64encode
from pathlib import Path

from .catalog import DEFAULT_ICON, ModuleCatalog, ModuleConfigField, ModuleDefinition, ScanProfile


DEFAULT_CATALOG_PATH = Path(__file__).with_name("definitions.json")
FAVICON_PATH = Path(__file__).with_name("assets") / "favicon.svg"
FAVICON_SVG = FAVICON_PATH.read_text(encoding="utf-8")
FAVICON_DATA_URL = f"data:image/svg+xml;base64,{b64encode(FAVICON_SVG.encode()).decode()}"


def load_default_catalog() -> ModuleCatalog:
    """Load the catalog shipped with NullBound."""
    return ModuleCatalog.load(DEFAULT_CATALOG_PATH)


__all__ = [
    "DEFAULT_CATALOG_PATH",
    "DEFAULT_ICON",
    "FAVICON_PATH",
    "FAVICON_DATA_URL",
    "FAVICON_SVG",
    "ModuleCatalog",
    "ModuleConfigField",
    "ModuleDefinition",
    "ScanProfile",
    "load_default_catalog",
]
