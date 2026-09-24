"""Blackwall NiceGUI entry point."""

from functools import partial
import sys

from nicegui import app, ui

from app_config import AppConfig
from blackwall_evidence import ProjectRunIngestor
from blackwall_execution import ExecutionManager
from dashboard_ui import build_ui
from recon_modules import FAVICON_SVG


def run(argv: list[str] | None = None) -> None:
    """Validate startup configuration before exposing the NiceGUI application."""
    config = AppConfig.from_args(argv)
    if config.remote_access_warning:
        print(f"WARNING: {config.remote_access_warning}", file=sys.stderr)

    execution_manager = ExecutionManager(post_run_processor=ProjectRunIngestor())
    execution_manager.recover_incomplete()
    print("Jacking in...", flush=True)
    app.on_startup(lambda: print("BlackWall ready!", flush=True))

    ui.run(
        root=partial(build_ui, app_config=config, execution_manager=execution_manager),
        title="Blackwall - All your base are belong to me",
        favicon=FAVICON_SVG,
        dark=True,
        host=config.host,
        port=config.port,
        reload=False,
        show=False,
        show_welcome_message=False,
    )


if __name__ == "__main__":
    run()
