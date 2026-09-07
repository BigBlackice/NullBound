"""Blackwall NiceGUI entry point."""

from nicegui import ui

from dashboard_ui import build_ui
from recon_modules import FAVICON_SVG


if __name__ == "__main__":
    ui.run(
        root=build_ui,
        title="Blackwall - All your base are belong to me",
        favicon=FAVICON_SVG,
        dark=True,
        host="0.0.0.0",
        port=8080,
        reload=False,
        show=False,
    )
