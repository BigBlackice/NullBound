"""NiceGUI directory browser for selecting project locations on the host."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from pathlib import Path

from nicegui import ui


class LocalDirectoryPicker:
    """Browse host directories without relying on an OS-specific dialog toolkit."""

    def __init__(self, title: str, on_select: Callable[[Path], None]) -> None:
        self.title = title
        self.on_select = on_select
        self.current_directory = Path.home()

        with ui.dialog().classes("directory-picker-dialog") as self.dialog:
            with ui.card().classes("directory-picker-modal"):
                with ui.element("header").classes("settings-header"):
                    with ui.element("div"):
                        ui.label("LOCAL FILESYSTEM / DIRECTORY").classes("section-kicker")
                        ui.label(title).classes("settings-title")
                    with ui.element("button").classes("settings-close").props(
                        f'type=button aria-label="Close {title}" data-escape-close=true'
                    ).on("click", self.dialog.close):
                        ui.label("×")

                with ui.element("div").classes("directory-picker-body"):
                    with ui.element("div").classes("directory-path-row"):
                        self.path_input = ui.input().props("dense outlined").classes(
                            "config-control directory-path-input"
                        )
                        ui.button("GO", on_click=self.apply_typed_path).props(
                            "flat dense no-caps"
                        ).classes("settings-action")
                    self.directory_list = ui.element("div").classes("directory-list")
                    with ui.element("div").classes("settings-actions directory-actions"):
                        ui.button("SELECT THIS DIRECTORY", icon="folder_open", on_click=self.select_current).props(
                            "flat no-caps"
                        ).classes("settings-action primary")

    def open(self, start: Path) -> None:
        """Open at the requested directory, falling back to its nearest existing parent."""
        candidate = start.expanduser().resolve(strict=False)
        while not candidate.is_dir() and candidate != candidate.parent:
            candidate = candidate.parent
        if not candidate.is_dir():
            candidate = Path.home().resolve()
        self.set_directory(candidate)
        self.dialog.open()

    def apply_typed_path(self) -> None:
        self.set_directory(Path(str(self.path_input.value or "")).expanduser())

    def set_directory(self, directory: Path) -> None:
        try:
            resolved = directory.resolve(strict=True)
            if not resolved.is_dir():
                raise NotADirectoryError(resolved)
            entries = sorted(
                (entry for entry in resolved.iterdir() if entry.is_dir()),
                key=lambda entry: entry.name.casefold(),
            )
        except (OSError, RuntimeError) as error:
            ui.notify(f"Cannot browse directory: {error}", type="negative")
            return

        self.current_directory = resolved
        self.path_input.value = str(resolved)
        self.directory_list.clear()
        with self.directory_list:
            if resolved != resolved.parent:
                self._directory_button("..", resolved.parent, "drive_folder_upload")
            for entry in entries:
                self._directory_button(entry.name, entry, "folder")
            if not entries and resolved == resolved.parent:
                ui.label("NO SUBDIRECTORIES").classes("settings-note")

    def select_current(self) -> None:
        selected = self.current_directory
        self.dialog.close()
        self.on_select(selected)

    def _directory_button(self, label: str, path: Path, icon_name: str) -> None:
        with ui.element("button").classes("directory-row").props("type=button").on(
            "click", partial(self.set_directory, path)
        ):
            ui.icon(icon_name)
            ui.label(label)
