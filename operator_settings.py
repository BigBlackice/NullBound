"""Persistent operator settings shared by every dashboard session."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import os
from pathlib import Path
from typing import Final
from uuid import uuid4


SETTINGS_SCHEMA_VERSION: Final = 1
DEFAULT_WEB_WORDLIST_DIRECTORY: Final = "wordlists/web-content"
DEFAULT_PASSWORD_WORDLIST_DIRECTORY: Final = "wordlists/passwords"


def default_settings_path(home: Path | None = None) -> Path:
    return (home or Path.home()).expanduser() / ".nullbound" / "settings.json"


def _project_directory(value: object, field: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = Path(text)
    if (
        not text
        or path.is_absolute()
        or ".." in path.parts
        or any(ord(character) < 32 for character in text)
    ):
        raise ValueError(f"{field} must be a project-relative directory")
    return path.as_posix().rstrip("/")


@dataclass(frozen=True, slots=True)
class OperatorSettings:
    proxy_enabled: bool = False
    proxy_protocol: str = "http"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    proxy_ca_certificate: str = ""
    web_wordlist_directory: str = DEFAULT_WEB_WORDLIST_DIRECTORY
    password_wordlist_directory: str = DEFAULT_PASSWORD_WORDLIST_DIRECTORY

    def __post_init__(self) -> None:
        protocol = str(self.proxy_protocol).strip().casefold()
        host = str(self.proxy_host).strip()
        if protocol not in {"http", "socks5"}:
            raise ValueError("proxy protocol must be HTTP or SOCKS5")
        if (
            not host
            or any(character.isspace() for character in host)
            or any(character in host for character in "/\\@")
        ):
            raise ValueError("proxy host must be a hostname or IP address")
        port = int(self.proxy_port)
        if not 1 <= port <= 65535:
            raise ValueError("proxy port must be between 1 and 65535")
        object.__setattr__(self, "proxy_protocol", protocol)
        object.__setattr__(self, "proxy_host", host)
        object.__setattr__(self, "proxy_port", port)
        object.__setattr__(
            self,
            "web_wordlist_directory",
            _project_directory(self.web_wordlist_directory, "web wordlist directory"),
        )
        object.__setattr__(
            self,
            "password_wordlist_directory",
            _project_directory(
                self.password_wordlist_directory, "password wordlist directory"
            ),
        )

    @classmethod
    def from_mapping(cls, data: object) -> "OperatorSettings":
        if not isinstance(data, dict) or data.get("schema_version") != SETTINGS_SCHEMA_VERSION:
            raise ValueError("unsupported operator settings")
        values = {key: data[key] for key in asdict(cls()).keys() if key in data}
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {"schema_version": SETTINGS_SCHEMA_VERSION, **asdict(self)}


class OperatorSettingsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = (path or default_settings_path()).expanduser().resolve(strict=False)
        self.settings = self.load()

    def load(self) -> OperatorSettings:
        if not self.path.is_file():
            return OperatorSettings()
        try:
            return OperatorSettings.from_mapping(
                json.loads(self.path.read_text(encoding="utf-8"))
            )
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError(f"cannot read operator settings: {self.path}") from error

    def update(self, **changes: object) -> OperatorSettings:
        updated = replace(self.settings, **changes)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(updated.to_mapping(), indent=2) + "\n", encoding="utf-8"
            )
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        self.settings = updated
        return updated

