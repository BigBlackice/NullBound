"""Models and persistence for user-configurable recon modules."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Iterator, Mapping
from uuid import uuid4


DEFAULT_ICON = "extension"
CATALOG_SCHEMA_VERSION = 1
FIELD_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
TARGET_TOKENS = {"{target}", "{targets}", "{target_file}"}


@dataclass(frozen=True, slots=True)
class ModuleConfigField:
    """One optional, data-driven module input mapped to a single argv flag."""

    id: str
    label: str
    argument: str
    placeholder: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ModuleConfigField:
        field_id = str(data.get("id", "")).strip()
        label = str(data.get("label", "")).strip()
        argument = str(data.get("argument", "")).strip()
        if not FIELD_ID_PATTERN.fullmatch(field_id):
            raise ValueError(f"invalid module config field id: {field_id!r}")
        if not label or not argument:
            raise ValueError(f"module config field {field_id!r} requires label and argument")
        return cls(
            id=field_id,
            label=label,
            argument=argument,
            placeholder=str(data.get("placeholder", "")).strip(),
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "id": self.id,
            "label": self.label,
            "argument": self.argument,
            "placeholder": self.placeholder,
        }


@dataclass(frozen=True, slots=True)
class ScanProfile:
    """A named, serializable command template for a module adapter.

    ``arguments`` is an argv template, not a shell command. Adapters expand its
    typed target tokens while every other item remains one argument.
    """

    name: str
    options: tuple[tuple[str, str], ...] = ()
    command: tuple[tuple[str, str], ...] = ()
    arguments: tuple[str, ...] = ()
    output_format: str = "text"

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ScanProfile:
        name = str(data.get("name", "")).strip()
        if not name:
            raise ValueError("scan profile name cannot be empty")
        arguments = tuple(str(item) for item in data.get("arguments", ()))
        if not arguments:
            raise ValueError(f"scan profile {name!r} requires an argument template")
        used_tokens = {token for token in TARGET_TOKENS if token in arguments}
        if len(used_tokens) > 1:
            raise ValueError(f"scan profile {name!r} mixes target placeholder styles")
        for token in used_tokens:
            if arguments.count(token) != 1:
                raise ValueError(f"scan profile {name!r} must use {token} once")
        return cls(
            name=name,
            options=tuple((str(item["label"]), str(item["value"])) for item in data.get("options", ())),
            command=tuple((str(item["type"]), str(item["text"])) for item in data.get("command", ())),
            arguments=arguments,
            output_format=str(data.get("output_format", "text")).strip() or "text",
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "options": [{"label": label, "value": value} for label, value in self.options],
            "command": [{"type": kind, "text": text} for kind, text in self.command],
            "arguments": list(self.arguments),
            "output_format": self.output_format,
        }


@dataclass(frozen=True, slots=True)
class ModuleDefinition:
    """A module record independent from any particular UI."""

    id: str
    eyebrow: str
    icon: str
    description: str
    bin: str
    path: str
    adapter: str = "declarative"
    target_summary: str = "ADD TARGET"
    target_placeholder: str = ""
    state: str = "MISSING"
    profiles: tuple[ScanProfile, ...] = ()
    config_fields: tuple[ModuleConfigField, ...] = ()

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ModuleDefinition:
        module_id = str(data.get("id", "")).strip()
        if not module_id.isdecimal():
            raise ValueError(f"module id must be numeric, got {module_id!r}")

        required = {
            field: str(data.get(field, "")).strip()
            for field in ("eyebrow", "description", "bin", "path")
        }
        missing = [field for field, value in required.items() if not value]
        if missing:
            raise ValueError(f"module {module_id}: missing {', '.join(missing)}")

        profiles = tuple(ScanProfile.from_mapping(profile) for profile in data.get("profiles", ()))
        profile_names = [profile.name.casefold() for profile in profiles]
        if len(profile_names) != len(set(profile_names)):
            raise ValueError(f"module {module_id}: scan profile names must be unique")
        return cls(
            id=module_id.zfill(2),
            eyebrow=required["eyebrow"],
            icon=str(data.get("icon") or DEFAULT_ICON).strip() or DEFAULT_ICON,
            description=required["description"],
            bin=required["bin"],
            path=required["path"],
            adapter=str(data.get("adapter", "declarative")).strip() or "declarative",
            target_summary=str(data.get("target_summary", "ADD TARGET")),
            # Read the old key as a migration fallback, but never submit it as a value.
            target_placeholder=str(data.get("target_placeholder", data.get("target_example", ""))),
            state=str(data.get("state", "MISSING")),
            profiles=profiles,
            config_fields=tuple(
                ModuleConfigField.from_mapping(field) for field in data.get("config_fields", ())
            ),
        )

    @property
    def display_eyebrow(self) -> str:
        return f"{self.eyebrow.upper()} / {self.id}"

    @property
    def profile_names(self) -> tuple[str, ...]:
        return tuple(profile.name for profile in self.profiles) or ("Default",)

    @property
    def default_profile(self) -> ScanProfile:
        if self.profiles:
            return self.profiles[0]
        return ScanProfile(name="Default", command=(("tool", self.bin),))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "eyebrow": self.eyebrow,
            "icon": self.icon,
            "description": self.description,
            "bin": self.bin,
            "path": self.path,
            "adapter": self.adapter,
            "target_summary": self.target_summary,
            "target_placeholder": self.target_placeholder,
            "state": self.state,
            "profiles": [profile.to_mapping() for profile in self.profiles],
            "config_fields": [field.to_mapping() for field in self.config_fields],
        }


class ModuleCatalog:
    """Ordered module registry used by Launchpad and, later, Settings."""

    def __init__(self, modules: Iterable[ModuleDefinition], source_path: Path | None = None) -> None:
        self._modules = list(modules)
        self.source_path = source_path
        self._validate_unique_ids()

    def __iter__(self) -> Iterator[ModuleDefinition]:
        return iter(self._modules)

    def __len__(self) -> int:
        return len(self._modules)

    @property
    def modules(self) -> tuple[ModuleDefinition, ...]:
        return tuple(self._modules)

    def get(self, module_id: str) -> ModuleDefinition:
        normalized_id = str(module_id).zfill(2)
        try:
            return next(module for module in self._modules if module.id == normalized_id)
        except StopIteration as error:
            raise KeyError(normalized_id) from error

    def next_id(self) -> str:
        next_number = max((int(module.id) for module in self._modules), default=0) + 1
        return str(next_number).zfill(max(2, len(str(next_number))))

    def create_module(
        self,
        *,
        eyebrow: str,
        description: str,
        bin: str,
        path: str,
        icon: str | None = None,
        adapter: str = "declarative",
        target_placeholder: str = "",
        profiles: Iterable[ScanProfile] = (),
        config_fields: Iterable[ModuleConfigField] = (),
    ) -> ModuleDefinition:
        """Create and register a module; its display/index ID is always allocated here."""
        module = ModuleDefinition.from_mapping(
            {
                "id": self.next_id(),
                "eyebrow": eyebrow,
                "icon": icon or DEFAULT_ICON,
                "description": description,
                "bin": bin,
                "path": path,
                "adapter": adapter,
                "target_placeholder": target_placeholder,
                "profiles": [profile.to_mapping() for profile in profiles],
                "config_fields": [field.to_mapping() for field in config_fields],
            }
        )
        self._modules.append(module)
        return module

    def replace_module(self, module_id: str, **changes: Any) -> ModuleDefinition:
        """Replace editable fields while preserving the automatically assigned ID."""
        current = self.get(module_id)
        changes.pop("id", None)
        if "profiles" in changes:
            changes["profiles"] = [profile.to_mapping() for profile in changes["profiles"]]
        if "config_fields" in changes:
            changes["config_fields"] = [field.to_mapping() for field in changes["config_fields"]]
        data = current.to_mapping()
        data.update(changes)
        updated = ModuleDefinition.from_mapping(data)
        self._modules[self._modules.index(current)] = updated
        return updated

    def remove_module(self, module_id: str) -> ModuleDefinition:
        """Remove and return one module from the catalog."""
        module = self.get(module_id)
        self._modules.remove(module)
        return module

    def save(self, path: Path | None = None) -> None:
        target = path or self.source_path
        if target is None:
            raise ValueError("a catalog path is required")
        payload = {
            "schema_version": CATALOG_SCHEMA_VERSION,
            "modules": [module.to_mapping() for module in self._modules],
        }
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    @classmethod
    def load(cls, path: Path) -> ModuleCatalog:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != CATALOG_SCHEMA_VERSION:
            raise ValueError(f"unsupported module catalog schema in {path}")
        return cls(
            (ModuleDefinition.from_mapping(data) for data in payload.get("modules", ())),
            source_path=path,
        )

    def _validate_unique_ids(self) -> None:
        ids = [module.id for module in self._modules]
        duplicates = sorted({module_id for module_id in ids if ids.count(module_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate module ids: {', '.join(duplicates)}")
