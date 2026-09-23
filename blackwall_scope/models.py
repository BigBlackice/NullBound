"""Portable target, scope, and execution-context models for Blackwall."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address, ip_network
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit


SCOPE_KIND = "blackwall-scope"
SCOPE_SCHEMA_VERSION = 1
TARGET_SET_ID_PATTERN = re.compile(r"^TS-[0-9]{4,}$")
SCOPE_RULE_ID_PATTERN = re.compile(r"^SC-[0-9]{4,}$")
_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$", re.IGNORECASE)


class ScopeValidationError(ValueError):
    """Raised when persisted or operator-supplied scope data is invalid."""


class TargetKind(StrEnum):
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    URL = "url"


class ScopeStatus(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class OwnershipConfidence(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNKNOWN = "unknown"


class TargetSource(StrEnum):
    DIRECT = "direct"
    TARGET_SET = "target_set"


def _enum_value(enum_type: type[StrEnum], value: object, field_name: str) -> Any:
    try:
        return enum_type(str(value).lower())
    except ValueError as error:
        choices = ", ".join(item.value for item in enum_type)
        raise ScopeValidationError(f"{field_name} must be one of: {choices}") from error


def normalize_target(kind: TargetKind, value: object) -> str:
    """Return a stable comparison value without discarding the original input."""
    raw = str(value or "").strip()
    if not raw:
        raise ScopeValidationError("target value cannot be empty")

    if kind in (TargetKind.IPV4, TargetKind.IPV6):
        try:
            address = ip_address(raw)
        except ValueError as error:
            raise ScopeValidationError(f"invalid {kind.value} target: {raw}") from error
        expected_version = 4 if kind is TargetKind.IPV4 else 6
        if address.version != expected_version:
            raise ScopeValidationError(f"target is not {kind.value}: {raw}")
        return address.compressed

    if kind is TargetKind.CIDR:
        try:
            return ip_network(raw, strict=False).with_prefixlen
        except ValueError as error:
            raise ScopeValidationError(f"invalid cidr target: {raw}") from error

    if kind is TargetKind.DOMAIN:
        domain = raw.rstrip(".").lower()
        wildcard = domain.startswith("*.")
        base = domain[2:] if wildcard else domain
        if not base or len(base) > 253 or any(not _DOMAIN_LABEL.fullmatch(x) for x in base.split(".")):
            raise ScopeValidationError(f"invalid domain target: {raw}")
        return f"*.{base}" if wildcard else base

    if kind is TargetKind.URL:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ScopeValidationError("url targets must be absolute HTTP or HTTPS URLs")
        if parsed.username or parsed.password:
            raise ScopeValidationError("url targets cannot contain credentials")
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        netloc = f"{host}:{parsed.port}" if parsed.port else host
        path = parsed.path or "/"
        return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))

    raise ScopeValidationError(f"unsupported target kind: {kind}")


@dataclass(frozen=True, slots=True)
class Target:
    """One typed target, preserving operator input and a normalized comparison key."""

    kind: TargetKind
    value: str
    normalized: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _enum_value(TargetKind, self.kind, "target kind"))
        raw = str(self.value or "").strip()
        object.__setattr__(self, "value", raw)
        object.__setattr__(self, "normalized", normalize_target(self.kind, raw))

    @classmethod
    def parse(cls, value: object) -> Target:
        """Infer a supported target kind for convenient direct-target entry."""
        raw = str(value or "").strip()
        if raw.lower().startswith(("http://", "https://")):
            return cls(TargetKind.URL, raw)
        if "/" in raw:
            try:
                ip_network(raw, strict=False)
            except ValueError:
                pass
            else:
                return cls(TargetKind.CIDR, raw)
        try:
            address = ip_address(raw)
        except ValueError:
            return cls(TargetKind.DOMAIN, raw)
        return cls(TargetKind.IPV4 if address.version == 4 else TargetKind.IPV6, raw)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Target:
        return cls(kind=data.get("kind", ""), value=str(data.get("value", "")))

    def to_mapping(self) -> dict[str, str]:
        return {"kind": self.kind.value, "value": self.value}


def _validate_id(value: object, pattern: re.Pattern[str], field_name: str) -> str:
    identifier = str(value or "").strip()
    if not pattern.fullmatch(identifier):
        raise ScopeValidationError(f"invalid {field_name}: {identifier!r}")
    return identifier


@dataclass(frozen=True, slots=True)
class TargetSet:
    id: str
    name: str
    targets: tuple[Target, ...]
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _validate_id(self.id, TARGET_SET_ID_PATTERN, "target set id"))
        name = str(self.name or "").strip()
        if not name:
            raise ScopeValidationError("target set name cannot be empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "targets", tuple(self.targets))
        keys = [(target.kind, target.normalized) for target in self.targets]
        if len(keys) != len(set(keys)):
            raise ScopeValidationError("target set cannot contain duplicate targets")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> TargetSet:
        targets = data.get("targets", [])
        if not isinstance(targets, list):
            raise ScopeValidationError("target set targets must be a list")
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            targets=tuple(Target.from_mapping(item) for item in targets if isinstance(item, Mapping)),
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "targets": [target.to_mapping() for target in self.targets],
        }


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """An include/exclusion rule; review is independent of authorization status."""

    id: str
    target: Target
    scope_status: ScopeStatus
    ownership_confidence: OwnershipConfidence = OwnershipConfidence.UNKNOWN
    review_required: bool = False
    source: str = "manual"
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _validate_id(self.id, SCOPE_RULE_ID_PATTERN, "scope rule id"))
        object.__setattr__(self, "scope_status", _enum_value(ScopeStatus, self.scope_status, "scope status"))
        object.__setattr__(
            self,
            "ownership_confidence",
            _enum_value(OwnershipConfidence, self.ownership_confidence, "ownership confidence"),
        )
        if self.scope_status is ScopeStatus.DENIED and self.review_required:
            raise ScopeValidationError("denied rules cannot also require review")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ScopeRule:
        target = data.get("target")
        if not isinstance(target, Mapping):
            raise ScopeValidationError("scope rule target must be an object")
        return cls(
            id=str(data.get("id", "")),
            target=Target.from_mapping(target),
            scope_status=data.get("scope_status", ""),
            ownership_confidence=data.get("ownership_confidence", "unknown"),
            review_required=bool(data.get("review_required", False)),
            source=str(data.get("source", "manual")),
            notes=str(data.get("notes", "")),
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "id": self.id,
            "target": self.target.to_mapping(),
            "scope_status": self.scope_status.value,
            "ownership_confidence": self.ownership_confidence.value,
            "review_required": self.review_required,
            "source": self.source,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class ScopeDocument:
    target_sets: tuple[TargetSet, ...] = ()
    rules: tuple[ScopeRule, ...] = ()
    kind: str = SCOPE_KIND
    schema_version: int = SCOPE_SCHEMA_VERSION

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> ScopeDocument:
        if data.get("kind") != SCOPE_KIND:
            raise ScopeValidationError(f"kind must be {SCOPE_KIND!r}")
        if data.get("schema_version") != SCOPE_SCHEMA_VERSION:
            raise ScopeValidationError(
                f"unsupported scope schema version: {data.get('schema_version')!r}"
            )
        target_sets = data.get("target_sets", [])
        rules = data.get("rules", [])
        if not isinstance(target_sets, list) or not isinstance(rules, list):
            raise ScopeValidationError("target_sets and rules must be lists")
        document = cls(
            target_sets=tuple(TargetSet.from_mapping(item) for item in target_sets if isinstance(item, Mapping)),
            rules=tuple(ScopeRule.from_mapping(item) for item in rules if isinstance(item, Mapping)),
        )
        document._validate_unique_ids()
        return document

    def _validate_unique_ids(self) -> None:
        for label, identifiers in (
            ("target set", [item.id for item in self.target_sets]),
            ("scope rule", [item.id for item in self.rules]),
        ):
            if len(identifiers) != len(set(identifiers)):
                raise ScopeValidationError(f"duplicate {label} id")

    def to_mapping(self) -> dict[str, object]:
        self._validate_unique_ids()
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "target_sets": [item.to_mapping() for item in self.target_sets],
            "rules": [item.to_mapping() for item in self.rules],
        }

    def get_target_set(self, target_set_id: str) -> TargetSet:
        try:
            return next(item for item in self.target_sets if item.id == target_set_id)
        except StopIteration as error:
            raise KeyError(target_set_id) from error


@dataclass(frozen=True, slots=True)
class TargetSelection:
    """Targets chosen directly or through a reusable project target set."""

    source: TargetSource
    targets: tuple[Target, ...]
    target_set_id: str | None = None
    target_set_name: str | None = None

    @classmethod
    def direct(cls, targets: Iterable[Target]) -> TargetSelection:
        return cls(source=TargetSource.DIRECT, targets=tuple(targets))

    @classmethod
    def saved(cls, target_set: TargetSet) -> TargetSelection:
        return cls(
            source=TargetSource.TARGET_SET,
            targets=target_set.targets,
            target_set_id=target_set.id,
            target_set_name=target_set.name,
        )


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Immutable launch-time context captured later in each run manifest."""

    selection: TargetSelection
    project_id: str | None = None
    project_name: str | None = None
    scope_enforced: bool = False

    def __post_init__(self) -> None:
        if (self.project_id is None) != (self.project_name is None):
            raise ScopeValidationError("project id and name must either both be set or both be absent")
        if self.selection.source is TargetSource.TARGET_SET and self.project_id is None:
            raise ScopeValidationError("saved project target sets require a project context")
