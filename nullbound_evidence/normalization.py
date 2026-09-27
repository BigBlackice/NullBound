"""Conservative, versioned normalization for evidence identifiers."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

from nullbound_scope import ScopeValidationError, Target, TargetKind

from .models import AssetKind, NORMALIZATION_VERSION, NormalizedRecord, ParsedRecord


def normalize_value(kind: AssetKind, value: str) -> tuple[str, tuple[str, ...]]:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("asset value cannot be empty")

    normalized = raw
    if kind is AssetKind.DOMAIN:
        normalized = Target(TargetKind.DOMAIN, raw).normalized
    elif kind is AssetKind.IPV4:
        normalized = str(ip_address(raw))
        if ip_address(raw).version != 4:
            raise ValueError(f"asset is not ipv4: {raw}")
    elif kind is AssetKind.IPV6:
        normalized = str(ip_address(raw))
        if ip_address(raw).version != 6:
            raise ValueError(f"asset is not ipv6: {raw}")
    elif kind is AssetKind.CIDR:
        normalized = ip_network(raw, strict=False).with_prefixlen
    elif kind is AssetKind.URL:
        try:
            normalized = Target(TargetKind.URL, raw).normalized
        except ScopeValidationError as error:
            raise ValueError(str(error)) from error
    elif kind is AssetKind.HOST:
        normalized = raw.rstrip(".").casefold()
    elif kind is AssetKind.EMAIL:
        local, separator, domain = raw.rpartition("@")
        if not separator or not local or not domain:
            raise ValueError(f"invalid email asset: {raw}")
        normalized = f"{local}@{domain.casefold().rstrip('.')}"
    elif kind in {AssetKind.SERVICE, AssetKind.USERNAME}:
        normalized = raw.casefold()
    elif kind in {
        AssetKind.AUTONOMOUS_SYSTEM, AssetKind.ORGANIZATION, AssetKind.TECHNOLOGY,
    }:
        normalized = " ".join(raw.split()).casefold()

    transformations: list[str] = []
    if raw != normalized:
        transformations.append("canonicalized")
    if kind is AssetKind.URL:
        parsed_raw = urlsplit(raw)
        parsed_normalized = urlsplit(normalized)
        if parsed_raw.fragment:
            transformations.append("removed_fragment")
        if parsed_raw.scheme != parsed_normalized.scheme:
            transformations.append("lowercased_scheme")
        if parsed_raw.hostname and parsed_raw.hostname != parsed_normalized.hostname:
            transformations.append("lowercased_host")
        if not parsed_raw.path:
            transformations.append("added_root_path")
    return normalized, tuple(dict.fromkeys(transformations))


def normalize_record(record: ParsedRecord) -> NormalizedRecord:
    normalized, transformations = normalize_value(record.kind, record.value)
    return NormalizedRecord(
        kind=record.kind,
        raw_value=str(record.value).strip(),
        normalized_key=normalized,
        source=str(record.source).strip() or "unknown",
        normalization_version=NORMALIZATION_VERSION,
        transformations=transformations,
        run_id=record.run_id,
        artifact_path=record.artifact_path,
        observed_at=record.observed_at,
        metadata=dict(record.metadata),
        related=tuple(record.related),
    )
