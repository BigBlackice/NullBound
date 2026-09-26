"""Native artifact parsers for Blackwall's supported discovery tools."""

from __future__ import annotations

from ipaddress import ip_address
import json
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Protocol
from urllib.parse import urlsplit
import xml.etree.ElementTree as ElementTree

from .models import AssetKind, AssetReference, ParsedRecord


class EvidenceParser(Protocol):
    key: str

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]: ...


def _artifact_name(path: Path) -> str:
    return path.name if path.is_absolute() else path.as_posix()


def _values(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    text = str(value).strip()
    return (text,) if text else ()


def _host_kind(value: str) -> AssetKind:
    candidate = value.strip().strip("[]")
    try:
        address = ip_address(candidate)
    except ValueError:
        return AssetKind.DOMAIN
    return AssetKind.IPV4 if address.version == 4 else AssetKind.IPV6


def _json_metadata(data: Mapping[str, object], keys: Iterable[str]) -> dict[str, object]:
    return {key: data[key] for key in keys if key in data and data[key] not in (None, "", [], {})}


def _dedupe_references(items: Iterable[AssetReference]) -> tuple[AssetReference, ...]:
    seen: set[tuple[AssetKind, str, str]] = set()
    records: list[AssetReference] = []
    for item in items:
        identity = (item.kind, item.value, item.relation)
        if identity not in seen:
            seen.add(identity)
            records.append(item)
    return tuple(records)


def _json_lines(path: Path) -> Iterator[tuple[int, Mapping[str, object]]]:
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        lines = stream.readlines()
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as error:
                # Cancelled/timed-out tools can leave one unterminated tail record.
                # Keep every complete record before it; a malformed complete line
                # still fails loudly because it indicates an incompatible schema.
                if line_number == len(lines) and not line.endswith(("\n", "\r")):
                    continue
                raise ValueError(f"invalid JSONL record at line {line_number}") from error
            if isinstance(data, str):
                data = {"url": data}
            if not isinstance(data, dict):
                raise ValueError(f"JSONL record at line {line_number} is not an object")
            yield line_number, data


class JsonLinesEnvelopeParser:
    """Parse Blackwall-neutral JSONL for imports and extension adapters."""

    key = "blackwall-jsonl"

    def __init__(self, source: str) -> None:
        self.source = source

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path)
        records: list[ParsedRecord] = []
        for line_number, data in _json_lines(artifact):
            try:
                related = tuple(
                    AssetReference(
                        kind=AssetKind(item["kind"]), value=str(item["value"]),
                        relation=str(item.get("relation", "related_to")),
                        confidence=str(item.get("confidence", "observed")),
                        metadata=dict(item.get("metadata", {})),
                    )
                    for item in data.get("related", ())
                )
                records.append(ParsedRecord(
                    kind=AssetKind(data["kind"]), value=str(data["value"]),
                    source=str(data.get("source", self.source)), run_id=run_id,
                    artifact_path=_artifact_name(artifact),
                    observed_at=data.get("observed_at"),
                    metadata=dict(data.get("metadata", {})), related=related,
                ))
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"invalid evidence JSONL record at line {line_number}") from error
        return tuple(records)


class SubfinderJsonlParser:
    """Parse Subfinder's compact source-attributed JSONL output."""

    key = "subfinder"

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path)
        records: list[ParsedRecord] = []
        for line_number, data in _json_lines(artifact):
            host = str(data.get("host") or data.get("value") or "").strip()
            if not host:
                raise ValueError(
                    f"subfinder JSONL record at line {line_number} has no host"
                )
            sources = _values(data.get("sources") or data.get("source"))
            metadata = _json_metadata(data, ("input", "timestamp"))
            if sources:
                metadata["sources"] = sources
            records.append(ParsedRecord(
                _host_kind(host), host, self.key, run_id=run_id,
                artifact_path=_artifact_name(artifact),
                observed_at=data.get("timestamp"), metadata=metadata,
            ))
        return tuple(records)


class DnsxJsonlParser:
    key = "dnsx"

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path)
        records: list[ParsedRecord] = []
        for line_number, data in _json_lines(artifact):
            host = str(data.get("host") or data.get("input") or "").strip()
            if not host:
                raise ValueError(f"dnsx JSONL record at line {line_number} has no host")
            related: list[AssetReference] = []
            for field in ("a", "aaaa", "ip"):
                related.extend(
                    AssetReference(_host_kind(value), value, "resolves_to")
                    for value in _values(data.get(field))
                )
            for field, relation in (
                ("cname", "aliases_to"), ("ns", "uses_nameserver"),
                ("mx", "routes_mail_to"), ("ptr", "reverse_resolves_to"),
            ):
                related.extend(
                    AssetReference(_host_kind(value), value, relation)
                    for value in _values(data.get(field))
                )
            records.append(ParsedRecord(
                _host_kind(host), host, self.key, run_id=run_id,
                artifact_path=_artifact_name(artifact), observed_at=data.get("timestamp"),
                metadata=_json_metadata(data, (
                    "status_code", "resolver", "ttl", "asn", "cdn-name", "cdn-type",
                    "query-time",
                )),
                related=_dedupe_references(related),
            ))
        return tuple(records)


class HttpxJsonlParser:
    key = "httpx"

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path)
        records: list[ParsedRecord] = []
        for line_number, data in _json_lines(artifact):
            url = str(data.get("url") or data.get("final_url") or "").strip()
            if not url:
                host = str(data.get("input") or data.get("host") or "").strip()
                scheme = str(data.get("scheme") or "https")
                port = str(data.get("port") or "").strip()
                if not host:
                    raise ValueError(f"httpx JSONL record at line {line_number} has no URL or host")
                url = f"{scheme}://{host}{':' + port if port else ''}/"
            related: list[AssetReference] = []
            for field in ("a", "aaaa", "ip"):
                related.extend(
                    AssetReference(_host_kind(value), value, "resolves_to")
                    for value in _values(data.get(field))
                )
            related.extend(
                AssetReference(AssetKind.DOMAIN, value, "aliases_to")
                for value in _values(data.get("cname"))
            )
            related.extend(
                AssetReference(AssetKind.TECHNOLOGY, value, "uses_technology")
                for value in _values(data.get("tech"))
            )
            records.append(ParsedRecord(
                AssetKind.URL, url, self.key, run_id=run_id,
                artifact_path=_artifact_name(artifact), observed_at=data.get("timestamp"),
                metadata=_json_metadata(data, (
                    "input", "status_code", "title", "webserver", "content_type", "method",
                    "port", "scheme", "location", "time", "failed", "cdn_name", "cdn_type",
                )), related=_dedupe_references(related),
            ))
        return tuple(records)


class GauJsonlParser:
    key = "gau"

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path)
        records: list[ParsedRecord] = []
        for line_number, data in _json_lines(artifact):
            url = str(data.get("url") or data.get("value") or "").strip()
            if not url:
                raise ValueError(f"gau JSONL record at line {line_number} has no URL")
            records.append(ParsedRecord(
                AssetKind.URL, url, self.key, run_id=run_id,
                artifact_path=_artifact_name(artifact),
                observed_at=data.get("timestamp") or data.get("date"),
                metadata=_json_metadata(data, ("source", "status", "mime", "method")),
            ))
        return tuple(records)


class TlsxJsonlParser:
    key = "tlsx"

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path)
        records: list[ParsedRecord] = []
        for line_number, data in _json_lines(artifact):
            host = str(data.get("host") or data.get("input") or data.get("ip") or "").strip()
            if not host:
                raise ValueError(f"tlsx JSONL record at line {line_number} has no host")
            port = str(data.get("port") or "443").strip()
            related: list[AssetReference] = []
            for value in _values(data.get("ip")):
                if value != host:
                    related.append(AssetReference(_host_kind(value), value, "resolves_to"))
            for field in ("subject_cn", "subject_an", "dns_names", "san"):
                related.extend(
                    AssetReference(_host_kind(value), value, "certificate_names")
                    for value in _values(data.get(field))
                    if "@" not in value and "*" not in value
                )
            related.append(AssetReference(
                AssetKind.SERVICE, f"tls://{host}:{port}", "exposes_service"
            ))
            records.append(ParsedRecord(
                _host_kind(host), host, self.key, run_id=run_id,
                artifact_path=_artifact_name(artifact), observed_at=data.get("timestamp"),
                metadata=_json_metadata(data, (
                    "port", "probe_status", "tls_version", "cipher", "serial", "not_before",
                    "not_after", "issuer_cn", "subject_cn", "self_signed", "mismatched",
                    "expired", "revoked", "untrusted", "jarm_hash", "ja3_hash",
                )), related=_dedupe_references(related),
            ))
        return tuple(records)


class NmapXmlParser:
    key = "nmap"

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path)
        records: list[ParsedRecord] = []
        try:
            iterator = ElementTree.iterparse(artifact, events=("end",))
            for _, element in iterator:
                if element.tag != "host":
                    continue
                addresses = tuple(
                    item.get("addr", "") for item in element.findall("address")
                    if item.get("addr") and item.get("addrtype") in {"ipv4", "ipv6"}
                )
                hostnames = tuple(
                    item.get("name", "") for item in element.findall("hostnames/hostname")
                    if item.get("name")
                )
                primary = addresses[0] if addresses else (hostnames[0] if hostnames else "")
                if not primary:
                    element.clear()
                    continue
                related = tuple(
                    AssetReference(_host_kind(name), name, "has_hostname") for name in hostnames
                )
                status = element.find("status")
                records.append(ParsedRecord(
                    _host_kind(primary), primary, self.key, run_id=run_id,
                    artifact_path=_artifact_name(artifact),
                    metadata={"state": status.get("state")} if status is not None else {},
                    related=related,
                ))
                for port in element.findall("ports/port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    protocol = port.get("protocol", "tcp")
                    port_id = port.get("portid", "")
                    service = port.find("service")
                    metadata = {
                        "host": primary, "protocol": protocol, "port": port_id,
                        **({key: service.get(key) for key in (
                            "name", "product", "version", "extrainfo", "tunnel",
                        ) if service is not None and service.get(key)}),
                    }
                    service_related = [
                        AssetReference(_host_kind(primary), primary, "runs_on")
                    ]
                    if service is not None:
                        technology = " ".join(filter(None, (
                            service.get("product"), service.get("version"),
                        ))).strip()
                        if technology:
                            service_related.append(AssetReference(
                                AssetKind.TECHNOLOGY, technology, "uses_technology"
                            ))
                    records.append(ParsedRecord(
                        AssetKind.SERVICE, f"{protocol}://{primary}:{port_id}", self.key,
                        run_id=run_id, artifact_path=_artifact_name(artifact),
                        metadata=metadata, related=tuple(service_related),
                    ))
                element.clear()
        except ElementTree.ParseError as error:
            if records:
                return tuple(records)
            raise ValueError(f"invalid Nmap XML: {artifact}") from error
        return tuple(records)


class ParserRegistry:
    def __init__(self, parsers: tuple[EvidenceParser, ...] = ()) -> None:
        self._parsers = {parser.key: parser for parser in parsers}

    @classmethod
    def native(cls) -> "ParserRegistry":
        return cls((
            SubfinderJsonlParser(), DnsxJsonlParser(), NmapXmlParser(),
            HttpxJsonlParser(), GauJsonlParser(), TlsxJsonlParser(),
        ))

    def register(self, parser: EvidenceParser) -> None:
        if parser.key in self._parsers:
            raise ValueError(f"parser already registered: {parser.key}")
        self._parsers[parser.key] = parser

    def get(self, key: str) -> EvidenceParser:
        try:
            return self._parsers[key.casefold()]
        except KeyError as error:
            raise KeyError(f"unknown evidence parser: {key}") from error
