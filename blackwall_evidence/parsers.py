"""Native artifact parsers for Blackwall's supported discovery tools."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from ipaddress import ip_address
import json
from pathlib import Path
import sqlite3
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


@dataclass(frozen=True, slots=True)
class _OamEntity:
    entity_id: int
    kind: AssetKind
    value: str
    observed_at: str | None
    metadata: Mapping[str, object]


class AmassOamSqliteParser:
    """Read Amass v5's native OAM SQLite graph without modifying it."""

    key = "amass"
    _TABLES: Mapping[str, tuple[AssetKind, tuple[str, ...]]] = {
        "fqdn": (AssetKind.DOMAIN, ("fqdn",)),
        "domainrecord": (AssetKind.DOMAIN, ("domain", "record_name")),
        "ipaddress": (AssetKind.HOST, ("ip_address",)),
        "netblock": (AssetKind.CIDR, ("netblock_cidr",)),
        "organization": (AssetKind.ORGANIZATION, ("org_name", "legal_name", "unique_id")),
        "autonomoussystem": (AssetKind.AUTONOMOUS_SYSTEM, ("asn",)),
        "autnumrecord": (AssetKind.AUTONOMOUS_SYSTEM, ("asn", "handle")),
        "service": (AssetKind.SERVICE, ("unique_id", "service_type")),
        "url": (AssetKind.URL, ("raw_url",)),
        "product": (AssetKind.TECHNOLOGY, ("product_name", "unique_id")),
    }

    def parse(self, path: Path, *, run_id: str | None = None) -> tuple[ParsedRecord, ...]:
        artifact = Path(path).resolve()
        if not artifact.is_file():
            raise ValueError(f"Amass asset database does not exist: {artifact}")
        uri = artifact.as_uri() + "?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if "entity" in tables:
                entities = self._graph_entities(connection, tables)
                references = self._graph_references(connection, tables, entities)
            else:
                entities = self._legacy_entities(connection, tables)
                references = {}
        except sqlite3.Error as error:
            raise ValueError(f"cannot read Amass OAM database: {artifact}") from error
        finally:
            if "connection" in locals():
                connection.close()
        return tuple(
            ParsedRecord(
                entity.kind, entity.value, self.key, run_id=run_id,
                artifact_path=_artifact_name(artifact), observed_at=entity.observed_at,
                metadata=dict(entity.metadata), related=references.get(entity.entity_id, ()),
            )
            for entity in entities.values()
        )

    def _graph_entities(
        self, connection: sqlite3.Connection, tables: set[str]
    ) -> dict[int, _OamEntity]:
        tags = self._tags(connection, tables, "entity")
        entities: dict[int, _OamEntity] = {}
        rows = connection.execute(
            "SELECT entity_id, created_at, updated_at, natural_key, table_name, row_id FROM entity"
        ).fetchall()
        for entity_row in rows:
            table = str(entity_row["table_name"]).casefold()
            definition = self._TABLES.get(table)
            if definition is None or table not in tables:
                continue
            columns = {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}
            selected = [column for column in definition[1] if column in columns]
            asset_row = connection.execute(
                f'SELECT * FROM "{table}" WHERE id = ?', (entity_row["row_id"],)
            ).fetchone()
            if asset_row is None:
                continue
            value = next((str(asset_row[column]) for column in selected if asset_row[column] not in (None, "")), "")
            if not value:
                value = str(entity_row["natural_key"] or "")
            kind = definition[0]
            if table == "ipaddress":
                kind = _host_kind(value)
            elif table in {"autonomoussystem", "autnumrecord"} and not value.upper().startswith("AS"):
                value = f"AS{value}"
            elif table == "service" and "service_type" in columns:
                value = f"{asset_row['service_type']}:{value}"
            metadata: dict[str, object] = {
                "oam_entity_id": entity_row["entity_id"], "oam_table": table,
                "oam_natural_key": entity_row["natural_key"],
            }
            if "attrs" in columns and asset_row["attrs"]:
                metadata["oam_attrs"] = self._json_object(asset_row["attrs"])
            if entity_row["entity_id"] in tags:
                metadata["oam_tags"] = tags[entity_row["entity_id"]]
            entities[int(entity_row["entity_id"])] = _OamEntity(
                int(entity_row["entity_id"]), kind, value,
                entity_row["updated_at"] or entity_row["created_at"], metadata,
            )
        return entities

    def _graph_references(
        self, connection: sqlite3.Connection, tables: set[str], entities: Mapping[int, _OamEntity]
    ) -> dict[int, tuple[AssetReference, ...]]:
        if "edge" not in tables:
            return {}
        tags = self._tags(connection, tables, "edge")
        edge_type_join = (
            "LEFT JOIN edge_type_lu t ON t.id = e.etype_id" if "edge_type_lu" in tables else ""
        )
        edge_type_column = "t.name AS edge_type" if edge_type_join else "NULL AS edge_type"
        rows = connection.execute(
            f"SELECT e.*, {edge_type_column} FROM edge e {edge_type_join}"
        ).fetchall()
        references: dict[int, list[AssetReference]] = defaultdict(list)
        for row in rows:
            source = entities.get(int(row["from_entity_id"]))
            target = entities.get(int(row["to_entity_id"]))
            if source is None or target is None:
                continue
            content = self._json_object(row["content"])
            edge_tags = tags.get(int(row["edge_id"]), ())
            confidence = str(content.get("confidence") or self._tag_value(edge_tags, "confidence") or "observed")
            relation = str(row["label"] or row["edge_type"] or "related_to")
            references[source.entity_id].append(AssetReference(
                target.kind, target.value, relation, confidence,
                {
                    "oam_edge_id": row["edge_id"], "oam_edge_type": row["edge_type"],
                    "oam_content": content, "oam_tags": edge_tags,
                },
            ))
        return {key: tuple(value) for key, value in references.items()}

    def _legacy_entities(
        self, connection: sqlite3.Connection, tables: set[str]
    ) -> dict[int, _OamEntity]:
        entities: dict[int, _OamEntity] = {}
        synthetic_id = 0
        for table, (configured_kind, candidates) in self._TABLES.items():
            if table not in tables:
                continue
            columns = {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}
            value_column = next((column for column in candidates if column in columns), None)
            if value_column is None:
                continue
            for row in connection.execute(f'SELECT * FROM "{table}"'):
                value = str(row[value_column] or "").strip()
                if not value:
                    continue
                synthetic_id += 1
                kind = _host_kind(value) if table == "ipaddress" else configured_kind
                if table in {"autonomoussystem", "autnumrecord"} and not value.upper().startswith("AS"):
                    value = f"AS{value}"
                entities[synthetic_id] = _OamEntity(
                    synthetic_id, kind, value,
                    row["updated_at"] if "updated_at" in columns else None,
                    {"oam_table": table, "legacy_schema": True},
                )
        return entities

    def _tags(
        self, connection: sqlite3.Connection, tables: set[str], target: str
    ) -> dict[int, tuple[dict[str, object], ...]]:
        table = f"{target}_tag"
        key = f"{target}_id"
        if table not in tables:
            return {}
        type_join = (
            f"LEFT JOIN tag_type_lu t ON t.id = x.ttype_id" if "tag_type_lu" in tables else ""
        )
        type_column = "t.name AS tag_type" if type_join else "NULL AS tag_type"
        grouped: dict[int, list[dict[str, object]]] = defaultdict(list)
        for row in connection.execute(
            f"SELECT x.*, {type_column} FROM {table} x {type_join}"
        ):
            grouped[int(row[key])].append({
                "type": row["tag_type"], "name": row["property_name"],
                "value": row["property_value"],
                "content": self._json_object(row["content"]),
            })
        return {key: tuple(value) for key, value in grouped.items()}

    @staticmethod
    def _tag_value(tags: Iterable[Mapping[str, object]], name: str) -> object | None:
        return next((tag.get("value") for tag in tags if tag.get("name") == name), None)

    @staticmethod
    def _json_object(value: object) -> dict[str, object]:
        if not value:
            return {}
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError):
            return {"raw": str(value)}
        return parsed if isinstance(parsed, dict) else {"value": parsed}


class ParserRegistry:
    def __init__(self, parsers: tuple[EvidenceParser, ...] = ()) -> None:
        self._parsers = {parser.key: parser for parser in parsers}

    @classmethod
    def native(cls) -> "ParserRegistry":
        return cls((
            AmassOamSqliteParser(), DnsxJsonlParser(), NmapXmlParser(),
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
