"""Repositories for assets, evidence, findings, scope, and relationships."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import sqlite3
from uuid import uuid4

from blackwall_scope import ScopeDocument, Target, TargetKind, evaluate_target

from .database import ProjectDatabase
from .models import (
    AssetKind,
    AssetRecord,
    EvidenceKind,
    EvidenceRecord,
    FindingRecord,
    FindingSeverity,
    FindingState,
    NormalizedRecord,
    ParsedFinding,
    RelationshipRecord,
    ScopeDisposition,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def stable_id(prefix: str, *parts: object) -> str:
    payload = "\0".join(str(part) for part in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:12].upper()}"


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _decoded(value: str) -> object:
    return json.loads(value)


def _portable_artifact_path(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("artifact path must be project-relative and cannot traverse parents")
    return path.as_posix()


class EvidenceStore:
    """High-level access to one project's searchable evidence index."""

    def __init__(self, project_path: Path) -> None:
        self.database = ProjectDatabase(project_path)
        self.database.initialize()

    def recover_incomplete(self) -> int:
        return self.database.recover_incomplete_batches(utc_now())

    def sync_scope(self, document: ScopeDocument) -> int:
        """Mirror portable scope.json rules and re-evaluate indexed assets."""
        synced_at = utc_now()
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM target_set_members")
            connection.execute("DELETE FROM target_sets")
            connection.execute("DELETE FROM scope_rules")
            for target_set in document.target_sets:
                connection.execute(
                    "INSERT INTO target_sets VALUES (?, ?, ?, ?)",
                    (target_set.id, target_set.name, target_set.description, synced_at),
                )
                for ordinal, target in enumerate(target_set.targets):
                    connection.execute(
                        "INSERT INTO target_set_members VALUES (?, ?, ?, ?, ?)",
                        (target_set.id, ordinal, target.kind.value, target.value, target.normalized),
                    )
            for rule in document.rules:
                connection.execute(
                    """INSERT INTO scope_rules (
                        id, target_kind, original_target, normalized_target, scope_status,
                        ownership_confidence, review_required, source, notes, synced_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        rule.id, rule.target.kind.value, rule.target.value, rule.target.normalized,
                        rule.scope_status.value, rule.ownership_confidence.value,
                        int(rule.review_required), rule.source, rule.notes, synced_at,
                    ),
                )
            rows = connection.execute(
                "SELECT id, kind, original_value FROM assets"
            ).fetchall()
            for row in rows:
                scope, ownership, review, matched = self._scope_for(
                    AssetKind(row["kind"]), row["original_value"], document
                )
                connection.execute(
                    """UPDATE assets SET scope_disposition = ?, ownership_confidence = ?,
                       review_required = ?, matched_rule_id = ? WHERE id = ?""",
                    (scope.value, ownership, int(review), matched, row["id"]),
                )
        return len(document.rules)

    @staticmethod
    def _scope_for(
        kind: AssetKind,
        value: str,
        document: ScopeDocument,
    ) -> tuple[ScopeDisposition, str, bool, str | None]:
        target_kind = {
            AssetKind.DOMAIN: TargetKind.DOMAIN,
            AssetKind.IPV4: TargetKind.IPV4,
            AssetKind.IPV6: TargetKind.IPV6,
            AssetKind.CIDR: TargetKind.CIDR,
            AssetKind.URL: TargetKind.URL,
        }.get(kind)
        if target_kind is None:
            return ScopeDisposition.UNMATCHED, "unknown", True, None
        try:
            evaluation = evaluate_target(Target(target_kind, value), document.rules, enforce=False)
        except Exception:
            return ScopeDisposition.UNMATCHED, "unknown", True, None
        if evaluation.scope_status is None:
            disposition = ScopeDisposition.UNMATCHED
        elif evaluation.scope_status.value == "denied":
            disposition = ScopeDisposition.DENIED
        elif evaluation.review_required:
            disposition = ScopeDisposition.REVIEW
        else:
            disposition = ScopeDisposition.ALLOWED
        return (
            disposition,
            evaluation.ownership_confidence.value,
            evaluation.review_required or disposition is ScopeDisposition.UNMATCHED,
            evaluation.matched_rule.id if evaluation.matched_rule else None,
        )

    def begin_batch(self, parser: str, source: str) -> str:
        batch_id = f"IB-{uuid4().hex[:12].upper()}"
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO ingestion_batches VALUES (?, ?, ?, 'running', ?, NULL, NULL)",
                (batch_id, parser, source, utc_now()),
            )
        return batch_id

    def finish_batch(self, batch_id: str, error: str | None = None) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """UPDATE ingestion_batches SET status = ?, finished_at = ?, error = ?
                   WHERE id = ?""",
                ("failed" if error else "completed", utc_now(), error, batch_id),
            )

    def put_asset(
        self,
        record: NormalizedRecord,
        scope_document: ScopeDocument,
        *,
        evidence_kind: EvidenceKind = EvidenceKind.OBSERVATION,
        batch_id: str | None = None,
    ) -> tuple[AssetRecord, EvidenceRecord, bool, bool]:
        observed_at = record.observed_at or utc_now()
        asset_id = stable_id("AS", record.kind.value, record.normalized_key)
        evidence_id = stable_id(
            "EV", record.kind.value, record.normalized_key, record.source,
            record.run_id or "", record.artifact_path or "", record.raw_value,
        )
        artifact_path = _portable_artifact_path(record.artifact_path)
        scope, ownership, review, matched = self._scope_for(
            record.kind, record.raw_value, scope_document
        )
        with self.database.transaction() as connection:
            asset_exists = connection.execute(
                "SELECT 1 FROM assets WHERE id = ?", (asset_id,)
            ).fetchone() is not None
            connection.execute(
                """INSERT INTO assets (
                    id, kind, original_value, normalized_key, normalization_version,
                    transformations_json, display_name, scope_disposition,
                    ownership_confidence, review_required, matched_rule_id, metadata_json,
                    first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(kind, normalized_key) DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    scope_disposition = excluded.scope_disposition,
                    ownership_confidence = excluded.ownership_confidence,
                    review_required = excluded.review_required,
                    matched_rule_id = excluded.matched_rule_id""",
                (
                    asset_id, record.kind.value, record.raw_value, record.normalized_key,
                    record.normalization_version, _json(record.transformations),
                    record.raw_value, scope.value, ownership, int(review), matched,
                    _json(dict(record.metadata)), observed_at, observed_at,
                ),
            )
            evidence_exists = connection.execute(
                "SELECT 1 FROM evidence_records WHERE id = ?", (evidence_id,)
            ).fetchone() is not None
            connection.execute(
                """INSERT INTO evidence_records (
                    id, kind, asset_id, finding_id, source, raw_value, normalized_key,
                    normalization_version, transformations_json, run_id, batch_id, artifact_path,
                    observed_at, integrity_status, metadata_json
                ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'recorded', ?)
                ON CONFLICT(id) DO UPDATE SET observed_at = excluded.observed_at""",
                (
                    evidence_id, evidence_kind.value, asset_id, record.source,
                    record.raw_value, record.normalized_key, record.normalization_version,
                    _json(record.transformations), record.run_id, batch_id, artifact_path,
                    observed_at, _json(dict(record.metadata)),
                ),
            )
        return self.get_asset(asset_id), self.get_evidence(evidence_id), not asset_exists, not evidence_exists

    def put_finding(
        self,
        finding: ParsedFinding,
        asset_id: str | None,
        batch_id: str | None = None,
    ) -> tuple[FindingRecord, bool]:
        observed_at = finding.observed_at or utc_now()
        fingerprint = finding.fingerprint or stable_id(
            "FP", finding.source.casefold(), finding.title.casefold(), asset_id or "",
            finding.location.casefold(),
        )
        finding_id = stable_id("FW", fingerprint)
        with self.database.transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone() is not None
            connection.execute(
                """INSERT INTO findings (
                    id, fingerprint, title, severity, lifecycle_state, confidence,
                    asset_id, location, description, evidence, recommendation, source,
                    run_id, batch_id, first_seen_at, last_seen_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    evidence = excluded.evidence,
                    metadata_json = excluded.metadata_json""",
                (
                    finding_id, fingerprint, finding.title, finding.severity.value,
                    finding.state.value, finding.confidence, asset_id, finding.location,
                    finding.description, finding.evidence, finding.recommendation,
                    finding.source, finding.run_id, batch_id, observed_at, observed_at,
                    _json(dict(finding.metadata)),
                ),
            )
        return self.get_finding(finding_id), not exists

    def put_relationship(
        self,
        source_type: str,
        source_id: str,
        target_type: str,
        target_id: str,
        relation: str,
        *,
        evidence_id: str | None = None,
        confidence: str = "observed",
        metadata: dict[str, object] | None = None,
    ) -> tuple[RelationshipRecord, bool]:
        relationship_id = stable_id(
            "RL", source_type, source_id, target_type, target_id, relation
        )
        created_at = utc_now()
        with self.database.transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM relationships WHERE id = ?", (relationship_id,)
            ).fetchone() is not None
            connection.execute(
                """INSERT INTO relationships (
                    id, source_type, source_id, target_type, target_id, relation,
                    evidence_id, confidence, created_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_type, source_id, target_type, target_id, relation)
                DO UPDATE SET evidence_id = COALESCE(excluded.evidence_id, evidence_id),
                              confidence = excluded.confidence,
                              metadata_json = excluded.metadata_json""",
                (
                    relationship_id, source_type, source_id, target_type, target_id,
                    relation, evidence_id, confidence, created_at, _json(metadata or {}),
                ),
            )
        return self.get_relationship(relationship_id), not exists

    def list_assets(
        self,
        query: str = "",
        *,
        include_denied: bool = False,
    ) -> tuple[AssetRecord, ...]:
        conditions: list[str] = []
        values: list[object] = []
        if not include_denied:
            conditions.append("scope_disposition != 'denied'")
        if query:
            conditions.append("(display_name LIKE ? OR normalized_key LIKE ? OR kind LIKE ?)")
            needle = f"%{query}%"
            values.extend((needle, needle, needle))
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        with self.database.read() as connection:
            rows = connection.execute(
                f"SELECT * FROM assets{where} ORDER BY last_seen_at DESC, id", values
            ).fetchall()
        return tuple(self._asset(row) for row in rows)

    def list_scope_review_assets(self) -> tuple[AssetRecord, ...]:
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT * FROM assets
                   WHERE scope_disposition IN ('denied', 'review', 'unmatched')
                   ORDER BY last_seen_at DESC"""
            ).fetchall()
        return tuple(self._asset(row) for row in rows)

    def list_findings(
        self,
        query: str = "",
        *,
        include_denied: bool = False,
    ) -> tuple[FindingRecord, ...]:
        conditions: list[str] = []
        values: list[object] = []
        if not include_denied:
            conditions.append("(a.scope_disposition IS NULL OR a.scope_disposition != 'denied')")
        if query:
            conditions.append("(f.title LIKE ? OR f.location LIKE ? OR f.source LIKE ?)")
            needle = f"%{query}%"
            values.extend((needle, needle, needle))
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT f.*, COALESCE(a.display_name, '') AS asset_name
                   FROM findings f LEFT JOIN assets a ON a.id = f.asset_id"""
                + where + " ORDER BY f.last_seen_at DESC, f.id",
                values,
            ).fetchall()
        return tuple(self._finding(row) for row in rows)

    def list_evidence(
        self,
        *,
        asset_id: str | None = None,
        include_denied: bool = False,
    ) -> tuple[EvidenceRecord, ...]:
        conditions: list[str] = []
        values: list[object] = []
        if asset_id:
            conditions.append("e.asset_id = ?")
            values.append(asset_id)
        if not include_denied:
            conditions.append("(a.scope_disposition IS NULL OR a.scope_disposition != 'denied')")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT e.* FROM evidence_records e
                   LEFT JOIN assets a ON a.id = e.asset_id"""
                + where + " ORDER BY e.observed_at DESC, e.id",
                values,
            ).fetchall()
        return tuple(self._evidence(row) for row in rows)

    def list_relationships(self, object_id: str | None = None) -> tuple[RelationshipRecord, ...]:
        where = ""
        values: tuple[object, ...] = ()
        if object_id:
            where = " WHERE source_id = ? OR target_id = ?"
            values = (object_id, object_id)
        with self.database.read() as connection:
            rows = connection.execute(
                "SELECT * FROM relationships" + where + " ORDER BY created_at DESC", values
            ).fetchall()
        return tuple(self._relationship(row) for row in rows)

    def list_scope_rules(self) -> tuple[dict[str, object], ...]:
        with self.database.read() as connection:
            rows = connection.execute(
                "SELECT * FROM scope_rules ORDER BY id DESC"
            ).fetchall()
        return tuple(dict(row) for row in rows)

    def get_asset(self, asset_id: str) -> AssetRecord:
        with self.database.read() as connection:
            row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if row is None:
            raise KeyError(asset_id)
        return self._asset(row)

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM evidence_records WHERE id = ?", (evidence_id,)
            ).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        return self._evidence(row)

    def get_finding(self, finding_id: str) -> FindingRecord:
        with self.database.read() as connection:
            row = connection.execute(
                """SELECT f.*, COALESCE(a.display_name, '') AS asset_name
                   FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
                   WHERE f.id = ?""",
                (finding_id,),
            ).fetchone()
        if row is None:
            raise KeyError(finding_id)
        return self._finding(row)

    def get_relationship(self, relationship_id: str) -> RelationshipRecord:
        with self.database.read() as connection:
            row = connection.execute(
                "SELECT * FROM relationships WHERE id = ?", (relationship_id,)
            ).fetchone()
        if row is None:
            raise KeyError(relationship_id)
        return self._relationship(row)

    @staticmethod
    def _asset(row: sqlite3.Row) -> AssetRecord:
        return AssetRecord(
            id=row["id"], kind=AssetKind(row["kind"]), original_value=row["original_value"],
            normalized_key=row["normalized_key"], display_name=row["display_name"],
            scope=ScopeDisposition(row["scope_disposition"]),
            ownership_confidence=row["ownership_confidence"],
            review_required=bool(row["review_required"]), matched_rule_id=row["matched_rule_id"],
            first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
            metadata=_decoded(row["metadata_json"]),
        )

    @staticmethod
    def _evidence(row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord(
            id=row["id"], kind=EvidenceKind(row["kind"]), asset_id=row["asset_id"],
            finding_id=row["finding_id"], source=row["source"], raw_value=row["raw_value"],
            normalized_key=row["normalized_key"], normalization_version=row["normalization_version"],
            transformations=tuple(_decoded(row["transformations_json"])), run_id=row["run_id"],
            batch_id=row["batch_id"], artifact_path=row["artifact_path"],
            observed_at=row["observed_at"],
            integrity_status=row["integrity_status"], metadata=_decoded(row["metadata_json"]),
        )

    @staticmethod
    def _finding(row: sqlite3.Row) -> FindingRecord:
        return FindingRecord(
            id=row["id"], fingerprint=row["fingerprint"], title=row["title"],
            severity=FindingSeverity(row["severity"]), state=FindingState(row["lifecycle_state"]),
            confidence=row["confidence"], asset_id=row["asset_id"], asset_name=row["asset_name"],
            location=row["location"], description=row["description"], evidence=row["evidence"],
            recommendation=row["recommendation"], source=row["source"], run_id=row["run_id"],
            batch_id=row["batch_id"],
            first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
            metadata=_decoded(row["metadata_json"]),
        )

    @staticmethod
    def _relationship(row: sqlite3.Row) -> RelationshipRecord:
        return RelationshipRecord(
            id=row["id"], source_type=row["source_type"], source_id=row["source_id"],
            target_type=row["target_type"], target_id=row["target_id"], relation=row["relation"],
            evidence_id=row["evidence_id"], confidence=row["confidence"],
            created_at=row["created_at"], metadata=_decoded(row["metadata_json"]),
        )
