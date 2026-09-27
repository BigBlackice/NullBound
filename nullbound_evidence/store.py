"""Repositories for assets, evidence, findings, scope, and relationships."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import sqlite3
from uuid import uuid4

from nullbound_scope import ScopeDocument, Target, TargetKind, evaluate_target

from .database import ProjectDatabase
from .models import (
    AssetKind,
    AssetRecord,
    EvidenceAnchorSummary,
    EvidenceAssetLink,
    EvidenceAssetSummary,
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

    def transaction(self):
        """Expose one project write transaction for an atomic ingestion batch."""
        return self.database.transaction()

    def _write_context(self, connection: sqlite3.Connection | None):
        return nullcontext(connection) if connection is not None else self.database.transaction()

    def change_token(self) -> tuple[tuple[int, int] | None, ...]:
        """Return a cheap token which changes when SQLite's database or WAL changes."""
        self.database.initialize()
        tokens: list[tuple[int, int] | None] = []
        for path in (self.database.path, self.database.path.with_name(f"{self.database.path.name}-wal")):
            try:
                stat = path.stat()
            except FileNotFoundError:
                tokens.append(None)
            else:
                tokens.append((stat.st_mtime_ns, stat.st_size))
        return tuple(tokens)

    def sync_scope(self, document: ScopeDocument) -> int:
        """Mirror portable scope.json rules and re-evaluate indexed assets."""
        synced_at = utc_now()
        with self.database.transaction() as connection:
            expected_sets = tuple(sorted(
                (item.id, item.name, item.description) for item in document.target_sets
            ))
            expected_members = tuple(sorted(
                (
                    target_set.id, ordinal, target.kind.value,
                    target.value, target.normalized,
                )
                for target_set in document.target_sets
                for ordinal, target in enumerate(target_set.targets)
            ))
            expected_rules = tuple(sorted(
                (
                    rule.id, rule.target.kind.value, rule.target.value,
                    rule.target.normalized, rule.scope_status.value,
                    rule.ownership_confidence.value, int(rule.review_required),
                    rule.source, rule.notes,
                )
                for rule in document.rules
            ))
            current_sets = tuple(tuple(row) for row in connection.execute(
                "SELECT id, name, description FROM target_sets ORDER BY id"
            ).fetchall())
            current_members = tuple(tuple(row) for row in connection.execute(
                """SELECT target_set_id, ordinal, target_kind, original_target,
                          normalized_target
                   FROM target_set_members ORDER BY target_set_id, ordinal"""
            ).fetchall())
            current_rules = tuple(tuple(row) for row in connection.execute(
                """SELECT id, target_kind, original_target, normalized_target,
                          scope_status, ownership_confidence, review_required,
                          source, notes
                   FROM scope_rules ORDER BY id"""
            ).fetchall())
            if (
                current_sets == expected_sets
                and current_members == expected_members
                and current_rules == expected_rules
            ):
                return len(document.rules)

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
        connection: sqlite3.Connection | None = None,
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
        with self._write_context(connection) as writer:
            asset_exists = writer.execute(
                "SELECT 1 FROM assets WHERE id = ?", (asset_id,)
            ).fetchone() is not None
            writer.execute(
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
            evidence_exists = writer.execute(
                "SELECT 1 FROM evidence_records WHERE id = ?", (evidence_id,)
            ).fetchone() is not None
            writer.execute(
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
            asset_row = writer.execute(
                "SELECT * FROM assets WHERE id = ?", (asset_id,)
            ).fetchone()
            evidence_row = writer.execute(
                "SELECT * FROM evidence_records WHERE id = ?", (evidence_id,)
            ).fetchone()
        return (
            self._asset(asset_row), self._evidence(evidence_row),
            not asset_exists, not evidence_exists,
        )

    def put_finding(
        self,
        finding: ParsedFinding,
        asset_id: str | None,
        batch_id: str | None = None,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> tuple[FindingRecord, bool]:
        observed_at = finding.observed_at or utc_now()
        fingerprint = finding.fingerprint or stable_id(
            "FP", finding.source.casefold(), finding.title.casefold(), asset_id or "",
            finding.location.casefold(),
        )
        finding_id = stable_id("FW", fingerprint)
        with self._write_context(connection) as writer:
            exists = writer.execute(
                "SELECT 1 FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone() is not None
            writer.execute(
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
            row = writer.execute(
                """SELECT f.*, COALESCE(a.display_name, '') AS asset_name
                   FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
                   WHERE f.id = ?""",
                (finding_id,),
            ).fetchone()
        return self._finding(row), not exists

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
        connection: sqlite3.Connection | None = None,
    ) -> tuple[RelationshipRecord, bool]:
        relationship_id = stable_id(
            "RL", source_type, source_id, target_type, target_id, relation
        )
        created_at = utc_now()
        with self._write_context(connection) as writer:
            exists = writer.execute(
                "SELECT 1 FROM relationships WHERE id = ?", (relationship_id,)
            ).fetchone() is not None
            writer.execute(
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
            row = writer.execute(
                "SELECT * FROM relationships WHERE id = ?", (relationship_id,)
            ).fetchone()
        return self._relationship(row), not exists

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

    def list_asset_provenance(
        self,
        *,
        include_denied: bool = False,
    ) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
        """Return source and run-ID summaries for all assets in one database read."""
        denied_filter = "" if include_denied else " AND a.scope_disposition != 'denied'"
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT e.asset_id, e.source, e.run_id
                   FROM evidence_records e
                   JOIN assets a ON a.id = e.asset_id
                   WHERE e.asset_id IS NOT NULL"""
                + denied_filter
                + " ORDER BY e.observed_at DESC, e.id"
            ).fetchall()

        sources: dict[str, list[str]] = {}
        run_ids: dict[str, list[str]] = {}
        for row in rows:
            asset_id = str(row["asset_id"])
            source = str(row["source"])
            source_items = sources.setdefault(asset_id, [])
            if source not in source_items:
                source_items.append(source)
            if row["run_id"]:
                run_id = str(row["run_id"])
                run_items = run_ids.setdefault(asset_id, [])
                if run_id not in run_items:
                    run_items.append(run_id)
        return {
            asset_id: (tuple(source_items), tuple(run_ids.get(asset_id, ())))
            for asset_id, source_items in sources.items()
        }

    def list_finding_scopes(self) -> dict[str, str]:
        """Return linked asset scope for every finding without materializing assets."""
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT f.id, COALESCE(a.scope_disposition, 'unmatched') AS scope
                   FROM findings f LEFT JOIN assets a ON a.id = f.asset_id"""
            ).fetchall()
        return {str(row["id"]): str(row["scope"]) for row in rows}

    def list_evidence_node_counts(
        self,
        *,
        include_denied: bool = False,
    ) -> dict[str, tuple[int, int]]:
        """Return evidence and relationship counts using two set-based queries."""
        denied_filter = "" if include_denied else " WHERE a.scope_disposition != 'denied'"
        with self.database.read() as connection:
            evidence_rows = connection.execute(
                """SELECT e.asset_id, COUNT(*) AS count
                   FROM evidence_records e
                   JOIN assets a ON a.id = e.asset_id"""
                + denied_filter
                + " GROUP BY e.asset_id"
            ).fetchall()
            relationship_rows = connection.execute(
                """SELECT endpoints.object_id, COUNT(DISTINCT endpoints.relationship_id) AS count
                   FROM (
                       SELECT id AS relationship_id, source_id AS object_id FROM relationships
                       UNION ALL
                       SELECT id AS relationship_id, target_id AS object_id FROM relationships
                   ) endpoints
                   JOIN assets a ON a.id = endpoints.object_id"""
                + denied_filter
                + " GROUP BY endpoints.object_id"
            ).fetchall()

        evidence_counts = {
            str(row["asset_id"]): int(row["count"]) for row in evidence_rows
        }
        relationship_counts = {
            str(row["object_id"]): int(row["count"]) for row in relationship_rows
        }
        return {
            asset_id: (count, relationship_counts.get(asset_id, 0))
            for asset_id, count in evidence_counts.items()
        } | {
            asset_id: (evidence_counts.get(asset_id, 0), count)
            for asset_id, count in relationship_counts.items()
        }

    @staticmethod
    def _evidence_anchor_identity(rule: dict[str, object]) -> tuple[str, str, str]:
        """Return a stable grouping key, display label, and visible anchor kind."""
        target_kind = str(rule["target_kind"])
        target = str(rule["normalized_target"])
        if target_kind == "domain":
            label = target.removeprefix("*.")
            key = f"domain:{label}"
            return stable_id("EA", key), label, "ROOT DOMAIN"
        if target_kind == "regex":
            return stable_id("EA", f"regex:{rule['id']}"), target, "REGEX"
        return stable_id("EA", f"{target_kind}:{target}"), target, target_kind.upper()

    def _evidence_anchor_groups(self) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
        groups: dict[str, dict[str, object]] = {}
        rule_to_anchor: dict[str, str] = {}
        for rule in self.list_scope_rules():
            anchor_id, label, kind = self._evidence_anchor_identity(rule)
            group = groups.setdefault(anchor_id, {
                "id": anchor_id,
                "label": label,
                "kind": kind,
                "rules": [],
            })
            group["rules"].append(rule)  # type: ignore[union-attr]
            rule_to_anchor[str(rule["id"])] = anchor_id
        return groups, rule_to_anchor

    @staticmethod
    def _evidence_category(kind: str) -> str:
        if kind in {"domain", "host"}:
            return "hostnames"
        if kind in {"ipv4", "ipv6", "cidr"}:
            return "addresses"
        if kind == "service":
            return "services"
        if kind == "url":
            return "urls"
        return "other"

    def list_evidence_anchors(self, query: str = "") -> tuple[EvidenceAnchorSummary, ...]:
        """Return compact scope-root summaries without materializing asset rows."""
        groups, rule_to_anchor = self._evidence_anchor_groups()
        unmatched_id = "EA-UNMATCHED"
        counts: dict[str, dict[str, object]] = {}
        source_sets: dict[str, set[str]] = {}
        finding_counts: dict[str, int] = {}

        with self.database.read() as connection:
            asset_rows = connection.execute(
                """SELECT matched_rule_id, kind, COUNT(*) AS count,
                          MAX(last_seen_at) AS last_seen_at
                   FROM assets WHERE scope_disposition != 'denied'
                   GROUP BY matched_rule_id, kind"""
            ).fetchall()
            source_rows = connection.execute(
                """SELECT DISTINCT a.matched_rule_id, e.source
                   FROM evidence_records e JOIN assets a ON a.id = e.asset_id
                   WHERE a.scope_disposition != 'denied'"""
            ).fetchall()
            finding_rows = connection.execute(
                """SELECT a.matched_rule_id, COUNT(DISTINCT f.id) AS count
                   FROM findings f JOIN assets a ON a.id = f.asset_id
                   WHERE a.scope_disposition != 'denied'
                   GROUP BY a.matched_rule_id"""
            ).fetchall()
            matching_rule_ids: set[str | None] | None = None
            needle = query.strip()
            if needle:
                like = f"%{needle}%"
                matching_rows = connection.execute(
                    """SELECT DISTINCT a.matched_rule_id
                       FROM assets a LEFT JOIN evidence_records e ON e.asset_id = a.id
                       WHERE a.scope_disposition != 'denied' AND (
                           a.display_name LIKE ? OR a.normalized_key LIKE ? OR a.kind LIKE ?
                           OR e.raw_value LIKE ? OR e.source LIKE ?
                       )""",
                    (like, like, like, like, like),
                ).fetchall()
                matching_rule_ids = {
                    str(row["matched_rule_id"]) if row["matched_rule_id"] is not None else None
                    for row in matching_rows
                }

        def anchor_for(rule_id: object) -> str:
            return rule_to_anchor.get(str(rule_id), unmatched_id) if rule_id else unmatched_id

        for row in asset_rows:
            anchor_id = anchor_for(row["matched_rule_id"])
            summary = counts.setdefault(anchor_id, {
                "assets": 0, "hostnames": 0, "addresses": 0, "services": 0,
                "urls": 0, "other": 0, "last_seen": "",
            })
            amount = int(row["count"])
            summary["assets"] = int(summary["assets"]) + amount
            category = self._evidence_category(str(row["kind"]))
            summary[category] = int(summary[category]) + amount
            summary["last_seen"] = max(str(summary["last_seen"]), str(row["last_seen_at"] or ""))

        for row in source_rows:
            source_sets.setdefault(anchor_for(row["matched_rule_id"]), set()).add(str(row["source"]))
        for row in finding_rows:
            anchor_id = anchor_for(row["matched_rule_id"])
            finding_counts[anchor_id] = finding_counts.get(anchor_id, 0) + int(row["count"])

        if unmatched_id in counts:
            groups[unmatched_id] = {
                "id": unmatched_id,
                "label": "Unmatched discoveries",
                "kind": "UNMATCHED",
                "rules": [],
            }

        query_folded = query.strip().casefold()
        summaries: list[EvidenceAnchorSummary] = []
        for anchor_id, group in groups.items():
            rules = tuple(sorted(group["rules"], key=lambda rule: str(rule["id"])))
            rule_ids = tuple(str(rule["id"]) for rule in rules)
            if query_folded:
                anchor_matches = query_folded in " ".join((
                    str(group["label"]), str(group["kind"]), *rule_ids,
                    *(str(rule["original_target"]) for rule in rules),
                )).casefold()
                asset_matches = matching_rule_ids is not None and (
                    (None in matching_rule_ids and anchor_id == unmatched_id)
                    or any(rule_id in matching_rule_ids for rule_id in rule_ids)
                )
                if not anchor_matches and not asset_matches:
                    continue
            metrics = counts.get(anchor_id, {})
            scope_status = "UNMATCHED"
            if rules:
                if any(str(rule["scope_status"]) == "denied" for rule in rules):
                    scope_status = "DENIED"
                elif any(bool(rule["review_required"]) for rule in rules):
                    scope_status = "REVIEW"
                else:
                    scope_status = "ALLOWED"
            summaries.append(EvidenceAnchorSummary(
                id=anchor_id,
                label=str(group["label"]),
                kind=str(group["kind"]),
                scope_status=scope_status,
                rule_ids=rule_ids,
                asset_count=int(metrics.get("assets", 0)),
                hostname_count=int(metrics.get("hostnames", 0)),
                address_count=int(metrics.get("addresses", 0)),
                service_count=int(metrics.get("services", 0)),
                url_count=int(metrics.get("urls", 0)),
                other_count=int(metrics.get("other", 0)),
                finding_count=finding_counts.get(anchor_id, 0),
                source_count=len(source_sets.get(anchor_id, set())),
                last_seen_at=str(metrics.get("last_seen", "")),
            ))
        return tuple(sorted(
            summaries,
            key=lambda item: (item.kind == "UNMATCHED", item.kind == "REGEX", item.label.casefold()),
        ))

    def _evidence_anchor_rule_ids(self, anchor_id: str) -> tuple[str, ...] | None:
        if anchor_id == "EA-UNMATCHED":
            return None
        groups, _ = self._evidence_anchor_groups()
        group = groups.get(anchor_id)
        if group is None:
            raise KeyError(anchor_id)
        return tuple(str(rule["id"]) for rule in group["rules"])

    def list_evidence_anchor_assets(
        self,
        anchor_id: str,
        category: str,
        *,
        query: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[tuple[EvidenceAssetSummary, ...], int]:
        """Load one bounded hierarchy bucket for an expanded Evidence anchor."""
        categories = {
            "hostnames": ("domain", "host"),
            "addresses": ("ipv4", "ipv6", "cidr"),
            "services": ("service",),
            "urls": ("url",),
            "other": ("email", "username", "organization", "autonomous_system", "technology"),
        }
        if category not in categories:
            raise ValueError(f"unknown evidence category: {category}")
        limit = min(max(int(limit), 1), 50)
        offset = max(int(offset), 0)
        rule_ids = self._evidence_anchor_rule_ids(anchor_id)
        conditions = ["a.scope_disposition != 'denied'"]
        values: list[object] = []
        if rule_ids is None:
            conditions.append("a.matched_rule_id IS NULL")
        else:
            placeholders = ", ".join("?" for _ in rule_ids)
            conditions.append(f"a.matched_rule_id IN ({placeholders})")
            values.extend(rule_ids)
        kind_placeholders = ", ".join("?" for _ in categories[category])
        conditions.append(f"a.kind IN ({kind_placeholders})")
        values.extend(categories[category])
        if query.strip():
            needle = f"%{query.strip()}%"
            conditions.append("(a.display_name LIKE ? OR a.normalized_key LIKE ? OR a.kind LIKE ?)")
            values.extend((needle, needle, needle))
        where = " AND ".join(conditions)
        with self.database.read() as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM assets a WHERE {where}", values
            ).fetchone()[0])
            rows = connection.execute(
                f"""SELECT a.*,
                       (SELECT COUNT(*) FROM evidence_records e WHERE e.asset_id = a.id) AS evidence_count,
                       (SELECT COUNT(*) FROM relationships r
                        WHERE (r.source_type = 'asset' AND r.source_id = a.id
                               AND r.target_type = 'asset')
                           OR (r.target_type = 'asset' AND r.target_id = a.id
                               AND r.source_type = 'asset')) AS relationship_count,
                       (SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id) AS finding_count
                    FROM assets a WHERE {where}
                    ORDER BY CASE a.kind
                        WHEN 'domain' THEN 0 WHEN 'host' THEN 1 WHEN 'ipv4' THEN 2
                        WHEN 'ipv6' THEN 3 WHEN 'cidr' THEN 4 WHEN 'service' THEN 5
                        WHEN 'url' THEN 6 ELSE 7 END,
                        a.display_name COLLATE NOCASE, a.id
                    LIMIT ? OFFSET ?""",
                (*values, limit, offset),
            ).fetchall()
        return tuple(EvidenceAssetSummary(
            asset=self._asset(row),
            evidence_count=int(row["evidence_count"]),
            relationship_count=int(row["relationship_count"]),
            finding_count=int(row["finding_count"]),
        ) for row in rows), total

    def list_evidence_asset_links(
        self,
        asset_id: str,
        *,
        limit: int = 25,
    ) -> tuple[tuple[EvidenceAssetLink, ...], int]:
        """Load a bounded set of direct asset links for one expanded hierarchy row."""
        limit = min(max(int(limit), 1), 25)
        link_query = """SELECT r.relation, r.confidence, a.*
            FROM relationships r
            JOIN assets a ON a.id = CASE
                WHEN r.source_type = 'asset' AND r.source_id = ? THEN r.target_id
                WHEN r.target_type = 'asset' AND r.target_id = ? THEN r.source_id
            END
            WHERE ((r.source_type = 'asset' AND r.source_id = ? AND r.target_type = 'asset')
                OR (r.target_type = 'asset' AND r.target_id = ? AND r.source_type = 'asset'))
              AND a.scope_disposition != 'denied'"""
        values = (asset_id, asset_id, asset_id, asset_id)
        with self.database.read() as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM ({link_query})", values
            ).fetchone()[0])
            rows = connection.execute(
                link_query + " ORDER BY r.created_at DESC, a.display_name COLLATE NOCASE LIMIT ?",
                (*values, limit),
            ).fetchall()
        return tuple(EvidenceAssetLink(
            relation=str(row["relation"]),
            confidence=str(row["confidence"]),
            asset=self._asset(row),
        ) for row in rows), total

    def list_related_assets(
        self,
        object_id: str,
        *,
        include_denied: bool = False,
    ) -> tuple[AssetRecord, ...]:
        """Load only asset records directly related to one selected object."""
        denied_filter = "" if include_denied else " AND a.scope_disposition != 'denied'"
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT DISTINCT a.* FROM assets a
                   JOIN (
                       SELECT target_id AS related_id FROM relationships WHERE source_id = ?
                       UNION
                       SELECT source_id AS related_id FROM relationships WHERE target_id = ?
                   ) related ON related.related_id = a.id
                   WHERE a.id != ?"""
                + denied_filter
                + " ORDER BY a.last_seen_at DESC, a.id",
                (object_id, object_id, object_id),
            ).fetchall()
        return tuple(self._asset(row) for row in rows)

    def search_evidence_asset_ids(self, query: str) -> set[str]:
        """Search lazy Evidence detail fields without materializing every node."""
        needle = f"%{query}%"
        values = (needle,) * 15
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT id FROM assets
                   WHERE display_name LIKE ? OR normalized_key LIKE ? OR kind LIKE ?
                      OR COALESCE(matched_rule_id, '') LIKE ?
                   UNION
                   SELECT asset_id FROM evidence_records
                   WHERE asset_id IS NOT NULL AND (
                       id LIKE ? OR kind LIKE ? OR raw_value LIKE ? OR source LIKE ?
                       OR integrity_status LIKE ?
                   )
                   UNION
                   SELECT r.source_id FROM relationships r
                   JOIN assets related ON related.id = r.target_id
                   WHERE related.scope_disposition != 'denied'
                     AND (related.kind LIKE ? OR related.normalized_key LIKE ?)
                   UNION
                   SELECT r.target_id FROM relationships r
                   JOIN assets related ON related.id = r.source_id
                   WHERE related.scope_disposition != 'denied'
                     AND (related.kind LIKE ? OR related.normalized_key LIKE ?)
                   UNION
                   SELECT source_id FROM relationships
                   WHERE relation LIKE ? OR confidence LIKE ?""",
                values,
            ).fetchall()
        return {str(row["id"]) for row in rows if row["id"] is not None}

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
        limit: int | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        conditions: list[str] = []
        values: list[object] = []
        if asset_id:
            conditions.append("e.asset_id = ?")
            values.append(asset_id)
        if not include_denied:
            conditions.append("(a.scope_disposition IS NULL OR a.scope_disposition != 'denied')")
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        limit_sql = ""
        if limit is not None:
            limit_sql = " LIMIT ?"
            values.append(min(max(int(limit), 1), 100))
        with self.database.read() as connection:
            rows = connection.execute(
                """SELECT e.* FROM evidence_records e
                   LEFT JOIN assets a ON a.id = e.asset_id"""
                + where + " ORDER BY e.observed_at DESC, e.id" + limit_sql,
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
