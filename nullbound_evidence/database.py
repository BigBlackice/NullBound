"""SQLite schema, migrations, transactions, and crash-state recovery."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator


DATABASE_NAME = "project.db"
DATABASE_SCHEMA_VERSION = 1


MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (1, (
        """CREATE TABLE ingestion_batches (
            id TEXT PRIMARY KEY,
            parser TEXT NOT NULL,
            source TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
            started_at TEXT NOT NULL,
            finished_at TEXT,
            error TEXT
        )""",
        """CREATE TABLE scope_rules (
            id TEXT PRIMARY KEY,
            target_kind TEXT NOT NULL,
            original_target TEXT NOT NULL,
            normalized_target TEXT NOT NULL,
            scope_status TEXT NOT NULL CHECK(scope_status IN ('allowed', 'denied')),
            ownership_confidence TEXT NOT NULL,
            review_required INTEGER NOT NULL CHECK(review_required IN (0, 1)),
            source TEXT NOT NULL,
            notes TEXT NOT NULL,
            synced_at TEXT NOT NULL
        )""",
        "CREATE INDEX scope_rules_normalized ON scope_rules(target_kind, normalized_target)",
        """CREATE TABLE target_sets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            synced_at TEXT NOT NULL
        )""",
        """CREATE TABLE target_set_members (
            target_set_id TEXT NOT NULL REFERENCES target_sets(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            target_kind TEXT NOT NULL,
            original_target TEXT NOT NULL,
            normalized_target TEXT NOT NULL,
            PRIMARY KEY(target_set_id, ordinal)
        )""",
        "CREATE INDEX target_set_members_normalized ON target_set_members(target_kind, normalized_target)",
        """CREATE TABLE assets (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            original_value TEXT NOT NULL,
            normalized_key TEXT NOT NULL,
            normalization_version INTEGER NOT NULL,
            transformations_json TEXT NOT NULL,
            display_name TEXT NOT NULL,
            scope_disposition TEXT NOT NULL,
            ownership_confidence TEXT NOT NULL,
            review_required INTEGER NOT NULL CHECK(review_required IN (0, 1)),
            matched_rule_id TEXT,
            metadata_json TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(kind, normalized_key)
        )""",
        "CREATE INDEX assets_scope ON assets(scope_disposition, review_required)",
        "CREATE INDEX assets_seen ON assets(last_seen_at DESC)",
        """CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL,
            confidence TEXT NOT NULL,
            asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            source TEXT NOT NULL,
            run_id TEXT,
            batch_id TEXT REFERENCES ingestion_batches(id) ON DELETE SET NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )""",
        "CREATE INDEX findings_severity ON findings(severity, lifecycle_state)",
        """CREATE TABLE evidence_records (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
            finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
            source TEXT NOT NULL,
            raw_value TEXT NOT NULL,
            normalized_key TEXT,
            normalization_version INTEGER,
            transformations_json TEXT NOT NULL,
            run_id TEXT,
            batch_id TEXT REFERENCES ingestion_batches(id) ON DELETE SET NULL,
            artifact_path TEXT,
            observed_at TEXT NOT NULL,
            integrity_status TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )""",
        "CREATE INDEX evidence_asset ON evidence_records(asset_id, observed_at DESC)",
        "CREATE INDEX evidence_run ON evidence_records(run_id)",
        """CREATE TABLE relationships (
            id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            relation TEXT NOT NULL,
            evidence_id TEXT REFERENCES evidence_records(id) ON DELETE SET NULL,
            confidence TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            UNIQUE(source_type, source_id, target_type, target_id, relation)
        )""",
        "CREATE INDEX relationships_source ON relationships(source_type, source_id)",
        "CREATE INDEX relationships_target ON relationships(target_type, target_id)",
    )),
)


class DatabaseVersionError(RuntimeError):
    """Raised when a project database is newer than this NullBound build."""


class ProjectDatabase:
    """Own one project's rebuildable SQLite evidence index."""

    def __init__(self, project_path: Path) -> None:
        self.project_path = Path(project_path).expanduser().resolve(strict=False)
        self.path = self.project_path / DATABASE_NAME
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        self.project_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self) -> Path:
        if self._initialized and self.path.is_file():
            return self.path
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if current > DATABASE_SCHEMA_VERSION:
                    raise DatabaseVersionError(
                        f"project database schema {current} is newer than supported "
                        f"schema {DATABASE_SCHEMA_VERSION}"
                    )
                for version, statements in MIGRATIONS:
                    if version <= current:
                        continue
                    for statement in statements:
                        connection.execute(statement)
                    connection.execute(f"PRAGMA user_version = {version}")
                    current = version
                connection.commit()
                self._initialized = True
            except Exception:
                connection.rollback()
                raise
        finally:
            connection.close()
        return self.path

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        self.initialize()
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize a write transaction using SQLite's portable lock."""
        self.initialize()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def recover_incomplete_batches(self, recovered_at: str) -> int:
        """Mark interrupted ingestion work explicitly instead of hiding it."""
        with self.transaction() as connection:
            cursor = connection.execute(
                """UPDATE ingestion_batches
                   SET status = 'failed', finished_at = ?,
                       error = 'NullBound stopped before ingestion completed'
                   WHERE status = 'running'""",
                (recovered_at,),
            )
            return cursor.rowcount
