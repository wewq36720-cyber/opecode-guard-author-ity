from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeAlias, cast

from ..contracts import RunRecord, Stage
from ..errors import GuardError
from ..integrity import canonical_json, digest_json, verify_event_records
from ..paths import default_state_dir

LEGACY_SCHEMA_VERSION = 1
PACKET_SCHEMA_VERSION = 2
V3_SCHEMA_VERSION = 3
V4_SCHEMA_VERSION = 4
V5_SCHEMA_VERSION = 5
V6_SCHEMA_VERSION = 6
SCHEMA_VERSION = 7
ZERO_HASH = "0" * 64
RowLike: TypeAlias = sqlite3.Row | Mapping[str, Any]
RUN_SESSIONS_SCHEMA = """
CREATE TABLE run_sessions (
    run_id TEXT NOT NULL,
    session_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    attached_revision INTEGER NOT NULL CHECK (attached_revision >= 0),
    attached_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    PRIMARY KEY (run_id, session_id),
    CHECK (
        (status = 'ACTIVE' AND revoked_at = '') OR
        (status = 'REVOKED' AND revoked_at <> '')
    ),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
"""
ARTIFACTS_V3_SCHEMA = """
CREATE TABLE artifacts_v3 (
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    body_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, kind, version),
    UNIQUE (run_id, kind, digest),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
"""
QUALITY_DRIVES_SCHEMA = """
CREATE TABLE quality_drives (
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    drive_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    event_seq INTEGER NOT NULL CHECK (event_seq >= 1),
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, request_id),
    UNIQUE (run_id, drive_id),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
"""
QUALITY_CONFIRMATIONS_SCHEMA = """
CREATE TABLE quality_confirmations (
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    confirmation_id TEXT NOT NULL,
    drive_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('FIT', 'UNFIT')),
    event_seq INTEGER NOT NULL CHECK (event_seq >= 1),
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, request_id),
    UNIQUE (run_id, confirmation_id),
    FOREIGN KEY (run_id, drive_id) REFERENCES quality_drives(run_id, drive_id) ON DELETE CASCADE
);
"""
PLANNING_ARTIFACTS_SCHEMA = """
CREATE TABLE planning_artifacts (
    run_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('BASELINE', 'SPEC', 'PLAN')),
    body_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    workspace_digest TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    planning_step TEXT NOT NULL,
    review_gate TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, artifact_id),
    UNIQUE (run_id, digest),
    UNIQUE (run_id, artifact_id, digest),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
"""
PLANNING_STATES_SCHEMA = """
CREATE TABLE planning_states (
    run_id TEXT PRIMARY KEY,
    planning_step TEXT NOT NULL,
    review_gate TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
"""
PLAN_APPROVAL_RECEIPTS_SCHEMA = """
CREATE TABLE plan_approval_receipts (
    approval_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind = 'PLAN_APPROVAL_RECEIPT'),
    run_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind = 'PLAN'),
    artifact_digest TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    workspace_digest TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    source TEXT NOT NULL CHECK (source IN ('ci', 'independent-review', 'user')),
    nonce TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision = 'APPROVE'),
    authority_ref TEXT NOT NULL,
    consumed_at TEXT NOT NULL DEFAULT '',
    UNIQUE (run_id, nonce),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, artifact_id, artifact_digest)
        REFERENCES planning_artifacts(run_id, artifact_id, digest) ON DELETE RESTRICT
);
"""
PLANNING_REVIEW_RECEIPTS_SCHEMA = """
CREATE TABLE planning_review_receipts (
    review_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind = 'PLANNING_REVIEW_RECEIPT'),
    run_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('BASELINE', 'SPEC')),
    artifact_digest TEXT NOT NULL,
    artifact_revision INTEGER NOT NULL CHECK (artifact_revision >= 0),
    base_sha TEXT NOT NULL,
    workspace_digest TEXT NOT NULL,
    issued_revision INTEGER NOT NULL CHECK (issued_revision >= 0),
    source TEXT NOT NULL CHECK (source IN ('ci', 'independent-review', 'user')),
    nonce TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ACCEPT', 'REQUEST_CHANGES')),
    authority_ref TEXT NOT NULL,
    consumed_at TEXT DEFAULT NULL,
    UNIQUE (run_id, nonce),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, artifact_id, artifact_digest)
        REFERENCES planning_artifacts(run_id, artifact_id, digest) ON DELETE RESTRICT
);
"""
PLAN_CANDIDATES_SCHEMA = """
CREATE TABLE plan_candidates (
    run_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    packet_json TEXT NOT NULL,
    packet_digest TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, artifact_id, artifact_digest)
        REFERENCES planning_artifacts(run_id, artifact_id, digest) ON DELETE RESTRICT
);
"""
PLANNING_IMMUTABILITY_TRIGGERS = (
    """
CREATE TRIGGER planning_artifacts_immutable_update
BEFORE UPDATE ON planning_artifacts
BEGIN
    SELECT RAISE(ABORT, 'planning artifacts are immutable');
END;
""",
    """
CREATE TRIGGER planning_artifacts_immutable_delete
BEFORE DELETE ON planning_artifacts
BEGIN
    SELECT RAISE(ABORT, 'planning artifacts are immutable');
END;
""",
    """
CREATE TRIGGER plan_approval_receipts_immutable_update
BEFORE UPDATE OF approval_id, kind, run_id, artifact_id, artifact_kind, artifact_digest,
    base_sha, workspace_digest, revision, source, nonce, issued_at, decision, authority_ref
ON plan_approval_receipts
BEGIN
    SELECT RAISE(ABORT, 'plan approval receipts are immutable');
END;
""",
    """
CREATE TRIGGER plan_approval_receipts_immutable_delete
BEFORE DELETE ON plan_approval_receipts
BEGIN
    SELECT RAISE(ABORT, 'plan approval receipts are immutable');
END;
""",
    """
CREATE TRIGGER plan_candidates_immutable_update
BEFORE UPDATE ON plan_candidates
BEGIN
    SELECT RAISE(ABORT, 'plan candidates are immutable');
END;
""",
    """
CREATE TRIGGER plan_candidates_immutable_delete
BEFORE DELETE ON plan_candidates
BEGIN
    SELECT RAISE(ABORT, 'plan candidates are immutable');
END;
""",
)
PLANNING_REVIEW_IMMUTABILITY_TRIGGERS = (
    """
CREATE TRIGGER planning_review_receipts_immutable_update
BEFORE UPDATE ON planning_review_receipts
WHEN NOT (OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'planning review receipts are immutable');
END;
""",
    """
CREATE TRIGGER planning_review_receipts_immutable_delete
BEFORE DELETE ON planning_review_receipts
BEGIN
    SELECT RAISE(ABORT, 'planning review receipts are immutable');
END;
""",
)
SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    git_common_dir TEXT NOT NULL,
    worktree TEXT NOT NULL UNIQUE,
    base_sha TEXT NOT NULL,
    stage TEXT NOT NULL,
    revision INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    task TEXT NOT NULL,
    packet_digest TEXT NOT NULL,
    environment_digest TEXT NOT NULL,
    workspace_digest TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    active_phase TEXT NOT NULL,
    blocked_code TEXT NOT NULL,
    blocked_message TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    event_head TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    body_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, kind, version),
    UNIQUE (run_id, kind, digest),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    revision INTEGER NOT NULL,
    before_stage TEXT NOT NULL,
    after_stage TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (run_id, seq),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS checks (
    run_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    PRIMARY KEY (run_id, check_id),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    set_digest TEXT NOT NULL,
    check_id TEXT NOT NULL,
    requirement_ids_json TEXT NOT NULL,
    acceptance_ids_json TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    packet_digest TEXT NOT NULL,
    workspace_digest TEXT NOT NULL,
    command_digest TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    output_digest TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    timed_out INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    output_preview TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS phase_executions (
    run_id TEXT NOT NULL,
    phase_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    status TEXT NOT NULL,
    requirement_ids_json TEXT NOT NULL,
    acceptance_ids_json TEXT NOT NULL,
    allowed_paths_json TEXT NOT NULL,
    check_ids_json TEXT NOT NULL,
    change_count INTEGER NOT NULL,
    conclusion TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, phase_id),
    UNIQUE (run_id, position),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS write_leases (
    run_id TEXT PRIMARY KEY,
    call_id TEXT NOT NULL UNIQUE,
    tool_name TEXT NOT NULL,
    phase_id TEXT NOT NULL,
    requirement_ids_json TEXT NOT NULL,
    acceptance_ids_json TEXT NOT NULL,
    declared_paths_json TEXT NOT NULL,
    before_digest TEXT NOT NULL,
    before_files_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
"""
    + RUN_SESSIONS_SCHEMA
    + QUALITY_DRIVES_SCHEMA
    + QUALITY_CONFIRMATIONS_SCHEMA
    + PLANNING_ARTIFACTS_SCHEMA
    + PLANNING_STATES_SCHEMA
    + PLAN_APPROVAL_RECEIPTS_SCHEMA
    + PLAN_CANDIDATES_SCHEMA
    + PLANNING_REVIEW_RECEIPTS_SCHEMA
    + "\n".join(PLANNING_IMMUTABILITY_TRIGGERS)
    + "\n".join(PLANNING_REVIEW_IMMUTABILITY_TRIGGERS)
)

LEGACY_TABLES = frozenset(
    {
        "runs",
        "artifacts",
        "events",
        "checks",
        "evidence",
        "phase_executions",
        "write_leases",
    }
)
V3_EXPECTED_TABLES = LEGACY_TABLES | {"run_sessions"}
V4_EXPECTED_TABLES = V3_EXPECTED_TABLES | {"quality_drives", "quality_confirmations"}
V5_EXPECTED_TABLES = V4_EXPECTED_TABLES | {
    "planning_artifacts",
    "planning_states",
    "plan_approval_receipts",
}
V6_EXPECTED_TABLES = V5_EXPECTED_TABLES | {
    "plan_candidates",
}
EXPECTED_TABLES = V6_EXPECTED_TABLES | {"planning_review_receipts"}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = (path or (default_state_dir() / "guard.db")).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self, *, readonly: bool = False) -> sqlite3.Connection:
        if readonly:
            connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=ro",
                uri=True,
                timeout=5,
            )
        else:
            connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        if readonly:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
        return connection

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            connection.commit()

    def _initialize(self) -> None:
        with self.connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if version == 0 and not tables:
                connection.executescript(SCHEMA)
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute("PRAGMA journal_mode = WAL")
                connection.commit()
                return
            if version == LEGACY_SCHEMA_VERSION and tables == LEGACY_TABLES:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(RUN_SESSIONS_SCHEMA)
                    connection.execute(f"PRAGMA user_version = {PACKET_SCHEMA_VERSION}")
                    self._migrate_v2_to_v3(connection, begin=False)
                    self._migrate_v3_to_v4(connection, begin=False)
                    self._migrate_v4_to_v5(connection, begin=False)
                    self._migrate_v5_to_v6(connection, begin=False)
                    self._migrate_v6_to_v7(connection, begin=False)
                    connection.commit()
                except Exception as exc:
                    connection.rollback()
                    raise GuardError(
                        "PERSISTED_STATE_BROKEN",
                        "Guard schema migration failed without changing historical state.",
                    ) from exc
                return
            if version == PACKET_SCHEMA_VERSION and tables == V3_EXPECTED_TABLES:
                try:
                    self._migrate_v2_to_v3(connection)
                    self._migrate_v3_to_v4(connection)
                    self._migrate_v4_to_v5(connection)
                    self._migrate_v5_to_v6(connection)
                    self._migrate_v6_to_v7(connection)
                except GuardError:
                    raise
                except Exception as exc:
                    raise GuardError(
                        "PERSISTED_STATE_BROKEN",
                        "Guard packet migration failed without changing historical state.",
                    ) from exc
                return
            if version == V3_SCHEMA_VERSION and tables == V3_EXPECTED_TABLES:
                self._migrate_v3_to_v4(connection)
                self._migrate_v4_to_v5(connection)
                self._migrate_v5_to_v6(connection)
                self._migrate_v6_to_v7(connection)
                return
            if version == V4_SCHEMA_VERSION and tables == V4_EXPECTED_TABLES:
                self._migrate_v4_to_v5(connection)
                self._migrate_v5_to_v6(connection)
                self._migrate_v6_to_v7(connection)
                return
            if version == V5_SCHEMA_VERSION and tables == V5_EXPECTED_TABLES:
                self._migrate_v5_to_v6(connection)
                self._migrate_v6_to_v7(connection)
                return
            if version == V6_SCHEMA_VERSION and tables == V6_EXPECTED_TABLES:
                self._migrate_v6_to_v7(connection)
                return
            if version != SCHEMA_VERSION:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE",
                    "This minimal Guard requires a version-7 state database.",
                    version=version,
                )
            if tables != EXPECTED_TABLES:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE",
                    "Guard state tables do not match the minimal runtime schema.",
                    tables=sorted(tables),
                )
            self._assert_v3_artifacts(connection)
            self._assert_v4_quality(connection)
            self._assert_v5_planning(connection)
            self._assert_v6_plan_candidates(connection)
            self._assert_v7_planning_reviews(connection)

    @staticmethod
    def _migrate_v2_to_v3(
        connection: sqlite3.Connection,
        *,
        begin: bool = True,
    ) -> None:
        if begin:
            connection.execute("BEGIN IMMEDIATE")
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if tables != V3_EXPECTED_TABLES:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE",
                    "Guard state tables do not match schema v2.",
                    tables=sorted(tables),
                )
            Database._assert_v2_artifacts(connection)
            run_ids = [
                str(row[0])
                for row in connection.execute("SELECT id FROM runs ORDER BY id").fetchall()
            ]
            for run_id in run_ids:
                select_run(connection, run_id, verify_state=False)
            before = [
                tuple(row)
                for row in connection.execute(
                    "SELECT run_id, kind, version, body_json, digest, created_at "
                    "FROM artifacts ORDER BY run_id, kind"
                ).fetchall()
            ]
            connection.execute(ARTIFACTS_V3_SCHEMA)
            connection.execute(
                """
                INSERT INTO artifacts_v3(run_id, kind, version, body_json, digest, created_at)
                SELECT run_id, kind, 1, body_json, digest, created_at FROM artifacts
                """
            )
            copied = [
                tuple(row)
                for row in connection.execute(
                    "SELECT run_id, kind, version, body_json, digest, created_at "
                    "FROM artifacts_v3 ORDER BY run_id, kind"
                ).fetchall()
            ]
            expected = [(row[0], row[1], 1, row[3], row[4], row[5]) for row in before]
            if copied != expected:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN",
                    "Packet artifacts changed during schema migration.",
                )
            connection.execute("DROP TABLE artifacts")
            connection.execute("ALTER TABLE artifacts_v3 RENAME TO artifacts")
            connection.execute(f"PRAGMA user_version = {V3_SCHEMA_VERSION}")
            Database._assert_v3_artifacts(connection)
            for run_id in run_ids:
                select_run(connection, run_id, verify_state=False)
            if begin:
                connection.commit()
        except Exception:
            if begin:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_v3_to_v4(
        connection: sqlite3.Connection,
        *,
        begin: bool = True,
    ) -> None:
        try:
            if begin:
                connection.execute("BEGIN IMMEDIATE")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if tables != V3_EXPECTED_TABLES:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE", "Guard state tables do not match schema v3."
                )
            Database._assert_v3_artifacts(connection)
            connection.execute(QUALITY_DRIVES_SCHEMA)
            connection.execute(QUALITY_CONFIRMATIONS_SCHEMA)
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN", "Quality migration foreign-key check failed."
                )
            connection.execute(f"PRAGMA user_version = {V4_SCHEMA_VERSION}")
            Database._assert_v4_quality(connection)
            if begin:
                connection.commit()
        except Exception:
            if begin:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_v4_to_v5(
        connection: sqlite3.Connection,
        *,
        begin: bool = True,
    ) -> None:
        try:
            if begin:
                connection.execute("BEGIN IMMEDIATE")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if tables != V4_EXPECTED_TABLES:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE", "Guard state tables do not match schema v4."
                )
            Database._assert_v3_artifacts(connection)
            Database._assert_v4_quality(connection)
            if connection.execute("SELECT 1 FROM write_leases LIMIT 1").fetchone() is not None:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN",
                    "Cannot migrate a Run with an unfinished write lease.",
                )
            Database._create_v5_tables(connection)
            migrated_at = utc_now()
            connection.execute(
                """
                INSERT INTO planning_states(run_id, planning_step, review_gate, updated_at)
                SELECT id, 'COMPATIBILITY_READ_ONLY', '', ? FROM runs
                """,
                (migrated_at,),
            )
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN", "Planning migration foreign-key check failed."
                )
            connection.execute(f"PRAGMA user_version = {V5_SCHEMA_VERSION}")
            Database._assert_v5_planning(connection)
            if begin:
                connection.commit()
        except Exception:
            if begin:
                connection.rollback()
            raise

    @staticmethod
    def _create_v5_tables(connection: sqlite3.Connection) -> None:
        connection.execute(PLANNING_ARTIFACTS_SCHEMA)
        connection.execute(PLANNING_STATES_SCHEMA)
        connection.execute(PLAN_APPROVAL_RECEIPTS_SCHEMA)
        for trigger in PLANNING_IMMUTABILITY_TRIGGERS[:4]:
            connection.execute(trigger)

    @staticmethod
    def _migrate_v5_to_v6(connection: sqlite3.Connection, *, begin: bool = True) -> None:
        try:
            if begin:
                connection.execute("BEGIN IMMEDIATE")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if tables != V5_EXPECTED_TABLES:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE", "Guard state tables do not match schema v5."
                )
            Database._assert_v5_planning(connection)
            connection.execute(PLAN_CANDIDATES_SCHEMA)
            for trigger in PLANNING_IMMUTABILITY_TRIGGERS[-2:]:
                connection.execute(trigger)
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN", "Candidate-plan migration foreign-key check failed."
                )
            connection.execute(f"PRAGMA user_version = {V6_SCHEMA_VERSION}")
            Database._assert_v6_plan_candidates(connection)
            if begin:
                connection.commit()
        except Exception:
            if begin:
                connection.rollback()
            raise

    @staticmethod
    def _migrate_v6_to_v7(connection: sqlite3.Connection, *, begin: bool = True) -> None:
        try:
            if begin:
                connection.execute("BEGIN IMMEDIATE")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if tables != V6_EXPECTED_TABLES:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE", "Guard state tables do not match schema v6."
                )
            Database._assert_v6_plan_candidates(connection)
            connection.execute(PLANNING_REVIEW_RECEIPTS_SCHEMA)
            for trigger in PLANNING_REVIEW_IMMUTABILITY_TRIGGERS:
                connection.execute(trigger)
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN", "Planning-review migration foreign-key check failed."
                )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            Database._assert_v7_planning_reviews(connection)
            if begin:
                connection.commit()
        except Exception:
            if begin:
                connection.rollback()
            raise

    @staticmethod
    def _assert_v5_planning(connection: sqlite3.Connection) -> None:
        expected = {
            "planning_artifacts": [
                "run_id",
                "artifact_id",
                "kind",
                "body_json",
                "digest",
                "base_sha",
                "workspace_digest",
                "revision",
                "planning_step",
                "review_gate",
                "created_at",
            ],
            "planning_states": ["run_id", "planning_step", "review_gate", "updated_at"],
            "plan_approval_receipts": [
                "approval_id",
                "kind",
                "run_id",
                "artifact_id",
                "artifact_kind",
                "artifact_digest",
                "base_sha",
                "workspace_digest",
                "revision",
                "source",
                "nonce",
                "issued_at",
                "decision",
                "authority_ref",
                "consumed_at",
            ],
        }
        for table, columns in expected.items():
            actual = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]
            if actual != columns:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE", "Planning table schema is incompatible."
                )
        Database._assert_planning_table_constraints(connection)
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                "AND (name LIKE 'planning_artifacts_%' OR name LIKE 'plan_approval_%')"
            )
        }
        if triggers != {
            "planning_artifacts_immutable_update",
            "planning_artifacts_immutable_delete",
            "plan_approval_receipts_immutable_update",
            "plan_approval_receipts_immutable_delete",
        }:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE", "Planning immutability triggers are incompatible."
            )
        expected_trigger_sql = {
            Database._normalized_sql(trigger): trigger
            for trigger in PLANNING_IMMUTABILITY_TRIGGERS[:4]
        }
        actual_trigger_sql = {
            Database._normalized_sql(str(row[1])): str(row[0])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND (name LIKE 'planning_artifacts_%' OR name LIKE 'plan_approval_%')"
            )
        }
        if set(actual_trigger_sql) != set(expected_trigger_sql):
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Planning immutability trigger definitions are incompatible.",
            )
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise GuardError("PERSISTED_STATE_BROKEN", "Planning table foreign-key check failed.")

    @staticmethod
    def _assert_planning_table_constraints(connection: sqlite3.Connection) -> None:
        expected = {
            "planning_artifacts": {
                "primary": ("run_id", "artifact_id"),
                "unique": {("run_id", "digest"), ("run_id", "artifact_id", "digest")},
                "foreign": {("runs", "run_id", "id", "NO ACTION", "CASCADE", "NONE")},
                "schema": PLANNING_ARTIFACTS_SCHEMA,
            },
            "planning_states": {
                "primary": ("run_id",),
                "unique": set(),
                "foreign": {("runs", "run_id", "id", "NO ACTION", "CASCADE", "NONE")},
                "schema": PLANNING_STATES_SCHEMA,
            },
            "plan_approval_receipts": {
                "primary": ("approval_id",),
                "unique": {("run_id", "nonce")},
                "foreign": {
                    ("runs", "run_id", "id", "NO ACTION", "CASCADE", "NONE"),
                    ("planning_artifacts", "run_id", "run_id", "NO ACTION", "RESTRICT", "NONE"),
                    (
                        "planning_artifacts",
                        "artifact_id",
                        "artifact_id",
                        "NO ACTION",
                        "RESTRICT",
                        "NONE",
                    ),
                    (
                        "planning_artifacts",
                        "artifact_digest",
                        "digest",
                        "NO ACTION",
                        "RESTRICT",
                        "NONE",
                    ),
                },
                "schema": PLAN_APPROVAL_RECEIPTS_SCHEMA,
            },
        }
        for table, constraints in expected.items():
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            primary = tuple(
                str(row[1]) for row in sorted(rows, key=lambda row: int(row[5])) if int(row[5])
            )
            unique = {
                tuple(
                    str(column[2])
                    for column in connection.execute(f"PRAGMA index_info('{index[1]}')").fetchall()
                )
                for index in connection.execute(f"PRAGMA index_list({table})").fetchall()
                if int(index[2]) and str(index[3]) == "u"
            }
            foreign_rows = cast(
                list[sqlite3.Row],
                connection.execute(f"PRAGMA foreign_key_list({table})").fetchall(),
            )
            foreign: set[tuple[str, str, str, str, str, str]] = set()
            for raw_row in foreign_rows:
                row = cast(tuple[Any, ...], raw_row)
                foreign.add(
                    (
                        str(row[2]),
                        str(row[3]),
                        str(row[4]),
                        str(row[5]).upper(),
                        str(row[6]).upper(),
                        str(row[7]).upper(),
                    )
                )
            schema_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
            details = cast(dict[str, object], constraints)
            expected_primary = cast(tuple[str, ...], details["primary"])
            expected_unique = cast(set[tuple[str, ...]], details["unique"])
            expected_foreign = cast(set[tuple[str, str, str, str, str, str]], details["foreign"])
            expected_schema = cast(str, details["schema"])
            if (
                primary != expected_primary
                or unique != expected_unique
                or foreign != expected_foreign
                or schema_row is None
                or Database._normalized_sql(str(schema_row[0]))
                != Database._normalized_sql(expected_schema)
            ):
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE", "Planning table constraints are incompatible."
                )

    @staticmethod
    def _assert_v6_plan_candidates(connection: sqlite3.Connection) -> None:
        columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(plan_candidates)")]
        if columns != [
            "run_id",
            "artifact_id",
            "artifact_digest",
            "packet_json",
            "packet_digest",
            "revision",
            "created_at",
        ]:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE", "Candidate-plan table schema is incompatible."
            )
        rows = connection.execute("PRAGMA table_info(plan_candidates)").fetchall()
        primary = tuple(
            str(row[1]) for row in sorted(rows, key=lambda row: int(row[5])) if int(row[5])
        )
        foreign_rows = cast(
            list[sqlite3.Row],
            connection.execute("PRAGMA foreign_key_list(plan_candidates)").fetchall(),
        )
        foreign = {
            (
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]).upper(),
                str(row[6]).upper(),
                str(row[7]).upper(),
            )
            for row in cast(list[tuple[Any, ...]], foreign_rows)
        }
        schema_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'plan_candidates'"
        ).fetchone()
        expected_foreign = {
            ("planning_artifacts", "run_id", "run_id", "NO ACTION", "RESTRICT", "NONE"),
            ("planning_artifacts", "artifact_id", "artifact_id", "NO ACTION", "RESTRICT", "NONE"),
            ("planning_artifacts", "artifact_digest", "digest", "NO ACTION", "RESTRICT", "NONE"),
        }
        if (
            primary != ("run_id",)
            or foreign != expected_foreign
            or schema_row is None
            or Database._normalized_sql(str(schema_row[0]))
            != Database._normalized_sql(PLAN_CANDIDATES_SCHEMA)
        ):
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE", "Candidate-plan constraints are incompatible."
            )
        expected_triggers = {
            Database._normalized_sql(trigger) for trigger in PLANNING_IMMUTABILITY_TRIGGERS[-2:]
        }
        actual_triggers = {
            Database._normalized_sql(str(row[1]))
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name LIKE 'plan_candidates_%'"
            )
        }
        if actual_triggers != expected_triggers:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Candidate-plan immutability triggers are incompatible.",
            )

    @staticmethod
    def _assert_v7_planning_reviews(connection: sqlite3.Connection) -> None:
        columns = [
            str(row[1]) for row in connection.execute("PRAGMA table_info(planning_review_receipts)")
        ]
        if columns != [
            "review_id",
            "kind",
            "run_id",
            "artifact_id",
            "artifact_kind",
            "artifact_digest",
            "artifact_revision",
            "base_sha",
            "workspace_digest",
            "issued_revision",
            "source",
            "nonce",
            "issued_at",
            "decision",
            "authority_ref",
            "consumed_at",
        ]:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE", "Planning-review table schema is incompatible."
            )
        schema_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' "
            "AND name = 'planning_review_receipts'"
        ).fetchone()
        actual_triggers = {
            Database._normalized_sql(str(row[1]))
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name LIKE 'planning_review_receipts_%'"
            )
        }
        expected_triggers = {
            Database._normalized_sql(trigger) for trigger in PLANNING_REVIEW_IMMUTABILITY_TRIGGERS
        }
        if (
            schema_row is None
            or Database._normalized_sql(str(schema_row[0]))
            != Database._normalized_sql(PLANNING_REVIEW_RECEIPTS_SCHEMA)
            or actual_triggers != expected_triggers
            or connection.execute("PRAGMA foreign_key_check").fetchone() is not None
        ):
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE", "Planning-review constraints are incompatible."
            )

    @staticmethod
    def _normalized_sql(value: str) -> str:
        return "".join(value.split()).casefold().rstrip(";")

    @staticmethod
    def _assert_v4_quality(connection: sqlite3.Connection) -> None:
        for table, expected_columns in (
            (
                "quality_drives",
                [
                    "run_id",
                    "request_id",
                    "drive_id",
                    "result_json",
                    "result_digest",
                    "event_seq",
                    "created_at",
                ],
            ),
            (
                "quality_confirmations",
                [
                    "run_id",
                    "request_id",
                    "confirmation_id",
                    "drive_id",
                    "outcome",
                    "event_seq",
                    "created_at",
                ],
            ),
        ):
            columns = [
                str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            ]
            if columns != expected_columns:
                raise GuardError(
                    "DATABASE_SCHEMA_INCOMPATIBLE", "Quality table schema is incompatible."
                )
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise GuardError("PERSISTED_STATE_BROKEN", "Quality table foreign-key check failed.")

    @staticmethod
    def _assert_v2_artifacts(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA table_info(artifacts)").fetchall()
        columns = [str(row[1]) for row in rows]
        primary = [
            str(item[1]) for item in sorted(rows, key=lambda item: int(item[5])) if int(item[5]) > 0
        ]
        expected_columns = [
            "run_id",
            "kind",
            "version",
            "body_json",
            "digest",
            "created_at",
        ]
        if columns != expected_columns or primary != ["run_id", "kind"]:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Artifact table does not match schema v2.",
            )
        unique_indexes = [
            row
            for row in connection.execute("PRAGMA index_list(artifacts)").fetchall()
            if int(row[2]) == 1
        ]
        indexed_columns = {
            tuple(
                str(column[2])
                for column in connection.execute(f"PRAGMA index_info('{index[1]!s}')").fetchall()
            )
            for index in unique_indexes
        }
        if indexed_columns != {("run_id", "kind")}:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Artifact uniqueness constraints do not match schema v2.",
            )
        Database._assert_artifact_foreign_key(connection)

    @staticmethod
    def _assert_v3_artifacts(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA table_info(artifacts)").fetchall()
        columns = [str(row[1]) for row in rows]
        primary = [
            str(item[1]) for item in sorted(rows, key=lambda item: int(item[5])) if int(item[5]) > 0
        ]
        expected_columns = [
            "run_id",
            "kind",
            "version",
            "body_json",
            "digest",
            "created_at",
        ]
        if columns != expected_columns or primary != ["run_id", "kind", "version"]:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Artifact table does not match schema v3.",
            )
        unique_indexes = [
            row
            for row in connection.execute("PRAGMA index_list(artifacts)").fetchall()
            if int(row[2]) == 1
        ]
        indexed_columns = {
            tuple(
                str(column[2])
                for column in connection.execute(f"PRAGMA index_info('{index[1]!s}')").fetchall()
            )
            for index in unique_indexes
        }
        if indexed_columns != {
            ("run_id", "kind", "version"),
            ("run_id", "kind", "digest"),
        }:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Artifact uniqueness constraints do not match schema v3.",
            )
        table_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'artifacts'"
        ).fetchone()
        normalized_sql = "" if table_sql is None else "".join(str(table_sql[0]).split()).casefold()
        if "check(version>=1)" not in normalized_sql:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Artifact version check constraint is missing.",
            )
        Database._assert_artifact_foreign_key(connection)

    @staticmethod
    def _assert_artifact_foreign_key(connection: sqlite3.Connection) -> None:
        foreign_keys = connection.execute("PRAGMA foreign_key_list(artifacts)").fetchall()
        if len(foreign_keys) != 1:
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Artifact foreign key does not match the Guard schema.",
            )
        foreign_key = foreign_keys[0]
        if (
            str(foreign_key[2]) != "runs"
            or str(foreign_key[3]) != "run_id"
            or str(foreign_key[4]) != "id"
            or str(foreign_key[5]).upper() != "NO ACTION"
            or str(foreign_key[6]).upper() != "CASCADE"
            or str(foreign_key[7]).upper() != "NONE"
        ):
            raise GuardError(
                "DATABASE_SCHEMA_INCOMPATIBLE",
                "Artifact foreign key does not match the Guard schema.",
            )
        if connection.execute("PRAGMA foreign_key_check(artifacts)").fetchone() is not None:
            raise GuardError(
                "PERSISTED_STATE_BROKEN",
                "Artifact foreign-key integrity check failed.",
            )


def select_run(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    verify: bool = True,
    verify_state: bool = True,
) -> sqlite3.Row:
    row = cast(
        sqlite3.Row | None,
        connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone(),
    )
    if row is None:
        raise GuardError("RUN_NOT_FOUND", f"Run not found: {run_id}")
    if verify:
        events = connection.execute(
            "SELECT * FROM events WHERE run_id = ? ORDER BY seq",
            (run_id,),
        ).fetchall()
        try:
            verify_event_records(
                cast(Mapping[str, Any], row),
                [cast(Mapping[str, Any], event) for event in events],
            )
            if verify_state:
                from .integrity import verify_persisted_state

                verify_persisted_state(
                    connection,
                    cast(Mapping[str, Any], row),
                    [cast(Mapping[str, Any], event) for event in events],
                )
        except GuardError:
            raise
        except (
            KeyError,
            MemoryError,
            OverflowError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
        ) as exc:
            raise GuardError(
                "EVENT_CHAIN_BROKEN",
                "Event chain contains malformed data.",
                run_id=run_id,
            ) from exc
    return row


def check_revision(row: RowLike, expected: int) -> None:
    if int(row["revision"]) != expected:
        raise GuardError(
            "REVISION_CONFLICT",
            "Run revision changed before this operation.",
            expected=expected,
            actual=int(row["revision"]),
        )


def append_created_event(connection: sqlite3.Connection, run_id: str) -> None:
    row = select_run(connection, run_id, verify=False)
    from .integrity import checks_digest

    created_at = str(row["created_at"])
    envelope = {
        "run_id": run_id,
        "type": "RUN_CREATED",
        "actor": "control",
        "payload": {
            "base_sha": row["base_sha"],
            "project_root": row["project_root"],
            "git_common_dir": row["git_common_dir"],
            "worktree": row["worktree"],
            "environment_digest": row["environment_digest"],
            "workspace_digest": row["workspace_digest"],
            "checks_digest": checks_digest(connection, run_id),
        },
        "revision": 0,
        "before_stage": Stage.PLANNING.value,
        "after_stage": Stage.PLANNING.value,
        "created_at": created_at,
    }
    event_hash = digest_json({"previous_hash": ZERO_HASH, "event": envelope})
    connection.execute(
        """
        INSERT INTO events(
            run_id, seq, type, actor, payload_json, revision,
            before_stage, after_stage, previous_hash, event_hash, created_at
        ) VALUES (?, 1, ?, ?, ?, 0, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            envelope["type"],
            envelope["actor"],
            canonical_json(envelope["payload"]),
            envelope["before_stage"],
            envelope["after_stage"],
            ZERO_HASH,
            event_hash,
            created_at,
        ),
    )
    connection.execute(
        "UPDATE runs SET event_count = 1, event_head = ? WHERE id = ?",
        (event_hash, run_id),
    )


def append_event(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    event: str,
    actor: str,
    payload: dict[str, Any],
    after_stage: Stage | None = None,
    created_at: str | None = None,
) -> int:
    row = select_run(connection, run_id, verify_state=False)
    before = Stage(str(row["stage"]))
    after = after_stage or before
    revision = int(row["revision"]) + 1
    seq = int(row["event_count"]) + 1
    previous = str(row["event_head"])
    created_at = created_at or utc_now()
    envelope = {
        "run_id": run_id,
        "type": event,
        "actor": actor,
        "payload": payload,
        "revision": revision,
        "before_stage": before.value,
        "after_stage": after.value,
        "created_at": created_at,
    }
    event_hash = digest_json({"previous_hash": previous, "event": envelope})
    connection.execute(
        """
        INSERT INTO events(
            run_id, seq, type, actor, payload_json, revision,
            before_stage, after_stage, previous_hash, event_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            seq,
            event,
            actor,
            canonical_json(payload),
            revision,
            before.value,
            after.value,
            previous,
            event_hash,
            created_at,
        ),
    )
    connection.execute(
        """
        UPDATE runs
        SET stage = ?, revision = ?, event_count = ?, event_head = ?, updated_at = ?
        WHERE id = ?
        """,
        (after.value, revision, seq, event_hash, created_at, run_id),
    )
    return revision


def run_from_row(row: RowLike) -> RunRecord:
    return RunRecord(
        run_id=str(row["id"]),
        project_root=Path(str(row["project_root"])),
        git_common_dir=Path(str(row["git_common_dir"])),
        worktree=Path(str(row["worktree"])),
        base_sha=str(row["base_sha"]),
        stage=Stage(str(row["stage"])),
        revision=int(row["revision"]),
        session_id=str(row["session_id"]),
        task=str(row["task"]),
        packet_digest=str(row["packet_digest"]),
        environment_digest=str(row["environment_digest"]),
        workspace_digest=str(row["workspace_digest"]),
        evidence_digest=str(row["evidence_digest"]),
        active_phase=str(row["active_phase"]),
        blocked_code=str(row["blocked_code"]),
        blocked_message=str(row["blocked_message"]),
        event_count=int(row["event_count"]),
        event_head=str(row["event_head"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )
