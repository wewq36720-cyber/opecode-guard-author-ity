from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, cast

from ..contracts import RunRecord, Stage, validate_task
from ..errors import GuardError
from ..integrity import canonical_json, digest_json
from .database import (
    Database,
    append_created_event,
    append_event,
    check_revision,
    run_from_row,
    select_run,
    utc_now,
)

_INACTIVE_BLOCK_CODES = frozenset({"STARTUP_FAILED", "LEGACY_RUN_RETIRED"})


class RunRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(
        self,
        *,
        run_id: str,
        project_root: Path,
        git_common_dir: Path,
        worktree: Path,
        base_sha: str,
        environment_digest: str,
        workspace_digest: str,
        checks: list[dict[str, Any]],
    ) -> RunRecord:
        created_at = utc_now()
        with self.database.write() as connection:
            connection.execute(
                """
                INSERT INTO runs(
                    id, project_root, git_common_dir, worktree, base_sha,
                    stage, revision, session_id, task, packet_digest,
                    environment_digest, workspace_digest, evidence_digest,
                    active_phase, blocked_code, blocked_message,
                    event_count, event_head, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, '', '', '', ?, ?, '', '', '', '', 0, '', ?, ?)
                """,
                (
                    run_id,
                    str(project_root.resolve()),
                    str(git_common_dir.resolve()),
                    str(worktree.resolve()),
                    base_sha,
                    Stage.PLANNING.value,
                    environment_digest,
                    workspace_digest,
                    created_at,
                    created_at,
                ),
            )
            self._insert_checks(connection, run_id, checks)
            append_created_event(connection, run_id)
            return run_from_row(select_run(connection, run_id))

    def get(self, run_id: str) -> RunRecord:
        with self.database.connect(readonly=True) as connection:
            return run_from_row(select_run(connection, run_id))

    def find_active(self, project_root: Path) -> RunRecord | None:
        root = str(project_root.resolve())
        with self.database.connect(readonly=True) as connection:
            run_ids = connection.execute(
                """
                SELECT id FROM runs
                ORDER BY created_at DESC
                """
            ).fetchall()
            rows = [select_run(connection, str(row["id"])) for row in run_ids]
        rows = [
            row
            for row in rows
            if row["project_root"] == root
            and row["stage"] != Stage.ACCEPTED.value
            and row["blocked_code"] not in _INACTIVE_BLOCK_CODES
        ]
        if len(rows) > 1:
            raise GuardError(
                "MULTIPLE_ACTIVE_RUNS",
                "Project has more than one active Guard Run.",
                run_ids=[str(row["id"]) for row in rows],
            )
        return run_from_row(rows[0]) if rows else None

    def cancel_startup(self, run_id: str) -> RunRecord:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            if row["stage"] != Stage.PLANNING.value or row["task"]:
                raise GuardError(
                    "STARTUP_CANCEL_NOT_ALLOWED",
                    "Only an unbound planning Run can be cancelled during startup.",
                )
            if row["blocked_code"] == "STARTUP_FAILED":
                return run_from_row(row)
            if row["blocked_code"]:
                raise GuardError(
                    "STARTUP_CANCEL_NOT_ALLOWED",
                    "Run was blocked for a reason unrelated to startup.",
                )
            connection.execute(
                "UPDATE runs SET blocked_code = ?, blocked_message = ? WHERE id = ?",
                (
                    "STARTUP_FAILED",
                    "Run startup failed before OpenCode became active.",
                    run_id,
                ),
            )
            append_event(
                connection,
                run_id,
                event="STARTUP_FAILED",
                actor="authority",
                payload={"code": "STARTUP_FAILED"},
            )
            return run_from_row(select_run(connection, run_id))

    def bind_task(
        self,
        run_id: str,
        *,
        expected_revision: int,
        task: str,
        session_id: str,
    ) -> RunRecord:
        normalized_task = validate_task(task)
        normalized_session = _control_text(session_id, "session_id", 200)
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            if row["blocked_code"]:
                raise GuardError("RUN_BLOCKED", "Blocked Run cannot bind a task.")
            if row["task"]:
                if row["task"] == normalized_task and row["session_id"] == normalized_session:
                    return run_from_row(row)
                raise GuardError("RUN_ALREADY_BOUND", "Run is already bound to a task.")
            if row["stage"] != Stage.PLANNING.value:
                raise GuardError("TASK_NOT_ALLOWED", "Task can only be bound while planning.")
            connection.execute(
                "UPDATE runs SET task = ?, session_id = ? WHERE id = ?",
                (normalized_task, normalized_session, run_id),
            )
            append_event(
                connection,
                run_id,
                event="TASK_BOUND",
                actor=f"session:{normalized_session}",
                payload={
                    "task_digest": digest_json(normalized_task),
                    "participant_attached": True,
                },
            )
            bound = connection.execute(
                """
                SELECT revision, created_at FROM events
                WHERE run_id = ? AND type = 'TASK_BOUND' ORDER BY seq DESC LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO run_sessions(
                    run_id, session_id, status, attached_revision, attached_at, revoked_at
                ) VALUES (?, ?, 'ACTIVE', ?, ?, '')
                """,
                (run_id, normalized_session, int(bound["revision"]), str(bound["created_at"])),
            )
            return run_from_row(select_run(connection, run_id))

    def attach_session(self, run_id: str, session_id: str, *, expected_revision: int) -> RunRecord:
        normalized = _control_text(session_id, "session_id", 200)
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            self._assert_session_owner(connection, run_id, normalized)
            participant = self._participant(connection, run_id, normalized)
            if participant is not None:
                if participant["status"] == "REVOKED":
                    raise GuardError("SESSION_REVOKED", "OpenCode session access was revoked.")
                return run_from_row(row)
            if connection.execute(
                "SELECT 1 FROM write_leases WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise GuardError(
                    "WRITE_LEASE_PENDING",
                    "Complete the pending write before changing participants.",
                )
            attached_revision = int(row["revision"]) + 1
            append_event(
                connection,
                run_id,
                event="SESSION_ATTACHED",
                actor="authority",
                payload={"session_id": normalized},
            )
            attached_at = connection.execute(
                "SELECT created_at FROM events WHERE run_id = ? AND revision = ?",
                (run_id, attached_revision),
            ).fetchone()["created_at"]
            connection.execute(
                """
                INSERT INTO run_sessions(
                    run_id, session_id, status, attached_revision, attached_at, revoked_at
                ) VALUES (?, ?, 'ACTIVE', ?, ?, '')
                """,
                (run_id, normalized, attached_revision, attached_at),
            )
            return run_from_row(select_run(connection, run_id))

    def revoke_session(self, run_id: str, session_id: str) -> RunRecord:
        normalized = _control_text(session_id, "session_id", 200)
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            self._assert_session_owner(connection, run_id, normalized)
            participant = self._participant(connection, run_id, normalized)
            if participant is not None:
                if participant["status"] == "REVOKED":
                    return run_from_row(row)
            elif row["session_id"] == normalized:
                attached_revision, attached_at = self._legacy_attachment(
                    connection, run_id, normalized, int(row["revision"])
                )
                connection.execute(
                    """
                    INSERT INTO run_sessions(
                        run_id, session_id, status, attached_revision, attached_at, revoked_at
                    ) VALUES (?, ?, 'ACTIVE', ?, ?, '')
                    """,
                    (run_id, normalized, attached_revision, attached_at),
                )
            else:
                raise GuardError(
                    "SESSION_NOT_ATTACHED",
                    "OpenCode session is not attached to this Run.",
                )
            if connection.execute(
                "SELECT 1 FROM write_leases WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise GuardError(
                    "WRITE_LEASE_PENDING",
                    "Complete the pending write before changing participants.",
                )
            revoked_revision = int(row["revision"]) + 1
            append_event(
                connection,
                run_id,
                event="SESSION_REVOKED",
                actor="authority",
                payload={"session_id": normalized},
            )
            revoked_at = connection.execute(
                "SELECT created_at FROM events WHERE run_id = ? AND revision = ?",
                (run_id, revoked_revision),
            ).fetchone()["created_at"]
            connection.execute(
                """
                UPDATE run_sessions
                SET status = 'REVOKED', revoked_at = ?
                WHERE run_id = ? AND session_id = ?
                """,
                (revoked_at, run_id, normalized),
            )
            return run_from_row(select_run(connection, run_id))

    def assert_session(self, run_id: str, session_id: str) -> RunRecord:
        normalized = _control_text(session_id, "session_id", 200)
        with self.database.connect(readonly=True) as connection:
            row = select_run(connection, run_id)
            self._assert_session_owner(connection, run_id, normalized)
            participant = self._participant(connection, run_id, normalized)
            if participant is not None:
                if participant["status"] == "REVOKED":
                    raise GuardError("SESSION_REVOKED", "OpenCode session access was revoked.")
                return run_from_row(row)
            if row["session_id"] == normalized:
                return run_from_row(row)
            raise GuardError(
                "SESSION_NOT_ATTACHED",
                "OpenCode session is not attached to this Run.",
            )

    def block(
        self,
        run_id: str,
        *,
        code: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> RunRecord:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            if row["blocked_code"]:
                return run_from_row(row)
            connection.execute(
                "UPDATE runs SET blocked_code = ?, blocked_message = ? WHERE id = ?",
                (code, message, run_id),
            )
            append_event(
                connection,
                run_id,
                event="RUN_BLOCKED",
                actor="authority",
                payload={"code": code, "message": message, **(payload or {})},
            )
            return run_from_row(select_run(connection, run_id))

    def list_checks(self, run_id: str) -> list[dict[str, Any]]:
        with self.database.connect(readonly=True) as connection:
            select_run(connection, run_id)
            rows = connection.execute(
                "SELECT definition_json FROM checks WHERE run_id = ? ORDER BY check_id",
                (run_id,),
            ).fetchall()
        import json

        return [json.loads(str(row["definition_json"])) for row in rows]

    @staticmethod
    def _insert_checks(
        connection: sqlite3.Connection,
        run_id: str,
        checks: list[dict[str, Any]],
    ) -> None:
        if not checks:
            raise GuardError("CHECKS_REQUIRED", "A Run requires registered checks.")
        seen: set[str] = set()
        for check in checks:
            check_id = _control_text(check.get("id"), "check.id", 64)
            if check_id in seen:
                raise GuardError("DUPLICATE_CHECK", f"Duplicate check ID: {check_id}")
            seen.add(check_id)
            body = canonical_json(check)
            connection.execute(
                """
                INSERT INTO checks(run_id, check_id, definition_json, definition_digest)
                VALUES (?, ?, ?, ?)
                """,
                (run_id, check_id, body, digest_json(check)),
            )

    @staticmethod
    def _participant(
        connection: sqlite3.Connection, run_id: str, session_id: str
    ) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM run_sessions WHERE run_id = ? AND session_id = ?",
                (run_id, session_id),
            ).fetchone(),
        )

    @staticmethod
    def _assert_session_owner(connection: sqlite3.Connection, run_id: str, session_id: str) -> None:
        owners = {
            str(row["run_id"])
            for row in connection.execute(
                """
                SELECT run_id FROM run_sessions WHERE session_id = ?
                UNION
                SELECT id AS run_id FROM runs WHERE session_id = ?
                """,
                (session_id, session_id),
            ).fetchall()
        }
        if owners - {run_id}:
            raise GuardError(
                "SESSION_RUN_MISMATCH",
                "OpenCode session belongs to a different Guard Run.",
            )

    @staticmethod
    def _legacy_attachment(
        connection: sqlite3.Connection,
        run_id: str,
        session_id: str,
        fallback_revision: int,
    ) -> tuple[int, str]:
        event = connection.execute(
            """
            SELECT revision, created_at FROM events
            WHERE run_id = ? AND type = 'TASK_BOUND' AND actor = ?
            ORDER BY seq LIMIT 1
            """,
            (run_id, f"session:{session_id}"),
        ).fetchone()
        if event is None:
            return fallback_revision, utc_now()
        return int(event["revision"]), str(event["created_at"])


def _control_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > maximum:
        raise GuardError("INVALID_CONTROL_VALUE", f"{field} must be bounded text.")
    return value.strip()
