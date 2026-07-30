from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from opencode_guardian.errors import GuardError
from opencode_guardian.facade import Guardian
from opencode_guardian.persistence import StateStore
from opencode_guardian.persistence.database import Database


def create_store(tmp_path: Path) -> tuple[StateStore, str]:
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-quality",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "image",
                "argv": ["pytest"],
                "timeout_seconds": 1,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    return store, run.run_id


def test_quality_drive_is_idempotent_and_event_anchored(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    first = store.drive_quality(
        run_id,
        expected_revision=0,
        request_id="request-1",
        drive_id="drive-1",
        result={"readiness": "NEEDS_PACKET", "evidence": {"failed": 0}},
    )
    second = store.drive_quality(
        run_id, expected_revision=0, request_id="request-1", drive_id="ignored", result={}
    )
    assert second == first
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM quality_drives").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE type = 'QUALITY_DRIVEN'"
            ).fetchone()[0]
            == 1
        )


def _downgrade_to_v3(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TABLE plan_candidates")
    connection.execute("DROP TABLE planning_review_receipts")
    connection.execute("DROP TABLE plan_approval_receipts")
    connection.execute("DROP TABLE planning_states")
    connection.execute("DROP TABLE planning_artifacts")
    connection.execute("DROP TABLE quality_confirmations")
    connection.execute("DROP TABLE quality_drives")
    connection.execute("PRAGMA user_version = 3")


def test_v3_database_migrates_to_current_schema(tmp_path: Path) -> None:
    path = tmp_path / "guard.db"
    Database(path)
    with sqlite3.connect(path) as connection:
        _downgrade_to_v3(connection)
        connection.commit()
    Database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        assert {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        } >= {
            "quality_drives",
            "quality_confirmations",
            "planning_artifacts",
            "planning_states",
            "plan_approval_receipts",
            "plan_candidates",
            "planning_review_receipts",
        }


def test_v3_to_v4_checkpoint_survives_a_v5_migration_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "guard.db"
    Database(path)
    with sqlite3.connect(path) as connection:
        _downgrade_to_v3(connection)
        connection.commit()

    def fail_v5(_connection: sqlite3.Connection) -> None:
        raise RuntimeError("v5 migration failpoint")

    monkeypatch.setattr(Database, "_create_v5_tables", staticmethod(fail_v5))
    with pytest.raises(RuntimeError, match="v5 migration failpoint"):
        Database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        } >= {"quality_drives", "quality_confirmations"}
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'planning_artifacts'"
            ).fetchone()
            is None
        )

    monkeypatch.undo()
    Database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7


@pytest.mark.parametrize("tamper", ["receipt_unique", "receipt_trigger"])
def test_v5_open_rejects_missing_receipt_constraint_or_trigger(tmp_path: Path, tamper: str) -> None:
    path = tmp_path / "guard.db"
    Database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        if tamper == "receipt_unique":
            connection.execute("DROP TABLE plan_approval_receipts")
            connection.execute(
                """
                CREATE TABLE plan_approval_receipts (
                    approval_id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    run_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
                    artifact_kind TEXT NOT NULL, artifact_digest TEXT NOT NULL,
                    base_sha TEXT NOT NULL, workspace_digest TEXT NOT NULL,
                    revision INTEGER NOT NULL, source TEXT NOT NULL, nonce TEXT NOT NULL,
                    issued_at TEXT NOT NULL, decision TEXT NOT NULL,
                    authority_ref TEXT NOT NULL, consumed_at TEXT NOT NULL DEFAULT ''
                )
                """
            )
        else:
            connection.execute("DROP TRIGGER plan_approval_receipts_immutable_delete")
            connection.execute(
                """
                CREATE TRIGGER plan_approval_receipts_immutable_delete
                BEFORE DELETE ON plan_approval_receipts
                BEGIN SELECT 1; END
                """
            )
        connection.commit()
    with pytest.raises(GuardError) as caught:
        Database(path)
    assert caught.value.code == "DATABASE_SCHEMA_INCOMPATIBLE"


def test_fitness_confirmation_is_idempotent_and_uses_the_drive_snapshot(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    drive = store.drive_quality(
        run_id,
        expected_revision=0,
        request_id="drive-request",
        drive_id="drive-1",
        result={"readiness": "EXTERNAL_REVIEW", "evidence": {"failed": 0}},
    )
    first = store.confirm_fitness(
        run_id,
        expected_revision=1,
        request_id="confirm-request",
        confirmation_id="confirmation-1",
        drive_id=drive["drive_id"],
    )
    second = store.confirm_fitness(
        run_id,
        expected_revision=0,
        request_id="confirm-request",
        confirmation_id="ignored",
        drive_id=drive["drive_id"],
    )
    assert first == second
    assert first["outcome"] == "FIT"


def test_guardian_quality_writes_require_current_context_and_active_session(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = store.bind_task(
        run_id,
        expected_revision=0,
        task="quality drive",
        session_id="session-1",
    )
    guardian = Guardian(store)
    status = guardian.status(run_id)
    values = {
        "expected_revision": status["revision"],
        "request_id": "drive-request",
        "session_id": "session-1",
        "context_digest": status["context_digest"],
        "skill_binding_digest": status["skill_binding"]["digest"],
    }
    first = guardian.drive_quality(run_id, **values)
    assert guardian.drive_quality(run_id, **values) == first
    assert store.get_run(run_id).revision == run.revision + 1

    current = guardian.status(run_id)
    confirmation_values = {
        "expected_revision": current["revision"],
        "request_id": "confirmation-request",
        "drive_id": first["drive_id"],
        "session_id": "session-1",
        "context_digest": current["context_digest"],
        "skill_binding_digest": current["skill_binding"]["digest"],
    }
    confirmation = guardian.confirm_fitness(run_id, **confirmation_values)
    assert guardian.confirm_fitness(run_id, **confirmation_values) == confirmation
    assert store.get_run(run_id).revision == run.revision + 2

    current = guardian.status(run_id)
    with pytest.raises(GuardError) as caught:
        guardian.drive_quality(
            run_id,
            **{
                **values,
                "expected_revision": current["revision"],
                "request_id": "other-request",
                "session_id": "other-session",
                "context_digest": current["context_digest"],
                "skill_binding_digest": current["skill_binding"]["digest"],
            },
        )
    assert caught.value.code == "SESSION_NOT_ATTACHED"

    with pytest.raises(GuardError) as caught:
        guardian.drive_quality(
            run_id,
            **{**values, "request_id": "stale-request"},
        )
    assert caught.value.code == "REVISION_CONFLICT"


def test_quality_integrity_rejects_a_tampered_drive_row(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    store.drive_quality(
        run_id,
        expected_revision=0,
        request_id="request-1",
        drive_id="drive-1",
        result={"readiness": "NEEDS_PACKET", "evidence": {"failed": 0}},
    )
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE quality_drives SET result_digest = 'forged' WHERE run_id = ?", (run_id,)
        )
        connection.commit()
    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"
