from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Barrier

import pytest

import opencode_guardian.persistence.database as database_module
import opencode_guardian.persistence.execution as execution_module
from opencode_guardian.contracts import Stage, packet_digest
from opencode_guardian.errors import GuardError
from opencode_guardian.evidence import VerificationEvidence, evidence_set_digest
from opencode_guardian.integrity import canonical_json, digest_json, load_bounded_json
from opencode_guardian.persistence import StateStore


def packet() -> dict[str, object]:
    return {
        "certainty": {"confirmed": True, "unresolved_items": [], "assumptions": []},
        "requirements": [{"id": "R1", "statement": "实现受控修改。", "acceptance_ids": ["A1"]}],
        "acceptance": [
            {
                "id": "A1",
                "criterion": "受控文件通过检查。",
                "verification": ["pytest"],
                "required_paths": ["src/app.py"],
            }
        ],
        "constraints": ["未知工具默认拒绝。"],
        "non_goals": ["不修改外部项目。"],
        "stop_conditions": ["可信验证不可用。"],
        "architecture": {
            "objective": "最小受控开发链路。",
            "public_interface": "Application",
            "dependency_direction": "adapter -> application -> domain",
            "components": [{"name": "Application", "responsibility": "编排。", "dependencies": []}],
            "trust_boundaries": ["模型输入不可信。"],
            "data_flows": ["请求进入守卫后写入。"],
            "concurrency": {
                "ordering": "按 Run revision。",
                "idempotency": "按 call_id。",
                "backpressure": "有界请求。",
                "limits": "单消息一 MiB。",
                "failures": "失败关闭。",
                "scaling": "按 Run 扩展。",
                "observability": "记录事件摘要。",
            },
        },
        "phases": [
            {
                "id": "P1",
                "goal": "实现。",
                "requirement_ids": ["R1"],
                "acceptance_ids": ["A1"],
                "allowed_paths": ["src/**"],
                "check_ids": ["pytest"],
            }
        ],
    }


def create_store(tmp_path: Path) -> tuple[StateStore, str]:
    store = StateStore(tmp_path / "guard.db")
    run_id = "run-test"
    store.create_run(
        run_id=run_id,
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktrees" / run_id,
        base_sha="a" * 40,
        environment_digest="env",
        workspace_digest="workspace-0",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    return store, run_id


def freeze_packet(store: StateStore, run_id: str):
    run = store.get_run(run_id)
    run = store.bind_task(
        run_id,
        expected_revision=run.revision,
        task="实现功能",
        session_id="session-1",
    )
    body = packet()
    return store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )


def make_participants_legacy(database: Path, run_id: str) -> None:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        bound = connection.execute(
            "SELECT payload_json FROM events WHERE run_id = ? AND type = 'TASK_BOUND'",
            (run_id,),
        ).fetchone()
        if bound is None:
            return
        payload = load_bounded_json(bound["payload_json"], code="TEST", label="payload")
        payload.pop("participant_attached", None)
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE run_id = ? AND type = 'TASK_BOUND'",
            (canonical_json(payload), run_id),
        )
        connection.execute("DELETE FROM run_sessions WHERE run_id = ?", (run_id,))
        events = connection.execute(
            "SELECT * FROM events WHERE run_id = ? ORDER BY seq", (run_id,)
        ).fetchall()
        previous = "0" * 64
        for row in events:
            envelope = {
                "run_id": run_id,
                "type": row["type"],
                "actor": row["actor"],
                "payload": load_bounded_json(row["payload_json"], code="TEST", label="payload"),
                "revision": row["revision"],
                "before_stage": row["before_stage"],
                "after_stage": row["after_stage"],
                "created_at": row["created_at"],
            }
            head = digest_json({"previous_hash": previous, "event": envelope})
            connection.execute(
                "UPDATE events SET previous_hash = ?, event_hash = ? WHERE run_id = ? AND seq = ?",
                (previous, head, run_id, row["seq"]),
            )
            previous = head
        connection.execute("UPDATE runs SET event_head = ? WHERE id = ?", (previous, run_id))
        connection.commit()


def rehash_event_chain(connection: sqlite3.Connection, run_id: str) -> None:
    connection.row_factory = sqlite3.Row
    previous = "0" * 64
    rows = connection.execute(
        "SELECT * FROM events WHERE run_id = ? ORDER BY seq", (run_id,)
    ).fetchall()
    for row in rows:
        envelope = {
            "run_id": row["run_id"],
            "type": row["type"],
            "actor": row["actor"],
            "payload": load_bounded_json(row["payload_json"], code="TEST", label="event payload"),
            "revision": row["revision"],
            "before_stage": row["before_stage"],
            "after_stage": row["after_stage"],
            "created_at": row["created_at"],
        }
        event_hash = digest_json({"previous_hash": previous, "event": envelope})
        connection.execute(
            "UPDATE events SET previous_hash = ?, event_hash = ? WHERE run_id = ? AND seq = ?",
            (previous, event_hash, run_id, row["seq"]),
        )
        previous = event_hash
    connection.execute("UPDATE runs SET event_head = ? WHERE id = ?", (previous, run_id))


def database_snapshot(database: Path) -> tuple[int, tuple[str, ...]]:
    with sqlite3.connect(database) as connection:
        return (
            int(connection.execute("PRAGMA user_version").fetchone()[0]),
            tuple(connection.iterdump()),
        )


def two_phase_packet() -> dict[str, object]:
    body = deepcopy(packet())
    body["phases"] = [
        body["phases"][0],
        {
            "id": "P2",
            "goal": "收尾。",
            "requirement_ids": ["R1"],
            "acceptance_ids": ["A1"],
            "allowed_paths": ["src/**"],
            "check_ids": ["pytest"],
        },
    ]
    return body


def freeze_body(store: StateStore, run_id: str, body: dict[str, object]):
    run = store.get_run(run_id)
    run = store.bind_task(
        run_id,
        expected_revision=run.revision,
        task="实现多阶段功能",
        session_id="session-1",
    )
    return store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )


def revise_after_completed_phase(tmp_path: Path):
    store, run_id = create_store(tmp_path)
    first_body = two_phase_packet()
    first = freeze_body(store, run_id, first_body)
    lease = store.create_write_lease(
        run_id,
        expected_revision=first.revision,
        session_id="session-1",
        call_id="snapshot-write",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="workspace-0",
        before_files=[],
    )
    run = store.finish_write(
        run_id,
        expected_revision=lease["revision"],
        session_id="session-1",
        call_id="snapshot-write",
        workspace_digest="workspace-1",
        actual_paths=["src/app.py"],
    )
    run = store.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="changed",
        rationale="第一阶段完成",
    )
    candidate = deepcopy(first_body)
    candidate["constraints"] = ["修订后的约束。"]
    revised = store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=candidate,
        digest=packet_digest(candidate),
    )
    return store, run_id, revised


def rebuild_artifacts_as_v2(connection: sqlite3.Connection) -> None:
    connection.execute("ALTER TABLE artifacts RENAME TO artifacts_v3_source")
    connection.execute(
        """
        CREATE TABLE artifacts (
            run_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            version INTEGER NOT NULL,
            body_json TEXT NOT NULL,
            digest TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (run_id, kind),
            FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        INSERT INTO artifacts(run_id, kind, version, body_json, digest, created_at)
        SELECT run_id, kind, version, body_json, digest, created_at
        FROM artifacts_v3_source
        """
    )
    connection.execute("DROP TABLE artifacts_v3_source")


def remove_v5_planning_tables(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TABLE plan_candidates")
    connection.execute("DROP TABLE planning_review_receipts")
    connection.execute("DROP TABLE plan_approval_receipts")
    connection.execute("DROP TABLE planning_states")
    connection.execute("DROP TABLE planning_artifacts")


def test_schema_contains_only_the_fifteen_runtime_tables(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "guard.db")
    with sqlite3.connect(store.database) as connection:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    assert names == {
        "runs",
        "artifacts",
        "events",
        "checks",
        "evidence",
        "phase_executions",
        "write_leases",
        "run_sessions",
        "quality_drives",
        "quality_confirmations",
        "planning_artifacts",
        "planning_states",
        "plan_approval_receipts",
        "plan_candidates",
        "planning_review_receipts",
    }


@pytest.mark.parametrize("variation", ["check", "foreign_key", "extra_unique"])
def test_v3_artifact_constraints_are_verified_on_open(tmp_path: Path, variation: str) -> None:
    database = tmp_path / "guard.db"
    StateStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE artifacts RENAME TO artifacts_original")
        check = "CHECK (version >= 1)" if variation != "check" else ""
        foreign_key = (
            ", FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE"
            if variation != "foreign_key"
            else ""
        )
        extra_unique = ", UNIQUE (run_id, digest)" if variation == "extra_unique" else ""
        connection.execute(
            f"""
            CREATE TABLE artifacts(
                run_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                version INTEGER NOT NULL {check},
                body_json TEXT NOT NULL,
                digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (run_id, kind, version),
                UNIQUE (run_id, kind, digest)
                {extra_unique}
                {foreign_key}
            )
            """
        )
        connection.execute(
            """
            INSERT INTO artifacts(run_id, kind, version, body_json, digest, created_at)
            SELECT run_id, kind, version, body_json, digest, created_at
            FROM artifacts_original
            """
        )
        connection.execute("DROP TABLE artifacts_original")
        connection.commit()

    with pytest.raises(GuardError) as caught:
        StateStore(database)
    assert caught.value.code == "DATABASE_SCHEMA_INCOMPATIBLE"


def test_orphan_artifacts_are_rejected_on_open(tmp_path: Path) -> None:
    database = tmp_path / "guard.db"
    StateStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """
            INSERT INTO artifacts(run_id, kind, version, body_json, digest, created_at)
            VALUES (?, 'packet', 1, '{}', ?, '2026-01-01T00:00:00+00:00')
            """,
            ("orphan-run", "0" * 64),
        )
        connection.commit()

    with pytest.raises(GuardError) as caught:
        StateStore(database)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_v1_schema_migration_preserves_historical_state(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    make_participants_legacy(store.database, run_id)
    historical_tables = (
        "runs",
        "artifacts",
        "events",
        "checks",
        "evidence",
        "phase_executions",
        "write_leases",
    )
    with sqlite3.connect(store.database) as connection:
        rebuild_artifacts_as_v2(connection)
        before = {
            table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in historical_tables
        }
        remove_v5_planning_tables(connection)
        connection.execute("DROP TABLE quality_confirmations")
        connection.execute("DROP TABLE quality_drives")
        connection.execute("DROP TABLE run_sessions")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()

    migrated = StateStore(store.database)

    with sqlite3.connect(store.database) as connection:
        after = {
            table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in historical_tables
        }
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        assert connection.execute("SELECT COUNT(*) FROM run_sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM quality_drives").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM quality_confirmations").fetchone()[0] == 0
    assert after == before
    assert migrated.assert_session(run_id, "session-1").run_id == run_id


def test_v1_schema_migration_failure_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "guard.db"
    StateStore(database)
    with sqlite3.connect(database) as connection:
        remove_v5_planning_tables(connection)
        connection.execute("DROP TABLE quality_confirmations")
        connection.execute("DROP TABLE quality_drives")
        connection.execute("DROP TABLE run_sessions")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    monkeypatch.setattr(database_module, "RUN_SESSIONS_SCHEMA", "CREATE TABL broken")

    with pytest.raises(GuardError) as caught:
        StateStore(database)

    assert caught.value.code == "PERSISTED_STATE_BROKEN"
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'run_sessions'"
            ).fetchone()[0]
            == 0
        )


def test_v2_schema_migration_preserves_participants_and_history(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    with sqlite3.connect(store.database) as connection:
        rebuild_artifacts_as_v2(connection)
        remove_v5_planning_tables(connection)
        connection.execute("DROP TABLE quality_confirmations")
        connection.execute("DROP TABLE quality_drives")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()

    migrated = StateStore(store.database)
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        assert connection.execute("SELECT COUNT(*) FROM run_sessions").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM quality_drives").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM quality_confirmations").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT version FROM artifacts WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == 1
        )
    assert migrated.get_artifact(run_id)["version"] == 1
    assert migrated.assert_session(run_id, "session-1").run_id == run_id


def test_v2_schema_migration_failure_rolls_back_to_v2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    with sqlite3.connect(store.database) as connection:
        rebuild_artifacts_as_v2(connection)
        remove_v5_planning_tables(connection)
        connection.execute("DROP TABLE quality_confirmations")
        connection.execute("DROP TABLE quality_drives")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
    monkeypatch.setattr(database_module, "ARTIFACTS_V3_SCHEMA", "CREATE TABLE artifacts_v3 (")

    with pytest.raises(GuardError) as caught:
        StateStore(store.database)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        columns = [row[1] for row in connection.execute("PRAGMA table_info(artifacts)")]
        primary = [row[1] for row in connection.execute("PRAGMA table_info(artifacts)") if row[5]]
        assert columns == ["run_id", "kind", "version", "body_json", "digest", "created_at"]
        assert primary == ["run_id", "kind"]
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM artifacts WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == 1
        )


def test_v2_schema_final_verification_failure_rolls_back_user_version_and_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    with sqlite3.connect(store.database) as connection:
        rebuild_artifacts_as_v2(connection)
        remove_v5_planning_tables(connection)
        connection.execute("DROP TABLE quality_confirmations")
        connection.execute("DROP TABLE quality_drives")
        connection.execute("PRAGMA user_version = 2")
        before = tuple(connection.execute("SELECT * FROM artifacts ORDER BY rowid").fetchall())
        connection.commit()

    def fail_final_verification(_connection: sqlite3.Connection) -> None:
        raise RuntimeError("final migration verification failed")

    monkeypatch.setattr(
        database_module.Database,
        "_assert_v3_artifacts",
        staticmethod(fail_final_verification),
    )
    with pytest.raises(GuardError) as caught:
        StateStore(store.database)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert tuple(connection.execute("SELECT * FROM artifacts ORDER BY rowid")) == before
        assert [row[1] for row in connection.execute("PRAGMA table_info(artifacts)") if row[5]] == [
            "run_id",
            "kind",
        ]
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'artifacts_v3'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("variation", ["foreign_key", "primary_order", "extra_unique", "on_update"])
def test_v2_artifact_constraints_must_match_before_migration(
    tmp_path: Path, variation: str
) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    with sqlite3.connect(store.database) as connection:
        rebuild_artifacts_as_v2(connection)
        remove_v5_planning_tables(connection)
        connection.execute("ALTER TABLE artifacts RENAME TO artifacts_with_fk")
        primary = (
            "PRIMARY KEY (kind, run_id)"
            if variation == "primary_order"
            else "PRIMARY KEY (run_id, kind)"
        )
        extra_unique = ", UNIQUE (run_id, digest)" if variation == "extra_unique" else ""
        if variation == "foreign_key":
            foreign_key = ""
        elif variation == "on_update":
            foreign_key = (
                ", FOREIGN KEY (run_id) REFERENCES runs(id) ON UPDATE CASCADE ON DELETE CASCADE"
            )
        else:
            foreign_key = ", FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE"
        connection.execute(
            f"""
            CREATE TABLE artifacts(
                run_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                version INTEGER NOT NULL,
                body_json TEXT NOT NULL,
                digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                {primary}
                {extra_unique}
                {foreign_key}
            )
            """
        )
        connection.execute(
            """
            INSERT INTO artifacts(run_id, kind, version, body_json, digest, created_at)
            SELECT run_id, kind, version, body_json, digest, created_at FROM artifacts_with_fk
            """
        )
        connection.execute("DROP TABLE artifacts_with_fk")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()

    with pytest.raises(GuardError) as caught:
        StateStore(store.database)
    assert caught.value.code == "DATABASE_SCHEMA_INCOMPATIBLE"
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 1


def test_participant_attach_is_idempotent_and_revoke_is_final(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    before = store.get_run(run_id)

    attached = store.attach_session(run_id, "session-new", expected_revision=before.revision)
    repeated = store.attach_session(run_id, "session-new", expected_revision=attached.revision)

    assert attached.revision == repeated.revision == before.revision + 1
    assert attached.event_count == repeated.event_count == before.event_count + 1
    assert store.assert_session(run_id, "session-new").run_id == run_id
    with sqlite3.connect(store.database) as connection:
        row = connection.execute(
            "SELECT status, attached_revision, attached_at, revoked_at FROM run_sessions"
        ).fetchone()
        assert row[:2] == ("ACTIVE", attached.revision)
        assert row[2]
        assert row[3] == ""

    store.revoke_session(run_id, "session-new")
    with sqlite3.connect(store.database) as connection:
        revoked_at = connection.execute(
            "SELECT revoked_at FROM run_sessions WHERE session_id = 'session-new'"
        ).fetchone()[0]
    store.revoke_session(run_id, "session-new")
    with sqlite3.connect(store.database) as connection:
        assert connection.execute(
            "SELECT status, revoked_at FROM run_sessions WHERE session_id = 'session-new'"
        ).fetchone() == ("REVOKED", revoked_at)
    for operation in (
        lambda: store.assert_session(run_id, "session-new"),
        lambda: store.attach_session(
            run_id,
            "session-new",
            expected_revision=store.get_run(run_id).revision,
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "SESSION_REVOKED"

    for operation in (
        lambda: store.assert_session(run_id, "session-unknown"),
        lambda: store.revoke_session(run_id, "session-unknown"),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "SESSION_NOT_ATTACHED"


def test_participant_session_cannot_cross_runs(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    other_run_id = "run-other"
    store.create_run(
        run_id=other_run_id,
        project_root=tmp_path / "other-project",
        git_common_dir=tmp_path / "other-project" / ".git",
        worktree=tmp_path / "worktrees" / other_run_id,
        base_sha="c" * 40,
        environment_digest="other-env",
        workspace_digest="other-workspace",
        checks=store.list_checks(run_id),
    )
    store.attach_session(
        run_id,
        "session-shared",
        expected_revision=store.get_run(run_id).revision,
    )

    for operation in (
        lambda: store.assert_session(other_run_id, "session-shared"),
        lambda: store.attach_session(
            other_run_id,
            "session-shared",
            expected_revision=store.get_run(other_run_id).revision,
        ),
        lambda: store.revoke_session(other_run_id, "session-shared"),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "SESSION_RUN_MISMATCH"


def test_legacy_session_is_implicit_until_revoked(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = store.bind_task(
        run_id,
        expected_revision=0,
        task="legacy participant",
        session_id="session-legacy",
    )
    make_participants_legacy(store.database, run_id)
    legacy = store.assert_session(run_id, "session-legacy")
    assert legacy.run_id == run.run_id
    assert legacy.session_id == run.session_id
    assert legacy.revision == run.revision
    assert legacy.stage is run.stage

    store.revoke_session(run_id, "session-legacy")

    with sqlite3.connect(store.database) as connection:
        participant = connection.execute(
            """
            SELECT status, attached_revision, attached_at, revoked_at
            FROM run_sessions WHERE run_id = ? AND session_id = ?
            """,
            (run_id, "session-legacy"),
        ).fetchone()
        bound = connection.execute(
            """
            SELECT revision, created_at FROM events
            WHERE run_id = ? AND type = 'TASK_BOUND'
            """,
            (run_id,),
        ).fetchone()
    assert participant[:3] == ("REVOKED", *bound)
    assert participant[3]
    with pytest.raises(GuardError) as caught:
        store.assert_session(run_id, "session-legacy")
    assert caught.value.code == "SESSION_REVOKED"


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE run_sessions SET attached_revision = 999 WHERE run_id = ?",
        "UPDATE run_sessions SET attached_at = 'not-a-time' WHERE run_id = ?",
        "UPDATE run_sessions SET session_id = ' padded ' WHERE run_id = ?",
        "UPDATE run_sessions SET attached_revision = 'not-an-integer' WHERE run_id = ?",
    ],
)
def test_tampered_participant_state_fails_closed(tmp_path: Path, mutation: str) -> None:
    store, run_id = create_store(tmp_path)
    store.attach_session(
        run_id,
        "session-new",
        expected_revision=store.get_run(run_id).revision,
    )
    with sqlite3.connect(store.database) as connection:
        connection.execute(mutation, (run_id,))
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)

    assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_packet_freeze_activates_the_first_phase(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = store.get_run(run_id)
    run = store.bind_task(
        run_id,
        expected_revision=run.revision,
        task="实现功能",
        session_id="session-1",
    )
    body = packet()
    run = store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )
    assert run.stage is Stage.IMPLEMENTING
    assert run.active_phase == "P1"
    assert store.get_artifact(run_id)["body"] == body


def test_persistence_verifier_keeps_a_legacy_frozen_packet_readable(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = store.get_run(run_id)
    run = store.bind_task(
        run_id,
        expected_revision=run.revision,
        task="实现功能",
        session_id="session-1",
    )
    body = packet()
    del body["certainty"]
    body["phases"] = [
        body["phases"][0],
        {
            **body["phases"][0],
            "id": "P2",
            "allowed_paths": ["tests/**"],
        },
    ]
    store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )

    assert store.get_run(run_id).run_id == run_id
    assert store.get_artifact(run_id)["body"] == body
    assert store.find_active(tmp_path / "project").run_id == run_id


def test_persistence_verifier_rejects_current_packet_with_incomplete_repair_scope(
    tmp_path: Path,
) -> None:
    store, run_id = create_store(tmp_path)
    run = store.bind_task(
        run_id,
        expected_revision=0,
        task="current packet",
        session_id="session-1",
    )
    body = packet()
    body["phases"] = [
        body["phases"][0],
        {
            **body["phases"][0],
            "id": "P2",
            "allowed_paths": ["tests/**"],
        },
    ]
    with pytest.raises(GuardError) as caught:
        store.submit_packet(
            run_id,
            expected_revision=run.revision,
            packet=body,
            digest=packet_digest(body),
        )

    assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_artifact_validation_and_read_share_one_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    original_select_run = execution_module.select_run

    def select_then_tamper(
        connection: sqlite3.Connection,
        selected_run_id: str,
        *,
        verify: bool = True,
        verify_state: bool = True,
    ) -> sqlite3.Row:
        row = original_select_run(
            connection,
            selected_run_id,
            verify=verify,
            verify_state=verify_state,
        )
        assert connection.in_transaction
        with sqlite3.connect(store.database) as writer:
            writer.execute(
                "UPDATE artifacts SET body_json = '{}' WHERE run_id = ?",
                (run_id,),
            )
            writer.commit()
        return row

    monkeypatch.setattr(execution_module, "select_run", select_then_tamper)

    assert store.get_artifact(run_id)["body"] == packet()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": value})


def test_startup_failure_is_recorded_but_not_active(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)

    cancelled = store.cancel_startup(run_id)

    assert cancelled.blocked_code == "STARTUP_FAILED"
    assert cancelled.event_count == 2
    assert store.cancel_startup(run_id).event_count == 2
    assert store.find_active(tmp_path / "project") is None
    with sqlite3.connect(store.database) as connection:
        event = connection.execute(
            "SELECT type FROM events WHERE run_id = ? ORDER BY seq DESC LIMIT 1",
            (run_id,),
        ).fetchone()[0]
    assert event == "STARTUP_FAILED"


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE events SET payload_json = '{\"tampered\":true}' WHERE run_id = ?",
        "UPDATE events SET event_hash = 'broken' WHERE run_id = ?",
        "UPDATE events SET previous_hash = 'broken' WHERE run_id = ?",
        "UPDATE events SET seq = 2 WHERE run_id = ?",
        "UPDATE events SET revision = 3 WHERE run_id = ?",
        "UPDATE events SET before_stage = 'IMPLEMENTING' WHERE run_id = ?",
        "DELETE FROM events WHERE run_id = ?",
        "UPDATE runs SET event_head = 'broken' WHERE id = ?",
        "UPDATE runs SET event_count = 2 WHERE id = ?",
        "UPDATE runs SET revision = 2 WHERE id = ?",
        "UPDATE runs SET stage = 'IMPLEMENTING' WHERE id = ?",
        "UPDATE events SET payload_json = '{' WHERE run_id = ?",
    ],
)
def test_tampered_event_chain_blocks_reads_and_writes(
    tmp_path: Path,
    mutation: str,
) -> None:
    store, run_id = create_store(tmp_path)
    with sqlite3.connect(store.database) as connection:
        connection.execute(mutation, (run_id,))
        connection.commit()
        tampered_event_count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    for operation in (
        lambda: store.get_run(run_id),
        lambda: store.bind_task(
            run_id,
            expected_revision=0,
            task="blocked",
            session_id="session-1",
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "EVENT_CHAIN_BROKEN"

    with sqlite3.connect(store.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == tampered_event_count
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE runs SET stage = 'ACCEPTED' WHERE id = ?",
        "UPDATE runs SET blocked_code = 'STARTUP_FAILED' WHERE id = ?",
        "UPDATE runs SET project_root = 'C:/hidden' WHERE id = ?",
    ],
)
def test_find_active_verifies_every_run_before_filtering(tmp_path: Path, mutation: str) -> None:
    store, run_id = create_store(tmp_path)
    with sqlite3.connect(store.database) as connection:
        connection.execute(mutation, (run_id,))
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.find_active(tmp_path / "project")

    expected = "EVENT_CHAIN_BROKEN" if "stage" in mutation else "PERSISTED_STATE_BROKEN"
    assert caught.value.code == expected


@pytest.mark.parametrize(
    "payload",
    [
        "[" * 20_000 + "]" * 20_000,
        '"' + "x" * (512 * 1024) + '"',
    ],
    ids=["too-deep", "too-large"],
)
def test_event_payload_limits_fail_closed(tmp_path: Path, payload: str) -> None:
    store, run_id = create_store(tmp_path)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE run_id = ? AND seq = 1",
            (payload, run_id),
        )
        connection.commit()
        count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    for operation in (
        lambda: store.get_run(run_id),
        lambda: store.bind_task(
            run_id,
            expected_revision=0,
            task="blocked",
            session_id="session-1",
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "EVENT_CHAIN_BROKEN"
    with sqlite3.connect(store.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == count
        )


@pytest.mark.parametrize(
    "payload",
    [
        "NaN",
        "Infinity",
        "-Infinity",
        '{"x": NaN}',
        "1e9999",
        "-1e9999",
        '{"x": 1e9999}',
        '{"x": -1e9999}',
        "[1e9999]",
        "[-1e9999]",
    ],
)
def test_event_payload_rejects_nonstandard_numbers(tmp_path: Path, payload: str) -> None:
    store, run_id = create_store(tmp_path)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE run_id = ? AND seq = 1",
            (payload, run_id),
        )
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)

    assert caught.value.code == "EVENT_CHAIN_BROKEN"


def test_bounded_json_preserves_finite_exponents() -> None:
    assert load_bounded_json("[1e3, -2.5e-2]", code="TEST", label="JSON") == [
        1000.0,
        -0.025,
    ]


@pytest.mark.parametrize(
    "payload",
    [
        "1e9999",
        "-1e9999",
        '{"x": 1e9999}',
        '{"x": -1e9999}',
        "[1e9999]",
        "[-1e9999]",
    ],
)
def test_bounded_json_rejects_exponent_overflow_at_parse_boundary(payload: str) -> None:
    with pytest.raises(GuardError) as caught:
        load_bounded_json(payload, code="BOUNDARY_OVERFLOW", label="JSON")

    assert caught.value.code == "BOUNDARY_OVERFLOW"


@pytest.mark.parametrize(
    "mutation",
    [
        'UPDATE checks SET definition_json = \'{"id":"pytest"}\' WHERE run_id = ?',
        "UPDATE checks SET definition_digest = 'broken' WHERE run_id = ?",
        """UPDATE checks SET definition_json = '{"id":"forged"}',
           definition_digest = '5a3cec41241fe9f9b980eeee58c7dd5f469b22b637574bbd316f32f783b77a5f'
           WHERE run_id = ?""",
        "UPDATE artifacts SET body_json = '{}' WHERE run_id = ?",
        "UPDATE artifacts SET digest = 'broken' WHERE run_id = ?",
        "UPDATE runs SET packet_digest = 'broken' WHERE id = ?",
        "UPDATE phase_executions SET phase_id = 'P9' WHERE run_id = ?",
        "UPDATE phase_executions SET position = 9 WHERE run_id = ?",
        "UPDATE phase_executions SET allowed_paths_json = '[\"**\"]' WHERE run_id = ?",
        "UPDATE phase_executions SET check_ids_json = '[]' WHERE run_id = ?",
        "UPDATE phase_executions SET status = 'COMPLETED' WHERE run_id = ?",
        "UPDATE phase_executions SET change_count = 1 WHERE run_id = ?",
        "UPDATE phase_executions SET conclusion = 'forged' WHERE run_id = ?",
        "UPDATE runs SET workspace_digest = 'forged' WHERE id = ?",
        "UPDATE runs SET environment_digest = 'forged' WHERE id = ?",
        "UPDATE runs SET task = 'forged' WHERE id = ?",
        "UPDATE runs SET session_id = 'forged' WHERE id = ?",
    ],
)
def test_tampered_frozen_execution_state_blocks_reads_and_writes(
    tmp_path: Path, mutation: str
) -> None:
    store, run_id = create_store(tmp_path)
    run = freeze_packet(store, run_id)
    with sqlite3.connect(store.database) as connection:
        connection.execute(mutation, (run_id,))
        connection.commit()
        count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    for operation in (
        lambda: store.get_run(run_id),
        lambda: store.create_write_lease(
            run_id,
            expected_revision=run.revision,
            session_id="session-1",
            call_id="blocked",
            tool_name="edit",
            declared_paths=["src/app.py"],
            before_digest="workspace-0",
            before_files=[],
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "PERSISTED_STATE_BROKEN"
    with sqlite3.connect(store.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == count
        )


def test_packet_event_anchor_rejects_recomputed_local_digests(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    forged = packet()
    forged["constraints"] = ["forged"]
    forged_digest = digest_json(forged)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE artifacts SET body_json = ?, digest = ? WHERE run_id = ?",
            (canonical_json(forged), forged_digest, run_id),
        )
        connection.execute(
            "UPDATE runs SET packet_digest = ? WHERE id = ?", (forged_digest, run_id)
        )
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)

    assert caught.value.code == "PERSISTED_STATE_BROKEN"


@pytest.mark.parametrize(
    "payload",
    [
        "[" * 20_000 + "]" * 20_000,
        '"' + "x" * (512 * 1024) + '"',
    ],
    ids=["too-deep", "too-large"],
)
def test_persisted_state_json_limits_fail_closed(tmp_path: Path, payload: str) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE phase_executions SET allowed_paths_json = ? WHERE run_id = ?",
            (payload, run_id),
        )
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)

    assert caught.value.code == "PERSISTED_STATE_BROKEN"


@pytest.mark.parametrize(
    "payload",
    [
        "NaN",
        "Infinity",
        "-Infinity",
        '{"x": NaN}',
        "1e9999",
        "-1e9999",
        '{"x": 1e9999}',
        '{"x": -1e9999}',
        "[1e9999]",
        "[-1e9999]",
    ],
)
def test_persisted_state_rejects_nonstandard_numbers(tmp_path: Path, payload: str) -> None:
    store, run_id = create_store(tmp_path)
    freeze_packet(store, run_id)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE phase_executions SET allowed_paths_json = ? WHERE run_id = ?",
            (payload, run_id),
        )
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)

    assert caught.value.code == "PERSISTED_STATE_BROKEN"


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE write_leases SET declared_paths_json = '[\"**\"]' WHERE run_id = ?",
        'UPDATE write_leases SET before_files_json = \'[["forged","hash"]]\' WHERE run_id = ?',
        "UPDATE write_leases SET tool_name = 'shell' WHERE run_id = ?",
        "UPDATE write_leases SET call_id = 'forged' WHERE run_id = ?",
        "UPDATE write_leases SET phase_id = 'P9' WHERE run_id = ?",
        "UPDATE write_leases SET requirement_ids_json = '[]' WHERE run_id = ?",
        "UPDATE write_leases SET acceptance_ids_json = '[]' WHERE run_id = ?",
        "UPDATE write_leases SET before_digest = 'forged' WHERE run_id = ?",
        "DELETE FROM write_leases WHERE run_id = ?",
    ],
)
def test_tampered_write_lease_blocks_consumption(tmp_path: Path, mutation: str) -> None:
    store, run_id = create_store(tmp_path)
    run = freeze_packet(store, run_id)
    lease = store.create_write_lease(
        run_id,
        expected_revision=run.revision,
        session_id="session-1",
        call_id="call-1",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="workspace-0",
        before_files=[],
    )
    with sqlite3.connect(store.database) as connection:
        connection.execute(mutation, (run_id,))
        connection.commit()
        count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    for operation in (
        lambda: store.get_write_lease(run_id),
        lambda: store.finish_write(
            run_id,
            expected_revision=lease["revision"],
            session_id="session-1",
            call_id="call-1",
            workspace_digest="workspace-1",
            actual_paths=["src/app.py"],
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "PERSISTED_STATE_BROKEN"
    with sqlite3.connect(store.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == count
        )


def test_non_startup_blocked_run_remains_active(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)

    store.block_run(run_id, code="OTHER_FAILURE", message="blocked")

    with pytest.raises(GuardError) as caught:
        store.cancel_startup(run_id)

    active = store.find_active(tmp_path / "project")
    assert caught.value.code == "STARTUP_CANCEL_NOT_ALLOWED"
    assert active is not None
    assert active.run_id == run_id


def test_legacy_retirement_preserves_frozen_state_and_is_not_active(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = store.bind_task(
        run_id,
        expected_revision=0,
        task="legacy packet",
        session_id="session-1",
    )
    body = packet()
    del body["certainty"]
    store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )
    before = store.get_run(run_id)
    artifact = store.get_artifact(run_id)
    phases = store.list_phases(run_id)

    retired = store.block_run(
        run_id,
        code="LEGACY_RUN_RETIRED",
        message="Legacy frozen Run was retired before starting a current Run.",
        payload={"contract_generation": "pre-certainty"},
    )
    repeated = store.block_run(
        run_id,
        code="LEGACY_RUN_RETIRED",
        message="Legacy frozen Run was retired before starting a current Run.",
    )

    assert retired.blocked_code == "LEGACY_RUN_RETIRED"
    assert repeated.event_count == retired.event_count == before.event_count + 1
    assert repeated.worktree == before.worktree
    assert store.get_artifact(run_id) == artifact
    assert store.list_phases(run_id) == phases
    assert store.find_active(tmp_path / "project") is None


def test_write_lease_is_persistent_and_consumed_once(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = store.get_run(run_id)
    run = store.bind_task(
        run_id,
        expected_revision=run.revision,
        task="实现功能",
        session_id="session-1",
    )
    body = packet()
    run = store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )
    lease = store.create_write_lease(
        run_id,
        expected_revision=run.revision,
        session_id="session-1",
        call_id="call-1",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="workspace-0",
        before_files=[],
    )
    assert store.get_write_lease(run_id)["call_id"] == "call-1"
    run = store.finish_write(
        run_id,
        expected_revision=lease["revision"],
        session_id="session-1",
        call_id="call-1",
        workspace_digest="workspace-1",
        actual_paths=["src/app.py"],
    )
    assert run.workspace_digest == "workspace-1"
    assert store.get_write_lease(run_id) is None


def test_write_lease_is_participant_bound_and_blocks_other_writers(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = freeze_packet(store, run_id)
    run = store.attach_session(run_id, "session-2", expected_revision=run.revision)
    lease = store.create_write_lease(
        run_id,
        expected_revision=run.revision,
        session_id="session-1",
        call_id="call-owner",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="workspace-0",
        before_files=[],
    )

    persisted = store.get_write_lease(run_id)
    assert persisted is not None
    assert persisted["session_id"] == lease["session_id"] == "session-1"
    assert persisted["revision"] == lease["revision"]
    for operation in (
        lambda: store.create_write_lease(
            run_id,
            expected_revision=lease["revision"],
            session_id="session-2",
            call_id="call-other",
            tool_name="edit",
            declared_paths=["src/app.py"],
            before_digest="workspace-0",
            before_files=[],
        ),
        lambda: store.finish_write(
            run_id,
            expected_revision=lease["revision"],
            session_id="session-2",
            call_id="call-owner",
            workspace_digest="workspace-1",
            actual_paths=["src/app.py"],
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "WRITE_BUSY"

    with pytest.raises(GuardError) as caught:
        store.complete_phase(
            run_id,
            expected_revision=lease["revision"],
            phase_id="P1",
            outcome="no-change",
            rationale="pending lease",
        )
    assert caught.value.code == "WRITE_LEASE_PENDING"
    assert store.get_write_lease(run_id)["session_id"] == "session-1"


def test_participant_changes_wait_for_an_active_write_lease(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = freeze_packet(store, run_id)
    lease = store.create_write_lease(
        run_id,
        expected_revision=run.revision,
        session_id="session-1",
        call_id="call-1",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="workspace-0",
        before_files=[],
    )
    for operation in (
        lambda: store.attach_session(
            run_id,
            "session-2",
            expected_revision=lease["revision"],
        ),
        lambda: store.revoke_session(run_id, "session-1"),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "WRITE_LEASE_PENDING"

    finished = store.finish_write(
        run_id,
        expected_revision=lease["revision"],
        session_id="session-1",
        call_id="call-1",
        workspace_digest="workspace-1",
        actual_paths=["src/app.py"],
    )
    attached = store.attach_session(
        run_id,
        "session-2",
        expected_revision=finished.revision,
    )
    revoked = store.revoke_session(run_id, "session-1")

    assert attached.revision == finished.revision + 1
    assert revoked.revision == attached.revision + 1
    assert store.get_write_lease(run_id) is None


def test_attach_session_compares_revision_inside_its_write_transaction(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    stale = store.get_run(run_id)
    store.attach_session(run_id, "session-2", expected_revision=stale.revision)

    with pytest.raises(GuardError) as caught:
        store.attach_session(run_id, "session-3", expected_revision=stale.revision)

    assert caught.value.code == "REVISION_CONFLICT"
    with pytest.raises(GuardError) as caught:
        store.assert_session(run_id, "session-3")
    assert caught.value.code == "SESSION_NOT_ATTACHED"


def test_revoked_participant_cannot_create_a_lease_after_completion(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = freeze_packet(store, run_id)
    lease = store.create_write_lease(
        run_id,
        expected_revision=run.revision,
        session_id="session-1",
        call_id="call-1",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="workspace-0",
        before_files=[],
    )

    with pytest.raises(GuardError) as caught:
        store.revoke_session(run_id, "session-1")
    assert caught.value.code == "WRITE_LEASE_PENDING"

    run = store.finish_write(
        run_id,
        expected_revision=lease["revision"],
        session_id="session-1",
        call_id=lease["call_id"],
        workspace_digest="workspace-1",
        actual_paths=["src/app.py"],
    )
    revoked = store.revoke_session(run_id, "session-1")

    assert revoked.revision == run.revision + 1
    with pytest.raises(GuardError) as caught:
        store.create_write_lease(
            run_id,
            expected_revision=revoked.revision,
            session_id="session-1",
            call_id="call-2",
            tool_name="edit",
            declared_paths=["src/app.py"],
            before_digest="workspace-1",
            before_files=[("src/app.py", "hash-1")],
        )
    assert caught.value.code == "SESSION_REVOKED"


def test_completing_last_phase_enters_verification(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = store.get_run(run_id)
    run = store.bind_task(
        run_id,
        expected_revision=run.revision,
        task="实现功能",
        session_id="session-1",
    )
    body = packet()
    run = store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=body,
        digest=packet_digest(body),
    )
    run = store.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="实现完成",
    )
    assert run.stage is Stage.VERIFYING
    assert run.active_phase == ""


def test_packet_revision_preserves_history_and_resets_current_projection(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    first = freeze_packet(store, run_id)
    candidate = deepcopy(packet())
    candidate["phases"][0]["allowed_paths"] = ["src/**", "docs/**"]
    candidate_digest = packet_digest(candidate)

    approval = store.approve_plan(
        run_id,
        expected_revision=first.revision,
        base_packet_digest=first.packet_digest,
        candidate_packet_digest=candidate_digest,
        added_paths=["docs/**"],
        approved_by="operator",
    )
    assert approval.revision == first.revision + 1
    revised = store.submit_packet(
        run_id,
        expected_revision=approval.revision,
        packet=candidate,
        digest=candidate_digest,
    )
    assert revised.packet_digest == candidate_digest

    current = store.get_artifact(run_id)
    historical = store.get_artifact(run_id, version=1)
    history = store.list_artifact_history(run_id)
    assert current["version"] == 2
    assert current["body"] == candidate
    assert historical["body"] == packet()
    assert [item["version"] for item in history] == [1, 2]
    assert history[0]["current"] is False
    assert history[1]["current"] is True
    assert store.list_phases(run_id)[0]["status"] == "ACTIVE"
    assert store.list_phases(run_id)[0]["change_count"] == 0
    assert store.list_evidence(run_id) == []


def test_packet_revision_preserves_run_identity_and_active_participants(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    first = freeze_packet(store, run_id)
    attached = store.attach_session(run_id, "session-2", expected_revision=first.revision)
    with sqlite3.connect(store.database) as connection:
        participants_before = connection.execute(
            "SELECT * FROM run_sessions WHERE run_id = ? ORDER BY session_id", (run_id,)
        ).fetchall()
    artifact_before = store.get_artifact(run_id, version=1)
    candidate = deepcopy(packet())
    candidate["constraints"] = ["双参与者修订。"]
    revised = store.submit_packet(
        run_id,
        expected_revision=attached.revision,
        packet=candidate,
        digest=packet_digest(candidate),
    )
    with sqlite3.connect(store.database) as connection:
        participants_after = connection.execute(
            "SELECT * FROM run_sessions WHERE run_id = ? ORDER BY session_id", (run_id,)
        ).fetchall()
    assert revised.run_id == first.run_id
    assert revised.project_root == first.project_root
    assert revised.worktree == first.worktree
    assert revised.base_sha == first.base_sha
    assert participants_after == participants_before
    assert store.get_artifact(run_id, version=1) == artifact_before


def test_scope_expansion_requires_exact_approval_and_failed_submit_is_atomic(
    tmp_path: Path,
) -> None:
    store, run_id = create_store(tmp_path)
    first = freeze_packet(store, run_id)
    candidate = deepcopy(packet())
    candidate["phases"][0]["allowed_paths"] = ["src/**", "docs/**"]
    candidate_digest = packet_digest(candidate)
    before = store.get_run(run_id)

    with pytest.raises(GuardError) as caught:
        store.submit_packet(
            run_id,
            expected_revision=before.revision,
            packet=candidate,
            digest=candidate_digest,
        )
    assert caught.value.code == "PLAN_SCOPE_APPROVAL_REQUIRED"
    after = store.get_run(run_id)
    assert after.revision == before.revision
    assert after.packet_digest == first.packet_digest
    assert len(store.list_artifact_history(run_id)) == 1

    approved = store.approve_plan(
        run_id,
        expected_revision=before.revision,
        base_packet_digest=first.packet_digest,
        candidate_packet_digest=candidate_digest,
        added_paths=["docs/**"],
        approved_by="operator",
    )
    repeated = store.approve_plan(
        run_id,
        expected_revision=approved.revision,
        base_packet_digest=first.packet_digest,
        candidate_packet_digest=candidate_digest,
        added_paths=["docs/**"],
        approved_by="operator",
    )
    assert repeated.revision == approved.revision


def test_scope_narrowing_needs_no_approval_but_expansion_does(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    first = freeze_packet(store, run_id)
    narrowed = deepcopy(packet())
    narrowed["phases"][0]["allowed_paths"] = ["src/app.py"]
    narrowed_digest = packet_digest(narrowed)
    narrowed_run = store.submit_packet(
        run_id,
        expected_revision=first.revision,
        packet=narrowed,
        digest=narrowed_digest,
    )
    assert narrowed_run.packet_digest == narrowed_digest

    expanded = deepcopy(narrowed)
    expanded["phases"][0]["allowed_paths"] = ["src/**", "docs/**"]
    expanded_digest = packet_digest(expanded)
    with pytest.raises(GuardError) as caught:
        store.submit_packet(
            run_id,
            expected_revision=narrowed_run.revision,
            packet=expanded,
            digest=expanded_digest,
        )
    assert caught.value.code == "PLAN_SCOPE_APPROVAL_REQUIRED"


def test_current_packet_resubmission_is_unchanged_and_zero_write(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    first_body = packet()
    first = freeze_body(store, run_id, first_body)
    before = database_snapshot(store.database)
    reordered = dict(reversed(list(first_body.items())))
    assert packet_digest(reordered) == first.packet_digest
    with pytest.raises(GuardError) as caught:
        store.submit_packet(
            run_id,
            expected_revision=first.revision,
            packet=reordered,
            digest=packet_digest(reordered),
        )
    assert caught.value.code == "PACKET_UNCHANGED"
    assert database_snapshot(store.database) == before


def test_packet_versions_are_continuous_and_gap_mutation_fails_closed(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    first_body = packet()
    run = freeze_body(store, run_id, first_body)
    second = deepcopy(first_body)
    second["constraints"] = ["第二版约束。"]
    run = store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=second,
        digest=packet_digest(second),
    )
    third = deepcopy(first_body)
    third["constraints"] = ["第三版约束。"]
    run = store.submit_packet(
        run_id,
        expected_revision=run.revision,
        packet=third,
        digest=packet_digest(third),
    )
    assert [item["version"] for item in store.list_artifact_history(run_id)] == [1, 2, 3]
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE artifacts SET version = 4 WHERE run_id = ? AND version = 3",
            (run_id,),
        )
        connection.commit()
    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_two_connections_competing_on_one_revision_have_one_winner(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    first_body = packet()
    first = freeze_body(store, run_id, first_body)
    candidates = []
    for label in ("A", "B"):
        candidate = deepcopy(first_body)
        candidate["constraints"] = [f"并发候选 {label}。"]
        candidates.append(candidate)
    barrier = Barrier(2)

    def submit(candidate: dict[str, object]) -> tuple[str, str]:
        competitor = StateStore(store.database)
        barrier.wait()
        try:
            result = competitor.submit_packet(
                run_id,
                expected_revision=first.revision,
                packet=candidate,
                digest=packet_digest(candidate),
            )
            return "ok", result.packet_digest
        except GuardError as exc:
            return "error", exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, candidates))
    assert sorted(status for status, _value in results) == ["error", "ok"]
    assert [value for status, value in results if status == "error"] == ["REVISION_CONFLICT"]
    assert [item["version"] for item in store.list_artifact_history(run_id)] == [1, 2]


def test_packet_approval_and_versions_are_isolated_between_projects(tmp_path: Path) -> None:
    store, first_run_id = create_store(tmp_path)
    first = freeze_packet(store, first_run_id)
    second_run_id = "run-second-project"
    second = store.create_run(
        run_id=second_run_id,
        project_root=tmp_path / "project-2",
        git_common_dir=tmp_path / "project-2" / ".git",
        worktree=tmp_path / "worktrees" / second_run_id,
        base_sha="c" * 40,
        environment_digest="env",
        workspace_digest="workspace-2",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "b" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    second = store.bind_task(
        second_run_id,
        expected_revision=second.revision,
        task="第二项目",
        session_id="session-second",
    )
    second_body = packet()
    second = store.submit_packet(
        second_run_id,
        expected_revision=second.revision,
        packet=second_body,
        digest=packet_digest(second_body),
    )
    expanded = deepcopy(packet())
    expanded["phases"][0]["allowed_paths"] = ["src/**", "docs/**"]
    expanded_digest = packet_digest(expanded)
    approved = store.approve_plan(
        first_run_id,
        expected_revision=first.revision,
        base_packet_digest=first.packet_digest,
        candidate_packet_digest=expanded_digest,
        added_paths=["docs/**"],
        approved_by="operator",
    )
    first = store.submit_packet(
        first_run_id,
        expected_revision=approved.revision,
        packet=expanded,
        digest=expanded_digest,
    )
    with pytest.raises(GuardError) as caught:
        store.submit_packet(
            second_run_id,
            expected_revision=second.revision,
            packet=expanded,
            digest=expanded_digest,
        )
    assert caught.value.code == "PLAN_SCOPE_APPROVAL_REQUIRED"
    assert [item["version"] for item in store.list_artifact_history(first_run_id)] == [1, 2]
    assert [item["version"] for item in store.list_artifact_history(second_run_id)] == [1]
    assert store.get_run(first_run_id).packet_digest == first.packet_digest
    assert store.get_run(second_run_id).packet_digest == second.packet_digest


def test_packet_submission_rejects_verifying_and_active_lease_without_writes(
    tmp_path: Path,
) -> None:
    verifying_store, verifying_run_id = create_store(tmp_path / "verifying")
    verifying = freeze_packet(verifying_store, verifying_run_id)
    verifying = verifying_store.complete_phase(
        verifying_run_id,
        expected_revision=verifying.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="进入验证",
    )
    candidate = deepcopy(packet())
    candidate["constraints"] = ["不允许提交。"]
    before = database_snapshot(verifying_store.database)
    with pytest.raises(GuardError) as caught:
        verifying_store.submit_packet(
            verifying_run_id,
            expected_revision=verifying.revision,
            packet=candidate,
            digest=packet_digest(candidate),
        )
    assert caught.value.code == "PACKET_NOT_ALLOWED"
    assert database_snapshot(verifying_store.database) == before

    leased_store, leased_run_id = create_store(tmp_path / "leased")
    leased = freeze_packet(leased_store, leased_run_id)
    lease = leased_store.create_write_lease(
        leased_run_id,
        expected_revision=leased.revision,
        session_id="session-1",
        call_id="active-lease",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="workspace-0",
        before_files=[],
    )
    before = database_snapshot(leased_store.database)
    with pytest.raises(GuardError) as caught:
        leased_store.submit_packet(
            leased_run_id,
            expected_revision=lease["revision"],
            packet=candidate,
            digest=packet_digest(candidate),
        )
    assert caught.value.code == "WRITE_LEASE_PENDING"
    assert database_snapshot(leased_store.database) == before


@pytest.mark.parametrize("fault", ["artifact", "phases", "event", "final_verify"])
def test_packet_revision_failpoints_roll_back_every_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    store, run_id = create_store(tmp_path)
    first_body = packet()
    first = freeze_body(store, run_id, first_body)
    candidate = deepcopy(first_body)
    candidate["constraints"] = [f"{fault} 回滚。"]
    before = database_snapshot(store.database)

    if fault == "artifact":
        original = execution_module.ExecutionRepository._insert_artifact

        def fail_after_artifact(*args: object, **kwargs: object) -> None:
            original(*args, **kwargs)
            raise RuntimeError("artifact failpoint")

        monkeypatch.setattr(
            execution_module.ExecutionRepository,
            "_insert_artifact",
            staticmethod(fail_after_artifact),
        )
    elif fault == "phases":
        original_phases = execution_module.ExecutionRepository._replace_phases

        def fail_after_phases(*args: object, **kwargs: object) -> None:
            original_phases(*args, **kwargs)
            raise RuntimeError("phase failpoint")

        monkeypatch.setattr(
            execution_module.ExecutionRepository,
            "_replace_phases",
            staticmethod(fail_after_phases),
        )
    elif fault == "event":
        original_append = execution_module.append_event

        def fail_before_event(*args: object, event: str, **kwargs: object) -> int:
            if event == "PACKET_REVISED":
                raise RuntimeError("event failpoint")
            return original_append(*args, event=event, **kwargs)

        monkeypatch.setattr(execution_module, "append_event", fail_before_event)
    else:
        original_select = execution_module.select_run
        calls = 0

        def fail_final_verify(*args: object, **kwargs: object):
            nonlocal calls
            calls += 1
            row = original_select(*args, **kwargs)
            if calls == 2:
                raise RuntimeError("final verify failpoint")
            return row

        monkeypatch.setattr(execution_module, "select_run", fail_final_verify)

    with pytest.raises(RuntimeError, match="failpoint"):
        store.submit_packet(
            run_id,
            expected_revision=first.revision,
            packet=candidate,
            digest=packet_digest(candidate),
        )
    assert database_snapshot(store.database) == before


def test_oversized_retired_snapshot_is_rejected_before_revision_writes(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    body = packet()
    body["phases"] = [
        {
            "id": f"P{position}",
            "goal": "执行。",
            "requirement_ids": ["R1"],
            "acceptance_ids": ["A1"],
            "allowed_paths": ["src/**"],
            "check_ids": ["pytest"],
        }
        for position in range(1, 257)
    ]
    run = freeze_body(store, run_id, body)
    conclusion = "x" * 2_000
    for position in range(1, 256):
        run = store.complete_phase(
            run_id,
            expected_revision=run.revision,
            phase_id=f"P{position}",
            outcome="no-change",
            rationale=conclusion,
        )
    candidate = deepcopy(body)
    candidate["constraints"] = ["超限 snapshot 必须失败。"]
    before = database_snapshot(store.database)
    with pytest.raises(GuardError) as caught:
        store.submit_packet(
            run_id,
            expected_revision=run.revision,
            packet=candidate,
            digest=packet_digest(candidate),
        )
    assert caught.value.code == "PACKET_TOO_LARGE"
    assert caught.value.details["component"] == "packet_revision_event"
    assert database_snapshot(store.database) == before


def test_scope_approval_is_single_use_and_removed_scope_requires_fresh_approval(
    tmp_path: Path,
) -> None:
    store, run_id = create_store(tmp_path)
    first_body = packet()
    first = freeze_body(store, run_id, first_body)
    expanded = deepcopy(first_body)
    expanded["phases"][0]["allowed_paths"] = ["src/**", "docs/**"]
    expanded_digest = packet_digest(expanded)
    approved = store.approve_plan(
        run_id,
        expected_revision=first.revision,
        base_packet_digest=first.packet_digest,
        candidate_packet_digest=expanded_digest,
        added_paths=["docs/**"],
        approved_by="operator",
    )
    expanded_run = store.submit_packet(
        run_id,
        expected_revision=approved.revision,
        packet=expanded,
        digest=expanded_digest,
    )
    with pytest.raises(GuardError) as caught:
        store.approve_plan(
            run_id,
            expected_revision=expanded_run.revision,
            base_packet_digest=first.packet_digest,
            candidate_packet_digest=expanded_digest,
            added_paths=["docs/**"],
            approved_by="operator",
        )
    assert caught.value.code == "PLAN_SCOPE_APPROVAL_CONSUMED"

    narrowed = deepcopy(first_body)
    narrowed["constraints"] = ["删除 docs scope。"]
    narrowed_run = store.submit_packet(
        run_id,
        expected_revision=expanded_run.revision,
        packet=narrowed,
        digest=packet_digest(narrowed),
    )
    readded = deepcopy(expanded)
    readded["constraints"] = ["重新加入 docs scope。"]
    with pytest.raises(GuardError) as caught:
        store.submit_packet(
            run_id,
            expected_revision=narrowed_run.revision,
            packet=readded,
            digest=packet_digest(readded),
        )
    assert caught.value.code == "PLAN_SCOPE_APPROVAL_REQUIRED"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("status", "ACTIVE"),
        ("change_count", 99),
        ("conclusion", "伪造结论"),
        ("updated_at", "2000-01-01T00:00:00+00:00"),
    ],
)
def test_rehashed_retired_phase_snapshot_mutations_fail_closed(
    tmp_path: Path, field: str, replacement: object
) -> None:
    store, run_id, _revised = revise_after_completed_phase(tmp_path)
    with sqlite3.connect(store.database) as connection:
        row = connection.execute(
            "SELECT payload_json FROM events WHERE run_id = ? AND type = 'PACKET_REVISED'",
            (run_id,),
        ).fetchone()
        payload = load_bounded_json(row[0], code="TEST", label="revision payload")
        payload["retired_phases"][0][field] = replacement
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE run_id = ? AND type = 'PACKET_REVISED'",
            (canonical_json(payload), run_id),
        )
        rehash_event_chain(connection, run_id)
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_rehashed_lifecycle_event_with_wrong_packet_digest_fails_closed(tmp_path: Path) -> None:
    store, run_id, _revised = revise_after_completed_phase(tmp_path)
    with sqlite3.connect(store.database) as connection:
        row = connection.execute(
            "SELECT payload_json FROM events WHERE run_id = ? AND type = 'PHASE_COMPLETED'",
            (run_id,),
        ).fetchone()
        payload = load_bounded_json(row[0], code="TEST", label="phase payload")
        payload["packet_digest"] = "f" * 64
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE run_id = ? AND type = 'PHASE_COMPLETED'",
            (canonical_json(payload), run_id),
        )
        rehash_event_chain(connection, run_id)
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_stale_verification_evidence_is_rejected_after_packet_revision(
    tmp_path: Path,
) -> None:
    store, run_id, revised = revise_after_completed_phase(tmp_path)
    old_packet_digest = store.get_artifact(run_id, version=1)["digest"]
    run = store.complete_phase(
        run_id,
        expected_revision=revised.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="重订计划后的第一阶段完成",
    )
    run = store.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P2",
        outcome="no-change",
        rationale="重订计划后的第二阶段完成",
    )
    assert run.stage is Stage.VERIFYING
    stale = VerificationEvidence(
        run_id=run_id,
        check_id="pytest",
        requirement_ids=("R1",),
        acceptance_ids=("A1",),
        base_sha="a" * 40,
        artifact_set_digest=old_packet_digest,
        workspace_digest="workspace-1",
        command_digest="command",
        image_digest="example@sha256:" + "b" * 64,
        output_digest="output",
        exit_code=0,
        timed_out=False,
        duration_ms=1,
    )
    with pytest.raises(GuardError) as caught:
        store.finish_verification(
            run_id,
            evidence=[stale],
            set_digest=evidence_set_digest([stale]),
            previews={"pytest": "stale"},
        )
    assert caught.value.code == "STALE_EVIDENCE"
    assert store.list_evidence(run_id) == []


def test_duplicate_verification_event_batch_fails_closed(tmp_path: Path) -> None:
    store, run_id = create_store(tmp_path)
    run = freeze_packet(store, run_id)
    run = store.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="验证通过",
    )
    assert run.stage is Stage.VERIFYING
    evidence = VerificationEvidence(
        run_id=run_id,
        check_id="pytest",
        requirement_ids=("R1",),
        acceptance_ids=("A1",),
        base_sha="a" * 40,
        artifact_set_digest=run.packet_digest,
        workspace_digest="workspace-0",
        command_digest="command",
        image_digest="example@sha256:" + "b" * 64,
        output_digest="output",
        exit_code=0,
        timed_out=False,
        duration_ms=1,
    )
    run = store.finish_verification(
        run_id,
        evidence=[evidence],
        set_digest=evidence_set_digest([evidence]),
        previews={"pytest": "ok"},
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    event_payload = None
    with sqlite3.connect(store.database) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT payload_json FROM events
            WHERE run_id = ? AND type = 'VERIFICATION_PASSED'
            """,
            (run_id,),
        ).fetchone()
        assert row is not None
        event_payload = load_bounded_json(
            row["payload_json"],
            code="TEST",
            label="verification payload",
        )
        database_module.append_event(
            connection,
            run_id,
            event="VERIFICATION_PASSED",
            actor="authority",
            payload=event_payload,
            after_stage=Stage.REVIEW_REQUIRED,
        )
        connection.commit()

    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"
