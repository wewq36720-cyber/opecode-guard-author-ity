from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Barrier

import pytest

from opencode_guardian.contracts import Stage, packet_digest
from opencode_guardian.errors import GuardError
from opencode_guardian.persistence import StateStore


def _store(tmp_path: Path) -> tuple[StateStore, str]:
    store = StateStore(tmp_path / "guard.db")
    run = store.create_run(
        run_id="run-v24",
        project_root=tmp_path / "project",
        git_common_dir=tmp_path / "project" / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="environment",
        workspace_digest="b" * 64,
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "c" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    return store, run.run_id


def _plan_body() -> dict[str, object]:
    packet = {
        "certainty": {"confirmed": True, "unresolved_items": [], "assumptions": []},
        "requirements": [{"id": "R1", "statement": "Implement.", "acceptance_ids": ["A1"]}],
        "acceptance": [
            {
                "id": "A1",
                "criterion": "Check passes.",
                "verification": ["pytest"],
                "required_paths": ["src/app.py"],
            }
        ],
        "constraints": ["Fail closed."],
        "non_goals": ["No external project."],
        "stop_conditions": ["Verification unavailable."],
        "architecture": {
            "objective": "Minimal guarded chain.",
            "public_interface": "Application",
            "dependency_direction": "adapter -> application -> domain",
            "components": [
                {"name": "Application", "responsibility": "Orchestrate.", "dependencies": []}
            ],
            "trust_boundaries": ["Model input is untrusted."],
            "data_flows": ["Request enters the guard."],
            "concurrency": {
                "ordering": "Run revision.",
                "idempotency": "call_id.",
                "backpressure": "Bounded.",
                "limits": "One MiB.",
                "failures": "Fail closed.",
                "scaling": "Per Run.",
                "observability": "Events.",
            },
        },
        "phases": [
            {
                "id": "P1",
                "goal": "Implement.",
                "requirement_ids": ["R1"],
                "acceptance_ids": ["A1"],
                "allowed_paths": ["src/**"],
                "check_ids": ["pytest"],
            }
        ],
    }
    return {
        "id": "PLAN-1",
        "kind": "PLAN",
        "base_sha": "a" * 40,
        "workspace_digest": "b" * 64,
        "source_digests": {"src/opencode_guardian/facade.py": "c" * 64},
        "evidence_refs": ["E1"],
        "requirement_ids": ["R400", "R401"],
        "acceptance_ids": ["A421", "A422"],
        "ra_mappings": [
            {"requirement_id": "R400", "acceptance_ids": ["A421"]},
            {"requirement_id": "R401", "acceptance_ids": ["A422"]},
        ],
        "facts": [{"id": "F1", "statement": "fact", "evidence_ref": "E1"}],
        "assumptions": [{"id": "H1", "statement": "assumption", "expiry": "P2"}],
        "decisions": [{"id": "D1", "statement": "decision", "evidence_ref": "E1"}],
        "deviations": [{"id": "DV1", "status": "PROVED", "evidence_ref": "E1"}],
        "implementation": {
            "packet": packet,
            "phases": packet["phases"],
        },
    }


def _artifact_body(kind: str, artifact_id: str) -> dict[str, object]:
    artifact = deepcopy(_plan_body())
    artifact["id"] = artifact_id
    artifact["kind"] = kind
    if kind != "PLAN":
        artifact.pop("implementation")
    return artifact


def _store_reviewed_plan(store: StateStore, run_id: str) -> dict[str, object]:
    baseline = store.execution.store_planning_artifact(
        run_id,
        expected_revision=store.get_run(run_id).revision,
        body=_artifact_body("BASELINE", "BASELINE-1"),
    )
    baseline_review = store.execution.record_planning_review_receipt(
        run_id,
        expected_revision=baseline["revision"],
        receipt=_planning_review(run_id, baseline),
    )
    spec = store.execution.store_planning_artifact(
        run_id,
        expected_revision=baseline_review["revision"],
        body=_artifact_body("SPEC", "SPEC-1"),
    )
    spec_review = store.execution.record_planning_review_receipt(
        run_id,
        expected_revision=spec["revision"],
        receipt=_planning_review(run_id, spec),
    )
    return store.execution.store_planning_artifact(
        run_id, expected_revision=spec_review["revision"], body=_plan_body()
    )


def _planning_review(
    run_id: str, result: dict[str, object], *, decision: str = "ACCEPT"
) -> dict[str, object]:
    artifact = result["artifact"]
    digest = result["digest"]
    revision = result["revision"]
    assert isinstance(artifact, dict)
    assert isinstance(digest, str)
    assert isinstance(revision, int)
    return {
        "review_id": f"REV-{artifact['kind']}-1",
        "kind": "PLANNING_REVIEW_RECEIPT",
        "run_id": run_id,
        "artifact_id": artifact["id"],
        "artifact_kind": artifact["kind"],
        "artifact_digest": digest,
        "artifact_revision": revision - 1,
        "base_sha": "a" * 40,
        "workspace_digest": "b" * 64,
        "issued_revision": revision,
        "source": "independent-review",
        "nonce": ("d" if artifact["kind"] == "BASELINE" else "e") * 64,
        "issued_at": "2026-07-29T00:00:00Z",
        "decision": decision,
        "authority_ref": "review-1",
    }


def test_planning_artifacts_require_ordered_predecessors(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    for body in (_plan_body(), _artifact_body("SPEC", "SPEC-1")):
        with pytest.raises(GuardError) as caught:
            store.execution.store_planning_artifact(run_id, expected_revision=0, body=body)
        assert caught.value.code == "PLANNING_ARTIFACT_SEQUENCE"

    baseline = store.execution.store_planning_artifact(
        run_id,
        expected_revision=0,
        body=_artifact_body("BASELINE", "BASELINE-1"),
    )
    baseline_review = store.execution.record_planning_review_receipt(
        run_id, expected_revision=baseline["revision"], receipt=_planning_review(run_id, baseline)
    )
    with pytest.raises(GuardError) as caught:
        store.execution.store_planning_artifact(
            run_id,
            expected_revision=baseline_review["revision"],
            body=_plan_body(),
        )
    assert caught.value.code == "PLANNING_ARTIFACT_SEQUENCE"

    spec = store.execution.store_planning_artifact(
        run_id,
        expected_revision=baseline_review["revision"],
        body=_artifact_body("SPEC", "SPEC-1"),
    )
    spec_review = store.execution.record_planning_review_receipt(
        run_id, expected_revision=spec["revision"], receipt=_planning_review(run_id, spec)
    )
    plan = store.execution.store_planning_artifact(
        run_id,
        expected_revision=spec_review["revision"],
        body=_plan_body(),
    )
    assert plan["artifact"]["kind"] == "PLAN"


def test_v25_7_review_gate_closure_and_server_digest(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    baseline = store.execution.store_planning_artifact(
        run_id, expected_revision=0, body=_artifact_body("BASELINE", "BASELINE-1")
    )
    with pytest.raises(GuardError) as caught:
        store.execution.store_planning_artifact(
            run_id,
            expected_revision=baseline["revision"],
            body=_artifact_body("SPEC", "SPEC-1"),
        )
    assert caught.value.code == "PLANNING_REVIEW_REQUIRED"
    review = store.execution.record_planning_review_receipt(
        run_id, expected_revision=baseline["revision"], receipt=_planning_review(run_id, baseline)
    )
    redirected = _artifact_body("SPEC", "SPEC-1")
    redirected["ra_mappings"] = [
        {"requirement_id": "R400", "acceptance_ids": ["A422"]},
        {"requirement_id": "R401", "acceptance_ids": ["A421"]},
    ]
    with pytest.raises(GuardError) as caught:
        store.execution.store_planning_artifact(
            run_id, expected_revision=review["revision"], body=redirected
        )
    assert caught.value.code == "PLANNING_INHERITANCE_MISMATCH"
    spec = store.execution.store_planning_artifact(
        run_id,
        expected_revision=review["revision"],
        body=_artifact_body("SPEC", "SPEC-1"),
    )
    spec_review = store.execution.record_planning_review_receipt(
        run_id, expected_revision=spec["revision"], receipt=_planning_review(run_id, spec)
    )
    plan = store.execution.store_planning_artifact(
        run_id, expected_revision=spec_review["revision"], body=_plan_body()
    )
    assert plan["packet_digest"] == packet_digest(_plan_body()["implementation"]["packet"])
    injected = _plan_body()
    implementation = injected["implementation"]
    assert isinstance(implementation, dict)
    implementation["packet_digest"] = "f" * 64
    with pytest.raises(GuardError) as caught:
        store.execution.store_planning_artifact(
            run_id, expected_revision=plan["revision"], body=injected
        )
    assert caught.value.code == "INVALID_PLANNING_ARTIFACT"


def _receipt(
    run_id: str,
    digest: str,
    revision: int,
    *,
    nonce: str = "e" * 64,
) -> dict[str, object]:
    return {
        "approval_id": "APR-1",
        "kind": "PLAN_APPROVAL_RECEIPT",
        "run_id": run_id,
        "artifact_id": "PLAN-1",
        "artifact_kind": "PLAN",
        "artifact_digest": digest,
        "base_sha": "a" * 40,
        "workspace_digest": "b" * 64,
        "revision": revision,
        "source": "independent-review",
        "nonce": nonce,
        "issued_at": "2026-07-27T00:00:00Z",
        "decision": "APPROVE",
        "authority_ref": "review-1",
    }


def test_plan_receipt_is_digest_bound_immutable_and_one_use(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)
    approved = store.execution.record_plan_approval_receipt(
        run_id,
        expected_revision=artifact["revision"],
        receipt=_receipt(run_id, artifact["digest"], artifact["revision"]),
    )
    consumed = store.execution.consume_plan_approval_receipt(
        run_id, expected_revision=approved["revision"], approval_id="APR-1"
    )
    assert consumed["consumed"] is True
    with pytest.raises(GuardError) as caught:
        store.execution.consume_plan_approval_receipt(
            run_id, expected_revision=consumed["revision"], approval_id="APR-1"
        )
    assert caught.value.code == "APPROVAL_NONCE_CONSUMED"

    with (
        sqlite3.connect(store.database) as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection.execute(
            "UPDATE planning_artifacts SET digest = ? WHERE run_id = ?", ("f" * 64, run_id)
        )


def test_receipt_nonce_replay_and_rehashed_body_tamper_fail_closed(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)
    approved = store.execution.record_plan_approval_receipt(
        run_id,
        expected_revision=artifact["revision"],
        receipt=_receipt(run_id, artifact["digest"], artifact["revision"]),
    )
    replay = _receipt(run_id, artifact["digest"], approved["revision"])
    replay["approval_id"] = "APR-2"
    with pytest.raises(GuardError) as caught:
        store.execution.record_plan_approval_receipt(
            run_id, expected_revision=approved["revision"], receipt=replay
        )
    assert caught.value.code == "APPROVAL_NONCE_REPLAY"

    with sqlite3.connect(store.database) as connection:
        connection.execute("DROP TRIGGER planning_artifacts_immutable_update")
        connection.execute(
            "UPDATE planning_artifacts SET body_json = ? WHERE run_id = ?",
            ('{"id":"PLAN-1"}', run_id),
        )
        connection.commit()
    with pytest.raises(GuardError) as caught:
        store.get_run(run_id)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"


def test_receipt_rejects_stale_workspace_and_wrong_artifact_binding(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)
    stale_workspace = _receipt(run_id, artifact["digest"], artifact["revision"])
    stale_workspace["workspace_digest"] = "f" * 64
    with pytest.raises(GuardError) as caught:
        store.execution.record_plan_approval_receipt(
            run_id, expected_revision=artifact["revision"], receipt=stale_workspace
        )
    assert caught.value.code == "APPROVAL_RECEIPT_INVALID"

    wrong_artifact = _receipt(run_id, "f" * 64, artifact["revision"])
    wrong_artifact["artifact_id"] = "PLAN-2"
    with pytest.raises(GuardError) as caught:
        store.execution.record_plan_approval_receipt(
            run_id, expected_revision=artifact["revision"], receipt=wrong_artifact
        )
    assert caught.value.code == "APPROVAL_RECEIPT_INVALID"


def test_receipt_consumption_rejects_stale_run_revision(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)
    recorded = store.execution.record_plan_approval_receipt(
        run_id,
        expected_revision=artifact["revision"],
        receipt=_receipt(run_id, artifact["digest"], artifact["revision"]),
    )
    with pytest.raises(GuardError) as caught:
        store.execution.consume_plan_approval_receipt(
            run_id, expected_revision=recorded["revision"] - 1, approval_id="APR-1"
        )
    assert caught.value.code == "REVISION_CONFLICT"


def test_concurrent_receipt_consumption_activates_exactly_once(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)
    recorded = store.execution.record_plan_approval_receipt(
        run_id,
        expected_revision=artifact["revision"],
        receipt=_receipt(run_id, artifact["digest"], artifact["revision"]),
    )
    barrier = Barrier(2)

    def consume() -> dict[str, object] | str:
        barrier.wait()
        try:
            return store.execution.consume_plan_approval_receipt(
                run_id,
                expected_revision=recorded["revision"],
                approval_id="APR-1",
            )
        except GuardError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: consume(), range(2)))

    successes = [outcome for outcome in outcomes if isinstance(outcome, dict)]
    failures = [outcome for outcome in outcomes if isinstance(outcome, str)]
    assert len(successes) == 1
    assert failures == ["REVISION_CONFLICT"]
    assert store.get_run(run_id).stage is Stage.IMPLEMENTING
    with sqlite3.connect(store.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM artifacts WHERE run_id = ?", (run_id,)
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM phase_executions WHERE run_id = ?", (run_id,)
        ).fetchone() == (1,)


def test_plan_candidate_does_not_materialize_execution_before_receipt(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)

    run = store.get_run(run_id)
    assert run.stage is Stage.PLANNING
    assert run.packet_digest == ""
    assert run.active_phase == ""
    assert store.execution.list_phases(run_id) == []
    expected_packet_digest = packet_digest(_plan_body()["implementation"]["packet"])
    with sqlite3.connect(store.database) as connection:
        assert connection.execute(
            "SELECT artifact_id, artifact_digest, packet_digest "
            "FROM plan_candidates WHERE run_id = ?",
            (run_id,),
        ).fetchone() == ("PLAN-1", artifact["digest"], expected_packet_digest)
        assert connection.execute(
            "SELECT COUNT(*) FROM artifacts WHERE run_id = ?", (run_id,)
        ).fetchone() == (0,)


def test_exact_receipt_materializes_scope_bound_phase_and_write_lease(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)
    recorded = store.execution.record_plan_approval_receipt(
        run_id,
        expected_revision=artifact["revision"],
        receipt=_receipt(run_id, artifact["digest"], artifact["revision"]),
    )
    consumed = store.execution.consume_plan_approval_receipt(
        run_id, expected_revision=recorded["revision"], approval_id="APR-1"
    )
    run = store.get_run(run_id)
    assert run.stage is Stage.IMPLEMENTING
    assert run.packet_digest == packet_digest(_plan_body()["implementation"]["packet"])
    assert run.active_phase == "P1"
    assert store.execution.list_phases(run_id)[0]["allowed_paths"] == ["src/**"]

    attached = store.attach_session(run_id, "session-v24", expected_revision=consumed["revision"])
    with pytest.raises(GuardError) as caught:
        store.execution.create_write_lease(
            run_id,
            expected_revision=attached.revision,
            session_id="session-v24",
            call_id="outside-scope",
            tool_name="edit",
            declared_paths=["tests/outside.py"],
            before_digest="b" * 64,
            before_files=[],
        )
    assert caught.value.code == "WRITE_SCOPE_VIOLATION"
    lease = store.execution.create_write_lease(
        run_id,
        expected_revision=attached.revision,
        session_id="session-v24",
        call_id="inside-scope",
        tool_name="edit",
        declared_paths=["src/app.py"],
        before_digest="b" * 64,
        before_files=[],
    )
    assert lease["phase_id"] == "P1"


def test_plan_candidate_rejects_unknown_registered_check(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    body = deepcopy(_plan_body())
    implementation = body["implementation"]
    assert isinstance(implementation, dict)
    packet = implementation["packet"]
    assert isinstance(packet, dict)
    phases = packet["phases"]
    assert isinstance(phases, list)
    phase = phases[0]
    assert isinstance(phase, dict)
    phase["check_ids"] = ["unknown-check"]
    implementation["phases"] = packet["phases"]

    with pytest.raises(GuardError) as caught:
        store.execution.store_planning_artifact(run_id, expected_revision=0, body=body)
    assert caught.value.code == "PLAN_UNRESOLVED"


def test_failed_candidate_activation_rolls_back_every_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, run_id = _store(tmp_path)
    artifact = _store_reviewed_plan(store, run_id)
    recorded = store.execution.record_plan_approval_receipt(
        run_id,
        expected_revision=artifact["revision"],
        receipt=_receipt(run_id, artifact["digest"], artifact["revision"]),
    )

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected phase failure")

    monkeypatch.setattr(store.execution, "_replace_phases", fail_replace)
    with pytest.raises(RuntimeError, match="injected phase failure"):
        store.execution.consume_plan_approval_receipt(
            run_id, expected_revision=recorded["revision"], approval_id="APR-1"
        )
    run = store.get_run(run_id)
    assert run.stage is Stage.PLANNING
    assert run.packet_digest == ""
    assert run.active_phase == ""
    with sqlite3.connect(store.database) as connection:
        assert connection.execute(
            "SELECT consumed_at FROM plan_approval_receipts WHERE approval_id = 'APR-1'"
        ).fetchone() == ("",)
        artifact_count = connection.execute(
            "SELECT COUNT(*) FROM artifacts WHERE run_id = ?", (run_id,)
        ).fetchone()
        assert artifact_count == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM phase_executions WHERE run_id = ?", (run_id,)
        ).fetchone() == (0,)


def test_v6_candidate_trigger_tampering_rejects_database_open(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    with sqlite3.connect(store.database) as connection:
        connection.execute("DROP TRIGGER plan_candidates_immutable_delete")
        connection.commit()
    with pytest.raises(GuardError) as caught:
        StateStore(store.database)
    assert caught.value.code == "DATABASE_SCHEMA_INCOMPATIBLE"


def test_v4_migration_marks_existing_runs_compatibility_read_only(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    with sqlite3.connect(store.database) as connection:
        connection.execute("DROP TABLE plan_candidates")
        connection.execute("DROP TABLE planning_review_receipts")
        connection.execute("DROP TABLE plan_approval_receipts")
        connection.execute("DROP TABLE planning_states")
        connection.execute("DROP TABLE planning_artifacts")
        connection.execute("PRAGMA user_version = 4")
        connection.commit()
    migrated = StateStore(store.database)
    with sqlite3.connect(migrated.database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        assert connection.execute(
            "SELECT planning_step FROM planning_states WHERE run_id = ?", (run_id,)
        ).fetchone() == ("COMPATIBILITY_READ_ONLY",)
    with pytest.raises(GuardError) as caught:
        migrated.execution.create_write_lease(
            run_id,
            expected_revision=0,
            session_id="missing",
            call_id="legacy-write",
            tool_name="edit",
            declared_paths=["src/file.py"],
            before_digest="b" * 64,
            before_files=[],
        )
    assert caught.value.code == "COMPATIBILITY_READ_ONLY"
    with pytest.raises(GuardError) as caught:
        migrated.execution.store_planning_artifact(run_id, expected_revision=0, body=_plan_body())
    assert caught.value.code == "COMPATIBILITY_READ_ONLY"
