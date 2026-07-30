from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from test_minimal_persistence import packet, rehash_event_chain

import opencode_guardian.persistence.execution as execution_module
from opencode_guardian.contracts import Stage
from opencode_guardian.errors import GuardError
from opencode_guardian.facade import Guardian
from opencode_guardian.persistence import StateStore
from opencode_guardian.sandbox import SandboxResult
from opencode_guardian.workspace import ProjectInfo, WorkspaceSnapshot

WORKSPACE_DIGEST = "b" * 64


class FakeWorkspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.worktree = root.parent / "worktree"
        self.snapshot_value = WorkspaceSnapshot((), WORKSPACE_DIGEST, 1, 1, ())
        self.removed: list[Path] = []
        self.cleanup_error = False

    def inspect_project(self, project_root: Path) -> ProjectInfo:
        return ProjectInfo(project_root, project_root / ".git", "a" * 40)

    def create_worktree(self, project: ProjectInfo, run_id: str) -> Path:
        self.worktree.mkdir(parents=True)
        return self.worktree

    def snapshot(
        self,
        project_root: Path,
        worktree: Path,
        base_sha: str,
    ) -> WorkspaceSnapshot:
        return self.snapshot_value

    def remove_worktree(self, project_root: Path, worktree: Path, *, force: bool) -> None:
        assert force is True
        self.removed.append(worktree)
        if self.cleanup_error:
            raise OSError("cleanup failed")
        worktree.rmdir()


class FakeSandbox:
    def __init__(self, *, exit_code: int = 0) -> None:
        self.exit_code = exit_code
        self.run_calls = 0

    def assert_images_available(self, images: list[str]) -> str:
        return "test"

    def run(
        self,
        *,
        worktree: Path,
        run_id: str,
        check: dict[str, Any],
    ) -> SandboxResult:
        self.run_calls += 1
        return SandboxResult(
            exit_code=self.exit_code,
            timed_out=False,
            duration_ms=1,
            output="ok" if self.exit_code == 0 else "failed",
            output_digest="output",
            output_bytes=2,
            output_truncated=False,
            command_digest="command",
            image_digest=check["image"],
        )


def planning_plan(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "PLAN-INITIAL",
        "kind": "PLAN",
        "base_sha": "a" * 40,
        "workspace_digest": WORKSPACE_DIGEST,
        "source_digests": {"src/opencode_guardian/facade.py": "c" * 64},
        "evidence_refs": ["E1"],
        "requirement_ids": ["R400"],
        "acceptance_ids": ["A421"],
        "ra_mappings": [{"requirement_id": "R400", "acceptance_ids": ["A421"]}],
        "facts": [{"id": "F1", "statement": "fact", "evidence_ref": "E1"}],
        "assumptions": [{"id": "H1", "statement": "assumption", "expiry": "P2"}],
        "decisions": [{"id": "D1", "statement": "decision", "evidence_ref": "E1"}],
        "deviations": [{"id": "DV1", "status": "PROVED", "evidence_ref": "E1"}],
        "implementation": {
            "packet": body,
            "phases": body["phases"],
        },
    }


def planning_artifact(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    artifact = planning_plan(body)
    artifact["id"] = f"{kind}-INITIAL"
    artifact["kind"] = kind
    if kind != "PLAN":
        artifact.pop("implementation")
    return artifact


def activate_initial_plan(guardian: Guardian, run_id: str, body: dict[str, Any]) -> object:
    baseline = guardian.submit_baseline(
        run_id,
        expected_revision=guardian.store.get_run(run_id).revision,
        body=planning_artifact("BASELINE", body),
    )
    baseline_review = guardian.record_planning_review_receipt(
        run_id,
        expected_revision=baseline["revision"],
        receipt=planning_review(run_id, baseline),
    )
    spec = guardian.submit_spec(
        run_id,
        expected_revision=baseline_review["revision"],
        body=planning_artifact("SPEC", body),
    )
    spec_review = guardian.record_planning_review_receipt(
        run_id,
        expected_revision=spec["revision"],
        receipt=planning_review(run_id, spec),
    )
    artifact = guardian.submit_plan(
        run_id,
        expected_revision=spec_review["revision"],
        body=planning_plan(body),
    )
    guardian.approve_plan_receipt(
        run_id,
        expected_revision=artifact["revision"],
        receipt={
            "approval_id": "APR-INITIAL",
            "kind": "PLAN_APPROVAL_RECEIPT",
            "run_id": run_id,
            "artifact_id": artifact["artifact"]["id"],
            "artifact_kind": "PLAN",
            "artifact_digest": artifact["digest"],
            "base_sha": "a" * 40,
            "workspace_digest": WORKSPACE_DIGEST,
            "revision": artifact["revision"],
            "source": "independent-review",
            "nonce": "e" * 64,
            "issued_at": "2026-07-27T00:00:00Z",
            "decision": "APPROVE",
            "authority_ref": "review-1",
        },
    )
    return guardian.store.get_run(run_id)


def planning_review(run_id: str, result: dict[str, Any]) -> dict[str, Any]:
    artifact = result["artifact"]
    return {
        "review_id": f"REV-{artifact['kind']}-INITIAL",
        "kind": "PLANNING_REVIEW_RECEIPT",
        "run_id": run_id,
        "artifact_id": artifact["id"],
        "artifact_kind": artifact["kind"],
        "artifact_digest": result["digest"],
        "artifact_revision": result["revision"] - 1,
        "base_sha": "a" * 40,
        "workspace_digest": WORKSPACE_DIGEST,
        "issued_revision": result["revision"],
        "source": "independent-review",
        "nonce": ("d" if artifact["kind"] == "BASELINE" else "e") * 64,
        "issued_at": "2026-07-29T00:00:00Z",
        "decision": "ACCEPT",
        "authority_ref": "review-1",
    }


def create_guardian(
    tmp_path: Path,
    *,
    exit_code: int = 0,
) -> tuple[Guardian, FakeWorkspace, str]:
    project = tmp_path / "project"
    project.mkdir()
    workspace = FakeWorkspace(project)
    guardian = Guardian(
        StateStore(tmp_path / "guard.db"),
        workspace=workspace,
        sandbox=FakeSandbox(exit_code=exit_code),
    )
    run = guardian.start_run(
        project,
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
        environment_digest="env",
    )
    run = guardian.bind_task(
        run.run_id,
        expected_revision=run.revision,
        task="实现功能",
        session_id="session-1",
    )
    run = activate_initial_plan(guardian, run.run_id, packet())
    return guardian, workspace, run.run_id


@pytest.mark.parametrize("failure", ["snapshot", "dirty", "create_run"])
def test_start_run_cleans_worktree_before_run_is_registered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = FakeWorkspace(project)
    store = StateStore(tmp_path / "guard.db")
    guardian = Guardian(store, workspace=workspace)
    if failure == "snapshot":
        monkeypatch.setattr(workspace, "snapshot", lambda *_args: (_ for _ in ()).throw(OSError()))
    elif failure == "dirty":
        workspace.snapshot_value = WorkspaceSnapshot(("dirty",), "dirty", 1, 1, ())
    else:
        monkeypatch.setattr(store, "create_run", lambda **_values: (_ for _ in ()).throw(OSError()))

    with pytest.raises(GuardError) as caught:
        guardian.start_run(project, checks=[], environment_digest="env", run_id="run-failed")

    assert caught.value.code == ("WORKTREE_NOT_CLEAN" if failure == "dirty" else "RUN_START_FAILED")
    assert workspace.removed == [workspace.worktree]
    assert not workspace.worktree.exists()
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


def test_start_run_reports_cleanup_failure_without_leaking_messages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = FakeWorkspace(project)
    workspace.cleanup_error = True
    store = StateStore(tmp_path / "guard.db")
    guardian = Guardian(store, workspace=workspace)
    monkeypatch.setattr(
        store, "create_run", lambda **_values: (_ for _ in ()).throw(OSError("secret"))
    )

    with pytest.raises(GuardError) as caught:
        guardian.start_run(project, checks=[], environment_digest="env", run_id="run-failed")

    assert caught.value.code == "RUN_START_CLEANUP_FAILED"
    assert "secret" not in str(caught.value)
    assert workspace.removed == [workspace.worktree]


def test_submit_packet_rejects_a_bare_existing_directory_before_freeze(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = FakeWorkspace(project)
    store = StateStore(tmp_path / "guard.db")
    guardian = Guardian(store, workspace=workspace, sandbox=FakeSandbox())
    run = guardian.start_run(
        project,
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
        environment_digest="env",
    )
    run = guardian.bind_task(
        run.run_id,
        expected_revision=run.revision,
        task="实现功能",
        session_id="session-1",
    )
    (workspace.worktree / "src").mkdir()
    body = packet()
    body["acceptance"][0]["required_paths"] = ["src"]
    body["phases"][0]["allowed_paths"] = ["src"]

    with pytest.raises(GuardError) as caught:
        guardian.submit_packet(run.run_id, expected_revision=run.revision, body=body)
    assert caught.value.code == "LEGACY_ROUTE_FORBIDDEN"
    with sqlite3.connect(store.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM phase_executions").fetchone()[0] == 0

    with pytest.raises(GuardError) as caught:
        guardian.submit_plan(run.run_id, expected_revision=run.revision, body=planning_plan(body))
    assert caught.value.code == "AMBIGUOUS_PATH_SCOPE"
    body["acceptance"][0]["required_paths"] = ["src/**"]
    body["phases"][0]["allowed_paths"] = ["src/**"]
    frozen = activate_initial_plan(guardian, run.run_id, body)
    assert frozen.stage is Stage.IMPLEMENTING


def test_legacy_facade_writes_fail_closed_without_state_change(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    before = guardian.store.get_run(run_id)
    for operation in (
        lambda: guardian.submit_packet(run_id, expected_revision=before.revision, body=packet()),
        lambda: guardian.approve_plan(
            run_id,
            expected_revision=before.revision,
            base_packet_digest=before.packet_digest,
            candidate_packet_digest="f" * 64,
            added_paths=["docs/**"],
            approved_by="free-text",
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "LEGACY_ROUTE_FORBIDDEN"
        assert guardian.store.get_run(run_id) == before


def test_guarded_write_and_automatic_verification(tmp_path: Path) -> None:
    guardian, workspace, run_id = create_guardian(tmp_path)
    lease = guardian.authorize_tool(
        run_id,
        "edit",
        ["src/app.py"],
        call_id="call-1",
    )
    workspace.snapshot_value = WorkspaceSnapshot(
        ("src/app.py",),
        "workspace-1",
        1,
        2,
        (("src/app.py", "hash-1"),),
    )
    run = guardian.post_tool(
        run_id,
        expected_revision=lease["revision"],
        tool_name="edit",
        call_id="call-1",
    )
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="changed",
        rationale="实现完成",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    assert guardian.status(run_id)["evidence"]


def test_participants_read_in_parallel_but_share_one_write_lease(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.attach_session(
        run_id,
        "session-2",
        expected_revision=guardian.store.get_run(run_id).revision,
    )

    first_read = guardian.authorize_tool(
        run_id, "read", [], call_id="read-1", session_id="session-1"
    )
    second_read = guardian.authorize_tool(
        run_id, "read", [], call_id="read-2", session_id="session-2"
    )
    assert first_read["revision"] == second_read["revision"] == run.revision

    lease = guardian.authorize_tool(
        run_id,
        "edit",
        ["src/app.py"],
        call_id="call-owner",
        session_id="session-1",
    )
    with pytest.raises(GuardError) as caught:
        guardian.authorize_tool(
            run_id,
            "edit",
            ["src/app.py"],
            call_id="call-other",
            session_id="session-2",
        )
    assert caught.value.code == "WRITE_BUSY"

    with pytest.raises(GuardError) as caught:
        guardian.post_tool(
            run_id,
            expected_revision=lease["revision"],
            tool_name="edit",
            call_id="call-owner",
            session_id="session-2",
        )
    assert caught.value.code == "WRITE_BUSY"
    assert guardian.store.get_write_lease(run_id)["session_id"] == "session-1"


def test_context_and_skill_bindings_fail_closed(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    stale = guardian.status(run_id)
    guardian.attach_session(
        run_id,
        "session-2",
        expected_revision=stale["source_revision"],
        context_digest=stale["context_digest"],
        skill_binding_digest=stale["skill_binding"]["digest"],
    )

    with pytest.raises(GuardError) as caught:
        guardian.authorize_tool(
            run_id,
            "read",
            [],
            call_id="read-stale",
            session_id="session-1",
            expected_revision=stale["source_revision"],
            context_digest=stale["context_digest"],
            skill_binding_digest=stale["skill_binding"]["digest"],
        )
    assert caught.value.code == "REVISION_CONFLICT"

    current = guardian.status(run_id)
    with pytest.raises(GuardError) as caught:
        guardian.authorize_tool(
            run_id,
            "read",
            [],
            call_id="read-wrong-skill",
            session_id="session-1",
            expected_revision=current["source_revision"],
            context_digest=current["context_digest"],
            skill_binding_digest="wrong",
        )
    assert caught.value.code == "SKILL_BINDING_INVALID"


def test_attach_context_cas_fails_closed_after_an_interleaving_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    stale = guardian.status(run_id)
    original_attach = guardian.store.attach_session

    def attach_after_interleaving(
        target_run_id: str,
        session_id: str,
        *,
        expected_revision: int,
    ) -> object:
        current = guardian.store.get_run(target_run_id)
        original_attach(
            target_run_id,
            "session-racer",
            expected_revision=current.revision,
        )
        return original_attach(
            target_run_id,
            session_id,
            expected_revision=expected_revision,
        )

    monkeypatch.setattr(guardian.store, "attach_session", attach_after_interleaving)
    with pytest.raises(GuardError) as caught:
        guardian.attach_session(
            run_id,
            "session-2",
            expected_revision=stale["source_revision"],
            context_digest=stale["context_digest"],
            skill_binding_digest=stale["skill_binding"]["digest"],
        )

    assert caught.value.code == "REVISION_CONFLICT"
    assert guardian.assert_session(run_id, "session-racer").run_id == run_id
    with pytest.raises(GuardError) as caught:
        guardian.assert_session(run_id, "session-2")
    assert caught.value.code == "SESSION_NOT_ATTACHED"


def test_phase_switch_changes_the_static_skill_binding(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = FakeWorkspace(project)
    guardian = Guardian(
        StateStore(tmp_path / "guard.db"),
        workspace=workspace,
        sandbox=FakeSandbox(),
    )
    run = guardian.start_run(
        project,
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
        environment_digest="env",
    )
    run = guardian.bind_task(
        run.run_id,
        expected_revision=run.revision,
        task="implement",
        session_id="session-1",
    )
    body = packet()
    body["phases"].append(
        {
            "id": "P2",
            "goal": "close",
            "requirement_ids": ["R1"],
            "acceptance_ids": ["A1"],
            "allowed_paths": ["src/**"],
            "check_ids": ["pytest"],
        }
    )
    run = activate_initial_plan(guardian, run.run_id, body)
    before = guardian.status(run.run_id)["skill_binding"]
    run = guardian.complete_phase(
        run.run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="complete",
    )
    after = guardian.status(run.run_id)["skill_binding"]

    assert before["phase_id"] == "P1"
    assert after["phase_id"] == "P2"
    assert before["digest"] != after["digest"]


@pytest.mark.parametrize("branch", ["unchanged", "in-scope", "out-of-scope"])
def test_interrupted_write_reuses_post_tool_scope_rules(tmp_path: Path, branch: str) -> None:
    guardian, workspace, run_id = create_guardian(tmp_path)
    guardian.authorize_tool(
        run_id,
        "edit",
        ["src/app.py"],
        call_id="call-1",
        session_id="session-1",
    )
    with pytest.raises(GuardError) as caught:
        guardian.store.revoke_session(run_id, "session-1")
    assert caught.value.code == "WRITE_LEASE_PENDING"
    if branch == "unchanged":
        recovered = guardian.reconcile_workspace(run_id)
        assert recovered.blocked_code == ""
        assert guardian.store.get_write_lease(run_id) is None
        return

    path = "src/app.py" if branch == "in-scope" else "src/escape.py"
    workspace.snapshot_value = WorkspaceSnapshot(
        (path,),
        "workspace-1",
        1,
        2,
        ((path, "hash-1"),),
    )
    if branch == "in-scope":
        recovered = guardian.reconcile_workspace(run_id)
        assert recovered.workspace_digest == "workspace-1"
        assert recovered.blocked_code == ""
        assert guardian.store.get_write_lease(run_id) is None
    else:
        with pytest.raises(GuardError) as caught:
            guardian.reconcile_workspace(run_id)
        assert caught.value.code == "WRITE_SCOPE_VIOLATION"
        assert guardian.status(run_id)["blocked"]["code"] == "WRITE_SCOPE_VIOLATION"


def test_failed_verification_reopens_the_last_phase(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path, exit_code=1)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="无需修改",
    )
    assert run.stage is Stage.IMPLEMENTING
    assert run.active_phase == "P1"


def test_actual_change_outside_declared_path_blocks_run(tmp_path: Path) -> None:
    guardian, workspace, run_id = create_guardian(tmp_path)
    lease = guardian.authorize_tool(
        run_id,
        "edit",
        ["src/app.py"],
        call_id="call-1",
    )
    workspace.snapshot_value = WorkspaceSnapshot(
        ("src/escape.py",),
        "workspace-1",
        1,
        2,
        (("src/escape.py", "hash-1"),),
    )
    with pytest.raises(GuardError, match="declared"):
        guardian.post_tool(
            run_id,
            expected_revision=lease["revision"],
            tool_name="edit",
            call_id="call-1",
        )
    assert guardian.status(run_id)["blocked"]["code"] == "WRITE_SCOPE_VIOLATION"


def test_only_external_review_accepts_current_evidence(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="无需修改",
    )
    accepted = guardian.review(
        run_id,
        decision="approve",
        reviewer="user",
        source="user",
    )
    assert accepted.stage is Stage.ACCEPTED
    candidate = packet()
    candidate["constraints"] = ["接受后不可修订。"]
    with pytest.raises(GuardError) as caught:
        guardian.submit_packet(
            run_id,
            expected_revision=accepted.revision,
            body=candidate,
        )
    assert caught.value.code == "LEGACY_ROUTE_FORBIDDEN"


@pytest.mark.skip(reason="V24 retires legacy packet revisions.")
def test_review_approve_rejects_revision_during_workspace_snapshot(tmp_path: Path) -> None:
    guardian, workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="初始验证通过",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    original_packet = run.packet_digest
    triggered = False

    def snapshot_with_interleaving(
        project_root: Path,
        worktree: Path,
        base_sha: str,
    ) -> WorkspaceSnapshot:
        nonlocal triggered
        if not triggered:
            triggered = True
            candidate = packet()
            candidate["constraints"] = ["review snapshot 期间修订计划。"]
            revised = guardian.submit_packet(
                run_id,
                expected_revision=run.revision,
                body=candidate,
            )
            assert revised.packet_digest != original_packet
            verified = guardian.complete_phase(
                run_id,
                expected_revision=revised.revision,
                phase_id="P1",
                outcome="no-change",
                rationale="修订后重新验证",
            )
            assert verified.stage is Stage.REVIEW_REQUIRED
        return workspace.snapshot_value

    workspace.snapshot = snapshot_with_interleaving  # type: ignore[method-assign]

    with pytest.raises(GuardError) as caught:
        guardian.review(run_id, decision="approve", reviewer="user", source="user")
    assert caught.value.code == "REVISION_CONFLICT"
    current = guardian.store.get_run(run_id)
    assert current.stage is Stage.REVIEW_REQUIRED
    assert current.packet_digest != original_packet


@pytest.mark.skip(reason="V24 retires legacy packet revisions.")
def test_stale_review_does_not_block_new_verified_workspace_revision(tmp_path: Path) -> None:
    guardian, workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="初始验证通过",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    original_packet = run.packet_digest
    triggered = False

    def snapshot_with_interleaving(
        project_root: Path,
        worktree: Path,
        base_sha: str,
    ) -> WorkspaceSnapshot:
        nonlocal triggered
        if not triggered:
            triggered = True
            candidate = packet()
            candidate["constraints"] = ["旧 review snapshot 期间完成合法新 revision。"]
            guardian.submit_packet(
                run_id,
                expected_revision=run.revision,
                body=candidate,
            )
            lease = guardian.authorize_tool(
                run_id,
                "edit",
                ["src/app.py"],
                call_id="review-race-write",
            )
            workspace.snapshot_value = WorkspaceSnapshot(
                ("src/app.py",),
                "workspace-1",
                1,
                2,
                (("src/app.py", "hash-1"),),
            )
            written = guardian.post_tool(
                run_id,
                expected_revision=lease["revision"],
                tool_name="edit",
                call_id="review-race-write",
            )
            verified = guardian.complete_phase(
                run_id,
                expected_revision=written.revision,
                phase_id="P1",
                outcome="changed",
                rationale="新 revision workspace-1 重新验证",
            )
            assert verified.stage is Stage.REVIEW_REQUIRED
            assert verified.packet_digest != original_packet
            assert verified.workspace_digest == "workspace-1"
        return workspace.snapshot_value

    workspace.snapshot = snapshot_with_interleaving  # type: ignore[method-assign]

    with pytest.raises(GuardError) as caught:
        guardian.review(run_id, decision="approve", reviewer="old-reviewer", source="user")

    current = guardian.store.get_run(run_id)
    assert current.stage is Stage.REVIEW_REQUIRED
    assert current.packet_digest != original_packet
    assert current.workspace_digest == "workspace-1"
    assert current.blocked_code == ""
    assert current.blocked_message == ""
    assert caught.value.code == "REVISION_CONFLICT"

    accepted = guardian.review(
        run_id,
        decision="approve",
        reviewer="current-reviewer",
        source="independent-review",
    )
    assert accepted.stage is Stage.ACCEPTED


def test_review_actual_workspace_mismatch_is_stale_without_blocking(tmp_path: Path) -> None:
    guardian, workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="验证通过后检测实际 workspace",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    workspace.snapshot_value = WorkspaceSnapshot(
        ("src/app.py",),
        "workspace-1",
        1,
        2,
        (("src/app.py", "hash-1"),),
    )

    with pytest.raises(GuardError) as caught:
        guardian.review(run_id, decision="approve", reviewer="reviewer", source="user")

    current = guardian.store.get_run(run_id)
    assert caught.value.code == "STALE_EVIDENCE"
    assert current.stage is Stage.REVIEW_REQUIRED
    assert current.revision == run.revision
    assert current.packet_digest == run.packet_digest
    assert current.evidence_digest == run.evidence_digest
    assert current.blocked_code == ""
    assert current.blocked_message == ""


def test_changes_requested_rejects_concurrent_approve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="等待外部 review",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    original_reopen = guardian.store.reopen_last_phase
    interleaved: dict[str, Any] = {}

    def reopen_after_approve(
        target_run_id: str,
        *,
        event: str,
        payload: dict[str, Any],
        **anchors: Any,
    ) -> object:
        accepted = guardian.review(
            target_run_id,
            decision="approve",
            reviewer="current-reviewer",
            source="independent-review",
        )
        interleaved["accepted"] = accepted
        return original_reopen(
            target_run_id,
            event=event,
            payload=payload,
            **anchors,
        )

    monkeypatch.setattr(guardian.store, "reopen_last_phase", reopen_after_approve)

    with pytest.raises(GuardError) as caught:
        guardian.review(
            run_id,
            decision="changes-requested",
            reviewer="old-reviewer",
            source="user",
        )

    accepted = interleaved["accepted"]
    current = guardian.store.get_run(run_id)
    assert caught.value.code == "REVISION_CONFLICT"
    assert current.stage is Stage.ACCEPTED
    assert current.revision == accepted.revision
    assert current.packet_digest == accepted.packet_digest
    assert current.workspace_digest == accepted.workspace_digest
    assert current.evidence_digest == accepted.evidence_digest
    assert current.event_head == accepted.event_head
    with sqlite3.connect(guardian.store.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id = ? AND type = 'CHANGES_REQUESTED'",
                (run_id,),
            ).fetchone()[0]
            == 0
        )


@pytest.mark.skip(reason="V24 retires legacy packet revisions.")
def test_changes_requested_rejects_concurrent_packet_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="等待外部 review",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    original_packet = run.packet_digest
    original_reopen = guardian.store.reopen_last_phase
    interleaved: dict[str, Any] = {}

    def reopen_after_revision(
        target_run_id: str,
        *,
        event: str,
        payload: dict[str, Any],
        **anchors: Any,
    ) -> object:
        candidate = packet()
        candidate["constraints"] = ["旧 changes-requested 期间完成新 packet revision。"]
        revised = guardian.submit_packet(
            target_run_id,
            expected_revision=run.revision,
            body=candidate,
        )
        verified = guardian.complete_phase(
            target_run_id,
            expected_revision=revised.revision,
            phase_id="P1",
            outcome="no-change",
            rationale="新 packet 重新验证",
        )
        interleaved["verified"] = verified
        return original_reopen(
            target_run_id,
            event=event,
            payload=payload,
            **anchors,
        )

    monkeypatch.setattr(guardian.store, "reopen_last_phase", reopen_after_revision)

    with pytest.raises(GuardError) as caught:
        guardian.review(
            run_id,
            decision="changes-requested",
            reviewer="old-reviewer",
            source="user",
        )

    verified = interleaved["verified"]
    current = guardian.store.get_run(run_id)
    assert caught.value.code == "REVISION_CONFLICT"
    assert current.stage is Stage.REVIEW_REQUIRED
    assert current.revision == verified.revision
    assert current.packet_digest == verified.packet_digest != original_packet
    assert current.workspace_digest == verified.workspace_digest
    assert current.evidence_digest == verified.evidence_digest
    assert current.active_phase == verified.active_phase
    assert current.event_head == verified.event_head
    with sqlite3.connect(guardian.store.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id = ? AND type = 'CHANGES_REQUESTED'",
                (run_id,),
            ).fetchone()[0]
            == 0
        )


def test_changes_requested_reopens_only_current_review(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="等待外部 review",
    )
    reopened = guardian.review(
        run_id,
        decision="changes-requested",
        reviewer="reviewer",
        source="independent-review",
    )

    assert reopened.stage is Stage.IMPLEMENTING
    assert reopened.active_phase == "P1"
    assert reopened.evidence_digest == ""
    with sqlite3.connect(guardian.store.database) as connection:
        event = connection.execute(
            "SELECT payload_json FROM events WHERE run_id = ? AND type = 'CHANGES_REQUESTED'",
            (run_id,),
        ).fetchone()
    assert event is not None
    assert json.loads(event[0])["packet_digest"] == run.packet_digest


@pytest.mark.skip(reason="V24 retires legacy packet revisions.")
def test_revision_invalidates_current_evidence_but_preserves_historical_rows(
    tmp_path: Path,
) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="初始验证",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    old_digest = run.packet_digest
    stale_context = guardian.status(run_id)
    assert guardian.evidence(run_id)

    candidate = packet()
    candidate["constraints"] = ["修订后的约束。"]
    revised = guardian.submit_packet(
        run_id,
        expected_revision=run.revision,
        body=candidate,
    )
    assert revised.packet_digest != old_digest
    assert guardian.evidence(run_id) == []
    historical = guardian.store.list_evidence(run_id, packet_digest=old_digest)
    assert historical
    assert all(item["historical"] is True for item in historical)
    with pytest.raises(GuardError) as caught:
        guardian.authorize_tool(
            run_id,
            "read",
            [],
            call_id="stale-after-revision",
            session_id="session-1",
            expected_revision=stale_context["source_revision"],
            context_digest=stale_context["context_digest"],
            skill_binding_digest=stale_context["skill_binding"]["digest"],
        )
    assert caught.value.code == "REVISION_CONFLICT"
    current = guardian.status(run_id)
    with pytest.raises(GuardError) as caught:
        guardian.authorize_tool(
            run_id,
            "read",
            [],
            call_id="old-skill-after-revision",
            session_id="session-1",
            expected_revision=current["source_revision"],
            context_digest=current["context_digest"],
            skill_binding_digest=stale_context["skill_binding"]["digest"],
        )
    assert caught.value.code == "SKILL_BINDING_INVALID"
    attached = guardian.attach_session(
        run_id,
        "session-2",
        expected_revision=current["source_revision"],
        context_digest=current["context_digest"],
        skill_binding_digest=current["skill_binding"]["digest"],
    )
    assert attached.run_id == run_id
    assert guardian.status(run_id)["packet_version"] == 2
    with pytest.raises(GuardError) as caught:
        guardian.review(run_id, decision="approve", reviewer="user", source="user")
    assert caught.value.code == "REVIEW_NOT_READY"


def test_stale_revision_precedes_blocked_state_for_submit_and_approve(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    before = guardian.store.get_run(run_id)
    blocked = guardian.store.block_run(
        run_id,
        code="TEST_BLOCKED",
        message="blocked for ordering test",
        payload={},
    )
    assert blocked.revision == before.revision + 1
    candidate = packet()
    candidate["constraints"] = ["新约束。"]
    for operation in (
        lambda: guardian.submit_packet(
            run_id,
            expected_revision=before.revision,
            body=candidate,
        ),
        lambda: guardian.approve_plan(
            run_id,
            expected_revision=before.revision,
            base_packet_digest=before.packet_digest,
            candidate_packet_digest="f" * 64,
            added_paths=["docs/**"],
            approved_by="operator",
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "LEGACY_ROUTE_FORBIDDEN"
    for operation in (
        lambda: guardian.submit_packet(
            run_id,
            expected_revision=blocked.revision,
            body=candidate,
        ),
        lambda: guardian.approve_plan(
            run_id,
            expected_revision=blocked.revision,
            base_packet_digest=blocked.packet_digest,
            candidate_packet_digest="f" * 64,
            added_paths=["docs/**"],
            approved_by="operator",
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "LEGACY_ROUTE_FORBIDDEN"


@pytest.mark.skip(reason="V24 retires legacy packet revisions.")
def test_late_revision_event_failure_rolls_back_current_evidence_and_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="初始验证完成",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    with sqlite3.connect(guardian.store.database) as connection:
        before = (
            connection.execute("PRAGMA user_version").fetchone()[0],
            tuple(connection.iterdump()),
        )
    original_append_event = execution_module.append_event

    def fail_revision_event(*args: object, event: str, **kwargs: object) -> int:
        if event == "PACKET_REVISED":
            raise RuntimeError("injected late revision failure")
        return original_append_event(*args, event=event, **kwargs)

    monkeypatch.setattr(execution_module, "append_event", fail_revision_event)
    candidate = packet()
    candidate["constraints"] = ["事务回滚约束。"]
    with pytest.raises(RuntimeError, match="injected late revision failure"):
        guardian.submit_packet(
            run_id,
            expected_revision=run.revision,
            body=candidate,
        )

    with sqlite3.connect(guardian.store.database) as connection:
        after = (
            connection.execute("PRAGMA user_version").fetchone()[0],
            tuple(connection.iterdump()),
        )
    assert after == before
    restored = guardian.store.get_run(run_id)
    assert restored.packet_digest == run.packet_digest
    assert restored.evidence_digest == run.evidence_digest
    assert guardian.evidence(run_id)


@pytest.mark.parametrize("field", ["packet_digest", "workspace_digest", "evidence_digest"])
def test_rehashed_run_accepted_digest_binding_fails_closed(tmp_path: Path, field: str) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="验证完成",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    accepted = guardian.review(run_id, decision="approve", reviewer="user", source="user")
    assert accepted.stage is Stage.ACCEPTED
    with sqlite3.connect(guardian.store.database) as connection:
        row = connection.execute(
            "SELECT payload_json FROM events WHERE run_id = ? AND type = 'RUN_ACCEPTED'",
            (run_id,),
        ).fetchone()
        payload = json.loads(row[0])
        payload[field] = "f" * 64
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE run_id = ? AND type = 'RUN_ACCEPTED'",
            (
                json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                run_id,
            ),
        )
        rehash_event_chain(connection, run_id)
        connection.commit()

    with pytest.raises(GuardError) as caught:
        guardian.store.get_run(run_id)
    assert caught.value.code == "PERSISTED_STATE_BROKEN"


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE evidence SET output_digest = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET set_digest = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET output_preview = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET check_id = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET base_sha = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET packet_digest = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET workspace_digest = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET requirement_ids_json = '[]' WHERE run_id = ?",
        "UPDATE evidence SET acceptance_ids_json = '[]' WHERE run_id = ?",
        "UPDATE evidence SET command_digest = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET image_digest = 'forged' WHERE run_id = ?",
        "UPDATE evidence SET exit_code = 1 WHERE run_id = ?",
        "UPDATE evidence SET timed_out = 1 WHERE run_id = ?",
        "UPDATE runs SET evidence_digest = 'forged' WHERE id = ?",
        "DELETE FROM evidence WHERE run_id = ?",
    ],
)
def test_tampered_evidence_blocks_reads_and_approval(tmp_path: Path, mutation: str) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    run = guardian.complete_phase(
        run_id,
        expected_revision=run.revision,
        phase_id="P1",
        outcome="no-change",
        rationale="完成",
    )
    assert run.stage is Stage.REVIEW_REQUIRED
    with sqlite3.connect(guardian.store.database) as connection:
        connection.execute(mutation, (run_id,))
        connection.commit()
        count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    for operation in (
        lambda: guardian.evidence(run_id),
        lambda: guardian.review(
            run_id,
            decision="approve",
            reviewer="user",
            source="user",
        ),
    ):
        with pytest.raises(GuardError) as caught:
            operation()
        assert caught.value.code == "PERSISTED_STATE_BROKEN"
    with sqlite3.connect(guardian.store.database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == count
        )


def test_unknown_tool_is_denied(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    with pytest.raises(GuardError, match="denied"):
        guardian.authorize_tool(run_id, "shell", [], call_id="call-1")


def test_tampered_check_blocks_docker_execution(tmp_path: Path) -> None:
    guardian, _workspace, run_id = create_guardian(tmp_path)
    run = guardian.store.get_run(run_id)
    with sqlite3.connect(guardian.store.database) as connection:
        connection.execute("UPDATE checks SET definition_json = '{}' WHERE run_id = ?", (run_id,))
        connection.commit()

    with pytest.raises(GuardError) as caught:
        guardian.complete_phase(
            run_id,
            expected_revision=run.revision,
            phase_id="P1",
            outcome="no-change",
            rationale="complete",
        )

    assert caught.value.code == "PERSISTED_STATE_BROKEN"
    assert guardian.sandbox.run_calls == 0
