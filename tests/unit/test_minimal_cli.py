from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_minimal_persistence import packet

from opencode_guardian import cli
from opencode_guardian.contracts import RunRecord, packet_digest
from opencode_guardian.errors import GuardError
from opencode_guardian.facade import Guardian
from opencode_guardian.persistence import StateStore
from opencode_guardian.workspace import ProjectInfo, WorkspaceSnapshot


def legacy_packet() -> dict[str, Any]:
    return {
        "requirements": [{"id": "R1"}],
        "acceptance": [{"id": "A1"}],
        "constraints": [],
        "non_goals": [],
        "stop_conditions": [],
        "architecture": {},
        "phases": [
            {
                "id": "P1",
                "requirement_ids": ["R1"],
                "acceptance_ids": ["A1"],
                "allowed_paths": ["src/**"],
                "check_ids": ["pytest"],
            }
        ],
    }


class StartupWorkspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.removed: list[Path] = []
        self.fail_remove = False

    def inspect_project(self, _project: Path) -> SimpleNamespace:
        return SimpleNamespace(root=self.root, head="a" * 40)

    def remove_worktree(self, _project: Path, worktree: Path, *, force: bool) -> None:
        assert force is True
        self.removed.append(worktree)
        if self.fail_remove:
            raise OSError("remove failed")


class StartupGuardian:
    def __init__(self, root: Path) -> None:
        self.workspace = StartupWorkspace(root)
        self.cancelled: list[str] = []
        self.fail_cancel = False
        self.store = SimpleNamespace(
            find_active=lambda _root: None,
            cancel_startup=self.cancel_startup,
        )
        self.run = SimpleNamespace(
            run_id="run-1",
            project_root=root,
            worktree=root.parent / "worktree",
            session_id="",
        )

    def start_run(self, *_args: Any, **_options: Any) -> SimpleNamespace:
        return self.run

    def cancel_startup(self, run_id: str) -> None:
        self.cancelled.append(run_id)
        if self.fail_cancel:
            raise OSError("cancel failed")


class PersistentStartupWorkspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.worktrees: list[Path] = []

    def inspect_project(self, project_root: Path) -> ProjectInfo:
        return ProjectInfo(project_root, project_root / ".git", "a" * 40)

    def create_worktree(self, _project: ProjectInfo, run_id: str) -> Path:
        worktree = self.root.parent / f"persistent-worktree-{run_id}"
        worktree.mkdir()
        self.worktrees.append(worktree)
        return worktree

    def snapshot(
        self,
        _project_root: Path,
        _worktree: Path,
        _base_sha: str,
    ) -> WorkspaceSnapshot:
        return WorkspaceSnapshot((), "workspace", 1, 1, ())

    def remove_worktree(self, _project_root: Path, worktree: Path, *, force: bool) -> None:
        assert force is True
        shutil.rmtree(worktree)


def test_cli_surface_exposes_only_authorized_local_commands() -> None:
    parser = cli._parser()
    choices = parser._subparsers._group_actions[0].choices
    assert set(choices) == {
        "open",
        "inspect",
        "quality-status",
        "drive-quality",
        "confirm-fitness",
        "review",
        "approve-plan",
        "record-planning-review",
    }
    assert "session" in choices["open"]._option_string_actions["--session"].dest


def test_quality_write_commands_forward_current_guard_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    class QualityGuardian:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def status(self, run_id: str) -> dict[str, Any]:
            return {
                "revision": 7,
                "context_digest": "context-7",
                "skill_binding": {"digest": "skill-7"},
            }

        def drive_quality(self, run_id: str, **values: Any) -> dict[str, Any]:
            calls.append(("drive", run_id, values))
            return {"drive_id": "d-1"}

        def confirm_fitness(self, run_id: str, **values: Any) -> dict[str, Any]:
            calls.append(("confirm", run_id, values))
            return {"confirmation_id": "c-1"}

    monkeypatch.setattr(cli, "StateStore", lambda _path: object())
    monkeypatch.setattr(cli, "WorkspaceManager", lambda _path: object())
    monkeypatch.setattr(cli, "Guardian", QualityGuardian)

    common = {
        "state_dir": str(tmp_path),
        "run": "run-quality",
        "session": "session-1",
        "request_id": "request-1",
    }
    assert cli._dispatch(SimpleNamespace(command="drive-quality", **common)) == {"drive_id": "d-1"}
    assert cli._dispatch(SimpleNamespace(command="confirm-fitness", drive_id="d-1", **common)) == {
        "confirmation_id": "c-1"
    }
    assert calls == [
        (
            "drive",
            "run-quality",
            {
                "expected_revision": 7,
                "session_id": "session-1",
                "context_digest": "context-7",
                "skill_binding_digest": "skill-7",
                "request_id": "request-1",
            },
        ),
        (
            "confirm",
            "run-quality",
            {
                "expected_revision": 7,
                "session_id": "session-1",
                "context_digest": "context-7",
                "skill_binding_digest": "skill-7",
                "request_id": "request-1",
                "drive_id": "d-1",
            },
        ),
    ]


def test_approve_plan_cli_forwards_only_a_typed_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    receipt = {"approval_id": "APR-1", "kind": "PLAN_APPROVAL_RECEIPT"}
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    calls: list[tuple[str, int, dict[str, object]]] = []

    class ReceiptGuardian:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def approve_plan_receipt(
            self, run_id: str, *, expected_revision: int, receipt: dict[str, object]
        ) -> dict[str, object]:
            calls.append((run_id, expected_revision, receipt))
            return {"approval_id": "APR-1", "consumed": True, "revision": 5}

        def status(self, run_id: str) -> dict[str, object]:
            return {"run_id": run_id, "revision": 5}

    monkeypatch.setattr(cli, "StateStore", lambda _path: SimpleNamespace())
    monkeypatch.setattr(cli, "WorkspaceManager", lambda _path: SimpleNamespace())
    monkeypatch.setattr(cli, "Guardian", ReceiptGuardian)
    result = cli._dispatch(
        SimpleNamespace(
            state_dir=str(tmp_path),
            command="approve-plan",
            run="run-approve",
            expected_revision=3,
            receipt=str(receipt_path),
        )
    )
    assert calls == [("run-approve", 3, receipt)]
    assert result == {
        "run_id": "run-approve",
        "revision": 5,
        "approval": {"approval_id": "APR-1", "consumed": True, "revision": 5},
    }


@pytest.mark.parametrize(
    ("requested_session", "expected_suffix"),
    [("", []), ("session-2", ["--session", "session-2"])],
)
def test_open_defaults_to_fresh_session_and_only_resumes_explicit_participant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requested_session: str,
    expected_suffix: list[str],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = PersistentStartupWorkspace(project)
    store = StateStore(tmp_path / "guard.db")
    guardian = Guardian(store, workspace=workspace)
    check = {
        "id": "pytest",
        "image": "example@sha256:" + "a" * 64,
        "argv": ["pytest"],
        "timeout_seconds": 60,
        "required": True,
        "writable_tmpfs": [],
    }
    run = guardian.start_run(project, checks=[check], environment_digest="same")
    run = guardian.bind_task(
        run.run_id,
        expected_revision=run.revision,
        task="current task",
        session_id="session-1",
    )
    store.attach_session(run.run_id, "session-2", expected_revision=run.revision)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        guardian,
        "resume_run",
        lambda _project: store.get_run(run.run_id),
    )
    monkeypatch.setattr(
        cli,
        "assert_guard_environment",
        lambda _root: SimpleNamespace(config_content="{}", isolated_mcp=()),
    )
    monkeypatch.setattr(cli, "trusted_executable", lambda *_args, **_options: "opencode")
    monkeypatch.setattr(cli, "guard_commands", lambda _roots: ("authority", "mcp"))

    def launch(*args: Any, **_options: Any) -> dict[str, Any]:
        captured["arguments"] = args[1]
        return {"run_id": args[2].run_id}

    monkeypatch.setattr(cli, "launch_opencode", launch)
    result = cli._open(
        guardian,
        SimpleNamespace(
            project=str(project),
            dry_run=False,
            opencode="opencode",
            session=requested_session,
            opencode_args=["--mini"],
        ),
        tmp_path / "state",
    )

    assert result["run_id"] == run.run_id
    assert captured["arguments"] == ["--mini", *expected_suffix]


def test_open_rejects_unknown_explicit_session_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = PersistentStartupWorkspace(project)
    store = StateStore(tmp_path / "guard.db")
    guardian = Guardian(store, workspace=workspace)
    run = store.create_run(
        run_id="run-current",
        project_root=project,
        git_common_dir=project / ".git",
        worktree=tmp_path / "worktree",
        base_sha="a" * 40,
        environment_digest="same",
        workspace_digest="workspace",
        checks=[
            {
                "id": "pytest",
                "image": "example@sha256:" + "a" * 64,
                "argv": ["pytest"],
                "timeout_seconds": 60,
                "required": True,
                "writable_tmpfs": [],
            }
        ],
    )
    launched = False

    def launch(*_args: Any, **_options: Any) -> dict[str, Any]:
        nonlocal launched
        launched = True
        return {}

    monkeypatch.setattr(cli, "launch_opencode", launch)
    with pytest.raises(GuardError) as caught:
        cli._open(
            guardian,
            SimpleNamespace(
                project=str(project),
                dry_run=False,
                opencode="opencode",
                session="session-unknown",
                opencode_args=[],
            ),
            tmp_path / "state",
        )
    assert caught.value.code == "SESSION_NOT_ATTACHED"
    assert store.get_run(run.run_id).revision == run.revision
    assert launched is False


def test_two_projects_keep_independent_active_runs_and_leases(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "guard.db")
    checks = [
        {
            "id": "pytest",
            "image": "example@sha256:" + "a" * 64,
            "argv": ["pytest"],
            "timeout_seconds": 60,
            "required": True,
            "writable_tmpfs": [],
        }
    ]
    runs = []
    for suffix in ("a", "b"):
        project = tmp_path / f"project-{suffix}"
        project.mkdir()
        run = store.create_run(
            run_id=f"run-{suffix}",
            project_root=project,
            git_common_dir=project / ".git",
            worktree=tmp_path / f"worktree-{suffix}",
            base_sha=suffix * 40,
            environment_digest=f"env-{suffix}",
            workspace_digest="workspace-0",
            checks=checks,
        )
        run = store.bind_task(
            run.run_id,
            expected_revision=run.revision,
            task=f"task-{suffix}",
            session_id=f"session-{suffix}",
        )
        body = packet()
        run = store.submit_packet(
            run.run_id,
            expected_revision=run.revision,
            packet=body,
            digest=packet_digest(body),
        )
        lease = store.create_write_lease(
            run.run_id,
            expected_revision=run.revision,
            session_id=f"session-{suffix}",
            call_id=f"call-{suffix}",
            tool_name="edit",
            declared_paths=["src/app.py"],
            before_digest="workspace-0",
            before_files=[],
        )
        runs.append((project, run, lease))

    assert store.find_active(runs[0][0]).run_id == "run-a"
    assert store.find_active(runs[1][0]).run_id == "run-b"
    assert store.get_write_lease("run-a")["session_id"] == "session-a"
    assert store.get_write_lease("run-b")["session_id"] == "session-b"

    guardian = Guardian(store, workspace=PersistentStartupWorkspace(runs[0][0]))
    with pytest.raises(GuardError) as caught:
        guardian.start_run(runs[0][0], checks=checks, environment_digest="env-new")
    assert caught.value.code == "RUN_ALREADY_ACTIVE"


def test_new_run_rechecks_actual_worktree_and_cleans_environment_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    guardian = StartupGuardian(project)
    checked: list[Path] = []
    prepared: list[Path] = []
    digests = iter(("before", "after"))
    monkeypatch.setattr(
        cli,
        "assert_guard_environment",
        lambda root: checked.append(root) or SimpleNamespace(config_content="{}", isolated_mcp=()),
    )
    monkeypatch.setattr(
        cli,
        "prepare_project_environment",
        lambda root: (
            prepared.append(root)
            or SimpleNamespace(
                digest=next(digests), image="image", python_version="3.13", checks=()
            )
        ),
    )

    with pytest.raises(GuardError) as caught:
        cli._open(
            guardian,  # type: ignore[arg-type]
            SimpleNamespace(
                project=str(project),
                dry_run=False,
                opencode="opencode",
                opencode_args=[],
            ),
            tmp_path / "state",
        )

    assert caught.value.code == "PROJECT_ENVIRONMENT_CHANGED"
    assert checked == [project]
    assert prepared == [project, guardian.run.worktree]
    assert guardian.workspace.removed == [guardian.run.worktree]


def test_new_run_preflights_actual_worktree_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    guardian = StartupGuardian(project)
    checked: list[Path] = []

    def preflight(root: Path) -> SimpleNamespace:
        checked.append(root)
        if root == guardian.run.worktree:
            raise GuardError("CONFLICTING_OPENCODE_PLUGIN", "blocked")
        return SimpleNamespace(config_content="{}", isolated_mcp=())

    monkeypatch.setattr(cli, "assert_guard_environment", preflight)
    monkeypatch.setattr(
        cli,
        "prepare_project_environment",
        lambda _root: SimpleNamespace(
            digest="same", image="image", python_version="3.13", checks=()
        ),
    )

    with pytest.raises(GuardError) as caught:
        cli._open(
            guardian,  # type: ignore[arg-type]
            SimpleNamespace(
                project=str(project),
                dry_run=False,
                opencode="opencode",
                opencode_args=[],
            ),
            tmp_path / "state",
        )

    assert caught.value.code == "CONFLICTING_OPENCODE_PLUGIN"
    assert checked == [project, guardian.run.worktree]
    assert guardian.workspace.removed == [guardian.run.worktree]


def test_new_run_cleans_worktree_after_process_start_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    guardian = StartupGuardian(project)
    monkeypatch.setattr(
        cli,
        "assert_guard_environment",
        lambda _root: SimpleNamespace(config_content="{}", isolated_mcp=()),
    )
    monkeypatch.setattr(
        cli,
        "prepare_project_environment",
        lambda _root: SimpleNamespace(
            digest="same", image="image", python_version="3.13", checks=()
        ),
    )
    monkeypatch.setattr(cli, "trusted_executable", lambda *_args, **_options: "opencode")
    monkeypatch.setattr(cli, "guard_commands", lambda _roots: ("authority", "mcp"))

    def fail_launch(*_args: Any, **_options: Any) -> None:
        raise GuardError("OPENCODE_START_FAILED", "OpenCode process could not be started.")

    monkeypatch.setattr(cli, "launch_opencode", fail_launch)

    with pytest.raises(GuardError) as caught:
        cli._open(
            guardian,  # type: ignore[arg-type]
            SimpleNamespace(
                project=str(project),
                dry_run=False,
                opencode="opencode",
                opencode_args=[],
            ),
            tmp_path / "state",
        )

    assert caught.value.code == "OPENCODE_START_FAILED"
    assert guardian.workspace.removed == [guardian.run.worktree]
    assert guardian.cancelled == [guardian.run.run_id]


@pytest.mark.parametrize("failed_cleanup", ["worktree", "run"])
def test_new_run_attempts_both_cleanup_sides_when_one_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_cleanup: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    guardian = StartupGuardian(project)
    guardian.workspace.fail_remove = failed_cleanup == "worktree"
    guardian.fail_cancel = failed_cleanup == "run"
    monkeypatch.setattr(
        cli,
        "assert_guard_environment",
        lambda _root: SimpleNamespace(config_content="{}", isolated_mcp=()),
    )
    monkeypatch.setattr(
        cli,
        "prepare_project_environment",
        lambda _root: SimpleNamespace(
            digest="same", image="image", python_version="3.13", checks=()
        ),
    )
    monkeypatch.setattr(cli, "trusted_executable", lambda *_args, **_options: "opencode")
    monkeypatch.setattr(cli, "guard_commands", lambda _roots: ("authority", "mcp"))
    monkeypatch.setattr(
        cli,
        "launch_opencode",
        lambda *_args, **_options: (_ for _ in ()).throw(
            GuardError("OPENCODE_START_FAILED", "failed")
        ),
    )

    with pytest.raises(GuardError) as caught:
        cli._open(
            guardian,  # type: ignore[arg-type]
            SimpleNamespace(
                project=str(project), dry_run=False, opencode="opencode", opencode_args=[]
            ),
            tmp_path / "state",
        )

    assert caught.value.code == "STARTUP_CLEANUP_FAILED"
    assert guardian.workspace.removed == [guardian.run.worktree]
    assert guardian.cancelled == [guardian.run.run_id]


def test_persistent_startup_failure_is_not_active_and_can_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = PersistentStartupWorkspace(project)
    store = StateStore(tmp_path / "guard.db")
    guardian = Guardian(store, workspace=workspace)
    check = {
        "id": "pytest",
        "image": "example@sha256:" + "a" * 64,
        "argv": ["pytest"],
        "timeout_seconds": 60,
        "required": True,
        "writable_tmpfs": [],
    }
    monkeypatch.setattr(
        cli,
        "assert_guard_environment",
        lambda _root: SimpleNamespace(config_content="{}", isolated_mcp=()),
    )
    monkeypatch.setattr(
        cli,
        "prepare_project_environment",
        lambda _root: SimpleNamespace(
            digest="same", image=check["image"], python_version="3.13", checks=[check]
        ),
    )
    monkeypatch.setattr(cli, "trusted_executable", lambda *_args, **_options: "opencode")
    monkeypatch.setattr(cli, "guard_commands", lambda _roots: ("authority", "mcp"))
    failed_run: list[RunRecord] = []
    launch_count = 0

    def launch(*args: Any, **_options: Any) -> dict[str, Any]:
        nonlocal launch_count
        launch_count += 1
        run = args[2]
        if launch_count == 1:
            failed_run.append(run)
            raise GuardError("OPENCODE_START_FAILED", "OpenCode process could not be started.")
        return {"run_id": run.run_id}

    monkeypatch.setattr(cli, "launch_opencode", launch)
    args = SimpleNamespace(
        project=str(project),
        dry_run=False,
        opencode="opencode",
        opencode_args=[],
    )

    with pytest.raises(GuardError) as caught:
        cli._open(guardian, args, tmp_path / "state")

    assert caught.value.code == "OPENCODE_START_FAILED"
    assert failed_run
    assert store.find_active(project) is None
    assert store.get_run(failed_run[0].run_id).blocked_code == "STARTUP_FAILED"
    assert store.get_run(failed_run[0].run_id).event_count == 2

    result = cli._open(guardian, args, tmp_path / "state")
    assert result["run_id"] != failed_run[0].run_id
    assert launch_count == 2


def test_open_retires_legacy_frozen_run_and_starts_current_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = PersistentStartupWorkspace(project)
    store = StateStore(tmp_path / "guard.db")
    guardian = Guardian(store, workspace=workspace)
    check = {
        "id": "pytest",
        "image": "example@sha256:" + "a" * 64,
        "argv": ["pytest"],
        "timeout_seconds": 60,
        "required": True,
        "writable_tmpfs": [],
    }
    legacy = guardian.start_run(project, checks=[check], environment_digest="same")
    legacy = store.bind_task(
        legacy.run_id,
        expected_revision=legacy.revision,
        task="legacy packet",
        session_id="session-1",
    )
    body = legacy_packet()
    legacy = store.submit_packet(
        legacy.run_id,
        expected_revision=legacy.revision,
        packet=body,
        digest=packet_digest(body),
    )
    legacy_artifact = store.get_artifact(legacy.run_id)
    legacy_worktree = legacy.worktree
    monkeypatch.setattr(
        cli,
        "assert_guard_environment",
        lambda _root: SimpleNamespace(config_content="{}", isolated_mcp=()),
    )
    monkeypatch.setattr(
        cli,
        "prepare_project_environment",
        lambda _root: SimpleNamespace(
            digest="same", image=check["image"], python_version="3.13", checks=[check]
        ),
    )
    monkeypatch.setattr(cli, "trusted_executable", lambda *_args, **_options: "opencode")
    monkeypatch.setattr(cli, "guard_commands", lambda _roots: ("authority", "mcp"))
    monkeypatch.setattr(
        cli,
        "launch_opencode",
        lambda *_args, **_options: {"run_id": _args[2].run_id},
    )
    args = SimpleNamespace(
        project=str(project), dry_run=False, opencode="opencode", opencode_args=[]
    )

    result = cli._open(guardian, args, tmp_path / "state")

    retired = store.get_run(legacy.run_id)
    assert retired.blocked_code == "LEGACY_RUN_RETIRED"
    assert retired.worktree == legacy_worktree
    assert legacy_worktree.exists()
    assert store.get_artifact(legacy.run_id) == legacy_artifact
    assert result["run_id"] != legacy.run_id


def test_open_dry_run_reports_legacy_restart_without_mutation(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    store = StateStore(tmp_path / "guard.db")
    workspace = PersistentStartupWorkspace(project)
    guardian = Guardian(store, workspace=workspace)
    check = {
        "id": "pytest",
        "image": "example@sha256:" + "a" * 64,
        "argv": ["pytest"],
        "timeout_seconds": 60,
        "required": True,
        "writable_tmpfs": [],
    }
    legacy = guardian.start_run(project, checks=[check], environment_digest="same")
    legacy = store.bind_task(
        legacy.run_id,
        expected_revision=legacy.revision,
        task="legacy packet",
        session_id="session-1",
    )
    body = legacy_packet()

    store.submit_packet(
        legacy.run_id,
        expected_revision=legacy.revision,
        packet=body,
        digest=packet_digest(body),
    )
    before = store.get_run(legacy.run_id)

    result = cli._open(
        guardian,
        SimpleNamespace(project=str(project), dry_run=True, opencode="opencode", opencode_args=[]),
        tmp_path / "state",
    )

    after = store.get_run(legacy.run_id)
    assert result == {
        "status": "LEGACY_RESTART_REQUIRED",
        "project_root": str(project.resolve()),
        "legacy_run_id": legacy.run_id,
    }
    assert after == before
