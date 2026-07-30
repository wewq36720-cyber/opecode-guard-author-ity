from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from opencode_guardian import GuardError
from opencode_guardian import workspace as workspace_module
from opencode_guardian.workspace import WorkspaceManager


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "guard@example.invalid")
    git(root, "config", "user.name", "Guard Test")
    (root / "src").mkdir()
    (root / "src/app.py").write_text("print('base')\n", encoding="utf-8")
    (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "baseline")
    return root


def test_worktree_is_transactional_and_detects_ignored_files(tmp_path: Path) -> None:
    root = repository(tmp_path)
    manager = WorkspaceManager(tmp_path / "guard-state")
    project = manager.inspect_project(root)
    worktree = manager.create_worktree(project, "run-1")

    assert manager.snapshot(root, worktree, project.head).changed_paths == ()
    (worktree / "src/app.py").write_text("print('changed')\n", encoding="utf-8")
    (worktree / "ignored.txt").write_text("must be visible\n", encoding="utf-8")
    snapshot = manager.snapshot(root, worktree, project.head)

    assert snapshot.changed_paths == ("ignored.txt", "src/app.py")
    assert (root / "src/app.py").read_text(encoding="utf-8") == "print('base')\n"
    assert not (root / "ignored.txt").exists()

    manager.remove_worktree(root, worktree, force=True)
    assert not worktree.exists()


def test_dirty_and_nested_projects_are_rejected(tmp_path: Path) -> None:
    root = repository(tmp_path)
    manager = WorkspaceManager(tmp_path / "guard-state")
    (root / "src/app.py").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(GuardError) as dirty:
        manager.inspect_project(root)
    assert dirty.value.code == "DIRTY_BASELINE"

    with pytest.raises(GuardError) as nested:
        manager.inspect_project(root / "src")
    assert nested.value.code == "PROJECT_NOT_GIT_ROOT"


def test_workspace_digest_detects_a_mode_only_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repository(tmp_path)
    manager = WorkspaceManager(tmp_path / "guard-state")
    project = manager.inspect_project(root)
    worktree = manager.create_worktree(project, "run-mode")
    original = manager.snapshot(root, worktree, project.head)

    monkeypatch.setattr(
        workspace_module,
        "_file_mode",
        lambda path, baseline_mode: (
            "100755" if path.name == "app.py" else (baseline_mode or "100644")
        ),
    )
    changed = manager.snapshot(root, worktree, project.head)

    assert changed.changed_paths == ("src/app.py",)
    assert changed.changed_files != original.changed_files
    assert changed.digest != original.digest


@pytest.mark.skipif(os.name == "nt", reason="Windows does not expose Git executable mode")
def test_materialized_posix_executable_mode_is_preserved(tmp_path: Path) -> None:
    root = repository(tmp_path)
    git(root, "update-index", "--chmod=+x", "src/app.py")
    (root / "src/app.py").chmod(0o755)
    git(root, "commit", "-qm", "make executable")
    manager = WorkspaceManager(tmp_path / "guard-state")
    project = manager.inspect_project(root)
    worktree = manager.create_worktree(project, "run-executable")

    target = worktree / "src/app.py"
    assert target.stat().st_mode & 0o111
    target.chmod(0o644)

    assert manager.snapshot(root, worktree, project.head).changed_paths == ("src/app.py",)
