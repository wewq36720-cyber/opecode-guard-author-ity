from __future__ import annotations

import os
import shutil
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .errors import GuardError
from .integrity import digest_bytes, digest_json
from .paths import default_state_dir

MAX_FILES = 20_000
MAX_BYTES = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ProjectInfo:
    root: Path
    git_common_dir: Path
    head: str


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    changed_paths: tuple[str, ...]
    digest: str
    file_count: int
    total_bytes: int
    changed_files: tuple[tuple[str, str], ...] = ()


class WorkspaceManager:
    def __init__(self, state_dir: Path | None = None) -> None:
        self.state_dir = (state_dir or default_state_dir()).resolve()
        self.worktrees_dir = self.state_dir / "worktrees"
        self.hooks_dir = self.state_dir / "empty-hooks"
        self.worktrees_dir.mkdir(parents=True, exist_ok=True)
        self.hooks_dir.mkdir(parents=True, exist_ok=True)

    def inspect_project(self, project_root: Path) -> ProjectInfo:
        root = project_root.resolve(strict=True)
        top = Path(self._git(root, "rev-parse", "--show-toplevel").strip()).resolve(strict=True)
        if os.path.normcase(str(top)) != os.path.normcase(str(root)):
            raise GuardError(
                "PROJECT_NOT_GIT_ROOT",
                "Project path must be the Git repository root.",
            )
        head = self._git(root, "rev-parse", "--verify", "HEAD").strip()
        if not head:
            raise GuardError("GIT_HEAD_REQUIRED", "Project requires an existing Git commit.")
        status = self._git(root, "status", "--porcelain", "--untracked-files=normal")
        if status.strip():
            raise GuardError(
                "DIRTY_BASELINE",
                "Project must be clean before a guarded Run starts.",
                paths=[line[3:] for line in status.splitlines()[:100]],
            )
        common_raw = self._git(root, "rev-parse", "--git-common-dir").strip()
        common = Path(common_raw)
        if not common.is_absolute():
            common = root / common
        return ProjectInfo(root=root, git_common_dir=common.resolve(strict=True), head=head)

    def create_worktree(self, project: ProjectInfo, run_id: str) -> Path:
        worktree = (self.worktrees_dir / run_id).resolve()
        self._assert_managed(worktree)
        if worktree.exists():
            raise GuardError("WORKTREE_EXISTS", f"Worktree already exists: {worktree}")
        try:
            self._git(
                project.root,
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                str(worktree),
                project.head,
            )
            self._git(worktree, "read-tree", project.head)
            self._materialize_commit(project.root, worktree, project.head)
        except Exception:
            self._remove_failed_worktree(project.root, worktree)
            raise
        snapshot = self.snapshot(project.root, worktree, project.head)
        if snapshot.changed_paths:
            self._remove_failed_worktree(project.root, worktree)
            raise GuardError(
                "WORKTREE_MATERIALIZATION_MISMATCH",
                "Guarded worktree does not match the Git base.",
                paths=list(snapshot.changed_paths),
            )
        return worktree

    def snapshot(self, project_root: Path, worktree: Path, base_sha: str) -> WorkspaceSnapshot:
        worktree = worktree.resolve(strict=True)
        self._assert_managed(worktree)
        self._validate_git_marker(worktree)
        baseline, baseline_modes = self._baseline_manifest(
            project_root.resolve(strict=True), base_sha
        )
        current, total_bytes = self._current_manifest(worktree, baseline_modes)
        changed = sorted(
            path
            for path in baseline.keys() | current.keys()
            if baseline.get(path) != current.get(path)
        )
        digest = digest_json(
            {
                "base_sha": base_sha,
                "files": [
                    {"path": path, "digest": current.get(path, "<deleted>")} for path in changed
                ],
            }
        )
        changed_files = tuple((path, current.get(path, "<deleted>")) for path in changed)
        return WorkspaceSnapshot(tuple(changed), digest, len(current), total_bytes, changed_files)

    def remove_worktree(self, project_root: Path, worktree: Path, *, force: bool = False) -> None:
        worktree = worktree.resolve(strict=False)
        self._assert_managed(worktree)
        args = ["worktree", "remove"]
        if force:
            args.append("--force")
        args.append(str(worktree))
        self._git(project_root.resolve(strict=True), *args)
        self._git(project_root.resolve(strict=True), "worktree", "prune")

    def _baseline_manifest(
        self, root: Path, base_sha: str
    ) -> tuple[dict[str, str], dict[str, str]]:
        output = self._git_bytes(root, "ls-tree", "-r", "-z", "--full-tree", base_sha)
        manifest: dict[str, str] = {}
        modes: dict[str, str] = {}
        for entry in output.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            if object_type != "blob" or mode not in {"100644", "100755"}:
                raise GuardError(
                    "UNSUPPORTED_GIT_ENTRY",
                    "Guarded projects cannot contain symlinks or submodules.",
                    path=raw_path.decode("utf-8", errors="replace"),
                    mode=mode,
                )
            relative = self._safe_git_path(raw_path)
            content = self._git_bytes(root, "cat-file", "blob", object_id)
            modes[relative] = mode
            manifest[relative] = _entry_digest(mode, digest_bytes(content))
            if len(manifest) > MAX_FILES:
                raise GuardError("WORKSPACE_TOO_LARGE", f"Project exceeds {MAX_FILES} files.")
        return manifest, modes

    def _materialize_commit(self, root: Path, worktree: Path, base_sha: str) -> None:
        output = self._git_bytes(root, "ls-tree", "-r", "-z", "--full-tree", base_sha)
        total = 0
        count = 0
        for entry in output.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            if object_type != "blob" or mode not in {"100644", "100755"}:
                raise GuardError(
                    "UNSUPPORTED_GIT_ENTRY",
                    "Guarded projects cannot contain symlinks or submodules.",
                    path=raw_path.decode("utf-8", errors="replace"),
                    mode=mode,
                )
            relative = self._safe_git_path(raw_path)
            content = self._git_bytes(root, "cat-file", "blob", object_id)
            total += len(content)
            count += 1
            if total > MAX_BYTES or count > MAX_FILES:
                raise GuardError(
                    "WORKSPACE_TOO_LARGE",
                    "Project exceeds worktree materialization limits.",
                )
            target = (worktree / relative).resolve(strict=False)
            try:
                target.relative_to(worktree)
            except ValueError as exc:
                raise GuardError("PATH_ESCAPE", f"Git path escapes worktree: {relative}") from exc
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            if os.name != "nt":
                target.chmod(0o755 if mode == "100755" else 0o644)

    def _current_manifest(
        self, worktree: Path, baseline_modes: dict[str, str]
    ) -> tuple[dict[str, str], int]:
        manifest: dict[str, str] = {}
        total = 0
        for directory, names, files in os.walk(worktree, followlinks=False):
            directory_path = Path(directory)
            for name in list(names):
                candidate = directory_path / name
                if _is_reparse_point(candidate):
                    raise GuardError(
                        "REPARSE_POINT",
                        f"Workspace contains a reparse point: {candidate}",
                    )
            for name in files:
                candidate = directory_path / name
                relative = candidate.relative_to(worktree).as_posix()
                if relative == ".git":
                    continue
                if _is_reparse_point(candidate) or not candidate.is_file():
                    raise GuardError(
                        "UNSAFE_FILE",
                        f"Workspace contains an unsafe file: {relative}",
                    )
                size = candidate.stat().st_size
                total += size
                if total > MAX_BYTES or len(manifest) >= MAX_FILES:
                    raise GuardError("WORKSPACE_TOO_LARGE", "Workspace exceeds snapshot limits.")
                mode = _file_mode(candidate, baseline_modes.get(relative))
                manifest[relative] = _entry_digest(mode, digest_bytes(candidate.read_bytes()))
        return manifest, total

    @staticmethod
    def _safe_git_path(raw_path: bytes) -> str:
        try:
            text = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GuardError("INVALID_GIT_PATH", "Git paths must be valid UTF-8.") from exc
        path = Path(text)
        if path.is_absolute() or ".." in path.parts or "\x00" in text:
            raise GuardError("INVALID_GIT_PATH", f"Unsafe Git path: {text}")
        return path.as_posix()

    def _git(self, cwd: Path, *args: str) -> str:
        return self._git_bytes(cwd, *args).decode("utf-8", errors="replace")

    def _git_bytes(self, cwd: Path, *args: str) -> bytes:
        command = [
            "git",
            "-c",
            f"core.hooksPath={self.hooks_dir}",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(cwd),
            *args,
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=60,
                shell=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise GuardError("GIT_UNAVAILABLE", "Git command could not run.") from exc
        if result.returncode != 0:
            raise GuardError(
                "GIT_FAILED",
                "Git command failed.",
                operation=args[0] if args else "unknown",
                stderr=result.stderr[-4_000:].decode("utf-8", errors="replace"),
            )
        return result.stdout

    def _validate_git_marker(self, worktree: Path) -> None:
        marker = worktree / ".git"
        if not marker.is_file() or marker.stat().st_size > 4_096:
            raise GuardError("INVALID_WORKTREE", "Worktree .git marker is missing or invalid.")
        text = marker.read_text(encoding="utf-8", errors="strict").strip()
        if not text.startswith("gitdir: "):
            raise GuardError("INVALID_WORKTREE", "Worktree .git marker has an invalid format.")

    def _assert_managed(self, path: Path) -> None:
        try:
            path.relative_to(self.worktrees_dir.resolve())
        except ValueError as exc:
            raise GuardError("UNMANAGED_WORKTREE", "Worktree must live under Guard state.") from exc

    def _remove_failed_worktree(self, project_root: Path, worktree: Path) -> None:
        try:
            self._git(project_root, "worktree", "remove", "--force", str(worktree))
        except GuardError:
            if worktree.exists():
                self._assert_managed(worktree.resolve())
                shutil.rmtree(worktree)
        with suppress(GuardError):
            self._git(project_root, "worktree", "prune")


def _is_reparse_point(path: Path) -> bool:
    stat = path.lstat()
    attributes = getattr(stat, "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & 0x400)


def _file_mode(path: Path, baseline_mode: str | None) -> str:
    if os.name == "nt":
        return baseline_mode or "100644"
    return "100755" if path.stat().st_mode & 0o111 else "100644"


def _entry_digest(mode: str, content_digest: str) -> str:
    return digest_json({"mode": mode, "content_sha256": content_digest})
