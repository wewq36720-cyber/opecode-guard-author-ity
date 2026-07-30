from __future__ import annotations

from pathlib import Path

import pytest

from opencode_guardian.errors import GuardError
from opencode_guardian.sandbox import SAFE_ENV, DockerSandbox


def check() -> dict:
    return {
        "id": "python-test",
        "image": "python@sha256:" + "a" * 64,
        "argv": ["python", "-m", "pytest"],
        "timeout_seconds": 120,
        "required": True,
        "writable_tmpfs": ["build"],
    }


def test_docker_command_contains_every_security_boundary(tmp_path: Path) -> None:
    sandbox = DockerSandbox()
    command, name, _digest = sandbox.build_command(
        worktree=tmp_path,
        run_id="run-1",
        check=check(),
    )
    joined = " ".join(command)
    assert name == "guard-run-1-python-test"
    assert "--network none" in joined
    assert "--read-only" in command
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges=true" in joined
    assert "--pids-limit 128" in joined
    assert "--memory 1024m" in joined
    assert "--cpus 1.0" in joined
    assert "--user 65532:65532" in joined
    assert "dst=/workspace,readonly" in joined
    assert "/workspace/build:rw,nosuid,nodev" in joined
    for key, value in SAFE_ENV.items():
        assert f"{key}={value}" in command


def test_unpinned_image_and_escaping_tmpfs_are_rejected(tmp_path: Path) -> None:
    sandbox = DockerSandbox()
    unpinned = check()
    unpinned["image"] = "python:latest"
    with pytest.raises(GuardError) as image_error:
        sandbox.build_command(worktree=tmp_path, run_id="run-1", check=unpinned)
    assert image_error.value.code == "UNPINNED_IMAGE"

    escaping = check()
    escaping["writable_tmpfs"] = ["../outside"]
    with pytest.raises(GuardError) as path_error:
        sandbox.build_command(worktree=tmp_path, run_id="run-1", check=escaping)
    assert path_error.value.code == "INVALID_TMPFS"


def test_multiple_plan_images_use_one_batched_inspect() -> None:
    class RecordingSandbox(DockerSandbox):
        def __init__(self) -> None:
            super().__init__()
            self.calls: list[tuple[str, ...]] = []

        def _docker_control(self, *args: str) -> str:
            self.calls.append(args)
            return "29.4.3"

    sandbox = RecordingSandbox()
    first = "python@sha256:" + "a" * 64
    second = "alpine@sha256:" + "b" * 64

    sandbox.assert_images_available([first, second, first])

    assert sandbox.calls == [
        ("info", "--format", "{{.ServerVersion}}"),
        ("image", "inspect", "--format", "{{.Id}}", first, second),
    ]
