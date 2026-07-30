from __future__ import annotations

import os
from pathlib import Path

import pytest

from opencode_guardian.sandbox import DockerSandbox

ALPINE_IMAGE = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"


@pytest.mark.docker_smoke
@pytest.mark.skipif(os.environ.get("RUN_DOCKER_SMOKE") != "1", reason="Docker smoke disabled")
def test_container_cannot_leak_secret_write_workspace_or_reach_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GUARD_SMOKE_SECRET", "must-not-enter-container")
    command = (
        'test -z "$GUARD_SMOKE_SECRET" '
        "&& test ! -e /authority "
        "&& ! touch /workspace/guard-smoke-write "
        "&& ! wget -q -T 2 -O - https://example.com"
    )
    check = {
        "id": "isolation-smoke",
        "image": ALPINE_IMAGE,
        "argv": ["sh", "-c", command],
        "timeout_seconds": 30,
        "required": True,
        "writable_tmpfs": [],
    }
    root = Path(__file__).parents[2]
    result = DockerSandbox().run(worktree=root, run_id="run-smoke", check=check)
    assert result.exit_code == 0, result.output
    assert result.timed_out is False
    assert not (root / "guard-smoke-write").exists()
