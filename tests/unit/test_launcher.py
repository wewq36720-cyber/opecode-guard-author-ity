from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from opencode_guardian import launcher
from opencode_guardian.errors import GuardError


class FinishedProcess:
    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        return 0


def test_opencode_arguments_only_resume_an_explicit_session() -> None:
    assert launcher.opencode_arguments(["--mini"]) == ["--mini"]
    assert launcher.opencode_arguments(["--mini"], session_id="session-2") == [
        "--mini",
        "--session",
        "session-2",
    ]


def test_launch_opencode_uses_clean_config_and_pure_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    state_dir = tmp_path / "state"
    captured: dict[str, Any] = {}
    process = FinishedProcess()

    def popen(arguments: list[str], **options: Any) -> FinishedProcess:
        captured.update(arguments=arguments, **options)
        return process

    def handshake(path: Path, **options: Any) -> None:
        captured.update(handshake=path, handshake_options=options)

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "host-xdg"))
    monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(tmp_path / "host-opencode"))
    monkeypatch.setenv("OPENCODE_CONFIG", str(tmp_path / "host-config.json"))
    monkeypatch.setattr(launcher.secrets, "token_urlsafe", lambda _size: "nonce")
    monkeypatch.setattr(launcher.subprocess, "Popen", popen)
    monkeypatch.setattr(launcher, "wait_for_plugin_handshake", handshake)

    result = launcher.launch_opencode(
        "opencode",
        ["--model", "provider/model"],
        SimpleNamespace(
            run_id="run-1",
            worktree=worktree,
            project_root=tmp_path,
        ),
        state_dir,
        config_content='{"plugin":["file:///guard.js"]}',
        authority_command=str((tmp_path / "authority.exe").resolve()),
        mcp_command=str((tmp_path / "mcp.exe").resolve()),
    )

    config_root = state_dir / "opencode-config" / "nonce"
    environment = captured["env"]
    assert captured["arguments"] == ["opencode", "--model", "provider/model"]
    assert captured["cwd"] == worktree
    assert captured["shell"] is False
    assert environment["XDG_CONFIG_HOME"] == str(config_root)
    assert environment["OPENCODE_CONFIG_DIR"] == str(config_root)
    assert environment["PROGRAMDATA"] == str(config_root)
    assert "OPENCODE_CONFIG" not in environment
    assert environment["OPENCODE_CONFIG_CONTENT"] == '{"plugin":["file:///guard.js"]}'
    assert config_root.is_dir()
    assert captured["handshake_options"]["nonce"] == "nonce"
    assert result["opencode_exit_code"] == 0


def test_launch_opencode_fails_when_clean_config_cannot_be_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_dir = tmp_path / "state"
    blocked = state_dir / "opencode-config" / "nonce"
    blocked.parent.mkdir(parents=True)
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(launcher.secrets, "token_urlsafe", lambda _size: "nonce")

    with pytest.raises(GuardError) as caught:
        launcher.launch_opencode(
            "opencode",
            [],
            SimpleNamespace(
                run_id="run-1",
                worktree=tmp_path,
                project_root=tmp_path,
            ),
            state_dir,
            config_content="{}",
            authority_command=str((tmp_path / "authority.exe").resolve()),
            mcp_command=str((tmp_path / "mcp.exe").resolve()),
        )

    assert caught.value.code == "OPENCODE_CONFIG_ISOLATION_FAILED"


def test_launch_opencode_converts_process_start_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    monkeypatch.setattr(launcher.secrets, "token_urlsafe", lambda _size: "nonce")

    def fail_start(*_args: Any, **_options: Any) -> None:
        raise OSError("sensitive host detail")

    monkeypatch.setattr(launcher.subprocess, "Popen", fail_start)
    with pytest.raises(GuardError) as caught:
        launcher.launch_opencode(
            "opencode",
            [],
            SimpleNamespace(run_id="run-1", worktree=worktree, project_root=tmp_path),
            tmp_path / "state",
            config_content="{}",
            authority_command=str((tmp_path / "authority.exe").resolve()),
            mcp_command=str((tmp_path / "mcp.exe").resolve()),
        )

    assert caught.value.code == "OPENCODE_START_FAILED"
    assert "sensitive host detail" not in str(caught.value.as_dict())
