from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .contracts import RunRecord
from .errors import GuardError
from .preflight import wait_for_plugin_handshake


def launch_opencode(
    executable: str,
    values: Sequence[str],
    run: RunRecord,
    state_dir: Path,
    *,
    config_content: str,
    authority_command: str,
    mcp_command: str,
) -> dict[str, Any]:
    handshake_directory = state_dir / "handshakes"
    handshake_directory.mkdir(parents=True, exist_ok=True)
    nonce = secrets.token_urlsafe(24)
    config_root = state_dir / "opencode-config" / nonce
    try:
        config_root.mkdir(parents=True)
    except OSError as exc:
        raise GuardError(
            "OPENCODE_CONFIG_ISOLATION_FAILED",
            "Guard could not create a clean OpenCode config directory.",
            path=str(config_root),
        ) from exc
    handshake = handshake_directory / f"{run.run_id}-{nonce}.json"
    environment = guard_launch_environment(
        base=os.environ,
        run_id=run.run_id,
        worktree=run.worktree,
        state_dir=state_dir,
        config_root=config_root,
        handshake=handshake,
        nonce=nonce,
        config_content=config_content,
        authority_command=authority_command,
        mcp_command=mcp_command,
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        try:
            process = subprocess.Popen(
                [executable, *values],
                cwd=run.worktree,
                env=environment,
                shell=False,
            )
        except OSError as exc:
            raise GuardError(
                "OPENCODE_START_FAILED",
                "OpenCode process could not be started.",
                executable=executable,
            ) from exc
        wait_for_plugin_handshake(
            handshake,
            nonce=nonce,
            run_id=run.run_id,
            worktree=run.worktree,
            process=process,
        )
        print(
            json.dumps(
                {
                    "guard": "ACTIVE",
                    "run_id": run.run_id,
                    "worktree": str(run.worktree),
                    "resume": open_command(state_dir, run.project_root),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
            flush=True,
        )
        return {
            "run_id": run.run_id,
            "worktree": str(run.worktree),
            "opencode_exit_code": process.wait(),
        }
    except BaseException:
        if process is not None:
            terminate(process)
        raise
    finally:
        handshake.unlink(missing_ok=True)


def trusted_executable(
    value: str,
    *,
    forbidden_roots: Sequence[Path],
    not_found_code: str = "GUARD_EXECUTABLE_NOT_FOUND",
) -> str:
    located = shutil.which(value)
    if not located:
        raise GuardError(not_found_code, f"Executable not found: {value}")
    try:
        executable = Path(located).resolve(strict=True)
    except OSError as exc:
        raise GuardError(not_found_code, f"Executable path is unavailable: {value}") from exc
    if not executable.is_file():
        raise GuardError(not_found_code, f"Executable path is not a file: {value}")
    for root in forbidden_roots:
        try:
            executable.relative_to(root.resolve(strict=True))
        except ValueError:
            continue
        raise GuardError(
            "UNTRUSTED_EXECUTABLE",
            "Guard and OpenCode executables must be outside the project and worktree.",
            executable=str(executable),
        )
    return str(executable)


def guard_commands(forbidden_roots: Sequence[Path]) -> tuple[str, str]:
    return (
        trusted_executable(
            "opencode-guard-authority",
            forbidden_roots=forbidden_roots,
        ),
        trusted_executable(
            "opencode-guard-mcp",
            forbidden_roots=forbidden_roots,
        ),
    )


def guard_launch_environment(
    *,
    base: Mapping[str, str],
    run_id: str,
    worktree: Path,
    state_dir: Path,
    config_root: Path,
    handshake: Path,
    nonce: str,
    config_content: str,
    authority_command: str,
    mcp_command: str,
) -> dict[str, str]:
    if not Path(authority_command).is_absolute() or not Path(mcp_command).is_absolute():
        raise GuardError(
            "TRUSTED_COMMAND_REQUIRED",
            "Authority and MCP commands must be absolute paths.",
        )
    environment = dict(base)
    environment.pop("OPENCODE_CONFIG", None)
    environment.update(
        {
            "OPENCODE_GUARD_RUN_ID": run_id,
            "OPENCODE_GUARD_WORKTREE": str(worktree),
            "OPENCODE_GUARD_STATE_DIR": str(state_dir),
            "OPENCODE_GUARD_AUTHORITY_COMMAND": authority_command,
            "OPENCODE_GUARD_MCP_COMMAND": mcp_command,
            "OPENCODE_GUARD_HANDSHAKE_FILE": str(handshake),
            "OPENCODE_GUARD_HANDSHAKE_NONCE": nonce,
            "OPENCODE_CONFIG_CONTENT": config_content,
            "XDG_CONFIG_HOME": str(config_root),
            "OPENCODE_CONFIG_DIR": str(config_root),
            "PROGRAMDATA": str(config_root),
        }
    )
    return environment


def opencode_arguments(values: Sequence[str], *, session_id: str = "") -> list[str]:
    arguments = list(values)
    if arguments[:1] == ["--"]:
        arguments.pop(0)
    value_options = {
        "--agent",
        "--cors",
        "--hostname",
        "--log-level",
        "--mdns-domain",
        "--model",
        "--port",
        "--prompt",
        "--replay-limit",
        "-m",
    }
    flag_options = {"--mdns", "--mini", "--no-replay", "--print-logs"}
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option in flag_options:
            index += 1
        elif option in value_options and index + 1 < len(arguments):
            index += 2
        else:
            raise GuardError(
                "OPENCODE_ARGUMENT_DENIED",
                f"OpenCode argument is not allowed in a guarded Run: {option}",
            )
    if session_id:
        arguments.extend(["--session", session_id])
    return arguments


def open_command(state_dir: Path, project_root: Path) -> str:
    return (
        f'opencode-guard --state-dir "{state_dir.resolve()}" '
        f'open --project "{project_root.resolve()}"'
    )


def terminate(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
