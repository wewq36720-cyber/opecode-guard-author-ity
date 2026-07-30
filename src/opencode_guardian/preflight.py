from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Protocol

from .errors import GuardError
from .integrity import digest_file
from .trusted_install import assert_trusted_node_dependencies, assert_trusted_plugin_files

GUARD_PLUGIN = "opencode-guard-authority.js"
HANDSHAKE_PROTOCOL = 1
_CONFIG_LIMIT = 2 * 1024 * 1024
_EXECUTABLE_EXTENSIONS = frozenset({".cjs", ".cts", ".js", ".mjs", ".mts", ".ts"})
_OWNED_PLUGIN_FILES = {
    "opencode-guard-authority.js",
    "opencode-guard-authority/client.js",
    "opencode-guard-authority/hooks.js",
    "opencode-guard-authority/index.js",
    "opencode-guard-authority/schemas.js",
    "opencode-guard-authority/tools.js",
}


class PollableProcess(Protocol):
    def poll(self) -> int | None: ...


@dataclass(frozen=True, slots=True)
class GuardEnvironment:
    plugin: Path
    config_content: str
    isolated_mcp: tuple[str, ...]


def default_config_root() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(configured).expanduser() if configured else Path.home() / ".config"
    return (base / "opencode").resolve()


def assert_guard_environment(
    project_root: Path, *, config_root: Path | None = None
) -> GuardEnvironment:
    project = project_root.resolve(strict=True)
    config = (config_root or default_config_root()).resolve()
    plugin = config / "plugins" / GUARD_PLUGIN
    if not plugin.is_file():
        raise GuardError(
            "GUARD_PLUGIN_NOT_INSTALLED",
            "Install the OpenCode Guard plugin before starting a guarded Run.",
            path=str(plugin),
        )
    _assert_owned_install(plugin, config)

    config_paths = [
        (config / "opencode.json", False),
        (config / "opencode.jsonc", False),
        (project / "opencode.json", True),
        (project / "opencode.jsonc", True),
    ]

    seen: set[Path] = set()
    isolated_mcp: set[str] = set()
    for candidate, project_owned in config_paths:
        resolved = candidate.resolve()
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        _inspect_config(
            _load_config(resolved),
            str(resolved),
            project_owned=project_owned,
            isolated_mcp=isolated_mcp,
        )

    inline = os.environ.get("OPENCODE_CONFIG_CONTENT", "").strip()
    inherited_inline = _parse_jsonc(inline, "OPENCODE_CONFIG_CONTENT") if inline else {}
    _inspect_config(
        inherited_inline,
        "inline config",
        project_owned=False,
        isolated_mcp=isolated_mcp,
    )

    extension_directories = (
        project / ".opencode" / "plugins",
        project / ".opencode" / "plugin",
        project / ".opencode" / "tools",
        project / ".opencode" / "tool",
    )
    for directory in extension_directories:
        if not directory.is_dir():
            continue
        for candidate in directory.iterdir():
            if candidate.is_file() and candidate.suffix.lower() in _EXECUTABLE_EXTENSIONS:
                raise GuardError(
                    "CONFLICTING_OPENCODE_PLUGIN",
                    "Guarded Runs cannot load project OpenCode plugins or custom tools.",
                    path=str(candidate),
                )
    inline_config: dict[str, Any] = {
        "plugin": [plugin.resolve(strict=True).as_uri()],
        "mcp": {},
        "formatter": False,
        "lsp": False,
    }
    mcp_override = inline_config["mcp"]
    assert isinstance(mcp_override, dict)
    for name in isolated_mcp:
        mcp_override[name] = {"enabled": False}
    return GuardEnvironment(
        plugin=plugin,
        config_content=json.dumps(inline_config, ensure_ascii=False, separators=(",", ":")),
        isolated_mcp=tuple(sorted(isolated_mcp)),
    )


def wait_for_plugin_handshake(
    handshake: Path,
    *,
    nonce: str,
    run_id: str,
    worktree: Path,
    process: PollableProcess,
    timeout_seconds: float = 15.0,
) -> None:
    expected_worktree = os.path.normcase(str(worktree.resolve()))
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if handshake.is_file():
            payload = _load_handshake(handshake)
            actual_worktree = payload.get("worktree")
            matches = (
                payload.get("protocol") == HANDSHAKE_PROTOCOL
                and payload.get("nonce") == nonce
                and payload.get("run_id") == run_id
                and isinstance(actual_worktree, str)
                and os.path.normcase(str(Path(actual_worktree).resolve())) == expected_worktree
            )
            if not matches:
                raise GuardError(
                    "PLUGIN_HANDSHAKE_INVALID",
                    "OpenCode Guard plugin returned a mismatched startup handshake.",
                )
            return
        exit_code = process.poll()
        if exit_code is not None:
            raise GuardError(
                "PLUGIN_HANDSHAKE_FAILED",
                "OpenCode exited before the Guard plugin completed its startup handshake.",
                exit_code=exit_code,
            )
        time.sleep(0.05)
    raise GuardError(
        "PLUGIN_HANDSHAKE_TIMEOUT",
        "OpenCode Guard plugin did not confirm startup before the timeout.",
    )


def _load_config(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > _CONFIG_LIMIT:
            raise GuardError(
                "OPENCODE_CONFIG_TOO_LARGE",
                "OpenCode config exceeds the two MiB inspection limit.",
                path=str(path),
            )
        return _parse_jsonc(path.read_text(encoding="utf-8"), str(path))
    except GuardError:
        raise
    except (OSError, UnicodeError) as exc:
        raise GuardError(
            "INVALID_OPENCODE_CONFIG",
            "OpenCode config could not be read safely.",
            path=str(path),
        ) from exc


def _assert_owned_install(plugin: Path, config_root: Path) -> None:
    manifest_path = plugin.parent / "opencode-guard-authority.install.json"
    if not manifest_path.is_file():
        raise GuardError(
            "GUARD_PLUGIN_OWNERSHIP_INVALID",
            "Guard plugin ownership manifest is missing.",
            path=str(manifest_path),
        )
    manifest = _load_config(manifest_path)
    files = manifest.get("files")
    if (
        manifest.get("owner") != "opencode-guard-authority"
        or not isinstance(files, dict)
        or set(files) != _OWNED_PLUGIN_FILES
    ):
        raise GuardError(
            "GUARD_PLUGIN_OWNERSHIP_INVALID",
            "Guard plugin ownership manifest does not match the minimal bundle.",
            path=str(manifest_path),
        )
    plugin_root = plugin.parent.resolve(strict=True)
    assert_trusted_plugin_files(plugin.parent)
    for relative, expected_hash in files.items():
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
        ):
            raise GuardError(
                "GUARD_PLUGIN_OWNERSHIP_INVALID",
                "Guard plugin manifest contains an unsafe entry.",
                path=str(manifest_path),
            )
        candidate = (plugin_root / relative_path).resolve(strict=True)
        try:
            candidate.relative_to(plugin_root)
        except ValueError as exc:
            raise GuardError(
                "GUARD_PLUGIN_OWNERSHIP_INVALID",
                "Guard plugin manifest path escapes the plugin directory.",
                path=str(candidate),
            ) from exc
        if not candidate.is_file() or digest_file(candidate) != expected_hash:
            raise GuardError(
                "GUARD_PLUGIN_OWNERSHIP_INVALID",
                "Guard plugin ownership record does not match the installed file.",
                path=str(candidate),
            )
    assert_trusted_node_dependencies(config_root)


def _parse_jsonc(text: str, source: str) -> dict[str, Any]:
    try:
        value = json.loads(_remove_trailing_commas(_strip_comments(text.removeprefix("\ufeff"))))
    except JSONDecodeError as exc:
        raise GuardError(
            "INVALID_OPENCODE_CONFIG",
            "OpenCode config is not valid JSON/JSONC.",
            source=source,
        ) from exc
    if not isinstance(value, dict):
        raise GuardError(
            "INVALID_OPENCODE_CONFIG",
            "OpenCode config root must be an object.",
            source=source,
        )
    return value


def _inspect_config(
    config: dict[str, Any],
    source: str,
    *,
    project_owned: bool,
    isolated_mcp: set[str],
) -> None:
    plugins = config.get("plugin", [])
    if plugins is not None and not isinstance(plugins, list):
        raise GuardError(
            "INVALID_OPENCODE_CONFIG",
            "OpenCode plugin config must be a list.",
            source=source,
        )
    mcp = config.get("mcp", {})
    if mcp in (None, {}):
        mcp = {}
    elif not isinstance(mcp, dict):
        raise GuardError(
            "INVALID_OPENCODE_CONFIG",
            "OpenCode mcp config must be an object.",
            source=source,
        )
    isolated_mcp.update(
        name
        for name, settings in mcp.items()
        if not isinstance(settings, dict) or settings.get("enabled", True) is not False
    )
    if not project_owned:
        return

    executable_keys = ["plugin"] if plugins else []
    executable_keys.extend(
        key for key in ("formatter", "lsp") if config.get(key) not in (None, False, {})
    )
    experimental = config.get("experimental", {})
    if isinstance(experimental, dict) and experimental.get("hook") not in (None, {}):
        executable_keys.append("experimental.hook")
    providers = config.get("provider", {})
    if isinstance(providers, dict) and any(
        isinstance(settings, dict) and settings.get("npm") for settings in providers.values()
    ):
        executable_keys.append("provider.*.npm")
    if executable_keys:
        raise GuardError(
            "UNTRUSTED_PROJECT_CONFIG",
            "Project OpenCode config may not declare host executable integrations.",
            source=source,
            keys=sorted(executable_keys),
        )


def _load_handshake(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (JSONDecodeError, OSError, UnicodeError) as exc:
        raise GuardError(
            "PLUGIN_HANDSHAKE_INVALID",
            "OpenCode Guard plugin returned an unreadable startup handshake.",
        ) from exc
    if not isinstance(value, dict):
        raise GuardError(
            "PLUGIN_HANDSHAKE_INVALID",
            "OpenCode Guard plugin handshake must be an object.",
        )
    return value


def _strip_comments(text: str) -> str:
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
        elif char == "/" and following == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
        elif char == "/" and following == "*":
            index += 2
            while index + 1 < len(text) and text[index : index + 2] != "*/":
                if text[index] in "\r\n":
                    output.append(text[index])
                index += 1
            index += 2
        else:
            output.append(char)
            index += 1
    return "".join(output)


def _remove_trailing_commas(text: str) -> str:
    output: list[str] = []
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            output.append(char)
            continue
        if char == ",":
            following = index + 1
            while following < len(text) and text[following].isspace():
                following += 1
            if following < len(text) and text[following] in "]}":
                continue
        output.append(char)
    return "".join(output)
