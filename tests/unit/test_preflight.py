from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from opencode_guardian import trusted_install
from opencode_guardian.errors import GuardError
from opencode_guardian.preflight import assert_guard_environment, wait_for_plugin_handshake


class RunningProcess:
    def poll(self) -> None:
        return None


def test_trusted_release_hashes_match_plugin_and_node_sources() -> None:
    root = Path(__file__).resolve().parents[2]
    plugin = root / "opencode-plugin"
    source_paths = {
        "opencode-guard-authority/client.js": plugin / "client.js",
        "opencode-guard-authority/hooks.js": plugin / "hooks.js",
        "opencode-guard-authority/index.js": plugin / "index.js",
        "opencode-guard-authority/schemas.js": plugin / "schemas.js",
        "opencode-guard-authority/tools.js": plugin / "tools.js",
    }
    for relative, path in source_paths.items():
        assert (
            sha256(path.read_bytes()).hexdigest() in trusted_install.TRUSTED_PLUGIN_HASHES[relative]
        )
    loader = 'export { OpenCodeGuardAuthority } from "./opencode-guard-authority/index.js";'
    loader_hashes = {
        sha256(bom + loader.encode() + newline).hexdigest()
        for bom in (b"", b"\xef\xbb\xbf")
        for newline in (b"\n", b"\r\n")
    }
    assert trusted_install.TRUSTED_PLUGIN_HASHES["opencode-guard-authority.js"] == loader_hashes
    node_modules = plugin / "node_modules"
    for relative, expected in trusted_install.TRUSTED_NODE_PACKAGES.items():
        assert (
            trusted_install._package_tree_digest(
                node_modules / Path(*relative.split("/")), node_modules
            )
            == expected
        )


def installed_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    project = tmp_path / "project"
    config = tmp_path / "config" / "opencode"
    project.mkdir()
    (config / "plugins").mkdir(parents=True)
    plugin = config / "plugins" / "opencode-guard-authority.js"
    plugin.write_text(
        'export { OpenCodeGuardAuthority } from "./opencode-guard-authority/index.js";\n',
        encoding="utf-8",
    )
    bundle = config / "plugins" / "opencode-guard-authority"
    bundle.mkdir()
    files = {"opencode-guard-authority.js": sha256(plugin.read_bytes()).hexdigest()}
    for name in ("index.js", "client.js", "hooks.js", "tools.js", "schemas.js"):
        path = bundle / name
        path.write_text("export const value = 1;\n", encoding="utf-8")
        files[f"opencode-guard-authority/{name}"] = sha256(path.read_bytes()).hexdigest()
    (config / "plugins" / "opencode-guard-authority.install.json").write_text(
        json.dumps(
            {
                "owner": "opencode-guard-authority",
                "files": files,
                "had_previous": False,
            }
        ),
        encoding="utf-8",
    )
    dependency = config / "node_modules" / "@opencode-ai" / "plugin" / "package.json"
    dependency.parent.mkdir(parents=True)
    dependency.write_text(
        json.dumps({"name": "@opencode-ai/plugin", "version": "1.18.3"}), encoding="utf-8"
    )
    (dependency.parent / "dist").mkdir()
    (dependency.parent / "dist" / "index.js").write_text(
        'export * from "./tool.js";\n', encoding="utf-8"
    )
    (dependency.parent / "dist" / "tool.js").write_text(
        'import { z } from "zod";\nexport const tool = (input) => input;\n',
        encoding="utf-8",
    )
    zod = config / "node_modules" / "zod"
    zod.mkdir()
    (zod / "package.json").write_text(
        json.dumps({"name": "zod", "version": "4.1.8", "type": "module"}),
        encoding="utf-8",
    )
    (zod / "index.js").write_text("export const z = {};\n", encoding="utf-8")
    monkeypatch.setattr(
        trusted_install,
        "TRUSTED_PLUGIN_HASHES",
        {
            relative: frozenset({sha256((config / "plugins" / relative).read_bytes()).hexdigest()})
            for relative in files
        },
    )
    monkeypatch.setattr(
        trusted_install,
        "TRUSTED_NODE_PACKAGES",
        {
            relative: trusted_install._package_tree_digest(
                config / "node_modules" / Path(*relative.split("/")),
                config / "node_modules",
            )
            for relative in ("@opencode-ai/plugin", "zod")
        },
    )
    return project, config


def test_preflight_accepts_comments_urls_and_disabled_mcp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    (config / "opencode.jsonc").write_text(
        """﻿
        {
          // Provider URLs are not comments.
          "provider": {"local": {"options": {"baseURL": "https://localhost/v1"}}},
          "mcp": {"disabled": {"enabled": false, "command": ["missing"]}},
        }
        """,
        encoding="utf-8",
    )

    assert assert_guard_environment(project, config_root=config).plugin.name == (
        "opencode-guard-authority.js"
    )


@pytest.mark.parametrize(
    "body",
    (
        {"plugin": ["file:///untrusted/plugin.js"]},
        {"mcp": {"legacy": {"type": "local", "enabled": True, "command": ["missing"]}}},
    ),
)
def test_preflight_isolates_configured_extensions(
    tmp_path: Path, body: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    (config / "opencode.json").write_text(json.dumps(body), encoding="utf-8")

    preflight = assert_guard_environment(project, config_root=config)
    override = json.loads(preflight.config_content)
    assert override["plugin"] == [preflight.plugin.resolve().as_uri()]
    for name in body.get("mcp", {}):
        assert override["mcp"][name]["enabled"] is False


@pytest.mark.parametrize(
    "body",
    (
        {"plugin": ["file:///untrusted/plugin.js"]},
        {"formatter": True},
        {"lsp": {"custom": {"command": ["host-command"]}}},
        {"experimental": {"hook": {"file_edited": {"command": ["host-command"]}}}},
        {"provider": {"custom": {"npm": "untrusted-provider-package"}}},
    ),
)
def test_preflight_rejects_project_config_that_can_execute_host_code(
    tmp_path: Path, body: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    (project / "opencode.json").write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(GuardError) as caught:
        assert_guard_environment(project, config_root=config)
    assert caught.value.code == "UNTRUSTED_PROJECT_CONFIG"


def test_preflight_ignores_other_installed_plugins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    (config / "plugins" / "other.js").write_text("export default {}\n")

    preflight = assert_guard_environment(project, config_root=config)

    assert json.loads(preflight.config_content)["plugin"] == [preflight.plugin.resolve().as_uri()]


def test_preflight_ignores_inherited_custom_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    custom = tmp_path / "untrusted.json"
    custom.write_text("not json", encoding="utf-8")
    monkeypatch.setenv("OPENCODE_CONFIG", str(custom))

    preflight = assert_guard_environment(project, config_root=config)

    assert json.loads(preflight.config_content)["plugin"] == [preflight.plugin.resolve().as_uri()]


def test_preflight_builds_inline_allowlist_and_ignores_managed_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    managed = tmp_path / "program-data" / "opencode"
    managed.mkdir(parents=True)
    (managed / "opencode.json").write_text(
        json.dumps({"plugin": ["file:///managed-plugin.js"]}), encoding="utf-8"
    )
    monkeypatch.setenv("PROGRAMDATA", str(managed.parent))
    monkeypatch.setenv(
        "OPENCODE_CONFIG_CONTENT",
        json.dumps(
            {
                "experimental": {"hook": {"file_edited": {"command": ["host"]}}},
                "provider": {"custom": {"npm": "host-provider", "secret": "do-not-copy"}},
                "unknown": {"command": ["host"]},
                "mcp": {"host": {"command": ["host"]}},
            }
        ),
    )

    preflight = assert_guard_environment(project, config_root=config)
    inline = json.loads(preflight.config_content)

    assert set(inline) == {"plugin", "mcp", "formatter", "lsp"}
    assert inline["plugin"] == [preflight.plugin.resolve().as_uri()]
    assert inline["mcp"] == {"host": {"enabled": False}}
    assert inline["formatter"] is False
    assert inline["lsp"] is False


def test_preflight_rejects_project_plugin_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    (project / ".opencode" / "plugins").mkdir(parents=True)
    (project / ".opencode" / "plugins" / "bypass.js").write_text("export default {}\n")

    with pytest.raises(GuardError) as caught:
        assert_guard_environment(project, config_root=config)

    assert caught.value.code == "CONFLICTING_OPENCODE_PLUGIN"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("missing-manifest", "GUARD_PLUGIN_OWNERSHIP_INVALID"),
        ("wrong-owner", "GUARD_PLUGIN_OWNERSHIP_INVALID"),
        ("self-certified-plugin", "GUARD_PLUGIN_OWNERSHIP_INVALID"),
        ("dependency-content", "GUARD_PLUGIN_DEPENDENCY_INVALID"),
        ("transitive-content", "GUARD_PLUGIN_DEPENDENCY_INVALID"),
        ("dependency-extra-file", "GUARD_PLUGIN_DEPENDENCY_INVALID"),
    ),
)
def test_preflight_rejects_untrusted_guard_installation(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, config = installed_config(tmp_path, monkeypatch)
    manifest = config / "plugins" / "opencode-guard-authority.install.json"
    dependency = config / "node_modules" / "@opencode-ai" / "plugin" / "package.json"
    if mutation == "missing-manifest":
        manifest.unlink()
    elif mutation == "wrong-owner":
        body = json.loads(manifest.read_text(encoding="utf-8"))
        body["owner"] = "other-package"
        manifest.write_text(json.dumps(body), encoding="utf-8")
    elif mutation == "self-certified-plugin":
        plugin_file = config / "plugins" / "opencode-guard-authority" / "index.js"
        plugin_file.write_text("export const bypass = true;\n", encoding="utf-8")
        body = json.loads(manifest.read_text(encoding="utf-8"))
        body["files"]["opencode-guard-authority/index.js"] = sha256(
            plugin_file.read_bytes()
        ).hexdigest()
        manifest.write_text(json.dumps(body), encoding="utf-8")
    elif mutation == "dependency-content":
        (dependency.parent / "dist" / "index.js").write_text(
            "export const bypass = true;\n", encoding="utf-8"
        )
    elif mutation == "transitive-content":
        (config / "node_modules" / "zod" / "index.js").write_text(
            "export const z = { bypass: true };\n",
            encoding="utf-8",
        )
    else:
        (dependency.parent / "dist" / "extra.js").write_text(
            "export const bypass = true;\n", encoding="utf-8"
        )

    with pytest.raises(GuardError) as caught:
        assert_guard_environment(project, config_root=config)
    assert caught.value.code == expected_code


def test_plugin_handshake_must_match_run_worktree_and_nonce(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    handshake = tmp_path / "handshake.json"
    handshake.write_text(
        json.dumps(
            {
                "protocol": 1,
                "nonce": "nonce-1",
                "run_id": "run-1",
                "worktree": str(worktree),
            }
        ),
        encoding="utf-8",
    )
    wait_for_plugin_handshake(
        handshake,
        nonce="nonce-1",
        run_id="run-1",
        worktree=worktree,
        process=RunningProcess(),
        timeout_seconds=0.1,
    )

    handshake.write_text(
        json.dumps(
            {
                "protocol": 1,
                "nonce": "wrong",
                "run_id": "run-1",
                "worktree": str(worktree),
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(GuardError) as caught:
        wait_for_plugin_handshake(
            handshake,
            nonce="nonce-1",
            run_id="run-1",
            worktree=worktree,
            process=RunningProcess(),
            timeout_seconds=0.1,
        )
    assert caught.value.code == "PLUGIN_HANDSHAKE_INVALID"
