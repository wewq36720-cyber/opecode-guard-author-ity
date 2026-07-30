from __future__ import annotations

import json
import shutil
import subprocess
import venv
from hashlib import sha256
from pathlib import Path

from opencode_guardian.trusted_install import assert_trusted_plugin_files


def run_script(root: Path, name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-File",
            str(root / "scripts" / name),
            *arguments,
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def installed_python(root: Path, tmp_path: Path) -> Path:
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / "Scripts" / "python.exe"
    installed = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(root)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert installed.returncode == 0, installed.stderr
    return python


def test_install_and_uninstall_own_the_complete_plugin_bundle(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    config = tmp_path / "opencode"
    python = installed_python(root, tmp_path)
    installed = run_script(
        root,
        "install.ps1",
        "-Python",
        str(python),
        "-ConfigRoot",
        str(config),
        "-SkipPythonInstall",
        "-SkipNodeInstall",
    )
    assert installed.returncode == 0, installed.stderr

    manifest_path = config / "plugins" / "opencode-guard-authority.install.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    assert set(manifest["files"]) == {
        "opencode-guard-authority.js",
        "opencode-guard-authority/client.js",
        "opencode-guard-authority/hooks.js",
        "opencode-guard-authority/index.js",
        "opencode-guard-authority/schemas.js",
        "opencode-guard-authority/tools.js",
    }
    for relative, expected in manifest["files"].items():
        assert sha256((config / "plugins" / relative).read_bytes()).hexdigest() == expected
    loader = config / "plugins" / "opencode-guard-authority.js"
    assert loader.read_bytes() == (
        b'export { OpenCodeGuardAuthority } from "./opencode-guard-authority/index.js";\n'
    )
    assert_trusted_plugin_files(config / "plugins")

    removed = run_script(
        root,
        "uninstall.ps1",
        "-ConfigRoot",
        str(config),
    )
    assert removed.returncode == 0, removed.stderr
    assert not (config / "plugins" / "opencode-guard-authority.js").exists()
    assert not (config / "plugins" / "opencode-guard-authority").exists()
    assert not manifest_path.exists()


def test_uninstall_restores_previous_top_level_plugin(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    config = tmp_path / "opencode"
    python = installed_python(root, tmp_path)
    plugins = config / "plugins"
    plugins.mkdir(parents=True)
    previous = b"export default { legacy: true };\n"
    (plugins / "opencode-guard-authority.js").write_bytes(previous)

    installed = run_script(
        root,
        "install.ps1",
        "-Python",
        str(python),
        "-ConfigRoot",
        str(config),
        "-SkipPythonInstall",
        "-SkipNodeInstall",
    )
    assert installed.returncode == 0, installed.stderr
    assert (plugins / "opencode-guard-authority.js.before-guard").read_bytes() == previous

    removed = run_script(root, "uninstall.ps1", "-ConfigRoot", str(config))
    assert removed.returncode == 0, removed.stderr
    assert (plugins / "opencode-guard-authority.js").read_bytes() == previous
    assert not (plugins / "opencode-guard-authority.js.before-guard").exists()


def test_install_rejects_a_stale_isolated_python_module(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    stale = tmp_path / "stale-contracts.py"
    stale.write_text("# stale\n", encoding="utf-8")
    fake_python = tmp_path / "python.cmd"
    fake_python.write_text(f"@echo off\r\necho {stale}\r\n", encoding="ascii")
    config = tmp_path / "opencode"

    installed = run_script(
        root,
        "install.ps1",
        "-Python",
        str(fake_python),
        "-ConfigRoot",
        str(config),
        "-SkipPythonInstall",
        "-SkipNodeInstall",
    )

    assert installed.returncode != 0
    assert "does not match repository source" in installed.stderr
    assert not (config / "plugins" / "opencode-guard-authority.js").exists()


def test_install_rejects_a_stale_sibling_python_module(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    package = tmp_path / "installed" / "opencode_guardian"
    shutil.copytree(root / "src" / "opencode_guardian", package)
    (package / "facade.py").write_text("# stale\n", encoding="utf-8")
    fake_python = tmp_path / "python.cmd"
    fake_python.write_text(f"@echo off\r\necho {package / 'contracts.py'}\r\n", encoding="ascii")
    config = tmp_path / "opencode"

    installed = run_script(
        root,
        "install.ps1",
        "-Python",
        str(fake_python),
        "-ConfigRoot",
        str(config),
        "-SkipPythonInstall",
        "-SkipNodeInstall",
    )

    assert installed.returncode != 0
    assert "does not match repository source" in installed.stderr
    assert not (config / "plugins" / "opencode-guard-authority.js").exists()
