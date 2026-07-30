from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import GuardError
from .integrity import digest_file, digest_json

TRUSTED_PLUGIN_HASHES = {
    "opencode-guard-authority.js": frozenset(
        {
            "32adf0c3df356f8b981ee62e752fe52317c8ab7f7c95f56332bd2d9da08fda6f",
            "5349cf261340afe45513c4591020ef8fec6686545f821b7df40d0d7347a5909f",
            "b43579607d432d7ec4cb832e93c319ef26c999b836420891b7421379dbb47df4",
            "d749f49ffd86211ee0cb287148298a3bc12e33744e592573e3cca1de1e03f246",
        }
    ),
    "opencode-guard-authority/client.js": frozenset(
        {"c3fc93ba6e38501f431577a1182ea0d1d2de5f748b386e645c8ad153eb60a8b1"}
    ),
    "opencode-guard-authority/hooks.js": frozenset(
        {
            "82a0d60770e38052fc37ebfbd267da260fe62199ff36a16f6f7fa5f37521a395",
            "cabfd4a3253c95119ea898dd14f8822185c8d1f2daa032bce6d76dae64249e1b",
        }
    ),
    "opencode-guard-authority/index.js": frozenset(
        {"28bcf0982d8ff74f28d187df810a310f9ebb3c1b5af3f46b749491ec3935c0b9"}
    ),
    "opencode-guard-authority/schemas.js": frozenset(
        {"6ed2b6b7fd025ea48d627a66d3c633db824a7d381b01e838804f01d7993aaef8"}
    ),
    "opencode-guard-authority/tools.js": frozenset(
        {
            "5a9411ef110f2a839a263ebdc3da575490ded29b2028df493616e29f76404bb4",
            "5557186ed362fc0dcdefea8166dc54a698322c804114981fe65e8c1fdc414715",
            "fddc90573f6056a0f7e493d0f93d2e76f577dbfdae8193a5697b93668250c99f",
        }
    ),
}

TRUSTED_NODE_PACKAGES = {
    "@opencode-ai/plugin": "cdbba1b65e8c7e6094798bc69275825840c5039ab70b15468b81c03793b1ea82",
    "zod": "39e6256d211f041004daa996f0b3bd42b83f02109b17f8955b24502c884c1b56",
}

_MAX_PACKAGE_FILES = 1_000
_MAX_PACKAGE_BYTES = 16 * 1024 * 1024


def assert_trusted_plugin_files(plugin_root: Path) -> None:
    if _unsafe_path(plugin_root):
        _invalid_plugin(plugin_root, "Guard plugin directory is not a regular directory.")
    root = plugin_root.resolve(strict=True)
    bundle = root / "opencode-guard-authority"
    if _unsafe_path(bundle):
        _invalid_plugin(bundle, "Guard plugin bundle is not a regular directory.")
    for path in bundle.rglob("*"):
        if path.is_dir() and _unsafe_path(path):
            _invalid_plugin(path, "Guard plugin directory contains a reparse point.")
    actual = {"opencode-guard-authority.js"} | {
        path.relative_to(root).as_posix() for path in bundle.rglob("*") if path.is_file()
    }
    expected = set(TRUSTED_PLUGIN_HASHES)
    if actual != expected:
        _invalid_plugin(root, "Guard plugin file set does not match the trusted release.")
    for relative, trusted_hashes in TRUSTED_PLUGIN_HASHES.items():
        candidate = root / relative
        if _unsafe_path(candidate) or digest_file(candidate) not in trusted_hashes:
            _invalid_plugin(candidate, "Guard plugin content does not match the trusted release.")


def assert_trusted_node_dependencies(config_root: Path) -> None:
    node_modules = config_root.resolve() / "node_modules"
    for relative, expected_digest in TRUSTED_NODE_PACKAGES.items():
        package_root = node_modules / Path(*relative.split("/"))
        try:
            actual_digest = _package_tree_digest(package_root, node_modules)
        except (OSError, ValueError) as exc:
            raise GuardError(
                "GUARD_PLUGIN_DEPENDENCY_INVALID",
                "OpenCode Guard plugin dependency could not be verified safely.",
                path=str(package_root),
            ) from exc
        if actual_digest != expected_digest:
            raise GuardError(
                "GUARD_PLUGIN_DEPENDENCY_INVALID",
                "OpenCode Guard plugin dependency content is not trusted.",
                path=str(package_root),
            )


def _package_tree_digest(package_root: Path, node_modules: Path) -> str:
    root = package_root.resolve(strict=True)
    root.relative_to(node_modules.resolve(strict=True))
    if _unsafe_path(package_root):
        raise ValueError("unsafe package root")
    entries: list[dict[str, str]] = []
    total_bytes = 0
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            if _unsafe_path(directory_path / name):
                raise ValueError("unsafe package directory")
        for name in files:
            candidate = directory_path / name
            if _unsafe_path(candidate) or not candidate.is_file():
                raise ValueError("unsafe package file")
            total_bytes += candidate.stat().st_size
            if len(entries) >= _MAX_PACKAGE_FILES or total_bytes > _MAX_PACKAGE_BYTES:
                raise ValueError("package tree exceeds integrity limits")
            entries.append(
                {
                    "path": candidate.relative_to(root).as_posix(),
                    "sha256": digest_file(candidate),
                }
            )
    entries.sort(key=lambda entry: entry["path"])
    return digest_json(entries)


def _unsafe_path(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _invalid_plugin(path: Path, message: str) -> None:
    raise GuardError("GUARD_PLUGIN_OWNERSHIP_INVALID", message, path=str(path))
