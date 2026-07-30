from __future__ import annotations

import json
from pathlib import Path

import pytest

from opencode_guardian.environment import (
    BUILDER_VERSION,
    PYTHON_BASE_IMAGES,
    UV_IMAGE,
    prepare_project_environment,
)
from opencode_guardian.errors import GuardError
from opencode_guardian.integrity import digest_bytes, digest_json


def write_uv_project(root: Path, *, requires_python: str = ">=3.13") -> None:
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "\n".join(
            (
                "[project]",
                'name = "dispatch-hub"',
                'version = "0.1.0"',
                f'requires-python = "{requires_python}"',
                'dependencies = ["fastapi>=0.115"]',
                "",
                "[project.optional-dependencies]",
                'dev = ["pytest>=8", "ruff>=0.6", "mypy>=1.11"]',
                "",
                "[build-system]",
                'requires = ["setuptools>=75"]',
                'build-backend = "setuptools.build_meta"',
            )
        ),
        encoding="utf-8",
    )
    (root / "uv.lock").write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.13"\n',
        encoding="utf-8",
    )


def expected_environment_digest(root: Path) -> str:
    return digest_json(
        {
            "builder_version": BUILDER_VERSION,
            "base_image": PYTHON_BASE_IMAGES["3.13"],
            "uv_image": UV_IMAGE,
            "pyproject": digest_bytes((root / "pyproject.toml").read_bytes()),
            "uv_lock": digest_bytes((root / "uv.lock").read_bytes()),
        }
    )


def test_project_environment_builds_a_pinned_trusted_check_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    write_uv_project(project)
    calls: list[tuple[str, ...]] = []
    built = False
    dockerfile = ""
    final_digest = "f" * 64
    environment_digest = expected_environment_digest(project)

    def metadata(environment_digest: str) -> str:
        return json.dumps(
            {
                "RepoDigests": [f"opencode-guard/dispatch-hub@sha256:{final_digest}"],
                "Config": {"Labels": {"org.opencode-guard.environment-digest": environment_digest}},
            }
        )

    def fake_docker(*args: str, cwd: Path | None = None, timeout: int = 30) -> str:
        nonlocal built, dockerfile
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            target = args[2]
            if target.startswith("opencode-guard/") and not built:
                raise GuardError("DOCKER_COMMAND_FAILED", "missing")
            if target.startswith("opencode-guard/"):
                return metadata(environment_digest)
            return json.dumps([target])
        if args[:1] == ("build",):
            assert cwd is not None
            dockerfile = (cwd / "Dockerfile").read_text(encoding="utf-8")
            built = True
            return "built"
        if args[:1] == ("run",):
            return "Python 3.13\nuv 0.11.28"
        raise AssertionError(args)

    monkeypatch.setattr("opencode_guardian.environment._docker", fake_docker)

    environment = prepare_project_environment(project)

    assert environment.image == f"opencode-guard/dispatch-hub@sha256:{final_digest}"
    assert environment.python_version == "3.13"
    assert [check["id"] for check in environment.checks] == [
        "sync",
        "lint",
        "format",
        "typecheck",
        "pytest",
        "smoke",
        "build",
    ]
    build_check = next(check for check in environment.checks if check["id"] == "build")
    assert build_check["argv"][:2] == ["sh", "-c"]
    assert "/tmp/build-src" in build_check["argv"][2]
    assert all(check["image"] == environment.image for check in environment.checks)
    assert "uv sync --frozen --no-install-project --extra dev" in dockerfile
    assert "uv venv /opt/build-venv" in dockerfile
    assert "UV_CACHE_DIR=/tmp/uv-cache" in dockerfile
    assert "PYTHONPATH=/workspace/src" in dockerfile
    assert "RUFF_CACHE_DIR=/tmp/ruff" in dockerfile
    assert any(call[:1] == ("build",) for call in calls)
    assert any(call[:1] == ("run",) for call in calls)


def test_project_environment_reuses_a_matching_cached_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    write_uv_project(project)
    calls: list[tuple[str, ...]] = []
    final_digest = "e" * 64
    environment_digest = expected_environment_digest(project)

    def fake_docker(*args: str, cwd: Path | None = None, timeout: int = 30) -> str:
        del cwd, timeout
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return json.dumps(
                {
                    "RepoDigests": [f"opencode-guard/dispatch-hub@sha256:{final_digest}"],
                    "Config": {
                        "Labels": {"org.opencode-guard.environment-digest": environment_digest}
                    },
                }
            )
        if args[:1] == ("run",):
            return "Python 3.13\nuv 0.11.28"
        raise AssertionError(args)

    monkeypatch.setattr("opencode_guardian.environment._docker", fake_docker)

    environment = prepare_project_environment(project)

    assert environment.image.endswith(final_digest)
    assert not any(call[:1] == ("build",) for call in calls)


def test_project_environment_rebuilds_a_tag_with_the_wrong_environment_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    write_uv_project(project)
    built = False
    final_digest = "d" * 64
    environment_digest = expected_environment_digest(project)

    def fake_docker(*args: str, cwd: Path | None = None, timeout: int = 30) -> str:
        nonlocal built
        del cwd, timeout
        if args[:2] == ("image", "inspect"):
            return json.dumps(
                {
                    "RepoDigests": [f"opencode-guard/dispatch-hub@sha256:{final_digest}"],
                    "Config": {
                        "Labels": {
                            "org.opencode-guard.environment-digest": (
                                environment_digest if built else "0" * 64
                            )
                        }
                    },
                }
            )
        if args[:1] == ("build",):
            built = True
            return "built"
        if args[:1] == ("run",):
            return "Python 3.13\nuv 0.11.28"
        raise AssertionError(args)

    monkeypatch.setattr("opencode_guardian.environment._docker", fake_docker)

    environment = prepare_project_environment(project)

    assert built is True
    assert environment.image.endswith(final_digest)


def test_project_environment_rejects_unsupported_python_versions(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write_uv_project(project, requires_python=">=3.12")

    with pytest.raises(GuardError) as caught:
        prepare_project_environment(project)

    assert caught.value.code == "PROJECT_PYTHON_UNSUPPORTED"


def test_project_environment_requires_a_lock_file(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write_uv_project(project)
    (project / "uv.lock").unlink()

    with pytest.raises(GuardError) as caught:
        prepare_project_environment(project)

    assert caught.value.code == "PROJECT_ENVIRONMENT_UNSUPPORTED"
