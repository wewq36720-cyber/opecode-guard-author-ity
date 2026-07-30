from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import GuardError
from .integrity import digest_bytes, digest_json

PYTHON_BASE_IMAGES = {
    "3.13": (
        "docker.m.daocloud.io/library/python@sha256:"
        "6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91"
    )
}
UV_IMAGE = (
    "ghcr.m.daocloud.io/astral-sh/uv@sha256:"
    "0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa"
)
BUILDER_VERSION = 5
_PYTHON_VERSION_RE = re.compile(r"(?:>=|==|~=)\s*(3\.\d+)")
_PROJECT_NAME_RE = re.compile(r"[^a-z0-9_.-]+")


@dataclass(frozen=True, slots=True)
class ProjectEnvironment:
    digest: str
    image: str
    python_version: str
    checks: tuple[dict[str, Any], ...]


def prepare_project_environment(project_root: Path) -> ProjectEnvironment:
    root = project_root.resolve(strict=True)
    pyproject_path = root / "pyproject.toml"
    lock_path = root / "uv.lock"
    if not pyproject_path.is_file() or not lock_path.is_file():
        raise GuardError(
            "PROJECT_ENVIRONMENT_UNSUPPORTED",
            "Guarded Python projects require committed pyproject.toml and uv.lock files.",
        )
    try:
        pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise GuardError(
            "PROJECT_ENVIRONMENT_INVALID",
            "pyproject.toml could not be parsed as UTF-8 TOML.",
        ) from exc
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise GuardError("PROJECT_ENVIRONMENT_INVALID", "pyproject.toml needs [project].")
    name = project.get("name")
    requires_python = project.get("requires-python")
    if not isinstance(name, str) or not name.strip() or not isinstance(requires_python, str):
        raise GuardError(
            "PROJECT_ENVIRONMENT_INVALID",
            "Project name and requires-python are required.",
        )
    match = _PYTHON_VERSION_RE.search(requires_python)
    python_version = match.group(1) if match else ""
    base_image = PYTHON_BASE_IMAGES.get(python_version)
    if not base_image:
        raise GuardError(
            "PROJECT_PYTHON_UNSUPPORTED",
            "No trusted Python base image is registered for the project requirement.",
            requires_python=requires_python,
            supported=sorted(PYTHON_BASE_IMAGES),
        )
    environment_digest = digest_json(
        {
            "builder_version": BUILDER_VERSION,
            "base_image": base_image,
            "uv_image": UV_IMAGE,
            "pyproject": digest_bytes(pyproject_path.read_bytes()),
            "uv_lock": digest_bytes(lock_path.read_bytes()),
        }
    )
    repository = "opencode-guard/" + _project_slug(name)
    tag = f"{repository}:{environment_digest[:16]}"
    image = _cached_image(tag, repository, environment_digest)
    if not image:
        _ensure_image(base_image)
        _ensure_image(UV_IMAGE)
        with tempfile.TemporaryDirectory(prefix="opencode-guard-environment-") as temporary:
            context = Path(temporary)
            shutil.copy2(pyproject_path, context / "pyproject.toml")
            shutil.copy2(lock_path, context / "uv.lock")
            (context / "Dockerfile").write_text(
                _dockerfile(base_image=base_image, uv_image=UV_IMAGE),
                encoding="utf-8",
            )
            _docker(
                "build",
                "--pull=false",
                "--network",
                "default",
                "--label",
                f"org.opencode-guard.environment-digest={environment_digest}",
                "--tag",
                tag,
                ".",
                cwd=context,
                timeout=1_800,
            )
        image = _cached_image(tag, repository, environment_digest)
        if not image:
            raise GuardError(
                "PROJECT_ENVIRONMENT_BUILD_FAILED",
                "The built project image did not expose a local repository digest.",
                tag=tag,
            )
    _probe_environment(image, python_version)
    return ProjectEnvironment(
        digest=environment_digest,
        image=image,
        python_version=python_version,
        checks=tuple(_checks(image)),
    )


def _project_slug(name: str) -> str:
    slug = _PROJECT_NAME_RE.sub("-", name.strip().lower()).strip("-.")
    if not slug:
        raise GuardError("PROJECT_ENVIRONMENT_INVALID", "Project name cannot form an image name.")
    return slug[:100]


def _cached_image(tag: str, repository: str, environment_digest: str) -> str:
    try:
        raw = _docker("image", "inspect", tag, "--format", "{{json .}}")
    except GuardError:
        return ""
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GuardError(
            "PROJECT_ENVIRONMENT_INVALID",
            "Docker returned invalid project image metadata.",
        ) from exc
    if not isinstance(metadata, dict):
        return ""
    digests = metadata.get("RepoDigests")
    config = metadata.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(digests, list)
        or not isinstance(labels, dict)
        or labels.get("org.opencode-guard.environment-digest") != environment_digest
    ):
        return ""
    digest_pattern = re.compile(rf"{re.escape(repository)}@sha256:[0-9a-f]{{64}}")
    return next(
        (item for item in digests if isinstance(item, str) and digest_pattern.fullmatch(item)),
        "",
    )


def _ensure_image(image: str) -> None:
    try:
        _docker("image", "inspect", image, "--format", "{{.Id}}")
        return
    except GuardError:
        pass
    _docker("pull", image, timeout=600)
    _docker("image", "inspect", image, "--format", "{{.Id}}")


def _probe_environment(image: str, python_version: str) -> None:
    output = _docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--user",
        "65532:65532",
        image,
        "sh",
        "-c",
        "python -V && uv --version",
        timeout=60,
    )
    if f"Python {python_version}" not in output or "uv " not in output:
        raise GuardError(
            "PROJECT_ENVIRONMENT_INVALID",
            "The project image does not provide the required Python and uv tools.",
            image=image,
        )


def _checks(image: str) -> list[dict[str, Any]]:
    commands = (
        (
            "sync",
            ["uv", "sync", "--frozen", "--offline", "--no-install-project", "--extra", "dev"],
            180,
        ),
        ("lint", ["uv", "run", "--frozen", "--offline", "--no-sync", "ruff", "check", "."], 120),
        (
            "format",
            ["uv", "run", "--frozen", "--offline", "--no-sync", "ruff", "format", "--check", "."],
            120,
        ),
        (
            "typecheck",
            [
                "uv",
                "run",
                "--frozen",
                "--offline",
                "--no-sync",
                "mypy",
                "--cache-dir=/tmp/mypy",
                "src",
            ],
            240,
        ),
        (
            "pytest",
            ["uv", "run", "--frozen", "--offline", "--no-sync", "pytest", "-p", "no:cacheprovider"],
            300,
        ),
        (
            "smoke",
            ["uv", "run", "--frozen", "--offline", "--no-sync", "python", "scripts/smoke.py"],
            240,
        ),
        (
            "build",
            [
                "sh",
                "-c",
                (
                    '/opt/build-venv/bin/python -c "import shutil; '
                    "shutil.copytree('/workspace', '/tmp/build-src', "
                    "ignore=shutil.ignore_patterns('.git', '.venv', '.mypy_cache', "
                    "'.pytest_cache', '.ruff_cache', 'dist', 'build', '*.egg-info', "
                    "'__pycache__'))\" && cd /tmp/build-src && "
                    "/opt/build-venv/bin/python -m build --no-isolation --outdir /tmp/dist"
                ),
            ],
            240,
        ),
    )
    return [
        {
            "id": check_id,
            "image": image,
            "argv": argv,
            "timeout_seconds": timeout,
            "required": True,
            "writable_tmpfs": [],
        }
        for check_id, argv, timeout in commands
    ]


def _dockerfile(*, base_image: str, uv_image: str) -> str:
    return f"""FROM {uv_image} AS uv
FROM {base_image}
COPY --from=uv /uv /uvx /bin/
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \\
    UV_CACHE_DIR=/tmp/uv-cache \\
    VIRTUAL_ENV=/opt/venv \\
    PATH=/opt/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \\
    PYTHONPATH=/workspace/src \\
    RUFF_CACHE_DIR=/tmp/ruff
WORKDIR /opt/project
COPY pyproject.toml uv.lock ./
RUN UV_CACHE_DIR=/opt/uv-cache uv sync --frozen --no-install-project --extra dev \\
    && uv venv /opt/build-venv \\
    && UV_CACHE_DIR=/opt/uv-cache uv pip install --python /opt/build-venv/bin/python \\
        build "setuptools>=75" wheel \\
    && chmod -R a+rX /opt/venv /opt/build-venv /opt/uv-cache
WORKDIR /workspace
"""


def _docker(*args: str, cwd: Path | None = None, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["docker", *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise GuardError("DOCKER_UNAVAILABLE", "Docker environment command failed.") from exc
    if result.returncode != 0:
        raise GuardError(
            "DOCKER_COMMAND_FAILED",
            "Docker environment command returned an error.",
            operation=args[0] if args else "unknown",
            stderr=result.stderr[-4_000:],
        )
    return result.stdout.strip()
