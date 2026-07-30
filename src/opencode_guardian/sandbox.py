from __future__ import annotations

import re
import subprocess
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import Any

from .errors import GuardError
from .integrity import digest_json

_IMAGE_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]+")
SAFE_ENV = {
    "CI": "1",
    "HOME": "/tmp/home",
    "NO_COLOR": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TMPDIR": "/tmp",
}


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    cpus: float = 1.0
    memory_mb: int = 1024
    pids: int = 128
    tmp_mb: int = 256

    def validate(self) -> None:
        if not 0.1 <= self.cpus <= 8:
            raise GuardError("INVALID_LIMIT", "Sandbox CPUs must be between 0.1 and 8.")
        if not 128 <= self.memory_mb <= 16_384:
            raise GuardError("INVALID_LIMIT", "Sandbox memory must be between 128 and 16384 MiB.")
        if not 16 <= self.pids <= 1_024:
            raise GuardError("INVALID_LIMIT", "Sandbox PID limit must be between 16 and 1024.")
        if not 16 <= self.tmp_mb <= 4_096:
            raise GuardError("INVALID_LIMIT", "Sandbox tmpfs must be between 16 and 4096 MiB.")


@dataclass(frozen=True, slots=True)
class SandboxResult:
    exit_code: int
    timed_out: bool
    duration_ms: int
    output: str
    output_digest: str
    output_bytes: int
    output_truncated: bool
    command_digest: str
    image_digest: str


class DockerSandbox:
    def __init__(
        self,
        *,
        docker: str = "docker",
        limits: SandboxLimits | None = None,
        output_limit: int = 100_000,
    ) -> None:
        self.docker = docker
        self.limits = limits or SandboxLimits()
        self.limits.validate()
        if not 1_024 <= output_limit <= 1_000_000:
            raise GuardError("INVALID_OUTPUT_LIMIT", "Output limit must be 1 KiB to 1 MiB.")
        self.output_limit = output_limit

    def assert_available(self, image: str | None = None) -> str:
        version = self._docker_control("info", "--format", "{{.ServerVersion}}")
        if not version.strip():
            raise GuardError("DOCKER_UNAVAILABLE", "Docker server did not report a version.")
        if image:
            self._validate_image(image)
            self._docker_control("image", "inspect", image, "--format", "{{.Id}}")
        return version.strip()

    def assert_images_available(self, images: list[str]) -> str:
        unique = list(dict.fromkeys(images))
        version = self.assert_available()
        if not unique:
            return version
        for image in unique:
            self._validate_image(image)
        self._docker_control("image", "inspect", "--format", "{{.Id}}", *unique)
        return version

    def build_command(
        self,
        *,
        worktree: Path,
        run_id: str,
        check: Mapping[str, Any],
    ) -> tuple[list[str], str, str]:
        worktree = worktree.resolve(strict=True)
        if "," in str(worktree):
            raise GuardError("UNSUPPORTED_MOUNT_PATH", "Docker bind source cannot contain a comma.")
        check_id = _required_text(check, "id", maximum=64)
        image = _required_text(check, "image", maximum=500)
        self._validate_image(image)
        argv = _string_list(check, "argv", maximum_items=64, item_maximum=4_096)
        timeout = _required_int(check, "timeout_seconds", minimum=1, maximum=3_600)
        writable_tmpfs = _relative_tmpfs(check.get("writable_tmpfs", []))
        name = _container_name(run_id, check_id)
        command = [
            self.docker,
            "run",
            "--rm",
            "--name",
            name,
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(self.limits.pids),
            "--memory",
            f"{self.limits.memory_mb}m",
            "--cpus",
            str(self.limits.cpus),
            "--user",
            "65532:65532",
            "--mount",
            f"type=bind,src={worktree},dst=/workspace,readonly",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={self.limits.tmp_mb * 1024 * 1024}",
            "--workdir",
            "/workspace",
        ]
        for key, value in sorted(SAFE_ENV.items()):
            command.extend(("--env", f"{key}={value}"))
        for relative in writable_tmpfs:
            tmpfs_option = (
                f"/workspace/{relative}:rw,nosuid,nodev,size={self.limits.tmp_mb * 1024 * 1024}"
            )
            command.extend(
                (
                    "--tmpfs",
                    tmpfs_option,
                )
            )
        command.extend((image, *argv))
        semantic = {
            "image": image,
            "argv": argv,
            "timeout_seconds": timeout,
            "writable_tmpfs": writable_tmpfs,
            "limits": {
                "cpus": self.limits.cpus,
                "memory_mb": self.limits.memory_mb,
                "pids": self.limits.pids,
                "tmp_mb": self.limits.tmp_mb,
            },
            "environment": SAFE_ENV,
        }
        return command, name, digest_json(semantic)

    def run(
        self,
        *,
        worktree: Path,
        run_id: str,
        check: Mapping[str, Any],
    ) -> SandboxResult:
        image = _required_text(check, "image", maximum=500)
        self.assert_available(image)
        command, container_name, command_digest = self.build_command(
            worktree=worktree,
            run_id=run_id,
            check=check,
        )
        timeout = _required_int(check, "timeout_seconds", minimum=1, maximum=3_600)
        started = monotonic()
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise GuardError("DOCKER_UNAVAILABLE", "Docker executable was not found.") from exc
        output = bytearray()
        output_digest = sha256()
        output_bytes = 0
        stream = process.stdout
        if stream is None:
            process.kill()
            raise GuardError("DOCKER_OUTPUT_UNAVAILABLE", "Docker output pipe was not created.")

        def drain() -> None:
            nonlocal output_bytes
            for chunk in iter(lambda: stream.read(65_536), b""):
                output_bytes += len(chunk)
                output_digest.update(chunk)
                remaining = self.output_limit - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])

        reader = threading.Thread(target=drain, name=f"guard-output-{container_name}", daemon=True)
        reader.start()
        timed_out = False
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._remove_container(container_name)
            process.kill()
            exit_code = 124
        finally:
            reader.join(timeout=10)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        return SandboxResult(
            exit_code=exit_code,
            timed_out=timed_out,
            duration_ms=round((monotonic() - started) * 1000),
            output=bytes(output).decode("utf-8", errors="replace"),
            output_digest=output_digest.hexdigest(),
            output_bytes=output_bytes,
            output_truncated=output_bytes > self.output_limit,
            command_digest=command_digest,
            image_digest=image,
        )

    def _docker_control(self, *args: str) -> str:
        try:
            result = subprocess.run(
                [self.docker, *args],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                shell=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise GuardError("DOCKER_UNAVAILABLE", "Docker control command failed.") from exc
        if result.returncode != 0:
            raise GuardError(
                "DOCKER_UNAVAILABLE",
                "Docker control command returned an error.",
                operation=args[0] if args else "unknown",
                stderr=result.stderr[-4_000:],
            )
        return result.stdout

    def _remove_container(self, name: str) -> None:
        subprocess.run(
            [self.docker, "rm", "-f", name],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            shell=False,
        )

    @staticmethod
    def _validate_image(image: str) -> None:
        if not _IMAGE_DIGEST_RE.fullmatch(image):
            raise GuardError("UNPINNED_IMAGE", "Docker image must be pinned by sha256 digest.")


def _container_name(run_id: str, check_id: str) -> str:
    normalized = _NAME_RE.sub("-", f"guard-{run_id}-{check_id}").strip("-.").lower()
    if not normalized:
        raise GuardError("INVALID_CONTAINER_NAME", "Run/check IDs cannot form a container name.")
    return normalized[:120]


def _relative_tmpfs(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 16:
        raise GuardError("INVALID_TMPFS", "writable_tmpfs must be a list up to 16 paths.")
    result = []
    for raw in value:
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 500:
            raise GuardError("INVALID_TMPFS", "tmpfs paths must be bounded text.")
        normalized = raw.replace("\\", "/").strip("/")
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise GuardError("INVALID_TMPFS", f"Unsafe tmpfs path: {raw}")
        result.append(path.as_posix())
    return list(dict.fromkeys(result))


def _required_text(value: Mapping[str, Any], field: str, *, maximum: int) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item or "\x00" in item or len(item) > maximum:
        raise GuardError("INVALID_CHECK", f"{field} must be bounded non-empty text.")
    return item


def _string_list(
    value: Mapping[str, Any], field: str, *, maximum_items: int, item_maximum: int
) -> list[str]:
    items = value.get(field)
    if (
        not isinstance(items, list)
        or not items
        or len(items) > maximum_items
        or not all(
            isinstance(item, str) and item and "\x00" not in item and len(item) <= item_maximum
            for item in items
        )
    ):
        raise GuardError("INVALID_CHECK", f"{field} contains invalid arguments.")
    return items


def _required_int(value: Mapping[str, Any], field: str, *, minimum: int, maximum: int) -> int:
    item = value.get(field)
    if not isinstance(item, int) or isinstance(item, bool) or not minimum <= item <= maximum:
        raise GuardError("INVALID_CHECK", f"{field} must be between {minimum} and {maximum}.")
    return item
