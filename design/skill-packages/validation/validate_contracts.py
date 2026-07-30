from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import ModuleType
from typing import Any

PROTOCOL_VERSION = "isolated-validator.v1"
VALIDATOR_VERSION = "1.5.3"
MAX_WORKER_OUTPUT_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 256 * 1024
MAX_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_FILES = 128
WORKER_TIMEOUT_SECONDS = 180
_RESPONSE_FIELDS = {
    "protocol",
    "validator_version",
    "request_digest",
    "semantic_result",
    "semantic_result_digest",
    "exit_code",
}
_BASE_CHECK_IDS = (
    "schema",
    "registry",
    "package_routes",
    "artifact_reachability",
    "system_lifecycle",
    "negative_probes",
)
_SCOPE_FIELDS = {"before", "after", "matches"}
_SCOPE_SNAPSHOT_FIELDS = {
    "schema_version",
    "root",
    "exclusions",
    "file_count",
    "aggregate_sha256",
}
_POLLUTED_MODULE_NAMES = (
    "graph_checks",
    "isolated_worker",
    "model",
    "registry_checks",
    "schema_checks",
)
_BOOTSTRAP = r"""
import hashlib
import importlib.abc
import importlib.util
import json
import pathlib
import sys

mirror = pathlib.Path(sys.argv[1]).resolve()
request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
snapshots = {}
sources = {}
for entry in request["snapshot_files"]:
    relative = pathlib.PurePosixPath(entry["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("unsafe snapshot path")
    path = (mirror / pathlib.Path(*relative.parts)).resolve()
    path.relative_to(mirror)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise ValueError(f"snapshot digest mismatch: {relative}")
    snapshots[str(path)] = raw
    if (
        len(relative.parts) == 2
        and relative.parts[0] == "validation"
        and relative.suffix == ".py"
        and relative.name != "validate_contracts.py"
    ):
        sources[relative.stem] = (path, raw)

class SnapshotLoader(importlib.abc.Loader):
    def __init__(self, path, raw):
        self.path = path
        self.raw = raw

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = str(self.path)
        code = compile(self.raw, str(self.path), "exec", dont_inherit=True)
        exec(code, module.__dict__)

class SnapshotFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        source = sources.get(fullname)
        if source is None:
            return None
        source_path, raw = source
        return importlib.util.spec_from_loader(
            fullname,
            SnapshotLoader(source_path, raw),
            origin=str(source_path),
        )

sys.meta_path.insert(0, SnapshotFinder())
import isolated_worker
raise SystemExit(isolated_worker.main(request, snapshots, mirror))
""".strip()


class IsolationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IsolationError("WORKER_RESPONSE_INVALID", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_object(raw: bytes, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IsolationError(code, "worker protocol was not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise IsolationError(code, "worker protocol root must be an object")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve(strict=True).relative_to(root).as_posix()
    except ValueError as error:
        raise IsolationError(
            "SNAPSHOT_PATH_INVALID", f"path is outside validation root: {path}"
        ) from error


def _read_snapshot_file(path: Path, relative: str) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_SNAPSHOT_FILE_BYTES + 1)
    except OSError as error:
        raise IsolationError("SNAPSHOT_READ_FAILED", relative) from error
    if len(raw) > MAX_SNAPSHOT_FILE_BYTES:
        raise IsolationError("SNAPSHOT_TOO_LARGE", relative)
    return raw


def _store_snapshot(snapshots: dict[str, bytes], relative: str, raw: bytes) -> None:
    if len(snapshots) >= MAX_SNAPSHOT_FILES:
        raise IsolationError("SNAPSHOT_TOO_LARGE", "snapshot file count exceeded limit")
    if sum(map(len, snapshots.values())) + len(raw) > MAX_SNAPSHOT_TOTAL_BYTES:
        raise IsolationError("SNAPSHOT_TOO_LARGE", "snapshot byte limit exceeded")
    snapshots[relative] = raw


def _snapshot_inputs(root: Path) -> tuple[dict[str, bytes], list[dict[str, str]], str]:
    contract_dir = root / "contracts"
    package_paths = sorted(
        (
            path
            for path in contract_dir.glob("*.contract.json")
            if path.name != "system-lifecycle.contract.json"
        ),
        key=lambda path: path.name,
    )
    if len(package_paths) != 6:
        raise IsolationError(
            "SNAPSHOT_INPUT_INVALID",
            f"expected 6 package contracts, found {len(package_paths)}",
        )
    registry_index_path = contract_dir / "guard-registry.json"
    registry_index_raw = _read_snapshot_file(
        registry_index_path, registry_index_path.relative_to(root).as_posix()
    )
    registry_index = _parse_object(registry_index_raw, code="SNAPSHOT_INPUT_INVALID")
    try:
        component_paths = [contract_dir / item["path"] for item in registry_index["components"]]
    except (KeyError, TypeError) as error:
        raise IsolationError(
            "SNAPSHOT_INPUT_INVALID", "invalid registry component index"
        ) from error
    expected_component_root = (contract_dir / "registries").resolve()
    if any(path.resolve().parent != expected_component_root for path in component_paths):
        raise IsolationError(
            "SNAPSHOT_PATH_INVALID", "registry component escaped contracts/registries"
        )
    files = [
        *package_paths,
        contract_dir / "system-lifecycle.contract.json",
        registry_index_path,
        *component_paths,
        *sorted((root / "schemas").glob("*.schema.json")),
        *sorted((root / "validation").glob("*.py")),
    ]
    if len(set(files)) != len(files):
        raise IsolationError("SNAPSHOT_INPUT_INVALID", "duplicate snapshot path")
    missing = [str(path) for path in files if not path.is_file()]
    if missing:
        raise IsolationError("SNAPSHOT_INPUT_INVALID", f"missing inputs: {missing}")
    snapshots: dict[str, bytes] = {}
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path == registry_index_path:
            raw = registry_index_raw
        else:
            raw = _read_snapshot_file(path, relative)
        _store_snapshot(snapshots, relative, raw)
    entries = [
        {"path": relative, "sha256": _sha256(raw)}
        for relative, raw in sorted(snapshots.items(), key=lambda item: item[0].lower())
    ]
    return snapshots, entries, _sha256(_canonical_bytes(entries))


def _minimal_environment() -> dict[str, str]:
    allowed = {"COMSPEC", "PATH", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _write_mirror(mirror: Path, snapshots: dict[str, bytes]) -> None:
    for relative, raw in snapshots.items():
        path = mirror / Path(*Path(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        if _sha256(path.read_bytes()) != _sha256(raw):
            raise IsolationError("SNAPSHOT_MIRROR_MISMATCH", relative)


def _validate_snapshot_capacity(snapshots: dict[str, bytes]) -> None:
    if len(snapshots) > MAX_SNAPSHOT_FILES:
        raise IsolationError("SNAPSHOT_TOO_LARGE", "snapshot file count exceeded limit")
    total = 0
    for relative, raw in snapshots.items():
        if len(raw) > MAX_SNAPSHOT_FILE_BYTES:
            raise IsolationError("SNAPSHOT_TOO_LARGE", relative)
        total += len(raw)
    if total > MAX_SNAPSHOT_TOTAL_BYTES:
        raise IsolationError("SNAPSHOT_TOO_LARGE", "snapshot byte limit exceeded")


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _assert_external_mirror(mirror: Path) -> None:
    try:
        mirror.relative_to(_repository_root())
    except ValueError:
        return
    raise IsolationError("SNAPSHOT_MIRROR_SCOPE", "temporary mirror is inside repository")


def _set_mirror_read_only(mirror: Path) -> None:
    paths = sorted(mirror.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        if path.is_file() or os.name != "nt":
            path.chmod(stat.S_IREAD | (stat.S_IEXEC if path.is_dir() else 0))
    if os.name != "nt":
        mirror.chmod(stat.S_IREAD | stat.S_IEXEC)
    for path in paths:
        if path.is_file() and stat.S_IMODE(path.stat().st_mode) & (
            stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        ):
            raise IsolationError("SNAPSHOT_MIRROR_NOT_READ_ONLY", str(path))


def _restore_mirror_permissions(mirror: Path) -> None:
    mirror.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    for path in sorted(mirror.rglob("*"), key=lambda item: len(item.parts)):
        path.chmod(stat.S_IREAD | stat.S_IWRITE | (stat.S_IEXEC if path.is_dir() else 0))


def _read_limited(stream: Any, output: bytearray, overflow: threading.Event) -> None:
    while not overflow.is_set():
        chunk = stream.read(64 * 1024)
        if not chunk:
            return
        if len(output) + len(chunk) > MAX_WORKER_OUTPUT_BYTES:
            overflow.set()
            return
        output.extend(chunk)


def _write_input(stream: Any, request_bytes: bytes) -> None:
    try:
        stream.write(request_bytes)
        stream.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _terminate_worker(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(OSError):
        process.kill()
    process.wait()


_SEMANTIC_FIELDS = {
    "schema_version",
    "validator_version",
    "correlation_id",
    "input_files",
    "input_digest",
    "checks",
    "status",
    "errors",
    "scope_evidence",
}
_CHECK_FIELDS = {"check_id", "status", "error_count"}


def _expected_check_ids(
    semantic_result: dict[str, Any], request: dict[str, Any]
) -> tuple[str, ...]:
    scope_root = request.get("scope_root")
    scope_before = request.get("scope_before")
    scope_evidence = semantic_result["scope_evidence"]
    if scope_root is None and scope_before is None:
        if scope_evidence is not None:
            raise IsolationError("WORKER_RESPONSE_INVALID", "unscoped response has scope evidence")
        return _BASE_CHECK_IDS
    if (
        not isinstance(scope_root, str)
        or not scope_root
        or not isinstance(scope_before, str)
        or not scope_before
    ):
        raise IsolationError("WORKER_RESPONSE_INVALID", "scope request fields are incomplete")
    if not isinstance(scope_evidence, dict) or set(scope_evidence) != _SCOPE_FIELDS:
        raise IsolationError("WORKER_RESPONSE_INVALID", "scoped response evidence is invalid")
    before = scope_evidence["before"]
    after = scope_evidence["after"]
    matches = scope_evidence["matches"]
    if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(matches, bool):
        raise IsolationError(
            "WORKER_RESPONSE_INVALID", "scoped response evidence values are invalid"
        )
    for snapshot in (before, after):
        if (
            set(snapshot) != _SCOPE_SNAPSHOT_FIELDS
            or snapshot.get("schema_version") != "scope-evidence.v1"
            or snapshot.get("root") != scope_root
            or not isinstance(snapshot.get("exclusions"), list)
            or not all(isinstance(item, str) for item in snapshot["exclusions"])
            or not isinstance(snapshot.get("file_count"), int)
            or isinstance(snapshot["file_count"], bool)
            or snapshot["file_count"] < 0
            or not isinstance(snapshot.get("aggregate_sha256"), str)
            or len(snapshot["aggregate_sha256"]) != 64
            or any(
                character not in "0123456789abcdef" for character in snapshot["aggregate_sha256"]
            )
        ):
            raise IsolationError("WORKER_RESPONSE_INVALID", "scope snapshot is invalid")
    if request.get("scope_before_digest") != _sha256(_canonical_bytes(before)):
        raise IsolationError("WORKER_DIGEST_MISMATCH", "scope baseline digest mismatch")
    before_count = before["file_count"]
    after_count = after["file_count"]
    before_digest = before["aggregate_sha256"]
    after_digest = after["aggregate_sha256"]
    if matches != (before_count == after_count and before_digest == after_digest):
        raise IsolationError("WORKER_RESPONSE_INVALID", "scoped response evidence disagrees")
    return (*_BASE_CHECK_IDS, "forbidden_scope")


def _validate_semantic_result(
    semantic_result: Any,
    request: dict[str, Any],
    process_exit_code: int,
    response_exit_code: Any,
) -> dict[str, Any]:
    if not isinstance(semantic_result, dict) or set(semantic_result) != _SEMANTIC_FIELDS:
        raise IsolationError("WORKER_RESPONSE_INVALID", "semantic result fields are invalid")
    status = semantic_result["status"]
    errors = semantic_result["errors"]
    checks = semantic_result["checks"]
    expected_check_ids = _expected_check_ids(semantic_result, request)
    if (
        semantic_result["schema_version"] != "contract-validation-report.v1"
        or semantic_result["validator_version"] != VALIDATOR_VERSION
        or semantic_result["correlation_id"] != request["input_digest"][:16]
    ):
        raise IsolationError("WORKER_RESPONSE_INVALID", "semantic identity is invalid")
    if (
        status not in {"OK", "ERROR"}
        or not isinstance(errors, list)
        or not all(isinstance(error, str) for error in errors)
    ):
        raise IsolationError("WORKER_RESPONSE_INVALID", "semantic status or errors are invalid")
    if not isinstance(checks, list) or not checks:
        raise IsolationError("WORKER_RESPONSE_INVALID", "semantic checks are invalid")
    check_ids: list[str] = []
    check_errors = 0
    for check in checks:
        if not isinstance(check, dict) or set(check) != _CHECK_FIELDS:
            raise IsolationError("WORKER_RESPONSE_INVALID", "semantic check fields are invalid")
        check_id = check["check_id"]
        error_count = check["error_count"]
        if (
            not isinstance(check_id, str)
            or check_id in check_ids
            or check["status"] not in {"OK", "ERROR"}
            or not isinstance(error_count, int)
            or isinstance(error_count, bool)
            or error_count < 0
            or (check["status"] == "OK") != (error_count == 0)
        ):
            raise IsolationError("WORKER_RESPONSE_INVALID", "semantic check values are invalid")
        check_ids.append(check_id)
        check_errors += error_count
    if tuple(check_ids) != expected_check_ids:
        raise IsolationError("WORKER_RESPONSE_INVALID", "semantic checks are incomplete")
    if len(expected_check_ids) == 7:
        expected_scope_errors = 0 if semantic_result["scope_evidence"]["matches"] else 1
        if checks[-1]["error_count"] != expected_scope_errors:
            raise IsolationError("WORKER_RESPONSE_INVALID", "scope evidence and check disagree")
    if (
        check_errors != len(errors)
        or (status == "OK") != (not errors)
        or (status == "OK") != (check_errors == 0)
    ):
        raise IsolationError("WORKER_RESPONSE_INVALID", "semantic status and errors disagree")
    expected_exit = 0 if status == "OK" else 1
    if process_exit_code != expected_exit or response_exit_code != process_exit_code:
        raise IsolationError("WORKER_EXIT_INVALID", "semantic status and exit code disagree")
    if semantic_result["input_digest"] != request["input_digest"]:
        raise IsolationError("WORKER_DIGEST_MISMATCH", "worker input digest mismatch")
    return semantic_result


def _validate_worker_response(
    response: dict[str, Any], request: dict[str, Any], process_exit_code: int
) -> dict[str, Any]:
    if set(response) != _RESPONSE_FIELDS:
        raise IsolationError("WORKER_RESPONSE_INVALID", "worker response fields are invalid")
    if response.get("protocol") != PROTOCOL_VERSION:
        raise IsolationError("WORKER_PROTOCOL_MISMATCH", "worker protocol version mismatch")
    if response.get("validator_version") != VALIDATOR_VERSION:
        raise IsolationError("WORKER_PROTOCOL_MISMATCH", "worker validator version mismatch")
    if response.get("request_digest") != request["request_digest"]:
        raise IsolationError("WORKER_DIGEST_MISMATCH", "worker request digest mismatch")
    semantic_result = response.get("semantic_result")
    semantic_digest = _sha256(_canonical_bytes(semantic_result))
    if response.get("semantic_result_digest") != semantic_digest:
        raise IsolationError("WORKER_DIGEST_MISMATCH", "semantic result digest mismatch")
    return _validate_semantic_result(
        semantic_result, request, process_exit_code, response.get("exit_code")
    )


def _run_worker(request: dict[str, Any], mirror: Path) -> tuple[dict[str, Any], int]:
    executable_value = sys.executable
    if not executable_value:
        raise IsolationError("PYTHON_EXECUTABLE_INVALID", "sys.executable is empty")
    executable = Path(executable_value)
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        raise IsolationError("PYTHON_EXECUTABLE_INVALID", str(executable))
    request_bytes = _canonical_bytes(request)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise IsolationError("WORKER_REQUEST_TOO_LARGE", "worker request exceeded limit")
    try:
        process = subprocess.Popen(
            [str(executable), "-X", "utf8", "-I", "-S", "-c", _BOOTSTRAP, str(mirror)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=mirror,
            env=_minimal_environment(),
            shell=False,
        )
    except OSError as error:
        raise IsolationError("WORKER_START_FAILED", str(error)) from error
    deadline = time.monotonic() + WORKER_TIMEOUT_SECONDS
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    threads = [
        threading.Thread(target=_write_input, args=(process.stdin, request_bytes)),
        threading.Thread(target=_read_limited, args=(process.stdout, stdout, overflow)),
        threading.Thread(target=_read_limited, args=(process.stderr, stderr, overflow)),
    ]
    for thread in threads:
        thread.start()
    try:
        timed_out = False
        while True:
            if overflow.is_set():
                _terminate_worker(process)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_worker(process)
                break
            if process.poll() is not None:
                break
            time.sleep(0.01)
        return_code = process.wait()
    finally:
        for thread in threads:
            thread.join()
    if timed_out:
        raise IsolationError("WORKER_TIMEOUT", "isolated validator timed out")
    if overflow.is_set():
        raise IsolationError("WORKER_OUTPUT_TOO_LARGE", "isolated validator output exceeded limit")
    if stderr:
        raise IsolationError(
            "WORKER_STDERR",
            bytes(stderr).decode("utf-8", errors="replace").strip(),
        )
    if return_code not in (0, 1):
        raise IsolationError("WORKER_EXIT_INVALID", f"worker exit code: {return_code}")
    response = _parse_object(bytes(stdout), code="WORKER_RESPONSE_INVALID")
    return _validate_worker_response(response, request, return_code), return_code


def _run_parent_pollution_probe(
    request: dict[str, Any],
    mirror: Path,
    expected_result: dict[str, Any],
    expected_exit_code: int,
) -> None:
    missing = object()
    original_modules = {name: sys.modules.get(name, missing) for name in _POLLUTED_MODULE_NAMES}
    original_meta_path = list(sys.meta_path)
    original_sys_path = list(sys.path)
    python_environment = {
        key: value for key, value in os.environ.items() if key.upper().startswith("PYTHON")
    }
    with tempfile.TemporaryDirectory(prefix="opencode-validator-poison-") as temporary:
        poison = Path(temporary).resolve()
        (poison / "sitecustomize.py").write_text(
            "raise RuntimeError('sitecustomize must not load')\n",
            encoding="utf-8",
        )
        sys.path.insert(0, str(poison))
        os.environ["PYTHONHOME"] = str(poison)
        os.environ["PYTHONPATH"] = str(poison)

        class PoisonImportHook:
            validator_pollution_probe = True

            def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
                if fullname in _POLLUTED_MODULE_NAMES:
                    raise RuntimeError(f"parent import hook intercepted {fullname}")
                return None

        def poisoned_function() -> str:
            return "parent-function-monkeypatch"

        class PoisonedClass:
            marker = "parent-class-monkeypatch"

        sys.meta_path.insert(0, PoisonImportHook())
        for name in _POLLUTED_MODULE_NAMES:
            fake = ModuleType(name)
            fake.__file__ = str(poison / f"{name}.py")
            fake.validate = poisoned_function
            fake.Path = PoisonedClass
            sys.modules[name] = fake
        try:
            actual_result, actual_exit_code = _run_worker(request, mirror)
        finally:
            sys.meta_path[:] = original_meta_path
            sys.path[:] = original_sys_path
            for key in [key for key in os.environ if key.upper().startswith("PYTHON")]:
                del os.environ[key]
            os.environ.update(python_environment)
            for name, original in original_modules.items():
                if original is missing:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = original
    if actual_exit_code != expected_exit_code or actual_result != expected_result:
        raise IsolationError(
            "PARENT_POLLUTION_NOT_ISOLATED",
            "parent modules, import path, or Python environment changed worker result",
        )


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def validate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    root = args.root.resolve(strict=True)
    snapshots, input_files, input_digest = _snapshot_inputs(root)
    _validate_snapshot_capacity(snapshots)
    scope_before_relative: str | None = None
    scope_before_digest: str | None = None
    if args.scope_before is not None:
        scope_before = args.scope_before.resolve(strict=True)
        scope_before_relative = _safe_relative(scope_before, root)
        if scope_before_relative not in snapshots:
            _store_snapshot(
                snapshots,
                scope_before_relative,
                _read_snapshot_file(scope_before, scope_before_relative),
            )
        scope_before_value = _parse_object(
            snapshots[scope_before_relative], code="SNAPSHOT_INPUT_INVALID"
        )
        scope_before_digest = _sha256(_canonical_bytes(scope_before_value))
    _validate_snapshot_capacity(snapshots)
    snapshot_files = [
        {"path": relative, "sha256": _sha256(raw)}
        for relative, raw in sorted(snapshots.items(), key=lambda item: item[0].lower())
    ]
    request_body: dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "snapshot_files": snapshot_files,
        "input_digest": input_digest,
        "limits": {
            "snapshot_files": MAX_SNAPSHOT_FILES,
            "snapshot_file_bytes": MAX_SNAPSHOT_FILE_BYTES,
            "snapshot_total_bytes": MAX_SNAPSHOT_TOTAL_BYTES,
            "request_bytes": MAX_REQUEST_BYTES,
            "worker_output_bytes": MAX_WORKER_OUTPUT_BYTES,
            "worker_timeout_seconds": WORKER_TIMEOUT_SECONDS,
        },
        "scope_root": str(args.scope_root.resolve(strict=True)) if args.scope_root else None,
        "scope_before": scope_before_relative,
        "scope_before_digest": scope_before_digest,
    }
    request = dict(request_body)
    request["request_digest"] = _sha256(_canonical_bytes(request_body))
    with tempfile.TemporaryDirectory(prefix="opencode-validator-") as temporary:
        mirror = Path(temporary).resolve()
        _assert_external_mirror(mirror)
        _write_mirror(mirror, snapshots)
        _set_mirror_read_only(mirror)
        try:
            semantic_result, exit_code = _run_worker(request, mirror)
            _run_parent_pollution_probe(request, mirror, semantic_result, exit_code)
        finally:
            _restore_mirror_permissions(mirror)
    if semantic_result.get("input_files") != input_files:
        raise IsolationError("WORKER_DIGEST_MISMATCH", "worker input file manifest mismatch")
    semantic_result_digest = _sha256(_canonical_bytes(semantic_result))
    report_body: dict[str, Any] = {
        **semantic_result,
        "validator_command": [sys.executable, *sys.argv],
        "semantic_result_digest": semantic_result_digest,
        "semantic_result_digest_definition": (
            "sha256(canonical JSON of schema_version, validator_version, correlation_id, "
            "input_files, input_digest, checks, status, errors, and scope_evidence)"
        ),
        "report_digest_definition": (
            "sha256(canonical JSON of the full report excluding report_digest); "
            "this includes validator_command and may vary across equivalent commands"
        ),
    }
    report = dict(report_body)
    report["report_digest"] = _sha256(_canonical_bytes(report_body))
    if args.report:
        _write_report(args.report.resolve(), report)
    return report, exit_code


def parser() -> argparse.ArgumentParser:
    default_root = Path(__file__).resolve().parent.parent
    result = argparse.ArgumentParser(description="Validate six-skill v3.3 contracts")
    result.add_argument("--root", type=Path, default=default_root)
    result.add_argument("--report", type=Path)
    result.add_argument("--scope-root", type=Path)
    result.add_argument("--scope-before", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        report, exit_code = validate(args)
    except IsolationError as error:
        print(
            json.dumps(
                {"status": "ERROR", "code": error.code, "fatal": str(error)},
                ensure_ascii=False,
            )
        )
        return 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "ERROR", "code": "VALIDATOR_FATAL", "fatal": str(error)}))
        return 2
    print(
        json.dumps(
            {
                "status": report["status"],
                "validator_version": report["validator_version"],
                "checks": report["checks"],
                "error_count": len(report["errors"]),
                "input_digest": report["input_digest"],
                "semantic_result_digest": report["semantic_result_digest"],
                "report_digest": report["report_digest"],
            },
            ensure_ascii=False,
        )
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
