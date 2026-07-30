from __future__ import annotations

import copy
import importlib.util
import sys
import time
from pathlib import Path

import pytest

VALIDATOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "design"
    / "skill-packages"
    / "validation"
    / "validate_contracts.py"
)
REPOSITORY_ROOT = VALIDATOR_PATH.parents[3]


@pytest.fixture
def validator():
    spec = importlib.util.spec_from_file_location("p29_validator_test_module", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(*, scoped: bool = False) -> dict[str, object]:
    request: dict[str, object] = {
        "request_digest": "request",
        "input_digest": "input",
        "scope_root": None,
        "scope_before": None,
        "scope_before_digest": None,
    }
    if scoped:
        request.update({"scope_root": "repository", "scope_before": "before.json"})
    return request


def _expect_error(module, code: str, callback) -> None:
    with pytest.raises(module.IsolationError) as caught:
        callback()
    assert caught.value.code == code


def _semantic(module, *, scoped: bool = False) -> dict[str, object]:
    check_ids = list(module._BASE_CHECK_IDS)
    scope_evidence = None
    if scoped:
        check_ids.append("forbidden_scope")
        snapshot = {
            "schema_version": "scope-evidence.v1",
            "root": "repository",
            "exclusions": [],
            "file_count": 1,
            "aggregate_sha256": "0" * 64,
        }
        scope_evidence = {"before": snapshot, "after": copy.deepcopy(snapshot), "matches": True}
    return {
        "schema_version": "contract-validation-report.v1",
        "validator_version": module.VALIDATOR_VERSION,
        "correlation_id": "input",
        "input_files": [],
        "input_digest": "input",
        "checks": [
            {"check_id": check_id, "status": "OK", "error_count": 0} for check_id in check_ids
        ],
        "status": "OK",
        "errors": [],
        "scope_evidence": scope_evidence,
    }


def _response(module) -> dict[str, object]:
    semantic = _semantic(module)
    return {
        "protocol": module.PROTOCOL_VERSION,
        "validator_version": module.VALIDATOR_VERSION,
        "request_digest": "request",
        "semantic_result": semantic,
        "semantic_result_digest": module._sha256(module._canonical_bytes(semantic)),
        "exit_code": 0,
    }


def test_semantic_status_errors_and_exit_are_bound(validator) -> None:
    semantic = _semantic(validator)
    semantic["errors"] = ["forged"]
    _expect_error(
        validator,
        "WORKER_RESPONSE_INVALID",
        lambda: validator._validate_semantic_result(semantic, _request(), 0, 0),
    )


def test_response_protocol_and_digest_matrix(validator) -> None:
    _expect_error(
        validator,
        "WORKER_RESPONSE_INVALID",
        lambda: validator._parse_object(
            b'{"status":"OK","status":"ERROR"}', code="WORKER_RESPONSE_INVALID"
        ),
    )
    mutations = [
        ("WORKER_RESPONSE_INVALID", lambda value: value.__setitem__("unknown", True)),
        ("WORKER_PROTOCOL_MISMATCH", lambda value: value.__setitem__("protocol", "wrong")),
        ("WORKER_DIGEST_MISMATCH", lambda value: value.__setitem__("request_digest", "wrong")),
        (
            "WORKER_DIGEST_MISMATCH",
            lambda value: value.__setitem__("semantic_result_digest", "0" * 64),
        ),
        ("WORKER_EXIT_INVALID", lambda value: value.__setitem__("exit_code", 1)),
    ]
    for code, mutate in mutations:
        response = copy.deepcopy(_response(validator))
        mutate(response)
        _expect_error(
            validator,
            code,
            lambda response=response: validator._validate_worker_response(response, _request(), 0),
        )


def test_response_requires_complete_checks_and_bound_scope(validator) -> None:
    scoped_request = _request(scoped=True)
    complete = _semantic(validator, scoped=True)
    scoped_request["scope_before_digest"] = validator._sha256(
        validator._canonical_bytes(complete["scope_evidence"]["before"])
    )
    assert validator._validate_semantic_result(complete, scoped_request, 0, 0) == complete

    mutations = [
        lambda value: value["checks"].pop(),
        lambda value: value.__setitem__("scope_evidence", None),
        lambda value: value["checks"].reverse(),
        lambda value: value["scope_evidence"]["after"].__setitem__("root", "wrong"),
        lambda value: value["scope_evidence"]["before"].__setitem__("unknown", True),
        lambda value: value["scope_evidence"]["after"].__setitem__("unknown", True),
    ]
    for mutate in mutations:
        semantic = copy.deepcopy(complete)
        mutate(semantic)
        _expect_error(
            validator,
            "WORKER_RESPONSE_INVALID",
            lambda semantic=semantic: validator._validate_semantic_result(
                semantic, scoped_request, 0, 0
            ),
        )

    unscoped = _semantic(validator)
    unscoped["scope_evidence"] = complete["scope_evidence"]
    _expect_error(
        validator,
        "WORKER_RESPONSE_INVALID",
        lambda: validator._validate_semantic_result(unscoped, _request(), 0, 0),
    )
    partial_request = _request()
    partial_request["scope_root"] = "repository"
    _expect_error(
        validator,
        "WORKER_RESPONSE_INVALID",
        lambda: validator._validate_semantic_result(_semantic(validator), partial_request, 0, 0),
    )
    wrong_baseline = copy.deepcopy(complete)
    scoped_request["scope_before_digest"] = "0" * 64
    _expect_error(
        validator,
        "WORKER_DIGEST_MISMATCH",
        lambda: validator._validate_semantic_result(wrong_baseline, scoped_request, 0, 0),
    )


def test_mirror_must_be_external_and_read_only(validator, tmp_path: Path) -> None:
    _expect_error(
        validator,
        "SNAPSHOT_MIRROR_SCOPE",
        lambda: validator._assert_external_mirror(REPOSITORY_ROOT),
    )
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    payload = mirror / "payload"
    payload.write_bytes(b"snapshot")
    try:
        validator._set_mirror_read_only(mirror)
        assert payload.stat().st_mode & 0o222 == 0
        if sys.platform != "win32":
            assert mirror.stat().st_mode & 0o222 == 0
    finally:
        validator._restore_mirror_permissions(mirror)


def test_snapshot_and_request_limits_fail_closed(validator, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(validator, "MAX_SNAPSHOT_FILE_BYTES", 3)
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"1234")
    _expect_error(
        validator,
        "SNAPSHOT_TOO_LARGE",
        lambda: validator._read_snapshot_file(oversized, "oversized"),
    )
    _expect_error(
        validator,
        "SNAPSHOT_TOO_LARGE",
        lambda: validator._validate_snapshot_capacity({"input": b"1234"}),
    )
    monkeypatch.setattr(validator, "MAX_REQUEST_BYTES", 1)
    _expect_error(
        validator,
        "WORKER_REQUEST_TOO_LARGE",
        lambda: validator._run_worker(_request(), tmp_path),
    )


def test_worker_failure_matrix_is_persistent(validator, tmp_path: Path, monkeypatch) -> None:
    request = _request()
    executable = sys.executable
    monkeypatch.setattr(validator.sys, "executable", "")
    _expect_error(
        validator,
        "PYTHON_EXECUTABLE_INVALID",
        lambda: validator._run_worker(request, tmp_path),
    )
    monkeypatch.setattr(validator.sys, "executable", executable)

    monkeypatch.setattr(validator, "_BOOTSTRAP", "import time; time.sleep(2)")
    monkeypatch.setattr(validator, "WORKER_TIMEOUT_SECONDS", 0.05)
    large_request = {**request, "padding": "x" * (128 * 1024)}
    started = time.monotonic()
    _expect_error(
        validator,
        "WORKER_TIMEOUT",
        lambda: validator._run_worker(large_request, tmp_path),
    )
    assert time.monotonic() - started < 1
    monkeypatch.setattr(validator, "WORKER_TIMEOUT_SECONDS", 180)

    monkeypatch.setattr(
        validator,
        "_BOOTSTRAP",
        "import sys; sys.stdout.buffer.write(b'x' * 1024); sys.stdout.flush()",
    )
    monkeypatch.setattr(validator, "MAX_WORKER_OUTPUT_BYTES", 128)
    _expect_error(
        validator,
        "WORKER_OUTPUT_TOO_LARGE",
        lambda: validator._run_worker(request, tmp_path),
    )

    monkeypatch.setattr(validator, "_BOOTSTRAP", "print('not-json')")
    monkeypatch.setattr(validator, "MAX_WORKER_OUTPUT_BYTES", 1024 * 1024)
    _expect_error(
        validator,
        "WORKER_RESPONSE_INVALID",
        lambda: validator._run_worker(request, tmp_path),
    )

    monkeypatch.setattr(validator, "_BOOTSTRAP", "raise RuntimeError('crash')")
    _expect_error(validator, "WORKER_STDERR", lambda: validator._run_worker(request, tmp_path))


def test_worker_forces_utf8_protocol_without_environment_inheritance(
    validator, tmp_path: Path, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def reject(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        raise OSError("expected worker start failure")

    monkeypatch.setattr(validator.subprocess, "Popen", reject)
    _expect_error(
        validator,
        "WORKER_START_FAILED",
        lambda: validator._run_worker(_request(), tmp_path),
    )

    command = captured["command"]
    assert isinstance(command, list)
    assert command[1:5] == ["-X", "utf8", "-I", "-S"]
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert "PYTHONUTF8" not in environment


def test_mirrored_source_tampering_fails_closed(validator, monkeypatch) -> None:
    original_write = validator._write_mirror

    def tamper(mirror, snapshots):
        original_write(mirror, snapshots)
        target = mirror / "validation" / "model.py"
        target.write_bytes(target.read_bytes() + b"\n# tampered\n")

    monkeypatch.setattr(validator, "_write_mirror", tamper)
    args = validator.parser().parse_args(["--root", "design/skill-packages"])
    _expect_error(validator, "WORKER_STDERR", lambda: validator.validate(args))


def test_parent_pollution_probe_injects_declared_matrix(
    validator, tmp_path: Path, monkeypatch
) -> None:
    observed: dict[str, bool] = {}

    def inspect_parent_state(request, mirror):
        modules = [sys.modules[name] for name in validator._POLLUTED_MODULE_NAMES]
        observed.update(
            {
                "sys_modules": all(
                    module.__name__ == name
                    for name, module in zip(validator._POLLUTED_MODULE_NAMES, modules, strict=True)
                ),
                "function": all(
                    module.validate() == "parent-function-monkeypatch" for module in modules
                ),
                "class": all(
                    module.Path.marker == "parent-class-monkeypatch" for module in modules
                ),
                "import_hook": any(
                    getattr(hook, "validator_pollution_probe", False) for hook in sys.meta_path
                ),
                "python_environment": "PYTHONHOME" in validator.os.environ
                and "PYTHONPATH" in validator.os.environ,
                "site": any((Path(entry) / "sitecustomize.py").is_file() for entry in sys.path),
            }
        )
        return {"clean": True}, 0

    monkeypatch.setattr(validator, "_run_worker", inspect_parent_state)
    validator._run_parent_pollution_probe(_request(), tmp_path, {"clean": True}, 0)
    assert observed and all(observed.values())


def test_baseline_runs_parent_pollution_probe(validator, monkeypatch) -> None:
    original_probe = validator._run_parent_pollution_probe
    calls = 0

    def tracking_probe(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_probe(*args, **kwargs)

    monkeypatch.setattr(validator, "_run_parent_pollution_probe", tracking_probe)
    args = validator.parser().parse_args(["--root", "design/skill-packages"])
    report, exit_code = validator.validate(args)
    assert exit_code == 0
    assert report["status"] == "OK"
    assert calls == 1
