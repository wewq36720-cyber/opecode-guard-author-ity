from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from graph_checks import (
    check_artifact_reachability,
    check_package_contracts,
    check_system_lifecycle,
    run_graph_negative_probes,
)
from model import (
    canonical_bytes,
    load_contract_inputs,
    parse_json_bytes,
    scope_snapshot,
    sha256_bytes,
    validate_json_schema,
)
from registry_checks import check_registry, run_registry_negative_probe
from schema_checks import check_schema_documents, run_schema_negative_probes

PROTOCOL_VERSION = "isolated-validator.v1"
VALIDATOR_VERSION = "1.5.3"
EXPECTED_LIMITS = {
    "snapshot_files": 128,
    "snapshot_file_bytes": 8 * 1024 * 1024,
    "snapshot_total_bytes": 64 * 1024 * 1024,
    "request_bytes": 256 * 1024,
    "worker_output_bytes": 1024 * 1024,
    "worker_timeout_seconds": 180,
}
_INTERNAL_MODULES = {
    "graph_checks",
    "isolated_worker",
    "model",
    "registry_checks",
    "schema_checks",
}


def _run_check(
    check_id: str,
    function: Callable[[], list[str]],
    checks: list[dict[str, Any]],
) -> list[str]:
    errors = function()
    checks.append(
        {
            "check_id": check_id,
            "status": "OK" if not errors else "ERROR",
            "error_count": len(errors),
        }
    )
    return [f"{check_id} {error}" for error in errors]


def _schema_errors(data: dict[str, Any]) -> list[str]:
    schemas = data["schemas"]
    errors = check_schema_documents(schemas, data["registry"])
    package_schema = schemas["skill-contract.v3.schema.json"]
    for package in data["packages"]:
        package_id = package.get("skill", {}).get("id", "unknown")
        errors.extend(
            f"{package_id} {error}" for error in validate_json_schema(package, package_schema)
        )
    errors.extend(
        f"system {error}"
        for error in validate_json_schema(
            data["system"], schemas["system-lifecycle.v1.schema.json"]
        )
    )
    errors.extend(
        f"registry {error}"
        for error in validate_json_schema(
            data["registry_index"], schemas["guard-registry.v1.schema.json"]
        )
    )
    component_schema = schemas["guard-registry-component.v1.schema.json"]
    for component in data["registry_components"]:
        errors.extend(
            f"registry.{component.get('kind', 'unknown')} {error}"
            for error in validate_json_schema(component, component_schema)
        )
    return errors


def _isolation_errors(
    request: dict[str, Any],
    data: dict[str, Any],
    mirror: Path,
) -> list[str]:
    errors: list[str] = []
    required_flags = {
        "isolated": 1,
        "ignore_environment": 1,
        "no_site": 1,
        "no_user_site": 1,
        "safe_path": True,
    }
    for name, expected in required_flags.items():
        if getattr(sys.flags, name) != expected:
            errors.append(f"ISOLATED_PYTHON_FLAG {name}")
    if data["input_digest"] != request["input_digest"]:
        errors.append("ISOLATED_INPUT_DIGEST_MISMATCH")
    if request.get("limits") != EXPECTED_LIMITS:
        errors.append("ISOLATED_LIMITS_MISMATCH")
    for name in sorted(_INTERNAL_MODULES):
        module = sys.modules.get(name)
        module_path = getattr(module, "__file__", None)
        if module_path is None:
            errors.append(f"ISOLATED_MODULE_MISSING {name}")
            continue
        try:
            Path(module_path).resolve().relative_to(mirror)
        except ValueError:
            errors.append(f"ISOLATED_MODULE_PATH {name}")
    return errors


def validate(
    request: dict[str, Any],
    snapshots: dict[str, bytes],
    mirror: Path,
) -> tuple[dict[str, Any], int]:
    def snapshot_reader(path: Path) -> bytes:
        try:
            return snapshots[str(path.resolve())]
        except KeyError as error:
            raise ValueError(f"snapshot path was not frozen: {path}") from error

    data = load_contract_inputs(mirror, reader=snapshot_reader)
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    errors.extend(_run_check("schema", lambda: _schema_errors(data), checks))
    errors.extend(
        _run_check(
            "registry",
            lambda: check_registry(
                data["packages"],
                data["system"],
                data["registry"],
                mirror,
                data["schemas"],
                data["input_file_digests"],
            ),
            checks,
        )
    )
    errors.extend(
        _run_check(
            "package_routes",
            lambda: check_package_contracts(data["packages"], data["registry"]),
            checks,
        )
    )
    errors.extend(
        _run_check(
            "artifact_reachability",
            lambda: check_artifact_reachability(data["packages"]),
            checks,
        )
    )
    errors.extend(
        _run_check(
            "system_lifecycle",
            lambda: check_system_lifecycle(data["packages"], data["system"], data["registry"]),
            checks,
        )
    )
    errors.extend(
        _run_check(
            "negative_probes",
            lambda: (
                run_graph_negative_probes(data["packages"], data["system"], data["registry"])
                + run_registry_negative_probe(
                    data["packages"],
                    data["system"],
                    data["registry"],
                    mirror,
                    data["schemas"],
                    data["input_file_digests"],
                )
                + run_schema_negative_probes(data["schemas"], data["registry"], data["system"])
                + _isolation_errors(request, data, mirror)
            ),
            checks,
        )
    )

    scope_evidence: dict[str, Any] | None = None
    scope_root = request.get("scope_root")
    scope_before = request.get("scope_before")
    if scope_root is not None and scope_before is not None:
        before_path = mirror / scope_before
        before = parse_json_bytes(snapshot_reader(before_path), before_path)
        after = scope_snapshot(Path(scope_root))
        matches = (
            before.get("file_count") == after["file_count"]
            and before.get("aggregate_sha256") == after["aggregate_sha256"]
        )
        scope_evidence = {"before": before, "after": after, "matches": matches}
        scope_errors = [] if matches else ["FORBIDDEN_SCOPE_CHANGED"]
        errors.extend(_run_check("forbidden_scope", lambda: scope_errors, checks))

    semantic_result: dict[str, Any] = {
        "schema_version": "contract-validation-report.v1",
        "validator_version": VALIDATOR_VERSION,
        "correlation_id": data["input_digest"][:16],
        "input_files": data["input_files"],
        "input_digest": data["input_digest"],
        "checks": checks,
        "status": "OK" if not errors else "ERROR",
        "errors": sorted(errors),
        "scope_evidence": scope_evidence,
    }
    return semantic_result, 0 if not errors else 1


def main(request: dict[str, Any], snapshots: dict[str, bytes], mirror: Path) -> int:
    semantic_result, exit_code = validate(request, snapshots, mirror)
    response = {
        "protocol": PROTOCOL_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "request_digest": request["request_digest"],
        "semantic_result": semantic_result,
        "semantic_result_digest": sha256_bytes(canonical_bytes(semantic_result)),
        "exit_code": exit_code,
    }
    sys.stdout.buffer.write(canonical_bytes(response) + b"\n")
    sys.stdout.buffer.flush()
    return exit_code
