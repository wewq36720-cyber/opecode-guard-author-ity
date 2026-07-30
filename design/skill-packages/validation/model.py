from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMA_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "allOf",
    "const",
    "enum",
    "items",
    "minItems",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, path: Path) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError(f"top-level JSON must be an object: {path}")
    return value


def load_json_snapshot(
    path: Path,
    *,
    reader: Callable[[Path], bytes] | None = None,
) -> tuple[dict[str, Any], str]:
    raw = (reader or Path.read_bytes)(path)
    return parse_json_bytes(raw, path), sha256_bytes(raw)


def load_json(path: Path) -> dict[str, Any]:
    return load_json_snapshot(path)[0]


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_artifact_schema_uri(schema_id: str) -> str:
    if re.fullmatch(r"[a-z][a-z0-9_.-]*", schema_id) is None:
        raise ValueError(f"invalid artifact schema id: {schema_id}")
    return f"https://opencode.local/artifact-schemas/{schema_id}"


def load_contract_inputs(
    root: Path,
    *,
    reader: Callable[[Path], bytes] | None = None,
) -> dict[str, Any]:
    read_bytes = reader or Path.read_bytes
    contract_dir = root / "contracts"
    package_paths = sorted(
        (
            path
            for path in contract_dir.glob("*.contract.json")
            if path.name != "system-lifecycle.contract.json"
        ),
        key=lambda path: path.name,
    )
    schema_paths = sorted((root / "schemas").glob("*.schema.json"))
    validator_paths = sorted((root / "validation").glob("*.py"))
    if len(package_paths) != 6:
        raise ValueError(f"expected 6 package contracts, found {len(package_paths)}")

    registry_index_path = contract_dir / "guard-registry.json"
    registry_index_raw = read_bytes(registry_index_path)
    registry_index = parse_json_bytes(registry_index_raw, registry_index_path)
    component_paths = [
        contract_dir / component["path"] for component in registry_index["components"]
    ]
    if any(path.parent != contract_dir / "registries" for path in component_paths):
        raise ValueError("registry component escaped contracts/registries")
    files = [
        *package_paths,
        contract_dir / "system-lifecycle.contract.json",
        registry_index_path,
        *component_paths,
        *schema_paths,
        *validator_paths,
    ]
    missing = [str(path) for path in files if not path.is_file()]
    if missing:
        raise ValueError(f"missing contract inputs: {missing}")

    snapshots = {
        path: registry_index_raw if path == registry_index_path else read_bytes(path)
        for path in files
    }
    relative_digests = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_bytes(snapshots[path]),
        }
        for path in sorted(files, key=lambda item: item.as_posix().lower())
    ]
    input_file_digests = {entry["path"]: entry["sha256"] for entry in relative_digests}
    registry_components = [parse_json_bytes(snapshots[path], path) for path in component_paths]
    expected_kinds = {component["kind"] for component in registry_index["components"]}
    actual_kinds = {component["kind"] for component in registry_components}
    if expected_kinds != actual_kinds or len(actual_kinds) != len(registry_components):
        raise ValueError("registry component kinds do not match index")
    registry = {
        "schema_version": registry_index["schema_version"],
        "registry_id": registry_index["registry_id"],
        "version": registry_index["version"],
    }
    for component in registry_components:
        registry[component["kind"]] = component["entries"]

    return {
        "packages": [parse_json_bytes(snapshots[path], path) for path in package_paths],
        "system": parse_json_bytes(
            snapshots[contract_dir / "system-lifecycle.contract.json"],
            contract_dir / "system-lifecycle.contract.json",
        ),
        "registry_index": registry_index,
        "registry_components": registry_components,
        "registry": registry,
        "schemas": {path.name: parse_json_bytes(snapshots[path], path) for path in schema_paths},
        "input_files": relative_digests,
        "input_file_digests": input_file_digests,
        "input_digest": sha256_bytes(canonical_bytes(relative_digests)),
        "validator_sources": {path.resolve(): snapshots[path] for path in validator_paths},
    }


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def resolve_local_ref(root_schema: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"only local JSON Pointer refs are supported: {reference}")
    current: Any = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"unresolved local schema ref: {reference}")
        current = current[part]
    if not isinstance(current, dict):
        raise ValueError(f"schema ref does not resolve to an object: {reference}")
    return current


def check_schema_keywords(schema: dict[str, Any], path: str = "$") -> list[str]:
    errors = [
        f"SCHEMA_KEYWORD_UNSUPPORTED {path}.{key}"
        for key in sorted(set(schema) - SUPPORTED_SCHEMA_KEYWORDS)
    ]
    for container_key in ("$defs", "properties"):
        container = schema.get(container_key, {})
        if isinstance(container, dict):
            for key, child in container.items():
                if isinstance(child, dict):
                    errors.extend(check_schema_keywords(child, f"{path}.{container_key}.{key}"))
    items = schema.get("items")
    if isinstance(items, dict):
        errors.extend(check_schema_keywords(items, f"{path}.items"))
    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        errors.extend(check_schema_keywords(additional, f"{path}.additionalProperties"))
    for combinator in ("allOf", "oneOf"):
        children = schema.get(combinator, [])
        if isinstance(children, list):
            for index, child in enumerate(children):
                if isinstance(child, dict):
                    errors.extend(check_schema_keywords(child, f"{path}.{combinator}[{index}]"))
    return errors


def validate_json_schema(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
    *,
    root_schema: dict[str, Any] | None = None,
    ref_stack: tuple[str, ...] = (),
) -> list[str]:
    """Validate every JSON Schema keyword admitted by this design."""
    root = root_schema or schema
    errors: list[str] = []
    unsupported = sorted(set(schema) - SUPPORTED_SCHEMA_KEYWORDS)
    if unsupported:
        return [f"SCHEMA_KEYWORD_UNSUPPORTED {path}.{key}" for key in unsupported]
    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str):
            return [f"SCHEMA_REF_TYPE {path}"]
        if reference in ref_stack:
            return [f"SCHEMA_REF_CYCLE {path}:{reference}"]
        try:
            target = resolve_local_ref(root, reference)
        except ValueError as error:
            return [f"SCHEMA_REF {path}: {error}"]
        errors.extend(
            validate_json_schema(
                value,
                target,
                path,
                root_schema=root,
                ref_stack=(*ref_stack, reference),
            )
        )
    expected_type = schema.get("type")
    if expected_type and not _matches_type(value, expected_type):
        return [f"SCHEMA_TYPE {path}: expected {expected_type}"]
    for child in schema.get("allOf", []):
        errors.extend(
            validate_json_schema(
                value,
                child,
                path,
                root_schema=root,
                ref_stack=ref_stack,
            )
        )
    one_of = schema.get("oneOf")
    if one_of is not None:
        matches = sum(
            not validate_json_schema(
                value,
                child,
                path,
                root_schema=root,
                ref_stack=ref_stack,
            )
            for child in one_of
        )
        if matches != 1:
            errors.append(f"SCHEMA_ONE_OF {path}: matches={matches}")
    if "const" in schema and value != schema["const"]:
        errors.append(f"SCHEMA_CONST {path}: expected {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"SCHEMA_ENUM {path}: {value!r} not allowed")
    if (
        isinstance(value, str)
        and "pattern" in schema
        and re.search(schema["pattern"], value) is None
    ):
        errors.append(f"SCHEMA_PATTERN {path}: {value!r}")
    if isinstance(value, list):
        minimum = schema.get("minItems")
        if minimum is not None and len(value) < minimum:
            errors.append(f"SCHEMA_MIN_ITEMS {path}: {len(value)} < {minimum}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(
                    validate_json_schema(
                        item,
                        item_schema,
                        f"{path}[{index}]",
                        root_schema=root,
                        ref_stack=ref_stack,
                    )
                )
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"SCHEMA_REQUIRED {path}.{key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"SCHEMA_UNKNOWN {path}.{key}")
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, dict):
                errors.extend(
                    validate_json_schema(
                        value[key],
                        child_schema,
                        f"{path}.{key}",
                        root_schema=root,
                        ref_stack=ref_stack,
                    )
                )
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            for key in set(value) - set(properties):
                errors.extend(
                    validate_json_schema(
                        value[key],
                        additional,
                        f"{path}.{key}",
                        root_schema=root,
                        ref_stack=ref_stack,
                    )
                )
    return errors


def scope_snapshot(root: Path) -> dict[str, Any]:
    entries: list[dict[str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        parts = relative.split("/")
        if relative.startswith(".codex/protocol/current/"):
            continue
        if relative.startswith("design/skill-packages/"):
            continue
        if relative == "tests/unit/test_contract_validator_isolation.py":
            continue
        if relative.startswith(".git/"):
            continue
        if parts[0] in {".pytest_cache", ".mypy_cache", ".ruff_cache"}:
            continue
        if "__pycache__" in parts:
            continue
        entries.append({"path": relative, "sha256": sha256_file(path)})
    entries.sort(key=lambda entry: entry["path"].lower())
    lines = "\n".join(f"{entry['path']}\t{entry['sha256']}" for entry in entries)
    return {
        "schema_version": "scope-evidence.v1",
        "root": str(root.resolve()),
        "exclusions": [
            ".codex/protocol/current/**",
            "design/skill-packages/**",
            "tests/unit/test_contract_validator_isolation.py",
            ".git/**",
            "tool caches",
            "__pycache__",
        ],
        "file_count": len(entries),
        "aggregate_sha256": sha256_bytes(lines.encode("utf-8")),
    }
