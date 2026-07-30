from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, cast

from .errors import GuardError
from .integrity import digest_json

MAX_PACKET_BYTES = 512 * 1024
MAX_ITEMS = 256
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_GLOB_MARKERS = frozenset("*?[")
_UNRESOLVED_TERMS = (
    "暂定",
    "待定",
    "不知道",
    "未检查",
    "待确认",
    "后续处理",
    "视情况",
    "可能",
    "大概",
    "tbd",
    "todo",
    "unknown",
    "not checked",
    "相关文件",
    "必要文件",
    "其他文件",
    "尚未确认",
    "后续确认",
    "不确定",
    "或许",
    "maybe",
    "perhaps",
    "to be checked",
)
_PLAN_PATH_FIELDS = frozenset({"required_paths", "allowed_paths"})
_PLANNING_ARTIFACT_KINDS = frozenset({"BASELINE", "SPEC", "PLAN"})
_APPROVAL_SOURCES = frozenset({"ci", "independent-review", "user"})
_HEX_40_TO_64_RE = re.compile(r"^[0-9a-f]{40,64}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_PLANNING_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{1,63}$")


class Stage(StrEnum):
    PLANNING = "PLANNING"
    IMPLEMENTING = "IMPLEMENTING"
    VERIFYING = "VERIFYING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ACCEPTED = "ACCEPTED"


class PlanningStep(StrEnum):
    BASELINE_DRAFT = "BASELINE_DRAFT"
    BASELINE_REVIEW_REQUIRED = "BASELINE_REVIEW_REQUIRED"
    SPEC_DRAFT = "SPEC_DRAFT"
    SPEC_REVIEW_REQUIRED = "SPEC_REVIEW_REQUIRED"
    PLAN_DRAFT = "PLAN_DRAFT"
    PLAN_REVIEW_REQUIRED = "PLAN_REVIEW_REQUIRED"
    PLAN_APPROVED = "PLAN_APPROVED"
    COMPATIBILITY_READ_ONLY = "COMPATIBILITY_READ_ONLY"


class ReviewGate(StrEnum):
    BASELINE = "BASELINE"
    SPEC = "SPEC"
    PLAN = "PLAN"
    FINAL = "FINAL"


@dataclass(frozen=True, slots=True)
class RunRecord:
    run_id: str
    project_root: Path
    git_common_dir: Path
    worktree: Path
    base_sha: str
    stage: Stage
    revision: int
    session_id: str
    task: str
    packet_digest: str
    environment_digest: str
    workspace_digest: str
    evidence_digest: str
    active_phase: str
    blocked_code: str
    blocked_message: str
    event_count: int
    event_head: str
    created_at: str
    updated_at: str


def validate_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise GuardError("INVALID_ID", f"{field} must be a stable identifier.")
    return value


def validate_task(value: Any) -> str:
    return _text(value, "task", maximum=20_000)


def normalize_packet(
    value: Any,
    *,
    available_checks: set[str],
    require_certainty: bool = True,
) -> dict[str, Any]:
    packet = _object(value, "packet")
    certainty = _certainty(packet.get("certainty"), required=require_certainty)
    expected_fields = {
        "requirements",
        "acceptance",
        "constraints",
        "non_goals",
        "stop_conditions",
        "architecture",
        "phases",
    }
    if require_certainty or "certainty" in packet:
        expected_fields.add("certainty")
    _exact_keys(
        packet,
        expected_fields,
        "packet",
    )
    if len(json.dumps(packet, ensure_ascii=False).encode("utf-8")) > MAX_PACKET_BYTES:
        raise GuardError("PACKET_TOO_LARGE", "Development packet exceeds 512 KiB.")
    _assert_resolved_plan(packet)

    requirements = _requirements(packet.get("requirements"))
    acceptance = _acceptance(packet.get("acceptance"))
    requirement_ids = set(requirements)
    acceptance_ids = set(acceptance)
    mapped_acceptance = {
        item for requirement in requirements.values() for item in requirement["acceptance_ids"]
    }
    if mapped_acceptance != acceptance_ids:
        raise GuardError(
            "ACCEPTANCE_MAPPING_INVALID",
            "Requirement acceptance_ids must cover every acceptance ID exactly.",
        )

    architecture = _architecture(packet.get("architecture"))
    phases = _phases(
        packet.get("phases"),
        requirements=requirements,
        acceptance=acceptance,
        available_checks=available_checks,
    )
    used_requirements = {item for phase in phases for item in phase["requirement_ids"]}
    used_acceptance = {item for phase in phases for item in phase["acceptance_ids"]}
    if used_requirements != requirement_ids or used_acceptance != acceptance_ids:
        raise GuardError(
            "PHASE_MAPPING_INVALID",
            "Phases must cover every requirement and acceptance ID.",
        )
    _require_path_coverage(phases, acceptance)
    _require_repair_scope(phases)

    normalized = {
        "requirements": list(requirements.values()),
        "acceptance": list(acceptance.values()),
        "constraints": _text_list(packet.get("constraints"), "constraints"),
        "non_goals": _text_list(packet.get("non_goals"), "non_goals"),
        "stop_conditions": _text_list(packet.get("stop_conditions"), "stop_conditions"),
        "architecture": architecture,
        "phases": phases,
    }
    if certainty is not None:
        normalized["certainty"] = certainty
    return deepcopy(normalized)


def packet_digest(packet: dict[str, Any]) -> str:
    return digest_json(packet)


def normalize_planning_artifact(value: Any) -> dict[str, Any]:
    artifact = _planning_object(value, "planning artifact")
    required = {
        "id",
        "kind",
        "base_sha",
        "workspace_digest",
        "source_digests",
        "evidence_refs",
        "requirement_ids",
        "acceptance_ids",
        "ra_mappings",
        "facts",
        "assumptions",
        "decisions",
        "deviations",
    }
    artifact_id = _planning_id(artifact.get("id"), "planning artifact.id")
    kind = artifact.get("kind")
    if kind not in _PLANNING_ARTIFACT_KINDS:
        _planning_invalid("planning artifact.kind is invalid.")
    if kind == "PLAN":
        required.add("implementation")
    _planning_exact_keys(artifact, required, "planning artifact")
    requirement_ids = _planning_ids(artifact.get("requirement_ids"), "requirement_ids")
    acceptance_ids = _planning_ids(artifact.get("acceptance_ids"), "acceptance_ids")
    mappings = _ra_mappings(artifact.get("ra_mappings"), requirement_ids, acceptance_ids)
    partitions = {
        "facts": _planning_entries(
            artifact.get("facts"), "facts", {"id", "statement", "evidence_ref"}
        ),
        "assumptions": _planning_entries(
            artifact.get("assumptions"), "assumptions", {"id", "statement", "expiry"}
        ),
        "decisions": _planning_entries(
            artifact.get("decisions"), "decisions", {"id", "statement", "evidence_ref"}
        ),
        "deviations": _planning_deviations(artifact.get("deviations")),
    }
    partition_ids = [entry["id"] for entries in partitions.values() for entry in entries]
    if len(set(partition_ids)) != len(partition_ids):
        _planning_invalid("Planning fact partitions must have disjoint IDs.")
    normalized = {
        "id": artifact_id,
        "kind": str(kind),
        "base_sha": _hex(artifact.get("base_sha"), "planning artifact.base_sha", _HEX_40_TO_64_RE),
        "workspace_digest": _hex(
            artifact.get("workspace_digest"), "planning artifact.workspace_digest", _HEX_64_RE
        ),
        "source_digests": _source_digests(artifact.get("source_digests")),
        "evidence_refs": _planning_ids(artifact.get("evidence_refs"), "evidence_refs"),
        "requirement_ids": requirement_ids,
        "acceptance_ids": acceptance_ids,
        "ra_mappings": mappings,
        **partitions,
    }
    if kind == "PLAN":
        normalized["implementation"] = _planning_implementation(artifact.get("implementation"))
    return normalized


def planning_artifact_digest(artifact: dict[str, Any]) -> str:
    return digest_json(normalize_planning_artifact(artifact))


def _planning_implementation(value: Any) -> dict[str, Any]:
    implementation = _planning_object(value, "PLAN implementation")
    _planning_exact_keys(implementation, {"packet", "phases"}, "PLAN implementation")
    packet_value = implementation.get("packet")
    if not isinstance(packet_value, dict):
        _planning_invalid("PLAN implementation packet must be an object.")
    packet_value = cast(dict[str, Any], packet_value)
    raw_phases = packet_value.get("phases")
    if not isinstance(raw_phases, list) or not all(isinstance(item, dict) for item in raw_phases):
        _planning_invalid("PLAN implementation packet phases are invalid.")
    raw_phases = cast(list[dict[str, Any]], raw_phases)
    check_ids = {
        item for phase in raw_phases for item in phase.get("check_ids", []) if isinstance(item, str)
    }
    packet = normalize_packet(packet_value, available_checks=check_ids)
    if implementation.get("phases") != packet["phases"]:
        _planning_invalid("PLAN implementation phases do not match its packet.")
    return {
        "packet": packet,
        "phases": packet["phases"],
    }


def normalize_planning_review_receipt(value: Any) -> dict[str, Any]:
    receipt = _planning_object(value, "planning review receipt")
    required = {
        "review_id",
        "kind",
        "run_id",
        "artifact_id",
        "artifact_kind",
        "artifact_digest",
        "artifact_revision",
        "base_sha",
        "workspace_digest",
        "issued_revision",
        "source",
        "nonce",
        "issued_at",
        "decision",
        "authority_ref",
    }
    _planning_exact_keys(receipt, required, "planning review receipt")
    if (
        receipt.get("kind") != "PLANNING_REVIEW_RECEIPT"
        or receipt.get("artifact_kind") not in {"BASELINE", "SPEC"}
        or receipt.get("source") not in _APPROVAL_SOURCES
        or receipt.get("decision") not in {"ACCEPT", "REQUEST_CHANGES"}
    ):
        _planning_invalid("Planning review receipt authority is invalid.")
    revisions = {name: receipt.get(name) for name in ("artifact_revision", "issued_revision")}
    if any(
        not isinstance(item, int) or isinstance(item, bool) or item < 0
        for item in revisions.values()
    ):
        _planning_invalid("Planning review receipt revision is invalid.")
    issued_at = _planning_text(receipt.get("issued_at"), "issued_at", maximum=64)
    try:
        parsed = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError:
        _planning_invalid("Planning review receipt issued_at is invalid.")
    if parsed.tzinfo is None:
        _planning_invalid("Planning review receipt issued_at is invalid.")
    return {
        "review_id": _planning_id(receipt.get("review_id"), "review_id"),
        "kind": "PLANNING_REVIEW_RECEIPT",
        "run_id": _run_id(receipt.get("run_id")),
        "artifact_id": _planning_id(receipt.get("artifact_id"), "artifact_id"),
        "artifact_kind": str(receipt["artifact_kind"]),
        "artifact_digest": _hex(receipt.get("artifact_digest"), "artifact_digest", _HEX_64_RE),
        "artifact_revision": revisions["artifact_revision"],
        "base_sha": _hex(receipt.get("base_sha"), "base_sha", _HEX_40_TO_64_RE),
        "workspace_digest": _hex(receipt.get("workspace_digest"), "workspace_digest", _HEX_64_RE),
        "issued_revision": revisions["issued_revision"],
        "source": str(receipt["source"]),
        "nonce": _hex(receipt.get("nonce"), "nonce", _HEX_64_RE),
        "issued_at": issued_at,
        "decision": str(receipt["decision"]),
        "authority_ref": _planning_text(receipt.get("authority_ref"), "authority_ref", maximum=200),
    }


def normalize_plan_approval_receipt(value: Any) -> dict[str, Any]:
    receipt = _planning_object(value, "plan approval receipt")
    required = {
        "approval_id",
        "kind",
        "run_id",
        "artifact_id",
        "artifact_kind",
        "artifact_digest",
        "base_sha",
        "workspace_digest",
        "revision",
        "source",
        "nonce",
        "issued_at",
        "decision",
        "authority_ref",
    }
    _planning_exact_keys(receipt, required, "plan approval receipt")
    if receipt.get("kind") != "PLAN_APPROVAL_RECEIPT" or receipt.get("artifact_kind") != "PLAN":
        _planning_invalid("Plan approval receipt kind is invalid.")
    if receipt.get("decision") != "APPROVE" or receipt.get("source") not in _APPROVAL_SOURCES:
        _planning_invalid("Plan approval receipt authority is invalid.")
    revision = receipt.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        _planning_invalid("Plan approval receipt revision is invalid.")
    issued_at = _planning_text(receipt.get("issued_at"), "issued_at", maximum=64)
    try:
        parsed = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError:
        _planning_invalid("Plan approval receipt issued_at is invalid.")
    if parsed.tzinfo is None:
        _planning_invalid("Plan approval receipt issued_at is invalid.")
    return {
        "approval_id": _planning_id(receipt.get("approval_id"), "approval_id"),
        "kind": "PLAN_APPROVAL_RECEIPT",
        "run_id": _run_id(receipt.get("run_id")),
        "artifact_id": _planning_id(receipt.get("artifact_id"), "artifact_id"),
        "artifact_kind": "PLAN",
        "artifact_digest": _hex(receipt.get("artifact_digest"), "artifact_digest", _HEX_64_RE),
        "base_sha": _hex(receipt.get("base_sha"), "base_sha", _HEX_40_TO_64_RE),
        "workspace_digest": _hex(receipt.get("workspace_digest"), "workspace_digest", _HEX_64_RE),
        "revision": revision,
        "source": str(receipt["source"]),
        "nonce": _hex(receipt.get("nonce"), "nonce", _HEX_64_RE),
        "issued_at": issued_at,
        "decision": "APPROVE",
        "authority_ref": _planning_text(receipt.get("authority_ref"), "authority_ref", maximum=200),
    }


def _planning_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _planning_invalid(f"{label} must be an object.")
    return cast(dict[str, Any], value)


def _planning_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _planning_invalid(f"{label} fields are not closed.")


def _planning_invalid(message: str) -> None:
    raise GuardError("INVALID_PLANNING_ARTIFACT", message)


def _planning_text(value: Any, label: str, *, maximum: int = 10_000) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > maximum:
        _planning_invalid(f"{label} must be bounded non-empty text.")
    return cast(str, value).strip()


def _planning_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _PLANNING_ID_RE.fullmatch(value) is None:
        _planning_invalid(f"{label} must be an uppercase stable identifier.")
    return cast(str, value)


def _run_id(value: Any) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _planning_invalid("run_id must be a stable identifier.")
    return cast(str, value)


def _planning_ids(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS:
        _planning_invalid(f"{label} must be a non-empty ID list.")
    values = [_planning_id(item, label) for item in value]
    if len(set(values)) != len(values):
        _planning_invalid(f"{label} contains duplicate IDs.")
    return values


def _hex(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _planning_invalid(f"{label} is invalid.")
    return cast(str, value)


def _source_digests(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or not value or len(value) > MAX_ITEMS:
        _planning_invalid("source_digests must be a non-empty object.")
    result: dict[str, str] = {}
    for path, digest in value.items():
        if (
            not isinstance(path, str)
            or not path
            or "\x00" in path
            or path.startswith("/")
            or ".." in Path(path).parts
        ):
            _planning_invalid("source_digests contains an invalid path.")
        result[path] = _hex(digest, "source_digests digest", _HEX_64_RE)
    return {path: result[path] for path in sorted(result)}


def _ra_mappings(
    value: Any, requirements: list[str], acceptance: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(requirements):
        _planning_invalid("ra_mappings must cover each requirement exactly once.")
    mappings: dict[str, list[str]] = {}
    for item in value:
        entry = _planning_object(item, "ra mapping")
        _planning_exact_keys(entry, {"requirement_id", "acceptance_ids"}, "ra mapping")
        requirement_id = _planning_id(entry.get("requirement_id"), "ra mapping requirement_id")
        if requirement_id in mappings:
            _planning_invalid("ra_mappings contains duplicate requirement IDs.")
        mappings[requirement_id] = _planning_ids(
            entry.get("acceptance_ids"), "ra mapping acceptance_ids"
        )
    if set(mappings) != set(requirements) or {
        item for values in mappings.values() for item in values
    } != set(acceptance):
        _planning_invalid("ra_mappings must exactly cover requirements and acceptance IDs.")
    return [
        {"requirement_id": requirement_id, "acceptance_ids": mappings[requirement_id]}
        for requirement_id in requirements
    ]


def _planning_entries(value: Any, label: str, fields: set[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS:
        _planning_invalid(f"{label} must be a non-empty entry list.")
    result: list[dict[str, Any]] = []
    for item in value:
        entry = _planning_object(item, label)
        _planning_exact_keys(entry, fields, label)
        result.append(
            {
                key: _planning_text(entry.get(key), f"{label}.{key}")
                for key in sorted(fields)
                if key != "id"
            }
            | {"id": _planning_id(entry.get("id"), f"{label}.id")}
        )
    if len({entry["id"] for entry in result}) != len(result):
        _planning_invalid(f"{label} contains duplicate IDs.")
    return result


def _planning_deviations(value: Any) -> list[dict[str, Any]]:
    entries = _planning_entries(value, "deviations", {"id", "status", "evidence_ref"})
    if any(entry["status"] not in {"PROVED", "UNPROVED"} for entry in entries):
        _planning_invalid("deviation status is invalid.")
    return entries


def _requirements(value: Any) -> dict[str, dict[str, Any]]:
    items = _object_list(value, "requirements")
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        _exact_keys(item, {"id", "statement", "acceptance_ids"}, "requirement")
        item_id = validate_id(item.get("id"), "requirement.id")
        if item_id in result:
            raise GuardError("DUPLICATE_ID", f"Duplicate requirement ID: {item_id}")
        result[item_id] = {
            "id": item_id,
            "statement": _text(item.get("statement"), "requirement.statement"),
            "acceptance_ids": _id_list(item.get("acceptance_ids"), "acceptance_ids"),
        }
    return result


def _acceptance(value: Any) -> dict[str, dict[str, Any]]:
    items = _object_list(value, "acceptance")
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        _exact_keys(
            item,
            {"id", "criterion", "verification", "required_paths"},
            "acceptance",
        )
        item_id = validate_id(item.get("id"), "acceptance.id")
        if item_id in result:
            raise GuardError("DUPLICATE_ID", f"Duplicate acceptance ID: {item_id}")
        result[item_id] = {
            "id": item_id,
            "criterion": _text(item.get("criterion"), "acceptance.criterion"),
            "verification": _text_list(item.get("verification"), "verification"),
            "required_paths": _paths(
                item.get("required_paths"),
                "acceptance.required_paths",
                allow_glob=True,
            ),
        }
    return result


def _architecture(value: Any) -> dict[str, Any]:
    architecture = _object(value, "architecture")
    _exact_keys(
        architecture,
        {
            "objective",
            "public_interface",
            "dependency_direction",
            "components",
            "trust_boundaries",
            "data_flows",
            "concurrency",
        },
        "architecture",
    )
    components = _object_list(architecture.get("components"), "architecture.components")
    normalized_components: list[dict[str, Any]] = []
    names: set[str] = set()
    for component in components:
        _exact_keys(component, {"name", "responsibility", "dependencies"}, "component")
        name = validate_id(component.get("name"), "component.name")
        if name in names:
            raise GuardError("DUPLICATE_ID", f"Duplicate component name: {name}")
        names.add(name)
        normalized_components.append(
            {
                "name": name,
                "responsibility": _text(
                    component.get("responsibility"),
                    "component.responsibility",
                ),
                "dependencies": _id_list(
                    component.get("dependencies"),
                    "component.dependencies",
                    allow_empty=True,
                ),
            }
        )
    for component in normalized_components:
        unknown = set(component["dependencies"]) - names
        if unknown:
            raise GuardError(
                "ARCHITECTURE_DEPENDENCY_INVALID",
                f"Unknown component dependencies: {sorted(unknown)}",
            )

    concurrency = _object(architecture.get("concurrency"), "architecture.concurrency")
    concurrency_fields = {
        "ordering",
        "idempotency",
        "backpressure",
        "limits",
        "failures",
        "scaling",
        "observability",
    }
    _exact_keys(concurrency, concurrency_fields, "architecture.concurrency")
    return {
        "objective": _text(architecture.get("objective"), "architecture.objective"),
        "public_interface": _text(
            architecture.get("public_interface"),
            "architecture.public_interface",
        ),
        "dependency_direction": _text(
            architecture.get("dependency_direction"),
            "architecture.dependency_direction",
        ),
        "components": normalized_components,
        "trust_boundaries": _text_list(
            architecture.get("trust_boundaries"),
            "architecture.trust_boundaries",
        ),
        "data_flows": _text_list(
            architecture.get("data_flows"),
            "architecture.data_flows",
        ),
        "concurrency": {
            field: _text(concurrency.get(field), f"architecture.concurrency.{field}")
            for field in sorted(concurrency_fields)
        },
    }


def _phases(
    value: Any,
    *,
    requirements: dict[str, dict[str, Any]],
    acceptance: dict[str, dict[str, Any]],
    available_checks: set[str],
) -> list[dict[str, Any]]:
    items = _object_list(value, "phases")
    result: list[dict[str, Any]] = []
    phase_ids: set[str] = set()
    for item in items:
        _exact_keys(
            item,
            {
                "id",
                "goal",
                "requirement_ids",
                "acceptance_ids",
                "allowed_paths",
                "check_ids",
            },
            "phase",
        )
        phase_id = validate_id(item.get("id"), "phase.id")
        if phase_id in phase_ids:
            raise GuardError("DUPLICATE_ID", f"Duplicate phase ID: {phase_id}")
        phase_ids.add(phase_id)
        requirement_ids = _id_list(item.get("requirement_ids"), "phase.requirement_ids")
        acceptance_ids = _id_list(item.get("acceptance_ids"), "phase.acceptance_ids")
        if set(requirement_ids) - set(requirements):
            raise GuardError("PHASE_MAPPING_INVALID", "Phase references an unknown requirement ID.")
        if set(acceptance_ids) - set(acceptance):
            raise GuardError("PHASE_MAPPING_INVALID", "Phase references an unknown acceptance ID.")
        expected_acceptance = {
            acceptance_id
            for requirement_id in requirement_ids
            for acceptance_id in requirements[requirement_id]["acceptance_ids"]
        }
        if set(acceptance_ids) != expected_acceptance:
            raise GuardError(
                "PHASE_MAPPING_INVALID",
                "Phase acceptance IDs must exactly match its requirement mapping.",
            )
        check_ids = _id_list(item.get("check_ids"), "phase.check_ids")
        unknown_checks = set(check_ids) - available_checks
        if unknown_checks:
            raise GuardError(
                "UNTRUSTED_CHECK",
                f"Phase references checks that are not registered: {sorted(unknown_checks)}",
            )
        result.append(
            {
                "id": phase_id,
                "goal": _text(item.get("goal"), "phase.goal"),
                "requirement_ids": requirement_ids,
                "acceptance_ids": acceptance_ids,
                "allowed_paths": _paths(
                    item.get("allowed_paths"),
                    "phase.allowed_paths",
                    allow_glob=True,
                ),
                "check_ids": check_ids,
            }
        )
    return result


def _require_path_coverage(
    phases: list[dict[str, Any]],
    acceptance: dict[str, dict[str, Any]],
) -> None:
    for acceptance_id, item in acceptance.items():
        patterns = [
            pattern
            for phase in phases
            if acceptance_id in phase["acceptance_ids"]
            for pattern in phase["allowed_paths"]
        ]
        for required_path in item["required_paths"]:
            if not any(fnmatchcase(required_path, pattern) for pattern in patterns):
                raise GuardError(
                    "ACCEPTANCE_PATH_UNCOVERED",
                    f"Acceptance required path is not covered by a phase: {required_path}",
                )


def _require_repair_scope(phases: list[dict[str, Any]]) -> None:
    earlier_paths = {path for phase in phases[:-1] for path in phase["allowed_paths"]}
    missing = earlier_paths - set(phases[-1]["allowed_paths"])
    if missing:
        raise GuardError(
            "REPAIR_SCOPE_INCOMPLETE",
            "Final phase must include every earlier allowed path.",
            paths=sorted(missing),
        )


def _assert_resolved_plan(value: Any, field: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _assert_resolved_plan(item, key)
        return
    if isinstance(value, list):
        for item in value:
            _assert_resolved_plan(item, field)
        return
    if isinstance(value, str) and field not in _PLAN_PATH_FIELDS:
        lowered = value.casefold()
        term = next((item for item in _UNRESOLVED_TERMS if item in lowered), "")
        if term:
            raise GuardError(
                "PLAN_UNRESOLVED",
                "Development packet contains unresolved or vague plan text.",
                field=field,
                term=term,
            )


def _certainty(value: Any, *, required: bool) -> dict[str, Any] | None:
    if value is None and not required:
        return None
    if (
        not isinstance(value, dict)
        or set(value) != {"confirmed", "unresolved_items", "assumptions"}
        or value.get("confirmed") is not True
        or value.get("unresolved_items") != []
        or value.get("assumptions") != []
    ):
        raise GuardError(
            "PLAN_UNRESOLVED",
            "Development packet certainty must be confirmed with no unresolved "
            "items or assumptions.",
        )
    return {"confirmed": True, "unresolved_items": [], "assumptions": []}


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuardError("INVALID_PACKET", f"{field} must be an object.")
    return value


def _object_list(value: Any, field: str) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_ITEMS
        or not all(isinstance(item, dict) for item in value)
    ):
        raise GuardError("INVALID_PACKET", f"{field} must be a non-empty object list.")
    return value


def _text(value: Any, field: str, *, maximum: int = 10_000) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > maximum:
        raise GuardError("INVALID_PACKET", f"{field} must be bounded non-empty text.")
    return value.strip()


def _text_list(value: Any, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_ITEMS
        or not all(isinstance(item, str) for item in value)
    ):
        raise GuardError("INVALID_PACKET", f"{field} must be a non-empty text list.")
    return list(dict.fromkeys(_text(item, field) for item in value))


def _id_list(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty) or len(value) > MAX_ITEMS:
        raise GuardError("INVALID_PACKET", f"{field} must be a bounded ID list.")
    result = [validate_id(item, field) for item in value]
    if len(set(result)) != len(result):
        raise GuardError("DUPLICATE_ID", f"{field} contains duplicate IDs.")
    return result


def _paths(value: Any, field: str, *, allow_glob: bool) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_ITEMS
        or not all(isinstance(item, str) for item in value)
    ):
        raise GuardError("INVALID_PATH", f"{field} must be a non-empty path list.")
    result: list[str] = []
    for raw in value:
        if not raw.strip() or "\x00" in raw or len(raw) > 500:
            raise GuardError("INVALID_PATH", f"{field} contains an invalid path.")
        normalized = raw.replace("\\", "/").strip()
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
            raise GuardError("INVALID_PATH", f"Unsafe relative path: {raw}")
        normalized = normalized.rstrip("/")
        path = Path(normalized)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise GuardError("INVALID_PATH", f"Unsafe relative path: {raw}")
        has_glob = any(marker in normalized for marker in _GLOB_MARKERS)
        if has_glob and (
            not allow_glob
            or not normalized.endswith("/**")
            or any(marker in normalized[:-3] for marker in _GLOB_MARKERS)
        ):
            raise GuardError(
                "INVALID_PATH",
                f"Path scope must be an exact path or an explicit directory tree: {raw}",
            )
        result.append(path.as_posix())
    return list(dict.fromkeys(result))


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    if set(value) != expected:
        raise GuardError(
            "INVALID_PACKET",
            f"{field} fields must be exactly: {sorted(expected)}",
        )
