from __future__ import annotations

import copy
import itertools
from collections import Counter, defaultdict, deque
from pathlib import PurePosixPath
from typing import Any


def _steps(packages: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {step["step_id"]: step for package in packages for step in package["lifecycle"]["steps"]}


def _step_states(step: dict[str, Any]) -> set[str]:
    if "public_state" in step:
        return {step["public_state"]}
    return set(step.get("public_states", []))


def _fact_domains(registry: dict[str, Any]) -> dict[str, list[Any]]:
    return {entry["id"]: entry["values"] for entry in registry["fact_domains"]}


def _route_matches(route: dict[str, Any], facts: dict[str, Any]) -> bool:
    return all(facts.get(key) == value for key, value in route["facts"].items())


def _duplicates(values: list[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def _reference_path_is_canonical(path: Any) -> bool:
    if not isinstance(path, str) or "\\" in path:
        return False
    parts = PurePosixPath(path).parts
    return (
        len(parts) == 2
        and parts[0] == "references"
        and parts[1].endswith(".md")
        and parts[1] not in {"", ".", ".."}
        and PurePosixPath(path).as_posix() == path
    )


def check_package_contracts(packages: list[dict[str, Any]], registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    all_step_ids = [
        step["step_id"] for package in packages for step in package["lifecycle"]["steps"]
    ]
    for step_id in _duplicates(all_step_ids):
        errors.append(f"STEP_ID_DUPLICATE global:{step_id}")
    domains = _fact_domains(registry)

    for package in packages:
        package_id = package["skill"]["id"]
        catalog = {entry["name"]: entry for entry in package["artifact_catalog"]}
        if len(catalog) != len(package["artifact_catalog"]):
            errors.append(f"ARTIFACT_DUPLICATE {package_id}")
        steps = {step["step_id"]: step for step in package["lifecycle"]["steps"]}
        profile_ids = [profile.get("id") for profile in package["profiles"]]
        for profile_id in _duplicates([value for value in profile_ids if isinstance(value, str)]):
            errors.append(f"PROFILE_ID_DUPLICATE package:{package_id}:{profile_id}")
        profiles = {profile["id"]: profile for profile in package["profiles"]}
        reference_ids = [reference.get("id") for reference in package["reference_catalog"]]
        for reference_id in _duplicates(
            [value for value in reference_ids if isinstance(value, str)]
        ):
            errors.append(f"REFERENCE_ID_DUPLICATE package:{package_id}:{reference_id}")
        references = {reference["id"]: reference for reference in package["reference_catalog"]}
        for reference in package["reference_catalog"]:
            reference_id = reference.get("id", "unknown")
            if not _reference_path_is_canonical(reference.get("path")):
                errors.append(f"REFERENCE_PATH_INVALID package:{package_id}:{reference_id}")
            if reference.get("bundle_required") is not True:
                errors.append(f"REFERENCE_BUNDLE_REQUIRED package:{package_id}:{reference_id}")
        for profile in package["profiles"]:
            profile_id = profile.get("id", "unknown")
            selected = profile.get("references", [])
            max_references = profile.get("max_references")
            if (
                not isinstance(selected, list)
                or not 1 <= len(selected) <= 2
                or not isinstance(max_references, int)
                or max_references not in (1, 2)
                or (isinstance(max_references, int) and len(selected) > max_references)
            ):
                errors.append(f"PROFILE_REFERENCE_LIMIT package:{package_id}:{profile_id}")
            for reference_id in selected if isinstance(selected, list) else []:
                if reference_id not in references:
                    errors.append(
                        "PROFILE_REFERENCE_UNKNOWN "
                        f"package:{package_id}:{profile_id}:{reference_id}"
                    )
            for step_id in profile.get("step_ids", []):
                if step_id not in steps:
                    errors.append(
                        f"PROFILE_STEP_UNKNOWN package:{package_id}:{profile_id}:{step_id}"
                    )
        for criterion_id in _duplicates(
            [
                criterion.get("id")
                for criterion in package["acceptance"]["criteria"]
                if isinstance(criterion.get("id"), str)
            ]
        ):
            errors.append(f"ACCEPTANCE_ID_DUPLICATE package:{package_id}:{criterion_id}")
        declared_states = set(package["lifecycle"]["public_states"])

        trust = package["trust"]
        for field in ("registry_record_required", "atomic_install_required"):
            if trust.get(field) is not True:
                errors.append(f"TRUST_CONTROL package:{package_id}:{field}")
        permissions = package.get("permissions", {})
        default_permissions = (
            permissions.get("default", {}) if isinstance(permissions, dict) else {}
        )
        for field in (
            "run_state",
            "approval",
            "version_selection",
            "profile_selection",
            "reference_selection",
        ):
            if (
                not isinstance(default_permissions, dict)
                or default_permissions.get(field) != "deny"
            ):
                errors.append(f"PERMISSION_CONTROL package:{package_id}:default:{field}")
        overrides = permissions.get("step_overrides", []) if isinstance(permissions, dict) else []
        for override in overrides:
            override_step = override.get("step_id", "unknown")
            if override_step not in steps:
                errors.append(f"PERMISSION_STEP_UNKNOWN package:{package_id}:{override_step}")
            for field in (
                "run_state",
                "approval",
                "version_selection",
                "profile_selection",
                "reference_selection",
            ):
                if field in override and override[field] != "deny":
                    errors.append(
                        f"PERMISSION_CONTROL package:{package_id}:{override_step}:{field}"
                    )
        acceptance = package["acceptance"]
        if acceptance.get("evaluation_point") != "before_external_acceptance":
            errors.append(f"ACCEPTANCE_EVALUATION_POINT package:{package_id}")
        if acceptance.get("aggregation") != "all_applicable":
            errors.append(f"ACCEPTANCE_AGGREGATION package:{package_id}")
        if acceptance.get("self_test_is_acceptance") is not False:
            errors.append(f"SELF_TEST_ACCEPTANCE package:{package_id}")

        for step in steps.values():
            if ("public_state" in step) == ("public_states" in step):
                errors.append(f"STEP_STATE_SHAPE {step['step_id']}")
            if not _step_states(step) or not _step_states(step) <= declared_states:
                errors.append(f"STEP_STATE_UNDECLARED {step['step_id']}")
            outcomes = set(step["allowed_outcomes"])
            if outcomes != set(step["outputs_by_outcome"]):
                errors.append(f"OUTCOME_OUTPUT_MISMATCH {step['step_id']}")
            if outcomes != set(step["exit_assertions_by_outcome"]):
                errors.append(f"OUTCOME_ASSERTION_MISMATCH {step['step_id']}")
            if step["owner"] == "guard":
                if step["profile_ids"] or not step.get("algorithm_id"):
                    errors.append(f"GUARD_STEP_SHAPE {step['step_id']}")
            else:
                if not step["profile_ids"] or step.get("algorithm_id"):
                    errors.append(f"SKILL_STEP_SHAPE {step['step_id']}")
                for profile_id in step["profile_ids"]:
                    profile = profiles.get(profile_id)
                    if not profile or step["step_id"] not in profile["step_ids"]:
                        errors.append(f"PROFILE_BINDING {step['step_id']}:{profile_id}")
            for item in step["inputs"]:
                if item["artifact"] not in catalog:
                    errors.append(f"INPUT_NOT_CATALOGED {step['step_id']}:{item['artifact']}")
                source = item["source"]
                is_collection = source["kind"] == "artifact_collection_ref"
                if (item["cardinality"] == "ordered_many") != is_collection:
                    errors.append(f"COLLECTION_CARDINALITY {step['step_id']}:{item['artifact']}")
                if is_collection and (
                    not source.get("collection_id") or not source.get("index_keys")
                ):
                    errors.append(f"COLLECTION_BINDING {step['step_id']}:{item['artifact']}")
            for outcome, outputs in step["outputs_by_outcome"].items():
                for output in outputs:
                    entry = catalog.get(output["artifact"])
                    if entry is None:
                        errors.append(
                            f"OUTPUT_NOT_CATALOGED {step['step_id']}:{outcome}:{output['artifact']}"
                        )
                    elif entry["producer"] not in {step["owner"], "skill_or_guard"}:
                        errors.append(f"OUTPUT_OWNER {step['step_id']}:{output['artifact']}")

        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        route_ids: set[str] = set()
        for route in package["lifecycle"]["routes"]:
            if route["route_id"] in route_ids:
                errors.append(f"ROUTE_ID_DUPLICATE {route['route_id']}")
            route_ids.add(route["route_id"])
            grouped[route["decision_point"]].append(route)
            target = route["next"]
            if ("step_id" in target) == ("terminal_outcome" in target):
                errors.append(f"ROUTE_TARGET_XOR {route['route_id']}")
            if "step_id" in target:
                if target["step_id"] not in steps:
                    errors.append(f"PACKAGE_ROUTE_ESCAPE {route['route_id']}")
                target_step = steps.get(target["step_id"])
                if target_step:
                    point = route["decision_point"]
                    if point.startswith("after:"):
                        source_step = steps.get(point.removeprefix("after:"))
                        if source_step and _step_states(source_step).isdisjoint(
                            _step_states(target_step)
                        ):
                            errors.append(f"PACKAGE_ROUTE_STATE {route['route_id']}")
                    expected_profile = target.get("profile_id")
                    if target_step["owner"] == "guard" and expected_profile is not None:
                        errors.append(f"GUARD_ROUTE_PROFILE {route['route_id']}")
                    if (
                        target_step["owner"] == "skill"
                        and expected_profile not in target_step["profile_ids"]
                    ):
                        errors.append(f"SKILL_ROUTE_PROFILE {route['route_id']}")
            elif "terminal_outcome" not in target:
                errors.append(f"ROUTE_TARGET_INVALID {route['route_id']}")

        required_points = {"start", *(f"after:{step_id}" for step_id in steps)}
        for point in sorted(required_points - set(grouped)):
            errors.append(f"ROUTE_GROUP_MISSING {package_id}:{point}")
        for point in sorted(set(grouped) - required_points):
            errors.append(f"ROUTE_GROUP_UNKNOWN {package_id}:{point}")

        for point, routes in grouped.items():
            keys = sorted({key for route in routes for key in route["facts"]})
            point_domains: list[list[Any]] = []
            for key in keys:
                if key == "outcome" and point.startswith("after:"):
                    step_id = point.removeprefix("after:")
                    if step_id not in steps:
                        errors.append(f"ROUTE_DECISION_STEP_UNKNOWN {point}")
                        point_domains.append([])
                    else:
                        point_domains.append(steps[step_id]["allowed_outcomes"])
                elif key in domains:
                    point_domains.append(domains[key])
                else:
                    errors.append(f"FACT_DOMAIN_UNKNOWN {package_id}:{point}:{key}")
                    point_domains.append([])
            for values in itertools.product(*point_domains) if keys else [()]:
                facts = dict(zip(keys, values, strict=True))
                matches = [route for route in routes if _route_matches(route, facts)]
                if len(matches) != 1:
                    errors.append(
                        f"ROUTE_PARTITION {package_id}:{point}:{facts}:matches={len(matches)}"
                    )
    return errors


def check_artifact_reachability(packages: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    steps = _steps(packages)
    pseudo_producers = {
        "external.control",
        "guard.freeze",
        "guard.collection.append",
        "guard.evidence_index",
    }
    for package in packages:
        for step in package["lifecycle"]["steps"]:
            for item in step["inputs"]:
                source = item["source"]
                expected = source["authority"]
                for producer_id in source["producer_step_ids"]:
                    if producer_id in pseudo_producers:
                        continue
                    producer = steps.get(producer_id)
                    if producer is None:
                        identity = f"{step['step_id']}:{item['artifact']}:{producer_id}"
                        errors.append(f"ARTIFACT_PRODUCER_UNKNOWN {identity}")
                        continue
                    produced = any(
                        output["artifact"] == item["artifact"]
                        for outputs in producer["outputs_by_outcome"].values()
                        for output in outputs
                    )
                    if not produced:
                        identity = f"{step['step_id']}:{item['artifact']}:{producer_id}"
                        errors.append(f"ARTIFACT_UNREACHABLE {identity}")
                    if expected != "skill_or_guard" and producer["owner"] != expected:
                        errors.append(
                            f"ARTIFACT_AUTHORITY {step['step_id']}:{item['artifact']}:{producer_id}"
                        )
    return errors


def _terminal_routes(packages: list[dict[str, Any]]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for package in packages:
        for route in package["lifecycle"]["routes"]:
            target = route["next"]
            if "terminal_outcome" not in target:
                continue
            if not route["decision_point"].startswith("after:"):
                continue
            result.append(
                (
                    route["decision_point"].removeprefix("after:"),
                    target["terminal_outcome"],
                )
            )
    return result


def check_system_lifecycle(
    packages: list[dict[str, Any]],
    system: dict[str, Any],
    registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    steps = _steps(packages)
    system_states = set(system["public_states"])
    node_states = {entry["node_id"]: entry["public_state"] for entry in system["virtual_nodes"]}
    nodes = set(node_states)
    package_versions = {package["skill"]["id"]: package["skill"]["version"] for package in packages}
    binding_ids = [entry["package_id"] for entry in system["package_contracts"]]
    for package_id in _duplicates(binding_ids):
        errors.append(f"PACKAGE_BINDING_DUPLICATE system:{package_id}")
    declared_versions = {
        entry["package_id"]: entry["version"] for entry in system["package_contracts"]
    }
    if package_versions != declared_versions or len(binding_ids) != len(package_versions):
        errors.append("SYSTEM_PACKAGE_VERSION_MISMATCH")
    domains = _fact_domains(registry)

    for node_id in _duplicates([entry["node_id"] for entry in system["virtual_nodes"]]):
        errors.append(f"SYSTEM_NODE_ID_DUPLICATE system:{node_id}")
    for transition_id in _duplicates([entry["transition_id"] for entry in system["transitions"]]):
        errors.append(f"SYSTEM_TRANSITION_ID_DUPLICATE system:{transition_id}")
    for suspension_id in _duplicates([entry["suspension_id"] for entry in system["suspensions"]]):
        errors.append(f"SUSPENSION_ID_DUPLICATE system:{suspension_id}")
    for criterion_id in _duplicates([entry["id"] for entry in system["acceptance"]["criteria"]]):
        errors.append(f"ACCEPTANCE_ID_DUPLICATE system:{criterion_id}")
    if system["acceptance"].get("aggregation") != "all_applicable":
        errors.append("ACCEPTANCE_AGGREGATION system")
    if system["acceptance"].get("self_test_is_acceptance") is not False:
        errors.append("SELF_TEST_ACCEPTANCE system")

    for step_id, step in steps.items():
        if not _step_states(step) <= system_states:
            errors.append(f"SYSTEM_STEP_STATE_UNKNOWN {step_id}")
    start = system["start"]
    start_target = steps.get(start["next_step_id"])
    if start_target is None:
        errors.append("SYSTEM_START_STEP_UNKNOWN")
    elif start["public_state"] not in _step_states(start_target):
        errors.append("SYSTEM_START_STEP_STATE")

    transition_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for transition in system["transitions"]:
        transition_state = transition["public_state"]
        if transition_state not in system_states:
            errors.append(f"SYSTEM_TRANSITION_STATE_UNKNOWN {transition['transition_id']}")
        step_source = "from_step_id" in transition
        node_source = "from_node_id" in transition
        step_event = "terminal_outcome" in transition
        node_event = "event_id" in transition
        source_valid = (step_source and step_event and not node_source and not node_event) or (
            node_source and node_event and not step_source and not step_event
        )
        if not source_valid:
            errors.append(f"SYSTEM_TRANSITION_SOURCE_XOR {transition['transition_id']}")
        elif step_source:
            key = (transition["from_step_id"], transition.get("terminal_outcome", ""))
            if transition["from_step_id"] not in steps:
                errors.append(f"SYSTEM_FROM_STEP_UNKNOWN {transition['transition_id']}")
        else:
            key = (transition["from_node_id"], transition.get("event_id", ""))
            if transition["from_node_id"] not in nodes:
                errors.append(f"SYSTEM_FROM_NODE_UNKNOWN {transition['transition_id']}")
        if source_valid:
            transition_groups[key].append(transition)

        step_target = "next_step_id" in transition
        node_target = "next_node_id" in transition
        if step_target == node_target:
            errors.append(f"SYSTEM_TRANSITION_TARGET_XOR {transition['transition_id']}")
        elif step_target:
            next_step = steps.get(transition["next_step_id"])
            if next_step is None:
                errors.append(f"SYSTEM_NEXT_STEP_UNKNOWN {transition['transition_id']}")
            elif transition_state not in _step_states(next_step):
                errors.append(f"SYSTEM_NEXT_STEP_STATE {transition['transition_id']}")
        else:
            next_node_state = node_states.get(transition["next_node_id"])
            if next_node_state is None:
                errors.append(f"SYSTEM_NEXT_NODE_UNKNOWN {transition['transition_id']}")
            elif transition_state != next_node_state:
                errors.append(f"SYSTEM_NEXT_NODE_STATE {transition['transition_id']}")

    for key, transitions in transition_groups.items():
        fact_keys = sorted(
            {
                condition["fact_id"]
                for transition in transitions
                for condition in transition.get("when", [])
            }
        )
        if not fact_keys:
            if len(transitions) != 1:
                errors.append(f"SYSTEM_TRANSITION_DUPLICATE {key}")
            continue
        value_domains: list[list[Any]] = []
        for fact_id in fact_keys:
            if fact_id not in domains:
                errors.append(f"SYSTEM_FACT_DOMAIN_UNKNOWN {fact_id}")
                value_domains.append([])
            else:
                value_domains.append(domains[fact_id])
        for values in itertools.product(*value_domains):
            facts = dict(zip(fact_keys, values, strict=True))
            matches = []
            for transition in transitions:
                conditions = transition.get("when", [])
                if all(
                    condition["operator"] == "eq"
                    and facts.get(condition["fact_id"]) == condition["value"]
                    for condition in conditions
                ):
                    matches.append(transition)
            if len(matches) != 1:
                errors.append(f"SYSTEM_TRANSITION_PARTITION {key}:{facts}:matches={len(matches)}")

    sidecars = {entry["step_id"] for entry in system["sidecars"]}
    suspensions_by_origin = {
        (entry["origin_step_id"], entry["terminal_outcome"]): entry
        for entry in system["suspensions"]
    }
    if len(suspensions_by_origin) != len(system["suspensions"]):
        errors.append("SUSPENSION_ORIGIN_DUPLICATE")
    for suspension in system["suspensions"]:
        for field in ("origin_step_id", "apply_step_id", "resume_step_id"):
            if suspension[field] not in steps:
                errors.append(f"SUSPENSION_STEP_UNKNOWN {suspension['suspension_id']}:{field}")
        resume_inputs = {item["artifact"] for item in steps[suspension["resume_step_id"]]["inputs"]}
        if suspension["resume_input_artifact"] not in resume_inputs:
            errors.append(f"SUSPENSION_RESUME_INPUT {suspension['suspension_id']}")
        origin_states = _step_states(steps[suspension["origin_step_id"]])
        if origin_states.isdisjoint(_step_states(steps[suspension["apply_step_id"]])):
            errors.append(f"SUSPENSION_APPLY_STATE {suspension['suspension_id']}")
        if origin_states.isdisjoint(_step_states(steps[suspension["resume_step_id"]])):
            errors.append(f"SUSPENSION_RESUME_STATE {suspension['suspension_id']}")
        apply_terminals = {
            outcome
            for step_id, outcome in _terminal_routes(packages)
            if step_id == suspension["apply_step_id"]
        }
        if suspension["apply_terminal_outcome"] not in apply_terminals:
            errors.append(f"SUSPENSION_APPLY_OUTCOME {suspension['suspension_id']}")

    terminal_policies = system["terminal_policies"]
    for step_id, outcome in _terminal_routes(packages):
        handlers = 0
        if (step_id, outcome) in transition_groups:
            handlers += 1
        if (step_id, outcome) in suspensions_by_origin:
            handlers += 1
        if any(
            suspension["apply_step_id"] == step_id
            and suspension["apply_terminal_outcome"] == outcome
            for suspension in system["suspensions"]
        ):
            handlers += 1
        if step_id in sidecars and outcome == "completed":
            handlers += 1
        if any(
            policy["terminal_outcome"] == outcome
            and (
                policy.get("applies_to") == "all_package_steps"
                or policy.get("from_step_id") == step_id
            )
            for policy in terminal_policies
        ):
            handlers += 1
        if handlers != 1:
            errors.append(f"SYSTEM_TERMINAL_HANDLER {step_id}:{outcome}:handlers={handlers}")

    edges: dict[str, set[str]] = defaultdict(set)
    for package in packages:
        for route in package["lifecycle"]["routes"]:
            point = route["decision_point"]
            if point.startswith("after:") and "step_id" in route["next"]:
                edges[point.removeprefix("after:")].add(route["next"]["step_id"])
    for transition in system["transitions"]:
        step_source = "from_step_id" in transition
        node_source = "from_node_id" in transition
        step_target = "next_step_id" in transition
        node_target = "next_node_id" in transition
        if step_source == node_source or step_target == node_target:
            continue
        source = transition["from_step_id"] if step_source else transition["from_node_id"]
        target = transition["next_step_id"] if step_target else transition["next_node_id"]
        edges[source].add(target)
    for suspension in system["suspensions"]:
        edges[suspension["origin_step_id"]].add(suspension["apply_step_id"])
        edges[suspension["apply_step_id"]].add(suspension["resume_step_id"])
    for step_id, outcome in _terminal_routes(packages):
        if outcome == "blocked":
            edges[step_id].add("system.blocked")

    start = system["start"]["next_step_id"]
    visited: set[str] = set()
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        queue.extend(edges[node] - visited)
    required = (set(steps) - sidecars) | {
        "system.awaiting_acceptance",
        "system.accepted",
        "system.blocked",
    }
    for node in sorted(required - visited):
        errors.append(f"SYSTEM_NODE_UNREACHABLE {node}")

    execute = next(p for p in packages if p["skill"]["id"] == "execute-in-slices")
    slice_step = next(
        s for s in execute["lifecycle"]["steps"] if s["step_id"] == "implementing.slice"
    )
    correction_outputs = {
        output["artifact"] for output in slice_step["outputs_by_outcome"]["correction_required"]
    }
    if {"implementation_record", "correction_proposal"} - correction_outputs:
        errors.append("CONDITIONAL_AC_EXECUTION_RECORD_MISSING")
    verify = next(p for p in packages if p["skill"]["id"] == "verify-and-diagnose")
    ver_ac_07 = next(c for c in verify["acceptance"]["criteria"] if c["id"] == "VER-AC-07")
    if ver_ac_07["applicability_predicate"] != "correction_proposal_present":
        errors.append("CONDITIONAL_AC_VERIFICATION_CYCLE")
    record = next(p for p in packages if p["skill"]["id"] == "record-and-handoff")
    rec_ac_08 = next(c for c in record["acceptance"]["criteria"] if c["id"] == "REC-AC-08")
    if "artifact.acceptance_transition.v1" in rec_ac_08["evidence_schema_ids"]:
        errors.append("CONDITIONAL_AC_ACCEPTANCE_CYCLE")
    if not any(c["id"] == "SYS-AC-12" for c in system["acceptance"]["criteria"]):
        errors.append("SYSTEM_ACCEPTANCE_POST_APPLY_MISSING")
    return errors


def run_graph_negative_probes(
    packages: list[dict[str, Any]],
    system: dict[str, Any],
    registry: dict[str, Any],
) -> list[str]:
    failures: list[str] = []

    def expect(errors: list[str], prefix: str, name: str) -> None:
        if not any(error.startswith(prefix) for error in errors):
            failures.append(f"NEGATIVE_PROBE missed {name}")

    package_control_mutations = (
        (
            "self-test acceptance",
            lambda value: value[0]["acceptance"].__setitem__("self_test_is_acceptance", True),
            "SELF_TEST_ACCEPTANCE",
        ),
        (
            "acceptance aggregation",
            lambda value: value[0]["acceptance"].__setitem__("aggregation", "first_passing"),
            "ACCEPTANCE_AGGREGATION",
        ),
        (
            "run-state permission",
            lambda value: value[0]["permissions"]["default"].__setitem__("run_state", "allow"),
            "PERMISSION_CONTROL",
        ),
        (
            "approval permission",
            lambda value: value[0]["permissions"]["default"].__setitem__("approval", "allow"),
            "PERMISSION_CONTROL",
        ),
        (
            "registry record requirement",
            lambda value: value[0]["trust"].__setitem__("registry_record_required", False),
            "TRUST_CONTROL",
        ),
        (
            "atomic install requirement",
            lambda value: value[0]["trust"].__setitem__("atomic_install_required", False),
            "TRUST_CONTROL",
        ),
        (
            "reference path escape",
            lambda value: value[0]["reference_catalog"][0].__setitem__("path", "../escaped.md"),
            "REFERENCE_PATH_INVALID",
        ),
        (
            "unknown profile reference",
            lambda value: value[0]["profiles"][0]["references"].__setitem__(0, "unknown-reference"),
            "PROFILE_REFERENCE_UNKNOWN",
        ),
        (
            "profile reference capacity",
            lambda value: value[0]["profiles"][0].__setitem__("max_references", 3),
            "PROFILE_REFERENCE_LIMIT",
        ),
    )
    for name, mutate, prefix in package_control_mutations:
        mutation = copy.deepcopy(packages)
        mutate(mutation)
        expect(check_package_contracts(mutation, registry), prefix, name)

    system_self_test = copy.deepcopy(system)
    system_self_test["acceptance"]["self_test_is_acceptance"] = True
    expect(
        check_system_lifecycle(packages, system_self_test, registry),
        "SELF_TEST_ACCEPTANCE",
        "system self-test acceptance",
    )

    route_group_probes = (
        (packages[0]["skill"]["id"], "start", "start route group"),
        ("requirements-contract", "after:planning.requirements.research", "middle route group"),
        ("record-and-handoff", "after:acceptance.apply", "terminal route group"),
    )
    for package_id, decision_point, name in route_group_probes:
        mutation = copy.deepcopy(packages)
        package = next(item for item in mutation if item["skill"]["id"] == package_id)
        package["lifecycle"]["routes"] = [
            route
            for route in package["lifecycle"]["routes"]
            if route["decision_point"] != decision_point
        ]
        expect(
            check_package_contracts(mutation, registry),
            f"ROUTE_GROUP_MISSING {package_id}:{decision_point}",
            name,
        )

    duplicate_profile = copy.deepcopy(packages)
    duplicate_profile[0]["profiles"].append(copy.deepcopy(duplicate_profile[0]["profiles"][0]))
    expect(
        check_package_contracts(duplicate_profile, registry),
        "PROFILE_ID_DUPLICATE",
        "duplicate profile id",
    )

    duplicate_package_ac = copy.deepcopy(packages)
    duplicate_package_ac[0]["acceptance"]["criteria"].append(
        copy.deepcopy(duplicate_package_ac[0]["acceptance"]["criteria"][0])
    )
    expect(
        check_package_contracts(duplicate_package_ac, registry),
        "ACCEPTANCE_ID_DUPLICATE package:",
        "duplicate package acceptance id",
    )

    system_duplicate_probes = (
        ("transitions", "SYSTEM_TRANSITION_ID_DUPLICATE", "duplicate system transition id"),
        ("suspensions", "SUSPENSION_ID_DUPLICATE", "duplicate suspension id"),
        ("package_contracts", "PACKAGE_BINDING_DUPLICATE", "duplicate package binding"),
    )
    for collection, prefix, name in system_duplicate_probes:
        mutation = copy.deepcopy(system)
        mutation[collection].append(copy.deepcopy(mutation[collection][0]))
        expect(check_system_lifecycle(packages, mutation, registry), prefix, name)

    missing_transition = copy.deepcopy(system)
    missing_transition["transitions"] = [
        item
        for item in missing_transition["transitions"]
        if item["transition_id"] != "requirements-to-design"
    ]
    if not any(
        error.startswith("SYSTEM_TERMINAL_HANDLER")
        for error in check_system_lifecycle(packages, missing_transition, registry)
    ):
        failures.append("NEGATIVE_PROBE missed system transition deletion")

    duplicate_transition = copy.deepcopy(system)
    duplicate = copy.deepcopy(
        next(
            item
            for item in duplicate_transition["transitions"]
            if item["transition_id"] == "review-to-simplicity-handoff"
        )
    )
    duplicate["transition_id"] = "review-to-simplicity-handoff-duplicate"
    duplicate_transition["transitions"].append(duplicate)
    if not any(
        error.startswith("SYSTEM_TRANSITION_PARTITION")
        for error in check_system_lifecycle(packages, duplicate_transition, registry)
    ):
        failures.append("NEGATIVE_PROBE missed duplicate system transition")

    bad_source = copy.deepcopy(packages)
    target = bad_source[0]["lifecycle"]["steps"][0]["inputs"][0]
    target["source"]["producer_step_ids"] = ["planning.missing.step"]
    if not any(
        error.startswith("ARTIFACT_PRODUCER_UNKNOWN")
        for error in check_artifact_reachability(bad_source)
    ):
        failures.append("NEGATIVE_PROBE missed artifact producer mutation")

    bad_transition_state = copy.deepcopy(system)
    correction = next(
        item
        for item in bad_transition_state["transitions"]
        if item["transition_id"] == "verification-to-correction"
    )
    correction["public_state"] = "VERIFYING"
    if not any(
        error.startswith("SYSTEM_NEXT_STEP_STATE")
        for error in check_system_lifecycle(packages, bad_transition_state, registry)
    ):
        failures.append("NEGATIVE_PROBE missed system target-state mutation")

    bad_step_state = copy.deepcopy(packages)
    execute = next(
        package for package in bad_step_state if package["skill"]["id"] == "execute-in-slices"
    )
    correction_step = next(
        step for step in execute["lifecycle"]["steps"] if step["step_id"] == "correction.route"
    )
    correction_step["public_state"] = "VERIFYING"
    step_errors = check_package_contracts(bad_step_state, registry) + check_system_lifecycle(
        bad_step_state, system, registry
    )
    if not any("STATE" in error for error in step_errors):
        failures.append("NEGATIVE_PROBE missed step-state mutation")

    source_mutations = []
    double_source = copy.deepcopy(system)
    target = next(
        item
        for item in double_source["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    target.update({"from_step_id": "review.handoff.final", "terminal_outcome": "completed"})
    source_mutations.append(("double source", double_source))
    missing_source = copy.deepcopy(system)
    target = next(
        item
        for item in missing_source["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    del target["from_node_id"]
    del target["event_id"]
    source_mutations.append(("missing source", missing_source))
    for name, mutation in source_mutations:
        if not any(
            error.startswith("SYSTEM_TRANSITION_SOURCE_XOR")
            for error in check_system_lifecycle(packages, mutation, registry)
        ):
            failures.append(f"NEGATIVE_PROBE missed system transition {name}")

    target_mutations = []
    double_target = copy.deepcopy(system)
    target = next(
        item
        for item in double_target["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    target["next_node_id"] = "system.awaiting_acceptance"
    target_mutations.append(("double target", double_target))
    missing_target = copy.deepcopy(system)
    target = next(
        item
        for item in missing_target["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    del target["next_step_id"]
    target_mutations.append(("missing target", missing_target))
    for name, mutation in target_mutations:
        if not any(
            error.startswith("SYSTEM_TRANSITION_TARGET_XOR")
            for error in check_system_lifecycle(packages, mutation, registry)
        ):
            failures.append(f"NEGATIVE_PROBE missed system transition {name}")
    return failures
