from __future__ import annotations

import copy
import re
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from model import (
    canonical_artifact_schema_uri,
    canonical_bytes,
    resolve_local_ref,
    sha256_bytes,
)

LOCAL_SCHEMA_FIELDS = {
    "id",
    "status",
    "schema_path",
    "fragment",
    "schema_uri",
    "file_sha256",
}
EXTERNAL_SCHEMA_FIELDS = {
    "id",
    "status",
    "registry_id",
    "registry_version",
    "schema_uri",
    "schema_digest",
    "registry_attestation_id",
}
SCHEMA_ATTESTATION_FIELDS = {
    "id",
    "registry_id",
    "registry_version",
    "issuer_authority_id",
    "signature_policy_id",
    "trust_store_id",
    "attestation_uri",
    "binding_set_digest",
    "verification_mode",
    "design_time_status",
}
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
PCHAR = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@-]+$")
EXPECTED_CRYPTO_POLICIES = {
    "skill-signature-ed25519.v1": {
        "canonicalization": "rfc8785-jcs",
        "hash_algorithm": "sha256",
        "signature_algorithm": "ed25519",
        "domain": "opencode.skill-manifest-signature.v1",
    },
    "provider-delivery-signature.v1": {
        "canonicalization": "rfc8785-jcs",
        "hash_algorithm": "sha256",
        "signature_algorithm": "registry_selected",
        "domain": "opencode.provider-delivery-signature.v1",
    },
    "schema-registry-signature-ed25519.v1": {
        "canonicalization": "rfc8785-jcs",
        "hash_algorithm": "sha256",
        "signature_algorithm": "ed25519",
        "domain": "opencode.schema-registry-attestation.v1",
    },
}
PACKAGE_SIGNATURE_POLICY_ID = "skill-signature-ed25519.v1"
ACCEPTANCE_ASSERTION_ID = "acceptance_transition_post_apply"
ACCEPTANCE_AUTHORITY_ID = "guard.acceptance"


def _canonical_https_uri(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or not value.startswith("https://")
        or "?" in value
        or "#" in value
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or host is None
        or HOSTNAME.fullmatch(host) is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.netloc != host
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or "\\" in parsed.path
        or "%" in parsed.path
    ):
        return False
    segments = parsed.path.split("/")[1:]
    return bool(segments) and all(
        segment not in {"", ".", ".."} and PCHAR.fullmatch(segment) is not None
        for segment in segments
    )


def _external_binding_set_digest(entries: list[dict[str, Any]], attestation_id: str) -> str:
    bindings = [
        {key: entry[key] for key in sorted(EXTERNAL_SCHEMA_FIELDS)}
        for entry in entries
        if entry.get("status") == "external_registered"
        and entry.get("registry_attestation_id") == attestation_id
        and set(entry) >= EXTERNAL_SCHEMA_FIELDS
    ]
    bindings.sort(key=lambda entry: entry["id"])
    return sha256_bytes(canonical_bytes(bindings))


def _refresh_binding_set_digest(registry: dict[str, Any], binding: dict[str, Any]) -> None:
    attestation_id = binding["registry_attestation_id"]
    attestation = next(
        entry for entry in registry["schema_attestations"] if entry["id"] == attestation_id
    )
    attestation["binding_set_digest"] = _external_binding_set_digest(
        registry["artifact_schemas"], attestation_id
    )


def _ids(entries: list[dict[str, Any]], kind: str, errors: list[str]) -> set[str]:
    values = [entry["id"] for entry in entries]
    duplicates = sorted({value for value in values if values.count(value) > 1})
    for value in duplicates:
        errors.append(f"REGISTRY_DUPLICATE {kind}:{value}")
    return set(values)


def check_registry(
    packages: list[dict[str, Any]],
    system: dict[str, Any],
    registry: dict[str, Any],
    design_root: Path,
    schema_documents: dict[str, dict[str, Any]],
    input_file_digests: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    authority_ids = _ids(registry["authorities"], "authority", errors)
    algorithm_ids = _ids(registry["algorithms"], "algorithm", errors)
    fact_ids = _ids(registry["fact_domains"], "fact", errors)
    predicate_ids = _ids(registry["predicates"], "predicate", errors)
    assertion_ids = _ids(registry["assertions"], "assertion", errors)
    schema_ids = _ids(registry["artifact_schemas"], "artifact_schema", errors)
    crypto_ids = _ids(registry["crypto_policies"], "crypto_policy", errors)
    attestation_ids = _ids(registry["schema_attestations"], "schema_attestation", errors)
    facts = {entry["id"]: entry["values"] for entry in registry["fact_domains"]}
    assertion_map = {entry["id"]: entry for entry in registry["assertions"]}
    authority_map = {entry["id"]: entry for entry in registry["authorities"]}
    attestation_map = {entry["id"]: entry for entry in registry["schema_attestations"]}

    crypto_map = {entry["id"]: entry for entry in registry["crypto_policies"]}
    for policy_id, expected in EXPECTED_CRYPTO_POLICIES.items():
        policy = crypto_map.get(policy_id)
        if policy is None:
            errors.append(f"CRYPTO_POLICY_REQUIRED {policy_id}")
            continue
        for field, value in expected.items():
            if policy.get(field) != value:
                errors.append(f"CRYPTO_POLICY_CONTROL {policy_id}:{field}")
    acceptance_authority = authority_map.get(ACCEPTANCE_AUTHORITY_ID)
    if acceptance_authority is None:
        errors.append(f"ACCEPTANCE_AUTHORITY_REQUIRED {ACCEPTANCE_AUTHORITY_ID}")
    else:
        if acceptance_authority.get("kind") != "acceptance_validator":
            errors.append(f"ACCEPTANCE_AUTHORITY_CONTROL {ACCEPTANCE_AUTHORITY_ID}:kind")
        if acceptance_authority.get("can_verify") != ["acceptance_assertion"]:
            errors.append(f"ACCEPTANCE_AUTHORITY_CONTROL {ACCEPTANCE_AUTHORITY_ID}:can_verify")
    acceptance_assertion = assertion_map.get(ACCEPTANCE_ASSERTION_ID)
    if acceptance_assertion is None:
        errors.append(f"ACCEPTANCE_ASSERTION_REQUIRED {ACCEPTANCE_ASSERTION_ID}")
    elif acceptance_assertion.get("authority_ids") != [ACCEPTANCE_AUTHORITY_ID]:
        errors.append(f"ACCEPTANCE_ASSERTION_AUTHORITY_BINDING {ACCEPTANCE_ASSERTION_ID}")

    local_schema_root = (design_root / "schemas").resolve()
    local_locations: set[tuple[Path, str]] = set()
    schema_uris: set[str] = set()
    external_bindings: set[tuple[str, str, str, str]] = set()
    for entry in registry["artifact_schemas"]:
        schema_id = entry["id"]
        if not isinstance(schema_id, str) or IDENTIFIER.fullmatch(schema_id) is None:
            errors.append(f"ARTIFACT_SCHEMA_ID {schema_id}")
        status = entry.get("status")
        if status == "defined":
            if set(entry) != LOCAL_SCHEMA_FIELDS:
                errors.append(f"ARTIFACT_SCHEMA_BINDING_SHAPE {schema_id}:defined")
                continue
            path = (design_root / entry["schema_path"]).resolve()
            if not path.is_relative_to(local_schema_root):
                errors.append(f"ARTIFACT_SCHEMA_PATH_ESCAPE {schema_id}")
                continue
            canonical_path = path.relative_to(design_root.resolve()).as_posix()
            if entry["schema_path"] != canonical_path:
                errors.append(f"ARTIFACT_SCHEMA_PATH_NONCANONICAL {schema_id}")
            relative_schema_path = path.relative_to(design_root.resolve()).as_posix()
            document = schema_documents.get(path.name)
            actual_digest = input_file_digests.get(relative_schema_path)
            if document is None or actual_digest is None:
                errors.append(f"ARTIFACT_SCHEMA_FILE_MISSING {schema_id}")
                continue
            location = (path, entry["fragment"])
            if location in local_locations:
                errors.append(f"ARTIFACT_SCHEMA_LOCATION_DUPLICATE {schema_id}")
            local_locations.add(location)
            if actual_digest != entry["file_sha256"]:
                errors.append(f"ARTIFACT_SCHEMA_DIGEST {schema_id}")
            try:
                target = (
                    document
                    if entry["fragment"] == "#"
                    else resolve_local_ref(document, entry["fragment"])
                )
                expected_uri = canonical_artifact_schema_uri(schema_id)
                if entry["schema_uri"] != expected_uri or target.get("$id") != expected_uri:
                    errors.append(f"ARTIFACT_SCHEMA_IDENTITY {schema_id}")
                if entry["schema_uri"] in schema_uris:
                    errors.append(f"ARTIFACT_SCHEMA_URI_DUPLICATE {schema_id}")
                schema_uris.add(entry["schema_uri"])
            except (OSError, ValueError) as error:
                errors.append(f"ARTIFACT_SCHEMA_FRAGMENT {schema_id}:{error}")
        elif status == "external_registered":
            if set(entry) != EXTERNAL_SCHEMA_FIELDS:
                errors.append(f"ARTIFACT_SCHEMA_BINDING_SHAPE {schema_id}:external")
                continue
            binding = (
                entry["registry_id"],
                entry["registry_version"],
                entry["schema_uri"],
                entry["schema_digest"],
            )
            if binding in external_bindings:
                errors.append(f"ARTIFACT_SCHEMA_BINDING_DUPLICATE {schema_id}")
            external_bindings.add(binding)
            if entry["schema_uri"] in schema_uris:
                errors.append(f"ARTIFACT_SCHEMA_URI_DUPLICATE {schema_id}")
            schema_uris.add(entry["schema_uri"])
            if not _canonical_https_uri(entry["schema_uri"]):
                errors.append(f"ARTIFACT_SCHEMA_URI {schema_id}")
            if re.fullmatch(r"[0-9a-f]{64}", entry["schema_digest"]) is None:
                errors.append(f"ARTIFACT_SCHEMA_EXTERNAL_DIGEST {schema_id}")
            for field in ("registry_id", "registry_attestation_id"):
                if not isinstance(entry[field], str) or IDENTIFIER.fullmatch(entry[field]) is None:
                    errors.append(f"ARTIFACT_SCHEMA_EXTERNAL_FIELD {schema_id}:{field}")
            if (
                not isinstance(entry["registry_version"], str)
                or SEMVER.fullmatch(entry["registry_version"]) is None
            ):
                errors.append(f"ARTIFACT_SCHEMA_EXTERNAL_VERSION {schema_id}")
            attestation = attestation_map.get(entry["registry_attestation_id"])
            if attestation is None:
                errors.append(f"ARTIFACT_SCHEMA_ATTESTATION_UNKNOWN {schema_id}")
            elif (
                attestation.get("registry_id") != entry["registry_id"]
                or attestation.get("registry_version") != entry["registry_version"]
            ):
                errors.append(f"ARTIFACT_SCHEMA_ATTESTATION_BINDING {schema_id}")
        else:
            errors.append(f"ARTIFACT_SCHEMA_STATUS {schema_id}:{status}")

    for attestation in registry["schema_attestations"]:
        attestation_id = attestation["id"]
        if set(attestation) != SCHEMA_ATTESTATION_FIELDS:
            errors.append(f"SCHEMA_ATTESTATION_SHAPE {attestation_id}")
            continue
        for field in ("id", "registry_id", "issuer_authority_id", "trust_store_id"):
            if IDENTIFIER.fullmatch(attestation[field]) is None:
                errors.append(f"SCHEMA_ATTESTATION_FIELD {attestation_id}:{field}")
        if SEMVER.fullmatch(attestation["registry_version"]) is None:
            errors.append(f"SCHEMA_ATTESTATION_VERSION {attestation_id}")
        if not _canonical_https_uri(attestation["attestation_uri"]):
            errors.append(f"SCHEMA_ATTESTATION_URI {attestation_id}")
        if re.fullmatch(r"[0-9a-f]{64}", attestation["binding_set_digest"]) is None:
            errors.append(f"SCHEMA_ATTESTATION_DIGEST_FORMAT {attestation_id}")
        elif attestation["binding_set_digest"] != _external_binding_set_digest(
            registry["artifact_schemas"], attestation_id
        ):
            errors.append(f"SCHEMA_ATTESTATION_BINDING_SET_DIGEST {attestation_id}")
        authority = authority_map.get(attestation["issuer_authority_id"])
        if authority is None:
            errors.append(f"SCHEMA_ATTESTATION_AUTHORITY_UNKNOWN {attestation_id}")
        elif (
            authority.get("kind") != "external_schema_registry"
            or authority.get("trust_store_id") != attestation["trust_store_id"]
        ):
            errors.append(f"SCHEMA_ATTESTATION_TRUST_MISMATCH {attestation_id}")
        if attestation["signature_policy_id"] not in crypto_ids:
            errors.append(f"SCHEMA_ATTESTATION_CRYPTO_UNKNOWN {attestation_id}")
        if attestation["verification_mode"] != "runtime_required":
            errors.append(f"SCHEMA_ATTESTATION_VERIFICATION_MODE {attestation_id}")
        if attestation["design_time_status"] != "unverified":
            errors.append(f"SCHEMA_ATTESTATION_DESIGN_STATUS {attestation_id}")
        if not any(
            entry.get("registry_attestation_id") == attestation_id
            for entry in registry["artifact_schemas"]
        ):
            errors.append(f"SCHEMA_ATTESTATION_UNUSED {attestation_id}")

    referenced_attestations = {
        entry["registry_attestation_id"]
        for entry in registry["artifact_schemas"]
        if entry.get("status") == "external_registered"
        and isinstance(entry.get("registry_attestation_id"), str)
    }
    for attestation_id in sorted(referenced_attestations - attestation_ids):
        errors.append(f"SCHEMA_ATTESTATION_UNREGISTERED {attestation_id}")

    referenced_assertions: set[str] = set()
    referenced_predicates: set[str] = set()
    referenced_schemas: set[str] = set()
    referenced_authorities: dict[str, set[str]] = defaultdict(set)
    all_steps = {
        step["step_id"]: step for package in packages for step in package["lifecycle"]["steps"]
    }

    for package in packages:
        trust = package["trust"]
        if trust["signature_policy_id"] not in crypto_ids:
            errors.append(
                f"CRYPTO_POLICY_UNKNOWN {package['skill']['id']}:{trust['signature_policy_id']}"
            )
        if trust["signature_policy_id"] != PACKAGE_SIGNATURE_POLICY_ID:
            errors.append(
                "PACKAGE_SIGNATURE_POLICY_BINDING "
                f"{package['skill']['id']}:{trust['signature_policy_id']}"
            )
        for artifact in package["artifact_catalog"]:
            referenced_schemas.add(artifact["schema_id"])
        for field in (
            "trust_proof_schema",
            "delivery_receipt_schema",
            "fragment_schema",
            "index_schema",
        ):
            referenced_schemas.add(package["evidence"][field])
        for step in package["lifecycle"]["steps"]:
            referenced_assertions.update(step["preconditions"])
            for values in step["exit_assertions_by_outcome"].values():
                referenced_assertions.update(values)
            if step["owner"] == "guard":
                algorithm_id = step.get("algorithm_id")
                if algorithm_id not in algorithm_ids:
                    errors.append(f"GUARD_ALGORITHM_UNKNOWN {step['step_id']}:{algorithm_id}")
            for item in step["inputs"]:
                for producer_id in item["source"]["producer_step_ids"]:
                    if (
                        producer_id.startswith("guard.")
                        and producer_id not in all_steps
                        and producer_id not in algorithm_ids
                    ):
                        errors.append(f"SOURCE_ALGORITHM_UNKNOWN {step['step_id']}:{producer_id}")
        for route in package["lifecycle"]["routes"]:
            for fact_id, value in route["facts"].items():
                if fact_id not in fact_ids:
                    errors.append(f"ROUTE_FACT_UNKNOWN {route['route_id']}:{fact_id}")
                elif fact_id != "outcome" and value not in facts[fact_id]:
                    errors.append(f"ROUTE_FACT_VALUE {route['route_id']}:{fact_id}:{value}")
        for criterion in package["acceptance"]["criteria"]:
            verifier = criterion["verifier"]
            referenced_authorities[criterion["assertion_id"]].add(verifier)
            referenced_assertions.add(criterion["assertion_id"])
            referenced_assertions.add(criterion["not_applicable_assertion_id"])
            referenced_predicates.add(criterion["applicability_predicate"])
            referenced_schemas.update(criterion["evidence_schema_ids"])
            if verifier not in authority_ids:
                errors.append(f"VERIFIER_AUTHORITY_UNKNOWN {criterion['id']}:{verifier}")

    for transition in system["transitions"]:
        for condition in transition.get("when", []):
            fact_id = condition["fact_id"]
            if fact_id not in fact_ids:
                errors.append(f"SYSTEM_FACT_UNKNOWN {transition['transition_id']}:{fact_id}")
            elif condition["value"] not in facts[fact_id]:
                errors.append(f"SYSTEM_FACT_VALUE {transition['transition_id']}:{fact_id}")
    for suspension in system["suspensions"]:
        referenced_schemas.add(suspension["question_schema_id"])
        referenced_schemas.add(suspension["response_schema_id"])
    system_acceptance_criteria = system["acceptance"]["criteria"]
    acceptance_transition_criteria = [
        criterion for criterion in system_acceptance_criteria if criterion["id"] == "SYS-AC-12"
    ]
    if len(acceptance_transition_criteria) != 1 or any(
        criterion.get("assertion_id") != ACCEPTANCE_ASSERTION_ID
        or criterion.get("verifier_authority_id") != ACCEPTANCE_AUTHORITY_ID
        for criterion in acceptance_transition_criteria
    ):
        errors.append("SYSTEM_ACCEPTANCE_BINDING SYS-AC-12")
    for criterion in system_acceptance_criteria:
        authority = criterion["verifier_authority_id"]
        referenced_assertions.add(criterion["assertion_id"])
        referenced_predicates.add(criterion["applicability_predicate"])
        referenced_authorities[criterion["assertion_id"]].add(authority)
        if authority not in authority_ids:
            errors.append(f"SYSTEM_VERIFIER_UNKNOWN {criterion['id']}:{authority}")

    for assertion_id in sorted(referenced_assertions - assertion_ids):
        errors.append(f"ASSERTION_UNREGISTERED {assertion_id}")
    for predicate_id in sorted(referenced_predicates - predicate_ids):
        errors.append(f"PREDICATE_UNREGISTERED {predicate_id}")
    for schema_id in sorted(referenced_schemas - schema_ids):
        errors.append(f"ARTIFACT_SCHEMA_UNREGISTERED {schema_id}")
    for assertion_id, authorities in referenced_authorities.items():
        registered = set(assertion_map.get(assertion_id, {}).get("authority_ids", []))
        if not authorities <= registered:
            errors.append(
                f"ASSERTION_AUTHORITY_MISMATCH {assertion_id}:{sorted(authorities - registered)}"
            )
    for entry in registry["predicates"] + registry["assertions"]:
        if entry["algorithm_id"] not in algorithm_ids:
            errors.append(f"REGISTRY_ALGORITHM_UNKNOWN {entry['id']}:{entry['algorithm_id']}")
    for assertion in registry["assertions"]:
        unknown = set(assertion["authority_ids"]) - authority_ids
        if unknown:
            errors.append(f"REGISTRY_AUTHORITY_UNKNOWN {assertion['id']}:{sorted(unknown)}")
    if "provider-delivery-signature.v1" not in crypto_ids:
        errors.append("PROVIDER_ATTESTATION_CRYPTO_POLICY_MISSING")
    return errors


def run_registry_negative_probe(
    packages: list[dict[str, Any]],
    system: dict[str, Any],
    registry: dict[str, Any],
    design_root: Path,
    schema_documents: dict[str, dict[str, Any]],
    input_file_digests: dict[str, str],
) -> list[str]:
    def run_check(
        registry_value: dict[str, Any],
        *,
        packages_value: list[dict[str, Any]] = packages,
        system_value: dict[str, Any] = system,
    ) -> list[str]:
        return check_registry(
            packages_value,
            system_value,
            registry_value,
            design_root,
            schema_documents,
            input_file_digests,
        )

    mutated = copy.deepcopy(registry)
    target = packages[0]["acceptance"]["criteria"][0]["assertion_id"]
    mutated["assertions"] = [entry for entry in mutated["assertions"] if entry["id"] != target]
    errors = run_check(mutated)
    if not any(error == f"ASSERTION_UNREGISTERED {target}" for error in errors):
        return ["NEGATIVE_PROBE missed registry assertion deletion"]

    failures: list[str] = []
    invalid_status = copy.deepcopy(registry)
    invalid_status["artifact_schemas"][0]["status"] = "trusted"
    if not any(error.startswith("ARTIFACT_SCHEMA_STATUS") for error in run_check(invalid_status)):
        failures.append("NEGATIVE_PROBE missed artifact schema status")

    missing_binding = copy.deepcopy(registry)
    external = next(
        entry
        for entry in missing_binding["artifact_schemas"]
        if entry["status"] == "external_registered"
    )
    del external["registry_version"]
    if not any(
        error.startswith("ARTIFACT_SCHEMA_BINDING_SHAPE") for error in run_check(missing_binding)
    ):
        failures.append("NEGATIVE_PROBE missed external schema binding field")

    bad_digest = copy.deepcopy(registry)
    defined = next(
        entry for entry in bad_digest["artifact_schemas"] if entry["status"] == "defined"
    )
    defined["file_sha256"] = "0" * 64
    if not any(error.startswith("ARTIFACT_SCHEMA_DIGEST") for error in run_check(bad_digest)):
        failures.append("NEGATIVE_PROBE missed local schema digest")

    bad_fragment = copy.deepcopy(registry)
    fragmented = next(
        entry
        for entry in bad_fragment["artifact_schemas"]
        if entry["status"] == "defined" and entry["fragment"] != "#"
    )
    fragmented["fragment"] = "#/$defs/missing"
    if not any(error.startswith("ARTIFACT_SCHEMA_FRAGMENT") for error in run_check(bad_fragment)):
        failures.append("NEGATIVE_PROBE missed local schema fragment")

    wrong_schema = copy.deepcopy(registry)
    delivery = next(
        entry
        for entry in wrong_schema["artifact_schemas"]
        if entry["id"] == "artifact.delivery_receipt.v2"
    )
    question = next(
        entry
        for entry in wrong_schema["artifact_schemas"]
        if entry["id"] == "artifact.question_set.v2"
    )
    for field in ("schema_path", "fragment", "file_sha256"):
        delivery[field] = question[field]
    if not any(error.startswith("ARTIFACT_SCHEMA_IDENTITY") for error in run_check(wrong_schema)):
        failures.append("NEGATIVE_PROBE missed local schema identity mismatch")

    duplicate_location = copy.deepcopy(registry)
    collection = next(
        entry
        for entry in duplicate_location["artifact_schemas"]
        if entry["id"] == "artifact.artifact_collection_ref.v1"
    )
    artifact_ref = next(
        entry
        for entry in duplicate_location["artifact_schemas"]
        if entry["id"] == "artifact.artifact_ref.v1"
    )
    collection["fragment"] = artifact_ref["fragment"]
    if not any(
        error.startswith("ARTIFACT_SCHEMA_LOCATION_DUPLICATE")
        for error in run_check(duplicate_location)
    ):
        failures.append("NEGATIVE_PROBE missed duplicate local schema location")

    invalid_uris = (
        "https://",
        "https://schemas.opencode.local/runtime/\x00schema.json",
        "https://user@schemas.opencode.local/runtime/schema.json",
        "https://schemas.opencode.local/runtime/schema.json?revision=1",
        "https://schemas.opencode.local/runtime/schema.json#fragment",
        "https://schemas.opencode.local/runtime/schema.json?",
        "https://schemas.opencode.local/runtime/schema.json#",
        "https://schemas.opencode.local/runtime/schema.json?#",
        "HTTPS://schemas.opencode.local/runtime/schema.json",
        "Https://schemas.opencode.local/runtime/schema.json",
        "https://schemas.opencode.local/runtime/../schema.json",
        "https://schemas.opencode.local/runtime/%73chema.json",
        "https://schemas.opencode.local/runtime/schema name.json",
        "https://schemas.opencode.local/runtime/<schema.json",
    )
    for invalid_uri in invalid_uris:
        bad_uri = copy.deepcopy(registry)
        external = next(
            entry
            for entry in bad_uri["artifact_schemas"]
            if entry["status"] == "external_registered"
        )
        external["schema_uri"] = invalid_uri
        _refresh_binding_set_digest(bad_uri, external)
        if not any(error.startswith("ARTIFACT_SCHEMA_URI") for error in run_check(bad_uri)):
            failures.append(
                f"NEGATIVE_PROBE missed non-canonical external schema URI {invalid_uri}"
            )

    duplicate_schema_uri = copy.deepcopy(registry)
    external = next(
        entry
        for entry in duplicate_schema_uri["artifact_schemas"]
        if entry["status"] == "external_registered"
    )
    defined = next(
        entry for entry in duplicate_schema_uri["artifact_schemas"] if entry["status"] == "defined"
    )
    external["schema_uri"] = defined["schema_uri"]
    _refresh_binding_set_digest(duplicate_schema_uri, external)
    if not any(
        error.startswith("ARTIFACT_SCHEMA_URI_DUPLICATE")
        for error in run_check(duplicate_schema_uri)
    ):
        failures.append("NEGATIVE_PROBE missed cross-status schema URI duplicate")

    blank_version = copy.deepcopy(registry)
    external = next(
        entry
        for entry in blank_version["artifact_schemas"]
        if entry["status"] == "external_registered"
    )
    external["registry_version"] = " "
    if not any(
        error.startswith("ARTIFACT_SCHEMA_EXTERNAL_VERSION") for error in run_check(blank_version)
    ):
        failures.append("NEGATIVE_PROBE missed blank external registry version")

    blank_attestation = copy.deepcopy(registry)
    external = next(
        entry
        for entry in blank_attestation["artifact_schemas"]
        if entry["status"] == "external_registered"
    )
    external["registry_attestation_id"] = " "
    if not any(
        error.startswith("ARTIFACT_SCHEMA_EXTERNAL_FIELD") for error in run_check(blank_attestation)
    ):
        failures.append("NEGATIVE_PROBE missed blank external attestation id")

    unknown_attestation = copy.deepcopy(registry)
    external = next(
        entry
        for entry in unknown_attestation["artifact_schemas"]
        if entry["status"] == "external_registered"
    )
    external["registry_attestation_id"] = "unknown-attestation"
    if not any(
        error.startswith("ARTIFACT_SCHEMA_ATTESTATION_UNKNOWN")
        for error in run_check(unknown_attestation)
    ):
        failures.append("NEGATIVE_PROBE missed unknown schema attestation")

    bad_attestation_digest = copy.deepcopy(registry)
    bad_attestation_digest["schema_attestations"][0]["binding_set_digest"] = "0" * 64
    if not any(
        error.startswith("SCHEMA_ATTESTATION_BINDING_SET_DIGEST")
        for error in run_check(bad_attestation_digest)
    ):
        failures.append("NEGATIVE_PROBE missed schema attestation binding digest")

    attestation_mutations = (
        (
            "issuer_authority_id",
            "guard",
            "SCHEMA_ATTESTATION_TRUST_MISMATCH",
            "schema attestation issuer authority",
        ),
        (
            "signature_policy_id",
            "unknown-signature-policy",
            "SCHEMA_ATTESTATION_CRYPTO_UNKNOWN",
            "schema attestation signature policy",
        ),
        (
            "trust_store_id",
            "unknown-trust-store",
            "SCHEMA_ATTESTATION_TRUST_MISMATCH",
            "schema attestation trust store",
        ),
    )
    for field, value, prefix, name in attestation_mutations:
        mutation = copy.deepcopy(registry)
        mutation["schema_attestations"][0][field] = value
        if not any(error.startswith(prefix) for error in run_check(mutation)):
            failures.append(f"NEGATIVE_PROBE missed {name}")

    crypto_mutations = (
        ("hash_algorithm", "md5", "crypto hash algorithm"),
        ("signature_algorithm", "none", "crypto signature algorithm"),
    )
    for field, value, name in crypto_mutations:
        mutation = copy.deepcopy(registry)
        policy = next(
            entry
            for entry in mutation["crypto_policies"]
            if entry["id"] == "skill-signature-ed25519.v1"
        )
        policy[field] = value
        if not any(error.startswith("CRYPTO_POLICY_CONTROL") for error in run_check(mutation)):
            failures.append(f"NEGATIVE_PROBE missed {name}")

    weak_acceptance_authority = copy.deepcopy(registry)
    authority = next(
        entry
        for entry in weak_acceptance_authority["authorities"]
        if entry["id"] == "guard.acceptance"
    )
    authority["kind"] = "advisory"
    if not any(
        error.startswith("ACCEPTANCE_AUTHORITY_CONTROL")
        for error in run_check(weak_acceptance_authority)
    ):
        failures.append("NEGATIVE_PROBE missed guard acceptance authority weakening")

    for wrong_policy_id in (
        "provider-delivery-signature.v1",
        "schema-registry-signature-ed25519.v1",
    ):
        wrong_policy_packages = copy.deepcopy(packages)
        wrong_policy_packages[0]["trust"]["signature_policy_id"] = wrong_policy_id
        if not any(
            error.startswith("PACKAGE_SIGNATURE_POLICY_BINDING")
            for error in run_check(registry, packages_value=wrong_policy_packages)
        ):
            failures.append(f"NEGATIVE_PROBE missed package policy binding {wrong_policy_id}")

    weak_policy_registry = copy.deepcopy(registry)
    weak_policy_id = "skill-signature-weak.v1"
    weak_policy_registry["crypto_policies"].append(
        {
            "id": weak_policy_id,
            "canonicalization": "rfc8785-jcs",
            "hash_algorithm": "md5",
            "signature_algorithm": "none",
            "domain": "opencode.skill-manifest-signature.v1",
        }
    )
    weak_policy_packages = copy.deepcopy(packages)
    weak_policy_packages[0]["trust"]["signature_policy_id"] = weak_policy_id
    if not any(
        error.startswith("PACKAGE_SIGNATURE_POLICY_BINDING")
        for error in run_check(
            weak_policy_registry,
            packages_value=weak_policy_packages,
        )
    ):
        failures.append("NEGATIVE_PROBE missed registered weak package policy binding")

    wrong_acceptance_registry = copy.deepcopy(registry)
    acceptance_assertion = next(
        entry
        for entry in wrong_acceptance_registry["assertions"]
        if entry["id"] == ACCEPTANCE_ASSERTION_ID
    )
    acceptance_assertion["authority_ids"] = ["guard.validator"]
    wrong_acceptance_system = copy.deepcopy(system)
    acceptance_criterion = next(
        entry
        for entry in wrong_acceptance_system["acceptance"]["criteria"]
        if entry["id"] == "SYS-AC-12"
    )
    acceptance_criterion["verifier_authority_id"] = "guard.validator"
    wrong_acceptance_errors = run_check(
        wrong_acceptance_registry,
        system_value=wrong_acceptance_system,
    )
    if not any(
        error.startswith("ACCEPTANCE_ASSERTION_AUTHORITY_BINDING")
        for error in wrong_acceptance_errors
    ) or not any(
        error.startswith("SYSTEM_ACCEPTANCE_BINDING") for error in wrong_acceptance_errors
    ):
        failures.append("NEGATIVE_PROBE missed acceptance authority domain binding")
    return failures
