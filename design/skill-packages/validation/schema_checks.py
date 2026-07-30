from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from model import check_schema_keywords, resolve_local_ref, validate_json_schema


def _artifact_ref() -> dict[str, Any]:
    digest = "0" * 64
    return {
        "artifact_id": "artifact-1",
        "schema_id": "artifact.request.v1",
        "producer_step_id": "external.control",
        "producer_owner": "external_control",
        "revision": 1,
        "digest": digest,
        "evidence_index_id": "evidence-1",
        "evidence_index_revision": 1,
        "validity_digest": digest,
        "frozen_at": "2026-07-20T00:00:00Z",
    }


def _defined_schema(
    schema_id: str,
    schemas: dict[str, dict[str, Any]],
    registry: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    bindings = [
        entry
        for entry in registry["artifact_schemas"]
        if entry["id"] == schema_id and entry["status"] == "defined"
    ]
    if len(bindings) != 1:
        raise ValueError(f"expected one defined schema binding: {schema_id}")
    binding = bindings[0]
    document = schemas[Path(binding["schema_path"]).name]
    target = (
        document if binding["fragment"] == "#" else resolve_local_ref(document, binding["fragment"])
    )
    return target, document


def _examples(
    schemas: dict[str, dict[str, Any]], registry: dict[str, Any]
) -> list[tuple[str, Any, dict[str, Any], dict[str, Any]]]:
    digest = "0" * 64
    artifact_ref_schema = _defined_schema("artifact.artifact_ref.v1", schemas, registry)
    collection_schema = _defined_schema("artifact.artifact_collection_ref.v1", schemas, registry)
    receipt_schema = _defined_schema("artifact.delivery_receipt.v2", schemas, registry)
    manifest_schema = _defined_schema("package-manifest.v2", schemas, registry)
    question_schema = _defined_schema("artifact.question_set.v2", schemas, registry)
    return [
        ("artifact_ref", _artifact_ref(), *artifact_ref_schema),
        (
            "artifact_collection_ref",
            {
                "collection_id": "collection-1",
                "schema_id": "artifact.review_fragment_collection.v1",
                "revision": 1,
                "digest": digest,
                "index_keys": ["review-1", "correctness", "1"],
                "member_refs": [_artifact_ref()],
                "evidence_index_id": "evidence-1",
                "evidence_index_revision": 1,
                "frozen_at": "2026-07-20T00:00:00Z",
            },
            *collection_schema,
        ),
        (
            "delivery_receipt",
            {
                "invocation_digest": digest,
                "rendered_context_digest": digest,
                "message_sequence_digest": digest,
                "tool_schema_digest": digest,
                "delivered_bytes": 128,
                "estimated_tokens": 32,
                "budget": 1024,
                "provider_id": "provider-1",
                "provider_build": "build-1",
                "session_id": "session-1",
                "request_nonce": "nonce-1",
                "truncation": False,
                "provider_attestation": {
                    "payload_type": "provider-delivery.v1",
                    "payload_hash_algorithm": "sha256",
                    "payload_hash": digest,
                    "signature_algorithm": "ed25519",
                    "issuer_key_id": "key-1",
                    "signature": "signature",
                    "issued_at": "2026-07-20T00:00:00Z",
                    "expires_at": "2026-07-20T01:00:00Z",
                },
                "delivered_at": "2026-07-20T00:00:00Z",
            },
            *receipt_schema,
        ),
        (
            "package_manifest",
            {
                "unsigned_manifest": {
                    "schema": "package-manifest.v2",
                    "skill_id": "requirements-contract",
                    "skill_version": "3.3.0",
                    "contract_schema": "skill-contract.v3",
                    "canonicalization_policy_id": "bundle-canonical-windows.v1",
                    "files": [
                        {
                            "normalized_relative_path": "SKILL.md",
                            "role": "entrypoint",
                            "byte_length": 1,
                            "sha256": digest,
                        },
                        {
                            "normalized_relative_path": "contract.json",
                            "role": "contract",
                            "byte_length": 1,
                            "sha256": digest,
                        },
                    ],
                    "installer_id": "installer-1",
                    "installed_at": "2026-07-20T00:00:00Z",
                },
                "signature_envelope": {
                    "payload_type": "package-manifest.v2",
                    "payload_hash_algorithm": "sha256",
                    "payload_hash": digest,
                    "signature_algorithm": "ed25519",
                    "key_id": "key-1",
                    "signature": "signature",
                    "signed_at": "2026-07-20T00:00:00Z",
                },
            },
            *manifest_schema,
        ),
        (
            "question_set",
            {
                "question_set_id": "questions-1",
                "revision": 1,
                "origin_step_id": "planning.requirements.analyze",
                "origin_profile_id": "standard",
                "resume_token": "a" * 32,
                "frozen_input_set_revision": 1,
                "questions": [
                    {"id": "q1", "class": "must_clarify", "owner": "user", "status": "open"}
                ],
                "issued_at": "2026-07-20T00:00:00Z",
                "expires_at": "2026-07-21T00:00:00Z",
            },
            *question_schema,
        ),
    ]


def check_schema_documents(
    schemas: dict[str, dict[str, Any]], registry: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    for name, schema in schemas.items():
        errors.extend(f"{name} {error}" for error in check_schema_keywords(schema))
    for name, value, schema, root_schema in _examples(schemas, registry):
        errors.extend(
            f"SCHEMA_EXAMPLE {name} {error}"
            for error in validate_json_schema(value, schema, root_schema=root_schema)
        )
    return errors


def run_schema_negative_probes(
    schemas: dict[str, dict[str, Any]], registry: dict[str, Any], system: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    examples = {
        name: (value, schema, root_schema)
        for name, value, schema, root_schema in _examples(schemas, registry)
    }

    mutations: list[tuple[str, Any, dict[str, Any], dict[str, Any]]] = []
    artifact_ref = copy.deepcopy(examples["artifact_ref"][0])
    del artifact_ref["revision"]
    mutations.append(("artifact_ref_missing_revision", artifact_ref, *examples["artifact_ref"][1:]))

    collection = copy.deepcopy(examples["artifact_collection_ref"][0])
    del collection["member_refs"][0]["digest"]
    mutations.append(
        (
            "collection_member_missing_digest",
            collection,
            *examples["artifact_collection_ref"][1:],
        )
    )

    receipt = copy.deepcopy(examples["delivery_receipt"][0])
    receipt["truncation"] = True
    mutations.append(("delivery_truncated", receipt, *examples["delivery_receipt"][1:]))

    manifest = copy.deepcopy(examples["package_manifest"][0])
    manifest["unsigned_manifest"]["manifest_hash"] = "0" * 64
    mutations.append(("manifest_self_reference", manifest, *examples["package_manifest"][1:]))

    question_set = copy.deepcopy(examples["question_set"][0])
    question_set["origin_step_id"] = "planning.requirements.missing"
    mutations.append(("question_origin_invalid", question_set, *examples["question_set"][1:]))

    for name, value, schema, root_schema in mutations:
        if not validate_json_schema(value, schema, root_schema=root_schema):
            failures.append(f"NEGATIVE_PROBE missed {name}")

    wrong_binding = copy.deepcopy(registry)
    delivery_binding = next(
        entry
        for entry in wrong_binding["artifact_schemas"]
        if entry["id"] == "artifact.delivery_receipt.v2"
    )
    question_binding = next(
        entry
        for entry in wrong_binding["artifact_schemas"]
        if entry["id"] == "artifact.question_set.v2"
    )
    delivery_binding["schema_path"] = question_binding["schema_path"]
    delivery_binding["fragment"] = question_binding["fragment"]
    wrong_receipt = next(
        item for item in _examples(schemas, wrong_binding) if item[0] == "delivery_receipt"
    )
    if not validate_json_schema(wrong_receipt[1], wrong_receipt[2], root_schema=wrong_receipt[3]):
        failures.append("NEGATIVE_PROBE missed registry-driven schema mismatch")

    if not check_schema_keywords({"type": "string", "minLength": 1}):
        failures.append("NEGATIVE_PROBE missed unsupported schema keyword")

    lifecycle_schema = schemas["system-lifecycle.v1.schema.json"]
    lifecycle_mutations: list[tuple[str, dict[str, Any]]] = []
    double_source = copy.deepcopy(system)
    transition = next(
        item
        for item in double_source["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    transition.update({"from_step_id": "review.handoff.final", "terminal_outcome": "completed"})
    lifecycle_mutations.append(("system_transition_double_source", double_source))
    missing_source = copy.deepcopy(system)
    transition = next(
        item
        for item in missing_source["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    del transition["from_node_id"]
    del transition["event_id"]
    lifecycle_mutations.append(("system_transition_missing_source", missing_source))
    double_target = copy.deepcopy(system)
    transition = next(
        item
        for item in double_target["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    transition["next_node_id"] = "system.awaiting_acceptance"
    lifecycle_mutations.append(("system_transition_double_target", double_target))
    missing_target = copy.deepcopy(system)
    transition = next(
        item
        for item in missing_target["transitions"]
        if item["transition_id"] == "acceptance-request"
    )
    del transition["next_step_id"]
    lifecycle_mutations.append(("system_transition_missing_target", missing_target))
    for name, mutation in lifecycle_mutations:
        if not validate_json_schema(mutation, lifecycle_schema):
            failures.append(f"NEGATIVE_PROBE missed {name}")
    return failures
