from __future__ import annotations

import json
from typing import Any

from ..contracts import (
    PlanningStep,
    ReviewGate,
    RunRecord,
    Stage,
    normalize_packet,
    normalize_plan_approval_receipt,
    normalize_planning_artifact,
    normalize_planning_review_receipt,
    packet_digest,
    planning_artifact_digest,
)
from ..errors import GuardError
from ..integrity import MAX_PERSISTED_JSON_BYTES, canonical_json, digest_json
from .database import (
    Database,
    append_event,
    check_revision,
    run_from_row,
    select_run,
    utc_now,
)

_APPROVAL_RECEIPT_FIELDS = (
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
)
_PLANNING_REVIEW_RECEIPT_FIELDS = (
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
)


class ExecutionRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def submit_packet(
        self,
        run_id: str,
        *,
        expected_revision: int,
        packet: dict[str, Any],
        digest: str,
    ) -> RunRecord:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            stage = str(row["stage"])
            current_digest = str(row["packet_digest"])
            first = stage == Stage.PLANNING.value and not current_digest
            revising = stage in {Stage.IMPLEMENTING.value, Stage.REVIEW_REQUIRED.value} and bool(
                current_digest
            )
            if not row["task"] or not (first or revising):
                raise GuardError(
                    "PACKET_NOT_ALLOWED",
                    "Packet submission is not allowed in the current Run state.",
                )
            if connection.execute(
                "SELECT 1 FROM write_leases WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise GuardError("WRITE_LEASE_PENDING", "Complete the pending write first.")
            if current_digest == digest:
                raise GuardError("PACKET_UNCHANGED", "Development packet is unchanged.")
            phases = packet["phases"]
            created_at = utc_now()
            if first:
                self._insert_artifact(connection, run_id, 1, packet, digest, created_at)
                self._replace_phases(connection, run_id, phases, created_at)
                first_phase = str(phases[0]["id"])
                connection.execute(
                    """
                    UPDATE runs
                    SET packet_digest = ?, active_phase = ?, evidence_digest = ''
                    WHERE id = ?
                    """,
                    (digest, first_phase, run_id),
                )
                append_event(
                    connection,
                    run_id,
                    event="PACKET_FROZEN",
                    actor="model",
                    payload={
                        "version": 1,
                        "digest": digest,
                        "phases": [phase["id"] for phase in phases],
                        "scope_digest": digest_json(_scope_declarations(packet)),
                    },
                    after_stage=Stage.IMPLEMENTING,
                )
                return run_from_row(select_run(connection, run_id))

            current = connection.execute(
                """
                SELECT * FROM artifacts
                WHERE run_id = ? AND kind = 'packet' AND digest = ?
                """,
                (run_id, current_digest),
            ).fetchone()
            if current is None:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN",
                    "Current packet pointer has no artifact.",
                )
            current_packet = json.loads(str(current["body_json"]))
            current_version = int(current["version"])
            next_version = current_version + 1
            if connection.execute(
                """
                SELECT 1 FROM artifacts
                WHERE run_id = ? AND kind = 'packet' AND (version = ? OR digest = ?)
                """,
                (run_id, next_version, digest),
            ).fetchone():
                raise GuardError(
                    "PERSISTED_STATE_BROKEN",
                    "Packet version or digest already exists.",
                )
            added_paths, removed_paths = _scope_delta(current_packet, packet)
            approval_seq = _consume_scope_approval(
                connection,
                run_id,
                base_digest=current_digest,
                candidate_digest=digest,
                added_paths=added_paths,
            )
            retired_phases = _phase_snapshot(connection, run_id)
            payload = {
                "from_version": current_version,
                "to_version": next_version,
                "from_digest": current_digest,
                "to_digest": digest,
                "retired_active_phase": str(row["active_phase"]),
                "retired_phases": retired_phases,
                "retired_phases_digest": digest_json(retired_phases),
                "phases": [phase["id"] for phase in phases],
                "scope_digest": digest_json(_scope_declarations(packet)),
                "added_paths": added_paths,
                "removed_paths": removed_paths,
                "approval_event_seq": approval_seq,
            }
            if len(canonical_json(payload).encode("utf-8")) > MAX_PERSISTED_JSON_BYTES:
                raise GuardError(
                    "PACKET_TOO_LARGE",
                    "Packet revision event exceeds 512 KiB.",
                    component="packet_revision_event",
                )
            self._insert_artifact(
                connection,
                run_id,
                next_version,
                packet,
                digest,
                created_at,
            )
            self._replace_phases(connection, run_id, phases, created_at)
            first_phase = str(phases[0]["id"])
            connection.execute(
                """
                UPDATE runs
                SET packet_digest = ?, active_phase = ?, evidence_digest = ''
                WHERE id = ?
                """,
                (digest, first_phase, run_id),
            )
            append_event(
                connection,
                run_id,
                event="PACKET_REVISED",
                actor="model",
                payload=payload,
                after_stage=Stage.IMPLEMENTING,
            )
            return run_from_row(select_run(connection, run_id))

    def approve_plan(
        self,
        run_id: str,
        *,
        expected_revision: int,
        base_packet_digest: str,
        candidate_packet_digest: str,
        added_paths: list[str],
        approved_by: str,
    ) -> RunRecord:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            if row["stage"] not in {Stage.IMPLEMENTING.value, Stage.REVIEW_REQUIRED.value}:
                raise GuardError("PACKET_NOT_ALLOWED", "Plan approval is not allowed now.")
            if connection.execute(
                "SELECT 1 FROM write_leases WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise GuardError("WRITE_LEASE_PENDING", "Complete the pending write first.")
            if (
                not _digest(candidate_packet_digest)
                or candidate_packet_digest == base_packet_digest
                or not added_paths
                or added_paths != sorted(set(added_paths))
                or any(not _valid_scope_declaration(path) for path in added_paths)
            ):
                raise GuardError("INVALID_PLAN_APPROVAL", "Plan approval fields are invalid.")
            approved = approved_by.strip()
            if not approved or "\x00" in approved or len(approved) > 200:
                raise GuardError("INVALID_PLAN_APPROVAL", "Plan approver must be bounded text.")
            paths_digest = digest_json(added_paths)
            existing = _approval_events(connection, run_id)
            exact = next(
                (
                    event
                    for event in existing
                    if event["payload"].get("base_packet_digest") == base_packet_digest
                    and event["payload"].get("candidate_packet_digest") == candidate_packet_digest
                    and event["payload"].get("added_paths") == added_paths
                    and event["payload"].get("added_paths_digest") == paths_digest
                ),
                None,
            )
            consumed = _consumed_approval_seqs(connection, run_id)
            if exact is not None:
                if exact["seq"] in consumed:
                    raise GuardError(
                        "PLAN_SCOPE_APPROVAL_CONSUMED",
                        "Plan approval was already consumed.",
                        approval_event_seq=exact["seq"],
                    )
                if row["packet_digest"] != base_packet_digest:
                    raise GuardError(
                        "PLAN_SCOPE_APPROVAL_MISMATCH",
                        "Plan approval base packet is not current.",
                        mismatch="base_packet_digest",
                    )
                return run_from_row(row)
            if row["packet_digest"] != base_packet_digest:
                raise GuardError(
                    "PLAN_SCOPE_APPROVAL_MISMATCH",
                    "Plan approval base packet is not current.",
                    mismatch="base_packet_digest",
                )
            append_event(
                connection,
                run_id,
                event="PLAN_SCOPE_APPROVED",
                actor="authority",
                payload={
                    "base_packet_digest": base_packet_digest,
                    "candidate_packet_digest": candidate_packet_digest,
                    "added_paths": added_paths,
                    "added_paths_digest": paths_digest,
                    "approved_by": approved,
                },
            )
            return run_from_row(select_run(connection, run_id))

    def get_plan_approval(
        self,
        run_id: str,
        *,
        base_packet_digest: str,
        candidate_packet_digest: str,
        added_paths: list[str],
    ) -> dict[str, Any]:
        with self.database.connect(readonly=True) as connection:
            select_run(connection, run_id)
            paths_digest = digest_json(added_paths)
            approval = next(
                (
                    event
                    for event in _approval_events(connection, run_id)
                    if event["payload"].get("base_packet_digest") == base_packet_digest
                    and event["payload"].get("candidate_packet_digest") == candidate_packet_digest
                    and event["payload"].get("added_paths") == added_paths
                    and event["payload"].get("added_paths_digest") == paths_digest
                ),
                None,
            )
            if approval is None:
                raise GuardError(
                    "PERSISTED_STATE_BROKEN",
                    "Plan approval event is missing after approval.",
                )
            consumed = int(approval["seq"]) in _consumed_approval_seqs(connection, run_id)
        return {
            "approval_event_seq": int(approval["seq"]),
            **approval["payload"],
            "consumed": consumed,
        }

    def store_planning_artifact(
        self,
        run_id: str,
        *,
        expected_revision: int,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        artifact = normalize_planning_artifact(body)
        expected_state = {
            "BASELINE": (PlanningStep.BASELINE_REVIEW_REQUIRED, ReviewGate.BASELINE),
            "SPEC": (PlanningStep.SPEC_REVIEW_REQUIRED, ReviewGate.SPEC),
            "PLAN": (PlanningStep.PLAN_REVIEW_REQUIRED, ReviewGate.PLAN),
        }[artifact["kind"]]
        expected_predecessor = {
            "BASELINE": (None, ()),
            "SPEC": (
                (PlanningStep.BASELINE_REVIEW_REQUIRED, ReviewGate.BASELINE),
                ("BASELINE",),
            ),
            "PLAN": (
                (PlanningStep.SPEC_REVIEW_REQUIRED, ReviewGate.SPEC),
                ("BASELINE", "SPEC"),
            ),
        }[artifact["kind"]]
        digest = planning_artifact_digest(artifact)
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            if artifact["base_sha"] != row["base_sha"]:
                raise GuardError(
                    "PLANNING_ARTIFACT_MISMATCH", "Artifact base SHA does not match Run."
                )
            if artifact["workspace_digest"] != row["workspace_digest"]:
                raise GuardError(
                    "PLANNING_ARTIFACT_MISMATCH", "Artifact workspace digest does not match Run."
                )
            if connection.execute(
                "SELECT 1 FROM planning_artifacts WHERE run_id = ? AND artifact_id = ?",
                (run_id, artifact["id"]),
            ).fetchone():
                raise GuardError(
                    "PLANNING_ARTIFACT_IMMUTABLE", "Planning artifact ID already exists."
                )
            candidate_packet: dict[str, Any] | None = None
            if artifact["kind"] == "PLAN":
                check_ids = {
                    str(item["check_id"])
                    for item in connection.execute(
                        "SELECT check_id FROM checks WHERE run_id = ?", (run_id,)
                    ).fetchall()
                }
                candidate_packet = normalize_packet(
                    artifact["implementation"]["packet"], available_checks=check_ids
                )
                if candidate_packet != artifact["implementation"]["packet"]:
                    raise GuardError(
                        "PLANNING_ARTIFACT_MISMATCH",
                        "PLAN implementation does not bind the registered Run checks.",
                    )
                if connection.execute(
                    "SELECT 1 FROM plan_candidates WHERE run_id = ?", (run_id,)
                ).fetchone():
                    raise GuardError(
                        "PLANNING_ARTIFACT_IMMUTABLE",
                        "Run already has an immutable PLAN candidate.",
                    )
            state = connection.execute(
                "SELECT planning_step, review_gate FROM planning_states WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            prior_state, required_kinds = expected_predecessor
            current_state = (
                None if state is None else (state["planning_step"], state["review_gate"])
            )
            if current_state != (
                None if prior_state is None else (prior_state[0].value, prior_state[1].value)
            ):
                raise GuardError(
                    "PLANNING_ARTIFACT_SEQUENCE",
                    "Planning artifacts must follow BASELINE, SPEC, then PLAN order.",
                )
            persisted_kinds = {
                str(item[0])
                for item in connection.execute(
                    "SELECT DISTINCT kind FROM planning_artifacts WHERE run_id = ?", (run_id,)
                ).fetchall()
            }
            if not set(required_kinds) <= persisted_kinds:
                raise GuardError(
                    "PLANNING_ARTIFACT_SEQUENCE",
                    "Planning artifact predecessors are missing.",
                )
            predecessor = _immediate_predecessor(connection, run_id, artifact["kind"])
            if predecessor is not None:
                _require_inherited_closure(artifact, predecessor["artifact"])
                receipt_id = _consume_planning_review(
                    connection,
                    run_id,
                    predecessor,
                    expected_revision,
                )
            else:
                receipt_id = ""
            created_at = utc_now()
            connection.execute(
                """
                INSERT INTO planning_artifacts(
                    run_id, artifact_id, kind, body_json, digest, base_sha, workspace_digest,
                    revision, planning_step, review_gate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    artifact["id"],
                    artifact["kind"],
                    canonical_json(artifact),
                    digest,
                    artifact["base_sha"],
                    artifact["workspace_digest"],
                    expected_revision,
                    expected_state[0].value,
                    expected_state[1].value,
                    created_at,
                ),
            )
            if candidate_packet is not None:
                connection.execute(
                    """
                    INSERT INTO plan_candidates(
                        run_id, artifact_id, artifact_digest, packet_json, packet_digest,
                        revision, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        artifact["id"],
                        digest,
                        canonical_json(candidate_packet),
                        packet_digest(candidate_packet),
                        expected_revision,
                        created_at,
                    ),
                )
            connection.execute(
                """
                INSERT INTO planning_states(run_id, planning_step, review_gate, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    planning_step = excluded.planning_step,
                    review_gate = excluded.review_gate,
                    updated_at = excluded.updated_at
                """,
                (run_id, expected_state[0].value, expected_state[1].value, created_at),
            )
            revision = append_event(
                connection,
                run_id,
                event="PLANNING_ARTIFACT_STORED",
                actor="model",
                payload={
                    "artifact_id": artifact["id"],
                    "kind": artifact["kind"],
                    "digest": digest,
                    "planning_step": expected_state[0].value,
                    "review_gate": expected_state[1].value,
                    "consumed_review_id": receipt_id,
                },
            )
        return {
            "artifact": artifact,
            "digest": digest,
            "packet_digest": "" if candidate_packet is None else packet_digest(candidate_packet),
            "revision": revision,
        }

    def record_planning_review_receipt(
        self,
        run_id: str,
        *,
        expected_revision: int,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        normalized = normalize_planning_review_receipt(receipt)
        if normalized["run_id"] != run_id:
            raise GuardError(
                "PLANNING_REVIEW_REQUIRED", "Review receipt Run does not match request."
            )
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            if normalized["issued_revision"] != expected_revision:
                raise GuardError("PLANNING_REVIEW_REQUIRED", "Review receipt revision is stale.")
            artifact_row = connection.execute(
                "SELECT * FROM planning_artifacts WHERE run_id = ? AND artifact_id = ? "
                "AND kind = ? AND digest = ?",
                (
                    run_id,
                    normalized["artifact_id"],
                    normalized["artifact_kind"],
                    normalized["artifact_digest"],
                ),
            ).fetchone()
            if (
                artifact_row is None
                or int(artifact_row["revision"]) != normalized["artifact_revision"]
                or normalized["base_sha"] != row["base_sha"]
                or normalized["workspace_digest"] != row["workspace_digest"]
            ):
                raise GuardError("PLANNING_REVIEW_REQUIRED", "Review receipt binding is invalid.")
            connection.execute(
                "INSERT INTO planning_review_receipts("
                "review_id, kind, run_id, artifact_id, artifact_kind, artifact_digest, "
                "artifact_revision, base_sha, workspace_digest, issued_revision, source, nonce, "
                "issued_at, decision, authority_ref) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(normalized[key] for key in _PLANNING_REVIEW_RECEIPT_FIELDS),
            )
            revision = append_event(
                connection,
                run_id,
                event="PLANNING_REVIEW_RECEIPT_RECORDED",
                actor="authority",
                payload=normalized,
            )
        return {"receipt": normalized, "revision": revision}

    def record_planning_submission_rejection(
        self,
        run_id: str,
        *,
        kind: str,
        input_digest: str,
        error_code: str,
    ) -> int | None:
        try:
            with self.database.write() as connection:
                row = select_run(connection, run_id)
                if row["blocked_code"] or row["stage"] == Stage.ACCEPTED.value:
                    return None
                return append_event(
                    connection,
                    run_id,
                    event="PLANNING_SUBMISSION_REJECTED",
                    actor="model",
                    payload={
                        "kind": kind,
                        "input_digest": input_digest,
                        "error_code": error_code,
                        "observed_at": utc_now(),
                    },
                )
        except GuardError:
            return None

    def record_plan_approval_receipt(
        self,
        run_id: str,
        *,
        expected_revision: int,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        normalized = normalize_plan_approval_receipt(receipt)
        if normalized["run_id"] != run_id:
            raise GuardError(
                "APPROVAL_RECEIPT_INVALID", "Approval receipt Run does not match request."
            )
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            existing = connection.execute(
                "SELECT * FROM plan_approval_receipts WHERE approval_id = ?",
                (normalized["approval_id"],),
            ).fetchone()
            if existing is not None:
                persisted = _approval_receipt(existing)
                if persisted != normalized:
                    raise GuardError(
                        "APPROVAL_RECEIPT_INVALID", "Approval receipt ID is immutable."
                    )
                return {
                    "receipt": persisted,
                    "consumed": bool(existing["consumed_at"]),
                    "revision": row["revision"],
                }
            check_revision(row, expected_revision)
            _mutable(connection, row)
            if normalized["revision"] != expected_revision:
                raise GuardError("APPROVAL_RECEIPT_INVALID", "Approval receipt revision is stale.")
            if (
                normalized["base_sha"] != row["base_sha"]
                or normalized["workspace_digest"] != row["workspace_digest"]
            ):
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "Approval receipt anchors do not match Run."
                )
            artifact_row = connection.execute(
                """
                SELECT * FROM planning_artifacts
                WHERE run_id = ? AND artifact_id = ? AND kind = 'PLAN' AND digest = ?
                """,
                (run_id, normalized["artifact_id"], normalized["artifact_digest"]),
            ).fetchone()
            if (
                artifact_row is None
                or _planning_artifact_digest_from_row(artifact_row) != normalized["artifact_digest"]
            ):
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "Approval receipt artifact binding is invalid."
                )
            candidate_row = connection.execute(
                """
                SELECT * FROM plan_candidates
                WHERE run_id = ? AND artifact_id = ? AND artifact_digest = ?
                """,
                (run_id, normalized["artifact_id"], normalized["artifact_digest"]),
            ).fetchone()
            if candidate_row is None:
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "Approval receipt has no PLAN candidate."
                )
            state = connection.execute(
                "SELECT planning_step, review_gate FROM planning_states WHERE run_id = ?", (run_id,)
            ).fetchone()
            if state is None or (state["planning_step"], state["review_gate"]) != (
                PlanningStep.PLAN_REVIEW_REQUIRED.value,
                ReviewGate.PLAN.value,
            ):
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "PLAN is not awaiting external approval."
                )
            if connection.execute(
                "SELECT 1 FROM plan_approval_receipts WHERE run_id = ? AND nonce = ?",
                (run_id, normalized["nonce"]),
            ).fetchone():
                raise GuardError(
                    "APPROVAL_NONCE_REPLAY", "Approval nonce was already issued for this Run."
                )
            if connection.execute(
                """
                SELECT 1 FROM plan_approval_receipts
                WHERE run_id = ? AND artifact_id = ? AND artifact_digest = ?
                """,
                (run_id, normalized["artifact_id"], normalized["artifact_digest"]),
            ).fetchone():
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "PLAN candidate already has an approval receipt."
                )
            connection.execute(
                """
                INSERT INTO plan_approval_receipts(
                    approval_id, kind, run_id, artifact_id, artifact_kind, artifact_digest,
                    base_sha, workspace_digest, revision, source, nonce, issued_at, decision,
                    authority_ref
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(normalized[key] for key in _APPROVAL_RECEIPT_FIELDS),
            )
            revision = append_event(
                connection,
                run_id,
                event="PLAN_APPROVAL_RECEIPT_RECORDED",
                actor="authority",
                payload=normalized,
            )
        return {"receipt": normalized, "consumed": False, "revision": revision}

    def consume_plan_approval_receipt(
        self,
        run_id: str,
        *,
        expected_revision: int,
        approval_id: str,
    ) -> dict[str, Any]:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            receipt_row = connection.execute(
                "SELECT * FROM plan_approval_receipts WHERE approval_id = ? AND run_id = ?",
                (approval_id, run_id),
            ).fetchone()
            if receipt_row is None:
                raise GuardError("APPROVAL_RECEIPT_INVALID", "Plan approval receipt is missing.")
            receipt = _approval_receipt(receipt_row)
            if receipt_row["consumed_at"]:
                raise GuardError(
                    "APPROVAL_NONCE_CONSUMED", "Plan approval nonce was already consumed."
                )
            if int(receipt["revision"]) + 1 != expected_revision:
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "Plan approval receipt revision is stale."
                )
            if (
                receipt["base_sha"] != row["base_sha"]
                or receipt["workspace_digest"] != row["workspace_digest"]
            ):
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "Plan approval receipt anchors are stale."
                )
            artifact_row = connection.execute(
                """
                SELECT * FROM planning_artifacts
                WHERE run_id = ? AND artifact_id = ? AND kind = 'PLAN' AND digest = ?
                """,
                (run_id, receipt["artifact_id"], receipt["artifact_digest"]),
            ).fetchone()
            if (
                artifact_row is None
                or _planning_artifact_digest_from_row(artifact_row) != receipt["artifact_digest"]
            ):
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "Plan approval receipt artifact is stale."
                )
            candidate_row = connection.execute(
                """
                SELECT * FROM plan_candidates
                WHERE run_id = ? AND artifact_id = ? AND artifact_digest = ?
                """,
                (run_id, receipt["artifact_id"], receipt["artifact_digest"]),
            ).fetchone()
            if candidate_row is None:
                raise GuardError(
                    "APPROVAL_RECEIPT_INVALID", "Plan approval receipt candidate is missing."
                )
            check_ids = {
                str(item["check_id"])
                for item in connection.execute(
                    "SELECT check_id FROM checks WHERE run_id = ?", (run_id,)
                ).fetchall()
            }
            candidate_packet = _candidate_packet_from_row(candidate_row, check_ids)
            artifact = json.loads(str(artifact_row["body_json"]))
            normalized_artifact = normalize_planning_artifact(artifact)
            implementation = normalized_artifact.get("implementation")
            if (
                not isinstance(implementation, dict)
                or implementation.get("packet") != candidate_packet
                or int(candidate_row["revision"]) != int(artifact_row["revision"])
            ):
                raise GuardError("PERSISTED_STATE_BROKEN", "PLAN candidate binding is invalid.")
            state = connection.execute(
                "SELECT planning_step, review_gate FROM planning_states WHERE run_id = ?", (run_id,)
            ).fetchone()
            if state is None or (state["planning_step"], state["review_gate"]) != (
                PlanningStep.PLAN_REVIEW_REQUIRED.value,
                ReviewGate.PLAN.value,
            ):
                raise GuardError("APPROVAL_RECEIPT_INVALID", "PLAN is not awaiting activation.")
            if (
                row["stage"] != Stage.PLANNING.value
                or row["packet_digest"]
                or row["active_phase"]
                or connection.execute(
                    "SELECT 1 FROM artifacts WHERE run_id = ? LIMIT 1", (run_id,)
                ).fetchone()
                or connection.execute(
                    "SELECT 1 FROM phase_executions WHERE run_id = ? LIMIT 1", (run_id,)
                ).fetchone()
            ):
                raise GuardError(
                    "PACKET_NOT_ALLOWED", "PLAN activation requires an empty planning Run."
                )
            consumed_at = utc_now()
            connection.execute(
                "UPDATE plan_approval_receipts SET consumed_at = ? WHERE approval_id = ?",
                (consumed_at, approval_id),
            )
            self._insert_artifact(
                connection,
                run_id,
                1,
                candidate_packet,
                str(candidate_row["packet_digest"]),
                consumed_at,
            )
            phases = candidate_packet["phases"]
            self._replace_phases(connection, run_id, phases, consumed_at)
            connection.execute(
                """
                UPDATE runs
                SET packet_digest = ?, active_phase = ?, evidence_digest = ''
                WHERE id = ?
                """,
                (candidate_row["packet_digest"], phases[0]["id"], run_id),
            )
            connection.execute(
                """
                UPDATE planning_states
                SET planning_step = ?, review_gate = '', updated_at = ?
                WHERE run_id = ?
                """,
                (PlanningStep.PLAN_APPROVED.value, consumed_at, run_id),
            )
            revision = append_event(
                connection,
                run_id,
                event="PLAN_APPROVAL_RECEIPT_CONSUMED",
                actor="authority",
                payload={
                    "approval_id": approval_id,
                    "nonce": receipt["nonce"],
                    "artifact_digest": receipt["artifact_digest"],
                    "packet_digest": candidate_row["packet_digest"],
                    "version": 1,
                    "phases": [phase["id"] for phase in phases],
                    "active_phase": phases[0]["id"],
                    "scope_digest": digest_json(_scope_declarations(candidate_packet)),
                },
                after_stage=Stage.IMPLEMENTING,
            )
        return {"approval_id": approval_id, "consumed": True, "revision": revision}

    @staticmethod
    def _insert_artifact(
        connection: Any,
        run_id: str,
        version: int,
        packet: dict[str, Any],
        digest: str,
        created_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO artifacts(run_id, kind, version, body_json, digest, created_at)
            VALUES (?, 'packet', ?, ?, ?, ?)
            """,
            (run_id, version, canonical_json(packet), digest, created_at),
        )

    @staticmethod
    def _replace_phases(
        connection: Any,
        run_id: str,
        phases: list[dict[str, Any]],
        created_at: str,
    ) -> None:
        connection.execute("DELETE FROM phase_executions WHERE run_id = ?", (run_id,))
        for position, phase in enumerate(phases):
            connection.execute(
                """
                INSERT INTO phase_executions(
                    run_id, phase_id, position, status,
                    requirement_ids_json, acceptance_ids_json,
                    allowed_paths_json, check_ids_json,
                    change_count, conclusion, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)
                """,
                (
                    run_id,
                    phase["id"],
                    position,
                    "ACTIVE" if position == 0 else "PENDING",
                    canonical_json(phase["requirement_ids"]),
                    canonical_json(phase["acceptance_ids"]),
                    canonical_json(phase["allowed_paths"]),
                    canonical_json(phase["check_ids"]),
                    created_at,
                ),
            )

    def get_artifact(self, run_id: str, *, version: int | None = None) -> dict[str, Any]:
        with self.database.connect(readonly=True) as connection:
            run = select_run(connection, run_id)
            if version is None:
                row = connection.execute(
                    """
                    SELECT * FROM artifacts
                    WHERE run_id = ? AND kind = 'packet' AND digest = ?
                    """,
                    (run_id, run["packet_digest"]),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT * FROM artifacts
                    WHERE run_id = ? AND kind = 'packet' AND version = ?
                    """,
                    (run_id, version),
                ).fetchone()
        if row is None:
            raise GuardError("ARTIFACT_NOT_FOUND", "Development packet is not frozen.")
        return {
            "kind": "packet",
            "version": int(row["version"]),
            "body": json.loads(str(row["body_json"])),
            "digest": str(row["digest"]),
            "created_at": str(row["created_at"]),
        }

    def list_artifact_history(self, run_id: str) -> list[dict[str, Any]]:
        with self.database.connect(readonly=True) as connection:
            run = select_run(connection, run_id)
            rows = connection.execute(
                """
                SELECT version, digest, created_at FROM artifacts
                WHERE run_id = ? AND kind = 'packet' ORDER BY version
                """,
                (run_id,),
            ).fetchall()
            retired = {
                int(payload["from_version"]): str(payload["retired_phases_digest"])
                for payload in (
                    json.loads(str(row["payload_json"]))
                    for row in connection.execute(
                        """
                        SELECT payload_json FROM events
                        WHERE run_id = ? AND type = 'PACKET_REVISED' ORDER BY seq
                        """,
                        (run_id,),
                    ).fetchall()
                )
            }
        return [
            {
                "version": int(row["version"]),
                "digest": str(row["digest"]),
                "created_at": str(row["created_at"]),
                "retired_phases_digest": retired.get(int(row["version"]), ""),
                "current": str(row["digest"]) == str(run["packet_digest"]),
            }
            for row in rows
        ]

    def list_phases(self, run_id: str) -> list[dict[str, Any]]:
        with self.database.connect(readonly=True) as connection:
            select_run(connection, run_id)
            rows = connection.execute(
                """
                SELECT * FROM phase_executions
                WHERE run_id = ? ORDER BY position
                """,
                (run_id,),
            ).fetchall()
        return [_phase(row) for row in rows]

    def create_write_lease(
        self,
        run_id: str,
        *,
        expected_revision: int,
        session_id: str,
        call_id: str,
        tool_name: str,
        declared_paths: list[str],
        before_digest: str,
        before_files: list[tuple[str, str]],
    ) -> dict[str, Any]:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            _assert_active_participant(connection, row, session_id)
            if row["stage"] != Stage.IMPLEMENTING.value or not row["active_phase"]:
                raise GuardError(
                    "WRITE_NOT_ALLOWED",
                    "Writes require an active implementation phase.",
                )
            if connection.execute(
                "SELECT 1 FROM write_leases WHERE run_id = ?",
                (run_id,),
            ).fetchone():
                raise GuardError("WRITE_BUSY", "Run already has an active write lease.")
            phase = connection.execute(
                """
                SELECT * FROM phase_executions
                WHERE run_id = ? AND phase_id = ? AND status = 'ACTIVE'
                """,
                (run_id, row["active_phase"]),
            ).fetchone()
            if phase is None:
                raise GuardError("PHASE_NOT_ACTIVE", "Run has no active frozen phase.")
            allowed_paths = json.loads(str(phase["allowed_paths_json"]))
            if (
                not isinstance(declared_paths, list)
                or not declared_paths
                or any(
                    not _valid_scope_declaration(path)
                    or str(path).endswith("/**")
                    or not any(_covers(pattern, str(path)) for pattern in allowed_paths)
                    for path in declared_paths
                )
            ):
                raise GuardError(
                    "WRITE_SCOPE_VIOLATION", "Write lease paths exceed the active PLAN phase scope."
                )
            created_at = utc_now()
            connection.execute(
                """
                INSERT INTO write_leases(
                    run_id, call_id, tool_name, phase_id,
                    requirement_ids_json, acceptance_ids_json,
                    declared_paths_json, before_digest, before_files_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    call_id,
                    tool_name,
                    phase["phase_id"],
                    phase["requirement_ids_json"],
                    phase["acceptance_ids_json"],
                    canonical_json(declared_paths),
                    before_digest,
                    canonical_json(before_files),
                    created_at,
                ),
            )
            lease = {
                "session_id": session_id,
                "call_id": call_id,
                "tool_name": tool_name,
                "phase_id": str(phase["phase_id"]),
                "requirement_ids": json.loads(str(phase["requirement_ids_json"])),
                "acceptance_ids": json.loads(str(phase["acceptance_ids_json"])),
                "declared_paths": declared_paths,
                "before_digest": before_digest,
                "before_files": before_files,
                "created_at": created_at,
            }
            revision = append_event(
                connection,
                run_id,
                event="WRITE_AUTHORIZED",
                actor=f"session:{session_id}",
                payload={
                    "call_id": call_id,
                    "tool": tool_name,
                    "phase": phase["phase_id"],
                    "paths": declared_paths,
                    "packet_digest": str(row["packet_digest"]),
                    "lease_digest": digest_json(lease),
                    "participant_bound": True,
                },
            )
            return {
                "revision": revision,
                "session_id": session_id,
                "call_id": call_id,
                "phase_id": str(phase["phase_id"]),
                "requirement_ids": json.loads(str(phase["requirement_ids_json"])),
                "acceptance_ids": json.loads(str(phase["acceptance_ids_json"])),
            }

    def get_write_lease(self, run_id: str) -> dict[str, Any] | None:
        with self.database.connect(readonly=True) as connection:
            run = select_run(connection, run_id)
            row = connection.execute(
                "SELECT * FROM write_leases WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                return None
            session_id, revision = _lease_binding(
                connection,
                run_id,
                str(row["call_id"]),
                str(run["session_id"]),
            )
            return {**_lease(row), "session_id": session_id, "revision": revision}

    def finish_write(
        self,
        run_id: str,
        *,
        expected_revision: int,
        session_id: str,
        call_id: str,
        workspace_digest: str,
        actual_paths: list[str],
    ) -> RunRecord:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            _assert_active_participant(connection, row, session_id)
            lease = connection.execute(
                "SELECT * FROM write_leases WHERE run_id = ? AND call_id = ?",
                (run_id, call_id),
            ).fetchone()
            if lease is None:
                raise GuardError("MISSING_WRITE_LEASE", "Write completed without authorization.")
            owner, _authorized_revision = _lease_binding(
                connection,
                run_id,
                call_id,
                str(row["session_id"]),
            )
            if owner != session_id:
                raise GuardError("WRITE_BUSY", "Write lease belongs to another participant.")
            changed_at = utc_now()
            connection.execute(
                "DELETE FROM write_leases WHERE run_id = ?",
                (run_id,),
            )
            connection.execute(
                """
                UPDATE phase_executions
                SET change_count = change_count + ?, updated_at = ?
                WHERE run_id = ? AND phase_id = ?
                """,
                (len(actual_paths), changed_at, run_id, lease["phase_id"]),
            )
            connection.execute(
                """
                UPDATE runs
                SET workspace_digest = ?, evidence_digest = ''
                WHERE id = ?
                """,
                (workspace_digest, run_id),
            )
            append_event(
                connection,
                run_id,
                event="WRITE_RECORDED",
                actor=f"session:{session_id}",
                payload={
                    "call_id": call_id,
                    "phase": lease["phase_id"],
                    "paths": actual_paths,
                    "packet_digest": str(row["packet_digest"]),
                    "workspace_digest": workspace_digest,
                },
                created_at=changed_at,
            )
            return run_from_row(select_run(connection, run_id))

    def cancel_unchanged_lease(self, run_id: str, call_id: str) -> RunRecord:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            _mutable(connection, row)
            deleted = connection.execute(
                "DELETE FROM write_leases WHERE run_id = ? AND call_id = ?",
                (run_id, call_id),
            ).rowcount
            if not deleted:
                raise GuardError("MISSING_WRITE_LEASE", "Write lease is no longer active.")
            append_event(
                connection,
                run_id,
                event="WRITE_RECOVERED",
                actor="authority",
                payload={
                    "call_id": call_id,
                    "changed": False,
                    "packet_digest": str(row["packet_digest"]),
                },
            )
            return run_from_row(select_run(connection, run_id))

    def complete_phase(
        self,
        run_id: str,
        *,
        expected_revision: int,
        phase_id: str,
        outcome: str,
        rationale: str,
    ) -> RunRecord:
        if outcome not in {"changed", "no-change"}:
            raise GuardError("INVALID_PHASE_OUTCOME", "Phase outcome is invalid.")
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 2_000:
            raise GuardError("INVALID_PHASE_OUTCOME", "Phase rationale is invalid.")
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            if row["stage"] != Stage.IMPLEMENTING.value or row["active_phase"] != phase_id:
                raise GuardError("PHASE_NOT_ACTIVE", "Only the active phase can be completed.")
            if connection.execute(
                "SELECT 1 FROM write_leases WHERE run_id = ?",
                (run_id,),
            ).fetchone():
                raise GuardError("WRITE_LEASE_PENDING", "Complete the pending write first.")
            phase = connection.execute(
                "SELECT * FROM phase_executions WHERE run_id = ? AND phase_id = ?",
                (run_id, phase_id),
            ).fetchone()
            if phase is None:
                raise GuardError("PHASE_NOT_FOUND", f"Unknown phase: {phase_id}")
            if outcome == "changed" and int(phase["change_count"]) == 0:
                raise GuardError(
                    "PHASE_OUTCOME_MISMATCH",
                    "A changed phase requires at least one recorded file change.",
                )
            completed_at = utc_now()
            connection.execute(
                """
                UPDATE phase_executions
                SET status = 'COMPLETED', conclusion = ?, updated_at = ?
                WHERE run_id = ? AND phase_id = ?
                """,
                (rationale.strip(), completed_at, run_id, phase_id),
            )
            next_phase = connection.execute(
                """
                SELECT * FROM phase_executions
                WHERE run_id = ? AND position > ?
                ORDER BY position LIMIT 1
                """,
                (run_id, phase["position"]),
            ).fetchone()
            if next_phase is None:
                connection.execute(
                    "UPDATE runs SET active_phase = '' WHERE id = ?",
                    (run_id,),
                )
                after_stage = Stage.VERIFYING
                next_id = ""
            else:
                connection.execute(
                    """
                    UPDATE phase_executions
                    SET status = 'ACTIVE', updated_at = ?
                    WHERE run_id = ? AND phase_id = ?
                    """,
                    (completed_at, run_id, next_phase["phase_id"]),
                )
                connection.execute(
                    "UPDATE runs SET active_phase = ? WHERE id = ?",
                    (next_phase["phase_id"], run_id),
                )
                after_stage = Stage.IMPLEMENTING
                next_id = str(next_phase["phase_id"])
            append_event(
                connection,
                run_id,
                event="PHASE_COMPLETED",
                actor="model",
                payload={
                    "phase_id": phase_id,
                    "outcome": outcome,
                    "next_phase": next_id,
                    "rationale": rationale.strip(),
                    "packet_digest": str(row["packet_digest"]),
                },
                after_stage=after_stage,
                created_at=completed_at,
            )
            return run_from_row(select_run(connection, run_id))

    def reopen_last_phase(
        self,
        run_id: str,
        *,
        event: str,
        payload: dict[str, Any],
        expected_revision: int,
        expected_packet_digest: str,
        expected_workspace_digest: str,
        expected_evidence_digest: str,
    ) -> RunRecord:
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            _mutable(connection, row)
            if row["stage"] != Stage.REVIEW_REQUIRED.value:
                raise GuardError("REVIEW_NOT_READY", "Run is not waiting for external review.")
            if (
                str(row["packet_digest"]) != expected_packet_digest
                or str(row["workspace_digest"]) != expected_workspace_digest
                or str(row["evidence_digest"]) != expected_evidence_digest
            ):
                raise GuardError(
                    "STALE_EVIDENCE",
                    "Review anchors changed before changes-requested.",
                )
            phase = connection.execute(
                """
                SELECT * FROM phase_executions
                WHERE run_id = ? ORDER BY position DESC LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            if phase is None:
                raise GuardError("PHASE_NOT_FOUND", "Run has no frozen phase.")
            reopened_at = utc_now()
            connection.execute(
                """
                UPDATE phase_executions
                SET status = 'ACTIVE', conclusion = '', updated_at = ?
                WHERE run_id = ? AND phase_id = ?
                """,
                (reopened_at, run_id, phase["phase_id"]),
            )
            connection.execute(
                """
                UPDATE runs
                SET active_phase = ?, evidence_digest = ''
                WHERE id = ?
                """,
                (phase["phase_id"], run_id),
            )
            append_event(
                connection,
                run_id,
                event=event,
                actor="authority",
                payload={**payload, "packet_digest": str(row["packet_digest"])},
                after_stage=Stage.IMPLEMENTING,
                created_at=reopened_at,
            )
            return run_from_row(select_run(connection, run_id))


def _phase(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["phase_id"]),
        "position": int(row["position"]),
        "status": str(row["status"]),
        "requirement_ids": json.loads(str(row["requirement_ids_json"])),
        "acceptance_ids": json.loads(str(row["acceptance_ids_json"])),
        "allowed_paths": json.loads(str(row["allowed_paths_json"])),
        "check_ids": json.loads(str(row["check_ids_json"])),
        "change_count": int(row["change_count"]),
        "conclusion": str(row["conclusion"]),
    }


def _lease(row: Any) -> dict[str, Any]:
    return {
        "run_id": str(row["run_id"]),
        "call_id": str(row["call_id"]),
        "tool_name": str(row["tool_name"]),
        "phase_id": str(row["phase_id"]),
        "requirement_ids": json.loads(str(row["requirement_ids_json"])),
        "acceptance_ids": json.loads(str(row["acceptance_ids_json"])),
        "declared_paths": json.loads(str(row["declared_paths_json"])),
        "before_digest": str(row["before_digest"]),
        "before_files": [tuple(item) for item in json.loads(str(row["before_files_json"]))],
        "created_at": str(row["created_at"]),
    }


def _lease_binding(
    connection: Any,
    run_id: str,
    call_id: str,
    legacy_session: str,
) -> tuple[str, int]:
    rows = connection.execute(
        """
        SELECT actor, payload_json, revision FROM events
        WHERE run_id = ? AND type = 'WRITE_AUTHORIZED'
        ORDER BY seq DESC
        """,
        (run_id,),
    ).fetchall()
    for row in rows:
        payload = json.loads(str(row["payload_json"]))
        if payload.get("call_id") != call_id:
            continue
        if payload.get("participant_bound") is True:
            actor = str(row["actor"])
            return actor.removeprefix("session:"), int(row["revision"])
        return legacy_session, int(row["revision"])
    raise GuardError("PERSISTED_STATE_BROKEN", "Write lease has no authorization event.")


def _assert_active_participant(connection: Any, run: Any, session_id: str) -> None:
    participant = connection.execute(
        "SELECT status FROM run_sessions WHERE run_id = ? AND session_id = ?",
        (str(run["id"]), session_id),
    ).fetchone()
    if participant is not None:
        if participant["status"] == "REVOKED":
            raise GuardError("SESSION_REVOKED", "OpenCode session access was revoked.")
        return
    if str(run["session_id"]) == session_id:
        return
    raise GuardError("SESSION_NOT_ATTACHED", "OpenCode session is not attached to this Run.")


def _mutable(connection: Any, row: Any) -> None:
    if row["blocked_code"]:
        raise GuardError(
            "RUN_BLOCKED",
            "Blocked Run cannot change state.",
            blocked_code=row["blocked_code"],
        )
    if row["stage"] == Stage.ACCEPTED.value:
        raise GuardError("RUN_ACCEPTED", "Accepted Run is immutable.")
    state = connection.execute(
        "SELECT planning_step FROM planning_states WHERE run_id = ?", (str(row["id"]),)
    ).fetchone()
    if state is not None and state["planning_step"] == PlanningStep.COMPATIBILITY_READ_ONLY.value:
        raise GuardError(
            "COMPATIBILITY_READ_ONLY",
            "Migrated legacy Run cannot acquire or continue write authority.",
        )


def _planning_artifact_digest_from_row(row: Any) -> str:
    body = json.loads(str(row["body_json"]))
    artifact = normalize_planning_artifact(body)
    digest = planning_artifact_digest(artifact)
    if canonical_json(artifact) != row["body_json"] or digest != row["digest"]:
        raise GuardError("PERSISTED_STATE_BROKEN", "Planning artifact is not canonical.")
    return digest


def _candidate_packet_from_row(row: Any, check_ids: set[str]) -> dict[str, Any]:
    try:
        body = json.loads(str(row["packet_json"]))
        packet = normalize_packet(body, available_checks=check_ids)
    except (TypeError, ValueError, GuardError) as exc:
        raise GuardError("PERSISTED_STATE_BROKEN", "PLAN candidate packet is invalid.") from exc
    if (
        canonical_json(packet) != row["packet_json"]
        or packet_digest(packet) != row["packet_digest"]
    ):
        raise GuardError("PERSISTED_STATE_BROKEN", "PLAN candidate packet is not canonical.")
    return packet


def _approval_receipt(row: Any) -> dict[str, Any]:
    return normalize_plan_approval_receipt(
        {field: row[field] for field in _APPROVAL_RECEIPT_FIELDS}
    )


def _immediate_predecessor(connection: Any, run_id: str, kind: str) -> dict[str, Any] | None:
    predecessor_kind = {"SPEC": "BASELINE", "PLAN": "SPEC"}.get(kind)
    if predecessor_kind is None:
        return None
    row = connection.execute(
        "SELECT * FROM planning_artifacts WHERE run_id = ? AND kind = ?", (run_id, predecessor_kind)
    ).fetchone()
    if row is None:
        raise GuardError("PLANNING_REVIEW_REQUIRED", "Planning predecessor is missing.")
    return {
        "row": row,
        "artifact": normalize_planning_artifact(json.loads(str(row["body_json"]))),
        "digest": _planning_artifact_digest_from_row(row),
    }


def _require_inherited_closure(candidate: dict[str, Any], predecessor: dict[str, Any]) -> None:
    fields = (
        "requirement_ids",
        "acceptance_ids",
        "ra_mappings",
        "source_digests",
        "facts",
        "assumptions",
        "decisions",
        "deviations",
    )
    if any(candidate[field] != predecessor[field] for field in fields):
        raise GuardError(
            "PLANNING_INHERITANCE_MISMATCH", "Planning authority is not an exact inheritance."
        )


def _consume_planning_review(
    connection: Any,
    run_id: str,
    predecessor: dict[str, Any],
    expected_revision: int,
) -> str:
    row = predecessor["row"]
    receipt_row = connection.execute(
        "SELECT * FROM planning_review_receipts WHERE run_id = ? AND artifact_id = ? "
        "AND artifact_kind = ? AND artifact_digest = ? AND decision = 'ACCEPT' "
        "AND consumed_at IS NULL",
        (run_id, row["artifact_id"], row["kind"], predecessor["digest"]),
    ).fetchone()
    if receipt_row is None:
        raise GuardError("PLANNING_REVIEW_REQUIRED", "External predecessor review is required.")
    receipt = normalize_planning_review_receipt(
        {field: receipt_row[field] for field in _PLANNING_REVIEW_RECEIPT_FIELDS}
    )
    if (
        receipt["artifact_revision"] != int(row["revision"])
        or receipt["issued_revision"] + 1 != expected_revision
    ):
        raise GuardError("PLANNING_REVIEW_REQUIRED", "External review receipt is stale.")
    consumed_at = utc_now()
    updated = connection.execute(
        "UPDATE planning_review_receipts SET consumed_at = ? WHERE review_id = ? "
        "AND consumed_at IS NULL",
        (consumed_at, receipt["review_id"]),
    )
    if updated.rowcount != 1:
        raise GuardError(
            "PLANNING_REVIEW_REQUIRED", "External review receipt was already consumed."
        )
    return str(receipt["review_id"])


def _scope_declarations(packet: dict[str, Any]) -> list[str]:
    return sorted({path for phase in packet["phases"] for path in phase["allowed_paths"]})


def _covers(pattern: str, declaration: str) -> bool:
    if pattern.endswith("/**"):
        root = pattern[:-3].rstrip("/")
        if declaration.endswith("/**"):
            candidate = declaration[:-3].rstrip("/")
            return candidate == root or candidate.startswith(f"{root}/")
        return declaration == root or declaration.startswith(f"{root}/")
    return pattern == declaration


def _scope_delta(current: dict[str, Any], candidate: dict[str, Any]) -> tuple[list[str], list[str]]:
    current_paths = _scope_declarations(current)
    candidate_paths = _scope_declarations(candidate)
    added = [
        path for path in candidate_paths if not any(_covers(old, path) for old in current_paths)
    ]
    removed = [
        path for path in current_paths if not any(_covers(new, path) for new in candidate_paths)
    ]
    return added, removed


def _phase_snapshot(connection: Any, run_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT * FROM phase_executions
        WHERE run_id = ? ORDER BY position
        """,
        (run_id,),
    ).fetchall()
    return [
        {
            "id": str(row["phase_id"]),
            "position": int(row["position"]),
            "status": str(row["status"]),
            "requirement_ids": json.loads(str(row["requirement_ids_json"])),
            "acceptance_ids": json.loads(str(row["acceptance_ids_json"])),
            "allowed_paths": json.loads(str(row["allowed_paths_json"])),
            "check_ids": json.loads(str(row["check_ids_json"])),
            "change_count": int(row["change_count"]),
            "conclusion": str(row["conclusion"]),
            "updated_at": str(row["updated_at"]),
        }
        for row in rows
    ]


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_scope_declaration(value: Any) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if "\\" in value or value.startswith("/") or ":" in value.split("/", 1)[0]:
        return False
    tree = value.endswith("/**")
    root = value[:-3] if tree else value
    if not root or root.endswith("/") or any(part in {"", ".", ".."} for part in root.split("/")):
        return False
    if any(marker in root for marker in "*?[]"):
        return False
    return tree or not any(marker in value for marker in "*?[]")


def _approval_events(connection: Any, run_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT seq, payload_json FROM events
        WHERE run_id = ? AND type = 'PLAN_SCOPE_APPROVED'
        ORDER BY seq
        """,
        (run_id,),
    ).fetchall()
    return [
        {"seq": int(row["seq"]), "payload": json.loads(str(row["payload_json"]))} for row in rows
    ]


def _consumed_approval_seqs(connection: Any, run_id: str) -> set[int]:
    rows = connection.execute(
        """
        SELECT payload_json FROM events
        WHERE run_id = ? AND type = 'PACKET_REVISED'
        ORDER BY seq
        """,
        (run_id,),
    ).fetchall()
    consumed: set[int] = set()
    for row in rows:
        payload = json.loads(str(row["payload_json"]))
        value = payload.get("approval_event_seq")
        if isinstance(value, int) and not isinstance(value, bool):
            consumed.add(value)
    return consumed


def _consume_scope_approval(
    connection: Any,
    run_id: str,
    *,
    base_digest: str,
    candidate_digest: str,
    added_paths: list[str],
) -> int | None:
    if not added_paths:
        return None
    paths = sorted(set(added_paths))
    path_digest = digest_json(paths)
    approvals = _approval_events(connection, run_id)
    consumed = _consumed_approval_seqs(connection, run_id)
    exact = next(
        (
            item
            for item in approvals
            if item["payload"].get("base_packet_digest") == base_digest
            and item["payload"].get("candidate_packet_digest") == candidate_digest
            and item["payload"].get("added_paths") == paths
            and item["payload"].get("added_paths_digest") == path_digest
        ),
        None,
    )
    if exact is None:
        candidate_related = [
            item
            for item in approvals
            if item["payload"].get("candidate_packet_digest") == candidate_digest
        ]
        if candidate_related:
            raise GuardError(
                "PLAN_SCOPE_APPROVAL_MISMATCH",
                "Plan scope approval does not match the current packet delta.",
                base_packet_digest=base_digest,
                candidate_packet_digest=candidate_digest,
                added_paths=paths,
            )
        raise GuardError(
            "PLAN_SCOPE_APPROVAL_REQUIRED",
            "Plan scope approval is required for added paths.",
            base_packet_digest=base_digest,
            candidate_packet_digest=candidate_digest,
            added_paths=paths,
        )
    sequence = int(exact["seq"])
    if sequence in consumed:
        raise GuardError(
            "PLAN_SCOPE_APPROVAL_CONSUMED",
            "Plan scope approval was already consumed.",
            approval_event_seq=sequence,
        )
    return sequence
