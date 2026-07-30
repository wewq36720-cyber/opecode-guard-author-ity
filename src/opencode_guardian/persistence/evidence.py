from __future__ import annotations

import json
import uuid
from typing import Any

from ..contracts import RunRecord, Stage
from ..errors import GuardError
from ..evidence import VerificationEvidence
from ..integrity import canonical_json, digest_json
from .database import Database, append_event, check_revision, run_from_row, select_run, utc_now


class EvidenceRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def finish_verification(
        self,
        run_id: str,
        *,
        evidence: list[VerificationEvidence],
        set_digest: str,
        previews: dict[str, str],
    ) -> RunRecord:
        if not evidence:
            raise GuardError("EVIDENCE_REQUIRED", "Verification produced no evidence.")
        passed = all(item.passed for item in evidence)
        batch_id = uuid.uuid4().hex
        bounded_previews = {
            item.check_id: previews.get(item.check_id, "")[:4_000] for item in evidence
        }
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            if row["stage"] != Stage.VERIFYING.value:
                raise GuardError("VERIFICATION_NOT_ACTIVE", "Run is not verifying.")
            current_packet_digest = str(row["packet_digest"])
            if any(item.artifact_set_digest != current_packet_digest for item in evidence):
                raise GuardError(
                    "STALE_EVIDENCE",
                    "Verification evidence is bound to an old packet.",
                )
            for item in evidence:
                connection.execute(
                    """
                    INSERT INTO evidence(
                        run_id, batch_id, set_digest, check_id,
                        requirement_ids_json, acceptance_ids_json,
                        base_sha, packet_digest, workspace_digest,
                        command_digest, image_digest, output_digest,
                        exit_code, timed_out, duration_ms, output_preview, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        batch_id,
                        set_digest,
                        item.check_id,
                        canonical_json(item.requirement_ids),
                        canonical_json(item.acceptance_ids),
                        item.base_sha,
                        item.artifact_set_digest,
                        item.workspace_digest,
                        item.command_digest,
                        item.image_digest,
                        item.output_digest,
                        item.exit_code,
                        int(item.timed_out),
                        item.duration_ms,
                        bounded_previews[item.check_id],
                        utc_now(),
                    ),
                )
            connection.execute(
                "UPDATE runs SET evidence_digest = ? WHERE id = ?",
                (set_digest, run_id),
            )
            if passed:
                append_event(
                    connection,
                    run_id,
                    event="VERIFICATION_PASSED",
                    actor="authority",
                    payload={
                        "batch_id": batch_id,
                        "evidence_digest": set_digest,
                        "previews_digest": digest_json(bounded_previews),
                        "packet_digest": current_packet_digest,
                    },
                    after_stage=Stage.REVIEW_REQUIRED,
                )
                return run_from_row(select_run(connection, run_id))

            phase = connection.execute(
                """
                SELECT phase_id FROM phase_executions
                WHERE run_id = ? ORDER BY position DESC LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            if phase is None:
                raise GuardError("PHASE_NOT_FOUND", "Run has no phase to reopen.")
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
                "UPDATE runs SET active_phase = ? WHERE id = ?",
                (phase["phase_id"], run_id),
            )
            append_event(
                connection,
                run_id,
                event="VERIFICATION_FAILED",
                actor="authority",
                payload={
                    "batch_id": batch_id,
                    "evidence_digest": set_digest,
                    "previews_digest": digest_json(bounded_previews),
                    "failed": [item.check_id for item in evidence if not item.passed],
                    "packet_digest": current_packet_digest,
                },
                after_stage=Stage.IMPLEMENTING,
                created_at=reopened_at,
            )
            return run_from_row(select_run(connection, run_id))

    def list_latest(
        self,
        run_id: str,
        *,
        packet_digest: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.database.connect(readonly=True) as connection:
            run = select_run(connection, run_id)
            current_digest = str(run["packet_digest"])
            selected_digest = current_digest if packet_digest is None else packet_digest
            if (
                selected_digest
                and connection.execute(
                    """
                SELECT 1 FROM artifacts
                WHERE run_id = ? AND kind = 'packet' AND digest = ?
                """,
                    (run_id, selected_digest),
                ).fetchone()
                is None
            ):
                raise GuardError("ARTIFACT_NOT_FOUND", "Packet artifact is not frozen.")
            latest = connection.execute(
                """
                SELECT batch_id FROM evidence
                WHERE run_id = ? AND packet_digest = ?
                ORDER BY id DESC LIMIT 1
                """,
                (run_id, selected_digest),
            ).fetchone()
            if latest is None:
                return []
            rows = connection.execute(
                """
                SELECT * FROM evidence
                WHERE run_id = ? AND batch_id = ? ORDER BY id
                """,
                (run_id, latest["batch_id"]),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["requirement_ids"] = json.loads(item.pop("requirement_ids_json"))
            item["acceptance_ids"] = json.loads(item.pop("acceptance_ids_json"))
            item["timed_out"] = bool(item["timed_out"])
            item["historical"] = selected_digest != current_digest
            result.append(item)
        return result

    def review(
        self,
        run_id: str,
        *,
        decision: str,
        reviewer: str,
        source: str,
        expected_revision: int,
        expected_packet_digest: str,
        expected_workspace_digest: str,
        expected_evidence_digest: str,
        actual_workspace_digest: str,
    ) -> RunRecord:
        if decision not in {"approve", "changes-requested"}:
            raise GuardError("INVALID_REVIEW", "Unknown review decision.")
        if source not in {"user", "ci", "independent-review"}:
            raise GuardError("INVALID_REVIEW", "Unknown review source.")
        if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 200:
            raise GuardError("INVALID_REVIEW", "Reviewer must be bounded text.")
        if decision == "changes-requested":
            raise GuardError(
                "REVIEW_REOPEN_REQUIRED",
                "Changes-requested must reopen the final phase through execution storage.",
            )
        with self.database.write() as connection:
            row = select_run(connection, run_id)
            check_revision(row, expected_revision)
            if row["stage"] != Stage.REVIEW_REQUIRED.value or not row["evidence_digest"]:
                raise GuardError(
                    "REVIEW_NOT_READY",
                    "Current passing evidence is required before approval.",
                )
            if (
                str(row["packet_digest"]) != expected_packet_digest
                or str(row["workspace_digest"]) != expected_workspace_digest
                or str(row["evidence_digest"]) != expected_evidence_digest
            ):
                raise GuardError(
                    "STALE_EVIDENCE",
                    "Review anchors changed before approval.",
                )
            if actual_workspace_digest != expected_workspace_digest:
                raise GuardError(
                    "STALE_EVIDENCE",
                    "Workspace changed after verification.",
                )
            connection.execute(
                "UPDATE runs SET active_phase = '' WHERE id = ?",
                (run_id,),
            )
            append_event(
                connection,
                run_id,
                event="RUN_ACCEPTED",
                actor=f"{source}:{reviewer.strip()}",
                payload={
                    "packet_digest": str(row["packet_digest"]),
                    "workspace_digest": str(row["workspace_digest"]),
                    "evidence_digest": str(row["evidence_digest"]),
                },
                after_stage=Stage.ACCEPTED,
            )
            return run_from_row(select_run(connection, run_id))
