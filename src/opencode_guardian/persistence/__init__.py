from __future__ import annotations

from pathlib import Path
from typing import Any

from ..contracts import RunRecord
from ..evidence import VerificationEvidence
from ..paths import default_state_dir
from .database import Database
from .evidence import EvidenceRepository
from .execution import ExecutionRepository
from .quality import QualityRepository
from .runs import RunRepository


class StateStore:
    """Single public persistence facade for the minimal Guard runtime."""

    def __init__(self, database: Path | None = None) -> None:
        self._database = Database(database)
        self.database = self._database.path
        self.runs = RunRepository(self._database)
        self.execution = ExecutionRepository(self._database)
        self.evidence = EvidenceRepository(self._database)
        self.quality = QualityRepository(self._database)

    def create_run(self, **values: Any) -> RunRecord:
        return self.runs.create(**values)

    def get_run(self, run_id: str) -> RunRecord:
        return self.runs.get(run_id)

    def find_active(self, project_root: Path) -> RunRecord | None:
        return self.runs.find_active(project_root)

    def cancel_startup(self, run_id: str) -> RunRecord:
        return self.runs.cancel_startup(run_id)

    def bind_task(self, run_id: str, **values: Any) -> RunRecord:
        return self.runs.bind_task(run_id, **values)

    def attach_session(self, run_id: str, session_id: str, *, expected_revision: int) -> RunRecord:
        return self.runs.attach_session(
            run_id,
            session_id,
            expected_revision=expected_revision,
        )

    def revoke_session(self, run_id: str, session_id: str) -> RunRecord:
        return self.runs.revoke_session(run_id, session_id)

    def assert_session(self, run_id: str, session_id: str) -> RunRecord:
        return self.runs.assert_session(run_id, session_id)

    def block_run(self, run_id: str, **values: Any) -> RunRecord:
        return self.runs.block(run_id, **values)

    def list_checks(self, run_id: str) -> list[dict[str, Any]]:
        return self.runs.list_checks(run_id)

    def submit_packet(self, run_id: str, **values: Any) -> RunRecord:
        return self.execution.submit_packet(run_id, **values)

    def approve_plan(self, run_id: str, **values: Any) -> RunRecord:
        return self.execution.approve_plan(run_id, **values)

    def get_plan_approval(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.execution.get_plan_approval(run_id, **values)

    def store_planning_artifact(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.execution.store_planning_artifact(run_id, **values)

    def record_plan_approval_receipt(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.execution.record_plan_approval_receipt(run_id, **values)

    def record_planning_review_receipt(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.execution.record_planning_review_receipt(run_id, **values)

    def record_planning_submission_rejection(self, run_id: str, **values: Any) -> int | None:
        return self.execution.record_planning_submission_rejection(run_id, **values)

    def consume_plan_approval_receipt(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.execution.consume_plan_approval_receipt(run_id, **values)

    def get_artifact(self, run_id: str, *, version: int | None = None) -> dict[str, Any]:
        return self.execution.get_artifact(run_id, version=version)

    def list_artifact_history(self, run_id: str) -> list[dict[str, Any]]:
        return self.execution.list_artifact_history(run_id)

    def list_phases(self, run_id: str) -> list[dict[str, Any]]:
        return self.execution.list_phases(run_id)

    def create_write_lease(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.execution.create_write_lease(run_id, **values)

    def get_write_lease(self, run_id: str) -> dict[str, Any] | None:
        return self.execution.get_write_lease(run_id)

    def finish_write(self, run_id: str, **values: Any) -> RunRecord:
        return self.execution.finish_write(run_id, **values)

    def cancel_unchanged_lease(self, run_id: str, call_id: str) -> RunRecord:
        return self.execution.cancel_unchanged_lease(run_id, call_id)

    def complete_phase(self, run_id: str, **values: Any) -> RunRecord:
        return self.execution.complete_phase(run_id, **values)

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
        return self.execution.reopen_last_phase(
            run_id,
            event=event,
            payload=payload,
            expected_revision=expected_revision,
            expected_packet_digest=expected_packet_digest,
            expected_workspace_digest=expected_workspace_digest,
            expected_evidence_digest=expected_evidence_digest,
        )

    def finish_verification(
        self,
        run_id: str,
        *,
        evidence: list[VerificationEvidence],
        set_digest: str,
        previews: dict[str, str],
    ) -> RunRecord:
        return self.evidence.finish_verification(
            run_id,
            evidence=evidence,
            set_digest=set_digest,
            previews=previews,
        )

    def list_evidence(
        self,
        run_id: str,
        *,
        packet_digest: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.evidence.list_latest(run_id, packet_digest=packet_digest)

    def drive_quality(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.quality.drive(run_id, **values)

    def get_quality_drive(self, run_id: str, request_id: str) -> dict[str, Any] | None:
        return self.quality.get_drive(run_id, request_id)

    def confirm_fitness(self, run_id: str, **values: Any) -> dict[str, Any]:
        return self.quality.confirm(run_id, **values)

    def get_fitness_confirmation(self, run_id: str, request_id: str) -> dict[str, Any] | None:
        return self.quality.get_confirmation(run_id, request_id)

    def approve(
        self,
        run_id: str,
        *,
        reviewer: str,
        source: str,
        expected_revision: int,
        expected_packet_digest: str,
        expected_workspace_digest: str,
        expected_evidence_digest: str,
        actual_workspace_digest: str,
    ) -> RunRecord:
        return self.evidence.review(
            run_id,
            decision="approve",
            reviewer=reviewer,
            source=source,
            expected_revision=expected_revision,
            expected_packet_digest=expected_packet_digest,
            expected_workspace_digest=expected_workspace_digest,
            expected_evidence_digest=expected_evidence_digest,
            actual_workspace_digest=actual_workspace_digest,
        )


__all__ = ["StateStore", "default_state_dir"]
